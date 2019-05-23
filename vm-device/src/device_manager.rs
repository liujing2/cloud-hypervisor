// Copyright © 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 and BSD-3-Clause

//! System device management.
//!
//! [DeviceManager](struct.DeviceManager.html) responds to manage all devices
//! of virtual machine, store basic device information like name and
//! parent bus, register IO resource callback, unregister devices and help
//! VM IO exit handling.

extern crate vm_allocator;

use self::vm_allocator::SystemAllocator;
use crate::device::*;
use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::collections::btree_map::BTreeMap;
use std::collections::HashMap;
use std::result;
use std::sync::{Arc, Mutex};
use vm_memory::{GuestAddress, GuestUsize};

/// Guest physical address and size pair to describe a range.
#[derive(Eq, Debug, Copy, Clone)]
pub struct Range(pub GuestAddress, pub GuestUsize);

impl PartialEq for Range {
    fn eq(&self, other: &Range) -> bool {
        self.0 == other.0
    }
}

impl Ord for Range {
    fn cmp(&self, other: &Range) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for Range {
    fn partial_cmp(&self, other: &Range) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

/// Error type for `DeviceManager` usage.
#[derive(Debug)]
pub enum Error {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
    /// The insertion failed because the resource is not enough.
    Oversize,
    /// PIO address is none.
    NonePIOAddress,
    /// The insertion failed because device already exists.
    Exist,
    /// The removing fails because the device doesn't exist.
    NonExist,
    /// IRQ allocated failed.
    AllocateIrq,
}

/// Simplify the `Result` type.
pub type Result<T> = result::Result<T, Error>;

/// System device manager serving for all devices management and VM exit handling.
pub struct DeviceManager {
    /// System allocator reference.
    resource: Arc<Mutex<SystemAllocator>>,
    /// Devices information mapped by name.
    devices: HashMap<String, DeviceDescriptor>,
    /// Range mapping for VM exit mmio operations.
    pub mmio_bus: BTreeMap<Range, Arc<Mutex<dyn Device>>>,
    /// Range mapping for VM exit pio operations.
    pub pio_bus: BTreeMap<Range, Arc<Mutex<dyn Device>>>,
}

impl DeviceManager {
    /// Create a new `DeviceManager` with a `SystemAllocator` reference which would be
    /// used to allocate resource for devices.
    pub fn new(resource: Arc<Mutex<SystemAllocator>>) -> Self {
        DeviceManager {
            resource,
            devices: HashMap::new(),
            mmio_bus: BTreeMap::new(),
            pio_bus: BTreeMap::new(),
        }
    }

    fn insert(&mut self, dev: DeviceDescriptor) -> Result<()> {
        // Insert if the key is non-present, else report error.
        if self.devices.get(&(dev.name)).is_some() {
            return Err(Error::Exist);
        }
        self.devices.insert(dev.name.clone(), dev);
        Ok(())
    }

    fn remove(&mut self, name: String) -> Option<DeviceDescriptor> {
        self.devices.remove(&name)
    }

    fn device_descriptor(
        &self,
        dev: Arc<Mutex<dyn Device>>,
        parent_bus: Option<Arc<Mutex<dyn Device>>>,
        resource: Vec<IoResource>,
    ) -> DeviceDescriptor {
        let name = dev.lock().expect("Failed to require lock").name();
        DeviceDescriptor::new(name, dev.clone(), parent_bus, resource)
    }

    fn allocate_resources(&mut self, resource: &mut Vec<IoResource>) -> Result<()> {
        let mut alloc_idx = 0;

        for res in resource.iter_mut() {
            match res.res_type {
                IoType::Pio => {
                    if res.addr.is_none() {
                        return Err(Error::NonePIOAddress);
                    }
                    res.addr = self
                        .resource
                        .lock()
                        .expect("Failed to acquire lock")
                        .allocate_io_addresses(res.addr.unwrap(), res.size);
                }
                IoType::PhysicalMmio | IoType::Mmio => {
                    res.addr = self.resource
                        .lock()
                        .expect("Failed to acquire lock")
                        .allocate_mmio_addresses(res.addr, res.size)
                }
            }
            if res.addr.is_none() {
                // Failed to allocate resource.
                break;
            }
            alloc_idx += 1;
        }

        // Successfully allocate.
        if alloc_idx == resource.len() {
            return Ok(());
        }

        // Failed and free the previous resource.
        self.free_resources(&resource[0..alloc_idx]);
        Err(Error::Overlap)
    }

    fn free_resources(&mut self, resource: &[IoResource]) {
        for res in resource.iter() {
            match res.res_type {
                IoType::Pio => self.resource.lock().expect("Failed to acquire lock").free_io_addresses(res.addr.unwrap(), res.size),
                IoType::PhysicalMmio | IoType::Mmio => self
                    .resource.lock().expect("Failed to acquire lock")
                    .free_mmio_addresses(res.addr.unwrap(), res.size),
            }
        }
    }

    fn register_resource(
        &mut self,
        dev: Arc<Mutex<dyn Device>>,
        resource: &mut Vec<IoResource>,
    ) -> Result<()> {
        for res in resource.iter() {
            match res.res_type {
                IoType::Pio => {
                    if self
                        .pio_bus
                        .insert(Range(res.addr.unwrap(), res.size), dev.clone())
                        .is_some()
                    {
                        return Err(Error::Overlap);
                    }
                }
                IoType::Mmio => {
                    if self
                        .mmio_bus
                        .insert(Range(res.addr.unwrap(), res.size), dev.clone())
                        .is_some()
                    {
                        return Err(Error::Overlap);
                    }
                }
                IoType::PhysicalMmio => continue,
            };
        }
        Ok(())
    }

    /// Register a new device with its parent bus and resource request set.
    pub fn register_device(
        &mut self,
        dev: Arc<Mutex<dyn Device>>,
        parent_bus: Option<Arc<Mutex<dyn Device>>>,
        resource: &mut Vec<IoResource>,
        interrupt: Option<IrqResource>,
    ) -> Result<()> {
        // Reserve resource
        if let Err(e) = self.allocate_resources(resource) {
            return Err(e);
        }

        // Register device resource
        if let Err(Error::Overlap) = self.register_resource(dev.clone(), resource) {
            return Err(Error::Overlap);
        }

        match interrupt {
            Some(IrqResource(irq)) => {
                match irq {
                    // TODO: Return Error when requesting a specified irq resource
                    Some(_) => {
                        return Err(Error::AllocateIrq);
                    }
                    // Allocate irq resource
                    None => {
                        // Set the allocated resource back
                        dev.lock().expect("Failed to acquire lock.").set_resources(
                            resource,
                            Some(IrqResource(self.resource.lock().expect("Failed to acquire lock").allocate_irq())),
                        );
                    }
                }
            }
            None => {
                dev.lock()
                    .expect("Failed to acquire lock.")
                    .set_resources(resource, None);
            }
        }

        // Insert bus/device to DeviceManager with parent bus
        let descriptor = self.device_descriptor(dev, parent_bus, resource.to_vec());
        self.insert(descriptor)
    }

    /// Unregister a device from `DeviceManager`.
    pub fn unregister_device(&mut self, dev: Arc<Mutex<dyn Device>>) -> Result<()> {
        let name = dev.lock().expect("Failed to acquire lock").name();

        if let Some(descriptor) = self.remove(name) {
            for res in descriptor.resource.iter() {
                if res.addr.is_some() {
                    match res.res_type {
                        IoType::Pio => self.pio_bus.remove(&Range(res.addr.unwrap(), res.size)),
                        IoType::Mmio => self.mmio_bus.remove(&Range(res.addr.unwrap(), res.size)),
                        IoType::PhysicalMmio => continue,
                    };
                }
            }
            // Free the resource
            self.free_resources(&descriptor.resource);
            Ok(())
        } else {
            Err(Error::NonExist)
        }
    }

    fn first_before(
        &self,
        addr: GuestAddress,
        io_type: IoType,
    ) -> Option<(Range, &Mutex<dyn Device>)> {
        match io_type {
            IoType::Pio => {
                for (range, dev) in self.pio_bus.iter().rev() {
                    if range.0 <= addr {
                        return Some((*range, dev));
                    }
                }
                None
            }
            IoType::Mmio => {
                for (range, dev) in self.mmio_bus.iter().rev() {
                    if range.0 <= addr {
                        return Some((*range, dev));
                    }
                }
                None
            }
            IoType::PhysicalMmio => None,
        }
    }

    /// Return the Device mapped the address.
    fn get_device(&self, addr: GuestAddress, io_type: IoType) -> Option<&Mutex<dyn Device>> {
        if let Some((Range(start, len), dev)) = self.first_before(addr, io_type) {
            if (addr.0 - start.0) < len {
                return Some(dev);
            }
        }
        None
    }

    /// A helper function handling PIO/MMIO read commands during VM exit.
    ///
    /// Figure out the device according to `addr` and hand over the handling to device
    /// specific read function.
    /// Return error if failed to get the device.
    pub fn read(&self, addr: GuestAddress, data: &mut [u8], io_type: IoType) -> Result<()> {
        if let Some(dev) = self.get_device(addr, io_type) {
            dev.lock()
                .expect("Failed to acquire device lock")
                .read(addr, data, io_type);
            Ok(())
        } else {
            Err(Error::NonExist)
        }
    }

    /// A helper function handling PIO/MMIO write commands during VM exit.
    ///
    /// Figure out the device according to `addr` and hand over the handling to device
    /// specific write function.
    /// Return error if failed to get the device.
    pub fn write(&self, addr: GuestAddress, data: &[u8], io_type: IoType) -> Result<()> {
        if let Some(dev) = self.get_device(addr, io_type) {
            dev.lock()
                .expect("Failed to acquire device lock")
                .write(addr, data, io_type);
            Ok(())
        } else {
            Err(Error::NonExist)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::device::*;
    use crate::device_manager::*;
    use std::string::String;

    #[test]
    fn test_dev_init() -> Result<()> {
        pub struct BusDevice {
            pub config_address: u32,
            pub name: String,
        }
        impl Device for BusDevice {
            /// Get the device name.
            fn name(&self) -> String {
                self.name.clone()
            }
            /// Read operation.
            fn read(&mut self, _addr: GuestAddress, data: &mut [u8], _io_type: IoType) {
                if data.len() > 4 {
                    for d in data {
                        *d = 0xff;
                    }
                    return;
                }
                for i in 0..data.len() {
                    data[i] = (self.config_address >> (i * 8) & 0xff) as u8;
                }
            }
            /// Write operation.
            fn write(&mut self, _addr: GuestAddress, data: &[u8], _io_type: IoType) {
                self.config_address = data[0] as u32 & 0xff;
            }
            /// Set the allocated resource to device.
            ///
            /// This will be called by DeviceManager::register_device() to set
            /// the allocated resource from the vm_allocator back to device.
            fn set_resources(&mut self, _res: &[IoResource], _irq: Option<IrqResource>) {}
        }
        impl BusDevice {
            pub fn new(name: String) -> Self {
                BusDevice {
                    name,
                    config_address: 0x1000,
                }
            }
            pub fn get_resource(&self) -> Vec<IoResource> {
                let mut req_vec = Vec::new();
                let res = IoResource::new(Some(GuestAddress(0xcf8)), 8 as GuestUsize, IoType::Pio);

                req_vec.push(res);
                req_vec
            }
        }

        let mut sys_res = SystemAllocator::new(
            Some(GuestAddress(0x100)),
            Some(0x10000),
            GuestAddress(0x10000000),
            0x10000000,
            5,
        )
        .unwrap();
        let mut dev_mgr = DeviceManager::new(Arc::new(Mutex::new(sys_res)));
        let dummy_bus = BusDevice::new("dummy-bus".to_string());
        let mut res_req = dummy_bus.get_resource();

        dev_mgr.register_device(
            Arc::new(Mutex::new(dummy_bus)),
            None,
            &mut res_req,
            Some(IrqResource(None)),
        )
    }

}

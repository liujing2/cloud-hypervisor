// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

extern crate devices;
extern crate pci;
extern crate vm_allocator;

use crate::vec_with_array_field;
use crate::vfio_device::VfioDevice;
use byteorder::{ByteOrder, LittleEndian};
use devices::BusDevice;
use kvm_bindings::{
    kvm_irq_routing, kvm_irq_routing_entry, kvm_userspace_memory_region, KVM_IRQ_ROUTING_MSI,
};
use kvm_ioctls::*;
use pci::{
    BarReprogrammingParams, MsiCap, MsixCap, MsixConfig, PciBarConfiguration, PciBarRegionType,
    PciCapabilityID, PciClassCode, PciConfiguration, PciDevice, PciDeviceError, PciHeaderType,
    PciSubclass, MSIX_TABLE_ENTRY_SIZE,
};
use std::any::Any;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::{fmt, io, result};
use vfio_bindings::bindings::vfio::*;
use vm_allocator::SystemAllocator;
use vm_memory::{Address, GuestAddress, GuestUsize};
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug)]
pub enum VfioPciError {
    AllocateGsi,
    EventFd(io::Error),
    IrqFd(kvm_ioctls::Error),
    NewVfioPciDevice,
    MapRegionGuest(kvm_ioctls::Error),
    SetGsiRouting(kvm_ioctls::Error),
    MsiNotConfigured,
    MsixNotConfigured,
}
pub type Result<T> = std::result::Result<T, VfioPciError>;

impl fmt::Display for VfioPciError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VfioPciError::AllocateGsi => write!(f, "failed to allocate GSI"),
            VfioPciError::EventFd(e) => write!(f, "failed to create eventfd: {}", e),
            VfioPciError::IrqFd(e) => write!(f, "failed to register irqfd: {}", e),
            VfioPciError::NewVfioPciDevice => write!(f, "failed to create VFIO PCI device"),
            VfioPciError::MapRegionGuest(e) => {
                write!(f, "failed to map VFIO PCI region into guest: {}", e)
            }
            VfioPciError::SetGsiRouting(e) => write!(f, "failed to set GSI routes for KVM: {}", e),
            VfioPciError::MsiNotConfigured => write!(f, "MSI interrupt not yet configured"),
            VfioPciError::MsixNotConfigured => write!(f, "MSI-X interrupt not yet configured"),
        }
    }
}

#[derive(Copy, Clone)]
enum PciVfioSubclass {
    VfioSubclass = 0xff,
}

impl PciSubclass for PciVfioSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

enum InterruptUpdateAction {
    EnableMsi,
    DisableMsi,
    EnableMsix,
    DisableMsix,
}

#[derive(Copy, Clone)]
struct VfioMsi {
    cap: MsiCap,
    cap_offset: u32,
}

impl VfioMsi {
    fn update(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        let old_enabled = self.cap.enabled();

        self.cap.update(offset, data);

        let new_enabled = self.cap.enabled();

        if !old_enabled && new_enabled {
            return Some(InterruptUpdateAction::EnableMsi);
        }

        if old_enabled && !new_enabled {
            return Some(InterruptUpdateAction::DisableMsi);
        }

        None
    }
}

struct VfioMsix {
    bar: MsixConfig,
    cap: MsixCap,
    cap_offset: u32,
}

impl VfioMsix {
    fn update(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        let old_enabled = self.cap.enabled();

        // Update "Message Control" word
        if offset == 2 && data.len() == 2 {
            self.cap.set_msg_ctl(LittleEndian::read_u16(data));
        }

        let new_enabled = self.cap.enabled();

        if !old_enabled && new_enabled {
            return Some(InterruptUpdateAction::EnableMsix);
        }

        if old_enabled && !new_enabled {
            return Some(InterruptUpdateAction::DisableMsix);
        }

        None
    }

    fn table_accessed(&self, bar_index: u32, offset: u64) -> bool {
        let table_offset: u64 = u64::from(self.cap.table_offset());
        let table_size: u64 = u64::from(self.cap.table_size()) * (MSIX_TABLE_ENTRY_SIZE as u64);
        let table_bir: u32 = self.cap.table_bir();

        bar_index == table_bir && offset >= table_offset && offset < table_offset + table_size
    }
}

struct Interrupt {
    msi: Option<VfioMsi>,
    msix: Option<VfioMsix>,
}

impl Interrupt {
    fn update_msi(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        if let Some(ref mut msi) = &mut self.msi {
            let action = msi.update(offset, data);
            return action;
        }

        None
    }

    fn update_msix(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        if let Some(ref mut msix) = &mut self.msix {
            let action = msix.update(offset, data);
            return action;
        }

        None
    }

    fn accessed(&self, offset: u64) -> Option<(PciCapabilityID, u64)> {
        if let Some(msi) = &self.msi {
            if offset >= u64::from(msi.cap_offset)
                && offset < u64::from(msi.cap_offset) + msi.cap.size()
            {
                return Some((
                    PciCapabilityID::MessageSignalledInterrupts,
                    u64::from(msi.cap_offset),
                ));
            }
        }

        if let Some(msix) = &self.msix {
            if offset == u64::from(msix.cap_offset) {
                return Some((PciCapabilityID::MSIX, u64::from(msix.cap_offset)));
            }
        }

        None
    }

    fn msix_table_accessed(&self, bar_index: u32, offset: u64) -> bool {
        if let Some(msix) = &self.msix {
            return msix.table_accessed(bar_index, offset);
        }

        false
    }

    fn msix_write_table(&mut self, offset: u64, data: &[u8]) {
        if let Some(ref mut msix) = &mut self.msix {
            let offset = offset - u64::from(msix.cap.table_offset());
            msix.bar.write_table(offset, data)
        }
    }

    fn msix_read_table(&self, offset: u64, data: &mut [u8]) {
        if let Some(msix) = &self.msix {
            let offset = offset - u64::from(msix.cap.table_offset());
            msix.bar.read_table(offset, data)
        }
    }
}

struct InterruptRoute {
    gsi: u32,
    irq_fd: EventFd,
}

impl InterruptRoute {
    fn new(allocator: &mut SystemAllocator) -> Result<Self> {
        let irq_fd = EventFd::new(libc::EFD_NONBLOCK).map_err(VfioPciError::EventFd)?;
        let gsi = allocator.allocate_gsi().ok_or(VfioPciError::AllocateGsi)?;

        Ok(InterruptRoute { gsi, irq_fd })
    }

    fn enable(&self, vm: &Arc<VmFd>) -> Result<()> {
        vm.register_irqfd(&self.irq_fd, self.gsi)
            .map_err(VfioPciError::IrqFd)
    }

    fn disable(&self, vm: &Arc<VmFd>) -> Result<()> {
        vm.unregister_irqfd(&self.irq_fd, self.gsi)
            .map_err(VfioPciError::IrqFd)
    }
}

#[derive(Copy, Clone)]
struct MmioRegion {
    start: GuestAddress,
    length: GuestUsize,
    index: u32,
    mem_slot: Option<u32>,
    host_addr: Option<u64>,
    mmap_size: Option<usize>,
}

struct VfioPciConfig {
    device: Arc<VfioDevice>,
}

impl VfioPciConfig {
    fn new(device: Arc<VfioDevice>) -> Self {
        VfioPciConfig { device }
    }

    fn read_config_byte(&self, offset: u32) -> u8 {
        let mut data: [u8; 1] = [0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        data[0]
    }

    fn read_config_word(&self, offset: u32) -> u16 {
        let mut data: [u8; 2] = [0, 0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        u16::from_le_bytes(data)
    }

    fn read_config_dword(&self, offset: u32) -> u32 {
        let mut data: [u8; 4] = [0, 0, 0, 0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        u32::from_le_bytes(data)
    }

    fn write_config_dword(&self, buf: u32, offset: u32) {
        let data: [u8; 4] = buf.to_le_bytes();
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, &data, offset.into())
    }
}

/// VfioPciDevice represents a VFIO PCI device.
/// This structure implements the BusDevice and PciDevice traits.
///
/// A VfioPciDevice is bound to a VfioDevice and is also a PCI device.
/// The VMM creates a VfioDevice, then assigns it to a VfioPciDevice,
/// which then gets added to the PCI bus.
pub struct VfioPciDevice {
    vm_fd: Arc<VmFd>,
    device: Arc<VfioDevice>,
    vfio_pci_configuration: VfioPciConfig,
    configuration: PciConfiguration,
    mmio_regions: Vec<MmioRegion>,
    interrupt: Interrupt,
    interrupt_routes: Vec<InterruptRoute>,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, kvm_irq_routing_entry>>>,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the given Vfio device
    pub fn new(
        vm_fd: &Arc<VmFd>,
        allocator: &mut SystemAllocator,
        device: VfioDevice,
        gsi_msi_routes: Arc<Mutex<HashMap<u32, kvm_irq_routing_entry>>>,
    ) -> Result<Self> {
        let device = Arc::new(device);
        device.reset();

        let configuration = PciConfiguration::new(
            0,
            0,
            PciClassCode::Other,
            &PciVfioSubclass::VfioSubclass,
            None,
            PciHeaderType::Device,
            0,
            0,
            None,
        );

        let vfio_pci_configuration = VfioPciConfig::new(Arc::clone(&device));

        let mut vfio_pci_device = VfioPciDevice {
            vm_fd: vm_fd.clone(),
            device,
            configuration,
            vfio_pci_configuration,
            mmio_regions: Vec::new(),
            interrupt: Interrupt {
                msi: None,
                msix: None,
            },
            interrupt_routes: Vec::new(),
            gsi_msi_routes,
        };

        vfio_pci_device.parse_capabilities();

        // Allocate temporary interrupt routes for now.
        // The MSI vectors will be filled when the guest driver programs the device.
        let max_interrupts = vfio_pci_device.device.max_interrupts();
        for _ in 0..max_interrupts {
            let route = InterruptRoute::new(allocator)?;
            vfio_pci_device.interrupt_routes.push(route);
        }

        Ok(vfio_pci_device)
    }

    fn enable_irq_fds(&self) -> Result<Vec<&EventFd>> {
        let mut irq_fds: Vec<&EventFd> = Vec::new();

        for r in &self.interrupt_routes {
            r.enable(&self.vm_fd)?;
            irq_fds.push(&r.irq_fd);
        }

        Ok(irq_fds)
    }

    fn disable_irq_fds(&self) -> Result<()> {
        for r in &self.interrupt_routes {
            r.disable(&self.vm_fd)?;
        }

        Ok(())
    }

    fn set_kvm_routes(&self) -> Result<()> {
        let mut entry_vec: Vec<kvm_irq_routing_entry> = Vec::new();
        for (_, entry) in self.gsi_msi_routes.lock().unwrap().iter() {
            entry_vec.push(*entry);
        }

        let mut irq_routing =
            vec_with_array_field::<kvm_irq_routing, kvm_irq_routing_entry>(entry_vec.len());
        irq_routing[0].nr = entry_vec.len() as u32;
        irq_routing[0].flags = 0;

        unsafe {
            let entries: &mut [kvm_irq_routing_entry] =
                irq_routing[0].entries.as_mut_slice(entry_vec.len());
            entries.copy_from_slice(&entry_vec);
        }

        self.vm_fd
            .set_gsi_routing(&irq_routing[0])
            .map_err(VfioPciError::SetGsiRouting)
    }

    fn parse_msix_capabilities(&mut self, cap: u8) {
        let msg_ctl = self
            .vfio_pci_configuration
            .read_config_word((cap + 2).into());

        let table = self
            .vfio_pci_configuration
            .read_config_dword((cap + 4).into());

        let pba = self
            .vfio_pci_configuration
            .read_config_dword((cap + 8).into());

        let msix_cap = MsixCap {
            msg_ctl,
            table,
            pba,
        };
        let msix_config = MsixConfig::new(msix_cap.table_size());

        self.interrupt.msix = Some(VfioMsix {
            bar: msix_config,
            cap: msix_cap,
            cap_offset: cap.into(),
        });
    }

    fn parse_msi_capabilities(&mut self, cap: u8) {
        let msg_ctl = self
            .vfio_pci_configuration
            .read_config_word((cap + 2).into());

        self.interrupt.msi = Some(VfioMsi {
            cap: MsiCap {
                msg_ctl,
                ..Default::default()
            },
            cap_offset: cap.into(),
        });
    }

    fn parse_capabilities(&mut self) {
        let mut cap_next = self
            .vfio_pci_configuration
            .read_config_byte(PCI_CONFIG_CAPABILITY_OFFSET);

        while cap_next != 0 {
            let cap_id = self
                .vfio_pci_configuration
                .read_config_byte(cap_next.into());

            match PciCapabilityID::from(cap_id) {
                PciCapabilityID::MessageSignalledInterrupts => {
                    self.parse_msi_capabilities(cap_next);
                }
                PciCapabilityID::MSIX => {
                    self.parse_msix_capabilities(cap_next);
                }
                _ => {}
            };

            cap_next = self
                .vfio_pci_configuration
                .read_config_byte((cap_next + 1).into());
        }
    }

    fn update_msi_interrupt_routes(&self, msi: &VfioMsi) -> Result<()> {
        if msi.cap.enabled() {
            let mut gsi_msi_routes = self.gsi_msi_routes.lock().unwrap();

            for (idx, route) in self.interrupt_routes.iter().enumerate() {
                // Ignore MSI vector if the amount of vectors supported by the
                // guest OS does not match the expected amount. This is related
                // to "Multiple Message Capable" and "Multiple Message Enable"
                // fields from the "Message Control" register.
                if idx >= msi.cap.num_enabled_vectors() {
                    continue;
                }

                // Ignore MSI vector if masked.
                if msi.cap.vector_masked(idx) {
                    continue;
                }

                let mut entry = kvm_irq_routing_entry {
                    gsi: route.gsi,
                    type_: KVM_IRQ_ROUTING_MSI,
                    ..Default::default()
                };

                entry.u.msi.address_lo = msi.cap.msg_addr_lo;
                entry.u.msi.address_hi = msi.cap.msg_addr_hi;
                entry.u.msi.data = u32::from(msi.cap.msg_data) | (idx as u32);

                gsi_msi_routes.insert(route.gsi, entry);
            }
        } else {
            let mut gsi_msi_routes = self.gsi_msi_routes.lock().unwrap();

            for route in self.interrupt_routes.iter() {
                gsi_msi_routes.remove(&route.gsi);
            }
        }

        self.set_kvm_routes()
    }

    fn update_msix_interrupt_routes(&self, msix: &VfioMsix) -> Result<()> {
        if msix.cap.enabled() && !msix.cap.masked() {
            let mut gsi_msi_routes = self.gsi_msi_routes.lock().unwrap();

            for (idx, table_entry) in msix.bar.table_entries.iter().enumerate() {
                // Ignore MSI-X vector if masked.
                if table_entry.masked() {
                    continue;
                }

                let gsi = self.interrupt_routes[idx].gsi;

                let mut entry = kvm_irq_routing_entry {
                    gsi,
                    type_: KVM_IRQ_ROUTING_MSI,
                    ..Default::default()
                };

                entry.u.msi.address_lo = table_entry.msg_addr_lo;
                entry.u.msi.address_hi = table_entry.msg_addr_hi;
                entry.u.msi.data = table_entry.msg_data;

                gsi_msi_routes.insert(gsi, entry);
            }
        } else {
            let mut gsi_msi_routes = self.gsi_msi_routes.lock().unwrap();

            for route in self.interrupt_routes.iter() {
                gsi_msi_routes.remove(&route.gsi);
            }
        }

        self.set_kvm_routes()
    }

    fn read_msix_table(&mut self, offset: u64, data: &mut [u8]) {
        self.interrupt.msix_read_table(offset, data);
    }

    fn write_msix_table(&mut self, offset: u64, data: &[u8]) {
        self.interrupt.msix_write_table(offset, data);

        if let Some(msix) = &self.interrupt.msix {
            if let Err(e) = self.update_msix_interrupt_routes(&msix) {
                error!("Could not update MSI-X interrupt routes: {}", e);
            }
        }
    }

    fn update_msi_capabilities(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        match self.interrupt.update_msi(offset, data) {
            Some(InterruptUpdateAction::EnableMsi) => match self.enable_irq_fds() {
                Ok(fds) => {
                    if let Err(e) = self.device.enable_msi(fds) {
                        warn!("Could not enable MSI: {}", e);
                    }
                }
                Err(e) => warn!("Could not get IRQ fds: {}", e),
            },
            Some(InterruptUpdateAction::DisableMsi) => {
                if let Err(e) = self.device.disable_msi() {
                    warn!("Could not disable MSI: {}", e);
                }
                if let Err(e) = self.disable_irq_fds() {
                    warn!("Could not disable MSI: {}", e);
                }
            }
            _ => {}
        }

        // Update the gsi_msi_routes table now that the MSI cache has been
        // updated. The point is to always update the table based on latest
        // changes to the cache, and based on the state of masking flags, the
        // KVM GSI routes should be configured.
        if let Some(msi) = &self.interrupt.msi {
            return self.update_msi_interrupt_routes(&msi);
        }

        // If the code reach this point, something went wrong.
        Err(VfioPciError::MsiNotConfigured)
    }

    fn update_msix_capabilities(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        match self.interrupt.update_msix(offset, data) {
            Some(InterruptUpdateAction::EnableMsix) => match self.enable_irq_fds() {
                Ok(fds) => {
                    if let Err(e) = self.device.enable_msix(fds) {
                        warn!("Could not enable MSI-X: {}", e);
                    }
                }
                Err(e) => warn!("Could not get IRQ fds: {}", e),
            },
            Some(InterruptUpdateAction::DisableMsix) => {
                if let Err(e) = self.device.disable_msix() {
                    warn!("Could not disable MSI-X: {}", e);
                }
                if let Err(e) = self.disable_irq_fds() {
                    warn!("Could not disable MSI: {}", e);
                }
            }
            _ => {}
        }

        // Update the gsi_msi_routes table because the state of the enable bit
        // changed.
        if let Some(msix) = &self.interrupt.msix {
            return self.update_msix_interrupt_routes(&msix);
        }

        // If the code reach this point, something went wrong.
        Err(VfioPciError::MsixNotConfigured)
    }

    fn find_region(&self, addr: u64) -> Option<MmioRegion> {
        for region in self.mmio_regions.iter() {
            if addr >= region.start.raw_value()
                && addr < region.start.unchecked_add(region.length).raw_value()
            {
                return Some(*region);
            }
        }
        None
    }

    /// Map MMIO regions into the guest, and avoid VM exits when the guest tries
    /// to reach those regions.
    ///
    /// # Arguments
    ///
    /// * `vm` - The KVM VM file descriptor. It is used to set the VFIO MMIO regions
    ///          as KVM user memory regions.
    /// * `mem_slot` - The KVM memory slot to set the user memopry regions.
    /// # Return value
    ///
    /// This function returns the updated KVM memory slot id.
    pub fn map_mmio_regions(&mut self, vm: &Arc<VmFd>, mem_slot: u32) -> Result<u32> {
        let fd = self.device.as_raw_fd();
        let mut new_mem_slot = mem_slot;

        for region in self.mmio_regions.iter_mut() {
            // We want to skip the mapping of the BAR containing the MSI-X
            // table even if it is mappable. The reason is we need to trap
            // any access to the MSI-X table and update the GSI routing
            // accordingly.
            if let Some(msix) = &self.interrupt.msix {
                if region.index == msix.cap.table_bir() || region.index == msix.cap.pba_bir() {
                    continue;
                }
            }

            let region_flags = self.device.get_region_flags(region.index);
            if region_flags & VFIO_REGION_INFO_FLAG_MMAP != 0 {
                let mut prot = 0;
                if region_flags & VFIO_REGION_INFO_FLAG_READ != 0 {
                    prot |= libc::PROT_READ;
                }
                if region_flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
                    prot |= libc::PROT_WRITE;
                }
                let (mmap_offset, mmap_size) = self.device.get_region_mmap(region.index);
                let offset = self.device.get_region_offset(region.index) + mmap_offset;

                let host_addr = unsafe {
                    libc::mmap(
                        null_mut(),
                        mmap_size as usize,
                        prot,
                        libc::MAP_SHARED,
                        fd,
                        offset as libc::off_t,
                    )
                };

                if host_addr == libc::MAP_FAILED {
                    error!(
                        "Could not mmap regions, error:{}",
                        io::Error::last_os_error()
                    );
                    continue;
                }

                let mem_region = kvm_userspace_memory_region {
                    slot: new_mem_slot as u32,
                    guest_phys_addr: region.start.raw_value() + mmap_offset,
                    memory_size: mmap_size as u64,
                    userspace_addr: host_addr as u64,
                    flags: 0,
                };

                // Safe because the guest regions are guaranteed not to overlap.
                unsafe {
                    vm.set_user_memory_region(mem_region)
                        .map_err(VfioPciError::MapRegionGuest)?;
                }

                // Update the region with memory mapped info.
                region.mem_slot = Some(new_mem_slot);
                region.host_addr = Some(host_addr as u64);
                region.mmap_size = Some(mmap_size as usize);

                new_mem_slot += 1;
            }
        }

        Ok(new_mem_slot)
    }

    pub fn unmap_mmio_regions(&mut self) {
        for region in self.mmio_regions.iter() {
            if let (Some(addr), Some(size)) = (region.host_addr, region.mmap_size) {
                let ret = unsafe { libc::munmap(addr as *mut libc::c_void, size) };
                if ret != 0 {
                    error!(
                        "Could not unmap regions, error:{}",
                        io::Error::last_os_error()
                    );
                }
            }
        }
    }
}

impl Drop for VfioPciDevice {
    fn drop(&mut self) {
        self.unmap_mmio_regions();

        if let Some(msix) = &self.interrupt.msix {
            if msix.cap.enabled() && self.device.disable_msix().is_err() {
                error!("Could not disable MSI-X");
            }
        }

        if let Some(msi) = &self.interrupt.msi {
            if msi.cap.enabled() && self.device.disable_msi().is_err() {
                error!("Could not disable MSI");
            }
        }

        if self.device.unset_dma_map().is_err() {
            error!("failed to remove all guest memory regions from iommu table");
        }
    }
}

impl BusDevice for VfioPciDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) {
        self.write_bar(base, offset, data)
    }
}

// First BAR offset in the PCI config space.
const PCI_CONFIG_BAR_OFFSET: u32 = 0x10;
// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// IO BAR when first BAR bit is 1.
const PCI_CONFIG_IO_BAR: u32 = 0x1;
// Memory BAR flags (lower 4 bits).
const PCI_CONFIG_MEMORY_BAR_FLAG_MASK: u32 = 0xf;
// 64-bit memory bar flag.
const PCI_CONFIG_MEMORY_BAR_64BIT: u32 = 0x4;
// PCI config register size (4 bytes).
const PCI_CONFIG_REGISTER_SIZE: usize = 4;
// Number of BARs for a PCI device
const BAR_NUMS: usize = 6;
// PCI Header Type register index
const PCI_HEADER_TYPE_REG_INDEX: usize = 3;
// First BAR register index
const PCI_CONFIG_BAR0_INDEX: usize = 4;
// PCI ROM expansion BAR register index
const PCI_ROM_EXP_BAR_INDEX: usize = 12;
// PCI interrupt pin and line register index
const PCI_INTX_REG_INDEX: usize = 15;

impl PciDevice for VfioPciDevice {
    fn allocate_bars(
        &mut self,
        allocator: &mut SystemAllocator,
    ) -> std::result::Result<Vec<(GuestAddress, GuestUsize, PciBarRegionType)>, PciDeviceError>
    {
        let mut ranges = Vec::new();
        let mut bar_id = VFIO_PCI_BAR0_REGION_INDEX as u32;

        // Going through all regular regions to compute the BAR size.
        // We're not saving the BAR address to restore it, because we
        // are going to allocate a guest address for each BAR and write
        // that new address back.
        while bar_id < VFIO_PCI_CONFIG_REGION_INDEX {
            let mut lsb_size: u32 = 0xffff_ffff;
            let mut msb_size = 0;
            let mut region_size: u64;
            let bar_addr: GuestAddress;

            // Read the BAR size (Starts by all 1s to the BAR)
            let bar_offset = if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                (PCI_ROM_EXP_BAR_INDEX * 4) as u32
            } else {
                PCI_CONFIG_BAR_OFFSET + bar_id * 4
            };

            self.vfio_pci_configuration
                .write_config_dword(lsb_size, bar_offset);
            lsb_size = self.vfio_pci_configuration.read_config_dword(bar_offset);

            // We've just read the BAR size back. Or at least its LSB.
            let lsb_flag = lsb_size & PCI_CONFIG_MEMORY_BAR_FLAG_MASK;

            if lsb_size == 0 {
                bar_id += 1;
                continue;
            }

            // Is this an IO BAR?
            let io_bar = if bar_id != VFIO_PCI_ROM_REGION_INDEX {
                match lsb_flag & PCI_CONFIG_IO_BAR {
                    PCI_CONFIG_IO_BAR => true,
                    _ => false,
                }
            } else {
                false
            };

            // Is this a 64-bit BAR?
            let is_64bit_bar = if bar_id != VFIO_PCI_ROM_REGION_INDEX {
                match lsb_flag & PCI_CONFIG_MEMORY_BAR_64BIT {
                    PCI_CONFIG_MEMORY_BAR_64BIT => true,
                    _ => false,
                }
            } else {
                false
            };

            // By default, the region type is 32 bits memory BAR.
            let mut region_type = PciBarRegionType::Memory32BitRegion;

            if io_bar {
                // IO BAR
                region_type = PciBarRegionType::IORegion;

                // Clear first bit.
                lsb_size &= 0xffff_fffc;

                // Find the first bit that's set to 1.
                let first_bit = lsb_size.trailing_zeros();
                region_size = 2u64.pow(first_bit);
                // We need to allocate a guest PIO address range for that BAR.
                // The address needs to be 4 bytes aligned.
                bar_addr = allocator
                    .allocate_io_addresses(None, region_size, Some(0x4))
                    .ok_or_else(|| PciDeviceError::IoAllocationFailed(region_size))?;
            } else {
                if is_64bit_bar {
                    // 64 bits Memory BAR
                    region_type = PciBarRegionType::Memory64BitRegion;

                    msb_size = 0xffff_ffff;
                    let msb_bar_offset: u32 = PCI_CONFIG_BAR_OFFSET + (bar_id + 1) * 4;

                    self.vfio_pci_configuration
                        .write_config_dword(msb_bar_offset, msb_size);

                    msb_size = self
                        .vfio_pci_configuration
                        .read_config_dword(msb_bar_offset);
                }

                // Clear the first four bytes from our LSB.
                lsb_size &= 0xffff_fff0;

                region_size = u64::from(msb_size);
                region_size <<= 32;
                region_size |= u64::from(lsb_size);

                // Find the first that's set to 1.
                let first_bit = region_size.trailing_zeros();
                region_size = 2u64.pow(first_bit);

                // We need to allocate a guest MMIO address range for that BAR.
                // In case the BAR is mappable directly, this means it might be
                // set as KVM user memory region, which expects to deal with 4K
                // pages. Therefore, the aligment has to be set accordingly.
                let bar_alignment = if (bar_id == VFIO_PCI_ROM_REGION_INDEX)
                    || (self.device.get_region_flags(bar_id) & VFIO_REGION_INFO_FLAG_MMAP != 0)
                {
                    // 4K alignment
                    0x1000
                } else {
                    // Default 16 bytes alignment
                    0x10
                };
                if is_64bit_bar {
                    bar_addr = allocator
                        .allocate_mmio_addresses(None, region_size, Some(bar_alignment))
                        .ok_or_else(|| PciDeviceError::IoAllocationFailed(region_size))?;
                } else {
                    bar_addr = allocator
                        .allocate_mmio_hole_addresses(None, region_size, Some(bar_alignment))
                        .ok_or_else(|| PciDeviceError::IoAllocationFailed(region_size))?;
                }
            }

            let reg_idx = if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                PCI_ROM_EXP_BAR_INDEX
            } else {
                bar_id as usize
            };

            // We can now build our BAR configuration block.
            let config = PciBarConfiguration::default()
                .set_register_index(reg_idx)
                .set_address(bar_addr.raw_value())
                .set_size(region_size)
                .set_region_type(region_type);

            if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                self.configuration
                    .add_pci_rom_bar(&config, lsb_flag & 0x1)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            } else {
                self.configuration
                    .add_pci_bar(&config)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            }

            ranges.push((bar_addr, region_size, region_type));
            self.mmio_regions.push(MmioRegion {
                start: bar_addr,
                length: region_size,
                index: bar_id as u32,
                mem_slot: None,
                host_addr: None,
                mmap_size: None,
            });

            bar_id += 1;
            if is_64bit_bar {
                bar_id += 1;
            }
        }

        if self.device.setup_dma_map().is_err() {
            error!("failed to add all guest memory regions into iommu table");
        }

        Ok(ranges)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        // When the guest wants to write to a BAR, we trap it into
        // our local configuration space. We're not reprogramming
        // VFIO device.
        if (reg_idx >= PCI_CONFIG_BAR0_INDEX && reg_idx < PCI_CONFIG_BAR0_INDEX + BAR_NUMS)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            // We keep our local cache updated with the BARs.
            // We'll read it back from there when the guest is asking
            // for BARs (see read_config_register()).
            return self
                .configuration
                .write_config_register(reg_idx, offset, data);
        }

        let reg = (reg_idx * PCI_CONFIG_REGISTER_SIZE) as u64;

        // If the MSI or MSI-X capabilities are accessed, we need to
        // update our local cache accordingly.
        // Depending on how the capabilities are modified, this could
        // trigger a VFIO MSI or MSI-X toggle.
        if let Some((cap_id, cap_base)) = self.interrupt.accessed(reg) {
            let cap_offset: u64 = reg - cap_base + offset;
            match cap_id {
                PciCapabilityID::MessageSignalledInterrupts => {
                    if let Err(e) = self.update_msi_capabilities(cap_offset, data) {
                        error!("Could not update MSI capabilities: {}", e);
                    }
                }
                PciCapabilityID::MSIX => {
                    if let Err(e) = self.update_msix_capabilities(cap_offset, data) {
                        error!("Could not update MSI-X capabilities: {}", e);
                    }
                }
                _ => {}
            }
        }

        // Make sure to write to the device's PCI config space after MSI/MSI-X
        // interrupts have been enabled/disabled. In case of MSI, when the
        // interrupts are enabled through VFIO (using VFIO_DEVICE_SET_IRQS),
        // the MSI Enable bit in the MSI capability structure found in the PCI
        // config space is disabled by default. That's why when the guest is
        // enabling this bit, we first need to enable the MSI interrupts with
        // VFIO through VFIO_DEVICE_SET_IRQS ioctl, and only after we can write
        // to the device region to update the MSI Enable bit.
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, reg + offset);
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        // When reading the BARs, we trap it and return what comes
        // from our local configuration space. We want the guest to
        // use that and not the VFIO device BARs as it does not map
        // with the guest address space.
        if (reg_idx >= PCI_CONFIG_BAR0_INDEX && reg_idx < PCI_CONFIG_BAR0_INDEX + BAR_NUMS)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            return self.configuration.read_reg(reg_idx);
        }

        // Since we don't support INTx (only MSI and MSI-X), we should not
        // expose an invalid Interrupt Pin to the guest. By using a specific
        // mask in case the register being read correspond to the interrupt
        // register, this code makes sure to always expose an Interrupt Pin
        // value of 0, which stands for no interrupt pin support.
        //
        // Since we don't support passing multi-functions devices, we should
        // mask the multi-function bit, bit 7 of the Header Type byte on the
        // register 3.
        let mask = if reg_idx == PCI_INTX_REG_INDEX {
            0xffff_00ff
        } else if reg_idx == PCI_HEADER_TYPE_REG_INDEX {
            0xff7f_ffff
        } else {
            0xffff_ffff
        };

        // The config register read comes from the VFIO device itself.
        self.vfio_pci_configuration
            .read_config_dword((reg_idx * 4) as u32)
            & mask
    }

    fn detect_bar_reprogramming(
        &mut self,
        reg_idx: usize,
        data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        self.configuration.detect_bar_reprogramming(reg_idx, data)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.read_msix_table(offset, data);
            } else {
                self.device.region_read(region.index, data, offset);
            }
        }
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            // If the MSI-X table is written to, we need to update our cache.
            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.write_msix_table(offset, data);
            } else {
                self.device.region_write(region.index, data, offset);
            }
        }
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> result::Result<(), io::Error> {
        for region in self.mmio_regions.iter_mut() {
            if region.start.raw_value() == old_base {
                region.start = GuestAddress(new_base);

                if let Some(mem_slot) = region.mem_slot {
                    if let Some(host_addr) = region.host_addr {
                        let (mmap_offset, mmap_size) = self.device.get_region_mmap(region.index);

                        // Remove old region from KVM
                        let old_mem_region = kvm_userspace_memory_region {
                            slot: mem_slot,
                            guest_phys_addr: old_base + mmap_offset,
                            memory_size: 0,
                            userspace_addr: host_addr,
                            flags: 0,
                        };
                        // Safe because the guest regions are guaranteed not to overlap.
                        unsafe {
                            self.vm_fd
                                .set_user_memory_region(old_mem_region)
                                .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;
                        }

                        // Insert new region to KVM
                        let new_mem_region = kvm_userspace_memory_region {
                            slot: mem_slot,
                            guest_phys_addr: new_base + mmap_offset,
                            memory_size: mmap_size as u64,
                            userspace_addr: host_addr,
                            flags: 0,
                        };
                        // Safe because the guest regions are guaranteed not to overlap.
                        unsafe {
                            self.vm_fd
                                .set_user_memory_region(new_mem_region)
                                .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

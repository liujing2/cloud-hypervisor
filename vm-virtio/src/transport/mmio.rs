// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use byteorder::{ByteOrder, LittleEndian};
use libc::EFD_NONBLOCK;

use crate::{
    Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, DEVICE_ACKNOWLEDGE, DEVICE_DRIVER,
    DEVICE_DRIVER_OK, DEVICE_FAILED, DEVICE_FEATURES_OK, DEVICE_INIT,
    INTERRUPT_STATUS_CONFIG_CHANGED, INTERRUPT_STATUS_USED_RING,
};
// VIS
use crate::transport::{VisTableEntry, VisTable, VisMbaRegister, VisPbaRegister};

use devices::{BusDevice, Interrupt};
use vm_memory::{Address, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::{errno::Result, eventfd::EventFd};

const VENDOR_ID: u32 = 0;

const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
const MMIO_VERSION: u32 = 2;

/* vis interrupt parameter */
pub struct VisInterruptParameters<'a> {
    pub vis: Option<&'a VisTableEntry>,
}

pub type VisInterruptDelivery =
    Box<dyn Fn(VisInterruptParameters) -> std::result::Result<(), std::io::Error> + Send + Sync>;


/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOTIFY_REG_OFFSET` offset from the MMIO
/// base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
/// is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioDevice {
    device: Box<dyn VirtioDevice>,
    device_activated: bool,

    features_select: u32,
    acked_features_select: u32,
    queue_select: u32,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    driver_status: u32,
    config_generation: u32,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    mem: Option<Arc<RwLock<GuestMemoryMmap>>>,

    vector_count: u16,
    // VET offset from mmio base
    vet_off: Option<GuestAddress>,
    // MBA offset from mmio base
    mba_off: Option<GuestAddress>,
    // PBA offset from mmio base
    pba_off: Option<GuestAddress>,

    // Being set after libc::mmap.
    // We must keep a mut pointer instead of value,
    // because value move will change the process virtual address,
    // and the pointer should be thread Sendable.
    vet_addr: Arc<AtomicPtr<VisTable>>,
    mba_addr: Arc<AtomicPtr<VisMbaRegister>>,
    pba_addr: Arc<AtomicPtr<VisPbaRegister>>,

    // Need when mask bits change
    interrupt_cb_unmask: Option<Arc<VisInterruptDelivery>>,
}

impl MmioDevice {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(
        mem: Arc<RwLock<GuestMemoryMmap>>,
        device: Box<dyn VirtioDevice>,
        vis_num: u16,
    ) -> Result<MmioDevice> {
        let mut queue_evts = Vec::new();

        for _ in device.queue_max_sizes().iter() {
            queue_evts.push(EventFd::new(EFD_NONBLOCK)?)
        }
        let queues = device
            .queue_max_sizes()
            .iter()
            .map(|&s| Queue::new(s))
            .collect();

        Ok(MmioDevice {
            device,
            device_activated: false,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_cb: None,
            driver_status: DEVICE_INIT,
            config_generation: 0,
            queues,
            queue_evts,
            mem: Some(mem),
            vector_count: vis_num,
            vet_off: None,
            mba_off: None,
            pba_off: None,
            vet_addr: Arc::new(AtomicPtr::new(null_mut())),
            mba_addr: Arc::new(AtomicPtr::new(null_mut())),
            pba_addr: Arc::new(AtomicPtr::new(null_mut())),
            interrupt_cb_unmask: None,
        })
    }

    pub fn set_vis_addr(
        &mut self,
        vet: AtomicPtr<VisTable>,
        mba: AtomicPtr<VisMbaRegister>,
        pba: AtomicPtr<VisPbaRegister>,
    ) {
        self.vet_addr = Arc::new(vet);
        self.mba_addr = Arc::new(mba);
        self.pba_addr = Arc::new(pba);
    }

    pub fn set_vis_guest_offset(
        &mut self,
        vet: Option<GuestAddress>,
        mba: Option<GuestAddress>,
        pba: Option<GuestAddress>
    ) {
        self.vet_off = vet;
        self.mba_off = mba;
        self.pba_off = pba;
    }

    /// Gets the list of queue events that must be triggered whenever the VM writes to
    /// `virtio::NOTIFY_REG_OFFSET` past the MMIO base. Each event must be triggered when the
    /// value being written equals the index of the event in this list.
    pub fn queue_evts(&self) -> &[EventFd] {
        self.queue_evts.as_slice()
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits = DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK;
        self.driver_status == ready_bits && self.driver_status & DEVICE_FAILED == 0
    }

    fn are_queues_valid(&self) -> bool {
        if let Some(mem) = self.mem.as_ref() {
            self.queues.iter().all(|q| q.is_valid(&mem.read().unwrap()))
        } else {
            false
        }
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        match self.queues.get(self.queue_select as usize) {
            Some(queue) => f(queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        if let Some(queue) = self.queues.get_mut(self.queue_select as usize) {
            f(queue);
            true
        } else {
            false
        }
    }

    pub fn assign_interrupt(&mut self, interrupt: Box<dyn Interrupt>) {
        let interrupt_status = self.interrupt_status.clone();
        let cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, _queue: Option<&Queue>| {
                let status = match int_type {
                    VirtioInterruptType::Config => INTERRUPT_STATUS_CONFIG_CHANGED,
                    VirtioInterruptType::Queue => INTERRUPT_STATUS_USED_RING,
                };
                interrupt_status.fetch_or(status as usize, Ordering::SeqCst);

                interrupt.deliver()
            },
        ) as VirtioInterrupt);

        self.interrupt_cb = Some(cb);
    }

    #[warn(unused_variables)]
    pub fn assign_vis(&mut self, vis_cb: Arc<VisInterruptDelivery>) {
            self.interrupt_cb_unmask = Some(vis_cb.clone());

            let vet_addr = self.vet_addr.clone();
            let mba_addr = self.mba_addr.clone();
            let pba_addr = self.pba_addr.clone();

            let cb = Arc::new(Box::new(
                move |int_type: &VirtioInterruptType, queue: Option<&Queue>| {
                    let vector = match int_type {
                        VirtioInterruptType::Config => {
                            0
                        }
                        VirtioInterruptType::Queue => {
                            if let Some(q) = queue {
                                q.vector
                            } else {
                                0
                            }
                        }
                    };

                let addr = vet_addr.load(Ordering::Relaxed);
                let entries = unsafe { (*addr).table_entries.clone() };
                let entry = &( entries[vector as usize] );

                    // The Pending Bit Array table is updated to reflect there
                    // is a pending interrupt for this specific vector.
                    unsafe {
                        let pba_addr = pba_addr.load(Ordering::Relaxed);
                        let mba_addr = mba_addr.load(Ordering::Relaxed);
                        if (*mba_addr).masked(vector) {
                            (*pba_addr).set_pba_bit(vector, false);
                            return Ok(());
                        }
                    } //unsafe

                    (vis_cb)(VisInterruptParameters { vis: Some(entry) })
                },
            ) as VirtioInterrupt);

            self.interrupt_cb = Some(cb);
    }

    // Use scenario: Guest unmask a vector
    // Move out from PbaRegister because we want to keep it simple for memory sharing.
    pub fn inject_vis_and_clear_pba(&mut self, vector: u16) {
        unsafe {
        if let Some(cb) = &self.interrupt_cb_unmask {
            let vet_addr = self.vet_addr.clone();
            let vet_addr = vet_addr.load(Ordering::Relaxed);
            let vis = (*vet_addr).get_vis_table_entry(vector);

            match (cb)(VisInterruptParameters {
                vis: Some(&vis),
            }) {
                Ok(_) => debug!("VIS injected on vector control flip"),
                Err(e) => error!("failed to inject VIS: {}", e),
            };
        }

        // Clear the bit from PBA
        let pba_addr = self.pba_addr.clone();
        let pba_addr = pba_addr.load(Ordering::Relaxed);
        (*pba_addr).set_pba_bit(vector as u16, true);
        } // unsafe
    }
}

impl BusDevice for MmioDevice {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.device.device_type(),
                    0x0c => VENDOR_ID, // vendor id
                    0x10 => {
                        self.device.features(self.features_select)
                            | if self.features_select == 1 { 0x1 } else { 0x0 }
                    }
                    0x34 => self.with_queue(0, |q| u32::from(q.get_max_size())),
                    0x44 => self.with_queue(0, |q| q.ready as u32),
                    0x60 => self.interrupt_status.load(Ordering::SeqCst) as u32,
                    0x70 => self.driver_status,
                    // VIS queue vector
                    0xa8 => self.with_queue(0, |q| q.vector as u32),
                    // VIS
                    0xb0 => self.vector_count as u32,
                    0xb4 => self.vet_off.unwrap().raw_value() as u32,
                    0xc0 => self.mba_off.unwrap().raw_value() as u32,
                    0xc4 => self.pba_off.unwrap().raw_value() as u32,
                    0xfc => self.config_generation,
                    _ => {
                        warn!("unknown virtio mmio register read: 0x{:x}", offset);
                        return;
                    }
                };
                LittleEndian::write_u32(data, v);
            }
            0x100..=0xfff => self.device.read_config(offset - 0x100, data),
            0x1000..=0x1fff => {
                unsafe {
                // VET table
                let vet_addr = self.vet_addr.clone();
                let vet_addr = vet_addr.load(Ordering::Relaxed);
                (*vet_addr).read_table(offset - 0x1000, data);
                } // unsafe
            }
            0x2000..=0x2fff => {
                unsafe {
                // MBA table
                let mba_addr = self.mba_addr.clone();
                let mba_addr = mba_addr.load(Ordering::Relaxed);
                (*mba_addr).read_mba(offset - 0x2000, data);
                } // unsafe
            }
            0x3000..=0x3fff => {
                unsafe {
                // PBA table
                let pba_addr = self.pba_addr.clone();
                let pba_addr = pba_addr.load(Ordering::Relaxed);
                (*pba_addr).read_pba(offset - 0x3000, data);
                } // unsafe
            }
            _ => {
                warn!(
                    "invalid virtio mmio read: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        };
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) {
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        let mut mut_q = false;
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = LittleEndian::read_u32(data);
                match offset {
                    0x14 => self.features_select = v,
                    0x20 => self.device.ack_features(self.acked_features_select, v),
                    0x24 => self.acked_features_select = v,
                    0x30 => self.queue_select = v,
                    0x38 => mut_q = self.with_queue_mut(|q| q.size = v as u16),
                    0x44 => mut_q = self.with_queue_mut(|q| q.ready = v == 1),
                    0x64 => {
                        self.interrupt_status
                            .fetch_and(!(v as usize), Ordering::SeqCst);
                    }
                    0x70 => self.driver_status = v,
                    0x80 => mut_q = self.with_queue_mut(|q| lo(&mut q.desc_table, v)),
                    0x84 => mut_q = self.with_queue_mut(|q| hi(&mut q.desc_table, v)),
                    0x90 => mut_q = self.with_queue_mut(|q| lo(&mut q.avail_ring, v)),
                    0x94 => mut_q = self.with_queue_mut(|q| hi(&mut q.avail_ring, v)),
                    0xa0 => mut_q = self.with_queue_mut(|q| lo(&mut q.used_ring, v)),
                    0xa4 => mut_q = self.with_queue_mut(|q| hi(&mut q.used_ring, v)),
                    // VIS queue vector
                    0xa8 => mut_q = self.with_queue_mut(|q| q.vector = LittleEndian::read_u16(data)),
                    _ => {
                        warn!("unknown virtio mmio register write: 0x{:x}", offset);
                        return;
                    }
                }
            }
            0x100..=0xfff => return self.device.write_config(offset - 0x100, data),
            0x1000..=0x1fff => {
                unsafe {
                // VET table
                let vet_addr = self.vet_addr.clone();
                let vet_addr = vet_addr.load(Ordering::Relaxed);
                (*vet_addr).write_table(offset - 0x1000, data);
                } // unsafe
            }
            0x2000..=0x2fff => {
                unsafe {
                // MBA table
                let mba_addr = self.mba_addr.clone();
                let mba_addr = mba_addr.load(Ordering::Relaxed);
                let (need_irq, vector) = (*mba_addr).write_mba(offset - 0x2000, data, self.pba_addr.clone().load(Ordering::Relaxed));
                if need_irq {
                   // inject and clear pba 
                   self.inject_vis_and_clear_pba(vector);
                }
                } // unsafe
            }
            0x3000..=0x3fff => {
                unsafe {
                // PBA table
                let pba_addr = self.pba_addr.clone();
                let pba_addr = pba_addr.load(Ordering::Relaxed);
                (*pba_addr).write_pba(offset - 0x3000, data);
                } // unsafe
            }
            _ => {
                warn!(
                    "invalid virtio mmio write: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
                return;
            }
        }

        if self.device_activated && mut_q {
            warn!("virtio queue was changed after device was activated");
        }

        if !self.device_activated && self.is_driver_ready() && self.are_queues_valid() {
            if let Some(interrupt_cb) = self.interrupt_cb.take() {
                if self.mem.is_some() {
                    let mem = self.mem.as_ref().unwrap().clone();
                    self.device
                        .activate(
                            mem,
                            interrupt_cb,
                            self.queues.clone(),
                            self.queue_evts.split_off(0),
                        )
                        .expect("Failed to activate device");
                    self.device_activated = true;
                }
            }
        }
    }
}

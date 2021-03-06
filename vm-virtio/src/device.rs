// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::*;
use std::sync::{Arc, RwLock};
use vm_memory::{GuestAddress, GuestMemoryMmap, GuestUsize};
use vmm_sys_util::eventfd::EventFd;

pub enum VirtioInterruptType {
    Config,
    Queue,
}

pub type VirtioInterrupt = Box<
    dyn Fn(&VirtioInterruptType, Option<&Queue>) -> std::result::Result<(), std::io::Error>
        + Send
        + Sync,
>;

pub type VirtioIommuRemapping =
    Box<dyn Fn(u64) -> std::result::Result<u64, std::io::Error> + Send + Sync>;

#[derive(Clone)]
pub struct VirtioSharedMemory {
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone)]
pub struct VirtioSharedMemoryList {
    pub addr: GuestAddress,
    pub len: GuestUsize,
    pub region_list: Vec<VirtioSharedMemory>,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send {
    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// The set of feature bits shifted by `page * 32`.
    fn features(&self, page: u32) -> u32 {
        let _ = page;
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, page: u32, value: u32);

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: Arc<RwLock<GuestMemoryMmap>>,
        interrupt_evt: Arc<VirtioInterrupt>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult;

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<(Arc<VirtioInterrupt>, Vec<EventFd>)> {
        None
    }

    /// Returns the list of shared memory regions required by the device.
    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        None
    }

    fn iommu_translate(&self, addr: u64) -> u64 {
        addr
    }
}

/// Trait providing address translation the same way a physical DMA remapping
/// table would provide translation between an IOVA and a physical address.
/// The goal of this trait is to be used by virtio devices to perform the
/// address translation before they try to read from the guest physical address.
/// On the other side, the implementation itself should be provided by the code
/// emulating the IOMMU for the guest.
pub trait DmaRemapping: Send + Sync {
    fn translate(&self, id: u32, addr: u64) -> std::result::Result<u64, std::io::Error>;
}

#[macro_export]
macro_rules! virtio_pausable_inner {
    () => {
        fn pause(&mut self) -> result::Result<(), MigratableError> {
            debug!(
                "Pausing virtio-{}",
                VirtioDeviceType::from(self.device_type())
            );
            self.paused.store(true, Ordering::SeqCst);
            if let Some(pause_evt) = &self.pause_evt {
                pause_evt
                    .write(1)
                    .map_err(|e| MigratableError::Pause(e.into()))?;
            }

            Ok(())
        }

        fn resume(&mut self) -> result::Result<(), MigratableError> {
            debug!(
                "Resuming virtio-{}",
                VirtioDeviceType::from(self.device_type())
            );
            self.paused.store(false, Ordering::SeqCst);
            if let Some(epoll_thread) = &self.epoll_thread {
                epoll_thread.thread().unpark();
            }

            Ok(())
        }
    }
}

#[macro_export]
macro_rules! virtio_pausable {
    ($name:ident) => {
        impl Pausable for $name {
            virtio_pausable_inner!();
        }
    };
}

// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
extern crate arch;
extern crate epoll;
extern crate kvm_ioctls;
extern crate legacy_device;
extern crate libc;
extern crate linux_loader;
extern crate net_util;
extern crate vm_memory;
extern crate vm_virtio;
extern crate vmm_sys_util;

use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::*;
use libc::{c_void, siginfo_t, EFD_NONBLOCK};
use linux_loader::cmdline;
use linux_loader::loader::KernelLoader;
use net_util::{MacAddr, Tap};
use pci::{PciConfigIo, PciDevice, PciRoot};
use qcow::{self, ImageType, QcowFile};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, stdout};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::{result, str, thread};
use vm_allocator::SystemAllocator;
use vm_device::device::{IoResource, IoType, IrqResource};
use vm_device::device_manager::DeviceManager;
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, GuestUsize,
    MmapError,
};
use vm_virtio::transport::VirtioPciDevice;
use vmm_sys_util::signal::register_signal_handler;
use vmm_sys_util::terminal::Terminal;
use vmm_sys_util::EventFd;

const VCPU_RTSIG_OFFSET: i32 = 0;
pub const DEFAULT_VCPUS: u8 = 1;
pub const DEFAULT_MEMORY: GuestUsize = 512;
const CMDLINE_OFFSET: GuestAddress = GuestAddress(0x20000);
const X86_64_IRQ_BASE: u32 = 5;

// CPUID feature bits
const ECX_HYPERVISOR_SHIFT: u32 = 31; // Hypervisor bit.

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot open the VM file descriptor.
    VmFd(io::Error),

    /// Cannot create the KVM instance
    VmCreate(io::Error),

    /// Cannot set the VM up
    VmSetup(io::Error),

    /// Cannot open the kernel image
    KernelFile(io::Error),

    /// Mmap backed guest memory error
    GuestMemory(MmapError),

    /// Cannot load the kernel in memory
    KernelLoad(linux_loader::loader::Error),

    /// Cannot load the command line in memory
    CmdLine,

    /// Cannot open the VCPU file descriptor.
    VcpuFd(io::Error),

    /// Cannot run the VCPUs.
    VcpuRun(io::Error),

    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),

    #[cfg(target_arch = "x86_64")]
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(arch::x86_64::interrupts::Error),

    #[cfg(target_arch = "x86_64")]
    /// Error configuring the MSR registers
    MSRSConfiguration(arch::x86_64::regs::Error),

    #[cfg(target_arch = "x86_64")]
    /// Error configuring the general purpose registers
    REGSConfiguration(arch::x86_64::regs::Error),

    #[cfg(target_arch = "x86_64")]
    /// Error configuring the special registers
    SREGSConfiguration(arch::x86_64::regs::Error),

    #[cfg(target_arch = "x86_64")]
    /// Error configuring the floating point related registers
    FPUConfiguration(arch::x86_64::regs::Error),

    /// The call to KVM_SET_CPUID2 failed.
    SetSupportedCpusFailed(io::Error),

    /// Cannot create devices.
    Devices(DeviceError),

    /// Cannot create EventFd.
    EventFd(io::Error),

    /// Cannot create epoll context.
    EpollError(io::Error),

    /// Write to the serial console failed.
    Serial(vmm_sys_util::Error),

    /// Cannot setup terminal in raw mode.
    SetTerminalRaw(vmm_sys_util::Error),

    /// Cannot setup terminal in canonical mode.
    SetTerminalCanon(vmm_sys_util::Error),

    /// Cannot configure the IRQ.
    Irq(io::Error),

    /// Cannot create the system allocator
    CreateSystemAllocator,

    /// Failed parsing network parameters
    ParseNetworkParameters,

    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,
}
pub type Result<T> = result::Result<T, Error>;

/// Errors associated with device manager
#[derive(Debug)]
pub enum DeviceError {
    /// Cannot create EventFd.
    EventFd(io::Error),

    /// Cannot open disk path
    Disk(io::Error),

    /// Cannot create virtio-blk device
    CreateVirtioBlock(io::Error),

    /// Cannot create virtio-net device
    CreateVirtioNet(vm_virtio::net::Error),

    /// Cannot create virtio-rng device
    CreateVirtioRng(io::Error),

    /// Failed parsing disk image format
    DetectImageType(qcow::Error),

    /// Cannot open qcow disk path
    QcowDeviceCreate(qcow::Error),

    /// Cannot open tap interface
    OpenTap(net_util::TapError),

    /// Cannot configure the IRQ.
    Irq(io::Error),

    /// Cannot register ioevent.
    RegisterIoevent(io::Error),

    /// Cannot create virtio device
    VirtioDevice(vmm_sys_util::Error),

    /// Cannot add PCI device
    AddPciDevice(pci::PciRootError),

    /// Cannot register device
    RegisterDevice(vm_device::DeviceManagerError),
}
pub type DeviceResult<T> = result::Result<T, DeviceError>;

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    fd: VcpuFd,
    id: u8,
    device_manager: Arc<Mutex<DeviceManager>>,
}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn new(id: u8, vm: &Vm, device_manager: Arc<Mutex<DeviceManager>>) -> Result<Self> {
        let kvm_vcpu = vm.fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            device_manager,
        })
    }

    /// Configures a x86_64 specific vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - Specifies necessary info used for the CPUID configuration.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn configure(&mut self, kernel_start_addr: GuestAddress, vm: &Vm) -> Result<()> {
        self.fd
            .set_cpuid2(&vm.cpuid)
            .map_err(Error::SetSupportedCpusFailed)?;

        arch::x86_64::regs::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
        // Safe to unwrap because this method is called after the VM is configured
        let vm_memory = vm.get_memory();
        arch::x86_64::regs::setup_regs(
            &self.fd,
            kernel_start_addr.raw_value(),
            arch::x86_64::layout::BOOT_STACK_POINTER.raw_value(),
            arch::x86_64::layout::ZERO_PAGE_START.raw_value(),
        )
        .map_err(Error::REGSConfiguration)?;
        arch::x86_64::regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
        arch::x86_64::regs::setup_sregs(vm_memory, &self.fd).map_err(Error::SREGSConfiguration)?;
        arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        Ok(())
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    // For now, only bypass the error case of DeviceManager handling.
    #[allow(unused)]
    pub fn run(&self) -> Result<()> {
        match self.fd.run() {
            Ok(run) => match run {
                VcpuExit::IoIn(addr, data) => {
                    self.device_manager
                        .lock()
                        .expect("failed to acquire lock")
                        .read(GuestAddress(u64::from(addr)), data, IoType::Pio);
                    Ok(())
                }
                VcpuExit::IoOut(addr, data) => {
                    self.device_manager
                        .lock()
                        .expect("failed to acquire lock")
                        .write(GuestAddress(u64::from(addr)), data, IoType::Pio);
                    Ok(())
                }
                VcpuExit::MmioRead(addr, data) => {
                    self.device_manager
                        .lock()
                        .expect("failed to acquire lock")
                        .read(GuestAddress(u64::from(addr)), data, IoType::Mmio);
                    Ok(())
                }
                VcpuExit::MmioWrite(addr, data) => {
                    self.device_manager
                        .lock()
                        .expect("failed to acquire lock")
                        .write(GuestAddress(u64::from(addr)), data, IoType::Mmio);
                    Ok(())
                }
                r => {
                    error!("Unexpected exit reason on vcpu run: {:?}", r);
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },

            Err(ref e) => match e.raw_os_error().unwrap() {
                libc::EAGAIN | libc::EINTR => Ok(()),
                _ => {
                    error!("VCPU {:?} error {:?}", self.id, e);
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },
        }
    }
}

pub struct VmConfig<'a> {
    kernel_path: &'a Path,
    disk_paths: Vec<PathBuf>,
    rng_path: Option<String>,
    cmdline: cmdline::Cmdline,
    cmdline_addr: GuestAddress,
    net_params: Option<String>,
    memory_size: GuestUsize,
    vcpu_count: u8,
}

impl<'a> VmConfig<'a> {
    pub fn new(
        kernel_path: &'a Path,
        disk_paths: Vec<PathBuf>,
        rng_path: Option<String>,
        cmdline_str: String,
        net_params: Option<String>,
        vcpus: u8,
        memory_size: GuestUsize,
    ) -> Result<Self> {
        let mut cmdline = cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline.insert_str(cmdline_str).unwrap();

        Ok(VmConfig {
            kernel_path,
            disk_paths,
            rng_path,
            cmdline,
            cmdline_addr: CMDLINE_OFFSET,
            net_params,
            memory_size,
            vcpu_count: vcpus,
        })
    }
}

#[derive(Debug)]
struct NetParams<'a> {
    tap_if_name: Option<&'a str>,
    ip_addr: Ipv4Addr,
    net_mask: Ipv4Addr,
    mac_addr: MacAddr,
}

fn parse_net_params(net_params: &str) -> Result<NetParams> {
    // Split the parameters based on the comma delimiter
    let params_list: Vec<&str> = net_params.split(',').collect();

    let mut tap: &str = "";
    let mut ip: &str = "";
    let mut mask: &str = "";
    let mut mac: &str = "";

    for param in params_list.iter() {
        if param.starts_with("tap=") {
            tap = &param[4..];
        } else if param.starts_with("ip=") {
            ip = &param[3..];
        } else if param.starts_with("mask=") {
            mask = &param[5..];
        } else if param.starts_with("mac=") {
            mac = &param[4..];
        }
    }

    let mut tap_if_name: Option<&str> = None;
    let mut ip_addr: Ipv4Addr = "192.168.249.1".parse().unwrap();
    let mut net_mask: Ipv4Addr = "255.255.255.0".parse().unwrap();
    let mut mac_addr: MacAddr = MacAddr::local_random();

    if !tap.is_empty() {
        tap_if_name = Some(tap);
    }
    if !ip.is_empty() {
        ip_addr = ip.parse().unwrap();
    }
    if !mask.is_empty() {
        net_mask = mask.parse().unwrap();
    }
    if !mac.is_empty() {
        mac_addr = MacAddr::parse_str(mac).unwrap();
    }

    Ok(NetParams {
        tap_if_name,
        ip_addr,
        net_mask,
        mac_addr,
    })
}

// legacy device instances
struct Devices {
    // Serial port on 0x3f8 clone here
    serial: Arc<Mutex<legacy_device::Serial>>,

    // Serial port on 0x3f8
    serial_evt: EventFd,

    // i8042 device for exit
    i8042: Arc<Mutex<legacy_device::I8042Device>>,

    // i8042 device for exit
    exit_evt: EventFd,
}

impl Devices {
    fn new() -> DeviceResult<Self> {
        let serial_evt = EventFd::new(EFD_NONBLOCK).map_err(DeviceError::EventFd)?;
        let serial = Arc::new(Mutex::new(legacy_device::Serial::new_out(
            serial_evt.try_clone().map_err(DeviceError::EventFd)?,
            Box::new(stdout()),
        )));

        let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(DeviceError::EventFd)?;
        let i8042 = Arc::new(Mutex::new(legacy_device::I8042Device::new(
            exit_evt.try_clone().map_err(DeviceError::EventFd)?,
        )));

        Ok(Devices {
            serial,
            serial_evt,
            i8042,
            exit_evt,
        })
    }

    fn register_devices(
        &mut self,
        memory: GuestMemoryMmap,
        vm_fd: &VmFd,
        vm_cfg: &VmConfig,
        device_manager: &mut DeviceManager,
    ) -> DeviceResult<()> {
        // Register serial device
        let mut resource = Vec::new();
        resource.push(IoResource::new(
            Some(GuestAddress(0x3f8)),
            8 as GuestUsize,
            IoType::Pio,
        ));
        device_manager
            .register_device(
                self.serial.clone(),
                None,
                &mut resource,
                Some(IrqResource(None)),
            )
            .map_err(DeviceError::RegisterDevice)?;

        // Register i8042
        let mut resource = Vec::new();
        resource.push(IoResource::new(
            Some(GuestAddress(0x61)),
            4 as GuestUsize,
            IoType::Pio,
        ));
        device_manager
            .register_device(
                self.i8042.clone(),
                None,
                &mut resource,
                Some(IrqResource(None)),
            )
            .map_err(DeviceError::RegisterDevice)?;

        let pci_root = PciRoot::new(None);
        let mut pci = Arc::new(Mutex::new(PciConfigIo::new(pci_root)));

        for disk_path in &vm_cfg.disk_paths {
            // Open block device path
            let raw_img: File = OpenOptions::new()
                .read(true)
                .write(true)
                .open(disk_path.as_path())
                .map_err(DeviceError::Disk)?;

            // Add virtio-blk
            let image_type =
                qcow::detect_image_type(&raw_img).map_err(DeviceError::DetectImageType)?;
            let block = match image_type {
                ImageType::Raw => {
                    let raw_img = vm_virtio::RawFile::new(raw_img);
                    let dev = vm_virtio::Block::new(raw_img, disk_path.to_path_buf(), false)
                        .map_err(DeviceError::CreateVirtioBlock)?;
                    Box::new(dev) as Box<vm_virtio::VirtioDevice>
                }
                ImageType::Qcow2 => {
                    let qcow_img =
                        QcowFile::from(raw_img).map_err(DeviceError::QcowDeviceCreate)?;
                    let dev = vm_virtio::Block::new(qcow_img, disk_path.to_path_buf(), false)
                        .map_err(DeviceError::CreateVirtioBlock)?;
                    Box::new(dev) as Box<vm_virtio::VirtioDevice>
                }
            };
            Devices::add_virtio_pci_device(
                "virtio-block".to_string(),
                block,
                memory.clone(),
                vm_fd,
                &mut pci,
                device_manager,
            )?;
        }

        // Add virtio-net if required
        if let Some(net_params) = &vm_cfg.net_params {
            if let Ok(net_params) = parse_net_params(net_params) {
                let mut virtio_net_device: vm_virtio::Net;

                if let Some(tap_if_name) = net_params.tap_if_name {
                    let tap = Tap::open_named(tap_if_name).map_err(DeviceError::OpenTap)?;
                    virtio_net_device =
                        vm_virtio::Net::new_with_tap(tap, Some(&net_params.mac_addr))
                            .map_err(DeviceError::CreateVirtioNet)?;
                } else {
                    virtio_net_device = vm_virtio::Net::new(
                        net_params.ip_addr,
                        net_params.net_mask,
                        Some(&net_params.mac_addr),
                    )
                    .map_err(DeviceError::CreateVirtioNet)?;
                }
                Devices::add_virtio_pci_device(
                    "virtio-net".to_string(),
                    Box::new(virtio_net_device),
                    memory.clone(),
                    vm_fd,
                    &mut pci,
                    device_manager,
                )?;
            }
        }

        // Add virtio-rng if required
        if let Some(rng_path) = &vm_cfg.rng_path {
            println!("VIRTIO_RNG PATH {}", rng_path);
            let virtio_rng_device =
                vm_virtio::Rng::new(rng_path).map_err(DeviceError::CreateVirtioRng)?;
            Devices::add_virtio_pci_device(
                "virtio-rng".to_string(),
                Box::new(virtio_rng_device),
                memory.clone(),
                vm_fd,
                &mut pci,
                device_manager,
            )?;
        }

        let res = IoResource::new(Some(GuestAddress(0xcf8)), 8, IoType::Pio);
        println!("register device 0xcf8");
        let mut res_req = Vec::new();
        res_req.push(res);

        device_manager
            .register_device(pci.clone(), None, &mut res_req, None)
            .map_err(DeviceError::RegisterDevice)?;
        Ok(())
    }

    fn add_virtio_pci_device(
        name: String,
        virtio_device: Box<vm_virtio::VirtioDevice>,
        memory: GuestMemoryMmap,
        vm_fd: &VmFd,
        pci: &mut Arc<Mutex<PciConfigIo>>,
        device_manager: &mut DeviceManager,
    ) -> DeviceResult<()> {
        let virtio_pci_device = VirtioPciDevice::new(name.clone(), memory, virtio_device)
            .map_err(DeviceError::VirtioDevice)?;

        // Register virtio device resource
        let mut resource = virtio_pci_device.get_resource();

        let virtio_pci_device = Arc::new(Mutex::new(virtio_pci_device));

        device_manager
            .register_device(
                virtio_pci_device.clone(),
                Some(pci.clone()),
                &mut resource,
                Some(IrqResource(None)),
            )
            .map_err(DeviceError::RegisterDevice)?;

        pci.lock()
            .expect("failed to acquire lock")
            .add_device(virtio_pci_device.clone())
            .map_err(DeviceError::AddPciDevice)?;

        for (event, addr, _) in virtio_pci_device
            .lock()
            .expect("failed to unlock")
            .ioeventfds()
        {
            let io_addr = IoEventAddress::Mmio(addr);
            vm_fd
                .register_ioevent(event.as_raw_fd(), &io_addr, NoDatamatch)
                .map_err(DeviceError::RegisterIoevent)?;
        }

        let irq_num = virtio_pci_device.lock().expect("failed").irq_num();
        let event_fd = virtio_pci_device
            .lock()
            .expect("failed")
            .interrupt_evt()
            .unwrap()
            .as_raw_fd();

        vm_fd
            .register_irqfd(event_fd, irq_num)
            .map_err(DeviceError::Irq)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EpollDispatch {
    Exit,
    Stdin,
}

pub struct EpollContext {
    raw_fd: RawFd,
    dispatch_table: Vec<Option<EpollDispatch>>,
}

impl EpollContext {
    pub fn new() -> result::Result<EpollContext, io::Error> {
        let raw_fd = epoll::create(true)?;

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 1 stdin event
        let mut dispatch_table = Vec::with_capacity(3);
        dispatch_table.push(None);

        Ok(EpollContext {
            raw_fd,
            dispatch_table,
        })
    }

    pub fn add_stdin(&mut self) -> result::Result<(), io::Error> {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;

        self.dispatch_table.push(Some(EpollDispatch::Stdin));

        Ok(())
    }

    fn add_event<T>(&mut self, fd: &T, token: EpollDispatch) -> result::Result<(), io::Error>
    where
        T: AsRawFd,
    {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;
        self.dispatch_table.push(Some(token));

        Ok(())
    }
}

impl AsRawFd for EpollContext {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }
}

pub struct Vm<'a> {
    fd: VmFd,
    kernel: File,
    memory: GuestMemoryMmap,
    vcpus: Vec<thread::JoinHandle<()>>,
    legacy: Devices,
    device_manager: Arc<Mutex<DeviceManager>>,
    cpuid: CpuId,
    config: VmConfig<'a>,
    epoll: EpollContext,
}

impl<'a> Vm<'a> {
    pub fn new(kvm: &Kvm, config: VmConfig<'a>) -> Result<Self> {
        let kernel = File::open(&config.kernel_path).map_err(Error::KernelFile)?;
        let fd = kvm.create_vm().map_err(Error::VmCreate)?;

        // Init guest memory
        let arch_mem_regions = arch::arch_memory_regions(config.memory_size << 20);
        let guest_memory = GuestMemoryMmap::new(&arch_mem_regions).map_err(Error::GuestMemory)?;

        guest_memory
            .with_regions(|index, region| {
                let mem_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len() as u64,
                    userspace_addr: region.as_ptr() as u64,
                    flags: 0,
                };

                // Safe because the guest regions are guaranteed not to overlap.
                fd.set_user_memory_region(mem_region)
            })
            .map_err(|_| Error::GuestMemory(MmapError::NoMemoryRegion))?;

        // Set TSS
        fd.set_tss_address(arch::x86_64::layout::KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(Error::VmSetup)?;

        // Create IRQ chip
        fd.create_irq_chip().map_err(Error::VmSetup)?;

        // Creates an in-kernel device model for the PIT.
        let mut pit_config = kvm_pit_config::default();
        // We need to enable the emulation of a dummy speaker port stub so that writing to port 0x61
        // (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
        pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
        fd.create_pit2(pit_config).map_err(Error::VmSetup)?;

        // Supported CPUID
        let mut cpuid = kvm
            .get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
            .map_err(Error::VmSetup)?;
        Vm::patch_cpuid(&mut cpuid);

        // Let's allocate 64 GiB of addressable MMIO space, starting at 0.
        let allocator = SystemAllocator::new(
            Some(GuestAddress(0)),
            Some(1 << 16 as GuestUsize),
            GuestAddress(0),
            1 << 36 as GuestUsize,
            X86_64_IRQ_BASE,
        )
        .ok_or(Error::CreateSystemAllocator)?;

        let mut device_manager = DeviceManager::new(Arc::new(Mutex::new(allocator)));

        // Create devices
        let mut devices = Devices::new().map_err(Error::Devices)?;

        devices
            .register_devices(guest_memory.clone(), &fd, &config, &mut device_manager)
            .map_err(Error::Devices)?;

        let dev_mgr = Arc::new(Mutex::new(device_manager));

        fd.register_irqfd(devices.serial_evt.as_raw_fd(), 4)
            .map_err(Error::Irq)?;

        // Let's add our STDIN fd.
        let mut epoll = EpollContext::new().map_err(Error::EpollError)?;
        epoll.add_stdin().map_err(Error::EpollError)?;

        // Let's add an exit event.
        epoll
            .add_event(&devices.exit_evt, EpollDispatch::Exit)
            .map_err(Error::EpollError)?;

        let vcpus = Vec::with_capacity(config.vcpu_count as usize);

        Ok(Vm {
            fd,
            kernel,
            memory: guest_memory,
            vcpus,
            legacy: devices,
            device_manager: dev_mgr,
            cpuid,
            config,
            epoll,
        })
    }

    pub fn load_kernel(&mut self) -> Result<GuestAddress> {
        let cmdline_cstring =
            CString::new(self.config.cmdline.clone()).map_err(|_| Error::CmdLine)?;
        let entry_addr = linux_loader::loader::Elf::load(
            &self.memory,
            None,
            &mut self.kernel,
            Some(arch::HIMEM_START),
        )
        .map_err(Error::KernelLoad)?;

        linux_loader::loader::load_cmdline(
            &self.memory,
            self.config.cmdline_addr,
            &cmdline_cstring,
        )
        .map_err(|_| Error::CmdLine)?;

        let vcpu_count = self.config.vcpu_count;

        arch::configure_system(
            &self.memory,
            self.config.cmdline_addr,
            cmdline_cstring.to_bytes().len() + 1,
            vcpu_count,
        )
        .map_err(|_| Error::CmdLine)?;

        Ok(entry_addr.kernel_load)
    }

    pub fn control_loop(&mut self) -> Result<()> {
        // Let's start the STDIN polling thread.
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];
        let epoll_fd = self.epoll.as_raw_fd();

        let stdin = io::stdin();
        let stdin_lock = stdin.lock();
        stdin_lock.set_raw_mode().map_err(Error::SetTerminalRaw)?;

        loop {
            let num_events =
                epoll::wait(epoll_fd, -1, &mut events[..]).map_err(Error::EpollError)?;

            for event in events.iter().take(num_events) {
                let dispatch_idx = event.data as usize;

                if let Some(dispatch_type) = self.epoll.dispatch_table[dispatch_idx] {
                    match dispatch_type {
                        EpollDispatch::Exit => {
                            // Consume the event.
                            self.legacy.exit_evt.read().map_err(Error::EventFd)?;

                            // Don't forget to set the terminal in canonical mode
                            // before to exit.
                            stdin_lock
                                .set_canon_mode()
                                .map_err(Error::SetTerminalCanon)?;

                            // Safe because we're terminating the process anyway.
                            unsafe {
                                libc::_exit(0);
                            }
                        }
                        EpollDispatch::Stdin => {
                            let mut out = [0u8; 64];
                            let count = stdin_lock.read_raw(&mut out).map_err(Error::Serial)?;

                            self.legacy
                                .serial
                                .lock()
                                .expect("Failed to process stdin event due to poisoned lock")
                                .queue_input_bytes(&out[..count])
                                .map_err(Error::Serial)?;
                        }
                    }
                }
            }
        }
    }

    pub fn start(&mut self, entry_addr: GuestAddress) -> Result<()> {
        let vcpu_count = self.config.vcpu_count;

        //        let vcpus: Vec<thread::JoinHandle<()>> = Vec::with_capacity(vcpu_count as usize);
        let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        for cpu_id in 0..vcpu_count {
            let mut vcpu = Vcpu::new(cpu_id, &self, self.device_manager.clone())?;
            vcpu.configure(entry_addr, &self)?;

            let vcpu_thread_barrier = vcpu_thread_barrier.clone();

            self.vcpus.push(
                thread::Builder::new()
                    .name(format!("cloud-hypervisor_vcpu{}", vcpu.id))
                    .spawn(move || {
                        unsafe {
                            extern "C" fn handle_signal(_: i32, _: *mut siginfo_t, _: *mut c_void) {
                            }
                            // This uses an async signal safe handler to kill the vcpu handles.
                            register_signal_handler(
                                VCPU_RTSIG_OFFSET,
                                vmm_sys_util::signal::SignalHandler::Siginfo(handle_signal),
                                true,
                                0,
                            )
                            .expect("Failed to register vcpu signal handler");
                        }

                        // Block until all CPUs are ready.
                        vcpu_thread_barrier.wait();

                        while vcpu.run().is_ok() {}
                    })
                    .map_err(Error::VcpuSpawn)?,
            );
        }

        // Unblock all CPU threads.
        vcpu_thread_barrier.wait();

        self.control_loop()?;

        Ok(())
    }

    /// Gets a reference to the guest memory owned by this VM.
    ///
    /// Note that `GuestMemory` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> &GuestMemoryMmap {
        &self.memory
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    ///
    pub fn get_fd(&self) -> &VmFd {
        &self.fd
    }

    fn patch_cpuid(cpuid: &mut CpuId) {
        let entries = cpuid.mut_entries_slice();

        for entry in entries.iter_mut() {
            if let 1 = entry.function {
                if entry.index == 0 {
                    entry.ecx |= 1 << ECX_HYPERVISOR_SHIFT;
                }
            }
        }
    }
}

#[allow(unused)]
pub fn test_vm() {
    // This example based on https://lwn.net/Articles/658511/
    let code = [
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8, /* add %bl, %al */
        0x04, b'0', /* add $'0', %al */
        0xee, /* out %al, (%dx) */
        0xb0, b'\n', /* mov $'\n', %al */
        0xee,  /* out %al, (%dx) */
        0xf4,  /* hlt */
    ];

    let mem_size = 0x1000;
    let load_addr = GuestAddress(0x1000);
    let mem = GuestMemoryMmap::new(&[(load_addr, mem_size)]).unwrap();

    let kvm = Kvm::new().expect("new KVM instance creation failed");
    let vm_fd = kvm.create_vm().expect("new VM fd creation failed");

    mem.with_regions(|index, region| {
        let mem_region = kvm_userspace_memory_region {
            slot: index as u32,
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len() as u64,
            userspace_addr: region.as_ptr() as u64,
            flags: 0,
        };

        // Safe because the guest regions are guaranteed not to overlap.
        vm_fd.set_user_memory_region(mem_region)
    })
    .expect("Cannot configure guest memory");
    mem.write_slice(&code, load_addr)
        .expect("Writing code to memory failed");

    let vcpu_fd = vm_fd.create_vcpu(0).expect("new VcpuFd failed");

    let mut vcpu_sregs = vcpu_fd.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu_fd.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let mut vcpu_regs = vcpu_fd.get_regs().expect("get regs failed");
    vcpu_regs.rip = 0x1000;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu_fd.set_regs(&vcpu_regs).expect("set regs failed");

    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::IoIn(addr, data) => {
                println!(
                    "IO in -- addr: {:#x} data [{:?}]",
                    addr,
                    str::from_utf8(&data).unwrap()
                );
            }
            VcpuExit::IoOut(addr, data) => {
                println!(
                    "IO out -- addr: {:#x} data [{:?}]",
                    addr,
                    str::from_utf8(&data).unwrap()
                );
            }
            VcpuExit::MmioRead(_addr, _data) => {}
            VcpuExit::MmioWrite(_addr, _data) => {}
            VcpuExit::Unknown => {}
            VcpuExit::Exception => {}
            VcpuExit::Hypercall => {}
            VcpuExit::Debug => {}
            VcpuExit::Hlt => {
                println!("HLT");
            }
            VcpuExit::IrqWindowOpen => {}
            VcpuExit::Shutdown => {}
            VcpuExit::FailEntry => {}
            VcpuExit::Intr => {}
            VcpuExit::SetTpr => {}
            VcpuExit::TprAccess => {}
            VcpuExit::S390Sieic => {}
            VcpuExit::S390Reset => {}
            VcpuExit::Dcr => {}
            VcpuExit::Nmi => {}
            VcpuExit::InternalError => {}
            VcpuExit::Osi => {}
            VcpuExit::PaprHcall => {}
            VcpuExit::S390Ucontrol => {}
            VcpuExit::Watchdog => {}
            VcpuExit::S390Tsch => {}
            VcpuExit::Epr => {}
            VcpuExit::SystemEvent => {}
            VcpuExit::S390Stsi => {}
            VcpuExit::IoapicEoi => {}
            VcpuExit::Hyperv => {}
        }
        //        r => panic!("unexpected exit reason: {:?}", r),
    }
}

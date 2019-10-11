// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

extern crate byteorder;
extern crate vm_memory;


use byteorder::{ByteOrder, LittleEndian};

// max 32 vectors
const MAX_VIS_VECTORS_PER_DEVICE: u16 = 32;
// vet occupies 64bit+32bit
const VIS_VET_TABLE_ENTRIES_MODULO: u64 = 12;

// VET table
#[derive(Debug, Clone, Copy)]
pub struct VisTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
}

impl Default for VisTableEntry {
    fn default() -> Self {
        VisTableEntry {
            msg_addr_lo: 0,
            msg_addr_hi: 0,
            msg_data: 0,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct VisTable {
    pub table_entries: [VisTableEntry; 32],
}

impl VisTable {
    pub fn get_vis_table_entry(&self, vector: u16) -> VisTableEntry {
        let entry = self.table_entries[vector as usize].clone();
	entry
    }

    pub fn read_table(&self, offset: u64, data: &mut [u8]) {
        assert!((data.len() == 4 || data.len() == 8));

        let index: usize = (offset / VIS_VET_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % VIS_VET_TABLE_ENTRIES_MODULO;

        match data.len() {
            4 => {
                let value = match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo,
                    0x4 => self.table_entries[index].msg_addr_hi,
                    0x8 => self.table_entries[index].msg_data,
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("VIS vet TABLE offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u32(data, value);
            }
            8 => {
                let value = match modulo_offset {
                    0x0 => {
                        (u64::from(self.table_entries[index].msg_addr_hi) << 32)
                            | u64::from(self.table_entries[index].msg_addr_lo)
                    }
                    // TODO: Here vis is different with msix, so take care!
                    // Hope it will not run
                    0x8 => {
                        u64::from(self.table_entries[index].msg_data)
                    }
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                debug!("VIS vet TABLE offset 0x{:x} data 0x{:x}", offset, value);
                LittleEndian::write_u64(data, value);
            }
            _ => {
                error!("invalid data length");
            }
        }
    }

    pub fn write_table(&mut self, offset: u64, data: &[u8]) {
        assert!((data.len() == 4 || data.len() == 8));

        let index: usize = (offset / VIS_VET_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % VIS_VET_TABLE_ENTRIES_MODULO;

        // Store the value of the entry before modification
        //let mut old_entry: Option<VisTableEntry> = None;

        match data.len() {
            4 => {
                let value = LittleEndian::read_u32(data);
                match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo = value,
                    0x4 => self.table_entries[index].msg_addr_hi = value,
                    0x8 => self.table_entries[index].msg_data = value,
                    _ => error!("invalid offset"),
                };

                debug!("VIS_W vet TABLE offset 0x{:x} data 0x{:x}", offset, value);
            }
	    // TODO hope no
            8 => {
                let value = LittleEndian::read_u64(data);
                match modulo_offset {
                    0x0 => {
                        self.table_entries[index].msg_addr_lo = (value & 0xffff_ffffu64) as u32;
                        self.table_entries[index].msg_addr_hi = (value >> 32) as u32;
                    }
                    0x8 => {
                        //old_entry = Some(self.table_entries[index].clone());
                        self.table_entries[index].msg_data = (value & 0xffff_ffffu64) as u32;
                        //self.table_entries[index].vector_ctl = (value >> 32) as u32;
                    }
                    _ => error!("invalid offset"),
                };

                debug!("VIS_W vet TABLE offset 0x{:x} data 0x{:x}", offset, value);
            }
            _ => error!("invalid data length"),
        };
    }
}

#[derive(Debug, Clone)]
pub struct VisMbaRegister {
    pub mask_bits: u32,
}

impl VisMbaRegister {
    pub fn new() -> Self {
        VisMbaRegister {
            mask_bits: 0xffff_ffff,
        }
    }

    pub fn masked(&self, vis_vec: u16) -> bool {
        assert!(vis_vec <= 32);

        if self.mask_bits & (1 << vis_vec) == 0 {
            false
        } else {
            true
        }
    }

    // this should not be trapped
    pub fn read_mba(&self, _offset: u64, data: &mut [u8]) {
        LittleEndian::write_u32(data, self.mask_bits);
    }

    // Get signal changing bit's offset
    fn get_changed_bit(&self, new: u32) -> u16 {
        let mut diff = self.mask_bits ^ new;
        for i in 0..31 {
            if diff & 0x1 == 0 {
                diff = diff >> (1 + i);
                continue;
            } else {
                return i;
            }
        }
        return 0xff;
    }

    // write being trapped
    // Return (true, vector) if caller needs to inject interrupt
    pub fn write_mba(&mut self, _offset: u64, data: &[u8], pba_addr: *mut VisPbaRegister) -> (bool, u16) {
        // guest kernel writes all the 32 mask bits
        assert!(data.len() == 4);

        let new = LittleEndian::read_u32(data);

        if new == 0xffff_ffff {
            self.mask_bits = new;
            return (false, 0);
        }

        let old = self.mask_bits;

        if old ^ new == 0 {
            // No changes at all
            (false, 0)
        } else {
            // Figure out the different bit
            let vector = self.get_changed_bit(new);
            if vector == 0xff {
                println!("Guest write mba a strange value!\n");
                return (false, 0);
            } else {
            }
            if new & (1 << vector) != 0 {
                // Guest writes 1 to this bit
                self.mask_bits |= 1 << vector;
                (false, 0)
            } else {
                // Guest writes 0 to this bit
                self.mask_bits &= !(1 << vector);

                if unsafe {(*pba_addr).get_pba_bit(vector as u16)} == 1 {
                    // TODO need call inject 
                    (true, vector)
                } else {
                    (false, 0)
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct VisPbaRegister {
    pub pending_bits: u32,
}

impl VisPbaRegister {
    pub fn new() -> Self {
        VisPbaRegister {
            pending_bits: 0,
        }
    }

    // no trap
    pub fn read_pba(&mut self, _offset: u64, _data: &mut [u8]) {
        // LittleEndian::write_u32(data, self.pending_bits);
    }

    // no trap
    pub fn write_pba(&mut self, _offset: u64, _data: &[u8]) {
        error!("Pending Bit Array is read only");
    }


    pub fn set_pba_bit(&mut self, vector: u16, reset: bool) {
        assert!(vector < MAX_VIS_VECTORS_PER_DEVICE);

        let mut mask: u32 = (1 << vector) as u32;

        if reset {
            mask = !mask;
            self.pending_bits &= mask;
        } else {
            self.pending_bits |= mask;
        }
    }

    fn get_pba_bit(&self, vector: u16) -> u8 {
        assert!(vector < MAX_VIS_VECTORS_PER_DEVICE);

        ((self.pending_bits >> vector) & 0x0000_0001u32) as u8
    }
}


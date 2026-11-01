/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Relative jump tables (`lea rT,[rip+T]; movsxd rX,dword ptr [rT+rI*4]`) of a function and the
//! table indices an address belongs to: a Rust `match` arm, e.g. an error enum variant.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{Mnemonic, Register};

use crate::image::Image;
use crate::scan::decode;

pub struct Table {
    pub dispatch: u64,
    pub base: u64,
    /// Arm address of every index.
    pub arms: Vec<u64>,
}

/// The jump tables dispatched inside `function`; entries are read while their target stays in it.
pub fn tables(image: &Image, function: &Range<u64>) -> Vec<Table> {
    let Some(bytes) = image.code(function) else { return Vec::new() };
    let mut leas: HashMap<Register, u64> = HashMap::new();
    let mut found = Vec::new();
    decode(bytes, function.start, |instruction| {
        if instruction.mnemonic() == Mnemonic::Lea && instruction.is_ip_rel_memory_operand() {
            leas.insert(instruction.op0_register().full_register(), instruction.ip_rel_memory_address());
        } else if instruction.mnemonic() == Mnemonic::Movsxd
            && instruction.memory_index_scale() == 4
            && let Some(&base) = leas.get(&instruction.memory_base().full_register())
        {
            let arms = (0..8192u64)
                .map_while(|index| {
                    let entry = image.read(base + index * 4, 4)?;
                    let offset = i32::from_le_bytes(entry.try_into().ok()?);
                    let arm = base.checked_add_signed(i64::from(offset))?;
                    function.contains(&arm).then_some(arm)
                })
                .collect();
            found.push(Table { dispatch: instruction.ip(), base, arms });
        }
    });
    found
}

/// Indices whose arm is the closest one at or before `addr` (shared arms give several).
pub fn arm_indices(arms: &[u64], addr: u64) -> Vec<usize> {
    let Some(arm) = arms.iter().copied().filter(|arm| *arm <= addr).max() else { return Vec::new() };
    arms.iter().enumerate().filter(|(_, candidate)| **candidate == arm).map(|(index, _)| index).collect()
}

#[cfg(test)]
mod tests {
    use super::arm_indices;

    #[test]
    fn an_address_belongs_to_the_closest_preceding_arm() {
        let arms = [0x100, 0x180, 0x140, 0x180];
        assert_eq!(arm_indices(&arms, 0x185), [1, 3]);
        assert_eq!(arm_indices(&arms, 0x17f), [2]);
        assert_eq!(arm_indices(&arms, 0xff), Vec::<usize>::new());
    }
}

/*
 * XRef — bounded offline CFI stack unwinding
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::Sample;
use super::types::remove_slide;
use crate::image::Image;
use gimli::{
    BaseAddresses, CfaRule, EhFrame, EndianSlice, LittleEndian, Register, RegisterRule, UnwindContext, UnwindSection,
};
use object::{Object, ObjectSection};

const MAX_FRAMES: usize = 512;
const PERF_TO_DWARF: [(usize, usize); 17] = [
    (0, 0),
    (1, 3),
    (2, 2),
    (3, 1),
    (4, 4),
    (5, 5),
    (6, 6),
    (7, 7),
    (8, 16),
    (16, 8),
    (17, 9),
    (18, 10),
    (19, 11),
    (20, 12),
    (21, 13),
    (22, 14),
    (23, 15),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindResult {
    /// Runtime IPs, leaf first; the last frame may be outside the target image.
    pub frames: Vec<u64>,
    pub stop_reason: &'static str,
}

pub struct Unwinder<'a> {
    image: &'a Image,
    frame: EhFrame<EndianSlice<'a, LittleEndian>>,
    bases: BaseAddresses,
    slide: i64,
    rules: std::sync::RwLock<std::collections::HashMap<u64, Result<std::sync::Arc<CachedRules>, &'static str>>>,
}

struct CachedRules {
    cfa_register: usize,
    cfa_offset: i64,
    return_register: usize,
    return_rule: RegisterRule<usize>,
    registers: Vec<RegisterRule<usize>>,
}

impl<'a> Unwinder<'a> {
    pub fn new(image: &'a Image, slide: i64) -> Result<Self, String> {
        let file = crate::image_format::parse(&image.data).map_err(|error| error.to_string())?;
        let section = file.section_by_name(".eh_frame").ok_or("missing .eh_frame")?;
        let bytes = section.data().map_err(|error| error.to_string())?;
        let mut bases = BaseAddresses::default().set_eh_frame(section.address());
        if let Some(header) = file.section_by_name(".eh_frame_hdr") {
            bases = bases.set_eh_frame_hdr(header.address());
        }
        if let Some(text) = file.section_by_name(".text") {
            bases = bases.set_text(text.address());
        }
        if let Some(got) = file.section_by_name(".got") {
            bases = bases.set_got(got.address());
        }
        Ok(Self {
            image,
            frame: EhFrame::new(bytes, LittleEndian),
            bases,
            slide,
            rules: std::sync::RwLock::new(std::collections::HashMap::new()),
        })
    }

    fn rules(&self, static_ip: u64) -> Result<std::sync::Arc<CachedRules>, &'static str> {
        if let Some(cached) = self.rules.read().map_err(|_| "cfi_cache_poisoned")?.get(&static_ip) {
            return cached.clone();
        }
        let parsed = (|| {
            let fde = self
                .frame
                .fde_for_address(&self.bases, static_ip, EhFrame::cie_from_offset)
                .map_err(|_| "missing_fde")?;
            let mut context = UnwindContext::new();
            let row = fde
                .unwind_info_for_address(&self.frame, &self.bases, &mut context, static_ip)
                .map_err(|_| "invalid_cfi")?;
            let CfaRule::RegisterAndOffset { register, offset } = row.cfa() else {
                return Err("unsupported_cfa_expression");
            };
            let return_register = fde.cie().return_address_register();
            Ok(std::sync::Arc::new(CachedRules {
                cfa_register: usize::from(register.0),
                cfa_offset: *offset,
                return_register: usize::from(return_register.0),
                return_rule: row.register(return_register),
                registers: (0..16).map(|index| row.register(Register(index))).collect(),
            }))
        })();
        let mut cache = self.rules.write().map_err(|_| "cfi_cache_poisoned")?;
        if cache.len() < 4_096 {
            cache.insert(static_ip, parsed.clone());
        }
        parsed
    }

    #[cfg(test)]
    pub fn unwind(&self, sample: &Sample, requested_frames: usize) -> UnwindResult {
        unwind_with(sample, requested_frames, |_, _| Some(self))
    }
}

pub fn unwind_with<'a, 'image: 'a>(
    sample: &Sample,
    requested_frames: usize,
    mut resolve: impl FnMut(u64, bool) -> Option<&'a Unwinder<'image>>,
) -> UnwindResult {
    let mut frames = vec![sample.ip];
    let Some(mut registers) = perf_registers(sample) else {
        return UnwindResult { frames, stop_reason: "registers_unavailable" };
    };
    let Some(stack_base) = registers[7] else {
        return UnwindResult { frames, stop_reason: "stack_pointer_unavailable" };
    };
    let limit = requested_frames.clamp(1, MAX_FRAMES);
    while frames.len() < limit {
        let ip = *frames.last().unwrap_or(&0);
        let Some(unwinder) = resolve(ip, frames.len() != 1) else {
            return UnwindResult { frames, stop_reason: "unverified_or_unmapped_module" };
        };
        let lookup = if frames.len() == 1 { Some(ip) } else { ip.checked_sub(1) };
        let Some(static_ip) = lookup.and_then(|value| remove_slide(value, unwinder.slide)) else {
            return UnwindResult { frames, stop_reason: "address_overflow" };
        };
        if unwinder.image.function_at(static_ip).is_none() {
            return UnwindResult { frames, stop_reason: "outside_mapped_function" };
        }
        let rules = match unwinder.rules(static_ip) {
            Ok(rules) => rules,
            Err(stop_reason) => return UnwindResult { frames, stop_reason },
        };
        let Some(cfa) = registers
            .get(rules.cfa_register)
            .copied()
            .flatten()
            .and_then(|base| base.checked_add_signed(rules.cfa_offset))
        else {
            return UnwindResult { frames, stop_reason: "cfa_register_unavailable" };
        };
        if registers[7].is_none_or(|rsp| cfa <= rsp) {
            return UnwindResult { frames, stop_reason: "non_increasing_stack" };
        }
        let Some(return_ip) =
            recover(&rules.return_rule, rules.return_register, cfa, &registers, stack_base, &sample.user_stack)
        else {
            return UnwindResult { frames, stop_reason: "return_address_unavailable" };
        };
        if return_ip == 0 {
            return UnwindResult { frames, stop_reason: "end_of_stack" };
        }
        let mut previous = [None; 17];
        for (index, value) in previous.iter_mut().enumerate().take(16) {
            *value = recover(&rules.registers[index], index, cfa, &registers, stack_base, &sample.user_stack);
        }
        previous[7] = Some(cfa);
        previous[16] = Some(return_ip);
        registers = previous;
        frames.push(return_ip);
    }
    UnwindResult { frames, stop_reason: "frame_limit" }
}

fn perf_registers(sample: &Sample) -> Option<[Option<u64>; 17]> {
    if sample.registers.len() != sample.registers_mask.count_ones() as usize {
        return None;
    }
    let mut out = [None; 17];
    let mut values = sample.registers.iter();
    for bit in 0..64 {
        if sample.registers_mask & (1_u64 << bit) == 0 {
            continue;
        }
        let value = *values.next()?;
        if let Some((_, dwarf)) = PERF_TO_DWARF.iter().find(|(perf, _)| *perf == bit) {
            out[*dwarf] = Some(value);
        }
    }
    out[16] = Some(sample.ip);
    Some(out)
}

fn recover<T: gimli::ReaderOffset>(
    rule: &RegisterRule<T>,
    target: usize,
    cfa: u64,
    registers: &[Option<u64>; 17],
    base: u64,
    stack: &[u8],
) -> Option<u64> {
    match rule {
        RegisterRule::SameValue => registers.get(target).copied().flatten(),
        RegisterRule::Register(register) => registers.get(usize::from(register.0)).copied().flatten(),
        RegisterRule::ValOffset(offset) => cfa.checked_add_signed(*offset),
        RegisterRule::Constant(value) => Some(*value),
        RegisterRule::Offset(offset) => {
            let address = cfa.checked_add_signed(*offset)?;
            let start = usize::try_from(address.checked_sub(base)?).ok()?;
            let end = start.checked_add(8)?;
            Some(u64::from_le_bytes(stack.get(start..end)?.try_into().ok()?))
        }
        _ => None,
    }
}

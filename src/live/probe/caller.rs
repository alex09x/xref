/*
 * XRef — Stage L2 caller return-address attribution and CALL-site verification
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Attributes observed return addresses using `return_static_va.saturating_sub(1)` and verifies
//! the preceding `CALL` instruction via `iced-x86`, preserving explicit unwind/tail-call caveats.

use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};

use crate::image::Image;
use crate::live::classify::{find_region, lookup_symbol, static_va_to_file_offset};
use crate::live::probe::types::{CallerEntry, UnwindEntryStatus};
use crate::live::types::{HexAddr, RegionEntry, remove_slide};

#[must_use]
pub fn attribute_caller(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    unwind_status: &UnwindEntryStatus,
    raw_return_runtime_va: u64,
    hits: u64,
) -> CallerEntry {
    if matches!(unwind_status, UnwindEntryStatus::Unavailable { .. }) {
        return CallerEntry {
            raw_return_runtime_va: HexAddr(raw_return_runtime_va),
            return_static_va: None,
            caller_function: None,
            caller_symbol: None,
            call_site_static_va: None,
            call_verified: false,
            hits,
            caveat: "cfi_unavailable_for_return_slot",
        };
    }

    let in_target_exec_region =
        find_region(regions, raw_return_runtime_va).is_some_and(|reg| reg.is_target_image && reg.perms.contains('x'));
    let Some(return_static) = remove_slide(raw_return_runtime_va, pie_slide) else {
        return unmapped_caller(raw_return_runtime_va, hits, "return_address_slide_overflow");
    };
    let in_exec_segment = static_va_to_file_offset(&image.metadata.load_segments, return_static)
        .is_some_and(|(off, in_bss, exec)| off.is_some() && !in_bss && exec);

    if !in_target_exec_region || !in_exec_segment {
        return unmapped_caller(raw_return_runtime_va, hits, "outside_target_executable");
    }

    let lookup_pc = return_static.saturating_sub(1);
    let caller_fn = image.function_at(lookup_pc);
    let caller_function = caller_fn.as_ref().map(|r| HexAddr(r.start));
    let caller_symbol = caller_fn.as_ref().and_then(|r| lookup_symbol(image, r.start));

    let call_site = caller_fn.as_ref().and_then(|func| find_preceding_call_site(image, func, return_static));

    let (call_site_static_va, call_verified, caveat) = match (call_site, unwind_status) {
        (Some(site), UnwindEntryStatus::StandardRsp8RaMinus8) => {
            (Some(HexAddr(site)), true, "unwind_evidence_only_tail_call_possible")
        }
        (Some(site), UnwindEntryStatus::InteriorFrameOffset { .. }) => {
            (Some(HexAddr(site)), true, "interior_cfi_frame_unwind_only")
        }
        (Some(site), UnwindEntryStatus::Unavailable { .. }) => {
            (Some(HexAddr(site)), true, "cfi_unavailable_for_return_slot")
        }
        (None, _) if caller_fn.is_none() => (None, false, "caller_fde_unavailable"),
        (None, _) => (None, false, "preceding_instruction_not_call"),
    };

    CallerEntry {
        raw_return_runtime_va: HexAddr(raw_return_runtime_va),
        return_static_va: Some(HexAddr(return_static)),
        caller_function,
        caller_symbol,
        call_site_static_va,
        call_verified,
        hits,
        caveat,
    }
}

const fn unmapped_caller(raw_return_runtime_va: u64, hits: u64, caveat: &'static str) -> CallerEntry {
    CallerEntry {
        raw_return_runtime_va: HexAddr(raw_return_runtime_va),
        return_static_va: None,
        caller_function: None,
        caller_symbol: None,
        call_site_static_va: None,
        call_verified: false,
        hits,
        caveat,
    }
}

#[must_use]
pub fn find_preceding_call_site(image: &Image, caller_fn: &Range<u64>, return_static_va: u64) -> Option<u64> {
    if return_static_va <= caller_fn.start || return_static_va > caller_fn.end {
        return None;
    }
    let prefix_len = usize::try_from(return_static_va - caller_fn.start).ok()?;
    let bytes = image.read(caller_fn.start, prefix_len)?;

    let mut decoder = Decoder::with_ip(64, bytes, caller_fn.start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            return None;
        }
        if instr.next_ip() == return_static_va {
            let is_call = instr.mnemonic() == Mnemonic::Call
                || matches!(instr.flow_control(), FlowControl::Call | FlowControl::IndirectCall);
            return is_call.then_some(instr.ip());
        }
        if instr.ip() >= return_static_va {
            break;
        }
    }
    None
}

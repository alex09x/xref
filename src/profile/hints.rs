/*
 * XRef — notes on reports that look plausible but mislead
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::aggregate::{Aggregate, Frame};
use super::resolve::Module;
use super::types::Header;
use crate::image::Image;
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use std::collections::BTreeSet;

/// Return addresses checked per sample: the innermost target frames.
const CHECKS_PER_SAMPLE: usize = 4;
/// Return addresses checked over the whole recording.
const MAX_CHECKS: u64 = 200_000;
/// Fewer checked return addresses than this decide nothing.
const MIN_CHECKS: u64 = 50;
/// Share of samples in library leaves (percent) from which the frame-pointer note is printed.
const LIBRARY_SHARE: f64 = 10.0;

/// Whether the recording's target addresses rest on a base the caller supplied, so that a check of
/// its return addresses is worth making. Every caller frame of these callchains is a return address.
pub fn checks_base(header: &Header, image: &Image) -> bool {
    !image.metadata.arm64
        && matches!(header.binary_match.as_str(), "caller_supplied_base_unverified" | "caller_supplied_maps_unverified")
        && matches!(header.callchain.as_str(), "fp" | "imported_perf_script" | "dwarf")
}

/// Of the innermost target return addresses of a user-mode sample (callers, not the leaf): how many
/// were checked and how many follow a call instruction. (A kernel-mode sample's first user frame is
/// where a system call returns to, not a return address.)
pub fn return_sites(image: &Image, frames: &[Frame]) -> (u64, u64) {
    let mut checked = 0;
    let mut after_call = 0;
    for frame in frames.iter().skip(1).filter(|frame| frame.function.module == 1).take(CHECKS_PER_SAMPLE) {
        // A return frame keeps the address before the return address.
        let Some(return_address) = frame.instruction.and_then(|address| address.checked_add(1)) else {
            continue;
        };
        checked += 1;
        after_call += u64::from(follows_call(image, return_address));
    }
    (checked, after_call)
}

/// Whether a call instruction of the image ends right before `return_address` (static).
fn follows_call(image: &Image, return_address: u64) -> bool {
    // `call rel32` first, then `call reg` and `call [mem]`: 2 to 8 bytes (REX, opcode, ModR/M, SIB and
    // a 32-bit displacement), 9 with a segment prefix as well.
    [5_usize, 2, 3, 4, 6, 7, 8, 9].into_iter().any(|length| {
        let Some(start) = return_address.checked_sub(length as u64) else { return false };
        let Some(bytes) = image.read(start, length) else { return false };
        let instruction = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE).decode();
        !instruction.is_invalid()
            && instruction.len() == length
            && matches!(instruction.flow_control(), FlowControl::Call | FlowControl::IndirectCall)
    })
}

/// Whether the recording counts CPU samples, not weights (bytes, off-CPU nanoseconds).
pub fn cpu_samples(event: &str) -> bool {
    !super::heap::is_bytes_event(event) && event != super::alloc::COUNT_EVENT && event != super::sched::EVENT
}

/// Return-address checks summed over a recording.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReturnSites {
    pub checked: u64,
    pub after_call: u64,
}

impl ReturnSites {
    pub const fn add(&mut self, (checked, after_call): (u64, u64)) {
        if self.checked < MAX_CHECKS {
            self.checked += checked;
            self.after_call += after_call;
        }
    }
}

/// Warnings (stable names) and notes (sentences for a reader) about the analysis.
#[allow(clippy::cast_precision_loss)] // Shares are display estimates.
pub fn notes(
    header: &Header,
    aggregate: &mut Aggregate,
    modules: &[Module],
    image: &Image,
    sites: ReturnSites,
    warnings: &mut BTreeSet<String>,
) -> Vec<String> {
    let mut notes = Vec::new();
    if sites.checked >= MIN_CHECKS && sites.after_call * 2 < sites.checked {
        warnings.insert("target_return_addresses_do_not_follow_calls".to_owned());
        aggregate.incomplete = true;
        notes.push(format!(
            "only {} of {} return addresses in the target follow a call instruction: the --base or --maps given to \
             profile import is likely wrong, and samples are then counted in the wrong functions",
            sites.after_call, sites.checked
        ));
    }
    // Only CPU samples with a recorded frame-pointer callchain on x86-64: perf-script text does not say
    // how perf unwound, `live alloc` stores chains it unwound with CFI as "fp" (its leaves are the
    // allocator), and arm64 libraries keep frame pointers by ABI.
    if cpu_samples(&header.event)
        && header.callchain == "fp"
        && !image.metadata.arm64
        && header.event != "macos-sample"
        && aggregate.samples > 0
    {
        let libraries: BTreeSet<u32> =
            modules.iter().filter(|module| module.kind == "shared_object").map(|module| module.id).collect();
        let mut leaves: Vec<_> = aggregate
            .functions
            .iter()
            .filter(|(function, counts)| counts.self_samples > 0 && libraries.contains(&function.module))
            .map(|(function, counts)| (*function, counts.self_samples))
            .collect();
        let in_libraries: u64 = leaves.iter().map(|(_, samples)| samples).sum();
        let share = super::report::percent(in_libraries, aggregate.samples);
        if share >= LIBRARY_SHARE {
            leaves.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let top = leaves
                .iter()
                .take(3)
                .map(|(function, samples)| {
                    let name = super::report::label(image, modules, *function);
                    format!("{name} {:.1}%", super::report::percent(*samples, aggregate.samples))
                })
                .collect::<Vec<_>>()
                .join(", ");
            warnings.insert("library_leaf_callers_unreliable_with_frame_pointers".to_owned());
            notes.push(format!(
                "{share:.1}% of samples are in library functions ({top}); a frame-pointer callchain often misses or \
                 misnames the direct caller of a library function built without frame pointers, so their callers \
                 (--by caller-path, --within) are unreliable: record with `perf record --call-graph dwarf` or \
                 `live profile --callers dwarf` to see them"
            ));
        }
    }
    notes
}

/*
 * XRef — Stage L2 probe target validation, instruction boundary, and CFI entry verification
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Validates probe addresses against verified target mappings, `iced-x86` instruction boundaries,
//! and effective first-PC `CIE + FDE` DWARF unwind rules.

use std::collections::BTreeSet;

use gimli::{BaseAddresses, CfaRule, EhFrame, LittleEndian, RegisterRule, UnwindContext, UnwindSection, X86_64};
use iced_x86::{Decoder, DecoderOptions, Instruction};
use object::{Object, ObjectSection};

use crate::image::Image;
use crate::live::classify::{find_region, resolve_address};
use crate::live::probe::types::{MAX_PROBES_PER_SESSION, ProbeTargetSpec, UnwindEntryStatus};
use crate::live::procfs::LiveSession;
use crate::live::types::{BinaryMatch, RegionEntry, ResolveDirection};

const MIN_FRAME_DISP: i64 = -4096;
const MAX_FRAME_DISP: i64 = 65_536;

pub fn validate_session_for_probe(session: &LiveSession) -> Result<(), String> {
    if session.process.binary_match == BinaryMatch::ForcedMismatch {
        return Err(
            "verified executable identity required for live probe: --force-bin mismatch cannot install verified probes"
                .to_owned(),
        );
    }
    for warn in &session.process.warnings {
        if warn == "target_identity_unverified" || warn == "pie_slide_unresolved_forced_zero" {
            return Err(format!("verified executable identity and load bias required for live probe ({warn})"));
        }
    }
    #[cfg(target_os = "linux")]
    if session.exe_dev_ino.is_none_or(|(_, ino)| ino == 0) {
        return Err("verified (dev, ino) for /proc/<pid>/exe required before installing uprobes".to_owned());
    }
    Ok(())
}

pub fn validate_probe_targets(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    addrs: &[u64],
) -> Result<Vec<ProbeTargetSpec>, String> {
    if addrs.is_empty() || addrs.len() > MAX_PROBES_PER_SESSION {
        return Err(format!("probe requires 1..={MAX_PROBES_PER_SESSION} target <ADDR> arguments"));
    }
    let mut specs = Vec::with_capacity(addrs.len());
    let mut seen_offsets = BTreeSet::new();

    for &input in addrs {
        let resolved = resolve_address(image, pie_slide, regions, input);
        if resolved.direction == ResolveDirection::Unmapped {
            return Err(format!("probe address {input:#x} does not map into the target executable or process"));
        }
        if resolved.in_bss {
            return Err(format!("probe address {input:#x} lies in zero-filled .bss, not file-backed executable code"));
        }
        if !resolved.executable {
            return Err(format!("probe address {input:#x} does not lie in an executable PT_LOAD segment (PF_X)"));
        }
        let Some(static_va) = resolved.static_va.map(|v| v.0) else {
            return Err(format!("probe address {input:#x} is outside the target ELF executable"));
        };
        let Some(runtime_va) = resolved.runtime_va.map(|v| v.0) else {
            return Err(format!("probe address {input:#x} could not be translated to a live runtime VA"));
        };
        let Some(file_offset) = resolved.file_offset.map(|v| v.0) else {
            return Err(format!("probe address {input:#x} has no file-backed ELF offset"));
        };
        let Some(region) = find_region(regions, runtime_va) else {
            return Err(format!(
                "probe runtime address {runtime_va:#x} (static {static_va:#x}) is not mapped in target process"
            ));
        };
        if !region.is_target_image || !region.perms.contains('x') {
            return Err(format!(
                "probe runtime address {runtime_va:#x} lands in {} ({}) rather than a verified executable target mapping",
                region.format_location(runtime_va),
                region.perms,
            ));
        }
        if !seen_offsets.insert(file_offset) {
            return Err(format!("duplicate probe target at file offset {file_offset:#x} (static {static_va:#x})"));
        }

        let instruction_mnemonic = verify_instruction_boundary(image, static_va)?;
        let (unwind_entry_abi, ra_fetch_arg) = evaluate_unwind_at(image, static_va);

        specs.push(ProbeTargetSpec {
            input,
            static_va,
            runtime_va,
            file_offset,
            function_start: resolved.function_start.map(|v| v.0),
            function_end: resolved.function_end.map(|v| v.0),
            function_offset: resolved.function_offset,
            symbol: resolved.symbol,
            instruction_mnemonic,
            unwind_entry_abi,
            ra_fetch_arg,
        });
    }

    Ok(specs)
}

pub fn verify_instruction_boundary(image: &Image, static_va: u64) -> Result<String, String> {
    let decode_span = if let Some(func) = image.function_at(static_va) {
        func
    } else if is_known_code_anchor(image, static_va) {
        let end = static_va.saturating_add(16);
        static_va..end
    } else {
        return Err(format!(
            "cannot verify x86-64 instruction boundary at {static_va:#x} without an enclosing .eh_frame FDE or symbol anchor"
        ));
    };

    let max_end = decode_span.end.min(static_va.saturating_add(16));
    let span_len = usize::try_from(max_end.saturating_sub(decode_span.start))
        .map_err(|_| format!("invalid decode range for {static_va:#x}"))?;
    let Some(bytes) = image.read(decode_span.start, span_len) else {
        return Err(format!("executable bytes at {static_va:#x} are unavailable in ELF image"));
    };

    let mut decoder = Decoder::with_ip(64, bytes, decode_span.start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let ip = instr.ip();
        let next_ip = instr.next_ip();
        if ip == static_va {
            if instr.is_invalid() {
                return Err(format!("address {static_va:#x} decodes as an invalid x86-64 instruction"));
            }
            return Ok(format!("{:?}", instr.mnemonic()).to_ascii_lowercase());
        }
        if ip < static_va && static_va < next_ip {
            let delta = static_va - ip;
            return Err(format!(
                "address {static_va:#x} lands mid-instruction inside {ip:#x}+{delta:#x}; refusing to place INT3 uprobe"
            ));
        }
        if ip > static_va {
            break;
        }
    }
    Err(format!("failed to reach instruction boundary at {static_va:#x} from anchor {:#x}", decode_span.start))
}

fn is_known_code_anchor(image: &Image, static_va: u64) -> bool {
    image.metadata.entry == Some(static_va)
        || image.metadata.exports.contains(&static_va)
        || image.metadata.function_starts.binary_search(&static_va).is_ok()
        || image.symbols.binary_search_by_key(&static_va, |(addr, _)| *addr).is_ok()
}

#[must_use]
pub fn evaluate_unwind_at(image: &Image, static_va: u64) -> (UnwindEntryStatus, Option<String>) {
    let Ok(file) = crate::image_format::parse(&image.data) else {
        return (UnwindEntryStatus::Unavailable { detail: "elf_reparse_failed".to_owned() }, None);
    };
    let Some(eh_sec) = file.section_by_name(".eh_frame") else {
        return (UnwindEntryStatus::Unavailable { detail: "missing_eh_frame".to_owned() }, None);
    };
    let Ok(eh_bytes) = eh_sec.data() else {
        return (UnwindEntryStatus::Unavailable { detail: "unreadable_eh_frame".to_owned() }, None);
    };

    let eh_frame = EhFrame::new(eh_bytes, LittleEndian);
    let mut bases = BaseAddresses::default().set_eh_frame(eh_sec.address());
    if let Some(hdr) = file.section_by_name(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(hdr.address());
    }
    if let Some(text) = file.section_by_name(".text") {
        bases = bases.set_text(text.address());
    }
    if let Some(got) = file.section_by_name(".got") {
        bases = bases.set_got(got.address());
    }

    let Ok(fde) = eh_frame.fde_for_address(&bases, static_va, EhFrame::cie_from_offset) else {
        return (UnwindEntryStatus::Unavailable { detail: "no_fde_for_address".to_owned() }, None);
    };
    let mut ctx = UnwindContext::new();
    let Ok(row) = fde.unwind_info_for_address(&eh_frame, &bases, &mut ctx, static_va) else {
        return (UnwindEntryStatus::Unavailable { detail: "cfi_row_evaluation_failed".to_owned() }, None);
    };

    let ra_reg = fde.cie().return_address_register();
    let ra_rule = row.register(ra_reg);
    match (row.cfa(), ra_rule) {
        (CfaRule::RegisterAndOffset { register, offset: cfa_off }, RegisterRule::Offset(ra_off)) => {
            let Some(disp) = cfa_off.checked_add(ra_off) else {
                return (UnwindEntryStatus::Unavailable { detail: "cfa_ra_offset_overflow".to_owned() }, None);
            };
            if !(MIN_FRAME_DISP..=MAX_FRAME_DISP).contains(&disp) {
                return (UnwindEntryStatus::Unavailable { detail: format!("cfa_ra_disp_out_of_bounds_{disp}") }, None);
            }
            if *register == X86_64::RSP && *cfa_off == 8 && ra_off == -8 {
                (UnwindEntryStatus::StandardRsp8RaMinus8, Some("+0(%sp):x64".to_owned()))
            } else if *register == X86_64::RSP {
                (
                    UnwindEntryStatus::InteriorFrameOffset { base_register: "rsp", disp },
                    Some(format!("{disp:+}(%sp):x64")),
                )
            } else if *register == X86_64::RBP {
                (
                    UnwindEntryStatus::InteriorFrameOffset { base_register: "rbp", disp },
                    Some(format!("{disp:+}(%bp):x64")),
                )
            } else {
                (UnwindEntryStatus::Unavailable { detail: format!("unsupported_cfa_register_{}", register.0) }, None)
            }
        }
        _ => (UnwindEntryStatus::Unavailable { detail: "non_offset_cfa_or_ra_rule".to_owned() }, None),
    }
}

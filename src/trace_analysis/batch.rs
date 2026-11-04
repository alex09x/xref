/*
 * XRef — Bounded inline stack symbolization
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::sync::atomic::{AtomicBool, Ordering};

use super::index::{SymbolIndex, parse_hex};
use super::models::{FrameKind, SymbolizeBatch, SymbolizeRequest};

pub fn symbolize_batch(
    index: &SymbolIndex,
    request: &SymbolizeRequest,
    cancel: Option<&AtomicBool>,
) -> Result<SymbolizeBatch, String> {
    let count: usize = request.stacks.iter().map(|stack| stack.frames.len()).sum();
    if request.stacks.is_empty() || request.stacks.len() > 64 || count > 512 {
        return Err("inline symbolization requires 1..=64 stacks and at most 512 frames".to_owned());
    }
    let verified = index.validate_identity(request.trace_build_id.as_deref())?;
    let mappings = request
        .base
        .as_deref()
        .map(parse_hex)
        .transpose()?
        .map(|base| index.mappings_from_base(base))
        .transpose()?
        .unwrap_or_default();
    let mut frames = Vec::with_capacity(request.stacks.len());
    let mut weights = Vec::with_capacity(request.stacks.len());
    let mut warnings = index.warnings.clone();
    for stack in &request.stacks {
        if stack.frames.is_empty() || stack.frames.len() > super::parse::MAX_STACK_FRAMES || stack.weight == 0 {
            return Err("each stack needs 1..=256 frames and positive weight".to_owned());
        }
        let mut output = Vec::with_capacity(stack.frames.len());
        for (position, input) in stack.frames.iter().enumerate() {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err("symbolization cancelled".to_owned());
            }
            if input.len() > 256 {
                return Err("frame token exceeds 256 bytes".to_owned());
            }
            let kind = if request.frame_kind == FrameKind::Auto {
                if position == 0 { FrameKind::Instruction } else { FrameKind::ReturnAddress }
            } else {
                request.frame_kind
            };
            output.push(index.frame(input, kind, None, &mappings));
        }
        frames.push(output);
        weights.push(stack.weight);
    }
    warnings.push("fde_ranges_and_panic_location_references_are_not_dwarf_function_or_line_proof".to_owned());
    warnings.push("return_address_call_site_is_exact_decoded_call_end_not_direct_edge_proof".to_owned());
    if !verified {
        warnings.push("caller_selected_mapping_not_trace_identity_proof".to_owned());
    }
    Ok(SymbolizeBatch {
        image: index.identity.clone(),
        mapping_evidence: if verified {
            "caller_declared_build_id_matches_selected_image"
        } else {
            "caller_selected_image"
        }
        .to_owned(),
        frames,
        weights,
        warnings,
    })
}

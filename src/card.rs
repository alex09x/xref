/*
 * XRef — Function card summary command
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

pub mod calls;
pub mod exits;
pub mod model;
pub mod render;
pub mod stores;

#[cfg(test)]
mod tests;

use std::io::Write;
use std::ops::Range;

use self::model::{CardInputs, FunctionCard, FunctionSpan};
use crate::commands::Res;
use crate::expr::reg_name;
use crate::graph::resolve_addr;
use crate::image::Image;

/// Generate a function card for the function in `function`.
#[must_use]
pub fn analyze_card(image: &Image, function: &Range<u64>) -> FunctionCard {
    let sig = crate::sig::fn_sig(image, function);
    let (return_registers, exits) = exits::analyze_exits(image, function);
    let stores = stores::analyze_stores(image, function, &sig);
    let (callees, indirect_calls, panic_callees) = calls::analyze_calls(image, function);

    let in_regs: Vec<String> = sig.regs.into_iter().map(reg_name).collect();
    let in_stack: Vec<String> = sig.stack_args.into_iter().map(|idx| format!("stack{idx}")).collect();

    let name = image
        .symbols
        .iter()
        .find(|(addr, _)| *addr == function.start)
        .map(|(_, name)| name.clone());

    FunctionCard {
        function: FunctionSpan {
            start: function.start,
            end: function.end,
            name,
        },
        inputs: CardInputs {
            registers: in_regs,
            stack_args: in_stack,
        },
        return_registers,
        stores,
        callees,
        indirect_calls,
        panic_callees,
        exits,
    }
}

/// CLI command handler for `xref card FN [--json]`.
pub fn card(image: &Image, spec: &str, json: bool, out: &mut dyn Write) -> Res {
    let raw = resolve_addr(image, spec)?;
    let function = image
        .function_at(raw)
        .ok_or_else(|| format!("no function contains {raw:#x}"))?;

    let card_data = analyze_card(image, &function);
    render::render_card(&card_data, json, out)
}

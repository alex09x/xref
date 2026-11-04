/*
 * XRef — Text and JSON rendering for function summary cards
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::io::Write;

use super::model::FunctionCard;
use crate::commands::Res;

fn format_offset(offset: i64) -> String {
    if offset >= 0 { format!("+{offset:#x}") } else { format!("-{:#x}", offset.unsigned_abs()) }
}

/// Render the function card as JSON or formatted text.
pub fn render_card(card: &FunctionCard, json: bool, out: &mut dyn Write) -> Res {
    if json {
        serde_json::to_writer_pretty(&mut *out, card)?;
        writeln!(out)?;
        return Ok(());
    }

    let fn_name = card.function.name.as_deref().map_or(String::new(), |n| format!(" ({n})"));
    writeln!(out, "function {:#x}..{:#x}{fn_name}", card.function.start, card.function.end)?;

    let in_regs = if card.inputs.registers.is_empty() { "none" } else { &card.inputs.registers.join(", ") };
    let in_stack = if card.inputs.stack_args.is_empty() { "none" } else { &card.inputs.stack_args.join(", ") };
    writeln!(out, "inputs:")?;
    writeln!(out, "  registers: {in_regs}")?;
    writeln!(out, "  stack: {in_stack}")?;

    let ret_regs = if card.return_registers.is_empty() { "none" } else { &card.return_registers.join(", ") };
    writeln!(out, "return registers: {ret_regs}")?;

    writeln!(out, "stores:")?;
    if card.stores.is_empty() {
        writeln!(out, "  none")?;
    } else {
        for (base, fields) in &card.stores {
            writeln!(out, "  {base}:")?;
            for field in fields {
                let off_str = format_offset(field.offset);
                let widths: Vec<String> = field.widths.iter().map(|w| format!("{w}")).collect();
                writeln!(out, "    {off_str}: {}", widths.join(", "))?;
            }
        }
    }

    writeln!(out, "callees:")?;
    if card.callees.is_empty() {
        writeln!(out, "  none")?;
    } else {
        for callee in &card.callees {
            let args_str = if callee.args.is_empty() { String::new() } else { format!("({})", callee.args.join(", ")) };
            writeln!(out, "  {:#x}: {}{args_str}", callee.ip, callee.name)?;
        }
    }

    writeln!(out, "indirect calls:")?;
    if card.indirect_calls.is_empty() {
        writeln!(out, "  none")?;
    } else {
        for ind in &card.indirect_calls {
            writeln!(out, "  {:#x}: {}", ind.ip, ind.target)?;
        }
    }

    writeln!(out, "panics:")?;
    if card.panic_callees.is_empty() {
        writeln!(out, "  none")?;
    } else {
        for panic_call in &card.panic_callees {
            writeln!(out, "  {:#x}: {}", panic_call.ip, panic_call.name)?;
        }
    }

    writeln!(out, "exits:")?;
    if card.exits.is_empty() {
        writeln!(out, "  none")?;
    } else {
        for exit in &card.exits {
            let ret_desc = exit.constant_code.map_or_else(
                || {
                    if exit.return_registers.is_empty() {
                        "ret (void)".to_owned()
                    } else {
                        format!("ret ({})", exit.return_registers.join(", "))
                    }
                },
                |code| {
                    if exit.is_error { format!("ret (rax = {code}) [error]") } else { format!("ret (rax = {code})") }
                },
            );
            writeln!(out, "  {:#x}: {ret_desc}", exit.ip)?;
        }
    }

    Ok(())
}

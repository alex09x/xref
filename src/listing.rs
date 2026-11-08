/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Function listings: the ordered calls of a function and its annotated disassembly.

use std::io::Write;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction};

use crate::commands::{Res, function};
use crate::image::{Image, Slot};
use crate::scan::{branch_target, decode, format};

/// A code address with the function or PLT import stub it starts or lies in.
pub fn describe_code(image: &Image, target: u64) -> String {
    match image.function_at(target) {
        Some(f) if f.start == target => format!("{target:#x}"),
        Some(f) => format!("{target:#x} (in {:#x}+{:#x})", f.start, target - f.start),
        None => crate::runtime::plt_import(image, target)
            .map_or_else(|| format!("{target:#x} (no function)"), |imp| format!("{target:#x} ({imp})")),
    }
}

/// Where a call or jump goes: a direct target, an imported symbol or pointer slot, or a register.
pub fn describe_branch(image: &Image, instruction: &Instruction) -> String {
    if let Some(target) = branch_target(instruction) {
        return describe_code(image, target);
    }
    if instruction.is_ip_rel_memory_operand() {
        let place = instruction.ip_rel_memory_address();
        return match image.slot(place) {
            Some(Slot::Import(name)) => format!("{name} via {place:#x}"),
            Some(Slot::Pointer(target)) => format!("{} via {place:#x}", describe_code(image, target)),
            None => format!("[{place:#x}]"),
        };
    }
    format!("indirect: {}", format(instruction))
}

/// A call, or a jump leaving `function` (a tail call).
pub fn is_call(instruction: &Instruction, function: &Range<u64>) -> bool {
    match instruction.flow_control() {
        FlowControl::Call | FlowControl::IndirectCall => true,
        FlowControl::UnconditionalBranch => branch_target(instruction).is_some_and(|t| !function.contains(&t)),
        FlowControl::IndirectBranch => instruction.is_ip_rel_memory_operand(),
        _ => false,
    }
}

pub fn calls(image: &Image, addr: u64, out: &mut dyn Write) -> Res {
    let f = function(image, addr)?;
    let code = image.code(&f).ok_or("function outside the image")?;
    let dispatches = crate::vtables::dispatches(image, f.start);
    let mut lines = Vec::new();
    decode(code, f.start, |instruction| {
        if is_call(instruction, &f) {
            let kind = if instruction.flow_control() == FlowControl::Call
                || instruction.flow_control() == FlowControl::IndirectCall
            {
                "call"
            } else {
                "jump"
            };
            // An indirect call through constant records: its possible targets.
            let targets = dispatches
                .iter()
                .find(|d| d.ip == instruction.ip())
                .map_or_else(String::new, |d| format!(" -> {}", crate::vtables::describe(d)));
            lines.push(format!("{:#x}  {kind} {}{targets}", instruction.ip(), describe_branch(image, instruction)));
        }
    });
    writeln!(out, "function {:#x}..{:#x}", f.start, f.end)?;
    for line in &lines {
        writeln!(out, "{line}")?;
    }
    writeln!(out, "{} calls", lines.len())?;
    Ok(())
}

fn annotation(image: &Image, instruction: &Instruction, function: &Range<u64>) -> Option<String> {
    if is_call(instruction, function) {
        return Some(describe_branch(image, instruction));
    }
    if !instruction.is_ip_rel_memory_operand() {
        return None;
    }
    let place = instruction.ip_rel_memory_address();
    match image.slot(place) {
        Some(Slot::Import(name)) => Some(name.to_owned()),
        Some(Slot::Pointer(target)) => Some(
            image.preview(target).map_or_else(|| format!("-> {target:#x}"), |text| format!("-> {target:#x} {text:?}")),
        ),
        None => image.preview(place).map(|text| format!("{text:?}")),
    }
}

pub fn asm(image: &Image, addr: u64, from: Option<u64>, to: Option<u64>, out: &mut dyn Write) -> Res {
    let f = function(image, addr)?;
    let code = image.code(&f).ok_or("function outside the image")?;
    let shown = from.unwrap_or(f.start)..to.unwrap_or(f.end);
    let mut lines = Vec::new();
    decode(code, f.start, |instruction| {
        if shown.contains(&instruction.ip()) {
            let text = format(instruction);
            let ip = instruction.ip();
            lines.push(
                annotation(image, instruction, &f)
                    .map_or_else(|| format!("{ip:#x}  {text}"), |note| format!("{ip:#x}  {text:<48} ; {note}")),
            );
        }
    });
    writeln!(out, "function {:#x}..{:#x}", f.start, f.end)?;
    for line in &lines {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{asm, calls, describe_code, is_call};
    use crate::image::{Image, Segment};
    use crate::scan::decode;

    fn instructions(bytes: &[u8], ip: u64) -> Vec<iced_x86::Instruction> {
        let mut all = Vec::new();
        decode(bytes, ip, |instruction| all.push(*instruction));
        all
    }

    #[test]
    fn calls_include_tail_jumps_but_not_local_jumps() {
        // call +0; jmp +0 (to the next instruction, inside); jmp rel32 far away; jmp rax.
        let code = [0xe8, 0, 0, 0, 0, 0xeb, 0x00, 0xe9, 0x00, 0x10, 0, 0, 0xff, 0xe0];
        let function = 0x1000..0x1000 + code.len() as u64;
        let flags: Vec<bool> = instructions(&code, 0x1000).iter().map(|i| is_call(i, &function)).collect();
        assert_eq!(flags, [true, false, true, false]);
    }

    #[test]
    fn listings_annotate_imports_pointers_and_tail_jumps() {
        let mut data = vec![0u8; 0x300];
        data[0x100..0x108].copy_from_slice(b"text msg");
        // jmp [rip + 0x100] (import); call [rip + 0x110] (ptr); call [rip + 0x120] (raw);
        // lea rax, [rip + 0x100] (import); lea rax, [rip + 0x110] (ptr->text); lea rax, [rip + 0x118] (ptr->code);
        let code: &[u8] = &[
            0xff, 0x25, 0xfa, 0x00, 0x00, 0x00, // 0x1000: jmp [0x1100] (import)
            0xff, 0x15, 0x04, 0x01, 0x00, 0x00, // 0x1006: call [0x1110] (ptr)
            0xff, 0x15, 0x0e, 0x01, 0x00, 0x00, // 0x100c: call [0x1120] (none)
            0x48, 0x8d, 0x05, 0xe7, 0x00, 0x00, 0x00, // 0x1012: lea rax, [0x1100] (import)
            0x48, 0x8d, 0x05, 0xf0, 0x00, 0x00, 0x00, // 0x1019: lea rax, [0x1110] (ptr->text)
            0x48, 0x8d, 0x05, 0xf1, 0x00, 0x00, 0x00, // 0x1020: lea rax, [0x1118] (ptr->raw)
        ];
        data[..code.len()].copy_from_slice(code);
        let end = 0x1000 + code.len() as u64;
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: std::iter::once(0x1000..end).collect(),
            pointers: vec![(0x1110, 0x1100), (0x1118, 0x1200)],
            imports: vec![(0x1100, "puts".to_owned())],
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        assert_eq!(describe_code(&image, 0x1002), "0x1002 (in 0x1000+0x2)");
        assert_eq!(describe_code(&image, 0x9000), "0x9000 (no function)");
        let mut out = Vec::new();
        assert!(calls(&image, 0x1000, &mut out).is_ok());
        assert!(asm(&image, 0x1000, None, None, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("jump puts via 0x1100") && text.contains("-> 0x1200"), "{text}");
    }
}

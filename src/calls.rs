/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Call-site expression lifting: target/runtime/import resolution, parameter arity selection, and
//! Rust `&str` / `core::fmt::Arguments` string slice recovery.

use std::collections::BTreeSet;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::expr::{ABI_ARGS, State, op_expr};
use crate::image::{Image, Slot};
use crate::locations::Location;
use crate::runtime::{RuntimeFn, RuntimeMap};
use crate::scan::{branch_target, decode};
use crate::sig::{callee_float_abi, fn_sig, import_arity};
use crate::simplify::resolve_str_slice;
use crate::tables::Table;

pub fn leaders_and_stack(
    bytes: &[u8],
    function: &Range<u64>,
    tables: &[Table],
) -> (BTreeSet<u64>, BTreeSet<u64>, bool) {
    let mut targets: BTreeSet<u64> = tables.iter().flat_map(|t| t.arms.iter().copied()).collect();
    let mut leaders = targets.clone();
    let mut stack_lea = false;
    decode(bytes, function.start, |instruction| {
        if instruction.mnemonic() == Mnemonic::Lea && instruction.memory_base().full_register() == Register::RSP {
            stack_lea = true;
        }
        if let Some(target) = branch_target(instruction)
            && function.contains(&target)
        {
            targets.insert(target);
            leaders.insert(target);
        }
        if !matches!(instruction.flow_control(), FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall) {
            let next = instruction.next_ip();
            if next > function.start && function.contains(&next) {
                leaders.insert(next);
            }
        }
    });
    (leaders, targets, stack_lea)
}

fn parse_lit(s: &str) -> Option<usize> {
    s.strip_prefix("0x").and_then(|h| usize::from_str_radix(h, 16).ok()).or_else(|| s.parse::<usize>().ok())
}

fn resolve_call_strings(img: &Image, state: &mut State, regs: &[Register], rt_kind: Option<RuntimeFn>, name: &str) {
    let fmt_pair = rt_kind.and_then(RuntimeFn::fmt_args_pair);
    if let Some((pi, li)) = fmt_pair
        && let (Some(&pr), Some(&lr)) = (ABI_ARGS.get(pi), ABI_ARGS.get(li))
        && let Some(&place) = state.rodata_ptrs.get(&pr)
        && let Some(raw) = state.regs.get(&lr).and_then(|s| parse_lit(s))
        && let Some(lit) = resolve_str_slice(img, place, raw, true)
    {
        state.regs.insert(pr, lit);
        state.regs.insert(lr, (raw >> 1).to_string());
    }
    if matches!(name, "bcmp" | "memcmp" | "strncmp")
        && regs.len() >= 3
        && let Some(n) = state.regs.get(&Register::RDX).and_then(|s| parse_lit(s))
    {
        for r in [Register::RDI, Register::RSI] {
            if let Some(&place) = state.rodata_ptrs.get(&r)
                && let Some(lit) = resolve_str_slice(img, place, n, false)
            {
                state.regs.insert(r, lit);
            }
        }
    }
    for pair in ABI_ARGS.windows(2) {
        if fmt_pair.is_some_and(|(pi, li)| ABI_ARGS.get(pi) == Some(&pair[0]) && ABI_ARGS.get(li) == Some(&pair[1])) {
            continue;
        }
        if regs.contains(&pair[0])
            && regs.contains(&pair[1])
            && let Some(&place) = state.rodata_ptrs.get(&pair[0])
            && let Some(raw) = state.regs.get(&pair[1]).and_then(|s| parse_lit(s))
            && let Some(lit) = resolve_str_slice(img, place, raw, false)
        {
            state.regs.insert(pair[0], lit);
        }
    }
}

pub fn call_expr(
    img: &Image,
    locations: &[Location],
    runtime: &RuntimeMap,
    state: &mut State,
    instruction: &Instruction,
    preset_regs: Option<&[Register]>,
) -> (Option<u64>, String) {
    let (target, call, _) = call_expr_abi(img, locations, runtime, state, instruction, preset_regs);
    (target, call)
}

/// [`call_expr`] plus the scalar float type the direct callee returns in `xmm0`; the callee's
/// float parameters (`xmm0`..`xmm7`) follow the integer arguments.
pub fn call_expr_abi(
    img: &Image,
    locations: &[Location],
    runtime: &RuntimeMap,
    state: &mut State,
    instruction: &Instruction,
    preset_regs: Option<&[Register]>,
) -> (Option<u64>, String, Option<&'static str>) {
    let active: Vec<Register> = ABI_ARGS.into_iter().filter(|r| state.regs.contains_key(r)).collect();
    let rip_ptr =
        instruction.is_ip_rel_memory_operand().then(|| img.slot(instruction.ip_rel_memory_address())).flatten();
    let target = branch_target(instruction).or(if let Some(Slot::Pointer(t)) = rip_ptr { Some(t) } else { None });
    let rt_kind = target.and_then(|t| runtime.get(t));
    let name = if let Some(t) = target {
        runtime.label(img, t).map_or_else(|| format!("fn_{t:x}"), str::to_owned)
    } else if instruction.op0_kind() == OpKind::Register {
        let r = instruction.op0_register().full_register();
        state.fn_saved.get(&r).cloned().unwrap_or_else(|| state.reg(r))
    } else {
        op_expr(img, locations, state, instruction, 0)
    };
    let regs = preset_regs.map_or_else(
        || {
            let known_arity = rt_kind.and_then(RuntimeFn::arity).or_else(|| import_arity(&name));
            match (known_arity, target.and_then(|t| img.function_at(t).filter(|f| f.start == t))) {
                (Some(arity), _) => ABI_ARGS[..arity].to_vec(),
                (None, Some(f)) => {
                    let sig = fn_sig(img, &f);
                    if sig.exact {
                        sig.regs
                    } else {
                        ABI_ARGS.into_iter().filter(|r| state.regs.contains_key(r) || sig.regs.contains(r)).collect()
                    }
                }
                (None, None) => active,
            }
        },
        <[Register]>::to_vec,
    );
    resolve_call_strings(img, state, &regs, rt_kind, &name);
    let mut rendered: Vec<String> = regs.into_iter().map(|r| state.reg(r)).collect();
    rendered.extend(state.pushed.drain(..).rev());
    let (floats, float_ret) = target.map_or_else(|| (Vec::new(), None), |t| callee_float_abi(img, t));
    rendered.extend(floats.into_iter().map(|p| state.reg(p.reg())));
    (target, format!("{name}({})", rendered.join(", ")), float_ret)
}

#[cfg(test)]
mod tests {
    use crate::c::c_one;
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;

    #[test]
    fn resolves_saved_imports_runtime_strings_saturating_and_tuples() {
        let mut data = vec![0u8; 0x400];
        data[0x220..0x224].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
        data[0x320..0x329].copy_from_slice(b"hello txt");
        data[0x340..0x361].copy_from_slice(b"\x20index out of bounds: the len is ");
        data[0x240..0x24e]
            .copy_from_slice(&[0x48, 0x8d, 0x3d, 0xf9, 0x00, 0x00, 0x00, 0xe8, 0x14, 0x00, 0x00, 0x00, 0x0f, 0x0b]);
        data[0x260] = 0xc3;
        let f3: &[u8] = &[
            0x4c, 0x8b, 0x3d, 0xa1, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc5, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc7, 0x01,
            0x49, 0x0f, 0x42, 0xfd, 0x41, 0xff, 0xd7, 0xe8, 0x92, 0xff, 0xff, 0xff, 0x48, 0x01, 0xd0, 0x48, 0x8d, 0x3d,
            0x88, 0x00, 0x00, 0x00, 0xbe, 0x0b, 0x00, 0x00, 0x00, 0xe8, 0xbe, 0xff, 0xff, 0xff, 0x48, 0x89, 0xfa, 0xc3,
        ];
        data[0x270..0x270 + f3.len()].copy_from_slice(f3);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
            functions: vec![0x1220..0x1224, 0x1240..0x124e, 0x1260..0x1261, 0x1270..0x1270 + f3.len() as u64],
            pointers: Vec::new(),
            imports: vec![(0x1318, "memcpy".to_owned())],
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        let rt = RuntimeMap::detect(&image);
        let (_, t3) = c_one(&image, &[], &rt, 0x1270, None, None).unwrap_or_default();
        assert!(t3.contains("memcpy(") && t3.contains(") = fn_1220(") && t3.contains("return ("), "{t3}");
        assert!(t3.contains("rust_panic_fmt(\"hello\", 5, ") && t3.contains("saturating_add("), "{t3}");
        assert!(c_one(&image, &[], &rt, 0x1260, None, None).unwrap_or_default().1.contains("rust_panic_fmt"));
    }

    #[test]
    fn avoids_unproven_packed_rodata_literals_while_slicing_known_lengths() {
        let mut data = vec![0u8; 0x300];
        let packed = b"called `Result::unwrap()` on an `Err` value0001020304050607080910111213";
        data[0x180..0x180 + packed.len()].copy_from_slice(packed);
        data[0x1e0..0x1ea].copy_from_slice(b"while (->\n");
        // 0x1000: callee taking (rdi, rsi) via `lea rsi, [rsi*2+1]; lea rax, [rdi+rsi]; ret`
        data[0x00..0x0d]
            .copy_from_slice(&[0x48, 0x8d, 0x34, 0x75, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x04, 0x37, 0xc3]);
        // 0x1020: lea rdi, [rip+0x159] (0x1180); mov esi, 43; call 0x1000; ret
        let caller: &[u8] = &[
            0x48, 0x8d, 0x3d, 0x59, 0x01, 0x00, 0x00, 0xbe, 0x2b, 0x00, 0x00, 0x00, 0xe8, 0xd0, 0xff, 0xff, 0xff, 0xc3,
        ];
        data[0x20..0x20 + caller.len()].copy_from_slice(caller);
        // 0x1050: lea rax, [rip+0x129] (0x1180); mov [rdi], rax; ret (standalone unproven length)
        let stand: &[u8] = &[0x48, 0x8d, 0x05, 0x29, 0x01, 0x00, 0x00, 0x48, 0x89, 0x07, 0xc3];
        data[0x50..0x50 + stand.len()].copy_from_slice(stand);
        // 0x1070: mov rsi, rdi; lea rdi, [rip+0x166] (0x11e0); mov edx, 7; jmp [rip+0xe4] (0x1168 bcmp)
        let bcmp_fn: &[u8] = &[
            0x48, 0x89, 0xfe, 0x48, 0x8d, 0x3d, 0x66, 0x01, 0x00, 0x00, 0xba, 0x07, 0x00, 0x00, 0x00, 0xff, 0x25, 0xe3,
            0x00, 0x00, 0x00,
        ];
        data[0x70..0x70 + bcmp_fn.len()].copy_from_slice(bcmp_fn);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: vec![
                0x1000..0x100d,
                0x1020..0x1020 + caller.len() as u64,
                0x1050..0x1050 + stand.len() as u64,
                0x1070..0x1070 + bcmp_fn.len() as u64,
            ],
            pointers: Vec::new(),
            imports: vec![(0x1168, "bcmp".to_owned())],
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        let rt = RuntimeMap::detect(&image);
        let (_, c_call) = c_one(&image, &[], &rt, 0x1020, None, None).unwrap_or_default();
        assert!(c_call.contains("\"called `Result::unwrap()` on an `Err` value\", 43"), "{c_call}");
        assert!(!c_call.contains("00010203"), "{c_call}");

        let (_, c_stand) = c_one(&image, &[], &rt, 0x1050, None, None).unwrap_or_default();
        assert!(c_stand.contains("0x1180") && !c_stand.contains("00010203"), "{c_stand}");

        let (_, c_bcmp) = c_one(&image, &[], &rt, 0x1070, None, None).unwrap_or_default();
        assert!(c_bcmp.contains("bcmp(\"while (\", arg_0, 7)"), "{c_bcmp}");
    }
}

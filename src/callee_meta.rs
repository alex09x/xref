/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Factual callee metadata, standard C/POSIX PLT signatures, and panic-path sanitization.

use std::collections::BTreeSet;
use std::ops::Range;

use iced_x86::{FlowControl, InstructionInfoFactory, OpAccess, Register};

use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::locations::Location;
use crate::runtime::{RuntimeFn, RuntimeMap, plt_import};
use crate::scan::decode;
use crate::source::location_at;

pub struct ImportSig {
    pub ret: &'static str,
    pub params: &'static [(&'static str, &'static str)],
    pub noreturn: bool,
}

/// Strips local build-host prefixes (`/home/...`, `/Users/...`, rustup/cargo sysroots) from panic paths.
pub fn sanitize_panic_path(raw: &str) -> String {
    if let Some((_, lib_rel)) = raw.split_once("/library/") {
        return lib_rel.to_owned();
    }
    if let Some((_, reg_rel)) = raw.split_once("/.cargo/registry/src/") {
        return reg_rel.split_once('/').map_or_else(|| reg_rel.to_owned(), |(_, crate_rel)| crate_rel.to_owned());
    }
    for prefix in ["/home/", "/Users/"] {
        if let Some(after_root) = raw.strip_prefix(prefix) {
            let after_user = after_root.split_once('/').map_or(after_root, |(_, rest)| rest);
            if let Some((_, src_rel)) = after_user.rsplit_once("/src/") {
                return format!("src/{src_rel}");
            }
            return after_user.rsplit_once('/').map_or_else(
                || after_user.to_owned(),
                |(parent, file)| {
                    let dir = parent.rsplit('/').next().unwrap_or(parent);
                    if dir.is_empty() { file.to_owned() } else { format!("{dir}/{file}") }
                },
            );
        }
    }
    raw.to_owned()
}

pub fn import_sig(raw_name: &str) -> Option<ImportSig> {
    let name = raw_name.split('@').next().unwrap_or(raw_name);
    Some(match name {
        "abort" => ImportSig { ret: "noreturn void", params: &[], noreturn: true },
        "_Unwind_Resume" => ImportSig { ret: "noreturn void", params: &[("void *", "exc")], noreturn: true },
        "__errno_location" => ImportSig { ret: "i32 *", params: &[], noreturn: false },
        "malloc" => ImportSig { ret: "void *", params: &[("usize", "size")], noreturn: false },
        "calloc" => ImportSig { ret: "void *", params: &[("usize", "nmemb"), ("usize", "size")], noreturn: false },
        "realloc" => ImportSig { ret: "void *", params: &[("void *", "ptr"), ("usize", "size")], noreturn: false },
        "free" => ImportSig { ret: "void", params: &[("void *", "ptr")], noreturn: false },
        "strlen" => ImportSig { ret: "usize", params: &[("const char *", "s")], noreturn: false },
        "strcmp" => {
            ImportSig { ret: "i32", params: &[("const char *", "s1"), ("const char *", "s2")], noreturn: false }
        }
        "strncmp" => ImportSig {
            ret: "i32",
            params: &[("const char *", "s1"), ("const char *", "s2"), ("usize", "n")],
            noreturn: false,
        },
        "memcpy" | "memmove" => ImportSig {
            ret: "void *",
            params: &[("void *", "dst"), ("const void *", "src"), ("usize", "n")],
            noreturn: false,
        },
        "memset" => {
            ImportSig { ret: "void *", params: &[("void *", "dst"), ("i32", "c"), ("usize", "n")], noreturn: false }
        }
        "memcmp" | "bcmp" => ImportSig {
            ret: "i32",
            params: &[("const void *", "s1"), ("const void *", "s2"), ("usize", "n")],
            noreturn: false,
        },
        "memchr" => ImportSig {
            ret: "const void *",
            params: &[("const void *", "s"), ("i32", "c"), ("usize", "n")],
            noreturn: false,
        },
        "read" => {
            ImportSig { ret: "isize", params: &[("i32", "fd"), ("void *", "buf"), ("usize", "count")], noreturn: false }
        }
        "write" => ImportSig {
            ret: "isize",
            params: &[("i32", "fd"), ("const void *", "buf"), ("usize", "count")],
            noreturn: false,
        },
        "close" => ImportSig { ret: "i32", params: &[("i32", "fd")], noreturn: false },
        "munmap" => ImportSig { ret: "i32", params: &[("void *", "addr"), ("usize", "len")], noreturn: false },
        "mprotect" => {
            ImportSig { ret: "i32", params: &[("void *", "addr"), ("usize", "len"), ("i32", "prot")], noreturn: false }
        }
        _ => return None,
    })
}

fn runtime_sig_note(rt: RuntimeFn) -> String {
    let spec = match rt {
        RuntimeFn::PanicBoundsCheck => "(index, len, loc) -> noreturn",
        RuntimeFn::PanicFmt => "(fmt_pieces, count, loc) -> noreturn",
        RuntimeFn::UnwrapFailed => "(msg_ptr, msg_len, val_ptr, vtable, loc) -> noreturn",
        RuntimeFn::SliceIndexFail => "(start, end, loc) -> noreturn",
        RuntimeFn::PanicInCleanup | RuntimeFn::PanicNounwind | RuntimeFn::CapacityOverflow => "() -> noreturn",
        RuntimeFn::OnceCall => "(once_state, closure_ptr) -> void",
        RuntimeFn::FmtWrite => "(out_ptr, vtable, pieces, count) -> u8",
        RuntimeFn::Alloc => "(size, align) -> void *",
        RuntimeFn::Dealloc => "(ptr, size, align) -> void",
    };
    format!("[runtime] {}{spec}", rt.name())
}

pub fn is_fn_noreturn(image: &Image, func: &Range<u64>) -> bool {
    if let Some(imp) = plt_import(image, func.start)
        && import_sig(imp).is_some_and(|s| s.noreturn)
    {
        return true;
    }
    let Some(bytes) = image.code(func) else { return false };
    let (mut has_ret, mut has_tail, mut has_ins) = (false, false, false);
    decode(bytes, func.start, |ins| {
        has_ins = true;
        if ins.flow_control() == FlowControl::Return {
            has_ret = true;
        } else if (ins.flow_control() == FlowControl::UnconditionalBranch && is_call(ins, func))
            || ins.flow_control() == FlowControl::IndirectBranch
        {
            has_tail = true;
        }
    });
    has_ins && !has_ret && !has_tail
}

pub fn is_target_noreturn(image: &Image, runtime: &RuntimeMap, target: u64) -> bool {
    if let Some(rt) = runtime.get(target) {
        return matches!(
            rt,
            RuntimeFn::PanicBoundsCheck
                | RuntimeFn::PanicFmt
                | RuntimeFn::UnwrapFailed
                | RuntimeFn::SliceIndexFail
                | RuntimeFn::PanicInCleanup
                | RuntimeFn::PanicNounwind
                | RuntimeFn::CapacityOverflow
        );
    }
    if let Some(imp) = plt_import(image, target)
        && import_sig(imp).is_some_and(|s| s.noreturn)
    {
        return true;
    }
    image.function_at(target).filter(|f| f.start == target).is_some_and(|f| is_fn_noreturn(image, &f))
}

pub fn describe_callee(image: &Image, locs: &[Location], runtime: &RuntimeMap, target: u64) -> Option<String> {
    if let Some(rt) = runtime.get(target) {
        return Some(runtime_sig_note(rt));
    }
    if let Some(imp) = plt_import(image, target) {
        if let Some(sig) = import_sig(imp) {
            let ps: Vec<String> = sig.params.iter().map(|(ty, nm)| format!("{ty} {nm}")).collect();
            let nr = if sig.noreturn { " [noreturn]" } else { "" };
            return Some(format!("[PLT] {} {}({}){nr}", sig.ret, imp.split('@').next().unwrap_or(imp), ps.join(", ")));
        }
        return Some(format!("[PLT] {imp}"));
    }
    let f = image.function_at(target).filter(|f| f.start == target)?;
    let bytes = image.code(&f)?;
    let mut parts = Vec::new();
    if is_fn_noreturn(image, &f) {
        parts.push("noreturn".to_owned());
    }
    let (mut first_loc, mut rdi_writes, mut callees, mut rdi_alive) = (None, BTreeSet::new(), Vec::new(), true);
    let mut factory = InstructionInfoFactory::new();
    decode(bytes, f.start, |ins| {
        if first_loc.is_none()
            && ins.is_ip_rel_memory_operand()
            && let Some(loc) = location_at(locs, ins.ip_rel_memory_address())
        {
            first_loc = Some(format!("{}:{}", sanitize_panic_path(&loc.file), loc.line));
        }
        let info = factory.info(ins);
        if rdi_alive {
            for m in info.used_memory() {
                if !ins.is_ip_rel_memory_operand()
                    && m.base().full_register() == Register::RDI
                    && m.index() == Register::None
                    && matches!(
                        m.access(),
                        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
                    )
                {
                    let d = m.displacement().cast_signed();
                    if (0..=0x80).contains(&d) {
                        rdi_writes.insert(d);
                    }
                }
            }
        }
        if info.used_registers().iter().any(|r| {
            r.register().full_register() == Register::RDI
                && matches!(
                    r.access(),
                    OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
                )
        }) || matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall)
        {
            rdi_alive = false;
        }
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::UnconditionalBranch)
            && let Some(ct) = call_target(image, ins)
            && ct != target
            && callees.len() < 3
        {
            let label = runtime.label(image, ct).map_or_else(|| format!("fn_{ct:x}"), str::to_owned);
            if !callees.contains(&label) {
                callees.push(label);
            }
            if first_loc.is_none()
                && f.end - f.start <= 64
                && let Some(sub_f) = image.function_at(ct).filter(|sf| sf.start == ct)
                && let Some(sub_b) = image.code(&sub_f)
            {
                decode(sub_b, sub_f.start, |sins| {
                    if first_loc.is_none()
                        && sins.is_ip_rel_memory_operand()
                        && let Some(loc) = location_at(locs, sins.ip_rel_memory_address())
                    {
                        first_loc = Some(format!("{}:{}", sanitize_panic_path(&loc.file), loc.line));
                    }
                });
            }
        }
    });
    if let Some(loc) = first_loc {
        parts.push(format!("source {loc}"));
    }
    if !rdi_writes.is_empty() {
        let offs: Vec<String> = rdi_writes.iter().take(4).map(|d| format!("+{d:#x}")).collect();
        parts.push(format!("writes arg_0 ({})", offs.join(", ")));
    }
    if !callees.is_empty() {
        parts.push(format!("calls {}", callees.join(", ")));
    }
    (!parts.is_empty()).then(|| format!("fn_{target:x}: {}", parts.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::{describe_callee, import_sig, is_fn_noreturn, sanitize_panic_path};
    use crate::c::c_one;
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;

    #[test]
    fn sanitizes_sysroot_registry_and_home_paths() {
        assert_eq!(
            sanitize_panic_path("/home/user/.rustup/toolchains/stable/lib/rustlib/src/rust/library/core/src/str.rs"),
            "core/src/str.rs"
        );
        assert_eq!(sanitize_panic_path("/rustc/abc123/library/alloc/src/vec/mod.rs"), "alloc/src/vec/mod.rs");
        assert_eq!(sanitize_panic_path("/Users/dev/work/proj/src/loops.rs"), "src/loops.rs");
        assert!(import_sig("bcmp@GLIBC_2.2.5").is_some_and(|s| s.params.len() == 3 && !s.noreturn));
    }

    #[test]
    fn preserves_single_call_eval_tail_return_braces_cfg_args_thunk_ret_and_read_only_cmp() {
        let mut data = vec![0xccu8; 0x300];
        // 0x1000 side_effect: mov eax, 1; ret
        let f_side: &[u8] = &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        // 0x1020 double_result: call 0x1000 (-0x25); add rax, rax; ret
        let f_dbl: &[u8] = &[0xe8, 0xdb, 0xff, 0xff, 0xff, 0x48, 0x01, 0xc0, 0xc3];
        // 0x1040 thunk: jmp rdi
        let f_thunk: &[u8] = &[0xff, 0xe7];
        // 0x1060 via_thunk: call 0x1040 (-0x25); add rax, 1; ret
        let f_via: &[u8] = &[0xe8, 0xdb, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 0x01, 0xc3];
        // 0x1080 reader: cmp qword ptr [rdi], 0; sete al; ret
        let f_reader: &[u8] = &[0x48, 0x83, 0x3f, 0x00, 0x0f, 0x94, 0xc0, 0xc3];
        // 0x10a0 fallthrough_arg: mov esi, 42; test edx, edx; jz +2 (0x10ab); call rdi; xor eax, eax; ret
        let f_fall: &[u8] = &[0xbe, 0x2a, 0x00, 0x00, 0x00, 0x85, 0xd2, 0x74, 0x02, 0xff, 0xd7, 0x31, 0xc0, 0xc3];
        // 0x10c0 tail_void: test edi, edi; jnz +2 (0x10c6); jmp rsi; mov qword ptr [rdx], 9; ret
        let f_tail: &[u8] = &[0x85, 0xff, 0x75, 0x02, 0xff, 0xe6, 0x48, 0xc7, 0x02, 0x09, 0x00, 0x00, 0x00, 0xc3];
        // 0x10e0 caller_tail: call 0x10c0 (-0x25); xor eax, eax; ret
        let f_use: &[u8] = &[0xe8, 0xdb, 0xff, 0xff, 0xff, 0x31, 0xc0, 0xc3];
        // 0x1100 sum_arr: mov rax, [rdi+rsi*8]; add rax, [rdi+rsi*8+8]; ret
        let f_sum: &[u8] = &[0x48, 0x8b, 0x04, 0xf7, 0x48, 0x03, 0x44, 0xf7, 0x08, 0xc3];
        // 0x1120 invoke: test rdi, rdi; js +7; call rsi; add rax, 1; ret; xor eax, eax; ret
        let f_inv: &[u8] = &[0x48, 0x85, 0xff, 0x78, 0x07, 0xff, 0xd6, 0x48, 0x83, 0xc0, 0x01, 0xc3, 0x31, 0xc0, 0xc3];

        data[..f_side.len()].copy_from_slice(f_side);
        data[0x20..0x20 + f_dbl.len()].copy_from_slice(f_dbl);
        data[0x40..0x40 + f_thunk.len()].copy_from_slice(f_thunk);
        data[0x60..0x60 + f_via.len()].copy_from_slice(f_via);
        data[0x80..0x80 + f_reader.len()].copy_from_slice(f_reader);
        data[0xa0..0xa0 + f_fall.len()].copy_from_slice(f_fall);
        data[0xc0..0xc0 + f_tail.len()].copy_from_slice(f_tail);
        data[0xe0..0xe0 + f_use.len()].copy_from_slice(f_use);
        data[0x100..0x100 + f_sum.len()].copy_from_slice(f_sum);
        data[0x120..0x120 + f_inv.len()].copy_from_slice(f_inv);

        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: vec![
                0x1000..0x1000 + f_side.len() as u64,
                0x1020..0x1020 + f_dbl.len() as u64,
                0x1040..0x1040 + f_thunk.len() as u64,
                0x1060..0x1060 + f_via.len() as u64,
                0x1080..0x1080 + f_reader.len() as u64,
                0x10a0..0x10a0 + f_fall.len() as u64,
                0x10c0..0x10c0 + f_tail.len() as u64,
                0x10e0..0x10e0 + f_use.len() as u64,
                0x1100..0x1100 + f_sum.len() as u64,
                0x1120..0x1120 + f_inv.len() as u64,
            ],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::detect(&img);

        let (_, c_dbl) = c_one(&img, &[], &rt, 0x1020, None, None).unwrap_or_default();
        assert_eq!(c_dbl.matches("fn_1000(").count(), 1, "{c_dbl}");

        assert!(!is_fn_noreturn(&img, &(0x1040..0x1042)));
        let (_, c_via) = c_one(&img, &[], &rt, 0x1060, None, None).unwrap_or_default();
        assert!(c_via.contains("return (fn_1040(arg_0) + 1);"), "{c_via}");

        assert!(describe_callee(&img, &[], &rt, 0x1080).is_none());

        let (_, c_fall) = c_one(&img, &[], &rt, 0x10a0, None, None).unwrap_or_default();
        assert!(c_fall.contains("v_1 = 42;") && c_fall.contains("arg_0(v_1);"), "{c_fall}");

        let (_, c_tail) = c_one(&img, &[], &rt, 0x10c0, None, None).unwrap_or_default();
        assert!(c_tail.contains("if (arg_0 == 0) {") && c_tail.contains("*(u64 *)(arg_2) = 9;"), "{c_tail}");

        let (_, c_sum) = c_one(&img, &[], &rt, 0x1100, None, None).unwrap_or_default();
        assert!(
            c_sum.contains("unk64 fn_1100(const u64 *arg_0, usize arg_1)")
                && c_sum.contains("((u64 *)arg_0)[arg_1 + 1]")
                && !c_sum.contains("const u64 *v_"),
            "{c_sum}"
        );

        let (_, c_inv) = c_one(&img, &[], &rt, 0x1120, None, None).unwrap_or_default();
        assert!(c_inv.contains("arg_1(arg_0)"), "{c_inv}");
    }
}

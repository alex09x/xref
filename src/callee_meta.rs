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

use iced_x86::{FlowControl, OpKind, Register};

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
        } else if matches!(ins.flow_control(), FlowControl::UnconditionalBranch | FlowControl::IndirectBranch)
            && is_call(ins, func)
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
    decode(bytes, f.start, |ins| {
        if first_loc.is_none()
            && ins.is_ip_rel_memory_operand()
            && let Some(loc) = location_at(locs, ins.ip_rel_memory_address())
        {
            first_loc = Some(format!("{}:{}", sanitize_panic_path(&loc.file), loc.line));
        }
        if rdi_alive
            && ins.op0_kind() == OpKind::Memory
            && !ins.is_ip_rel_memory_operand()
            && ins.memory_base().full_register() == Register::RDI
            && ins.memory_index() == Register::None
        {
            let d = ins.memory_displacement64().cast_signed();
            if (0..=0x80).contains(&d) {
                rdi_writes.insert(d);
            }
        }
        if ins.op0_kind() == OpKind::Register && ins.op0_register().full_register() == Register::RDI {
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
    use super::{import_sig, sanitize_panic_path};

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
}

/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Conservative evidence-backed type inference, provenance headers, C function signatures, and
//! used local variable declarations for `xref c`.

use std::ops::Range;

use iced_x86::{FlowControl, Register};

use crate::callee_meta::{import_sig, is_fn_noreturn, sanitize_panic_path};
use crate::expr::{ABI_ARGS, reg_name};
use crate::image::Image;
use crate::locations::Location;
use crate::runtime::{RuntimeMap, plt_import};
use crate::sig::{FloatRet, FnSig};
use crate::source::location_at;
use crate::ssa_webs::SsaCfg;
use crate::type_prop::LocalTypes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnKind {
    NoReturn,
    VoidUnused,
    Pair,
    Single(&'static str),
    /// Scalar `f64`/`f32` in `xmm0`.
    Float(&'static str),
}

pub struct TypeFacts {
    pub ret_kind: ReturnKind,
    pub header_block: String,
    pub sig_line: String,
    pub local_types: LocalTypes,
    /// Scalar float type also in `xmm0` on every return path when the integer result was preferred.
    pub xmm0_note: Option<&'static str>,
}

/// Prefers a scalar float in `xmm0` unless `rax` also holds a written integer result candidate;
/// then keeps the integer kind and notes the `xmm0` value. When every caller is known and none
/// reads `xmm0` after the call, the float is a leftover (`*p = x * y; ret`), not a result.
fn with_float_return(
    kind: ReturnKind,
    note: String,
    float_ret: Option<FloatRet>,
    xmm0_used: impl FnOnce() -> bool,
) -> (ReturnKind, String, Option<&'static str>) {
    let Some(fr) = float_ret.filter(|_| xmm0_used()) else { return (kind, note, None) };
    let ty = fr.ty;
    match kind {
        ReturnKind::VoidUnused => {
            (ReturnKind::Float(ty), format!("{ty} in xmm0 (scalar SSE result on every return path; rax unread)"), None)
        }
        // Callers reading rax (or rax:rdx) after the call do not make it an integer result when no
        // return path writes rax.
        ReturnKind::Single(_) | ReturnKind::Pair if !fr.rax_written => {
            (ReturnKind::Float(ty), format!("{ty} in xmm0 (scalar SSE result on every return path)"), None)
        }
        ReturnKind::Single(_) | ReturnKind::Pair => {
            (kind, format!("{note}; xmm0 also holds a scalar {ty} on every return path"), Some(ty))
        }
        ReturnKind::NoReturn | ReturnKind::Float(_) => (kind, note, None),
    }
}

fn clean_c_ident(raw: &str) -> Option<String> {
    let base = raw.split('@').next().unwrap_or(raw);
    if base.is_empty() || base.len() > 48 || base.starts_with("_ZN") || base.starts_with("_R") {
        return None;
    }
    let ok = base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && base.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    ok.then(|| base.to_owned())
}

fn recover_name(image: &Image, runtime: &RuntimeMap, start: u64) -> (String, String) {
    if let Ok(idx) = image.symbols.binary_search_by_key(&start, |(a, _)| *a) {
        let sym = &image.symbols[idx].1;
        if let Some(id) = clean_c_ident(sym) {
            return (
                id,
                if image.metadata.kind == crate::image_format::Kind::MachO { "Mach-O symbol" } else { "ELF symbol" }
                    .to_owned(),
            );
        }
        return (format!("fn_{start:x}"), format!("synthetic; raw symbol {sym}"));
    }
    if let Some(rt) = runtime.get(start) {
        return (rt.name().to_owned(), "runtime pattern".to_owned());
    }
    if let Some(imp) = plt_import(image, start)
        && let Some(id) = clean_c_ident(imp)
    {
        return (id, "PLT import".to_owned());
    }
    (format!("fn_{start:x}"), "synthetic FDE entry".to_owned())
}

fn collect_panic_anchors(locs: &[Location], ssa: &SsaCfg) -> Vec<String> {
    let mut seen = Vec::new();
    for ins in &ssa.insns {
        if ins.is_ip_rel_memory_operand()
            && let Some(loc) = location_at(locs, ins.ip_rel_memory_address())
        {
            let entry = format!("{}:{}:{}", sanitize_panic_path(&loc.file), loc.line, loc.col);
            if !seen.contains(&entry) && seen.len() < 3 {
                seen.push(entry);
            }
        }
    }
    seen
}

fn infer_param_type(ssa: &SsaCfg, lt: &LocalTypes, ak: usize) -> (&'static str, String) {
    let (fields, has_load, has_store) = ssa.param_fields(ak);
    let pw = ssa.webs.iter().position(|w| w.is_param == Some(ak));
    let ev = pw.map(|w| &lt.web_ev[w]);
    let wty = pw.map_or("unk64", |w| lt.web_ty[w]);
    if wty == "code_ptr" && !ev.is_some_and(crate::type_prop::WebEv::is_int_operand) {
        return ("code_ptr", "invoked via indirect call/jump".to_owned());
    }
    if !fields.is_empty() || has_store || has_load || wty.ends_with('*') {
        let writes: Vec<String> = fields
            .iter()
            .filter(|(_, (_, _, w))| *w > 0)
            .take(4)
            .map(|(o, (sz, _, _))| format!("+{o:#x} ({sz}B)"))
            .collect();
        let reads: Vec<String> = fields
            .iter()
            .filter(|(_, (_, r, _))| *r > 0)
            .take(4)
            .map(|(o, (sz, _, _))| format!("+{o:#x} ({sz}B)"))
            .collect();
        if !writes.is_empty() || has_store || ev.is_some_and(|e| e.stores > 0) {
            let mut note = if writes.is_empty() {
                "dereferenced by store".to_owned()
            } else {
                format!("writes {}", writes.join(", "))
            };
            if ak == 0 && reads.is_empty() && fields.contains_key(&0) && fields.len() >= 2 {
                note.push_str(" [heuristic: out-ptr candidate]");
            }
            let pty = if wty.ends_with('*') && !wty.starts_with("const ") { wty } else { "void *" };
            return (pty, note);
        }
        let note =
            if reads.is_empty() { "dereferenced by load".to_owned() } else { format!("reads {}", reads.join(", ")) };
        let pty = if wty.ends_with('*') { wty } else { "const void *" };
        return (pty, note);
    }
    if let Some((pty, note)) = ev.and_then(|e| e.plt_ty.as_ref()) {
        return (pty, note.clone());
    }
    if let Some(sc) = ev.and_then(|e| e.scale_factor) {
        return ("usize", format!("count/index (scaled by {sc})"));
    }
    match wty {
        "usize" => ("usize", "index/size operand".to_owned()),
        "i64" | "i32" | "i16" | "i8" => (wty, "signed comparison/arithmetic".to_owned()),
        "u8" => ("u8", "8-bit register read".to_owned()),
        "u16" => ("u16", "16-bit register read".to_owned()),
        "u32" => ("u32", "32-bit register read".to_owned()),
        "u64" => ("u64", "unsigned comparison/bitwise".to_owned()),
        _ => ("unk64", "64-bit register (signedness unconstrained)".to_owned()),
    }
}

const fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn infer_return(image: &Image, function: &Range<u64>, ssa: &SsaCfg, lt: &LocalTypes) -> (ReturnKind, String) {
    if is_fn_noreturn(image, function) {
        return (ReturnKind::NoReturn, "noreturn (no return path)".to_owned());
    }
    if ssa.rdx_returned {
        return (ReturnKind::Pair, "unk128_pair in (rax, rdx)".to_owned());
    }
    let st = ssa.caller_stats;
    let cs_s = plural(st.direct_callers);
    if ssa.rax_proven_unused {
        let n = st.direct_callers;
        let all_word = if n == 1 { "1 direct call site" } else { "all" };
        let msg = if n == 1 {
            format!("void (rax proven unread at {all_word})")
        } else {
            format!("void (rax proven unread across all {n} direct call sites)")
        };
        return (ReturnKind::VoidUnused, msg);
    }
    if let Some(imp) = plt_import(image, function.start)
        && let Some(isig) = import_sig(imp)
    {
        return (ReturnKind::Single(isig.ret), format!("{} [PLT signature]", isig.ret));
    }
    let mut ret_webs = Vec::new();
    for (i, ins) in ssa.insns.iter().enumerate() {
        if ins.flow_control() == FlowControl::Return
            && let Some(w) = ssa.metas[i].web_of_read(Register::RAX)
        {
            ret_webs.push(w);
        }
    }
    let ty = if st.ret_rax_bytes() == 1
        || (!ret_webs.is_empty() && ret_webs.iter().all(|&w| ssa.webs[w].only_setcc && !ssa.webs[w].defs.is_empty()))
    {
        "u8"
    } else if !ret_webs.is_empty()
        && ret_webs.iter().all(|&w| lt.web_ty[w] == lt.web_ty[ret_webs[0]] && lt.web_ty[w] != "unk64")
    {
        lt.web_ty[ret_webs[0]]
    } else if !ret_webs.is_empty() && ret_webs.iter().all(|&w| ssa.webs[w].deref_store) {
        "void *"
    } else if !ret_webs.is_empty() && ret_webs.iter().all(|&w| ssa.webs[w].deref_base) {
        "const void *"
    } else {
        "unk64"
    };
    let note = if st.direct_callers > 0 && st.rax_readers == 0 {
        format!("{ty} in rax (0/{} direct call site{cs_s} read immediately; may escape)", st.direct_callers)
    } else if st.direct_callers > 0 {
        format!("{ty} in rax (consumed by {}/{} direct call site{cs_s})", st.rax_readers, st.direct_callers)
    } else {
        format!("{ty} in rax")
    };
    (ReturnKind::Single(ty), note)
}

impl TypeFacts {
    pub fn build(
        image: &Image,
        locs: &[Location],
        runtime: &RuntimeMap,
        function: &Range<u64>,
        sig: &FnSig,
        ssa: &SsaCfg,
    ) -> Self {
        let local_types = LocalTypes::analyze(image, locs, runtime, ssa);
        let (fn_name, name_origin) = recover_name(image, runtime, function.start);
        let (ret_kind, ret_note) = infer_return(image, function, ssa, &local_types);
        let (ret_kind, ret_note, xmm0_note) =
            with_float_return(ret_kind, ret_note, sig.float_ret, || runtime.xmm0_result_used(image, function.start));
        let ret_ty_str = match ret_kind {
            ReturnKind::NoReturn => "noreturn void",
            ReturnKind::VoidUnused => "void",
            ReturnKind::Pair => "unk128_pair",
            ReturnKind::Single(t) | ReturnKind::Float(t) => t,
        };
        let mut c_params = Vec::new();
        let mut param_notes = Vec::new();
        for &reg in &sig.regs {
            if let Some(ak) = ABI_ARGS.iter().position(|&r| r == reg) {
                let (pty, ev) = infer_param_type(ssa, &local_types, ak);
                let sep = if pty.ends_with('*') { "" } else { " " };
                c_params.push(format!("{pty}{sep}arg_{ak}"));
                param_notes.push(format!(" *     arg_{ak} ({}): {pty} — {ev}", reg_name(reg)));
            }
        }
        for &sk in &sig.stack_args {
            let idx = 6 + sk;
            c_params.push(format!("unk64 arg_{idx}"));
            param_notes.push(format!(" *     arg_{idx} (stack +{:#x}): unk64 — caller stack argument", sk * 8));
        }
        for p in &sig.float_params {
            let (name, ty) = (p.name(), p.ty);
            c_params.push(format!("{ty} {name}"));
            param_notes.push(format!(" *     {name} (xmm{}): {ty} — scalar SSE argument read before written", p.index));
        }
        let nc = ssa.caller_stats.direct_callers;
        let callers_note = format!(", {nc} direct caller{}", plural(nc));
        let mut hdr = Vec::new();
        hdr.push("/*".to_owned());
        hdr.push(format!(
            " * {fn_name} — {:#x}..{:#x} ({} bytes{callers_note}; {name_origin})",
            function.start,
            function.end,
            function.end - function.start
        ));
        let anchors = collect_panic_anchors(locs, ssa);
        if !anchors.is_empty() {
            hdr.push(format!(" *   source: {}", anchors.join(", ")));
        }
        if !param_notes.is_empty() {
            hdr.push(" *   params:".to_owned());
            hdr.extend(param_notes);
        }
        hdr.push(format!(" *   return: {ret_note}"));
        hdr.push(" */".to_owned());

        let sig_params = if c_params.is_empty() { "void".to_owned() } else { c_params.join(", ") };
        let rsep = if ret_ty_str.ends_with('*') { "" } else { " " };
        let sig_line = format!("{ret_ty_str}{rsep}{fn_name}({sig_params}) {{");
        Self { ret_kind, header_block: hdr.join("\n"), sig_line, local_types, xmm0_note }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReturnKind, TypeFacts};
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;
    use crate::sig::fn_sig;
    use crate::ssa_webs::SsaCfg;

    #[test]
    fn infers_out_ptr_candidate_comment_without_fabricating_sret_or_vec() {
        // mov qword ptr [rdi], 1; mov qword ptr [rdi+8], 2; ret
        let code: &[u8] =
            &[0x48, 0xc7, 0x07, 0x01, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x47, 0x08, 0x02, 0x00, 0x00, 0x00, 0xc3];
        let mut data = vec![0u8; 0x80];
        data[..code.len()].copy_from_slice(code);
        let f = 0x1000..0x1000 + code.len() as u64;
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x80 }],
            functions: vec![f.clone()],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        let rt = RuntimeMap::default();
        let sig = fn_sig(&img, &f);
        let ssa = SsaCfg::analyze(&img, &rt, &f, &sig, &[]);
        let tf = TypeFacts::build(&img, &[], &rt, &f, &sig, &ssa);
        assert!(tf.sig_line.contains("void * arg_0") || tf.sig_line.contains("void *arg_0"), "{}", tf.sig_line);
        assert!(!tf.sig_line.contains("sret") && !tf.sig_line.contains("Vec"), "{}", tf.sig_line);
        assert!(tf.header_block.contains("[heuristic: out-ptr candidate]"), "{}", tf.header_block);
        assert_eq!(tf.ret_kind, ReturnKind::Single("unk64"));
    }

    #[test]
    fn preserves_pair_return_when_caller_reads_only_rdx_and_recovers_indirect_and_signed_args() {
        let mut data = vec![0u8; 0x300];
        // 0x1000: target() -> mov eax, 456; mov edx, 123; ret (returns (rax, rdx))
        let f_target: &[u8] = &[0xb8, 0xc8, 0x01, 0x00, 0x00, 0xba, 0x7b, 0x00, 0x00, 0x00, 0xc3];
        data[..f_target.len()].copy_from_slice(f_target);
        // 0x1040: caller() -> sub rsp, 8; call 0x1000; mov rax, rdx; add rsp, 8; ret (reads only rdx!)
        let f_caller: &[u8] =
            &[0x48, 0x83, 0xec, 0x08, 0xe8, 0xb7, 0xff, 0xff, 0xff, 0x48, 0x89, 0xd0, 0x48, 0x83, 0xc4, 0x08, 0xc3];
        data[0x40..0x40 + f_caller.len()].copy_from_slice(f_caller);
        // 0x1080: invoke(x, f) -> sub rsp, 8; call rsi; add rsp, 8; add rax, 1; ret
        let f_invoke: &[u8] =
            &[0x48, 0x83, 0xec, 0x08, 0xff, 0xd6, 0x48, 0x83, 0xc4, 0x08, 0x48, 0x83, 0xc0, 0x01, 0xc3];
        data[0x80..0x80 + f_invoke.len()].copy_from_slice(f_invoke);
        // 0x10c0: signed_cmp(x) -> cmp rdi, -100; jl +5; mov rax, rdi; ret; mov rax, -1; ret
        let f_signed: &[u8] = &[
            0x48, 0x83, 0xff, 0x9c, 0x7c, 0x04, 0x48, 0x89, 0xf8, 0xc3, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xc3,
        ];
        data[0xc0..0xc0 + f_signed.len()].copy_from_slice(f_signed);

        let r_target = 0x1000..0x1000 + f_target.len() as u64;
        let r_caller = 0x1040..0x1040 + f_caller.len() as u64;
        let r_invoke = 0x1080..0x1080 + f_invoke.len() as u64;
        let r_signed = 0x10c0..0x10c0 + f_signed.len() as u64;
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: vec![r_target, r_caller, r_invoke, r_signed],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: vec![(0x1000, "target".to_owned()), (0x1080, "invoke".to_owned())],
            metadata: crate::image_format::Metadata::default(),
        };
        let rt = RuntimeMap::detect(&img);
        let (_, c_target) = crate::c::c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default();
        assert!(c_target.contains("unk128_pair target(void)") && c_target.contains("return (456, 123);"), "{c_target}");

        let (_, c_invoke) = crate::c::c_one(&img, &[], &rt, 0x1080, None, None).unwrap_or_default();
        assert!(c_invoke.contains("invoke(unk64 arg_0, code_ptr arg_1)"), "{c_invoke}");
        assert!(c_invoke.contains("arg_1(arg_0)"), "{c_invoke}");

        let (_, c_signed) = crate::c::c_one(&img, &[], &rt, 0x10c0, None, None).unwrap_or_default();
        assert!(c_signed.contains("(i64 arg_0)"), "{c_signed}");
    }
}

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

use iced_x86::{FlowControl, Mnemonic, OpKind, Register};

use crate::callee_meta::{import_sig, is_fn_noreturn, sanitize_panic_path};
use crate::expr::{ABI_ARGS, reg_name};
use crate::graph::call_target;
use crate::image::Image;
use crate::locations::Location;
use crate::runtime::{RuntimeMap, plt_import};
use crate::sig::FnSig;
use crate::source::location_at;
use crate::ssa_webs::SsaCfg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnKind {
    NoReturn,
    VoidUnused,
    Pair,
    Single(&'static str),
}

pub struct TypeFacts {
    pub ret_kind: ReturnKind,
    pub header_block: String,
    pub sig_line: String,
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
            return (id, "ELF symbol".to_owned());
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

fn infer_param_type(
    image: &Image,
    runtime: &RuntimeMap,
    ssa: &SsaCfg,
    ak: usize,
    reg: Register,
) -> (&'static str, String) {
    let (fields, mut has_load, mut has_store) = ssa.param_fields(ak);
    let (mut scaled_by, mut max_rb, mut has_int_op) = (None, 0u8, false);
    let mut plt_ty: Option<(&'static str, String)> = None;
    for (i, ins) in ssa.insns.iter().enumerate() {
        let meta = &ssa.metas[i];
        let reads_param = (0..usize::from(meta.read_cnt)).any(|k| {
            let wid = meta.read_webs[k].1;
            ssa.webs[wid].is_param == Some(ak) || ssa.webs[wid].init_from_arg == Some(ak)
        });
        if !reads_param {
            continue;
        }
        let m = ins.mnemonic();
        if (0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory) && !ins.is_ip_rel_memory_operand() {
            if ins.memory_base().full_register() == reg
                && m != Mnemonic::Lea
                && meta.web_of_read(reg).is_some_and(|w| ssa.webs[w].is_param == Some(ak))
            {
                has_load = true;
                has_store |= ins.op0_kind() == OpKind::Memory && !matches!(m, Mnemonic::Cmp | Mnemonic::Test);
            }
            if ins.memory_index().full_register() == reg
                && ins.memory_index_scale() > 1
                && meta.web_of_read(reg).is_some_and(|w| ssa.webs[w].is_param == Some(ak))
            {
                let extra = u64::from(m == Mnemonic::Lea && ins.memory_base().full_register() == reg);
                scaled_by = Some(u64::from(ins.memory_index_scale()) + extra);
            }
        }
        for k in 0..ins.op_count() {
            if ins.op_kind(k) == OpKind::Register
                && meta.web_of_read(ins.op_register(k)).is_some_and(|w| ssa.webs[w].is_param == Some(ak))
            {
                max_rb = max_rb.max(u8::try_from(ins.op_register(k).size()).unwrap_or(8));
                has_int_op |= matches!(
                    m,
                    Mnemonic::Cmp
                        | Mnemonic::Test
                        | Mnemonic::Imul
                        | Mnemonic::Shl
                        | Mnemonic::Shr
                        | Mnemonic::Sar
                        | Mnemonic::And
                        | Mnemonic::Sub
                        | Mnemonic::Add
                );
                if m == Mnemonic::Imul && ins.op_count() >= 2 {
                    let last = ins.op_count() - 1;
                    if matches!(
                        ins.op_kind(last),
                        OpKind::Immediate8 | OpKind::Immediate32 | OpKind::Immediate8to64 | OpKind::Immediate32to64
                    ) {
                        scaled_by = Some(ins.immediate(last));
                    }
                }
            }
        }
        if plt_ty.is_none()
            && matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall)
            && let Some(pos) = meta
                .call_arg_regs
                .iter()
                .position(|&cr| meta.web_of_read(cr).is_some_and(|w| ssa.webs[w].is_param == Some(ak)))
            && let Some(ct) = call_target(image, ins)
            && let Some(imp) = runtime.label(image, ct)
            && let Some(isig) = import_sig(imp)
            && let Some(&(pty, role)) = isig.params.get(pos)
        {
            plt_ty = Some((pty, format!("via {imp} param `{role}`")));
        }
    }

    finalize_param_type(ak, &fields, (has_load, has_store), plt_ty, scaled_by, (max_rb, has_int_op))
}

fn finalize_param_type(
    ak: usize,
    fields: &std::collections::BTreeMap<u64, (usize, usize, usize)>,
    (has_load, has_store): (bool, bool),
    plt_ty: Option<(&'static str, String)>,
    scaled_by: Option<u64>,
    (max_rb, has_int_op): (u8, bool),
) -> (&'static str, String) {
    if !fields.is_empty() || has_store || has_load {
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
        if !writes.is_empty() || has_store {
            let mut note = if writes.is_empty() {
                "dereferenced by store".to_owned()
            } else {
                format!("writes {}", writes.join(", "))
            };
            if ak == 0 && reads.is_empty() && fields.contains_key(&0) && fields.len() >= 2 {
                note.push_str(" [heuristic: out-ptr candidate]");
            }
            return ("void *", note);
        }
        let note =
            if reads.is_empty() { "dereferenced by load".to_owned() } else { format!("reads {}", reads.join(", ")) };
        return ("const void *", note);
    }
    if let Some((pty, note)) = plt_ty {
        return (pty, note);
    }
    if let Some(sc) = scaled_by {
        return ("u64", format!("count/index (scaled by {sc})"));
    }
    match max_rb {
        1 => ("u8", "8-bit register read".to_owned()),
        2 => ("u16", "16-bit register read".to_owned()),
        4 => ("u32", "32-bit register read".to_owned()),
        8 if has_int_op => ("u64", "64-bit arithmetic/comparison".to_owned()),
        _ => ("unk64", "64-bit register (type unconstrained)".to_owned()),
    }
}

const fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn infer_return(image: &Image, function: &Range<u64>, ssa: &SsaCfg) -> (ReturnKind, String) {
    if is_fn_noreturn(image, function) {
        return (ReturnKind::NoReturn, "noreturn (no return path)".to_owned());
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
    if ssa.rdx_returned {
        return (ReturnKind::Pair, "unk128_pair in (rax, rdx)".to_owned());
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
    let ty = if !ret_webs.is_empty() && ret_webs.iter().all(|&w| ssa.webs[w].only_setcc && !ssa.webs[w].defs.is_empty())
    {
        "u8"
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
        let (fn_name, name_origin) = recover_name(image, runtime, function.start);
        let (ret_kind, ret_note) = infer_return(image, function, ssa);
        let ret_ty_str = match ret_kind {
            ReturnKind::NoReturn => "noreturn void",
            ReturnKind::VoidUnused => "void",
            ReturnKind::Pair => "unk128_pair",
            ReturnKind::Single(t) => t,
        };
        let mut c_params = Vec::new();
        let mut param_notes = Vec::new();
        for &reg in &sig.regs {
            if let Some(ak) = ABI_ARGS.iter().position(|&r| r == reg) {
                let (pty, ev) = infer_param_type(image, runtime, ssa, ak, reg);
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
        Self { ret_kind, header_block: hdr.join("\n"), sig_line }
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
}

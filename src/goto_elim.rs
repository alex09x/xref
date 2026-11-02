/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Post-structuring `goto` elimination: trailing loop-latch `continue` rewriting, return-stub
//! `goto` inlining, inward label sinking, short forward-chain inlining, and scoped synthetic
//! skip-flag structuring for multi-level loop/guard exits.

use std::collections::HashMap;

use crate::cfg::{Block, Term, can_fall, indent, wrap_if};
pub use crate::cond::{invert_cond, parse_label, split_top_stmts, strip_trailing_continue_label};
use crate::loops::{block_targets, rewrite_continues, stmt_gotos};
use crate::reduce::{has_call, prune_unreachable};

fn leading_pad(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

fn pad_lines(pad: &str, lines: Vec<String>) -> Vec<String> {
    lines.into_iter().map(|s| format!("{pad}{s}")).collect()
}

pub fn inline_stmt_return_gotos(blocks: &mut Vec<Block>) -> bool {
    let mut ref_counts: HashMap<u64, usize> = HashMap::new();
    for (idx, b) in blocks.iter().enumerate() {
        for gt in block_targets(b) {
            *ref_counts.entry(gt).or_default() += 1;
        }
        if b.term == Term::Fall && idx + 1 < blocks.len() {
            *ref_counts.entry(blocks[idx + 1].start).or_default() += 1;
        }
    }
    let mut eligible: HashMap<u64, Vec<String>> = HashMap::new();
    for (t, b) in blocks.iter().enumerate() {
        let is_single = t > 0 && !can_fall(blocks, t) && ref_counts.get(&b.start).copied() == Some(1);
        let term_line = match &b.term {
            Term::Return(ret) if !ret.is_empty() => ret.clone(),
            Term::Jump(j) if is_single && *j != b.start => format!("goto L_{j:x};"),
            _ => continue,
        };
        let is_short_stub = matches!(b.term, Term::Return(_))
            && b.stmts.len() <= 6
            && b.stmts.iter().all(|s| !s.trim_end().ends_with('{') && !has_call(s) && !s.contains("goto "));
        if !b.stmts.iter().any(|s| parse_label(s).is_some())
            && (is_short_stub || (is_single && !b.stmts.iter().any(|s| s.contains(&format!("L_{:x}", b.start)))))
        {
            let mut body = b.stmts.clone();
            body.push(term_line);
            eligible.insert(b.start, body);
        }
    }
    if eligible.is_empty() {
        return false;
    }
    let mut changed = false;
    for b in blocks.iter_mut() {
        let mut new_stmts = Vec::with_capacity(b.stmts.len());
        for line in &b.stmts {
            let (pad, trim) = (leading_pad(line), line.trim());
            let parsed = trim.strip_prefix("goto L_").and_then(|s| Some((None, s.strip_suffix(';')?))).or_else(|| {
                let (c, h) = trim.strip_prefix("if (")?.rsplit_once(") goto L_")?;
                Some((Some(c), h.strip_suffix(';')?))
            });
            if let Some((opt_cond, hex)) = parsed
                && let Ok(addr) = u64::from_str_radix(hex, 16)
                && addr != b.start
                && let Some(body) = eligible.get(&addr)
            {
                let lines = opt_cond.map_or_else(|| body.clone(), |c| wrap_if(c, body, None));
                new_stmts.extend(pad_lines(pad, lines));
                changed = true;
                continue;
            }
            new_stmts.push(line.clone());
        }
        b.stmts = new_stmts;
    }
    if changed {
        prune_unreachable(blocks);
    }
    changed
}

fn is_uncond_term(t: &str) -> bool {
    t.starts_with("return") || t.starts_with("goto L_") || t == "break;" || t == "continue;"
}

fn find_open(lines: &[String], before: usize, pad: &str) -> Option<usize> {
    (0..before)
        .rev()
        .find(|&k| leading_pad(&lines[k]) == pad && lines[k].trim().ends_with('{') && !lines[k].trim().starts_with('}'))
}

fn sink_labels_inward(lines: &mut Vec<String>) -> bool {
    let all_gotos = stmt_gotos(lines);
    for i in 1..lines.len() {
        let Some(addr) = parse_label(&lines[i]) else { continue };
        let needle = format!("goto L_{addr:x};");
        if !all_gotos.contains(&addr) {
            lines.remove(i);
            return true;
        }
        let lbl_pad = leading_pad(&lines[i]).to_owned();
        if leading_pad(&lines[i - 1]) == lbl_pad
            && is_uncond_term(lines[i - 1].trim())
            && all_gotos.iter().filter(|&&g| g == addr).count() == 1
        {
            let end_info = (i + 1..lines.len().min(i + 48))
                .take_while(|&k| {
                    leading_pad(&lines[k]).len() >= lbl_pad.len()
                        && !lines[k].contains("break;")
                        && !lines[k].contains("continue;")
                })
                .find_map(|k| {
                    let k_pad = leading_pad(&lines[k]);
                    parse_label(&lines[k]).map_or_else(
                        || (k_pad == lbl_pad && is_uncond_term(lines[k].trim())).then_some(Some((k, None))),
                        |next_addr| Some((k > i + 1 && k_pad == lbl_pad).then_some((k - 1, Some(next_addr)))),
                    )
                })
                .flatten();
            if let Some((end_idx, fall_lbl)) = end_info
                && split_top_stmts(&lines[i + 1..=end_idx]).is_some()
                && let Some(gt_idx) =
                    (0..lines.len()).find(|&k| !(i..=end_idx).contains(&k) && lines[k].contains(&needle))
                && (fall_lbl.is_none() || gt_idx < i)
            {
                let (gt_pad, gt_trim) = (leading_pad(&lines[gt_idx]).to_owned(), lines[gt_idx].trim().to_owned());
                let mut body: Vec<String> =
                    lines[i + 1..=end_idx].iter().map(|s| s[lbl_pad.len()..].to_owned()).collect();
                if let Some(next_addr) = fall_lbl {
                    body.push(format!("goto L_{next_addr:x};"));
                }
                let repl = (gt_trim == needle).then(|| pad_lines(&gt_pad, body.clone())).or_else(|| {
                    let cond = gt_trim.strip_prefix("if (")?.strip_suffix(&format!(") {needle}"))?;
                    Some(pad_lines(&gt_pad, wrap_if(cond, &body, None)))
                });
                if let Some(r) = repl {
                    if gt_idx < i {
                        lines.drain(i..=end_idx);
                        lines.splice(gt_idx..=gt_idx, r);
                    } else {
                        lines.splice(gt_idx..=gt_idx, r);
                        lines.drain(i..=end_idx);
                    }
                    return true;
                }
            }
        }
        if lines[i + 1..].iter().any(|s| s.contains(&needle)) {
            continue;
        }
        if lines[i - 1].trim() == "}" {
            let close_pad = leading_pad(&lines[i - 1]).to_owned();
            if let Some(open_idx) = find_open(lines, i - 1, &close_pad)
                && !lines[..=open_idx].iter().any(|s| s.contains(&needle))
                && lines[open_idx].trim_start().starts_with("if (")
            {
                lines.swap(i - 1, i);
                lines[i - 1] = format!("{close_pad}  L_{addr:x}:");
                return true;
            }
        }
        if i + 1 < lines.len() {
            let (next_trim, next_pad) = (lines[i + 1].trim_start(), leading_pad(&lines[i + 1]).to_owned());
            if (next_trim.starts_with("} while (") || next_trim == "}")
                && let Some(open_idx) = find_open(lines, i, &next_pad)
                && ["do {", "while ("].iter().any(|p| lines[open_idx].trim_start().starts_with(p))
                && !lines[..=open_idx].iter().any(|s| s.contains(&needle))
                && rewrite_continues(&mut lines[open_idx + 1..i], addr)
            {
                if !stmt_gotos(lines).contains(&addr) {
                    lines.remove(i);
                }
                return true;
            }
        }
    }
    false
}

fn rewrite_loop_gotos(loop_lines: &[String], target: u64, flag: &str) -> Option<Vec<String>> {
    let needle = format!("goto L_{target:x};");
    let mut nested = 0usize;
    let mut out = vec![loop_lines[0].clone()];
    for line in &loop_lines[1..loop_lines.len() - 1] {
        let trim = line.trim();
        if trim.starts_with('}') {
            nested = nested.saturating_sub(1);
        }
        if ["do {", "while (", "switch ("].iter().any(|p| trim.starts_with(p))
            || (nested > 0 && trim.ends_with('{') && !trim.starts_with('}'))
        {
            nested += 1;
        }
        if !line.contains(&needle) {
            out.push(line.clone());
            continue;
        }
        if nested > 0 {
            return None;
        }
        let pad = leading_pad(line);
        if trim == needle {
            out.extend([format!("{pad}{flag} = 1;"), format!("{pad}break;")]);
        } else {
            let cond = trim.strip_prefix("if (")?.strip_suffix(&format!(") {needle}"))?;
            out.extend(pad_lines(pad, wrap_if(cond, &[format!("{flag} = 1;"), "break;".to_owned()], None)));
        }
    }
    out.push(loop_lines[loop_lines.len() - 1].clone());
    Some(out)
}

fn rewrite_seq(seq: &[String], target: u64, flag: &str, need_flag: bool) -> Option<(Vec<String>, bool)> {
    let needle = format!("goto L_{target:x};");
    let stmts = split_top_stmts(seq)?;
    let Some(m) = stmts.iter().position(|&(s, e)| seq[s..e].iter().any(|l| l.contains(&needle))) else {
        return Some((seq.to_vec(), false));
    };
    let (s_start, s_end) = stmts[m];
    let (mut out, s_m) = (seq[..s_start].to_vec(), &seq[s_start..s_end]);
    let (pad, has_tail, mut used_flag) = (leading_pad(&s_m[0]).to_owned(), m + 1 < stmts.len() || need_flag, false);

    if s_m.len() == 1 {
        let trim = s_m[0].trim();
        if trim == needle {
            out.extend(need_flag.then(|| format!("{pad}{flag} = 1;")));
            return Some((out, need_flag));
        }
        let cond = trim.strip_prefix("if (")?.strip_suffix(&format!(") {needle}"))?;
        if m + 1 == stmts.len() {
            out.extend(need_flag.then(|| format!("{pad}if ({cond}) {flag} = 1;")));
            return Some((out, need_flag));
        }
        let (rest_out, rf) = rewrite_seq(&seq[s_end..], target, flag, need_flag)?;
        let unpadded: Vec<String> = rest_out.iter().map(|s| s.strip_prefix(&pad).unwrap_or(s).to_owned()).collect();
        let wrapped = if need_flag {
            wrap_if(cond, &[format!("{flag} = 1;")], Some(&unpadded))
        } else {
            wrap_if(&invert_cond(cond), &unpadded, None)
        };
        out.extend(pad_lines(&pad, wrapped));
        return Some((out, need_flag || rf));
    }

    let head_trim = s_m[0].trim_start();
    if head_trim.starts_with("do {") || head_trim.starts_with("while (") {
        out.extend(rewrite_loop_gotos(s_m, target, flag)?);
        used_flag = true;
    } else if head_trim.starts_with("if (") {
        let end = s_m.len() - 1;
        let else_pos = (1..end).find(|&k| leading_pad(&s_m[k]) == pad && s_m[k].trim() == "} else {");
        out.push(s_m[0].clone());
        let (t_out, tf) = rewrite_seq(&s_m[1..else_pos.unwrap_or(end)], target, flag, has_tail)?;
        out.extend(t_out);
        used_flag |= tf;
        if let Some(ep) = else_pos {
            let (e_out, ef) = rewrite_seq(&s_m[ep + 1..end], target, flag, has_tail)?;
            out.push(s_m[ep].clone());
            out.extend(e_out);
            used_flag |= ef;
        }
        out.push(s_m[end].clone());
    } else {
        return None;
    }

    if m + 1 < stmts.len() {
        let (rest_out, _) = rewrite_seq(&seq[s_end..], target, flag, need_flag)?;
        out.push(format!("{pad}if (!{flag}) {{"));
        out.extend(indent(&rest_out));
        out.push(format!("{pad}}}"));
        used_flag = true;
    }
    Some((out, used_flag))
}

fn step_eliminate_forward_label(lines: &mut Vec<String>) -> bool {
    let label_positions: Vec<(usize, u64)> =
        lines.iter().enumerate().filter_map(|(idx, s)| Some((idx, parse_label(s)?))).collect();
    for &(lbl_idx, addr) in label_positions.iter().rev() {
        let needle = format!("goto L_{addr:x};");
        if lines[lbl_idx + 1..].iter().any(|s| s.contains(&needle)) {
            continue;
        }
        let Some(first_gt) = (0..lbl_idx).find(|&k| lines[k].contains(&needle)) else {
            lines.remove(lbl_idx);
            return true;
        };
        let scope_open = (0..=first_gt).rev().find(|&k| {
            let kp = leading_pad(&lines[k]);
            lines[k].trim().ends_with('{')
                && !lines[k + 1..lbl_idx]
                    .iter()
                    .any(|s| leading_pad(s) == kp && s.trim().starts_with('}') && !s.trim().ends_with('{'))
        });
        let region_start = scope_open.map_or(0, |k| k + 1);
        let region = &lines[region_start..lbl_idx];
        let Some((stmts, first_stmt)) = split_top_stmts(region).and_then(|st| {
            let pos = st.iter().position(|&(s, e)| region[s..e].iter().any(|l| l.contains(&needle)))?;
            Some((st, pos))
        }) else {
            continue;
        };
        let sub_start = region_start + stmts[first_stmt].0;
        let pad = leading_pad(&lines[sub_start]).to_owned();
        let else_join = (lbl_idx > sub_start && leading_pad(&lines[lbl_idx - 1]) == pad)
            .then(|| lines[lbl_idx - 1].trim().strip_prefix("goto L_")?.strip_suffix(';'))
            .flatten()
            .and_then(|j_hex| u64::from_str_radix(j_hex, 16).ok())
            .and_then(|j_addr| {
                let j_idx = (lbl_idx + 1..lines.len()).find(|&k| parse_label(&lines[k]) == Some(j_addr))?;
                (stmt_gotos(lines).iter().filter(|&&g| g == j_addr).count() == 1
                    && lines[lbl_idx + 1..j_idx].iter().all(|s| parse_label(s).is_none())
                    && split_top_stmts(&lines[lbl_idx + 1..j_idx]).is_some())
                .then_some(j_idx)
            });

        let end_before_lbl = if else_join.is_some() { lbl_idx - 1 } else { lbl_idx };
        if lines[sub_start..end_before_lbl].iter().any(|s| parse_label(s).is_some()) {
            continue;
        }
        let flag = format!("skip_{addr:x}");
        let Some((mut rewritten, used_flag)) =
            rewrite_seq(&lines[sub_start..end_before_lbl], addr, &flag, else_join.is_some())
        else {
            continue;
        };
        if used_flag {
            rewritten.insert(0, format!("{pad}u8 {flag} = 0;"));
        }
        if let Some(j_idx) = else_join {
            rewritten.push(format!("{pad}if ({flag}) {{"));
            rewritten.extend(indent(&lines[lbl_idx + 1..j_idx]));
            rewritten.push(format!("{pad}}}"));
        }
        lines.splice(sub_start..=else_join.unwrap_or(lbl_idx), rewritten);
        return true;
    }
    false
}

pub fn eliminate_forward_gotos(lines: &mut Vec<String>) {
    while sink_labels_inward(lines) || step_eliminate_forward_label(lines) {}
}

#[cfg(test)]
mod tests {
    use super::eliminate_forward_gotos;

    #[test]
    fn eliminates_cold_backward_branch_and_loop_exit_gotos() {
        let mut lines: Vec<String> = [
            "if (a > 94) goto L_90;",
            "L_50:",
            "do {",
            "  if (b > 15) goto L_80;",
            "  b += 1;",
            "} while (b < 10);",
            "push(b);",
            "L_80:",
            "return;",
            "L_90:",
            "a -= 32;",
            "goto L_50;",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        eliminate_forward_gotos(&mut lines);
        let text = lines.join("\n");
        assert!(!text.contains("goto ") && !text.contains("L_"), "{text}");
        assert!(text.contains("u8 skip_80 = 0;") && text.contains("if (!skip_80)"), "{text}");
    }
}

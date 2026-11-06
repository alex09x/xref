/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Folds single-use float temporaries (`f64 fp_X = EXPR;`) into the statement that reads them, so
//! `x as f64 / d` reads `return (f64)(u64)(arg_0) / arg_f0;` instead of a chain of `fp_*` copies.
//!
//! A temporary is folded only into the next statement of the same straight-line run: everything
//! between definition and use must itself be a call-free float temporary definition (which reads
//! but never writes memory or variables), and an expression with a call or a memory read is not
//! moved across or into another call.

use std::collections::HashMap;

use crate::c::{find_comment_outside_str, line_idents};

struct Def<'a> {
    indent: usize,
    name: &'a str,
    rhs: &'a str,
}

fn parse_def(line: &str) -> Option<Def<'_>> {
    let body = line.trim_start();
    let indent = line.len() - body.len();
    let rest = body.strip_prefix("f64 ").or_else(|| body.strip_prefix("f32 "))?;
    let (name, rhs) = rest.split_once(" = ")?;
    let rhs = rhs.strip_suffix(';')?;
    let valid_name = name.starts_with("fp_") && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    (valid_name && find_comment_outside_str(line).is_none() && !rhs.contains('"')).then_some(Def { indent, name, rhs })
}

/// An identifier directly followed by `(`, other than the pure math builtins the lifter emits.
fn has_call(code: &str) -> bool {
    let bytes = code.as_bytes();
    (0..bytes.len()).any(|i| {
        if bytes[i] != b'(' || i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
            return false;
        }
        let start = code[..i].rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).map_or(0, |p| p + 1);
        !matches!(&code[start..i], "sqrt" | "sqrtf" | "isnan")
    })
}

fn reads_memory(code: &str) -> bool {
    code.contains("*(") || code.contains('[') || code.contains("->") || code.contains("slot_")
}

fn is_plain_statement(line: &str) -> bool {
    let code = find_comment_outside_str(line).map_or(line, |idx| &line[..idx]).trim();
    let control = ["if ", "if(", "while", "for ", "for(", "do ", "do{", "switch", "case ", "default", "else", "goto "];
    code.ends_with(';') && !code.starts_with('}') && !control.iter().any(|kw| code.starts_with(kw))
}

/// Replaces the single occurrence of identifier `name` in the code part of `line`.
fn substitute(line: &str, name: &str, rhs: &str) -> Option<String> {
    let end = find_comment_outside_str(line).unwrap_or(line.len());
    let code = &line[..end];
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let hits: Vec<usize> = code
        .match_indices(name)
        .map(|(pos, _)| pos)
        .filter(|&pos| !code[..pos].ends_with(is_ident) && !code[pos + name.len()..].starts_with(is_ident))
        .collect();
    let [pos] = hits[..] else { return None };
    let mut depth = 0i32;
    let top_level_space = rhs.chars().any(|c| {
        depth += i32::from(c == '(') - i32::from(c == ')');
        c == ' ' && depth == 0
    });
    let value = if top_level_space { format!("({rhs})") } else { rhs.to_owned() };
    Some(format!("{}{value}{}", &line[..pos], &line[pos + name.len()..]))
}

pub fn inline_float_temps(lines: &mut Vec<String>) {
    let mut uses: HashMap<String, Vec<usize>> = HashMap::new();
    for (l, line) in lines.iter().enumerate() {
        for id in line_idents(line).into_iter().filter(|id| id.starts_with("fp_")) {
            uses.entry(id).or_default().push(l);
        }
    }
    let mut removed = vec![false; lines.len()];
    for i in (0..lines.len()).rev() {
        let Some(def) = parse_def(&lines[i]) else { continue };
        let (name, rhs) = (def.name.to_owned(), def.rhs.to_owned());
        let Some(&[j]) =
            uses.get(&name).map(|ls| ls.iter().copied().filter(|&l| l != i).collect::<Vec<_>>()).as_deref()
        else {
            continue;
        };
        let use_line = &lines[j];
        let use_indent = use_line.len() - use_line.trim_start().len();
        if j <= i || j - i > 64 || use_indent != def.indent || !is_plain_statement(use_line) {
            continue;
        }
        let between: Vec<usize> = (i + 1..j).filter(|&l| !removed[l]).collect();
        let (rhs_call, rhs_mem) = (has_call(&rhs), reads_memory(&rhs));
        let use_code = find_comment_outside_str(use_line).map_or(use_line.as_str(), |idx| &use_line[..idx]);
        if line_idents(&rhs).contains(&name)
            || (rhs_call && !between.is_empty())
            || ((rhs_call || rhs_mem) && has_call(use_code))
            || !between.iter().all(|&l| parse_def(&lines[l]).is_some_and(|d| !has_call(d.rhs)))
        {
            continue;
        }
        let Some(new_line) = substitute(use_line, &name, &rhs) else { continue };
        lines[j] = new_line;
        removed[i] = true;
        for id in line_idents(&rhs).into_iter().filter(|id| id.starts_with("fp_")) {
            if let Some(ls) = uses.get_mut(&id) {
                for l in ls.iter_mut().filter(|l| **l == i) {
                    *l = j;
                }
                ls.sort_unstable();
                ls.dedup();
            }
        }
    }
    let mut keep = removed.iter().map(|r| !r);
    lines.retain(|_| keep.next().unwrap_or(true));
}

#[cfg(test)]
mod tests {
    use super::inline_float_temps;

    fn run(src: &[&str]) -> Vec<String> {
        let mut lines: Vec<String> = src.iter().map(|s| (*s).to_owned()).collect();
        inline_float_temps(&mut lines);
        lines
    }

    #[test]
    fn f64_abi_folds_single_use_chain_into_return() {
        let out = run(&[
            "  f64 fp_10 = (f64)(u64)(arg_0);",
            "  f64 fp_31 = (fp_10 / arg_f0);",
            "  f64 fp_35 = fp_31;",
            "  return fp_35;",
        ]);
        assert_eq!(out, vec!["  return ((f64)(u64)(arg_0) / arg_f0);".to_owned()]);
    }

    #[test]
    fn f64_abi_keeps_multi_use_calls_across_statements_and_control_flow() {
        let out = run(&[
            "  f64 fp_1 = arg_f0;",
            "  f64 fp_3 = fn_1000(arg_0);",
            "  *(u64 *)(arg_1) = 0;",
            "  f64 fp_2 = (fp_1 * fp_1);",
            "  f64 fp_4 = (fp_3 + fp_2);",
            "  if (fp_4 > 1.0) {",
        ]);
        assert_eq!(out[0], "  f64 fp_1 = arg_f0;");
        assert!(out.iter().any(|l| l == "  f64 fp_3 = fn_1000(arg_0);"), "{out:?}");
        assert!(out.iter().any(|l| l.starts_with("  f64 fp_4 = (fp_3 + (fp_1 * fp_1))")), "{out:?}");
        assert!(out.iter().any(|l| l == "  if (fp_4 > 1.0) {"), "{out:?}");
    }

    #[test]
    fn f64_abi_does_not_move_memory_reads_into_calls() {
        let out = run(&["  f64 fp_1 = *(f64 *)(arg_0);", "  fn_2000(arg_0, fp_1);"]);
        assert_eq!(out.len(), 2, "{out:?}");
        let out = run(&["  f64 fp_1 = fn_1000(arg_0);", "  f64 fp_2 = (fp_1 * 2.0);", "  return fp_2;"]);
        assert_eq!(out, vec!["  return (fn_1000(arg_0) * 2.0);".to_owned()]);
    }
}

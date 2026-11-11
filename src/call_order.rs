/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `calls --order`: the calls of a function in program order with the loops and conditions
//! around them, read off its pseudo-C. Statements that are not calls are dropped, and so are the
//! loops and branches holding no call, so a 10 KB function shows as the skeleton of what it calls
//! and when ("is `f` called before or after the loop guarded by `x`?").

use std::collections::HashMap;
use std::io::Write;

use crate::commands::Res;

/// The code of a line without a trailing `/* ... */` comment.
fn code_of(line: &str) -> &str {
    crate::c::find_comment_outside_str(line).map_or(line, |at| &line[..at]).trim_end()
}

/// Lines that open a block: `if (..) {`, `while (..) {`, `for`, `do {`, `switch`.
fn opens(code: &str) -> bool {
    code.ends_with('{') && !code.trim_start().starts_with('}')
}

/// `name = expr;` or a declaration `u8 name = expr;` with a plain variable on the left (not `==`,
/// `+=` or a store through a pointer).
fn assignment(t: &str) -> Option<(&str, &str)> {
    let (lhs, rhs) = t.strip_suffix(';')?.split_once(" = ")?;
    let word = |w: &str| !w.is_empty() && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    let mut parts = lhs.split_whitespace().rev();
    let name = parts.next()?.trim_start_matches('*');
    let typed = parts.all(|w| word(w.trim_end_matches('*')));
    (word(name) && typed && !name.starts_with(|c: char| c.is_ascii_digit())).then_some((name, rhs))
}

/// Lines whose condition decides what runs: `if`, `while`, `for`, `switch`, `} else if`, `} while`.
fn is_guard(t: &str) -> bool {
    let t = t.trim_start_matches('}').trim_start();
    ["if (", "else if (", "while (", "for (", "switch ("].iter().any(|k| t.starts_with(k))
}

/// `code` with each identifier for which `replace` gives a text replaced by that text.
fn map_names(code: &str, mut replace: impl FnMut(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(code.len());
    let mut rest = code;
    while let Some(start) = rest.find(|c: char| c.is_ascii_alphabetic() || c == '_') {
        out.push_str(&rest[..start]);
        let word = &rest[start..];
        let len = word.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(word.len());
        let name = &word[..len];
        out.push_str(&replace(name).unwrap_or_else(|| name.to_owned()));
        rest = &word[len..];
    }
    out.push_str(rest);
    out
}

/// A guard with each variable whose memory load was dropped followed by that load, once per line:
/// `if ((v_96 /* = *(u8 *)(ptr_7 + 0xabb) */ & 1) != 0)`.
fn annotate(code: &str, loads: &HashMap<String, String>) -> String {
    let mut done: Vec<String> = Vec::new();
    map_names(code, |name| {
        let load = loads.get(name).filter(|_| !done.iter().any(|d| d == name))?;
        done.push(name.to_owned());
        Some(format!("{name} /* = {load} */"))
    })
}

/// The skeleton of a pseudo-C body: calls, the blocks holding them (with `} else {` kept inside
/// its `if`), labels and the jumps between them; blocks without a call are dropped.
#[must_use]
pub fn skeleton(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // Per open block: where its header is in `out`, and whether a call is inside it.
    let mut stack: Vec<(usize, bool)> = Vec::new();
    let mut labels: Vec<&str> = Vec::new();
    // Variables last assigned by a dropped statement that reads memory, with that load.
    let mut loads: HashMap<String, String> = HashMap::new();
    for line in lines {
        let code = code_of(line);
        let t = code.trim();
        if t.is_empty() || t.starts_with("/*") || t.starts_with("//") {
            continue;
        }
        if t.starts_with('}') {
            if t.ends_with('{') {
                // `} else {` / `} else if (..) {`: the same if/else chain continues.
                out.push(annotate(code, &loads));
                continue;
            }
            let Some((start, has_call)) = stack.pop() else { continue };
            if has_call {
                out.push(if is_guard(t) { annotate(code, &loads) } else { code.to_owned() });
                if let Some(parent) = stack.last_mut() {
                    parent.1 = true;
                }
            } else {
                out.truncate(start);
            }
            continue;
        }
        if opens(code) {
            stack.push((out.len(), false));
            out.push(if is_guard(t) { annotate(code, &loads) } else { code.to_owned() });
            continue;
        }
        let is_call = crate::cond::has_call(code);
        if let Some((name, rhs)) = assignment(t) {
            // A load through another dropped load reads as the first one: `v_2 = v_1 & 1` after
            // `v_1 = *(u8 *)(p + 8)` names the byte.
            let rhs = map_names(rhs, |name| {
                loads.get(name).map(|load| {
                    if load.starts_with('(') && load.ends_with(')') { load.clone() } else { format!("({load})") }
                })
            });
            if !is_call && rhs.contains("*(") {
                loads.insert(name.to_owned(), rhs);
            } else {
                loads.remove(name);
            }
        }
        let is_flow = t.ends_with(':')
            || t.starts_with("goto ")
            || t.contains(" goto ")
            || t.starts_with("return")
            || t.starts_with("break")
            || t.starts_with("continue")
            || t.starts_with("case ")
            || t.starts_with("default");
        if is_call {
            if let Some(top) = stack.last_mut() {
                top.1 = true;
            }
            out.push(code.to_owned());
        } else if is_flow {
            if t.ends_with(':') {
                labels.push(t.trim_end_matches(':'));
            }
            // A jump back to a label already passed closes a loop written with goto.
            let back = t
                .split("goto ")
                .nth(1)
                .map(|rest| rest.trim_end_matches(';').trim())
                .is_some_and(|label| labels.contains(&label));
            let code = if is_guard(t) { annotate(code, &loads) } else { code.to_owned() };
            out.push(if back { format!("{code} /* loop back */") } else { code });
        }
    }
    // A goto, label or return left alone between two kept lines is still worth showing; trailing
    // ones after the last call are not.
    while out.last().is_some_and(|l| !crate::cond::has_call(l) && !l.trim().starts_with('}')) {
        out.pop();
    }
    out
}

/// `xref calls --order ADDR`.
pub fn order(image: &crate::image::Image, addr: u64, out: &mut dyn Write) -> Res {
    let locs = crate::locations::locations(image);
    let runtime = crate::runtime::RuntimeMap::detect(image);
    let (_, text) = crate::c::c_one(image, &locs, &runtime, addr, None, None)?;
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    // The function header and its closing brace stay as the outer frame.
    let Some(body) = lines.iter().position(|l| !l.starts_with(' ') && l.trim_end().ends_with('{')) else {
        return Err("no function body in the pseudo-C".into());
    };
    writeln!(out, "{}", lines[body])?;
    for line in skeleton(&lines[body + 1..]) {
        writeln!(out, "{line}")?;
    }
    writeln!(out, "}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::skeleton;

    fn body(text: &str) -> Vec<String> {
        text.lines().map(str::to_owned).collect()
    }

    #[test]
    fn keeps_calls_with_their_loops_and_conditions_and_drops_the_rest() {
        let lines = body(
            "  v_1 = arg_0 + 8;\n  fn_100(v_1);\n  while (v_2 != 0) {\n    v_2 = v_2 - 1;\n  }\n  if (*(u8 *)(arg_0 + 0xabb) != 0) {\n    v_3 = 1;\n    while (v_3 < 10) {\n      fn_200(v_3); /* note */\n      v_3 += 1;\n    }\n  } else {\n    v_4 = 2;\n  }\n  fn_300();\n  return v_1;\n",
        );
        assert_eq!(
            skeleton(&lines),
            vec![
                "  fn_100(v_1);",
                "  if (*(u8 *)(arg_0 + 0xabb) != 0) {",
                "    while (v_3 < 10) {",
                "      fn_200(v_3);",
                "    }",
                "  } else {",
                "  }",
                "  fn_300();",
            ]
        );
    }

    #[test]
    fn a_guard_names_the_dropped_load_of_its_variable() {
        let lines = body(
            "  u8 v_96 = *(u8 *)(ptr_7 + 0xabb);\n  v_97 = v_96 & 1;\n  v_5 = fn_1(v_96);\n  if ((v_96 & 1) != 0) {\n    fn_2();\n  }\n  while (v_97 != 0 && v_5 != 0) {\n    fn_3();\n  }\n  v_96 = 0;\n  if (v_96 == 0) goto L_1;\n  fn_4();\nL_1:\n  fn_5();\n",
        );
        assert_eq!(
            skeleton(&lines),
            vec![
                "  v_5 = fn_1(v_96);",
                "  if ((v_96 /* = *(u8 *)(ptr_7 + 0xabb) */ & 1) != 0) {",
                "    fn_2();",
                "  }",
                "  while (v_97 /* = (*(u8 *)(ptr_7 + 0xabb)) & 1 */ != 0 && v_5 != 0) {",
                "    fn_3();",
                "  }",
                "  if (v_96 == 0) goto L_1;",
                "  fn_4();",
                "L_1:",
                "  fn_5();",
            ]
        );
    }

    #[test]
    fn gotos_and_labels_between_calls_stay_but_a_call_free_tail_goes() {
        let lines = body("  if (v_1 == 0) goto L_1;\n  fn_1();\nL_1:\n  fn_2();\n  goto L_2;\nL_2:\n  return 0;\n");
        assert_eq!(skeleton(&lines), vec!["  if (v_1 == 0) goto L_1;", "  fn_1();", "L_1:", "  fn_2();"]);
        let looped = body("L_1:\n  fn_1();\n  if (v_1 != 0) goto L_1;\n  fn_2();\n");
        assert_eq!(
            skeleton(&looped),
            vec!["L_1:", "  fn_1();", "  if (v_1 != 0) goto L_1; /* loop back */", "  fn_2();"]
        );
    }
}

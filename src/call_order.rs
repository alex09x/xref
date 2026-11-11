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

/// The skeleton of a pseudo-C body: calls, the blocks holding them (with `} else {` kept inside
/// its `if`), labels and the jumps between them; blocks without a call are dropped.
#[must_use]
pub fn skeleton(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // Per open block: where its header is in `out`, and whether a call is inside it.
    let mut stack: Vec<(usize, bool)> = Vec::new();
    let mut labels: Vec<&str> = Vec::new();
    for line in lines {
        let code = code_of(line);
        let t = code.trim();
        if t.is_empty() || t.starts_with("/*") || t.starts_with("//") {
            continue;
        }
        if t.starts_with('}') {
            if t.ends_with('{') {
                // `} else {` / `} else if (..) {`: the same if/else chain continues.
                out.push(code.to_owned());
                continue;
            }
            let Some((start, has_call)) = stack.pop() else { continue };
            if has_call {
                out.push(code.to_owned());
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
            out.push(code.to_owned());
            continue;
        }
        let is_call = crate::cond::has_call(code);
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
            out.push(if back { format!("{code} /* loop back */") } else { code.to_owned() });
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

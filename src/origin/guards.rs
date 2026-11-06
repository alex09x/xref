/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The check guarding one statement of rendered pseudo-C: the enclosing conditions, the early
//! exits before it, the definitions of the innermost condition's operands and the payload stored
//! next to it.

use crate::slice_parse::{BlockSpan, build_block_spans, strip_comment};

const MARK: &str = "@xref_slice_target";
/// The innermost guards shown; outer ones rarely decide the error.
const MAX_GUARDS: usize = 6;
const MAX_DEFS: usize = 4;
const MAX_PAYLOAD: usize = 4;

/// What decides that the marked statement runs.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Guarded {
    /// Definitions of the innermost condition's operands, in source order.
    pub defs: Vec<String>,
    /// Enclosing conditions and early exits, outermost first.
    pub guards: Vec<String>,
    pub statement: String,
    /// Statements right after it in the same block (the variant's payload).
    pub payload: Vec<String>,
}

/// The guards of the line carrying the slice mark in `c`, or `None` when no line is marked.
pub fn guarded(c: &str) -> Option<Guarded> {
    let lines: Vec<&str> = c.lines().collect();
    let target = lines.iter().position(|line| line.contains(MARK))?;
    let sig = lines.iter().position(|l| !l.starts_with(' ') && !l.starts_with("/*") && l.ends_with(") {")).unwrap_or(0);
    let spans = build_block_spans(&lines, sig);
    let enclosing: Vec<&BlockSpan> = spans.iter().filter(|s| s.open < target && target < s.close).collect();
    let parent =
        |span: &BlockSpan| spans.iter().filter(|o| o.open < span.open && span.close < o.close).max_by_key(|o| o.open);
    // Where the branch holding the target starts inside each ancestor (`None` is the body itself).
    let branch_start = |ancestor: Option<&BlockSpan>| {
        ancestor.map_or(sig, |a| a.elses.iter().copied().filter(|&e| e < target).max().unwrap_or(a.open))
    };
    let mut found: Vec<(usize, String)> = Vec::new();
    let mut innermost: Option<(usize, String)> = None;
    for span in &enclosing {
        let (at, condition) = branch_taken(&lines, span, target);
        if innermost.as_ref().is_none_or(|(line, _)| *line < at) {
            innermost = Some((at, condition.clone()));
        }
        found.push((at, condition));
    }
    for span in spans.iter().filter(|s| s.close < target && s.elses.is_empty()) {
        let up = parent(span);
        let on_path = up.is_none_or(|p| enclosing.iter().any(|e| e.open == p.open));
        // A label between the exit and the target: the target is reached by a jump to it.
        let jumped_over = (span.close + 1..target)
            .any(|at| is_label(lines[at]) && block_of(&spans, at).map(|s| s.open) == up.map(|p| p.open));
        if on_path
            && !jumped_over
            && span.open > branch_start(up)
            && let Some(exit) = early_exit(&lines, span)
        {
            found.push((span.open, exit));
        }
    }
    found.sort_by_key(|(line, _)| *line);
    let guards: Vec<String> = found[found.len().saturating_sub(MAX_GUARDS)..].iter().map(|(_, g)| g.clone()).collect();
    let defs = innermost.map(|(line, condition)| definitions(&lines, line, &condition)).unwrap_or_default();
    Some(Guarded { defs, guards, statement: clean(lines[target]), payload: payload(&lines, target) })
}

/// The condition under which `target` runs inside `span`: its opener, or the `else` branch it is in.
fn branch_taken(lines: &[&str], span: &BlockSpan, target: usize) -> (usize, String) {
    let opener = strip_comment(lines[span.open]).trim_end_matches('{').trim().to_owned();
    match span.elses.iter().copied().filter(|&e| e < target).max() {
        None => (span.open, opener),
        Some(at) => {
            let line = strip_comment(lines[at]).trim_start_matches('}').trim().trim_end_matches('{').trim();
            let shown = if line == "else" { format!("else of {opener}") } else { line.to_owned() };
            (at, shown)
        }
    }
}

fn is_label(line: &str) -> bool {
    let code = strip_comment(line);
    code.strip_suffix(':')
        .is_some_and(|name| !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// The innermost block holding line `at`.
fn block_of(spans: &[BlockSpan], at: usize) -> Option<&BlockSpan> {
    spans.iter().filter(|s| s.open < at && at < s.close).max_by_key(|s| s.open)
}

/// `if (c) { … return; }` before the target: the target runs only when `c` is false.
fn early_exit(lines: &[&str], span: &BlockSpan) -> Option<String> {
    let opener = strip_comment(lines[span.open]);
    if !opener.starts_with("if ") {
        return None;
    }
    let last = strip_comment(lines[span.close.checked_sub(1)?]);
    let exits = last.starts_with("return") || last.starts_with("goto ") || last == "break;" || last == "unreachable();";
    exits.then(|| format!("{} … {last} }}", opener.trim_end_matches('{').trim_end().to_owned() + " {"))
}

/// The nearest definition above `from` of each local the condition reads.
fn definitions(lines: &[&str], from: usize, condition: &str) -> Vec<String> {
    let mut defs: Vec<(usize, String)> = Vec::new();
    for name in locals(condition).into_iter().take(MAX_DEFS) {
        let taken = format!("&{name}");
        let Some(at) = (0..from).rev().find(|&i| {
            let code = strip_comment(lines[i]);
            assigns(code, &name) || code.contains(&taken)
        }) else {
            continue;
        };
        if defs.iter().all(|(line, _)| *line != at) {
            defs.push((at, clean(lines[at])));
        }
    }
    defs.sort_by_key(|(line, _)| *line);
    defs.into_iter().map(|(_, d)| d).collect()
}

/// Locals of the pseudo-C (`v_12`, `slot_20`, `ptr_3`, `fp_…`) a condition reads, in order.
fn locals(condition: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for token in condition.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        let local =
            ["v_", "slot_", "ptr_", "fp_"].iter().any(|p| token.strip_prefix(p).is_some_and(|rest| !rest.is_empty()));
        if local && !names.iter().any(|n| n == token) {
            names.push(token.to_owned());
        }
    }
    names
}

/// `name = …;` or a declaration `type name = …;`, not a store through it or a comparison.
fn assigns(code: &str, name: &str) -> bool {
    let pattern = format!("{name} = ");
    code.match_indices(&pattern).any(|(at, _)| {
        let before = &code[..at];
        (before.is_empty() || before.ends_with(' ') || before.ends_with('*'))
            && !before.contains('(')
            && !before.contains('=')
            && !before.trim_start().starts_with("if ")
    })
}

fn payload(lines: &[&str], target: usize) -> Vec<String> {
    let indent = |line: &str| line.len() - line.trim_start().len();
    let depth = indent(lines[target]);
    lines[target + 1..]
        .iter()
        .take_while(|line| indent(line) == depth && !strip_comment(line).starts_with('}'))
        .map(|line| strip_comment(line))
        .filter(|code| !code.is_empty())
        .take_while(|code| !code.starts_with("return") && !code.starts_with("goto ") && !code.ends_with(':'))
        .take(MAX_PAYLOAD)
        .map(str::to_owned)
        .collect()
}

fn clean(line: &str) -> String {
    strip_comment(line).to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Guarded, guarded};

    const C: &str = "\
void f(void *arg_0, u64 arg_1) {
  u64 v_2 = *(u64 *)(arg_1 + 8);
  if (arg_1 == 0) {
    return;
  }
  /* fn_9: source a.rs:1 */
  fn_9(&slot_20, v_2);
  if (v_2 != 0) {
    if ((i64)slot_20 <= (i64)0x5f5e0ff) {
      *(u16 *)(arg_0) = 312; /* @xref_slice_target */
      *(u64 *)(arg_0 + 8) = slot_20;
      return;
    }
  } else {
    v_2 = 1;
  }
}";

    #[test]
    fn the_guard_of_a_marked_store_is_its_enclosing_conditions_and_early_exits() -> Result<(), &'static str> {
        let found = guarded(C).ok_or("marked")?;
        assert_eq!(
            found,
            Guarded {
                defs: vec!["fn_9(&slot_20, v_2);".to_owned()],
                guards: vec![
                    "if (arg_1 == 0) { … return; }".to_owned(),
                    "if (v_2 != 0)".to_owned(),
                    "if ((i64)slot_20 <= (i64)0x5f5e0ff)".to_owned(),
                ],
                statement: "*(u16 *)(arg_0) = 312;".to_owned(),
                payload: vec!["*(u64 *)(arg_0 + 8) = slot_20;".to_owned()],
            }
        );
        let in_else =
            C.replace(" /* @xref_slice_target */", "").replace("v_2 = 1;", "v_2 = 1; /* @xref_slice_target */");
        let found = guarded(&in_else).ok_or("marked")?;
        assert_eq!(found.guards.last().map(String::as_str), Some("else of if (v_2 != 0)"));
        // Reached through a label: the exit before it is on another path.
        let labelled = C.replace("  /* fn_9: source a.rs:1 */\n", "L_10:\n");
        let found = guarded(&labelled).ok_or("marked")?;
        assert_eq!(found.guards.first().map(String::as_str), Some("if (v_2 != 0)"));
        assert!(guarded("void f() {\n}").is_none());
        Ok(())
    }
}

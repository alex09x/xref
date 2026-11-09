/*
 * XRef — bounded Linux uprobe fetch-argument parsing
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeSet;

pub const MAX_FETCH_ARGS: usize = 16;
pub const RESERVED_FETCH_NAMES: &[&str] = &["ra"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchArg {
    pub name: String,
    pub expression: String,
}

#[must_use]
pub fn is_reserved_fetch_name(name: &str) -> bool {
    RESERVED_FETCH_NAMES.contains(&name)
}

pub fn parse_fetch_args(specs: &[String]) -> Result<Vec<FetchArg>, String> {
    if specs.len() > MAX_FETCH_ARGS {
        return Err(format!("--fetch accepts at most {MAX_FETCH_ARGS} arguments"));
    }
    let mut names = BTreeSet::new();
    specs
        .iter()
        .map(|spec| {
            let parsed = parse_fetch_arg(spec)?;
            if !names.insert(parsed.name.clone()) {
                return Err(format!("duplicate --fetch name {:?}", parsed.name));
            }
            Ok(parsed)
        })
        .collect()
}

pub fn parse_fetch_arg(spec: &str) -> Result<FetchArg, String> {
    let (name, expression) = spec.split_once('=').ok_or("--fetch must be NAME=EXPR")?;
    if !valid_identifier(name) || name.len() > 31 {
        return Err("--fetch NAME must be a valid identifier of at most 31 bytes".to_owned());
    }
    if is_reserved_fetch_name(name) {
        return Err(format!(
            "--fetch NAME must be a non-reserved identifier (reserved: {})",
            RESERVED_FETCH_NAMES.join(", ")
        ));
    }
    let bounded = "--fetch EXPR must be a bounded typed uprobe register or nested memory fetch";
    if expression.len() > 128 {
        return Err(bounded.to_owned());
    }
    let expression = canonical_typed_expression(expression)?.ok_or(bounded)?;
    Ok(FetchArg { name: name.to_owned(), expression })
}

/// The expression with its registers in tracefs names (`%rcx` is written as `%cx`), or `None`
/// when it is not a typed register or nested memory fetch.
fn canonical_typed_expression(expression: &str) -> Result<Option<String>, String> {
    let Some((node, kind)) = expression.rsplit_once(':') else { return Ok(None) };
    if !matches!(kind, "u8" | "u16" | "u32" | "u64" | "x8" | "x16" | "x32" | "x64") {
        return Ok(None);
    }
    let (mut at, mut out) = (0, String::with_capacity(expression.len()));
    if !parse_node(node.as_bytes(), &mut at, &mut out)? || at != node.len() {
        return Ok(None);
    }
    out.push(':');
    out.push_str(kind);
    Ok(Some(out))
}

fn parse_node(bytes: &[u8], at: &mut usize, out: &mut String) -> Result<bool, String> {
    if *at >= bytes.len() {
        return Ok(false);
    }
    if bytes[*at] == b'%' {
        *at += 1;
        let start = *at;
        while *at < bytes.len() && (bytes[*at].is_ascii_alphanumeric() || bytes[*at] == b'_') {
            *at += 1;
        }
        let Some(name) = std::str::from_utf8(&bytes[start..*at]).ok().filter(|n| !n.is_empty()) else {
            return Ok(false);
        };
        let Some(register) = tracefs_register(name)? else { return Ok(false) };
        out.push('%');
        out.push_str(register);
        return Ok(true);
    }
    let begin = *at;
    if bytes[*at] == b'+' {
        *at += 1;
    }
    let start = *at;
    if bytes.get(*at..*at + 2).is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"0x")) {
        *at += 2;
        let digits = *at;
        while *at < bytes.len() && bytes[*at].is_ascii_hexdigit() {
            *at += 1;
        }
        if digits == *at {
            return Ok(false);
        }
    } else {
        while *at < bytes.len() && bytes[*at].is_ascii_digit() {
            *at += 1;
        }
    }
    if start == *at || bytes.get(*at) != Some(&b'(') {
        return Ok(false);
    }
    out.push_str(&String::from_utf8_lossy(&bytes[begin..=*at]));
    *at += 1;
    if !parse_node(bytes, at, out)? || bytes.get(*at) != Some(&b')') {
        return Ok(false);
    }
    out.push(')');
    *at += 1;
    Ok(true)
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.bytes();
    chars.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The x86-64 tracefs (`pt_regs`) name of a general-purpose register: tracefs knows `%ax %bx %cx
/// %dx %si %di %bp %sp %r8..%r15`, so `rcx` is accepted and written as `cx`. A 32/16/8-bit
/// sub-register (`eax`, `al`, `r8d`) is not a tracefs register; the error says to fetch the full
/// register with a narrower type. `None` for any other name.
fn tracefs_register(name: &str) -> Result<Option<&'static str>, String> {
    const FULL: [(&str, &str); 16] = [
        ("rax", "ax"),
        ("rbx", "bx"),
        ("rcx", "cx"),
        ("rdx", "dx"),
        ("rsi", "si"),
        ("rdi", "di"),
        ("rbp", "bp"),
        ("rsp", "sp"),
        ("r8", "r8"),
        ("r9", "r9"),
        ("r10", "r10"),
        ("r11", "r11"),
        ("r12", "r12"),
        ("r13", "r13"),
        ("r14", "r14"),
        ("r15", "r15"),
    ];
    const PARTS: [(&str, &str, &str); 8] = [
        ("eax", "al", "ax"),
        ("ebx", "bl", "bx"),
        ("ecx", "cl", "cx"),
        ("edx", "dl", "dx"),
        ("esi", "sil", "si"),
        ("edi", "dil", "di"),
        ("ebp", "bpl", "bp"),
        ("esp", "spl", "sp"),
    ];
    if let Some(&(_, tracefs)) = FULL.iter().find(|(long, short)| name == *long || name == *short) {
        return Ok(Some(tracefs));
    }
    let partial =
        PARTS.iter().find(|(d, b, _)| name == *d || name == *b).map(|(_, _, full)| (*full).to_owned()).or_else(|| {
            let base = name.strip_suffix(['d', 'w', 'b'])?;
            FULL[8..].iter().any(|(r, _)| *r == base).then(|| base.to_owned())
        });
    partial.map_or(Ok(None), |full| {
        Err(format!(
            "--fetch register %{name} is a sub-register; tracefs reads whole registers: use %{full} with a narrower type (e.g. %{full}:u32)"
        ))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // Parser tests assert valid and invalid grammar fixtures.

    use super::{parse_fetch_arg, parse_fetch_args};

    #[test]
    fn parses_bounded_register_and_nested_memory_fetches() {
        assert_eq!(parse_fetch_arg("value=+0x30(%rcx):u64").unwrap().name, "value");
        assert!(parse_fetch_arg("nested=+8(+0(%rsi)):u64").is_ok());
        assert!(parse_fetch_arg("direct=%rdi:u64").is_ok());
    }

    #[test]
    fn writes_registers_in_tracefs_names_and_rejects_sub_registers() {
        let expr = |spec: &str| parse_fetch_arg(spec).map(|a| a.expression);
        assert_eq!(expr("v=+0x30(%rcx):u64").as_deref(), Ok("+0x30(%cx):u64"));
        assert_eq!(expr("v=+8(+0(%rsi)):u32").as_deref(), Ok("+8(+0(%si)):u32"));
        assert_eq!(expr("v=%di:u64").as_deref(), Ok("%di:u64"));
        assert_eq!(expr("v=%r12:x64").as_deref(), Ok("%r12:x64"));
        let err = expr("v=%eax:u32").unwrap_err();
        assert!(err.contains("use %ax with a narrower type"), "{err}");
        assert!(expr("v=%r9d:u32").unwrap_err().contains("use %r9"));
        assert!(expr("v=%rip:u64").unwrap_err().contains("bounded typed"));
    }

    #[test]
    fn accepts_register_names_as_labels_and_rejects_reserved_names_with_list() {
        assert!(parse_fetch_arg("rdi=%di:u64").is_ok());
        assert!(parse_fetch_arg("rax=+0x10(%rdi):u64").is_ok());
        assert!(parse_fetch_arg("rbx=%bx:u64").is_ok());

        let err = parse_fetch_arg("ra=+0(%rsp):u64").unwrap_err();
        assert!(err.contains("must be a non-reserved identifier"));
        assert!(err.contains("ra"));
    }

    #[test]
    fn rejects_event_injection_duplicate_names_and_untyped_reads() {
        assert!(parse_fetch_arg("x=+0(%rdi);:u64").is_err());
        assert!(parse_fetch_arg("x=+0(%rdi)").is_err());
        assert!(parse_fetch_args(&["x=%rdi:u64".to_owned(), "x=%rsi:u64".to_owned()]).is_err());
    }
}

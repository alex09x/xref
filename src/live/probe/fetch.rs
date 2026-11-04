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
    if expression.len() > 128 || !valid_typed_expression(expression) {
        return Err("--fetch EXPR must be a bounded typed uprobe register or nested memory fetch".to_owned());
    }
    Ok(FetchArg { name: name.to_owned(), expression: expression.to_owned() })
}

fn valid_typed_expression(expression: &str) -> bool {
    let Some((node, kind)) = expression.rsplit_once(':') else { return false };
    if !matches!(kind, "u8" | "u16" | "u32" | "u64" | "x8" | "x16" | "x32" | "x64") {
        return false;
    }
    let mut at = 0;
    parse_node(node.as_bytes(), &mut at) && at == node.len()
}

fn parse_node(bytes: &[u8], at: &mut usize) -> bool {
    if *at >= bytes.len() {
        return false;
    }
    if bytes[*at] == b'%' {
        *at += 1;
        let start = *at;
        while *at < bytes.len() && (bytes[*at].is_ascii_alphanumeric() || bytes[*at] == b'_') {
            *at += 1;
        }
        return start < *at && valid_register(&bytes[start..*at]);
    }
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
            return false;
        }
    } else {
        while *at < bytes.len() && bytes[*at].is_ascii_digit() {
            *at += 1;
        }
    }
    if start == *at || bytes.get(*at) != Some(&b'(') {
        return false;
    }
    *at += 1;
    if !parse_node(bytes, at) || bytes.get(*at) != Some(&b')') {
        return false;
    }
    *at += 1;
    true
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.bytes();
    chars.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

const fn valid_register(name: &[u8]) -> bool {
    matches!(
        name,
        b"rax"
            | b"eax"
            | b"ax"
            | b"al"
            | b"rbx"
            | b"ebx"
            | b"bx"
            | b"bl"
            | b"rcx"
            | b"ecx"
            | b"cx"
            | b"cl"
            | b"rdx"
            | b"edx"
            | b"dx"
            | b"dl"
            | b"rsi"
            | b"esi"
            | b"si"
            | b"sil"
            | b"rdi"
            | b"edi"
            | b"di"
            | b"dil"
            | b"rbp"
            | b"ebp"
            | b"bp"
            | b"bpl"
            | b"rsp"
            | b"esp"
            | b"sp"
            | b"spl"
            | b"r8"
            | b"r8d"
            | b"r8w"
            | b"r8b"
            | b"r9"
            | b"r9d"
            | b"r9w"
            | b"r9b"
            | b"r10"
            | b"r11"
            | b"r12"
            | b"r13"
            | b"r14"
            | b"r15"
    )
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

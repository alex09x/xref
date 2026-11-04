/*
 * XRef — bounded live-probe value filters
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CompareOp {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }

    pub const fn test(self, left: u64, right: u64) -> bool {
        match self {
            Self::Eq => left == right,
            Self::Ne => left != right,
            Self::Lt => left < right,
            Self::Le => left <= right,
            Self::Gt => left > right,
            Self::Ge => left >= right,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueFilter {
    pub field: String,
    pub op: CompareOp,
    pub value: u64,
}

impl ValueFilter {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (field, op, value) = ["==", "!=", "<=", ">=", "<", ">"]
            .into_iter()
            .find_map(|op| text.split_once(op).map(|(field, value)| (field.trim(), op, value.trim())))
            .ok_or("--filter must be FIELD <OP> INTEGER")?;
        if !valid_field(field) {
            return Err("--filter FIELD must be a register name or --fetch name".to_owned());
        }
        let value = value
            .strip_prefix("0x")
            .map_or_else(|| value.parse::<u64>(), |hex| u64::from_str_radix(hex, 16))
            .map_err(|_| "--filter value must be an unsigned 64-bit integer")?;
        let op = match op {
            "==" => CompareOp::Eq,
            "!=" => CompareOp::Ne,
            "<" => CompareOp::Lt,
            "<=" => CompareOp::Le,
            ">" => CompareOp::Gt,
            ">=" => CompareOp::Ge,
            _ => return Err("unsupported --filter operator".to_owned()),
        };
        Ok(Self { field: field.to_owned(), op, value })
    }

    pub fn tracefs_expression(&self) -> String {
        format!("{} {} {}", self.field, self.op.as_str(), self.value)
    }
}

pub fn parse_filters(filters: &[String], regs: bool, fetch_names: &[String]) -> Result<Vec<ValueFilter>, String> {
    if filters.len() > 16 {
        return Err("--filter accepts at most 16 predicates".to_owned());
    }
    filters
        .iter()
        .map(|text| {
            let filter = ValueFilter::parse(text)?;
            if !field_available(&filter.field, regs, fetch_names) {
                return Err(format!("--filter field {:?} requires --regs or matching --fetch", filter.field));
            }
            Ok(filter)
        })
        .collect()
}

fn valid_field(field: &str) -> bool {
    !field.is_empty()
        && field.len() <= 31
        && field.bytes().enumerate().all(|(i, b)| {
            if i == 0 { b.is_ascii_alphabetic() || b == b'_' } else { b.is_ascii_alphanumeric() || b == b'_' }
        })
}

fn field_available(field: &str, regs: bool, fetch_names: &[String]) -> bool {
    (regs && matches!(field, "rdi" | "rsi" | "rdx" | "rcx" | "r8" | "r9" | "rax" | "rsp" | "rbp"))
        || fetch_names.iter().any(|name| name == field)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // Predicate tests assert valid and invalid grammar fixtures.

    use super::{CompareOp, ValueFilter, parse_filters};

    #[test]
    fn parses_numeric_filters_and_checks_available_fields() {
        let filter = ValueFilter::parse("value >= 0x20").unwrap();
        assert_eq!(filter, ValueFilter { field: "value".to_owned(), op: CompareOp::Ge, value: 32 });
        assert_eq!(filter.tracefs_expression(), "value >= 32");
        assert!(parse_filters(&["rdi == 7".to_owned()], true, &[]).is_ok());
        assert!(parse_filters(&["value > 7".to_owned()], false, &["value".to_owned()]).is_ok());
        assert!(parse_filters(&["value > 7".to_owned()], false, &[]).is_err());
    }

    #[test]
    fn rejects_arbitrary_filter_syntax() {
        for text in ["rdi == 1 || 1", "rdi == -1", "rdi == 0x", "rdi =~ 1", "rdi == 1; clear"] {
            assert!(ValueFilter::parse(text).is_err(), "accepted {text:?}");
        }
    }
}

/*
 * XRef Code — Bounded MCP stdio frames
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

const MAX_INPUT: usize = 65536;
const MAX_OUTPUT: usize = 262_144;

pub(super) enum Frame {
    Eof,
    Message(Vec<u8>),
    TooLarge,
}

pub(super) fn read(reader: &mut impl BufRead) -> io::Result<Frame> {
    let (mut bytes, mut oversized, mut any) = (Vec::new(), false, false);
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(if !any {
                Frame::Eof
            } else if oversized {
                Frame::TooLarge
            } else {
                Frame::Message(bytes)
            });
        }
        any = true;
        let newline = chunk.iter().position(|&b| b == b'\n');
        let count = newline.map_or(chunk.len(), |at| at + 1);
        if !oversized && bytes.len() + count <= MAX_INPUT {
            bytes.extend_from_slice(&chunk[..count]);
        } else {
            oversized = true;
        }
        reader.consume(count);
        if newline.is_some() {
            return Ok(if oversized { Frame::TooLarge } else { Frame::Message(bytes) });
        }
    }
}

pub(super) struct Message {
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

pub(super) fn id_key(id: &Value) -> Option<String> {
    (id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()).then(|| id.to_string())
}

pub(super) fn parse(bytes: &[u8]) -> Result<Message, Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| error(Value::Null, -32700, "invalid JSON"))?;
    if value["jsonrpc"] != "2.0" || !value["method"].is_string() || value.as_object().is_none() {
        return Err(error(Value::Null, -32600, "invalid JSON-RPC request"));
    }
    let id = value.get("id").cloned();
    if id.as_ref().is_some_and(|id| id_key(id).is_none()) {
        return Err(error(Value::Null, -32600, "invalid request ID"));
    }
    Ok(Message {
        id,
        method: value["method"].as_str().unwrap_or_default().to_owned(),
        params: value.get("params").cloned().unwrap_or(Value::Null),
    })
}

pub(super) fn result(id: Value, result: Value) -> Value {
    Value::Object(serde_json::Map::from_iter([
        ("jsonrpc".to_owned(), json!("2.0")),
        ("id".to_owned(), id),
        ("result".to_owned(), result),
    ]))
}
pub(super) fn error(id: Value, code: i64, message: &str) -> Value {
    Value::Object(serde_json::Map::from_iter([
        ("jsonrpc".to_owned(), json!("2.0")),
        ("id".to_owned(), id),
        ("error".to_owned(), json!({"code":code,"message":message})),
    ]))
}

pub(super) fn write(writer: &mut impl Write, value: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_OUTPUT {
        bytes = serde_json::to_vec(&error(value["id"].clone(), -32603, "response exceeds 256 KiB; reduce page limit"))
            .map_err(io::Error::other)?;
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mcp_wire_bounds_resynchronize_and_validate_ids() -> io::Result<()> {
        let mut source = vec![b'x'; MAX_INPUT + 8];
        source.extend_from_slice(b"\n{}\n");
        let mut reader = io::Cursor::new(source);
        assert!(matches!(read(&mut reader)?, Frame::TooLarge));
        assert!(matches!(read(&mut reader)?, Frame::Message(_)));
        assert!(matches!(read(&mut reader)?, Frame::Eof));
        assert!(parse(br#"{"jsonrpc":"2.0","method":"ping","id":null}"#).is_err());
        assert!(parse(br#"{"jsonrpc":"2.0","method":"ping","id":1.5}"#).is_err());
        assert!(parse(br#"{"jsonrpc":"2.0","method":"ping","id":"1"}"#).is_ok());
        assert_ne!(id_key(&json!(1)), id_key(&json!("1")));
        assert!(parse(b"[").is_err());
        Ok(())
    }
}

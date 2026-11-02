/*
 * XRef Code — MCP cancellation and admission rules
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{Analysis, Cancellation, Message, Phase, Server};
use serde_json::{Value, json};

#[test]
fn mcp_cancellation_keeps_admission_reserved_until_work_finishes() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = Analysis::open(&std::env::current_exe()?)?;
    let mut server = Server::new(analysis, Vec::<u8>::new());
    server.phase = Phase::Ready;
    let (first, second) = (Cancellation::default(), Cancellation::default());
    {
        let mut active = server.active.lock().map_err(|_| "poisoned test map")?;
        active.insert("1".to_owned(), first.clone());
        active.insert("2".to_owned(), second.clone());
    }
    let params = json!({"name":"xref_query","arguments":{"request":{"operation":"info"}}});
    server.dispatch(Message { id: Some(json!(3)), method: "tools/call".into(), params: params.clone() })?;
    server.dispatch(Message { id: None, method: "notifications/cancelled".into(), params: json!({"requestId":1}) })?;
    assert!(first.checkpoint().is_err());
    assert!(second.checkpoint().is_ok());
    assert_eq!(server.active.lock().map_err(|_| "poisoned test map")?.len(), 2);
    server.dispatch(Message { id: Some(json!(2)), method: "tools/call".into(), params })?;
    let output = server.writer.lock().map_err(|_| "poisoned writer")?.clone();
    let rows: Vec<Value> = output
        .split(|&b| b == b'\n')
        .filter(|row| !row.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["result"]["structuredContent"]["error"]["code"], "busy");
    assert_eq!(rows[1]["error"]["code"], -32600);
    assert!(second.checkpoint().is_ok());
    server.close();
    assert!(second.checkpoint().is_err());
    Ok(())
}

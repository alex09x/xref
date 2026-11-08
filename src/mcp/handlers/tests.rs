/*
 * XRef Code — MCP cancellation and admission rules
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::super::live_tool::LiveMcpContext;
use super::{Analysis, Cancellation, Message, Phase, Server};
use serde_json::{Value, json};
use std::path::PathBuf;

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

#[test]
fn default_mcp_hides_xref_live_and_opt_in_enforces_schema_budgets_and_concurrency()
-> Result<(), Box<dyn std::error::Error>> {
    let analysis = Analysis::open(&std::env::current_exe()?)?;
    let mut ro_server = Server::new(analysis, Vec::<u8>::new());
    ro_server.phase = Phase::Ready;
    ro_server.dispatch(Message { id: Some(json!(10)), method: "tools/list".into(), params: json!({}) })?;
    ro_server.dispatch(Message {
        id: Some(json!(11)),
        method: "tools/call".into(),
        params: json!({"name":"xref_live","arguments":{"request":{"operation":"maps"}}}),
    })?;
    let ro_rows: Vec<Value> = ro_server
        .writer
        .lock()
        .map_err(|_| "poisoned")?
        .split(|&b| b == b'\n')
        .filter(|row| !row.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()?;
    assert_eq!(ro_rows[0]["result"]["tools"].as_array().map(Vec::len), Some(1));
    assert_eq!(ro_rows[0]["result"]["tools"][0]["name"], "xref_query");
    assert_eq!(ro_rows[1]["error"]["code"], -32602);
    ro_server.close();

    let live_ctx = LiveMcpContext::synthetic_for_test(PathBuf::from("/nonexistent"), 4242, 999);
    let analysis2 = Analysis::open(&std::env::current_exe()?)?;
    let mut live_server = Server::new_with_live(analysis2, Some(live_ctx.clone()), Vec::<u8>::new());
    live_server.phase = Phase::Ready;
    live_server.dispatch(Message { id: Some(json!(20)), method: "tools/list".into(), params: json!({}) })?;

    // 1. Extra `pid` or `force_bin` field inside `request` -> rejected by `deny_unknown_fields` (-32602).
    live_server.dispatch(Message {
        id: Some(json!(21)),
        method: "tools/call".into(),
        params: json!({"name":"xref_live","arguments":{"request":{"operation":"maps","pid":1}}}),
    })?;

    // 2. Budget violation (`duration_ms: 6000 > 5000`) -> structured `invalid_request` tool error (`isError: true`).
    live_server.dispatch(Message {
        id: Some(json!(22)),
        method: "tools/call".into(),
        params: json!({"name":"xref_live","arguments":{"request":{"operation":"probe","addresses":["0x401000"],"duration_ms":6000}}}),
    })?;

    // 3. Single-active-live-call guard (`busy` when another live request is already running).
    let held_guard = live_ctx.try_acquire().ok_or("expected initial live guard")?;
    live_server.dispatch(Message {
        id: Some(json!(23)),
        method: "tools/call".into(),
        params: json!({"name":"xref_live","arguments":{"request":{"operation":"maps"}}}),
    })?;
    drop(held_guard);

    let live_rows: Vec<Value> = live_server
        .writer
        .lock()
        .map_err(|_| "poisoned")?
        .split(|&b| b == b'\n')
        .filter(|row| !row.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()?;
    assert_eq!(live_rows[0]["result"]["tools"].as_array().map(Vec::len), Some(2));
    assert_eq!(live_rows[0]["result"]["tools"][1]["name"], "xref_live");
    assert_eq!(live_rows[0]["result"]["tools"][1]["annotations"]["readOnlyHint"], false);
    assert_eq!(live_rows[1]["error"]["code"], -32602);
    assert_eq!(live_rows[2]["result"]["isError"], true);
    assert_eq!(live_rows[2]["result"]["structuredContent"]["error"]["code"], "invalid_request");
    assert_eq!(live_rows[3]["result"]["isError"], true);
    assert_eq!(live_rows[3]["result"]["structuredContent"]["error"]["code"], "busy");
    assert_eq!(live_rows[3]["result"]["structuredContent"]["pinned_process"]["pid"], 4242);
    live_server.close();
    Ok(())
}

/// #171/#174: a client sends its next request as soon as it reads an answer, so the request's slot
/// is free by the time the answer is written (no `busy` for strictly sequential requests).
#[test]
fn mcp_frees_the_request_slot_before_answering() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = Analysis::open(&std::env::current_exe()?)?;
    let mut server = Server::new(analysis, Vec::<u8>::new());
    server.phase = Phase::Ready;
    let params = json!({"name":"xref_query","arguments":{"request":{"operation":"info"}}});
    for id in 1..=20 {
        let seen = server.writer.lock().map_err(|_| "poisoned writer")?.len();
        server.dispatch(Message { id: Some(json!(id)), method: "tools/call".into(), params: params.clone() })?;
        let started = std::time::Instant::now();
        // Watch for the answer and the slot under the writer lock, as a reading client would.
        loop {
            let out = server.writer.lock().map_err(|_| "poisoned writer")?;
            if out.len() > seen {
                let active = server.active.lock().map_err(|_| "poisoned test map")?.len();
                drop(out);
                assert_eq!(active, 0, "request {id} still holds its slot after answering");
                break;
            }
            drop(out);
            assert!(started.elapsed() < std::time::Duration::from_secs(30), "request {id} never answered");
            std::thread::yield_now();
        }
    }
    server.close();
    Ok(())
}

#[test]
fn compact_mcp_omits_output_schema_and_deduplicates_text_channel() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = Analysis::open(&std::env::current_exe()?)?;
    let mut server = Server::new_with_options(analysis, None, true, Vec::<u8>::new());
    server.dispatch(Message {
        id: Some(json!(1)),
        method: "initialize".into(),
        params: json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "compact-test", "version": "1.0"}
        }),
    })?;
    server.dispatch(Message { id: None, method: "notifications/initialized".into(), params: json!({}) })?;
    server.dispatch(Message { id: Some(json!(2)), method: "tools/list".into(), params: json!({}) })?;
    let writer = std::sync::Arc::clone(&server.writer);
    server.dispatch(Message {
        id: Some(json!(3)),
        method: "tools/call".into(),
        params: json!({"name": "xref_query", "arguments": {"request": {"operation": "info"}}}),
    })?;
    for worker in server.workers.drain(..) {
        let _ = worker.join();
    }
    server.close();

    let raw = writer.lock().map_err(|_| "poisoned")?.clone();
    let rows: Vec<Value> = raw
        .split(|&b| b == b'\n')
        .filter(|row| !row.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 3);
    let init_inst = rows[0]["result"]["instructions"].as_str().ok_or("missing instructions")?;
    assert!(init_inst.contains("untrusted_binary_content"), "{init_inst}");
    assert!(rows[1]["result"]["tools"][0].get("outputSchema").is_none());
    let text = rows[2]["result"]["content"][0]["text"].as_str().ok_or("missing compact text")?;
    assert!(text.starts_with("ok op=info confidence=observed evidence_id=ev_"), "{text}");
    assert!(text.len() < 160, "compact text should not duplicate JSON: {text}");
    assert_eq!(rows[2]["result"]["structuredContent"]["operation"], "info");
    Ok(())
}

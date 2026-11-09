/*
 * XRef Code — Real MCP client and JSON CLI integration
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![cfg(target_os = "linux")]

use rmcp::{
    ClientLifecycleMode, ClientServiceExt, ServiceExt,
    model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation, ProtocolVersion},
    transport::TokioChildProcess,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

type Error = Box<dyn std::error::Error>;

#[path = "mcp/field_tests.rs"]
mod field_tests;
#[path = "mcp/investigate_tests.rs"]
mod investigate_tests;
#[path = "mcp/live_tests.rs"]
mod live_tests;
#[path = "mcp/macho_tests.rs"]
mod macho_tests;
#[path = "mcp/wire_tests.rs"]
mod wire_tests;

fn check(condition: bool, message: impl Into<String>) -> Result<(), Error> {
    if condition { Ok(()) } else { Err(message.into().into()) }
}

fn fixture() -> Result<PathBuf, Error> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let output =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("xref-mcp-fixture-{}-{id}", std::process::id()));
    std::fs::create_dir_all(output.parent().ok_or("fixture parent missing")?)?;
    let status = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .args(["--edition=2021", "-C", "opt-level=2", "-C", "force-unwind-tables=yes", "-C", "strip=symbols", "-o"])
        .arg(&output)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp.rs"))
        .status()?;
    check(status.success(), "fixture compilation failed")?;
    Ok(output)
}

fn cli(path: &Path, arguments: &[&str]) -> Result<std::process::Output, Error> {
    Ok(Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(path).args(arguments).output()?)
}

fn transport(path: &Path) -> Result<TokioChildProcess, Error> {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_xref"));
    command.arg("-b").arg(path).arg("mcp");
    Ok(TokioChildProcess::new(command)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_real_sdk_string_to_slice_and_json_cli_agree() -> Result<(), Error> {
    let image = fixture()?;
    let started = Instant::now();
    let config = ClientConfig::new(ClientCapabilities::default(), Implementation::new("xref-test", "1"))
        .with_protocol_version(ProtocolVersion::V_2025_11_25);
    let client = config.serve(transport(&image)?).await?;
    let startup = started.elapsed();
    let outcome: Result<(), Error> = async {
        let tools = client.list_all_tools().await?;
        check(tools.len()==1 && tools[0].name=="xref_query", "tool discovery mismatch")?;
        check(tools[0].output_schema.is_some(), "missing output schema")?;
        let request = |value:Value| CallToolRequestParams::new("xref_query").with_arguments(rmcp::object!({"request":value}));
        let begin=Instant::now();
        let info=client.call_tool(request(json!({"operation":"info"}))).await?;
        check(info.is_error!=Some(true),"info failed")?;
        let info=info.structured_content.ok_or("missing structured info")?;
        let mut expected_sha=String::with_capacity(64);
        for byte in Sha256::digest(std::fs::read(&image)?) { let _=write!(expected_sha,"{byte:02x}"); }
        check(info["image"]["sha256"]==expected_sha,"image digest mismatch")?;
        let strings=client.call_tool(request(json!({"operation":"strings","text":"XREF_MCP_BOUNDARY_NEEDLE"}))).await?;
        let strings=strings.structured_content.ok_or("missing string results")?;
        let address=strings["data"]["locations"][0].as_str().ok_or("needle not found")?;
        let refs=client.call_tool(request(json!({"operation":"refs","address":address}))).await?;
        let refs=refs.structured_content.ok_or("missing refs")?;
        let function=refs["data"]["references"][0]["function"]["start"].as_str().ok_or("needle has no function reference")?;
        let facts=client.call_tool(request(json!({"operation":"function","address":function}))).await?;
        let facts=facts.structured_content.ok_or("missing function facts")?;
        check(facts["data"]["function"]["range_origin"]=="eh_frame_fde","function provenance missing")?;
        let calls=client.call_tool(request(json!({"operation":"calls","address":function}))).await?;
        let calls=calls.structured_content.ok_or("missing calls")?;
        let call=calls["data"]["calls"][0]["address"].as_str().ok_or("fixture call missing")?;
        let target=calls["data"]["calls"][0]["target"].as_str().ok_or("direct target missing")?;
        let asm=client.call_tool(request(json!({"operation":"asm","address":function}))).await?;
        let asm=asm.structured_content.ok_or("missing assembly")?;
        check(asm["data"].is_object(),format!("asm failed: {}",asm["error"]))?;
        check(asm["data"]["instructions"].as_array().is_some_and(|rows|rows.iter().any(|row|row["address"]==call && row["direct_branch_target"]==target)),"call lacks instruction evidence")?;
        let sliced=client.call_tool(request(json!({"operation":"slice","address":function,"to":call}))).await?;
        check(sliced.is_error!=Some(true),"slice tool failed")?;
        let sliced=sliced.structured_content.ok_or("missing slice")?;
        let text=sliced["data"]["text"].as_str().ok_or("missing slice text")?;
        let investigation=begin.elapsed();
        check(!sliced["data"]["fragment"].as_bool().unwrap_or(true),"small slice was unexpectedly truncated")?;
        let human=cli(&image,&["slice",function,"--to",call])?;
        check(human.status.success() && human.stdout==text.as_bytes(),"MCP slice and human CLI differ")?;
        let c=client.call_tool(request(json!({"operation":"c","address":function}))).await?;
        let c=c.structured_content.ok_or("missing pseudo-C")?;
        let human=cli(&image,&["c",function])?;
        check(human.status.success() && human.stdout==c["data"]["text"].as_str().ok_or("missing pseudo-C text")?.as_bytes(),"MCP C and CLI differ")?;
        let mut assembled=String::new();
        let mut offset=0;
        for _ in 0..100 {
            let page=client.call_tool(request(json!({"operation":"c","address":function,"page":{"offset":offset,"limit":64}}))).await?;
            let page=page.structured_content.ok_or("missing C page")?;
            assembled.push_str(page["data"]["text"].as_str().ok_or("missing C fragment")?);
            let Some(next)=page["page"]["next_offset"].as_u64() else { break; };
            check(next>offset,"non-progressing text cursor")?; offset=next;
        }
        check(assembled==c["data"]["text"].as_str().ok_or("missing full C")?,"text continuation changed the result")?;
        let bad=client.call_tool(request(json!({"operation":"function","address":"not-hex"}))).await?;
        check(bad.is_error==Some(true),"invalid address should be a tool error")?;
        let bad=bad.structured_content.ok_or("missing structured error")?;
        check(bad["error"]["code"]=="invalid_address","wrong application error")?;
        let page=client.call_tool(request(json!({"operation":"asm","address":function,"page":{"limit":1}}))).await?;
        let page=page.structured_content.ok_or("missing page")?;
        check(page["page"]["next_offset"]==1,"continuation missing")?;
        let query_output=cli(&image,&["query",&json!({"operation":"function","address":function}).to_string()])?;
        let query_value:Value=serde_json::from_slice(&query_output.stdout)?;
        check(query_output.status.success() && query_value==facts,"JSON CLI and MCP facts differ")?;
        eprintln!("mcp walkthrough: image_bytes={}, image_sha256={}, startup_to_initialized={startup:?}, query_sequence={investigation:?}, with_parity_checks={:?}",info["image"]["bytes"],info["image"]["sha256"],begin.elapsed());
        Ok(())
    }.await;
    let cleanup = client.cancel().await;
    outcome?;
    cleanup?;
    let auto = ClientConfig::default()
        .serve_with_lifecycle(
            transport(&image)?,
            ClientLifecycleMode::Auto {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                legacy_version: Some(ProtocolVersion::V_2025_11_25),
            },
        )
        .await?;
    let discovered = auto.list_all_tools().await;
    let cleanup = auto.cancel().await;
    check(discovered?.len() == 1, "latest SDK auto fallback failed")?;
    cleanup?;
    std::fs::remove_file(image)?;
    Ok(())
}

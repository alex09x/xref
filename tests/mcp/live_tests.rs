/*
 * XRef — Stage L4 opt-in `xref_live` MCP end-to-end integration tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::*;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Stdio};

struct LiveFixtureChild {
    bin_path: PathBuf,
    child: Option<Child>,
}

impl LiveFixtureChild {
    fn compile_and_spawn(seed: u64) -> Result<(Self, BTreeMap<String, String>), Error> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bin_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("xref-mcp-live-target-{}-{id}", std::process::id()));
        std::fs::create_dir_all(bin_path.parent().ok_or("missing parent")?)?;
        let status = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
            .args(["--edition=2021", "-O", "-C", "strip=symbols", "-o"])
            .arg(&bin_path)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live_target_app.rs"))
            .status()?;
        check(status.success(), "live_target_app compilation failed")?;

        let mut child = Command::new(&bin_path)
            .arg(seed.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("missing child stdout")?;
        let mut reader = BufReader::new(stdout);
        let mut ready_line = String::new();
        reader.read_line(&mut ready_line)?;
        if !ready_line.starts_with("READY ") {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&bin_path);
            return Err(format!("unexpected readiness line: {ready_line:?}").into());
        }
        let mut kv = BTreeMap::new();
        for token in ready_line.split_ascii_whitespace().skip(1) {
            if let Some((k, v)) = token.split_once('=') {
                kv.insert(k.to_owned(), v.to_owned());
            }
        }
        Ok((Self { bin_path, child: Some(child) }, kv))
    }

    fn stop_child(&mut self) -> Result<(), Error> {
        if let Some(mut child) = self.child.take() {
            drop(child.stdin.take());
            let _ = child.wait()?;
        }
        Ok(())
    }
}

impl Drop for LiveFixtureChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.bin_path);
    }
}

fn live_transport(path: &Path, pid: &str) -> Result<TokioChildProcess, Error> {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_xref"));
    command.arg("-b").arg(path).args(["mcp", "--allow-live-pid", pid]);
    Ok(TokioChildProcess::new(command)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_live_tool_is_strictly_opt_in_pinned_to_pid_and_correlated_with_xref_query() -> Result<(), Error> {
    let other_bin = fixture()?;
    let (mut target, kv) = LiveFixtureChild::compile_and_spawn(777_888_999)?;
    let pid_str = kv.get("pid").ok_or("missing pid")?;
    let fn_va = kv.get("fn_va").ok_or("missing fn_va")?;
    let magic0 = kv.get("magic0").ok_or("missing magic0")?;
    let magic1 = kv.get("magic1").ok_or("missing magic1")?;
    let heap_va = kv.get("heap_va").ok_or("missing heap_va")?;

    // 1. Startup with `--allow-live-pid 0` or mismatched `--bin` must fail before emitting any stdout frame.
    let zero_pid = cli(&target.bin_path, &["mcp", "--allow-live-pid", "0"])?;
    check(!zero_pid.status.success() && zero_pid.stdout.is_empty(), "--allow-live-pid 0 must fail cleanly")?;
    let mismatch_bin = cli(&other_bin, &["mcp", "--allow-live-pid", pid_str])?;
    check(
        !mismatch_bin.status.success() && mismatch_bin.stdout.is_empty(),
        "mismatched --bin with --allow-live-pid must fail cleanly at startup",
    )?;
    let _ = std::fs::remove_file(&other_bin);

    // 2. Start MCP server pinned to `target`'s live PID.
    let config = ClientConfig::new(ClientCapabilities::default(), Implementation::new("xref-live-test", "1"))
        .with_protocol_version(ProtocolVersion::V_2025_11_25);
    let client = config.serve(live_transport(&target.bin_path, pid_str)?).await?;

    let outcome: Result<(), Error> = async {
        let tools = client.list_all_tools().await?;
        check(
            tools.len() == 2 && tools[0].name == "xref_query" && tools[1].name == "xref_live",
            "expected xref_query + xref_live when --allow-live-pid is set",
        )?;
        check(tools[1].output_schema.is_some(), "xref_live missing output schema")?;

        let live_call =
            |v: Value| CallToolRequestParams::new("xref_live").with_arguments(rmcp::object!({"request": v}));
        let query_call =
            |v: Value| CallToolRequestParams::new("xref_query").with_arguments(rmcp::object!({"request": v}));

        // 2a. `maps` on pinned process
        let maps = client.call_tool(live_call(json!({"operation": "maps"}))).await?;
        check(maps.is_error != Some(true), "live maps failed")?;
        let maps_sc = maps.structured_content.ok_or("missing maps structured_content")?;
        check(maps_sc["pinned_process"]["pid"] == pid_str.parse::<u64>()?, "pinned pid mismatch")?;
        check(maps_sc["data"]["operation"] == "live_maps", "unexpected live_maps operation")?;
        check(
            maps_sc["data"]["process"]["binary_match"] == "verified_build_id"
                || maps_sc["data"]["process"]["binary_match"] == "verified_sha256",
            "expected verified binary match",
        )?;

        // 2b. `resolve` runtime `fn_va` -> static function start -> feed directly into `xref_query` pseudo-C!
        let resolve = client.call_tool(live_call(json!({"operation": "resolve", "addresses": [fn_va]}))).await?;
        check(resolve.is_error != Some(true), "live resolve failed")?;
        let resolve_sc = resolve.structured_content.ok_or("missing resolve structured_content")?;
        let entry0 = &resolve_sc["data"]["addresses"][0];
        check(entry0["direction"] == "runtime_to_static", "expected runtime_to_static")?;
        let fn_start = entry0["function_start"].as_str().ok_or("missing function_start")?;

        let c_res = client.call_tool(query_call(json!({"operation": "c", "address": fn_start}))).await?;
        check(c_res.is_error != Some(true), "xref_query c on resolved static function failed")?;
        let c_text = c_res.structured_content.ok_or("missing c structured_content")?["data"]["text"]
            .as_str()
            .ok_or("missing c text")?
            .to_owned();
        check(c_text.contains("0x1337"), "decompiled vault_mix_secret did not contain expected multiplier 0x1337")?;

        // 2c. `memscan` finds the live `VaultRecord` on the heap and classifies its `mix_fn` pointer as `code_ptr` to `fn_start`.
        let scan = client
            .call_tool(live_call(json!({
                "operation": "memscan",
                "values": [magic0, magic1],
                "before_words": 0,
                "after_words": 4,
                "max_hits": 16,
                "timeout_ms": 3000
            })))
            .await?;
        check(scan.is_error != Some(true), "live memscan failed")?;
        let scan_sc = scan.structured_content.ok_or("missing memscan structured_content")?;
        let hits = scan_sc["data"]["hits"].as_array().ok_or("missing hits array")?;
        let record_hit =
            hits.iter().find(|h| h["runtime_va"] == *heap_va).ok_or("VaultRecord heap hit not found in MCP memscan")?;
        let ctx_words = record_hit["context"].as_array().ok_or("missing context words")?;
        check(
            ctx_words
                .iter()
                .any(|w| w["relative_offset"] == 24 && w["kind"] == "code_ptr" && w["target_function"] == fn_start),
            "MCP memscan did not classify +0x18 mix_fn as code_ptr to fn_start",
        )?;

        // 3. Stop the pinned target process while MCP stays open; next `xref_live` call must fail with `process_exited` while `xref_query` continues working!
        target.stop_child()?;
        let after_exit = client.call_tool(live_call(json!({"operation": "maps"}))).await?;
        check(after_exit.is_error == Some(true), "xref_live after target exit must report isError=true")?;
        let after_sc = after_exit.structured_content.ok_or("missing error structured_content")?;
        let err_code = after_sc["error"]["code"].as_str().unwrap_or("");
        check(
            err_code == "process_exited" || err_code == "process_changed",
            format!("expected process_exited/process_changed after target exit, got {err_code:?}"),
        )?;

        let static_still_ok = client.call_tool(query_call(json!({"operation": "info"}))).await?;
        check(static_still_ok.is_error != Some(true), "static xref_query should still succeed after live target exit")?;
        Ok(())
    }
    .await;

    let cleanup = client.cancel().await;
    outcome?;
    cleanup?;
    Ok(())
}

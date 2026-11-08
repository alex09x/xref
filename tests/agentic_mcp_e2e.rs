/*
 * XRef Code — End-to-end MCP SDK & CLI tests for provenance, auto-triage, and structured ops
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use miniz_oxide::deflate::compress_to_vec_zlib;
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation, ProtocolVersion},
    transport::TokioChildProcess,
};
use serde_json::{Value, json};

type Error = Box<dyn std::error::Error + Send + Sync>;

fn check(condition: bool, message: &str) -> Result<(), Error> {
    if condition { Ok(()) } else { Err(message.into()) }
}

fn build_fixture_with_dep_v0() -> Result<(tempfile::TempDir, PathBuf), Error> {
    let dir = tempfile::tempdir()?;
    let c_src = dir.path().join("fixture.c");
    let dep_bin = dir.path().join("dep_v0.bin");
    let out_elf = dir.path().join("fixture_auditable");

    let manifest = r#"{
        "format": 1,
        "packages": [
            {"name": "tokio", "version": "1.44.1", "source": "crates.io", "dependencies": []},
            {"name": "serde", "version": "1.0.219", "source": "crates.io", "dependencies": []},
            {"name": "fixture-bin", "version": "0.9.2", "source": "local", "root": true, "dependencies": [0, 1]}
        ]
    }"#;
    std::fs::write(&dep_bin, compress_to_vec_zlib(manifest.as_bytes(), 6))?;

    std::fs::write(
        &c_src,
        r#"
        #include <stdint.h>
        struct State {
            uint64_t header;
            uint64_t count;
            uint32_t flags;
        };
        static const char TAG[] = "AGENTIC_TRIAGE_NEEDLE";
        __attribute__((noinline)) uint64_t inspect_state(struct State *st) {
            if (st->flags == 0x42) {
                return st->count + (uint64_t)(uintptr_t)TAG;
            }
            return st->header;
        }
        int main(int argc, char **argv) {
            struct State s = { (uint64_t)argc, 7, 0x42 };
            return (int)inspect_state(&s);
        }
        "#,
    )?;

    let cc_status = Command::new("cc")
        .args(["-O1", "-fno-omit-frame-pointer", "-funwind-tables"])
        .arg(&c_src)
        .arg("-o")
        .arg(&out_elf)
        .status()?;
    check(cc_status.success(), "cc failed to compile fixture")?;

    let objcopy_status = Command::new("objcopy")
        .arg("--add-section")
        .arg(format!(".dep-v0={}", dep_bin.display()))
        .arg(&out_elf)
        .status()?;
    check(objcopy_status.success(), "objcopy failed to embed .dep-v0")?;

    Ok((dir, out_elf))
}

fn spawn_mcp(path: &Path, compact: bool) -> Result<TokioChildProcess, Error> {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_xref"));
    cmd.arg("-b").arg(path).arg("mcp");
    if compact {
        cmd.arg("--compact");
    }
    Ok(TokioChildProcess::new(cmd)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_sdk_triage_dependencies_card_find_layout_and_compact_mode() -> Result<(), Error> {
    let (_dir, elf) = build_fixture_with_dep_v0()?;

    // 1. CLI `xref deps` human + JSON modes.
    let cli_deps =
        Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(&elf).args(["deps", "--filter", "tok"]).output()?;
    check(cli_deps.status.success(), "xref deps CLI failed")?;
    let deps_stdout = String::from_utf8_lossy(&cli_deps.stdout);
    check(deps_stdout.contains("tokio") && deps_stdout.contains("1.44.1"), "xref deps filter missed tokio")?;

    // 2. Compact MCP client via real rmcp SDK.
    let config = ClientConfig::new(ClientCapabilities::default(), Implementation::new("xref-e2e", "1"))
        .with_protocol_version(ProtocolVersion::V_2025_11_25);
    let client = config.serve(spawn_mcp(&elf, true)?).await?;

    let outcome: Result<(), Error> = async {
        let tools = client.list_all_tools().await?;
        check(tools.len() == 1 && tools[0].name == "xref_query", "unexpected tool list")?;
        check(tools[0].output_schema.is_none(), "compact mode should omit outputSchema")?;

        let req = |val: Value| CallToolRequestParams::new("xref_query").with_arguments(rmcp::object!({"request": val}));

        let info_res = client.call_tool(req(json!({"operation": "info"}))).await?;
        check(info_res.is_error != Some(true), "info returned error")?;
        let info = info_res.structured_content.ok_or("missing info structuredContent")?;
        check(info["confidence"] == "observed", "wrong info confidence")?;
        check(info["untrusted_binary_content"] == true, "missing untrusted_binary_content")?;
        check(info["evidence_id"].as_str().is_some_and(|s| s.starts_with("ev_")), "missing evidence_id")?;
        check(info["data"]["triage"]["language"] == "rust", "dep-v0 should classify language as rust")?;
        check(info["data"]["triage"]["embedded_dependencies"]["root_package"] == "fixture-bin", "wrong root_package")?;
        check(info["data"]["triage"]["embedded_dependencies"]["count"] == 3, "wrong dep count")?;

        let deps_res = client.call_tool(req(json!({"operation": "dependencies", "filter": "serde"}))).await?;
        let deps = deps_res.structured_content.ok_or("missing dependencies")?;
        check(deps["data"]["packages"][0]["name"] == "serde", "serde missing from dependencies op")?;

        let find_res =
            client.call_tool(req(json!({"operation": "find", "refs": ["AGENTIC_TRIAGE_NEEDLE"], "imm": [66]}))).await?;
        let found = find_res.structured_content.ok_or("missing find response")?;
        check(found["confidence"] == "derived", "wrong find confidence")?;
        let fn_addr = found["data"]["matches"][0]["function"]["start"]
            .as_str()
            .ok_or("expected inspect_state match from multi-predicate find")?;

        let card_res = client.call_tool(req(json!({"operation": "card", "address": fn_addr}))).await?;
        let card = card_res.structured_content.ok_or("missing card response")?;
        check(card["confidence"] == "inferred", "wrong card confidence")?;
        check(
            card["data"]["card"]["inputs"]["registers"].as_array().is_some_and(|regs| regs.iter().any(|r| r == "rdi")),
            "card should recover rdi input register",
        )?;

        let layout_res =
            client.call_tool(req(json!({"operation": "layout", "address": fn_addr, "reg": "rdi"}))).await?;
        let layout = layout_res.structured_content.ok_or("missing layout response")?;
        check(
            layout["data"]["fields"].as_array().is_some_and(|f| !f.is_empty()),
            "layout should recover struct State fields on rdi",
        )?;
        Ok(())
    }
    .await;

    let cleanup = client.cancel().await;
    outcome?;
    cleanup?;
    Ok(())
}

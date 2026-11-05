/*
 * XRef — field searches in one long-lived MCP process agree with one-shot CLI searches
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
use std::io::{BufRead as _, BufReader, Write as _};
use std::process::Stdio;

fn cli_report(binary: &std::path::Path, cache: &std::path::Path, args: &[&str]) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
    command
        .arg("-b")
        .arg(binary)
        .arg("field")
        .args(args)
        .arg("--json")
        .env("XDG_CACHE_HOME", cache)
        .env("XREF_NO_RESULT_CACHE", "1");
    serde_json::from_slice(&run(&mut command).stdout).unwrap()
}

/// Several different key sets and filters in one MCP session reuse the whole-image scan, writer index
/// and analyzed functions; every report must equal the one-shot CLI report for the same query.
#[test]
fn mcp_field_session_reuses_state_without_changing_results() {
    let fixture = Fixture::build("release");
    let binary = fixture.stripped();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let cache = std::env::temp_dir().join(format!("xref-mcp-field-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&cache).unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .arg("mcp")
        .env("XDG_CACHE_HOME", &cache)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = server.stdin.take().unwrap();
    let mut output = BufReader::new(server.stdout.take().unwrap());
    let mut id = 0;
    let mut call = |method: &str, params: Value| -> Value {
        id += 1;
        let message = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(input, "{message}").unwrap();
        if method == "initialize" {
            writeln!(input, "{}", serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
                .unwrap();
        }
        loop {
            let mut line = String::new();
            assert!(output.read_line(&mut line).unwrap() > 0, "server closed");
            let response: Value = serde_json::from_str(&line).unwrap();
            if response["id"] == id {
                return response;
            }
        }
    };
    call(
        "initialize",
        serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "0"}}),
    );
    let queries: [(Value, &[&str]); 4] = [
        (
            serde_json::json!({"keys": ["c","m","e"], "writes_all_of": ["m","e"]}),
            &["--keys", "c,m,e", "--write", "--writes-all-of", "m,e", "--limit", "16"],
        ),
        (
            serde_json::json!({"keys": ["c","m","e"], "writes_all_of": ["c","m","e"], "limit": 8}),
            &["--keys", "c,m,e", "--write", "--writes-all-of", "c,m,e", "--limit", "8"],
        ),
        (
            serde_json::json!({"keys": ["c","m","e"], "writes_all_of": ["m","e"], "writer_root": "argument"}),
            &["--keys", "c,m,e", "--write", "--writes-all-of", "m,e", "--writer-root", "argument", "--limit", "16"],
        ),
        (serde_json::json!({"keys": ["c","m","e"], "layout_only": true}), &["--keys", "c,m,e", "--layout-only"]),
    ];
    for (request, args) in queries {
        let response = call(
            "tools/call",
            serde_json::json!({"name": "xref_query", "arguments": {"request": {"operation": "field", "request": request}}}),
        );
        let report = &response["result"]["structuredContent"]["data"]["report"];
        let expected = cli_report(&binary, &cache, args);
        assert_eq!(report["candidates"], expected["candidates"], "layouts differ for {args:?}");
        assert_eq!(report["accessor_candidates"], expected["accessor_candidates"], "writers differ for {args:?}");
        assert_eq!(report["status"], expected["status"], "status differs for {args:?}");
    }
    drop(input);
    let _ = server.wait();
    let _ = fs::remove_dir_all(&cache);
}

/// With an empty cache the MCP server builds the writer index during its start-up warm-up, so the
/// first writer query reuses it instead of analysing every function.
#[test]
fn mcp_warm_up_builds_the_writer_index_from_a_cold_cache() {
    let fixture = Fixture::build("release");
    let binary = fixture.stripped();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let cache = std::env::temp_dir().join(format!("xref-mcp-warm-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&cache).unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .arg("mcp")
        .env("XDG_CACHE_HOME", &cache)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Scan index + writer index appear on disk once the warm-up has finished.
    let index = cache.join("xref/field-index-v1");
    let ready = (0..600).any(|_| {
        let files = fs::read_dir(&index)
            .map_or(0, |entries| entries.filter_map(Result::ok).filter(|e| e.path().is_file()).count());
        files >= 2 || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            false
        }
    });
    assert!(ready, "warm-up did not write the scan and writer indexes");
    let mut input = server.stdin.take().unwrap();
    let mut output = BufReader::new(server.stdout.take().unwrap());
    let mut send = |message: Value| {
        writeln!(input, "{message}").unwrap();
    };
    send(
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "0"}}}),
    );
    send(serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    send(
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "xref_query", "arguments": {"request": {"operation": "field", "request": {"keys": ["c","m","e"], "writes_all_of": ["m","e"]}}}}}),
    );
    let report = loop {
        let mut line = String::new();
        assert!(output.read_line(&mut line).unwrap() > 0, "server closed");
        let response: Value = serde_json::from_str(&line).unwrap();
        if response["id"] == 2 {
            break response["result"]["structuredContent"]["data"]["report"].clone();
        }
    };
    assert_eq!(report["coverage"]["writer_index_cache_hits"], 1, "{report}");
    assert!(!report["accessor_candidates"].as_array().unwrap().is_empty(), "{report}");
    drop(input);
    let _ = server.wait();
    let _ = fs::remove_dir_all(&cache);
}

/// After a (forced) slow run the CLI starts a field daemon; the next `xref field` with other arguments
/// is answered by it with exactly the report a local run prints.
#[cfg(unix)]
#[test]
fn cli_field_daemon_answers_with_the_local_report() {
    let fixture = Fixture::build("release");
    let binary = fixture.stripped();
    let cache = std::path::PathBuf::from(format!("/tmp/xd{}", std::process::id())); // short: socket path limit
    fs::create_dir_all(&cache).unwrap();
    // A cache root writable by the group (umask 002) is rightly not trusted for the daemon socket.
    fs::set_permissions(&cache, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let field = |args: &[&str], envs: &[(&str, &str)]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
        command
            .arg("-b")
            .arg(&binary)
            .arg("field")
            .args(args)
            .env("XDG_CACHE_HOME", &cache)
            .env("XREF_FIELD_DAEMON_MIN_MS", "0")
            .env("XREF_FIELD_DAEMON_IDLE_SECS", "20");
        for (key, value) in envs {
            command.env(key, value);
        }
        run(&mut command)
    };
    let _ = field(&["--keys", "c,m,e", "--layout-only"], &[]);
    let daemon = cache.join("xref/field-index-v1/daemon");
    let ready = (0..300).any(|_| {
        let sockets = fs::read_dir(&daemon).map_or(0, |entries| entries.filter_map(Result::ok).count());
        sockets > 0 || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            false
        }
    });
    assert!(ready, "no field daemon socket appeared");
    let args = ["--keys", "c,m,e", "--write", "--writes-all-of", "m,e", "--limit", "8"];
    let via_daemon = field(&args, &[("XREF_NO_RESULT_CACHE", "1")]);
    let local = field(&args, &[("XREF_NO_RESULT_CACHE", "1"), ("XREF_NO_DAEMON", "1")]);
    assert!(String::from_utf8_lossy(&via_daemon.stderr).contains("field daemon"), "not answered by the daemon");
    assert_eq!(via_daemon.stdout, local.stdout, "daemon and local reports differ");
    let _ = fs::remove_dir_all(&cache);
}

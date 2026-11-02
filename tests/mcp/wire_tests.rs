/*
 * XRef Code — MCP wire and input-error integration
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{Error, check, cli, fixture};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Stdio},
    sync::mpsc,
    thread::JoinHandle,
    time::Duration,
};

struct RawClient {
    child: Child,
    input: Option<ChildStdin>,
    frames: mpsc::Receiver<Result<Value, String>>,
    reader: Option<JoinHandle<()>>,
}

impl RawClient {
    fn start(path: &std::path::Path) -> Result<Self, Error> {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_xref"))
            .arg("-b")
            .arg(path)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().ok_or("missing stdin")?;
        let stdout = child.stdout.take().ok_or("missing stdout")?;
        let (send, frames) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let value =
                    line.map_err(|e| e.to_string()).and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()));
                if send.send(value).is_err() {
                    break;
                }
            }
        });
        Ok(Self { child, input: Some(input), frames, reader: Some(reader) })
    }
    fn send(&mut self, value: &Value) -> Result<(), Error> {
        self.bytes(format!("{value}\n").as_bytes())
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let input = self.input.as_mut().ok_or("stdin already closed")?;
        input.write_all(bytes)?;
        input.flush()?;
        Ok(())
    }
    fn read(&self) -> Result<Value, Error> {
        self.frames.recv_timeout(Duration::from_secs(10))?.map_err(Into::into)
    }
    fn finish(&mut self) -> Result<(), Error> {
        self.input.take();
        for _ in 0..500 {
            if let Some(status) = self.child.try_wait()? {
                return check(status.success(), "MCP did not exit cleanly on EOF");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err("MCP shutdown exceeded five seconds".into())
    }
}
impl Drop for RawClient {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn mcp_malformed_frames_and_notifications_keep_stdout_json() -> Result<(), Error> {
    let image = fixture()?;
    let mut client = RawClient::start(&image)?;
    client.send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))?;
    check(client.read()?["error"]["code"] == -32002, "pre-initialization request was accepted")?;
    client.bytes(b"{\n")?;
    check(client.read()?["error"]["code"] == -32700, "invalid JSON was not rejected")?;
    client.send(&json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}))?;
    check(client.read()?["error"]["code"] == -32602, "invalid initialize was accepted")?;
    client.send(&json!({"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw-test","version":"1"}}}))?;
    check(client.read()?["result"]["protocolVersion"] == "2025-11-25", "protocol negotiation failed")?;
    client.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":17}))?;
    client.send(&json!({"jsonrpc":"2.0","id":30,"method":"tools/list"}))?;
    check(client.read()?["error"]["code"] == -32002, "malformed notification advanced initialization")?;
    client.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
    client.send(&json!({"jsonrpc":"2.0","id":31,"method":"tools/list","params":"bad"}))?;
    check(client.read()?["error"]["code"] == -32602, "scalar MCP parameters were accepted")?;
    client.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999}}))?;
    client.send(&json!({"jsonrpc":"2.0","id":4,"method":"ping"}))?;
    check(client.read()?["id"] == 4, "notification incorrectly produced a response")?;
    client.send(&json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"xref_query","arguments":{"request":{"operation":"info","extra":1}}}}))?;
    check(client.read()?["error"]["code"] == -32602, "unknown query field was accepted")?;
    let mut oversized = vec![b'x'; 65538];
    oversized.push(b'\n');
    client.bytes(&oversized)?;
    client.send(&json!({"jsonrpc":"2.0","id":6,"method":"ping"}))?;
    check(client.read()?["error"]["code"] == -32700, "oversized frame was accepted")?;
    check(client.read()?["id"] == 6, "frame reader did not resynchronize")?;
    client.send(&json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"xref_query","arguments":{"request":{"operation":"info"}}}}))?;
    let info = client.read()?;
    check(info["id"] == 7 && info["result"]["structuredContent"]["schema_version"] == 1, "server did not recover")?;
    client.finish()?;
    std::fs::remove_file(image)?;
    Ok(())
}

#[test]
fn mcp_json_cli_rejects_unsupported_images_and_invalid_json() -> Result<(), Error> {
    let image = fixture()?;
    let bad = cli(&image, &["query", "{"])?;
    check(!bad.status.success(), "invalid request exited successfully")?;
    let value: Value = serde_json::from_slice(&bad.stdout)?;
    check(value["error"]["code"] == "invalid_request", "invalid JSON lacked structured error")?;
    let mut data = std::fs::read(&image)?;
    data[18..20].copy_from_slice(&183u16.to_le_bytes()); // ELF EM_AARCH64
    let unsupported = image.with_extension("arm64");
    std::fs::write(&unsupported, &data)?;
    let output = cli(&unsupported, &["query", r#"{"operation":"info"}"#])?;
    let value: Value = serde_json::from_slice(&output.stdout)?;
    check(!output.status.success() && value["error"]["code"] == "unsupported_image", "unsupported ELF was accepted")?;
    let server = cli(&unsupported, &["mcp"])?;
    check(!server.status.success() && server.stdout.is_empty(), "startup failure contaminated protocol stdout")?;
    std::fs::write(&unsupported, b"MZ unsupported input")?;
    let output = cli(&unsupported, &["query", r#"{"operation":"info"}"#])?;
    check(
        serde_json::from_slice::<Value>(&output.stdout)?["error"]["code"] == "unsupported_image",
        "non-ELF was accepted",
    )?;
    std::fs::remove_file(image)?;
    std::fs::remove_file(unsupported)?;
    Ok(())
}

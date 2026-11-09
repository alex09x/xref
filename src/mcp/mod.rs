/*
 * XRef Code — Local stdio MCP adapter
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

mod compact;
mod handlers;
pub mod live_tool;
pub mod live_tool_exec;
mod wire;

use crate::api::Analysis;
use handlers::Server;
use live_tool::LiveMcpContext;
use std::{
    io::{self, BufRead},
    path::Path,
};

#[allow(dead_code)]
pub fn serve(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    serve_with_options(path, None, false)
}

#[allow(dead_code)]
pub fn serve_with_live(path: &Path, allow_live_pid: Option<u32>) -> Result<(), Box<dyn std::error::Error>> {
    serve_with_options(path, allow_live_pid, false)
}

pub fn serve_with_options(
    path: &Path,
    allow_live_pid: Option<u32>,
    compact: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let analysis = Analysis::open(path)?;
    let live = match allow_live_pid {
        Some(pid) => Some(LiveMcpContext::open(path, pid)?),
        None => None,
    };
    let input = io::stdin();
    serve_io(analysis, live, compact, input.lock(), io::stdout())?;
    Ok(())
}

fn serve_io(
    analysis: Analysis,
    live: Option<LiveMcpContext>,
    compact: bool,
    mut input: impl BufRead,
    output: impl io::Write + Send + 'static,
) -> io::Result<()> {
    let mut server = Server::new_with_options(analysis, live, compact, output);
    let result = (|| {
        loop {
            match wire::read(&mut input)? {
                wire::Frame::Eof => return Ok(()),
                wire::Frame::TooLarge => {
                    server.send(&wire::error(serde_json::Value::Null, -32700, "input frame exceeds 64 KiB"))?;
                }
                wire::Frame::Message(bytes) => {
                    if bytes.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    match wire::parse(&bytes) {
                        Ok(message) => server.dispatch(message)?,
                        Err(error) => server.send(&error)?,
                    }
                }
            }
        }
    })();
    server.close();
    result
}

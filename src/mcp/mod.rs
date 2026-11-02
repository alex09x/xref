/*
 * XRef Code — Local stdio MCP adapter
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

mod handlers;
mod wire;

use crate::api::Analysis;
use handlers::Server;
use std::{
    io::{self, BufRead},
    path::Path,
};

pub fn serve(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let analysis = Analysis::open(path)?;
    let input = io::stdin();
    serve_io(analysis, input.lock(), io::stdout())?;
    Ok(())
}

fn serve_io(analysis: Analysis, mut input: impl BufRead, output: impl io::Write + Send + 'static) -> io::Result<()> {
    let mut server = Server::new(analysis, output);
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

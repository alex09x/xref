/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! In-memory HTTP web workbench (`xref web`) serving `docs/` and sub-millisecond JSON queries.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use crate::cli::{Command, parse_number};
use crate::commands::{self, Res};
use crate::image::Image;
use crate::locations::{Location, locations};
use crate::runtime::RuntimeMap;
use crate::scan::decode;
use crate::source::location_at;

const INDEX_HTML: &str = include_str!("../docs/index.html");
const STYLES_CSS: &str = include_str!("../docs/styles.css");
const APP_JS: &str = include_str!("../docs/app.js");

struct FnMeta {
    start: u64,
    end: u64,
    label: String,
    interesting: bool,
}

pub struct WebCtx<'a> {
    image: &'a Image,
    binary: String,
    load_ms: String,
    locs: Vec<Location>,
    files_count: usize,
    code_bytes: u64,
    runtime: RuntimeMap,
    metas: Vec<FnMeta>,
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

fn url_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(val) = u8::from_str_radix(hex, 16)
        {
            out.push(val);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(url_decode(v));
        }
    }
    None
}

impl<'a> WebCtx<'a> {
    pub fn build(image: &'a Image, bin_path: &Path, loaded: Duration) -> Self {
        let locs = locations(image);
        let mut files: Vec<&str> = locs.iter().map(|l| l.file.as_str()).collect();
        files.sort_unstable();
        files.dedup();
        let files_count = files.len();
        let runtime = RuntimeMap::detect(image);
        let sym_map: HashMap<u64, &str> = image.symbols.iter().map(|(a, n)| (*a, n.as_str())).collect();
        let code_bytes: u64 = image.functions.iter().map(|f| f.end - f.start).sum();
        let metas: Vec<FnMeta> = image
            .functions
            .par_iter()
            .map(|f| {
                if let Some(&sym) = sym_map.get(&f.start) {
                    return FnMeta { start: f.start, end: f.end, label: sym.to_owned(), interesting: true };
                }
                if let Some(rt) = runtime.get(f.start) {
                    return FnMeta {
                        start: f.start,
                        end: f.end,
                        label: format!("/* {} */", rt.name()),
                        interesting: true,
                    };
                }
                let mut first_loc: Option<String> = None;
                if let Some(code) = image.code(f) {
                    decode(code, f.start, |ins| {
                        if first_loc.is_none()
                            && ins.is_ip_rel_memory_operand()
                            && let Some(l) = location_at(&locs, ins.ip_rel_memory_address())
                        {
                            first_loc = Some(format!("{}:{}", l.file, l.line));
                        }
                    });
                }
                let interesting =
                    first_loc.as_deref().is_some_and(|s| !s.starts_with("/rustc/") && !s.starts_with('/'));
                FnMeta { start: f.start, end: f.end, label: first_loc.unwrap_or_default(), interesting }
            })
            .collect();
        let binary = bin_path.file_name().map_or_else(|| "binary".to_owned(), |s| s.to_string_lossy().into_owned());
        Self { image, binary, load_ms: format!("{loaded:.1?}"), locs, files_count, code_bytes, runtime, metas }
    }

    fn render_fn_list(&self, filter: &str) -> String {
        let q = filter.trim().to_ascii_lowercase();
        let mut items = Vec::new();
        for m in &self.metas {
            if q.is_empty() && !m.interesting && self.metas.len() > 80 {
                continue;
            }
            let addr_hex = format!("{:#x}", m.start);
            if !q.is_empty() && !addr_hex.contains(&q) && !m.label.to_ascii_lowercase().contains(&q) {
                continue;
            }
            let _ = write!(
                items,
                "{{\"addr\":\"{addr_hex}\",\"end\":\"{:#x}\",\"size\":{},\"label\":\"{}\"}},",
                m.end,
                m.end - m.start,
                json_escape(&m.label)
            );
            if items.len() > 12_000 {
                break;
            }
        }
        let body = String::from_utf8_lossy(&items);
        format!("[{}]", body.trim_end_matches(','))
    }

    fn inspect_json(&self, addr_str: &str, reg: &str) -> (u16, String) {
        let Ok(addr) = parse_number(addr_str) else {
            return (400, "{\"error\":\"invalid address\"}".to_owned());
        };
        let t0 = Instant::now();
        let Ok((start, pseudo_c)) = crate::c::c_one(self.image, &self.locs, &self.runtime, addr, None, None) else {
            return (404, "{\"error\":\"no function at address\"}".to_owned());
        };
        let end = self.image.function_at(start).map_or(start, |f| f.end);
        let mut layout_buf = Vec::new();
        let _ = crate::layout::layout(self.image, &format!("{start:#x}"), reg, true, &mut layout_buf);
        let mut asm_buf = Vec::new();
        let _ = crate::listing::asm(self.image, start, None, None, &mut asm_buf);
        let mut calls_buf = Vec::new();
        let _ = writeln!(calls_buf, "=== Callers ===");
        let _ = commands::run(self.image, Command::Callers { addr: start }, &mut calls_buf);
        let _ = writeln!(calls_buf, "\n=== Callees ===");
        let _ = commands::run(self.image, Command::Calls { addr: start }, &mut calls_buf);
        let elapsed = format!("{:.2?}", t0.elapsed());
        let json = format!(
            "{{\"addr\":\"{start:#x}\",\"end\":\"{end:#x}\",\"size\":{},\"pseudo_c\":\"{}\",\"layout\":\"{}\",\"asm\":\"{}\",\"calls\":\"{}\",\"elapsed_ms\":\"{}\"}}",
            end - start,
            json_escape(&pseudo_c),
            json_escape(&String::from_utf8_lossy(&layout_buf)),
            json_escape(&String::from_utf8_lossy(&asm_buf)),
            json_escape(&String::from_utf8_lossy(&calls_buf)),
            json_escape(&elapsed),
        );
        (200, json)
    }

    fn search_json(&self, mode: &str, q: &str) -> String {
        let t0 = Instant::now();
        let mut buf = Vec::new();
        let res = match mode {
            "disp" => parse_number(q).map_err(Into::into).and_then(|v| {
                commands::run(
                    self.image,
                    Command::Disp { values: vec![v], write: false, lea: true, all: false, stride: None, within: None },
                    &mut buf,
                )
            }),
            "imm" => parse_number(q).map_err(Into::into).and_then(|v| {
                commands::run(self.image, Command::Imm { value: v, store: false, cmp: false, within: None }, &mut buf)
            }),
            "where" => commands::run(self.image, Command::Where { pattern: q.to_owned(), line: None }, &mut buf),
            _ => commands::run(
                self.image,
                Command::Refs { targets: vec![q.to_owned()], back: 1, inline: false },
                &mut buf,
            ),
        };
        if let Err(err) = res {
            let _ = writeln!(buf, "error: {err}");
        }
        let text = String::from_utf8_lossy(&buf);
        let capped: String = text.lines().take(250).collect::<Vec<_>>().join("\n");
        format!(
            "{{\"output\":\"{}\",\"elapsed_ms\":\"{}\"}}",
            json_escape(&capped),
            json_escape(&format!("{:.2?}", t0.elapsed()))
        )
    }

    pub fn route(&self, target: &str) -> (u16, &'static str, String) {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        match path {
            "/" | "/index.html" => (200, "text/html; charset=utf-8", INDEX_HTML.to_owned()),
            "/styles.css" => (200, "text/css; charset=utf-8", STYLES_CSS.to_owned()),
            "/app.js" => (200, "application/javascript; charset=utf-8", APP_JS.to_owned()),
            "/api/stats" => {
                let body = format!(
                    "{{\"binary\":\"{}\",\"load_ms\":\"{}\",\"functions\":{},\"code_bytes\":{},\"locations\":{},\"files\":{},\"initial_functions\":{}}}",
                    json_escape(&self.binary),
                    json_escape(&self.load_ms),
                    self.image.functions.len(),
                    self.code_bytes,
                    self.locs.len(),
                    self.files_count,
                    self.render_fn_list(""),
                );
                (200, "application/json; charset=utf-8", body)
            }
            "/api/functions" => {
                let q = query_param(query, "q").unwrap_or_default();
                (200, "application/json; charset=utf-8", format!("{{\"functions\":{}}}", self.render_fn_list(&q)))
            }
            "/api/inspect" => {
                let addr = query_param(query, "addr").unwrap_or_default();
                let reg = query_param(query, "reg").unwrap_or_else(|| "rdi".to_owned());
                let (code, body) = self.inspect_json(&addr, &reg);
                (code, "application/json; charset=utf-8", body)
            }
            "/api/search" => {
                let mode = query_param(query, "mode").unwrap_or_default();
                let q = query_param(query, "q").unwrap_or_default();
                (200, "application/json; charset=utf-8", self.search_json(&mode, &q))
            }
            _ => (404, "text/plain; charset=utf-8", "not found".to_owned()),
        }
    }
}

pub fn serve_limit(image: &Image, bin_path: &Path, addr: &str, loaded: Duration, max_reqs: Option<usize>) -> Res {
    let ctx = WebCtx::build(image, bin_path, loaded);
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    eprintln!("xref web: http://{local} ({} functions ready)", image.functions.len());
    for (served, stream) in listener.incoming().enumerate() {
        let mut stream = stream?;
        let mut line = String::new();
        let _ = BufReader::new(&stream).read_line(&mut line);
        let target = line.split_whitespace().nth(1).unwrap_or("/");
        let (code, ctype, body) = ctx.route(target);
        let status = if code == 200 { "200 OK" } else { "404 Not Found" };
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body.as_bytes());
        if max_reqs.is_some_and(|m| served + 1 >= m) {
            break;
        }
    }
    Ok(())
}

pub fn serve(image: &Image, bin_path: &Path, addr: &str, loaded: Duration) -> Res {
    serve_limit(image, bin_path, addr, loaded, None)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::time::Duration;

    use super::{WebCtx, json_escape, serve_limit, url_decode};
    use crate::image::{Image, Segment};

    #[test]
    fn routes_assets_api_endpoints_and_serves_http_requests() {
        let mut data = vec![0u8; 0x200];
        data[..6].copy_from_slice(&[0x48, 0x8b, 0x47, 0x08, 0xc3, 0x90]);
        data[0x40..0x48].copy_from_slice(&[0x48, 0x8d, 0x05, 0x49, 0x00, 0x00, 0x00, 0xc3]);
        data[0x80..0x88].copy_from_slice(b"src/a.rs");
        data[0x90..0x98].copy_from_slice(&0x1080u64.to_le_bytes());
        data[0x98..0xa0].copy_from_slice(&8u64.to_le_bytes());
        data[0xa0..0xa4].copy_from_slice(&7u32.to_le_bytes());
        data[0xa4..0xa8].copy_from_slice(&1u32.to_le_bytes());
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
            functions: vec![0x1000..0x1005, 0x1040..0x1048],
            pointers: vec![(0x1090, 0x1080)],
            imports: Vec::new(),
            symbols: vec![(0x1000, "demo_fn".to_owned())],
        };
        assert_eq!(url_decode("0x1000+a%2fb"), "0x1000 a/b");
        assert!(json_escape("a\"\\\n\r\t\x01").contains("\\u0001"));
        let ctx = WebCtx::build(&image, Path::new("sample.elf"), Duration::from_millis(12));
        for path in [
            "/",
            "/styles.css",
            "/app.js",
            "/api/stats",
            "/api/functions?q=demo",
            "/api/inspect?addr=0x1000&reg=rdi",
            "/api/search?mode=disp&q=0x8",
            "/api/search?mode=imm&q=1",
            "/api/search?mode=where&q=a.rs",
            "/api/search?mode=refs&q=src/a.rs",
            "/api/search?mode=disp&q=bad",
        ] {
            let (code, _, body) = ctx.route(path);
            assert_eq!(code, 200, "{path}");
            assert!(!body.is_empty());
        }
        assert_eq!(ctx.route("/api/inspect?addr=bad").0, 400);
        assert_eq!(ctx.route("/api/inspect?addr=0x9999").0, 404);
        assert_eq!(ctx.route("/nope").0, 404);

        let probe = TcpListener::bind("127.0.0.1:0").ok().and_then(|l| l.local_addr().ok());
        if let Some(addr) = probe {
            let addr_s = addr.to_string();
            std::thread::scope(|s| {
                s.spawn(|| {
                    let _ = serve_limit(&image, Path::new("sample.elf"), &addr_s, Duration::ZERO, Some(1));
                });
                for _ in 0..40 {
                    if let Ok(mut sock) = TcpStream::connect(addr) {
                        let _ = sock.write_all(b"GET /api/stats HTTP/1.1\r\nHost: localhost\r\n\r\n");
                        let mut resp = String::new();
                        let _ = sock.read_to_string(&mut resp);
                        assert!(resp.contains("200 OK") && resp.contains("sample.elf"));
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
        }
    }
}

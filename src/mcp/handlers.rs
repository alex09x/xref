/*
 * XRef Code — Read-only MCP request handlers
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::wire::{self, Message};
use crate::api::{
    Analysis, Cancellation,
    types::{ApiError, Query, Response},
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{self, Write},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

pub(super) const PROTOCOL: &str = "2025-11-25";
type Active = Arc<Mutex<HashMap<String, Cancellation>>>;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Arguments {
    request: Query,
}

#[derive(PartialEq, Eq)]
enum Phase {
    New,
    Initialized,
    Ready,
}

pub(super) struct Server<W> {
    analysis: Arc<Analysis>,
    writer: Arc<Mutex<W>>,
    active: Active,
    workers: Vec<JoinHandle<()>>,
    phase: Phase,
}

struct ActiveGuard {
    active: Active,
    key: String,
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.key);
        }
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("MCP state lock was poisoned")
}

fn send<W: Write>(writer: &Mutex<W>, value: &Value) -> io::Result<()> {
    wire::write(&mut *writer.lock().map_err(poisoned)?, value)
}

fn tool_result(response: &Response) -> Value {
    let value = response.json();
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":!value["error"].is_null()})
}

impl<W: Write + Send + 'static> Server<W> {
    pub(super) fn new(analysis: Analysis, writer: W) -> Self {
        Self {
            analysis: Arc::new(analysis),
            writer: Arc::new(Mutex::new(writer)),
            active: Arc::new(Mutex::new(HashMap::new())),
            workers: Vec::new(),
            phase: Phase::New,
        }
    }

    pub(super) fn send(&self, value: &Value) -> io::Result<()> {
        send(&self.writer, value)
    }

    pub(super) fn dispatch(&mut self, message: Message) -> io::Result<()> {
        self.reap();
        let Message { id, method, params } = message;
        if !params.is_null() && !params.is_object() {
            return id.map_or(Ok(()), |id| self.send(&wire::error(id, -32602, "MCP parameters must be an object")));
        }
        let Some(id) = id else {
            if method == "notifications/initialized" && self.phase == Phase::Initialized {
                self.phase = Phase::Ready;
            }
            if method == "notifications/cancelled"
                && let Some(key) = wire::id_key(&params["requestId"])
                && let Some(token) = self.active.lock().map_err(poisoned)?.get(&key)
            {
                token.cancel();
            }
            return Ok(());
        };
        match method.as_str() {
            "ping" => self.send(&wire::result(id, json!({}))),
            "initialize" => {
                if self.phase != Phase::New {
                    return self.send(&wire::error(id, -32600, "already initialized"));
                }
                if !params["protocolVersion"].is_string()
                    || !params["capabilities"].is_object()
                    || !params["clientInfo"]["name"].is_string()
                    || !params["clientInfo"]["version"].is_string()
                {
                    return self.send(&wire::error(id, -32602, "invalid initialize parameters"));
                }
                self.phase = Phase::Initialized;
                self.send(&wire::result(id, json!({"protocolVersion":PROTOCOL,"capabilities":{"tools":{}},
                    "serverInfo":{"name":"xref","version":env!("CARGO_PKG_VERSION")},
                "instructions":"Read-only analysis of one immutable x86-64 ELF or supported Mach-O snapshot. Use xref_query; inspect schema_version, warnings and continuation offsets."})))
            }
            "tools/list" | "tools/call" if self.phase != Phase::Ready => {
                self.send(&wire::error(id, -32002, "server not initialized"))
            }
            "tools/list" => {
                if params.get("cursor").is_some_and(|c| !c.is_null()) {
                    return self.send(&wire::error(id, -32602, "invalid tools cursor"));
                }
                self.send(&wire::result(id, json!({"tools":[{"name":"xref_query","title":"Analyze selected binary",
                    "description":"Structured info, strings, refs, function ranges, calls, assembly, pseudo-C and slices. Hexadecimal addresses; bounded pages. Does not execute the input.",
                    "inputSchema":schemars::schema_for!(Arguments),"outputSchema":schemars::schema_for!(Response),
                    "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}]})))
            }
            "tools/call" => {
                if params["name"] != "xref_query" {
                    return self.send(&wire::error(id, -32602, "unknown tool"));
                }
                let arguments = match serde_json::from_value::<Arguments>(params["arguments"].clone()) {
                    Ok(arguments) => arguments,
                    Err(error) => {
                        return self.send(&wire::error(id, -32602, &crate::api::clipped(&error.to_string(), 512).0));
                    }
                };
                self.query(id, arguments.request)
            }
            _ => self.send(&wire::error(id, -32601, "method not found")),
        }
    }

    fn query(&mut self, id: Value, query: Query) -> io::Result<()> {
        let key = wire::id_key(&id).ok_or_else(|| io::Error::other("validated ID missing"))?;
        let cancellation = Cancellation::default();
        let admission = {
            let mut active = self.active.lock().map_err(poisoned)?;
            if active.contains_key(&key) {
                Err("duplicate request ID")
            } else if active.len() >= 2 {
                Err("busy")
            } else {
                active.insert(key.clone(), cancellation.clone());
                drop(active);
                Ok(())
            }
        };
        if let Err(reason) = admission {
            return if reason == "busy" {
                self.send(&wire::result(
                    id,
                    tool_result(
                        &self
                            .analysis
                            .failure(query.name(), ApiError::new("busy", "two analysis requests are already running")),
                    ),
                ))
            } else {
                self.send(&wire::error(id, -32600, reason))
            };
        }
        let (analysis, writer, active) = (self.analysis.clone(), self.writer.clone(), self.active.clone());
        let worker_key = key.clone();
        let spawned = std::thread::Builder::new().name("xref-query".to_owned()).spawn(move || {
            let _guard = ActiveGuard { active, key: worker_key };
            let response =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| analysis.query(&query, &cancellation)))
                    .unwrap_or_else(|_| {
                        analysis.failure(query.name(), ApiError::new("analysis_failed", "analysis worker panicked"))
                    });
            if cancellation.checkpoint().is_ok() {
                let _ = send(&writer, &wire::result(id, tool_result(&response)));
            }
        });
        match spawned {
            Ok(worker) => {
                self.workers.push(worker);
                Ok(())
            }
            Err(error) => {
                self.active.lock().map_err(poisoned)?.remove(&key);
                Err(error)
            }
        }
    }

    fn reap(&mut self) {
        let mut index = 0;
        while index < self.workers.len() {
            if self.workers[index].is_finished() {
                let _ = self.workers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
    }

    pub(super) fn close(self) {
        if let Ok(active) = self.active.lock() {
            for token in active.values() {
                token.cancel();
            }
        }
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;

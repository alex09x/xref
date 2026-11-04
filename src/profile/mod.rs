/*
 * XRef — sampling profile capture and analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
pub mod aggregate;
pub mod analyze;
pub mod annotate;
pub mod annotate_c;
pub mod blocks;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod capture;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod capture_stream;
pub mod cli;
pub mod codec;
mod codec_sample;
pub mod config;
pub mod diff;
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
pub mod flight;
mod import_maps;
mod import_native;
mod import_native_header;
mod import_native_identity;
mod import_native_read;
mod import_native_records;
mod import_native_regs;
pub mod import_text;
pub mod lines;
#[cfg(any(target_os = "linux", test))]
pub mod live_cli;
#[cfg(any(target_os = "linux", test))]
pub mod mcp;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod module_hash;
pub mod offline_cli;
mod parallel;
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
pub mod perf_decode;
pub mod report;
pub mod resolve;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod trigger;
pub mod types;
pub mod unwind;

#[cfg(test)]
mod tests;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests_live;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests_live_perf;
#[cfg(all(test, target_os = "linux"))]
mod tests_live_read;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests_live_scenarios;
#[cfg(test)]
mod tests_misc;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests_multi;
#[cfg(test)]
mod tests_perf;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests_rust;

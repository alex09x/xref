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
mod import_native_compressed;
mod import_native_header;
mod import_native_identity;
mod import_native_pt;
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
#[cfg(test)]
mod nested_aux_expand;
#[cfg(test)]
mod nested_aux_normalize;
mod nested_aux_relocate;
mod nested_aux_stream;
pub mod offline_cli;
mod parallel;
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
pub mod perf_decode;
mod pt_aux_identity;
#[cfg(test)]
mod pt_aux_session;
mod pt_decode;
mod pt_mapping;
mod pt_packet;
mod pt_synthesis;
#[cfg(test)]
mod pt_time;
pub mod report;
pub mod resolve;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests_pt_import;
#[cfg(test)]
mod tests_pt_mixed;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod trigger;
pub mod types;
pub mod unwind;

#[cfg(test)]
mod tests;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests_lbr_compiled;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests_live;
#[cfg(all(test, target_os = "linux"))]
mod tests_live_aux;
#[cfg(all(test, target_os = "linux"))]
mod tests_live_compressed;
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

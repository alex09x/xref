/*
 * XRef — Offline runtime-stack CLI arguments
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{adapter::build_index, io};
use crate::trace_analysis::{
    index::parse_hex, mapping::MappingState, models::FrameKind, parse::InputFormat, stream::TraceConfig,
};
use crate::{commands::Res, image::Image};
use clap::{Args, Subcommand, ValueEnum};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Copy, ValueEnum, Debug, Default)]
pub enum Format {
    #[default]
    Addresses,
    Perf,
    Folded,
}
#[derive(Clone, Copy, ValueEnum, Debug, Default)]
pub enum Kind {
    #[default]
    Auto,
    Instruction,
    ReturnAddress,
    Static,
    Symbol,
}

#[derive(Args, Debug)]
pub struct TraceInput {
    /// Saved addresses, perf script, or root-first folded stacks; '-' reads stdin
    #[arg(long, default_value = "-")]
    pub input: PathBuf,
    #[arg(long, value_enum, default_value = "addresses")]
    pub format: Format,
    /// Runtime address of the lowest image virtual address (not an arbitrary text mapping)
    #[arg(long, conflicts_with = "maps")]
    pub base: Option<String>,
    /// Saved /proc/PID/maps from the sampled process, not the current process
    #[arg(long)]
    pub maps: Option<PathBuf>,
    /// Original executable path as it appears in maps/MMAP records
    #[arg(long)]
    pub target_path: Option<String>,
    /// Process TGID to select from perf-script samples
    #[arg(long)]
    pub pid: Option<u32>,
    /// Reject a mismatch against the selected binary's build ID
    #[arg(long)]
    pub build_id: Option<String>,
    /// Auto: sampled leaf is instruction IP, ancestors are return addresses
    #[arg(long, value_enum, default_value = "auto")]
    pub kind: Kind,
    /// Input byte budget; reading stops there and the result is marked truncated
    #[arg(long, default_value_t = 2_147_483_648_u64)]
    pub max_bytes: u64,
    /// Stack sample budget; reading stops there and the result is marked truncated
    #[arg(long, default_value_t = 100_000_u64)]
    pub max_samples: u64,
    /// Time budget in milliseconds; reading stops there and the result is marked truncated
    #[arg(long, default_value_t = 30_000_u64)]
    pub timeout_ms: u64,
}

#[derive(Args, Debug)]
pub struct SymbolizeArgs {
    #[command(flatten)]
    pub trace: TraceInput,
    /// Stream one JSON object per sample, followed by a summary object
    #[arg(long,conflicts_with_all=["folded","group_by"])]
    pub jsonl: bool,
    /// Aggregate canonical root-first function stacks (bounded memory)
    #[arg(long, visible_alias = "collapse")]
    pub folded: bool,
    /// Include exact decoded return call-sites in ancestor grouping keys
    #[arg(long, requires = "folded")]
    pub group_callers: bool,
    /// Count samples by the immediate caller's call site; unknown caller stays unknown
    #[arg(long,value_parser=["caller"])]
    pub group_by: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum EdgeCommand {
    /// Import observed stack adjacencies; counts are stack samples, not call counts
    Import {
        #[command(flatten)]
        trace: TraceInput,
        /// Path of the edge evidence store to write
        #[arg(long)]
        out: PathBuf,
    },
}

impl TraceInput {
    pub fn config(
        &self,
        index: &crate::trace_analysis::index::SymbolIndex,
        bin: &str,
    ) -> Result<TraceConfig<'static>, String> {
        let mut mappings = self
            .base
            .as_deref()
            .map(parse_hex)
            .transpose()?
            .map(|base| index.mappings_from_base(base))
            .transpose()?
            .unwrap_or_default();
        let target_path = self.target_path.clone().unwrap_or_else(|| {
            PathBuf::from(bin)
                .canonicalize()
                .map_or_else(|_| bin.to_owned(), |path| path.to_string_lossy().into_owned())
        });
        if let Some(path) = &self.maps {
            let text = io::read_text(path, 16 * 1024 * 1024)?;
            let mut state = MappingState::default();
            state.set_proc_maps(index, &text, &target_path)?;
            mappings = state.explicit;
        }
        Ok(TraceConfig {
            format: match self.format {
                Format::Addresses => InputFormat::Addresses,
                Format::Perf => InputFormat::Perf,
                Format::Folded => InputFormat::Folded,
            },
            frame_kind: match self.kind {
                Kind::Auto => FrameKind::Auto,
                Kind::Instruction => FrameKind::Instruction,
                Kind::ReturnAddress => FrameKind::ReturnAddress,
                Kind::Static => FrameKind::Static,
                Kind::Symbol => FrameKind::Symbol,
            },
            target_path: Some(target_path),
            pid: self.pid,
            mappings,
            trace_build_id: self.build_id.clone(),
            max_bytes: self.max_bytes,
            max_samples: self.max_samples,
            timeout: Duration::from_millis(self.timeout_ms),
            cancel: None,
        })
    }
}

pub fn symbolize(image: &Image, bin: &str, args: &SymbolizeArgs, out: &mut dyn std::io::Write) -> Res {
    let index = build_index(image, None)?;
    let config = args.trace.config(&index, bin)?;
    io::symbolize(&index, &config, args, out)
}

pub fn edges(image: &Image, bin: &str, command: &EdgeCommand, out: &mut dyn std::io::Write) -> Res {
    match command {
        EdgeCommand::Import { trace, out: destination } => {
            let index = build_index(image, None)?;
            let config = trace.config(&index, bin)?;
            let mut reader = io::input_reader(&trace.input)?;
            let store = crate::trace_analysis::stream::import_trace(&mut reader, &index, &config, |_, _| Ok(()))?;
            io::save_store(destination, &store)?;
            writeln!(
                out,
                "imported {} observed stack-adjacency edges from {} samples; counts are stack samples",
                store.edges.len(),
                store.stats.samples
            )?;
            for warning in store.warnings {
                writeln!(out, "warning: {warning}")?;
            }
            Ok(())
        }
    }
}

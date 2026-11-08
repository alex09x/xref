/*
 * XRef Code — CLI handler (`xref deps`) and `xref stats` provenance summary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::io::Write;

use clap::Args;
use serde::Serialize;

use super::{ProvenanceSummary, inspect};
use crate::commands::Res;
use crate::image::Image;

/// Arguments for `xref deps` — inspect embedded Rust (`.dep-v0`) and Go (`.go.buildinfo`) manifests.
#[derive(Args, Clone, Debug)]
pub struct DepsArgs {
    /// Case-insensitive substring filter on package or module name.
    #[arg(long)]
    pub filter: Option<String>,
    /// Emit structured JSON output instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct CliDepsReport<'a> {
    ecosystem: Option<&'static str>,
    build_id: &'a Option<String>,
    toolchains: &'a [String],
    root_package: Option<String>,
    root_version: Option<String>,
    go_version: Option<&'a str>,
    total_packages: usize,
    packages: Vec<CliDepEntry>,
}

#[derive(Serialize)]
struct CliDepEntry {
    name: String,
    version: String,
    kind: &'static str,
    source: Option<String>,
    root: bool,
    replaced_by: Option<String>,
}

/// Execute `xref deps [--filter SUBSTR] [--json]`.
pub fn run(image: &Image, args: &DepsArgs, out: &mut dyn Write) -> Res {
    let prov = inspect(image);
    let needle = args.filter.as_deref().map(str::to_ascii_lowercase);
    let matches_filter = |name: &str| needle.as_ref().is_none_or(|sub| name.to_ascii_lowercase().contains(sub));

    let (ecosystem, root_package, root_version, go_version, total_packages, packages) =
        if let Some(rust) = &prov.rust_audit {
            let pkgs: Vec<CliDepEntry> = rust
                .packages
                .iter()
                .filter(|p| matches_filter(&p.name))
                .map(|p| CliDepEntry {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    kind: if p.kind == "build" { "build" } else { "runtime" },
                    source: (!p.source.is_empty()).then(|| p.source.clone()),
                    root: p.root,
                    replaced_by: None,
                })
                .collect();
            (Some("rust"), rust.root_name.clone(), rust.root_version.clone(), None, rust.packages.len(), pkgs)
        } else if let Some(go) = &prov.go_build {
            let (root_name, root_ver) = go
                .main_module
                .as_ref()
                .map_or_else(|| (go.path.clone(), None), |(m, v)| (Some(m.clone()), Some(v.clone())));
            let pkgs: Vec<CliDepEntry> = go
                .deps
                .iter()
                .filter(|d| matches_filter(&d.path))
                .map(|d| CliDepEntry {
                    name: d.path.clone(),
                    version: d.version.clone(),
                    kind: "module",
                    source: d.sum.clone(),
                    root: false,
                    replaced_by: d.replaced_by.as_ref().map(|(m, v)| format!("{m}@{v}")),
                })
                .collect();
            (Some("go"), root_name, root_ver, Some(go.go_version.as_str()), go.deps.len(), pkgs)
        } else {
            (None, None, None, None, 0, Vec::new())
        };

    if args.json {
        let report = CliDepsReport {
            ecosystem,
            build_id: &prov.build_id,
            toolchains: &prov.toolchains,
            root_package,
            root_version,
            go_version,
            total_packages,
            packages,
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
        return Ok(());
    }

    if let Some(id) = &prov.build_id {
        writeln!(out, "build-id {id}")?;
    }
    if !prov.toolchains.is_empty() {
        writeln!(out, "toolchain {}", prov.toolchains.join(" | "))?;
    }
    match ecosystem {
        Some("rust") => {
            if let Some(root) = &root_package {
                let ver = root_version.as_deref().unwrap_or("?");
                writeln!(out, "ecosystem rust (.dep-v0)  root {root} {ver}  total {total_packages}")?;
            } else {
                writeln!(out, "ecosystem rust (.dep-v0)  total {total_packages}")?;
            }
        }
        Some("go") => {
            let gv = go_version.unwrap_or("unknown");
            let root = root_package.as_deref().unwrap_or("<unknown>");
            let ver = root_version.as_deref().unwrap_or("");
            writeln!(out, "ecosystem go ({gv})  main {root} {ver}  modules {total_packages}")?;
        }
        _ => {
            if let Some(err) = &prov.rust_audit_error {
                writeln!(out, "no readable dependency manifest ({err})")?;
            } else {
                writeln!(out, "no embedded dependency manifest (.dep-v0 or .go.buildinfo)")?;
            }
            return Ok(());
        }
    }
    for pkg in &packages {
        let root_tag = if pkg.root { " [root]" } else { "" };
        let repl = pkg.replaced_by.as_deref().map_or(String::new(), |r| format!(" => {r}"));
        writeln!(out, "  {:<36} {:<16} {}{}{}", pkg.name, pkg.version, pkg.kind, root_tag, repl)?;
    }
    writeln!(out, "{} packages shown", packages.len())?;
    Ok(())
}

/// Append provenance summary lines to `xref stats` when metadata is present.
pub fn write_stats_summary(image: &Image, out: &mut dyn Write) -> Res {
    let prov: ProvenanceSummary = inspect(image);
    if let Some(id) = &prov.build_id {
        writeln!(out, "build-id {id}")?;
    }
    if !prov.toolchains.is_empty() {
        writeln!(out, "toolchain {}", prov.toolchains.join(" | "))?;
    }
    if let Some(rust) = &prov.rust_audit {
        let root = match (&rust.root_name, &rust.root_version) {
            (Some(n), Some(v)) => format!("  root {n} {v}"),
            _ => String::new(),
        };
        writeln!(
            out,
            "rust dependencies {} ({} runtime, {} build){root}",
            rust.packages.len(),
            rust.runtime_count,
            rust.build_count
        )?;
    }
    if let Some(go) = &prov.go_build {
        let main =
            go.main_module.as_ref().map_or_else(|| go.path.clone().unwrap_or_default(), |(m, v)| format!("{m} {v}"));
        writeln!(out, "go {}  main {}  modules {}", go.go_version, main.trim(), go.deps.len())?;
    }
    for sec in &prov.high_entropy_executable {
        writeln!(
            out,
            "warning: high-entropy executable {} ({:#x} bytes, {}.{:03} bits/byte — possible packer)",
            sec.name,
            sec.size_bytes,
            sec.entropy_milli / 1000,
            sec.entropy_milli % 1000
        )?;
    }
    Ok(())
}

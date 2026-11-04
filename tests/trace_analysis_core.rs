/*
 * XRef — Stack mapping and observed-edge contracts
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
// Test oracles deliberately panic on unexpected values; production paths remain fallible.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "../src/trace_analysis/mod.rs"]
#[allow(dead_code)]
mod trace_analysis;
use std::fmt::Write as _;
use std::{collections::BTreeMap, io::Cursor, sync::atomic::AtomicBool};
use trace_analysis::{index::*, models::*, parse::InputFormat, stream::*};

fn index() -> SymbolIndex {
    SymbolIndex::new(
        TraceIdentity { sha256: "a".repeat(64), build_id: Some("aabb".to_owned()) },
        0x0040_0000,
        vec![
            IndexedFunction {
                start: 0x0040_1000,
                end: 0x0040_1020,
                symbol: Some("leaf".to_owned()),
                source_sites: vec![],
            },
            IndexedFunction {
                start: 0x0040_1020,
                end: 0x0040_1040,
                symbol: Some("caller".to_owned()),
                source_sites: vec![],
            },
        ],
        BTreeMap::from([(0x0040_1025, IndexedCall { instruction: 0x0040_1020, caller: 0x0040_1020 })]),
        vec![IndexedSegment {
            va: 0x0040_1000,
            file_offset: 0x1000,
            file_size: 0x1000,
            mem_size: 0x1000,
            executable: true,
        }],
    )
}

#[allow(clippy::needless_pass_by_value)] // Each case supplies an owned temporary configuration.
fn run(text: &str, config: TraceConfig<'_>) -> (ObservedStore, Vec<Vec<SymbolizedFrame>>) {
    let mut frames = vec![];
    let report = import_trace(&mut Cursor::new(text), &index(), &config, |stack, _| {
        frames.push(stack.to_vec());
        Ok(())
    })
    .unwrap();
    (report, frames)
}

#[test]
fn return_addresses_preserve_raw_ip_and_require_exact_call_end() {
    let index = index();
    let maps = index.mappings_from_base(0x0070_0000).unwrap();
    let frame = index.frame("0x701025", FrameKind::ReturnAddress, None, &maps);
    assert_eq!(frame.static_address.as_deref(), Some("0x401025"));
    assert_eq!(frame.call_site.as_deref(), Some("0x401020"));
    assert_eq!(index.frame("0x701026", FrameKind::ReturnAddress, None, &maps).call_site, None);
    let boundary = index.frame("0x701020", FrameKind::ReturnAddress, None, &maps);
    assert_eq!(boundary.function.unwrap().start, "0x401000");
    assert_eq!(index.frame("0x701020", FrameKind::Instruction, None, &maps).function.unwrap().start, "0x401020");
    assert!(index.frame("0x701025", FrameKind::Instruction, None, &[]).function.is_none());
    assert!(index.mappings_from_base(u64::MAX).is_err());
}

#[test]
fn perf_mmap_build_identity_threads_and_unknown_gaps_are_preserved() {
    let text = concat!(
        "PERF_RECORD_MMAP2 7/8: [0x701000(0x1000) @ 0x1000 <aabb>]: r-xp /app\n",
        "task 7/8 [000] 1.000: cycles: 701001 leaf (/app)\n",
        "        701001 leaf (/app)\n",
        "        701025 caller (/app)\n\n",
        "task 7/8 [000] 1.100: cycles: 701001 leaf (/app)\n",
        "        701001 leaf (/app)\n",
        "        dead unknown (/lib/foreign.so)\n",
        "        701025 caller (/app)\n\n"
    );
    let (report, frames) = run(
        text,
        TraceConfig { format: InputFormat::Perf, target_path: Some("/app".to_owned()), ..TraceConfig::default() },
    );
    assert_eq!(report.stats.samples, 2);
    assert_eq!(frames[0].len(), 2, "header duplicate must be removed exactly once");
    assert_eq!(report.edges.len(), 1);
    assert_eq!(report.edges[0].sample_count, 1, "unknown frames must not be bridged");
    assert_eq!(report.identity_evidence, "mmap_build_id_matches_selected_image");
    assert_eq!(report.stats.unresolved_frames, 1);
    let bad = text.replace("<aabb>", "<ffff>");
    assert!(
        import_trace(
            &mut Cursor::new(bad),
            &index(),
            &TraceConfig { format: InputFormat::Perf, target_path: Some("/app".to_owned()), ..TraceConfig::default() },
            |_, _| Ok(())
        )
        .unwrap_err()
        .contains("mismatch")
    );
}

#[test]
fn folded_symbols_recursion_weight_and_serialized_store_identity() {
    let (report, frames) =
        run("caller;leaf 4\nleaf;leaf 2\n", TraceConfig { format: InputFormat::Folded, ..TraceConfig::default() });
    assert_eq!(report.stats.weight, 6);
    assert_eq!(report.edges.len(), 2);
    assert!(report.edges.iter().any(|edge| edge.caller == edge.callee && edge.sample_count == 2));
    let restored: ObservedStore = serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
    trace_analysis::observed::validate_store(&restored, &index()).unwrap();
    let mut changed = restored;
    changed.image.sha256 = "b".repeat(64);
    assert!(trace_analysis::observed::validate_store(&changed, &index()).is_err());
    let mut groups = trace_analysis::grouping::FoldedGroups::default();
    groups.add(&frames[0], 4, true).unwrap();
    assert_eq!(groups.groups.values().sum::<u64>(), 4);
    assert!(groups.groups.keys().next().unwrap().contains("unknown_call_site"));
}

#[test]
fn explicit_mapping_cannot_silently_merge_processes_or_survive_exec() {
    let index = index();
    let maps = index.mappings_from_base(0x0070_0000).unwrap();
    let text = "task 7/7 1.000: cycles: 701001\n\ntask 9/9 2.000: cycles: 701001\n\n";
    assert!(
        import_trace(
            &mut Cursor::new(text),
            &index,
            &TraceConfig { format: InputFormat::Perf, mappings: maps.clone(), ..TraceConfig::default() },
            |_, _| Ok(())
        )
        .unwrap_err()
        .contains("multiple processes")
    );
    let text = "task 7/7 1.000: cycles: 701001\n\nPERF_RECORD_COMM exec: app:7/7\ntask 7/7 2.000: cycles: 701001\n\n";
    let (_, frames) = run(text, TraceConfig { format: InputFormat::Perf, mappings: maps, ..TraceConfig::default() });
    assert!(frames[0][0].function.is_some());
    assert!(frames[1][0].function.is_none());
}

#[test]
fn bounded_reader_hashes_only_consumed_prefix_and_reports_limits() {
    let (report, _) = run("fn_401001\n", TraceConfig { max_samples: 1, ..TraceConfig::default() });
    assert!(!report.stats.input_truncated, "exact EOF is complete");
    let (report, _) = run("fn_401001\nfn_401002\n", TraceConfig { max_samples: 1, ..TraceConfig::default() });
    assert_eq!(report.stats.samples, 1);
    assert!(report.stats.input_truncated);
    let (report, _) = run("fn_401001\nfn_401002\n", TraceConfig { max_bytes: 10, ..TraceConfig::default() });
    assert_eq!(report.stats.samples, 1);
    assert!(report.stats.input_truncated);
    assert_eq!(report.stats.input_bytes, 10);
    let text = "x".repeat(trace_analysis::parse::MAX_LINE_BYTES + 1);
    assert!(
        import_trace(&mut Cursor::new(text), &index(), &TraceConfig::default(), |_, _| Ok(()))
            .unwrap_err()
            .contains("64 KiB")
    );
    let cancelled = AtomicBool::new(true);
    assert!(
        import_trace(
            &mut Cursor::new("fn_401001\n"),
            &index(),
            &TraceConfig { cancel: Some(&cancelled), ..TraceConfig::default() },
            |_, _| Ok(())
        )
        .unwrap_err()
        .contains("cancelled")
    );
}

#[test]
fn inline_symbolization_has_no_file_or_process_surface() {
    let query:SymbolizeRequest=serde_json::from_value(serde_json::json!({"stacks":[{"frames":["0x701001","0x701025"],"weight":3}],"base":"0x700000","trace_build_id":"aabb"})).unwrap();
    let result = trace_analysis::batch::symbolize_batch(&index(), &query, None).unwrap();
    assert_eq!(result.frames[0][1].call_site.as_deref(), Some("0x401020"));
    assert_eq!(result.weights, vec![3]);
    assert!(serde_json::from_value::<SymbolizeRequest>(serde_json::json!({"stacks":[],"file":"/etc/passwd"})).is_err());
}

#[test]
fn streams_seventy_thousand_twenty_frame_stacks_with_bounded_aggregation() {
    let line = format!("{}\n", vec!["fn_401001"; 20].join(" "));
    let input = line.repeat(70_000);
    let mut emitted = 0_u64;
    let report = import_trace(&mut Cursor::new(input), &index(), &TraceConfig::default(), |frames, _| {
        assert_eq!(frames.len(), 20);
        emitted += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(emitted, 70_000);
    assert_eq!(report.stats.frames, 1_400_000);
    assert_eq!(report.edges.len(), 1);
    assert_eq!(report.edges[0].sample_count, 70_000 * 19);
    assert!(!report.stats.input_truncated);
}

#[test]
fn fork_inherits_address_space_and_reused_pid_cannot_keep_an_old_mapping() {
    let text = concat!(
        "PERF_RECORD_MMAP2 7/7: [0x701000(0x1000) @ 0x1000 <aabb>]: r-xp /app\n",
        "PERF_RECORD_FORK(9:10):(7:7)\n",
        "task 9/10 1.000: cycles: 701001\n\n",
        "PERF_RECORD_MMAP2 11/11: [0x900000(0x1000) @ 0x1000 00:00 1 0]: r-xp /foreign\n",
        "PERF_RECORD_FORK(9:10):(11:11)\n",
        "task 9/10 2.000: cycles: 701001\n\n"
    );
    let (report, frames) = run(
        text,
        TraceConfig { format: InputFormat::Perf, target_path: Some("/app".to_owned()), ..TraceConfig::default() },
    );
    assert_eq!(report.stats.samples, 2);
    assert!(frames[0][0].function.is_some());
    assert!(frames[1][0].function.is_none());
}

#[test]
fn trace_metadata_loss_and_tid_only_headers_preserve_coverage() {
    let text = concat!(
        "PERF_RECORD_MMAP -1/0: [0xffffffff81000000(0x0) @ 0x0]: x [kernel.kallsyms]\n",
        "PERF_RECORD_MMAP2 7/7: [0x701000(0x1000) @ 0x1000 <aabb>]: r-xp /app\n",
        "PERF_RECORD_FORK(7:8):(7:7)\n",
        "PERF_RECORD_LOST lost 7\n",
        "unrecognized producer note\n",
        "worker 8 [001] 1.000: cycles: 701001\n\n"
    );
    let (report, frames) = run(
        text,
        TraceConfig {
            format: InputFormat::Perf,
            pid: Some(7),
            target_path: Some("/app".to_owned()),
            ..TraceConfig::default()
        },
    );
    assert_eq!(report.stats.samples, 1);
    assert_eq!(report.stats.lost_events, 7);
    assert_eq!(report.stats.malformed_lines, 1);
    assert!(frames[0][0].function.is_some());
    assert_eq!(report.stats.kernel_mapping_records_ignored, 1);
    assert!(report.warnings.iter().any(|warning| warning.contains("lost")));
    assert!(report.warnings.iter().any(|warning| warning.contains("unrecognized")));
}

#[test]
fn trace_metadata_budget_and_forged_call_site_are_rejected() {
    let mut input = String::new();
    for pid in 1..=4097 {
        let _ = writeln!(input, "PERF_RECORD_MMAP2 {pid}/{pid}: [0x900000(0x1000) @ 0x1000 00:00 1 0]: r-xp /foreign");
    }
    let error = import_trace(
        &mut Cursor::new(input),
        &index(),
        &TraceConfig { format: InputFormat::Perf, ..TraceConfig::default() },
        |_, _| Ok(()),
    )
    .unwrap_err();
    assert!(error.contains("budget"), "{error}");
    let (mut store, _) =
        run("fn_401025;fn_401001 1\n", TraceConfig { format: InputFormat::Folded, ..TraceConfig::default() });
    assert_eq!(store.edges.len(), 1);
    store.edges[0].caller_call_site = Some("0xdead".to_owned());
    assert!(trace_analysis::observed::validate_store(&store, &index()).is_err());
}

#[test]
fn unrelated_process_build_id_does_not_certify_selected_process_base() {
    let text = concat!(
        "PERF_RECORD_MMAP2 9/9: [0x901000(0x1000) @ 0x1000 <aabb>]: r-xp /app\n",
        "task 7/7 1.000: cycles: 701001\n\n"
    );
    let maps = index().mappings_from_base(0x0070_0000).unwrap();
    let (report, frames) =
        run(text, TraceConfig { format: InputFormat::Perf, pid: Some(7), mappings: maps, ..TraceConfig::default() });
    assert!(frames[0][0].function.is_some());
    assert_eq!(report.identity_evidence, "caller_selected_image_mapping_not_trace_identity_proof");
    assert!(report.warnings.iter().any(|warning| warning.contains("not_independently_build_id_verified")));
}

#[test]
fn perf_ip_only_stacks_and_explicit_return_leaf_kind_are_supported() {
    let maps = index().mappings_from_base(0x0070_0000).unwrap();
    let (report, frames) = run(
        "701001\n701025\n\n701002\n701026\n\n",
        TraceConfig { format: InputFormat::Perf, mappings: maps.clone(), ..TraceConfig::default() },
    );
    assert_eq!(report.stats.samples, 2);
    assert_eq!(frames[0].len(), 2);
    assert_eq!(frames[0][1].call_site.as_deref(), Some("0x401020"));
    let (_, frames) = run(
        "worker 7/7 [000] 1.000: uprobe: 701025\n\n",
        TraceConfig {
            format: InputFormat::Perf,
            frame_kind: FrameKind::ReturnAddress,
            mappings: maps,
            ..TraceConfig::default()
        },
    );
    assert_eq!(frames[0][0].kind, FrameKind::ReturnAddress);
    assert_eq!(frames[0][0].call_site.as_deref(), Some("0x401020"));
}

#[test]
fn immediate_caller_group_counts_samples_once_without_bridging_unknowns() {
    let (_, frames) = run(
        "701001 701025 701005\n",
        TraceConfig { mappings: index().mappings_from_base(0x0070_0000).unwrap(), ..TraceConfig::default() },
    );
    let mut group = trace_analysis::grouping::FoldedGroups::default();
    group.add_caller(&frames[0], 2).unwrap();
    let mut changed = frames[0].clone();
    changed.pop();
    group.add_caller(&changed, 3).unwrap();
    assert_eq!(group.groups.len(), 1);
    assert_eq!(group.groups["fn_401020@0x401020"], 5);
    let mut gap = frames[0].clone();
    gap[1].function = None;
    group.add_caller(&gap, 1).unwrap();
    assert_eq!(group.groups["[unknown_immediate_caller]"], 1);
}

#[test]
fn record_names_in_comm_or_symbols_do_not_become_mapping_events() {
    let text = concat!(
        "0.100: PERF_RECORD_MMAP2 7/7: [0x701000(0x1000) @ 0x1000 <aabb>]: r-xp /app\n",
        "0.200: PERF_RECORD_MMAP -1/0: [0xffff000000000000(0x0) @ 0x0]: x [kernel.kallsyms]\n",
        "PERF_RECORD_MMAP2 7/7 [000] 1.000: cycles: 701001\n",
        "        701001 PERF_RECORD_MMAP2 (/app)\n",
        "        701025 PERF_RECORD_FORK (/app)\n\n",
        "2.000: PERF_RECORD_COMM exec: other:7/7\n",
        "PERF_RECORD_MMAP2 7/7 [000] 3.000: cycles: 701001\n\n"
    );
    let (report, frames) = run(
        text,
        TraceConfig { format: InputFormat::Perf, target_path: Some("/app".to_owned()), ..TraceConfig::default() },
    );
    assert_eq!(report.stats.samples, 2);
    assert_eq!(report.stats.kernel_mapping_records_ignored, 1);
    assert_eq!(frames[0].len(), 2);
    assert_eq!(frames[0][1].call_site.as_deref(), Some("0x401020"));
    assert!(frames[1][0].function.is_none(), "exec record must invalidate the old mapping");
}

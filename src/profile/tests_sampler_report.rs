/*
 * XRef — sampler report and annotation tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    cli::{GroupBy, ProfileCommand},
    codec::ProfileWriter,
    types::{Mapping, Record},
};
use sha2::{Digest, Sha256};

#[test]
fn accepts_sampler_aliases_and_millisecond_arguments() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser;
    #[derive(Parser)]
    struct Args {
        #[command(flatten)]
        live: super::cli::LiveProfileArgs,
    }
    #[derive(Parser)]
    struct Offline {
        #[command(subcommand)]
        command: ProfileCommand,
    }
    let parsed = Args::try_parse_from([
        "xref",
        "--pid",
        "42",
        "--hz",
        "999",
        "--duration-ms",
        "30000",
        "--callgraph",
        "fp",
        "--trigger-probe",
        "0x1000",
        "--window-ms",
        "500",
        "--max-windows",
        "20",
        "--trigger-fetch",
        "op=%di:u64",
        "--trigger-filter",
        "op == 1",
    ])?;
    let config = parsed.live.config();
    assert_eq!(config.frequency_hz, Some(999));
    assert_eq!(config.duration, std::time::Duration::from_secs(30));
    assert_eq!(config.trigger_window, std::time::Duration::from_millis(500));
    assert_eq!(config.callers.name(), "fp");
    assert_eq!(config.max_windows, Some(20));
    config.validate()?;
    let mut long = config;
    long.duration = std::time::Duration::from_secs(24 * 60 * 60);
    long.validate()?;
    let report = Offline::try_parse_from(["xref", "report", "run.xprof", "--within", "0x1000", "--window", "2"])?;
    assert!(matches!(report.command, ProfileCommand::Report { window: Some(2), .. }));
    let diff =
        Offline::try_parse_from(["xref", "diff", "a.xprof", "b.xprof", "--by", "function", "--min-delta", "0.5%"])?;
    assert!(matches!(diff.command, ProfileCommand::Diff { min_delta, .. } if (min_delta - 0.5).abs() < f64::EPSILON));
    let annotation = Offline::try_parse_from(["xref", "annotate", "run.xprof", "0x1000", "--percent", "function"])?;
    assert!(matches!(annotation.command, ProfileCommand::Annotate { percent: super::cli::PercentScale::Function, .. }));
    Ok(())
}

#[test]
fn reports_one_window_or_a_deduplicated_union() -> Result<(), Box<dyn std::error::Error>> {
    let image = crate::image::Image::default();
    let mut header = super::tests::header();
    header.schema_version = 3;
    header.callchain = "none".into();
    header.image_sha256 = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    let file = tempfile::NamedTempFile::new()?;
    let mut writer = ProfileWriter::new(file.reopen()?, &header)?;
    writer.write_record(&Record::Window { trigger_ns: 100, end_ns: 120 })?;
    writer.write_record(&Record::Window { trigger_ns: 110, end_ns: 130 })?;
    for timestamp_ns in [105, 115, 125, 130] {
        let mut sample = super::tests::sample();
        sample.timestamp_ns = timestamp_ns;
        writer.write_record(&Record::Sample(sample))?;
    }
    writer.finish(130, 0, false, "fixture", None, 0)?;
    for (window, merge_windows, expected) in [(Some(1), false, 2), (Some(2), false, 2), (None, true, 3)] {
        let mut output = Vec::new();
        super::offline_cli::run(
            &image,
            file.path(),
            ProfileCommand::Report {
                profile: file.path().to_owned(),
                top: 30,
                by: GroupBy::Function,
                json: true,
                folded: None,
                within: Vec::new(),
                window,
                merge_windows,
            },
            &mut output,
        )?;
        let report: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(report["samples"], expected);
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // One profile checks filtering, annotations and diff semantics.
fn filters_report_and_calculates_function_local_annotation() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = vec![0x90, 0xc3, 0x90, 0xc3];
    let image = crate::image::Image {
        segments: vec![crate::image::Segment { va: 0x1000, offset: 0, size: bytes.len() }],
        functions: vec![0x1000..0x1002, 0x1002..0x1004],
        data: bytes,
        ..crate::image::Image::default()
    };
    let mut header = super::tests::header();
    header.image_sha256 = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    header.callchain = "fp".into();
    header.pie_slide = 0;
    let file = tempfile::NamedTempFile::new()?;
    let mut writer = ProfileWriter::new(file.reopen()?, &header)?;
    writer.write_record(&Record::Mapping(Mapping {
        timestamp_ns: 0,
        pid: header.pid,
        tid: header.pid,
        start: 0x1000,
        length: 4,
        file_offset: 0,
        device_major: u32::try_from(header.exe_device_major)?,
        device_minor: u32::try_from(header.exe_device_minor)?,
        inode: header.exe_inode,
        executable: true,
        sha256: None,
        path: "[caller-supplied target mapping]".into(),
    }))?;
    for ip in [0x1000, 0x1001, 0x1002] {
        let mut sample = super::tests::sample();
        sample.ip = ip;
        sample.callchain = if ip == 0x1002 { vec![0x1001] } else { Vec::new() };
        writer.write_record(&Record::Sample(sample))?;
    }
    writer.finish(1, 0, false, "fixture", None, 0)?;
    let mut output = Vec::new();
    super::offline_cli::run(
        &image,
        file.path(),
        ProfileCommand::Report {
            profile: file.path().to_owned(),
            top: 30,
            by: GroupBy::Function,
            json: true,
            folded: None,
            within: vec!["0x1000".into()],
            window: None,
            merge_windows: false,
        },
        &mut output,
    )?;
    let report: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(report["samples"], 3, "callee samples with the requested caller must be retained");
    assert_eq!(report["functions"][0]["label"], "target:fn_1000");
    assert!(
        report["functions"].as_array().ok_or("missing functions")?.iter().any(|row| row["label"] == "target:fn_1002")
    );
    output.clear();
    super::offline_cli::run(
        &image,
        file.path(),
        ProfileCommand::Annotate {
            profile: file.path().to_owned(),
            function: "0x1000".into(),
            c: false,
            json: true,
            min_samples: 1,
            percent: super::cli::PercentScale::Both,
        },
        &mut output,
    )?;
    let rows: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(rows.as_array().ok_or("missing rows")?.len(), 2);
    assert_eq!(rows[0]["percent_of_function"], 50.0);
    assert!((rows[0]["percent_of_profile"].as_f64().ok_or("missing profile percentage")? - 100.0 / 3.0).abs() < 1e-8);
    output.clear();
    super::offline_cli::run(
        &image,
        file.path(),
        ProfileCommand::Annotate {
            profile: file.path().to_owned(),
            function: "0x1000".into(),
            c: false,
            json: true,
            min_samples: 2,
            percent: super::cli::PercentScale::Function,
        },
        &mut output,
    )?;
    let filtered: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(filtered.as_array().ok_or("missing filtered rows")?.len(), 0);
    output.clear();
    super::offline_cli::run(
        &image,
        file.path(),
        ProfileCommand::Diff {
            before: file.path().to_owned(),
            after: file.path().to_owned(),
            other: None,
            top: 30,
            json: true,
            by: super::cli::DiffGroup::Function,
            min_delta: 0.5,
        },
        &mut output,
    )?;
    let diff: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(diff["rows"].as_array().ok_or("missing diff rows")?.len(), 0);
    Ok(())
}

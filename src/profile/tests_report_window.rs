/*
 * XRef — tests of `profile report --from/--to` and of the report notes
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::aggregate::{Aggregate, Frame, FunctionKey, Limits};
use super::cli::{GroupBy, ProfileCommand};
use super::codec::ProfileWriter;
use super::types::{Mapping, Record};
use sha2::{Digest, Sha256};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn report(image: &crate::image::Image, path: &std::path::Path, from: Option<u64>, to: Option<u64>) -> Result<String> {
    let mut output = Vec::new();
    super::offline_cli::run(
        image,
        path,
        ProfileCommand::Report {
            profile: path.to_owned(),
            top: 30,
            by: GroupBy::Function,
            json: false,
            folded: None,
            within: Vec::new(),
            window: None,
            merge_windows: false,
            from,
            to,
        },
        &mut output,
    )?;
    Ok(String::from_utf8(output)?)
}

/// Fifty samples 100 ms apart, the first at 1 s.
fn timed_recording(image: &crate::image::Image, step_ns: u64) -> Result<tempfile::NamedTempFile> {
    let mut header = super::tests::header();
    header.callchain = "none".into();
    header.image_sha256 = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    let file = tempfile::NamedTempFile::new()?;
    let mut writer = ProfileWriter::new(file.reopen()?, &header)?;
    for index in 0..50 {
        let mut sample = super::tests::sample();
        sample.timestamp_ns = if step_ns == 0 { 0 } else { 1_000_000_000 + index * step_ns };
        writer.write_record(&Record::Sample(sample))?;
    }
    writer.finish(6_000_000_000, 0, false, "fixture", None, 0)?;
    Ok(file)
}

#[test]
fn keeps_the_samples_of_a_time_window() -> Result {
    let image = crate::image::Image::default();
    let file = timed_recording(&image, 100_000_000)?;
    let text = report(&image, file.path(), Some(1_000_000_000), Some(2_000_000_000))?;
    assert!(text.starts_with("10 samples"), "{text}");
    assert!(text.contains("time window: 1.000 s to 2.000 s of 4.900 s"), "{text}");
    assert!(text.contains("10 samples before it and 30 after left out, 0 lost in it"), "{text}");
    // Without --to the window runs to the last sample.
    let tail = report(&image, file.path(), Some(4_500_000_000), None)?;
    assert!(tail.starts_with("5 samples"), "{tail}");
    let empty = report(&image, file.path(), Some(10_000_000_000), None).map_err(|error| error.to_string());
    assert!(empty.as_ref().is_err_and(|error| error.contains("no samples between")), "{empty:?}");
    let reversed = report(&image, file.path(), Some(2_000_000_000), Some(1_000_000_000));
    assert!(reversed.is_err());
    let untimed = timed_recording(&image, 0)?;
    let refused = report(&image, untimed.path(), Some(1), None).map_err(|error| error.to_string());
    assert!(refused.as_ref().is_err_and(|error| error.contains("carry no timestamps")), "{refused:?}");
    // The whole recording is reported as before, with no window line.
    let whole = report(&image, file.path(), None, None)?;
    assert!(whole.starts_with("50 samples") && !whole.contains("time window"), "{whole}");
    Ok(())
}

#[test]
fn counts_losses_in_the_window_and_those_without_a_time_apart() -> Result {
    let image = crate::image::Image::default();
    let mut header = super::tests::header();
    header.callchain = "none".into();
    header.image_sha256 = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    let file = tempfile::NamedTempFile::new()?;
    let mut writer = ProfileWriter::new(file.reopen()?, &header)?;
    for index in 0..10 {
        let mut sample = super::tests::sample();
        sample.timestamp_ns = 1_000_000_000 * (index + 1);
        writer.write_record(&Record::Sample(sample))?;
    }
    // In the window, after it, and at no time (as live captures write them).
    for (timestamp_ns, count) in [(3_500_000_000, 2), (9_500_000_000, 5), (0, 7)] {
        writer.write_record(&Record::Lost { timestamp_ns, tid: header.pid, count })?;
    }
    writer.finish(10_000_000_000, 0, false, "fixture", None, 0)?;
    let text = report(&image, file.path(), Some(2_000_000_000), Some(5_000_000_000))?;
    assert!(text.contains("partial=true"), "{text}");
    assert!(text.contains("after left out, 2 lost in it"), "{text}");
    assert!(text.contains("time window: 7 samples lost at no recorded time may fall in it"), "{text}");
    assert!(text.contains("warning: losses_without_a_time_may_fall_in_the_time_window"), "{text}");
    Ok(())
}

#[test]
fn refuses_a_time_window_on_a_trigger_recording_without_window_records() -> Result {
    // Written before schema 3: the trigger window is rebuilt from the header and the footer.
    let image = crate::image::Image::default();
    let mut header = super::tests::header();
    header.callchain = "none".into();
    header.trigger_window_ns = Some(1_000_000_000);
    header.trigger_static_va = Some(0x1000);
    header.image_sha256 = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    let file = tempfile::NamedTempFile::new()?;
    let mut writer = ProfileWriter::new(file.reopen()?, &header)?;
    let mut sample = super::tests::sample();
    sample.timestamp_ns = 2_000_000_000;
    writer.write_record(&Record::Sample(sample))?;
    writer.finish(3_000_000_000, 0, false, "fixture", Some(2_000_000_000), 0)?;
    let refused = report(&image, file.path(), Some(0), None).map_err(|error| error.to_string());
    assert!(refused.as_ref().is_err_and(|error| error.contains("keeps trigger windows")), "{refused:?}");
    Ok(())
}

#[test]
fn time_window_parses_and_conflicts_with_trigger_windows() -> Result {
    #[derive(clap::Parser)]
    struct Offline {
        #[command(subcommand)]
        command: ProfileCommand,
    }
    use clap::Parser;
    let parsed = Offline::try_parse_from(["xref", "report", "run.xprof", "--from", "2.5", "--to", "9s"])?;
    assert!(matches!(
        parsed.command,
        ProfileCommand::Report { from: Some(2_500_000_000), to: Some(9_000_000_000), .. }
    ));
    assert!(Offline::try_parse_from(["xref", "report", "run.xprof", "--from", "1", "--window", "1"]).is_err());
    assert!(Offline::try_parse_from(["xref", "report", "run.xprof", "--to", "1", "--merge-windows"]).is_err());
    Ok(())
}

/// `call 0x1010` at 0x1000 (returning to 0x1005), `call qword ptr [r12+0x100]` at 0x1005
/// (returning to 0x100d), padding, and `nop; ret` at 0x1010.
fn call_image() -> crate::image::Image {
    let mut bytes = vec![0xe8, 0x0b, 0x00, 0x00, 0x00, 0x41, 0xff, 0x94, 0x24, 0x00, 0x01, 0x00, 0x00];
    bytes.resize(0x10, 0x90);
    bytes.extend([0x90, 0xc3]);
    crate::image::Image {
        segments: vec![crate::image::Segment { va: 0x1000, offset: 0, size: bytes.len() }],
        functions: vec![0x1000..0x1010, 0x1010..0x1012],
        data: bytes,
        ..crate::image::Image::default()
    }
}

fn based_recording(image: &crate::image::Image, return_address: u64) -> Result<tempfile::NamedTempFile> {
    let mut header = super::tests::header();
    header.image_sha256 = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    header.callchain = "fp".into();
    header.binary_match = "caller_supplied_base_unverified".into();
    header.pie_slide = 0;
    let file = tempfile::NamedTempFile::new()?;
    let mut writer = ProfileWriter::new(file.reopen()?, &header)?;
    writer.write_record(&Record::Mapping(Mapping {
        timestamp_ns: 0,
        pid: header.pid,
        tid: header.pid,
        start: 0x1000,
        length: 0x12,
        file_offset: 0,
        device_major: u32::try_from(header.exe_device_major)?,
        device_minor: u32::try_from(header.exe_device_minor)?,
        inode: header.exe_inode,
        executable: true,
        sha256: None,
        path: "[caller-supplied target mapping]".into(),
    }))?;
    for _ in 0..60 {
        let mut sample = super::tests::sample();
        sample.ip = 0x1010;
        sample.callchain = vec![return_address];
        writer.write_record(&Record::Sample(sample))?;
    }
    writer.finish(1, 0, false, "fixture", None, 0)?;
    Ok(file)
}

#[test]
fn warns_when_target_return_addresses_follow_no_call() -> Result {
    let image = call_image();
    for return_address in [0x1005, 0x100d] {
        let right = report(&image, based_recording(&image, return_address)?.path(), None, None)?;
        assert!(!right.contains("target_return_addresses_do_not_follow_calls"), "{return_address:#x}: {right}");
    }
    let wrong = report(&image, based_recording(&image, 0x1003)?.path(), None, None)?;
    assert!(wrong.contains("warning: target_return_addresses_do_not_follow_calls"), "{wrong}");
    assert!(wrong.contains("note: only 0 of 60 return addresses in the target follow a call instruction"), "{wrong}");
    Ok(())
}

#[test]
fn notes_library_leaves_under_frame_pointer_callchains() {
    let image = crate::image::Image::default();
    let library = super::resolve::Module {
        id: 5,
        kind: "shared_object",
        path: "/usr/lib/libc.so.6".into(),
        device_major: 0,
        device_minor: 0,
        inode: 0,
        sha256: None,
        symbols_loaded: false,
        symbol_source: None,
        names: None,
    };
    let frames =
        |module, start| vec![Frame { function: FunctionKey { module, start: Some(start) }, instruction: None }];
    let mut header = super::tests::header();
    // perf-script text does not say how perf unwound, so its imports get no frame-pointer advice.
    let cases = [("fp", 3, true), ("fp", 1, false), ("dwarf", 3, false), ("imported_perf_script", 3, false)];
    for (callchain, library_samples, expected) in cases {
        header.callchain = callchain.into();
        let mut aggregate = Aggregate::new(Limits::default());
        for _ in 0..library_samples {
            aggregate.add(&frames(5, 0x40), 1);
        }
        for _ in 0..(20 - library_samples) {
            aggregate.add(&frames(1, 0x1000), 1);
        }
        let mut warnings = std::collections::BTreeSet::new();
        let notes = super::hints::notes(
            &header,
            &mut aggregate,
            std::slice::from_ref(&library),
            &image,
            super::hints::ReturnSites::default(),
            &mut warnings,
        );
        assert_eq!(warnings.contains("library_leaf_callers_unreliable_with_frame_pointers"), expected, "{callchain}");
        if expected {
            assert!(notes[0].starts_with("15.0% of samples are in library functions (/usr/lib/libc.so.6:fn_40 15.0%)"));
            assert!(notes[0].contains("--call-graph dwarf"));
        }
    }
}

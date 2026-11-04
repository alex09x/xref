/*
 * XRef — mixed sampling and Intel PT profile tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::codec::{ProfileReader, ProfileWriter};
use super::types::Record;
use std::io::Cursor;

#[test]
fn separates_instruction_records_from_samples_and_rejects_schema_one() -> Result<(), Box<dyn std::error::Error>> {
    let sample = super::tests::sample();
    let mut header = super::tests::header();
    let mut old = ProfileWriter::new(Vec::new(), &header)?;
    assert!(old.write_record(&Record::PtInstruction(sample.clone())).is_err(), "schema 1 must reject PT tags");
    header.schema_version = 2;
    let mut writer = ProfileWriter::new(Vec::new(), &header)?;
    writer.write_record(&Record::Sample(sample.clone()))?;
    writer.write_record(&Record::PtInstruction(sample.clone()))?;
    let bytes = writer.finish(1, 0, false, "fixture", None, 0)?;
    let mut reader = ProfileReader::new(Cursor::new(bytes))?;
    assert_eq!(reader.read_record()?, Some(Record::Sample(sample.clone())));
    assert_eq!(reader.read_record()?, Some(Record::PtInstruction(sample)));
    assert!(matches!(reader.read_record()?, Some(Record::End(footer)) if footer.samples == 2));
    Ok(())
}

#[test]
fn analyzes_instruction_and_sample_counts_separately() -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/macho/basic.macho");
    let image = crate::image::Image::load(&fixture)?;
    let mut header = super::tests::header();
    header.schema_version = 2;
    header.image_sha256 = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    let mut writer = ProfileWriter::new(Vec::new(), &header)?;
    writer.write_record(&Record::Sample(super::tests::sample()))?;
    writer.write_record(&Record::PtInstruction(super::tests::sample()))?;
    writer.write_record(&Record::PtInstruction(super::tests::sample()))?;
    let bytes = writer.finish(1, 0, false, "fixture", None, 0)?;
    let analysis = super::analyze::analyze(&mut Cursor::new(&bytes), &image, &std::collections::BTreeSet::new())?;
    assert_eq!(analysis.aggregate.samples, 1);
    assert_eq!(analysis.pt_aggregate.as_ref().ok_or("missing PT aggregate")?.samples, 2);
    assert!(analysis.warnings.contains("intel_pt_instruction_events_are_not_cpu_samples"));
    let report = super::report::build(&analysis, &image, 10)?;
    assert_eq!(report.samples, 1);
    assert_eq!(report.pt.ok_or("missing PT report")?.instruction_events, 2);
    let mut json = Vec::new();
    super::report::write(&analysis, &image, 10, super::cli::GroupBy::Line, true, &mut json)?;
    let output: serde_json::Value = serde_json::from_slice(&json)?;
    assert!(output["pt"]["instruction_events"].is_array());
    assert!(output["pt"]["unresolved_events"].is_number());
    let filtered =
        super::analyze::analyze(&mut Cursor::new(&bytes), &image, &std::collections::BTreeSet::from([0x1234]))?;
    assert_eq!(filtered.pt_ignored, 2);
    assert!(filtered.pt_aggregate.is_some(), "a fully filtered PT stream must remain visible");
    Ok(())
}

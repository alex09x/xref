/*
 * XRef — bounded profile record codec tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{ProfileReader, ProfileWriter};
use crate::profile::types::Record;
use std::io::Cursor;

#[test]
fn metadata_and_full_reads_enforce_combined_sample_budget() -> Result<(), Box<dyn std::error::Error>> {
    let mut header = super::super::tests::header();
    header.schema_version = 2;
    let mut writer = ProfileWriter::new(Vec::new(), &header)?;
    writer.write_record(&Record::Sample(super::super::tests::sample()))?;
    writer.write_record(&Record::PtInstruction(super::super::tests::sample()))?;
    let data = writer.finish(0, 0, false, "fixture", None, 0)?;
    for metadata_only in [false, true] {
        let mut reader = ProfileReader::new(Cursor::new(&data))?;
        reader.samples = super::super::config::MAX_SAMPLES - 1;
        let result = if metadata_only {
            reader.read_metadata_record()
        } else {
            reader.read_record()?;
            reader.read_record()
        };
        assert_eq!(result.err().ok_or("sample budget was not enforced")?.to_string(), "profile sample budget exceeded");
    }
    Ok(())
}

/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::tests_live::start_fixture;
use std::collections::BTreeSet;
use std::io::Write;
use std::process::Command;

fn read_word(bytes: &[u8], offset: usize) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::from_le_bytes(bytes.get(offset..offset + 8).ok_or("short perf data")?.try_into()?))
}

fn compressed_copy(data: &[u8], version_two: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let start = usize::try_from(read_word(data, 40)?)?;
    let length = usize::try_from(read_word(data, 48)?)?;
    let end = start.checked_add(length).ok_or("data size overflow")?;
    let payload = data.get(start..end).ok_or("short perf data section")?;
    let mut encoded = vec![0_u8; zstd_safe::compress_bound(payload.len())];
    let size = zstd_safe::compress(encoded.as_mut_slice(), payload, 1).map_err(|_| "compression failed")?;
    encoded.truncate(size);
    let body_size = if version_two { (size + 8 + 7) & !7 } else { size };
    let record_size = u16::try_from(body_size + 8)?;
    let mut output = data[..start].to_vec();
    output.extend_from_slice(&(if version_two { 83_u32 } else { 81_u32 }).to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&record_size.to_le_bytes());
    if version_two {
        output.extend_from_slice(&u64::try_from(size)?.to_le_bytes());
    }
    output.extend_from_slice(&encoded);
    output.resize(start + usize::from(record_size), 0);
    output.extend_from_slice(&data[end..]);
    output[48..56].copy_from_slice(&u64::from(record_size).to_le_bytes());
    let new_end = start + usize::from(record_size);
    let shift = i128::try_from(new_end)? - i128::try_from(end)?;
    for at in [24_usize, 56] {
        let offset = read_word(data, at)?;
        if usize::try_from(offset)? >= end && offset != 0 {
            output[at..at + 8].copy_from_slice(&u64::try_from(i128::from(offset) + shift)?.to_le_bytes());
        }
    }
    let features = (72..104)
        .step_by(8)
        .map(|at| read_word(data, at).map(u64::count_ones))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<u32>();
    for i in 0..usize::try_from(features)? {
        let old = end + i * 16;
        let value = read_word(data, old)?;
        let shifted = if usize::try_from(value)? >= end { u64::try_from(i128::from(value) + shift)? } else { value };
        output[new_end + i * 16..new_end + i * 16 + 8].copy_from_slice(&shifted.to_le_bytes());
    }
    Ok(output)
}

#[test]
#[ignore = "requires perf, sudo -n and hardware event permission"]
fn imports_compressed_real_perf_recording_with_equal_sample_count() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let perf = std::env::split_paths(&std::env::var_os("PATH").ok_or("missing PATH")?)
        .map(|path| path.join("perf"))
        .find(|path| path.is_file())
        .ok_or("perf missing")?;
    let original = fixture.directory.join("original.data");
    let result = Command::new("sudo")
        .arg("-n")
        .arg(perf)
        .args(["record", "--no-buildid-cache", "-F", "50", "-e", "{cycles:u,instructions:u}:S", "-g", "-p"])
        .arg(fixture.child.id().to_string())
        .arg("-o")
        .arg(&original)
        .args(["--", "sleep", "1"])
        .output()?;
    assert!(result.status.success(), "perf: {}", String::from_utf8_lossy(&result.stderr));
    let perf_file =
        linux_perf_data::PerfFileReader::parse_file(std::io::BufReader::new(std::fs::File::open(&original)?))?;
    assert!(
        perf_file.perf_file.event_attributes()[0]
            .attr
            .sample_format
            .contains(linux_perf_data::linux_perf_event_reader::SampleFormat::READ),
        "recording must include sample READ"
    );
    let original_bytes = std::fs::read(&original)?;
    let compressed = fixture.directory.join("compressed.data");
    let compressed_two = fixture.directory.join("compressed2.data");
    std::fs::write(&compressed, compressed_copy(&original_bytes, false)?)?;
    std::fs::write(&compressed_two, compressed_copy(&original_bytes, true)?)?;
    let session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let base = u64::try_from(i128::from(session.image.metadata.base) + i128::from(session.process.pie_slide))?;
    let base_text = format!("{base:#x}");
    let mut counts = Vec::new();
    let mut samples = Vec::new();
    for (index, source) in [original, compressed, compressed_two].iter().enumerate() {
        let output = fixture.directory.join(format!("{index}.xprof"));
        let options = super::import_text::Options {
            bin: &binary,
            input: source,
            output: &output,
            base: Some(&base_text),
            maps: None,
            target_path: None,
            pid: Some(fixture.child.id()),
        };
        super::import_text::run(&session.image, &options)?;
        counts.push(
            super::analyze::analyze(&mut std::fs::File::open(&output)?, &session.image, &BTreeSet::new())?
                .aggregate
                .samples,
        );
        let mut reader = super::codec::ProfileReader::new(std::fs::File::open(output)?)?;
        let mut imported = Vec::new();
        while let Some(record) = reader.read_record()? {
            if let super::types::Record::Sample(sample) = record {
                imported.push(sample);
            }
        }
        samples.push(imported);
    }
    assert!(counts[0] > 0, "fixture must produce samples");
    assert_eq!(counts[0], counts[1], "compressed import changed the sample count");
    assert_eq!(counts[0], counts[2], "compressed2 import changed the sample count");
    assert_eq!(samples[0], samples[1], "compressed import changed sample data");
    assert_eq!(samples[0], samples[2], "compressed2 import changed sample data");
    fixture.child.stdin.as_mut().ok_or("missing stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

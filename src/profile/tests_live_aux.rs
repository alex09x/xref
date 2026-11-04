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

fn word(bytes: &[u8], offset: usize) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::from_le_bytes(bytes.get(offset..offset + 8).ok_or("short perf data")?.try_into()?))
}

fn insert_aux(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let start = usize::try_from(word(data, 40)?)?;
    let length = usize::try_from(word(data, 48)?)?;
    let end = start.checked_add(length).ok_or("data size overflow")?;
    let mut event = vec![0_u8; 64];
    event[..4].copy_from_slice(&71_u32.to_le_bytes());
    event[6..8].copy_from_slice(&48_u16.to_le_bytes());
    event[8..16].copy_from_slice(&16_u64.to_le_bytes());
    event[48..].fill(0x5a);
    let mut result = data[..start].to_vec();
    result.extend_from_slice(&event);
    result.extend_from_slice(&data[start..]);
    result[48..56].copy_from_slice(&u64::try_from(length + event.len())?.to_le_bytes());
    for at in [24_usize, 56] {
        let offset = word(data, at)?;
        if usize::try_from(offset)? >= start && offset != 0 {
            result[at..at + 8].copy_from_slice(&(offset + u64::try_from(event.len())?).to_le_bytes());
        }
    }
    let features = (72..104)
        .step_by(8)
        .map(|at| word(data, at).map(u64::count_ones))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<u32>();
    let new_end = end + event.len();
    for i in 0..usize::try_from(features)? {
        let old = end + i * 16;
        let value = word(data, old)?;
        let shifted = if usize::try_from(value)? >= start { value + u64::try_from(event.len())? } else { value };
        result[new_end + i * 16..new_end + i * 16 + 8].copy_from_slice(&shifted.to_le_bytes());
    }
    Ok(result)
}

#[test]
#[ignore = "requires perf, sudo -n and hardware event permission"]
fn retains_real_samples_and_marks_synthetic_aux_undecoded() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let perf = std::env::split_paths(&std::env::var_os("PATH").ok_or("missing PATH")?)
        .map(|path| path.join("perf"))
        .find(|path| path.is_file())
        .ok_or("perf missing")?;
    let original = fixture.directory.join("original.data");
    let status = Command::new("sudo")
        .arg("-n")
        .arg(perf)
        .args(["record", "--no-buildid-cache", "-F", "50", "-e", "cycles:u", "-g", "-p"])
        .arg(fixture.child.id().to_string())
        .arg("-o")
        .arg(&original)
        .args(["--", "sleep", "1"])
        .output()?;
    assert!(status.status.success(), "perf: {}", String::from_utf8_lossy(&status.stderr));
    let augmented = fixture.directory.join("aux.data");
    std::fs::write(&augmented, insert_aux(&std::fs::read(&original)?)?)?;
    let session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let base = u64::try_from(i128::from(session.image.metadata.base) + i128::from(session.process.pie_slide))?;
    let base_text = format!("{base:#x}");
    let mut samples = Vec::new();
    for (index, source) in [original, augmented].iter().enumerate() {
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
        let analysis = super::analyze::analyze(&mut std::fs::File::open(&output)?, &session.image, &BTreeSet::new())?;
        if index == 1 {
            assert!(analysis.warnings.contains("aux_trace_not_decoded"), "missing AUX warning");
        }
        let mut reader = super::codec::ProfileReader::new(std::fs::File::open(output)?)?;
        let mut actual = Vec::new();
        while let Some(record) = reader.read_record()? {
            if let super::types::Record::Sample(sample) = record {
                actual.push(sample);
            }
        }
        samples.push(actual);
    }
    assert!(!samples[0].is_empty(), "fixture must produce samples");
    assert_eq!(samples[0], samples[1], "AUX metadata must not change regular samples");
    fixture.child.stdin.as_mut().ok_or("missing stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

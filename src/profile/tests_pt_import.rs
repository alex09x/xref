/*
 * XRef — Intel PT import integration fixture
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use object::{Object, ObjectSymbol};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

struct Target(Child);
impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn word(data: &[u8], at: usize) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::from_le_bytes(data.get(at..at + 8).ok_or("truncated data")?.try_into()?))
}

/// Preserve the real perf-generated sideband and build-ID sections, removing
/// ordinary samples so the result exercises AUX-only import. PT bytes and AUX
/// metadata are synthetic; this is not a hardware Intel PT recording.
fn add_aux(data: &[u8], trace: &[u8], pid: u32, mixed: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let start = usize::try_from(word(data, 40)?)?;
    let old_end = start.checked_add(usize::try_from(word(data, 48)?)?).ok_or("data overflow")?;
    let mut events = Vec::new();
    events.extend_from_slice(&70_u32.to_le_bytes());
    events.extend_from_slice(&0_u16.to_le_bytes());
    events.extend_from_slice(&96_u16.to_le_bytes());
    events.extend_from_slice(&1_u32.to_le_bytes());
    events.extend_from_slice(&0_u32.to_le_bytes());
    events.extend_from_slice(&[0_u8; 80]);
    // The synthetic Intel PT PMU must match the event attribute, just as it
    // would in a genuine perf recording.
    events[16..24].copy_from_slice(&99_u64.to_le_bytes());
    let mut pos = start;
    while pos < old_end {
        let header = data.get(pos..pos + 8).ok_or("truncated perf event")?;
        let kind = u32::from_le_bytes(header[..4].try_into()?);
        let size = usize::from(u16::from_le_bytes([header[6], header[7]]));
        if size < 8 || pos.checked_add(size).is_none_or(|end| end > old_end) {
            return Err("invalid perf event".into());
        }
        if mixed || kind != 9 {
            events.extend_from_slice(&data[pos..pos + size]);
        }
        pos += size;
    }
    let mut aux = [0_u8; 48];
    aux[..4].copy_from_slice(&71_u32.to_le_bytes());
    aux[6..8].copy_from_slice(&48_u16.to_le_bytes());
    aux[8..16].copy_from_slice(&u64::try_from(trace.len())?.to_le_bytes());
    aux[36..40].copy_from_slice(&pid.to_le_bytes());
    events.extend_from_slice(&aux);
    events.extend_from_slice(trace);
    let new_end = start.checked_add(events.len()).ok_or("data overflow")?;
    let delta = i128::try_from(new_end)? - i128::try_from(old_end)?;
    let shifted = |value: u64| -> Result<u64, Box<dyn std::error::Error>> {
        if value != 0 && usize::try_from(value)? >= old_end {
            Ok(u64::try_from(i128::from(value) + delta)?)
        } else {
            Ok(value)
        }
    };
    let mut result = data[..start].to_vec();
    result.extend_from_slice(&events);
    result.extend_from_slice(&data[old_end..]);
    result[48..56].copy_from_slice(&u64::try_from(events.len())?.to_le_bytes());
    for at in [24_usize, 56] {
        result[at..at + 8].copy_from_slice(&shifted(word(data, at)?)?.to_le_bytes());
    }
    let attr = usize::try_from(shifted(word(data, 24)?)?)? + if mixed { usize::try_from(word(data, 16)?)? } else { 0 };
    result[attr..attr + 4].copy_from_slice(&99_u32.to_le_bytes());
    let mut index = 0_usize;
    for bit in 0..128_usize {
        if word(data, 72 + (bit / 64) * 8)? & (1_u64 << (bit % 64)) == 0 {
            continue;
        }
        let old_at = old_end + index * 16;
        let new_at = new_end + index * 16;
        let feature = usize::try_from(shifted(word(data, old_at)?)?)?;
        result[new_at..new_at + 8].copy_from_slice(&u64::try_from(feature)?.to_le_bytes());
        if bit == 12 {
            let mut event = feature + 8;
            if mixed {
                let attr_size = usize::try_from(u32::from_le_bytes(result[feature + 4..feature + 8].try_into()?))?;
                let ids =
                    usize::try_from(u32::from_le_bytes(result[event + attr_size..event + attr_size + 4].try_into()?))?;
                let name = usize::try_from(u32::from_le_bytes(
                    result[event + attr_size + 4..event + attr_size + 8].try_into()?,
                ))?;
                event += attr_size + 8 + name + ids * 8;
            }
            result[event..event + 4].copy_from_slice(&99_u32.to_le_bytes());
        }
        index += 1;
    }
    Ok(result)
}

#[test]
#[ignore = "requires perf, sudo -n and hardware event permission"]
#[allow(clippy::too_many_lines)] // Exercise both container forms and invalid sideband in one capture.
fn imports_aux_only_pt_with_real_elf_and_perf_sideband() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("target.c");
    let binary = dir.path().join("target");
    std::fs::write(
        &source,
        r#"
#include <stdio.h>
__asm__(".text\n.globl pt_entry\n.type pt_entry,@function\npt_entry:\n.cfi_startproc\ncall pt_ret\njz pt_end\nhlt\npt_ret:\nret\npt_end:\nnop\n.cfi_endproc\n.size pt_entry,.-pt_entry\n");
int main(void) { puts("READY"); fflush(stdout); volatile unsigned long n=0; for (;;) n++; }
"#,
    )?;
    let status =
        Command::new("cc").args(["-O2", "-no-pie", "-Wl,--build-id"]).arg(&source).arg("-o").arg(&binary).status()?;
    assert!(status.success(), "target compilation failed");
    let bytes = std::fs::read(&binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let entry = object
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("pt_entry"))
        .map(|symbol| symbol.address())
        .ok_or("missing PT entry")?;
    assert!(entry < (1_u64 << 47) && entry & 0xffff <= 0xfff0, "fixture address cannot be encoded");
    let mut trace = [2, 0x82].repeat(8);
    trace.push(0x7d);
    trace.extend_from_slice(&entry.to_le_bytes()[..6]);
    trace.extend_from_slice(&[0x99, 1, 2, 0x23, 0x0e, 0x3d]);
    trace.extend_from_slice(&(entry + 9).to_le_bytes()[..2]);
    trace.push(1);
    let child = Command::new(&binary).stdout(Stdio::piped()).spawn()?;
    let mut target = Target(child);
    let mut ready = String::new();
    BufReader::new(target.0.stdout.take().ok_or("missing stdout")?).read_line(&mut ready)?;
    assert!(ready.starts_with("READY"), "target did not start");
    let perf = std::env::split_paths(&std::env::var_os("PATH").ok_or("missing PATH")?)
        .map(|path| path.join("perf"))
        .find(|path| path.is_file())
        .ok_or("perf missing")?;
    let recording = dir.path().join("original.data");
    let result = Command::new("sudo")
        .arg("-n")
        .arg(&perf)
        .args(["record", "--no-buildid-cache", "--buildid-all", "-F", "100", "-e", "cycles:u", "-p"])
        .arg(target.0.id().to_string())
        .arg("-o")
        .arg(&recording)
        .args(["--", "sleep", "1"])
        .output()?;
    assert!(result.status.success(), "perf: {}", String::from_utf8_lossy(&result.stderr));
    let input = dir.path().join("pt.data");
    let pt_data = add_aux(&std::fs::read(recording)?, &trace, target.0.id(), false)?;
    std::fs::write(&input, &pt_data)?;
    let compressed_input = dir.path().join("pt-compressed.data");
    std::fs::write(&compressed_input, super::tests_live_compressed::compressed_copy(&pt_data, true)?)?;
    let image = crate::image::Image::load(&binary)?;
    let base = format!("{:#x}", image.metadata.base);
    for (index, path) in [&input, &compressed_input].iter().enumerate() {
        let output = dir.path().join(format!("profile-{index}.xprof"));
        let options = super::import_text::Options {
            bin: &binary,
            input: path,
            output: &output,
            base: Some(&base),
            maps: None,
            target_path: None,
            pid: Some(target.0.id()),
        };
        super::import_text::run(&image, &options)?;
        let mut reader = super::codec::ProfileReader::new(std::fs::File::open(output)?)?;
        assert_eq!(reader.header.event, super::types::SYNTHETIC_PT_EVENT);
        let mut samples = Vec::new();
        while let Some(record) = reader.read_record()? {
            if let super::types::Record::Sample(sample) = record {
                samples.push(sample);
            }
        }
        assert_eq!(samples.iter().map(|sample| sample.ip).collect::<Vec<_>>(), [entry, entry + 8, entry + 5]);
        assert_eq!(samples[1].callchain, [entry + 5]);
        assert!(
            samples.iter().all(|sample| sample.timestamp_ns == 0),
            "synthetic instruction times must not be invented"
        );
    }
    let wrong_pmu = dir.path().join("wrong-pmu.data");
    let mut altered = pt_data;
    let events_at = usize::try_from(word(&altered, 40)?)?;
    altered[events_at + 16..events_at + 24].copy_from_slice(&100_u64.to_le_bytes());
    std::fs::write(&wrong_pmu, altered)?;
    let rejected = dir.path().join("rejected.xprof");
    let options = super::import_text::Options {
        bin: &binary,
        input: &wrong_pmu,
        output: &rejected,
        base: Some(&base),
        maps: None,
        target_path: None,
        pid: Some(target.0.id()),
    };
    assert!(super::import_text::run(&image, &options).is_err(), "mismatched PMU must fail");
    assert!(!rejected.exists(), "failed import must not leave output");
    let wrong_base = format!("{:#x}", image.metadata.base + 0x1000);
    let wrong_output = dir.path().join("wrong-base.xprof");
    let options = super::import_text::Options {
        bin: &binary,
        input: &input,
        output: &wrong_output,
        base: Some(&wrong_base),
        maps: None,
        target_path: None,
        pid: Some(target.0.id()),
    };
    assert!(super::import_text::run(&image, &options).is_err(), "incorrect slide must fail");
    assert!(!wrong_output.exists(), "failed import must not leave output");
    // A real two-event perf capture supplies CPU samples and MMAP/COMM sideband;
    // only the PT PMU attribute and AUX bytes are synthetic.
    let mixed_recording = dir.path().join("mixed-original.data");
    let result = Command::new("sudo")
        .arg("-n")
        .arg(&perf)
        .args(["record", "--no-buildid-cache", "--buildid-all", "-F", "100", "-e", "cycles:u", "-e", "dummy:u", "-p"])
        .arg(target.0.id().to_string())
        .arg("-o")
        .arg(&mixed_recording)
        .args(["--", "sleep", "1"])
        .output()?;
    assert!(result.status.success(), "mixed perf: {}", String::from_utf8_lossy(&result.stderr));
    let baseline_output = dir.path().join("mixed-baseline.xprof");
    let baseline_options = super::import_text::Options {
        bin: &binary,
        input: &mixed_recording,
        output: &baseline_output,
        base: Some(&base),
        maps: None,
        target_path: None,
        pid: Some(target.0.id()),
    };
    super::import_text::run(&image, &baseline_options)?;
    let mut baseline_reader = super::codec::ProfileReader::new(std::fs::File::open(baseline_output)?)?;
    let mut baseline = Vec::new();
    while let Some(record) = baseline_reader.read_record()? {
        if let super::types::Record::Sample(sample) = record {
            baseline.push(sample);
        }
    }
    assert!(!baseline.is_empty(), "capture must contain ordinary samples");
    let mixed_data = add_aux(&std::fs::read(&mixed_recording)?, &trace, target.0.id(), true)?;
    for compressed in [false, true] {
        let input = dir.path().join(format!("mixed-{compressed}.data"));
        let bytes = if compressed {
            super::tests_live_compressed::compressed_copy(&mixed_data, true)?
        } else {
            mixed_data.clone()
        };
        std::fs::write(&input, bytes)?;
        let output = dir.path().join(format!("mixed-{compressed}.xprof"));
        let options = super::import_text::Options {
            bin: &binary,
            input: &input,
            output: &output,
            base: Some(&base),
            maps: None,
            target_path: None,
            pid: Some(target.0.id()),
        };
        super::import_text::run(&image, &options)?;
        let mut reader = super::codec::ProfileReader::new(std::fs::File::open(output)?)?;
        assert_eq!(reader.header.schema_version, 2);
        let (mut ordinary, mut instructions) = (Vec::new(), Vec::new());
        while let Some(record) = reader.read_record()? {
            match record {
                super::types::Record::Sample(sample) => ordinary.push(sample),
                super::types::Record::PtInstruction(sample) => instructions.push(sample.ip),
                _ => {}
            }
        }
        assert_eq!(ordinary, baseline, "ordinary samples must be preserved without changes");
        assert_eq!(instructions, [entry, entry + 8, entry + 5]);
    }
    Ok(())
}

/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![allow(clippy::unwrap_used, clippy::expect_used)] // Controlled compiled-fixture test oracles.
use super::aggregate::{Aggregate, Frame, FunctionKey, Limits};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::tests::sample;

#[test]
fn metadata_pass_skips_samples_but_full_pass_validates_them() -> Result<(), Box<dyn std::error::Error>> {
    use super::codec::{ProfileReader, ProfileWriter};
    use super::types::Record;
    let mut writer = ProfileWriter::new(Vec::new(), &super::tests::header())?;
    writer.write_record(&Record::Sample(super::tests::sample()))?;
    writer.write_record(&Record::Lost { timestamp_ns: 200, tid: 43, count: 2 })?;
    let bytes = writer.finish(200, 0, true, "fixture", None, 0)?;
    let mut metadata = ProfileReader::new(std::io::Cursor::new(&bytes))?;
    assert!(matches!(metadata.read_metadata_record()?, Some(Record::Lost { count: 2, .. })));
    assert!(matches!(metadata.read_metadata_record()?, Some(Record::End(footer)) if footer.samples == 1));
    let header_len = usize::try_from(u32::from_le_bytes(bytes[8..12].try_into()?))?;
    let mask_offset = 12 + header_len + 4 + 35;
    let mut corrupted = bytes;
    corrupted[mask_offset..mask_offset + 8].fill(0);
    let mut metadata = ProfileReader::new(std::io::Cursor::new(&corrupted))?;
    assert!(metadata.read_metadata_record()?.is_some());
    let mut full = ProfileReader::new(std::io::Cursor::new(&corrupted))?;
    assert!(full.read_record().is_err(), "the full pass must reject malformed sample data");
    Ok(())
}

#[test]
fn profile_address_slide_handles_both_directions_and_extremes() {
    use super::types::remove_slide;
    assert_eq!(remove_slide(12, 4), Some(8));
    assert_eq!(remove_slide(12, -4), Some(16));
    assert_eq!(remove_slide(0, i64::MIN), Some(1_u64 << 63));
    assert_eq!(remove_slide(0, 1), None);
    assert_eq!(remove_slide(u64::MAX, -1), None);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn dwarf_unwind_uses_cfi_from_a_compiled_stripped_elf() -> Result<(), Box<dyn std::error::Error>> {
    use object::{Object, ObjectSymbol};
    use std::{fs, process::Command};
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-profile-cfi-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let original = dir.join("original");
    let stripped = dir.join("stripped");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_unwind.S");
    let status = Command::new("cc")
        .args(["-nostdlib", "-no-pie", "-Wl,-e,profile_leaf"])
        .arg(source)
        .arg("-o")
        .arg(&original)
        .status()?;
    assert!(status.success());
    let bytes = fs::read(&original)?;
    let object = object::File::parse(bytes.as_slice())?;
    let symbol = |name: &str| {
        object.symbols().find(|symbol| symbol.name().ok() == Some(name)).map(|symbol| symbol.address()).unwrap()
    };
    let leaf = symbol("profile_leaf");
    let parent = symbol("profile_parent");
    assert!(Command::new("objcopy").arg("--strip-all").arg(&original).arg(&stripped).status()?.success());
    let image = crate::image::Image::load(&stripped)?;
    let mut stack = Vec::new();
    stack.extend_from_slice(&(parent + 1).to_le_bytes());
    stack.extend_from_slice(&0_u64.to_le_bytes());
    let mut input = sample();
    input.ip = leaf;
    input.registers_mask = 1 << 7;
    input.registers = vec![0x7000];
    input.user_stack = stack;
    let unwinder = super::unwind::Unwinder::new(&image, 0)?;
    let result = unwinder.unwind(&input, 16);
    assert_eq!(result.frames, vec![leaf, parent + 1]);
    assert_eq!(result.stop_reason, "end_of_stack");
    input.user_stack.truncate(7);
    assert_eq!(unwinder.unwind(&input, 16).stop_reason, "return_address_unavailable");
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn samples_group_into_decoded_control_flow_blocks() {
    let bytes = vec![0x74, 0x02, 0x90, 0xc3, 0xc3];
    let image = crate::image::Image {
        segments: vec![crate::image::Segment { va: 0x1000, offset: 0, size: bytes.len() }],
        data: bytes,
        functions: std::iter::once(0x1000..0x1005).collect(),
        ..crate::image::Image::default()
    };
    let key = FunctionKey { module: 1, start: Some(0x1000) };
    let mut aggregate = Aggregate::new(Limits::default());
    aggregate.add(&[Frame { function: key, instruction: Some(0x1002) }], 1);
    aggregate.add(&[Frame { function: key, instruction: Some(0x1002) }], 1);
    aggregate.add(&[Frame { function: key, instruction: Some(0x1004) }], 1);
    let blocks = super::blocks::collect(&image, &aggregate);
    assert_eq!(blocks.len(), 2);
    assert_eq!((blocks[0].start, blocks[0].end, blocks[0].samples), (0x1002, 0x1004, 2));
    assert_eq!((blocks[1].start, blocks[1].end, blocks[1].samples), (0x1004, 0x1005, 1));
    assert!(!blocks[0].cfg_incomplete);
}

/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::{Branch, Mapping};
use object::{Object, ObjectSymbol};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

#[test]
fn lbr_branch_sources_map_to_ordered_functions_in_stripped_elf() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let original = dir.path().join("original");
    let stripped = dir.path().join("stripped");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_unwind.S");
    let status = Command::new("cc")
        .args(["-nostdlib", "-no-pie", "-Wl,-e,profile_leaf"])
        .arg(source)
        .arg("-o")
        .arg(&original)
        .status()?;
    assert!(status.success(), "failed to compile ELF fixture");
    let bytes = std::fs::read(&original)?;
    let object = object::File::parse(bytes.as_slice())?;
    let symbol = |name: &str| {
        object
            .symbols()
            .find(|entry| entry.name().ok() == Some(name))
            .map(|entry| entry.address())
            .ok_or("missing fixture symbol")
    };
    let leaf = symbol("profile_leaf")?;
    let parent = symbol("profile_parent")?;
    assert!(Command::new("objcopy").arg("--strip-all").arg(&original).arg(&stripped).status()?.success());
    let image = crate::image::Image::load(&stripped)?;
    let mut header = super::tests::header();
    header.callchain = "lbr".into();
    let mapping = Mapping {
        timestamp_ns: 0,
        pid: 42,
        tid: 42,
        start: 0,
        length: u64::MAX,
        file_offset: 0,
        device_major: 8,
        device_minor: 1,
        inode: 73,
        executable: true,
        sha256: None,
        path: "/target".into(),
    };
    let index = super::resolve::MappingIndex::new(vec![mapping], &header);
    let mut sample = super::tests::sample();
    sample.ip = leaf;
    sample.branches =
        vec![Branch { from: parent, to: leaf, flags: 0 }, Branch { from: 0xdead_beef, to: parent, flags: 0 }];
    let frames =
        super::analyze::sample_frames(&index, &image, &header, &sample, &BTreeMap::new(), &mut BTreeSet::new());
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].function.start, Some(leaf));
    assert_eq!(frames[1].function.start, Some(parent));
    assert_eq!(frames[2].function.start, None, "unknown branch source must remain unresolved");
    Ok(())
}

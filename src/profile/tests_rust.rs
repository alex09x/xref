/*
 * XRef — optimized Rust CFI integration fixture
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{types::Sample, unwind::Unwinder};
use object::{Object, ObjectSymbol};
use std::{path::PathBuf, process::Command};

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unwinds_optimized_stripped_rust_cfi_without_frame_pointers() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = TempDir(std::env::temp_dir().join(format!("xref-rust-cfi-{}-{nonce}", std::process::id())));
    std::fs::create_dir_all(&dir.0)?;
    let original = dir.0.join("original");
    let stripped = dir.0.join("stripped");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_target.rs");
    let output = Command::new("rustc")
        .args(["--edition=2024", "-C", "opt-level=2", "-C", "force-frame-pointers=no", "-C", "debuginfo=2"])
        .arg(source)
        .arg("-o")
        .arg(&original)
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let original_bytes = std::fs::read(&original)?;
    let object = object::File::parse(original_bytes.as_slice())?;
    let symbol = |name: &str| {
        object
            .symbols()
            .find(|symbol| symbol.name().ok() == Some(name))
            .map(|symbol| symbol.address())
            .ok_or("missing fixture symbol")
    };
    let leaf = symbol("profile_rust_hot")?;
    let parent = symbol("profile_rust_parent")?;
    assert!(Command::new("objcopy").arg("--strip-all").arg(&original).arg(&stripped).status()?.success());
    let image = crate::image::Image::load(&stripped)?;
    let mut stack = Vec::new();
    stack.extend_from_slice(&(parent + 1).to_le_bytes());
    stack.extend_from_slice(&0_u64.to_le_bytes());
    let sample = Sample {
        timestamp_ns: 1,
        pid: 1,
        tid: 1,
        cpu_mode: 2,
        ip: leaf,
        period: 1,
        registers_mask: 1 << 7,
        registers: vec![0x7000],
        user_stack: stack,
        callchain: vec![],
        branches: vec![],
    };
    let result = Unwinder::new(&image, 0)?.unwind(&sample, 16);
    assert_eq!(result.frames, vec![leaf, parent + 1]);
    assert_eq!(result.stop_reason, "end_of_stack");
    Ok(())
}

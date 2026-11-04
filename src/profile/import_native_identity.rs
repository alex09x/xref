/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::image::Image;
use linux_perf_data::linux_perf_event_reader::CpuMode;
use linux_perf_data::{DsoInfo, DsoKey, PerfFile};
use object::Object;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;

/// Reject a recorded target build ID that contradicts the chosen binary.
/// Absence of either ID is not proof of identity.
pub fn verify_target(
    file: &PerfFile,
    image: &Image,
    target_path: &str,
) -> Result<HashMap<DsoKey, DsoInfo>, Box<dyn std::error::Error>> {
    let ids = file.build_ids()?;
    if let Some(key) = DsoKey::detect(target_path.as_bytes(), CpuMode::User)
        && let (Some(recorded), Some(actual)) = (ids.get(&key), image.metadata.build_id.as_ref())
        && recorded.build_id != *actual
    {
        return Err("binary_mismatch: perf.data target build ID differs from --bin".into());
    }
    Ok(ids)
}

/// Hash a bounded local module only if its build ID agrees with the recording.
pub fn verified_module(path: &str, expected: &[u8], remaining: u64) -> Option<(String, u64)> {
    let path = std::path::Path::new(path);
    if !path.is_absolute() || path.to_string_lossy().ends_with(" (deleted)") {
        return None;
    }
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    let before = file.metadata().ok()?;
    if !before.is_file() || before.len() > 128 * 1024 * 1024 || before.len() > remaining {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(128 * 1024 * 1024 + 1).read_to_end(&mut bytes).ok()?;
    if u64::try_from(bytes.len()).ok()? != before.len() {
        return None;
    }
    let object = object::File::parse(bytes.as_slice()).ok()?;
    if object.build_id().ok().flatten()? != expected {
        return None;
    }
    let after = std::fs::metadata(path).ok()?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return None;
    }
    Some((crate::trace_analysis::index::hex_bytes(&Sha256::digest(&bytes)), before.len()))
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;
    #[test]
    fn hashes_only_local_shared_object_with_matching_build_id() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("xref-import-module-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("module.so");
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_unwind.S");
        assert!(
            std::process::Command::new("cc")
                .args(["-nostdlib", "-shared", "-Wl,--build-id"])
                .arg(source)
                .arg("-o")
                .arg(&path)
                .status()?
                .success()
        );
        let bytes = std::fs::read(&path)?;
        let object = object::File::parse(bytes.as_slice())?;
        let build_id = object.build_id()?.ok_or("missing build ID")?;
        let path_str = path.to_str().ok_or("invalid path")?;
        let (hash, size) = verified_module(path_str, build_id, u64::MAX).ok_or("matching module not verified")?;
        assert_eq!(hash, crate::trace_analysis::index::hex_bytes(&Sha256::digest(&bytes)));
        assert_eq!(size, u64::try_from(bytes.len())?);
        assert!(verified_module(path_str, &[0; 20], u64::MAX).is_none());
        assert!(verified_module(path_str, build_id, 0).is_none());
        let fifo = dir.join("not-a-module");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status()?.success());
        assert!(verified_module(fifo.to_str().ok_or("invalid FIFO path")?, build_id, u64::MAX).is_none());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}

/*
 * XRef — persistent result cache for repeated `field` queries
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A repeated `xref -b BIN field ...` with the same arguments on an unchanged input returns the stored
//! report without loading or hashing the image (#76: tens of milliseconds instead of a full search).
//!
//! The key covers every command-line argument, the canonical input path and its file metadata
//! (device, inode, size, modification and change times in nanoseconds), and the same metadata of the
//! running xref executable. Any change to the input, to xref or to an argument misses. Entries live
//! next to the field index (`$XDG_CACHE_HOME/xref/field-index-v1/results`, private, checksummed).
//! Set `XREF_NO_RESULT_CACHE=1` to bypass it.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"XRFRES01";
const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(unix)]
fn stat_bytes(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let canonical = std::fs::canonicalize(path).ok()?;
    let meta = std::fs::metadata(&canonical).ok()?;
    let mut bytes = canonical.as_os_str().as_encoded_bytes().to_vec();
    bytes.push(0);
    for value in [meta.dev(), meta.ino(), meta.size()] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in [meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec()] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    Some(bytes)
}

/// Cache path for this exact invocation, or `None` when caching is unavailable or disabled.
#[cfg(unix)]
#[must_use]
pub fn path_for(bin: &Path) -> Option<PathBuf> {
    if std::env::var_os("XREF_NO_RESULT_CACHE").is_some() {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(MAGIC);
    digest.update(stat_bytes(bin)?);
    digest.update(stat_bytes(&std::env::current_exe().ok()?)?);
    for argument in std::env::args_os() {
        digest.update(argument.as_encoded_bytes());
        digest.update([0]);
    }
    let key = crate::trace_analysis::index::hex_bytes(&digest.finalize());
    let root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    root.is_absolute().then(|| root.join("xref").join("field-index-v1").join("results").join(key))
}

#[cfg(not(unix))]
#[must_use]
pub const fn path_for(_bin: &Path) -> Option<PathBuf> {
    None
}

/// The stored report, if present, private and intact.
#[cfg(unix)]
#[must_use]
pub fn load(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    let directory = path.parent()?;
    let private = |p: &Path, dir: bool| {
        std::fs::symlink_metadata(p).is_ok_and(|meta| {
            (if dir { meta.file_type().is_dir() } else { meta.file_type().is_file() })
                && meta.permissions().mode().trailing_zeros() >= 6
        })
    };
    if !private(directory, true) || !private(path, false) {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path).ok()?.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    let (content, checksum) = bytes.split_at_checked(bytes.len().checked_sub(32)?)?;
    (u64::try_from(bytes.len()).ok()? <= MAX_BYTES
        && Sha256::digest(content)[..] == *checksum
        && content.get(..8)? == MAGIC)
        .then(|| content[8..].to_vec())
}

#[cfg(not(unix))]
#[must_use]
pub const fn load(_path: &Path) -> Option<Vec<u8>> {
    None
}

/// Store a report atomically with private permissions; failures are ignored (the cache is optional).
#[cfg(unix)]
pub fn store(path: &Path, report: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let Some(directory) = path.parent() else { return };
    if u64::try_from(report.len()).map_or(true, |len| len > MAX_BYTES - 40)
        || std::fs::DirBuilder::new().recursive(true).mode(0o700).create(directory).is_err()
    {
        return;
    }
    let mut data = Vec::with_capacity(report.len() + 40);
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(report);
    let checksum = Sha256::digest(&data);
    data.extend_from_slice(&checksum);
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
    let temporary = directory.join(format!(".{}.{nonce}", std::process::id()));
    let Ok(mut file) = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary) else {
        return;
    };
    if file.write_all(&data).is_ok() {
        let _ = std::fs::rename(&temporary, path);
    }
    let _ = std::fs::remove_file(temporary);
}

#[cfg(not(unix))]
pub const fn store(_path: &Path, _report: &[u8]) {}

/// A report that depends on wall-clock budgets must not be replayed.
#[must_use]
pub fn cacheable(report: &[u8]) -> bool {
    !report.windows(b"cooperative_30_second".len()).any(|window| window == b"cooperative_30_second")
}

#[cfg(all(test, unix))]
mod tests {
    use super::{cacheable, load, store};

    #[test]
    fn stores_and_replays_a_private_checksummed_report() {
        let base = std::env::temp_dir().join(format!("xref-result-cache-{}", std::process::id()));
        let path = base.join("results").join("key");
        store(&path, b"report body\n");
        assert_eq!(load(&path).as_deref(), Some(&b"report body\n"[..]));

        // A corrupted entry is rejected instead of replayed.
        let mut bytes = std::fs::read(&path).unwrap_or_default();
        if let Some(byte) = bytes.get_mut(10) {
            *byte ^= 0xff;
        }
        let _ = std::fs::write(&path, &bytes);
        assert_eq!(load(&path), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn time_budget_reports_are_not_cached() {
        assert!(cacheable(b"layout 0: ...\n"));
        assert!(!cacheable(b"warning: cooperative_30_second_analysis_budget_exhausted\n"));
    }
}

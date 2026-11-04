/*
 * XRef — bounded snapshots of mapped module identities
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::live::types::RegionEntry;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

const MAX_MODULE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MODULES: usize = 128;

fn target_path(pid: u32, path: &str) -> Option<PathBuf> {
    if !path.starts_with('/') || path.ends_with(" (deleted)") {
        return None;
    }
    let relative = Path::new(path).strip_prefix("/").ok()?;
    if relative.components().any(|component| !matches!(component, Component::Normal(_))) {
        return None;
    }
    Some(PathBuf::from(format!("/proc/{pid}/root")).join(relative))
}

const fn device(dev: u64) -> (u64, u64) {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff), (dev & 0xff) | ((dev >> 12) & !0xff))
}

/// Hashes are snapshots of backing files, not proof of in-memory text bytes.
pub(super) fn collect(
    pid: u32,
    regions: &[RegionEntry],
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<BTreeMap<(String, u64), String>, String> {
    if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
        return Err("profile cancelled".to_owned());
    }
    let mut hashes = BTreeMap::new();
    let mut total = 0_u64;
    for region in regions {
        if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
            return Err("profile cancelled".to_owned());
        }
        if hashes.len() >= MAX_MODULES
            || region.is_target_image
            || region.inode == 0
            || region.perms.as_bytes().get(2) != Some(&b'x')
        {
            continue;
        }
        let key = (region.dev.clone(), region.inode);
        if hashes.contains_key(&key) {
            continue;
        }
        let Some(path) = region.pathname.as_deref().and_then(|path| target_path(pid, path)) else { continue };
        let Ok(mut file) = File::open(path) else { continue };
        let Ok(before) = file.metadata() else { continue };
        let Some((major, minor)) = region
            .dev
            .split_once(':')
            .and_then(|(a, b)| Some((u64::from_str_radix(a, 16).ok()?, u64::from_str_radix(b, 16).ok()?)))
        else {
            continue;
        };
        if !before.is_file()
            || before.ino() != region.inode
            || device(before.dev()) != (major, minor)
            || before.len() > MAX_MODULE_BYTES
            || total.saturating_add(before.len()) > MAX_TOTAL_BYTES
        {
            continue;
        }
        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut read = 0_u64;
        loop {
            if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                return Err("profile cancelled".to_owned());
            }
            let Ok(size) = file.read(&mut buffer) else {
                read = u64::MAX;
                break;
            };
            if size == 0 {
                break;
            }
            read = read.saturating_add(u64::try_from(size).unwrap_or(u64::MAX));
            if read > before.len() {
                break;
            }
            digest.update(&buffer[..size]);
        }
        let Ok(after) = file.metadata() else { continue };
        if read != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            continue;
        }
        total = total.saturating_add(read);
        hashes.insert(key, crate::trace_analysis::index::hex_bytes(&digest.finalize()));
    }
    Ok(hashes)
}

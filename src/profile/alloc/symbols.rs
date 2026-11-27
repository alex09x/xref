/*
 * XRef — finding the allocator a live process calls: malloc, calloc, realloc and free
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use object::{Object, ObjectSegment, ObjectSymbol};
use serde::Serialize;
use std::io::Read;

const MAX_MODULE_BYTES: u64 = 256 * 1024 * 1024;

/// The allocator functions of one mapped file, by file offset (where a uprobe is placed).
#[derive(Clone, Debug, Serialize)]
pub struct Allocator {
    /// The file as the process maps it.
    pub path: String,
    /// The same file reached through the process's root (`/proc/PID/root/…`), checked to be the
    /// mapped device and inode: the path the uprobes are placed on.
    #[serde(skip)]
    pub probe_path: String,
    pub malloc: u64,
    pub free: u64,
    pub calloc: Option<u64>,
    pub realloc: Option<u64>,
}

/// The file offset of the exported function `name`, through the load segment holding it.
fn offset_of(file: &object::File<'_>, name: &str) -> Option<u64> {
    let symbol = file
        .dynamic_symbols()
        .find(|symbol| symbol.is_definition() && symbol.address() != 0 && symbol.name().ok() == Some(name))?;
    let address = symbol.address();
    file.segments().find_map(|segment| {
        let (offset, size) = segment.file_range();
        let start = segment.address();
        (address >= start && address < start.saturating_add(size)).then(|| offset + (address - start))
    })
}

/// The allocator in one file, when it exports at least `malloc` and `free`.
pub fn in_file(path: &str, data: &[u8]) -> Option<Allocator> {
    let file = object::File::parse(data).ok()?;
    Some(Allocator {
        path: path.to_owned(),
        probe_path: path.to_owned(),
        malloc: offset_of(&file, "malloc")?,
        free: offset_of(&file, "free")?,
        calloc: offset_of(&file, "calloc"),
        realloc: offset_of(&file, "realloc"),
    })
}

/// Search order for the allocator: the executable (a statically linked allocator), then other
/// libraries (an interposed jemalloc, mimalloc, tcmalloc), then the C library.
fn rank(path: &str, exe: &str) -> u8 {
    let name = std::path::Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or(path);
    if path == exe {
        0
    } else if name.starts_with("libc.so") || name.starts_with("libc-") || name.starts_with("ld-musl") {
        2
    } else {
        1
    }
}

/// The allocator the process calls: the first mapped file, in the search order, that exports
/// `malloc` and `free`.
/// `(major, minor)` of a `stat` device number.
const fn device(dev: u64) -> (u64, u64) {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff), (dev & 0xff) | ((dev >> 12) & !0xff))
}

pub fn find(session: &crate::live::procfs::LiveSession) -> Result<Allocator, String> {
    use std::os::unix::fs::MetadataExt;
    let exe = session.regions.iter().find(|region| region.is_target_image).and_then(|r| r.pathname.clone());
    // Mapped executable files with the device and inode the process maps.
    let mut files: Vec<(String, (u64, u64), u64)> = session
        .regions
        .iter()
        .filter(|region| region.perms.as_bytes().get(2) == Some(&b'x'))
        .filter_map(|region| {
            let path = region.pathname.clone()?;
            let (major, minor) = region.dev.split_once(':')?;
            let dev = (u64::from_str_radix(major, 16).ok()?, u64::from_str_radix(minor, 16).ok()?);
            Some((path, dev, region.inode))
        })
        .filter(|(path, _, _)| path.starts_with('/') && !path.ends_with(" (deleted)"))
        .collect();
    files.sort_by_key(|(path, _, _)| rank(path, exe.as_deref().unwrap_or("")));
    let mut seen = std::collections::BTreeSet::new();
    files.retain(|(path, _, _)| seen.insert(path.clone()));
    for (path, dev, inode) in files {
        // Through the process's root: the file it maps, even in another mount namespace.
        let probe_path = format!("/proc/{}/root{path}", session.process.pid);
        let Ok(file) = std::fs::File::open(&probe_path) else { continue };
        let Ok(metadata) = file.metadata() else { continue };
        if device(metadata.dev()) != dev || metadata.ino() != inode {
            continue;
        }
        let mut data = Vec::new();
        if file.take(MAX_MODULE_BYTES).read_to_end(&mut data).is_err() {
            continue;
        }
        if let Some(mut allocator) = in_file(&path, &data) {
            allocator.probe_path = probe_path;
            return Ok(allocator);
        }
    }
    Err("no_allocator: no mapped file exports malloc and free (a statically linked allocator without exported symbols, such as Rust's jemallocator, cannot be traced)".to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_executable_then_other_libraries_then_libc_are_searched() {
        let exe = "/srv/app";
        assert_eq!(super::rank("/srv/app", exe), 0);
        assert_eq!(super::rank("/usr/lib/libjemalloc.so.2", exe), 1);
        assert_eq!(super::rank("/usr/lib/x86_64-linux-gnu/libc.so.6", exe), 2);
    }
}

/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::{image::Image, listing, scan};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, ops::Range};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

const MAGIC: &[u8; 8] = b"XRFIDX01";
const MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct Identity {
    pub image_hex: String,
    image: [u8; 32],
    executable: Option<[u8; 32]>,
}

thread_local! {
    /// Digest supplied by the owner of an immutable image for the duration of one call
    /// ([`with_known_digest`]); keyed by the exact buffer so it cannot apply to other bytes.
    static KNOWN_DIGEST: std::cell::Cell<Option<(usize, usize, [u8; 32])>> = const { std::cell::Cell::new(None) };
}

/// Run `f` with `digest` declared as the SHA-256 of `image`. The caller owns `image` immutably and
/// computed the digest from it (e.g. the MCP `Analysis` at load), so searches skip rehashing it.
pub fn with_known_digest<T>(image: &[u8], digest: [u8; 32], f: impl FnOnce() -> T) -> T {
    struct Reset(Option<(usize, usize, [u8; 32])>);
    impl Drop for Reset {
        fn drop(&mut self) {
            KNOWN_DIGEST.with(|known| known.set(self.0));
        }
    }
    let _reset = Reset(KNOWN_DIGEST.with(|known| known.replace(Some((image.as_ptr() as usize, image.len(), digest)))));
    f()
}

/// Digest of the running executable, read once: it identifies the code that is actually running.
fn executable_digest() -> Option<[u8; 32]> {
    static EXECUTABLE: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
    *EXECUTABLE.get_or_init(|| {
        std::env::current_exe().ok().and_then(|path| fs::read(path).ok()).map(|bytes| Sha256::digest(bytes).into())
    })
}

impl Identity {
    pub const fn digest(&self) -> [u8; 32] {
        self.image
    }

    pub fn new(image: &[u8], cache_enabled: bool) -> Self {
        let declared = KNOWN_DIGEST
            .with(std::cell::Cell::get)
            .filter(|(address, length, _)| *address == image.as_ptr() as usize && *length == image.len())
            .map(|(_, _, digest)| digest);
        let image: [u8; 32] = declared.unwrap_or_else(|| Sha256::digest(image).into());
        let image_hex = crate::trace_analysis::index::hex_bytes(&image);
        let executable = if cache_enabled { executable_digest() } else { None };
        Self { image_hex, image, executable }
    }
}

#[derive(Clone)]
pub(super) struct ScanRecord {
    pub start: u64,
    pub references: Vec<u64>,
    pub calls: Vec<u64>,
    pub has_write: bool,
}

pub(super) fn scan_function(image: &Image, range: &Range<u64>) -> ScanRecord {
    let mut references = Vec::new();
    let mut targets = BTreeSet::new();
    let mut has_write = false;
    let mut factory = iced_x86::InstructionInfoFactory::new();
    if let Some(code) = image.code(range) {
        scan::decode(code, range.start, |instruction| {
            if !has_write
                && instruction.mnemonic() != iced_x86::Mnemonic::Lea
                && let Some(operand) =
                    (0..instruction.op_count()).find(|&index| instruction.op_kind(index) == iced_x86::OpKind::Memory)
            {
                has_write = super::step::writes(factory.info(instruction).op_access(operand));
            }
            if instruction.is_ip_rel_memory_operand() {
                references.push(instruction.ip_rel_memory_address());
            }
            references.extend(scan::immediates(instruction));
            if listing::is_call(instruction, range)
                && let Some(target) = super::static_target(image, instruction)
                && image.function_at(target).is_some_and(|function| function.start == target)
            {
                targets.insert(target);
            }
        });
    }
    references.sort_unstable();
    references.dedup();
    ScanRecord { start: range.start, references, calls: targets.into_iter().collect(), has_write }
}

fn cache_path(identity: &Identity, kind: &[u8], parameter: u64) -> Option<PathBuf> {
    let mut digest = Sha256::new();
    digest.update(MAGIC);
    digest.update(kind);
    digest.update(parameter.to_le_bytes());
    digest.update(identity.image);
    digest.update(identity.executable?);
    let key = crate::trace_analysis::index::hex_bytes(&digest.finalize());
    let root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    root.is_absolute().then(|| root.join("xref").join("field-index-v1").join(key))
}

pub(super) fn number(bytes: &[u8], cursor: &mut usize, width: usize) -> Option<u64> {
    let end = cursor.checked_add(width)?;
    let mut raw = [0_u8; 8];
    raw[..width].copy_from_slice(bytes.get(*cursor..end)?);
    *cursor = end;
    Some(u64::from_le_bytes(raw))
}

pub(super) fn load(identity: &Identity, functions: &[std::ops::Range<u64>]) -> Option<Vec<ScanRecord>> {
    let content = read_cache(identity, b"scan", 0)?;
    let mut cursor = 0;
    let count = usize::try_from(number(&content, &mut cursor, 4)?).ok()?;
    if count != functions.len() {
        return None;
    }
    let mut records = Vec::with_capacity(count);
    for function in functions {
        let start = number(&content, &mut cursor, 8)?;
        if start != function.start {
            return None;
        }
        let has_write = match number(&content, &mut cursor, 1)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let references = usize::try_from(number(&content, &mut cursor, 4)?).ok()?;
        let calls = usize::try_from(number(&content, &mut cursor, 4)?).ok()?;
        if references.checked_add(calls)?.checked_mul(8)? > content.len().checked_sub(cursor)? {
            return None;
        }
        let mut refs = Vec::with_capacity(references);
        for _ in 0..references {
            refs.push(number(&content, &mut cursor, 8)?);
        }
        let mut targets = Vec::with_capacity(calls);
        for _ in 0..calls {
            targets.push(number(&content, &mut cursor, 8)?);
        }
        records.push(ScanRecord { start, references: refs, calls: targets, has_write });
    }
    (cursor == content.len()).then_some(records)
}

pub(super) fn read_cache(identity: &Identity, kind: &[u8], parameter: u64) -> Option<Vec<u8>> {
    let path = cache_path(identity, kind, parameter)?;
    if !private_cache(&path) || fs::metadata(&path).ok()?.len() > MAX_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path).ok()?.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    let (content, checksum) = bytes.split_at_checked(bytes.len().checked_sub(32)?)?;
    if &Sha256::digest(content)[..] != checksum || content.get(..8)? != MAGIC {
        return None;
    }
    Some(content[8..].to_vec())
}

#[cfg(unix)]
fn private_cache(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Some(directory) = path.parent() else { return false };
    fs::symlink_metadata(directory)
        .is_ok_and(|metadata| metadata.file_type().is_dir() && metadata.permissions().mode().trailing_zeros() >= 6)
        && fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.permissions().mode().trailing_zeros() >= 6)
}

#[cfg(not(unix))]
fn private_cache(_path: &std::path::Path) -> bool {
    false
}

#[cfg(unix)]
pub(super) fn save(identity: &Identity, records: &[ScanRecord]) {
    let Ok(count) = u32::try_from(records.len()) else { return };
    let mut data = Vec::new();
    data.extend_from_slice(&count.to_le_bytes());
    for record in records {
        let (Ok(refs), Ok(calls)) = (u32::try_from(record.references.len()), u32::try_from(record.calls.len())) else {
            return;
        };
        data.extend_from_slice(&record.start.to_le_bytes());
        data.push(u8::from(record.has_write));
        data.extend_from_slice(&refs.to_le_bytes());
        data.extend_from_slice(&calls.to_le_bytes());
        for address in record.references.iter().chain(&record.calls) {
            data.extend_from_slice(&address.to_le_bytes());
        }
        if data.len() as u64 > MAX_BYTES - 40 {
            return;
        }
    }
    write_cache(identity, b"scan", 0, &data);
}

#[cfg(unix)]
pub(super) fn write_cache(identity: &Identity, kind: &[u8], parameter: u64, content: &[u8]) {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let Some(path) = cache_path(identity, kind, parameter) else { return };
    let Some(directory) = path.parent() else { return };
    if content.len() as u64 > MAX_BYTES - 40 {
        return;
    }
    if fs::DirBuilder::new().recursive(true).mode(0o700).create(directory).is_err() {
        return;
    }
    if !fs::symlink_metadata(directory)
        .is_ok_and(|metadata| metadata.file_type().is_dir() && metadata.permissions().mode().trailing_zeros() >= 6)
    {
        return;
    }
    let mut data = Vec::with_capacity(8 + content.len() + 32);
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(content);
    data.extend_from_slice(&Sha256::digest(&data));
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
    let temporary = directory.join(format!(".{}.{nonce}", std::process::id()));
    let Ok(mut file) = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary) else { return };
    if file.write_all(&data).is_ok() {
        let _ = fs::rename(&temporary, &path);
    }
    let _ = fs::remove_file(temporary);
}

#[cfg(not(unix))]
pub(super) fn save(_identity: &Identity, _records: &[ScanRecord]) {}

#[cfg(not(unix))]
pub(super) fn write_cache(_identity: &Identity, _kind: &[u8], _parameter: u64, _content: &[u8]) {}

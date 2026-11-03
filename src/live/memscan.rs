/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Safe chunked `ReadAt` memory scanner with overlap deduplication, `EIO`/`EFAULT` page recovery,
//! cooperative elapsed-time budgets, and aligned 8-byte context window extraction.

use std::collections::BTreeSet;
use std::io;
use std::time::{Duration, Instant};

use crate::image::{Image, occurrence_iter};
use crate::live::classify::{WordMeta, classify_word, find_load_segment};
use crate::live::cli::{validate_align, validate_context_words};
use crate::live::types::{ContextWord, HexAddr, MemHit, RegionEntry, ScanStatus, StopReason, remove_slide};

pub const CHUNK_BYTES: usize = 256 * 1024;
pub const PAGE_ADVANCE_BYTES: u64 = 4096;

pub trait ReadAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;
}

#[cfg(unix)]
impl ReadAt for std::fs::File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(self, buf, offset)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ScanConfig {
    pub align: usize,
    pub before_words: usize,
    pub after_words: usize,
    pub max_hits: usize,
    pub max_bytes: u64,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ScanOutcome {
    pub elapsed_ms: u64,
    pub regions_scanned: usize,
    pub regions_skipped: usize,
    pub bytes_scanned: u64,
    pub unreadable_ranges: usize,
    pub stop_reason: StopReason,
    pub hits: Vec<MemHit>,
}

struct HitEnv<'a> {
    reader: &'a dyn ReadAt,
    image: &'a Image,
    pie_slide: i64,
    regions: &'a [RegionEntry],
    needle: &'a [u8],
    align_u64: u64,
    overlap_u64: u64,
    chunk_cap_u64: u64,
    cfg: &'a ScanConfig,
}

struct ScanState {
    started: Instant,
    buf: Vec<u8>,
    seen_hits: BTreeSet<u64>,
    hits: Vec<MemHit>,
    regions_scanned: usize,
    bytes_scanned: u64,
    unreadable_ranges: usize,
    stop_reason: StopReason,
}

pub fn scan_memory(
    reader: &dyn ReadAt,
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    needle: &[u8],
    cfg: &ScanConfig,
) -> Result<ScanOutcome, String> {
    validate_align(cfg.align)?;
    validate_context_words(cfg.before_words, "--before-words")?;
    validate_context_words(cfg.after_words, "--after-words")?;
    if needle.is_empty() {
        return Err("memscan needle must not be empty".to_owned());
    }

    let align_u64 = u64::try_from(cfg.align).map_err(|_| "alignment overflow".to_owned())?;
    let overlap_u64 =
        u64::try_from(needle.len().saturating_sub(cfg.align)).map_err(|_| "overlap overflow".to_owned())?;
    let chunk_cap = CHUNK_BYTES.max(needle.len().saturating_mul(2));
    let chunk_cap_u64 = u64::try_from(chunk_cap).map_err(|_| "chunk capacity overflow".to_owned())?;

    let regions_skipped = regions.iter().filter(|r| r.scan_status != ScanStatus::ScannableRwp).count();
    let env = HitEnv { reader, image, pie_slide, regions, needle, align_u64, overlap_u64, chunk_cap_u64, cfg };
    let mut st = ScanState {
        started: Instant::now(),
        buf: vec![0_u8; chunk_cap],
        seen_hits: BTreeSet::new(),
        hits: Vec::new(),
        regions_scanned: 0,
        bytes_scanned: 0,
        unreadable_ranges: 0,
        stop_reason: StopReason::Complete,
    };

    for region in regions.iter().filter(|r| r.scan_status == ScanStatus::ScannableRwp && r.end.0 > r.start.0) {
        if check_budget(&env, &mut st) || !scan_one_region(&env, region, &mut st)? {
            break;
        }
    }

    let elapsed_ms = u64::try_from(st.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(ScanOutcome {
        elapsed_ms,
        regions_scanned: st.regions_scanned,
        regions_skipped,
        bytes_scanned: st.bytes_scanned,
        unreadable_ranges: st.unreadable_ranges,
        stop_reason: st.stop_reason,
        hits: st.hits,
    })
}

fn check_budget(env: &HitEnv<'_>, st: &mut ScanState) -> bool {
    if st.started.elapsed() >= env.cfg.timeout {
        st.stop_reason = StopReason::Timeout;
        return true;
    }
    if st.hits.len() >= env.cfg.max_hits {
        st.stop_reason = StopReason::MaxHits;
        return true;
    }
    if st.bytes_scanned >= env.cfg.max_bytes {
        st.stop_reason = StopReason::MaxBytes;
        return true;
    }
    false
}

fn next_page_after(addr: u64, limit: u64) -> u64 {
    let next = (addr / PAGE_ADVANCE_BYTES).saturating_add(1).saturating_mul(PAGE_ADVANCE_BYTES);
    next.max(addr.saturating_add(1)).min(limit)
}

fn read_chunk_with_page_fallback(reader: &dyn ReadAt, buf: &mut [u8], cursor: u64) -> io::Result<usize> {
    match reader.read_at(buf, cursor) {
        Err(err)
            if is_recoverable_read_error(&err) && u64::try_from(buf.len()).is_ok_and(|l| l > PAGE_ADVANCE_BYTES) =>
        {
            let page_rem = PAGE_ADVANCE_BYTES - (cursor % PAGE_ADVANCE_BYTES);
            let retry_len = usize::try_from(page_rem).unwrap_or(buf.len()).min(buf.len());
            reader.read_at(&mut buf[..retry_len], cursor)
        }
        other => other,
    }
}

fn scan_one_region(env: &HitEnv<'_>, region: &RegionEntry, st: &mut ScanState) -> Result<bool, String> {
    st.regions_scanned += 1;
    let reg_start = region.start.0;
    let reg_end = region.end.0;
    let mut cursor = reg_start;
    let mut scanned_up_to = reg_start;
    let mut no_overlap_before = reg_start;

    while cursor < reg_end {
        if check_budget(env, st) {
            return Ok(false);
        }
        let prefix_already = scanned_up_to.saturating_sub(cursor);
        let max_window = prefix_already.saturating_add(env.cfg.max_bytes - st.bytes_scanned);
        let want_u64 = (reg_end - cursor).min(env.chunk_cap_u64).min(max_window);
        let want = usize::try_from(want_u64).map_err(|_| "chunk read length overflow".to_owned())?;
        if want == 0 {
            break;
        }

        match read_chunk_with_page_fallback(env.reader, &mut st.buf[..want], cursor) {
            Ok(0) => {
                st.unreadable_ranges += 1;
                cursor = next_page_after(cursor.max(scanned_up_to), reg_end);
                scanned_up_to = scanned_up_to.max(cursor);
                no_overlap_before = cursor;
            }
            Err(err) if is_recoverable_read_error(&err) => {
                st.unreadable_ranges += 1;
                cursor = next_page_after(cursor.max(scanned_up_to), reg_end);
                scanned_up_to = scanned_up_to.max(cursor);
                no_overlap_before = cursor;
            }
            Err(err) => return Err(format!("procfs mem read failed at {cursor:#x}: {err}")),
            Ok(n) => {
                let n_u64 = u64::try_from(n).map_err(|_| "read count overflow".to_owned())?;
                let read_end = cursor.saturating_add(n_u64).min(reg_end);
                let new_bytes = read_end.saturating_sub(scanned_up_to);
                if new_bytes == 0 && n < want {
                    cursor = scanned_up_to;
                    no_overlap_before = cursor;
                    continue;
                }
                for rel in occurrence_iter(&st.buf[..n], env.needle) {
                    let Ok(rel_u64) = u64::try_from(rel) else { continue };
                    let hit_va = cursor + rel_u64;
                    if !hit_va.is_multiple_of(env.align_u64) || !st.seen_hits.insert(hit_va) {
                        continue;
                    }
                    st.hits.push(build_mem_hit(env, region, hit_va));
                    if st.hits.len() >= env.cfg.max_hits {
                        st.bytes_scanned = st.bytes_scanned.saturating_add(new_bytes);
                        st.stop_reason = StopReason::MaxHits;
                        return Ok(false);
                    }
                }
                st.bytes_scanned = st.bytes_scanned.saturating_add(new_bytes);
                scanned_up_to = scanned_up_to.max(read_end);
                if read_end >= reg_end {
                    break;
                }
                cursor = read_end.saturating_sub(env.overlap_u64).max(no_overlap_before).max(cursor + 1);
            }
        }
    }
    Ok(true)
}

fn is_recoverable_read_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(5 | 14)) || err.kind() == io::ErrorKind::Other
}

fn build_mem_hit(env: &HitEnv<'_>, region: &RegionEntry, hit_va: u64) -> MemHit {
    let static_va = remove_slide(hit_va, env.pie_slide)
        .filter(|&s| region.is_target_image && find_load_segment(&env.image.metadata.load_segments, s).is_some())
        .map(HexAddr);
    let (context, window_truncated) = read_context_window(env, region, hit_va);
    MemHit { runtime_va: HexAddr(hit_va), static_va, region: region.format_location(hit_va), window_truncated, context }
}

fn read_context_window(env: &HitEnv<'_>, region: &RegionEntry, hit_va: u64) -> (Vec<ContextWord>, bool) {
    let before_cap = u64::try_from(env.cfg.before_words).unwrap_or(0);
    let after_cap = u64::try_from(env.cfg.after_words).unwrap_or(0);
    let matched_words = u64::try_from(env.needle.len().div_ceil(8)).unwrap_or(1);
    let requested_post = matched_words.saturating_add(after_cap);

    let actual_before = ((hit_va - region.start.0) / 8).min(before_cap);
    let actual_post = ((region.end.0 - hit_va) / 8).min(requested_post);
    let mut window_truncated = actual_before < before_cap || actual_post < requested_post;

    let total_words = actual_before.saturating_add(actual_post);
    let win_start = hit_va - actual_before * 8;
    let Ok(total_usize) = usize::try_from(total_words) else {
        return (Vec::new(), true);
    };
    let win_bytes_len = total_usize.saturating_mul(8);

    let mut raw = vec![0_u8; win_bytes_len];
    let fast_ok = matches!(env.reader.read_at(&mut raw, win_start), Ok(n) if n == win_bytes_len);

    let mut words = Vec::with_capacity(total_usize);
    for idx in 0..total_usize {
        let idx_u64 = u64::try_from(idx).unwrap_or(0);
        let word_va = win_start + idx_u64 * 8;
        let rel_words = i128::from(idx_u64) - i128::from(actual_before);
        let Ok(relative_offset) = i64::try_from(rel_words.saturating_mul(8)) else { continue };
        let is_match = idx_u64.checked_sub(actual_before).is_some_and(|w| w < matched_words);

        let word_bytes: Option<[u8; 8]> = if fast_ok {
            raw.get(idx * 8..idx * 8 + 8).and_then(|s| s.try_into().ok())
        } else {
            let mut single = [0_u8; 8];
            match env.reader.read_at(&mut single, word_va) {
                Ok(8) => Some(single),
                _ => None,
            }
        };
        if let Some(bytes) = word_bytes {
            let meta = WordMeta { runtime_va: word_va, relative_offset, is_match, value: u64::from_le_bytes(bytes) };
            words.push(classify_word(env.image, env.pie_slide, env.regions, &meta));
        } else {
            window_truncated = true;
            words.push(ContextWord::unreadable(word_va, relative_offset, is_match));
        }
    }
    (words, window_truncated)
}

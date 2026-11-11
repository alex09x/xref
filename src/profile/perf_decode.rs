/*
 * XRef — Linux perf sampling record decoding
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::{Branch, Mapping, Sample};

pub const SAMPLE_IP: u64 = 1 << 0;
pub const SAMPLE_TID: u64 = 1 << 1;
pub const SAMPLE_TIME: u64 = 1 << 2;
pub const SAMPLE_CALLCHAIN: u64 = 1 << 5;
pub const SAMPLE_PERIOD: u64 = 1 << 8;
pub const SAMPLE_RAW: u64 = 1 << 10;
pub const SAMPLE_BRANCH_STACK: u64 = 1 << 11;
pub const SAMPLE_REGS_USER: u64 = 1 << 12;
pub const SAMPLE_STACK_USER: u64 = 1 << 13;
pub const SUPPORTED: u64 = SAMPLE_IP
    | SAMPLE_TID
    | SAMPLE_TIME
    | SAMPLE_CALLCHAIN
    | SAMPLE_PERIOD
    | SAMPLE_BRANCH_STACK
    | SAMPLE_REGS_USER
    | SAMPLE_STACK_USER;
const MAX_FRAMES: usize = 512;
const MAX_STACK: usize = 64 * 1024;

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(length).ok_or("perf sample length overflow")?;
        let bytes = self.bytes.get(self.offset..end).ok_or("truncated perf sample")?;
        self.offset = end;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| "invalid u32")?))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| "invalid u64")?))
    }
    fn length(&mut self, cap: usize) -> Result<usize, String> {
        let value = usize::try_from(self.u64()?).map_err(|_| "perf sample length overflow")?;
        if value > cap {
            return Err("perf sample field exceeds limit".to_owned());
        }
        Ok(value)
    }
}

/// Decode the exact subset requested by the profiler. Other perf sample fields
/// are rejected so their presence cannot silently shift subsequent data.
pub fn decode_sample(bytes: &[u8], sample_type: u64, register_mask: u64) -> Result<Sample, String> {
    if sample_type & !SUPPORTED != 0 {
        return Err("unsupported perf sample fields".to_owned());
    }
    decode_sample_raw(bytes, sample_type, register_mask).map(|(sample, _)| sample)
}

/// [`decode_sample`] that also accepts `PERF_SAMPLE_RAW` (a tracepoint's fields) and returns it.
pub fn decode_sample_raw(bytes: &[u8], sample_type: u64, register_mask: u64) -> Result<(Sample, Vec<u8>), String> {
    if sample_type & !(SUPPORTED | SAMPLE_RAW) != 0 {
        return Err("unsupported perf sample fields".to_owned());
    }
    let mut cursor = Cursor { bytes, offset: 0 };
    let ip = if sample_type & SAMPLE_IP != 0 { cursor.u64()? } else { 0 };
    let (pid, tid) = if sample_type & SAMPLE_TID != 0 { (cursor.u32()?, cursor.u32()?) } else { (0, 0) };
    let timestamp_ns = if sample_type & SAMPLE_TIME != 0 { cursor.u64()? } else { 0 };
    let period = if sample_type & SAMPLE_PERIOD != 0 { cursor.u64()? } else { 0 };
    let mut callchain = Vec::new();
    if sample_type & SAMPLE_CALLCHAIN != 0 {
        let count = cursor.length(MAX_FRAMES)?;
        callchain.reserve(count);
        for _ in 0..count {
            callchain.push(cursor.u64()?);
        }
    }
    let mut raw = Vec::new();
    if sample_type & SAMPLE_RAW != 0 {
        let size = usize::try_from(cursor.u32()?).map_err(|_| "perf raw size overflow")?;
        raw.extend_from_slice(cursor.take(size)?);
    }
    let mut branches = Vec::new();
    if sample_type & SAMPLE_BRANCH_STACK != 0 {
        let count = cursor.length(MAX_FRAMES)?;
        branches.reserve(count);
        for _ in 0..count {
            branches.push(Branch { from: cursor.u64()?, to: cursor.u64()?, flags: cursor.u64()? });
        }
    }
    let mut registers = Vec::new();
    let mut actual_mask = 0;
    if sample_type & SAMPLE_REGS_USER != 0 {
        match cursor.u64()? {
            0 => {}
            2 => {
                actual_mask = register_mask;
                for _ in 0..register_mask.count_ones() {
                    registers.push(cursor.u64()?);
                }
            }
            _ => return Err("unsupported perf register ABI".to_owned()),
        }
    }
    let mut user_stack = Vec::new();
    if sample_type & SAMPLE_STACK_USER != 0 {
        let length = cursor.length(MAX_STACK)?;
        if length > 0 {
            let raw = cursor.take(length)?;
            let valid = usize::try_from(cursor.u64()?).map_err(|_| "perf stack size overflow")?;
            if valid > length {
                return Err("perf stack dynamic size exceeds capture".to_owned());
            }
            user_stack.extend_from_slice(&raw[..valid]);
        }
    }
    if cursor.offset != bytes.len() {
        return Err("unexpected trailing perf sample bytes".to_owned());
    }
    Ok((
        Sample {
            timestamp_ns,
            pid,
            tid,
            cpu_mode: 0,
            ip,
            period,
            registers_mask: actual_mask,
            registers,
            user_stack,
            callchain,
            branches,
        },
        raw,
    ))
}

/// Decode `PERF_RECORD_MMAP2` with the ordinary device/inode union. When
/// `sample_id_all` is enabled, the requested TID and TIME fields are the suffix.
pub fn decode_mmap2(bytes: &[u8], misc: u16, sample_id_all: bool) -> Result<Mapping, String> {
    if misc & (1 << 14) != 0 {
        return Err("MMAP2 build-id union is unsupported".to_owned());
    }
    let trailer = if sample_id_all { 16 } else { 0 };
    let body_end = bytes.len().checked_sub(trailer).ok_or("truncated MMAP2 sample ID")?;
    let mut cursor = Cursor { bytes: &bytes[..body_end], offset: 0 };
    let pid = cursor.u32()?;
    let tid = cursor.u32()?;
    let start = cursor.u64()?;
    let length = cursor.u64()?;
    let file_offset = cursor.u64()?;
    let device_major = cursor.u32()?;
    let device_minor = cursor.u32()?;
    let inode = cursor.u64()?;
    let _inode_generation = cursor.u64()?;
    let protection = cursor.u32()?;
    let _flags = cursor.u32()?;
    if length == 0 || start.checked_add(length).is_none() {
        return Err("invalid MMAP2 range".to_owned());
    }
    let name = cursor.bytes.get(cursor.offset..).ok_or("truncated MMAP2 name")?;
    let end = name.iter().position(|byte| *byte == 0).ok_or("unterminated MMAP2 name")?;
    if end > 4096 {
        return Err("MMAP2 name exceeds limit".to_owned());
    }
    let path = std::str::from_utf8(&name[..end]).map_err(|_| "MMAP2 name is not UTF-8")?.to_owned();
    let timestamp_ns = if sample_id_all {
        let mut sample_id = Cursor { bytes: &bytes[body_end..], offset: 0 };
        let _sample_pid = sample_id.u32()?;
        let _sample_tid = sample_id.u32()?;
        sample_id.u64()?
    } else {
        0
    };
    Ok(Mapping {
        timestamp_ns,
        pid,
        tid,
        start,
        length,
        file_offset,
        device_major,
        device_minor,
        inode,
        executable: protection & 4 != 0,
        sha256: None,
        path,
    })
}

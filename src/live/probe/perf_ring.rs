/*
 * XRef — Safe binary perf_event_open ring-buffer reader and PERF_RECORD_* decoder
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Pure safe binary decoder for Linux `<linux/perf_event.h>` ring buffers (`PERF_RECORD_SAMPLE`,
//! `PERF_RECORD_LOST`, `PERF_RECORD_FORK`, `PERF_RECORD_EXIT`), circular wrap-around reassembly,
//! x86-64 `PERF_SAMPLE_REGS_USER` bitmasks, and CFI-verified `PERF_SAMPLE_STACK_USER` return slots.

use crate::live::probe::types::UnwindEntryStatus;

pub const PERF_RECORD_LOST: u32 = 2;
pub const PERF_RECORD_EXIT: u32 = 4;
pub const PERF_RECORD_FORK: u32 = 7;
pub const PERF_RECORD_SAMPLE: u32 = 9;

pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub const PERF_SAMPLE_REGS_USER: u64 = 1 << 12;
pub const PERF_SAMPLE_STACK_USER: u64 = 1 << 13;

pub const PERF_SAMPLE_REGS_ABI_NONE: u64 = 0;
pub const PERF_SAMPLE_REGS_ABI_64: u64 = 2;

pub const PERF_REG_X86_AX: u32 = 0;
pub const PERF_REG_X86_CX: u32 = 2;
pub const PERF_REG_X86_DX: u32 = 3;
pub const PERF_REG_X86_SI: u32 = 4;
pub const PERF_REG_X86_DI: u32 = 5;
pub const PERF_REG_X86_BP: u32 = 6;
pub const PERF_REG_X86_SP: u32 = 7;
pub const PERF_REG_X86_R8: u32 = 16;
pub const PERF_REG_X86_R9: u32 = 17;

pub const XREF_PERF_REGS_MASK: u64 = (1_u64 << PERF_REG_X86_AX)
    | (1_u64 << PERF_REG_X86_CX)
    | (1_u64 << PERF_REG_X86_DX)
    | (1_u64 << PERF_REG_X86_SI)
    | (1_u64 << PERF_REG_X86_DI)
    | (1_u64 << PERF_REG_X86_BP)
    | (1_u64 << PERF_REG_X86_SP)
    | (1_u64 << PERF_REG_X86_R8)
    | (1_u64 << PERF_REG_X86_R9);

#[cfg(target_os = "linux")]
pub const XREF_PERF_STACK_USER_BYTES: u32 = 128;
#[cfg(test)]
const PERF_EVENT_HEADER_SIZE: usize = 8;

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerfRawRecord {
    pub rec_type: u32,
    pub misc: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfRegsSample {
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub r8: u64,
    pub r9: u64,
    pub rax: u64,
    pub rsp: u64,
    pub rbp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerfSampleEvent {
    pub ip: Option<u64>,
    pub tgid: Option<u32>,
    pub thread_id: Option<u32>,
    pub timestamp_ns: Option<u64>,
    pub regs: Option<PerfRegsSample>,
    pub user_stack: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedPerfRecord {
    Sample(PerfSampleEvent),
    Lost { event_id: u64, lost: u64 },
    Fork { tgid: u32, parent_tgid: u32, thread_id: u32, parent_tid: u32, timestamp_ns: u64 },
    Exit { tgid: u32, thread_id: u32, timestamp_ns: u64 },
    Other { rec_type: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PerfDecodeError {
    #[cfg(test)]
    InvalidRingSize,
    #[cfg(test)]
    HeadBeforeTail,
    #[cfg(test)]
    UnreadExceedsRing {
        unread: u64,
        capacity: usize,
    },
    #[cfg(test)]
    InvalidRecordSize {
        size: u16,
    },
    TruncatedRecord {
        needed: usize,
        available: usize,
    },
    UnexpectedRegsAbi {
        abi: u64,
    },
}

/// Drains circular ring-buffer bytes from `data_tail..data_head`, handling wrap-around across
/// `ring.len()` for both the 8-byte `perf_event_header` and variable-length record payloads.
#[cfg(test)]
pub fn drain_raw_ring_bytes(
    ring: &[u8],
    data_tail: u64,
    data_head: u64,
) -> Result<(Vec<PerfRawRecord>, u64), PerfDecodeError> {
    if ring.is_empty() || !ring.len().is_power_of_two() {
        return Err(PerfDecodeError::InvalidRingSize);
    }
    if data_head < data_tail {
        return Err(PerfDecodeError::HeadBeforeTail);
    }
    let unread = data_head - data_tail;
    let cap_u64 = u64::try_from(ring.len()).unwrap_or(u64::MAX);
    if unread > cap_u64 {
        return Err(PerfDecodeError::UnreadExceedsRing { unread, capacity: ring.len() });
    }

    let mask = ring.len() - 1;
    let mut cursor = data_tail;
    let mut out = Vec::new();

    while cursor < data_head {
        let remaining = usize::try_from(data_head - cursor).unwrap_or(usize::MAX);
        if remaining < PERF_EVENT_HEADER_SIZE {
            return Err(PerfDecodeError::TruncatedRecord { needed: PERF_EVENT_HEADER_SIZE, available: remaining });
        }
        let mut hdr = [0_u8; PERF_EVENT_HEADER_SIZE];
        copy_circular(ring, mask, cursor, &mut hdr);
        let rec_type = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let misc = u16::from_le_bytes([hdr[4], hdr[5]]);
        let total_size = u16::from_le_bytes([hdr[6], hdr[7]]);
        let record_len = usize::from(total_size);
        if record_len < PERF_EVENT_HEADER_SIZE || !record_len.is_multiple_of(8) {
            return Err(PerfDecodeError::InvalidRecordSize { size: total_size });
        }
        if record_len > remaining {
            return Err(PerfDecodeError::TruncatedRecord { needed: record_len, available: remaining });
        }
        let payload_len = record_len - PERF_EVENT_HEADER_SIZE;
        let mut payload = vec![0_u8; payload_len];
        copy_circular(ring, mask, cursor + 8, &mut payload);
        out.push(PerfRawRecord { rec_type, misc, payload });
        cursor += u64::from(total_size);
    }

    Ok((out, cursor))
}

#[cfg(test)]
fn copy_circular(ring: &[u8], mask: usize, start_pos: u64, dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    let start_idx = usize::try_from(start_pos & (mask as u64)).unwrap_or(0);
    let first_len = dst.len().min(ring.len() - start_idx);
    dst[..first_len].copy_from_slice(&ring[start_idx..start_idx + first_len]);
    if first_len < dst.len() {
        let rest = dst.len() - first_len;
        dst[first_len..].copy_from_slice(&ring[..rest]);
    }
}

pub fn decode_perf_record(
    rec_type: u32,
    _misc: u16,
    payload: &[u8],
    sample_type: u64,
    regs_mask: u64,
) -> Result<DecodedPerfRecord, PerfDecodeError> {
    let mut rd = ByteCursor { bytes: payload, pos: 0 };
    match rec_type {
        PERF_RECORD_LOST => {
            let event_id = rd.read_u64()?;
            let lost = rd.read_u64()?;
            Ok(DecodedPerfRecord::Lost { event_id, lost })
        }
        PERF_RECORD_FORK => {
            let tgid = rd.read_u32()?;
            let spawner_tgid = rd.read_u32()?;
            let thread_id = rd.read_u32()?;
            let spawner_thread = rd.read_u32()?;
            let timestamp_ns = rd.read_u64()?;
            Ok(DecodedPerfRecord::Fork {
                tgid,
                parent_tgid: spawner_tgid,
                thread_id,
                parent_tid: spawner_thread,
                timestamp_ns,
            })
        }
        PERF_RECORD_EXIT => {
            let tgid = rd.read_u32()?;
            let _spawner_tgid = rd.read_u32()?;
            let thread_id = rd.read_u32()?;
            let _spawner_thread = rd.read_u32()?;
            let timestamp_ns = rd.read_u64()?;
            Ok(DecodedPerfRecord::Exit { tgid, thread_id, timestamp_ns })
        }
        PERF_RECORD_SAMPLE => decode_sample_payload(&mut rd, sample_type, regs_mask).map(DecodedPerfRecord::Sample),
        other => Ok(DecodedPerfRecord::Other { rec_type: other }),
    }
}

fn decode_sample_payload(
    rd: &mut ByteCursor<'_>,
    sample_type: u64,
    regs_mask: u64,
) -> Result<PerfSampleEvent, PerfDecodeError> {
    let ip = if sample_type & PERF_SAMPLE_IP != 0 { Some(rd.read_u64()?) } else { None };
    let (tgid, thread_id) = if sample_type & PERF_SAMPLE_TID != 0 {
        let group = rd.read_u32()?;
        let thr = rd.read_u32()?;
        (Some(group), Some(thr))
    } else {
        (None, None)
    };
    let timestamp_ns = if sample_type & PERF_SAMPLE_TIME != 0 { Some(rd.read_u64()?) } else { None };

    let regs = if sample_type & PERF_SAMPLE_REGS_USER != 0 {
        let abi = rd.read_u64()?;
        if abi == PERF_SAMPLE_REGS_ABI_NONE {
            None
        } else if abi == PERF_SAMPLE_REGS_ABI_64 {
            let count = regs_mask.count_ones() as usize;
            let mut words = Vec::with_capacity(count);
            for _ in 0..count {
                words.push(rd.read_u64()?);
            }
            extract_x86_64_regs(&words, regs_mask)
        } else {
            return Err(PerfDecodeError::UnexpectedRegsAbi { abi });
        }
    } else {
        None
    };

    let user_stack = if sample_type & PERF_SAMPLE_STACK_USER != 0 {
        let raw_len = rd.read_u64()?;
        let alloc_len = usize::try_from(raw_len)
            .map_err(|_| PerfDecodeError::TruncatedRecord { needed: usize::MAX, available: rd.remaining() })?;
        if alloc_len == 0 {
            Vec::new()
        } else {
            let raw_stack = rd.read_slice(alloc_len)?;
            let dyn_size = usize::try_from(rd.read_u64()?).unwrap_or(alloc_len);
            raw_stack[..dyn_size.min(alloc_len)].to_vec()
        }
    } else {
        Vec::new()
    };

    Ok(PerfSampleEvent { ip, tgid, thread_id, timestamp_ns, regs, user_stack })
}

fn extract_x86_64_regs(words: &[u64], mask: u64) -> Option<PerfRegsSample> {
    Some(PerfRegsSample {
        rdi: reg_from_mask(words, mask, PERF_REG_X86_DI)?,
        rsi: reg_from_mask(words, mask, PERF_REG_X86_SI)?,
        rdx: reg_from_mask(words, mask, PERF_REG_X86_DX)?,
        rcx: reg_from_mask(words, mask, PERF_REG_X86_CX)?,
        r8: reg_from_mask(words, mask, PERF_REG_X86_R8)?,
        r9: reg_from_mask(words, mask, PERF_REG_X86_R9)?,
        rax: reg_from_mask(words, mask, PERF_REG_X86_AX)?,
        rsp: reg_from_mask(words, mask, PERF_REG_X86_SP)?,
        rbp: reg_from_mask(words, mask, PERF_REG_X86_BP)?,
    })
}

#[must_use]
pub fn reg_from_mask(words: &[u64], mask: u64, reg_bit: u32) -> Option<u64> {
    let bit = 1_u64.checked_shl(reg_bit)?;
    if mask & bit == 0 {
        return None;
    }
    let idx = (mask & (bit - 1)).count_ones() as usize;
    words.get(idx).copied()
}

/// Extracts the 8-byte return address from `PERF_SAMPLE_STACK_USER` ONLY when `.eh_frame` CFI
/// proves the exact stack slot relative to `RSP` or `RBP`.
#[must_use]
pub fn extract_return_addr_from_perf_sample(
    unwind: &UnwindEntryStatus,
    regs: Option<&PerfRegsSample>,
    user_stack: &[u8],
) -> Option<u64> {
    let rsp_offset_bytes: usize = match unwind {
        UnwindEntryStatus::StandardRsp8RaMinus8 => 0,
        UnwindEntryStatus::InteriorFrameOffset { base_register: "rsp", disp } => usize::try_from(*disp).ok()?,
        UnwindEntryStatus::InteriorFrameOffset { base_register: "rbp", disp } => {
            let r = regs?;
            let rel = i128::from(r.rbp) - i128::from(r.rsp) + i128::from(*disp);
            usize::try_from(rel).ok()?
        }
        UnwindEntryStatus::InteriorFrameOffset { .. } | UnwindEntryStatus::Unavailable { .. } => return None,
    };
    let end = rsp_offset_bytes.checked_add(8)?;
    let slot: [u8; 8] = user_stack.get(rsp_offset_bytes..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(slot))
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], PerfDecodeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| PerfDecodeError::TruncatedRecord { needed: usize::MAX, available: self.remaining() })?;
        let Some(slice) = self.bytes.get(self.pos..end) else {
            return Err(PerfDecodeError::TruncatedRecord { needed: len, available: self.remaining() });
        };
        self.pos = end;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<u32, PerfDecodeError> {
        let s = self.read_slice(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, PerfDecodeError> {
        let s = self.read_slice(8)?;
        Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }
}

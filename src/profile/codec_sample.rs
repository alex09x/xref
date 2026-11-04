/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::codec::{Cursor, MAX_FRAMES, MAX_STACK, invalid, put_len, put_u16, put_u32, put_u64};
use super::types::Branch;
use super::types::Sample;
use std::io;

pub(super) fn encode_sample(out: &mut Vec<u8>, sample: &Sample) -> io::Result<()> {
    if sample.registers.len() != sample.registers_mask.count_ones() as usize
        || sample.user_stack.len() > MAX_STACK
        || sample.callchain.len() > MAX_FRAMES
        || sample.branches.len() > MAX_FRAMES
    {
        return Err(invalid("invalid or oversized profile sample"));
    }
    out.push(1);
    put_u64(out, sample.timestamp_ns);
    put_u32(out, sample.pid);
    put_u32(out, sample.tid);
    put_u16(out, sample.cpu_mode);
    put_u64(out, sample.ip);
    put_u64(out, sample.period);
    put_u64(out, sample.registers_mask);
    for length in [sample.registers.len(), sample.user_stack.len(), sample.callchain.len(), sample.branches.len()] {
        put_len(out, length)?;
    }
    for value in &sample.registers {
        put_u64(out, *value);
    }
    out.extend_from_slice(&sample.user_stack);
    for value in &sample.callchain {
        put_u64(out, *value);
    }
    for branch in &sample.branches {
        put_u64(out, branch.from);
        put_u64(out, branch.to);
        put_u64(out, branch.flags);
    }
    Ok(())
}

pub(super) fn decode_sample(cursor: &mut Cursor<'_>) -> io::Result<Sample> {
    let timestamp_ns = cursor.u64()?;
    let pid = cursor.u32()?;
    let tid = cursor.u32()?;
    let cpu_mode = cursor.u16()?;
    let ip = cursor.u64()?;
    let period = cursor.u64()?;
    let registers_mask = cursor.u64()?;
    let register_count = cursor.len(64)?;
    let stack_len = cursor.len(MAX_STACK)?;
    let frame_count = cursor.len(MAX_FRAMES)?;
    let branch_count = cursor.len(MAX_FRAMES)?;
    if register_count != registers_mask.count_ones() as usize {
        return Err(invalid("profile register mask mismatch"));
    }
    let mut registers = Vec::with_capacity(register_count);
    for _ in 0..register_count {
        registers.push(cursor.u64()?);
    }
    let user_stack = cursor.take(stack_len)?.to_vec();
    let mut callchain = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        callchain.push(cursor.u64()?);
    }
    let mut branches = Vec::with_capacity(branch_count);
    for _ in 0..branch_count {
        branches.push(Branch { from: cursor.u64()?, to: cursor.u64()?, flags: cursor.u64()? });
    }
    Ok(Sample {
        timestamp_ns,
        pid,
        tid,
        cpu_mode,
        ip,
        period,
        registers_mask,
        registers,
        user_stack,
        callchain,
        branches,
    })
}

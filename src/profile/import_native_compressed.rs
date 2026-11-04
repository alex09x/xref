/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use zstd_safe::{DCtx, DParameter, InBuffer, OutBuffer};

const MAX_ROUND: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: u64 = 131_072;

/// Preflight decompression with bounded windows, expansion and record queues.
/// The reader decodes the same stream only after this validation succeeds.
pub struct Validator {
    decoder: DCtx<'static>,
    pending: Vec<u8>,
    round_bytes: u64,
    records: u64,
}

impl Validator {
    pub fn new() -> Result<Self, &'static str> {
        let mut decoder = DCtx::create();
        decoder.set_parameter(DParameter::WindowLogMax(26)).map_err(|_| "cannot bound zstd window")?;
        Ok(Self { decoder, pending: Vec::new(), round_bytes: 0, records: 0 })
    }

    pub fn plain(&mut self, kind: u32, size: u64) -> Result<(), &'static str> {
        if !self.pending.is_empty() {
            return Err("compressed record interrupted by plain record");
        }
        self.record(kind, size)
    }

    fn record(&mut self, kind: u32, size: u64) -> Result<(), &'static str> {
        if matches!(kind, 71 | 81 | 83) {
            return Err("nested compressed or AUX trace record is unsupported");
        }
        if kind == 68 {
            if size != 8 {
                return Err("invalid perf finished-round record");
            }
            self.round_bytes = 0;
            self.records = 0;
        } else {
            self.round_bytes = self.round_bytes.checked_add(size).ok_or("perf round size overflow")?;
            self.records += 1;
            if self.round_bytes > MAX_ROUND || self.records > MAX_RECORDS {
                return Err("perf event round exceeds processing limits");
            }
        }
        Ok(())
    }

    pub fn compressed(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        let mut input = InBuffer::around(bytes);
        let mut block = vec![0_u8; 1024 * 1024];
        let mut expanded = 0_usize;
        loop {
            let before = input.pos();
            let mut out = OutBuffer::around(block.as_mut_slice());
            self.decoder.decompress_stream(&mut out, &mut input).map_err(|_| "invalid compressed perf stream")?;
            let size = out.pos();
            expanded = expanded.checked_add(size).ok_or("compressed perf size overflow")?;
            if expanded > 64 * 1024 * 1024 {
                return Err("compressed perf record expands beyond 64 MiB");
            }
            self.pending.extend_from_slice(&block[..size]);
            self.consume()?;
            if input.pos() == bytes.len() && size < block.len() {
                break;
            }
            if input.pos() == before && size == 0 {
                return Err("stalled compressed perf stream");
            }
        }
        Ok(())
    }

    fn consume(&mut self) -> Result<(), &'static str> {
        let mut offset = 0_usize;
        while self.pending.len().saturating_sub(offset) >= 8 {
            let header = &self.pending[offset..offset + 8];
            let kind = u32::from_le_bytes(header[..4].try_into().map_err(|_| "invalid event header")?);
            let size = usize::from(u16::from_le_bytes([header[6], header[7]]));
            if size < 8 {
                return Err("invalid compressed perf event size");
            }
            if size > self.pending.len() - offset {
                break;
            }
            self.record(kind, size as u64)?;
            offset += size;
        }
        self.pending.drain(..offset);
        Ok(())
    }

    pub const fn finish(&self) -> Result<(), &'static str> {
        if self.pending.is_empty() { Ok(()) } else { Err("truncated compressed perf event") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_split_records_and_rejects_bad_or_nested_records() -> Result<(), Box<dyn std::error::Error>> {
        let mut data = vec![0_u8; 16];
        data[..4].copy_from_slice(&9_u32.to_le_bytes());
        data[6..8].copy_from_slice(&16_u16.to_le_bytes());
        let mut compressed = vec![0_u8; zstd_safe::compress_bound(data.len())];
        let size = zstd_safe::compress(compressed.as_mut_slice(), &data, 1).map_err(|_| "compression failed")?;
        compressed.truncate(size);
        let mut validator = Validator::new()?;
        let half = compressed.len() / 2;
        validator.compressed(&compressed[..half])?;
        validator.compressed(&compressed[half..])?;
        validator.finish()?;
        let mut bad = Validator::new()?;
        assert!(bad.compressed(b"invalid zstd").is_err());
        let mut nested = Validator::new()?;
        assert!(nested.plain(71, 8).is_err());
        Ok(())
    }

    #[test]
    fn rejects_compressed_expansion_above_limit() -> Result<(), Box<dyn std::error::Error>> {
        let mut event = vec![0_u8; 32_768];
        event[..4].copy_from_slice(&9_u32.to_le_bytes());
        event[6..8].copy_from_slice(&32_768_u16.to_le_bytes());
        let data = event.repeat(2049);
        let mut compressed = vec![0_u8; zstd_safe::compress_bound(data.len())];
        let size = zstd_safe::compress(compressed.as_mut_slice(), &data, 1).map_err(|_| "compression failed")?;
        compressed.truncate(size);
        assert!(Validator::new()?.compressed(&compressed).is_err(), "excessive decompression must fail");
        Ok(())
    }
}

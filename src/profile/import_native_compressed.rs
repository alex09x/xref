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
    nested_aux: bool,
    intel_pt: bool,
}

impl Validator {
    pub fn new() -> Result<Self, &'static str> {
        let mut decoder = DCtx::create();
        decoder.set_parameter(DParameter::WindowLogMax(26)).map_err(|_| "cannot bound zstd window")?;
        Ok(Self { decoder, pending: Vec::new(), round_bytes: 0, records: 0, nested_aux: false, intel_pt: false })
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
            let total = if kind == 71 {
                self.nested_aux = true;
                if size < 48 {
                    return Err("invalid compressed AUXTRACE header");
                }
                if self.pending.len() - offset < 16 {
                    break;
                }
                let value = u64::from_le_bytes(
                    self.pending[offset + 8..offset + 16].try_into().map_err(|_| "invalid AUXTRACE size")?,
                );
                if value > MAX_ROUND {
                    return Err("compressed AUXTRACE exceeds limits");
                }
                let total = size
                    .checked_add(usize::try_from(value).map_err(|_| "AUXTRACE size overflow")?)
                    .ok_or("AUXTRACE size overflow")?;
                if u64::try_from(total).map_err(|_| "AUXTRACE size overflow")? > MAX_ROUND {
                    return Err("compressed AUXTRACE exceeds limits");
                }
                total
            } else {
                size
            };
            if total > self.pending.len() - offset {
                break;
            }
            if kind == 70 {
                if total < 16 {
                    return Err("invalid compressed AUXTRACE_INFO");
                }
                let aux_type = u32::from_le_bytes(
                    self.pending[offset + 8..offset + 12].try_into().map_err(|_| "invalid AUXTRACE_INFO")?,
                );
                let reserved = u32::from_le_bytes(
                    self.pending[offset + 12..offset + 16].try_into().map_err(|_| "invalid AUXTRACE_INFO")?,
                );
                if reserved != 0 {
                    return Err("invalid AUXTRACE_INFO reserved field");
                }
                self.intel_pt |= aux_type == 1;
            }
            self.record(if kind == 71 { 0 } else { kind }, u64::try_from(total).map_err(|_| "record size overflow")?)?;
            offset += total;
        }
        self.pending.drain(..offset);
        Ok(())
    }

    pub const fn finish(&self) -> Result<(), &'static str> {
        if self.pending.is_empty() { Ok(()) } else { Err("truncated compressed perf event") }
    }

    pub const fn has_nested_aux(&self) -> bool {
        self.nested_aux
    }
    pub const fn has_intel_pt(&self) -> bool {
        self.intel_pt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_intel_pt_info_inside_compressed_events() -> Result<(), Box<dyn std::error::Error>> {
        let encode = |aux_type: u32| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut event = [0_u8; 16];
            event[..4].copy_from_slice(&70_u32.to_le_bytes());
            event[6..8].copy_from_slice(&16_u16.to_le_bytes());
            event[8..12].copy_from_slice(&aux_type.to_le_bytes());
            let mut output = vec![0; zstd_safe::compress_bound(event.len())];
            let len = zstd_safe::compress(output.as_mut_slice(), &event, 1).map_err(|_| "compression failed")?;
            output.truncate(len);
            Ok(output)
        };
        let mut pt = Validator::new()?;
        pt.compressed(&encode(1)?)?;
        assert!(pt.has_intel_pt());
        let mut other = Validator::new()?;
        other.compressed(&encode(2)?)?;
        assert!(!other.has_intel_pt(), "other AUX types must not be treated as Intel PT");
        Ok(())
    }

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

    #[test]
    fn nested_aux_can_span_zstd_frames_and_rejects_truncation() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = vec![0_u8; 64];
        record[..4].copy_from_slice(&71_u32.to_le_bytes());
        record[6..8].copy_from_slice(&48_u16.to_le_bytes());
        record[8..16].copy_from_slice(&16_u64.to_le_bytes());
        let encode = |data: &[u8]| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut out = vec![0; zstd_safe::compress_bound(data.len())];
            let len = zstd_safe::compress(out.as_mut_slice(), data, 1).map_err(|_| "compression failed")?;
            out.truncate(len);
            Ok(out)
        };
        let mut validator = Validator::new()?;
        validator.compressed(&encode(&record[..25])?)?;
        validator.compressed(&encode(&record[25..])?)?;
        validator.finish()?;
        let mut truncated = Validator::new()?;
        truncated.compressed(&encode(&record[..63])?)?;
        assert!(truncated.finish().is_err(), "truncated AUX payload must fail");
        record[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Validator::new()?.compressed(&encode(&record)?).is_err(), "oversized AUX payload must fail");
        Ok(())
    }
}

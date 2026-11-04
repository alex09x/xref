/*
 * XRef — bounded perf event stream expansion
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use zstd_safe::{DCtx, DParameter, InBuffer, OutBuffer};

const LIMIT: usize = 64 * 1024 * 1024;

/// Expand a bounded event stream while retaining the original AUXTRACE header
/// and its external payload. This is a test-stage building block: relocation
/// of the surrounding perf.data sections is handled separately.
fn expand(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut decoder = DCtx::create();
    decoder.set_parameter(DParameter::WindowLogMax(26)).map_err(|_| "cannot bound zstd window")?;
    let mut offset = 0_usize;
    let mut result = Vec::new();
    let mut block = vec![0_u8; 1024 * 1024];
    while offset < input.len() {
        let header = input.get(offset..offset + 8).ok_or("truncated event header")?;
        let kind = u32::from_le_bytes(header[..4].try_into().map_err(|_| "invalid event")?);
        let size = usize::from(u16::from_le_bytes([header[6], header[7]]));
        if size < 8 {
            return Err("invalid event size");
        }
        let end = offset.checked_add(size).ok_or("event size overflow")?;
        let body = input.get(offset + 8..end).ok_or("truncated event")?;
        if matches!(kind, 81 | 83) {
            let compressed = if kind == 83 {
                let len = usize::try_from(u64::from_le_bytes(
                    body.get(..8)
                        .ok_or("truncated compressed header")?
                        .try_into()
                        .map_err(|_| "invalid compressed header")?,
                ))
                .map_err(|_| "compressed length overflow")?;
                body.get(8..8_usize.checked_add(len).ok_or("compressed length overflow")?)
                    .ok_or("truncated compressed bytes")?
            } else {
                body
            };
            let mut source = InBuffer::around(compressed);
            loop {
                let before = source.pos();
                let mut target = OutBuffer::around(block.as_mut_slice());
                decoder.decompress_stream(&mut target, &mut source).map_err(|_| "invalid zstd stream")?;
                let count = target.pos();
                if result.len().checked_add(count).is_none_or(|n| n > LIMIT) {
                    return Err("expanded stream exceeds limit");
                }
                result.extend_from_slice(&block[..count]);
                if source.pos() == compressed.len() && count < block.len() {
                    break;
                }
                if source.pos() == before && count == 0 {
                    return Err("stalled zstd stream");
                }
            }
            offset = end;
        } else {
            let extra = if kind == 71 {
                if size < 48 {
                    return Err("invalid AUXTRACE header");
                }
                usize::try_from(u64::from_le_bytes(body[..8].try_into().map_err(|_| "invalid AUXTRACE size")?))
                    .map_err(|_| "AUXTRACE size overflow")?
            } else {
                0
            };
            let complete = end.checked_add(extra).ok_or("AUXTRACE size overflow")?;
            let record = input.get(offset..complete).ok_or("truncated AUXTRACE payload")?;
            if result.len().checked_add(record.len()).is_none_or(|n| n > LIMIT) {
                return Err("expanded stream exceeds limit");
            }
            result.extend_from_slice(record);
            offset = complete;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::expand;

    #[test]
    fn expands_both_formats_without_changing_aux_payload() -> Result<(), &'static str> {
        let mut aux = vec![0_u8; 64];
        aux[..4].copy_from_slice(&71_u32.to_le_bytes());
        aux[6..8].copy_from_slice(&48_u16.to_le_bytes());
        aux[8..16].copy_from_slice(&16_u64.to_le_bytes());
        aux[48..].fill(0x5a);
        let mut compressed = vec![0; zstd_safe::compress_bound(aux.len())];
        let len = zstd_safe::compress(compressed.as_mut_slice(), &aux, 1).map_err(|_| "compression failed")?;
        compressed.truncate(len);
        for kind in [81_u32, 83] {
            let mut body = Vec::new();
            if kind == 83 {
                body.extend_from_slice(&u64::try_from(len).map_err(|_| "length overflow")?.to_le_bytes());
            }
            body.extend_from_slice(&compressed);
            let mut record = kind.to_le_bytes().to_vec();
            record.extend_from_slice(&0_u16.to_le_bytes());
            record.extend_from_slice(&u16::try_from(body.len() + 8).map_err(|_| "record overflow")?.to_le_bytes());
            record.extend_from_slice(&body);
            assert_eq!(expand(&record)?, aux);
            assert!(expand(&record[..record.len() - 1]).is_err(), "truncation must fail");
        }
        Ok(())
    }
}

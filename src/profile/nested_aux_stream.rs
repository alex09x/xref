/*
 * XRef — bounded perf event stream expansion
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::io::{self, Read, Write};
use zstd_safe::{DCtx, DParameter, InBuffer, OutBuffer};

const MAX_TOTAL: u64 = 16 * 1024 * 1024 * 1024;
const MAX_BLOCK: usize = 64 * 1024 * 1024;

/// Expand the data section of a previously validated perf snapshot. It keeps
/// ordinary records and external AUX payload bytes in their original order.
pub(super) fn expand<R: Read, W: Write>(input: &mut R, output: &mut W, mut remaining: u64) -> io::Result<u64> {
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
    let mut decoder = DCtx::create();
    decoder.set_parameter(DParameter::WindowLogMax(26)).map_err(|_| invalid("cannot bound zstd window"))?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut written = 0_u64;
    while remaining > 0 {
        if remaining < 8 {
            return Err(invalid("truncated event header"));
        }
        let mut header = [0_u8; 8];
        input.read_exact(&mut header)?;
        let kind = u32::from_le_bytes(header[..4].try_into().map_err(|_| invalid("invalid event header"))?);
        let size = usize::from(u16::from_le_bytes([header[6], header[7]]));
        if size < 8 || u64::try_from(size).map_err(|_| invalid("event size overflow"))? > remaining {
            return Err(invalid("invalid event size"));
        }
        let mut body = vec![0_u8; size - 8];
        input.read_exact(&mut body)?;
        remaining -= u64::try_from(size).map_err(|_| invalid("event size overflow"))?;
        if matches!(kind, 81 | 83) {
            let source = if kind == 83 {
                let length = usize::try_from(u64::from_le_bytes(
                    body.get(..8)
                        .ok_or_else(|| invalid("truncated compressed header"))?
                        .try_into()
                        .map_err(|_| invalid("invalid compressed header"))?,
                ))
                .map_err(|_| invalid("compressed length overflow"))?;
                body.get(8..8_usize.checked_add(length).ok_or_else(|| invalid("compressed length overflow"))?)
                    .ok_or_else(|| invalid("truncated compressed data"))?
            } else {
                &body
            };
            let mut input_buffer = InBuffer::around(source);
            let mut expanded = 0_usize;
            loop {
                let before = input_buffer.pos();
                let mut out = OutBuffer::around(buffer.as_mut_slice());
                decoder.decompress_stream(&mut out, &mut input_buffer).map_err(|_| invalid("invalid zstd stream"))?;
                let count = out.pos();
                expanded = expanded.checked_add(count).ok_or_else(|| invalid("expansion overflow"))?;
                written = written
                    .checked_add(u64::try_from(count).map_err(|_| invalid("size overflow"))?)
                    .ok_or_else(|| invalid("size overflow"))?;
                if expanded > MAX_BLOCK || written > MAX_TOTAL {
                    return Err(invalid("expanded data exceeds limits"));
                }
                output.write_all(&buffer[..count])?;
                if input_buffer.pos() == source.len() && count < buffer.len() {
                    break;
                }
                if input_buffer.pos() == before && count == 0 {
                    return Err(invalid("stalled zstd stream"));
                }
            }
        } else {
            let extra = if kind == 71 {
                if size < 48 {
                    return Err(invalid("invalid AUXTRACE header"));
                }
                u64::from_le_bytes(body[..8].try_into().map_err(|_| invalid("invalid AUXTRACE size"))?)
            } else {
                0
            };
            if extra > remaining || extra > u64::try_from(MAX_BLOCK).map_err(|_| invalid("size overflow"))? {
                return Err(invalid("AUXTRACE exceeds limits"));
            }
            written = written
                .checked_add(u64::try_from(size).map_err(|_| invalid("size overflow"))?)
                .and_then(|n| n.checked_add(extra))
                .ok_or_else(|| invalid("size overflow"))?;
            if written > MAX_TOTAL {
                return Err(invalid("expanded data exceeds limits"));
            }
            output.write_all(&header)?;
            output.write_all(&body)?;
            if io::copy(&mut input.take(extra), output)? != extra {
                return Err(invalid("truncated AUXTRACE payload"));
            }
            remaining -= extra;
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::expand;

    #[test]
    fn preserves_nested_aux_bytes_in_stream() -> Result<(), Box<dyn std::error::Error>> {
        let mut aux = vec![0_u8; 64];
        aux[..4].copy_from_slice(&71_u32.to_le_bytes());
        aux[6..8].copy_from_slice(&48_u16.to_le_bytes());
        aux[8..16].copy_from_slice(&16_u64.to_le_bytes());
        aux[48..].fill(0x5a);
        let mut compressed = vec![0_u8; zstd_safe::compress_bound(aux.len())];
        let size = zstd_safe::compress(compressed.as_mut_slice(), &aux, 1).map_err(|_| "compression failed")?;
        compressed.truncate(size);
        let mut event = 81_u32.to_le_bytes().to_vec();
        event.extend_from_slice(&0_u16.to_le_bytes());
        event.extend_from_slice(&u16::try_from(size + 8)?.to_le_bytes());
        event.extend_from_slice(&compressed);
        let mut output = Vec::new();
        assert_eq!(expand(&mut event.as_slice(), &mut output, u64::try_from(event.len())?)?, 64);
        assert_eq!(output, aux);
        assert!(expand(&mut event.as_slice(), &mut Vec::new(), u64::try_from(event.len() + 1)?).is_err());
        Ok(())
    }
}

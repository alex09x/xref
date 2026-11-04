/*
 * XRef — bounded perf AUXTRACE normalization
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/// Normalize complete decompressed records for the upstream reader. AUXTRACE
/// payload bytes follow header.size, whereas the reader expects them inside it.
/// This function keeps incomplete records for the next decompressed chunk.
#[derive(Default)]
struct Normalizer {
    pending: Vec<u8>,
}

impl Normalizer {
    fn push(&mut self, input: &[u8]) -> Result<Vec<u8>, &'static str> {
        const LIMIT: usize = 64 * 1024 * 1024;
        if self.pending.len().checked_add(input.len()).is_none_or(|n| n > LIMIT) {
            return Err("nested record buffer exceeds limit");
        }
        self.pending.extend_from_slice(input);
        let mut offset = 0;
        let mut out = Vec::new();
        while self.pending.len() - offset >= 8 {
            let header = &self.pending[offset..offset + 8];
            let kind = u32::from_le_bytes(header[..4].try_into().map_err(|_| "invalid record")?);
            let size = usize::from(u16::from_le_bytes([header[6], header[7]]));
            if size < 8 {
                return Err("invalid record size");
            }
            let total = if kind == 71 {
                if size < 48 {
                    return Err("invalid AUXTRACE header");
                }
                if self.pending.len() - offset < 16 {
                    break;
                }
                let payload = u64::from_le_bytes(
                    self.pending[offset + 8..offset + 16].try_into().map_err(|_| "invalid AUXTRACE size")?,
                );
                size.checked_add(usize::try_from(payload).map_err(|_| "AUXTRACE size overflow")?)
                    .ok_or("AUXTRACE size overflow")?
            } else {
                size
            };
            if total > LIMIT {
                return Err("nested AUXTRACE exceeds limit");
            }
            if self.pending.len() - offset < total {
                break;
            }
            if kind == 71 {
                let payload = &self.pending[offset + size..offset + total];
                let initial = u64::from_le_bytes(
                    self.pending[offset + 16..offset + 24].try_into().map_err(|_| "invalid AUXTRACE offset")?,
                );
                let chunk_limit = (usize::from(u16::MAX) - size) & !7;
                if chunk_limit == 0 && !payload.is_empty() {
                    return Err("AUXTRACE header too large");
                }
                let mut consumed = 0;
                loop {
                    let len = (payload.len() - consumed).min(chunk_limit);
                    let start = out.len();
                    out.extend_from_slice(&self.pending[offset..offset + size]);
                    out.extend_from_slice(&payload[consumed..consumed + len]);
                    let record_size = u16::try_from(size + len).map_err(|_| "AUXTRACE chunk too large")?;
                    out[start + 6..start + 8].copy_from_slice(&record_size.to_le_bytes());
                    out[start + 8..start + 16]
                        .copy_from_slice(&u64::try_from(len).map_err(|_| "AUXTRACE size overflow")?.to_le_bytes());
                    let trace_offset = initial
                        .checked_add(u64::try_from(consumed).map_err(|_| "AUXTRACE offset overflow")?)
                        .ok_or("AUXTRACE offset overflow")?;
                    out[start + 16..start + 24].copy_from_slice(&trace_offset.to_le_bytes());
                    consumed += len;
                    if consumed == payload.len() {
                        break;
                    }
                }
            } else {
                out.extend_from_slice(&self.pending[offset..offset + total]);
            }
            offset += total;
        }
        self.pending.drain(..offset);
        Ok(out)
    }

    fn finish(&self) -> Result<(), &'static str> {
        if self.pending.is_empty() { Ok(()) } else { Err("truncated nested record") }
    }
}

#[cfg(test)]
mod tests {
    use super::Normalizer;

    #[test]
    fn normalizes_aux_split_across_chunks() -> Result<(), &'static str> {
        let mut aux = [0_u8; 64];
        aux[..4].copy_from_slice(&71_u32.to_le_bytes());
        aux[6..8].copy_from_slice(&48_u16.to_le_bytes());
        aux[8..16].copy_from_slice(&16_u64.to_le_bytes());
        let mut normalizer = Normalizer::default();
        assert_eq!(normalizer.push(&aux[..20])?.len(), 0);
        let output = normalizer.push(&aux[20..])?;
        assert_eq!(output.len(), 64);
        assert_eq!(u16::from_le_bytes([output[6], output[7]]), 64);
        assert_eq!(&output[8..], &aux[8..]);
        normalizer.finish()?;
        Ok(())
    }

    #[test]
    fn splits_large_aux_payload_and_preserves_offsets() -> Result<(), &'static str> {
        let mut aux = vec![0_u8; 48 + 70_000];
        aux[..4].copy_from_slice(&71_u32.to_le_bytes());
        aux[6..8].copy_from_slice(&48_u16.to_le_bytes());
        aux[8..16].copy_from_slice(&70_000_u64.to_le_bytes());
        aux[16..24].copy_from_slice(&123_u64.to_le_bytes());
        for (index, byte) in aux[48..].iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).map_err(|_| "byte overflow")?;
        }
        let output = Normalizer::default().push(&aux)?;
        let mut position = 0;
        let mut payload = Vec::new();
        let mut chunks = 0;
        while position < output.len() {
            let size = usize::from(u16::from_le_bytes([output[position + 6], output[position + 7]]));
            let start =
                u64::from_le_bytes(output[position + 16..position + 24].try_into().map_err(|_| "invalid offset")?);
            assert_eq!(start, 123 + u64::try_from(payload.len()).map_err(|_| "size overflow")?);
            payload.extend_from_slice(&output[position + 48..position + size]);
            position += size;
            chunks += 1;
        }
        assert!(chunks > 1, "large payload must be split");
        assert_eq!(payload, aux[48..]);
        Ok(())
    }
}

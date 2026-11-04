/*
 * XRef — perf.data section relocation
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::io::{self, Read, Seek, SeekFrom, Write};

fn word(bytes: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or_else(|| invalid("truncated header"))?
            .try_into()
            .map_err(|_| invalid("invalid header"))?,
    ))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn shifted(value: u64, start: u64, end: u64, delta: i128) -> io::Result<u64> {
    if value == 0 || value < start {
        return Ok(value);
    }
    if value < end {
        return Err(invalid("metadata points into event data"));
    }
    u64::try_from(i128::from(value) + delta).map_err(|_| invalid("relocated offset overflow"))
}

pub(super) fn rewrite<R: Read + Seek, W: Read + Write + Seek>(input: &mut R, output: &mut W) -> io::Result<()> {
    input.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; 104];
    input.read_exact(&mut header)?;
    if &header[..8] != b"PERFILE2" {
        return Err(invalid("invalid perf magic"));
    }
    let data_start = word(&header, 40)?;
    let old_length = word(&header, 48)?;
    let old_end = data_start.checked_add(old_length).ok_or_else(|| invalid("data offset overflow"))?;
    let attr_start = word(&header, 24)?;
    let attr_size = word(&header, 16)?;
    let attr_len = word(&header, 32)?;
    if data_start < 104 || !(64..=4096).contains(&attr_size) || attr_len % attr_size != 0 || attr_len / attr_size > 64 {
        return Err(invalid("invalid section layout"));
    }
    let attr_end = attr_start.checked_add(attr_len).ok_or_else(|| invalid("attribute offset overflow"))?;
    if attr_start < old_end && attr_end > data_start {
        return Err(invalid("attributes overlap event data"));
    }
    input.seek(SeekFrom::Start(0))?;
    if io::copy(&mut input.take(data_start), output)? != data_start {
        return Err(invalid("truncated prefix"));
    }
    let new_length = super::nested_aux_stream::expand(input, output, old_length)?;
    let new_end = data_start.checked_add(new_length).ok_or_else(|| invalid("expanded data offset overflow"))?;
    let delta = i128::from(new_end) - i128::from(old_end);
    io::copy(input, output)?;
    output.seek(SeekFrom::Start(48))?;
    output.write_all(&new_length.to_le_bytes())?;
    let relocated_attr = shifted(attr_start, data_start, old_end, delta)?;
    output.seek(SeekFrom::Start(24))?;
    output.write_all(&relocated_attr.to_le_bytes())?;
    for index in 0..attr_len / attr_size {
        let ids_at = relocated_attr
            .checked_add(index * attr_size)
            .and_then(|x| x.checked_add(attr_size - 16))
            .ok_or_else(|| invalid("attribute offset overflow"))?;
        output.seek(SeekFrom::Start(ids_at))?;
        let mut bytes = [0_u8; 8];
        output.read_exact(&mut bytes)?;
        let id_offset = shifted(u64::from_le_bytes(bytes), data_start, old_end, delta)?;
        output.seek(SeekFrom::Start(ids_at))?;
        output.write_all(&id_offset.to_le_bytes())?;
    }
    let count =
        (72..104).step_by(8).try_fold(0_u32, |n, at| Ok::<_, io::Error>(n + word(&header, at)?.count_ones()))?;
    for index in 0..u64::from(count) {
        let at = new_end.checked_add(index * 16).ok_or_else(|| invalid("feature offset overflow"))?;
        output.seek(SeekFrom::Start(at))?;
        let mut bytes = [0_u8; 8];
        output.read_exact(&mut bytes)?;
        let feature = shifted(u64::from_le_bytes(bytes), data_start, old_end, delta)?;
        output.seek(SeekFrom::Start(at))?;
        output.write_all(&feature.to_le_bytes())?;
    }
    output.seek(SeekFrom::Start(0))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn relocates_feature_and_attribute_id_offsets() -> io::Result<()> {
        let mut source = vec![0_u8; 282];
        source[..8].copy_from_slice(b"PERFILE2");
        for (at, value) in [
            (8, 104_u64),
            (16, 144),
            (24, 104),
            (32, 144),
            (40, 248),
            (48, 8),
            (72, 1),
            (232, 272),
            (256, 272),
            (264, 10),
        ] {
            source[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        source[248..252].copy_from_slice(&68_u32.to_le_bytes());
        source[254..256].copy_from_slice(&8_u16.to_le_bytes());
        let mut output = Cursor::new(Vec::new());
        rewrite(&mut Cursor::new(source.clone()), &mut output)?;
        assert_eq!(output.into_inner(), source);
        Ok(())
    }

    #[test]
    fn updates_offsets_when_compressed_data_expands() -> Result<(), Box<dyn std::error::Error>> {
        let mut event = [0_u8; 8];
        event[..4].copy_from_slice(&68_u32.to_le_bytes());
        event[6..].copy_from_slice(&8_u16.to_le_bytes());
        let mut compressed = vec![0_u8; zstd_safe::compress_bound(event.len())];
        let length = zstd_safe::compress(compressed.as_mut_slice(), &event, 1).map_err(|_| "compression failed")?;
        compressed.truncate(length);
        let old_length = u64::try_from(length + 8)?;
        let old_end = 248 + old_length;
        let mut source = vec![0_u8; usize::try_from(old_end + 26)?];
        source[..8].copy_from_slice(b"PERFILE2");
        for (at, value) in
            [(8, 104_u64), (16, 144), (24, 104), (32, 144), (40, 248), (48, old_length), (72, 1), (232, old_end + 16)]
        {
            source[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        source[248..252].copy_from_slice(&81_u32.to_le_bytes());
        source[254..256].copy_from_slice(&u16::try_from(old_length)?.to_le_bytes());
        source[256..256 + length].copy_from_slice(&compressed);
        let old_end = usize::try_from(old_end)?;
        source[old_end..old_end + 8].copy_from_slice(&u64::try_from(old_end + 16)?.to_le_bytes());
        source[old_end + 8..old_end + 16].copy_from_slice(&10_u64.to_le_bytes());
        source[old_end + 16..old_end + 26].copy_from_slice(b"sideband!!");
        let mut output = Cursor::new(Vec::new());
        rewrite(&mut Cursor::new(source), &mut output)?;
        let bytes = output.into_inner();
        assert_eq!(word(&bytes, 48)?, 8);
        assert_eq!(&bytes[248..256], &event);
        assert_eq!(word(&bytes, 232)?, 272);
        assert_eq!(word(&bytes, 256)?, 272);
        assert_eq!(&bytes[272..282], b"sideband!!");
        Ok(())
    }
}

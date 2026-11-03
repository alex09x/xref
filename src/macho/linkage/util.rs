/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
pub(super) fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b).ok_or_else(|| "Mach-O address overflow".into())
}

pub(super) fn bytes(data: &[u8], off: usize, len: usize) -> Result<&[u8], String> {
    let end = off.checked_add(len).ok_or("Mach-O byte range overflow")?;
    data.get(off..end).ok_or_else(|| "Truncated Mach-O metadata".into())
}

pub(super) fn u16_at(data: &[u8], off: usize, le: bool) -> Result<u16, String> {
    let v: [u8; 2] = bytes(data, off, 2)?.try_into().map_err(|_| "Truncated Mach-O u16")?;
    Ok(if le { u16::from_le_bytes(v) } else { u16::from_be_bytes(v) })
}

pub(super) fn u32_at(data: &[u8], off: usize, le: bool) -> Result<u32, String> {
    let v: [u8; 4] = bytes(data, off, 4)?.try_into().map_err(|_| "Truncated Mach-O u32")?;
    Ok(if le { u32::from_le_bytes(v) } else { u32::from_be_bytes(v) })
}

pub(super) fn u64_at(data: &[u8], off: usize, le: bool) -> Result<u64, String> {
    let v: [u8; 8] = bytes(data, off, 8)?.try_into().map_err(|_| "Truncated Mach-O u64")?;
    Ok(if le { u64::from_le_bytes(v) } else { u64::from_be_bytes(v) })
}

pub(super) struct Cursor<'a> {
    data: &'a [u8],
    pub(super) pos: usize,
}

impl<'a> Cursor<'a> {
    pub(super) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub(super) fn at(data: &'a [u8], pos: usize) -> Result<Self, String> {
        if pos >= data.len() {
            return Err("Mach-O offset out of bounds".into());
        }
        Ok(Self { data, pos })
    }
    pub(super) const fn remaining(&self) -> bool {
        self.pos < self.data.len()
    }
    pub(super) fn byte(&mut self) -> Result<u8, String> {
        let value = *self.data.get(self.pos).ok_or("Truncated Mach-O bytecode")?;
        self.pos = self.pos.checked_add(1).ok_or("Mach-O cursor overflow")?;
        Ok(value)
    }
    pub(super) fn uleb(&mut self) -> Result<u64, String> {
        let mut result = 0u64;
        for i in 0..10 {
            let b = self.byte()?;
            let bits = u64::from(b & 0x7f);
            if i == 9 && bits > 1 {
                return Err("Mach-O ULEB overflow".into());
            }
            result |= bits << (i * 7);
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err("Mach-O ULEB too long".into())
    }
    pub(super) fn sleb(&mut self) -> Result<i64, String> {
        let mut result = 0u64;
        for i in 0..10 {
            let b = self.byte()?;
            let bits = u64::from(b & 0x7f);
            if i == 9 && bits != 0 && bits != 0x7f {
                return Err("Mach-O SLEB overflow".into());
            }
            result |= bits << (i * 7);
            if b & 0x80 == 0 {
                let shift = (i + 1) * 7;
                if shift < 64 && b & 0x40 != 0 {
                    result |= u64::MAX << shift;
                }
                return Ok(result.cast_signed());
            }
        }
        Err("Mach-O SLEB too long".into())
    }
    pub(super) fn cstr(&mut self) -> Result<&'a [u8], String> {
        let tail = self.data.get(self.pos..).ok_or("Mach-O string offset out of bounds")?;
        let len = tail.iter().position(|b| *b == 0).ok_or("Unterminated Mach-O string")?;
        let start = self.pos;
        self.pos = self.pos.checked_add(len + 1).ok_or("Mach-O cursor overflow")?;
        bytes(self.data, start, len)
    }
}

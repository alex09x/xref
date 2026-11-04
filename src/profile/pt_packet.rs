/*
 * XRef — Intel PT packet parsing
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Packet {
    Psb,
    PsbEnd,
    Mode(u8),
    Ip { kind: u8, compression: u8, payload: u64 },
    Tnt { bits: u64, count: u8 },
    Pip(u64),
    Cbr(u8),
    Tsc(u64),
    Timing,
    Overflow,
    Pad,
}

pub(super) fn packet(input: &[u8]) -> Result<(Packet, usize), &'static str> {
    let first = *input.first().ok_or("truncated packet")?;
    if first == 0 {
        return Ok((Packet::Pad, 1));
    }
    if first == 2 {
        let second = *input.get(1).ok_or("truncated extended packet")?;
        return match second {
            0x82 => {
                let psb = input.get(..16).ok_or("truncated PSB")?;
                if psb.as_chunks::<2>().0.iter().any(|v| *v != [2, 0x82]) {
                    return Err("invalid PSB");
                }
                Ok((Packet::Psb, 16))
            }
            0x23 => Ok((Packet::PsbEnd, 2)),
            0xf3 => Ok((Packet::Overflow, 2)),
            0x73 => {
                input.get(..7).ok_or("truncated TMA")?;
                Ok((Packet::Timing, 7))
            }
            0x43 => Ok((Packet::Pip(little(input.get(2..8).ok_or("truncated PIP")?)), 8)),
            0x03 => Ok((
                Packet::Cbr(*input.get(2).ok_or("truncated CBR")?),
                if input.get(3).is_some() {
                    4
                } else {
                    return Err("truncated CBR");
                },
            )),
            0xa3 => {
                let bits = little(input.get(2..8).ok_or("truncated long TNT")?);
                let stop = 63_u32.checked_sub(bits.leading_zeros()).ok_or("invalid long TNT")?;
                Ok((Packet::Tnt { bits, count: u8::try_from(stop).map_err(|_| "invalid long TNT")? }, 8))
            }
            _ => Err("unsupported extended packet"),
        };
    }
    if first == 0x99 {
        return Ok((Packet::Mode(*input.get(1).ok_or("truncated MODE")?), 2));
    }
    if first == 0x19 {
        return Ok((Packet::Tsc(little(input.get(1..8).ok_or("truncated TSC")?)), 8));
    }
    if first == 0x59 {
        input.get(..2).ok_or("truncated MTC")?;
        return Ok((Packet::Timing, 2));
    }
    let kind = first & 0x1f;
    if matches!(kind, 0x01 | 0x0d | 0x11 | 0x1d) {
        let compression = first >> 5;
        let size = match compression {
            0 => 0,
            1 => 2,
            2 => 4,
            3 | 4 => 6,
            6 => 8,
            _ => return Err("invalid IP compression"),
        };
        let bytes = input.get(1..1 + size).ok_or("truncated IP packet")?;
        let mut value = [0_u8; 8];
        value[..size].copy_from_slice(bytes);
        return Ok((Packet::Ip { kind, compression, payload: u64::from_le_bytes(value) }, 1 + size));
    }
    if first & 1 == 0 {
        let stop = 7_u32.checked_sub(first.leading_zeros()).ok_or("invalid TNT")?;
        if stop == 0 {
            return Err("invalid TNT stop bit");
        }
        return Ok((
            Packet::Tnt { bits: u64::from(first >> 1), count: u8::try_from(stop - 1).map_err(|_| "invalid TNT")? },
            1,
        ));
    }
    Err("unsupported PT packet")
}

fn little(bytes: &[u8]) -> u64 {
    let mut value = [0_u8; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(value)
}

pub(super) fn ip_address(previous: Option<u64>, compression: u8, payload: u64) -> Result<Option<u64>, &'static str> {
    let prior = || previous.ok_or("IP update without previous address");
    match compression {
        0 => Ok(None),
        1 => Ok(Some((prior()? & !0xffff) | payload)),
        2 => Ok(Some((prior()? & !0xffff_ffff) | payload)),
        3 => Ok(Some(if payload & (1 << 47) != 0 { payload | 0xffff_0000_0000_0000 } else { payload })),
        4 => Ok(Some((prior()? & 0xffff_0000_0000_0000) | payload)),
        6 => Ok(Some(payload)),
        _ => Err("invalid IP compression"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_reference_packet_boundaries_and_rejects_truncation() -> Result<(), &'static str> {
        let mut trace = [2, 0x82].repeat(8);
        trace.extend_from_slice(&[0x7d, 0, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23, 0x2d, 5, 0, 0x3d, 6, 0, 1]);
        let mut pos = 0;
        let mut parsed = Vec::new();
        while pos < trace.len() {
            let (item, size) = packet(&trace[pos..])?;
            parsed.push(item);
            pos += size;
        }
        assert_eq!(parsed.len(), 7);
        assert_eq!(parsed[0], Packet::Psb);
        assert!(matches!(parsed[1], Packet::Ip { kind: 0x1d, compression: 3, payload: 0x10_0000 }));
        assert!(matches!(parsed[4], Packet::Ip { kind: 0x0d, compression: 1, payload: 5 }));
        assert!(packet(&[0x7d, 0]).is_err(), "truncated IP must fail");
        assert!(packet(&[2, 0x82]).is_err(), "truncated PSB must fail");
        assert_eq!(packet(&[0x59, 7])?, (Packet::Timing, 2));
        assert_eq!(packet(&[2, 0x73, 1, 2, 3, 4, 5])?, (Packet::Timing, 7));
        assert!(packet(&[0x59]).is_err(), "truncated MTC must fail");
        assert!(packet(&[2, 0x73, 1, 2]).is_err(), "truncated TMA must fail");
        Ok(())
    }

    #[test]
    fn reconstructs_ip_and_rejects_uninitialized_updates() -> Result<(), &'static str> {
        assert_eq!(ip_address(None, 3, 0x8000_0000_0000)?, Some(0xffff_8000_0000_0000));
        assert_eq!(ip_address(Some(0x1234_5678), 1, 0xabcd)?, Some(0x1234_abcd));
        assert!(ip_address(None, 1, 7).is_err(), "partial IP needs a prior address");
        assert_eq!(packet(&[2, 3, 0x2a, 0])?, (Packet::Cbr(0x2a), 4));
        assert!(packet(&[2, 0x43, 1]).is_err(), "truncated PIP must fail");
        Ok(())
    }
}

/*
 * XRef — Intel PT timestamp conversion
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/// Values recorded by perf for translating hardware cycles to its clock.
struct Conversion {
    time_zero: u64,
    time_mult: u32,
    time_shift: u16,
    user_time_zero: bool,
    short_counter: Option<(u64, u64)>,
}

impl Conversion {
    /// Parse `PERF_RECORD_TIME_CONV`'s body without reading beyond older records.
    /// Older records lack capability flags and therefore cannot establish a
    /// trustworthy absolute conversion on their own.
    fn from_record(data: &[u8]) -> Result<Self, &'static str> {
        fn word(data: &[u8], offset: usize) -> Result<u64, &'static str> {
            Ok(u64::from_le_bytes(
                data.get(offset..offset + 8)
                    .ok_or("truncated TIME_CONV")?
                    .try_into()
                    .map_err(|_| "invalid TIME_CONV")?,
            ))
        }
        if data.len() != 24 && data.len() < 48 {
            return Err("truncated TIME_CONV capabilities");
        }
        let time_shift = u16::try_from(word(data, 0)?).map_err(|_| "TIME_CONV shift overflow")?;
        let time_mult = u32::try_from(word(data, 8)?).map_err(|_| "TIME_CONV multiplier overflow")?;
        let time_zero = word(data, 16)?;
        let (user_time_zero, short_counter) = if data.len() == 24 {
            (false, None)
        } else {
            let flags = data.get(40..48).ok_or("truncated TIME_CONV capabilities")?;
            if flags[0] > 1 || flags[1] > 1 || flags[2..].iter().any(|&value| value != 0) {
                return Err("invalid TIME_CONV capability flags");
            }
            (flags[0] == 1, if flags[1] == 1 { Some((word(data, 24)?, word(data, 32)?)) } else { None })
        };
        Ok(Self { time_zero, time_mult, time_shift, user_time_zero, short_counter })
    }
    /// `truncated` must be set for PT's partial-width TSC. Such a value cannot
    /// be correlated safely unless perf supplied a cycle anchor and mask.
    fn to_perf_time(&self, value: u64, truncated: bool) -> Option<u64> {
        if !self.user_time_zero || self.time_mult == 0 || self.time_shift >= 64 {
            return None;
        }
        let cycles = if truncated {
            let (anchor, mask) = self.short_counter?;
            if mask == 0 || mask == u64::MAX || mask & mask.wrapping_add(1) != 0 || value & !mask != 0 {
                return None;
            }
            anchor.checked_add(value.wrapping_sub(anchor) & mask)?
        } else {
            value
        };
        let scaled = (u128::from(cycles) * u128::from(self.time_mult)) >> self.time_shift;
        u64::try_from(scaled.checked_add(u128::from(self.time_zero))?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::Conversion;

    #[test]
    fn converts_full_and_anchored_short_tsc_without_overflow() {
        let mut value =
            Conversion { time_zero: 100, time_mult: 3, time_shift: 2, user_time_zero: true, short_counter: None };
        assert_eq!(value.to_perf_time(20, false), Some(115));
        assert_eq!(value.to_perf_time(20, true), None, "partial TSC needs an anchor");
        value.short_counter = Some((250, 0xff));
        assert_eq!(value.to_perf_time(5, true), Some(295));
        value.short_counter = Some((250, 0xf0));
        assert_eq!(value.to_perf_time(5, true), None, "invalid mask must fail");
        value.short_counter = None;
        value.time_zero = u64::MAX;
        assert_eq!(value.to_perf_time(u64::MAX, false), None, "overflow must fail");
        value.user_time_zero = false;
        assert_eq!(value.to_perf_time(1, false), None, "missing time conversion must fail");
    }

    #[test]
    fn parses_extended_and_legacy_perf_time_records() -> Result<(), &'static str> {
        let mut data = vec![0_u8; 48];
        data[..8].copy_from_slice(&2_u64.to_le_bytes());
        data[8..16].copy_from_slice(&3_u64.to_le_bytes());
        data[16..24].copy_from_slice(&100_u64.to_le_bytes());
        data[24..32].copy_from_slice(&250_u64.to_le_bytes());
        data[32..40].copy_from_slice(&0xff_u64.to_le_bytes());
        data[40] = 1;
        data[41] = 1;
        assert_eq!(Conversion::from_record(&data)?.to_perf_time(5, true), Some(295));
        assert_eq!(Conversion::from_record(&data[..24])?.to_perf_time(20, false), None);
        assert!(Conversion::from_record(&data[..41]).is_err(), "partial capability fields must fail");
        data[47] = 1;
        assert!(Conversion::from_record(&data).is_err(), "reserved bits must not be ignored");
        Ok(())
    }
}

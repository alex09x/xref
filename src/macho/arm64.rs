/*
 * XRef — arm64 Mach-O images for profiles: symbols and function ranges from function starts
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! xref decodes x86-64 code only. For profiles of Apple Silicon programs an arm64 Mach-O is read
//! for what attribution needs: its segments, its function symbols and `LC_FUNCTION_STARTS`, which
//! give every function's start (a function ends where the next one starts). Nothing is
//! disassembled, so annotation and block or line grouping are not available for it.

use std::error::Error;
use std::ops::Range;

use object::{Architecture, BinaryFormat, Object, ObjectSegment, ObjectSymbol, SymbolKind};

use crate::image::{Image, Segment};

/// `CPU_TYPE_ARM64`.
const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// Whether `data` is a thin 64-bit little-endian arm64 Mach-O.
pub fn is_arm64(data: &[u8]) -> bool {
    data.get(..4) == Some(&[0xcf, 0xfa, 0xed, 0xfe]) && data.get(4..8) == Some(&CPU_TYPE_ARM64.to_le_bytes())
}

/// Function ranges from sorted starts: each ends at the next start, the last at the end of the
/// code range that holds it.
pub fn ranges_from_starts(starts: &[u64], code: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut sorted: Vec<u64> = starts.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted
        .iter()
        .enumerate()
        .filter_map(|(index, &start)| {
            let section = code.iter().find(|range| range.contains(&start))?;
            let next = sorted.get(index + 1).copied().filter(|next| *next <= section.end).unwrap_or(section.end);
            (next > start).then_some(start..next)
        })
        .collect()
}

/// The image of an arm64 Mach-O for profile attribution.
pub fn profile_image(data: Vec<u8>) -> Result<Image, Box<dyn Error>> {
    crate::macho::profile::validate(&data)?;
    let (segments, symbols, metadata) = {
        let file = object::File::parse(data.as_slice())?;
        if file.format() != BinaryFormat::MachO || file.architecture() != Architecture::Aarch64 || !file.is_64() {
            return Err("expected a thin 64-bit arm64 Mach-O".into());
        }
        let segments = file
            .segments()
            .filter(|segment| segment.file_range().1 > 0)
            .map(|segment| {
                let (offset, size) = segment.file_range();
                if offset.checked_add(size).is_none_or(|end| end > data.len() as u64) {
                    return Err("segment range overflow".into());
                }
                Ok(Segment { va: segment.address(), offset: usize::try_from(offset)?, size: usize::try_from(size)? })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let mut symbols: Vec<(u64, String)> = file
            .symbols()
            .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.is_definition() && symbol.address() != 0)
            // Mach-O prefixes C names with `_` (`_main`, `__ZN…` for Rust): reports show the source name.
            .filter_map(|symbol| {
                let name = symbol.name().ok()?;
                Some((symbol.address(), name.strip_prefix('_').unwrap_or(name).to_owned()))
            })
            .collect();
        symbols.sort_unstable();
        symbols.dedup_by_key(|(address, _)| *address);
        let mut metadata = crate::macho::profile::metadata(&file, &data, &segments, &[])?;
        metadata.arm64 = true;
        metadata.warnings.retain(|warning| *warning != "macho_function_coverage_incomplete");
        metadata.warn("arm64_profile_only_no_disassembly");
        (segments, symbols, metadata)
    };
    // Boundaries come from LC_FUNCTION_STARTS: a text symbol can be a label inside a function, so
    // symbols only name functions, and give boundaries only when the table is missing.
    let starts = if metadata.function_starts.is_empty() {
        symbols.iter().map(|(address, _)| *address).collect()
    } else {
        metadata.function_starts.clone()
    };
    let functions = ranges_from_starts(&starts, &metadata.code_ranges);
    Ok(Image { data, segments, functions, pointers: Vec::new(), imports: Vec::new(), symbols, metadata })
}

/// The `LC_UUID` of a Mach-O, as `sample` prints it (upper-case, dashed).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn uuid(data: &[u8]) -> Option<String> {
    let file = object::File::parse(data).ok()?;
    let bytes = file.mach_uuid().ok().flatten()?;
    let hex = bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02X}");
        text
    });
    Some(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}

#[cfg(test)]
mod tests {
    use super::ranges_from_starts;

    #[test]
    fn functions_end_at_the_next_start_or_their_section() {
        let code = [0x1000..0x1100, 0x2000..0x2040];
        let ranges = ranges_from_starts(&[0x1080, 0x1000, 0x2000, 0x1000, 0x3000], &code);
        assert_eq!(ranges, vec![0x1000..0x1080, 0x1080..0x1100, 0x2000..0x2040]);
    }

    #[test]
    fn arm64_magic_is_recognized() {
        let mut header = vec![0xcf, 0xfa, 0xed, 0xfe];
        header.extend(0x0100_000c_u32.to_le_bytes());
        assert!(super::is_arm64(&header));
        header[4] = 7;
        assert!(!super::is_arm64(&header));
    }
}

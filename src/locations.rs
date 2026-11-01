/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Rust panic locations (`core::panic::Location`: file `&str`, line, column) stored in relocated
//! data. Code passing one names a source file and line, which maps machine code back to the
//! source module it was compiled from.

use rayon::prelude::*;

use crate::image::Image;

pub struct Location {
    pub place: u64,
    pub file: String,
    pub line: u32,
    pub col: u32,
}

/// The file name of a location whose `&str` points at `bytes`, when it looks like one.
pub fn file_name(bytes: &[u8], line: u32, col: u32) -> Option<String> {
    let bytes = bytes.strip_suffix(b"\0").unwrap_or(bytes);
    let name = std::str::from_utf8(bytes).ok()?;
    let rust = std::path::Path::new(name).extension().is_some_and(|extension| extension.eq_ignore_ascii_case("rs"));
    let plausible = rust && (1..=2_000_000).contains(&line) && col <= 10_000;
    (plausible && !name.contains(char::is_control)).then(|| name.to_owned())
}

/// Every panic location, sorted by place.
pub fn locations(image: &Image) -> Vec<Location> {
    image
        .pointers
        .par_iter()
        .filter_map(|&(place, target)| {
            let len = usize::try_from(image.read_u64(place + 8)?).ok().filter(|len| (4..=1024).contains(len))?;
            let line = image.read_u32(place + 16)?;
            let col = image.read_u32(place + 20)?;
            let file = file_name(image.read(target, len)?, line, col)?;
            Some(Location { place, file, line, col })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::file_name;

    #[test]
    fn only_rust_source_names_with_sane_positions_are_locations() {
        let name = b"/build/app/src/order.rs";
        assert_eq!(file_name(name, 120, 9).as_deref(), Some("/build/app/src/order.rs"));
        assert_eq!(file_name(b"src/lib.rs\0", 1, 0).as_deref(), Some("src/lib.rs"));
        assert!(file_name(b"plain text", 1, 1).is_none());
        assert!(file_name(name, 0, 1).is_none());
        assert!(file_name(b"bad\nname.rs", 3, 1).is_none());
    }
}

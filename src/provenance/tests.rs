/*
 * XRef Code — Unit tests for provenance, `.dep-v0`, `.go.buildinfo`, and entropy guards
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use miniz_oxide::deflate::compress_to_vec_zlib;

use super::go_buildinfo::parse_buildinfo_blob;
use super::rust_deps::{MAX_AUDIT_JSON_BYTES, parse_compressed_dep_v0};
use super::toolchain::{HIGH_ENTROPY_MILLI_THRESHOLD, collect_comment_strings, hex_build_id, shannon_entropy_milli};

fn push_uleb(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[test]
fn rust_dep_v0_parses_root_runtime_and_build_packages() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = r#"{
        "format": 1,
        "packages": [
            {"name": "serde", "version": "1.0.219", "source": "crates.io", "dependencies": []},
            {"name": "cc", "version": "1.2.16", "source": "crates.io", "kind": "build", "dependencies": []},
            {"name": "demo-app", "version": "0.4.0", "source": "local", "root": true, "dependencies": [0, 1]}
        ]
    }"#;
    let compressed = compress_to_vec_zlib(manifest.as_bytes(), 6);
    let info = parse_compressed_dep_v0(&compressed)?;
    assert_eq!(info.format, Some(1));
    assert_eq!(info.root_name.as_deref(), Some("demo-app"));
    assert_eq!(info.root_version.as_deref(), Some("0.4.0"));
    assert_eq!(info.runtime_count, 2);
    assert_eq!(info.build_count, 1);
    assert_eq!(info.packages.len(), 3);
    assert!(info.packages[0].root);
    assert_eq!(info.packages[0].name, "demo-app");
    assert_eq!(info.packages[0].dependency_count, 2);
    Ok(())
}

#[test]
fn rust_dep_v0_rejects_decompression_bomb_and_corrupt_streams() {
    // 20 MiB of zeros compresses down to ~20 KiB in zlib, well under the 4 MiB compressed cap,
    // exercising the 16 MiB uncompressed limit directly without OOM.
    let bomb_raw = vec![b' '; MAX_AUDIT_JSON_BYTES + 4 * 1024 * 1024];
    let compressed_bomb = compress_to_vec_zlib(&bomb_raw, 9);
    assert!(compressed_bomb.len() < 256 * 1024);
    let err = parse_compressed_dep_v0(&compressed_bomb);
    assert!(err.is_err(), "expected zip-bomb to fail decompression bound");

    assert!(parse_compressed_dep_v0(b"not-valid-zlib-stream").is_err());
}

#[test]
fn go_buildinfo_inline_varint_and_sentinels_parse_modules_and_replacements() -> Result<(), Box<dyn std::error::Error>> {
    let mut blob = vec![0u8; 32];
    blob[..14].copy_from_slice(b"\xff Go buildinf:");
    blob[14] = 8; // 64-bit pointer size
    blob[15] = 0x02; // Go 1.18+ inline varint strings

    let go_ver = b"go1.25.5";
    push_uleb(&mut blob, go_ver.len());
    blob.extend_from_slice(go_ver);

    let mod_body = concat!(
        "path\tgithub.com/example/agentd/cmd/agentd\n",
        "mod\tgithub.com/example/agentd\tv1.4.2\th1:root==\n",
        "dep\tgolang.org/x/sys\tv0.30.0\th1:sys==\n",
        "dep\tgithub.com/foo/bar\tv0.1.0\n",
        "=>\tgithub.com/fork/bar\tv0.1.1-patched\th1:fork==\n",
        "build\t-buildmode=pie\n",
        "build\tCGO_ENABLED=0\n",
    );
    let start_sentinel: [u8; 16] =
        [0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6];
    let end_sentinel: [u8; 16] =
        [0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2];

    let mut framed_mod = Vec::new();
    framed_mod.extend_from_slice(&start_sentinel);
    framed_mod.extend_from_slice(mod_body.as_bytes());
    framed_mod.extend_from_slice(&end_sentinel);

    push_uleb(&mut blob, framed_mod.len());
    blob.extend_from_slice(&framed_mod);

    let parsed = parse_buildinfo_blob(&blob, None).ok_or("expected valid GoBuildInfo")?;
    assert_eq!(parsed.go_version, "go1.25.5");
    assert_eq!(parsed.path.as_deref(), Some("github.com/example/agentd/cmd/agentd"));
    assert_eq!(parsed.main_module, Some(("github.com/example/agentd".into(), "v1.4.2".into())));
    assert_eq!(parsed.deps.len(), 2);
    assert_eq!(parsed.deps[0].path, "github.com/foo/bar");
    assert_eq!(parsed.deps[0].replaced_by, Some(("github.com/fork/bar".into(), "v0.1.1-patched".into())));
    assert_eq!(parsed.deps[1].path, "golang.org/x/sys");
    assert_eq!(parsed.settings.len(), 2);
    Ok(())
}

/// An inline `.go.buildinfo` header with `version` and an empty module text.
fn inline_header(version: &[u8]) -> Vec<u8> {
    let mut blob = vec![0u8; 32];
    blob[..14].copy_from_slice(b"\xff Go buildinf:");
    blob[14] = 8;
    blob[15] = 0x02;
    push_uleb(&mut blob, version.len());
    blob.extend_from_slice(version);
    push_uleb(&mut blob, 0);
    blob
}

#[test]
fn go_buildinfo_needs_a_go_version_and_an_aligned_header_in_a_segment_scan() {
    assert!(parse_buildinfo_blob(&inline_header(b"go1.22.3"), None).is_some());
    assert!(parse_buildinfo_blob(&inline_header(b"devel go1.23-abc"), None).is_some());
    for bad in [&b""[..], b"1.22", b"xyz", b"go\x01bad"] {
        assert!(parse_buildinfo_blob(&inline_header(bad), None).is_none(), "{bad:?}");
    }
    // The same header found by the segment scan: at a 16-byte aligned address it is one, one byte
    // further (a string literal in `.rodata`) it is not.
    let header = inline_header(b"go1.22.3");
    for (at, found) in [(0x40usize, true), (0x41, false)] {
        let mut data = vec![0u8; 0x200];
        data[at..at + header.len()].copy_from_slice(&header);
        let image = crate::image::Image {
            segments: vec![crate::image::Segment { va: 0x1000, offset: 0, size: data.len() }],
            data,
            ..crate::image::Image::default()
        };
        assert_eq!(super::go_buildinfo::extract(&image, None).is_some(), found, "header at {at:#x}");
    }
}

#[test]
fn toolchain_comments_build_id_and_entropy_bounds_behave_accurately() {
    assert_eq!(hex_build_id(Some(&[0xde, 0xad, 0xbe, 0xef])), Some("deadbeef".into()));
    assert_eq!(hex_build_id(Some(&[])), None);

    let mut comments = Vec::new();
    collect_comment_strings(
        b"\0GCC: (Ubuntu 13.3.0) 13.3.0\0rustc version 1.88.0\0GCC: (Ubuntu 13.3.0) 13.3.0\0",
        &mut comments,
    );
    assert_eq!(comments, vec!["GCC: (Ubuntu 13.3.0) 13.3.0", "rustc version 1.88.0"]);

    // Uniform 0..=255 cycle has maximum 8.000 bits/byte entropy (>= 7.200 threshold).
    let high: Vec<u8> = (0..4096usize).map(|i| u8::try_from(i & 0xff).unwrap_or(0)).collect();
    assert_eq!(shannon_entropy_milli(&high), 8000);
    assert!(shannon_entropy_milli(&high) >= HIGH_ENTROPY_MILLI_THRESHOLD);

    // Zero-filled or sparse buffer has low entropy.
    let low = vec![0x90u8; 4096];
    assert_eq!(shannon_entropy_milli(&low), 0);

    // glibc's `__cxa_finalize` / `__cxa_atexit` in C PIE binaries must NOT misclassify C as C++.
    let mut c_img = crate::image::Image {
        functions: std::iter::once(0x1000..0x1010).collect(),
        imports: vec![(0x2000, "__cxa_finalize".into()), (0x2008, "printf".into())],
        ..crate::image::Image::default()
    };
    let prov = super::ProvenanceSummary::default();
    assert_eq!(super::detect_language(&c_img, 0, &prov), "c_or_native");
    c_img.imports.push((0x2010, "__gxx_personality_v0".into()));
    assert_eq!(super::detect_language(&c_img, 0, &prov), "cpp");
}

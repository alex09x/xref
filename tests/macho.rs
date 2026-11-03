/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
type Error = Box<dyn std::error::Error>;
fn input(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/macho/{name}.macho"))
}
fn manifest(name: &str) -> Result<Value, Error> {
    Ok(serde_json::from_slice(&std::fs::read(input(name).with_extension("json"))?)?)
}
fn query(file: &Path, value: &Value) -> Result<Value, Error> {
    let out =
        Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(file).arg("query").arg(value.to_string()).output()?;
    let result: Value = serde_json::from_slice(&out.stdout)?;
    if !out.status.success() {
        return Err(format!("query failed: {result} {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(result)
}
fn c(file: &Path, addr: &str) -> Result<String, Error> {
    let out = Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(file).args(["c", addr]).output()?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned().into());
    }
    Ok(String::from_utf8(out.stdout)?)
}
fn address(v: &Value) -> Result<String, Error> {
    Ok(format!("{:#x}", v.as_u64().ok_or("address")?))
}
#[test]
fn macho_native_trace_and_return_values() -> Result<(), Error> {
    for name in ["basic", "legacy", "chained", "dylib", "bundle"] {
        let file = input(name);
        let expected = manifest(name)?;
        let info = query(&file, &json!({"operation":"info"}))?;
        assert_eq!(info["image"]["format"], "macho");
        assert_eq!(info["image"]["architecture"], "x86_64");
        assert_eq!(info["image"]["base_address"], address(&expected["base"])?);
        assert_eq!(info["image"]["rva_basis"], "macho_text_segment_vmaddr");
        if name != "dylib" && name != "bundle" {
            assert_eq!(info["data"]["format_details"]["entry_point"], address(&expected["symbols"]["_macho_entry"])?);
        }
        let strings = query(&file, &json!({"operation":"strings","text":"XREF_MACHO_SEED"}))?;
        assert!(
            strings["data"]["locations"]
                .as_array()
                .is_some_and(|v| v.iter().any(|x| x == &address(&expected["marker"]).unwrap_or_default()))
        );
        let refs = query(&file, &json!({"operation":"refs","address":address(&expected["marker"])?}))?;
        assert!(
            refs["data"]["references"]
                .as_array()
                .is_some_and(|v| v.iter().any(|x| x["address"] == address(&expected["reference"]).unwrap_or_default()))
        );
        let calls =
            query(&file, &json!({"operation":"calls","address":address(&expected["symbols"]["_macho_entry"])?}))?;
        assert!(calls["data"]["calls"].as_array().is_some_and(|v| {
            v.iter().any(|x| {
                x["address"] == address(&expected["call"]).unwrap_or_default()
                    && x["target"] == address(&expected["target"]).unwrap_or_default()
            })
        }));
        assert!(c(&file, &address(&expected["symbols"]["_macho_helper"])?)?.contains("return 7;"));
        if name != "basic" {
            assert!(c(&file, &address(&expected["symbols"]["_macho_export_return"])?)?.contains("return 99;"));
            assert!(c(&file, &address(&expected["symbols"]["_macho_hidden"])?)?.contains("return 55;"));
            let pair = c(&file, &address(&expected["symbols"]["_macho_pair"])?)?;
            assert!(pair.contains("unk128_pair"), "{pair}");
            let import = c(&file, &address(&expected["symbols"]["_macho_import"])?)?;
            assert!(import.contains("puts("), "{import}");
            let abort = c(&file, &address(&expected["symbols"]["_macho_abort"])?)?;
            assert!(abort.contains("abort(") && abort.contains("noreturn"), "{abort}");
            let ptrs =
                query(&file, &json!({"operation":"refs","address":address(&expected["symbols"]["_macho_hidden"])?}))?;
            assert!(
                ptrs["data"]["pointer_slots"].as_array().is_some_and(|v| v
                    .iter()
                    .any(|x| x["address"] == address(&expected["callback"]).unwrap_or_default()))
            );
            let symbols = query(&file, &json!({"operation":"strings","text":"_macho_export_return"}))?;
            assert_eq!(symbols["data"]["locations"], json!([]));
        }
    }
    Ok(())
}
#[test]
fn macho_partial_function_coverage_is_explicit() -> Result<(), Error> {
    let file = input("mixed");
    let expected = manifest("mixed")?;
    let result = query(&file, &json!({"operation":"info"}))?;
    assert!(result["warnings"].as_array().is_some_and(|v| v.iter().any(|x| x == "macho_function_coverage_incomplete")));
    assert!(result["data"]["format_details"]["starts_without_fde"].as_u64().is_some_and(|n| n > 0));
    let compact = address(&expected["compact"])?;
    let output = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(file)
        .args(["query", &json!({"operation":"function","address":compact}).to_string()])
        .output()?;
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["error"]["code"], "no_function");
    Ok(())
}

#[test]
fn macho_rejects_wrong_architecture_kind_encryption_and_bad_commands() -> Result<(), Error> {
    let source = std::fs::read(input("basic"))?;
    let temp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("macho-invalid-{}", std::process::id()));
    let check = |bytes: &[u8], code: &str| -> Result<(), Error> {
        std::fs::write(&temp, bytes)?;
        let out = Command::new(env!("CARGO_BIN_EXE_xref"))
            .arg("-b")
            .arg(&temp)
            .args(["query", "{\"operation\":\"info\"}"])
            .output()?;
        let value: Value = serde_json::from_slice(&out.stdout)?;
        assert_eq!(value["error"]["code"], code);
        assert!(!out.status.success());
        Ok(())
    };
    let mut bytes = source.clone();
    bytes[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
    check(&bytes, "unsupported_image")?;
    let mut bytes = source.clone();
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    check(&bytes, "unsupported_image")?;
    let mut bytes = source.clone();
    bytes[36..40].copy_from_slice(&0u32.to_le_bytes());
    check(&bytes, "invalid_image")?;
    let mut bytes = source;
    let mut at = 32;
    while at < bytes.len() {
        let cmd = u32::from_le_bytes(bytes[at..at + 4].try_into()?);
        let size = usize::try_from(u32::from_le_bytes(bytes[at + 4..at + 8].try_into()?))?;
        if cmd == 0x32 {
            bytes[at..at + 4].copy_from_slice(&0x2cu32.to_le_bytes());
            bytes[at + 16..at + 20].copy_from_slice(&1u32.to_le_bytes());
            break;
        }
        at += size;
    }
    check(&bytes, "unsupported_image")?;
    std::fs::remove_file(temp)?;
    Ok(())
}

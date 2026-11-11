/*
 * XRef — End-to-end tests for indirect calls through constant vtables (#168)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use object::{Object, ObjectSymbol};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        // Parallel tests in one process: a counter keeps fixtures from one clock tick apart.
        let seq = {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        };
        let path = std::env::temp_dir().join(format!("xref-vtables-{}-{nonce}-{seq}", std::process::id()));
        fs::create_dir_all(&path)?;
        // A PIE, so the vtables' function pointers are 0 in the file and filled by
        // R_X86_64_RELATIVE relocations; an if-chain rather than a jump table picks one.
        let compile = Command::new("cc")
            .args(["-O2", "-fpie", "-pie", "-fno-jump-tables", "-fno-tree-switch-conversion"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vtables.c"))
            .arg("-o")
            .arg(path.join("vtables"))
            .output()?;
        assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
        let strip = Command::new("objcopy")
            .arg("--strip-all")
            .arg(path.join("vtables"))
            .arg(path.join("vtables.stripped"))
            .output()?;
        assert!(strip.status.success(), "{}", String::from_utf8_lossy(&strip.stderr));
        Ok(Self(path))
    }

    fn symbols(&self) -> Result<BTreeMap<String, u64>, Box<dyn Error>> {
        let data = fs::read(self.0.join("vtables"))?;
        let file = object::File::parse(&*data)?;
        Ok(file.symbols().filter_map(|s| Some((s.name().ok()?.to_owned(), s.address()))).collect())
    }

    fn run(&self, args: &[&str]) -> Result<String, Box<dyn Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_xref"))
            .arg("-b")
            .arg(self.0.join("vtables.stripped"))
            .args(args)
            .output()?;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        Ok(String::from_utf8(output.stdout)?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const HANDLERS: [(&str, Option<&str>); 5] = [
    ("add_one", Some("0xa")),
    ("double_it", Some("0x14")),
    ("negate", Some("0x1e")),
    ("square", Some("0x28")),
    // The default branch falls through every compare: no single condition.
    ("keep", None),
];

#[test]
fn calls_and_c_list_the_five_vtable_targets_with_their_conditions() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let dispatch = format!("{:#x}", symbols["dispatch"]);
    let calls = fixture.run(&["calls", &dispatch])?;
    let c = fixture.run(&["c", &dispatch])?;
    for (handler, value) in HANDLERS {
        let target = format!("{:#x}", symbols[handler]);
        let listed = match value {
            Some(_) => format!("{target} (when "),
            None => target.clone(),
        };
        assert!(calls.contains(&listed), "calls lists {handler}:\n{calls}");
        assert!(c.lines().any(|l| l.contains("/* targets: {") && l.contains(&listed)), "c lists {handler}:\n{c}");
        if let Some(value) = value {
            // The selector's register depends on the compiler (gcc 13 copies it to eax, gcc 15 keeps edi).
            let condition = calls.split(&format!("{target} (when ")).nth(1).and_then(|rest| rest.split(')').next());
            assert!(
                condition.is_some_and(|c| c.ends_with(&format!(" == {value}"))),
                "{handler} with its condition:\n{calls}"
            );
        }
    }
    Ok(())
}

#[test]
fn table_dumps_a_vtable_with_its_relocated_pointer() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    // `first_vtable` holds `&V0`, a relocated pointer `table` resolves too.
    let pointer = fixture.run(&["table", &format!("{:#x}", symbols["first_vtable"]), "--stride", "8"])?;
    let v0 = pointer
        .lines()
        .find_map(|l| l.trim().strip_prefix("+0x00  -> "))
        .and_then(|rest| u64::from_str_radix(rest.split_whitespace().next()?.trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| format!("no pointer to V0:\n{pointer}"))?;
    let text = fixture.run(&["table", &format!("{v0:#x}"), "--stride", "32"])?;
    assert!(text.contains(&format!("record 0 at {v0:#x}")), "{text}");
    assert!(text.contains("  +0x08  0x8\n"), "the size field is plain data:\n{text}");
    assert!(text.contains(&format!("  +0x18  -> {:#x}", symbols["add_one"])), "the call slot is relocated:\n{text}");
    Ok(())
}

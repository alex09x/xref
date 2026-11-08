/*
 * XRef — End-to-end tests for constant call arguments and tags passed to a helper (#151)
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
        let path = std::env::temp_dir().join(format!("xref-callargs-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path)?;
        let binary = path.join("callargs");
        // A jump table for the `describe` switch, as rustc emits for `Display` of a large enum.
        let compile = Command::new("cc")
            .args(["-O2", "-fno-tree-switch-conversion"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/callargs.c"))
            .arg("-o")
            .arg(&binary)
            .output()?;
        assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
        let strip =
            Command::new("objcopy").arg("--strip-all").arg(&binary).arg(path.join("callargs.stripped")).output()?;
        assert!(strip.status.success(), "{}", String::from_utf8_lossy(&strip.stderr));
        Ok(Self(path))
    }

    fn symbols(&self) -> Result<BTreeMap<String, u64>, Box<dyn Error>> {
        let data = fs::read(self.0.join("callargs"))?;
        let file = object::File::parse(&*data)?;
        Ok(file.symbols().filter_map(|s| Some((s.name().ok()?.to_owned(), s.address()))).collect())
    }

    fn run(&self, args: &[&str]) -> Result<String, Box<dyn Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_xref"))
            .arg("-b")
            .arg(self.0.join("callargs.stripped"))
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

/// The producer's tail jump to `h`: the only call or jump in `produce39`.
fn site_in(text: &str, function: u64) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        let ip = u64::from_str_radix(words.next()?.strip_prefix("0x")?, 16).ok()?;
        (words.next()? == "in" && words.next()?.starts_with(&format!("{function:#x}.."))).then_some(ip)
    })
}

#[test]
fn callargs_finds_the_one_call_passing_39_in_r9_and_names_the_helper() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let (h, produce39) = (symbols["h"], symbols["produce39"]);
    let text = fixture.run(&["callargs", "39", "--arg", "r9"])?;
    assert!(
        text.contains(&format!(
            "callee {h:#x}  r9: 1 of 4 call sites pass 0x27; constants there: 0xd ×1, 0xf ×1, 0x10 ×1, 0x27 ×1"
        )),
        "{text}"
    );
    let site = site_in(&text, produce39).ok_or_else(|| format!("no call site in produce39:\n{text}"))?;
    assert!(text.contains("1 call sites pass 0x27 to 1 callee arguments"), "{text}");
    for other in ["produce13", "produce15", "produce16"] {
        assert!(site_in(&text, symbols[other]).is_none(), "{other} passes another status:\n{text}");
    }
    // Without --arg every position is searched; the 39 is still only in r9 of that call.
    let any = fixture.run(&["callargs", "39"])?;
    assert_eq!(site_in(&any, produce39), Some(site), "{any}");
    Ok(())
}

#[test]
fn origin_lists_the_call_passing_the_tag_with_its_argument_position() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let text = fixture.run(&["origin", "job 39 sibling cancelled"])?;
    let expected = format!(
        "in {:#x}  jmp {:#x}  [passed as r9 to {:#x}, stored by {:#x} at",
        symbols["produce39"], symbols["h"], symbols["h"], symbols["h"]
    );
    assert!(text.lines().any(|l| l.starts_with("  argument site ") && l.contains(&expected)), "{expected}\n{text}");
    assert!(text.contains("1 calls passing the tag to a store at its offset"), "{text}");
    // The tag handed on to another function in another register is followed one call deeper.
    let forwarded = fixture.run(&["origin", "job 38 forwarded cancel"])?;
    let expected = format!(
        "in {:#x}  jmp {:#x}  [passed as rdx to {:#x}, stored by {:#x} (passed on as rsi) at",
        symbols["produce38"], symbols["forward"], symbols["forward"], symbols["store_tag"]
    );
    assert!(forwarded.lines().any(|l| l.contains(&expected)), "{expected}\n{forwarded}");
    Ok(())
}

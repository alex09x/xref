/*
 * XRef — macOS tests: arm64 images for profiles, and `live profile` through `sample`
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::process::{Command, Stdio};
use std::time::Duration;

const SOURCE: &str = r"
#include <string.h>
static char buf[65536];
__attribute__((noinline)) unsigned long spin_hot(unsigned long n) {
    unsigned long s = 0; for (unsigned long i = 0; i < n; i++) s += i * i ^ (s >> 3); return s;
}
__attribute__((noinline)) void zero(int v) { memset(buf, v, sizeof buf); }
int main(void) { volatile unsigned long k = 0; for (int r = 0;; r++) { k += spin_hot(200000); zero(r); } }
";

fn build(dir: &std::path::Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let (source, binary) = (dir.join("spin.c"), dir.join("spin"));
    std::fs::write(&source, SOURCE)?;
    assert!(Command::new("cc").args(["-O0", "-g"]).arg(&source).arg("-o").arg(&binary).status()?.success());
    Ok(binary)
}

fn scratch(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[test]
fn an_arm64_executable_is_read_for_its_functions() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::consts::ARCH != "aarch64" {
        return Ok(());
    }
    let dir = scratch("arm64-image")?;
    let binary = build(&dir)?;
    let image = crate::image::Image::load_for_profile(&binary)?;
    assert!(image.metadata.arm64);
    let hot = image.symbols.iter().find(|(_, name)| name == "spin_hot").ok_or("no spin_hot symbol")?.0;
    let range = image.function_at(hot + 4).ok_or("no function range")?;
    assert_eq!(range.start, hot, "a function ends where the next one starts");
    assert!(crate::macho::arm64::uuid(&image.data).is_some());
    // The x86-64 loader still refuses it.
    assert!(crate::image::Image::load(&binary).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn a_recording_needs_matching_uuids_on_both_sides() -> Result<(), Box<dyn std::error::Error>> {
    let report = super::sample_text::parse(
        "Load Address:    0x100000000\nCall graph:\n    1 Thread_1\n    + 1 main  (in spin) + 4  [0x100000004]\n\nBinary Images:\n       0x100000000 -        0x100003fff +spin (0) /tmp/spin\n",
    );
    // No UUID in the report, and none in the (empty) image: no proof of identity.
    let error = super::macos::recording(&report, &crate::image::Image::default(), std::path::Path::new("spin"), 7)
        .err()
        .unwrap_or_default();
    assert!(error.contains("binary_unverified"), "{error}");
    Ok(())
}

#[test]
#[ignore = "runs /usr/bin/sample on a child process"]
fn live_profile_records_a_running_process_through_sample() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser;
    let dir = scratch("macos-sample")?;
    let binary = build(&dir)?;
    let mut child = Command::new(&binary).stdout(Stdio::null()).spawn()?;
    std::thread::sleep(Duration::from_millis(200));
    let pid = child.id().to_string();
    let cli = crate::cli::Cli::try_parse_from(["xref", "live", "profile", "--pid", &pid, "--duration", "1s", "--json"]);
    let result = (|| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let Ok(crate::cli::Cli { command: crate::cli::Command::Live(command), .. }) = cli else {
            return Err("parse".into());
        };
        let crate::live::cli::LiveSubcommand::Profile(args) = command.subcommand else {
            return Err("not profile".into());
        };
        let mut output = Vec::new();
        super::macos::run(Some(&binary), &args, &mut output)?;
        Ok(serde_json::from_slice(&output)?)
    })();
    let _ = child.kill();
    let _ = child.wait();
    let report = result?;
    let functions = report["report"]["functions"].as_array().ok_or("functions")?;
    let top = functions.first().ok_or("no functions")?;
    assert_eq!(top["label"], "target:spin_hot", "{report}");
    assert!(top["self_percent"].as_f64().unwrap_or(0.0) > 80.0, "{top}");
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

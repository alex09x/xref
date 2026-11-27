/*
 * XRef — privileged test: `live alloc` attributes malloc, calloc, realloc and free to call sites
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::process::{Command, Stdio};
use std::time::Duration;

/// Per round: ten 64-byte blocks allocated and freed, one 16-byte block kept, one buffer grown.
const SOURCE: &str = r"
#include <stdlib.h>
#include <unistd.h>
static void *volatile kept[1 << 20];
static int count;
void *volatile sink;
__attribute__((noinline, noipa)) void alloc_row(void) { char *p = malloc(64); sink = p; free(p); }
__attribute__((noinline, noipa)) void keep_style(void) { if (count < (1 << 20)) kept[count++] = calloc(1, 16); }
__attribute__((noinline, noipa)) void grow_buffer(void) {
    static char *buffer; static size_t size = 16;
    size = size < (1 << 20) ? size * 2 : 16;
    buffer = realloc(buffer, size);
    sink = buffer;
}
int main(void) { for (;;) { for (int i = 0; i < 10; i++) alloc_row(); keep_style(); grow_buffer(); usleep(1000); } }
";

struct Killed(std::process::Child, std::path::PathBuf);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

#[test]
#[ignore = "requires root (uprobes)"]
fn allocations_are_counted_by_call_site_with_live_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-alloc-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (source, binary) = (dir.join("allocs.c"), dir.join("allocs"));
    std::fs::write(&source, SOURCE)?;
    // -O0 -fno-builtin: the compiler must not drop a malloc/free pair it can see through.
    let built = Command::new("cc").args(["-O0", "-fno-builtin", "-g"]).arg(&source).arg("-o").arg(&binary).status()?;
    assert!(built.success());
    let guard = Killed(Command::new(&binary).stdout(Stdio::null()).spawn()?, dir);
    std::thread::sleep(Duration::from_millis(100));
    let args = super::alloc::AllocArgs {
        allocator: None,
        pid: guard.0.id(),
        duration: Duration::from_millis(1000),
        stack_bytes: 4096,
        out: None,
        top: 20,
        json: true,
    };
    let mut output = Vec::new();
    super::alloc::run(Some(&binary), &args, &mut output)?;
    let report: serde_json::Value = serde_json::from_slice(&output)?;
    let function = |name: &str| -> Result<(u64, u64, u64), String> {
        let rows = report["functions"].as_array().ok_or("functions")?;
        let row = rows
            .iter()
            .find(|row| row["frames"][0] == format!("target:{name}"))
            .ok_or_else(|| format!("no {name}: {report}"))?;
        let field = |key: &str| row[key].as_u64().unwrap_or(0);
        Ok((field("allocations"), field("bytes"), field("live_bytes")))
    };
    let (rows, row_bytes, row_live) = function("alloc_row")?;
    let (styles, style_bytes, style_live) = function("keep_style")?;
    let (grows, _, grow_live) = function("grow_buffer")?;
    assert!(styles >= 100, "a round per millisecond: {styles}");
    assert!(rows.abs_diff(10 * styles) <= 20, "ten rows per style: {rows} vs {styles}");
    // The capture may end between a row's malloc and its free: one block can be in flight.
    assert_eq!(row_bytes, rows * 64);
    assert!(row_live <= 64, "every row block is freed but one in flight: {row_live}");
    assert_eq!((style_bytes, style_live), (styles * 16, styles * 16), "every style block is kept");
    assert!(grows.abs_diff(styles) <= 2, "{grows}");
    assert!(grow_live <= 1 << 20, "only the current buffer is live: {grow_live}");
    assert_eq!(report["capture"]["undecoded"], 0);
    drop(guard);
    Ok(())
}

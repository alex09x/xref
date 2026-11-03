/*
 * XRef — Standalone Rust target process fixture for live analysis E2E tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Compiled at test time with `rustc --edition 2021 -O -C strip=symbols` to produce a real,
//! stripped x86-64 PIE Rust executable holding dynamic values, function pointers, `.rodata`
//! references, a `dyn Trait` vtable, and writable `.data` state in live memory.

use std::hint::black_box;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};

static VAULT_BANNER: &[u8; 28] = b"XREF_VAULT_ENGINE_ACTIVE_v1\0";

#[repr(C, align(8))]
struct GlobalVaultSlot([AtomicU64; 3]);

static GLOBAL_SLOT: GlobalVaultSlot = GlobalVaultSlot([
    AtomicU64::new(0x1111_2222_3333_4444),
    AtomicU64::new(0x5555_6666_7777_8888),
    AtomicU64::new(0x9999_aaaa_bbbb_cccc),
]);

trait VaultPolicy {
    fn audit_tag(&self, x: u64) -> u64;
}

struct HmacPolicy {
    salt: Box<u64>,
}

impl VaultPolicy for HmacPolicy {
    #[inline(never)]
    fn audit_tag(&self, x: u64) -> u64 {
        (*self.salt ^ x).wrapping_add(0x4242_9999)
    }
}

#[inline(never)]
fn vault_mix_secret(input: u64, factor: u64) -> u64 {
    (input ^ 0x517c_c1b7_2722_0a95).wrapping_add(factor.wrapping_mul(0x1337))
}

#[repr(C)]
struct VaultRecord {
    magic0: u64,
    magic1: u64,
    live_secret: u64,
    mix_fn: fn(u64, u64) -> u64,
    banner: *const u8,
    policy: Box<dyn VaultPolicy>,
}

#[cfg(target_os = "linux")]
fn allow_sibling_ptrace() {
    const PR_SET_PTRACER: i32 = 0x5961_6d61;
    extern "C" {
        fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
    }
    // Allow non-root test runner subprocesses (`xref live ...`) to inspect this fixture's
    // `/proc/<pid>/mem` on hosts with Yama `ptrace_scope = 1`.
    unsafe {
        let _ = prctl(PR_SET_PTRACER, usize::MAX, 0, 0, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn allow_sibling_ptrace() {}

fn main() {
    allow_sibling_ptrace();
    // Force `std::backtrace` symbolization init, which on Linux mmaps `/proc/self/exe` read-only.
    let _bt = black_box(std::backtrace::Backtrace::force_capture());

    let seed = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(987_654_321);

    let magic0 = black_box(0x5852_4546_4c49_5645_u64) ^ seed.rotate_left(17);
    let magic1 = black_box(0x2026_1102_cafe_f00d_u64) ^ seed.rotate_right(11);
    let live_secret = vault_mix_secret(seed, 7);
    let global_secret = live_secret ^ 0x00ff_00ff_00ff_00ff;

    GLOBAL_SLOT.0[0].store(magic0, Ordering::SeqCst);
    GLOBAL_SLOT.0[1].store(magic1, Ordering::SeqCst);
    GLOBAL_SLOT.0[2].store(global_secret, Ordering::SeqCst);

    let policy: Box<dyn VaultPolicy> = Box::new(HmacPolicy {
        salt: Box::new(seed ^ 0xdead_c0de_1234_5678),
    });
    let tag_check = policy.audit_tag(live_secret);

    let record = black_box(Box::new(VaultRecord {
        magic0,
        magic1,
        live_secret,
        mix_fn: vault_mix_secret,
        banner: VAULT_BANNER.as_ptr(),
        policy,
    }));

    let pid = std::process::id();
    let record_va = (&*record as *const VaultRecord) as usize;
    let global_va = (&GLOBAL_SLOT as *const GlobalVaultSlot) as usize;
    let fn_va = (record.mix_fn as *const ()) as usize;

    println!(
        "READY pid={pid} magic0={magic0:#x} magic1={magic1:#x} secret={live_secret:#x} \
         global_secret={global_secret:#x} tag={tag_check:#x} heap_va={record_va:#x} \
         global_va={global_va:#x} fn_va={fn_va:#x}"
    );
    let _ = io::stdout().flush();

    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    black_box((&record, &GLOBAL_SLOT, tag_check));
}

/*
 * XRef — Interactive stripped Rust daemon fixture for blind reverse-engineering + live RAM E2E tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Compiled at test time with `rustc --edition 2021 -O -C strip=symbols`.
//! Runs as a stateful background daemon that prints ONLY `DAEMON_READY pid=<pid>` (leaking zero
//! addresses, magic numbers, function pointers, or secrets) and mutates heap + `.data` memory in
//! response to live stdin commands (`DEPOSIT <acct> <amount>`, `ROTATE <epoch_key>`, `QUIT`).

use std::hint::black_box;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};

static DAEMON_BANNER: &[u8; 28] = b"XREF_DAEMON_VAULT_ACTIVE_V2\0";
static OP_DEPOSIT_TAG: &str = "DAEMON_OP_DEPOSIT_V2";
static OP_ROTATE_TAG: &str = "DAEMON_OP_ROTATE_V2";

const SIG_HI: u64 = 0x4441_454d_4f4e_5632; // "DAEMONV2"
const SIG_LO: u64 = 0x7788_99aa_bbcc_ddee;
const INITIAL_EPOCH_KEY: u64 = 0x0042_0042;

#[repr(C, align(8))]
struct GlobalLedgerMirror([AtomicU64; 6]);

static GLOBAL_LEDGER: GlobalLedgerMirror = GlobalLedgerMirror([
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
]);

trait AuditEngine {
    fn compute_mac(&self, seq: u64, sealed: u64) -> u64;
}

struct SipAuditEngine {
    pepper: Box<u64>,
}

impl AuditEngine for SipAuditEngine {
    #[inline(never)]
    fn compute_mac(&self, seq: u64, sealed: u64) -> u64 {
        (*self.pepper ^ sealed).wrapping_add(seq.wrapping_mul(0x55aa_77cc))
    }
}

#[inline(never)]
fn fast_seal_hook(balance: u64, epoch_key: u64) -> u64 {
    (balance ^ 0x1357_9bdf_2468_ace0).wrapping_add(epoch_key.wrapping_mul(0x31337))
}

#[inline(never)]
fn strict_seal_hook(balance: u64, epoch_key: u64) -> u64 {
    (balance.rotate_left(13) ^ 0xfedc_ba98_7654_3210).wrapping_add(epoch_key.wrapping_mul(0x7331))
}

#[repr(C)]
struct DaemonVault {
    signature_hi: u64,
    signature_lo: u64,
    tx_seq: u64,
    account_id: u64,
    raw_balance: u64,
    sealed_balance: u64,
    epoch_key: u64,
    commit_hook: fn(u64, u64) -> u64,
    tag_banner: *const u8,
    auditor: Box<dyn AuditEngine>,
    last_mac: u64,
    op_label_ptr: *const u8,
}

impl DaemonVault {
    fn new() -> Box<Self> {
        Box::new(Self {
            signature_hi: 0,
            signature_lo: 0,
            tx_seq: 0,
            account_id: 0,
            raw_balance: 0,
            sealed_balance: 0,
            epoch_key: INITIAL_EPOCH_KEY,
            commit_hook: fast_seal_hook,
            tag_banner: DAEMON_BANNER.as_ptr(),
            auditor: Box::new(SipAuditEngine {
                pepper: Box::new(0xface_b00c_dead_beef),
            }),
            last_mac: 0,
            op_label_ptr: std::ptr::null(),
        })
    }

    fn sync_global(&self) {
        GLOBAL_LEDGER.0[0].store(self.signature_hi, Ordering::SeqCst);
        GLOBAL_LEDGER.0[1].store(self.signature_lo, Ordering::SeqCst);
        GLOBAL_LEDGER.0[2].store(self.tx_seq, Ordering::SeqCst);
        GLOBAL_LEDGER.0[3].store(self.account_id, Ordering::SeqCst);
        GLOBAL_LEDGER.0[4].store(self.raw_balance, Ordering::SeqCst);
        GLOBAL_LEDGER.0[5].store(self.sealed_balance, Ordering::SeqCst);
    }
}

#[inline(never)]
fn execute_deposit(vault: &mut DaemonVault, account_id: u64, amount: u64) -> u64 {
    vault.op_label_ptr = black_box(OP_DEPOSIT_TAG.as_ptr());
    vault.signature_hi = black_box(SIG_HI);
    vault.signature_lo = black_box(SIG_LO);
    vault.tx_seq = vault.tx_seq.wrapping_add(1);
    vault.account_id = account_id;
    vault.raw_balance = vault.raw_balance.wrapping_add(amount);
    vault.sealed_balance = (vault.commit_hook)(vault.raw_balance, vault.epoch_key);
    vault.last_mac = vault.auditor.compute_mac(vault.tx_seq, vault.sealed_balance);
    vault.sync_global();
    vault.tx_seq
}

#[inline(never)]
fn execute_rotate(vault: &mut DaemonVault, new_epoch_key: u64) -> u64 {
    vault.op_label_ptr = black_box(OP_ROTATE_TAG.as_ptr());
    vault.signature_hi = black_box(SIG_HI);
    vault.signature_lo = black_box(SIG_LO);
    vault.tx_seq = vault.tx_seq.wrapping_add(1);
    vault.epoch_key = new_epoch_key;
    vault.commit_hook = strict_seal_hook;
    vault.sealed_balance = (vault.commit_hook)(vault.raw_balance, vault.epoch_key);
    vault.last_mac = vault.auditor.compute_mac(vault.tx_seq, vault.sealed_balance);
    vault.sync_global();
    vault.tx_seq
}

#[cfg(target_os = "linux")]
fn allow_sibling_ptrace() {
    const PR_SET_PTRACER: i32 = 0x5961_6d61;
    extern "C" {
        fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
    }
    unsafe {
        let _ = prctl(PR_SET_PTRACER, usize::MAX, 0, 0, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn allow_sibling_ptrace() {}

fn parse_u64_token(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    }
}

fn main() {
    allow_sibling_ptrace();
    let mut vault = black_box(DaemonVault::new());

    println!("DAEMON_READY pid={}", std::process::id());
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    for line_res in stdin.lock().lines() {
        let Ok(line) = line_res else { break };
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["DEPOSIT", acct_str, amount_str] => {
                if let (Some(acct), Some(amount)) = (parse_u64_token(acct_str), parse_u64_token(amount_str)) {
                    let seq = execute_deposit(&mut vault, acct, amount);
                    println!("ACK op=DEPOSIT seq={seq}");
                } else {
                    println!("ERR invalid DEPOSIT args");
                }
            }
            ["ROTATE", key_str] => {
                if let Some(new_key) = parse_u64_token(key_str) {
                    let seq = execute_rotate(&mut vault, new_key);
                    println!("ACK op=ROTATE seq={seq}");
                } else {
                    println!("ERR invalid ROTATE arg");
                }
            }
            ["PING"] => {
                println!("PONG seq={}", vault.tx_seq);
            }
            ["QUIT"] => {
                println!("BYE seq={}", vault.tx_seq);
                let _ = io::stdout().flush();
                break;
            }
            _ => {
                println!("ERR unknown command");
            }
        }
        let _ = io::stdout().flush();
    }
    black_box((&vault, &GLOBAL_LEDGER));
}

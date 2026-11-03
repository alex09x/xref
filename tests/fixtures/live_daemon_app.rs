/*
 * XRef — Interactive stripped Rust daemon fixture for blind reverse-engineering + live RAM/probe E2E tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Compiled at test time with `rustc --edition 2021 -O -C strip=symbols`.
//! Runs as a stateful background daemon that prints ONLY `DAEMON_READY pid=<pid>` (leaking zero
//! addresses, magic numbers, function pointers, or secrets) and mutates heap + `.bss` memory in
//! response to live stdin commands:
//! - `DEPOSIT <acct> <amount>`
//! - `ROTATE <epoch_key>`
//! - `WORKER_PREPARE`, `WORKER_RUN <count>`, `WORKER_SHORT <count>`, `FORK_CHILD <count>`
//! - `PING`, `QUIT`

use std::hint::black_box;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

static DAEMON_BANNER: &[u8; 28] = b"XREF_DAEMON_VAULT_ACTIVE_V2\0";
static OP_DEPOSIT_TAG: &str = "DAEMON_OP_DEPOSIT_V2";
static OP_ROTATE_TAG: &str = "DAEMON_OP_ROTATE_V2";

#[repr(C, align(8))]
struct AlignedSliceBytes(std::cell::UnsafeCell<[u8; 19]>);
unsafe impl Sync for AlignedSliceBytes {}
static RICH_SLICE_BYTES: AlignedSliceBytes =
    AlignedSliceBytes(std::cell::UnsafeCell::new(*b"XREF\0UTF8_\xF0\x9F\x94\xA5_END!"));

const SIG_HI: u64 = 0x4441_454d_4f4e_5632; // "DAEMONV2"
const SIG_LO: u64 = 0x7788_99aa_bbcc_ddee;
const EXT_SIG_HI: u64 = 0x5852_4546_5459_5045; // "XREFTYPE"
const EXT_SIG_LO: u64 = 0x1122_3344_5566_7788;
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

#[no_mangle]
#[inline(never)]
pub extern "C" fn xref_abi_anchor(acct: u64, amount: u64, seq: u64) -> u64 {
    black_box(acct ^ amount.rotate_left(7) ^ seq)
}

#[repr(C, u64)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
enum VaultCommandEnum {
    Idle = 0,
    Deposit { acct: u64, amount: u64, fee_bps: u32, flags: u32 } = 1,
    Rotate { old_key: u64, new_key: u64, reason_code: u64 } = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FeePolicy {
    base_fee_u32: u32,
    tier_u16: u16,
    active_u8: u8,
    mode_u8: u8,
    multiplier_i64: i64,
    rate_f32: f32,
    pad_u32: u32,
     precise_f64: f64,
}

#[repr(C)]
struct RichTypeMirror {
    ext_sig_hi: u64,
    ext_sig_lo: u64,
    cmd_enum: VaultCommandEnum, // 32 bytes: tag (u64) + 3 * u64 payload
    policy: FeePolicy,          // 32 bytes: packed u32/u16/u8/u8 + i64 + f32/u32 + f64
    vec_ptr: *const u64,        // explicit repr(C) snapshot of Vec<u64> (ptr, cap, len)
    vec_cap: usize,
    vec_len: usize,
    slice_ptr: *const u8,       // explicit repr(C) snapshot of &[u8] with embedded NUL + UTF-8
    slice_len: usize,
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

struct DaemonState {
    vault: Box<DaemonVault>,
    rich: Box<RichTypeMirror>,
    tx_history: Vec<u64>,
    prepared_worker: Option<(SyncSender<u64>, Receiver<u64>, JoinHandle<()>)>,
}

impl DaemonState {
    fn new() -> Self {
        let vault = Box::new(DaemonVault {
            signature_hi: 0,
            signature_lo: 0,
            tx_seq: 0,
            account_id: 0,
            raw_balance: 0,
            sealed_balance: 0,
            epoch_key: INITIAL_EPOCH_KEY,
            commit_hook: fast_seal_hook,
            tag_banner: DAEMON_BANNER.as_ptr(),
            auditor: Box::new(SipAuditEngine { pepper: Box::new(0xface_b00c_dead_beef) }),
            last_mac: 0,
            op_label_ptr: std::ptr::null(),
        });
        let rich = Box::new(RichTypeMirror {
            ext_sig_hi: EXT_SIG_HI,
            ext_sig_lo: EXT_SIG_LO,
            cmd_enum: VaultCommandEnum::Idle,
            policy: FeePolicy {
                base_fee_u32: 0,
                tier_u16: 0,
                active_u8: 0,
                mode_u8: 0,
                multiplier_i64: -1,
                rate_f32: 0.25_f32,
                pad_u32: 0,
                precise_f64: -123.875_f64,
            },
            vec_ptr: std::ptr::null(),
            vec_cap: 0,
            vec_len: 0,
            slice_ptr: RICH_SLICE_BYTES.0.get().cast::<u8>(),
            slice_len: 19,
        });
        Self { vault, rich, tx_history: Vec::new(), prepared_worker: None }
    }

    fn sync_rich(&mut self, cmd: VaultCommandEnum, policy: FeePolicy, history_entry: u64) {
        self.tx_history.push(history_entry);
        self.rich.cmd_enum = black_box(cmd);
        self.rich.policy = black_box(policy);
        self.rich.vec_len = self.tx_history.len();
        self.rich.vec_cap = self.tx_history.capacity();
        self.rich.vec_ptr = if self.tx_history.is_empty() { std::ptr::null() } else { self.tx_history.as_ptr() };
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
    let _ = xref_abi_anchor(account_id, amount, vault.tx_seq);
    sync_global(vault);
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
    let _ = xref_abi_anchor(0, new_epoch_key, vault.tx_seq);
    sync_global(vault);
    vault.tx_seq
}

fn sync_global(vault: &DaemonVault) {
    GLOBAL_LEDGER.0[0].store(vault.signature_hi, Ordering::SeqCst);
    GLOBAL_LEDGER.0[1].store(vault.signature_lo, Ordering::SeqCst);
    GLOBAL_LEDGER.0[2].store(vault.tx_seq, Ordering::SeqCst);
    GLOBAL_LEDGER.0[3].store(vault.account_id, Ordering::SeqCst);
    GLOBAL_LEDGER.0[4].store(vault.raw_balance, Ordering::SeqCst);
    GLOBAL_LEDGER.0[5].store(vault.sealed_balance, Ordering::SeqCst);
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

#[cfg(target_os = "linux")]
fn run_fork_child_calls(count: u64) -> i32 {
    extern "C" {
        fn fork() -> i32;
        fn _exit(status: i32) -> !;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    }
    unsafe {
        let pid = fork();
        if pid == 0 {
            for i in 0..count {
                let _ = xref_abi_anchor(0xdead_0000 | i, 0xbeef, i + 1);
            }
            _exit(0);
        }
        let mut status = 0;
        let _ = waitpid(pid, &raw mut status, 0);
        pid
    }
}

#[cfg(not(target_os = "linux"))]
fn allow_sibling_ptrace() {}

#[cfg(not(target_os = "linux"))]
fn run_fork_child_calls(_count: u64) -> i32 {
    -1
}

fn parse_u64_token(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .map_or_else(|| trimmed.parse::<u64>().ok(), |hex| u64::from_str_radix(hex, 16).ok())
}

fn handle_command(state: &mut DaemonState, parts: &[&str]) -> bool {
    match parts {
        ["DEPOSIT", acct_str, amount_str] => {
            if let (Some(acct), Some(amount)) = (parse_u64_token(acct_str), parse_u64_token(amount_str)) {
                let seq = execute_deposit(&mut state.vault, acct, amount);
                state.sync_rich(
                    VaultCommandEnum::Deposit { acct, amount, fee_bps: 25, flags: 0x8000_0001 },
                    FeePolicy {
                        base_fee_u32: u32::MAX,
                        tier_u16: 0x1234,
                        active_u8: 1,
                        mode_u8: 0xff,
                        multiplier_i64: -42_000_000_000,
                        rate_f32: 1.5_f32,
                        pad_u32: 0,
                        precise_f64: 3.125_f64,
                    },
                    (seq << 48) | (amount & 0xffff_ffff_ffff),
                );
                println!("ACK op=DEPOSIT seq={seq}");
            } else {
                println!("ERR invalid DEPOSIT args");
            }
        }
        ["ROTATE", key_str] => {
            if let Some(new_key) = parse_u64_token(key_str) {
                let old_key = state.vault.epoch_key;
                let seq = execute_rotate(&mut state.vault, new_key);
                state.sync_rich(
                    VaultCommandEnum::Rotate { old_key, new_key, reason_code: 0x0102_0304_0506_0708 },
                    FeePolicy {
                        base_fee_u32: 2500,
                        tier_u16: u16::MAX,
                        active_u8: u8::MAX,
                        mode_u8: 2,
                        multiplier_i64: i64::MIN,
                        rate_f32: -0.75_f32,
                        pad_u32: 0,
                        precise_f64: -9999.0625_f64,
                    },
                    (seq << 48) | (new_key & 0xffff_ffff_ffff),
                );
                println!("ACK op=ROTATE seq={seq}");
            } else {
                println!("ERR invalid ROTATE arg");
            }
        }
        ["WORKER_PREPARE"] => {
            let (tx_cmd, rx_cmd) = mpsc::sync_channel::<u64>(1);
            let (tx_done, rx_done) = mpsc::sync_channel::<u64>(1);
            let handle = thread::spawn(move || {
                if let Ok(count) = rx_cmd.recv() {
                    for i in 0..count {
                        let _ = xref_abi_anchor(0x1111, 0x2222, i + 1);
                    }
                    let _ = tx_done.send(count);
                }
            });
            state.prepared_worker = Some((tx_cmd, rx_done, handle));
            println!("ACK op=WORKER_PREPARE");
        }
        ["WORKER_RUN", count_str] => {
            let count = parse_u64_token(count_str).unwrap_or(1);
            if let Some((tx, rx, handle)) = state.prepared_worker.take() {
                let _ = tx.send(count);
                let done = rx.recv().unwrap_or(0);
                let _ = handle.join();
                println!("ACK op=WORKER_RUN count={done}");
            } else {
                println!("ERR no prepared worker");
            }
        }
        ["WORKER_SHORT", count_str] => {
            let count = parse_u64_token(count_str).unwrap_or(1);
            let _ = thread::spawn(move || {
                for i in 0..count {
                    let _ = xref_abi_anchor(0x3333, 0x4444, i + 1);
                }
            })
            .join();
            println!("ACK op=WORKER_SHORT count={count}");
        }
        ["FORK_CHILD", count_str] => {
            let count = parse_u64_token(count_str).unwrap_or(1);
            let child_pid = run_fork_child_calls(count);
            println!("ACK op=FORK_CHILD child_pid={child_pid} count={count}");
        }
        ["PING"] => println!("PONG seq={}", state.vault.tx_seq),
        ["QUIT"] => {
            println!("BYE seq={}", state.vault.tx_seq);
            return false;
        }
        _ => println!("ERR unknown command"),
    }
    true
}

fn main() {
    allow_sibling_ptrace();
    let mut state = black_box(DaemonState::new());
    println!("DAEMON_READY pid={}", std::process::id());
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    for line_res in stdin.lock().lines() {
        let Ok(line) = line_res else { break };
        let parts: Vec<&str> = line.split_whitespace().collect();
        let keep_going = handle_command(&mut state, &parts);
        let _ = io::stdout().flush();
        if !keep_going {
            break;
        }
    }
    black_box((&state.vault, &state.rich, &GLOBAL_LEDGER));
}

// Neutral optimized Rust target for hardware-sampling integration tests.
use std::{io, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}}, thread};

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn profile_rust_hot(mut value: u64) -> u64 {
    for index in 0..10_000_u64 {
        value = value.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(index);
        std::hint::black_box(value);
    }
    value
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn profile_rust_parent(value: u64) -> u64 {
    profile_rust_hot(value).wrapping_add(1)
}

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let observed = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for index in 0..2_u64 {
        let running = Arc::clone(&running);
        let observed = Arc::clone(&observed);
        workers.push(thread::spawn(move || {
            let mut value = index + 1;
            while running.load(Ordering::Relaxed) {
                value = profile_rust_parent(value);
                observed.store(value, Ordering::Relaxed);
            }
        }));
    }
    println!("READY pid={}", std::process::id());
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    running.store(false, Ordering::Relaxed);
    for worker in workers { worker.join().expect("fixture worker"); }
}

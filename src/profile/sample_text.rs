/*
 * XRef — reading the report of macOS `sample`: the call tree and the binary images
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `sample PID SECONDS INTERVAL_MS -file F` writes, per thread, a call tree: each line is a frame
//! with the number of samples whose stack passed through it, its symbol and module, and its
//! address in brackets (a leaf's sampled PC, a caller's return address). A frame's own samples are
//! its count minus its children's. The "Binary Images" list gives every module's load range and
//! UUID, and "Load Address" the main executable's.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

/// A module in the "Binary Images" list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryImage {
    pub start: u64,
    /// Inclusive end.
    pub end: u64,
    pub name: String,
    pub uuid: Option<String>,
    pub path: String,
}

/// One stack and how many samples ended in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stack {
    /// The frame the samples were taken in first, then its callers' return addresses.
    pub ips: Vec<u64>,
    pub samples: u64,
    /// The thread, numbered in the report's order.
    pub thread: u32,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SampleReport {
    pub load_address: Option<u64>,
    pub interval_ms: Option<u64>,
    pub images: Vec<BinaryImage>,
    pub stacks: Vec<Stack>,
}

fn hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()
}

/// The first address of a frame line: `[0x102b54380,0x102b54388]` (several when `sample` merged
/// samples at different offsets of one frame).
fn frame_address(rest: &str) -> Option<u64> {
    let open = rest.rfind('[')?;
    let close = rest[open..].find(']')? + open;
    let inside = &rest[open + 1..close];
    inside.split(',').next().filter(|first| first.trim().starts_with("0x")).and_then(hex)
}

fn image_line(line: &str) -> Option<BinaryImage> {
    let mut words = line.split_whitespace();
    let start = hex(words.next()?)?;
    if words.next()? != "-" {
        return None;
    }
    let end = hex(words.next()?)?;
    let rest: Vec<&str> = words.collect();
    let name = rest.first()?.trim_start_matches('+').to_owned();
    let text = rest.join(" ");
    let uuid = text
        .find('<')
        .and_then(|open| text[open + 1..].find('>').map(|close| text[open + 1..open + 1 + close].to_owned()));
    let path = text.rfind('>').map_or_else(String::new, |close| text[close + 1..].trim().to_owned());
    Some(BinaryImage { start, end, name, uuid, path })
}

struct Open {
    depth: usize,
    ip: Option<u64>,
    count: u64,
    children: u64,
}

/// Emits the own samples of the deepest open frames down to `depth` (exclusive of shallower ones).
fn close_to(open: &mut Vec<Open>, depth: usize, thread: u32, stacks: &mut Vec<Stack>) {
    while open.last().is_some_and(|frame| frame.depth >= depth) {
        let Some(frame) = open.pop() else { break };
        let own = frame.count.saturating_sub(frame.children);
        if own > 0 && frame.ip.is_some() {
            // The frame and its callers, innermost first; the thread line itself has no address.
            let mut ips: Vec<u64> = vec![frame.ip.unwrap_or(0)];
            ips.extend(open.iter().rev().filter_map(|caller| caller.ip));
            stacks.push(Stack { ips, samples: own, thread });
        }
    }
}

/// Parses a `sample` report.
pub fn parse(text: &str) -> SampleReport {
    let mut report = SampleReport::default();
    let mut section = "";
    let mut open: Vec<Open> = Vec::new();
    let mut thread = 0_u32;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Load Address:") {
            report.load_address = hex(value);
            continue;
        }
        if trimmed.starts_with("Analysis of sampling") {
            report.interval_ms =
                trimmed.split_whitespace().skip_while(|word| *word != "every").nth(1).and_then(|n| n.parse().ok());
        }
        if trimmed == "Call graph:" {
            section = "graph";
            continue;
        }
        if trimmed == "Binary Images:" {
            close_to(&mut open, 0, thread, &mut report.stacks);
            section = "images";
            continue;
        }
        if trimmed.starts_with("Total number in stack") || trimmed.starts_with("Sort by top of stack") {
            close_to(&mut open, 0, thread, &mut report.stacks);
            section = "";
            continue;
        }
        match section {
            "graph" => {
                // Depth is where the count starts, after the tree's `+ ! : |` guides.
                let Some(depth) = line.find(|c: char| c.is_ascii_digit()) else { continue };
                let rest = &line[depth..];
                let Some((count, frame)) = rest.split_once(char::is_whitespace) else { continue };
                let Ok(count) = count.parse::<u64>() else { continue };
                close_to(&mut open, depth, thread, &mut report.stacks);
                if let Some(parent) = open.last_mut() {
                    parent.children += count;
                }
                let frame = frame.trim_start();
                if frame.starts_with("Thread_") {
                    thread += 1;
                    open.push(Open { depth, ip: None, count, children: 0 });
                } else {
                    open.push(Open { depth, ip: frame_address(frame), count, children: 0 });
                }
            }
            "images" => {
                if let Some(image) = image_line(trimmed) {
                    report.images.push(image);
                }
            }
            _ => {}
        }
    }
    close_to(&mut open, 0, thread, &mut report.stacks);
    report
}

#[cfg(test)]
mod tests {
    use super::{BinaryImage, parse};

    const REPORT: &str = "Analysis of sampling spin (pid 45111) every 1 millisecond
Process:         spin [45111]
Load Address:    0x102b54000
Code Type:       ARM64

Call graph:
    900 Thread_924905897   DispatchQueue_1: com.apple.main-thread  (serial)
    + 900 start  (in dyld) + 6076  [0x183b36b98]
    +   900 main  (in spin) + 28  [0x102b54380]
    +     600 spin_hot  (in spin) + 20,24  [0x102b54320,0x102b54324]
    +     10 ???  (in spin)  load address 0x102b54000 + 0x330  [0x102b54330]
    +     290 zero  (in spin) + 12  [0x102b54360]
    +       290 _platform_memset  (in libsystem_platform.dylib) + 84  [0x183ee0554]
    5 Thread_924905898
    + 5 __workq_kernreturn  (in libsystem_kernel.dylib) + 8  [0x183e7a3c8]

Total number in stack (recursive counted multiple, when >=5):

Binary Images:
       0x102b54000 -        0x102b543ef +spin (0) <49C46386-1686-390E-B73F-1A35F4A726E3> /tmp/*/spin
       0x183ed8000 -        0x183ee3fff  libsystem_platform.dylib (349) <AAAA0000-1111-2222-3333-444455556666> /usr/lib/system/libsystem_platform.dylib
";

    #[test]
    fn own_samples_are_counts_minus_children_with_their_callers() {
        let report = parse(REPORT);
        assert_eq!(report.load_address, Some(0x1_02b5_4000));
        assert_eq!(report.interval_ms, Some(1));
        let total: u64 = report.stacks.iter().map(|stack| stack.samples).sum();
        assert_eq!(total, 905, "every sample lands in exactly one stack");
        let find = |ip: u64| report.stacks.iter().find(|stack| stack.ips[0] == ip).cloned();
        let hot = find(0x1_02b5_4320).map(|stack| (stack.samples, stack.ips));
        assert_eq!(hot, Some((600, vec![0x1_02b5_4320, 0x1_02b5_4380, 0x1_83b3_6b98])));
        assert_eq!(find(0x1_02b5_4330).map(|stack| stack.samples), Some(10), "a `+` guide is part of the indent");
        assert_eq!(find(0x1_83ee_0554).map(|stack| (stack.samples, stack.ips.len())), Some((290, 4)));
        assert_eq!(find(0x1_02b5_4360), None, "zero has no samples of its own");
        assert_eq!(find(0x1_83e7_a3c8).map(|stack| (stack.samples, stack.thread)), Some((5, 2)));
        assert_eq!(
            report.images[1],
            BinaryImage {
                start: 0x1_83ed_8000,
                end: 0x1_83ee_3fff,
                name: "libsystem_platform.dylib".to_owned(),
                uuid: Some("AAAA0000-1111-2222-3333-444455556666".to_owned()),
                path: "/usr/lib/system/libsystem_platform.dylib".to_owned(),
            }
        );
        assert_eq!(report.images[0].name, "spin");
    }
}

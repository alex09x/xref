/*
 * XRef — function names for shared libraries, the vdso and the kernel in profile reports
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A shared library names its frames from its own `.symtab` and `.dynsym`; a stripped one also
//! from its separate debug file (`/usr/lib/debug/.build-id/..`, `.gnu_debuglink`, or debuginfod
//! when `DEBUGINFOD_URLS` is set), which holds the local names such as
//! `__memset_avx2_unaligned_erms`. Kernel frames are named from `/proc/kallsyms` and `[vdso]`
//! frames from xref's own vdso, both only when the recording was made in the running boot (the
//! capture writes a boot marker mapping), since kernel addresses change with every boot.

use super::types::Mapping;
use object::{Object, ObjectSymbol, SymbolKind};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The path of the marker mapping that records which boot a capture ran in.
pub const BOOT_MARKER_PATH: &str = "[kernel.boot_id]";
/// Default roots searched for separate debug files.
pub const DEBUG_ROOTS: &[&str] = &["/usr/lib/debug"];
const MAX_DEBUG_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_KALLSYMS_BYTES: u64 = 256 * 1024 * 1024;
const DEBUGINFOD_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    start: u64,
    /// 0 when the symbol table gives no size.
    size: u64,
    name: String,
}

/// Function names of one module by static address.
#[derive(Debug, Default)]
pub struct ModuleNames {
    entries: Vec<Entry>,
    /// `reach[i]`: the furthest end (exclusive) of `entries[..=i]`, so a backward search stops as
    /// soon as no earlier symbol can still hold the address.
    reach: Vec<u64>,
    /// Where the names came from: `symtab`, `dynsym`, `debug_file`, `debuginfod`, `kallsyms`, `vdso`.
    pub source: &'static str,
}

/// A candidate name: address, size, rank (lower wins at one address) and the name itself.
type Raw = (u64, u64, u8, String);

impl ModuleNames {
    fn new(mut raw: Vec<Raw>, source: &'static str) -> Self {
        // At one address the full symbol table wins over `.dynsym`, then the shorter name.
        raw.sort_by(|a, b| (a.0, a.2, a.3.len(), &a.3).cmp(&(b.0, b.2, b.3.len(), &b.3)));
        let mut entries: Vec<Entry> = Vec::with_capacity(raw.len());
        for (start, size, _, name) in raw {
            match entries.last_mut() {
                Some(last) if last.start == start => last.size = last.size.max(size),
                _ => entries.push(Entry { start, size, name }),
            }
        }
        let mut furthest = 0_u64;
        let reach = entries
            .iter()
            .map(|entry| {
                furthest = furthest.max(entry.start.saturating_add(entry.size.max(1)));
                furthest
            })
            .collect();
        Self { entries, reach, source }
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The innermost symbol holding `address`: the latest start among the symbols that begin at it
    /// or whose size covers it (a later unsized symbol does not hide an earlier sized one).
    fn containing(&self, address: u64) -> Option<&Entry> {
        let mut index = self.entries.partition_point(|entry| entry.start <= address);
        while index > 0 && self.reach[index - 1] > address {
            index -= 1;
            let entry = &self.entries[index];
            if entry.start == address || address - entry.start < entry.size {
                return Some(entry);
            }
        }
        None
    }

    /// The name of the function starting at `address`, or of the sized symbol that holds it.
    pub fn name_at(&self, address: u64) -> Option<&str> {
        self.containing(address).map(|entry| entry.name.as_str())
    }

    /// The start of the symbol that holds `address`.
    pub fn start_containing(&self, address: u64) -> Option<u64> {
        self.containing(address).map(|entry| entry.start)
    }
}

fn elf_symbols(file: &object::File<'_>, rank: u8, dynamic: bool, bias: u64) -> Vec<Raw> {
    let keep = |symbol: &object::Symbol<'_, '_>| -> Option<Raw> {
        if symbol.kind() != SymbolKind::Text || symbol.address() == 0 || !symbol.is_definition() {
            return None;
        }
        let name = symbol.name().ok().filter(|name| !name.is_empty())?;
        Some((symbol.address().checked_sub(bias)?, symbol.size(), rank, name.to_owned()))
    };
    if dynamic {
        file.dynamic_symbols().filter_map(|s| keep(&s)).collect()
    } else {
        file.symbols().filter_map(|s| keep(&s)).collect()
    }
}

/// Names for a verified shared library: its own symbol tables and, when it has no `.symtab`, the
/// symbol table of its separate debug file; failing that, the implementations an exported IFUNC
/// resolver selects are named after the IFUNC (`memset` for `__memset_avx2_unaligned_erms`).
pub fn for_library(image: &crate::image::Image, path: &str) -> Option<ModuleNames> {
    let file = object::File::parse(image.data.as_slice()).ok()?;
    let mut raw = elf_symbols(&file, 0, false, 0);
    let has_symtab = !raw.is_empty();
    raw.extend(elf_symbols(&file, 1, true, 0));
    let mut source = if has_symtab { "symtab" } else { "dynsym" };
    if !has_symtab {
        let roots: Vec<PathBuf> = DEBUG_ROOTS.iter().map(PathBuf::from).collect();
        if let Some((debug, found)) = debug_symbols(&file, Path::new(path), &roots) {
            raw.extend(debug);
            source = found;
        } else {
            raw.extend(ifunc_implementations(&file, image));
        }
    }
    (!raw.is_empty()).then(|| ModuleNames::new(raw, source))
}

/// `STT_GNU_IFUNC`.
const STT_GNU_IFUNC: u8 = 10;

/// Functions an exported IFUNC resolver returns, named after the IFUNC with the lowest rank, so any
/// real name of the same function wins.
fn ifunc_implementations(file: &object::File<'_>, image: &crate::image::Image) -> Vec<Raw> {
    let mut out = Vec::new();
    for symbol in file.dynamic_symbols() {
        let object::SymbolFlags::Elf { st_info, .. } = symbol.flags() else { continue };
        let Ok(name) = symbol.name() else { continue };
        if st_info & 0xf != STT_GNU_IFUNC || symbol.address() == 0 || name.is_empty() {
            continue;
        }
        let resolver = symbol.address();
        let length =
            image.function_at(resolver).map_or_else(|| symbol.size(), |range| range.end - range.start).clamp(1, 4096);
        let Some(bytes) = image.read(resolver, usize::try_from(length).unwrap_or(0)) else { continue };
        for target in resolver_results(bytes, resolver) {
            if target != resolver && image.function_at(target).is_some_and(|range| range.start == target) {
                out.push((target, 0, 2, name.to_owned()));
            }
        }
    }
    out
}

/// Addresses a resolver can return: a resolver returns its choice in `rax`, so a RIP-relative
/// `lea` counts once its value reaches `rax` (directly, or through `mov`/`cmov` from the register
/// it was loaded into), not when it is only passed to a helper.
fn resolver_results(bytes: &[u8], ip: u64) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
    let mut loaded: std::collections::HashMap<Register, u64> = std::collections::HashMap::new();
    let mut out = Vec::new();
    for instruction in Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE) {
        let cmov = matches!(
            instruction.mnemonic(),
            Mnemonic::Cmova
                | Mnemonic::Cmovae
                | Mnemonic::Cmovb
                | Mnemonic::Cmovbe
                | Mnemonic::Cmove
                | Mnemonic::Cmovg
                | Mnemonic::Cmovge
                | Mnemonic::Cmovl
                | Mnemonic::Cmovle
                | Mnemonic::Cmovne
                | Mnemonic::Cmovno
                | Mnemonic::Cmovnp
                | Mnemonic::Cmovns
                | Mnemonic::Cmovo
                | Mnemonic::Cmovp
                | Mnemonic::Cmovs
        );
        let destination = instruction.op0_register().full_register();
        let value = if instruction.mnemonic() == Mnemonic::Lea && instruction.is_ip_rel_memory_operand() {
            Some(instruction.ip_rel_memory_address())
        } else if instruction.op_count() == 2
            && instruction.op1_kind() == OpKind::Register
            && (instruction.mnemonic() == Mnemonic::Mov || cmov)
        {
            loaded.get(&instruction.op1_register().full_register()).copied()
        } else {
            None
        };
        match value {
            Some(value) if destination == Register::RAX => out.push(value),
            Some(value) if destination != Register::None => {
                loaded.insert(destination, value);
            }
            _ => {
                if destination != Register::None && !cmov {
                    loaded.remove(&destination);
                }
            }
        }
    }
    out
}

/// The `.symtab` names of the separate debug file of `file`, and how it was found.
pub fn debug_symbols(file: &object::File<'_>, path: &Path, roots: &[PathBuf]) -> Option<(Vec<Raw>, &'static str)> {
    let build_id = file.build_id().ok().flatten().filter(|id| id.len() >= 2).map(<[u8]>::to_vec);
    let link = file.gnu_debuglink().ok().flatten().map(|(name, crc)| (name.to_vec(), crc));
    let crc = link.as_ref().map(|(_, crc)| *crc);
    for (candidate, by_build_id) in
        debug_candidates(build_id.as_deref(), link.as_ref().map(|(name, _)| name.as_slice()), path, roots)
    {
        let check = if by_build_id { Check::BuildId } else { Check::Debuglink(crc) };
        if let Some(raw) = read_debug(&candidate, build_id.as_deref(), check) {
            return Some((raw, "debug_file"));
        }
    }
    let id = build_id.as_deref()?;
    let fetched = debuginfod(&crate::trace_analysis::index::hex_bytes(id))?;
    read_debug(&fetched, Some(id), Check::BuildId).map(|raw| (raw, "debuginfod"))
}

/// How a debug file candidate proves it belongs to the library.
#[derive(Clone, Copy)]
enum Check {
    /// Found by build ID: it must carry the same build ID.
    BuildId,
    /// Found by `.gnu_debuglink` name: the CRC must match, or the build IDs when both have one.
    Debuglink(Option<u32>),
}

/// Where gdb looks: `<root>/.build-id/ab/cdef….debug` (found by build ID), then the
/// `.gnu_debuglink` name next to the library, in its `.debug/` directory, and under
/// `<root>/<library dir>/`.
fn debug_candidates(
    build_id: Option<&[u8]>,
    link: Option<&[u8]>,
    path: &Path,
    roots: &[PathBuf],
) -> Vec<(PathBuf, bool)> {
    let mut out = Vec::new();
    if let Some(id) = build_id {
        let hex = crate::trace_analysis::index::hex_bytes(id);
        for root in roots {
            out.push((root.join(".build-id").join(&hex[..2]).join(format!("{}.debug", &hex[2..])), true));
        }
    }
    let name =
        link.and_then(|name| std::str::from_utf8(name).ok()).filter(|name| !name.is_empty() && !name.contains('/'));
    if let (Some(name), Some(dir)) = (name, path.parent()) {
        out.push((dir.join(name), false));
        out.push((dir.join(".debug").join(name), false));
        for root in roots {
            out.push((root.join(dir.strip_prefix("/").unwrap_or(dir)).join(name), false));
        }
    }
    out.retain(|(candidate, _)| candidate != path);
    out
}

/// The `.symtab` of a debug file that `check` proves belongs to the library.
fn read_debug(path: &Path, build_id: Option<&[u8]>, check: Check) -> Option<Vec<Raw>> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_DEBUG_BYTES {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    let debug = object::File::parse(data.as_slice()).ok()?;
    let debug_id = debug.build_id().ok().flatten();
    let same_id = build_id.is_some() && debug_id == build_id;
    let proven = match check {
        Check::BuildId => same_id,
        Check::Debuglink(crc) => same_id || crc.is_some_and(|crc| crc32(&data) == crc),
    };
    if !proven {
        return None;
    }
    let raw = elf_symbols(&debug, 0, false, 0);
    (!raw.is_empty()).then_some(raw)
}

/// CRC-32 (IEEE), the `.gnu_debuglink` checksum.
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0_u32; 256];
    for (index, slot) in table.iter_mut().enumerate() {
        let mut value = u32::try_from(index).unwrap_or(0);
        for _ in 0..8 {
            value = if value & 1 == 1 { 0xedb8_8320 ^ (value >> 1) } else { value >> 1 };
        }
        *slot = value;
    }
    !data.iter().fold(!0_u32, |crc, &byte| table[usize::from(crc.to_le_bytes()[0] ^ byte)] ^ (crc >> 8))
}

/// The debug file of `build_id` from debuginfod, when `DEBUGINFOD_URLS` is set: the client cache
/// first, then `debuginfod-find` (bounded by a timeout).
fn debuginfod(build_id: &str) -> Option<PathBuf> {
    std::env::var("DEBUGINFOD_URLS").ok().filter(|urls| !urls.trim().is_empty())?;
    let cache = std::env::var_os("DEBUGINFOD_CACHE_PATH").map(PathBuf::from).or_else(|| {
        std::env::var_os("XDG_CACHE_HOME")
            .map(|dir| PathBuf::from(dir).join("debuginfod_client"))
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache/debuginfod_client")))
    });
    if let Some(cached) = cache.map(|dir| dir.join(build_id).join("debuginfo")).filter(|path| path.is_file()) {
        return Some(cached);
    }
    let mut child = std::process::Command::new("debuginfod-find")
        .args(["debuginfo", build_id])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(None) if started.elapsed() < DEBUGINFOD_TIMEOUT => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut text = String::new();
    child.stdout.take()?.read_to_string(&mut text).ok()?;
    let path = PathBuf::from(text.trim());
    path.is_file().then_some(path)
}

/// SHA-256 of the running boot's ID.
fn boot_hash() -> Option<String> {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let id = id.trim();
    (!id.is_empty()).then(|| crate::trace_analysis::index::hex_bytes(&Sha256::digest(id.as_bytes())))
}

/// The marker mapping a capture writes (pid 0, never matched by a sample) to record its boot.
#[cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code))]
pub fn boot_marker() -> Option<Mapping> {
    Some(Mapping {
        timestamp_ns: 0,
        pid: 0,
        tid: 0,
        start: 0,
        length: 1,
        file_offset: 0,
        device_major: 0,
        device_minor: 0,
        inode: 0,
        executable: false,
        sha256: Some(boot_hash()?),
        path: BOOT_MARKER_PATH.to_owned(),
    })
}

/// Whether the recording's boot marker names the running boot.
pub fn recorded_in_this_boot(mappings: &[Mapping]) -> bool {
    let Some(current) = boot_hash() else { return false };
    mappings.iter().any(|mapping| {
        mapping.pid == 0 && mapping.path == BOOT_MARKER_PATH && mapping.sha256.as_deref() == Some(&current)
    })
}

/// Kernel text symbols from `kallsyms` text; `None` when the addresses are hidden (all zero).
pub fn parse_kallsyms(text: &str) -> Option<ModuleNames> {
    let mut starts: Vec<(u64, String)> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let kind = fields.next()?;
            let name = fields.next()?;
            // Loadable module text (`name [module]`) can be unloaded and its addresses reused
            // within one boot, so module frames stay unnamed rather than risk another's name.
            let core = fields.next().is_none();
            (address != 0 && core && matches!(kind, "t" | "T")).then(|| (address, name.to_owned()))
        })
        .collect();
    starts.sort_unstable();
    starts.dedup_by_key(|entry| entry.0);
    if starts.is_empty() {
        return None;
    }
    let raw = starts
        .iter()
        .enumerate()
        .map(|(index, (start, name))| {
            // A kernel symbol ends where the next one starts; the gap is bounded so an address
            // past the last one or in unlisted memory is not given a far symbol's name.
            let next = starts.get(index + 1).map_or_else(|| start.saturating_add(4096), |(next, _)| *next);
            (*start, (next - start).min(1 << 20), 0, name.clone())
        })
        .collect();
    Some(ModuleNames::new(raw, "kallsyms"))
}

pub fn kallsyms() -> Option<ModuleNames> {
    let file = std::fs::File::open("/proc/kallsyms").ok()?;
    let mut text = String::new();
    file.take(MAX_KALLSYMS_BYTES).read_to_string(&mut text).ok()?;
    parse_kallsyms(&text)
}

/// Names of xref's own vdso, by offset from its start: the kernel maps one vdso image into every
/// process of a boot.
pub fn own_vdso() -> Option<ModuleNames> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let line = maps.lines().find(|line| line.trim_end().ends_with("[vdso]"))?;
    let (start, end) = line.split_whitespace().next()?.split_once('-')?;
    let (start, end) = (u64::from_str_radix(start, 16).ok()?, u64::from_str_radix(end, 16).ok()?);
    let length = usize::try_from(end.checked_sub(start)?).ok().filter(|len| *len <= 1 << 20)?;
    let mut memory = std::fs::File::open("/proc/self/mem").ok()?;
    memory.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = vec![0; length];
    memory.read_exact(&mut bytes).ok()?;
    let file = object::File::parse(bytes.as_slice()).ok()?;
    let bias = file.segments().map(|segment| object::ObjectSegment::address(&segment)).min().unwrap_or(0);
    let mut raw = elf_symbols(&file, 1, true, bias);
    raw.extend(elf_symbols(&file, 0, false, bias));
    (!raw.is_empty()).then(|| ModuleNames::new(raw, "vdso"))
}

#[cfg(test)]
mod tests {
    use super::{ModuleNames, crc32, parse_kallsyms};

    #[test]
    fn names_prefer_the_full_symbol_table_and_respect_sizes() {
        let names = ModuleNames::new(
            vec![
                (0x100, 0x20, 1, "memset".to_owned()),
                (0x100, 0, 0, "__memset_avx2_unaligned_erms".to_owned()),
                (0x200, 0, 1, "unsized".to_owned()),
            ],
            "symtab",
        );
        assert_eq!(names.name_at(0x100), Some("__memset_avx2_unaligned_erms"));
        assert_eq!(names.name_at(0x11f), Some("__memset_avx2_unaligned_erms"));
        assert_eq!(names.name_at(0x120), None, "past the symbol size");
        assert_eq!(names.name_at(0x200), Some("unsized"));
        assert_eq!(names.start_containing(0x210), None, "an unsized symbol names only its start");
        assert_eq!(names.start_containing(0x110), Some(0x100));
        // An unsized symbol inside a sized one does not hide it.
        let nested =
            ModuleNames::new(vec![(0x100, 0x40, 0, "outer".to_owned()), (0x110, 0, 0, "label".to_owned())], "symtab");
        assert_eq!(nested.name_at(0x120), Some("outer"));
        assert_eq!(nested.name_at(0x110), Some("label"));
        // However many unsized symbols lie between, the sized one still holds the address.
        let mut raw = vec![(0x1000, 0x1000, 0, "big".to_owned())];
        raw.extend((1..=20).map(|i| (0x1000 + i * 0x10, 0, 0, format!("l{i}"))));
        let many = ModuleNames::new(raw, "symtab");
        assert_eq!(many.name_at(0x1f00), Some("big"));
        assert_eq!(many.name_at(0x2000), None);
    }

    #[test]
    fn kallsyms_names_text_and_hides_zeroed_tables() {
        let text = "ffffffff81000000 T _stext\nffffffff81000100 t do_syscall_64\nffffffff82000000 D data\n\
                    ffffffffc0000000 t ext4_read [ext4]\n";
        let names = parse_kallsyms(text).unwrap_or_default();
        assert_eq!(names.name_at(0xffff_ffff_8100_0180), Some("do_syscall_64"));
        assert_eq!(names.name_at(0xffff_ffff_c000_0010), None, "module text can move within a boot");
        assert_eq!(names.name_at(0xffff_ffff_8200_0000), None, "beyond the last text symbol");
        assert!(parse_kallsyms("0000000000000000 T _stext\n0000000000000000 t f\n").is_none());
    }

    #[test]
    fn resolver_results_follow_values_into_rax_but_not_helper_arguments() {
        let code = [
            0x48, 0x8d, 0x15, 0xf9, 0x00, 0x00, 0x00, // lea rdx, [rip+0xf9]   -> 0x1100
            0x48, 0x8d, 0x05, 0xf2, 0x01, 0x00, 0x00, // lea rax, [rip+0x1f2]  -> 0x1200
            0x48, 0x0f, 0x45, 0xc2, // cmovne rax, rdx
            0x48, 0x8d, 0x3d, 0xe7, 0x02, 0x00, 0x00, // lea rdi, [rip+0x2e7]  -> 0x1300 (an argument)
            0xc3, // ret
        ];
        assert_eq!(super::resolver_results(&code, 0x1000), vec![0x1200, 0x1100]);
    }

    #[test]
    fn debuglink_crc_is_ieee_crc32() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }
}

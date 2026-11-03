/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Bounded Linux `/proc/<pid>` handle acquisition, executable auto-loading, and identity rechecks.

#[cfg(any(target_os = "linux", test))]
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
use object::Object;
#[cfg(any(target_os = "linux", test))]
use sha2::{Digest, Sha256};

use crate::api::MAX_IMAGE_BYTES;
use crate::image::Image;
use crate::image_format::Kind;
#[cfg(target_os = "linux")]
use crate::live::procparse::{
    MAX_MAPS_BYTES, MAX_STAT_BYTES, TargetIdentity, compute_pie_slide, parse_maps, parse_stat_starttime,
};
#[cfg(any(target_os = "linux", test))]
use crate::live::types::{BinaryMatch, ProcessMeta, RegionEntry};

pub const ELF_REQUIRED_ERROR: &str = "live Linux procfs inspection requires an x86-64 ELF binary";

pub fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let init_cap = usize::try_from(max_bytes.min(65_536)).unwrap_or(65_536);
    let mut buf = Vec::with_capacity(init_cap);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    if u64::try_from(buf.len()).is_ok_and(|len| len > max_bytes) {
        return Err(format!("{} exceeds {max_bytes}-byte limit", path.display()));
    }
    Ok(buf)
}

pub fn parse_elf_image_bytes(data: Vec<u8>) -> Result<Image, String> {
    if is_macho_magic(&data) {
        return Err(ELF_REQUIRED_ERROR.to_owned());
    }
    let has_elf_magic = data.get(..4) == Some(b"\x7fELF");
    let image = match Image::parse_for_live(data) {
        Ok(img) => img,
        Err(err) => {
            if !has_elf_magic {
                return Err(format!("{ELF_REQUIRED_ERROR}: {err}"));
            }
            return Err(err.to_string());
        }
    };
    if image.metadata.kind != Kind::Elf {
        return Err(ELF_REQUIRED_ERROR.to_owned());
    }
    Ok(image)
}

pub fn load_elf_image(bin: &Path) -> Result<Image, String> {
    let data = read_bounded_file(bin, MAX_IMAGE_BYTES)?;
    parse_elf_image_bytes(data)
}

fn is_macho_magic(data: &[u8]) -> bool {
    let Some(bytes) = data.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
        return false;
    };
    matches!(
        u32::from_be_bytes(bytes),
        0xfeed_facf | 0xcffa_edfe | 0xfeed_face | 0xcefa_edfe | 0xcafe_babe | 0xbeba_feca
    )
}

#[cfg(any(target_os = "linux", test))]
pub struct LiveSession {
    pub image: Image,
    pub process: ProcessMeta,
    pub regions: Vec<RegionEntry>,
    #[cfg(target_os = "linux")]
    pub exe_dev_ino: Option<(u64, u64)>,
}

#[cfg(target_os = "linux")]
pub fn open_session(pid: u32, bin: Option<&Path>, force_bin: bool) -> Result<LiveSession, String> {
    use std::{os::unix::fs::MetadataExt, path::PathBuf};

    let selected_image = match bin {
        Some(path) => Some(load_elf_image(path)?),
        None => None,
    };
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    let stat_before = read_bounded_file(&proc_dir.join("stat"), u64::try_from(MAX_STAT_BYTES).unwrap_or(65_536))?;
    let starttime_ticks = parse_stat_starttime(&stat_before, pid)?;

    let exe_path = proc_dir.join("exe");
    let exe_meta = std::fs::metadata(&exe_path).ok();
    let exe_dev_ino = exe_meta.as_ref().map(|m| (m.dev(), m.ino()));
    let exe_link = std::fs::read_link(&exe_path).ok().map(|p| p.to_string_lossy().into_owned());

    let (image, binary_match, exe_sha256, mut warnings) = if let Some(img) = selected_image {
        match read_bounded_file(&exe_path, MAX_IMAGE_BYTES) {
            Ok(exe_bytes) => {
                let (bm, sha, warns) = verify_binary_bytes(&img, &exe_bytes, force_bin)?;
                (img, bm, Some(sha), warns)
            }
            Err(err) if force_bin => {
                (img, BinaryMatch::ForcedMismatch, None, vec![format!("forced_unverified_exe: {err}")])
            }
            Err(err) => return Err(format!("{err} (pass --force-bin)")),
        }
    } else {
        let exe_bytes = read_bounded_file(&exe_path, MAX_IMAGE_BYTES)?;
        let sha = sha256_hex(&exe_bytes);
        let img = parse_elf_image_bytes(exe_bytes)?;
        (img, BinaryMatch::ProcExeAuto, Some(sha), Vec::new())
    };
    for &warn in &image.metadata.warnings {
        push_unique_warning(&mut warnings, warn);
    }

    let dev_major_minor = exe_meta.as_ref().map(|m| {
        let d = m.dev();
        (((d >> 8) & 0xfff) | ((d >> 32) & !0xfff), (d & 0xff) | ((d >> 12) & !0xff))
    });
    let target = TargetIdentity { dev_major_minor, inode: exe_meta.as_ref().map(MetadataExt::ino), pathname: exe_link };
    if !target.has_verified_file_id() {
        if !force_bin {
            return Err("failed to obtain verified (dev, ino) for procfs exe (pass --force-bin)".to_owned());
        }
        push_unique_warning(&mut warnings, "target_identity_unverified");
    }

    let (mut regions, smaps_ok) = read_consistent_maps_snapshot(&proc_dir, &target)?;
    if !smaps_ok {
        push_unique_warning(&mut warnings, "smaps_unavailable");
    }
    let pie_slide = match compute_pie_slide(&image.metadata.load_segments, &mut regions) {
        Ok(slide) => slide,
        Err(_) if force_bin => {
            warnings.push("pie_slide_unresolved_forced_zero".to_owned());
            0
        }
        Err(err) => return Err(err),
    };

    let mut session = LiveSession {
        image,
        process: ProcessMeta {
            pid,
            starttime_ticks,
            pid_alive_after: true,
            process_changed: false,
            binary_match,
            exe_sha256,
            pie_slide,
            warnings,
        },
        regions,
        exe_dev_ino,
    };
    refresh_session_identity(&mut session);
    Ok(session)
}

#[cfg(all(not(target_os = "linux"), test))]
pub fn open_session(pid: u32, bin: Option<&Path>, _force_bin: bool) -> Result<LiveSession, String> {
    if let Some(path) = bin {
        let _ = load_elf_image(path)?;
    }
    Err(format!("unsupported_platform: live Linux procfs inspection (pid {pid}) requires a Linux x86-64 host"))
}

#[cfg(target_os = "linux")]
pub fn refresh_session_identity(session: &mut LiveSession) {
    use std::{os::unix::fs::MetadataExt, path::PathBuf};

    let proc_dir = PathBuf::from(format!("/proc/{}", session.process.pid));
    let stat_max = u64::try_from(MAX_STAT_BYTES).unwrap_or(65_536);
    let alive = read_bounded_file(&proc_dir.join("stat"), stat_max)
        .ok()
        .and_then(|raw| parse_stat_starttime(&raw, session.process.pid).ok());
    match alive {
        Some(ticks) if ticks == session.process.starttime_ticks => {
            session.process.pid_alive_after = true;
        }
        Some(_) => {
            session.process.pid_alive_after = false;
            session.process.process_changed = true;
            push_unique_warning(&mut session.process.warnings, "pid_reused_during_inspection");
            return;
        }
        None => {
            session.process.pid_alive_after = false;
            push_unique_warning(&mut session.process.warnings, "pid_exited_during_inspection");
            return;
        }
    }
    if let Some(expected_exe) = session.exe_dev_ino {
        let current_exe = std::fs::metadata(proc_dir.join("exe")).ok().map(|m| (m.dev(), m.ino()));
        if current_exe != Some(expected_exe) {
            session.process.process_changed = true;
            push_unique_warning(&mut session.process.warnings, "process_exe_changed_during_inspection");
        }
    }
}

#[cfg(all(not(target_os = "linux"), test))]
pub const fn refresh_session_identity(_session: &mut LiveSession) {}

#[cfg(target_os = "linux")]
fn read_consistent_maps_snapshot(proc_dir: &Path, target: &TargetIdentity) -> Result<(Vec<RegionEntry>, bool), String> {
    let maps_max = u64::try_from(MAX_MAPS_BYTES).unwrap_or(16_777_216);
    let mut last_err = String::new();
    for _ in 0..4 {
        let maps_bytes = read_bounded_file(&proc_dir.join("maps"), maps_max)?;
        let smaps_bytes = read_bounded_file(&proc_dir.join("smaps"), maps_max).ok();
        match parse_maps(&maps_bytes, smaps_bytes.as_deref(), target) {
            Ok(regions) => return Ok((regions, smaps_bytes.is_some())),
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

#[cfg(target_os = "linux")]
fn push_unique_warning(warnings: &mut Vec<String>, tag: &str) {
    if !warnings.iter().any(|w| w == tag) {
        warnings.push(tag.to_owned());
    }
}

#[cfg(target_os = "linux")]
pub fn open_process_mem(pid: u32, expected_starttime: u64) -> Result<File, String> {
    let mem_path = format!("/proc/{pid}/mem");
    let file = File::open(&mem_path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            format!("permission_denied: failed to open {mem_path}: {err}")
        } else {
            format!("failed to open {mem_path}: {err}")
        }
    })?;
    let stat_now =
        read_bounded_file(Path::new(&format!("/proc/{pid}/stat")), u64::try_from(MAX_STAT_BYTES).unwrap_or(65_536))
            .map_err(|e| format!("process_exited: process {pid} exited while opening mem: {e}"))?;
    if parse_stat_starttime(&stat_now, pid)? != expected_starttime {
        return Err(format!("process_changed: pid {pid} was reused before memory scan started"));
    }
    Ok(file)
}

#[cfg(all(not(target_os = "linux"), test))]
pub fn open_process_mem(pid: u32, _expected_starttime: u64) -> Result<File, String> {
    Err(format!("unsupported_platform: opening /proc/{pid}/mem requires a Linux x86-64 host"))
}

#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(any(target_os = "linux", test))]
pub fn verify_binary_bytes(
    image: &Image,
    exe_bytes: &[u8],
    force_bin: bool,
) -> Result<(BinaryMatch, String, Vec<String>), String> {
    let exe_sha = sha256_hex(exe_bytes);
    let exe_build_id =
        object::File::parse(exe_bytes).ok().and_then(|f| f.build_id().ok().flatten().map(<[u8]>::to_vec));
    if let (Some(bin_id), Some(live_id)) = (&image.metadata.build_id, &exe_build_id)
        && !bin_id.is_empty()
        && !live_id.is_empty()
    {
        if bin_id == live_id {
            return Ok((BinaryMatch::VerifiedBuildId, exe_sha, Vec::new()));
        }
        return if force_bin {
            Ok((BinaryMatch::ForcedMismatch, exe_sha, vec!["forced_binary_mismatch".to_owned()]))
        } else {
            Err("binary_mismatch: --bin GNU build-id differs from procfs exe (pass --force-bin)".into())
        };
    }
    if sha256_hex(&image.data) == exe_sha {
        return Ok((BinaryMatch::VerifiedSha256, exe_sha, Vec::new()));
    }
    if force_bin {
        Ok((BinaryMatch::ForcedMismatch, exe_sha, vec!["forced_binary_mismatch".to_owned()]))
    } else {
        Err("binary_mismatch: --bin SHA-256 differs from procfs exe (pass --force-bin)".into())
    }
}

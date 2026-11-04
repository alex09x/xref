/*
 * XRef — Intel PT instruction flow reconstruction tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;

#[test]
fn reference_uncompressed_return() -> Result<(), &'static str> {
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x7d, 0, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23, 0x2d, 5, 0, 0x3d, 6, 0, 1]);
    let observations = decode(&trace, &[0xe8, 2, 0, 0, 0, 0x90, 0x90, 0xc3], 0x10_0000, false, None)?;
    assert_eq!(observations.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x10_0000, 0x10_0007, 0x10_0005]);
    assert_eq!(observations[0].return_addresses.as_slice(), &[] as &[u64]);
    assert_eq!(observations[1].return_addresses, [0x10_0005]);
    assert_eq!(observations[2].return_addresses.as_slice(), &[] as &[u64]);
    let mixed = decode(&trace, &[0xe8, 2, 0, 0, 0, 0x90, 0x90, 0xc3], 0x10_0000, true, None)?;
    assert_eq!(
        mixed.iter().map(|item| item.ip).collect::<Vec<_>>(),
        [0x10_0000, 0x10_0007, 0x10_0005],
        "TIP-encoded return must work with return compression enabled"
    );
    assert!(observations.iter().all(|item| item.preceding_tsc.is_none()));
    let mut timed = trace.clone();
    timed.splice(27..27, [0x19, 7, 0, 0, 0, 0, 0, 0]);
    let anchors = decode(&timed, &[0xe8, 2, 0, 0, 0, 0x90, 0x90, 0xc3], 0x10_0000, false, None)?;
    assert!(anchors.iter().all(|item| item.preceding_tsc == Some(7)), "TSC is retained only as a preceding anchor");
    assert!(
        decode(&trace[..trace.len() - 1], &[0xe8, 2, 0, 0, 0, 0x90, 0x90, 0xc3], 0x10_0000, false, None).is_err(),
        "unterminated trace must not appear complete"
    );
    assert!(decode(&[2, 0x23], &[], 0, false, None).is_err(), "PSBEND without PSB must fail");
    Ok(())
}

#[test]
fn rejects_unverified_address_space_and_overflow() {
    assert!(decode(&[], &[], 0, false, None).is_err(), "empty trace must not appear complete");
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[2, 0x43, 1, 0, 0, 0, 0, 0, 2, 0x23, 1]);
    assert!(decode(&trace, &[], 0, false, None).is_err(), "PIP requires verified address space");
    trace.truncate(16);
    trace.extend_from_slice(&[2, 0xf3]);
    assert!(decode(&trace, &[], 0, false, None).is_err(), "overflow must not yield complete output");
}

#[test]
fn reference_compressed_return() -> Result<(), &'static str> {
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x7d, 0, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23, 0x0e, 0x3d, 9, 0, 1]);
    let observations = decode(&trace, &[0xe8, 3, 0, 0, 0, 0x74, 2, 0xf4, 0xc3, 0x90], 0x10_0000, true, None)?;
    assert_eq!(observations.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x10_0000, 0x10_0008, 0x10_0005]);
    assert_eq!(observations[1].return_addresses, [0x10_0005]);
    assert_eq!(observations[2].return_addresses.as_slice(), &[] as &[u64]);
    Ok(())
}

#[test]
fn nested_calls_compressed_returns_and_not_taken_branch() -> Result<(), &'static str> {
    // Generated from a neutral assembly program using Intel pttc. The TNT
    // bits are: inner return, outer return, branch not taken.
    let image = [0xe8, 3, 0, 0, 0, 0x75, 8, 0xf4, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3, 0x90];
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x7d, 0, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23, 0x1c, 0x3d, 7, 0, 1]);
    let result = decode(&trace, &image, 0x10_0000, true, None)?;
    assert_eq!(
        result.iter().map(|item| item.ip).collect::<Vec<_>>(),
        [0x10_0000, 0x10_0008, 0x10_000e, 0x10_000d, 0x10_0005]
    );
    assert_eq!(result[2].return_addresses, [0x10_000d, 0x10_0005]);
    assert_eq!(result[3].return_addresses, [0x10_0005]);
    assert_eq!(result[4].return_addresses.as_slice(), &[] as &[u64]);
    Ok(())
}

#[test]
fn indirect_call_and_tip_return_follow_reference_trace() -> Result<(), &'static str> {
    let image = [0xff, 0xd0, 0x90, 0xf4, 0xc3];
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x7d, 0, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23, 0x2d, 4, 0, 0x2d, 2, 0, 0x3d, 3, 0, 1]);
    let result = decode(&trace, &image, 0x10_0000, true, None)?;
    assert_eq!(result.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x10_0000, 0x10_0004, 0x10_0002]);
    assert_eq!(result[1].return_addresses, [0x10_0002]);
    assert_eq!(result[2].return_addresses.as_slice(), &[] as &[u64]);
    Ok(())
}

#[test]
fn tip_pge_starts_trace_after_empty_psb_header() -> Result<(), &'static str> {
    let image = [0xe8, 2, 0, 0, 0, 0x90, 0xf4, 0xc3];
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x99, 1, 2, 0x23, 0x71, 0, 0, 0x10, 0, 0, 0, 6, 0x3d, 6, 0, 1]);
    let observations = decode(&trace, &image, 0x10_0000, true, None)?;
    assert_eq!(observations.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x10_0000, 0x10_0007, 0x10_0005]);
    assert_eq!(observations[1].return_addresses, [0x10_0005]);
    Ok(())
}

#[test]
fn syscall_and_sysenter_end_user_trace_without_a_return_target() -> Result<(), &'static str> {
    for opcode in [0x05, 0x34] {
        let code = [0x90, 0x0f, opcode];
        let mut trace = [2, 0x82].repeat(8);
        trace.extend_from_slice(&[0x99, 1, 2, 0x23, 0x71, 0, 0, 0x10, 0, 0, 0, 0x01]);
        let observations = decode(&trace, &code, 0x10_0000, true, None)?;
        assert_eq!(observations.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x10_0000, 0x10_0001]);
    }
    Ok(())
}

#[test]
fn syscall_disable_with_explicit_ip_stops_at_the_system_boundary() -> Result<(), &'static str> {
    let code = [0x90, 0x0f, 0x05, 0x90, 0xf4];
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x99, 1, 2, 0x23, 0x71, 0, 0, 0x10, 0, 0, 0, 0x21, 3, 0]);
    let observations = decode(&trace, &code, 0x10_0000, true, None)?;
    assert_eq!(observations.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x10_0000, 0x10_0001]);
    let offset = trace.len() - 2;
    trace[offset] = 4;
    assert!(decode(&trace, &code, 0x10_0000, true, None).is_err(), "unverified continuation must fail");
    Ok(())
}

#[test]
fn budget_exhaustion_returns_the_prefix_as_truncated() -> Result<(), &'static str> {
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x99, 1, 2, 0x23, 0x71, 0, 0, 0x10, 0, 0, 0, 0x21, 4, 0]);
    let decoded = decode_with_code(&trace, Code::Bytes(&[0xeb, 0xfe], 0x10_0000), true, None, 2)?;
    assert!(decoded.truncated);
    assert_eq!(decoded.observations.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x10_0000; 2]);
    Ok(())
}

#[test]
fn disabled_trace_does_not_reuse_a_previously_observed_return_stack() {
    let image = [0xff, 0xd0, 0x90, 0xf4, 0xc3];
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x7d, 0, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23]);
    // Indirect call; stop tracing at its callee; restart at a return.
    trace.extend_from_slice(&[0x2d, 4, 0, 0x3d, 4, 0, 1, 0x31, 4, 0, 6, 0x3d, 3, 0, 1]);
    assert!(
        decode(&trace, &image, 0x10_0000, true, None).is_err(),
        "a return after a tracing gap must not use stale stack state"
    );
}

#[test]
fn resynchronizes_on_periodic_psb_without_losing_return_stack() -> Result<(), &'static str> {
    let image = [0xe8, 2, 0, 0, 0, 0x90, 0xf4, 0xc3];
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x7d, 0, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23]);
    trace.extend_from_slice(&[2, 0x82].repeat(8));
    trace.extend_from_slice(&[0x7d, 7, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23, 6, 0x3d, 6, 0, 1]);
    let observations = decode(&trace, &image, 0x10_0000, true, None)?;
    assert_eq!(observations.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x10_0000, 0x10_0007, 0x10_0005]);
    assert_eq!(observations[1].return_addresses, [0x10_0005]);
    assert_eq!(observations[2].return_addresses.as_slice(), &[] as &[u64]);
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[allow(clippy::too_many_lines)] // Exercise decoding and lifecycle against the same compiled image.
fn reference_trace_reconstructs_compiled_elf() -> Result<(), Box<dyn std::error::Error>> {
    use linux_perf_data::{
        RawUserRecord, UserRecord, UserRecordType,
        linux_perf_event_reader::{Endianness, RawData},
    };
    use object::{Object, ObjectSection};
    use std::process::Command;
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("target.S");
    let binary = dir.path().join("target");
    std::fs::write(
        &source,
        ".text\n.global _start\n_start:\n .cfi_startproc\n call target\n jz end\n hlt\ntarget:\n ret\nend:\n nop\n .cfi_endproc\n.section .note.GNU-stack,\"\",@progbits\n",
    )?;
    let status = Command::new("cc")
        .args(["-nostdlib", "-no-pie", "-Wl,-Ttext=0x100000"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()?;
    assert!(status.success(), "ELF compilation failed");
    let file = std::fs::read(&binary)?;
    let object = object::File::parse(file.as_slice())?;
    let section = object.section_by_name(".text").ok_or("missing .text")?;
    assert_eq!(section.address(), 0x10_0000);
    let mut trace = [2, 0x82].repeat(8);
    trace.extend_from_slice(&[0x7d, 0, 0, 0x10, 0, 0, 0, 0x99, 1, 2, 0x23, 0x0e, 0x3d, 9, 0, 1]);
    assert_eq!(
        decode(&trace, section.data()?, section.address(), true, None)?.iter().map(|item| item.ip).collect::<Vec<_>>(),
        [0x10_0000, 0x10_0008, 0x10_0005]
    );
    let image = crate::image::Image::load(&binary)?;
    trace[19] = 0x30;
    assert_eq!(
        decode_image(&trace, &image, 0x20_0000, true, None)?.iter().map(|item| item.ip).collect::<Vec<_>>(),
        [0x30_0000, 0x30_0008, 0x30_0005]
    );
    assert!(decode_image(&trace, &image, 0, true, None).is_err(), "incorrect slide must not map code");
    let mut body = vec![0_u8; 40];
    body[..8].copy_from_slice(&u64::try_from(trace.len())?.to_le_bytes());
    body[28..32].copy_from_slice(&42_u32.to_le_bytes());
    body.extend_from_slice(&trace);
    let aux = RawUserRecord {
        record_type: UserRecordType::PERF_AUXTRACE,
        endian: Endianness::LittleEndian,
        misc: 0,
        data: RawData::from(body.as_slice()),
    };
    let UserRecord::Auxtrace(aux) = aux.parse()? else {
        return Err("expected AUXTRACE".into());
    };
    let mut threads = super::super::pt_aux_identity::Threads::new(42)?;
    threads.advance(1)?;
    assert!(threads.accepts(aux.tid));
    assert!(super::super::pt_aux_identity::intel_pt_info(&[1, 0, 0, 0, 0, 0, 0, 0])?);
    let id = image.metadata.build_id.as_deref().ok_or("compiled ELF lacks build ID")?;
    assert!(super::super::pt_aux_identity::verified_build_id(Some(id), Some(id)));
    let segment = image
        .segments
        .iter()
        .find(|segment| segment.va <= 0x10_0000 && 0x10_0000 - segment.va < u64::try_from(segment.size).unwrap_or(0))
        .ok_or("missing code segment")?;
    let mapping = super::super::types::Mapping {
        timestamp_ns: 1,
        pid: 42,
        tid: 42,
        start: segment.va + 0x20_0000,
        length: u64::try_from(segment.size)?,
        file_offset: u64::try_from(segment.offset)?,
        device_major: 0,
        device_minor: 0,
        inode: 1,
        executable: true,
        sha256: None,
        path: "/target".into(),
    };
    assert!(super::super::pt_aux_identity::mapping_matches(&mapping, &image, 42, 0x20_0000));
    let observations = decode_image(&aux.aux_data.as_slice(), &image, 0x20_0000, true, None)?;
    assert_eq!(observations.iter().map(|item| item.ip).collect::<Vec<_>>(), [0x30_0000, 0x30_0008, 0x30_0005]);
    assert_eq!(observations[1].return_addresses, [0x30_0005]);
    let synthetic = super::super::pt_synthesis::synthesize(&trace, &image, 0x20_0000, 42, 42, true, None)?;
    assert!(synthetic.untimed && synthetic.instruction_events);
    assert_eq!(synthetic.samples.iter().map(|sample| sample.ip).collect::<Vec<_>>(), [0x30_0000, 0x30_0008, 0x30_0005]);
    assert_eq!(synthetic.samples[1].callchain, [0x30_0005]);
    let mut session = super::super::pt_aux_session::Session::new(&image, 0x20_0000, 42, "/target", Some(id))?;
    assert!(session.decode(1, 42, &trace, true).is_err(), "mapping must be established before AUX");
    session.mapping(&mapping)?;
    session.fork(2, 42, 43)?;
    let from_thread = session.decode(3, 43, &trace, true)?;
    assert_eq!(from_thread.samples[1].callchain, [0x30_0005]);
    session.exit(4, 42, 43)?;
    assert!(session.decode(5, 43, &trace, true).is_err(), "exited TID must not be reused");
    session.exec(6, 42)?;
    assert!(session.decode(7, 42, &trace, true).is_err(), "exec must invalidate identity");
    let mut lost = super::super::pt_aux_session::Session::new(&image, 0x20_0000, 42, "/target", Some(id))?;
    lost.mapping(&mapping)?;
    lost.lost();
    assert!(lost.decode(2, 42, &trace, true).is_err(), "sideband loss must invalidate identity");
    let mut other = super::super::pt_aux_session::Session::new(&image, 0x20_0000, 42, "/other", Some(id))?;
    assert!(other.mapping(&mapping).is_err(), "matching geometry from another file must fail");
    let mut overlap = super::super::pt_aux_session::Session::new(&image, 0x20_0000, 42, "/target", Some(id))?;
    overlap.mapping(&mapping)?;
    let mut replacement = mapping.clone();
    replacement.timestamp_ns = 2;
    replacement.path = "/other".into();
    assert!(overlap.other_mapping(&replacement).is_err(), "replacement mapping must invalidate target");
    assert!(overlap.decode(3, 42, &trace, true).is_err(), "replaced target must not be decoded");
    Ok(())
}

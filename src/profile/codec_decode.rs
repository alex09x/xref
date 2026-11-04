/*
 * XRef — profile record decoding
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::types::{Footer, Mapping, Record};
use super::{Cursor, MAX_PATH, invalid};
use crate::profile::codec_sample::decode_sample;
use std::io;

#[allow(clippy::too_many_lines)] // A record tag and its bounded fields are decoded together.
pub(super) fn decode_record(bytes: &[u8]) -> io::Result<Record> {
    let mut cursor = Cursor { bytes, offset: 0 };
    let record = match cursor.u8()? {
        1 => Record::Sample(decode_sample(&mut cursor)?),
        7 => Record::PtInstruction(decode_sample(&mut cursor)?),
        8 => {
            let trigger_ns = cursor.u64()?;
            let end_ns = cursor.u64()?;
            if end_ns <= trigger_ns {
                return Err(invalid("invalid profile window"));
            }
            Record::Window { trigger_ns, end_ns }
        }
        2 => {
            let timestamp_ns = cursor.u64()?;
            let pid = cursor.u32()?;
            let tid = cursor.u32()?;
            let start = cursor.u64()?;
            let length = cursor.u64()?;
            let file_offset = cursor.u64()?;
            if length == 0 || start.checked_add(length).is_none() {
                return Err(invalid("invalid profile mapping"));
            }
            let device_major = cursor.u32()?;
            let device_minor = cursor.u32()?;
            let inode = cursor.u64()?;
            let executable = match cursor.u8()? {
                0 => false,
                1 => true,
                _ => return Err(invalid("invalid mapping permissions")),
            };
            let hash_len = cursor.len(64)?;
            let hash = std::str::from_utf8(cursor.take(hash_len)?).map_err(|_| invalid("invalid module hash"))?;
            if !hash.is_empty() && (hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())) {
                return Err(invalid("invalid module hash"));
            }
            let sha256 = (!hash.is_empty()).then(|| hash.to_owned());
            let path_len = cursor.len(MAX_PATH)?;
            let path =
                std::str::from_utf8(cursor.take(path_len)?).map_err(|_| invalid("invalid mapping path"))?.to_owned();
            Record::Mapping(Mapping {
                timestamp_ns,
                pid,
                tid,
                start,
                length,
                file_offset,
                device_major,
                device_minor,
                inode,
                executable,
                sha256,
                path,
            })
        }
        3 => Record::Lost { timestamp_ns: cursor.u64()?, tid: cursor.u32()?, count: cursor.u64()? },
        4 => Record::Fork {
            timestamp_ns: cursor.u64()?,
            pid: cursor.u32()?,
            tid: cursor.u32()?,
            parent_pid: cursor.u32()?,
            parent_tid: cursor.u32()?,
        },
        5 => Record::Exit { timestamp_ns: cursor.u64()?, pid: cursor.u32()?, tid: cursor.u32()? },
        6 => {
            let timestamp_ns = cursor.u64()?;
            let samples = cursor.u64()?;
            let lost = cursor.u64()?;
            let dropped = cursor.u64()?;
            let partial_coverage = match cursor.u8()? {
                0 => false,
                1 => true,
                _ => return Err(invalid("invalid coverage flag")),
            };
            let trigger_present = match cursor.u8()? {
                0 => false,
                1 => true,
                _ => return Err(invalid("invalid trigger flag")),
            };
            let trigger_value = cursor.u64()?;
            if !trigger_present && trigger_value != 0 {
                return Err(invalid("invalid absent trigger timestamp"));
            }
            let trigger_timestamp_ns = trigger_present.then_some(trigger_value);
            let trigger_lost = cursor.u64()?;
            let reason_len = cursor.len(128)?;
            let stop_reason =
                std::str::from_utf8(cursor.take(reason_len)?).map_err(|_| invalid("invalid stop reason"))?.to_owned();
            if stop_reason.is_empty() {
                return Err(invalid("invalid profile stop reason"));
            }
            Record::End(Footer {
                timestamp_ns,
                samples,
                lost,
                dropped,
                partial_coverage,
                stop_reason,
                trigger_timestamp_ns,
                trigger_lost,
            })
        }
        _ => return Err(invalid("unknown profile record type")),
    };
    if cursor.offset != bytes.len() {
        return Err(invalid("trailing profile record data"));
    }
    Ok(record)
}

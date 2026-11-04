/*
 * XRef — bounded streaming profile record codec
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::{Footer, Header, Mapping, Record};
use crate::profile::codec_sample::decode_sample;
use crate::profile::codec_sample::encode_sample;
use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"XREFPRF1";
const MAX_HEADER: usize = 64 * 1024;
const MAX_RECORD: usize = 1024 * 1024;
pub(super) const MAX_STACK: usize = 64 * 1024;
pub(super) const MAX_FRAMES: usize = 512;
const MAX_PATH: usize = 4096;

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub(super) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
pub(super) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
pub(super) fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
pub(super) fn put_len(out: &mut Vec<u8>, length: usize) -> io::Result<()> {
    put_u32(out, u32::try_from(length).map_err(|_| invalid("profile length overflow"))?);
    Ok(())
}

fn validate_header(header: &Header) -> io::Result<()> {
    if header.schema_version != 1
        || header.image_sha256.len() != 64
        || !header.image_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || header
            .process_exe_sha256
            .as_deref()
            .is_some_and(|hash| hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || header.frequency_hz == Some(0)
        || header.period == Some(0)
        || (header.frequency_hz.is_some() && header.period.is_some())
        || (header.trigger_static_va.is_some() != header.trigger_window_ns.is_some())
        || header.trigger_window_ns == Some(0)
    {
        return Err(invalid("invalid profile header"));
    }
    Ok(())
}

pub struct ProfileWriter<W> {
    out: W,
    scratch: Vec<u8>,
    samples: u64,
    lost: u64,
}
impl<W: Write> ProfileWriter<W> {
    pub fn new(mut out: W, header: &Header) -> io::Result<Self> {
        validate_header(header)?;
        let json = serde_json::to_vec(header).map_err(|_| invalid("cannot encode profile header"))?;
        if json.len() > MAX_HEADER {
            return Err(invalid("profile header too large"));
        }
        out.write_all(MAGIC)?;
        out.write_all(&u32::try_from(json.len()).map_err(|_| invalid("profile header too large"))?.to_le_bytes())?;
        out.write_all(&json)?;
        Ok(Self { out, scratch: Vec::new(), samples: 0, lost: 0 })
    }

    pub fn write_record(&mut self, record: &Record) -> io::Result<()> {
        self.scratch.clear();
        match record {
            Record::Sample(sample) => encode_sample(&mut self.scratch, sample)?,
            Record::Mapping(mapping) => {
                if mapping.length == 0
                    || mapping.start.checked_add(mapping.length).is_none()
                    || mapping.path.len() > MAX_PATH
                {
                    return Err(invalid("invalid profile mapping"));
                }
                self.scratch.push(2);
                put_u64(&mut self.scratch, mapping.timestamp_ns);
                put_u32(&mut self.scratch, mapping.pid);
                put_u32(&mut self.scratch, mapping.tid);
                put_u64(&mut self.scratch, mapping.start);
                put_u64(&mut self.scratch, mapping.length);
                put_u64(&mut self.scratch, mapping.file_offset);
                put_u32(&mut self.scratch, mapping.device_major);
                put_u32(&mut self.scratch, mapping.device_minor);
                put_u64(&mut self.scratch, mapping.inode);
                self.scratch.push(u8::from(mapping.executable));
                let hash = mapping.sha256.as_deref().unwrap_or("");
                if !hash.is_empty() && (hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())) {
                    return Err(invalid("invalid profile module hash"));
                }
                put_len(&mut self.scratch, hash.len())?;
                self.scratch.extend_from_slice(hash.as_bytes());
                put_len(&mut self.scratch, mapping.path.len())?;
                self.scratch.extend_from_slice(mapping.path.as_bytes());
            }
            Record::Lost { timestamp_ns, tid, count } => {
                self.scratch.push(3);
                put_u64(&mut self.scratch, *timestamp_ns);
                put_u32(&mut self.scratch, *tid);
                put_u64(&mut self.scratch, *count);
            }
            Record::Fork { timestamp_ns, pid, tid, parent_pid, parent_tid } => {
                self.scratch.push(4);
                put_u64(&mut self.scratch, *timestamp_ns);
                for value in [pid, tid, parent_pid, parent_tid] {
                    put_u32(&mut self.scratch, *value);
                }
            }
            Record::Exit { timestamp_ns, pid, tid } => {
                self.scratch.push(5);
                put_u64(&mut self.scratch, *timestamp_ns);
                put_u32(&mut self.scratch, *pid);
                put_u32(&mut self.scratch, *tid);
            }
            Record::End(_) => return Err(invalid("use finish to write the profile footer")),
        }
        if self.scratch.len() > MAX_RECORD {
            return Err(invalid("profile record too large"));
        }
        self.out.write_all(
            &u32::try_from(self.scratch.len()).map_err(|_| invalid("profile record too large"))?.to_le_bytes(),
        )?;
        self.out.write_all(&self.scratch)?;
        match record {
            Record::Sample(_) => {
                self.samples = self.samples.checked_add(1).ok_or_else(|| invalid("profile sample count overflow"))?;
            }
            Record::Lost { count, .. } => {
                self.lost = self.lost.checked_add(*count).ok_or_else(|| invalid("profile loss count overflow"))?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn finish(
        mut self,
        timestamp_ns: u64,
        dropped: u64,
        partial_coverage: bool,
        stop_reason: &str,
        trigger_timestamp_ns: Option<u64>,
        trigger_lost: u64,
    ) -> io::Result<W> {
        if stop_reason.is_empty() || stop_reason.len() > 128 {
            return Err(invalid("invalid profile stop reason"));
        }
        self.scratch.clear();
        self.scratch.push(6);
        for value in [timestamp_ns, self.samples, self.lost, dropped] {
            put_u64(&mut self.scratch, value);
        }
        self.scratch.push(u8::from(partial_coverage));
        self.scratch.push(u8::from(trigger_timestamp_ns.is_some()));
        put_u64(&mut self.scratch, trigger_timestamp_ns.unwrap_or(0));
        put_u64(&mut self.scratch, trigger_lost);
        put_len(&mut self.scratch, stop_reason.len())?;
        self.scratch.extend_from_slice(stop_reason.as_bytes());
        self.out.write_all(
            &u32::try_from(self.scratch.len()).map_err(|_| invalid("profile footer too large"))?.to_le_bytes(),
        )?;
        self.out.write_all(&self.scratch)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

pub struct ProfileReader<R> {
    input: R,
    pub header: Header,
    scratch: Vec<u8>,
    samples: u64,
    lost: u64,
    ended: bool,
}
impl<R: Read> ProfileReader<R> {
    pub fn new(mut input: R) -> io::Result<Self> {
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(invalid("unrecognized profile format"));
        }
        let mut length = [0; 4];
        input.read_exact(&mut length)?;
        let length = usize::try_from(u32::from_le_bytes(length)).map_err(|_| invalid("profile header too large"))?;
        if length == 0 || length > MAX_HEADER {
            return Err(invalid("profile header too large"));
        }
        let mut bytes = vec![0; length];
        input.read_exact(&mut bytes)?;
        let header = serde_json::from_slice(&bytes).map_err(|_| invalid("invalid profile header JSON"))?;
        validate_header(&header)?;
        Ok(Self { input, header, scratch: Vec::new(), samples: 0, lost: 0, ended: false })
    }

    pub fn read_record(&mut self) -> io::Result<Option<Record>> {
        let mut length = [0; 4];
        if self.input.read(&mut length[..1])? == 0 {
            return if self.ended {
                Ok(None)
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "profile footer missing"))
            };
        }
        if self.ended {
            return Err(invalid("data follows profile footer"));
        }
        self.input.read_exact(&mut length[1..])?;
        let length = usize::try_from(u32::from_le_bytes(length)).map_err(|_| invalid("profile record too large"))?;
        if length == 0 || length > MAX_RECORD {
            return Err(invalid("invalid profile record length"));
        }
        self.scratch.resize(length, 0);
        self.input.read_exact(&mut self.scratch)?;
        let record = decode_record(&self.scratch)?;
        match &record {
            Record::Sample(_) => {
                self.samples = self.samples.checked_add(1).ok_or_else(|| invalid("profile sample count overflow"))?;
            }
            Record::Lost { count, .. } => {
                self.lost = self.lost.checked_add(*count).ok_or_else(|| invalid("profile loss count overflow"))?;
            }
            Record::End(footer) => {
                if footer.samples != self.samples || footer.lost != self.lost {
                    return Err(invalid("profile footer counts do not match records"));
                }
                self.ended = true;
            }
            _ => {}
        }
        Ok(Some(record))
    }
}

pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    pub(super) fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.offset.checked_add(n).ok_or_else(|| invalid("profile record length overflow"))?;
        let bytes = self.bytes.get(self.offset..end).ok_or_else(|| invalid("truncated profile record"))?;
        self.offset = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(super) fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| invalid("invalid u16"))?))
    }
    pub(super) fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| invalid("invalid u32"))?))
    }
    pub(super) fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| invalid("invalid u64"))?))
    }
    pub(super) fn len(&mut self, cap: usize) -> io::Result<usize> {
        let length = usize::try_from(self.u32()?).map_err(|_| invalid("profile length overflow"))?;
        if length > cap {
            return Err(invalid("profile field exceeds limit"));
        }
        Ok(length)
    }
}

fn decode_record(bytes: &[u8]) -> io::Result<Record> {
    let mut cursor = Cursor { bytes, offset: 0 };
    let record = match cursor.u8()? {
        1 => Record::Sample(decode_sample(&mut cursor)?),
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

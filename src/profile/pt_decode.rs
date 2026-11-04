/*
 * XRef — Intel PT instruction flow reconstruction
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::pt_packet::{Packet, ip_address, packet};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic};
use std::collections::VecDeque;

const MAX_STEPS: usize = 1_000_000;
const MAX_STACK: usize = 4096;
const MAX_RECORDED_FRAMES: usize = 2_000_000;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Observation {
    pub(super) ip: u64,
    pub(super) return_addresses: Vec<u64>,
    /// Most recent preceding partial TSC packet; not an exact instruction time.
    pub(super) preceding_tsc: Option<u64>,
}

pub(super) struct Decoded {
    pub(super) observations: Vec<Observation>,
    pub(super) truncated: bool,
}

enum Code<'a> {
    #[cfg(test)]
    Bytes(&'a [u8], u64),
    Image(&'a crate::image::Image, i64),
}

impl<'a> Code<'a> {
    fn at(&self, runtime_ip: u64) -> Option<&'a [u8]> {
        match self {
            #[cfg(test)]
            Self::Bytes(bytes, base) => bytes.get(usize::try_from(runtime_ip.checked_sub(*base)?).ok()?..),
            Self::Image(image, slide) => {
                let address = super::types::remove_slide(runtime_ip, *slide)?;
                let function = image.function_at(address)?;
                let available = usize::try_from(function.end.checked_sub(address)?).ok()?.min(15);
                (1..=available).rev().find_map(|length| image.read(address, length))
            }
        }
    }
}

struct State<'a> {
    code: Code<'a>,
    ip: Option<u64>,
    last_packet_ip: Option<u64>,
    stack: Vec<u64>,
    tnt: VecDeque<bool>,
    seen: Vec<Observation>,
    recorded_frames: usize,
    return_compression: bool,
    in_psb: bool,
    address_space: Option<u64>,
    preceding_tsc: Option<u64>,
    system_boundary: bool,
    step_limit: usize,
}

impl State<'_> {
    fn walk(&mut self, stop: Option<u64>, indirect: Option<u64>, allow_system_stop: bool) -> Result<(), &'static str> {
        for _ in 0..MAX_STEPS {
            let ip = self.ip.ok_or("missing instruction pointer")?;
            if stop == Some(ip) {
                return Ok(());
            }
            let bytes = self.code.at(ip).ok_or("instruction outside verified image")?;
            let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                return Err("invalid instruction");
            }
            let next = instruction.next_ip();
            if ip.checked_add(u64::try_from(instruction.len()).map_err(|_| "instruction length overflow")?)
                != Some(next)
            {
                return Err("instruction address overflow");
            }
            let flow = instruction.flow_control();
            if matches!(instruction.mnemonic(), Mnemonic::Syscall | Mnemonic::Sysenter) {
                if indirect.is_some() || stop.is_some_and(|target| !allow_system_stop || target != next) {
                    return Err("system transition before PT branch target");
                }
                self.record(ip)?;
                self.ip = Some(next);
                self.system_boundary = true;
                return Ok(());
            }
            // Even with return compression enabled, a return may be encoded
            // by TIP when the hardware return stack cannot predict it.
            let return_via_tip = flow == FlowControl::Return && indirect.is_some() && self.tnt.is_empty();
            let consumes_tnt = flow == FlowControl::ConditionalBranch
                || (flow == FlowControl::Return && self.return_compression && !return_via_tip);
            if consumes_tnt && self.tnt.is_empty() {
                return if stop.is_some() || indirect.is_some() { Err("missing TNT before target") } else { Ok(()) };
            }
            if matches!(flow, FlowControl::IndirectBranch | FlowControl::IndirectCall)
                || (flow == FlowControl::Return && (!self.return_compression || return_via_tip))
            {
                let Some(target) = indirect else {
                    return Ok(());
                };
                self.record(ip)?;
                if flow == FlowControl::IndirectCall {
                    self.push_return(next)?;
                }
                if flow == FlowControl::Return && self.stack.pop().is_some_and(|value| value != target) {
                    self.stack.clear();
                }
                self.ip = Some(target);
                return Ok(());
            }
            self.record(ip)?;
            self.ip = Some(match flow {
                FlowControl::Next => next,
                FlowControl::Call => {
                    self.push_return(next)?;
                    instruction.near_branch_target()
                }
                FlowControl::UnconditionalBranch => instruction.near_branch_target(),
                FlowControl::ConditionalBranch => {
                    if self.tnt.pop_front().ok_or("missing TNT")? {
                        instruction.near_branch_target()
                    } else {
                        next
                    }
                }
                FlowControl::Return => {
                    if !self.tnt.pop_front().ok_or("missing return TNT")? {
                        return Err("unexpected uncompressed return");
                    }
                    self.stack.pop().ok_or("return stack unavailable")?
                }
                _ => return Err("unsupported control flow"),
            });
            if consumes_tnt && self.tnt.is_empty() && stop.is_none() && indirect.is_none() {
                return Ok(());
            }
        }
        Err("instruction budget exceeded")
    }

    fn push_return(&mut self, ip: u64) -> Result<(), &'static str> {
        if self.stack.len() >= MAX_STACK {
            return Err("return stack budget exceeded");
        }
        self.stack.push(ip);
        Ok(())
    }

    fn record(&mut self, ip: u64) -> Result<(), &'static str> {
        if self.seen.len() >= self.step_limit {
            return Err("instruction budget exceeded");
        }
        self.recorded_frames = self.recorded_frames.checked_add(self.stack.len()).ok_or("callchain budget overflow")?;
        if self.recorded_frames > MAX_RECORDED_FRAMES {
            return Err("callchain budget exceeded");
        }
        self.seen.push(Observation {
            ip,
            return_addresses: self.stack.iter().rev().copied().collect(),
            preceding_tsc: self.preceding_tsc,
        });
        Ok(())
    }
}

#[cfg(test)]
fn decode(
    trace: &[u8],
    image: &[u8],
    base: u64,
    return_compression: bool,
    address_space: Option<u64>,
) -> Result<Vec<Observation>, &'static str> {
    decode_with_code(trace, Code::Bytes(image, base), return_compression, address_space, MAX_STEPS)
        .map(|decoded| decoded.observations)
}

#[cfg(test)]
pub(super) fn decode_image(
    trace: &[u8],
    image: &crate::image::Image,
    slide: i64,
    return_compression: bool,
    address_space: Option<u64>,
) -> Result<Vec<Observation>, &'static str> {
    decode_image_bounded(trace, image, slide, return_compression, address_space).map(|decoded| decoded.observations)
}

pub(super) fn decode_image_bounded(
    trace: &[u8],
    image: &crate::image::Image,
    slide: i64,
    return_compression: bool,
    address_space: Option<u64>,
) -> Result<Decoded, &'static str> {
    decode_with_code(trace, Code::Image(image, slide), return_compression, address_space, MAX_STEPS)
}

#[allow(clippy::too_many_lines)] // Packet dispatch and its synchronization state belong together.
fn decode_with_code(
    trace: &[u8],
    code: Code<'_>,
    return_compression: bool,
    address_space: Option<u64>,
    step_limit: usize,
) -> Result<Decoded, &'static str> {
    let mut state = State {
        code,
        ip: None,
        last_packet_ip: None,
        stack: Vec::new(),
        tnt: VecDeque::new(),
        seen: Vec::new(),
        recorded_frames: 0,
        return_compression,
        in_psb: false,
        address_space,
        preceding_tsc: None,
        system_boundary: false,
        step_limit,
    };
    macro_rules! walk {
        ($stop:expr, $indirect:expr, $allow_system_stop:expr) => {
            match state.walk($stop, $indirect, $allow_system_stop) {
                Ok(()) => {}
                Err("instruction budget exceeded" | "callchain budget exceeded") => {
                    return Ok(Decoded { observations: state.seen, truncated: true });
                }
                Err(error) => return Err(error),
            }
        };
    }
    let mut offset = 0;
    let mut synchronized = false;
    let mut fup_boundary = false;
    let mut psb_fup = false;
    while offset < trace.len() {
        let (item, size) = packet(&trace[offset..])?;
        offset += size;
        if state.system_boundary
            && !matches!(
                item,
                Packet::Ip { kind: 0x01, .. } | Packet::Timing | Packet::Pad | Packet::Cbr(_) | Packet::Tsc(_)
            )
        {
            return Err("system transition requires PT trace disable");
        }
        if !synchronized && !matches!(item, Packet::Psb | Packet::Pad) {
            return Err("trace is not synchronized");
        }
        match item {
            Packet::Psb => {
                if state.in_psb || !state.tnt.is_empty() {
                    return Err("resynchronization requires sideband");
                }
                state.in_psb = true;
                state.last_packet_ip = None;
                state.preceding_tsc = None;
                synchronized = true;
                fup_boundary = false;
                psb_fup = false;
            }
            Packet::PsbEnd => {
                if !state.in_psb {
                    return Err("PSBEND without PSB");
                }
                if state.ip.is_some() && !psb_fup {
                    return Err("active PSB lacks flow anchor");
                }
                state.in_psb = false;
            }
            Packet::Ip { kind, compression, payload } => {
                let target = ip_address(state.last_packet_ip, compression, payload)?;
                if let Some(ip) = target {
                    state.last_packet_ip = Some(ip);
                }
                match kind {
                    0x1d if state.in_psb => {
                        let anchor = target.ok_or("suppressed PSB flow anchor")?;
                        if state.ip.is_some() {
                            walk!(Some(anchor), None, false);
                        } else {
                            state.ip = Some(anchor);
                        }
                        if !state.tnt.is_empty() {
                            return Err("unconsumed TNT at PSB flow anchor");
                        }
                        psb_fup = true;
                    }
                    0x1d if target.is_some() && state.ip.is_some() => {
                        walk!(target, None, false);
                        fup_boundary = true;
                    }
                    0x11 => {
                        state.ip = Some(target.ok_or("suppressed initial IP")?);
                        fup_boundary = false;
                    }
                    0x0d if state.ip.is_some() && target.is_some() => {
                        walk!(None, target, false);
                        fup_boundary = false;
                    }
                    0x01 if state.ip.is_some() => {
                        if !state.tnt.is_empty() {
                            return Err("unconsumed TNT at trace disable");
                        }
                        if let Some(stop) = target {
                            if state.system_boundary {
                                if state.ip != Some(stop) {
                                    return Err("PT disable target differs from system boundary");
                                }
                            } else {
                                walk!(Some(stop), None, true);
                            }
                        } else if !fup_boundary && !state.system_boundary {
                            walk!(None, None, false);
                            if !state.system_boundary {
                                return Err("suppressed disable without flow boundary");
                            }
                        }
                        state.ip = None;
                        state.stack.clear();
                        state.system_boundary = false;
                        state.preceding_tsc = None;
                        fup_boundary = false;
                    }
                    _ => return Err("unsupported IP packet sequence"),
                }
            }
            Packet::Tnt { bits, count } => {
                if state.in_psb {
                    return Err("TNT inside PSB header");
                }
                fup_boundary = false;
                if state.tnt.len().saturating_add(usize::from(count)) > MAX_STACK {
                    return Err("TNT budget exceeded");
                }
                for index in (0..count).rev() {
                    state.tnt.push_back(bits & (1_u64 << index) != 0);
                }
                if state.ip.is_some() {
                    walk!(None, None, false);
                }
            }
            Packet::Mode(value) if value & 0xe0 == 0 && value & 3 == 1 => {}
            Packet::Mode(_) => return Err("unsupported execution mode"),
            Packet::Tsc(value) => state.preceding_tsc = Some(value),
            Packet::Pad | Packet::Cbr(_) | Packet::Timing => {}
            Packet::Pip(value) => {
                if state.address_space != Some(value) {
                    return Err("address-space switch requires sideband");
                }
            }
            Packet::Overflow => return Err("trace overflow"),
        }
    }
    if !synchronized || state.in_psb || state.ip.is_some() || !state.tnt.is_empty() {
        return Err("incomplete PT trace");
    }
    Ok(Decoded { observations: state.seen, truncated: false })
}

#[cfg(test)]
#[path = "pt_decode_tests.rs"]
mod tests;

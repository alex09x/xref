/*
 * XRef — Intel PT instruction event synthesis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::Sample;

/// Synthesized instruction events are counts, not sampled periods or timing.
/// The caller must retain both flags in the final report and establish process
/// ownership and executable mapping before invoking this routine.
pub(super) struct SyntheticBatch {
    pub(super) samples: Vec<Sample>,
    pub(super) untimed: bool,
    pub(super) instruction_events: bool,
}

pub(super) fn synthesize(
    trace: &[u8],
    image: &crate::image::Image,
    slide: i64,
    pid: u32,
    tid: u32,
    return_compression: bool,
    address_space: Option<u64>,
) -> Result<SyntheticBatch, &'static str> {
    if pid == 0 || tid == 0 || tid == u32::MAX {
        return Err("unverified PT process or thread");
    }
    let observations = super::pt_decode::decode_image(trace, image, slide, return_compression, address_space)?;
    if observations.is_empty() {
        return Err("PT trace produced no instruction events");
    }
    let samples = observations
        .into_iter()
        .map(|observation| {
            let _ = observation.preceding_tsc;
            Sample {
                timestamp_ns: 0,
                pid,
                tid,
                cpu_mode: 2,
                ip: observation.ip,
                period: 1,
                registers_mask: 0,
                registers: Vec::new(),
                user_stack: Vec::new(),
                callchain: observation.return_addresses,
                branches: Vec::new(),
            }
        })
        .collect();
    Ok(SyntheticBatch { samples, untimed: true, instruction_events: true })
}

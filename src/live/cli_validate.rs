/*
 * XRef — bounded validation for live analysis commands
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::live::cli::{
    LiveCommand, LiveSubcommand, MAX_HITS_CAP, MAX_PATTERN_WORDS, MAX_PROBE_DURATION_MS, MAX_PROBE_EVENTS_CAP,
    MAX_PROBES_PER_SESSION, MAX_WATCHES_PER_SESSION, ProbeBackend, validate_align, validate_context_words,
};

impl LiveCommand {
    #[must_use]
    pub const fn pid(&self) -> u32 {
        match &self.subcommand {
            LiveSubcommand::Maps { pid, .. }
            | LiveSubcommand::Resolve { pid, .. }
            | LiveSubcommand::Memscan { pid, .. }
            | LiveSubcommand::Probe { pid, .. }
            | LiveSubcommand::Watch { pid, .. } => *pid,
            LiveSubcommand::TracefsWatchdog { .. } => 0,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if matches!(self.subcommand, LiveSubcommand::TracefsWatchdog { .. }) {
            return Ok(());
        }
        if self.pid() == 0 {
            return Err("invalid --pid 0: process ID must be non-zero".to_owned());
        }
        match &self.subcommand {
            LiveSubcommand::Maps { .. } | LiveSubcommand::TracefsWatchdog { .. } => Ok(()),
            LiveSubcommand::Resolve { addrs, .. } => {
                if addrs.is_empty() {
                    return Err("resolve requires at least one <ADDR>".to_owned());
                }
                Ok(())
            }
            LiveSubcommand::Memscan { align, before_words, after_words, max_hits, values, .. } => {
                validate_align(*align)?;
                validate_context_words(*before_words, "--before-words")?;
                validate_context_words(*after_words, "--after-words")?;
                if *max_hits == 0 || *max_hits > MAX_HITS_CAP {
                    return Err(format!("--max-hits {max_hits} must be in 1..={MAX_HITS_CAP}"));
                }
                if values.is_empty() || values.len() > MAX_PATTERN_WORDS {
                    return Err(format!("memscan requires 1..={MAX_PATTERN_WORDS} <VALUES> words"));
                }
                Ok(())
            }
            LiveSubcommand::Probe {
                duration_ms,
                max_events,
                fetch,
                filter,
                every,
                first,
                until_hits,
                backend,
                regs,
                addrs,
                ..
            } => {
                if *duration_ms == 0 || *duration_ms > MAX_PROBE_DURATION_MS {
                    return Err(format!("--duration-ms {duration_ms} must be in 1..={MAX_PROBE_DURATION_MS}"));
                }
                if *max_events == 0 || *max_events > MAX_PROBE_EVENTS_CAP {
                    return Err(format!("--max-events {max_events} must be in 1..={MAX_PROBE_EVENTS_CAP}"));
                }
                if addrs.is_empty() || addrs.len() > MAX_PROBES_PER_SESSION {
                    return Err(format!("probe requires 1..={MAX_PROBES_PER_SESSION} <ADDR> targets"));
                }
                if *every == 0 || *every > 1_000_000 {
                    return Err("--every must be in 1..=1000000".to_owned());
                }
                if first.is_some_and(|value| value == 0 || value > MAX_PROBE_EVENTS_CAP) {
                    return Err(format!("--first must be in 1..={MAX_PROBE_EVENTS_CAP}"));
                }
                if until_hits.is_some_and(|value| value == 0 || value > MAX_PROBE_EVENTS_CAP) {
                    return Err(format!("--until-hits must be in 1..={MAX_PROBE_EVENTS_CAP}"));
                }
                #[cfg(any(target_os = "linux", test))]
                {
                    let fetches = crate::live::probe::fetch::parse_fetch_args(fetch)?;
                    let names = fetches.iter().map(|arg| arg.name.clone()).collect::<Vec<_>>();
                    crate::live::probe::filter::parse_filters(filter, *regs, &names)?;
                    if *backend != ProbeBackend::Tracefs
                        && (!fetch.is_empty()
                            || !filter.is_empty()
                            || *every != 1
                            || first.is_some()
                            || until_hits.is_some())
                    {
                        return Err("--fetch, --filter, --every, --first, and --until-hits require --backend tracefs"
                            .to_owned());
                    }
                }
                #[cfg(not(any(target_os = "linux", test)))]
                if !fetch.is_empty() || !filter.is_empty() || *every != 1 || first.is_some() || until_hits.is_some() {
                    return Err("advanced live probe options require Linux tracefs".to_owned());
                }
                Ok(())
            }
            LiveSubcommand::Watch { duration_ms, max_events, len, access, follow, addrs, .. } => {
                if *duration_ms == 0 || *duration_ms > MAX_PROBE_DURATION_MS {
                    return Err(format!("--duration-ms {duration_ms} must be in 1..={MAX_PROBE_DURATION_MS}"));
                }
                if *max_events == 0 || *max_events > MAX_PROBE_EVENTS_CAP {
                    return Err(format!("--max-events {max_events} must be in 1..={MAX_PROBE_EVENTS_CAP}"));
                }
                let mut total_slots = addrs.len();
                for spec_str in follow {
                    let parsed = crate::live::watch::rebind::parse_follow_spec(spec_str, *len, *access)?;
                    total_slots = total_slots.saturating_add(parsed.hardware_slots_required());
                }
                if total_slots == 0 || total_slots > MAX_WATCHES_PER_SESSION {
                    return Err(format!(
                        "watch requires 1..={MAX_WATCHES_PER_SESSION} total hardware watchpoint slots across <ADDR> and --follow (requested {total_slots}; x86-64 DR0..DR3 hardware limit)"
                    ));
                }
                Ok(())
            }
        }
    }
}

/*
 * XRef — tracefs instance setup for live probes
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::live::probe::tracefs_cleanup::{format_tracefs_io_error, write_tracefs_control};
use std::path::Path;

pub fn configure_tracefs_instance_format(instance_dir: &Path) -> Result<(), String> {
    write_tracefs_control(&instance_dir.join("tracing_on"), "0\n", "init tracing_on")?;
    let clock_path = instance_dir.join("trace_clock");
    write_tracefs_control(&clock_path, "mono\n", "set trace_clock mono")?;
    let clock_readback = std::fs::read_to_string(&clock_path)
        .map_err(|e| format_tracefs_io_error("verify trace_clock", &clock_path, &e))?;
    if !clock_readback.contains("[mono]") && clock_readback.trim() != "mono" {
        return Err(format!(
            "tracefs trace_clock verification failed on {}: expected active [mono], got {:?}",
            clock_path.display(),
            clock_readback.trim()
        ));
    }

    let required_options = [
        ("context-info", "1", "context-info"),
        ("raw", "0", "noraw"),
        ("hex", "0", "nohex"),
        ("bin", "0", "nobin"),
        ("latency-format", "0", "nolatency-format"),
    ];
    for (opt_name, expected_val, fallback_token) in required_options {
        let opt_path = instance_dir.join("options").join(opt_name);
        if write_tracefs_control(&opt_path, &format!("{expected_val}\n"), &format!("set options/{opt_name}")).is_ok() {
            let actual = std::fs::read_to_string(&opt_path)
                .map_err(|e| format_tracefs_io_error("verify option", &opt_path, &e))?;
            if actual.trim() != expected_val {
                return Err(format!(
                    "tracefs option verification failed on {}: expected {expected_val}, got {:?}",
                    opt_path.display(),
                    actual.trim()
                ));
            }
        } else {
            let trace_options = instance_dir.join("trace_options");
            write_tracefs_control(
                &trace_options,
                &format!("{fallback_token}\n"),
                &format!("set trace_options {fallback_token}"),
            )?;
            let actual = std::fs::read_to_string(&trace_options)
                .map_err(|e| format_tracefs_io_error("verify trace_options", &trace_options, &e))?;
            if !actual.lines().any(|line| line.trim() == fallback_token) {
                return Err(format!(
                    "tracefs trace_options verification failed on {}: missing {fallback_token}",
                    trace_options.display()
                ));
            }
        }
    }
    Ok(())
}

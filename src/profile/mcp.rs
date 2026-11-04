/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::api::{Cancellation, types::ApiError};
use serde_json::Value;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Default)]
struct BoundedCapture(Vec<u8>);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl std::io::Write for BoundedCapture {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(data.len()) > 16 * 1024 * 1024 {
            return Err(std::io::Error::other("profile capture exceeds MCP memory limit"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn run(
    session: &mut crate::live::procfs::LiveSession,
    duration_ms: Option<u64>,
    max_events: Option<usize>,
    cancel: &Cancellation,
) -> Result<Value, ApiError> {
    use super::config::{Callers, Config};
    use std::collections::BTreeSet;
    use std::io::Cursor;
    use std::time::Duration;
    let config = Config {
        duration: Duration::from_millis(duration_ms.unwrap_or(1000)),
        max_samples: max_events.unwrap_or(4096) as u64,
        callers: Callers::Dwarf,
        stack_bytes: 2048,
        ..Config::default()
    };
    let (bytes, stats) = super::capture::capture(session, &config, BoundedCapture::default(), Some(cancel.flag()))
        .map_err(|error| ApiError::new("live_profile_failed", error))?;
    let analysis = super::analyze::analyze(&mut Cursor::new(bytes.0), &session.image, &BTreeSet::new())
        .map_err(|error| ApiError::new("live_profile_failed", error))?;
    let report = super::report::build(&analysis, &session.image, 30)
        .map_err(|error| ApiError::new("live_profile_failed", error))?;
    Ok(serde_json::json!({ "capture": stats, "report": report }))
}

#[cfg(all(any(target_os = "linux", test), not(all(target_os = "linux", target_arch = "x86_64"))))]
pub fn run(
    _session: &mut crate::live::procfs::LiveSession,
    _duration_ms: Option<u64>,
    _max_events: Option<usize>,
    _cancel: &Cancellation,
) -> Result<Value, ApiError> {
    Err(ApiError::new("unsupported_platform", "live profiling requires Linux x86-64"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test inputs are fixed JSON fixtures.
mod tests {
    #[test]
    fn profile_mcp_preserves_target_pinning_and_budgets() {
        use crate::mcp::live_tool::LiveQuery;
        use crate::mcp::live_tool_exec::validate_live_query_budgets;
        let valid: LiveQuery =
            serde_json::from_str(r#"{"operation":"profile","duration_ms":100,"max_events":64}"#).unwrap();
        assert!(validate_live_query_budgets(&valid).is_ok());
        let too_long: LiveQuery = serde_json::from_str(r#"{"operation":"profile","duration_ms":5001}"#).unwrap();
        assert!(validate_live_query_budgets(&too_long).is_err());
        assert!(serde_json::from_str::<LiveQuery>(r#"{"operation":"profile","pid":123}"#).is_err());
    }
}

/*
 * XRef — tracefs probe filter setup
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::path::Path;

use super::filter::ValueFilter;
use super::tracefs_cleanup::write_tracefs_control;

pub fn configure_probe_filters(instance_dir: &Path, events: &[String], filters: &[ValueFilter]) -> Result<(), String> {
    if filters.is_empty() {
        return Ok(());
    }
    let expression = filters.iter().map(ValueFilter::tracefs_expression).collect::<Vec<_>>().join(" && ");
    for event in events {
        if let Some((group, name)) = event.split_once('/') {
            let path = instance_dir.join("events").join(group).join(name).join("filter");
            write_tracefs_control(&path, &format!("{expression}\n"), "set probe value filter")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // Test fixture paths and filter contents are controlled.

    use std::time::{SystemTime, UNIX_EPOCH};

    use super::configure_probe_filters;
    use crate::live::probe::filter::ValueFilter;

    #[test]
    fn installs_only_parsed_numeric_predicates_on_each_session_event() {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("xref-tracefs-filter-{nonce}"));
        let filter_path = root.join("events/xref/probe/filter");
        std::fs::create_dir_all(filter_path.parent().unwrap()).unwrap();
        std::fs::write(&filter_path, "0\n").unwrap();
        let filters = [ValueFilter::parse("amount > 5").unwrap(), ValueFilter::parse("rdi == 1").unwrap()];
        configure_probe_filters(&root, &["xref/probe".to_owned()], &filters).unwrap();
        assert_eq!(std::fs::read_to_string(&filter_path).unwrap(), "amount > 5 && rdi == 1\n");
        std::fs::remove_dir_all(root).unwrap();
    }
}

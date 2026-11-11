/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;

/// `field --within FN` with no key lists the keys FN passes and the offsets they read.
#[test]
fn within_alone_lists_every_key_of_the_serializer_with_its_offset() {
    let fixture = Fixture::build("release");
    for binary in [&fixture.bin, &fixture.stripped()] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
        command.arg("-b").arg(binary).args(["field", "--json", "--within"]);
        command.arg(format!("{:#x}", fixture.symbols["serialize_payload_entry"]));
        let report: Value = serde_json::from_slice(&run(&mut command).stdout).expect("field JSON report");
        let candidates = report["candidates"].as_array().unwrap();
        for name in ["payload", "narrow", "flag", "nested"] {
            let expected = fixture.offsets[&format!("Payload.{name}")];
            assert!(
                candidates.iter().any(|candidate| {
                    candidate["fields"].as_array().unwrap().iter().any(|field| {
                        field["name"] == serde_json::json!(name) && field["offset"].as_u64() == Some(expected)
                    })
                }),
                "{name} at {expected:#x} missing: {report}"
            );
        }
    }
}

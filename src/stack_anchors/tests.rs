/*
 * XRef Code — Stack coordinate dataflow tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::StackAnchors;

fn analyze(bytes: &[u8], frame_pointer: bool) -> StackAnchors {
    let mut insns = Vec::new();
    crate::scan::decode(bytes, 0x1000, |ins| insns.push(*ins));
    StackAnchors::analyze(&insns, frame_pointer)
}

#[test]
fn dominating_anchor_survives_guard_but_branch_local_anchor_does_not() -> Result<(), Box<dyn std::error::Error>> {
    let dominant = analyze(
        &[0x48, 0x8d, 0x7c, 0x24, 0x40, 0x85, 0xff, 0x74, 0x05, 0xb8, 1, 0, 0, 0, 0x48, 0x8b, 0x44, 0x24, 0x58, 0xc3],
        false,
    );
    let access = dominant.access(0x100e).ok_or("missing reachable access")?;
    assert_eq!(access.coordinate, 0x58);
    assert_eq!(access.anchors.len(), 1);
    assert_eq!(access.anchors[0].frame_offset, 0x40);
    let partial =
        analyze(&[0x85, 0xff, 0x74, 0x05, 0x48, 0x8d, 0x7c, 0x24, 0x40, 0x48, 0x8b, 0x44, 0x24, 0x58, 0xc3], false);
    assert!(partial.access(0x1009).ok_or("missing joined access")?.anchors.is_empty());
    Ok(())
}

#[test]
fn conflicting_stack_coordinates_and_unreachable_islands_are_not_reused() {
    let conflict = analyze(
        &[0x48, 0x8d, 0x7c, 0x24, 0x40, 0x85, 0xff, 0x74, 0x01, 0x50, 0x48, 0x8b, 0x44, 0x24, 0x58, 0xc3],
        false,
    );
    assert!(conflict.access(0x100a).is_none());
    let cycle = analyze(
        &[
            0x48, 0x8d, 0x7c, 0x24, 0x40, 0x50, 0xeb, 0xfd, // loop with a nonzero SP delta
            0x48, 0x8b, 0x44, 0x24, 0x58, 0xc3,
        ],
        false,
    );
    assert!(cycle.access(0x1008).is_none());
    let indirect = analyze(&[0xff, 0xe0, 0x48, 0x8b, 0x44, 0x24, 0x58], false);
    assert!(indirect.access(0x1002).is_none());
    assert!(StackAnchors::analyze(&[], false).access(0x1000).is_none());
}

#[test]
fn stack_pointer_copies_widths_restoration_and_clobbers() -> Result<(), Box<dyn std::error::Error>> {
    let copied = analyze(&[0x48, 0x89, 0xe7, 0x48, 0x8b, 0x44, 0x24, 0x18, 0xc3], false);
    let access = copied.access(0x1003).ok_or("missing copied-SP access")?;
    assert_eq!(access.coordinate, 0x18);
    assert_eq!(access.anchors[0].frame_offset, 0);
    let narrow = analyze(
        &[
            0x66, 0x50, // push ax
            0x48, 0x8d, 0x7c, 0x24, 0x40, 0x66, 0x58, // pop ax
            0x48, 0x8b, 0x44, 0x24, 0x58, 0xc3,
        ],
        false,
    );
    let access = narrow.access(0x1009).ok_or("missing word push/pop access")?;
    assert_eq!(access.coordinate, 0x58);
    assert_eq!(access.anchors[0].frame_offset, 0x3e);
    let restored =
        analyze(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xc9, 0x48, 0x8b, 0x44, 0x24, 0x18, 0xc3], true);
    assert_eq!(restored.access(0x1009).ok_or("missing leave restoration")?.coordinate, 0x18);
    let aligned =
        analyze(&[0x48, 0x8d, 0x7c, 0x24, 0x40, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x8b, 0x44, 0x24, 0x58, 0xc3], false);
    assert!(aligned.access(0x1009).is_none());
    Ok(())
}

#[test]
fn indexed_leas_and_frame_less_rbp_do_not_establish_anchors() -> Result<(), Box<dyn std::error::Error>> {
    let indexed = analyze(&[0x48, 0x8d, 0x7c, 0xcc, 0x40, 0x48, 0x8b, 0x44, 0x24, 0x58, 0xc3], false);
    assert!(indexed.access(0x1005).ok_or("missing literal indexed test access")?.anchors.is_empty());
    let frameless = analyze(&[0x48, 0x8d, 0x7d, 0x40, 0x48, 0x8b, 0x45, 0x58, 0xc3], false);
    assert!(frameless.access(0x1000).is_none());
    assert!(frameless.access(0x1004).is_none());
    Ok(())
}

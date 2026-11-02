/*
 * XRef Code — Program slice tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{slice_fn, slice_fn_with_mode, slice_rendered_c};
use crate::image::{Image, Segment};

fn rendered(source: &str, target: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    slice_rendered_c(&(0x1000..0x1100), target, &[target.to_owned()], source, &mut out)?;
    Ok(String::from_utf8(out)?)
}

#[test]
fn forward_goto_guards_and_empty_sinks_survive_without_tail_calls() -> Result<(), Box<dyn std::error::Error>> {
    for guards in [
        "  if (arg_0 != 417) goto L_exit;\n",
        "  if (arg_0 != 417) {\n    goto L_exit;\n  }\n",
        "  if (arg_0 == 417) {\n    before();\n  } else {\n    goto L_exit;\n  }\n",
    ] {
        let source = format!("void demo(u64 arg_0) {{\n{guards}  target();\n  ignored();\nL_exit:\n}}\n");
        let slice = rendered(&source, "target()")?;
        assert!(slice.contains("417") && slice.contains("goto L_exit;") && slice.contains("L_exit: ;"), "{slice}");
        assert!(!slice.contains("ignored()"), "{slice}");
        assert_eq!(slice.matches('{').count(), slice.matches('}').count(), "{slice}");
    }
    let direct = rendered(
        "void demo(void) {\n  goto L_exit; /* @xref_slice_target */\nL_unused:\n  ignored();\nL_exit:\n}\n",
        "selected",
    )?;
    assert!(direct.contains("goto L_exit;") && direct.contains("L_exit: ;"), "{direct}");
    assert!(!direct.contains("L_unused:") && !direct.contains("ignored()"), "{direct}");
    Ok(())
}

#[test]
fn goto_text_in_literals_and_multiline_comments_is_not_control_flow() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"/* goto L_fake;
L_fake:
*/
const void *demo(void) {
  /* note
  if (arg_0) goto L_fake;
  */
  // goto L_fake;
  return "goto L_fake; with an escaped quote: \"";
L_fake:
  ignored();
}
"#;
    let slice = rendered(source, "escaped quote")?;
    assert!(slice.contains("return \"goto L_fake;"), "{slice}");
    assert!(!slice.contains("L_fake:") && !slice.contains("ignored()"), "{slice}");
    Ok(())
}

#[test]
fn empty_sink_terminator_precedes_trailing_comments() -> Result<(), Box<dyn std::error::Error>> {
    for label in [
        "L_exit: // sink",
        "/* note: */ L_exit: /* sink */",
        "L_exit /* marker */ : // sink",
        "/* 注: */ L_exit: // τέλος",
    ] {
        let source = format!("void demo(void) {{\n  goto L_exit; /* @xref_slice_target */\n{label}\n}}\n");
        let slice = rendered(&source, "selected")?;
        assert!(slice.contains(": ;"), "null statement must be outside comments:\n{slice}");
    }
    Ok(())
}

#[test]
fn slices_reaching_defs_skip_flags_balanced_braces_and_exact_call_ip() {
    let mut data = vec![0u8; 0x100];
    let code: &[u8] = &[
        0x48, 0x89, 0xfb, 0x48, 0xc7, 0xc1, 0x2a, 0x00, 0x00, 0x00, 0x48, 0x89, 0x0e, 0x48, 0x85, 0xdb, 0x74, 0x06,
        0x48, 0x8d, 0x43, 0x05, 0xc3, 0x31, 0xc0, 0xc3,
    ];
    data[..code.len()].copy_from_slice(code);
    data[0x40..0x43].copy_from_slice(&[0x89, 0xf8, 0xc3]);
    let f2: &[u8] = &[
        0x53, 0x48, 0x89, 0xfb, 0x48, 0x85, 0xf6, 0x74, 0x0c, 0x48, 0x83, 0xfa, 0x09, 0x74, 0x1a, 0x48, 0x83, 0xc3,
        0x01, 0xeb, 0x09, 0x48, 0x81, 0xf9, 0xa1, 0x01, 0x00, 0x00, 0x75, 0x0b, 0x48, 0x89, 0xdf, 0xe8, 0xca, 0xff,
        0xff, 0xff, 0x48, 0x01, 0xc3, 0xbf, 0x63, 0x00, 0x00, 0x00, 0xe8, 0xbd, 0xff, 0xff, 0xff, 0x48, 0x85, 0xc0,
        0x74, 0x04, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x01, 0xd8, 0x5b, 0xc3,
    ];
    data[0x50..0x50 + f2.len()].copy_from_slice(f2);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions: vec![0x1000..0x1000 + code.len() as u64, 0x1040..0x1043, 0x1050..0x1050 + f2.len() as u64],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
    };
    let mut out = Vec::new();
    assert!(slice_fn(&image, "0x1000", "arg_0 + 5", false, &mut out).is_ok());
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("arg_0") && s.contains("if (") && !s.contains("42"), "{s}");
    assert!(slice_fn(&image, "0x1000", "nonexistent_token", false, &mut out).is_err());

    out.clear();
    assert!(slice_fn(&image, "0x1050", "0x1071", false, &mut out).is_ok());
    let s2 = String::from_utf8_lossy(&out);
    let opens = s2.chars().filter(|&c| c == '{').count();
    let closes = s2.chars().filter(|&c| c == '}').count();
    assert_eq!(opens, closes, "unbalanced braces:\n{s2}");
    assert!(s2.contains("u8 skip_1079 = 0;") && s2.contains("417") && !s2.contains("fn_1040(99)"), "{s2}");

    out.clear();
    assert!(slice_fn_with_mode(&image, "0x1050", "0x1071", false, true, &mut out).is_ok());
    let raw = String::from_utf8_lossy(&out);
    assert!(raw.contains("417") && raw.contains("goto L_1079;") && raw.contains("L_1079:"), "{raw}");
    assert!(!raw.contains("fn_1040(99)"), "{raw}");
    assert_eq!(raw.matches('{').count(), raw.matches('}').count(), "{raw}");

    out.clear();
    assert!(slice_fn(&image, "0x1050", "fn_1040(99)", false, &mut out).is_ok());
    let s3 = String::from_utf8_lossy(&out);
    assert_eq!(s3.chars().filter(|&c| c == '{').count(), s3.chars().filter(|&c| c == '}').count(), "{s3}");
}

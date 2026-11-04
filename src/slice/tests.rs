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
fn default_switch_label_stays_with_its_selected_statement() -> Result<(), Box<dyn std::error::Error>> {
    let slice =
        rendered("void demo(u64 arg_0) {\n  switch (arg_0) {\n    default:\n      target();\n  }\n}\n", "target()")?;
    assert!(slice.contains("default:"), "switch default guard was lost:\n{slice}");
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
        metadata: crate::image_format::Metadata::default(),
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

#[test]
fn field_slice_target_parsing_and_display() -> Result<(), Box<dyn std::error::Error>> {
    use crate::slice_parse::FieldSliceTarget;
    use iced_x86::Register;

    let t = FieldSliceTarget::parse("+0x10 of rax@0x1000").ok_or("valid target")?;
    assert_eq!(t.offset, 16);
    assert_eq!(t.reg, Register::RAX);
    assert_eq!(t.va, 0x1000);
    assert_eq!(t.to_string(), "+0x10 of rax@0x1000");

    let t2 = FieldSliceTarget::parse("-0x8 of rbp@0x2000").ok_or("valid negative")?;
    assert_eq!(t2.offset, -8);
    assert_eq!(t2.reg, Register::RBP);
    assert_eq!(t2.va, 0x2000);
    assert_eq!(t2.to_string(), "-0x8 of rbp@0x2000");

    let t3 = FieldSliceTarget::parse("0x18 of rdi@1000").ok_or("valid positive")?;
    assert_eq!(t3.offset, 24);
    assert_eq!(t3.reg, Register::RDI);
    assert_eq!(t3.va, 0x1000);

    assert!(FieldSliceTarget::parse("fn_1040").is_none());
    assert!(FieldSliceTarget::parse("0x1000").is_none());
    assert!(FieldSliceTarget::parse("+0x10 of ").is_none());
    Ok(())
}

#[test]
fn slice_to_field_isolates_target_chain_and_marks_may_alias() -> Result<(), Box<dyn std::error::Error>> {
    let code: &[u8] = &[
        0x48, 0x89, 0xfb,                         // 0x1000: mov rbx, rdi
        0xc7, 0x47, 0x10, 0x2a, 0x00, 0x00, 0x00, // 0x1003: mov dword ptr [rdi+0x10], 42 (target field 0x10)
        0xc7, 0x47, 0x20, 0x63, 0x00, 0x00, 0x00, // 0x100a: mov dword ptr [rdi+0x20], 99 (other field 0x20)
        0xc7, 0x44, 0x24, 0x08, 0x4d, 0x00, 0x00, 0x00, // 0x1011: mov dword ptr [rsp+8], 77 (unrelated stack local)
        0x48, 0x8d, 0x57, 0x08,                   // 0x1019: lea rdx, [rdi+8]
        0x8b, 0x42, 0x08,                         // 0x101d: mov eax, [rdx+8] (field 0x10 via lea)
        0x83, 0xc0, 0x05,                         // 0x1020: add eax, 5 (dep on eax)
        0x89, 0x43, 0x10,                         // 0x1023: mov [rbx+0x10], eax (field 0x10 via rbx)
        0x8b, 0x4f, 0x20,                         // 0x1026: mov ecx, [rdi+0x20] (other field 0x20)
        0x83, 0xc1, 0x0a,                         // 0x1029: add ecx, 10
        0x89, 0x4f, 0x20,                         // 0x102c: mov [rdi+0x20], ecx (other field 0x20)
        0xc7, 0x46, 0x10, 0x58, 0x00, 0x00, 0x00, // 0x102f: mov dword ptr [rsi+0x10], 88 (may-alias via rsi)
        0xc7, 0x46, 0x28, 0x31, 0x00, 0x00, 0x00, // 0x1036: mov dword ptr [rsi+0x28], 49 (other pointer, other offset)
        0xc3,                                     // 0x103d: ret
    ];
    let mut data = vec![0x90u8; 0x100];
    data[..code.len()].copy_from_slice(code);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions: std::iter::once(0x1000..0x1000 + u64::try_from(code.len()).unwrap_or_default()).collect(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };

    let mut out = Vec::new();
    slice_fn(&image, "0x1000", "+0x10 of rdi@0x1000", false, &mut out)?;
    let s = String::from_utf8(out)?;
    assert!(s.contains("42"), "target field write missing:\n{s}");
    assert!(s.contains("may-alias"), "may-alias marker missing:\n{s}");
    assert!(!s.contains("99"), "unrelated field +0x20 must be excluded:\n{s}");
    assert!(!s.contains("77"), "unrelated local stack write must be excluded:\n{s}");
    assert!(!s.contains("49"), "another pointer at a different offset cannot alias the field:\n{s}");

    let mut out_fields = Vec::new();
    slice_fn(&image, "0x1000", "+0x10 of rdi@0x1000", true, &mut out_fields)?;
    let sf = String::from_utf8(out_fields)?;
    assert!(sf.contains("f_10") || sf.contains("42"), "sugared field 0x10 missing:\n{sf}");
    assert!(!sf.contains("99"), "unrelated field 0x20 in sugared output:\n{sf}");

    let mut out_lea = Vec::new();
    slice_fn(&image, "0x1000", "+0x08 of rdx@0x1019", false, &mut out_lea)?;
    let sl = String::from_utf8(out_lea)?;
    assert!(sl.contains("42") && !sl.contains("99"), "lea-relative target slice mismatch:\n{sl}");

    Ok(())
}

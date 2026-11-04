/*
 * XRef — Real native stacks, offline symbolization and observed graph integration
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // Failures are test-oracle assertions.
use object::{Object, ObjectSymbol};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture {
    root: PathBuf,
    bin: PathBuf,
    symbols: BTreeMap<String, u64>,
    base: u64,
    pid: u32,
    frames: Vec<String>,
    maps: String,
    build_id: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn output(command: &mut Command) -> Output {
    let result = command.output().expect("spawn fixture command");
    assert!(result.status.success(), "command {command:?}: {}", String::from_utf8_lossy(&result.stderr));
    result
}
fn text(result: Output) -> String {
    String::from_utf8(result.stdout).unwrap()
}
fn cli(bin: &Path, args: &[&str]) -> Output {
    output(Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(bin).args(args))
}

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root =
            PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("runtime-stacks-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let unstripped = root.join("native");
        let bin = root.join("native-stripped");
        output(
            Command::new("cc")
                .args([
                    "-O1",
                    "-fPIE",
                    "-pie",
                    "-fno-omit-frame-pointer",
                    "-fno-optimize-sibling-calls",
                    "-Wl,--build-id=sha1",
                ])
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/runtime_stacks.c"))
                .args(["-ldl", "-o"])
                .arg(&unstripped),
        );
        let bytes = fs::read(&unstripped).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let symbols = object.symbols().filter_map(|s| Some((s.name().ok()?.to_owned(), s.address()))).collect();
        let mut build_id = String::new();
        for byte in object.build_id().unwrap().unwrap() {
            write!(build_id, "{byte:02x}").unwrap();
        }
        output(Command::new("objcopy").args(["--strip-all", "--keep-section=.eh_frame"]).arg(&unstripped).arg(&bin));
        let stripped = fs::read(&bin).unwrap();
        assert_eq!(object::File::parse(stripped.as_slice()).unwrap().symbols().count(), 0);
        let capture = text(output(&mut Command::new(&bin)));
        let base = u64::from_str_radix(capture.lines().find_map(|l| l.strip_prefix("BASE=0x")).unwrap(), 16).unwrap();
        let pid = capture.lines().find_map(|l| l.strip_prefix("PID=")).unwrap().parse().unwrap();
        let frames = capture.lines().filter_map(|l| l.strip_prefix("FRAME=").map(str::to_owned)).collect();
        let mut maps = capture.lines().filter_map(|l| l.strip_prefix("MAP=")).collect::<Vec<_>>().join("\n");
        maps.push('\n');
        Self { root, bin, symbols, base, pid, frames, maps, build_id }
    }
    fn query(&self, request: &Value) -> Value {
        serde_json::from_slice(&cli(&self.bin, &["query", &request.to_string()]).stdout).unwrap()
    }
    fn stack_request(&self) -> Value {
        json!({"operation":"symbolize","request":{"stacks":[{"frames":self.frames}],"base":format!("{:#x}",self.base),"trace_build_id":self.build_id}})
    }
    fn perf_text(&self) -> String {
        let mut trace = String::new();
        for line in self.maps.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 6 {
                continue;
            }
            let (start, end) = fields[0].split_once('-').unwrap();
            let start = u64::from_str_radix(start, 16).unwrap();
            let end = u64::from_str_radix(end, 16).unwrap();
            let id = if fields[5] == self.bin.to_str().unwrap() {
                format!("<{}>", self.build_id)
            } else {
                "00:00 1 0".to_owned()
            };
            let _ = writeln!(
                trace,
                "PERF_RECORD_MMAP2 {0}/{0}: [{start:#x}({len:#x}) @ 0x{offset} {id}]: {perms} {path}",
                self.pid,
                len = end - start,
                offset = fields[2],
                perms = fields[1],
                path = fields[5]
            );
        }
        // This is perf-compatible text around real native backtrace addresses, not a perf recording.
        let _ = writeln!(trace, "native {0}/{0} [000] 1.000: cycles: {1} unknown (native)", self.pid, self.frames[0]);
        for frame in &self.frames {
            let _ = writeln!(trace, "        {} unknown (native)", frame.trim_start_matches("0x"));
        }
        trace.push('\n');
        trace
    }
}

#[test]
#[allow(clippy::too_many_lines, clippy::similar_names)] // One coherent native-stack evidence chain.
fn real_pie_stripped_stack_maps_call_sites_and_observed_indirect_edge() {
    let f = Fixture::new();
    let result = f.query(&f.stack_request());
    let frames = result["data"]["result"]["frames"][0].as_array().expect("symbolized native stack");
    assert_eq!(frames[0]["function"]["start"], format!("{:#x}", f.symbols["trace_leaf"]));
    assert_eq!(frames[1]["function"]["start"], format!("{:#x}", f.symbols["trace_middle"]));
    assert_eq!(frames[1]["static_address"], format!("{:#x}", f.symbols["trace_middle_return"]));
    assert!(frames[1]["call_site"].as_str().is_some(), "indirect CALL-end should have instruction evidence: {result}");
    assert!(
        frames.iter().any(|frame| frame["status"] == "outside_target_or_ambiguous_mapping"),
        "shared-library frames remain unknown: {result}"
    );
    let maps = f.root.join("maps.txt");
    fs::write(&maps, &f.maps).unwrap();
    let addresses = f.root.join("addresses.txt");
    fs::write(&addresses, format!("{}\n", f.frames.join(" "))).unwrap();
    let rendered = text(cli(
        &f.bin,
        &[
            "symbolize",
            "--input",
            addresses.to_str().unwrap(),
            "--maps",
            maps.to_str().unwrap(),
            "--target-path",
            f.bin.to_str().unwrap(),
            "--jsonl",
        ],
    ));
    let mapped: Value = serde_json::from_str(rendered.lines().next().unwrap()).unwrap();
    assert_eq!(mapped["frames"][1]["static_address"], frames[1]["static_address"]);
    let collapsed = text(cli(
        &f.bin,
        &[
            "symbolize",
            "--input",
            addresses.to_str().unwrap(),
            "--base",
            &format!("{:#x}", f.base),
            "--collapse",
            "--group-by",
            "caller",
        ],
    ));
    assert!(
        collapsed.contains(&format!(
            "fn_{:x}@{} 1",
            f.symbols["trace_middle"],
            frames[1]["call_site"].as_str().unwrap()
        )),
        "{collapsed}"
    );
    let trace = f.root.join("perf.txt");
    fs::write(&trace, f.perf_text()).unwrap();
    let store = f.root.join("observed.json");
    cli(
        &f.bin,
        &[
            "edges",
            "import",
            "--format",
            "perf",
            "--input",
            trace.to_str().unwrap(),
            "--pid",
            &f.pid.to_string(),
            "--target-path",
            f.bin.to_str().unwrap(),
            "--out",
            store.to_str().unwrap(),
        ],
    );
    let observed: Value = serde_json::from_slice(&fs::read(&store).unwrap()).unwrap();
    assert_eq!(observed["stats"]["frames"], f.frames.len(), "header IP duplication must not invent another frame");
    let caller = format!("{:#x}", f.symbols["trace_middle"]);
    let callee = format!("{:#x}", f.symbols["trace_leaf"]);
    assert!(
        observed["edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge["caller"] == caller && edge["callee"] == callee && edge["sample_count"] == 1),
        "actual indirect adjacency missing: {observed}"
    );
    let static_callers = text(cli(&f.bin, &["callers", &callee]));
    assert!(
        !static_callers.contains(&caller),
        "volatile indirect call should not be a resolved static edge: {static_callers}"
    );
    let combined = text(cli(&f.bin, &["callers", &callee, "--with-observed", store.to_str().unwrap()]));
    assert!(combined.contains("[observed samples=1"), "{combined}");
    let path = text(cli(&f.bin, &["path", &caller, &callee, "--with-observed", store.to_str().unwrap()]));
    assert!(path.contains("[observed samples=1"), "{path}");
    let tree = text(cli(&f.bin, &["tree", &callee, "--callers", "--with-observed", store.to_str().unwrap()]));
    assert!(tree.contains("[observed samples=1"), "{tree}");
    let mut forged = observed;
    forged["image"]["sha256"] = json!("0".repeat(64));
    let wrong = f.root.join("wrong.json");
    fs::write(&wrong, forged.to_string()).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&f.bin)
        .args(["callers", &callee, "--with-observed", wrong.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_mcp_client_symbolizes_the_same_native_stack_without_live_access()
-> Result<(), Box<dyn std::error::Error>> {
    use rmcp::{
        ServiceExt,
        model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation},
        transport::TokioChildProcess,
    };
    let f = Fixture::new();
    let expected = f.query(&f.stack_request());
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_xref"));
    command.arg("-b").arg(&f.bin).arg("mcp");
    let client = ClientConfig::new(ClientCapabilities::default(), Implementation::new("trace-test", "1"))
        .serve(TokioChildProcess::new(command)?)
        .await?;
    let result: Result<(), Box<dyn std::error::Error>> = async {
        let tools = client.list_all_tools().await?;
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "xref_query");
        let request =
            CallToolRequestParams::new("xref_query").with_arguments(rmcp::object!({"request":f.stack_request()}));
        let response = client.call_tool(request).await?.structured_content.ok_or("missing structured symbolization")?;
        assert_eq!(response["data"], expected["data"]);
        let malformed = json!({"operation":"symbolize","request":{"stacks":[],"file":"/proc/1/mem","pid":1}});
        let response = client
            .call_tool(CallToolRequestParams::new("xref_query").with_arguments(rmcp::object!({"request":malformed})))
            .await;
        assert!(response.is_err(), "unknown fields must fail JSON-RPC validation");
        Ok(())
    }
    .await;
    client.cancel().await?;
    result
}

#[test]
#[ignore = "requires perf installed and kernel permission for own-process cpu-clock sampling"]
fn actual_perf_record_of_controlled_native_binary_imports_target_frames() {
    let f = Fixture::new();
    let data = f.root.join("perf.data");
    let perf = std::env::var_os("XREF_TEST_PERF").unwrap_or_else(|| "perf".into());
    output(
        Command::new(&perf)
            .args(["record", "-q", "-e", "cpu-clock:u", "-F", "99", "--call-graph", "fp", "-o"])
            .arg(&data)
            .arg("--")
            .arg(&f.bin)
            .arg("--burn"),
    );
    let script = output(
        Command::new(&perf)
            .args([
                "script",
                "--show-mmap-events",
                "--show-task-events",
                "--show-lost-events",
                "-F",
                "comm,pid,tid,cpu,time,event,ip,sym,dso",
                "-i",
            ])
            .arg(&data),
    );
    let input = f.root.join("actual-perf.txt");
    fs::write(&input, &script.stdout).unwrap();
    let store = f.root.join("actual-observed.json");
    cli(
        &f.bin,
        &[
            "edges",
            "import",
            "--format",
            "perf",
            "--input",
            input.to_str().unwrap(),
            "--target-path",
            f.bin.to_str().unwrap(),
            "--out",
            store.to_str().unwrap(),
        ],
    );
    let report: Value = serde_json::from_slice(&fs::read(&store).unwrap()).unwrap();
    assert!(report["stats"]["samples"].as_u64().unwrap() > 0, "perf produced no sample records: {report}");
    assert!(
        report["stats"]["resolved_frames"].as_u64().unwrap() > 0,
        "real MMAP/perf header should resolve native frames: {report}"
    );
}

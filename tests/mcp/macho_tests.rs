/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_macho_native_queries_and_slice_match_cli() -> Result<(), Error> {
    let image = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/macho/legacy.macho");
    let expected: Value = serde_json::from_slice(&std::fs::read(image.with_extension("json"))?)?;
    let function = format!("{:#x}", expected["symbols"]["_macho_entry"].as_u64().ok_or("entry")?);
    let call = format!("{:#x}", expected["call"].as_u64().ok_or("call")?);
    let config = ClientConfig::new(ClientCapabilities::default(), Implementation::new("xref-macho-test", "1"))
        .with_protocol_version(ProtocolVersion::V_2025_11_25);
    let client = config.serve(transport(&image)?).await?;
    let outcome: Result<(), Error> = async {
        check(client.list_all_tools().await?.len() == 1, "tool discovery")?;
        let request = |v: Value| CallToolRequestParams::new("xref_query").with_arguments(rmcp::object!({"request":v}));
        let info = client.call_tool(request(json!({"operation":"info"}))).await?.structured_content.ok_or("info")?;
        check(info["image"]["format"] == "macho" && info["image"]["base_address"] == "0x100000000", "identity")?;
        check(info["image"]["sha256"] == expected["sha256"], "input hash")?;
        let slice = client.call_tool(request(json!({"operation":"slice","address":function,"to":call}))).await?;
        check(slice.is_error != Some(true), "slice failed")?;
        let value = slice.structured_content.ok_or("slice content")?;
        let human = cli(&image, &["slice", &function, "--to", &call])?;
        check(
            human.status.success() && human.stdout == value["data"]["text"].as_str().ok_or("slice text")?.as_bytes(),
            "Mach-O slice parity",
        )?;
        let args = json!({"operation":"function","address":function});
        let facts = client.call_tool(request(args.clone())).await?.structured_content.ok_or("function")?;
        let output = cli(&image, &["query", &args.to_string()])?;
        check(
            output.status.success() && serde_json::from_slice::<Value>(&output.stdout)? == facts,
            "Mach-O JSON parity",
        )?;
        Ok(())
    }
    .await;
    let cleanup = client.cancel().await;
    outcome?;
    cleanup?;
    Ok(())
}

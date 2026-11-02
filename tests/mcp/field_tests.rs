/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
fn field_fixture() -> Result<PathBuf, Error> {
    let output = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("xref-field-fixture-{}", std::process::id()));
    std::fs::create_dir_all(output.parent().ok_or("fixture parent missing")?)?;
    let status = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .args(["--edition=2021", "-C", "opt-level=2", "-C", "force-unwind-tables=yes", "-C", "strip=symbols", "-o"])
        .arg(&output)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/field_origin.rs"))
        .status()?;
    check(status.success(), "field fixture compilation failed")?;
    Ok(output)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_field_origin_provenance_and_selected_slice_match_cli() -> Result<(), Error> {
    let image = field_fixture()?;
    let client = ClientConfig::new(ClientCapabilities::default(), Implementation::new("xref-field-test", "1"))
        .with_protocol_version(ProtocolVersion::V_2025_11_25)
        .serve(transport(&image)?)
        .await?;
    let outcome: Result<(), Error> = async {
        let request = |v:Value| CallToolRequestParams::new("xref_query").with_arguments(rmcp::object!({"request":v}));
        let strings = client.call_tool(request(json!({"operation":"strings","text":"XREF_FIELD_ORIGIN_NEEDLE"}))).await?
            .structured_content.ok_or("strings")?;
        let address = strings["data"]["locations"][0].as_str().ok_or("marker")?;
        let refs = client.call_tool(request(json!({"operation":"refs","address":address}))).await?
            .structured_content.ok_or("refs")?;
        let function = refs["data"]["references"][0]["function"]["start"].as_str().ok_or("function")?;
        let mut query = json!({"operation":"field_origin","request":{"address":function,"register":"rdi","offsets":["0x18"],"callees":true}});
        let result = client.call_tool(request(query.clone())).await?;
        check(result.is_error!=Some(true),"field query failed")?;
        let result = result.structured_content.ok_or("field report")?;
        let report = &result["data"]["report"];
        let call = report["calls"].as_array().and_then(|v|v.first()).ok_or("field call")?;
        let args = call["arguments"].as_array().ok_or("arguments")?;
        check(args.iter().any(|a|a["register"]=="rsi" && a["relation"]=="field_address"),"address relationship missing")?;
        check(args.iter().any(|a|a["register"]=="rdx" && a["relation"]=="loaded_value" && a["load_width_bytes"]==8),"loaded value missing")?;
        check(report["accesses"].as_array().is_some_and(|v|v.iter().any(|a|a["via"]["argument_register"]=="rsi" && a["access"]=="read_write" && !a["instruction"]["bytes"].as_str().unwrap_or("").is_empty())),"callee memory evidence missing")?;
        check(report["slice"].is_null(),"discovery rendered a slice")?;
        let token = call["selection"].clone();
        check(token["image_sha256"]==result["image"]["sha256"],"selection digest missing")?;
        query["request"]["selection"]=token.clone();
        let result = client.call_tool(request(query.clone())).await?.structured_content.ok_or("selected report")?;
        let slice = &result["data"]["report"]["slice"];
        let text = slice["data"]["text"].as_str().ok_or("slice")?;
        let human = cli(&image,&["slice",token["function"].as_str().ok_or("function")?,"--to",token["call_site"].as_str().ok_or("site")?])?;
        check(human.status.success() && human.stdout==text.as_bytes(),"field slice and CLI differ")?;
        let output = cli(&image,&["query",&query.to_string()])?;
        let cli_value:Value=serde_json::from_slice(&output.stdout)?;
        check(output.status.success() && cli_value==result,"field JSON CLI and MCP differ")?;
        Ok(())
    }.await;
    let cleanup = client.cancel().await;
    let removal = std::fs::remove_file(image);
    outcome?;
    cleanup?;
    removal?;
    Ok(())
}

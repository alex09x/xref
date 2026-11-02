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
async fn mcp_compound_discovery_and_selected_slice_preserve_evidence() -> Result<(), Error> {
    let image = fixture()?;
    let client = ClientConfig::new(ClientCapabilities::default(), Implementation::new("xref-compound-test", "1"))
        .with_protocol_version(ProtocolVersion::V_2025_11_25)
        .serve(transport(&image)?)
        .await?;
    let outcome: Result<(), Error> = async {
        let request =
            |value: Value| CallToolRequestParams::new("xref_query").with_arguments(rmcp::object!({"request":value}));
        let shape = json!({"operation":"investigate","request":{
            "seed":{"kind":"text","text":"XREF_MCP_BOUNDARY_NEEDLE"},"limits":{"depth":0}
        }});
        let result = client.call_tool(request(shape.clone())).await?;
        check(result.is_error != Some(true), "compound discovery failed")?;
        let result = result.structured_content.ok_or("missing compound discovery")?;
        let trail = &result["data"]["investigation"];
        check(
            trail["evidence"].as_array().is_some_and(|steps| {
                steps.iter().any(|s| s["operation"] == "refs" && s["parent"] == 0)
                    && steps.iter().all(|s| s["operation"] != "slice")
            }),
            "discovery evidence or laziness lost",
        )?;
        let candidates = trail["call_sites"].as_array().ok_or("missing callsite candidates")?;
        check(!candidates.is_empty(), "fixture calls not discovered")?;
        let selection = candidates[0]["selection"].clone();
        check(selection["image_sha256"] == result["image"]["sha256"], "selection not bound to image")?;
        let mut chosen = shape;
        chosen["request"]["selection"] = selection.clone();
        let result = client.call_tool(request(chosen.clone())).await?;
        check(result.is_error != Some(true), "selected investigation failed")?;
        let result = result.structured_content.ok_or("missing selected investigation")?;
        let steps = result["data"]["investigation"]["evidence"].as_array().ok_or("missing selected evidence")?;
        let sliced = steps.iter().find(|s| s["operation"] == "slice").ok_or("selected slice not rendered")?;
        check(sliced["target"] == selection["call_site"], "slice changed selected instruction")?;
        let human = cli(
            &image,
            &[
                "slice",
                selection["function"].as_str().ok_or("function missing")?,
                "--to",
                selection["call_site"].as_str().ok_or("site missing")?,
            ],
        )?;
        check(
            human.status.success()
                && human.stdout == sliced["data"]["text"].as_str().ok_or("slice text missing")?.as_bytes(),
            "compound slice differs from human CLI",
        )?;
        let cli_result = cli(&image, &["query", &chosen.to_string()])?;
        let cli_value: Value = serde_json::from_slice(&cli_result.stdout)?;
        check(cli_result.status.success() && cli_value == result, "MCP and CLI compound results differ")?;
        Ok(())
    }
    .await;
    let cleanup = client.cancel().await;
    let removal = std::fs::remove_file(image);
    outcome?;
    cleanup?;
    removal?;
    Ok(())
}

use super::rest_impl_tests::{
    CaptureSink, response_json, seed_unloaded_render_capability, test_gateway_state, trace_headers,
};
use super::*;
use std::sync::Arc;

#[tokio::test]
async fn gateway_rest_v1_call_rejects_missing_tool_slug_and_calls() {
    let gs = test_gateway_state("1.2.3");
    let (status, body) = response_json(
        handle_v1_call(State(gs), HeaderMap::new(), Json(json!({"arguments": {}}))).await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["kind"], "bad-request");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("tool_slug or calls")),
        "expected message mentioning tool_slug or calls, got {:?}",
        body["error"]["message"]
    );
}

#[tokio::test]
async fn gateway_rest_v1_call_batch_via_calls_dispatches_batch_response() {
    let gs = test_gateway_state("1.2.3");
    // Seeded capability — backend won't be reachable but batch dispatch
    // is validated through the response envelope shape.
    seed_unloaded_render_capability(&gs);
    let slug = "maya.00000000-0000-0000-0000-000000000000.render";

    let (status, body) = response_json(
        handle_v1_call(
            State(gs),
            trace_headers(),
            Json(json!({
                "calls": [
                    {"id": "step-1", "tool_slug": slug, "arguments": {"radius": 3.0}},
                    {"id": "step-2", "tool_slug": "missing.slug", "arguments": {}}
                ],
                "stop_on_error": false
            })),
        )
        .await,
    )
    .await;
    // Batch dispatch succeeds at the gateway level — individual items may
    // fail because no backend is live, but the response envelope is the
    // batch shape.
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("success").is_some(),
        "batch response should have 'success'"
    );
    assert!(
        body.get("results").is_some(),
        "batch response should have 'results'"
    );
    assert!(
        body["results"]
            .as_array()
            .is_some_and(|results| results.len() == 2),
        "expected 2 results, got {:?}",
        body["results"]
    );
    assert_eq!(body["stop_on_error"], false);
    assert_eq!(body["results"][0]["id"], "step-1");
    assert_eq!(body["results"][1]["id"], "step-2");
    assert_eq!(body["results"][0]["index"], 0);
    assert_eq!(body["results"][1]["index"], 1);
}

#[tokio::test]
async fn gateway_rest_v1_call_single_tool_slug_accepts_params_alias() {
    use crate::gateway::middleware::{AuditMiddleware, MiddlewareChain};

    let sink = Arc::new(CaptureSink::default());
    let mut gs = test_gateway_state("1.2.3");
    gs.middleware_chain =
        Arc::new(MiddlewareChain::new().with_after(Arc::new(AuditMiddleware::new(sink.clone()))));
    // Without a live backend single-call reports the prior owner as gone,
    // but the dispatch path must still be exercised (backward compat).
    seed_unloaded_render_capability(&gs);
    let slug = "maya.00000000-0000-0000-0000-000000000000.render";

    let (status, body) = response_json(
        handle_v1_call(
            State(gs),
            HeaderMap::new(),
            Json(json!({"tool_slug": slug, "params": {"radius": 3.0}})),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(body["error"]["previous_status"], "exited");
    assert_eq!(body["error"]["retryable"], false);
    assert!(body["error"]["recommended_next_action"].is_string());
    assert!(
        body.get("error").is_some(),
        "single-call error should have 'error', got {:?}",
        body
    );
    assert!(
        body.get("success").is_none(),
        "single-call error should NOT have batch 'success' field"
    );
    let entries = sink.0.lock().unwrap();
    let input: Value = serde_json::from_str(
        &entries[0]
            .input_payload
            .as_ref()
            .expect("REST audit should capture call arguments")
            .content,
    )
    .unwrap();
    assert_eq!(input["radius"], 3.0);
}

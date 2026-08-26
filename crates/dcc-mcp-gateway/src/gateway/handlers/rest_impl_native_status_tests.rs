use super::*;

use axum::http::HeaderMap;
use dcc_mcp_transport::discovery::file_registry::FileRegistry;
use dcc_mcp_transport::discovery::types::ServiceEntry;
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::sync::Arc;

struct FakeCallBackend {
    state: GatewayState,
    instance_id: uuid::Uuid,
    slug: String,
    traffic: Arc<Mutex<Vec<dcc_mcp_actions::events::EventEnvelope>>>,
    _registry_dir: tempfile::TempDir,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn fake_call_backend() -> FakeCallBackend {
    let app = axum::Router::new().route(
        "/v1/call",
        axum::routing::post(
            |headers: HeaderMap, axum::Json(body): axum::Json<Value>| async move {
                let request_id = headers
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();
                let scenario = body
                    .pointer("/arguments/scenario")
                    .and_then(Value::as_str)
                    .unwrap_or("pending");
                let (status, output) = match scenario {
                    "completed" => (
                        StatusCode::OK,
                        json!({"status": "completed", "job_id": "native-job-42"}),
                    ),
                    "empty-job" => (
                        StatusCode::ACCEPTED,
                        json!({"status": "pending", "job_id": ""}),
                    ),
                    _ => (
                        StatusCode::ACCEPTED,
                        json!({"status": "pending", "job_id": "native-job-42"}),
                    ),
                };
                (
                    status,
                    axum::Json(json!({
                        "slug": body["tool_slug"],
                        "output": output,
                        "validation_skipped": false,
                        "request_id": request_id,
                    })),
                )
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let registry_dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(FileRegistry::new(registry_dir.path()).unwrap());
    let entry = ServiceEntry::new("nuke", "127.0.0.1", port);
    let instance_id = entry.instance_id;
    registry.register(entry).unwrap();

    let slug = crate::gateway::capability::tool_slug("nuke", &instance_id, "render_sequence");
    let record = crate::gateway::capability::CapabilityRecord::new(
        slug.clone(),
        "render_sequence".to_string(),
        "render_sequence".to_string(),
        Some("layered-compositing".to_string()),
        "Render a sequence",
        Vec::new(),
        "nuke".to_string(),
        instance_id,
        true,
        true,
        None,
    );

    let mut state = super::rest_impl_tests::test_gateway_state("1.2.3");
    state.registry = registry;
    state.capability_index.upsert_instance(
        instance_id,
        vec![record],
        crate::gateway::capability::InstanceFingerprint(1),
    );
    let traffic = Arc::new(Mutex::new(Vec::new()));
    let traffic_sink = traffic.clone();
    let _subscription = state
        .traffic_capture
        .subscribe_redacted_frames(move |frame| traffic_sink.lock().push(frame.clone()));

    FakeCallBackend {
        state,
        instance_id,
        slug,
        traffic,
        _registry_dir: registry_dir,
        shutdown,
    }
}

fn request_headers(request_id: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", request_id.parse().unwrap());
    headers
}

#[tokio::test]
async fn gateway_call_routes_preserve_native_pending_status_and_traces() {
    let backend = fake_call_backend().await;

    let (canonical_status, canonical_body) = super::rest_impl_tests::response_json(
        handle_v1_call(
            State(backend.state.clone()),
            request_headers("req-canonical-pending"),
            Json(json!({
                "tool_slug": backend.slug,
                "arguments": {"scenario": "pending"},
            })),
        )
        .await,
    )
    .await;
    assert_eq!(canonical_status, StatusCode::ACCEPTED);
    assert_eq!(canonical_body["output"]["status"], "pending");
    assert_eq!(canonical_body["output"]["job_id"], "native-job-42");

    let (instance_status, instance_body) = super::rest_impl_tests::response_json(
        handle_v1_dcc_instance_call(
            State(backend.state.clone()),
            request_headers("req-instance-pending"),
            Path(("nuke".to_string(), backend.instance_id.to_string())),
            Json(json!({
                "backend_tool": "render_sequence",
                "arguments": {"scenario": "pending"},
            })),
        )
        .await,
    )
    .await;
    assert_eq!(instance_status, StatusCode::ACCEPTED);
    assert_eq!(instance_body["output"]["status"], "pending");

    let (completed_status, _) = super::rest_impl_tests::response_json(
        handle_v1_call(
            State(backend.state.clone()),
            request_headers("req-canonical-completed"),
            Json(json!({
                "tool_slug": backend.slug,
                "arguments": {"scenario": "completed"},
            })),
        )
        .await,
    )
    .await;
    assert_eq!(completed_status, StatusCode::OK);

    let (invalid_pending_status, _) = super::rest_impl_tests::response_json(
        handle_v1_call(
            State(backend.state.clone()),
            request_headers("req-invalid-pending"),
            Json(json!({
                "tool_slug": backend.slug,
                "arguments": {"scenario": "empty-job"},
            })),
        )
        .await,
    )
    .await;
    assert_eq!(invalid_pending_status, StatusCode::OK);

    let traffic = backend.traffic.lock();
    for (request_id, expected) in [
        ("req-canonical-pending", 202),
        ("req-instance-pending", 202),
        ("req-canonical-completed", 200),
        ("req-invalid-pending", 200),
    ] {
        let outbound = traffic
            .iter()
            .find(|frame| {
                frame.attributes["leg"] == "gateway_to_client"
                    && frame.correlation["request_id"] == request_id
            })
            .expect("gateway response trace");
        assert_eq!(outbound.attributes["http"]["status"], expected);
    }
    let backend_statuses: Vec<_> = traffic
        .iter()
        .filter(|frame| frame.attributes["leg"] == "adapter_to_gateway")
        .filter_map(|frame| frame.attributes["http"]["status"].as_u64())
        .collect();
    assert_eq!(backend_statuses, [202, 202, 200, 202]);
    drop(traffic);

    let openapi = crate::gateway::rest_openapi::build_gateway_openapi_document("1.2.3");
    for path in [
        "/v1/call",
        "/v1/dcc/{dcc_type}/instances/{instance_id}/call",
    ] {
        assert_eq!(
            openapi["paths"][path]["post"]["responses"]["202"]["content"]["application/json"]["schema"]
                ["$ref"],
            "#/components/schemas/CallOutcome"
        );
    }
    assert!(
        openapi["paths"]["/v1/call_batch"]["post"]["responses"]
            .get("202")
            .is_none()
    );

    let _ = backend.shutdown.send(());
}

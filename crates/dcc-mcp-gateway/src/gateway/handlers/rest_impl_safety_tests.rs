use super::rest_impl_tests::{
    CaptureSink, policy_record, response_json, test_dispatch_ingress, test_gateway_state,
};
use super::*;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

struct AuthBackendProof {
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<BackendRequestObservation>>>,
    authorization_headers: Arc<Mutex<Vec<Option<String>>>>,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendRequestObservation {
    http_method: String,
    uri: String,
    jsonrpc_method: Option<String>,
    backend_tool: Option<String>,
}

#[derive(Default)]
struct ParkingCaptureSink(Mutex<Vec<crate::gateway::middleware::AuditEntry>>);

impl crate::gateway::middleware::AuditSink for ParkingCaptureSink {
    fn record(&self, entry: crate::gateway::middleware::AuditEntry) {
        self.0.lock().push(entry);
    }
}

fn assert_audit_target_matches_backend(
    entry: &crate::gateway::middleware::AuditEntry,
    request: &BackendRequestObservation,
    dcc_type: &str,
    instance_id: uuid::Uuid,
) {
    let backend_tool = request
        .backend_tool
        .as_deref()
        .expect("backend request should name the dispatched tool");
    let observed_slug = format!("{dcc_type}.{instance_id}.{backend_tool}");
    assert_eq!(entry.tool_slug.as_deref(), Some(observed_slug.as_str()));
    let execution_span = entry
        .trace_spans
        .iter()
        .find(|span| matches!(span.name.as_str(), "backend.execute" | "batch.execute"))
        .expect("audit entry should include the effective execution span");
    assert_eq!(
        execution_span.attributes.get("tool_slug"),
        Some(&json!(observed_slug))
    );
}

struct CountBeforeMiddleware(Arc<AtomicUsize>);

impl crate::gateway::middleware::BeforeCallMiddleware for CountBeforeMiddleware {
    fn before_call<'a>(
        &'a self,
        _ctx: &'a mut crate::gateway::middleware::CallContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), crate::gateway::middleware::MiddlewareError>,
                > + Send
                + 'a,
        >,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

struct RewriteDispatchTarget {
    target_slug: Arc<Mutex<String>>,
    calls: Arc<AtomicUsize>,
}

impl crate::gateway::middleware::BeforeCallMiddleware for RewriteDispatchTarget {
    fn before_call<'a>(
        &'a self,
        ctx: &'a mut crate::gateway::middleware::CallContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), crate::gateway::middleware::MiddlewareError>,
                > + Send
                + 'a,
        >,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let target_slug = self.target_slug.lock().clone();
        ctx.tool_slug = Some(target_slug.clone());
        if let Some(calls) = ctx.args.get_mut("calls").and_then(Value::as_array_mut) {
            for call in calls {
                if let Some(call) = call.as_object_mut() {
                    call.insert("tool_slug".to_string(), json!(target_slug));
                }
            }
        } else if let Some(args) = ctx.args.as_object_mut()
            && args.contains_key("tool_slug")
        {
            args.insert("tool_slug".to_string(), json!(target_slug));
        }
        Box::pin(async { Ok(()) })
    }
}

async fn seed_auth_backend(
    gs: &GatewayState,
) -> (
    String,
    uuid::Uuid,
    tokio::sync::oneshot::Sender<()>,
    AuthBackendProof,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let authorization_headers = Arc::new(Mutex::new(Vec::new()));
    let route_calls = calls.clone();
    let route_requests = requests.clone();
    let route_headers = authorization_headers.clone();
    let handler = move |request: axum::extract::Request| {
        let calls = route_calls.clone();
        let requests = route_requests.clone();
        let authorization_headers = route_headers.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = to_bytes(body, 1024 * 1024).await.unwrap();
            let payload = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
            calls.fetch_add(1, Ordering::SeqCst);
            requests.lock().push(BackendRequestObservation {
                http_method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                jsonrpc_method: payload
                    .get("method")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                backend_tool: payload
                    .pointer("/params/name")
                    .or_else(|| payload.get("tool_slug"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
            authorization_headers.lock().push(
                parts
                    .headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
            );
            let id = payload.get("id").cloned().unwrap_or(json!(1));
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"content": [], "isError": false},
                "success": true
            });
            if matches!(parts.uri.path(), "/v1/call" | "/mcp") {
                Json(response).into_response()
            } else {
                (StatusCode::NOT_FOUND, Json(response)).into_response()
            }
        }
    };
    // A fallback on an otherwise empty router observes every HTTP method and
    // URI, including unexpected discovery or readiness probes. Negative auth
    // assertions therefore prove zero backend I/O rather than only zero calls
    // to the two expected dispatch paths.
    let app = axum::Router::new().fallback(handler);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });

    let instance_id = uuid::Uuid::new_v4();
    let mut entry = ServiceEntry::new("maya", "127.0.0.1", port);
    entry.instance_id = instance_id;
    entry
        .metadata
        .insert("mcp_url".into(), format!("http://127.0.0.1:{port}/mcp"));
    gs.registry.register(entry).unwrap();
    let record = policy_record("maya", instance_id, "mutate", "scene-edit", false);
    let slug = record.tool_slug.clone();
    gs.capability_index.upsert_instance(
        instance_id,
        vec![record],
        crate::gateway::capability::InstanceFingerprint(1),
    );
    (
        slug,
        instance_id,
        tx,
        AuthBackendProof {
            calls,
            requests,
            authorization_headers,
            port,
        },
    )
}

async fn post_gateway(
    router: axum::Router,
    uri: &str,
    authorization: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", "application/json");
    if let Some(authorization) = authorization {
        request = request.header("authorization", authorization);
    }
    let response = router
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn seed_call_backend(
    gs: &GatewayState,
    payload: Value,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = axum::Router::new().route(
        "/v1/call",
        axum::routing::post(move || {
            let payload = payload.clone();
            async move { Json(payload) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });

    let instance_id = uuid::Uuid::new_v4();
    let mut entry = ServiceEntry::new("maya", "127.0.0.1", port);
    entry.instance_id = instance_id;
    entry
        .metadata
        .insert("mcp_url".into(), format!("http://127.0.0.1:{port}/mcp"));
    gs.registry.register(entry).unwrap();
    let record = policy_record("maya", instance_id, "capture", "ui-control", true);
    let slug = record.tool_slug.clone();
    gs.capability_index.upsert_instance(
        instance_id,
        vec![record],
        crate::gateway::capability::InstanceFingerprint(1),
    );
    (slug, tx)
}

#[tokio::test]
async fn transport_success_with_tool_failure_stays_http_ok_but_fails_mcp_and_batch() {
    use crate::gateway::middleware::{AuditMiddleware, MiddlewareChain};

    let sink = Arc::new(CaptureSink::default());
    let mut gs = test_gateway_state("1.2.3");
    gs.middleware_chain =
        Arc::new(MiddlewareChain::new().with_after(Arc::new(AuditMiddleware::new(sink.clone()))));
    let (slug, shutdown) = seed_call_backend(
        &gs,
        json!({
            "success": true,
            "output": {"success": false, "message": "tool domain failure"}
        }),
    )
    .await;
    let dispatch_context = gs
        .auth
        .authenticate_dispatch(crate::gateway::security::PresentedAuthorization::new(None))
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("accept", "application/json".parse().unwrap());

    let (status, rest_body) = response_json(
        handle_v1_call(
            State(gs.clone()),
            headers,
            Json(json!({
                "tool_slug": slug,
                "arguments": {
                    "action": "type",
                    "text": "rest-private-text",
                    "password": "rest-password",
                    "access_token": "rest-token"
                }
            })),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "backend transport succeeded");
    assert_eq!(rest_body["output"]["success"], false);
    {
        let entries = sink.0.lock().unwrap();
        assert!(entries[0].is_error);
        let input = &entries[0].input_payload.as_ref().unwrap().content;
        for secret in ["rest-private-text", "rest-password", "rest-token"] {
            assert!(!input.contains(secret));
            assert!(!serde_json::to_string(&rest_body).unwrap().contains(secret));
        }
    }

    let (mcp_text, mcp_is_error) = crate::gateway::tools::tool_call_tool(
        &gs,
        &json!({"tool_slug": slug, "arguments": {}}),
        None,
        &dispatch_context,
        None,
        None,
    )
    .await;
    assert!(
        mcp_is_error,
        "MCP must expose the domain failure via isError"
    );
    assert!(mcp_text.contains("tool domain failure"));

    let batch = crate::gateway::tools::gateway_call_batch_inner(
        &gs,
        &json!({"calls": [{"tool_slug": slug, "arguments": {}}]}),
        None,
        &dispatch_context,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(batch["success"], false);
    assert_eq!(batch["results"][0]["ok"], false);
    assert_eq!(batch["results"][0]["error"]["kind"], "tool-error");
    assert_eq!(batch["results"][0]["result"]["output"]["success"], false);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn rest_single_keeps_images_in_response_but_redacts_audit_payloads() {
    use crate::gateway::middleware::{AuditMiddleware, MiddlewareChain};

    let rich_image = format!("RICH_IMAGE_{}", "A".repeat(8192));
    let mcp_image = format!("MCP_IMAGE_{}", "B".repeat(8192));
    let backend_output = json!({
        "success": true,
        "output": {
            "context": {
                "__rich__": {
                    "kind": "image",
                    "mime": "image/png",
                    "data": rich_image,
                }
            },
            "content": [{
                "type": "image",
                "mimeType": "image/png",
                "data": mcp_image,
            }]
        }
    });
    let sink = Arc::new(CaptureSink::default());
    let mut gs = test_gateway_state("1.2.3");
    gs.middleware_chain =
        Arc::new(MiddlewareChain::new().with_after(Arc::new(AuditMiddleware::new(sink.clone()))));
    let (slug, shutdown) = seed_call_backend(&gs, backend_output).await;
    let request_body = json!({
        "tool_slug": slug,
        "arguments": {},
        "response_format": "json",
    });
    let headers = HeaderMap::new();
    let ingress = test_dispatch_ingress(&gs, &headers);

    let response = call_service_with_admin_trace(
        &gs,
        &ingress,
        RestCallTraceRequest {
            method: "v1/call",
            slug: request_body["tool_slug"].as_str().unwrap(),
            arguments: json!({}),
            meta: None,
            request_body: &request_body,
            trace_context: crate::gateway::admin::trace::TraceContext::from_headers(&headers),
        },
    )
    .await
    .expect("single call should preserve the backend response");

    assert!(
        response
            .pointer("/output/context/__rich__/data")
            .and_then(Value::as_str)
            .is_some_and(|data| data.starts_with("RICH_IMAGE_"))
    );
    assert!(
        response
            .pointer("/output/content/0/data")
            .and_then(Value::as_str)
            .is_some_and(|data| data.starts_with("MCP_IMAGE_"))
    );
    let entries = sink.0.lock().unwrap();
    let entry = entries.first().expect("single call should be audited");
    assert!(!entry.result_preview.contains("RICH_IMAGE_"));
    assert!(!entry.result_preview.contains("MCP_IMAGE_"));
    let output = &entry.output_payload.as_ref().unwrap().content;
    assert!(!output.contains("RICH_IMAGE_"));
    assert!(!output.contains("MCP_IMAGE_"));
    assert!(output.contains(INLINE_IMAGE_TRACE_PLACEHOLDER));
    assert!(entry.token_accounting.as_ref().unwrap().original_bytes < rich_image.len());
    drop(entries);
    let _ = shutdown.send(());
}

#[tokio::test]
async fn rest_batch_keeps_images_in_response_but_redacts_audit_payloads() {
    use crate::gateway::middleware::{AuditMiddleware, MiddlewareChain};

    let rich_image = format!("BATCH_RICH_IMAGE_{}", "A".repeat(8192));
    let mcp_image = format!("BATCH_MCP_IMAGE_{}", "B".repeat(8192));
    let backend_output = json!({
        "success": true,
        "output": {
            "context": {
                "__rich__": {
                    "kind": "image",
                    "mime": "image/png",
                    "data": rich_image,
                }
            },
            "content": [{
                "type": "image",
                "mimeType": "image/png",
                "data": mcp_image,
            }]
        }
    });
    let sink = Arc::new(CaptureSink::default());
    let mut gs = test_gateway_state("1.2.3");
    gs.middleware_chain =
        Arc::new(MiddlewareChain::new().with_after(Arc::new(AuditMiddleware::new(sink.clone()))));
    let (slug, shutdown) = seed_call_backend(&gs, backend_output).await;
    let request_body = json!({
        "calls": [{"tool_slug": slug, "arguments": {}}],
        "response_format": "toon",
    });
    let headers = HeaderMap::new();
    let ingress = test_dispatch_ingress(&gs, &headers);

    let response = call_batch_with_admin_trace(
        &gs,
        &ingress,
        &request_body,
        crate::gateway::admin::trace::TraceContext::from_headers(&headers),
    )
    .await
    .expect("batch call should preserve the backend response");

    assert!(
        response
            .pointer("/results/0/result/output/context/__rich__/data")
            .and_then(Value::as_str)
            .is_some_and(|data| data.starts_with("BATCH_RICH_IMAGE_"))
    );
    assert!(
        response
            .pointer("/results/0/result/output/content/0/data")
            .and_then(Value::as_str)
            .is_some_and(|data| data.starts_with("BATCH_MCP_IMAGE_"))
    );
    let entries = sink.0.lock().unwrap();
    let entry = entries.first().expect("batch call should be audited");
    assert!(!entry.result_preview.contains("BATCH_RICH_IMAGE_"));
    assert!(!entry.result_preview.contains("BATCH_MCP_IMAGE_"));
    let output = &entry.output_payload.as_ref().unwrap().content;
    assert!(!output.contains("BATCH_RICH_IMAGE_"));
    assert!(!output.contains("BATCH_MCP_IMAGE_"));
    assert!(output.contains(INLINE_IMAGE_TRACE_PLACEHOLDER));
    let tokens = entry.token_accounting.as_ref().unwrap();
    assert_eq!(tokens.response_format, "toon");
    assert!(tokens.original_bytes < rich_image.len());
    assert!(tokens.returned_bytes < rich_image.len());
    drop(entries);
    let _ = shutdown.send(());
}

#[tokio::test]
async fn configured_auth_gates_rest_mcp_and_batch_before_backend_dispatch() {
    let secret = "gateway-call-secret";
    let mut gs = test_gateway_state("1.2.3");
    gs.auth = Arc::new(crate::gateway::security::GatewayAuth {
        tokens: vec![
            crate::gateway::security::GatewayAuthToken::for_dcc(secret, ["maya"]),
            crate::gateway::security::GatewayAuthToken::for_dcc("nuke-scoped-secret", ["nuke"]),
        ],
    });
    let middleware_calls = Arc::new(AtomicUsize::new(0));
    gs.middleware_chain = Arc::new(
        crate::gateway::middleware::MiddlewareChain::new()
            .with_before(Arc::new(CountBeforeMiddleware(middleware_calls.clone()))),
    );
    let (slug, instance_id, shutdown, proof) = seed_auth_backend(&gs).await;
    let router = crate::gateway::router::build_gateway_router(gs.clone());
    let full_uuid_slug = format!("maya.{instance_id}.mutate");
    let unindexed_full_uuid_slug = format!("maya.{instance_id}.newly_registered_mutation");

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call",
        None,
        json!({"tool_slug": slug, "arguments": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["kind"], "unauthorized");
    assert!(!body.to_string().contains(secret));
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert!(
        proof.requests.lock().is_empty(),
        "credential rejection must precede every backend method, including tools/list"
    );
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);

    let exact_uri = format!("/v1/dcc/maya/instances/{instance_id}/call");
    let (status, body) = post_gateway(
        router.clone(),
        &exact_uri,
        None,
        json!({"backend_tool": "mutate", "arguments": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["kind"], "unauthorized");
    assert!(!body.to_string().contains(secret));
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call_batch",
        Some("Bearer nuke-scoped-secret"),
        json!({"calls": [{"id": "one", "tool_slug": slug, "arguments": {}}]}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["success"], false);
    assert_eq!(body["error"]["kind"], "unauthorized");
    assert!(!body.to_string().contains(secret));
    assert!(!body.to_string().contains("nuke-scoped-secret"));
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);

    let (status, body) = post_gateway(
        router.clone(),
        "/mcp",
        None,
        json!({
            "jsonrpc": "2.0",
            "id": "mcp-missing-auth",
            "method": "tools/call",
            "params": {
                "name": "call",
                "arguments": {"tool_slug": slug, "arguments": {}}
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "mcp-missing-auth");
    assert_eq!(body["result"]["isError"], true);
    assert!(body.to_string().contains("unauthorized"));
    assert!(!body.to_string().contains(secret));
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);
    assert!(gs.pending_calls.read().await.is_empty());

    let (status, body) = post_gateway(
        router.clone(),
        "/mcp",
        Some("Bearer nuke-scoped-secret"),
        json!({
            "jsonrpc": "2.0",
            "id": "mcp-wrong-scope",
            "method": "tools/call",
            "params": {
                "name": "call_tool",
                "arguments": {
                    "tool_slug": unindexed_full_uuid_slug.clone(),
                    "arguments": {}
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "mcp-wrong-scope");
    assert_eq!(body["result"]["isError"], true);
    assert!(body.to_string().contains("unauthorized"));
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);
    assert!(gs.pending_calls.read().await.is_empty());
    assert_eq!(gs.search_telemetry.snapshot(1).total, 0);

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call",
        Some("Basic not-a-bearer"),
        json!({"tool_slug": slug, "arguments": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["kind"], "unauthorized");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert!(proof.requests.lock().is_empty());
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call",
        Some("Bearer nuke-scoped-secret"),
        json!({"tool_slug": unindexed_full_uuid_slug, "arguments": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["kind"], "unauthorized");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert!(
        proof.requests.lock().is_empty(),
        "scope rejection must precede recovery tools/list I/O"
    );
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);
    assert_eq!(gs.search_telemetry.snapshot(1).total, 0);

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call",
        Some(&format!("Bearer {secret}")),
        json!({"tool_slug": slug, "arguments": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 1);

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call_batch",
        Some(&format!("Bearer {secret}")),
        json!({"calls": [{"tool_slug": slug, "arguments": {}}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(proof.calls.load(Ordering::SeqCst), 2);

    let (status, body) = post_gateway(
        router.clone(),
        "/mcp",
        Some(&format!("Bearer {secret}")),
        json!({
            "jsonrpc": "2.0",
            "id": "mcp-valid-auth",
            "method": "tools/call",
            "params": {
                "name": "call",
                "arguments": {"tool_slug": full_uuid_slug, "arguments": {}}
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "mcp-valid-auth");
    assert_eq!(body["result"]["isError"], false);
    assert_eq!(proof.calls.load(Ordering::SeqCst), 3);

    let (status, body) = post_gateway(
        router.clone(),
        &exact_uri,
        Some(&format!("Bearer {secret}")),
        json!({"backend_tool": "mutate", "arguments": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(proof.calls.load(Ordering::SeqCst) >= 4);

    let calls_before_mcp_batch = proof.calls.load(Ordering::SeqCst);
    let (status, body) = post_gateway(
        router,
        "/mcp",
        Some(&format!("Bearer {secret}")),
        json!({
            "jsonrpc": "2.0",
            "id": "mcp-valid-call-tools",
            "method": "tools/call",
            "params": {
                "name": "call_tools",
                "arguments": {
                    "calls": [{"tool_slug": slug, "arguments": {}}]
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "mcp-valid-call-tools");
    assert_eq!(body["result"]["isError"], false);
    assert!(proof.calls.load(Ordering::SeqCst) > calls_before_mcp_batch);
    assert!(
        proof
            .authorization_headers
            .lock()
            .iter()
            .all(Option::is_none)
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn middleware_route_rewrites_are_reauthorized_before_effective_dispatch() {
    let secret = "gateway-rewrite-secret";
    let mut gs = test_gateway_state("1.2.3");
    gs.auth = Arc::new(crate::gateway::security::GatewayAuth {
        tokens: vec![crate::gateway::security::GatewayAuthToken::for_dcc(
            secret,
            ["maya"],
        )],
    });
    let (original_slug, maya_id, shutdown, proof) = seed_auth_backend(&gs).await;

    let same_scope_tool = "same_scope_mutation";
    let same_scope_record = policy_record("maya", maya_id, same_scope_tool, "scene-edit", false);
    gs.capability_index.upsert_instance(
        maya_id,
        vec![
            policy_record("maya", maya_id, "mutate", "scene-edit", false),
            same_scope_record,
        ],
        crate::gateway::capability::InstanceFingerprint(2),
    );
    let same_scope_full_uuid_slug = format!("maya.{maya_id}.{same_scope_tool}");

    let nuke_id = uuid::Uuid::new_v4();
    let mut nuke_entry = ServiceEntry::new("nuke", "127.0.0.1", proof.port);
    nuke_entry.instance_id = nuke_id;
    nuke_entry.metadata.insert(
        "mcp_url".into(),
        format!("http://127.0.0.1:{}/mcp", proof.port),
    );
    gs.registry.register(nuke_entry).unwrap();
    let wrong_scope_full_uuid_slug = format!("nuke.{nuke_id}.unindexed_mutation");

    let rewritten_target = Arc::new(Mutex::new(wrong_scope_full_uuid_slug));
    let middleware_calls = Arc::new(AtomicUsize::new(0));
    let audit_entries = Arc::new(ParkingCaptureSink::default());
    let audit_middleware = Arc::new(crate::gateway::middleware::AuditMiddleware::new(
        audit_entries.clone(),
    ));
    gs.middleware_chain = Arc::new(
        crate::gateway::middleware::MiddlewareChain::new()
            .with_before(audit_middleware.clone())
            .with_before(Arc::new(RewriteDispatchTarget {
                target_slug: rewritten_target.clone(),
                calls: middleware_calls.clone(),
            }))
            .with_after(audit_middleware),
    );
    let router = crate::gateway::router::build_gateway_router(gs.clone());
    let bearer = format!("Bearer {secret}");

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call",
        Some(&bearer),
        json!({"tool_slug": original_slug, "arguments": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["kind"], "unauthorized");
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 1);
    assert!(proof.requests.lock().is_empty());

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call_batch",
        Some(&bearer),
        json!({"calls": [{"tool_slug": original_slug, "arguments": {}}]}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["kind"], "unauthorized");
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 2);
    assert!(proof.requests.lock().is_empty());

    for (id, wrapper, arguments) in [
        (
            "rewrite-call",
            "call",
            json!({"tool_slug": original_slug, "arguments": {}}),
        ),
        (
            "rewrite-call-tool",
            "call_tool",
            json!({"tool_slug": original_slug, "arguments": {}}),
        ),
        (
            "rewrite-call-tools",
            "call_tools",
            json!({"calls": [{"tool_slug": original_slug, "arguments": {}}]}),
        ),
    ] {
        let (status, body) = post_gateway(
            router.clone(),
            "/mcp",
            Some(&bearer),
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": wrapper, "arguments": arguments}
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], id);
        assert_eq!(body["result"]["isError"], true, "{body}");
        assert!(body.to_string().contains("unauthorized"));
        assert!(proof.requests.lock().is_empty());
        assert!(gs.pending_calls.read().await.is_empty());
    }
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 5);
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert_eq!(gs.search_telemetry.snapshot(1).total, 0);
    assert!(audit_entries.0.lock().is_empty());

    *rewritten_target.lock() = same_scope_full_uuid_slug.clone();
    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call",
        Some(&bearer),
        json!({"tool_slug": original_slug, "arguments": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 1);
    {
        let requests = proof.requests.lock();
        let entries = audit_entries.0.lock();
        assert_audit_target_matches_backend(
            entries.last().unwrap(),
            requests.last().unwrap(),
            "maya",
            maya_id,
        );
    }

    let (status, body) = post_gateway(
        router.clone(),
        "/v1/call_batch",
        Some(&bearer),
        json!({"calls": [{"tool_slug": original_slug, "arguments": {}}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 2);
    {
        let requests = proof.requests.lock();
        let entries = audit_entries.0.lock();
        assert_audit_target_matches_backend(
            entries.last().unwrap(),
            requests.last().unwrap(),
            "maya",
            maya_id,
        );
    }

    for (id, wrapper, arguments) in [
        (
            "same-scope-call",
            "call",
            json!({"tool_slug": original_slug, "arguments": {}}),
        ),
        (
            "same-scope-call-tool",
            "call_tool",
            json!({"tool_slug": original_slug, "arguments": {}}),
        ),
        (
            "same-scope-call-tools",
            "call_tools",
            json!({"calls": [{"tool_slug": original_slug, "arguments": {}}]}),
        ),
    ] {
        let (status, body) = post_gateway(
            router.clone(),
            "/mcp",
            Some(&bearer),
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": wrapper, "arguments": arguments}
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["isError"], false, "{body}");
        let requests = proof.requests.lock();
        let entries = audit_entries.0.lock();
        assert_audit_target_matches_backend(
            entries.last().unwrap(),
            requests.last().unwrap(),
            "maya",
            maya_id,
        );
    }
    assert_eq!(proof.calls.load(Ordering::SeqCst), 5);
    assert_eq!(audit_entries.0.lock().len(), 5);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn auth_disabled_raw_proxy_preserves_historical_authorization_forwarding() {
    let gs = test_gateway_state("1.2.3");
    let (_slug, instance_id, shutdown, proof) = seed_auth_backend(&gs).await;
    let router = crate::gateway::router::build_gateway_router(gs);

    let (status, body) = post_gateway(
        router,
        &format!("/mcp/{instance_id}"),
        Some("Bearer backend-owned-secret"),
        json!({
            "jsonrpc": "2.0",
            "id": "historical-forward",
            "method": "tools/call",
            "params": {"name": "legacy_backend_call", "arguments": {}}
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "historical-forward");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        proof.authorization_headers.lock().as_slice(),
        &[Some("Bearer backend-owned-secret".to_string())]
    );
    let _ = shutdown.send(());
}

#[tokio::test]
async fn configured_auth_gates_raw_proxy_and_strips_gateway_bearer() {
    let secret = "gateway-proxy-secret";
    let mut gs = test_gateway_state("1.2.3");
    gs.auth = Arc::new(crate::gateway::security::GatewayAuth {
        tokens: vec![
            crate::gateway::security::GatewayAuthToken::for_dcc(secret, ["maya"]),
            crate::gateway::security::GatewayAuthToken::for_dcc("nuke-only", ["nuke"]),
        ],
    });
    let (_slug, instance_id, shutdown, proof) = seed_auth_backend(&gs).await;
    let router = crate::gateway::router::build_gateway_router(gs);
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": "proxy-call",
        "method": "tools/call",
        "params": {"name": "maya_scene__open_scene", "arguments": {}}
    });

    let (status, body) = post_gateway(
        router.clone(),
        &format!("/mcp/{instance_id}"),
        None,
        request_body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["id"], "proxy-call");
    assert_eq!(body["error"]["data"]["kind"], "unauthorized");
    assert!(!body.to_string().contains(secret));
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);

    let (status, body) =
        post_gateway(router.clone(), "/mcp/dcc/maya", None, request_body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["data"]["kind"], "unauthorized");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);
    assert!(proof.requests.lock().is_empty());

    let (status, body) = post_gateway(
        router.clone(),
        "/mcp/dcc/maya",
        Some("Bearer nuke-only"),
        request_body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["data"]["kind"], "unauthorized");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);

    let (status, body) = post_gateway(
        router.clone(),
        &format!("/mcp/{instance_id}"),
        None,
        json!([
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": "old"}
            },
            {
                "jsonrpc": "2.0",
                "id": "proxy-batch-auth",
                "method": "tools/call",
                "params": {"name": "maya_scene__save_scene", "arguments": {}}
            }
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.as_array().map(Vec::len), Some(1));
    assert_eq!(body[0]["id"], "proxy-batch-auth");
    assert_eq!(body[0]["error"]["data"]["kind"], "unauthorized");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 0);

    let (status, body) = post_gateway(
        router.clone(),
        &format!("/mcp/{instance_id}"),
        Some(&format!("Bearer {secret}")),
        request_body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "proxy-call");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 1);
    assert_eq!(proof.authorization_headers.lock().as_slice(), &[None]);

    let (status, body) = post_gateway(
        router,
        "/mcp/dcc/maya",
        Some(&format!("Bearer {secret}")),
        request_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "proxy-call");
    assert_eq!(proof.calls.load(Ordering::SeqCst), 2);
    assert_eq!(proof.authorization_headers.lock().as_slice(), &[None, None]);

    let _ = shutdown.send(());
}

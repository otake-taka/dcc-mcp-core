use super::*;
use crate::gateway::http_registration::entry_mcp_url;
use dcc_mcp_models::DccName;

/// `POST /mcp/{instance_id}` — conditional proxy to a specific DCC instance.
pub async fn handle_proxy_instance(
    State(gs): State<GatewayState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ingress = match DispatchIngress::authenticate(&gs.auth, headers) {
        Ok(ingress) => ingress,
        Err(_) => return auth_rejection_response(&body),
    };
    let entry = gs
        .resolve_instance_async(Some(instance_id.as_str()), None)
        .await
        .ok();

    match entry {
        Some(entry) => {
            let resolved_dcc_type = DccName::parse(&entry.dcc_type);
            if gs
                .auth
                .authorize_dispatch(&ingress.context, &resolved_dcc_type)
                .is_err()
            {
                return auth_rejection_response(&body);
            }
            if let Err(error) = crate::gateway::lease_guard::check_raw_mcp_call_owner(&entry, &body)
            {
                return lease_rejection_response(&entry, error, &body);
            }
            let url = entry_mcp_url(&entry);
            proxy_request(&gs.http_client, &url, ingress.headers, body).await
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Instance '{}' not found", instance_id)})),
        )
            .into_response(),
    }
}

/// `POST /mcp/dcc/{dcc_type}` — conditional proxy to a DCC type.
pub async fn handle_proxy_dcc(
    State(gs): State<GatewayState>,
    Path(dcc_type): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ingress = match DispatchIngress::authenticate(&gs.auth, headers) {
        Ok(ingress) => ingress,
        Err(_) => return auth_rejection_response(&body),
    };
    let mut candidates = gs
        .live_instances_async()
        .await
        .into_iter()
        .filter(|entry| entry.dcc_type == dcc_type)
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("No live '{}' instances", dcc_type)})),
        )
            .into_response();
    }

    candidates.sort_by_key(|entry| matches!(entry.status, ServiceStatus::Busy) as u8);
    let entry = &candidates[0];
    let resolved_dcc_type = DccName::parse(&entry.dcc_type);
    if gs
        .auth
        .authorize_dispatch(&ingress.context, &resolved_dcc_type)
        .is_err()
    {
        return auth_rejection_response(&body);
    }
    if let Err(error) = crate::gateway::lease_guard::check_raw_mcp_call_owner(entry, &body) {
        return lease_rejection_response(entry, error, &body);
    }
    let url = entry_mcp_url(entry);
    proxy_request(&gs.http_client, &url, ingress.headers, body).await
}

fn auth_rejection_response(body: &[u8]) -> Response {
    let payload = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    if let Value::Array(requests) = payload {
        let responses = requests
            .into_iter()
            .filter_map(|request| request.get("id").cloned().map(auth_error_value))
            .collect::<Vec<_>>();
        if responses.is_empty() {
            return StatusCode::ACCEPTED.into_response();
        }
        return (StatusCode::UNAUTHORIZED, Json(Value::Array(responses))).into_response();
    }
    let Some(id) = payload.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    (StatusCode::UNAUTHORIZED, Json(auth_error_value(id))).into_response()
}

fn auth_error_value(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": "Valid bearer authorization is required for this operation.",
            "data": {"kind": "unauthorized"}
        }
    })
}

fn lease_rejection_response(
    entry: &dcc_mcp_transport::discovery::types::ServiceEntry,
    error: dcc_mcp_transport::discovery::types::LeaseOwnerError,
    body: &[u8],
) -> Response {
    let payload = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    if let Value::Array(requests) = payload {
        let responses = requests
            .into_iter()
            .filter_map(|request| {
                let id = request.get("id")?.clone();
                Some(match crate::gateway::lease_guard::check_raw_request_owner(entry, &request) {
                    Err(error) => lease_error_value(entry, error, id),
                    Ok(()) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32000,
                            "message": "batch was not dispatched because another tools/call item failed active lease validation",
                            "data": {"kind": "batch-rejected"}
                        }
                    }),
                })
            })
            .collect::<Vec<_>>();
        if responses.is_empty() {
            return StatusCode::ACCEPTED.into_response();
        }
        return (StatusCode::OK, Json(Value::Array(responses))).into_response();
    }
    let Some(id) = payload.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    (StatusCode::OK, Json(lease_error_value(entry, error, id))).into_response()
}

fn lease_error_value(
    entry: &dcc_mcp_transport::discovery::types::ServiceEntry,
    error: dcc_mcp_transport::discovery::types::LeaseOwnerError,
    id: Value,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": format!("{error} for instance {}", entry.instance_id),
            "data": {
                "kind": error.kind(),
                "instance_id": entry.instance_id,
            }
        }
    })
}

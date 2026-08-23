use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use dcc_mcp_transport::discovery::types::ServiceStatus;

use super::tests::admin_tests::{body_json, make_gateway_state, make_service_entry};
use super::{AdminState, build_admin_router};

#[tokio::test]
async fn test_admin_workers_keeps_booting_failure_rows_visible() {
    let gs = make_gateway_state();
    {
        let reg = &gs.registry;
        let mut booting = make_service_entry("3dsmax", "127.0.0.1", 0, Some(4244));
        booting.status = ServiceStatus::Booting;
        booting
            .metadata
            .insert("failure_reason".into(), "host-rpc connect failed".into());
        booting
            .metadata
            .insert("failure_stage".into(), "host-rpc-connect".into());
        booting
            .metadata
            .insert("host_rpc_uri".into(), "commandport://127.0.0.1:6000".into());
        booting
            .metadata
            .insert("host_rpc_scheme".into(), "commandport".into());
        booting
            .metadata
            .insert("dispatch_status".into(), "unavailable".into());
        reg.register(booting).unwrap();
    }
    let (status, body) = body_json(build_admin_router(AdminState::new(gs)), "/api/workers").await;
    assert_eq!(status, StatusCode::OK);
    let workers = body["workers"].as_array().unwrap();
    assert_eq!(workers.len(), 1, "expected booting worker row");
    assert_eq!(workers[0]["status"], "booting");
    assert_eq!(workers[0]["port"], 0);
    assert_eq!(workers[0]["failure_reason"], "host-rpc connect failed");
    assert_eq!(workers[0]["failure_stage"], "host-rpc-connect");
    assert_eq!(workers[0]["host_rpc_scheme"], "commandport");
    assert_eq!(workers[0]["dispatch_status"], "unavailable");
    assert_eq!(workers[0]["dispatch_ready"], false);
    assert_eq!(body["summary"]["unhealthy"].as_u64(), Some(1));
}

#[tokio::test]
async fn test_admin_workers_hides_stale_registry_rows() {
    let gs = make_gateway_state();
    {
        let reg = &gs.registry;
        reg.register(make_service_entry("maya", "127.0.0.1", 18813, Some(4242)))
            .unwrap();

        let mut stale = make_service_entry("maya", "127.0.0.1", 18814, Some(4243));
        stale.last_heartbeat = SystemTime::now() - Duration::from_secs(120);
        reg.register(stale).unwrap();
    }

    let (status, body) = body_json(build_admin_router(AdminState::new(gs)), "/api/workers").await;
    assert_eq!(status, StatusCode::OK);
    let workers = body["workers"].as_array().unwrap();
    assert_eq!(
        workers.len(),
        1,
        "expected only live workers, got {workers:?}"
    );
    assert_eq!(workers[0]["port"], 18813);
    assert_eq!(body["total"].as_u64(), Some(1));
    assert_eq!(body["summary"]["live"].as_u64(), Some(1));
    assert_eq!(body["summary"]["stale"].as_u64(), Some(0));
}

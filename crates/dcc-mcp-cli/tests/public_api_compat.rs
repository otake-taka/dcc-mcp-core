use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dcc_mcp_cli::application::control_plane::DccControlPlane;
use dcc_mcp_cli::application::gateway_ctrl::{
    GatewayDaemonRequest, GatewayDaemonStartRequest, GatewayStartOpts,
};
use dcc_mcp_cli::application::gateway_ensure::EnsureGatewayArgs;
use dcc_mcp_cli::application::gateway_profile::{
    GatewayProfile, GatewayProfileStore, GatewayTarget,
};
use dcc_mcp_cli::domain::rest::Endpoint;
use dcc_mcp_sidecar::gateway_daemon::{GatewayArgs, RelaySourceArg};

#[test]
fn c1_2a_preserves_pre_auth_public_rust_construction_contracts() {
    let profile = GatewayProfile {
        base_url: "http://127.0.0.1:9765".to_string(),
    };
    let mut store = GatewayProfileStore {
        current: "studio".to_string(),
        profiles: BTreeMap::from([("studio".to_string(), profile)]),
    };
    store
        .register_remote("legacy", "http://127.0.0.1:19765")
        .unwrap();
    let target = GatewayTarget::Remote {
        name: "studio".to_string(),
        endpoint: Endpoint::new("http://127.0.0.1:9765"),
    };
    let control: DccControlPlane = DccControlPlane::new(
        target,
        Endpoint::new("http://127.0.0.1:9765"),
        PathBuf::from("registry"),
        false,
    );
    let _ = (store, control);

    let start_opts = GatewayStartOpts {
        name: None,
        remote_host: "127.0.0.1".to_string(),
        remote_port: 59765,
        gateway_idle_timeout_secs: 30,
        gateway_bin: None,
        wait_timeout_secs: 1,
    };
    let start_request = GatewayDaemonStartRequest {
        host: "127.0.0.1".to_string(),
        port: 9765,
        name: None,
        registry_dir: None,
        remote_host: "127.0.0.1".to_string(),
        remote_port: 59765,
        gateway_idle_timeout_secs: 30,
        gateway_bin: None,
        wait_timeout_secs: 1,
    };
    let ensure = EnsureGatewayArgs {
        host: "127.0.0.1".to_string(),
        port: 9765,
        name: None,
        registry_dir: PathBuf::from("registry"),
        remote_host: "127.0.0.1".to_string(),
        remote_port: 59765,
        gateway_idle_timeout_secs: 30,
        gateway_bin: None,
        wait_timeout_secs: 1,
        pidfile: None,
    };
    let _ = (start_opts, start_request, ensure);

    let gateway_args = GatewayArgs {
        host: "127.0.0.1".to_string(),
        port: 9765,
        name: None,
        remote_host: "127.0.0.1".to_string(),
        remote_port: 59765,
        registry_dir: None,
        no_admin: true,
        admin_path: "/admin".to_string(),
        stale_timeout_secs: 30,
        relay_sources: Vec::<RelaySourceArg>::new(),
        gateway_persist: false,
        gateway_idle_timeout_secs: 30,
        semantic_search_enabled: false,
        daemon: false,
        pidfile: None,
        restart: false,
    };
    let config = dcc_mcp_sidecar::gateway_daemon::build_gateway_config(&gateway_args, "compat");
    assert!(!config.auth.is_enabled());

    let argv = dcc_mcp_gateway_ensure::gateway_command_args(
        "127.0.0.1",
        9765,
        None,
        "127.0.0.1",
        59765,
        30,
    );
    assert_eq!(argv.first().and_then(|arg| arg.to_str()), Some("gateway"));

    let _register_profile: fn(&Path, String, String) -> anyhow::Result<serde_json::Value> =
        dcc_mcp_cli::application::gateway_profile::register_profile;
}

fn legacy_gateway_daemon_request_kind(request: GatewayDaemonRequest) -> &'static str {
    match request {
        GatewayDaemonRequest::Start(_) => "start",
        GatewayDaemonRequest::Restart { .. } => "restart",
        GatewayDaemonRequest::Stop(_) => "stop",
        GatewayDaemonRequest::Status(_) => "status",
    }
}

#[test]
fn gateway_daemon_request_preserves_legacy_exhaustive_match_contract() {
    let _match_fixture: fn(GatewayDaemonRequest) -> &'static str =
        legacy_gateway_daemon_request_kind;
}

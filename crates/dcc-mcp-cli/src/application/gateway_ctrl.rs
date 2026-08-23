//! Gateway lifecycle commands: start, stop, status.
//!
//! Wraps `gateway_ensure` for `start` and adds PID-based stop/status.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use dcc_mcp_transport::discovery::file_registry::FileRegistry;
use dcc_mcp_transport::discovery::types::{GATEWAY_SENTINEL_DCC_TYPE, ServiceEntry};
use serde::Serialize;
use serde_json::Value;

use crate::application::gateway_ensure;
use crate::domain::rest::Endpoint;

/// Parameters shared across `start`, `stop`, and `status`.
#[derive(Debug, Clone)]
pub struct GatewayCtrlArgs {
    pub host: String,
    pub port: u16,
    pub registry_dir: PathBuf,
    pub pidfile: PathBuf,
    /// Used only by `start`.
    pub start_opts: Option<GatewayStartOpts>,
}

#[derive(Debug, Clone)]
pub struct GatewayStartOpts {
    pub name: Option<String>,
    pub remote_host: String,
    pub remote_port: u16,
    pub gateway_idle_timeout_secs: u64,
    pub gateway_bin: Option<PathBuf>,
    pub wait_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewayStatus {
    pub host: String,
    pub port: u16,
    pub health_url: String,
    pub healthy: bool,
    pub pid: Option<u32>,
    pub alive: bool,
    pub running: bool,
    pub registry_dir: PathBuf,
    pub pidfile: PathBuf,
    pub cli_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedGatewayStatus {
    #[serde(flatten)]
    pub status: GatewayStatus,
    pub auth_state: gateway_ensure::GatewayAuthState,
}

#[derive(Debug, Clone)]
pub struct GatewayDaemonStartRequest {
    pub host: String,
    pub port: u16,
    pub name: Option<String>,
    pub registry_dir: Option<PathBuf>,
    pub remote_host: String,
    pub remote_port: u16,
    pub gateway_idle_timeout_secs: u64,
    pub gateway_bin: Option<PathBuf>,
    pub wait_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct GatewayDaemonStopRequest {
    pub host: String,
    pub port: u16,
    pub registry_dir: Option<PathBuf>,
    pub wait_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct GatewayDaemonStatusRequest {
    pub host: String,
    pub port: u16,
    pub registry_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum GatewayDaemonRequest {
    Start(GatewayDaemonStartRequest),
    Restart {
        start: GatewayDaemonStartRequest,
        stop_timeout_secs: u64,
    },
    Stop(GatewayDaemonStopRequest),
    Status(GatewayDaemonStatusRequest),
}

#[derive(Debug, Clone)]
pub(crate) enum GatewayDaemonAuthRequest {
    Start {
        start: GatewayDaemonStartRequest,
        auth_token_file: Option<PathBuf>,
    },
    Restart {
        start: GatewayDaemonStartRequest,
        auth_token_file: Option<PathBuf>,
        stop_timeout_secs: u64,
    },
}

enum GatewayDaemonOperation {
    Start {
        start: GatewayDaemonStartRequest,
        auth_token_file: Option<PathBuf>,
    },
    Restart {
        start: GatewayDaemonStartRequest,
        auth_token_file: Option<PathBuf>,
        stop_timeout_secs: u64,
    },
    Stop(GatewayDaemonStopRequest),
    Status(GatewayDaemonStatusRequest),
}

/// Start the gateway (ensure it's running; alias for `ensure`).
pub async fn gateway_start(args: &GatewayCtrlArgs) -> anyhow::Result<gateway_ensure::EnsureResult> {
    Ok(gateway_start_with_auth(args, None).await?.ensure)
}

pub async fn gateway_start_with_auth(
    args: &GatewayCtrlArgs,
    auth_token_file: Option<&std::path::Path>,
) -> anyhow::Result<gateway_ensure::ManagedEnsureResult> {
    let ensure_args = gateway_start_ensure_args(args)?;
    gateway_ensure::ensure_gateway_running_with_auth(&ensure_args, auth_token_file).await
}

fn gateway_start_ensure_args(
    args: &GatewayCtrlArgs,
) -> anyhow::Result<gateway_ensure::EnsureGatewayArgs> {
    let start = args.start_opts.as_ref().context("start options required")?;
    Ok(gateway_ensure::EnsureGatewayArgs {
        host: args.host.clone(),
        port: args.port,
        name: start.name.clone(),
        registry_dir: args.registry_dir.clone(),
        remote_host: start.remote_host.clone(),
        remote_port: start.remote_port,
        gateway_idle_timeout_secs: start.gateway_idle_timeout_secs,
        gateway_bin: start.gateway_bin.clone(),
        wait_timeout_secs: start.wait_timeout_secs,
        pidfile: Some(args.pidfile.clone()),
    })
}

/// Stop the gateway by sending a termination signal to the PID recorded
/// in the pidfile, then wait for the health endpoint to become unreachable.
pub async fn gateway_stop(
    args: &GatewayCtrlArgs,
    wait_timeout_secs: u64,
) -> anyhow::Result<GatewayStatus> {
    let status_before = gateway_status(args).await;
    if !status_before.running {
        return Ok(status_before);
    }

    let Some(pid) = status_before.pid else {
        anyhow::bail!(
            "refusing to stop healthy gateway at {host}:{port}: pidfile {pidfile} is missing or invalid",
            host = args.host,
            port = args.port,
            pidfile = args.pidfile.display()
        );
    };

    if !gateway_ensure::is_process_alive(pid) {
        anyhow::bail!(
            "refusing to stop healthy gateway at {host}:{port}: pidfile {pidfile} contains stale pid {pid}",
            host = args.host,
            port = args.port,
            pidfile = args.pidfile.display()
        );
    }

    verify_gateway_pid_ownership(args, pid)?;
    gateway_ensure::stop_process(pid)?;
    // Wait for the health endpoint to go dark.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_timeout_secs);
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if !gateway_ensure::gateway_health_ok(&args.host, args.port).await {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "gateway at {host}:{port} did not stop within {wait_timeout_secs}s",
                host = args.host,
                port = args.port
            );
        }
    }

    prune_stopped_gateway_registry(args)?;
    gateway_ensure::remove_pidfile(Some(&args.pidfile));
    Ok(gateway_status(args).await)
}

fn prune_stopped_gateway_registry(args: &GatewayCtrlArgs) -> anyhow::Result<usize> {
    let registry = FileRegistry::new(args.registry_dir.clone()).with_context(|| {
        format!(
            "opening gateway FileRegistry at {} after shutdown",
            args.registry_dir.display()
        )
    })?;
    let (_, evicted) = registry
        .read_alive()
        .context("pruning stopped gateway sentinel rows")?;
    Ok(evicted)
}

/// Query the gateway status: health check + PID liveness.
pub async fn gateway_status(args: &GatewayCtrlArgs) -> GatewayStatus {
    let healthy = gateway_ensure::gateway_health_ok(&args.host, args.port).await;
    let pid = resolve_gateway_pid(args, healthy);
    let alive = pid.is_some_and(gateway_ensure::is_process_alive);
    GatewayStatus {
        host: args.host.clone(),
        port: args.port,
        health_url: format!("http://{}:{}/health", args.host, args.port),
        healthy,
        pid,
        alive,
        running: healthy,
        registry_dir: args.registry_dir.clone(),
        pidfile: args.pidfile.clone(),
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

pub async fn managed_gateway_status(args: &GatewayCtrlArgs) -> ManagedGatewayStatus {
    let status = gateway_status(args).await;
    let auth_state = if status.healthy {
        gateway_ensure::gateway_auth_state(&args.host, args.port).await
    } else {
        gateway_ensure::GatewayAuthState::Unknown
    };
    ManagedGatewayStatus { status, auth_state }
}

fn resolve_gateway_pid(args: &GatewayCtrlArgs, healthy: bool) -> Option<u32> {
    resolve_gateway_pid_with(args, healthy, gateway_ensure::is_process_alive)
}

fn resolve_gateway_pid_with(
    args: &GatewayCtrlArgs,
    healthy: bool,
    is_alive: impl Fn(u32) -> bool + Copy,
) -> Option<u32> {
    let pidfile_pid = gateway_ensure::read_pid_from_pidfile(Some(&args.pidfile));
    if pidfile_pid.is_some_and(is_alive) || !healthy {
        return pidfile_pid;
    }

    live_gateway_sentinel_pid(args, is_alive).or(pidfile_pid)
}

fn live_gateway_sentinel_pid(
    args: &GatewayCtrlArgs,
    is_alive: impl Fn(u32) -> bool,
) -> Option<u32> {
    let registry = FileRegistry::new(args.registry_dir.clone()).ok()?;
    let (entries, _) = registry.read_alive().ok()?;
    let mut pids = entries
        .into_iter()
        .filter(|entry| entry.dcc_type == GATEWAY_SENTINEL_DCC_TYPE)
        .filter(|entry| gateway_sentinel_targets(entry, &args.host, args.port))
        .filter_map(|entry| gateway_sentinel_pid(&entry))
        .filter(|pid| is_alive(*pid))
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    (pids.len() == 1).then(|| pids[0])
}

pub async fn run_gateway_daemon(request: GatewayDaemonRequest) -> anyhow::Result<Value> {
    let operation = match request {
        GatewayDaemonRequest::Start(start) => GatewayDaemonOperation::Start {
            start,
            auth_token_file: None,
        },
        GatewayDaemonRequest::Restart {
            start,
            stop_timeout_secs,
        } => GatewayDaemonOperation::Restart {
            start,
            auth_token_file: None,
            stop_timeout_secs,
        },
        GatewayDaemonRequest::Stop(stop) => GatewayDaemonOperation::Stop(stop),
        GatewayDaemonRequest::Status(status) => GatewayDaemonOperation::Status(status),
    };
    run_gateway_daemon_operation(operation).await
}

pub(crate) async fn run_gateway_daemon_with_auth(
    request: GatewayDaemonAuthRequest,
) -> anyhow::Result<Value> {
    let operation = match request {
        GatewayDaemonAuthRequest::Start {
            start,
            auth_token_file,
        } => GatewayDaemonOperation::Start {
            start,
            auth_token_file,
        },
        GatewayDaemonAuthRequest::Restart {
            start,
            auth_token_file,
            stop_timeout_secs,
        } => GatewayDaemonOperation::Restart {
            start,
            auth_token_file,
            stop_timeout_secs,
        },
    };
    run_gateway_daemon_operation(operation).await
}

async fn run_gateway_daemon_operation(operation: GatewayDaemonOperation) -> anyhow::Result<Value> {
    match operation {
        GatewayDaemonOperation::Start {
            start,
            auth_token_file,
        } => {
            let args = start.into_ctrl_args();
            Ok(serde_json::to_value(
                gateway_start_with_auth(&args, auth_token_file.as_deref()).await?,
            )?)
        }
        GatewayDaemonOperation::Restart {
            start,
            auth_token_file,
            stop_timeout_secs,
        } => {
            let args = start.into_ctrl_args();
            restart_gateway_with_auth(&args, auth_token_file.as_deref(), stop_timeout_secs).await
        }
        GatewayDaemonOperation::Stop(stop) => {
            let args = gateway_ctrl_args(stop.host, stop.port, stop.registry_dir, None);
            Ok(serde_json::to_value(
                gateway_stop(&args, stop.wait_timeout_secs).await?,
            )?)
        }
        GatewayDaemonOperation::Status(status) => {
            let args = gateway_ctrl_args(status.host, status.port, status.registry_dir, None);
            Ok(serde_json::to_value(managed_gateway_status(&args).await)?)
        }
    }
}

async fn restart_gateway_with_auth(
    args: &GatewayCtrlArgs,
    auth_token_file: Option<&std::path::Path>,
    stop_timeout_secs: u64,
) -> anyhow::Result<Value> {
    if let Some(path) = auth_token_file {
        gateway_ensure::validate_auth_token_file(path)?;
    }
    reject_restart_auth_downgrade(args, auth_token_file).await?;
    let stopped = gateway_stop(args, stop_timeout_secs).await?;
    let started = gateway_start_with_auth(args, auth_token_file).await?;
    Ok(serde_json::json!({
        "restarted": true,
        "stopped": stopped,
        "started": started,
    }))
}

pub async fn ensure_local_gateway_for_endpoint(
    endpoint: &Endpoint,
    gateway_bin: Option<PathBuf>,
    wait_timeout_secs: u64,
) -> anyhow::Result<Option<gateway_ensure::EnsureResult>> {
    ensure_local_gateway_for_endpoint_with_auth(endpoint, gateway_bin, wait_timeout_secs, None)
        .await
}

pub(crate) async fn ensure_local_gateway_for_endpoint_with_auth(
    endpoint: &Endpoint,
    gateway_bin: Option<PathBuf>,
    wait_timeout_secs: u64,
    auth_token_file: Option<&std::path::Path>,
) -> anyhow::Result<Option<gateway_ensure::EnsureResult>> {
    let Some((host, port)) = local_auto_gateway_target(endpoint) else {
        return Ok(None);
    };

    let registry_dir = gateway_ensure::default_registry_dir();
    let pidfile = default_pidfile(&registry_dir);
    let args = gateway_ensure::EnsureGatewayArgs {
        host,
        port,
        name: env_string("DCC_MCP_GATEWAY_NAME")
            .or_else(|| Some("dcc-mcp-cli-gateway".to_string())),
        registry_dir,
        remote_host: env_string("DCC_MCP_GATEWAY_REMOTE_HOST")
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        remote_port: env_u16("DCC_MCP_GATEWAY_REMOTE_PORT").unwrap_or(59765),
        gateway_idle_timeout_secs: env_u64("DCC_MCP_GATEWAY_IDLE_TIMEOUT_SECS").unwrap_or(30),
        gateway_bin,
        wait_timeout_secs,
        pidfile: Some(pidfile),
    };

    Ok(Some(
        gateway_ensure::ensure_gateway_running_with_auth(&args, auth_token_file)
            .await?
            .ensure,
    ))
}

pub fn local_auto_gateway_target(endpoint: &Endpoint) -> Option<(String, u16)> {
    let parsed = reqwest::Url::parse(&endpoint.base_url).ok()?;
    if parsed.scheme() != "http" {
        return None;
    }
    let host = parsed.host_str()?;
    let host = if host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1"
    } else {
        host
    };
    if !matches!(host, "127.0.0.1" | "0.0.0.0") {
        return None;
    }
    let port = parsed.port_or_known_default()?;
    Some((host.to_string(), port))
}

/// Build the default PID file path under the registry directory.
pub fn default_pidfile(registry_dir: &std::path::Path) -> PathBuf {
    registry_dir.join("gateway.pid")
}

pub fn gateway_ctrl_args(
    host: String,
    port: u16,
    registry_dir: Option<PathBuf>,
    start_opts: Option<GatewayStartOpts>,
) -> GatewayCtrlArgs {
    let registry_dir = registry_dir.unwrap_or_else(gateway_ensure::default_registry_dir);
    let pidfile = default_pidfile(&registry_dir);
    GatewayCtrlArgs {
        host,
        port,
        registry_dir,
        pidfile,
        start_opts,
    }
}

fn verify_gateway_pid_ownership(args: &GatewayCtrlArgs, pid: u32) -> anyhow::Result<()> {
    let registry = FileRegistry::new(args.registry_dir.clone()).with_context(|| {
        format!(
            "opening gateway FileRegistry at {}",
            args.registry_dir.display()
        )
    })?;
    let (entries, _) = registry
        .read_alive()
        .context("reading live gateway sentinel rows")?;
    let sentinels: Vec<_> = entries
        .into_iter()
        .filter(|entry| entry.dcc_type == GATEWAY_SENTINEL_DCC_TYPE)
        .collect();

    if sentinels
        .iter()
        .filter(|entry| gateway_sentinel_targets(entry, &args.host, args.port))
        .any(|entry| gateway_sentinel_pid(entry) == Some(pid))
    {
        return Ok(());
    }

    let observed = if sentinels.is_empty() {
        "none".to_string()
    } else {
        sentinels
            .iter()
            .map(gateway_sentinel_summary)
            .collect::<Vec<_>>()
            .join(", ")
    };
    anyhow::bail!(
        "refusing to stop gateway at {host}:{port}: pidfile {pidfile} contains pid {pid}, but no live __gateway__ sentinel proves that PID owns this healthy endpoint. This usually means a stale pidfile or PID reuse; observed sentinels: {observed}",
        host = args.host,
        port = args.port,
        pidfile = args.pidfile.display()
    )
}

fn gateway_sentinel_targets(entry: &ServiceEntry, host: &str, port: u16) -> bool {
    if entry.port == port && gateway_hosts_match(&entry.host, host) {
        return true;
    }
    entry
        .metadata
        .get("gateway_health_url")
        .is_some_and(|url| gateway_health_url_targets(url, host, port))
}

fn gateway_health_url_targets(url: &str, host: &str, port: u16) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    parsed.scheme() == "http"
        && parsed.path() == "/health"
        && parsed.port_or_known_default() == Some(port)
        && parsed
            .host_str()
            .is_some_and(|actual| gateway_hosts_match(actual, host))
}

fn gateway_hosts_match(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
        || (is_local_gateway_host(actual) && is_local_gateway_host(expected))
}

fn is_local_gateway_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1" | "0.0.0.0"
    )
}

fn gateway_sentinel_pid(entry: &ServiceEntry) -> Option<u32> {
    entry
        .metadata
        .get("gateway_process_pid")
        .and_then(|value| value.parse::<u32>().ok())
        .or(entry.pid)
}

fn gateway_sentinel_summary(entry: &ServiceEntry) -> String {
    format!(
        "{}:{} pid={} health_url={}",
        entry.host,
        entry.port,
        gateway_sentinel_pid(entry)
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        entry
            .metadata
            .get("gateway_health_url")
            .map(String::as_str)
            .unwrap_or("unknown")
    )
}

impl GatewayDaemonStartRequest {
    fn into_ctrl_args(self) -> GatewayCtrlArgs {
        let start_opts = GatewayStartOpts {
            name: self.name,
            remote_host: self.remote_host,
            remote_port: self.remote_port,
            gateway_idle_timeout_secs: self.gateway_idle_timeout_secs,
            gateway_bin: self.gateway_bin,
            wait_timeout_secs: self.wait_timeout_secs,
        };
        gateway_ctrl_args(self.host, self.port, self.registry_dir, Some(start_opts))
    }
}

async fn reject_restart_auth_downgrade(
    args: &GatewayCtrlArgs,
    auth_token_file: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let replacement_has_auth = auth_token_file.is_some();
    if !replacement_has_auth
        && gateway_ensure::gateway_auth_state(&args.host, args.port).await
            == gateway_ensure::GatewayAuthState::Enabled
    {
        anyhow::bail!(
            "refusing to restart auth-enabled gateway at {host}:{port} without --auth-token-file or DCC_MCP_GATEWAY_AUTH_TOKEN_FILE; the running process was not stopped",
            host = args.host,
            port = args.port,
        );
    }
    Ok(())
}

fn env_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_u16(name: &str) -> Option<u16> {
    env_string(name).and_then(|value| value.parse::<u16>().ok())
}

fn env_u64(name: &str) -> Option<u64> {
    env_string(name).and_then(|value| value.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcc_mcp_transport::discovery::file_registry::FileRegistry;

    async fn spawn_health_document(body: serde_json::Value) -> (u16, tokio::task::JoinHandle<()>) {
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(move || {
                let body = body.clone();
                async move { axum::Json(body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, server)
    }

    fn restart_request(
        port: u16,
        registry_dir: PathBuf,
        auth_token_file: Option<PathBuf>,
    ) -> GatewayDaemonAuthRequest {
        GatewayDaemonAuthRequest::Restart {
            start: GatewayDaemonStartRequest {
                host: "127.0.0.1".to_string(),
                port,
                name: None,
                registry_dir: Some(registry_dir),
                remote_host: "127.0.0.1".to_string(),
                remote_port: 59765,
                gateway_idle_timeout_secs: 0,
                gateway_bin: None,
                wait_timeout_secs: 1,
            },
            auth_token_file,
            stop_timeout_secs: 1,
        }
    }

    #[tokio::test]
    async fn restart_rejects_invalid_replacement_auth_before_stopping_any_resident_mode() {
        for auth_enabled in [true, false] {
            let (port, server) = spawn_health_document(
                serde_json::json!({"ok": true, "auth_enabled": auth_enabled}),
            )
            .await;
            let registry = tempfile::tempdir().unwrap();
            let unreadable = registry.path().join("unreadable");
            std::fs::create_dir(&unreadable).unwrap();
            let empty = registry.path().join("empty.token");
            std::fs::write(&empty, " \n\t").unwrap();
            let invalid = registry.path().join("invalid.token");
            std::fs::write(&invalid, "two tokens").unwrap();
            let invalid_header = registry.path().join("invalid-header.token");
            std::fs::write(&invalid_header, b"bad\x7fvalue").unwrap();

            for token_file in [
                registry.path().join("missing.token"),
                unreadable.clone(),
                empty.clone(),
                invalid.clone(),
                invalid_header.clone(),
            ] {
                let error = run_gateway_daemon_with_auth(restart_request(
                    port,
                    registry.path().to_path_buf(),
                    Some(token_file),
                ))
                .await
                .unwrap_err()
                .to_string();
                assert!(error.contains("auth token file"), "{error}");
                assert!(
                    !error.contains("pidfile"),
                    "invalid replacement must fail before stop handling: {error}"
                );
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn gateway_status_reports_secret_free_auth_state() {
        let (port, server) =
            spawn_health_document(serde_json::json!({"ok": true, "auth_enabled": true})).await;
        let registry = tempfile::tempdir().unwrap();
        let args = gateway_ctrl_args(
            "127.0.0.1".to_string(),
            port,
            Some(registry.path().to_path_buf()),
            None,
        );

        let output = serde_json::to_value(managed_gateway_status(&args).await).unwrap();

        assert_eq!(output["auth_state"], "enabled");
        assert!(output.get("auth_token_file").is_none());
        server.abort();
    }

    #[tokio::test]
    async fn restart_rejects_auth_downgrade_before_pidfile_or_stop_handling() {
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"ok": true, "auth_enabled": true}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let registry = tempfile::tempdir().unwrap();
        let request = GatewayDaemonRequest::Restart {
            start: GatewayDaemonStartRequest {
                host: "127.0.0.1".to_string(),
                port,
                name: None,
                registry_dir: Some(registry.path().to_path_buf()),
                remote_host: "127.0.0.1".to_string(),
                remote_port: 59765,
                gateway_idle_timeout_secs: 0,
                gateway_bin: None,
                wait_timeout_secs: 1,
            },
            stop_timeout_secs: 1,
        };

        let error = run_gateway_daemon(request).await.unwrap_err().to_string();
        assert!(error.contains("auth-enabled gateway"), "{error}");
        assert!(error.contains("--auth-token-file"), "{error}");
        assert!(
            !error.contains("pidfile"),
            "preflight must fail before stop: {error}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn restart_auth_preflight_allows_disabled_and_legacy_health_documents() {
        for body in [
            serde_json::json!({"ok": true, "auth_enabled": false}),
            serde_json::json!({"ok": true}),
        ] {
            let app = axum::Router::new().route(
                "/health",
                axum::routing::get(move || {
                    let body = body.clone();
                    async move { axum::Json(body) }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let request = GatewayDaemonStartRequest {
                host: "127.0.0.1".to_string(),
                port,
                name: None,
                registry_dir: None,
                remote_host: "127.0.0.1".to_string(),
                remote_port: 59765,
                gateway_idle_timeout_secs: 0,
                gateway_bin: None,
                wait_timeout_secs: 1,
            };

            reject_restart_auth_downgrade(&request.into_ctrl_args(), None)
                .await
                .unwrap();
            server.abort();
        }
    }

    #[test]
    fn auth_aware_start_variant_keeps_path_outside_legacy_request_struct() {
        let token_file = PathBuf::from("/run/secrets/dcc-mcp-gateway.token");
        let request = GatewayDaemonStartRequest {
            host: "127.0.0.1".to_string(),
            port: 9765,
            name: None,
            registry_dir: None,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 59765,
            gateway_idle_timeout_secs: 0,
            gateway_bin: None,
            wait_timeout_secs: 1,
        };
        let request = GatewayDaemonAuthRequest::Start {
            start: request,
            auth_token_file: Some(token_file.clone()),
        };

        let GatewayDaemonAuthRequest::Start {
            auth_token_file, ..
        } = request
        else {
            panic!("expected auth-aware start request")
        };
        assert_eq!(auth_token_file.as_ref(), Some(&token_file));
    }

    #[test]
    fn local_auto_gateway_target_accepts_loopback_http() {
        assert_eq!(
            local_auto_gateway_target(&Endpoint::new("http://localhost:9765")),
            Some(("127.0.0.1".to_string(), 9765))
        );
        assert_eq!(
            local_auto_gateway_target(&Endpoint::new("http://127.0.0.1:19001/")),
            Some(("127.0.0.1".to_string(), 19001))
        );
    }

    #[test]
    fn local_auto_gateway_target_rejects_remote_or_non_http_targets() {
        assert_eq!(
            local_auto_gateway_target(&Endpoint::new("https://127.0.0.1:9765")),
            None
        );
        assert_eq!(
            local_auto_gateway_target(&Endpoint::new("http://192.0.2.10:9765")),
            None
        );
    }

    #[test]
    fn gateway_pid_ownership_accepts_matching_live_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let args = gateway_ctrl_args(
            "127.0.0.1".to_string(),
            19765,
            Some(dir.path().to_path_buf()),
            None,
        );
        let pid = 42_424;
        let mut sentinel = ServiceEntry::new(GATEWAY_SENTINEL_DCC_TYPE, "127.0.0.1", 19765);
        sentinel.metadata.insert(
            "gateway_health_url".to_string(),
            "http://127.0.0.1:19765/health".to_string(),
        );
        sentinel
            .metadata
            .insert("gateway_process_pid".to_string(), pid.to_string());
        let registry = FileRegistry::new(dir.path()).unwrap();
        registry.register(sentinel).unwrap();

        verify_gateway_pid_ownership(&args, pid).unwrap();
    }

    #[test]
    fn stopped_gateway_registry_prunes_dead_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let args = gateway_ctrl_args(
            "127.0.0.1".to_string(),
            19765,
            Some(dir.path().to_path_buf()),
            None,
        );
        let mut sentinel = ServiceEntry::new(GATEWAY_SENTINEL_DCC_TYPE, "127.0.0.1", 19765);
        sentinel.pid = Some(u32::MAX);
        sentinel
            .metadata
            .insert("gateway_process_pid".to_string(), u32::MAX.to_string());
        let registry = FileRegistry::new(dir.path()).unwrap();
        registry.register(sentinel).unwrap();
        drop(registry);

        assert_eq!(prune_stopped_gateway_registry(&args).unwrap(), 1);
        let registry = FileRegistry::new(dir.path()).unwrap();
        assert!(
            registry
                .list_instances(GATEWAY_SENTINEL_DCC_TYPE)
                .is_empty()
        );
    }

    #[test]
    fn gateway_pid_ownership_rejects_stale_pidfile_pid() {
        let dir = tempfile::tempdir().unwrap();
        let args = gateway_ctrl_args(
            "127.0.0.1".to_string(),
            19765,
            Some(dir.path().to_path_buf()),
            None,
        );
        let mut sentinel = ServiceEntry::new(GATEWAY_SENTINEL_DCC_TYPE, "127.0.0.1", 19765);
        sentinel.metadata.insert(
            "gateway_health_url".to_string(),
            "http://127.0.0.1:19765/health".to_string(),
        );
        sentinel
            .metadata
            .insert("gateway_process_pid".to_string(), "99".to_string());
        let registry = FileRegistry::new(dir.path()).unwrap();
        registry.register(sentinel).unwrap();

        let err = verify_gateway_pid_ownership(&args, 42).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("refusing to stop gateway"));
        assert!(message.contains("stale pidfile"));
        assert!(message.contains("PID reuse"));
    }

    #[test]
    fn gateway_pid_ownership_rejects_wrong_gateway_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let args = gateway_ctrl_args(
            "127.0.0.1".to_string(),
            19765,
            Some(dir.path().to_path_buf()),
            None,
        );
        let pid = 42;
        let mut sentinel = ServiceEntry::new(GATEWAY_SENTINEL_DCC_TYPE, "127.0.0.1", 19766);
        sentinel.metadata.insert(
            "gateway_health_url".to_string(),
            "http://127.0.0.1:19766/health".to_string(),
        );
        sentinel
            .metadata
            .insert("gateway_process_pid".to_string(), pid.to_string());
        let registry = FileRegistry::new(dir.path()).unwrap();
        registry.register(sentinel).unwrap();

        let err = verify_gateway_pid_ownership(&args, pid).unwrap_err();
        assert!(err.to_string().contains("no live __gateway__ sentinel"));
    }

    #[test]
    fn gateway_pid_falls_back_to_unique_live_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let args = gateway_ctrl_args(
            "127.0.0.1".to_string(),
            19765,
            Some(dir.path().to_path_buf()),
            None,
        );
        let stale_pid = 42;
        std::fs::write(&args.pidfile, stale_pid.to_string()).unwrap();
        let pid = std::process::id();
        let mut sentinel = ServiceEntry::new(GATEWAY_SENTINEL_DCC_TYPE, "127.0.0.1", 19765);
        sentinel.metadata.insert(
            "gateway_health_url".to_string(),
            "http://127.0.0.1:19765/health".to_string(),
        );
        sentinel
            .metadata
            .insert("gateway_process_pid".to_string(), pid.to_string());
        let registry = FileRegistry::new(dir.path()).unwrap();
        registry.register(sentinel).unwrap();

        assert_eq!(
            resolve_gateway_pid_with(&args, true, |candidate| candidate == pid),
            Some(pid)
        );
    }

    #[test]
    fn gateway_pid_keeps_stale_pid_without_matching_live_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let args = gateway_ctrl_args(
            "127.0.0.1".to_string(),
            19765,
            Some(dir.path().to_path_buf()),
            None,
        );
        let stale_pid = 42;
        std::fs::write(&args.pidfile, stale_pid.to_string()).unwrap();
        let mut sentinel = ServiceEntry::new(GATEWAY_SENTINEL_DCC_TYPE, "127.0.0.1", 19766);
        sentinel.metadata.insert(
            "gateway_health_url".to_string(),
            "http://127.0.0.1:19766/health".to_string(),
        );
        sentinel.metadata.insert(
            "gateway_process_pid".to_string(),
            std::process::id().to_string(),
        );
        let registry = FileRegistry::new(dir.path()).unwrap();
        registry.register(sentinel).unwrap();

        assert_eq!(
            resolve_gateway_pid_with(&args, true, |candidate| candidate == std::process::id()),
            Some(stale_pid)
        );
    }
}

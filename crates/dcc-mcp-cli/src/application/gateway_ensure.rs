//! Gateway health check and auto-launch helpers.
//!
//! Ported from `dcc-mcp-sidecar`'s `gateway_daemon::launcher` and simplified:
//! - No version takeover (CLI is not a DCC adapter).
//! - No FileRegistry dependency.
//! - No adapter_version / adapter_dcc fields.
//!
//! Shared primitives (health check, launch lock, spawn, pidfile, process
//! utilities) live in `dcc-mcp-gateway-ensure`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;
use dcc_mcp_gateway_ensure as ensure;
use serde::Serialize;

use super::gateway_discovery;

/// Outcome of an `ensure_gateway_running` call.
#[derive(Debug, Clone, Serialize)]
pub struct EnsureResult {
    pub host: String,
    pub port: u16,
    pub already_running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub registry_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pidfile: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_binary: Option<PathBuf>,
    pub cli_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedEnsureResult {
    #[serde(flatten)]
    pub ensure: EnsureResult,
    pub auth_state: ensure::GatewayAuthState,
}

/// Parameters for `ensure_gateway_running`.
#[derive(Debug, Clone)]
pub struct EnsureGatewayArgs {
    pub host: String,
    pub port: u16,
    pub name: Option<String>,
    pub registry_dir: PathBuf,
    pub remote_host: String,
    pub remote_port: u16,
    pub gateway_idle_timeout_secs: u64,
    pub gateway_bin: Option<PathBuf>,
    pub wait_timeout_secs: u64,
    /// Optional path for the PID file written after a successful start.
    pub pidfile: Option<PathBuf>,
}

/// Ensure the gateway is reachable at `host:port`, launching it once if needed.
pub async fn ensure_gateway_running(args: &EnsureGatewayArgs) -> anyhow::Result<EnsureResult> {
    Ok(ensure_gateway_running_with_auth(args, None).await?.ensure)
}

pub async fn ensure_gateway_running_with_auth(
    args: &EnsureGatewayArgs,
    auth_token_file: Option<&std::path::Path>,
) -> anyhow::Result<ManagedEnsureResult> {
    if args.port == 0 {
        anyhow::bail!("gateway port must be non-zero");
    }
    if let Some(path) = auth_token_file {
        crate::infra::http::HttpGateway::validate_auth_token_file(path)?;
    }

    if ensure::gateway_health_ok(&args.host, args.port).await {
        let auth_state = ensure::gateway_auth_state(&args.host, args.port).await;
        validate_resident_auth_mode(args, auth_token_file, auth_state)?;
        return Ok(managed_ensure_result(
            args,
            true,
            ensure::read_pid_from_pidfile(args.pidfile.as_deref()),
            args.gateway_bin.clone(),
            auth_state,
        ));
    }

    std::fs::create_dir_all(&args.registry_dir)
        .with_context(|| format!("creating registry dir {}", args.registry_dir.display()))?;
    let lock_path = args.registry_dir.join("gateway-launch.lock");
    let started = Instant::now();
    match ensure::acquire_launch_lock(&lock_path) {
        Ok(_lock) => {
            // Double-check after acquiring the lock (race protection).
            if ensure::gateway_health_ok(&args.host, args.port).await {
                let auth_state = ensure::gateway_auth_state(&args.host, args.port).await;
                validate_resident_auth_mode(args, auth_token_file, auth_state)?;
                return Ok(managed_ensure_result(
                    args,
                    true,
                    ensure::read_pid_from_pidfile(args.pidfile.as_deref()),
                    args.gateway_bin.clone(),
                    auth_state,
                ));
            }

            let exe = resolve_gateway_bin(args).await?;
            let cmd_args = ensure::gateway_command_args_with_auth(
                &args.host,
                args.port,
                args.name.as_deref(),
                &args.remote_host,
                args.remote_port,
                args.gateway_idle_timeout_secs,
                auth_token_file,
            );
            let context = ensure::GatewayLaunchContext::gateway(
                &args.host,
                args.port,
                &args.remote_host,
                args.remote_port,
                args.gateway_idle_timeout_secs,
            );
            let launch = ensure::spawn_detached_gateway_with_context(
                &exe,
                &cmd_args,
                &args.registry_dir,
                context,
            )?;

            ensure::wait_gateway_ready_with_diagnostics(
                &args.host,
                args.port,
                Duration::from_secs(ensure::resolve_ensure_timeout_secs(args.wait_timeout_secs)),
                ensure::GatewayReadyDiagnostics {
                    registry_dir: Some(&args.registry_dir),
                    launch_lock: Some(&lock_path),
                    launch: Some(&launch),
                    started: Some(started),
                    gateway_idle_timeout_secs: Some(args.gateway_idle_timeout_secs),
                    remote_host: Some(&args.remote_host),
                    remote_port: Some(args.remote_port),
                },
            )
            .await?;

            // Release lock after gateway is confirmed ready.
            drop(_lock);

            // Write PID file so stop/status commands can find the process.
            if let Some(ref pidfile) = args.pidfile {
                ensure::write_pidfile(pidfile, launch.pid)?;
            }

            let auth_state = ensure::gateway_auth_state(&args.host, args.port).await;
            validate_resident_auth_mode(args, auth_token_file, auth_state)?;
            Ok(managed_ensure_result(
                args,
                false,
                Some(launch.pid),
                Some(exe),
                auth_state,
            ))
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process holds the launch lock — wait for its winner to
            // finish and check whether the gateway becomes healthy (mirrors
            // Python `_wait_gateway_ready` on lock-loser path).
            let timeout =
                Duration::from_secs(ensure::resolve_ensure_timeout_secs(args.wait_timeout_secs));
            ensure::wait_gateway_ready_with_diagnostics(
                &args.host,
                args.port,
                timeout,
                ensure::GatewayReadyDiagnostics {
                    registry_dir: Some(&args.registry_dir),
                    launch_lock: Some(&lock_path),
                    launch: None,
                    started: Some(started),
                    gateway_idle_timeout_secs: Some(args.gateway_idle_timeout_secs),
                    remote_host: Some(&args.remote_host),
                    remote_port: Some(args.remote_port),
                },
            )
            .await?;
            let auth_state = ensure::gateway_auth_state(&args.host, args.port).await;
            validate_resident_auth_mode(args, auth_token_file, auth_state)?;
            Ok(managed_ensure_result(
                args,
                true,
                ensure::read_pid_from_pidfile(args.pidfile.as_deref()),
                args.gateway_bin.clone(),
                auth_state,
            ))
        }
        Err(err) => {
            Err(err).with_context(|| format!("creating launch lock {}", lock_path.display()))?
        }
    }
}

pub fn validate_auth_token_file(path: &std::path::Path) -> anyhow::Result<()> {
    crate::infra::http::HttpGateway::validate_auth_token_file(path).map_err(Into::into)
}

fn validate_resident_auth_mode(
    args: &EnsureGatewayArgs,
    auth_token_file: Option<&std::path::Path>,
    auth_state: ensure::GatewayAuthState,
) -> anyhow::Result<()> {
    let requested_auth = auth_token_file.is_some();
    let compatible = matches!(
        (requested_auth, auth_state),
        (true, ensure::GatewayAuthState::Enabled)
            | (
                false,
                ensure::GatewayAuthState::Disabled | ensure::GatewayAuthState::Unknown
            )
    );
    if compatible {
        return Ok(());
    }
    let requested = if requested_auth {
        "enabled"
    } else {
        "disabled"
    };
    anyhow::bail!(
        "gateway at {host}:{port} is already running with authentication mode {auth_state:?}, but this request requires {requested}; restart it with matching --auth-token-file / DCC_MCP_GATEWAY_AUTH_TOKEN_FILE configuration",
        host = args.host,
        port = args.port,
    )
}

fn ensure_result(
    args: &EnsureGatewayArgs,
    already_running: bool,
    pid: Option<u32>,
    launch_binary: Option<PathBuf>,
) -> EnsureResult {
    EnsureResult {
        host: args.host.clone(),
        port: args.port,
        already_running,
        pid,
        registry_dir: args.registry_dir.clone(),
        pidfile: args.pidfile.clone(),
        launch_binary,
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn managed_ensure_result(
    args: &EnsureGatewayArgs,
    already_running: bool,
    pid: Option<u32>,
    launch_binary: Option<PathBuf>,
    auth_state: ensure::GatewayAuthState,
) -> ManagedEnsureResult {
    ManagedEnsureResult {
        ensure: ensure_result(args, already_running, pid, launch_binary),
        auth_state,
    }
}

// ── Binary resolution (CLI-specific: uses gateway_discovery) ────────────────

async fn resolve_gateway_bin(args: &EnsureGatewayArgs) -> anyhow::Result<PathBuf> {
    gateway_discovery::resolve_gateway_bin(args.gateway_bin.as_ref()).await
}

// ── Re-exports for convenience ──────────────────────────────────────────────

pub use ensure::{
    GatewayAuthState, default_registry_dir, gateway_auth_state, gateway_health_ok,
    is_process_alive, read_pid_from_pidfile, remove_pidfile, stop_process,
};

#[cfg(test)]
mod tests {
    use super::*;

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

    fn ensure_args(port: u16, registry_dir: PathBuf) -> EnsureGatewayArgs {
        EnsureGatewayArgs {
            host: "127.0.0.1".to_string(),
            port,
            name: None,
            registry_dir,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 59765,
            gateway_idle_timeout_secs: 30,
            gateway_bin: None,
            wait_timeout_secs: 1,
            pidfile: None,
        }
    }

    #[tokio::test]
    async fn ensure_rejects_requested_auth_against_disabled_or_legacy_resident() {
        for body in [
            serde_json::json!({"ok": true, "auth_enabled": false}),
            serde_json::json!({"ok": true}),
        ] {
            let (port, server) = spawn_health_document(body).await;
            let registry = tempfile::tempdir().unwrap();
            let token_file = registry.path().join("gateway.token");
            std::fs::write(&token_file, "valid-test-token\n").unwrap();
            let args = ensure_args(port, registry.path().to_path_buf());

            let error = ensure_gateway_running_with_auth(&args, Some(&token_file))
                .await
                .unwrap_err()
                .to_string();

            assert!(error.contains("authentication mode"), "{error}");
            assert!(error.contains("restart"), "{error}");
            server.abort();
        }
    }

    #[tokio::test]
    async fn ensure_rejects_missing_auth_against_enabled_resident() {
        let (port, server) =
            spawn_health_document(serde_json::json!({"ok": true, "auth_enabled": true})).await;
        let registry = tempfile::tempdir().unwrap();
        let args = ensure_args(port, registry.path().to_path_buf());

        let error = ensure_gateway_running(&args).await.unwrap_err().to_string();

        assert!(error.contains("authentication mode"), "{error}");
        assert!(error.contains("--auth-token-file"), "{error}");
        assert!(error.contains("restart"), "{error}");
        server.abort();
    }

    #[tokio::test]
    async fn ensure_preserves_legacy_no_auth_success_and_reports_unknown_state() {
        let (port, server) = spawn_health_document(serde_json::json!({"ok": true})).await;
        let registry = tempfile::tempdir().unwrap();
        let args = ensure_args(port, registry.path().to_path_buf());

        let result = ensure_gateway_running_with_auth(&args, None).await.unwrap();
        let output = serde_json::to_value(&result).unwrap();

        assert!(result.ensure.already_running);
        assert_eq!(output["auth_state"], "unknown");
        assert!(output.get("auth_token_file").is_none());
        server.abort();
    }

    #[test]
    fn test_gateway_command_args_minimal() {
        let argv: Vec<String> =
            ensure::gateway_command_args("127.0.0.1", 9765, None, "0.0.0.0", 59765, 30)
                .into_iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
        assert!(argv[0] == "gateway");
        assert!(argv.contains(&"--port".to_string()));
        assert!(argv.contains(&"9765".to_string()));
    }

    #[test]
    fn test_gateway_command_args_include_only_auth_token_file_path() {
        let token_file = PathBuf::from("/run/secrets/dcc-mcp-gateway.token");
        let argv: Vec<String> = ensure::gateway_command_args_with_auth(
            "127.0.0.1",
            9765,
            None,
            "0.0.0.0",
            59765,
            30,
            Some(&token_file),
        )
        .into_iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect();

        let flag = argv
            .iter()
            .position(|arg| arg == "--auth-token-file")
            .unwrap();
        assert_eq!(argv.get(flag + 1), Some(&token_file.display().to_string()));
        assert_eq!(
            argv.iter()
                .filter(|arg| *arg == "--auth-token-file")
                .count(),
            1
        );
    }

    #[test]
    fn test_default_registry_dir_is_not_empty() {
        let dir = default_registry_dir();
        assert!(!dir.as_os_str().is_empty());
        assert!(dir.is_absolute());
    }
}

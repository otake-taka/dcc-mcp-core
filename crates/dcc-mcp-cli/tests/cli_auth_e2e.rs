mod support;

use tempfile::TempDir;

use support::*;

#[test]
fn authenticated_remote_profile_covers_health_rest_mcp_direct_and_batch_without_auth_fallback() {
    let fixture = spawn_auth_gateway_fixture();
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let token_file = config.path().join("gateway.token");
    std::fs::write(&token_file, "studio-secret\n").unwrap();
    let profiles_s = profiles.to_string_lossy().to_string();
    let token_file_s = token_file.to_string_lossy().to_string();
    let envs = [("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str())];

    let registered = run_json_with_env(
        &[
            "gateway",
            "register",
            &fixture.base_url,
            "--name",
            "secure",
            "--token-file",
            &token_file_s,
        ],
        &envs,
    );
    assert_eq!(registered["registered"], true);
    assert!(!registered.to_string().contains(&token_file_s));
    run_json_with_env(&["gateway", "set", "secure"], &envs);

    let health = run_json_with_env(&["health"], &envs);
    assert_eq!(health["auth_enabled"], true);
    let recording = run_json_with_env(
        &[
            "--agent-session-id",
            "auth-session",
            "record-replay",
            "start",
            "--dcc-type",
            "nuke",
        ],
        &envs,
    );
    assert_eq!(recording["recording_id"], "rec-auth");
    let rest = run_json_with_env(&["call", "maya.abc12345.inspect", "--json", "{}"], &envs);
    assert_eq!(rest["route"], "rest");
    let compat = run_json_with_env(&["call", "compat_tool", "--json", "{}"], &envs);
    assert_eq!(compat["output"]["route"], "mcp");
    let direct = run_json_with_env(
        &[
            "call",
            "nuke_graph__inspect",
            "--dcc-type",
            "nuke",
            "--instance-id",
            "abc12345",
            "--json",
            "{}",
        ],
        &envs,
    );
    assert_eq!(direct["route"], "direct");
    let batch = run_json_with_env(
        &[
            "call",
            "--batch",
            "--steps",
            r#"[{"tool_slug":"nuke.abc12345.render","arguments":{}}]"#,
        ],
        &envs,
    );
    assert_eq!(batch["route"], "batch");

    let authorized_dispatches = fixture.dispatches.load(std::sync::atomic::Ordering::SeqCst);
    let authorized_mcp_calls = fixture.mcp_calls.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(authorized_mcp_calls, 1);
    run_json_with_env(
        &[
            "gateway",
            "register",
            &fixture.base_url,
            "--name",
            "missing",
        ],
        &envs,
    );
    run_json_with_env(&["gateway", "set", "missing"], &envs);
    let unauthorized = run_failure_with_env(
        &[
            "--agent-session-id",
            "auth-session",
            "record-replay",
            "start",
            "--dcc-type",
            "nuke",
        ],
        &envs,
    );
    assert!(unauthorized.contains("HTTP 401"), "{unauthorized}");
    let unauthorized_call =
        run_failure_with_env(&["call", "maya.abc12345.inspect", "--json", "{}"], &envs);
    assert!(
        unauthorized_call.contains("HTTP 401"),
        "{unauthorized_call}"
    );

    let denied_file = config.path().join("denied.token");
    std::fs::write(&denied_file, "denied\n").unwrap();
    let denied_file_s = denied_file.to_string_lossy().to_string();
    run_json_with_env(
        &[
            "gateway",
            "register",
            &fixture.base_url,
            "--name",
            "denied",
            "--token-file",
            &denied_file_s,
        ],
        &envs,
    );
    run_json_with_env(&["gateway", "set", "denied"], &envs);
    let forbidden = run_failure_with_env(
        &[
            "--agent-session-id",
            "auth-session",
            "record-replay",
            "start",
            "--dcc-type",
            "nuke",
        ],
        &envs,
    );
    assert!(forbidden.contains("HTTP 403"), "{forbidden}");
    let forbidden_call =
        run_failure_with_env(&["call", "maya.abc12345.inspect", "--json", "{}"], &envs);
    assert!(forbidden_call.contains("HTTP 403"), "{forbidden_call}");
    assert_eq!(
        fixture.dispatches.load(std::sync::atomic::Ordering::SeqCst),
        authorized_dispatches
    );
    assert_eq!(
        fixture.mcp_calls.load(std::sync::atomic::Ordering::SeqCst),
        authorized_mcp_calls
    );
}

#[test]
fn smoke_explicit_url_ignores_missing_selected_profile_credential_and_sends_no_auth() {
    let profile_gateway = spawn_auth_gateway_fixture();
    let explicit_gateway = spawn_gateway_fixture();
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let token_file = config.path().join("gateway.token");
    let profiles_s = profiles.to_string_lossy().to_string();
    let token_file_s = token_file.to_string_lossy().to_string();
    let lifecycle_token = config.path().join("lifecycle.token");
    std::fs::write(&lifecycle_token, "studio-secret\n").unwrap();
    let lifecycle_token_s = lifecycle_token.to_string_lossy().to_string();
    let envs = [
        ("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str()),
        (
            "DCC_MCP_GATEWAY_AUTH_TOKEN_FILE",
            lifecycle_token_s.as_str(),
        ),
    ];

    run_json_with_env(
        &[
            "gateway",
            "register",
            &profile_gateway.base_url,
            "--name",
            "secure",
            "--token-file",
            &token_file_s,
        ],
        &envs,
    );
    run_json_with_env(&["gateway", "set", "secure"], &envs);
    let smoke = run_json_with_env(
        &[
            "smoke",
            "--url",
            &format!("{}/mcp", explicit_gateway.base_url),
        ],
        &envs,
    );

    assert_eq!(smoke["ok"], true);
    assert_eq!(
        explicit_gateway
            .authorization_headers
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn gateway_profile_commands_can_recover_from_a_missing_remote_token_file() {
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let profiles_s = profiles.to_string_lossy().to_string();
    std::fs::write(
        &profiles,
        serde_json::to_vec_pretty(&serde_json::json!({
            "current": "secure",
            "profiles": {
                "secure": {
                    "base_url": "https://example.invalid",
                    "token_file": config.path().join("missing.token")
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let envs = [("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str())];

    let listed = run_json_with_env(&["gateway", "list"], &envs);
    assert_eq!(listed["selected"]["mode"], "remote");
    assert!(!listed.to_string().contains("missing.token"));
    let local = run_json_with_env(&["gateway", "set", "local"], &envs);
    assert_eq!(local["mode"], "local");
}

#[test]
fn explicit_loopback_base_url_uses_one_env_credential_for_ensure_and_call() {
    let fixture = spawn_auth_gateway_fixture();
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let token_file = config.path().join("gateway.token");
    std::fs::write(&token_file, "studio-secret\n").unwrap();
    let profiles_s = profiles.to_string_lossy().to_string();
    let token_file_s = token_file.to_string_lossy().to_string();
    let envs = [
        ("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str()),
        ("DCC_MCP_GATEWAY_AUTH_TOKEN_FILE", token_file_s.as_str()),
    ];

    let result = run_json_with_env(
        &[
            "--base-url",
            &fixture.base_url,
            "call",
            "maya.abc12345.inspect",
            "--json",
            "{}",
        ],
        &envs,
    );

    assert_eq!(result["route"], "rest");
    assert_eq!(
        fixture.dispatches.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn explicit_loopback_base_url_wrong_credential_is_terminal_before_backend_dispatch() {
    let fixture = spawn_auth_gateway_fixture();
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let token_file = config.path().join("gateway.token");
    std::fs::write(&token_file, "denied\n").unwrap();
    let profiles_s = profiles.to_string_lossy().to_string();
    let token_file_s = token_file.to_string_lossy().to_string();
    let envs = [
        ("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str()),
        ("DCC_MCP_GATEWAY_AUTH_TOKEN_FILE", token_file_s.as_str()),
    ];

    let error = run_failure_with_env(
        &[
            "--base-url",
            &fixture.base_url,
            "call",
            "maya.abc12345.inspect",
            "--json",
            "{}",
        ],
        &envs,
    );

    assert!(error.contains("HTTP 403"), "{error}");
    assert_eq!(
        fixture.dispatches.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn explicit_loopback_base_url_missing_credential_fails_before_backend_dispatch() {
    let fixture = spawn_auth_gateway_fixture();
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let missing = config.path().join("missing.token");
    let profiles_s = profiles.to_string_lossy().to_string();
    let missing_s = missing.to_string_lossy().to_string();
    let envs = [
        ("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str()),
        ("DCC_MCP_GATEWAY_AUTH_TOKEN_FILE", missing_s.as_str()),
    ];

    let error = run_failure_with_env(
        &[
            "--base-url",
            &fixture.base_url,
            "call",
            "maya.abc12345.inspect",
            "--json",
            "{}",
        ],
        &envs,
    );

    assert!(error.contains("auth token file"), "{error}");
    assert_eq!(
        fixture.dispatches.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn named_profile_uses_its_snapshot_credential_when_local_env_credential_also_exists() {
    let fixture = spawn_auth_gateway_fixture();
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let profile_token = config.path().join("profile.token");
    let lifecycle_token = config.path().join("lifecycle.token");
    std::fs::write(&profile_token, "studio-secret\n").unwrap();
    std::fs::write(&lifecycle_token, "denied\n").unwrap();
    let profiles_s = profiles.to_string_lossy().to_string();
    let profile_token_s = profile_token.to_string_lossy().to_string();
    let lifecycle_token_s = lifecycle_token.to_string_lossy().to_string();
    let profile_env = [("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str())];

    run_json_with_env(
        &[
            "gateway",
            "register",
            &fixture.base_url,
            "--name",
            "secure",
            "--token-file",
            &profile_token_s,
        ],
        &profile_env,
    );
    run_json_with_env(&["gateway", "set", "secure"], &profile_env);

    let envs = [
        ("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str()),
        (
            "DCC_MCP_GATEWAY_AUTH_TOKEN_FILE",
            lifecycle_token_s.as_str(),
        ),
    ];
    let result = run_json_with_env(&["call", "maya.abc12345.inspect", "--json", "{}"], &envs);

    assert_eq!(result["route"], "rest");
    assert_eq!(
        fixture.dispatches.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn explicit_loopback_base_url_remains_compatible_without_auth() {
    let fixture = spawn_gateway_fixture();
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let profiles_s = profiles.to_string_lossy().to_string();
    let envs = [("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str())];

    let result = run_json_with_env(
        &[
            "--base-url",
            &fixture.base_url,
            "search",
            "--query",
            "sphere",
        ],
        &envs,
    );

    assert!(result.is_object());
}

#[test]
fn explicit_non_managed_base_url_does_not_receive_local_lifecycle_credential() {
    let fixture = spawn_gateway_fixture();
    let port = reqwest::Url::parse(&fixture.base_url)
        .unwrap()
        .port()
        .unwrap();
    let unmanaged_base_url = format!("http://127.0.0.2:{port}");
    let config = TempDir::new().unwrap();
    let profiles = config.path().join("gateway-profiles.json");
    let lifecycle_token = config.path().join("lifecycle.token");
    std::fs::write(&lifecycle_token, "denied\n").unwrap();
    let profiles_s = profiles.to_string_lossy().to_string();
    let lifecycle_token_s = lifecycle_token.to_string_lossy().to_string();
    let envs = [
        ("DCC_MCP_GATEWAY_PROFILES_FILE", profiles_s.as_str()),
        (
            "DCC_MCP_GATEWAY_AUTH_TOKEN_FILE",
            lifecycle_token_s.as_str(),
        ),
    ];

    let result = run_json_with_env(
        &[
            "--base-url",
            &unmanaged_base_url,
            "search",
            "--query",
            "sphere",
        ],
        &envs,
    );

    assert!(result.is_object());
    assert_eq!(
        fixture
            .authorization_headers
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

use std::path::{Path, PathBuf};

use crate::application::gateway_ctrl;
use crate::application::gateway_profile::GatewayTarget;
use crate::domain::rest::Endpoint;

use super::{Command, MarketplaceAction};

pub(super) async fn ensure_gateway_for_command(
    base_url: &str,
    command: &Command,
    gateway_target: &GatewayTarget,
    gateway_bin: Option<PathBuf>,
    wait_timeout_secs: u64,
    auth_token_file: Option<&Path>,
) -> anyhow::Result<()> {
    let Some(endpoint) = gateway_endpoint_for_command(base_url, command, gateway_target) else {
        return Ok(());
    };
    if !gateway_target_uses_local_lifecycle(gateway_target, &endpoint) {
        return Ok(());
    }
    let Some(result) = gateway_ctrl::ensure_local_gateway_for_endpoint_with_auth(
        &endpoint,
        gateway_bin,
        wait_timeout_secs,
        auth_token_file,
    )
    .await?
    else {
        return Ok(());
    };

    if !result.already_running {
        if let Some(pid) = result.pid {
            eprintln!(
                "info: auto-started gateway at http://{}:{} (pid {pid})",
                result.host, result.port
            );
        } else {
            eprintln!(
                "info: auto-started gateway at http://{}:{}",
                result.host, result.port
            );
        }
    }
    Ok(())
}

pub(super) fn resolve_gateway_credential_for_command(
    base_url: &str,
    command: &Command,
    gateway_target: &GatewayTarget,
    profile_token_file: Option<PathBuf>,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(endpoint) = gateway_endpoint_for_command(base_url, command, gateway_target) else {
        return Ok(None);
    };

    if gateway_target_uses_local_lifecycle(gateway_target, &endpoint) {
        debug_assert!(profile_token_file.is_none());
        return Ok(std::env::var_os("DCC_MCP_GATEWAY_AUTH_TOKEN_FILE").map(PathBuf::from));
    }
    if matches!(gateway_target, GatewayTarget::Remote { name, .. } if name == "base-url") {
        debug_assert!(profile_token_file.is_none());
        return Ok(None);
    }
    Ok(profile_token_file)
}

pub(super) fn gateway_target_uses_local_lifecycle(
    target: &GatewayTarget,
    endpoint: &Endpoint,
) -> bool {
    matches!(target, GatewayTarget::Local)
        || (matches!(target, GatewayTarget::Remote { name, .. } if name == "base-url")
            && gateway_ctrl::local_auto_gateway_target(endpoint).is_some())
}

pub(super) fn gateway_endpoint_for_command(
    base_url: &str,
    command: &Command,
    _gateway_target: &GatewayTarget,
) -> Option<Endpoint> {
    match command {
        Command::Smoke { url: None, .. } => Some(Endpoint::new(base_url)),
        Command::Smoke { url: Some(_), .. } => None,
        Command::Health | Command::Stats { .. } | Command::Update { .. } => {
            Some(Endpoint::new(base_url))
        }
        Command::Doctor { .. } | Command::DccTypes { .. } => None,
        Command::List
        | Command::Search { .. }
        | Command::Describe { .. }
        | Command::LoadSkill { .. }
        | Command::Call { .. }
        | Command::CallBatch { .. }
        | Command::UiControl { .. }
        | Command::RecordReplay { .. }
        | Command::WaitReady { .. }
        | Command::ReloadSkills { .. }
        | Command::StopInstance { .. } => Some(Endpoint::new(base_url)),
        Command::Marketplace {
            action: MarketplaceAction::Install { reload: true, .. },
        }
        | Command::Marketplace {
            action: MarketplaceAction::Uninstall { reload: true, .. },
        } => Some(Endpoint::new(base_url)),
        // Local mode still executes these commands through FileRegistry/direct
        // MCP where that is the richer path, but the CLI owns gateway
        // lifecycle by default so agents can rely on the admin/control plane.
        Command::Install { .. }
        | Command::Marketplace { .. }
        | Command::Lint(_)
        | Command::Components { .. }
        | Command::Gateway { .. } => None,
    }
}

//! Gateway profile persistence for `dcc-mcp-cli`.
//!
//! The `local` profile is built in and means "use the local FileRegistry /
//! direct local instance path". Named profiles point at remote gateway base
//! URLs and are selected with `dcc-mcp-cli gateway set <name>` or
//! `--gateway <name>`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::domain::rest::Endpoint;

pub const LOCAL_PROFILE_NAME: &str = "local";
const PROFILE_FILE_ENV: &str = "DCC_MCP_GATEWAY_PROFILES_FILE";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayProfile {
    pub base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayProfileStore {
    #[serde(default = "default_current")]
    pub current: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, GatewayProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayTarget {
    Local,
    Remote { name: String, endpoint: Endpoint },
}

impl GatewayTarget {
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }

    #[must_use]
    pub fn endpoint_or_default(&self, default_base_url: &str) -> Endpoint {
        match self {
            Self::Local => Endpoint::new(default_base_url),
            Self::Remote { endpoint, .. } => endpoint.clone(),
        }
    }

    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Local => LOCAL_PROFILE_NAME,
            Self::Remote { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayProfileDocument {
    #[serde(default = "default_current")]
    current: String,
    #[serde(default)]
    profiles: BTreeMap<String, GatewayProfileWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayProfileWire {
    base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedGatewaySelection {
    pub store: GatewayProfileStore,
    pub target: GatewayTarget,
    pub token_file: Option<PathBuf>,
}

impl Default for GatewayProfileStore {
    fn default() -> Self {
        Self {
            current: default_current(),
            profiles: BTreeMap::new(),
        }
    }
}

impl GatewayProfileStore {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Ok(load_profile_document(path)?
            .as_ref()
            .map(store_from_document)
            .unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating gateway profile dir {}", parent.display()))?;
        }
        save_profile_document(path, self, None)
    }

    pub fn register_remote(
        &mut self,
        name: impl Into<String>,
        base_url: impl Into<String>,
    ) -> anyhow::Result<GatewayProfile> {
        let name = normalize_profile_name(name.into())?;
        if name.eq_ignore_ascii_case(LOCAL_PROFILE_NAME) {
            anyhow::bail!("'local' is a built-in gateway profile and cannot be registered");
        }
        let endpoint = Endpoint::new(base_url.into());
        validate_gateway_url(&endpoint.base_url)?;
        let profile = GatewayProfile {
            base_url: endpoint.base_url,
        };
        self.profiles.insert(name, profile.clone());
        Ok(profile)
    }

    pub fn set_current(&mut self, name: impl Into<String>) -> anyhow::Result<GatewayTarget> {
        let name = normalize_profile_name(name.into())?;
        let target = self.resolve(Some(&name), None)?;
        self.current = target.label().to_string();
        Ok(target)
    }

    pub fn resolve(
        &self,
        explicit_name: Option<&str>,
        explicit_base_url: Option<&str>,
    ) -> anyhow::Result<GatewayTarget> {
        if let Some(base_url) = explicit_base_url.filter(|value| !value.trim().is_empty()) {
            let endpoint = Endpoint::new(base_url);
            validate_gateway_url(&endpoint.base_url)?;
            return Ok(GatewayTarget::Remote {
                name: "base-url".to_string(),
                endpoint,
            });
        }

        let name = explicit_name
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&self.current);
        let name = normalize_profile_name(name)?;
        if name.eq_ignore_ascii_case(LOCAL_PROFILE_NAME) {
            return Ok(GatewayTarget::Local);
        }

        let profile = self
            .profiles
            .get(&name)
            .ok_or_else(|| anyhow::anyhow!("unknown gateway profile '{name}'"))?;
        Ok(GatewayTarget::Remote {
            name,
            endpoint: Endpoint::new(profile.base_url.clone()),
        })
    }

    #[must_use]
    pub fn summary(&self, path: &Path, selected: Option<&GatewayTarget>) -> Value {
        let profiles: Vec<_> = self
            .profiles
            .iter()
            .map(|(name, profile)| {
                json!({
                    "name": name,
                    "base_url": profile.base_url,
                })
            })
            .collect();
        json!({
            "config_path": path,
            "current": self.current,
            "stored_current": self.current,
            "selected": selected.map(target_summary).unwrap_or(Value::Null),
            "profiles": profiles,
        })
    }
}

pub(crate) fn load_and_resolve_selection(
    path: &Path,
    explicit_name: Option<&str>,
    explicit_base_url: Option<&str>,
) -> anyhow::Result<ResolvedGatewaySelection> {
    let document = load_profile_document(path)?;
    let store = document
        .as_ref()
        .map(store_from_document)
        .unwrap_or_default();
    let target = store.resolve(explicit_name, explicit_base_url)?;
    let token_file = match (&document, &target) {
        (Some(document), GatewayTarget::Remote { name, .. }) if name != "base-url" => document
            .profiles
            .get(name)
            .and_then(|profile| profile.token_file.clone()),
        _ => None,
    };
    Ok(ResolvedGatewaySelection {
        store,
        target,
        token_file,
    })
}

pub fn register_profile(path: &Path, name: String, url: String) -> anyhow::Result<Value> {
    register_profile_with_token_file(path, name, url, None)
}

pub fn register_profile_with_token_file(
    path: &Path,
    name: String,
    url: String,
    token_file: Option<PathBuf>,
) -> anyhow::Result<Value> {
    let mut store = GatewayProfileStore::load(path)?;
    let name = normalize_profile_name(name)?;
    let profile = store.register_remote(name.clone(), url)?;
    save_profile_document(path, &store, Some((&name, token_file)))?;
    Ok(json!({
        "registered": true,
        "name": name,
        "base_url": profile.base_url,
        "current": store.current,
        "config_path": path,
    }))
}

pub fn set_current_profile(path: &Path, name: String) -> anyhow::Result<Value> {
    let mut store = GatewayProfileStore::load(path)?;
    let target = store.set_current(name)?;
    store.save(path)?;
    let mut summary = target_summary(&target);
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("config_path".to_string(), json!(path));
    }
    Ok(summary)
}

pub fn list_profiles(path: &Path) -> anyhow::Result<Value> {
    let store = GatewayProfileStore::load(path)?;
    let selected = store.resolve(None, None)?;
    Ok(store.summary(path, Some(&selected)))
}

pub fn default_profile_path() -> PathBuf {
    if let Ok(path) = std::env::var(PROFILE_FILE_ENV)
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    let home = dirs::home_dir().unwrap_or_else(std::env::temp_dir);
    home.join(".dcc-mcp").join("gateway-profiles.json")
}

fn default_current() -> String {
    LOCAL_PROFILE_NAME.to_string()
}

fn load_profile_document(path: &Path) -> anyhow::Result<Option<GatewayProfileDocument>> {
    let Some(raw) = std::fs::read_to_string(path)
        .optional()
        .with_context(|| format!("reading gateway profile file {}", path.display()))?
    else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&raw)
        .map(Some)
        .with_context(|| format!("parsing gateway profile file {}", path.display()))
}

fn store_from_document(document: &GatewayProfileDocument) -> GatewayProfileStore {
    let current = if document.current.trim().is_empty() {
        default_current()
    } else {
        document.current.clone()
    };
    GatewayProfileStore {
        current,
        profiles: document
            .profiles
            .iter()
            .map(|(name, profile)| {
                (
                    name.clone(),
                    GatewayProfile {
                        base_url: profile.base_url.clone(),
                    },
                )
            })
            .collect(),
    }
}

fn save_profile_document(
    path: &Path,
    store: &GatewayProfileStore,
    token_override: Option<(&str, Option<PathBuf>)>,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating gateway profile dir {}", parent.display()))?;
    }
    let existing = load_profile_document(path)?.unwrap_or(GatewayProfileDocument {
        current: default_current(),
        profiles: BTreeMap::new(),
    });
    let profiles = store
        .profiles
        .iter()
        .map(|(name, profile)| {
            let token_file = token_override
                .as_ref()
                .filter(|(override_name, _)| *override_name == name)
                .map(|(_, token_file)| token_file.clone())
                .unwrap_or_else(|| {
                    existing
                        .profiles
                        .get(name)
                        .and_then(|profile| profile.token_file.clone())
                });
            (
                name.clone(),
                GatewayProfileWire {
                    base_url: profile.base_url.clone(),
                    token_file,
                },
            )
        })
        .collect();
    let body = serde_json::to_string_pretty(&GatewayProfileDocument {
        current: store.current.clone(),
        profiles,
    })
    .context("serializing gateway profiles")?;
    std::fs::write(path, format!("{body}\n"))
        .with_context(|| format!("writing gateway profile file {}", path.display()))
}

fn normalize_profile_name(name: impl AsRef<str>) -> anyhow::Result<String> {
    let name = name.as_ref().trim();
    if name.is_empty() {
        anyhow::bail!("gateway profile name must not be empty");
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        anyhow::bail!(
            "gateway profile names may contain only ASCII letters, digits, '.', '_' and '-'"
        );
    }
    Ok(name.to_string())
}

fn validate_gateway_url(base_url: &str) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(base_url)
        .with_context(|| format!("invalid gateway URL '{base_url}'"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        scheme => anyhow::bail!("gateway URL must use http or https, got '{scheme}'"),
    }
}

fn target_summary(target: &GatewayTarget) -> Value {
    match target {
        GatewayTarget::Local => json!({
            "current": LOCAL_PROFILE_NAME,
            "name": LOCAL_PROFILE_NAME,
            "mode": "local",
        }),
        GatewayTarget::Remote { name, endpoint, .. } => json!({
            "current": name,
            "name": name,
            "mode": "remote",
            "base_url": endpoint.base_url,
        }),
    }
}

trait OptionalIo<T> {
    fn optional(self) -> std::io::Result<Option<T>>;
}

impl OptionalIo<String> for std::io::Result<String> {
    fn optional(self) -> std::io::Result<Option<String>> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_store_resolves_local() {
        let store = GatewayProfileStore::default();
        assert_eq!(store.resolve(None, None).unwrap(), GatewayTarget::Local);
    }

    #[test]
    fn register_and_select_remote_profile() {
        let mut store = GatewayProfileStore::default();
        store
            .register_remote("pcA", "https://example.com:19293/")
            .unwrap();
        let target = store.set_current("pcA").unwrap();
        assert_eq!(store.current, "pcA");
        assert_eq!(
            target,
            GatewayTarget::Remote {
                name: "pcA".to_string(),
                endpoint: Endpoint::new("https://example.com:19293"),
            }
        );
    }

    #[test]
    fn set_current_canonicalizes_builtin_local_profile() {
        let mut store = GatewayProfileStore::default();
        store
            .register_remote("pcA", "https://example.com:19293/")
            .unwrap();
        store.set_current("pcA").unwrap();

        let target = store.set_current("LOCAL").unwrap();

        assert_eq!(target, GatewayTarget::Local);
        assert_eq!(store.current, LOCAL_PROFILE_NAME);
    }

    #[test]
    fn register_profile_reports_canonical_profile_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");

        let value = register_profile(
            &path,
            " pcA ".to_string(),
            "https://example.com:19293/".to_string(),
        )
        .unwrap();

        assert_eq!(value["name"], "pcA");
        let store = GatewayProfileStore::load(&path).unwrap();
        assert!(store.profiles.contains_key("pcA"));
    }

    #[test]
    fn explicit_base_url_overrides_current_profile_without_persisting() {
        let mut store = GatewayProfileStore::default();
        store
            .register_remote("pcA", "https://example.com:19293/")
            .unwrap();
        store.set_current("pcA").unwrap();

        let target = store
            .resolve(None, Some("https://override.example:19293/"))
            .unwrap();

        assert_eq!(
            target,
            GatewayTarget::Remote {
                name: "base-url".to_string(),
                endpoint: Endpoint::new("https://override.example:19293"),
            }
        );
        assert_eq!(store.current, "pcA");
    }

    #[test]
    fn list_profiles_reports_current_selection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");

        register_profile(
            &path,
            "pcA".to_string(),
            "https://example.com:19293".to_string(),
        )
        .unwrap();
        set_current_profile(&path, "pcA".to_string()).unwrap();
        let value = list_profiles(&path).unwrap();

        assert_eq!(value["current"], "pcA");
        assert_eq!(value["selected"]["mode"], "remote");
        assert_eq!(value["profiles"][0]["name"], "pcA");
        assert_eq!(
            value["profiles"][0]["base_url"],
            "https://example.com:19293"
        );
    }

    #[test]
    fn old_profile_json_remains_compatible() {
        let store: GatewayProfileStore = serde_json::from_value(json!({
            "current": "pcA",
            "profiles": {
                "pcA": {"base_url": "https://example.com:19293"}
            }
        }))
        .unwrap();

        assert_eq!(store.profiles["pcA"].base_url, "https://example.com:19293");
    }

    #[test]
    fn remote_profile_persists_only_token_file_path_and_hides_it_from_summary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        let token_file = dir.path().join("gateway.token");
        register_profile_with_token_file(
            &path,
            "pcA".to_string(),
            "https://example.com:19293".to_string(),
            Some(token_file.clone()),
        )
        .unwrap();
        let mut store = GatewayProfileStore::load(&path).unwrap();
        store.set_current("pcA").unwrap();
        store.save(&path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains(token_file.to_string_lossy().as_ref()));
        assert!(!raw.contains("studio-secret"));
        let selection = load_and_resolve_selection(&path, None, None).unwrap();
        let target = selection.target;
        assert_eq!(selection.token_file, Some(token_file.clone()));
        let summary = store.summary(&path, Some(&target));
        assert!(
            summary
                .to_string()
                .find(token_file.to_string_lossy().as_ref())
                .is_none()
        );
    }

    #[test]
    fn selected_remote_endpoint_and_token_file_come_from_one_document_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        let original_token = dir.path().join("original.token");
        let replacement_token = dir.path().join("replacement.token");
        register_profile_with_token_file(
            &path,
            "studio".to_string(),
            "https://original.example:19293".to_string(),
            Some(original_token.clone()),
        )
        .unwrap();
        set_current_profile(&path, "studio".to_string()).unwrap();

        let selection = load_and_resolve_selection(&path, None, None).unwrap();
        register_profile_with_token_file(
            &path,
            "studio".to_string(),
            "https://replacement.example:19293".to_string(),
            Some(replacement_token),
        )
        .unwrap();

        assert_eq!(
            selection
                .target
                .endpoint_or_default("http://127.0.0.1:9765")
                .base_url,
            "https://original.example:19293"
        );
        assert_eq!(selection.token_file, Some(original_token));
    }
}

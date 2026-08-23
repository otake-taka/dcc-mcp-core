//! Bearer-token authentication for gateway registration and backend dispatch.
//!
//! This module implements the **minimum** viable authentication and
//! scope-enforcement layer required by epic #1367 to close the local-trust
//! gap once the gateway can be reached over the network. The contract is
//! intentionally small:
//!
//! 1. **No auth by default.** [`GatewayAuth::disabled()`] is the value used
//!    on `main`; every request is accepted exactly as before. Operators opt
//!    in by passing a populated [`GatewayAuth`] to the gateway runner.
//!
//! 2. **One header, one token.** When auth is enabled, callers must send
//!    `Authorization: Bearer <secret>`. The secret is matched against a
//!    static list of pre-shared tokens. Richer identity schemes are outside
//!    this bounded dispatch contract.
//!
//! 3. **DCC scope is enforced at the token level.** Every token may
//!    declare an `allowed_dcc` set (e.g. `["maya", "blender"]`). On
//!    `POST /v1/instances/register` the gateway compares the incoming
//!    `dcc_type` against the token's set. Protected backend dispatch uses the
//!    resolved registry row rather than caller metadata for the same check.
//!
//! Out-of-scope for this module (tracked in #1367 follow-ups):
//!
//! * In-binary TLS termination — operators run the gateway behind a
//!   reverse proxy that does TLS, mTLS, and rate limiting.
//! * Native gateway mutators, direct per-DCC listeners, and principal-to-lease
//!   or audit binding. Those require a wider ingress contract than this module.
//!
//! See `docs/guide/gateway.md` § Security and `tests/vrs/traces/core-1365
//! -gateway-auth-negative.jsonl` for the operator-facing contract.

use std::collections::BTreeSet;
use std::fmt;

use dcc_mcp_models::DccName;
use serde::{Deserialize, Serialize};

/// Borrowed credential presented at an HTTP ingress boundary.
///
/// The raw header value is deliberately non-cloneable, non-serializable, and
/// non-debuggable. It must be consumed immediately by
/// [`GatewayAuth::authenticate_dispatch`] and must never enter tracing, audit
/// metadata, or a backend request.
pub(crate) struct PresentedAuthorization<'a> {
    raw: Option<&'a str>,
}

impl<'a> PresentedAuthorization<'a> {
    pub(crate) fn new(raw: Option<&'a str>) -> Self {
        Self { raw }
    }
}

/// Secret-free authentication context for one protected backend dispatch.
///
/// Fields are private so only this module can construct an authenticated
/// grant. Caller-provided agent, session, lease, and correlation metadata are
/// intentionally not authentication identity.
pub(crate) struct DispatchRequestContext<'auth> {
    authority: &'auth GatewayAuth,
    authorization: DispatchAuthorization,
}

enum DispatchAuthorization {
    AuthDisabled,
    Authenticated { token_index: usize },
}

/// A single pre-shared bearer token plus its allowed registration and dispatch
/// DCC scope.
///
/// `allowed_dcc == None` means "this token can use any `dcc_type`",
/// useful for an operator that bootstraps a multi-DCC studio with a
/// single master token. `allowed_dcc = Some(set)` confines the token to
/// those DCC types and rejects anything else with a structured
/// `dcc_scope_mismatch` envelope.
#[derive(Clone, Deserialize, Serialize)]
pub struct GatewayAuthToken {
    /// Bearer secret. Never logged in `Debug` form — `Display` is not
    /// implemented on purpose. Operators are responsible for keeping the
    /// values outside of process argv (use a config file or env var).
    pub token: String,
    /// Optional scope: `None` accepts any DCC, `Some(set)` confines the
    /// token to the listed DCC types (`"maya"`, `"blender"`, …).
    pub allowed_dcc: Option<BTreeSet<String>>,
    /// Optional opaque operator label retained in configuration. It is not
    /// used for matching or dispatch attribution. Defaults to the empty string.
    #[serde(default)]
    pub label: String,
}

impl fmt::Debug for GatewayAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayAuthToken")
            .field("token", &"[REDACTED]")
            .field("allowed_dcc", &self.allowed_dcc)
            .field("label", &self.label)
            .finish()
    }
}

impl GatewayAuthToken {
    /// Build a token that accepts any DCC.
    pub fn any_dcc(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            allowed_dcc: None,
            label: String::new(),
        }
    }

    /// Build a token confined to the given DCC types.
    pub fn for_dcc<I, S>(token: impl Into<String>, dccs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            token: token.into(),
            allowed_dcc: Some(dccs.into_iter().map(Into::into).collect()),
            label: String::new(),
        }
    }
}

/// Top-level auth configuration consumed by the gateway.
///
/// When [`GatewayAuth::is_enabled`] is `false` (the default), the
/// gateway behaves exactly as it did before #1365 — every request is
/// accepted. When `true`, callers must supply a matching bearer token
/// on every request the auth layer protects.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GatewayAuth {
    /// List of pre-shared tokens. Order is preserved but not significant
    /// — the first matching token wins.
    pub tokens: Vec<GatewayAuthToken>,
}

impl GatewayAuth {
    /// Disabled auth — every request is accepted. This is the default
    /// `main` behaviour and the value used by every test that does not
    /// specifically exercise auth.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Whether any token is configured. When `false`, callers should
    /// skip auth checks entirely.
    pub fn is_enabled(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// Authenticate a presented credential exactly once at the ingress boundary.
    ///
    /// Invalid and missing credentials fail before backend discovery,
    /// middleware, pending-call bookkeeping, or telemetry. The returned
    /// context contains no raw credential and is bound to this exact auth
    /// configuration instance.
    pub(crate) fn authenticate_dispatch(
        &self,
        presented: PresentedAuthorization<'_>,
    ) -> Result<DispatchRequestContext<'_>, AuthError> {
        if !self.is_enabled() {
            return Ok(DispatchRequestContext {
                authority: self,
                authorization: DispatchAuthorization::AuthDisabled,
            });
        }
        let candidate = presented
            .raw
            .and_then(strip_bearer)
            .ok_or(AuthError::CallUnauthorized)?;
        let token_index = self
            .tokens
            .iter()
            .position(|configured| {
                constant_time_eq(configured.token.as_bytes(), candidate.as_bytes())
            })
            .ok_or(AuthError::CallUnauthorized)?;
        Ok(DispatchRequestContext {
            authority: self,
            authorization: DispatchAuthorization::Authenticated { token_index },
        })
    }

    /// Authorise one authenticated request for an authoritative resolved DCC.
    ///
    /// This second-stage check is owned by the current auth configuration. A
    /// context issued by another configuration (including an auth-disabled
    /// configuration) fails closed rather than acting as a self-contained
    /// grant.
    pub(crate) fn authorize_dispatch(
        &self,
        context: &DispatchRequestContext<'_>,
        resolved_dcc_type: &DccName,
    ) -> Result<(), AuthError> {
        if !std::ptr::eq(self, context.authority) {
            return Err(AuthError::CallUnauthorized);
        }
        match context.authorization {
            DispatchAuthorization::AuthDisabled if !self.is_enabled() => Ok(()),
            DispatchAuthorization::Authenticated { token_index } if self.is_enabled() => {
                let token = self
                    .tokens
                    .get(token_index)
                    .ok_or(AuthError::CallUnauthorized)?;
                if token
                    .allowed_dcc
                    .as_ref()
                    .is_some_and(|scope| !scope.contains(resolved_dcc_type.as_str()))
                {
                    return Err(AuthError::CallUnauthorized);
                }
                Ok(())
            }
            _ => Err(AuthError::CallUnauthorized),
        }
    }

    /// Authorise a `POST /v1/instances/register` request.
    ///
    /// * `authorization_header` — the raw `Authorization` header value as
    ///   received by axum (or `None` if absent).
    /// * `dcc_type` — the `dcc_type` field from the registration body.
    ///
    /// Returns `Ok(())` when the request is allowed and an [`AuthError`]
    /// otherwise. Callers should map the error into the structured 401/
    /// 403 envelope expected by agents.
    pub fn authorize_register(
        &self,
        authorization_header: Option<&str>,
        dcc_type: &str,
    ) -> Result<(), AuthError> {
        if !self.is_enabled() {
            return Ok(());
        }
        let raw = authorization_header.ok_or(AuthError::MissingBearer)?;
        let presented = strip_bearer(raw).ok_or(AuthError::MalformedBearer)?;
        let token = self
            .tokens
            .iter()
            .find(|t| constant_time_eq(t.token.as_bytes(), presented.as_bytes()))
            .ok_or(AuthError::UnknownToken)?;
        if let Some(scope) = token.allowed_dcc.as_ref()
            && !scope.contains(dcc_type)
        {
            return Err(AuthError::DccScopeMismatch {
                presented_dcc: dcc_type.to_string(),
            });
        }
        Ok(())
    }
}

/// Structured authentication / authorisation failure.
///
/// The variants map 1:1 to the `error.kind` field of the JSON envelope
/// returned to agents; see [`AuthError::kind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// `Authorization` header absent on a request that requires it.
    MissingBearer,
    /// `Authorization` header present but not a `Bearer <token>` value.
    MalformedBearer,
    /// `Bearer` value did not match any configured token.
    UnknownToken,
    /// Token was recognised but the requested `dcc_type` is outside its
    /// `allowed_dcc` scope.
    DccScopeMismatch { presented_dcc: String },
    /// A protected dispatch did not present an authorised credential. The
    /// specific authentication or scope failure is hidden from callers.
    CallUnauthorized,
}

impl AuthError {
    /// Stable `error.kind` slug for the JSON envelope.
    pub fn kind(&self) -> &'static str {
        match self {
            AuthError::MissingBearer | AuthError::MalformedBearer | AuthError::UnknownToken => {
                "unauthorized"
            }
            AuthError::DccScopeMismatch { .. } => "dcc_scope_mismatch",
            AuthError::CallUnauthorized => "unauthorized",
        }
    }

    /// Human-readable message suitable for `error.message`.
    pub fn message(&self) -> String {
        match self {
            AuthError::MissingBearer => {
                "Authorization header is required for this endpoint.".to_string()
            }
            AuthError::MalformedBearer => {
                "Authorization header must be of the form 'Bearer <token>'.".to_string()
            }
            AuthError::UnknownToken => "Bearer token is not recognised.".to_string(),
            AuthError::DccScopeMismatch { presented_dcc } => {
                format!("Bearer token is not authorised to register dcc_type={presented_dcc}.")
            }
            AuthError::CallUnauthorized => {
                "Valid bearer authorization is required for this operation.".to_string()
            }
        }
    }

    /// HTTP status the envelope should ship under.
    pub fn http_status(&self) -> u16 {
        match self {
            AuthError::MissingBearer | AuthError::MalformedBearer | AuthError::UnknownToken => 401,
            AuthError::DccScopeMismatch { .. } => 403,
            AuthError::CallUnauthorized => 401,
        }
    }
}

fn strip_bearer(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let (scheme, rest) = trimmed.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod security_tests;

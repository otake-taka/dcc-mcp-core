use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::{self, HeaderMap, HeaderValue};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("server returned HTTP {status}: {body}")]
    Status {
        status: reqwest::StatusCode,
        body: String,
    },
}

#[derive(Debug, Error)]
pub(crate) enum HttpGatewayBuildError {
    #[error("failed to read gateway auth token file {path}: {source}")]
    ReadToken {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("gateway auth token file {path} is empty after trimming whitespace")]
    EmptyToken { path: PathBuf },
    #[error(
        "gateway auth token file {path} contains a value that cannot be used in an HTTP Authorization header"
    )]
    InvalidToken { path: PathBuf },
    #[error("failed to build gateway HTTP client: {0}")]
    Client(#[source] reqwest::Error),
}

#[derive(Clone)]
pub struct HttpGateway {
    client: reqwest::Client,
    authorization: Option<HeaderValue>,
}

impl fmt::Debug for HttpGateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpGateway")
            .field("authorization_configured", &self.authorization.is_some())
            .finish()
    }
}

impl Default for HttpGateway {
    fn default() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }
}

impl HttpGateway {
    pub(crate) fn validate_auth_token_file(path: &Path) -> Result<(), HttpGatewayBuildError> {
        load_authorization(path).map(drop)
    }

    pub(crate) fn build(
        timeout: Duration,
        token_file: Option<&Path>,
    ) -> Result<Self, HttpGatewayBuildError> {
        let authorization = token_file.map(load_authorization).transpose()?;
        Self::build_with_authorization(timeout, authorization)
    }

    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        Self::build(timeout, None).expect("building an unauthenticated reqwest client")
    }

    pub(crate) fn with_request_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Self, HttpGatewayBuildError> {
        Self::build_with_authorization(timeout, self.authorization.clone())
    }

    fn build_with_authorization(
        timeout: Duration,
        authorization: Option<HeaderValue>,
    ) -> Result<Self, HttpGatewayBuildError> {
        let mut default_headers = HeaderMap::new();
        if let Some(value) = authorization.clone() {
            default_headers.insert(header::AUTHORIZATION, value);
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .default_headers(default_headers)
            .build()
            .map_err(HttpGatewayBuildError::Client)?;
        Ok(Self {
            client,
            authorization,
        })
    }

    #[cfg(test)]
    fn authorization_header(&self) -> Option<&HeaderValue> {
        self.authorization.as_ref()
    }

    pub async fn get_json(&self, url: &str) -> Result<Value, HttpError> {
        let response = self
            .client
            .get(url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await?;
        Self::json_response(response).await
    }

    pub async fn get_json_with_headers(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<Value, HttpError> {
        let mut request = self
            .client
            .get(url)
            .header(header::ACCEPT, "application/json");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        Self::json_response(request.send().await?).await
    }

    pub async fn post_json(&self, url: &str, body: &Value) -> Result<Value, HttpError> {
        let response = self
            .client
            .post(url)
            .header(header::ACCEPT, "application/json")
            .json(body)
            .send()
            .await?;
        Self::json_response(response).await
    }

    pub async fn post_json_with_headers(
        &self,
        url: &str,
        body: &Value,
        headers: &[(&str, &str)],
    ) -> Result<Value, HttpError> {
        let mut request = self.client.post(url).json(body);
        let has_accept = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("accept"));
        if !has_accept {
            request = request.header(header::ACCEPT, "application/json");
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await?;
        Self::json_response(response).await
    }

    async fn json_response(response: reqwest::Response) -> Result<Value, HttpError> {
        let status = response.status();
        if status.is_success() {
            return response.json::<Value>().await.map_err(Into::into);
        }

        let body = response.text().await.unwrap_or_default();
        Err(HttpError::Status { status, body })
    }
}

fn load_authorization(path: &Path) -> Result<HeaderValue, HttpGatewayBuildError> {
    let raw = std::fs::read_to_string(path).map_err(|source| HttpGatewayBuildError::ReadToken {
        path: path.to_path_buf(),
        source,
    })?;
    let token = raw.trim();
    if token.is_empty() {
        return Err(HttpGatewayBuildError::EmptyToken {
            path: path.to_path_buf(),
        });
    }
    if token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(HttpGatewayBuildError::InvalidToken {
            path: path.to_path_buf(),
        });
    }
    let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
        HttpGatewayBuildError::InvalidToken {
            path: path.to_path_buf(),
        }
    })?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::extract::Json;
    use axum::http::{HeaderMap, header};
    use axum::routing::get;
    use serde_json::json;
    use tokio::sync::oneshot;

    struct AcceptFixture {
        url: String,
        shutdown: Option<oneshot::Sender<()>>,
    }

    impl Drop for AcceptFixture {
        fn drop(&mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
    }

    async fn accept_echo(headers: HeaderMap) -> Json<Value> {
        let accept = headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        Json(json!({ "accept": accept }))
    }

    async fn spawn_accept_fixture() -> AcceptFixture {
        let app = Router::new().route("/accept", get(accept_echo).post(accept_echo));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        AcceptFixture {
            url: format!("http://{addr}/accept"),
            shutdown: Some(shutdown_tx),
        }
    }

    #[tokio::test]
    async fn get_json_requests_json_response() {
        let fixture = spawn_accept_fixture().await;
        let gateway = HttpGateway::default();

        let response = gateway.get_json(&fixture.url).await.unwrap();

        assert_eq!(response["accept"], "application/json");
    }

    #[tokio::test]
    async fn post_json_requests_json_response() {
        let fixture = spawn_accept_fixture().await;
        let gateway = HttpGateway::default();

        let response = gateway.post_json(&fixture.url, &json!({})).await.unwrap();

        assert_eq!(response["accept"], "application/json");
    }

    #[tokio::test]
    async fn post_json_with_headers_defaults_to_json_accept() {
        let fixture = spawn_accept_fixture().await;
        let gateway = HttpGateway::default();

        let response = gateway
            .post_json_with_headers(&fixture.url, &json!({}), &[("X-Test", "yes")])
            .await
            .unwrap();

        assert_eq!(response["accept"], "application/json");
    }

    #[tokio::test]
    async fn post_json_with_headers_preserves_explicit_accept() {
        let fixture = spawn_accept_fixture().await;
        let gateway = HttpGateway::default();

        let response = gateway
            .post_json_with_headers(
                &fixture.url,
                &json!({}),
                &[("Accept", "application/json, text/event-stream")],
            )
            .await
            .unwrap();

        assert_eq!(response["accept"], "application/json, text/event-stream");
    }

    #[tokio::test]
    async fn token_file_configures_one_sensitive_bearer_header_for_get_and_post() {
        async fn auth_echo(headers: HeaderMap) -> Json<Value> {
            Json(json!({
                "authorization": headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
            }))
        }

        let app = Router::new().route("/auth", get(auth_echo).post(auth_echo));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("gateway.token");
        std::fs::write(&token_file, "  studio-secret\n").unwrap();
        let gateway = HttpGateway::build(Duration::from_secs(1), Some(&token_file)).unwrap();
        let url = format!("http://{addr}/auth");

        assert_eq!(
            gateway.get_json(&url).await.unwrap()["authorization"],
            "Bearer studio-secret"
        );
        assert_eq!(
            gateway.post_json(&url, &json!({})).await.unwrap()["authorization"],
            "Bearer studio-secret"
        );
        assert!(gateway.authorization_header().unwrap().is_sensitive());
    }

    #[test]
    fn token_file_rejects_missing_empty_and_invalid_values_without_echoing_secret() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.token");
        assert!(HttpGateway::build(Duration::from_secs(1), Some(&missing)).is_err());

        let empty = dir.path().join("empty.token");
        std::fs::write(&empty, " \n\t").unwrap();
        assert!(HttpGateway::build(Duration::from_secs(1), Some(&empty)).is_err());

        let invalid = dir.path().join("invalid.token");
        std::fs::write(&invalid, "secret\0suffix").unwrap();
        let error = HttpGateway::build(Duration::from_secs(1), Some(&invalid))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret"));
    }
}

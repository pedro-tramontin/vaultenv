//! Vault HTTP client wrapper.
//!
//! Handles connection setup, request building, authentication dispatch,
//! mount info discovery, and concurrent secret fetching.

use std::{collections::HashMap, sync::Arc, time::Duration};

use backon::{ExponentialBuilder, Retryable};
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use tokio::sync::Semaphore;
use tracing::{debug, trace};

use crate::auth::AuthMethod;
use crate::secrets_file::Secret;

use super::{
    data::{ClientToken, MountInfo, VaultData},
    error::{VaultError, is_retryable},
};

/// Vault API client.
#[derive(Debug, Clone)]
pub struct VaultClient {
    client: Client,
    base_url: Url,
    token: Option<String>,
    retry_builder: ExponentialBuilder,
}

impl VaultClient {
    /// Create a new Vault client.
    pub fn new(
        host: &str,
        port: u16,
        tls: bool,
        token: Option<String>,
        retry_base_delay_ms: u64,
        retry_attempts: u32,
    ) -> Result<Self, VaultError> {
        let scheme = if tls { "https" } else { "http" };
        let base_url = Url::parse(&format!("{scheme}://{host}:{port}"))
            .map_err(|e| VaultError::InvalidUrl(e.to_string()))?;

        let retry_builder = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(retry_base_delay_ms))
            .with_max_times(retry_attempts as usize)
            .with_jitter();

        Ok(VaultClient {
            client: Client::new(),
            base_url,
            token,
            retry_builder,
        })
    }

    // ── internal helpers ──────────────────────────────────────────────

    fn request_builder(&self, method: reqwest::Method, path: &str, auth: bool) -> RequestBuilder {
        let url = self.base_url.join(path).expect("valid vault path segment");
        let mut req = self.client.request(method, url);
        req = req.header("x-vault-request", "true");
        if auth {
            if let Some(ref token) = self.token {
                req = req.header("x-vault-token", token);
            }
        }
        req
    }

    async fn do_json_request<T: for<'de> serde::Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, VaultError> {
        let mut req = self.request_builder(method.clone(), path, true);
        if let Some(body) = body {
            req = req.json(&body);
        }

        trace!(path, method = %method, "sending authenticated request");
        let resp = req.send().await.map_err(VaultError::ServerUnreachable)?;
        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "(unreadable body)".to_string());

        debug!(path, status = status.as_u16(), "received response");
        match status {
            StatusCode::OK => {
                serde_json::from_str::<T>(&body_text).map_err(|e| VaultError::BadJson {
                    body: body_text,
                    msg: e.to_string(),
                })
            }
            StatusCode::BAD_REQUEST => Err(VaultError::BadRequest(body_text)),
            StatusCode::FORBIDDEN => Err(VaultError::Forbidden),
            StatusCode::NOT_FOUND => Err(VaultError::SecretNotFound(path.to_string())),
            StatusCode::INTERNAL_SERVER_ERROR => Err(VaultError::ServerError(body_text)),
            StatusCode::SERVICE_UNAVAILABLE => Err(VaultError::ServerUnavailable(body_text)),
            _ => Err(VaultError::Unspecified {
                status: status.as_u16(),
                body: body_text,
            }),
        }
    }

    // ── authentication ──────────────────────────────────────────────────

    /// Authenticate and return a new client with the resolved token.
    pub async fn authenticate(
        &self,
        auth_method: &AuthMethod,
        backend: Option<&str>,
    ) -> Result<Self, VaultError> {
        match auth_method {
            AuthMethod::VaultToken { token } => {
                debug!("using direct token authentication");
                Ok(self.with_token(token.clone()))
            }
            AuthMethod::None => {
                debug!("no authentication method set");
                Ok(self.clone())
            }
            other => {
                let (path, body) = self.build_auth_payload(other, backend).await?;
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
            }
        }
    }

    /// Build the request path and JSON body for a given authentication method.
    async fn build_auth_payload(
        &self,
        auth_method: &AuthMethod,
        backend: Option<&str>,
    ) -> Result<(String, serde_json::Value), VaultError> {
        match auth_method {
            AuthMethod::VaultToken { .. } | AuthMethod::None => {
                unreachable!("direct token / none are handled before this call")
            }
            AuthMethod::GitHub(github_token) => {
                let backend = backend.unwrap_or("github");
                let body = serde_json::json!({ "token": github_token });
                let path = format!("/v1/auth/{backend}/login");
                Ok((path, body))
            }
            AuthMethod::Kubernetes { role } => {
                let backend = backend.unwrap_or("kubernetes");
                let jwt = read_kubernetes_jwt().await?;
                let body = serde_json::json!({ "jwt": jwt, "role": role });
                let path = format!("/v1/auth/{backend}/login");
                Ok((path, body))
            }
            AuthMethod::AppRole { role_id, secret_id } => {
                let backend = backend.unwrap_or("approle");
                let body = serde_json::json!({ "role_id": role_id, "secret_id": secret_id });
                let path = format!("/v1/auth/{backend}/login");
                Ok((path, body))
            }
            AuthMethod::Ldap { username, password } => {
                let backend = backend.unwrap_or("ldap");
                let body = serde_json::json!({ "password": password });
                let path = format!("/v1/auth/{backend}/login/{username}");
                Ok((path, body))
            }
            AuthMethod::Okta { username, password } => {
                let backend = backend.unwrap_or("okta");
                let body = serde_json::json!({ "password": password });
                let path = format!("/v1/auth/{backend}/login/{username}");
                Ok((path, body))
            }
            AuthMethod::Azure { role, resource } => {
                let backend = backend.unwrap_or("azure");
                let resource = resource
                    .as_deref()
                    .unwrap_or("https://management.azure.com/");
                let jwt = crate::cloud_metadata::get_azure_jwt(resource)
                    .await
                    .map_err(|e| VaultError::CloudMetadataFailed(e.to_string()))?;
                let metadata = crate::cloud_metadata::get_azure_vm_metadata()
                    .await
                    .map_err(|e| VaultError::CloudMetadataFailed(e.to_string()))?;
                let body = serde_json::json!({
                    "role": role,
                    "jwt": jwt,
                    "vm_name": metadata.name,
                    "vmss_name": metadata.vm_scale_set_name,
                    "subscription_id": metadata.subscription_id,
                    "resource_group_name": metadata.resource_group_name,
                });
                let path = format!("/v1/auth/{backend}/login");
                Ok((path, body))
            }
            AuthMethod::Gcp { role } => {
                let backend = backend.unwrap_or("gcp");
                let vault_addr = self.base_url.to_string().trim_end_matches('/').to_string();
                let audience = format!("{vault_addr}/vault/{role}");
                let jwt = crate::cloud_metadata::get_gce_jwt(&audience)
                    .await
                    .map_err(|e| VaultError::CloudMetadataFailed(e.to_string()))?;
                let body = serde_json::json!({ "role": role, "jwt": jwt });
                let path = format!("/v1/auth/{backend}/login");
                Ok((path, body))
            }
            AuthMethod::AwsEc2 {
                role,
                signature_type,
            } => {
                let backend = backend.unwrap_or("aws");
                let metadata = crate::cloud_metadata::get_ec2_metadata(*signature_type)
                    .await
                    .map_err(|e| VaultError::CloudMetadataFailed(e.to_string()))?;
                let mut body = serde_json::Map::new();
                body.insert("role".to_string(), serde_json::Value::String(role.clone()));
                for (k, v) in metadata {
                    body.insert(k, serde_json::Value::String(v));
                }
                let nonce = uuid::Uuid::new_v4().to_string();
                body.insert("nonce".to_string(), serde_json::Value::String(nonce));
                let body = serde_json::Value::Object(body);
                let path = format!("/v1/auth/{backend}/login");
                Ok((path, body))
            }
            AuthMethod::Jwt { role, token } => {
                let backend = backend.unwrap_or("jwt");
                let body = serde_json::json!({ "role": role, "jwt": token });
                let path = format!("/v1/auth/{backend}/login");
                Ok((path, body))
            }
        }
    }

    /// Perform a login POST with retry wrapper (unauthenticated).
    async fn do_unauthed_login_with_retry(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<String, VaultError> {
        let client = self.clone();
        let p = path.to_string();
        let resp: ClientToken = (|| async {
            client
                .do_unauthenticated_json_request::<ClientToken>(
                    reqwest::Method::POST,
                    &p,
                    Some(body.clone()),
                )
                .await
        })
        .retry(self.retry_builder)
        .when(is_retryable)
        .await?;
        Ok(resp.auth.client_token)
    }

    /// Return the current Vault token, if any.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Return a new client configured with the given token.
    pub fn with_token(&self, token: String) -> Self {
        VaultClient {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            token: Some(token),
            retry_builder: self.retry_builder,
        }
    }

    /// Return a new client pointing at a different host (port and tls preserved).
    pub fn with_host(&self, host: &str) -> Result<Self, VaultError> {
        let scheme = self.base_url.scheme();
        let port = self.base_url.port_or_known_default().unwrap_or(8200);
        let base_url = Url::parse(&format!("{scheme}://{host}:{port}"))
            .map_err(|e| VaultError::InvalidUrl(e.to_string()))?;
        Ok(VaultClient {
            client: self.client.clone(),
            base_url,
            token: self.token.clone(),
            retry_builder: self.retry_builder,
        })
    }

    /// Return a new client pointing at a different port (host and tls preserved).
    pub fn with_port(&self, port: u16) -> Result<Self, VaultError> {
        let scheme = self.base_url.scheme();
        let host = self.base_url.host_str().unwrap_or("localhost").to_string();
        let base_url = Url::parse(&format!("{scheme}://{host}:{port}"))
            .map_err(|e| VaultError::InvalidUrl(e.to_string()))?;
        Ok(VaultClient {
            client: self.client.clone(),
            base_url,
            token: self.token.clone(),
            retry_builder: self.retry_builder,
        })
    }

    /// Return a new client with TLS toggled (host and port preserved).
    pub fn with_tls(&self, tls: bool) -> Result<Self, VaultError> {
        let scheme = if tls { "https" } else { "http" };
        let host = self.base_url.host_str().unwrap_or("localhost").to_string();
        let port = self.base_url.port_or_known_default().unwrap_or(8200);
        let base_url = Url::parse(&format!("{scheme}://{host}:{port}"))
            .map_err(|e| VaultError::InvalidUrl(e.to_string()))?;
        Ok(VaultClient {
            client: self.client.clone(),
            base_url,
            token: self.token.clone(),
            retry_builder: self.retry_builder,
        })
    }

    /// Return a new client with updated retry base delay.
    pub fn with_retry_base_delay(&self, ms: u64) -> Self {
        VaultClient {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            token: self.token.clone(),
            retry_builder: self.retry_builder.with_min_delay(Duration::from_millis(ms)),
        }
    }

    /// Return a new client with updated retry max attempts.
    pub fn with_retry_attempts(&self, attempts: u32) -> Self {
        VaultClient {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            token: self.token.clone(),
            retry_builder: self.retry_builder.with_max_times(attempts as usize),
        }
    }

    async fn do_unauthenticated_json_request<T: for<'de> serde::Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, VaultError> {
        let mut req = self.request_builder(method, path, false);
        if let Some(body) = body {
            req = req.json(&body);
        }

        let resp = req.send().await.map_err(VaultError::ServerUnreachable)?;
        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "(unreadable body)".to_string());

        match status {
            StatusCode::OK => {
                serde_json::from_str::<T>(&body_text).map_err(|e| VaultError::BadJson {
                    body: body_text,
                    msg: e.to_string(),
                })
            }
            _ => Err(VaultError::ServerError(body_text)),
        }
    }

    // ── mount info ──────────────────────────────────────────────────────

    /// Discover the mount information from Vault's `/v1/sys/mounts` endpoint.
    pub async fn get_mount_info(&self) -> Result<MountInfo, VaultError> {
        let client = self.clone();
        let path = "/v1/sys/mounts".to_string();
        (|| async {
            client
                .do_json_request::<MountInfo>(reqwest::Method::GET, &path, None)
                .await
        })
        .retry(self.retry_builder)
        .when(is_retryable)
        .await
    }

    // ── secret fetching ─────────────────────────────────────────────────

    /// Fetch a single secret from Vault.
    pub async fn get_secret(
        &self,
        mount_info: &MountInfo,
        secret: &Secret,
    ) -> Result<VaultData, VaultError> {
        let path = mount_info.secret_path(secret);
        trace!(path, "fetching single secret");
        let client = self.clone();
        (|| async {
            client
                .do_json_request::<VaultData>(reqwest::Method::GET, &path, None)
                .await
        })
        .retry(self.retry_builder)
        .when(is_retryable)
        .await
    }

    /// Fetch multiple secrets concurrently, respecting a semaphore limit.
    pub async fn get_secrets(
        &self,
        mount_info: &MountInfo,
        secrets: &[Secret],
        max_concurrent: usize,
    ) -> Result<HashMap<String, VaultData>, VaultError> {
        let sem = Arc::new(Semaphore::new(if max_concurrent == 0 {
            usize::MAX
        } else {
            max_concurrent
        }));
        let limit = if max_concurrent == 0 {
            "unlimited".to_string()
        } else {
            max_concurrent.to_string()
        };
        debug!(count = secrets.len(), concurrency_limit = %limit, "fetching secrets concurrently");

        let mut tasks = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let path = mount_info.secret_path(secret);
            let permit = Arc::clone(&sem).acquire_owned().await.ok();
            let client = self.clone();
            let p = path.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                trace!(path = %p, "acquired permit, fetching");
                let data = client.get_secret_by_path(&p).await?;
                trace!(path = %p, "secret fetched");
                Ok::<_, VaultError>((p, data))
            }));
        }

        let mut results = HashMap::with_capacity(tasks.len());
        for task in tasks {
            let (path, data) = task
                .await
                .map_err(|e| VaultError::ServerError(format!("concurrent task panicked: {e}")))??;
            results.insert(path, data);
        }

        debug!(count = results.len(), "all secrets fetched");
        Ok(results)
    }

    /// Fetch a secret by its raw Vault API path (used internally by `get_secrets`).
    async fn get_secret_by_path(&self, path: &str) -> Result<VaultData, VaultError> {
        let client = self.clone();
        let p = path.to_string();
        (|| async {
            client
                .do_json_request::<VaultData>(reqwest::Method::GET, &p, None)
                .await
        })
        .retry(self.retry_builder)
        .when(is_retryable)
        .await
    }
}

/// Read the Kubernetes service account JWT from the well-known path.
async fn read_kubernetes_jwt() -> Result<String, VaultError> {
    let path = std::env::var("VAULTENV_KUBERNETES_JWT_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
        });
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(VaultError::KubernetesJwtFailed)?;
    String::from_utf8(bytes).map_err(|_| VaultError::KubernetesJwtInvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_new_parses_base_url() {
        let client = VaultClient::new("localhost", 8200, false, None, 40, 9).unwrap();
        assert_eq!(client.base_url.as_str(), "http://localhost:8200/");
        assert!(client.token().is_none());
    }

    #[test]
    fn test_client_with_token() {
        let client = VaultClient::new("localhost", 8200, false, None, 40, 9).unwrap();
        let client2 = client.with_token("s.abc123".to_string());
        assert_eq!(client2.token(), Some("s.abc123"));
    }

    #[test]
    fn test_client_with_host() {
        let client = VaultClient::new("old.example.com", 8200, false, None, 40, 9).unwrap();
        let client2 = client.with_host("vault.example.com").unwrap();
        assert_eq!(client2.base_url.as_str(), "http://vault.example.com:8200/");
        assert_eq!(client2.token(), client.token());
    }

    #[test]
    fn test_client_with_port() {
        let client = VaultClient::new("localhost", 8200, false, None, 40, 9).unwrap();
        let client2 = client.with_port(8300).unwrap();
        assert_eq!(client2.base_url.as_str(), "http://localhost:8300/");
    }

    #[test]
    fn test_client_with_tls_toggle() {
        let client = VaultClient::new("vault.example.com", 8200, false, None, 40, 9).unwrap();
        let https = client.with_tls(true).unwrap();
        assert_eq!(https.base_url.as_str(), "https://vault.example.com:8200/");
        let http = https.with_tls(false).unwrap();
        assert_eq!(http.base_url.as_str(), "http://vault.example.com:8200/");
    }

    #[test]
    fn test_client_with_retry_base_delay() {
        let client = VaultClient::new("localhost", 8200, false, None, 40, 9).unwrap();
        let client2 = client.with_retry_base_delay(100);
        // retry_builder internals are opaque; just assert structural equality
        assert_eq!(client2.base_url, client.base_url);
        assert_eq!(client2.token, client.token);
    }

    #[test]
    fn test_client_with_retry_attempts() {
        let client = VaultClient::new("localhost", 8200, false, None, 40, 9).unwrap();
        let client2 = client.with_retry_attempts(3);
        assert_eq!(client2.base_url, client.base_url);
        assert_eq!(client2.token, client.token);
    }

    #[test]
    fn test_builder_chain_preserves_token() {
        let client = VaultClient::new("localhost", 8200, false, Some("tok".into()), 40, 9).unwrap();
        let client2 = client.with_host("other").unwrap().with_port(8300).unwrap();
        assert_eq!(client2.token(), Some("tok"));
        assert_eq!(client2.base_url.as_str(), "http://other:8300/");
    }
}

//! Vault HTTP client wrapper.
//!
//! Handles connection setup, request building, authentication dispatch,
//! mount info discovery, and concurrent secret fetching.

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

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
            AuthMethod::GitHub(github_token) => {
                let backend = backend.unwrap_or("github");
                let body = serde_json::json!({ "token": github_token });
                let path = format!("/v1/auth/{backend}/login");
                debug!(backend, path, "authenticating via GitHub");
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
            }
            AuthMethod::Kubernetes { role } => {
                let backend = backend.unwrap_or("kubernetes");
                let jwt = read_kubernetes_jwt().await?;
                let body = serde_json::json!({ "jwt": jwt, "role": role });
                let path = format!("/v1/auth/{backend}/login");
                debug!(backend, path, "authenticating via Kubernetes");
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
            }
            AuthMethod::AppRole { role_id, secret_id } => {
                let backend = backend.unwrap_or("approle");
                let body = serde_json::json!({ "role_id": role_id, "secret_id": secret_id });
                let path = format!("/v1/auth/{backend}/login");
                debug!(backend, path, "authenticating via AppRole");
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
            }
            AuthMethod::Ldap { username, password } => {
                let backend = backend.unwrap_or("ldap");
                let body = serde_json::json!({ "password": password });
                let path = format!("/v1/auth/{backend}/login/{username}");
                debug!(backend, path, %username, "authenticating via LDAP");
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
            }
            AuthMethod::Okta { username, password } => {
                let backend = backend.unwrap_or("okta");
                let body = serde_json::json!({ "password": password });
                let path = format!("/v1/auth/{backend}/login/{username}");
                debug!(backend, path, %username, "authenticating via Okta");
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
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
                debug!(backend, path, "authenticating via Azure MSI");
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
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
                debug!(backend, path, "authenticating via GCP GCE");
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
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
                debug!(backend, path, "authenticating via AWS EC2");
                let token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(token))
            }
            AuthMethod::Jwt { role, token } => {
                let backend = backend.unwrap_or("jwt");
                let body = serde_json::json!({ "role": role, "jwt": token });
                let path = format!("/v1/auth/{backend}/login");
                debug!(backend, path, "authenticating via JWT");
                let client_token = self.do_unauthed_login_with_retry(&path, body).await?;
                Ok(self.with_token(client_token))
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
    let path = Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token");
    let bytes = tokio::fs::read(path)
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
}

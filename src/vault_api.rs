//! Vault HTTP API client.
//!
//! Handles authentication, mount info discovery, secret fetching,
//! response parsing, and retry logic.

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use backon::{ExponentialBuilder, Retryable};
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::{config::AuthMethod, secrets_file::Secret};

/// Vault KV engine type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum EngineType {
    #[serde(rename = "1")]
    V1,
    #[serde(rename = "2")]
    V2,
}

/// KV mount options used when parsing /sys/mounts.
#[derive(Debug, Deserialize)]
struct MountOptions {
    version: String,
}

/// KV mount spec used when parsing /sys/mounts.
#[derive(Debug, Deserialize)]
struct MountSpec {
    #[serde(rename = "type")]
    mount_type: String,
    options: MountOptions,
}

/// Parsed Vault secret data.
#[derive(Debug, Clone)]
pub struct VaultData(pub HashMap<String, serde_json::Value>);

impl<'de> Deserialize<'de> for VaultData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut obj = HashMap::<String, serde_json::Value>::deserialize(deserializer)?;

        if let Some(serde_json::Value::Object(inner)) = obj.remove("data") {
            if let Some(serde_json::Value::Object(data)) = inner.get("data") {
                let map: HashMap<String, serde_json::Value> = data.clone().into_iter().collect();
                return Ok(VaultData(map));
            }
            let map: HashMap<String, serde_json::Value> = inner.into_iter().collect();
            return Ok(VaultData(map));
        }
        Err(serde::de::Error::custom(
            "missing 'data' field in Vault response",
        ))
    }
}

/// Vault client token returned by auth backends.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientToken {
    pub auth: AuthPayload,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthPayload {
    #[serde(rename = "client_token")]
    pub client_token: String,
}

/// Errors that can occur during Vault interaction.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("key not found for secret {path:?}")]
    KeyNotFound { path: String },
    #[error("key is not a string for secret {path:?}")]
    WrongType { path: String },
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("forbidden: the provided token is invalid or expired")]
    Forbidden,
    #[error("received bad JSON from Vault: {msg}. Response was: {body}")]
    BadJson { body: String, msg: String },
    #[error("internal Vault error: {0}")]
    ServerError(String),
    #[error("Vault is unavailable: {0}")]
    ServerUnavailable(String),
    #[error("server unreachable: {0}")]
    ServerUnreachable(#[source] reqwest::Error),
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("duplicate environment variable: {0}")]
    DuplicateVar(String),
    #[error("unknown error (status {status}): {body}")]
    Unspecified { status: u16, body: String },
    #[error("failed to read Kubernetes JWT: {0}")]
    KubernetesJwtFailed(#[source] std::io::Error),
    #[error("Kubernetes JWT is not valid UTF-8")]
    KubernetesJwtInvalidUtf8,
    #[error("cloud metadata fetch failed: {0}")]
    CloudMetadataFailed(String),
}

/// Retryable Vault errors (should trigger a retry attempt).
fn is_retryable(err: &VaultError) -> bool {
    matches!(
        err,
        VaultError::ServerError(_)
            | VaultError::ServerUnavailable(_)
            | VaultError::ServerUnreachable(_)
            | VaultError::Unspecified { .. }
            | VaultError::BadJson { .. }
    )
}

/// Mount info: maps mount path (e.g. "secret/") to engine version.
#[derive(Debug, Clone)]
pub struct MountInfo {
    mounts: HashMap<String, EngineType>,
}

impl MountInfo {
    /// Create mount info from an explicit map.
    pub fn from_map(mounts: HashMap<String, EngineType>) -> Self {
        MountInfo { mounts }
    }

    /// Return the engine type for a given mount, defaulting to KV1.
    fn engine_type(&self, mount: &str) -> EngineType {
        let key = format!("{mount}/");
        self.mounts.get(&key).copied().unwrap_or(EngineType::V1)
    }

    /// Build the Vault API path for a secret given mount info.
    pub fn secret_path(&self, secret: &Secret) -> String {
        match self.engine_type(&secret.mount) {
            EngineType::V1 => format!("/v1/{}/{}", secret.mount, secret.path),
            EngineType::V2 => format!("/v1/{}/data/{}", secret.mount, secret.path),
        }
    }
}

impl<'de> Deserialize<'de> for MountInfo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = HashMap::<String, serde_json::Value>::deserialize(deserializer)?;
        let mounts = raw
            .into_iter()
            .filter_map(|(key, val)| {
                let spec = serde_json::from_value::<MountSpec>(val).ok()?;
                if spec.mount_type != "kv" {
                    return None;
                }
                let engine = match spec.options.version.as_str() {
                    "1" => EngineType::V1,
                    "2" => EngineType::V2,
                    _ => return None,
                };
                Some((key, engine))
            })
            .collect();
        Ok(MountInfo { mounts })
    }
}

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
    ///
    /// * `host`: e.g. `"localhost"` or `"vault.example.com"`
    /// * `port`: e.g. `8200`
    /// * `tls`: `true` for HTTPS, `false` for plain HTTP
    /// * `token`: initial Vault token (may be `None` before auth)
    /// * `retry_base_delay_ms`: base retry delay in milliseconds
    /// * `retry_attempts`: max number of retry attempts
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
        let mut req = self.request_builder(method, path, true);
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
    ///
    /// If the auth method is `VaultToken` or `None`, returns a clone of self.
    pub async fn authenticate(
        &self,
        auth_method: &AuthMethod,
        backend: Option<&str>,
    ) -> Result<Self, VaultError> {
        match auth_method {
            AuthMethod::VaultToken { token } => Ok(self.with_token(token.clone())),
            AuthMethod::None => Ok(self.clone()),
            AuthMethod::GitHub(github_token) => {
                let backend = backend.unwrap_or("github");
                let body = serde_json::json!({ "token": github_token });
                let path = format!("/v1/auth/{backend}/login");
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
            }
            AuthMethod::Kubernetes { role } => {
                let backend = backend.unwrap_or("kubernetes");
                let jwt = read_kubernetes_jwt().await?;
                let body = serde_json::json!({ "jwt": jwt, "role": role });
                let path = format!("/v1/auth/{backend}/login");
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
            }
            AuthMethod::AppRole { role_id, secret_id } => {
                let backend = backend.unwrap_or("approle");
                let body = serde_json::json!({ "role_id": role_id, "secret_id": secret_id });
                let path = format!("/v1/auth/{backend}/login");
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
            }
            AuthMethod::Ldap { username, password } => {
                let backend = backend.unwrap_or("ldap");
                let body = serde_json::json!({ "password": password });
                let path = format!("/v1/auth/{backend}/login/{username}");
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
            }
            AuthMethod::Okta { username, password } => {
                let backend = backend.unwrap_or("okta");
                let body = serde_json::json!({ "password": password });
                let path = format!("/v1/auth/{backend}/login/{username}");
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
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
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
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
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
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
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
            }
            AuthMethod::Jwt { role, token } => {
                let backend = backend.unwrap_or("jwt");
                let body = serde_json::json!({ "role": role, "jwt": token });
                let path = format!("/v1/auth/{backend}/login");
                let client = self.clone();
                let resp: ClientToken = (|| async {
                    client
                        .do_unauthenticated_json_request::<ClientToken>(
                            reqwest::Method::POST,
                            &path,
                            Some(body.clone()),
                        )
                        .await
                })
                .retry(self.retry_builder)
                .when(is_retryable)
                .await?;
                Ok(self.with_token(resp.auth.client_token))
            }
        }
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
    ///
    /// Returns a map from the Vault request path to the fetched `VaultData`.
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

        let mut tasks = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let path = mount_info.secret_path(secret);
            let permit = Arc::clone(&sem).acquire_owned().await.ok();
            let client = self.clone();
            let p = path.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let data = client.get_secret_by_path(&p).await?;
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

/// Resolve secrets from fetched Vault data.
///
/// Takes the original `Secret` specs and the fetched `VaultData` map, and
/// returns a list of `(var_name, value)` environment variable pairs.
///
/// Errors if a key is missing or has a non-string value.
pub fn resolve_secrets(
    mount_info: &MountInfo,
    secrets: &[Secret],
    vault_data: &HashMap<String, VaultData>,
) -> Result<Vec<(String, String)>, VaultError> {
    let mut env_vars = Vec::with_capacity(secrets.len());

    for secret in secrets {
        let path = mount_info.secret_path(secret);
        let data = vault_data
            .get(&path)
            .ok_or_else(|| VaultError::SecretNotFound(path.clone()))?;

        let value = data
            .0
            .get(&secret.key)
            .ok_or_else(|| VaultError::KeyNotFound { path: path.clone() })?;

        let string_value = value
            .as_str()
            .ok_or_else(|| VaultError::WrongType { path: path.clone() })?
            .to_string();

        env_vars.push((secret.var_name.clone(), string_value));
    }

    Ok(env_vars)
}

/// Deduplicate environment variables according to the requested behavior.
pub fn deduplicate(
    vars: Vec<(String, String)>,
    behavior: crate::config::DuplicateBehavior,
) -> Result<Vec<(String, String)>, VaultError> {
    match behavior {
        crate::config::DuplicateBehavior::Error => {
            let mut seen = std::collections::HashSet::new();
            for (name, _) in &vars {
                if !seen.insert(name) {
                    return Err(VaultError::DuplicateVar(name.clone()));
                }
            }
            Ok(vars)
        }
        crate::config::DuplicateBehavior::Keep => {
            let mut result = HashMap::new();
            for (name, value) in vars {
                result.entry(name).or_insert(value);
            }
            Ok(result.into_iter().collect())
        }
        crate::config::DuplicateBehavior::Overwrite => {
            let mut result = HashMap::new();
            for (name, value) in vars {
                result.insert(name, value);
            }
            Ok(result.into_iter().collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets_file::Secret;

    #[test]
    fn test_vault_data_v2_parsing() {
        let json = serde_json::json!({
            "data": {
                "data": {
                    "foo": "bar"
                },
                "metadata": {
                    "version": 1
                }
            }
        });
        let data: VaultData = serde_json::from_value(json).unwrap();
        assert_eq!(data.0.get("foo").unwrap().as_str().unwrap(), "bar");
    }

    #[test]
    fn test_vault_data_v1_parsing() {
        let json = serde_json::json!({
            "data": {
                "foo": "bar"
            }
        });
        let data: VaultData = serde_json::from_value(json).unwrap();
        assert_eq!(data.0.get("foo").unwrap().as_str().unwrap(), "bar");
    }

    #[test]
    fn test_secret_path_v1() {
        let mi = MountInfo {
            mounts: [("secret/".to_string(), EngineType::V1)]
                .into_iter()
                .collect(),
        };
        let s = Secret {
            mount: "secret".to_string(),
            path: "foo/bar".to_string(),
            key: "baz".to_string(),
            var_name: "FOO".to_string(),
        };
        assert_eq!(mi.secret_path(&s), "/v1/secret/foo/bar");
    }

    #[test]
    fn test_secret_path_v2() {
        let mi = MountInfo {
            mounts: [("secret/".to_string(), EngineType::V2)]
                .into_iter()
                .collect(),
        };
        let s = Secret {
            mount: "secret".to_string(),
            path: "foo/bar".to_string(),
            key: "baz".to_string(),
            var_name: "FOO".to_string(),
        };
        assert_eq!(mi.secret_path(&s), "/v1/secret/data/foo/bar");
    }

    #[test]
    fn test_resolve_secrets_ok() {
        let mi = MountInfo {
            mounts: HashMap::new(),
        };
        let secrets = vec![Secret {
            mount: "secret".to_string(),
            path: "foo".to_string(),
            key: "bar".to_string(),
            var_name: "MY_VAR".to_string(),
        }];
        let mut vault_data = HashMap::new();
        vault_data.insert(
            "/v1/secret/foo".to_string(),
            VaultData(
                [("bar".to_string(), serde_json::json!("baz"))]
                    .into_iter()
                    .collect(),
            ),
        );

        let resolved = resolve_secrets(&mi, &secrets, &vault_data).unwrap();
        assert_eq!(resolved, vec![("MY_VAR".to_string(), "baz".to_string())]);
    }

    #[test]
    fn test_resolve_secrets_key_not_found() {
        let mi = MountInfo {
            mounts: HashMap::new(),
        };
        let secrets = vec![Secret {
            mount: "secret".to_string(),
            path: "foo".to_string(),
            key: "missing".to_string(),
            var_name: "MY_VAR".to_string(),
        }];
        let mut vault_data = HashMap::new();
        vault_data.insert(
            "/v1/secret/foo".to_string(),
            VaultData(
                [("bar".to_string(), serde_json::json!("baz"))]
                    .into_iter()
                    .collect(),
            ),
        );

        assert!(matches!(
            resolve_secrets(&mi, &secrets, &vault_data),
            Err(VaultError::KeyNotFound { .. })
        ));
    }

    #[test]
    fn test_resolve_secrets_wrong_type() {
        let mi = MountInfo {
            mounts: HashMap::new(),
        };
        let secrets = vec![Secret {
            mount: "secret".to_string(),
            path: "foo".to_string(),
            key: "num".to_string(),
            var_name: "MY_VAR".to_string(),
        }];
        let mut vault_data = HashMap::new();
        vault_data.insert(
            "/v1/secret/foo".to_string(),
            VaultData(
                [("num".to_string(), serde_json::json!(42))]
                    .into_iter()
                    .collect(),
            ),
        );

        assert!(matches!(
            resolve_secrets(&mi, &secrets, &vault_data),
            Err(VaultError::WrongType { .. })
        ));
    }

    #[test]
    fn test_deduplicate_error() {
        let vars = vec![
            ("FOO".to_string(), "a".to_string()),
            ("FOO".to_string(), "b".to_string()),
        ];
        assert!(matches!(
            deduplicate(vars, crate::config::DuplicateBehavior::Error),
            Err(VaultError::DuplicateVar(name)) if name == "FOO"
        ));
    }

    #[test]
    fn test_deduplicate_overwrite() {
        let vars = vec![
            ("FOO".to_string(), "a".to_string()),
            ("FOO".to_string(), "b".to_string()),
        ];
        let result = deduplicate(vars, crate::config::DuplicateBehavior::Overwrite).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("FOO".to_string(), "b".to_string()));
    }

    #[test]
    fn test_client_token_deserialization() {
        let json = serde_json::json!({
            "auth": {
                "client_token": "s.abc123"
            }
        });
        let token: ClientToken = serde_json::from_value(json).unwrap();
        assert_eq!(token.auth.client_token, "s.abc123");
    }
}

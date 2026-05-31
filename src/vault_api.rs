//! Vault HTTP API client.
//!
//! Handles authentication, mount info discovery, secret fetching,
//! response parsing, and retry logic.

use serde::Deserialize;
use std::collections::HashMap;

/// Vault KV engine type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineType {
    #[serde(rename = "1")]
    V1,
    #[serde(rename = "2")]
    V2,
}

/// Parsed Vault secret data.
#[derive(Debug, Clone)]
pub struct VaultData(pub HashMap<String, serde_json::Value>);

/// Vault client token returned by auth backends.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientToken {
    #[serde(rename = "client_token")]
    pub token: String,
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
    KubernetesJwtFailed(String),
    #[error("Kubernetes JWT is not valid UTF-8")]
    KubernetesJwtInvalidUtf8,
}

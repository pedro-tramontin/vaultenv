//! Vault API error variants.

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
pub fn is_retryable(err: &VaultError) -> bool {
    matches!(
        err,
        VaultError::ServerError(_)
            | VaultError::ServerUnavailable(_)
            | VaultError::ServerUnreachable(_)
            | VaultError::Unspecified { .. }
            | VaultError::BadJson { .. }
    )
}

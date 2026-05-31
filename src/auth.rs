//! Authentication methods for Vault.

use anyhow::Context;

/// Authentication method for Vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication (do not send `X-Vault-Token`).
    None,
    /// Authenticate via GitHub personal access token.
    GitHub(String),
    /// Authenticate via Kubernetes service account.
    Kubernetes { role: String },
    /// Direct Vault token.
    VaultToken { token: String },
    /// Authenticate via AppRole (role_id + secret_id).
    AppRole { role_id: String, secret_id: String },
    /// Authenticate via LDAP (username + password).
    Ldap { username: String, password: String },
    /// Authenticate via Okta (username + password).
    Okta { username: String, password: String },
    /// Authenticate via Azure Managed Service Identity (instance mode).
    Azure {
        role: String,
        resource: Option<String>,
    },
    /// Authenticate via GCP GCE instance metadata.
    Gcp { role: String },
    /// Authenticate via AWS EC2 instance metadata (PKCS7 / identity document).
    AwsEc2 {
        role: String,
        signature_type: crate::cloud_metadata::Ec2SignatureType,
    },
    /// Authenticate via JWT/OIDC pre-exchanged token.
    Jwt { role: String, token: String },
}

/// Resolve the effective authentication token (if JWT is passed via file).
pub fn resolve_jwt_file_token(file: &std::path::Path, role: String) -> anyhow::Result<AuthMethod> {
    let token = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read jwt file: {}", file.display()))?;
    Ok(AuthMethod::Jwt {
        role,
        token: token.trim().to_string(),
    })
}

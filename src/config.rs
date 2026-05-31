//! Configuration parsing and validation.
//!
//! Ports the logic from Haskell's `Config.hs` to Rust.
//! Uses `clap` for CLI argument parsing with `#[command(env)]` support
//! to eliminate the manual env-var-override boilerplate.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use url::Url;

/// Log level for vaultenv output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LogLevel {
    /// Print errors only (default).
    #[default]
    Error,
    /// Print informational messages.
    Info,
}

/// Behavior when duplicate environment variables are detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicateBehavior {
    /// Produce an error (default).
    #[default]
    Error,
    /// Keep the existing variable, ignore the secret.
    Keep,
    /// Overwrite the existing variable with the secret value.
    Overwrite,
}

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

/// All configuration resolved from CLI, environment variables, and defaults.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "vaultenv",
    about = "Run programs with secrets from HashiCorp Vault",
    version
)]
pub struct Options {
    /// Vault host (IP or DNS name).
    #[arg(long, env = "VAULT_HOST", default_value = "localhost")]
    pub host: String,

    /// Vault port.
    #[arg(long, env = "VAULT_PORT", default_value_t = 8200)]
    pub port: u16,

    /// Full Vault address (scheme://host:port); overrides host/port/tls.
    #[arg(long, env = "VAULT_ADDR")]
    pub addr: Option<String>,

    /// Vault authentication backend name.
    #[arg(long, env = "VAULT_AUTH_BACKEND")]
    pub auth_backend: Option<String>,

    /// Direct Vault token.
    #[arg(long, env = "VAULT_TOKEN")]
    pub token: Option<String>,

    /// GitHub personal access token for Vault auth.
    #[arg(long, env = "VAULTENV_GITHUB_TOKEN")]
    pub github_token: Option<String>,

    /// Kubernetes role for Vault auth.
    #[arg(long, env = "VAULTENV_KUBERNETES_ROLE")]
    pub kubernetes_role: Option<String>,

    /// AppRole role ID for Vault auth.
    #[arg(long, env = "VAULTENV_APPROLE_ROLE_ID")]
    pub approle_role_id: Option<String>,

    /// AppRole secret ID for Vault auth.
    #[arg(long, env = "VAULTENV_APPROLE_SECRET_ID")]
    pub approle_secret_id: Option<String>,

    /// LDAP username for Vault auth.
    #[arg(long, env = "VAULTENV_LDAP_USERNAME")]
    pub ldap_username: Option<String>,

    /// LDAP password for Vault auth.
    #[arg(long, env = "VAULTENV_LDAP_PASSWORD")]
    pub ldap_password: Option<String>,

    /// Okta username for Vault auth.
    #[arg(long, env = "VAULTENV_OKTA_USERNAME")]
    pub okta_username: Option<String>,

    /// Okta password for Vault auth.
    #[arg(long, env = "VAULTENV_OKTA_PASSWORD")]
    pub okta_password: Option<String>,

    /// Azure role for Vault auth.
    #[arg(long, env = "VAULTENV_AZURE_ROLE")]
    pub azure_role: Option<String>,

    /// Azure resource URL for MSI (optional).
    #[arg(long, env = "VAULTENV_AZURE_RESOURCE")]
    pub azure_resource: Option<String>,

    /// GCE role for Vault auth.
    #[arg(long, env = "VAULTENV_GCP_GCE_ROLE")]
    pub gcp_gce_role: Option<String>,

    /// AWS EC2 role for Vault auth.
    #[arg(long, env = "VAULTENV_AWS_EC2_ROLE")]
    pub aws_ec2_role: Option<String>,

    /// AWS EC2 signature type (pkcs7, identity, rsa2048).
    #[arg(long, env = "VAULTENV_AWS_EC2_SIGNATURE_TYPE", default_value = "pkcs7")]
    pub aws_ec2_signature_type: crate::cloud_metadata::Ec2SignatureTypeArg,

    /// JWT role for Vault auth.
    #[arg(long, env = "VAULTENV_JWT_ROLE")]
    pub jwt_role: Option<String>,

    /// JWT token for Vault auth (direct value; prefer --jwt-token-file).
    #[arg(long, env = "VAULTENV_JWT_TOKEN")]
    pub jwt_token: Option<String>,

    /// Path to file containing JWT token for Vault auth.
    #[arg(long, env = "VAULTENV_JWT_TOKEN_FILE")]
    pub jwt_token_file: Option<PathBuf>,

    /// Path to the secrets file.
    #[arg(long, env = "VAULTENV_SECRETS_FILE")]
    pub secrets_file: PathBuf,

    /// Command to run after fetching secrets.
    pub cmd: String,

    /// Arguments to pass to CMD.
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,

    /// Use TLS when connecting to Vault.
    #[arg(long, env = "VAULTENV_CONNECT_TLS", default_value_t = true)]
    pub connect_tls: bool,

    /// Validate TLS certificates.
    #[arg(long, env = "VAULTENV_VALIDATE_CERTS", default_value_t = true)]
    pub validate_certs: bool,

    /// Merge the parent environment with fetched secrets.
    #[arg(long, env = "VAULTENV_INHERIT_ENV", default_value_t = true)]
    pub inherit_env: bool,

    /// Comma-separated list of environment variables to remove before executing CMD.
    #[arg(long, env = "VAULTENV_INHERIT_ENV_BLACKLIST", value_delimiter = ',')]
    pub inherit_env_blacklist: Vec<String>,

    /// Base delay for retry backoff (milliseconds).
    #[arg(long, env = "VAULTENV_RETRY_BASE_DELAY", default_value_t = 40)]
    pub retry_base_delay_ms: u64,

    /// Maximum number of retry attempts.
    #[arg(long, env = "VAULTENV_RETRY_ATTEMPTS", default_value_t = 9)]
    pub retry_attempts: u32,

    /// Log level.
    #[arg(long, env = "VAULTENV_LOG_LEVEL", default_value = "error")]
    pub log_level: LogLevelArg,

    /// Use PATH when searching for CMD.
    #[arg(long, env = "VAULTENV_USE_PATH", default_value_t = false)]
    pub use_path: bool,

    /// Maximum concurrent requests to Vault (0 = unlimited).
    #[arg(long, env = "VAULTENV_MAX_CONCURRENT_REQUESTS", default_value_t = 8)]
    pub max_concurrent_requests: usize,

    /// Behavior when duplicate environment variables are detected.
    #[arg(
        long,
        env = "VAULTENV_DUPLICATE_VARIABLE_BEHAVIOR",
        default_value = "error"
    )]
    pub duplicate_behavior: DuplicateBehaviorArg,
}

impl Options {
    /// Resolve `VAULT_ADDR` if present, overriding host/port/connect_tls.
    /// Returns an error if the address is malformed or contains a non-empty path.
    pub fn resolve_addr(&mut self) -> Result<()> {
        let Some(ref addr_str) = self.addr else {
            return Ok(());
        };

        let url = Url::parse(addr_str)
            .with_context(|| format!("failed to parse VAULT_ADDR: {}", addr_str))?;

        if url.path() != "/" && !url.path().is_empty() {
            anyhow::bail!(
                "VAULT_ADDR '{}' contains a non-empty path '{}'. Only scheme://host:port is supported.",
                addr_str,
                url.path()
            );
        }

        let scheme = url.scheme();
        let tls = match scheme {
            "https" => true,
            "http" => false,
            _ => anyhow::bail!(
                "VAULT_ADDR '{}' has unsupported scheme '{}'. Use http:// or https://.",
                addr_str,
                scheme
            ),
        };

        // Override host/port/tls from the parsed URL
        self.host = url.host_str().unwrap_or("localhost").to_string();
        self.port = url
            .port_or_known_default()
            .unwrap_or(if tls { 443 } else { 80 });
        self.connect_tls = tls;

        Ok(())
    }

    /// Resolve the auth backend name, defaulting from auth method if not set.
    pub fn resolve_auth_backend(&mut self) {
        if self.auth_backend.is_some() {
            return;
        }
        self.auth_backend = match (
            &self.token,
            &self.github_token,
            &self.kubernetes_role,
            &self.approle_role_id,
            &self.ldap_username,
            &self.okta_username,
            &self.azure_role,
            &self.gcp_gce_role,
            &self.aws_ec2_role,
            &self.jwt_role,
        ) {
            (_, Some(_), _, _, _, _, _, _, _, _) => Some("github".to_string()),
            (_, _, Some(_), _, _, _, _, _, _, _) => Some("kubernetes".to_string()),
            (_, _, _, Some(_), _, _, _, _, _, _) => Some("approle".to_string()),
            (_, _, _, _, Some(_), _, _, _, _, _) => Some("ldap".to_string()),
            (_, _, _, _, _, Some(_), _, _, _, _) => Some("okta".to_string()),
            (_, _, _, _, _, _, Some(_), _, _, _) => Some("azure".to_string()),
            (_, _, _, _, _, _, _, Some(_), _, _) => Some("gcp".to_string()),
            (_, _, _, _, _, _, _, _, Some(_), _) => Some("aws".to_string()),
            (_, _, _, _, _, _, _, _, _, Some(_)) => Some("jwt".to_string()),
            _ => None,
        };
    }

    /// Determine the effective authentication method from parsed tokens/roles.
    pub fn auth_method(&self) -> AuthMethod {
        if let Some(ref token) = self.token {
            return AuthMethod::VaultToken {
                token: token.clone(),
            };
        }
        if let Some(ref gh) = self.github_token {
            return AuthMethod::GitHub(gh.clone());
        }
        if let Some(ref role) = self.kubernetes_role {
            return AuthMethod::Kubernetes { role: role.clone() };
        }
        if let (Some(role_id), Some(secret_id)) = (&self.approle_role_id, &self.approle_secret_id) {
            return AuthMethod::AppRole {
                role_id: role_id.clone(),
                secret_id: secret_id.clone(),
            };
        }
        if let (Some(user), Some(pass)) = (&self.ldap_username, &self.ldap_password) {
            return AuthMethod::Ldap {
                username: user.clone(),
                password: pass.clone(),
            };
        }
        if let (Some(user), Some(pass)) = (&self.okta_username, &self.okta_password) {
            return AuthMethod::Okta {
                username: user.clone(),
                password: pass.clone(),
            };
        }
        if let Some(role) = &self.azure_role {
            return AuthMethod::Azure {
                role: role.clone(),
                resource: self.azure_resource.clone(),
            };
        }
        if let Some(role) = &self.gcp_gce_role {
            return AuthMethod::Gcp { role: role.clone() };
        }
        if let Some(role) = &self.aws_ec2_role {
            return AuthMethod::AwsEc2 {
                role: role.clone(),
                signature_type: self.aws_ec2_signature_type.0,
            };
        }
        if let (Some(role), Some(token)) = (&self.jwt_role, &self.jwt_token) {
            return AuthMethod::Jwt {
                role: role.clone(),
                token: token.clone(),
            };
        }
        if let Some(role) = &self.jwt_role {
            if let Some(ref token_file) = self.jwt_token_file {
                let token = std::fs::read_to_string(token_file)
                    .with_context(|| format!("failed to read jwt token file: {:?}", token_file))
                    .expect("jwt token file read failed");
                return AuthMethod::Jwt {
                    role: role.clone(),
                    token: token.trim().to_string(),
                };
            }
        }
        AuthMethod::None
    }

    /// Validate that all required fields are present.
    pub fn validate(&self) -> Result<()> {
        if self.secrets_file.as_os_str().is_empty() {
            anyhow::bail!("--secrets-file is required");
        }
        if self.cmd.is_empty() {
            anyhow::bail!("CMD is required");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// clap value parsers for enum types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogLevelArg(pub LogLevel);

impl Default for LogLevelArg {
    fn default() -> Self {
        LogLevelArg(LogLevel::Error)
    }
}

impl std::str::FromStr for LogLevelArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Ok(LogLevelArg(LogLevel::Error)),
            "info" => Ok(LogLevelArg(LogLevel::Info)),
            _ => Err(format!(
                "unknown log level '{}', expected 'error' or 'info'",
                s
            )),
        }
    }
}

impl std::fmt::Display for LogLevelArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            LogLevel::Error => write!(f, "error"),
            LogLevel::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateBehaviorArg(pub DuplicateBehavior);

impl Default for DuplicateBehaviorArg {
    fn default() -> Self {
        DuplicateBehaviorArg(DuplicateBehavior::Error)
    }
}

impl std::str::FromStr for DuplicateBehaviorArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Ok(DuplicateBehaviorArg(DuplicateBehavior::Error)),
            "keep" => Ok(DuplicateBehaviorArg(DuplicateBehavior::Keep)),
            "overwrite" => Ok(DuplicateBehaviorArg(DuplicateBehavior::Overwrite)),
            _ => Err(format!(
                "unknown duplicate behavior '{}', expected 'error', 'keep', or 'overwrite'",
                s
            )),
        }
    }
}

impl std::fmt::Display for DuplicateBehaviorArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            DuplicateBehavior::Error => write!(f, "error"),
            DuplicateBehavior::Keep => write!(f, "keep"),
            DuplicateBehavior::Overwrite => write!(f, "overwrite"),
        }
    }
}

// ---------------------------------------------------------------------------
// Env-file loading (from /etc/vaultenv.conf, ~/.config/vaultenv/vaultenv.conf, ./vaultenv.conf)
// ---------------------------------------------------------------------------

/// Read environment files in standard locations and return their contents
/// as a list of (key, value) pairs per file.
pub fn read_env_files() -> Vec<Vec<(String, String)>> {
    let mut result = Vec::new();

    let machine = PathBuf::from("/etc/vaultenv.conf");
    if let Some(vars) = read_env_file(&machine) {
        result.push(vars);
    }

    if let Some(xdg) = dirs::config_dir() {
        let user = xdg.join("vaultenv").join("vaultenv.conf");
        if let Some(vars) = read_env_file(&user) {
            result.push(vars);
        }
    }

    let cwd = PathBuf::from("./vaultenv.conf");
    if let Some(vars) = read_env_file(&cwd) {
        result.push(vars);
    }

    result
}

fn read_env_file(path: &std::path::Path) -> Option<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path).ok()?;
    Some(
        content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                line.split_once('=')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_addr_https() {
        let mut opts = Options {
            host: "old".to_string(),
            port: 9999,
            addr: Some("https://vault.example.com:8200".to_string()),
            ..make_minimal()
        };
        opts.resolve_addr().unwrap();
        assert_eq!(opts.host, "vault.example.com");
        assert_eq!(opts.port, 8200);
        assert!(opts.connect_tls);
    }

    #[test]
    fn test_resolve_addr_http_defaults_port() {
        let mut opts = Options {
            host: "old".to_string(),
            port: 9999,
            addr: Some("http://vault.example.com".to_string()),
            ..make_minimal()
        };
        opts.resolve_addr().unwrap();
        assert_eq!(opts.host, "vault.example.com");
        assert_eq!(opts.port, 80);
        assert!(!opts.connect_tls);
    }

    #[test]
    fn test_resolve_addr_rejects_path() {
        let mut opts = Options {
            addr: Some("https://vault.example.com:8200/foo".to_string()),
            ..make_minimal()
        };
        assert!(opts.resolve_addr().is_err());
    }

    #[test]
    fn test_resolve_addr_rejects_bad_scheme() {
        let mut opts = Options {
            addr: Some("ftp://vault.example.com".to_string()),
            ..make_minimal()
        };
        assert!(opts.resolve_addr().is_err());
    }

    #[test]
    fn test_auth_backend_default_github() {
        let mut opts = Options {
            github_token: Some("ghp_xxx".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("github".to_string()));
    }

    #[test]
    fn test_auth_backend_default_kubernetes() {
        let mut opts = Options {
            kubernetes_role: Some("my-app".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("kubernetes".to_string()));
    }

    #[test]
    fn test_auth_backend_default_approle() {
        let mut opts = Options {
            approle_role_id: Some("role-123".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("approle".to_string()));
    }

    #[test]
    fn test_auth_backend_default_ldap() {
        let mut opts = Options {
            ldap_username: Some("alice".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("ldap".to_string()));
    }

    #[test]
    fn test_auth_backend_default_okta() {
        let mut opts = Options {
            okta_username: Some("alice".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("okta".to_string()));
    }

    #[test]
    fn test_auth_backend_default_azure() {
        let mut opts = Options {
            azure_role: Some("web-role".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("azure".to_string()));
    }

    #[test]
    fn test_auth_backend_default_gcp() {
        let mut opts = Options {
            gcp_gce_role: Some("web-role".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("gcp".to_string()));
    }

    #[test]
    fn test_auth_backend_default_aws() {
        let mut opts = Options {
            aws_ec2_role: Some("web-role".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("aws".to_string()));
    }

    #[test]
    fn test_auth_backend_keeps_explicit() {
        let mut opts = Options {
            auth_backend: Some("custom".to_string()),
            github_token: Some("ghp_xxx".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("custom".to_string()));
    }

    #[test]
    fn test_auth_method_token() {
        let opts = Options {
            token: Some("hvs.xxx".to_string()),
            ..make_minimal()
        };
        assert!(
            matches!(opts.auth_method(), AuthMethod::VaultToken { token } if token == "hvs.xxx")
        );
    }

    #[test]
    fn test_auth_method_none() {
        let opts = make_minimal();
        assert!(matches!(opts.auth_method(), AuthMethod::None));
    }

    #[test]
    fn test_auth_method_approle() {
        let opts = Options {
            approle_role_id: Some("role-123".to_string()),
            approle_secret_id: Some("secret-456".to_string()),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::AppRole { role_id, secret_id } => {
                assert_eq!(role_id, "role-123");
                assert_eq!(secret_id, "secret-456");
            }
            other => panic!("expected AppRole, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_method_ldap() {
        let opts = Options {
            ldap_username: Some("alice".to_string()),
            ldap_password: Some("p@ss".to_string()),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::Ldap { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "p@ss");
            }
            other => panic!("expected LDAP, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_method_okta() {
        let opts = Options {
            okta_username: Some("alice".to_string()),
            okta_password: Some("p@ss".to_string()),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::Okta { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "p@ss");
            }
            other => panic!("expected Okta, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_method_azure() {
        let opts = Options {
            azure_role: Some("web-role".to_string()),
            azure_resource: Some("https://management.azure.com/".to_string()),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::Azure { role, resource } => {
                assert_eq!(role, "web-role");
                assert_eq!(resource, Some("https://management.azure.com/".to_string()));
            }
            other => panic!("expected Azure, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_method_gcp() {
        let opts = Options {
            gcp_gce_role: Some("web-role".to_string()),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::Gcp { role } => {
                assert_eq!(role, "web-role");
            }
            other => panic!("expected GCP, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_method_aws_ec2() {
        let opts = Options {
            aws_ec2_role: Some("web-role".to_string()),
            aws_ec2_signature_type: crate::cloud_metadata::Ec2SignatureTypeArg(
                crate::cloud_metadata::Ec2SignatureType::Identity,
            ),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::AwsEc2 {
                role,
                signature_type,
            } => {
                assert_eq!(role, "web-role");
                assert_eq!(
                    signature_type,
                    crate::cloud_metadata::Ec2SignatureType::Identity
                );
            }
            other => panic!("expected AwsEc2, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_backend_default_jwt() {
        let mut opts = Options {
            jwt_role: Some("ci-role".to_string()),
            ..make_minimal()
        };
        opts.resolve_auth_backend();
        assert_eq!(opts.auth_backend, Some("jwt".to_string()));
    }

    #[test]
    fn test_auth_method_jwt_direct() {
        let opts = Options {
            jwt_role: Some("ci-role".to_string()),
            jwt_token: Some("my-jwt-token".to_string()),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::Jwt { role, token } => {
                assert_eq!(role, "ci-role");
                assert_eq!(token, "my-jwt-token");
            }
            other => panic!("expected Jwt, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_method_jwt_from_file() {
        let tmp = std::env::temp_dir().join("vaultenv_test_jwt.txt");
        std::fs::write(&tmp, "file-jwt-token\n").unwrap();
        let opts = Options {
            jwt_role: Some("ci-role".to_string()),
            jwt_token_file: Some(tmp.clone()),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::Jwt { role, token } => {
                assert_eq!(role, "ci-role");
                assert_eq!(token, "file-jwt-token");
            }
            other => panic!("expected Jwt, got {other:?}"),
        }
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_auth_method_jwt_direct_takes_precedence() {
        let tmp = std::env::temp_dir().join("vaultenv_test_jwt_prec.txt");
        std::fs::write(&tmp, "from-file").unwrap();
        let opts = Options {
            jwt_role: Some("ci-role".to_string()),
            jwt_token: Some("from-direct".to_string()),
            jwt_token_file: Some(tmp.clone()),
            ..make_minimal()
        };
        match opts.auth_method() {
            AuthMethod::Jwt { token, .. } => assert_eq!(token, "from-direct"),
            other => panic!("expected Jwt, got {other:?}"),
        }
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_validate_missing_cmd() {
        let mut opts = make_minimal();
        opts.cmd.clear();
        assert!(opts.validate().is_err());
    }

    // Helper to build Options with only the required fields populated.
    fn make_minimal() -> Options {
        Options {
            host: "localhost".to_string(),
            port: 8200,
            addr: None,
            auth_backend: None,
            token: None,
            github_token: None,
            kubernetes_role: None,
            approle_role_id: None,
            approle_secret_id: None,
            ldap_username: None,
            ldap_password: None,
            okta_username: None,
            okta_password: None,
            azure_role: None,
            azure_resource: None,
            gcp_gce_role: None,
            aws_ec2_role: None,
            aws_ec2_signature_type: crate::cloud_metadata::Ec2SignatureTypeArg(
                crate::cloud_metadata::Ec2SignatureType::Pkcs7,
            ),
            jwt_role: None,
            jwt_token: None,
            jwt_token_file: None,
            secrets_file: PathBuf::from("/dev/null"),
            cmd: "echo".to_string(),
            args: Vec::new(),
            connect_tls: true,
            validate_certs: true,
            inherit_env: true,
            inherit_env_blacklist: Vec::new(),
            retry_base_delay_ms: 40,
            retry_attempts: 9,
            log_level: LogLevelArg(LogLevel::Error),
            use_path: false,
            max_concurrent_requests: 8,
            duplicate_behavior: DuplicateBehaviorArg(DuplicateBehavior::Error),
        }
    }
}

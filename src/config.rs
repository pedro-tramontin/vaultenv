//! Configuration parsing and validation.
//!
//! Uses `clap` for CLI argument parsing with `#[command(env)]` support
//! to eliminate the manual env-var-override boilerplate.
//!
//! Flags are aligned with the Vault CLI `-method=<TYPE>` + `KEY=VALUE` conventions.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use url::Url;

use crate::auth::AuthMethod;
use crate::types::{DuplicateBehaviorArg, LogLevelArg};

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

    /// Authentication method (token, github, kubernetes, approle, ldap, okta,
    /// azure, gcp, aws, jwt).  Defaults to "token".
    #[arg(long, env = "VAULTENV_METHOD", default_value = "token")]
    pub method: String,

    /// Mount path for the auth backend (e.g. "oidc" for auth/oidc).
    /// Defaults to the method name.
    #[arg(long, env = "VAULTENV_PATH")]
    pub path: Option<String>,

    /// Vault token (for `--method=token` or as the GitHub PAT when
    /// `--method=github`).
    #[arg(long, env = "VAULT_TOKEN")]
    pub token: Option<String>,

    /// Role name (required for kubernetes, azure, gcp, aws, jwt methods).
    #[arg(long, env = "VAULTENV_ROLE")]
    pub role: Option<String>,

    /// AppRole role ID (for `--method=approle`).
    #[arg(long, env = "VAULTENV_ROLE_ID")]
    pub role_id: Option<String>,

    /// AppRole secret ID (for `--method=approle`).
    #[arg(long, env = "VAULTENV_SECRET_ID")]
    pub secret_id: Option<String>,

    /// Username (for `--method=ldap` or `--method=okta`).
    #[arg(long, env = "VAULTENV_USERNAME")]
    pub username: Option<String>,

    /// Password (for `--method=ldap` or `--method=okta`).
    #[arg(long, env = "VAULTENV_PASSWORD")]
    pub password: Option<String>,

    /// JWT value (for `--method=jwt` or `--method=kubernetes`).
    #[arg(long, env = "VAULTENV_JWT")]
    pub jwt: Option<String>,

    /// Path to file containing a JWT (for `--method=jwt` or
    /// `--method=kubernetes`).
    #[arg(long, env = "VAULTENV_JWT_FILE")]
    pub jwt_file: Option<PathBuf>,

    /// Azure resource URL for MSI (for `--method=azure`).
    #[arg(long, env = "VAULTENV_RESOURCE")]
    pub resource: Option<String>,

    /// AWS EC2 signature type (pkcs7, identity, rsa2048).
    #[arg(long, env = "VAULTENV_AWS_SIGNATURE_TYPE", default_value = "pkcs7")]
    pub aws_signature_type: crate::cloud_metadata::Ec2SignatureTypeArg,

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

        self.host = url.host_str().unwrap_or("localhost").to_string();
        self.port = url
            .port_or_known_default()
            .unwrap_or(if tls { 443 } else { 80 });
        self.connect_tls = tls;

        Ok(())
    }

    /// Resolve the mount path for the auth backend.
    /// Prefers `--path`, then defaults to `--method`.
    pub fn auth_path(&self) -> String {
        self.path.clone().unwrap_or_else(|| self.method.clone())
    }

    /// Determine the effective authentication method from `--method`
    /// and the corresponding method-specific flags.
    pub fn auth_method(&self) -> AuthMethod {
        match self.method.as_str() {
            "token" => {
                if let Some(ref token) = self.token {
                    return AuthMethod::VaultToken {
                        token: token.clone(),
                    };
                }
                AuthMethod::None
            }
            "github" => {
                if let Some(ref t) = self.token {
                    return AuthMethod::GitHub(t.clone());
                }
                AuthMethod::None
            }
            "kubernetes" => {
                if let Some(ref r) = self.role {
                    return AuthMethod::Kubernetes { role: r.clone() };
                }
                AuthMethod::None
            }
            "approle" => {
                if let (Some(rid), Some(sid)) = (&self.role_id, &self.secret_id) {
                    return AuthMethod::AppRole {
                        role_id: rid.clone(),
                        secret_id: sid.clone(),
                    };
                }
                AuthMethod::None
            }
            "ldap" => {
                if let (Some(u), Some(p)) = (&self.username, &self.password) {
                    return AuthMethod::Ldap {
                        username: u.clone(),
                        password: p.clone(),
                    };
                }
                AuthMethod::None
            }
            "okta" => {
                if let (Some(u), Some(p)) = (&self.username, &self.password) {
                    return AuthMethod::Okta {
                        username: u.clone(),
                        password: p.clone(),
                    };
                }
                AuthMethod::None
            }
            "azure" => {
                if let Some(ref r) = self.role {
                    return AuthMethod::Azure {
                        role: r.clone(),
                        resource: self.resource.clone(),
                    };
                }
                AuthMethod::None
            }
            "gcp" => {
                if let Some(ref r) = self.role {
                    return AuthMethod::Gcp { role: r.clone() };
                }
                AuthMethod::None
            }
            "aws" => {
                if let Some(ref r) = self.role {
                    return AuthMethod::AwsEc2 {
                        role: r.clone(),
                        signature_type: self.aws_signature_type.0,
                    };
                }
                AuthMethod::None
            }
            "jwt" => {
                let role = self.role.as_ref();
                let token = self.jwt.as_ref();
                if let (Some(r), Some(t)) = (role, token) {
                    return AuthMethod::Jwt {
                        role: r.clone(),
                        token: t.clone(),
                    };
                }
                if let Some(r) = role {
                    if let Some(ref path) = self.jwt_file {
                        let token = std::fs::read_to_string(path)
                            .with_context(|| format!("failed to read jwt file: {}", path.display()))
                            .expect("jwt file read failed");
                        return AuthMethod::Jwt {
                            role: r.clone(),
                            token: token.trim().to_string(),
                        };
                    }
                }
                AuthMethod::None
            }
            _ => AuthMethod::None,
        }
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
    fn test_auth_path_prefers_path() {
        let opts = Options {
            method: "jwt".to_string(),
            path: Some("oidc".to_string()),
            ..make_minimal()
        };
        assert_eq!(opts.auth_path(), "oidc");
    }

    #[test]
    fn test_auth_path_falls_back_to_method() {
        let opts = Options {
            method: "github".to_string(),
            ..make_minimal()
        };
        assert_eq!(opts.auth_path(), "github");
    }

    #[test]
    fn test_auth_method_token() {
        let opts = Options {
            method: "token".to_string(),
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
            method: "approle".to_string(),
            role_id: Some("role-123".to_string()),
            secret_id: Some("secret-456".to_string()),
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
            method: "ldap".to_string(),
            username: Some("alice".to_string()),
            password: Some("p@ss".to_string()),
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
            method: "okta".to_string(),
            username: Some("alice".to_string()),
            password: Some("p@ss".to_string()),
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
            method: "azure".to_string(),
            role: Some("web-role".to_string()),
            resource: Some("https://management.azure.com/".to_string()),
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
            method: "gcp".to_string(),
            role: Some("web-role".to_string()),
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
    fn test_auth_method_aws() {
        let opts = Options {
            method: "aws".to_string(),
            role: Some("web-role".to_string()),
            aws_signature_type: crate::cloud_metadata::Ec2SignatureTypeArg(
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
    fn test_auth_method_jwt() {
        let opts = Options {
            method: "jwt".to_string(),
            role: Some("ci-role".to_string()),
            jwt: Some("my-jwt-token".to_string()),
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
        let tmp = std::env::temp_dir().join("vaultenv_test_jwt_ref.txt");
        std::fs::write(&tmp, "file-jwt-token\n").unwrap();
        let opts = Options {
            method: "jwt".to_string(),
            role: Some("ci-role".to_string()),
            jwt_file: Some(tmp.clone()),
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
    fn test_validate_missing_cmd() {
        let mut opts = make_minimal();
        opts.cmd.clear();
        assert!(opts.validate().is_err());
    }

    fn make_minimal() -> Options {
        Options {
            host: "localhost".to_string(),
            port: 8200,
            addr: None,
            method: "token".to_string(),
            path: None,
            token: None,
            role: None,
            role_id: None,
            secret_id: None,
            username: None,
            password: None,
            jwt: None,
            jwt_file: None,
            resource: None,
            aws_signature_type: crate::cloud_metadata::Ec2SignatureTypeArg(
                crate::cloud_metadata::Ec2SignatureType::Pkcs7,
            ),
            secrets_file: PathBuf::from("/dev/null"),
            cmd: "echo".to_string(),
            args: Vec::new(),
            connect_tls: true,
            validate_certs: true,
            inherit_env: true,
            inherit_env_blacklist: Vec::new(),
            retry_base_delay_ms: 40,
            retry_attempts: 9,
            log_level: LogLevelArg::default(),
            use_path: false,
            max_concurrent_requests: 8,
            duplicate_behavior: DuplicateBehaviorArg::default(),
        }
    }
}

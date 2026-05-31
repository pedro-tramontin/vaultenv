//! Configuration parsing and validation.
//!
//! Ports the logic from Haskell's `Config.hs` to Rust.
//! Uses `clap` for CLI argument parsing with `#[command(env)]` support
//! to eliminate the manual env-var-override boilerplate.

use clap::Parser;
use std::path::PathBuf;

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

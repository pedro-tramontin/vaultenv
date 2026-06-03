//! Authentication methods for Vault.

use anyhow::{Context, Result};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::debug;
#[cfg(unix)]
use tracing::warn;

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

/// Read a token from a file (typically `~/.vault-token`).
///
/// Returns `Ok(None)` if the file does not exist (this is normal — `vault login`
/// creates the file but a fresh install won't have it). Returns `Ok(Some(token))`
/// on success. Returns an error only on permission-policy violations or I/O
/// errors that are not "file missing".
///
/// The file's permission bits are checked. By default, any group/other read
/// bit (mode & 0o077 != 0) is rejected — this matches the
/// `vault agent unsafe_password_file` opt-in model and defends against the
/// common case of a token being leaked via `chmod 644`. Set the
/// `VAULTENV_ALLOW_INSECURE_TOKEN_FILE` env var to `"1"` to bypass the check
/// (a `warn!` is logged so the unsafe use is at least visible in logs).
///
/// Whitespace at the start/end of the file content is trimmed (matches
/// upstream `vault` behaviour, including treating an all-whitespace file as
/// "no token").
pub fn resolve_token_file(file: &Path) -> Result<Option<String>> {
    let raw = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %file.display(), "no token file found, skipping file fallback");
            return Ok(None);
        }
        Err(e) => {
            return Err(anyhow::Error::new(e)
                .context(format!("failed to read token file: {}", file.display())));
        }
    };

    let token = raw.trim().to_string();
    if token.is_empty() {
        debug!(path = %file.display(), "token file is empty, skipping file fallback");
        return Ok(None);
    }

    // Permission check (Unix only). On non-Unix platforms the bit is 0 and the
    // check is a no-op — which is the right behaviour because chmod/0o077 are
    // Unix concepts.
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(file)
            .with_context(|| format!("failed to stat token file: {}", file.display()))?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            let allow_insecure = std::env::var("VAULTENV_ALLOW_INSECURE_TOKEN_FILE")
                .ok()
                .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
            if !allow_insecure {
                return Err(anyhow::anyhow!(
                    "refusing to read token from {}: file is group/world readable (mode 0o{:o}). \
                     chmod 600 it, or set VAULTENV_ALLOW_INSECURE_TOKEN_FILE=1 to bypass this check.",
                    file.display(),
                    mode & 0o7777,
                ));
            }
            warn!(
                path = %file.display(),
                mode = format!("0o{:o}", mode & 0o7777),
                "reading token from a group/world-readable file because \
                 VAULTENV_ALLOW_INSECURE_TOKEN_FILE is set",
            );
        }
    }

    Ok(Some(token))
}

// All tests in this module exercise Unix file-mode semantics (`OpenOptionsExt::mode`),
// so the module is Unix-only by design. On Windows, the permission-check path is
// a no-op (see the `#[cfg(unix)]` block on the production code) and the
// `~/.vault-token` fallback behaviour is verified through the OS trust store
// rather than POSIX mode bits.
#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serialises all tests in this module that touch the process environment
    /// via `std::env::set_var`. `set_var` is `unsafe` in Rust 2024 because it
    /// races with concurrent readers; serialising the writers is enough for
    /// our test purposes.
    ///
    /// The mutex is `lazy_static`-style (const-constructed) so it survives
    /// the test binary for its full lifetime and tests can grab a guard at
    /// any time.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn write_token_file(dir: &TempDir, name: &str, content: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&path)
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        path
    }

    // RAII guard: ensures a possibly-set env var is restored (or cleared) on
    // drop, even if the test panics. Tests that touch VAULTENV_ALLOW_INSECURE_TOKEN_FILE
    // use this to avoid leaking state into the next test.
    //
    // `std::env::set_var` and `remove_var` are `unsafe` in Rust 2024 because
    // they can race with other threads reading the env. In tests this is OK
    // because each test that uses the guard is the only writer for the var.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: tests using EnvGuard hold ENV_LOCK, so there is no
            // concurrent writer to this env var.
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: see EnvGuard::set.
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn missing_file_returns_none_no_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist");
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn empty_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "", 0o600);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn whitespace_only_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "   \n\t  \n", 0o600);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn secure_mode_0600_reads_token() {
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc123\n", 0o600);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result.as_deref(), Some("hvs.abc123"));
    }

    #[test]
    fn secure_mode_0400_reads_token() {
        // Read-only owner, no group/other bits — also acceptable.
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc", 0o400);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result.as_deref(), Some("hvs.abc"));
    }

    #[test]
    fn group_readable_0644_is_rejected_by_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        // Make sure no leftover override leaks in from a previous test.
        let _g = EnvGuard::set("VAULTENV_ALLOW_INSECURE_TOKEN_FILE", "0");
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc", 0o644);
        let err = resolve_token_file(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("refusing to read token"), "msg was: {msg}");
        assert!(msg.contains("chmod 600"), "msg was: {msg}");
        assert!(
            msg.contains("VAULTENV_ALLOW_INSECURE_TOKEN_FILE"),
            "msg was: {msg}"
        );
    }

    #[test]
    fn world_readable_0604_is_rejected_by_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set("VAULTENV_ALLOW_INSECURE_TOKEN_FILE", "0");
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc", 0o604);
        let err = resolve_token_file(&path).unwrap_err();
        assert!(format!("{err:#}").contains("refusing to read token"));
    }

    #[test]
    fn group_readable_0644_is_allowed_with_env_override_1() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set("VAULTENV_ALLOW_INSECURE_TOKEN_FILE", "1");
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc", 0o644);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result.as_deref(), Some("hvs.abc"));
    }

    #[test]
    fn env_override_accepts_true_string() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set("VAULTENV_ALLOW_INSECURE_TOKEN_FILE", "true");
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc", 0o644);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result.as_deref(), Some("hvs.abc"));
    }

    #[test]
    fn env_override_accepts_uppercase_true() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set("VAULTENV_ALLOW_INSECURE_TOKEN_FILE", "TRUE");
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc", 0o644);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result.as_deref(), Some("hvs.abc"));
    }

    #[test]
    fn env_override_set_to_zero_does_not_bypass() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set("VAULTENV_ALLOW_INSECURE_TOKEN_FILE", "0");
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc", 0o644);
        let err = resolve_token_file(&path).unwrap_err();
        assert!(format!("{err:#}").contains("refusing to read token"));
    }

    #[test]
    fn token_with_trailing_newline_is_trimmed() {
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc\n\n", 0o600);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result.as_deref(), Some("hvs.abc"));
    }

    #[test]
    fn token_with_leading_whitespace_is_trimmed() {
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "  \thvs.abc\n", 0o600);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result.as_deref(), Some("hvs.abc"));
    }

    #[test]
    fn token_with_internal_whitespace_preserved() {
        // The trim should only strip leading/trailing, not internal.
        let dir = TempDir::new().unwrap();
        let path = write_token_file(&dir, "tok", "hvs.abc xyz\n", 0o600);
        let result = resolve_token_file(&path).unwrap();
        assert_eq!(result.as_deref(), Some("hvs.abc xyz"));
    }
}

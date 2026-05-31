//! Parser for the vaultenv secrets file format.
//!
//! Supports both version 1 (implicit `secret/` mount) and version 2
//! (`MOUNT` blocks with explicit mount paths).
//!
//! Grammar (informal):
//! ```text
//! secrets_file := version? (secret | secret_block)*
//! version      := "VERSION" "2" newline+
//! secret_block := "MOUNT" path newline+ secret*
//! secret       := var_name? path "#" key newline+
//! var_name     := [A-Za-z_] [A-Za-z0-9_]* "="
//! path         := non-whitespace, non-control, excluding '#' and '='+
//! key          := same as path
//! ```

/// A single secret specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// Vault mount point (e.g. `"secret"`).
    pub mount: String,
    /// Secret path within the mount.
    pub path: String,
    /// Key to extract from the secret.
    pub key: String,
    /// Environment variable name to expose the value under.
    pub var_name: String,
}

/// Errors that can occur while reading or parsing a secrets file.
#[derive(Debug, thiserror::Error)]
pub enum SecretsFileError {
    #[error("failed to read secrets file: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
}

/// Read and parse a secrets file from disk.
pub fn read_secrets_file(_path: &std::path::Path) -> Result<Vec<Secret>, SecretsFileError> {
    // TODO: Phase 3 – implement winnow-based parser
    todo!("Phase 3: secrets file parser")
}

//! Parser for the vaultenv secrets file format (V2 only).
//!
//! Grammar (informal):
//! ```text
//! secrets_file := newlines? whitespace "VERSION" "2" newlines secret_block*
//! secret_block := "MOUNT" path newlines secret*
//! secret       := var_name? path "#" key newlines
//! var_name     := [A-Za-z_] [A-Za-z0-9_]* "="
//! path         := non-whitespace, non-control, excluding '#' and '=' (1+ chars)
//! key          := same as path
//! ```

use std::path::Path;
use winnow::{
    Parser,
    ascii::line_ending,
    combinator::opt,
    error::ContextError,
    token::{literal, take_while},
};

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
pub fn read_secrets_file(path: &Path) -> Result<Vec<Secret>, SecretsFileError> {
    let contents = std::fs::read_to_string(path)?;
    parse_secrets_file(&contents).map_err(SecretsFileError::Parse)
}

/// Parse a secrets file from a string.
pub fn parse_secrets_file(input: &str) -> Result<Vec<Secret>, String> {
    let mut input = input;
    let secrets = secrets_file
        .parse_next(&mut input)
        .map_err(|e| format!("{e}"))?;

    let remaining = input.trim();
    if !remaining.is_empty() {
        return Err(format!(
            "unexpected trailing content after parse: {remaining}"
        ));
    }

    Ok(secrets)
}

/// Zero or more spaces / tabs (newlines are handled separately).
fn whitespace(input: &mut &str) -> Result<(), ContextError> {
    let _ = take_while(0.., |c: char| c.is_ascii_whitespace() && c != '\n').parse_next(input)?;
    Ok(())
}

/// One or more newlines, consuming trailing spaces/tabs on each line.
fn newlines(input: &mut &str) -> Result<(), ContextError> {
    line_ending::<&str, ContextError>.parse_next(input)?;
    whitespace(input)?;
    while line_ending::<&str, ContextError>.parse_next(input).is_ok() {
        whitespace(input)?;
    }
    Ok(())
}

/// Parse a path component: non-whitespace, non-control, excluding '#' and '='.
fn path_component(input: &mut &str) -> Result<String, ContextError> {
    let s: &str = take_while(1.., |c: char| {
        !c.is_whitespace() && c != '#' && c != '=' && !c.is_control()
    })
    .parse_next(input)?;
    Ok(s.to_string())
}

/// Parse an explicit environment variable name: `FOO_BAR=`.
fn var_name(input: &mut &str) -> Result<String, ContextError> {
    let start = take_while(1, |c: char| c.is_ascii_alphabetic() || c == '_').parse_next(input)?;
    let rest =
        take_while(0.., |c: char| c.is_ascii_alphanumeric() || c == '_').parse_next(input)?;
    "=".parse_next(input)?;
    whitespace(input)?;
    Ok(format!("{start}{rest}"))
}

/// Parse a single secret line within a mount block.
fn secret(input: &mut &str, mount: &str) -> Result<Secret, ContextError> {
    let var = opt(var_name).parse_next(input)?;
    let path = path_component(input)?;
    whitespace(input)?;
    "#".parse_next(input)?;
    whitespace(input)?;
    let key = path_component(input)?;
    whitespace(input)?;
    newlines.parse_next(input)?;

    let var_name = var.unwrap_or_else(|| generate_var_name(mount, &path, &key));

    Ok(Secret {
        mount: mount.to_string(),
        path: path.to_string(),
        key: key.to_string(),
        var_name,
    })
}

/// Parse a `MOUNT` block: `MOUNT <path>` followed by zero or more secrets.
fn secret_block(input: &mut &str) -> Result<Vec<Secret>, ContextError> {
    literal("MOUNT").parse_next(input)?;
    whitespace(input)?;
    let mount_path = path_component(input)?;
    whitespace(input)?;
    newlines.parse_next(input)?;

    let mut secrets = Vec::new();
    loop {
        let checkpoint = *input;
        if newlines.parse_next(input).is_ok() {
            continue;
        }
        *input = checkpoint;

        if let Ok(s) = secret(input, &mount_path) {
            secrets.push(s);
        } else {
            *input = checkpoint;
            break;
        }
    }

    Ok(secrets)
}

/// Top-level secrets file parser (V2 only).
fn secrets_file(input: &mut &str) -> Result<Vec<Secret>, ContextError> {
    opt(newlines).parse_next(input)?;
    whitespace(input)?;

    literal("VERSION").parse_next(input)?;
    whitespace(input)?;
    literal("2").parse_next(input)?;
    whitespace(input)?;
    newlines.parse_next(input)?;

    let mut all_secrets = Vec::new();
    loop {
        let checkpoint = *input;
        if newlines.parse_next(input).is_ok() {
            continue;
        }
        *input = checkpoint;

        if let Ok(block_secrets) = secret_block.parse_next(input) {
            all_secrets.extend(block_secrets);
        } else {
            *input = checkpoint;
            break;
        }
    }

    // Allow trailing whitespace/newlines
    let _ = newlines.parse_next(input);
    let _ = whitespace(input);

    Ok(all_secrets)
}

/// Generate a default environment variable name from mount, path, and key.
fn generate_var_name(mount: &str, path: &str, key: &str) -> String {
    format!("{mount}_{path}_{key}")
        .replace('/', "_")
        .replace('-', "_")
        .to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Golden tests (V2 only) ──────────────────────────────────────────

    #[test]
    fn test_empty_v2() {
        let secrets = parse_secrets_file("VERSION 2\n").unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_v2_basic() {
        let secrets = parse_secrets_file("VERSION 2\nMOUNT secret\nfoo#bar\n").unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].mount, "secret");
        assert_eq!(secrets[0].path, "foo");
        assert_eq!(secrets[0].key, "bar");
        assert_eq!(secrets[0].var_name, "SECRET_FOO_BAR");
    }

    #[test]
    fn test_v2_explicit_var() {
        let secrets = parse_secrets_file("VERSION 2\nMOUNT secret\nBAR=foo/baz#bar\n").unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].var_name, "BAR");
        assert_eq!(secrets[0].path, "foo/baz");
        assert_eq!(secrets[0].key, "bar");
    }

    #[test]
    fn test_v2_multiple_mounts() {
        let input = "\n\
VERSION 2\n\
\n\
MOUNT secret\n\
foo#bar\n\
BAR=foo/baz#bar\n\
\n\
MOUNT otherthing\n\
foo#bar\n\
BAR=foo/baz#bar\n\
";
        let secrets = parse_secrets_file(input).unwrap();
        assert_eq!(secrets.len(), 4);

        assert_eq!(secrets[0].mount, "secret");
        assert_eq!(secrets[0].var_name, "SECRET_FOO_BAR");

        assert_eq!(secrets[1].mount, "secret");
        assert_eq!(secrets[1].var_name, "BAR");

        assert_eq!(secrets[2].mount, "otherthing");
        assert_eq!(secrets[2].var_name, "OTHERTHING_FOO_BAR");

        assert_eq!(secrets[3].mount, "otherthing");
        assert_eq!(secrets[3].var_name, "BAR");
    }

    #[test]
    fn test_empty_block() {
        let input = "\n\
VERSION 2\n\
MOUNT empty\n\
MOUNT nonempty\n\
FOO_BAR=foo#bar\n\
MOUNT empty2\n\
";
        let secrets = parse_secrets_file(input).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].mount, "nonempty");
        assert_eq!(secrets[0].var_name, "FOO_BAR");
    }

    #[test]
    fn test_whitespace_forgiving() {
        let input = "VERSION    2\n\n  MOUNT secret\nstuff/and#things\n";
        let secrets = parse_secrets_file(input).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].mount, "secret");
        assert_eq!(secrets[0].path, "stuff/and");
        assert_eq!(secrets[0].key, "things");
        assert_eq!(secrets[0].var_name, "SECRET_STUFF_AND_THINGS");
    }

    // ── Invalid tests ───────────────────────────────────────────────────

    #[test]
    fn test_rejects_plain_v1() {
        let result = parse_secrets_file("foo#bar\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_version_1() {
        let result = parse_secrets_file("VERSION 1\nfoo#bar\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_ambiguous() {
        let result = parse_secrets_file("VERSION 2\nMOUNT secret\nfoo#bar/baz#quix\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_bad_envvar() {
        let result = parse_secrets_file(
            "VERSION 2\nMOUNT secret\n5_shouldnt_lead_with_numbers=testing#secret\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_mount_without_path() {
        let result = parse_secrets_file("VERSION 2\nMOUNT\nfoo#bar\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_version_without_2() {
        let result = parse_secrets_file("VERSION\n2\nMOUNT secret\nfoo#bar\n");
        assert!(result.is_err());
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn test_auto_var_name_with_dashes_and_slashes() {
        let secrets = parse_secrets_file("VERSION 2\nMOUNT secret\na-b/c-d#e-f\n").unwrap();
        assert_eq!(secrets[0].var_name, "SECRET_A_B_C_D_E_F");
    }

    #[test]
    fn test_special_chars_in_path() {
        let secrets = parse_secrets_file("VERSION 2\nMOUNT secret\nfoob@ar#baz\n").unwrap();
        assert_eq!(secrets[0].path, "foob@ar");
        assert_eq!(secrets[0].key, "baz");
    }

    #[test]
    fn test_unicode_path() {
        let secrets = parse_secrets_file("VERSION 2\nMOUNT secret\nfoՔob@ar#baz\n").unwrap();
        assert_eq!(secrets[0].path, "foՔob@ar");
        assert_eq!(secrets[0].key, "baz");
    }

    #[test]
    fn test_no_trailing_newline() {
        let result = parse_secrets_file("VERSION 2\nMOUNT secret\nfoo#bar");
        assert!(result.is_err());
    }

    #[test]
    fn test_golden_file_roundtrip() {
        let golden_dir = std::path::PathBuf::from("test/golden");
        if !golden_dir.exists() {
            return;
        }

        let v2_golden = [
            "empty-block.secrets",
            "empty-v2.secrets",
            "v2.secrets",
            "whitespace.secrets",
        ];

        for name in &v2_golden {
            let path = golden_dir.join(name);
            let result = read_secrets_file(&path);
            assert!(result.is_ok(), "{name} should parse: {result:?}");
        }
    }

    #[test]
    fn test_invalid_files_fail() {
        let invalid_dir = std::path::PathBuf::from("test/invalid");
        if !invalid_dir.exists() {
            return;
        }

        let entries = std::fs::read_dir(&invalid_dir).unwrap();
        for entry in entries {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) == Some("secrets") {
                let result = read_secrets_file(&path);
                assert!(result.is_err(), "{} should fail", path.display());
            }
        }
    }
}

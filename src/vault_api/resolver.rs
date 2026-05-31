//! Resolve secrets from fetched Vault data into environment variable pairs.

use std::collections::HashMap;

use tracing::trace;

use crate::secrets_file::Secret;
use crate::types::DuplicateBehavior;

use super::{
    data::{MountInfo, VaultData},
    error::VaultError,
};

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
        trace!(path = %path, key = %secret.key, "looking up secret value");
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

        trace!(var_name = %secret.var_name, path = %path, "resolved secret value");
        env_vars.push((secret.var_name.clone(), string_value));
    }

    Ok(env_vars)
}

/// Deduplicate environment variables according to the requested behavior.
pub fn deduplicate(
    vars: Vec<(String, String)>,
    behavior: DuplicateBehavior,
) -> Result<Vec<(String, String)>, VaultError> {
    match behavior {
        DuplicateBehavior::Error => {
            let mut seen = std::collections::HashSet::new();
            for (name, _) in &vars {
                if !seen.insert(name) {
                    return Err(VaultError::DuplicateVar(name.clone()));
                }
            }
            Ok(vars)
        }
        DuplicateBehavior::Keep => {
            let mut result = HashMap::new();
            for (name, value) in vars {
                result.entry(name).or_insert(value);
            }
            Ok(result.into_iter().collect())
        }
        DuplicateBehavior::Overwrite => {
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

    #[test]
    fn test_resolve_secrets_ok() {
        let mi = MountInfo::from_map(HashMap::new());
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
        let mi = MountInfo::from_map(HashMap::new());
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
        let mi = MountInfo::from_map(HashMap::new());
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
            deduplicate(vars, DuplicateBehavior::Error),
            Err(VaultError::DuplicateVar(name)) if name == "FOO"
        ));
    }

    #[test]
    fn test_deduplicate_overwrite() {
        let vars = vec![
            ("FOO".to_string(), "a".to_string()),
            ("FOO".to_string(), "b".to_string()),
        ];
        let result = deduplicate(vars, DuplicateBehavior::Overwrite).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("FOO".to_string(), "b".to_string()));
    }
}

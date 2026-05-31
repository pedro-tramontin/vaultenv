#! Vault API data models.

use std::collections::HashMap;

use serde::Deserialize;

/// Vault KV engine type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum EngineType {
    #[serde(rename = "1")]
    V1,
    #[serde(rename = "2")]
    V2,
}

/// KV mount options used when parsing /sys/mounts.
#[derive(Debug, Deserialize)]
struct MountOptions {
    version: String,
}

/// KV mount spec used when parsing /sys/mounts.
#[derive(Debug, Deserialize)]
struct MountSpec {
    #[serde(rename = "type")]
    mount_type: String,
    options: MountOptions,
}

/// Parsed Vault secret data.
#[derive(Debug, Clone)]
pub struct VaultData(pub HashMap<String, serde_json::Value>);

impl<'de> Deserialize<'de> for VaultData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut obj = HashMap::<String, serde_json::Value>::deserialize(deserializer)?;

        if let Some(serde_json::Value::Object(inner)) = obj.remove("data") {
            if let Some(serde_json::Value::Object(data)) = inner.get("data") {
                let map: HashMap<String, serde_json::Value> = data.clone().into_iter().collect();
                return Ok(VaultData(map));
            }
            let map: HashMap<String, serde_json::Value> = inner.into_iter().collect();
            return Ok(VaultData(map));
        }
        Err(serde::de::Error::custom(
            "missing 'data' field in Vault response",
        ))
    }
}

/// Vault client token returned by auth backends.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientToken {
    pub auth: AuthPayload,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthPayload {
    #[serde(rename = "client_token")]
    pub client_token: String,
}

/// Mount info: maps mount path (e.g. "secret/") to engine version.
#[derive(Debug, Clone)]
pub struct MountInfo {
    mounts: HashMap<String, EngineType>,
}

impl MountInfo {
    /// Create mount info from an explicit map.
    pub fn from_map(mounts: HashMap<String, EngineType>) -> Self {
        MountInfo { mounts }
    }

    /// Return the engine type for a given mount, defaulting to KV1.
    pub(crate) fn engine_type(&self, mount: &str) -> EngineType {
        let key = format!("{mount}/");
        self.mounts.get(&key).copied().unwrap_or(EngineType::V1)
    }

    /// Build the Vault API path for a secret given mount info.
    pub fn secret_path(&self, secret: &crate::secrets_file::Secret) -> String {
        match self.engine_type(&secret.mount) {
            EngineType::V1 => format!("/v1/{}/{}", secret.mount, secret.path),
            EngineType::V2 => format!("/v1/{}/data/{}", secret.mount, secret.path),
        }
    }
}

impl<'de> Deserialize<'de> for MountInfo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = HashMap::<String, serde_json::Value>::deserialize(deserializer)?;
        let mounts = raw
            .into_iter()
            .filter_map(|(key, val)| {
                let spec = serde_json::from_value::<MountSpec>(val).ok()?;
                if spec.mount_type != "kv" {
                    return None;
                }
                let engine = match spec.options.version.as_str() {
                    "1" => EngineType::V1,
                    "2" => EngineType::V2,
                    _ => return None,
                };
                Some((key, engine))
            })
            .collect();
        Ok(MountInfo { mounts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets_file::Secret;

    #[test]
    fn test_vault_data_v2_parsing() {
        let json = serde_json::json!({
            "data": {
                "data": { "foo": "bar" },
                "metadata": { "version": 1 }
            }
        });
        let data: VaultData = serde_json::from_value(json).unwrap();
        assert_eq!(data.0.get("foo").unwrap().as_str().unwrap(), "bar");
    }

    #[test]
    fn test_vault_data_v1_parsing() {
        let json = serde_json::json!({ "data": { "foo": "bar" } });
        let data: VaultData = serde_json::from_value(json).unwrap();
        assert_eq!(data.0.get("foo").unwrap().as_str().unwrap(), "bar");
    }

    #[test]
    fn test_secret_path_v1() {
        let mi = MountInfo {
            mounts: [("secret/".to_string(), EngineType::V1)]
                .into_iter()
                .collect(),
        };
        let s = Secret {
            mount: "secret".to_string(),
            path: "foo/bar".to_string(),
            key: "baz".to_string(),
            var_name: "FOO".to_string(),
        };
        assert_eq!(mi.secret_path(&s), "/v1/secret/foo/bar");
    }

    #[test]
    fn test_secret_path_v2() {
        let mi = MountInfo {
            mounts: [("secret/".to_string(), EngineType::V2)]
                .into_iter()
                .collect(),
        };
        let s = Secret {
            mount: "secret".to_string(),
            path: "foo/bar".to_string(),
            key: "baz".to_string(),
            var_name: "FOO".to_string(),
        };
        assert_eq!(mi.secret_path(&s), "/v1/secret/data/foo/bar");
    }

    #[test]
    fn test_client_token_deserialization() {
        let json = serde_json::json!({
            "auth": { "client_token": "s.abc123" }
        });
        let token: ClientToken = serde_json::from_value(json).unwrap();
        assert_eq!(token.auth.client_token, "s.abc123");
    }
}

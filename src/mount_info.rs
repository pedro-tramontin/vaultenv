//! Mount information discovery.
//!
//! Maps mount prefixes (e.g. `"secret/"`) to their KV engine version.

use serde::Deserialize;
use std::collections::HashMap;

/// Vault KV engine type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineType {
    #[serde(rename = "1")]
    #[default]
    V1,
    #[serde(rename = "2")]
    V2,
}

/// A mapping from mount prefix → engine type.
#[derive(Debug, Clone)]
pub struct MountInfo(pub HashMap<String, EngineType>);

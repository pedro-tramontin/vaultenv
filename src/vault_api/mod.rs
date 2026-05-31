//! Vault HTTP API client.
//!
//! Handles authentication, mount info discovery, secret fetching,
//! response parsing, and retry logic.

pub mod client;
pub mod data;
pub mod error;
pub mod resolver;

pub use client::VaultClient;
pub use data::{ClientToken, EngineType, MountInfo, VaultData};
pub use error::VaultError;
pub use resolver::{deduplicate, resolve_secrets};

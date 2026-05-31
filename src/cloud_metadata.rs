//! Cloud instance metadata fetchers for Vault cloud auth backends.
//!
//! Covers Azure (MSI), GCP (GCE metadata), and AWS (EC2 IMDS).
//! All operations use plain HTTP — no external SDKs.

use anyhow::{Context, Result};
use serde::Deserialize;

// ═════════════════════════════════════════════════════════════════════════════
// Azure
// ═════════════════════════════════════════════════════════════════════════════

const AZURE_METADATA_ENDPOINT: &str = "http://169.254.169.254";
const AZURE_METADATA_API_VERSION: &str = "2021-05-01";

fn azure_metadata_endpoint() -> String {
    std::env::var("VAULTENV_AZURE_METADATA_ENDPOINT")
        .unwrap_or_else(|_| AZURE_METADATA_ENDPOINT.to_string())
}

/// Fetch a JWT token from the Azure Managed Service Identity endpoint.
pub async fn get_azure_jwt(resource: &str) -> Result<String> {
    let url = format!(
        "{}/metadata/identity/oauth2/token?api-version={}&resource={}",
        azure_metadata_endpoint(),
        AZURE_METADATA_API_VERSION,
        percent_encoding::utf8_percent_encode(resource, percent_encoding::NON_ALPHANUMERIC),
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("Metadata", "true")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("failed to request Azure MSI token")?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Azure MSI returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    #[derive(Debug, Deserialize)]
    struct MsiTokenResponse {
        access_token: String,
    }

    let body: MsiTokenResponse = resp
        .json()
        .await
        .context("failed to parse Azure MSI token response")?;

    Ok(body.access_token)
}

#[derive(Debug, Deserialize)]
pub struct AzureVmMetadata {
    pub name: String,
    #[serde(default)]
    pub vm_scale_set_name: String,
    #[serde(default)]
    pub subscription_id: String,
    #[serde(default)]
    pub resource_group_name: String,
}

/// Fetch Azure IMDS compute metadata (name, subscription, resource group, etc.).
pub async fn get_azure_vm_metadata() -> Result<AzureVmMetadata> {
    let url = format!(
        "{}/metadata/instance/compute?api-version={}",
        azure_metadata_endpoint(),
        AZURE_METADATA_API_VERSION
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("Metadata", "true")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("failed to request Azure VM metadata")?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Azure metadata returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let body: AzureVmMetadata = resp
        .json()
        .await
        .context("failed to parse Azure VM metadata response")?;

    Ok(body)
}

// ═════════════════════════════════════════════════════════════════════════════
// GCP (GCE)
// ═════════════════════════════════════════════════════════════════════════════

const GCE_METADATA_HOST: &str = "http://metadata.google.internal";
const GCE_IDENTITY_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/identity";

fn gce_metadata_host() -> String {
    std::env::var("VAULTENV_GCE_METADATA_HOST").unwrap_or_else(|_| GCE_METADATA_HOST.to_string())
}

/// Fetch an identity JWT from the GCE metadata service.
///
/// `audience` should be the Vault URL + `/vault/{role}` as expected by Vault.
pub async fn get_gce_jwt(audience: &str) -> Result<String> {
    let url = format!(
        "{}{}?audience={}&format=full",
        gce_metadata_host(),
        GCE_IDENTITY_PATH,
        percent_encoding::utf8_percent_encode(audience, percent_encoding::NON_ALPHANUMERIC),
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("failed to request GCE identity JWT")?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "GCE metadata returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let jwt = resp
        .text()
        .await
        .context("failed to read GCE identity JWT body")?;

    Ok(jwt.trim().to_string())
}

// ═════════════════════════════════════════════════════════════════════════════
// AWS (EC2 IMDS)
// ═════════════════════════════════════════════════════════════════════════════

const EC2_METADATA_ENDPOINT: &str = "http://169.254.169.254";

fn ec2_metadata_endpoint() -> String {
    std::env::var("VAULTENV_EC2_METADATA_ENDPOINT")
        .unwrap_or_else(|_| EC2_METADATA_ENDPOINT.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ec2SignatureType {
    /// PKCS #7 document (default).
    #[default]
    Pkcs7,
    /// Identity document + RSA signature.
    Identity,
    /// RSA 2048 PKCS#7 document.
    Rsa2048,
}

impl std::str::FromStr for Ec2SignatureType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "pkcs7" => Ok(Ec2SignatureType::Pkcs7),
            "identity" => Ok(Ec2SignatureType::Identity),
            "rsa2048" => Ok(Ec2SignatureType::Rsa2048),
            _ => Err(format!(
                "unknown EC2 signature type '{}', expected 'pkcs7', 'identity', or 'rsa2048'",
                s
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ec2SignatureTypeArg(pub Ec2SignatureType);

impl Default for Ec2SignatureTypeArg {
    fn default() -> Self {
        Ec2SignatureTypeArg(Ec2SignatureType::Pkcs7)
    }
}

impl std::str::FromStr for Ec2SignatureTypeArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ec2SignatureType::from_str(s).map(Ec2SignatureTypeArg)
    }
}

impl std::fmt::Display for Ec2SignatureTypeArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            Ec2SignatureType::Pkcs7 => "pkcs7",
            Ec2SignatureType::Identity => "identity",
            Ec2SignatureType::Rsa2048 => "rsa2048",
        };
        write!(f, "{}", s)
    }
}

/// Fetch EC2 metadata for the given signature type.
///
/// Returns a map of login fields for Vault AWS auth.
pub async fn get_ec2_metadata(
    sig: Ec2SignatureType,
) -> Result<std::collections::HashMap<String, String>> {
    let mut data = std::collections::HashMap::new();

    match sig {
        Ec2SignatureType::Pkcs7 => {
            let pkcs7 = fetch_ec2("/latest/dynamic/instance-identity/pkcs7").await?;
            data.insert("pkcs7".to_string(), pkcs7.trim().to_string());
        }
        Ec2SignatureType::Identity => {
            let doc = fetch_ec2("/latest/dynamic/instance-identity/document").await?;
            let sig = fetch_ec2("/latest/dynamic/instance-identity/signature").await?;
            data.insert(
                "identity".to_string(),
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, doc.as_bytes()),
            );
            data.insert("signature".to_string(), sig.trim().to_string());
        }
        Ec2SignatureType::Rsa2048 => {
            let pkcs7 = fetch_ec2("/latest/dynamic/instance-identity/rsa2048").await?;
            data.insert("pkcs7".to_string(), pkcs7.trim().to_string());
        }
    }

    Ok(data)
}

async fn fetch_ec2(path: &str) -> Result<String> {
    let url = format!("{}{}", ec2_metadata_endpoint(), path);
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("failed to request EC2 instance metadata")?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "EC2 IMDS returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let text = resp
        .text()
        .await
        .context("failed to read EC2 metadata response")?;
    Ok(text)
}

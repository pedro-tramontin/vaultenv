//! Real Vault integration tests using testcontainers.
//!
//! These tests run against an actual HashiCorp Vault container.
//! They are gated by the `VAULT_INTEGRATION_TEST` environment variable
//! and run only on CI for Release Please PRs.

use std::time::Duration;

use testcontainers::{
    GenericImage, ImageExt,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::time::sleep;
use vaultenv::{
    auth::AuthMethod,
    secrets_file::Secret,
    vault_api::{EngineType, MountInfo, VaultClient},
};

static ROOT_TOKEN: &str = "test-root-token";

/// Start a Vault dev container and return (host, port) for the API.
async fn start_vault_container() -> (String, u16) {
    let container = GenericImage::new("hashicorp/vault", "1.17")
        .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
        .with_exposed_port(ContainerPort::Tcp(8200))
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
        .with_env_var("VAULT_ADDR", "http://0.0.0.0:8200")
        .start()
        .await
        .expect("vault container starts");

    let host = container
        .get_host()
        .await
        .expect("host available")
        .to_string();
    let port = container
        .get_host_port_ipv4(8200)
        .await
        .expect("port mapped");
    (host, port)
}

/// Wait for Vault to be ready — the container log message isn't enough for
/// the HTTP port to be bound.
async fn wait_for_vault(client: &VaultClient) {
    for _ in 0..30 {
        if client.get_mount_info().await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(200)).await;
    }
    panic!("vault did not become ready in time");
}

#[tokio::test]
async fn test_real_vault_token_auth_and_mount_discovery() {
    if std::env::var("VAULT_INTEGRATION_TEST").is_err() {
        eprintln!("skipping: VAULT_INTEGRATION_TEST not set");
        return;
    }
    let (host, port) = start_vault_container().await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::VaultToken {
                token: ROOT_TOKEN.to_string(),
            },
            None,
        )
        .await
        .unwrap();

    wait_for_vault(&client).await;

    let mount_info = client.get_mount_info().await.unwrap();

    // Dev mode mounts `secret/` as KV v2 by default.
    let secret = Secret {
        mount: "secret".to_string(),
        path: "foo/bar".to_string(),
        key: "baz".to_string(),
        var_name: "FOO".to_string(),
    };
    assert_eq!(mount_info.secret_path(&secret), "/v1/secret/data/foo/bar");
}

#[tokio::test]
async fn test_real_vault_fetch_and_write_kv2() {
    if std::env::var("VAULT_INTEGRATION_TEST").is_err() {
        eprintln!("skipping: VAULT_INTEGRATION_TEST not set");
        return;
    }
    let (host, port) = start_vault_container().await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::VaultToken {
                token: ROOT_TOKEN.to_string(),
            },
            None,
        )
        .await
        .unwrap();

    wait_for_vault(&client).await;

    // Write a secret via raw HTTP first — vaultenv only reads.
    let req = reqwest::Client::new()
        .post(format!("http://{host}:{port}/v1/secret/data/app/config"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&serde_json::json!({ "data": { "api_key": "real-secret-123" } }))
        .send()
        .await
        .expect("write succeeds");
    assert!(req.status().is_success());

    let mount_info = MountInfo::from_map(
        [("secret/".to_string(), EngineType::V2)]
            .into_iter()
            .collect(),
    );

    let secret = Secret {
        mount: "secret".to_string(),
        path: "app/config".to_string(),
        key: "api_key".to_string(),
        var_name: "API_KEY".to_string(),
    };

    let data = client.get_secret(&mount_info, &secret).await.unwrap();
    assert_eq!(
        data.0.get("api_key").unwrap().as_str().unwrap(),
        "real-secret-123"
    );
}

#[tokio::test]
async fn test_real_vault_approle_auth() {
    if std::env::var("VAULT_INTEGRATION_TEST").is_err() {
        eprintln!("skipping: VAULT_INTEGRATION_TEST not set");
        return;
    }
    let (host, port) = start_vault_container().await;

    // Set up AppRole via raw HTTP — create backend, role, and fetch secret_id.
    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");

    // Enable approle auth method.
    let resp = http
        .post(format!("{base}/v1/sys/auth/approle"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&serde_json::json!({ "type": "approle" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Create a role.
    let resp = http
        .put(format!("{base}/v1/auth/approle/role/testrole"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&serde_json::json!({ "policies": ["default"], "token_ttl": "1h" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Get role_id.
    let resp = http
        .get(format!("{base}/v1/auth/approle/role/testrole/role-id"))
        .header("x-vault-token", ROOT_TOKEN)
        .send()
        .await
        .unwrap();
    let role_id = resp.json::<serde_json::Value>().await.unwrap()["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Get secret_id.
    let resp = http
        .post(format!("{base}/v1/auth/approle/role/testrole/secret-id"))
        .header("x-vault-token", ROOT_TOKEN)
        .send()
        .await
        .unwrap();
    let secret_id = resp.json::<serde_json::Value>().await.unwrap()["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Authenticate via vaultenv client.
    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(&AuthMethod::AppRole { role_id, secret_id }, Some("approle"))
        .await
        .unwrap();

    assert!(client.token().is_some());
}

#[tokio::test]
async fn test_real_vault_concurrent_fetch() {
    if std::env::var("VAULT_INTEGRATION_TEST").is_err() {
        eprintln!("skipping: VAULT_INTEGRATION_TEST not set");
        return;
    }
    let (host, port) = start_vault_container().await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::VaultToken {
                token: ROOT_TOKEN.to_string(),
            },
            None,
        )
        .await
        .unwrap();

    wait_for_vault(&client).await;

    // Write multiple secrets.
    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");
    for i in 0..5 {
        let resp = http
            .post(format!("{base}/v1/secret/data/concurrent/{i}"))
            .header("x-vault-token", ROOT_TOKEN)
            .json(&serde_json::json!({
                "data": { "value": format!("val-{i}") }
            }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    let mount_info = MountInfo::from_map(
        [("secret/".to_string(), EngineType::V2)]
            .into_iter()
            .collect(),
    );

    let secrets: Vec<Secret> = (0..5)
        .map(|i| Secret {
            mount: "secret".to_string(),
            path: format!("concurrent/{i}"),
            key: "value".to_string(),
            var_name: format!("V{i}"),
        })
        .collect();

    let results = client.get_secrets(&mount_info, &secrets, 4).await.unwrap();
    assert_eq!(results.len(), 5);
}

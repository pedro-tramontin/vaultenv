//! Real Vault integration tests using testcontainers.
//!
//! These tests run against an actual HashiCorp Vault container.
//! They are gated by the `VAULT_INTEGRATION_TEST` environment variable
//! and run only on CI for Release Please PRs.
//!
//! All tests share **one** Vault container (started lazily on first use) and
//! are serialised via `VAULT_LOCK` to avoid Docker resource exhaustion and
//! state collisions between tests.

use std::time::Duration;

use serde_json::json;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::time::sleep;
use vaultenv::{
    auth::AuthMethod,
    cloud_metadata::Ec2SignatureType,
    secrets_file::Secret,
    vault_api::{EngineType, MountInfo, VaultClient},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

static ROOT_TOKEN: &str = "test-root-token";

/// Global lock that serialises all real-Vault tests.
/// One shared container is cheaper and more stable than 16 concurrent ones.
static VAULT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Global lock for tests that mutate process environment variables.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Lazily-started shared Vault container.
static SHARED_VAULT: tokio::sync::Mutex<Option<(String, u16, ContainerAsync<GenericImage>)>> =
    tokio::sync::Mutex::const_new(None);

/// Skip test unless `VAULT_INTEGRATION_TEST` is set.
fn skip_unless_integration() -> bool {
    if std::env::var("VAULT_INTEGRATION_TEST").is_err() {
        eprintln!("skipping: VAULT_INTEGRATION_TEST not set");
        return true;
    }
    false
}

// ── shared helpers ─────────────────────────────────────────────────────────

/// Start a Vault dev container.
async fn start_vault_container() -> (String, u16, ContainerAsync<GenericImage>) {
    let container = GenericImage::new("hashicorp/vault", "1.17")
        .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
        .with_exposed_port(ContainerPort::Tcp(8200))
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
        .with_env_var("VAULT_ADDR", "http://0.0.0.0:8200")
        .with_label("vaultenv.test", "true")
        .with_label("vaultenv.purpose", "integration-test")
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
    (host, port, container)
}

/// Get or start the shared Vault container. All tests reuse one instance.
async fn shared_vault() -> (String, u16) {
    let mut guard = SHARED_VAULT.lock().await;
    if let Some((host, port, _)) = guard.as_ref() {
        return (host.clone(), *port);
    }
    let (host, port, container) = start_vault_container().await;
    // Warm up — generous timeout because cold container startup can take >30 s.
    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    for _ in 0..120 {
        if client.get_mount_info().await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    *guard = Some((host.clone(), port, container));
    (host, port)
}

/// Sign a JWT signing input with an RSA private key using openssl CLI.
fn sign_with_openssl(key_path: &std::path::Path, data: &str) -> String {
    use std::process::Command;
    let mut child = Command::new("openssl")
        .args(["dgst", "-sha256", "-sign", key_path.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("openssl dgst available");
    {
        let stdin = child.stdin.take().expect("stdin");
        use std::io::Write;
        let mut stdin = stdin;
        stdin.write_all(data.as_bytes()).unwrap();
        // stdin drops here, closing the pipe
    }
    let output = child.wait_with_output().expect("openssl completes");
    assert!(
        output.status.success(),
        "openssl dgst failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &output.stdout,
    )
}

// ── secret helpers ─────────────────────────────────────────────────────────

async fn write_secret_kv2(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    mount: &str,
    path: &str,
    key: &str,
    value: &str,
) {
    let resp = http
        .post(format!("{base}/v1/{mount}/data/{path}"))
        .header("x-vault-token", token)
        .json(&json!({ "data": { key: value } }))
        .send()
        .await
        .expect("write succeeds");
    assert!(
        resp.status().is_success(),
        "kv2 write failed: {}",
        resp.text().await.unwrap_or_default()
    );
}

async fn write_secret_kv1(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    mount: &str,
    path: &str,
    key: &str,
    value: &str,
) {
    let resp = http
        .post(format!("{base}/v1/{mount}/{path}"))
        .header("x-vault-token", token)
        .json(&json!({ key: value }))
        .send()
        .await
        .expect("write succeeds");
    assert!(
        resp.status().is_success(),
        "kv1 write failed: {}",
        resp.text().await.unwrap_or_default()
    );
}

async fn enable_kv_v1(http: &reqwest::Client, base: &str, token: &str, mount: &str) {
    let resp = http
        .post(format!("{base}/v1/sys/mounts/{mount}"))
        .header("x-vault-token", token)
        .json(&json!({ "type": "kv", "options": { "version": "1" } }))
        .send()
        .await
        .expect("mount succeeds");
    assert!(
        resp.status().is_success(),
        "kv1 mount failed: {}",
        resp.text().await.unwrap_or_default()
    );
}

// ── authentication tests ───────────────────────────────────────────────────

#[tokio::test]
async fn test_real_vault_token_auth_and_mount_discovery() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

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

    let mount_info = client.get_mount_info().await.unwrap();

    let secret = Secret {
        mount: "secret".to_string(),
        path: "foo/bar".to_string(),
        key: "baz".to_string(),
        var_name: "FOO".to_string(),
    };
    assert_eq!(mount_info.secret_path(&secret), "/v1/secret/data/foo/bar");
}

#[tokio::test]
async fn test_real_vault_approle_auth() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");

    let resp = http
        .post(format!("{base}/v1/sys/auth/approle"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({ "type": "approle" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let resp = http
        .put(format!("{base}/v1/auth/approle/role/testrole"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({ "policies": ["default"], "token_ttl": "1h" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

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

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(&AuthMethod::AppRole { role_id, secret_id }, Some("approle"))
        .await
        .unwrap();

    assert!(client.token().is_some());
}

#[tokio::test]
async fn test_real_vault_jwt_auth() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

    let tmp = tempfile::tempdir().unwrap();
    let priv_path = tmp.path().join("private.pem");
    let pub_path = tmp.path().join("public.pem");

    let openssl = std::process::Command::new("openssl")
        .args(["genrsa", "-out", priv_path.to_str().unwrap(), "2048"])
        .status()
        .expect("openssl must be available for JWT test key generation");
    assert!(openssl.success(), "openssl genrsa failed");

    let openssl = std::process::Command::new("openssl")
        .args([
            "rsa",
            "-in",
            priv_path.to_str().unwrap(),
            "-pubout",
            "-out",
            pub_path.to_str().unwrap(),
        ])
        .status()
        .expect("openssl rsa failed");
    assert!(openssl.success(), "openssl rsa -pubout failed");

    let pub_pem = tokio::fs::read_to_string(&pub_path).await.unwrap();

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");

    let resp = http
        .post(format!("{base}/v1/sys/auth/jwt"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({ "type": "jwt" }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "enable jwt auth failed: {:?}",
        resp.text().await
    );

    let resp = http
        .post(format!("{base}/v1/auth/jwt/config"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({ "jwt_validation_pubkeys": [pub_pem.trim()] }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "jwt config failed: {:?}",
        resp.text().await
    );

    let resp = http
        .post(format!("{base}/v1/auth/jwt/role/testrole"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "role_type": "jwt",
            "bound_subject": "test-subject",
            "user_claim": "sub",
            "token_policies": ["default"]
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "jwt role create failed: {:?}",
        resp.text().await
    );

    let header_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_string(&json!({"alg":"RS256","typ":"JWT"}))
            .unwrap()
            .as_bytes(),
    );

    let claims = json!({
        "sub": "test-subject",
        "iss": "test-issuer",
        "nbf": (std::time::SystemTime::now() - std::time::Duration::from_secs(60))
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "exp": (std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let claims_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_string(&claims).unwrap().as_bytes(),
    );

    let sig_input = format!("{header_b64}.{claims_b64}");
    let sig = sign_with_openssl(&priv_path, &sig_input);
    let token = format!("{sig_input}.{sig}");

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::Jwt {
                role: "testrole".into(),
                token,
            },
            Some("jwt"),
        )
        .await
        .unwrap();

    assert!(client.token().is_some());
}

#[tokio::test]
async fn test_real_vault_kubernetes_auth() {
    if skip_unless_integration() {
        return;
    }
    // Vault's Kubernetes auth method requires a real Kubernetes TokenReview API
    // to verify the JWT after signature validation. Since testcontainers can't
    // provide a real k8s control plane, we skip this test. The request shape is
    // covered by wiremock tests in vault_api_mocked.rs.
    eprintln!("skipping real kubernetes auth: requires real Kubernetes API access");
}

#[tokio::test]
async fn test_real_vault_github_auth_skipped() {
    if skip_unless_integration() {
        return;
    }
    // GitHub auth requires Vault to call the real GitHub API (api.github.com).
    // We cannot mock this inside the testcontainer without network interception.
    // The wiremock tests in vault_api_mocked.rs cover the request shape.
    eprintln!("skipping real GitHub auth: requires real GitHub API access");
}

#[tokio::test]
async fn test_real_vault_azure_auth() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

    let _env_guard = ENV_LOCK.lock().await;
    let metadata_server = MockServer::start().await;
    let metadata_uri = metadata_server.uri();

    unsafe {
        std::env::set_var("VAULTENV_AZURE_METADATA_ENDPOINT", &metadata_uri);
    }

    Mock::given(method("GET"))
        .and(path("/metadata/identity/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fake-azure-jwt-123"
        })))
        .mount(&metadata_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/metadata/instance/compute"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "vm-01",
            "subscriptionId": "sub-123",
            "resourceGroupName": "rg-01"
        })))
        .mount(&metadata_server)
        .await;

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");

    let resp = http
        .post(format!("{base}/v1/sys/auth/azure"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({ "type": "azure" }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "enable azure auth failed: {:?}",
        resp.text().await
    );

    let resp = http
        .post(format!("{base}/v1/auth/azure/config"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "tenant_id": "fake-tenant-123",
            "resource": "https://management.azure.com/",
            "client_id": "fake-client"
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "azure config failed: {:?}",
        resp.text().await
    );

    let resp = http
        .post(format!("{base}/v1/auth/azure/role/testrole"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "policies": ["default"],
            "bound_subscription_ids": ["sub-123"]
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "azure role create failed: {:?}",
        resp.text().await
    );

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let err = client
        .authenticate(
            &AuthMethod::Azure {
                role: "testrole".into(),
                resource: Some("https://management.azure.com/".into()),
            },
            Some("azure"),
        )
        .await
        .unwrap_err();

    let err_msg = format!("{err}").to_lowercase();
    assert!(
        err_msg.contains("error")
            || err_msg.contains("invalid")
            || err_msg.contains("unauthorized"),
        "expected Vault to reject the fake Azure JWT, got: {err}"
    );
}

#[tokio::test]
async fn test_real_vault_gcp_auth() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

    let _env_guard = ENV_LOCK.lock().await;
    let metadata_server = MockServer::start().await;
    let metadata_uri = metadata_server.uri();

    unsafe {
        std::env::set_var("VAULTENV_GCE_METADATA_HOST", &metadata_uri);
    }

    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/identity",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("fake-gcp-jwt-123"))
        .mount(&metadata_server)
        .await;

    // Generate a dummy RSA key for the fake service account credentials.
    let tmp = tempfile::tempdir().unwrap();
    let priv_path = tmp.path().join("gcp_private.pem");
    let openssl = std::process::Command::new("openssl")
        .args(["genrsa", "-out", priv_path.to_str().unwrap(), "2048"])
        .status()
        .expect("openssl available");
    assert!(openssl.success());

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");

    let resp = http
        .post(format!("{base}/v1/sys/auth/gcp"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({ "type": "gcp" }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "enable gcp auth failed: {:?}",
        resp.text().await
    );

    // Reuse the private key as a fake Google service account key.
    let fake_sa = json!({
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "fake-key-id",
        "private_key": tokio::fs::read_to_string(&priv_path).await.unwrap().trim(),
        "client_email": "test-sa@test-project.iam.gserviceaccount.com",
        "client_id": "123456789",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    });
    let resp = http
        .post(format!("{base}/v1/auth/gcp/config"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "credentials": fake_sa.to_string(),
            "gce_alias": "instance_id"
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "gcp config failed: {:?}",
        resp.text().await
    );

    let resp = http
        .post(format!("{base}/v1/auth/gcp/role/testrole"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "type": "gce",
            "policies": ["default"],
            "bound_service_accounts": ["test-sa@project.iam.gserviceaccount.com"],
            "bound_projects": ["test-project"],
            "bound_zones": ["us-central1-a"]
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "gcp role create failed: {:?}",
        resp.text().await
    );

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let err = client
        .authenticate(
            &AuthMethod::Gcp {
                role: "testrole".into(),
            },
            Some("gcp"),
        )
        .await
        .unwrap_err();

    let err_msg = format!("{err}").to_lowercase();
    assert!(
        err_msg.contains("error")
            || err_msg.contains("invalid")
            || err_msg.contains("unauthorized"),
        "expected Vault to reject the fake GCP JWT, got: {err}"
    );
}

#[tokio::test]
async fn test_real_vault_aws_ec2_auth() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

    let _env_guard = ENV_LOCK.lock().await;
    let metadata_server = MockServer::start().await;
    let metadata_uri = metadata_server.uri();

    unsafe {
        std::env::set_var("VAULTENV_EC2_METADATA_ENDPOINT", &metadata_uri);
    }

    Mock::given(method("GET"))
        .and(path("/latest/dynamic/instance-identity/pkcs7"))
        .respond_with(ResponseTemplate::new(200).set_body_string("fake-pkcs7-123"))
        .mount(&metadata_server)
        .await;

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");

    let resp = http
        .post(format!("{base}/v1/sys/auth/aws"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({ "type": "aws" }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "enable aws auth failed: {:?}",
        resp.text().await
    );

    let resp = http
        .post(format!("{base}/v1/auth/aws/config/client"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "access_key": "fake-access",
            "secret_key": "fake-secret",
            "region": "us-east-1"
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "aws client config failed: {:?}",
        resp.text().await
    );

    let resp = http
        .post(format!("{base}/v1/auth/aws/role/testrole"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "auth_type": "ec2",
            "bound_account_id": "123456789012",
            "policies": ["default"]
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "aws role create failed: {:?}",
        resp.text().await
    );

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let err = client
        .authenticate(
            &AuthMethod::AwsEc2 {
                role: "testrole".into(),
                signature_type: Ec2SignatureType::Pkcs7,
            },
            Some("aws"),
        )
        .await
        .unwrap_err();

    let err_msg = format!("{err}").to_lowercase();
    assert!(
        err_msg.contains("error")
            || err_msg.contains("invalid")
            || err_msg.contains("unauthorized"),
        "expected Vault to reject the fake AWS credentials, got: {err}"
    );
}

// ── secret retrieval tests ─────────────────────────────────────────────────

#[tokio::test]
async fn test_real_vault_fetch_and_write_kv2() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

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

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");
    write_secret_kv2(
        &http,
        &base,
        ROOT_TOKEN,
        "secret",
        "app/config",
        "api_key",
        "real-secret-123",
    )
    .await;

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
async fn test_real_vault_kv1_fetch() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

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

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");
    enable_kv_v1(&http, &base, ROOT_TOKEN, "kv1").await;
    write_secret_kv1(
        &http,
        &base,
        ROOT_TOKEN,
        "kv1",
        "app/config",
        "api_key",
        "kv1-secret",
    )
    .await;

    let mount_info =
        MountInfo::from_map([("kv1/".to_string(), EngineType::V1)].into_iter().collect());
    let secret = Secret {
        mount: "kv1".to_string(),
        path: "app/config".to_string(),
        key: "api_key".to_string(),
        var_name: "API_KEY".to_string(),
    };

    let data = client.get_secret(&mount_info, &secret).await.unwrap();
    assert_eq!(
        data.0.get("api_key").unwrap().as_str().unwrap(),
        "kv1-secret"
    );
}

#[tokio::test]
async fn test_real_vault_secret_not_found() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

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

    let mount_info = MountInfo::from_map(
        [("secret/".to_string(), EngineType::V2)]
            .into_iter()
            .collect(),
    );
    let secret = Secret {
        mount: "secret".to_string(),
        path: "app/nonexistent".to_string(),
        key: "key".to_string(),
        var_name: "MISSING".to_string(),
    };

    let err = client.get_secret(&mount_info, &secret).await.unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("not found"));
}

#[tokio::test]
async fn test_real_vault_forbidden_policy() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");

    let resp = http
        .put(format!("{base}/v1/sys/policies/acl/limited"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "policy": r#"
                path "secret/data/foo/*" {
                    capabilities = ["read"]
                }
            "#
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let resp = http
        .post(format!("{base}/v1/auth/token/create"))
        .header("x-vault-token", ROOT_TOKEN)
        .json(&json!({
            "policies": ["limited"],
            "ttl": "1h"
        }))
        .send()
        .await
        .unwrap();
    let limited_token = resp.json::<serde_json::Value>().await.unwrap()["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_string();

    write_secret_kv2(
        &http,
        &base,
        ROOT_TOKEN,
        "secret",
        "foo/allowed",
        "key",
        "val",
    )
    .await;
    write_secret_kv2(
        &http,
        &base,
        ROOT_TOKEN,
        "secret",
        "bar/denied",
        "key",
        "val",
    )
    .await;

    let client = VaultClient::new(&host, port, false, Some(limited_token), 40, 9).unwrap();

    let mount_info = MountInfo::from_map(
        [("secret/".to_string(), EngineType::V2)]
            .into_iter()
            .collect(),
    );

    let secret = Secret {
        mount: "secret".to_string(),
        path: "foo/allowed".to_string(),
        key: "key".to_string(),
        var_name: "ALLOWED".to_string(),
    };
    let data = client.get_secret(&mount_info, &secret).await.unwrap();
    assert_eq!(data.0.get("key").unwrap().as_str().unwrap(), "val");

    let secret = Secret {
        mount: "secret".to_string(),
        path: "bar/denied".to_string(),
        key: "key".to_string(),
        var_name: "DENIED".to_string(),
    };
    let err = client.get_secret(&mount_info, &secret).await.unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("forbidden"));
}

#[tokio::test]
async fn test_real_vault_mixed_mounts() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

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

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");

    enable_kv_v1(&http, &base, ROOT_TOKEN, "legacy").await;
    write_secret_kv1(
        &http,
        &base,
        ROOT_TOKEN,
        "legacy",
        "old/config",
        "password",
        "hunter2",
    )
    .await;
    write_secret_kv2(
        &http,
        &base,
        ROOT_TOKEN,
        "secret",
        "new/config",
        "api_key",
        "shh",
    )
    .await;

    let mount_info = MountInfo::from_map(
        [
            ("secret/".to_string(), EngineType::V2),
            ("legacy/".to_string(), EngineType::V1),
        ]
        .into_iter()
        .collect(),
    );

    let secrets = vec![
        Secret {
            mount: "secret".to_string(),
            path: "new/config".to_string(),
            key: "api_key".to_string(),
            var_name: "NEW".to_string(),
        },
        Secret {
            mount: "legacy".to_string(),
            path: "old/config".to_string(),
            key: "password".to_string(),
            var_name: "OLD".to_string(),
        },
    ];

    let results = client.get_secrets(&mount_info, &secrets, 2).await.unwrap();
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_real_vault_get_secrets_empty() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

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

    let mount_info = MountInfo::from_map(
        [("secret/".to_string(), EngineType::V2)]
            .into_iter()
            .collect(),
    );
    let results = client.get_secrets(&mount_info, &[], 4).await.unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_real_vault_get_secrets_low_concurrency() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

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

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");
    for i in 0..3 {
        write_secret_kv2(
            &http,
            &base,
            ROOT_TOKEN,
            "secret",
            &format!("seq/{i}"),
            "val",
            &format!("v{i}"),
        )
        .await;
    }

    let mount_info = MountInfo::from_map(
        [("secret/".to_string(), EngineType::V2)]
            .into_iter()
            .collect(),
    );
    let secrets: Vec<Secret> = (0..3)
        .map(|i| Secret {
            mount: "secret".to_string(),
            path: format!("seq/{i}"),
            key: "val".to_string(),
            var_name: format!("V{i}"),
        })
        .collect();

    let results = client.get_secrets(&mount_info, &secrets, 1).await.unwrap();
    assert_eq!(results.len(), 3);
}

#[tokio::test]
async fn test_real_vault_concurrent_fetch() {
    if skip_unless_integration() {
        return;
    }
    let _guard = VAULT_LOCK.lock().await;
    let (host, port) = shared_vault().await;

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

    let http = reqwest::Client::new();
    let base = format!("http://{host}:{port}");
    for i in 0..5 {
        write_secret_kv2(
            &http,
            &base,
            ROOT_TOKEN,
            "secret",
            &format!("concurrent/{i}"),
            "value",
            &format!("val-{i}"),
        )
        .await;
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

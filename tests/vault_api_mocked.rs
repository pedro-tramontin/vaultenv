use reqwest::Url;
use serde_json::json;
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

/// Global lock for tests that mutate process environment variables.
/// Wiremock tests run in parallel by default; `std::env::set_var` is not thread-safe.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn parse_uri(uri: &str) -> (String, u16) {
    let url = Url::parse(uri).expect("valid mock URI");
    let host = url.host_str().unwrap_or("localhost").to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    (host, port)
}

#[tokio::test]
async fn test_github_auth_success() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "gh-token-123" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(&AuthMethod::GitHub("ghp_xxx".into()), Some("github"))
        .await
        .unwrap();

    assert_eq!(client.token(), Some("gh-token-123"));
}

#[tokio::test]
async fn test_github_auth_failure_403() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let err = client
        .authenticate(&AuthMethod::GitHub("bad_token".into()), Some("github"))
        .await
        .unwrap_err();

    assert!(format!("{err}").contains("forbidden"));
}

#[tokio::test]
async fn test_mount_info_discovery() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "secret/": {
                "type": "kv",
                "options": { "version": "2" }
            }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 40, 9).unwrap();
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
async fn test_fetch_secret_kv2() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "api_key": "shh-secret" } }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 40, 9).unwrap();
    let mount_info = MountInfo::from_map([("secret/".to_string(), EngineType::V2)].into());

    let secret = Secret {
        mount: "secret".to_string(),
        path: "app/config".to_string(),
        key: "api_key".to_string(),
        var_name: "API_KEY".to_string(),
    };

    let data = client.get_secret(&mount_info, &secret).await.unwrap();
    assert_eq!(
        data.0.get("api_key").unwrap().as_str().unwrap(),
        "shh-secret"
    );
}

#[tokio::test]
async fn test_fetch_secret_kv1() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/secret/app/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "api_key": "old-secret" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 40, 9).unwrap();
    let mount_info = MountInfo::from_map([("secret/".to_string(), EngineType::V1)].into());

    let secret = Secret {
        mount: "secret".to_string(),
        path: "app/config".to_string(),
        key: "api_key".to_string(),
        var_name: "API_KEY".to_string(),
    };

    let data = client.get_secret(&mount_info, &secret).await.unwrap();
    assert_eq!(
        data.0.get("api_key").unwrap().as_str().unwrap(),
        "old-secret"
    );
}

#[tokio::test]
async fn test_secret_not_found_404() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app/404"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 40, 9).unwrap();
    let mount_info = MountInfo::from_map([("secret/".to_string(), EngineType::V2)].into());

    let secret = Secret {
        mount: "secret".to_string(),
        path: "app/404".to_string(),
        key: "api_key".to_string(),
        var_name: "API_KEY".to_string(),
    };

    let err = client.get_secret(&mount_info, &secret).await.unwrap_err();
    assert!(format!("{err}").contains("not found"));
}

#[tokio::test]
async fn test_retry_on_503_then_success() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    // First call fails, second succeeds
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app/flaky"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app/flaky"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "key": "recovered" } }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 40, 1).unwrap();
    let mount_info = MountInfo::from_map([("secret/".to_string(), EngineType::V2)].into());

    let secret = Secret {
        mount: "secret".to_string(),
        path: "app/flaky".to_string(),
        key: "key".to_string(),
        var_name: "FLAKY".to_string(),
    };

    let data = client.get_secret(&mount_info, &secret).await.unwrap();
    assert_eq!(data.0.get("key").unwrap().as_str().unwrap(), "recovered");
}

#[tokio::test]
async fn test_concurrent_fetch() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/a"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "key": "alpha" } }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/b"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "key": "beta" } }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 40, 9).unwrap();
    let mount_info = MountInfo::from_map([("secret/".to_string(), EngineType::V2)].into());

    let secrets = vec![
        Secret {
            mount: "secret".to_string(),
            path: "a".to_string(),
            key: "key".to_string(),
            var_name: "A".to_string(),
        },
        Secret {
            mount: "secret".to_string(),
            path: "b".to_string(),
            key: "key".to_string(),
            var_name: "B".to_string(),
        },
    ];

    let results = client.get_secrets(&mount_info, &secrets, 8).await.unwrap();
    assert_eq!(results.len(), 2);
}

// ---------------------------------------------------------------------------
// AppRole, LDAP, Okta
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_approle_auth_success() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "approle-token-123" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::AppRole {
                role_id: "role-123".into(),
                secret_id: "secret-456".into(),
            },
            Some("approle"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("approle-token-123"));
}

#[tokio::test]
async fn test_ldap_auth_success() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/ldap/login/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "ldap-token-123" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::Ldap {
                username: "alice".into(),
                password: "p@ss".into(),
            },
            Some("ldap"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("ldap-token-123"));
}

#[tokio::test]
async fn test_okta_auth_success() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/okta/login/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "okta-token-123" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::Okta {
                username: "alice".into(),
                password: "p@ss".into(),
            },
            Some("okta"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("okta-token-123"));
}

// ---------------------------------------------------------------------------
// Cloud auth (Azure / GCP / AWS EC2 instance metadata)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_azure_auth_success() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    unsafe {
        std::env::set_var("VAULTENV_AZURE_METADATA_ENDPOINT", server.uri());
    }

    Mock::given(method("GET"))
        .and(path("/metadata/identity/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "msi-jwt-123"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/metadata/instance/compute"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "vm-01",
            "subscriptionId": "sub-123",
            "resourceGroupName": "rg-01"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/azure/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "azure-token-123" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::Azure {
                role: "web-role".into(),
                resource: Some("https://management.azure.com/".into()),
            },
            Some("azure"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("azure-token-123"));
}

#[tokio::test]
async fn test_gcp_gce_auth_success() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    unsafe {
        std::env::set_var("VAULTENV_GCE_METADATA_HOST", server.uri());
    }

    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/identity",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("gce-jwt-123"))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/gcp/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "gcp-token-123" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::Gcp {
                role: "web-role".into(),
            },
            Some("gcp"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("gcp-token-123"));
}

#[tokio::test]
async fn test_aws_ec2_auth_success() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    unsafe {
        std::env::set_var("VAULTENV_EC2_METADATA_ENDPOINT", server.uri());
    }

    Mock::given(method("GET"))
        .and(path("/latest/dynamic/instance-identity/pkcs7"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pkcs7-payload"))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/aws/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "aws-token-123" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::AwsEc2 {
                role: "web-role".into(),
                signature_type: Ec2SignatureType::Pkcs7,
            },
            Some("aws"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("aws-token-123"));
}

#[tokio::test]
async fn test_jwt_auth_success() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "jwt-token-123" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::Jwt {
                role: "ci-role".into(),
                token: "id-jwt-abc".into(),
            },
            Some("jwt"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("jwt-token-123"));
}

#[tokio::test]
async fn test_jwt_auth_failure_400() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(ResponseTemplate::new(400).set_body_string("invalid jwt"))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let err = client
        .authenticate(
            &AuthMethod::Jwt {
                role: "ci-role".into(),
                token: "bad-jwt".into(),
            },
            Some("jwt"),
        )
        .await
        .unwrap_err();

    assert!(format!("{err}").contains("invalid jwt"));
}

#[tokio::test]
async fn test_jwt_auth_with_oidc_backend_path() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/oidc/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "oidc-token-456" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::Jwt {
                role: "ci-role".into(),
                token: "id-jwt-xyz".into(),
            },
            Some("oidc"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("oidc-token-456"));
}

// ---------------------------------------------------------------------------
// Builder method integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_builder_with_host_redirects_requests() {
    let server_a = MockServer::start().await;
    let server_b = MockServer::start().await;
    let (host_a, port_a) = parse_uri(&server_a.uri());
    let (host_b, port_b) = parse_uri(&server_b.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "token-a" }
        })))
        .mount(&server_a)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "token-b" }
        })))
        .mount(&server_b)
        .await;

    let client = VaultClient::new(&host_a, port_a, false, None, 40, 9).unwrap();
    let on_a = client
        .authenticate(&AuthMethod::GitHub("ghp_xxx".into()), Some("github"))
        .await
        .unwrap();
    assert_eq!(on_a.token(), Some("token-a"));

    let on_b = client
        .with_host(&host_b)
        .unwrap()
        .with_port(port_b)
        .unwrap();
    let on_b = on_b
        .authenticate(&AuthMethod::GitHub("ghp_xxx".into()), Some("github"))
        .await
        .unwrap();
    assert_eq!(on_b.token(), Some("token-b"));
}

#[tokio::test]
async fn test_builder_with_port_redirects_requests() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "port-token" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, 9999, false, None, 40, 9).unwrap();
    let client2 = client.with_port(port).unwrap();
    let client2 = client2
        .authenticate(&AuthMethod::GitHub("ghp_xxx".into()), Some("github"))
        .await
        .unwrap();
    assert_eq!(client2.token(), Some("port-token"));
}

#[tokio::test]
async fn test_builder_with_retry_attempts_limits_retries() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    // Three consecutive 503s.
    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(3)
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 1).unwrap();
    let err = client
        .authenticate(&AuthMethod::GitHub("ghp_xxx".into()), Some("github"))
        .await
        .unwrap_err();

    // With max_times=1 the retry happens once (original + 1 retry), still fails.
    let msg = format!("{err}");
    assert!(
        msg.contains("internal Vault error")
            || msg.contains("Vault is unavailable")
            || msg.contains("503")
    );

    // Now set max_times=0 — backon should not retry at all.
    let client_no_retry = client.with_retry_attempts(0);
    let err_no_retry = client_no_retry
        .authenticate(&AuthMethod::GitHub("ghp_xxx".into()), Some("github"))
        .await
        .unwrap_err();
    let msg2 = format!("{err_no_retry}");
    assert!(
        msg2.contains("internal Vault error")
            || msg2.contains("Vault is unavailable")
            || msg2.contains("503")
    );
}

#[tokio::test]
async fn test_auth_method_none_skips_login() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    // No mocks mounted — any request would fail.
    let client = VaultClient::new(&host, port, false, Some("existing".into()), 40, 9).unwrap();
    let client2 = client.authenticate(&AuthMethod::None, None).await.unwrap();

    // None should preserve whatever token was already present.
    assert_eq!(client2.token(), Some("existing"));
}

#[tokio::test]
async fn test_vault_token_auth_reuses_client_token() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    // No mocks — token auth does not hit the server.
    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client2 = client
        .authenticate(
            &AuthMethod::VaultToken {
                token: "direct-token".to_string(),
            },
            None,
        )
        .await
        .unwrap();

    assert_eq!(client2.token(), Some("direct-token"));
}

// ---------------------------------------------------------------------------
// Cloud auth edge cases (failure paths + alternate signature types)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_azure_auth_failure_when_msi_returns_500() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    unsafe {
        std::env::set_var("VAULTENV_AZURE_METADATA_ENDPOINT", server.uri());
    }

    Mock::given(method("GET"))
        .and(path("/metadata/identity/oauth2/token"))
        .respond_with(ResponseTemplate::new(500).set_body_string("msi outage"))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let err = client
        .authenticate(
            &AuthMethod::Azure {
                role: "web-role".into(),
                resource: Some("https://management.azure.com/".into()),
            },
            Some("azure"),
        )
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(msg.contains("cloud metadata failed") || msg.contains("cloud metadata fetch failed"));
}

#[tokio::test]
async fn test_gcp_auth_failure_when_metadata_returns_500() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    unsafe {
        std::env::set_var("VAULTENV_GCE_METADATA_HOST", server.uri());
    }

    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/identity",
        ))
        .respond_with(ResponseTemplate::new(500).set_body_string("metadata outage"))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let err = client
        .authenticate(
            &AuthMethod::Gcp {
                role: "web-role".into(),
            },
            Some("gcp"),
        )
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(msg.contains("cloud metadata failed") || msg.contains("cloud metadata fetch failed"));
}

#[tokio::test]
async fn test_aws_ec2_identity_signature_type() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    unsafe {
        std::env::set_var("VAULTENV_EC2_METADATA_ENDPOINT", server.uri());
    }

    Mock::given(method("GET"))
        .and(path("/latest/dynamic/instance-identity/document"))
        .respond_with(ResponseTemplate::new(200).set_body_string("identity-doc"))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/latest/dynamic/instance-identity/signature"))
        .respond_with(ResponseTemplate::new(200).set_body_string("rsa-sig"))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/aws/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "aws-identity-token" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::AwsEc2 {
                role: "web-role".into(),
                signature_type: Ec2SignatureType::Identity,
            },
            Some("aws"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("aws-identity-token"));
}

#[tokio::test]
async fn test_aws_ec2_rsa2048_signature_type() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    unsafe {
        std::env::set_var("VAULTENV_EC2_METADATA_ENDPOINT", server.uri());
    }

    Mock::given(method("GET"))
        .and(path("/latest/dynamic/instance-identity/rsa2048"))
        .respond_with(ResponseTemplate::new(200).set_body_string("rsa2048-payload"))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/aws/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "aws-rsa-token" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::AwsEc2 {
                role: "web-role".into(),
                signature_type: Ec2SignatureType::Rsa2048,
            },
            Some("aws"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("aws-rsa-token"));
}

#[tokio::test]
async fn test_azure_auth_default_resource() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    unsafe {
        std::env::set_var("VAULTENV_AZURE_METADATA_ENDPOINT", server.uri());
    }

    Mock::given(method("GET"))
        .and(path("/metadata/identity/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "msi-default-jwt"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/metadata/instance/compute"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "vm-01"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/azure/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "azure-default-token" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client
        .authenticate(
            &AuthMethod::Azure {
                role: "web-role".into(),
                resource: None, // default resource
            },
            Some("azure"),
        )
        .await
        .unwrap();

    assert_eq!(client.token(), Some("azure-default-token"));
}

// ---------------------------------------------------------------------------
// Builder method tests — the remaining with_* methods
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_builder_with_token_sets_token_and_uses_it() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts"))
        .and(wiremock::matchers::header("x-vault-token", "my-test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "secret/": { "type": "kv", "options": { "version": "2" } }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client.with_token("my-test-token".into());
    assert_eq!(client.token(), Some("my-test-token"));

    // Verify the token is actually sent in authenticated requests.
    let _ = client.get_mount_info().await.unwrap();
}

#[tokio::test]
async fn test_builder_with_tls_toggles_scheme() {
    // Use a non-routable address (port 1 on localhost) so the request fails fast.
    let client = VaultClient::new("127.0.0.1", 1, false, Some("t".into()), 40, 9).unwrap();
    let https_client = client.with_tls(true).unwrap();

    let err = https_client.get_mount_info().await.unwrap_err();
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("error")
            || msg.contains("connect")
            || msg.contains("refused")
            || msg.contains("tls")
            || msg.contains("handshake"),
        "expected connection error after with_tls(true), got: {msg}"
    );
}

#[tokio::test]
async fn test_builder_with_retry_base_delay_produces_working_client() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "delay-token" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, None, 40, 9).unwrap();
    let client = client.with_retry_base_delay(5);
    let client = client
        .authenticate(&AuthMethod::GitHub("ghp_xxx".into()), Some("github"))
        .await
        .unwrap();
    assert_eq!(client.token(), Some("delay-token"));
}

#[tokio::test]
async fn test_builder_chain_all_with_methods() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts"))
        .and(wiremock::matchers::header("x-vault-token", "chained-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "secret/": { "type": "kv", "options": { "version": "2" } }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new("wrong-host", 9999, false, None, 40, 9).unwrap();
    let client = client
        .with_host(&host)
        .unwrap()
        .with_port(port)
        .unwrap()
        .with_token("chained-token".into())
        .with_retry_base_delay(1)
        .with_retry_attempts(0);

    assert_eq!(client.token(), Some("chained-token"));
    let _ = client.get_mount_info().await.unwrap();
}

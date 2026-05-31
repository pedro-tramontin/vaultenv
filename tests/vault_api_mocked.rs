use reqwest::Url;
use serde_json::json;
use vaultenv::{
    cloud_metadata::Ec2SignatureType,
    config::AuthMethod,
    secrets_file::Secret,
    vault_api::{EngineType, MountInfo, VaultClient},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

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

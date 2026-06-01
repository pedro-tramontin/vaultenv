use reqwest::Url;
use serde_json::json;
use vaultenv::{
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
    // V2 => path should include /data/
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
        .and(path("/v1/legacy/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "password": "old-but-gold" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 40, 9).unwrap();
    let mount_info = MountInfo::from_map([("legacy/".to_string(), EngineType::V1)].into());

    let secret = Secret {
        mount: "legacy".to_string(),
        path: "config".to_string(),
        key: "password".to_string(),
        var_name: "LEGACY_PASSWORD".to_string(),
    };

    let data = client.get_secret(&mount_info, &secret).await.unwrap();
    assert_eq!(
        data.0.get("password").unwrap().as_str().unwrap(),
        "old-but-gold"
    );
}

#[tokio::test]
async fn test_secret_not_found_404() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 40, 9).unwrap();
    let mount_info = MountInfo::from_map([("secret/".to_string(), EngineType::V2)].into());

    let secret = Secret {
        mount: "secret".to_string(),
        path: "missing".to_string(),
        key: "anything".to_string(),
        var_name: "MISSING".to_string(),
    };

    let err = client.get_secret(&mount_info, &secret).await.unwrap_err();
    assert!(format!("{err}").contains("not found"));
}

#[tokio::test]
async fn test_retry_on_503_then_success() {
    let server = MockServer::start().await;
    let (host, port) = parse_uri(&server.uri());

    // First request returns 503; second returns 200
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/flaky"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/flaky"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": " recovered" } }
        })))
        .mount(&server)
        .await;

    // Fast retry settings for the test
    let client = VaultClient::new(&host, port, false, Some("s.xxx".into()), 10, 3).unwrap();
    let mount_info = MountInfo::from_map([("secret/".to_string(), EngineType::V2)].into());

    let secret = Secret {
        mount: "secret".to_string(),
        path: "flaky".to_string(),
        key: "value".to_string(),
        var_name: "FLAKY".to_string(),
    };

    let data = client.get_secret(&mount_info, &secret).await.unwrap();
    assert_eq!(data.0.get("value").unwrap().as_str().unwrap(), " recovered");
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

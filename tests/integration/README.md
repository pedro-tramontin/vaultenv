# Integration Test Mocking Strategy for vaultenv

## TL;DR

**Use `wiremock` for unit/integration tests** + **one smoke test with `testcontainers`** if you want real Vault coverage. Everything else is unnecessary overhead.

---

## Option 1: `wiremock` (RECOMMENDED)

- **What it is:** Embedded async HTTP server that runs inside the test process.
- **Why it wins:** Zero Docker, fast compile, deterministic, `reqwest`-compatible.
- **Trade-off:** You mock at HTTP-level, not Vault-level. Good enough for verifying request/response parsing, retry logic, auth flows.

### Example (already wired)

```rust
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

#[tokio::test]
async fn test_vault_auth_github() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/github/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "test-token" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::new(
        server.host(), server.port(), false, None, 40, 9
    ).unwrap();

    let client = client.authenticate(
        &AuthMethod::GitHub("ghp_xxx".into()), Some("github")
    ).await.unwrap();

    assert_eq!(client.token(), "test-token");
}
```

**Verdict:** Best cost/benefit. Already in `Cargo.toml` as `dev-dependencies`.

---

## Option 2: `mockito`

- **What it is:** HTTP mocking crate (not the Python framework). Similar to `wiremock` but older.
- **Status:** Less active than `wiremock`; `wiremock` has better async ergonomics.
- **Verdict:** Skip — `wiremock` supersedes it for async Rust.

---

## Option 3: `testcontainers`

- **What it is:** Spins up real Docker containers (e.g. Vault, PostgreSQL) for tests.
- **Why you might want it:** Tests against the *real* Vault binary — full fidelity.
- **Why you probably don't:** Adds Docker dependency to CI, slower, images can drift.
- **Verdict:** Good for a single nightly/smoke test, not for fast PR feedback.

---

## Option 4: `mockserver` (Java / crates.io)

- **What it is:** Test framework that runs a Java-based mock server.
- **Verdict:** Total overkill. JVM startup, Docker requirement, heavy maintenance. Avoid.

---

## Proposed Test Layout

```
tests/
├── integration/
│   ├── vault_api_mocked.rs      ← wiremock tests (auth, retry, KV1/KV2)
│   └── end_to_end.rs            ← assert_cmd tests with mock Vault
└── fixtures/
    └── secrets/
        ├── valid-v2.secrets
        └── invalid-v1.secrets
```

Add this to `Cargo.toml` if needed:

```toml
[dev-dependencies]
wiremock = "0.6"
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

Already present ✅.

---

## Decision Matrix

| Concern | wiremock | mockito | testcontainers | mockserver |
|---------|----------|---------|----------------|------------|
| Speed | ⭐⭐⭐ | ⭐⭐ | ⭐ | ⭐ |
| Determinism | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| No Docker | ⭐⭐⭐ | ⭐⭐⭐ | ❌ | ❌ |
| Real Vault fidelity | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Maintenance burden | Low | Low | Medium | High |

**Winner: `wiremock`.** One optional `testcontainers` nightly if you want Vault binary fidelity.

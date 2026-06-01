<div align="center">
  <h1>vaultenv</h1>
  <img src="docs/assets/rustacean-ferris.svg" alt="Ferris, the Rust mascot, cheerfully holding a Vault key" width="180">
</div>

<p align="center">
  <a href="https://github.com/pedro-tramontin/vaultenv/actions/workflows/ci.yml"><img src="https://github.com/pedro-tramontin/vaultenv/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/pedro-tramontin/vaultenv/actions/workflows/extended.yml"><img src="https://github.com/pedro-tramontin/vaultenv/actions/workflows/extended.yml/badge.svg" alt="Extended Checks"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20BSD--3-blue.svg" alt="License"></a>
</p>

<p align="center"><em>Run programs with secrets from <a href="https://www.vaultproject.io/">HashiCorp Vault</a>.</em></p>

---

This project is inspired by the original [`vaultenv`](https://github.com/channable/vaultenv) (Haskell, created by [Channable](https://www.channable.com/)). It preserves the core idea — reading a secrets file, fetching values from Vault, injecting them into the environment, and replacing itself via `execve` — but reimagines the interface and significantly expands the feature set.

---

## Features

- **V2 KV engine only** — modern Vault deployments.
- **Vault CLI-compatible auth** — uses `--method=<TYPE>` + `KEY=VALUE` conventions.
- **10 auth backends** — token, GitHub, Kubernetes, AppRole, LDAP, Okta, Azure, GCP, AWS EC2, JWT/OIDC.
- **Concurrent fetching** — bounded by a semaphore to avoid overwhelming Vault.
- **Automatic retry** — exponential backoff with jitter via `backon`.
- **Environment merging** — inherit parent env, blacklist specific variables, deduplicate.
- **PATH search** — optionally resolve the command via `PATH`.
- **Structured logging** — `tracing`-based info-level progress reporting.

---

## Installation

### From source (requires Rust ≥ 1.85)

```bash
git clone https://github.com/pedro-tramontin/vaultenv.git
cd vaultenv
cargo build --release
```

The binary is at `target/release/vaultenv`.

### Pre-built binaries

Download from the [Releases](https://github.com/pedro-tramontin/vaultenv/releases) page.

---

## Quick Start

### 1. Create a secrets file

```text
VERSION 2
MOUNT secret

DATABASE_URL=production/db#url
REDIS_PASSWORD=production/redis#password
```

### 2. Run vaultenv

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="hvs.xxx"

vaultenv --secrets-file ./secrets.env -- ./my-app
```

The `DATABASE_URL` and `REDIS_PASSWORD` variables will be fetched from Vault and injected into `my-app`'s environment.

---

## Secrets File Format

```text
VERSION 2
MOUNT <mount-point>

# Optional explicit variable name
MY_VAR=path/to/secret#key

# Implicit variable name (path_KEY)
path/to/secret#key
```

| Element | Description |
|---------|-------------|
| `VERSION 2` | Required header. Only V2 is supported. |
| `MOUNT <name>` | Sets the KV mount point for subsequent secrets. |
| `VAR=path#key` | Fetch `key` from `path`, assign to `VAR`. |
| `path#key` | Fetch `key` from `path`, auto-generate variable name. |

Auto-generated names convert dashes and slashes to underscores. For example, `app/db#password` becomes `APP_DB_PASSWORD`.

---

## CLI Options

### Global flags

Every CLI flag has a corresponding environment variable:

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--host` | `VAULT_HOST` | `localhost` | Vault host |
| `--port` | `VAULT_PORT` | `8200` | Vault port |
| `--addr` | `VAULT_ADDR` | — | Full URL (`scheme://host:port`). Overrides host/port/TLS. |
| `--secrets-file` | `VAULTENV_SECRETS_FILE` | — | Path to secrets file **(required)** |
| `--connect-tls` | `VAULTENV_CONNECT_TLS` | `true` | Use TLS |
| `--validate-certs` | `VAULTENV_VALIDATE_CERTS` | `true` | Validate TLS certificates |
| `--inherit-env` | `VAULTENV_INHERIT_ENV` | `true` | Inherit parent environment |
| `--inherit-env-blacklist` | `VAULTENV_INHERIT_ENV_BLACKLIST` | — | Comma-separated vars to drop |
| `--duplicate-behavior` | `VAULTENV_DUPLICATE_VARIABLE_BEHAVIOR` | `error` | `error`, `keep`, `overwrite` |
| `--retry-base-delay` | `VAULTENV_RETRY_BASE_DELAY` | `40` | Retry base delay (ms) |
| `--retry-attempts` | `VAULTENV_RETRY_ATTEMPTS` | `9` | Max retry attempts |
| `--max-concurrent-requests` | `VAULTENV_MAX_CONCURRENT_REQUESTS` | `8` | Parallel fetch limit (`0` = unlimited) |
| `--log-level` | `VAULTENV_LOG_LEVEL` | `error` | `error` or `info` |
| `--use-path` | `VAULTENV_USE_PATH` | `false` | Search `PATH` for the command |
| `--help`, `--version` | — | — | Clap built-ins |

### Auth method flags

vaultenv follows the Vault CLI convention:

```bash
vaultenv --method=<TYPE> [method-specific flags...] --secrets-file secrets -- CMD
```

| Method | Flag | Description |
|--------|------|-------------|
| **token** (default) | `--token <VAULT_TOKEN>` | Direct Vault token |
| **github** | `--token <GITHUB_PAT>` | GitHub personal access token |
| **kubernetes** | `--role <ROLE>` | K8s reads SA token automatically from `/var/run/secrets/...` |
| **approle** | `--role-id <ID>`, `--secret-id <ID>` | AppRole credentials |
| **ldap** | `--username <USER>`, `--password <PASS>` | LDAP credentials |
| **okta** | `--username <USER>`, `--password <PASS>` | Okta credentials |
| **azure** | `--role <ROLE>`, `[--resource <URL>]` | Auto-fetches MSI token + VM metadata |
| **gcp** | `--role <ROLE>` | Auto-fetches GCE identity JWT |
| **aws** | `--role <ROLE>`, `[--signature-type <TYPE>]` | Auto-fetches EC2 metadata |
| **jwt** | `--role <ROLE>`, `--jwt <TOKEN>` or `--jwt-file <PATH>` | Pre-exchanged JWT |

Custom mount paths (like Vault's `-path=`):

```bash
# Vault mounted at auth/oidc
vaultenv --method=jwt --path=oidc --role=ci-role --jwt-file=/tmp/token -- ...
```

**Flag parity table:**

| What you need | Vault CLI (`vault login`) | vaultenv CLI |
|---------------|-----------------|----------------|
| Direct token | `vault login token=hvs.xxx` (default) | `vaultenv --token=hvs.xxx` (default) |
| GitHub | `vault login -method=github token=ghp_xxx` | `vaultenv --method=github --token=ghp_xxx` |
| Kubernetes | `vault login -method=kubernetes role=my-role` | `vaultenv --method=kubernetes --role=my-role` |
| AppRole | `vault login -method=approle role_id=xxx secret_id=yyy` | `vaultenv --method=approle --role-id=xxx --secret-id=yyy` |
| LDAP | `vault login -method=ldap username=alice password=p@ss` | `vaultenv --method=ldap --username=alice --password=p@ss` |
| Okta | `vault login -method=okta username=alice password=p@ss` | `vaultenv --method=okta --username=alice --password=p@ss` |
| Azure | `vault login -method=azure role=... jwt=...` | `vaultenv --method=azure --role=...` (auto-fetches jwt) |
| GCP | `vault login -method=gcp role=... jwt=...` | `vaultenv --method=gcp --role=...` (auto-fetches jwt) |
| AWS EC2 | `vault login -method=aws role=...` | `vaultenv --method=aws --role=...` (auto-fetches metadata) |
| JWT | `vault login -method=jwt role=... jwt=...` | `vaultenv --method=jwt --role=... --jwt=...` |
| OIDC mount | `vault login -method=jwt -path=oidc role=... jwt=...` | `vaultenv --method=jwt --path=oidc --role=... --jwt=...` |

---

## Building & Testing

```bash
# Fast check
cargo check

# Run all tests (unit + integration)
cargo test --all-targets

# Format
cargo fmt

# Lint
cargo clippy --all-targets --all-features

# License audit
cargo deny check

# Release build
cargo build --release
```

### Running integration tests

Integration tests use [`wiremock`](https://docs.rs/wiremock) to simulate Vault HTTP responses. No Docker or real Vault instance is required:

```bash
cargo test --test vault_api_mocked
cargo test --test end_to_end
```

---

## Architecture

```text
┌─────────────────┐
│   CLI (clap)    │
└────────┬────────┘
         │ Options
┌────────▼────────┐
│   Config        │── VAULT_ADDR parsing, auth method resolution
│   (config.rs)   │── env-file loading
└────────┬────────┘
         │ SecretsFile path
┌────────▼────────┐
│ Secrets File    │── winnow parser (V2-only)
│ (secrets_file.rs)│
└────────┬────────┘
         │ Vec<Secret>
┌────────▼────────┐
│  Vault API      │── reqwest + backon retry
│  (vault_api.rs) │── tokio::sync::Semaphore (concurrency)
└────────┬────────┘
         │ HashMap<path, VaultData>
┌────────▼────────┐
│  Resolution     │── deduplication, env merging
│  (main.rs)      │── nix::unistd::execve
└─────────────────┘
```

### Concurrency model

- A single `tokio::sync::Semaphore` limits concurrent in-flight Vault HTTP requests.
- Each secret is fetched in its own `tokio::spawn` task, holding a permit until the request completes.
- Retry logic wraps individual requests using `backon::Retryable` with exponential backoff and jitter.

### Process replacement

vaultenv resolves all secrets, builds the environment, and calls `execve` to replace itself with the target program. This means:

- No vaultenv process remains in the background.
- Signals go directly to the child.
- The child PID is the same as the original vaultenv PID (under `execve`).

---

## License

This project is dual-licensed under [Apache-2.0](LICENSE) OR [BSD-3-Clause](LICENSE).

The Rust implementation is licensed under Apache-2.0. It is a derivative work of the original `vaultenv` project by Channable, which was written in Haskell and licensed under the BSD-3-Clause license (Copyright © 2017 Channable, https://www.channable.com/). See the `LICENSE` file for the full dual-license text and attribution notices.

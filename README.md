# vaultenv

Run programs with secrets from [HashiCorp Vault](https://www.vaultproject.io/).

A Rust rewrite of the Haskell [`vaultenv`](https://github.com/channable/vaultenv) tool. It reads a secrets file, fetches values from Vault, injects them into the environment, and `execve`s into your program — replacing the vaultenv process entirely.

---

## Features

- **V2 KV engine only** — modern Vault deployments; V1 support was explicitly dropped for simplicity.
- **Multiple auth backends** — direct Vault token, GitHub personal access token, Kubernetes JWT.
- **Concurrent fetching** — bounded by a semaphore to avoid overwhelming Vault.
- **Automatic retry** — exponential backoff with jitter on 5xx and connection errors via `backon`.
- **Environment merging** — inherit parent env, blacklist specific variables, deduplicate with configurable behavior (error, keep, overwrite).
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

The `DATABASE_URL` and `REDIS_PASSWORD` variables will be fetched from Vault and injected into `my-app`'s environment before the process is started.

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

## CLI Options & Environment Variables

Every CLI flag has a corresponding environment variable:

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--host` | `VAULT_HOST` | `localhost` | Vault host |
| `--port` | `VAULT_PORT` | `8200` | Vault port |
| `--addr` | `VAULT_ADDR` | — | Full URL (`scheme://host:port`). Overrides host/port/TLS. |
| `--secrets-file` | `VAULTENV_SECRETS_FILE` | — | Path to secrets file **(required)** |
| `--token` | `VAULT_TOKEN` | — | Direct Vault token |
| `--github-token` | `VAULTENV_GITHUB_TOKEN` | — | GitHub PAT for Vault GitHub auth |
| `--kubernetes-role` | `VAULTENV_KUBERNETES_ROLE` | — | K8s role for Vault Kubernetes auth |
| `--auth-backend` | `VAULT_AUTH_BACKEND` | — | Override auth backend name |
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

### Authentication priority

If multiple credentials are provided, resolution order is:

1. `--token` (`VAULT_TOKEN`)
2. `--github-token` (`VAULTENV_GITHUB_TOKEN`)
3. `--kubernetes-role` (`VAULTENV_KUBERNETES_ROLE`)
4. None (unauthenticated)

When `--auth-backend` is omitted, it defaults from the detected auth method:
- GitHub → `github`
- Kubernetes → `kubernetes`
- Token / None → no backend login needed

---

## Configuration Files

vaultenv reads optional environment files in this order:

1. `/etc/vaultenv.conf`
2. `~/.config/vaultenv/vaultenv.conf`
3. `./vaultenv.conf`

Format: `KEY=value` lines, `#` comments.

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

Unlike `std::process::Command::exec`, which spawns a child, vaultenv uses `nix::unistd::execve` to **replace** the current process image. This means:
- The target program inherits the same PID.
- No vaultenv process remains in memory after handoff.
- Signal handling is delegated entirely to the child program.

### Logging conventions

All log output goes to **stderr** to avoid polluting stdout of the wrapped program.

- `info!` spans mark major pipeline milestones ("Authenticating", "Fetching secrets", "Preparing to exec").
- Structured fields use `tracing` key-value pairs (`count`, `path`, `backend`, etc.).
- Errors are propagated as typed `VaultError` values and logged at the top-level `#[tokio::main]` boundary.

Set `--log-level info` to see the full pipeline trace.

---

## License

BSD-3-Clause. See [LICENSE](LICENSE).

---

## Credits

Originally by [Channable](https://github.com/channable/vaultenv) (Haskell). This is a ground-up Rust rewrite.

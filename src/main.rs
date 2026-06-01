use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};

use vaultenv::{
    config::{LogLevel, Options},
    secrets_file::read_secrets_file,
    vault_api::{VaultClient, deduplicate, resolve_secrets},
};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        // Ensure the error is always reported, even if tracing is not initialised yet.
        error!(error = %e, "vaultenv failed");
        eprintln!("[ERROR] {e:?}");
        std::process::exit(1);
    }
}

#[tracing::instrument(skip_all, fields(vaultenv_version = env!("CARGO_PKG_VERSION")))]
async fn run() -> Result<()> {
    let mut opts = Options::parse();

    // Initialise tracing subscriber from the requested log level.
    let filter = match opts.log_level.0 {
        LogLevel::Error => tracing::Level::ERROR,
        LogLevel::Info => tracing::Level::INFO,
    };
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_writer(std::io::stderr)
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "vaultenv starting");

    // ── Phase 2: configuration ───────────────────────────────────────────
    info!("resolving configuration");
    opts.resolve_addr().context("invalid VAULT_ADDR")?;
    opts.resolve_auth_backend();
    opts.validate().context("invalid configuration")?;

    if opts.log_level.0 == LogLevel::Info {
        eprintln!("{opts:#?}");
    }

    // ── Phase 3: secrets file ──────────────────────────────────────────
    info!(path = %opts.secrets_file.display(), "reading secrets file");
    let secrets = read_secrets_file(&opts.secrets_file)
        .map_err(|e| anyhow::anyhow!("failed to read secrets file: {e}"))?;

    if secrets.is_empty() {
        anyhow::bail!("no secrets specified in {}", opts.secrets_file.display());
    }
    info!(count = secrets.len(), "secrets loaded");

    // ── Phase 4: Vault client ──────────────────────────────────────────
    let client = VaultClient::new(
        &opts.host,
        opts.port,
        opts.connect_tls,
        opts.token.clone(),
        opts.retry_base_delay_ms,
        opts.retry_attempts,
    )
    .map_err(|e| anyhow::anyhow!("failed to create Vault client: {e}"))?;

    // Authenticate
    let auth_method = opts.auth_method();
    info!(
        backend = opts.auth_backend.as_deref(),
        "authenticating to Vault"
    );
    let client = client
        .authenticate(&auth_method, opts.auth_backend.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("authentication failed: {e}"))?;
    info!("Vault authentication successful");

    // Discover mount info
    info!("discovering mount info");
    let mount_info = client
        .get_mount_info()
        .await
        .map_err(|e| anyhow::anyhow!("mount info discovery failed: {e}"))?;

    // Fetch secrets concurrently
    info!(
        count = secrets.len(),
        max_concurrent = opts.max_concurrent_requests,
        "fetching secrets from Vault"
    );
    let vault_data = client
        .get_secrets(&mount_info, &secrets, opts.max_concurrent_requests)
        .await
        .map_err(|e| anyhow::anyhow!("secret fetching failed: {e}"))?;

    // Resolve (var_name, value) pairs
    info!("resolving secret values");
    let mut secret_env = resolve_secrets(&mount_info, &secrets, &vault_data)
        .map_err(|e| anyhow::anyhow!("secret resolution failed: {e}"))?;

    // Deduplicate
    info!("checking for duplicate environment variables");
    secret_env = deduplicate(secret_env, opts.duplicate_behavior.0)
        .map_err(|e| anyhow::anyhow!("duplicate variable check failed: {e}"))?;

    info!(
        count = secret_env.len(),
        "secrets resolved and deduplicated"
    );

    // ── Phase 5: build environment ─────────────────────────────────────
    info!(inherit = opts.inherit_env, "building process environment");
    let mut env: Vec<(String, String)> = if opts.inherit_env {
        let blacklist: std::collections::HashSet<String> =
            opts.inherit_env_blacklist.iter().cloned().collect();
        std::env::vars()
            .filter(|(k, _)| !blacklist.contains(k))
            .chain(secret_env)
            .collect()
    } else {
        secret_env
    };

    // Remove duplicate keys (in case a secret shadowed an inherited var)
    // Prefer the secret (which comes later in the chain above)
    env = env.into_iter().fold(Vec::new(), |mut acc, item| {
        if !acc.iter().any(|(k, _)| k == &item.0) {
            acc.push(item);
        } else {
            // Replace existing with new value (secret wins over inherited)
            for (k, v) in &mut acc {
                if k == &item.0 {
                    *v = item.1.clone();
                }
            }
        }
        acc
    });

    // ── Phase 6: execve into CMD ───────────────────────────────────────
    let program = if opts.use_path {
        which::which(&opts.cmd).unwrap_or_else(|_| std::path::PathBuf::from(&opts.cmd))
    } else {
        std::path::PathBuf::from(&opts.cmd)
    };
    info!(program = %opts.cmd, path = ?program, "preparing to exec");

    let args: Vec<std::ffi::CString> = std::iter::once(opts.cmd.clone())
        .chain(opts.args)
        .map(|s| std::ffi::CString::new(s).expect("invalid NUL in argument"))
        .collect();

    let env_cstr: Vec<std::ffi::CString> = env
        .into_iter()
        .map(|(k, v)| {
            std::ffi::CString::new(format!("{k}={v}")).expect("invalid NUL in environment variable")
        })
        .collect();

    let argv: Vec<&std::ffi::CStr> = args.iter().map(|s| s.as_c_str()).collect();
    let envp: Vec<&std::ffi::CStr> = env_cstr.iter().map(|s| s.as_c_str()).collect();

    let program_cstr = std::ffi::CString::new(program.as_os_str().as_bytes())
        .expect("invalid NUL in program path");

    nix::unistd::execve(&program_cstr, &argv, &envp)
        .map_err(|e| anyhow::anyhow!("exec failed: {e}"))?;

    unreachable!("execve should not return on success")
}

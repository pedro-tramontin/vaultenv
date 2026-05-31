use std::fs;

use assert_cmd::Command;

#[test]
fn test_help() {
    let mut cmd = Command::cargo_bin("vaultenv").unwrap();
    cmd.arg("--help");
    cmd.assert().success().stdout(predicates::str::contains(
        "Run programs with secrets from HashiCorp Vault",
    ));
}

#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("vaultenv").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("vaultenv"));
}

#[test]
fn test_missing_secrets_file() {
    let mut cmd = Command::cargo_bin("vaultenv").unwrap();
    cmd.arg("--secrets-file")
        .arg("/nonexistent/path.env")
        .arg("echo");
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("failed to read secrets file"));
}

#[test]
fn test_empty_secrets_file() {
    let tmp = tempfile::NamedTempFile::with_suffix(".secrets").unwrap();
    fs::write(tmp.path(), "VERSION 2\nMOUNT secret\n").unwrap();

    let mut cmd = Command::cargo_bin("vaultenv").unwrap();
    cmd.arg("--secrets-file").arg(tmp.path()).arg("echo");
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("no secrets specified"));
}

#[test]
fn test_missing_cmd() {
    let tmp = tempfile::NamedTempFile::with_suffix(".secrets").unwrap();
    fs::write(tmp.path(), "VERSION 2\nMOUNT secret\nfoo#bar\n").unwrap();

    let mut cmd = Command::cargo_bin("vaultenv").unwrap();
    cmd.arg("--secrets-file").arg(tmp.path());
    cmd.assert().failure().stderr(predicates::str::contains(
        "required arguments were not provided",
    ));
}

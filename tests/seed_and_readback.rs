//! Hermetic integration tests — no external infra, fully local.
//!
//! The headline proof (`seeded_secret_is_decrypted_through_the_library_read_path`): seed a vault
//! with `ec-secrets` (its real `set`/`import` path over the library vault), then open that SAME
//! vault file through the EdgeCommons **library** exactly as a component does
//! (`edgecommons::credentials::open` — i.e. `gg.credentials()`), decrypt the values, and resolve a
//! `$secret` config reference. If the bytes weren't envelope-compatible, decryption would fail
//! closed — so a green readback proves format/KEK compatibility with real components.

use std::path::Path;

use ec_secrets::{Cli, ExitCode, open_service, resolve_config_secrets, run};
use edgecommons::credentials::{
    CredentialService, CredentialsConfig, KeyProviderConfig, VaultConfig, open, open_namespaced,
};
use serde_json::json;

use clap::Parser;

/// Run one `ec-secrets` invocation (argv without the leading program name is prepended) against a
/// freshly opened service and return its exit code.
fn ec_secrets(args: &[&str]) -> ExitCode {
    let mut argv = vec!["ec-secrets"];
    argv.extend_from_slice(args);
    let cli = Cli::try_parse_from(argv).expect("parse CLI");
    let svc = open_service(&cli).expect("open vault");
    run(&cli, &svc).expect("run command")
}

/// Build the component-side [`CredentialsConfig`] for a file-provider vault at `vault`/`keyfile` —
/// the config a real component would carry to open the same vault.
fn component_config(vault: &Path, keyfile: &Path) -> CredentialsConfig {
    CredentialsConfig {
        vault: VaultConfig {
            path: vault.to_string_lossy().into_owned(),
            key_provider: KeyProviderConfig {
                kind: Some("file".to_string()),
                key_path: Some(keyfile.to_string_lossy().into_owned()),
                ..KeyProviderConfig::default()
            },
            keep_versions: 2,
            cache_ttl_secs: 300,
        },
        ..CredentialsConfig::default()
    }
}

#[test]
fn seeded_secret_is_decrypted_through_the_library_read_path() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let keyfile = dir.path().join("vault.key");
    let (vs, ks) = (vault.to_str().unwrap(), keyfile.to_str().unwrap());

    // --- SEED with the tool (its real put path over the library vault) ---
    assert_eq!(
        ec_secrets(&[
            "--vault", vs, "--key-provider", "file", "--keyfile", ks, "set", "db/password",
            "s3cr3t",
        ]),
        ExitCode::Ok
    );
    // A JSON-shaped secret (an AWS-credentials typed view) stored inline.
    assert_eq!(
        ec_secrets(&[
            "--vault", vs, "--keyfile", ks, "set", "aws/main",
            r#"{"accessKeyId":"AKIA","secretAccessKey":"sk"}"#,
        ]),
        ExitCode::Ok
    );

    // --- READ BACK through the library, exactly as a component (gg.credentials()) does ---
    let cfg = component_config(&vault, &keyfile);
    let component = open(&cfg).expect("a component opens the same vault");
    assert_eq!(
        component.get_string("db/password").unwrap().unwrap(),
        "s3cr3t",
        "the tool-seeded secret must decrypt through the library read path"
    );
    // The typed view parses the tool-written JSON secret.
    let aws = component.get_aws_credentials("aws/main").unwrap().unwrap();
    assert_eq!(aws.access_key_id, "AKIA");
    assert_eq!(aws.secret_access_key, "sk");

    // --- and a `$secret` config reference resolves against the tool-seeded vault ---
    let mut doc = json!({
        "sink": { "type": "postgres", "properties": {
            "password": { "$secret": "db/password" },
            "accessKey": { "$secret": "aws/main", "field": "accessKeyId" }
        }},
        "plain": "untouched"
    });
    resolve_config_secrets(&mut doc, &component).unwrap();
    assert_eq!(doc["sink"]["properties"]["password"], "s3cr3t");
    assert_eq!(doc["sink"]["properties"]["accessKey"], "AKIA");
    assert_eq!(doc["plain"], "untouched");
}

#[test]
fn import_json_and_dotenv_seed_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let keyfile = dir.path().join("vault.key");
    let (vs, ks) = (vault.to_str().unwrap(), keyfile.to_str().unwrap());

    let json_file = dir.path().join("secrets.json");
    std::fs::write(
        &json_file,
        r#"{ "svc/token": "tok-123", "kafka/sasl": {"username":"ku","password":"kp"} }"#,
    )
    .unwrap();
    let env_file = dir.path().join("prod.env");
    std::fs::write(
        &env_file,
        "# seed\nexport DB_PASSWORD=pgpw\nAPI_KEY=\"a b c\"\n",
    )
    .unwrap();

    assert_eq!(
        ec_secrets(&["--vault", vs, "--keyfile", ks, "import", json_file.to_str().unwrap()]),
        ExitCode::Ok
    );
    assert_eq!(
        ec_secrets(&["--vault", vs, "--keyfile", ks, "import", env_file.to_str().unwrap()]),
        ExitCode::Ok
    );

    // Component reads every imported secret back through the library.
    let component = open(&component_config(&vault, &keyfile)).unwrap();
    assert_eq!(component.get_string("svc/token").unwrap().unwrap(), "tok-123");
    let kafka = component.get_kafka_sasl("kafka/sasl").unwrap().unwrap();
    assert_eq!(kafka.username, "ku");
    assert_eq!(kafka.password, "kp");
    assert_eq!(component.get_string("DB_PASSWORD").unwrap().unwrap(), "pgpw");
    assert_eq!(component.get_string("API_KEY").unwrap().unwrap(), "a b c");
}

#[test]
fn namespacing_matches_the_library_model() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let keyfile = dir.path().join("vault.key");
    let (vs, ks) = (vault.to_str().unwrap(), keyfile.to_str().unwrap());

    // Seed under a component namespace, as `gg.credentials()` would for `thing-1/CompA`.
    assert_eq!(
        ec_secrets(&[
            "--vault", vs, "--keyfile", ks, "--namespace", "thing-1/CompA", "set", "db/password",
            "ns-secret",
        ]),
        ExitCode::Ok
    );

    let cfg = component_config(&vault, &keyfile);
    // A component in the SAME namespace sees the bare key.
    let same_ns = open_namespaced(&cfg, "thing-1/CompA").unwrap();
    assert_eq!(same_ns.get_string("db/password").unwrap().unwrap(), "ns-secret");
    // A non-namespaced view sees the fully-qualified on-disk key (and not the bare one).
    let raw = open(&cfg).unwrap();
    assert!(raw.get("db/password").unwrap().is_none());
    assert_eq!(
        raw.get_string("thing-1/CompA/db/password").unwrap().unwrap(),
        "ns-secret"
    );
}

#[test]
fn get_delete_and_list_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let keyfile = dir.path().join("vault.key");
    let (vs, ks) = (vault.to_str().unwrap(), keyfile.to_str().unwrap());

    for (n, v) in [("a", "1"), ("b", "2")] {
        assert_eq!(ec_secrets(&["--vault", vs, "--keyfile", ks, "set", n, v]), ExitCode::Ok);
    }
    // get present + absent
    assert_eq!(ec_secrets(&["--vault", vs, "--keyfile", ks, "get", "a"]), ExitCode::Ok);
    assert_eq!(
        ec_secrets(&["--vault", vs, "--keyfile", ks, "get", "missing"]),
        ExitCode::NotFound
    );
    // list is safe (never values); just assert it succeeds.
    assert_eq!(ec_secrets(&["--vault", vs, "--keyfile", ks, "list"]), ExitCode::Ok);
    // delete present then absent
    assert_eq!(ec_secrets(&["--vault", vs, "--keyfile", ks, "delete", "a"]), ExitCode::Ok);
    assert_eq!(
        ec_secrets(&["--vault", vs, "--keyfile", ks, "delete", "a"]),
        ExitCode::NotFound
    );
    // The library agrees `a` is gone and `b` remains.
    let component = open(&component_config(&vault, &keyfile)).unwrap();
    assert!(component.get("a").unwrap().is_none());
    assert_eq!(component.get_string("b").unwrap().unwrap(), "2");
}

#[test]
fn wrong_kek_fails_closed_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let keyfile = dir.path().join("vault.key");
    let other_key = dir.path().join("other.key");
    let (vs, ks) = (vault.to_str().unwrap(), keyfile.to_str().unwrap());

    assert_eq!(
        ec_secrets(&["--vault", vs, "--keyfile", ks, "set", "k", "v"]),
        ExitCode::Ok
    );
    // Opening with a DIFFERENT keyfile must fail (never returns plaintext).
    std::fs::write(&other_key, [9u8; 32]).unwrap();
    let cli = Cli::try_parse_from([
        "ec-secrets",
        "--vault",
        vs,
        "--keyfile",
        other_key.to_str().unwrap(),
        "get",
        "k",
    ])
    .unwrap();
    assert!(open_service(&cli).is_err(), "wrong KEK must fail to open the vault");
}

#[test]
fn rotate_kek_reports_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let keyfile = dir.path().join("vault.key");
    let (vs, ks) = (vault.to_str().unwrap(), keyfile.to_str().unwrap());
    assert_eq!(ec_secrets(&["--vault", vs, "--keyfile", ks, "set", "k", "v"]), ExitCode::Ok);
    // The library exposes no in-place KEK re-wrap; the command reports that (exit 3).
    assert_eq!(
        ec_secrets(&["--vault", vs, "--keyfile", ks, "rotate-kek"]),
        ExitCode::VaultError
    );
}

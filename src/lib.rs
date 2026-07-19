//! # ec-secrets — reusable EdgeCommons vault-seeding core (library)
//!
//! **One-liner purpose**: the pure, reusable logic behind the `ec-secrets` binary — the CLI
//! surface, the config/key-provider selection that maps flags onto an
//! [`edgecommons::credentials::CredentialsConfig`], the import parsers (JSON object + dotenv),
//! and the subcommand dispatch over a live [`CredentialService`]. The binary
//! ([`main`](../main.rs)) is a thin wrapper; the vault it opens and the bytes it writes come
//! entirely from the EdgeCommons library.
//!
//! ## What the tool does
//! Components read secrets from the EdgeCommons **credentials vault** (`gg.credentials()`,
//! `$secret` config refs). `ec-secrets` is the tool that POPULATES that vault. It is a thin CLI
//! over the library's **own** vault, so everything it writes is byte-compatible with what a
//! component decrypts: the same envelope encryption ([DEK sealed with AES-256-GCM, wrapped by a
//! KeyProvider/KEK]), the same on-disk [`format`], and the same key namespacing. Scope is the
//! **local vault only** — no AWS Secrets Manager (that has its own console/CLI for seeding).
//!
//! ## How it opens the vault (the real library path)
//! [`open_service`] builds an [`edgecommons::credentials::CredentialsConfig`] from the CLI flags
//! (or a reused component `credentials` config block) and calls
//! [`edgecommons::credentials::open_namespaced_with_default`] — the **exact** call a component's
//! runtime makes. That constructs the [`KeyProvider`](edgecommons::credentials::KeyProvider)
//! (`file`/`env`/`kms`), opens the [`LocalVault`](edgecommons::credentials::LocalVault) at the
//! configured path, and returns a
//! [`DefaultCredentialService`](edgecommons::credentials::DefaultCredentialService). The tool
//! then drives that service's [`put`](CredentialService::put)/[`get`](CredentialService::get)/
//! [`list`](CredentialService::list)/[`delete`](CredentialService::delete). No vault crypto or
//! format is reimplemented here.
//!
//! [`format`]: edgecommons::credentials::format

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use edgecommons::credentials::{
    AuditConfig, CredentialService, CredentialsConfig, DefaultCredentialService, KeyProviderConfig,
    PutOptions, open_namespaced_with_default, resolve_secret_refs,
};
use serde_json::{Value, json};

/// The default local vault path when `--vault` is absent (matches the library default).
pub const DEFAULT_VAULT_PATH: &str = "vault";
/// The default number of retained versions per secret (matches the library default).
pub const DEFAULT_KEEP_VERSIONS: usize = 2;

/// Seed and inspect a LOCAL EdgeCommons credentials vault.
///
/// `ec-secrets` is a thin CLI over the EdgeCommons library's own vault, so what it writes is
/// byte-compatible with what a component decrypts (`gg.credentials()`, `$secret` refs). It opens
/// the vault at `--vault` with the selected `--key-provider`, exactly as a component would, then
/// sets, gets, lists, deletes, or bulk-imports secrets.
#[derive(Debug, Parser)]
#[command(
    name = "ec-secrets",
    about = "Seed and inspect a local EdgeCommons credentials vault (a thin CLI over the library's own vault).",
    version
)]
pub struct Cli {
    // ----- vault + key-provider selection (how a component would open the vault) -----
    /// Path to the local vault file. The keyfile (for `--key-provider file`) defaults to
    /// `<vault>.key` unless `--keyfile` is given.
    #[arg(long, value_name = "PATH", global = true)]
    pub vault: Option<String>,

    /// KEK custodian: `file` (default), `env`, or `kms` (needs the `kms` build feature).
    #[arg(long, value_name = "KIND", global = true)]
    pub key_provider: Option<String>,

    /// KEK key file (32 raw bytes) for `--key-provider file`. Generated on first use if absent.
    #[arg(long, value_name = "PATH", global = true)]
    pub keyfile: Option<String>,

    /// Env var holding the base64 32-byte KEK for `--key-provider env`
    /// (default `EDGECOMMONS_VAULT_KEK`).
    #[arg(long, value_name = "VAR", global = true)]
    pub kek_env: Option<String>,

    /// AWS KMS key id/ARN for `--key-provider kms` (needs the `kms` build feature).
    #[arg(long, value_name = "ID", global = true)]
    pub kms_key_id: Option<String>,

    /// AWS region for the `kms` key provider.
    #[arg(long, value_name = "REGION", global = true)]
    pub region: Option<String>,

    /// Override the KMS endpoint URL (floci/LocalStack/VPC endpoint) for the `kms` provider.
    #[arg(long, value_name = "URL", global = true)]
    pub endpoint_url: Option<String>,

    /// Reuse an existing edgecommons config file's `credentials` block to select the vault +
    /// key provider (individual flags above still override). The file is a component config
    /// JSON document with a top-level `credentials` object.
    #[arg(long, value_name = "FILE", global = true)]
    pub config: Option<String>,

    /// Transparent key namespace (typically `<thingName>/<componentName>`) — prepended to every
    /// key so a shared device vault can't collide. Callers see the bare key. Omit for none.
    #[arg(long, value_name = "NS", global = true)]
    pub namespace: Option<String>,

    /// Retained versions per secret (older versions are pruned).
    #[arg(long, value_name = "N", global = true)]
    pub keep_versions: Option<usize>,

    /// Emit access-audit events (op/name/version, never the value) to the log.
    #[arg(long, global = true)]
    pub audit: bool,

    /// Machine-readable JSON output on stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// Verbose library/tool logging on stderr (default: warnings only).
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// The operation.
    #[command(subcommand)]
    pub command: Command,
}

/// The vault operations.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt and store a secret. The value comes from `<value>`, `--from-file`, or `--stdin`.
    Set {
        /// The secret name (the caller-facing key, e.g. `db/password` or `tls/cip-client`).
        name: String,
        /// The secret value, inline. Mutually exclusive with `--from-file`/`--stdin`.
        value: Option<String>,
        /// Read the value from a file (raw bytes) instead of an inline argument.
        #[arg(long, value_name = "FILE", conflicts_with = "stdin")]
        from_file: Option<String>,
        /// Read the value from stdin (raw bytes).
        #[arg(long)]
        stdin: bool,
        /// Content-type label stored with the secret (default `application/octet-stream`).
        #[arg(long, value_name = "TYPE")]
        content_type: Option<String>,
    },
    /// Decrypt and print a secret (for verification). Prints the value by default.
    Get {
        /// The secret name.
        name: String,
        /// A specific version id (default: the latest).
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
        /// Extract a single string field from a JSON secret (the `$secret` `field` model).
        #[arg(long, value_name = "KEY")]
        field: Option<String>,
        /// Print only metadata (name/version/created/source/content-type), never the value.
        #[arg(long)]
        no_reveal: bool,
    },
    /// List secret names and metadata (never values).
    List {
        /// Only names starting with this prefix (empty = all).
        #[arg(long, value_name = "PREFIX", default_value = "")]
        prefix: String,
    },
    /// Delete a secret entirely.
    Delete {
        /// The secret name.
        name: String,
    },
    /// Bulk-seed from a JSON object (`{"name":"value",…}`) or a dotenv (`KEY=VALUE`) file.
    Import {
        /// The file to import.
        file: String,
        /// Force the input format instead of inferring it from the extension/content.
        #[arg(long, value_name = "FORMAT")]
        format: Option<ImportFormat>,
    },
    /// Re-encrypt the vault under a new KEK. Not exposed by the library (see the CLI reference).
    RotateKek,
}

/// The bulk-import input format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ImportFormat {
    /// A JSON object mapping name → value (string values stored as-is; JSON values as JSON).
    Json,
    /// A dotenv file: `KEY=VALUE` lines, `#` comments, optional `export ` prefix, quoted values.
    Env,
}

/// Process exit codes (documented in `docs/reference/cli.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// The operation succeeded.
    Ok = 0,
    /// The secret was not found, or the operation was refused.
    NotFound = 1,
    /// A usage / argument error (also clap's own exit code).
    Usage = 2,
    /// A vault or key-provider error (wrong KEK, tampered file, unavailable provider, I/O).
    VaultError = 3,
}

impl ExitCode {
    /// The integer this code passes to the OS.
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// Where a `set` value comes from — exactly one source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueSource {
    /// An inline `<value>` argument.
    Inline(String),
    /// A file path to read raw bytes from.
    FromFile(String),
    /// Standard input.
    Stdin,
}

/// Select the single value source for `set`, enforcing that exactly one is given.
///
/// # Errors
/// Returns an error when zero or more than one of `value` / `--from-file` / `--stdin` is present.
pub fn select_value_source(
    value: Option<String>,
    from_file: Option<String>,
    stdin: bool,
) -> anyhow::Result<ValueSource> {
    let count = value.is_some() as u8 + from_file.is_some() as u8 + stdin as u8;
    match count {
        0 => bail!("provide the secret value inline, or with --from-file <FILE>, or --stdin"),
        1 => Ok(if let Some(v) = value {
            ValueSource::Inline(v)
        } else if let Some(f) = from_file {
            ValueSource::FromFile(f)
        } else {
            ValueSource::Stdin
        }),
        _ => bail!("the value, --from-file, and --stdin are mutually exclusive — pick one"),
    }
}

/// Parse a JSON-object secrets document (`{"name": <value>, …}`) into ordered `(name, bytes)`.
///
/// A string value is stored as its UTF-8 bytes. Any non-string JSON value (object, array,
/// number, bool) is stored as its compact JSON serialization, so JSON-shaped secrets (AWS
/// creds, TLS bundles, Kafka SASL — the library's typed views) round-trip as valid JSON.
///
/// # Errors
/// Returns an error when the document is not a JSON object, or a value is JSON `null`.
pub fn parse_json_secrets(text: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let value: Value = serde_json::from_str(text).context("import file is not valid JSON")?;
    let Value::Object(map) = value else {
        bail!("a JSON import must be a top-level object of name → value");
    };
    let mut out = Vec::with_capacity(map.len());
    for (name, v) in map {
        let bytes = match v {
            Value::String(s) => s.into_bytes(),
            Value::Null => bail!("secret '{name}' has a null value"),
            other => serde_json::to_vec(&other).context("re-serialize JSON secret value")?,
        };
        out.push((name, bytes));
    }
    Ok(out)
}

/// Parse a dotenv document into ordered `(name, bytes)`.
///
/// Recognizes `KEY=VALUE` (and `export KEY=VALUE`), skips blank lines and `#` comments, trims
/// surrounding whitespace, and strips one layer of matching single/double quotes from the value.
/// A `#` after an unquoted value begins a trailing comment.
///
/// # Errors
/// Returns an error on a non-comment, non-blank line with no `=`, or an empty key.
pub fn parse_dotenv(text: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map(str::trim).unwrap_or(line);
        let (key, val) = line
            .split_once('=')
            .with_context(|| format!("line {}: not a KEY=VALUE assignment: {raw:?}", i + 1))?;
        let key = key.trim();
        if key.is_empty() {
            bail!("line {}: empty key", i + 1);
        }
        out.push((key.to_string(), dotenv_value(val.trim()).into_bytes()));
    }
    Ok(out)
}

/// Unquote/uncomment a dotenv value: strip one layer of matching quotes, else drop a trailing
/// `#`-comment from an unquoted value.
fn dotenv_value(v: &str) -> String {
    let bytes = v.as_bytes();
    if v.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        return v[1..v.len() - 1].to_string();
    }
    match v.split_once(" #") {
        Some((before, _)) => before.trim_end().to_string(),
        None => v.to_string(),
    }
}

/// Infer the import format from an explicit choice, then the extension, then the content.
pub fn detect_format(path: &str, explicit: Option<ImportFormat>, content: &str) -> ImportFormat {
    if let Some(f) = explicit {
        return f;
    }
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".json") {
        return ImportFormat::Json;
    }
    if lower.ends_with(".env") || lower.contains(".env") {
        return ImportFormat::Env;
    }
    // Fall back to content sniffing: a leading `{` is JSON, otherwise dotenv.
    if content.trim_start().starts_with('{') {
        ImportFormat::Json
    } else {
        ImportFormat::Env
    }
}

/// Build the [`CredentialsConfig`] the way a component would, from the CLI flags and an optional
/// reused `credentials` config block. Central sync is always forced off (local vault only).
///
/// Precedence: the `--config` file's `credentials` block is the base; individual flags override
/// it; anything unset falls back to the library defaults.
///
/// # Errors
/// Returns an error when `--config` is given but cannot be read or has no valid `credentials`
/// block.
pub fn build_credentials_config(cli: &Cli) -> anyhow::Result<CredentialsConfig> {
    let mut cfg = match &cli.config {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read config file {path}"))?;
            let doc: Value =
                serde_json::from_str(&text).with_context(|| format!("parse config file {path}"))?;
            match doc.get("credentials") {
                Some(section) => serde_json::from_value::<CredentialsConfig>(section.clone())
                    .context("parse the `credentials` block")?,
                None => bail!("config file {path} has no top-level `credentials` block"),
            }
        }
        None => CredentialsConfig::default(),
    };

    // Vault path.
    if let Some(v) = &cli.vault {
        cfg.vault.path = v.clone();
    } else if cfg.vault.path.is_empty() {
        cfg.vault.path = DEFAULT_VAULT_PATH.to_string();
    }

    // Key provider selection (only override what the flags name).
    let kp = &mut cfg.vault.key_provider;
    apply_key_provider_flags(kp, cli);

    if let Some(n) = cli.keep_versions {
        cfg.vault.keep_versions = n.max(1);
    }

    // LOCAL vault only: never start a central sync from here.
    cfg.central = Default::default();
    // Audit is opt-in for the tool (quiet by default); the library defaults it on.
    cfg.audit = AuditConfig {
        enabled: cli.audit,
    };
    Ok(cfg)
}

/// Apply the key-provider CLI flags onto a [`KeyProviderConfig`] (only overriding named fields).
fn apply_key_provider_flags(kp: &mut KeyProviderConfig, cli: &Cli) {
    if let Some(k) = &cli.key_provider {
        kp.kind = Some(k.clone());
    }
    if let Some(f) = &cli.keyfile {
        kp.key_path = Some(f.clone());
    }
    if let Some(e) = &cli.kek_env {
        kp.env_var = Some(e.clone());
    }
    if let Some(id) = &cli.kms_key_id {
        kp.kms_key_id = Some(id.clone());
    }
    if let Some(r) = &cli.region {
        kp.region = Some(r.clone());
    }
    if let Some(u) = &cli.endpoint_url {
        kp.endpoint_url = Some(u.clone());
    }
}

/// Open the local vault as a component would and return the credential service.
///
/// Builds the config with [`build_credentials_config`] and calls
/// [`edgecommons::credentials::open_namespaced_with_default`] — the exact library entry point a
/// component's runtime uses — so the vault is opened with the same KeyProvider, format, and key
/// namespace.
///
/// # Errors
/// [`edgecommons::EdgeCommonsError::Credentials`] on a wrong KEK, tampered/incompatible vault,
/// unavailable key provider, or I/O failure.
pub fn open_service(cli: &Cli) -> anyhow::Result<DefaultCredentialService> {
    let cfg = build_credentials_config(cli)?;
    let namespace = cli.namespace.clone().unwrap_or_default();
    let svc = open_namespaced_with_default(&cfg, &namespace, None)
        .context("open the local vault")?;
    Ok(svc)
}

/// Read a `set` value's raw bytes from the selected source (inline, file, or stdin).
fn read_value(source: &ValueSource) -> anyhow::Result<Vec<u8>> {
    match source {
        ValueSource::Inline(v) => Ok(v.clone().into_bytes()),
        ValueSource::FromFile(f) => {
            std::fs::read(f).with_context(|| format!("read value file {f}"))
        }
        ValueSource::Stdin => {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("read value from stdin")?;
            Ok(buf)
        }
    }
}

/// Dispatch a parsed [`Cli`] against an opened [`CredentialService`], printing to stdout and
/// returning the process exit code. All vault crypto/format is the library's; this only maps the
/// CLI onto `put`/`get`/`list`/`delete`.
pub fn run(cli: &Cli, svc: &dyn CredentialService) -> anyhow::Result<ExitCode> {
    match &cli.command {
        Command::Set {
            name,
            value,
            from_file,
            stdin,
            content_type,
        } => {
            let source = select_value_source(value.clone(), from_file.clone(), *stdin)?;
            let bytes = read_value(&source)?;
            let opts = PutOptions {
                content_type: content_type.clone(),
                ..PutOptions::default()
            };
            let version = svc
                .put(name, &bytes, opts)
                .with_context(|| format!("store secret '{name}'"))?;
            if cli.json {
                print_json(&json!({ "name": name, "version": version, "bytes": bytes.len() }));
            } else {
                println!("set {name} (version {version}, {} bytes)", bytes.len());
            }
            Ok(ExitCode::Ok)
        }

        Command::Get {
            name,
            version,
            field,
            no_reveal,
        } => {
            let secret = match version {
                Some(v) => svc.get_version(name, v),
                None => svc.get(name),
            }
            .with_context(|| format!("read secret '{name}'"))?;
            let Some(secret) = secret else {
                eprintln!("ec-secrets: secret '{name}' not found");
                return Ok(ExitCode::NotFound);
            };
            emit_get(cli, &secret, field.as_deref(), *no_reveal)
        }

        Command::List { prefix } => {
            let metas = svc
                .list(prefix)
                .with_context(|| format!("list secrets under '{prefix}'"))?;
            if cli.json {
                let arr: Vec<Value> = metas
                    .iter()
                    .map(|m| {
                        json!({
                            "name": m.name,
                            "version": m.version,
                            "createdMs": m.created_ms,
                            "source": m.source,
                        })
                    })
                    .collect();
                print_json(&Value::Array(arr));
            } else if metas.is_empty() {
                eprintln!("(no secrets)");
            } else {
                for m in &metas {
                    println!("{}\t(version {}, source {})", m.name, m.version, m.source);
                }
            }
            Ok(ExitCode::Ok)
        }

        Command::Delete { name } => {
            let deleted = svc
                .delete(name)
                .with_context(|| format!("delete secret '{name}'"))?;
            if deleted {
                if cli.json {
                    print_json(&json!({ "name": name, "deleted": true }));
                } else {
                    println!("deleted {name}");
                }
                Ok(ExitCode::Ok)
            } else {
                eprintln!("ec-secrets: secret '{name}' not found");
                Ok(ExitCode::NotFound)
            }
        }

        Command::Import { file, format } => {
            let text = std::fs::read_to_string(file)
                .with_context(|| format!("read import file {file}"))?;
            let fmt = detect_format(file, *format, &text);
            let entries = match fmt {
                ImportFormat::Json => parse_json_secrets(&text)?,
                ImportFormat::Env => parse_dotenv(&text)?,
            };
            let mut names = Vec::with_capacity(entries.len());
            for (name, bytes) in &entries {
                let opts = PutOptions {
                    content_type: json_content_type(fmt, bytes),
                    ..PutOptions::default()
                };
                svc.put(name, bytes, opts)
                    .with_context(|| format!("import secret '{name}'"))?;
                names.push(name.clone());
            }
            if cli.json {
                print_json(&json!({ "imported": names.len(), "names": names }));
            } else {
                println!("imported {} secret(s) from {file}", names.len());
            }
            Ok(ExitCode::Ok)
        }

        Command::RotateKek => {
            eprintln!(
                "ec-secrets: in-place KEK rotation is not exposed by the edgecommons library \
                 (no public re-wrap API). To change custodians, open a fresh vault under the new \
                 --key-provider and re-import the secrets (e.g. `ec-secrets get`/`set` or an \
                 exported JSON)."
            );
            Ok(ExitCode::VaultError)
        }
    }
}

/// Content-type for an imported secret: `application/json` for a JSON-object import whose value
/// is itself JSON, else the library default (`None` ⇒ `application/octet-stream`).
fn json_content_type(fmt: ImportFormat, bytes: &[u8]) -> Option<String> {
    if fmt == ImportFormat::Json && serde_json::from_slice::<Value>(bytes).is_ok() {
        // Only tag structured JSON (objects/arrays) — a bare JSON string is a plain value.
        if let Ok(Value::Object(_) | Value::Array(_)) = serde_json::from_slice::<Value>(bytes) {
            return Some("application/json".to_string());
        }
    }
    None
}

/// Print a `get` result: the value (optionally a single field), or metadata only.
fn emit_get(
    cli: &Cli,
    secret: &edgecommons::credentials::Secret,
    field: Option<&str>,
    no_reveal: bool,
) -> anyhow::Result<ExitCode> {
    if no_reveal {
        if cli.json {
            print_json(&json!({
                "name": secret.name,
                "version": secret.version,
                "createdMs": secret.created_ms,
                "source": secret.source,
                "contentType": secret.content_type,
            }));
        } else {
            println!(
                "{} (version {}, source {}, {})",
                secret.name, secret.version, secret.source, secret.content_type
            );
        }
        return Ok(ExitCode::Ok);
    }

    // Optional single-field extraction from a JSON secret (mirrors `$secret` `field`).
    if let Some(key) = field {
        let value = secret.as_json().with_context(|| {
            format!("secret '{}' is not JSON, cannot extract field '{key}'", secret.name)
        })?;
        let extracted = value.get(key).and_then(Value::as_str).ok_or_else(|| {
            anyhow::anyhow!("field '{key}' missing or not a string in secret '{}'", secret.name)
        })?;
        if cli.json {
            print_json(&json!({ "name": secret.name, "field": key, "value": extracted }));
        } else {
            println!("{extracted}");
        }
        return Ok(ExitCode::Ok);
    }

    // Full value. Prefer UTF-8; fall back to base64-less raw bytes to stdout for binary.
    match secret.as_str() {
        Ok(s) => {
            if cli.json {
                print_json(&json!({
                    "name": secret.name,
                    "version": secret.version,
                    "value": s,
                }));
            } else {
                println!("{s}");
            }
        }
        Err(_) => {
            use std::io::Write;
            // Binary value: write the raw bytes verbatim (never lossy) to stdout.
            let mut out = std::io::stdout();
            out.write_all(secret.bytes()).context("write secret bytes")?;
            out.flush().ok();
        }
    }
    Ok(ExitCode::Ok)
}

/// Resolve `$secret` references in a JSON document against the vault (exposed so callers/tests can
/// prove config-time resolution works over a tool-seeded vault). Thin wrapper over
/// [`edgecommons::credentials::resolve_secret_refs`].
pub fn resolve_config_secrets(doc: &mut Value, svc: &dyn CredentialService) -> anyhow::Result<()> {
    resolve_secret_refs(doc, svc).context("resolve $secret references")?;
    Ok(())
}

/// Pretty-print a JSON value to stdout.
fn print_json(value: &Value) {
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // ---- select_value_source ----
    #[test]
    fn value_source_requires_exactly_one() {
        assert_eq!(
            select_value_source(Some("v".into()), None, false).unwrap(),
            ValueSource::Inline("v".into())
        );
        assert_eq!(
            select_value_source(None, Some("f".into()), false).unwrap(),
            ValueSource::FromFile("f".into())
        );
        assert_eq!(
            select_value_source(None, None, true).unwrap(),
            ValueSource::Stdin
        );
        assert!(select_value_source(None, None, false).is_err()); // zero
        assert!(select_value_source(Some("v".into()), None, true).is_err()); // two
        assert!(select_value_source(Some("v".into()), Some("f".into()), false).is_err());
    }

    // ---- parse_json_secrets ----
    #[test]
    fn json_secrets_string_and_structured_values() {
        let entries = parse_json_secrets(
            r#"{ "db/password": "s3cr3t", "aws": {"accessKeyId":"AKIA","secretAccessKey":"sk"} }"#,
        )
        .unwrap();
        let map: std::collections::BTreeMap<_, _> = entries.into_iter().collect();
        assert_eq!(map["db/password"], b"s3cr3t".to_vec());
        // Structured values round-trip as compact JSON bytes.
        let aws: Value = serde_json::from_slice(&map["aws"]).unwrap();
        assert_eq!(aws["accessKeyId"], "AKIA");
    }

    #[test]
    fn json_secrets_rejects_non_object_and_null() {
        assert!(parse_json_secrets("[1,2,3]").is_err());
        assert!(parse_json_secrets("not json").is_err());
        assert!(parse_json_secrets(r#"{"k": null}"#).is_err());
    }

    // ---- parse_dotenv ----
    #[test]
    fn dotenv_parses_assignments_comments_and_quotes() {
        let text = "\
# a comment

export DB_PASSWORD=s3cr3t
API_TOKEN = \"abc def\"
QUOTED='v#notcomment'
TRAILING=value # trailing comment
";
        let map: std::collections::BTreeMap<_, _> = parse_dotenv(text)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, String::from_utf8(v).unwrap()))
            .collect();
        assert_eq!(map["DB_PASSWORD"], "s3cr3t");
        assert_eq!(map["API_TOKEN"], "abc def");
        assert_eq!(map["QUOTED"], "v#notcomment");
        assert_eq!(map["TRAILING"], "value");
    }

    #[test]
    fn dotenv_rejects_bad_line_and_empty_key() {
        assert!(parse_dotenv("NOEQUALS").is_err());
        assert!(parse_dotenv("=novalue").is_err());
    }

    // ---- detect_format ----
    #[test]
    fn format_detection_prefers_explicit_then_extension_then_content() {
        assert_eq!(
            detect_format("x.env", Some(ImportFormat::Json), "KEY=v"),
            ImportFormat::Json
        );
        assert_eq!(detect_format("secrets.json", None, "{}"), ImportFormat::Json);
        assert_eq!(detect_format("prod.env", None, "K=v"), ImportFormat::Env);
        assert_eq!(detect_format(".env.prod", None, "K=v"), ImportFormat::Env);
        assert_eq!(detect_format("unknown", None, "  {\"a\":1}"), ImportFormat::Json);
        assert_eq!(detect_format("unknown", None, "K=v"), ImportFormat::Env);
    }

    // ---- build_credentials_config ----
    #[test]
    fn config_from_flags_selects_vault_and_provider() {
        let cli = Cli::try_parse_from([
            "ec-secrets",
            "--vault",
            "/tmp/v",
            "--key-provider",
            "env",
            "--kek-env",
            "MY_KEK",
            "--keep-versions",
            "5",
            "list",
        ])
        .unwrap();
        let cfg = build_credentials_config(&cli).unwrap();
        assert_eq!(cfg.vault.path, "/tmp/v");
        assert_eq!(cfg.vault.key_provider.kind.as_deref(), Some("env"));
        assert_eq!(cfg.vault.key_provider.env_var.as_deref(), Some("MY_KEK"));
        assert_eq!(cfg.vault.keep_versions, 5);
        // Local only: central is always off.
        assert_eq!(cfg.central.kind, "none");
        assert!(!cfg.audit.enabled); // quiet unless --audit
    }

    #[test]
    fn config_reuses_component_credentials_block_with_flag_override() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("component.json");
        std::fs::write(
            &cfg_path,
            r#"{ "component": {"token":"c"},
                 "credentials": {
                    "vault": { "path": "from-config", "keyProvider": {"type":"env","envVar":"CFG_KEK"} }
                 } }"#,
        )
        .unwrap();
        // No --vault → the config's path wins; --key-provider file overrides just the kind.
        let cli = Cli::try_parse_from([
            "ec-secrets",
            "--config",
            cfg_path.to_str().unwrap(),
            "--key-provider",
            "file",
            "list",
        ])
        .unwrap();
        let cfg = build_credentials_config(&cli).unwrap();
        assert_eq!(cfg.vault.path, "from-config");
        assert_eq!(cfg.vault.key_provider.kind.as_deref(), Some("file"));
        // Untouched config field survives.
        assert_eq!(cfg.vault.key_provider.env_var.as_deref(), Some("CFG_KEK"));
    }

    #[test]
    fn config_errors_when_block_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("no-creds.json");
        std::fs::write(&p, r#"{ "component": {"token":"c"} }"#).unwrap();
        let cli =
            Cli::try_parse_from(["ec-secrets", "--config", p.to_str().unwrap(), "list"]).unwrap();
        assert!(build_credentials_config(&cli).is_err());
    }

    // ---- json_content_type ----
    #[test]
    fn structured_json_import_is_tagged_json() {
        assert_eq!(
            json_content_type(ImportFormat::Json, br#"{"a":1}"#).as_deref(),
            Some("application/json")
        );
        assert_eq!(json_content_type(ImportFormat::Json, b"plain"), None);
        assert_eq!(json_content_type(ImportFormat::Env, br#"{"a":1}"#), None);
    }

    // ---- clap wiring ----
    #[test]
    fn cli_parses_set_and_get() {
        let set = Cli::try_parse_from(["ec-secrets", "set", "db/pw", "s3cr3t"]).unwrap();
        assert!(matches!(set.command, Command::Set { .. }));
        let get = Cli::try_parse_from(["ec-secrets", "--json", "get", "db/pw", "--no-reveal"])
            .unwrap();
        assert!(get.json);
        assert!(matches!(
            get.command,
            Command::Get {
                no_reveal: true,
                ..
            }
        ));
    }

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Ok.code(), 0);
        assert_eq!(ExitCode::NotFound.code(), 1);
        assert_eq!(ExitCode::Usage.code(), 2);
        assert_eq!(ExitCode::VaultError.code(), 3);
    }
}

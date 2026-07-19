# ec-secrets — tool notes

EdgeCommons **secrets tool** (Rust). Repo/crate/bin `ec-secrets`. Depends on the `edgecommons`
Rust library. Read the org umbrella `../AGENTS.md` first (platform matrix, validation infra,
local-dev sibling override).

## What it is

A standalone ecosystem utility that seeds and inspects a **local** EdgeCommons credentials vault
from the command line. Components read secrets from the vault (`gg.credentials()`, `$secret` config
refs), but there was no credible tool to POPULATE one. `ec-secrets` fills that gap as a thin CLI
over the library's **own** vault, so every byte it writes is what a component decrypts — the same
envelope encryption, the same KeyProvider/KEK, the same on-disk format, the same key namespacing.

Scope is the **local vault only** — no AWS Secrets Manager (AWS has its own console/CLI for seeding
Secrets Manager). The `kms` KEK *custodian* is available behind an off-by-default cargo feature.

## How it works (the real library APIs it uses)

It opens the vault the exact way a component's runtime does — it does **not** reimplement any vault
crypto or format:

- **Config → service.** `ec_secrets::build_credentials_config` maps the flags (or a reused
  component `credentials` config block) onto an `edgecommons::credentials::CredentialsConfig`, then
  `ec_secrets::open_service` calls `edgecommons::credentials::open_namespaced_with_default(&cfg, ns,
  None)` — the same entry point the runtime builder uses. That builds the `KeyProvider`
  (`FileKeyProvider`/`EnvKeyProvider`/KMS, via the library's `build_key_provider`), opens the
  `LocalVault` at `vault.path`, and returns a `DefaultCredentialService`.
- **Ops.** The subcommands drive the `CredentialService` trait: `put` (set/import), `get`/
  `get_version`/typed views (get), `list` (names + metadata only), `delete`.
- **`$secret` proof.** `resolve_config_secrets` wraps `edgecommons::credentials::resolve_secret_refs`
  so a tool-seeded vault resolves the `{"$secret":"name"[, "field":"k"]}` config references a
  component uses.

Every public surface the tool needs is `pub` in `edgecommons::credentials` (`open_namespaced_with_default`,
`CredentialsConfig`/`VaultConfig`/`KeyProviderConfig`, `CredentialService`, `PutOptions`,
`resolve_secret_refs`, `FileKeyProvider`/`EnvKeyProvider`). The only `pub(crate)` helper,
`build_key_provider`, is reached transitively through the public `open_*` family, so no library
change was needed.

## CLI surface

`set` · `get` · `list` · `delete` · `import` (JSON object or dotenv) · `rotate-kek`. Global vault
selectors: `--vault`, `--key-provider file|env|kms`, `--keyfile`, `--kek-env`, `--kms-key-id`/
`--region`/`--endpoint-url`, `--config`, `--namespace`, `--keep-versions`, `--audit`, `--json`.
Exit codes: `0` ok · `1` not-found/refused · `2` usage · `3` vault/key-provider error.

`rotate-kek` reports that in-place KEK rotation is **not exposed** by the library (no public re-wrap
API) and exits `3` — the honest state; there is no hand-rolled re-encryption.

## Layout

- `src/lib.rs` — the reusable logic (clap `Cli`, config/provider mapping, JSON + dotenv import
  parsers, value-source selection, subcommand dispatch over a `CredentialService`) — unit-tested.
- `src/main.rs` — opens the vault and dispatches; stdout = output, stderr = logs.
- `examples/component_read.rs` — a stand-in component that opens the vault via
  `edgecommons::credentials::open` and decrypts a secret.
- `tests/seed_and_readback.rs` — hermetic proof: seed with the tool, read back through the library.

## Conventions

- **Depends on `edgecommons` by pinned git `rev`** (the `credentials` feature; same rev the
  reference components pin). A gitignored `.cargo/config.toml` patches it to
  `../edgecommons/core/libs/rust` for dev; CI uses the pinned rev. Do NOT edit `.cargo/config.toml`
  or the pin as part of feature work.
- **stdout is the command output only**; logs go to stderr (pipe-friendly).
- **BUSL-1.1**, `publish = false`.

## Synergy

`ec-secrets` is how you provision the TLS client cert/key/CA that the `ethernet-ip-adapter`'s CIP
Security reads from the vault: store a `tls/*` bundle here (a `{"certPem","keyPem","caPem"}` JSON
secret), then reference it from the adapter config with `{"$secret":"tls/cip-client"}`.

## Validation

```bash
cargo build --all-targets
cargo clippy --all-targets -- -D warnings
cargo test          # 12 unit + 6 hermetic integration tests (no external infra)
```

The integration suite creates a temp vault with a `file` KeyProvider, seeds it via the tool's real
`set`/`import` path, and reads every secret back through `edgecommons::credentials::open` (the
component path) — proving format/KEK compatibility. It needs no broker, AWS, or Greengrass.

# ec-secrets — EdgeCommons secrets tool

`ec-secrets` seeds and inspects a **local** EdgeCommons credentials vault from the command line. It
is a thin CLI over the EdgeCommons library's own vault, so everything it writes is byte-compatible
with what a component decrypts — the same envelope encryption, the same KeyProvider/KEK, the same
on-disk format, and the same key namespacing.

EdgeCommons components read secrets from the credentials vault (`gg.credentials()`, `$secret` config
references), but there is no in-band way to *populate* that vault. `ec-secrets` fills that gap: it
opens the vault exactly as a component would and stores, reads, lists, deletes, and bulk-imports
secrets.

Scope is the **local vault only**. Seeding AWS Secrets Manager is out of scope — AWS provides its
own console and CLI for that, and EdgeCommons syncs from Secrets Manager at runtime.

## What it does

- Opens the local vault at `--vault` with the selected `--key-provider` (`file`, `env`, or `kms`) —
  the same construction a component's runtime uses.
- `set` encrypts and stores a secret; the value comes from an inline argument, a file, or stdin.
- `get` decrypts and prints a secret (for verification), a single JSON field of it, or just its
  metadata.
- `list` prints names and metadata only, never values.
- `delete` removes a secret.
- `import` bulk-seeds from a JSON object (`{"name": "value", …}`) or a dotenv (`KEY=VALUE`) file.
- `rotate-kek` rotates the vault's KEK — it re-encrypts every secret under a new custodian and
  atomically swaps the new vault in (backing the original up to `<vault>.bak`).

Because it writes through the library's own vault, a component immediately decrypts what you seed —
no format guessing, no bespoke crypto.

## Install

`ec-secrets` is a Rust binary crate. It depends on the EdgeCommons Rust library by a pinned git
revision (the `credentials` feature only — no broker or transport).

```bash
cargo build --release
# binary at target/release/ec-secrets
```

For local development against a sibling `edgecommons` checkout, create a gitignored
`.cargo/config.toml` that patches the git dependency to your local library path (this repo ships one
for the reference layout):

```toml
[patch."https://github.com/edgecommons/edgecommons"]
edgecommons = { path = "../edgecommons/core/libs/rust" }

[net]
git-fetch-with-cli = true
```

## Usage

```text
ec-secrets [--vault <path>] [--key-provider file|env|kms] [--keyfile <f> | --kek-env <VAR>] <command>

  set <name> [<value> | --from-file <f> | --stdin] [--content-type <t>]
  get <name> [--version <v>] [--field <k>] [--no-reveal]
  list [--prefix <p>]
  delete <name>
  import <file> [--format json|env]
  rotate-kek [--new-key-provider file|env|kms] [--new-keyfile <f> | --new-kek-env <VAR>]
```

Every flag is documented in [`docs/reference/cli.md`](docs/reference/cli.md).

### Examples

Store a database password (the `file` KEK is generated at `<vault>.key` on first use):

```bash
ec-secrets --vault ./vault set db/password 's3cr3t'
# set db/password (version 00000001, 7 bytes)
```

Bulk-seed from a dotenv file, then a JSON object:

```bash
ec-secrets --vault ./vault import ./plant.env
ec-secrets --vault ./vault import ./secrets.json
```

List what is in the vault (names and metadata only):

```bash
ec-secrets --vault ./vault list
```

Read one back to verify a component will decrypt it:

```bash
ec-secrets --vault ./vault get db/password
# s3cr3t
```

Seed under a component namespace so a shared device vault does not collide:

```bash
ec-secrets --vault /var/edgecommons/vault --namespace gw-01/opcua-adapter set db/password 's3cr3t'
```

Select the vault and key provider from an existing component config's `credentials` block:

```bash
ec-secrets --config ./component-config.json set db/password 's3cr3t'
```

Rotate the vault's KEK — re-encrypt every secret under a fresh keyfile (current KEK from the global
flags, new KEK from `--new-*`):

```bash
ec-secrets --vault ./vault --keyfile ./old.key rotate-kek --new-key-provider file --new-keyfile ./new.key
# rotated 3 secret(s) in ./vault: file → file KEK (backup: ./vault.bak)
# the vault now opens ONLY under the new KEK; reopen it with the --new-* selectors you chose …
ec-secrets --vault ./vault --keyfile ./new.key get db/password   # decrypts under the new KEK
```

This is a re-encrypt-all rotation (each secret is briefly decrypted, then re-sealed under the new
KEK), made atomic by staging the new vault and swapping it in with a `<vault>.bak` backup. It is not
an envelope-only DEK re-wrap — that would need a new public API in the credentials library. It keeps
the latest version of each secret. See [`docs/reference/cli.md`](docs/reference/cli.md#rotate-kek).

## How it fits the ecosystem

- **The library's own vault.** `ec-secrets` calls `edgecommons::credentials::open_namespaced_with_default`
  — the same entry point a component's runtime uses — to build the KeyProvider and open the
  `LocalVault`. The bytes on disk are the normative cross-language vault format, so the Java, Python,
  Rust, and TypeScript ports all read what the tool writes.
- **`$secret` config references.** Seed a secret here, then reference it from any subsystem's config
  with `{"$secret": "name"}` (or `{"$secret": "name", "field": "key"}` for a field of a JSON
  secret). The library resolves it at subsystem-init time.
- **CIP Security synergy.** This is how you provision the TLS client certificate, private key, and CA
  that the `ethernet-ip-adapter`'s CIP Security reads from the vault. Store a
  `{"certPem": …, "keyPem": …, "caPem": …}` bundle under `tls/cip-client`, then point the adapter at
  it with `{"$secret": "tls/cip-client"}`. `ec-secrets` provisions; the adapter consumes.
- **Scriptable and CI-friendly.** stdout carries only the command output (logs go to stderr), and
  the process exit code reflects the outcome, so `ec-secrets` slots into provisioning scripts and
  end-to-end test setup.

## Key providers

| `--key-provider` | KEK source | Notes |
|------------------|-----------|-------|
| `file` (default) | 32 raw bytes in a key file (`--keyfile`, default `<vault>.key`) | Generated on first use. The offline / standalone custodian. |
| `env` | base64 32-byte KEK in an env var (`--kek-env`, default `EDGECOMMONS_VAULT_KEK`) | Cryptographically identical to `file`. The default vault custodian on Kubernetes (a mounted Secret). |
| `kms` | an AWS KMS CMK | Needs the `kms` build feature (`cargo build --features kms`) and live AWS credentials. |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The operation succeeded. |
| 1 | The secret was not found, or the operation was refused. |
| 2 | Usage / argument error. |
| 3 | A vault or key-provider error (wrong KEK, tampered file, unavailable provider, I/O). |

## Development

```bash
cargo build --all-targets
cargo clippy --all-targets -- -D warnings
cargo test          # 14 unit + 8 hermetic integration tests (no external infra)
```

The integration suite (`tests/seed_and_readback.rs`) creates a temp vault, seeds it through the
tool's real `set`/`import` path, and reads every secret back through `edgecommons::credentials::open`
— the same call a component makes — proving format and KEK compatibility. No broker, AWS, or
Greengrass is required.

## License

Business Source License 1.1 (BUSL-1.1) — see [`LICENSE`](LICENSE). Licensed Work: *EdgeCommons
Secrets Tool*. Converts to MPL-2.0 four years after each version's publication.

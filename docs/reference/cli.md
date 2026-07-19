# CLI reference

```text
ec-secrets [OPTIONS] <COMMAND>
```

`ec-secrets` opens a local EdgeCommons credentials vault the same way a component's runtime does — it
builds the KeyProvider and opens the `LocalVault` through the EdgeCommons library — then stores,
reads, lists, deletes, or bulk-imports secrets. Everything it writes is byte-compatible with what a
component decrypts.

## Commands

| Command | Meaning |
|---------|---------|
| `set <name> [<value>]` | Encrypt and store a secret. The value comes from the inline `<value>` argument, `--from-file <FILE>`, or `--stdin` (exactly one). |
| `get <name>` | Decrypt and print a secret. Prints the value by default; `--field` extracts one JSON field; `--no-reveal` prints only metadata. |
| `list` | Print secret names and metadata (version, source) — never values. |
| `delete <name>` | Remove a secret entirely. |
| `import <file>` | Bulk-seed from a JSON object (`{"name":"value",…}`) or a dotenv (`KEY=VALUE`) file. |
| `rotate-kek` | Rotate the vault's KEK: re-encrypt every secret under a NEW custodian and atomically swap it in. See [rotate-kek](#rotate-kek). |

## Global options (vault + key-provider selection)

These select which vault to open and how to unlock it — the same choices a component's `credentials`
config makes. They apply to every command.

| Option | Default | Meaning |
|--------|---------|---------|
| `--vault <PATH>` | `vault` | Path to the local vault file. The `file` keyfile defaults to `<vault>.key`. |
| `--key-provider <KIND>` | `file` | KEK custodian: `file`, `env`, or `kms`. `kms` needs the `kms` build feature. |
| `--keyfile <PATH>` | `<vault>.key` | KEK key file (32 raw bytes) for `--key-provider file`. Generated on first use if absent. |
| `--kek-env <VAR>` | `EDGECOMMONS_VAULT_KEK` | Env var holding the base64 32-byte KEK for `--key-provider env`. |
| `--kms-key-id <ID>` | — | AWS KMS key id/ARN for `--key-provider kms`. |
| `--region <REGION>` | — | AWS region for the `kms` provider. |
| `--endpoint-url <URL>` | — | Override the KMS endpoint (floci/LocalStack/VPC endpoint) for the `kms` provider. |
| `--config <FILE>` | — | Reuse an existing component config file's `credentials` block to select the vault + key provider. Individual flags override it. |
| `--namespace <NS>` | — | Transparent key namespace (typically `<thingName>/<componentName>`), prepended to every key so a shared device vault can't collide. Callers see the bare key. |
| `--keep-versions <N>` | `2` | Retained versions per secret; older versions are pruned. |
| `--audit` | off | Emit access-audit events (op/name/version, never the value) to the log. |
| `--json` | off | Machine-readable JSON output on stdout. |
| `-v`, `--verbose` | off | Verbose library/tool logging on stderr (default: warnings only). |
| `-h`, `--help` | — | Print help. |
| `-V`, `--version` | — | Print the version. |

The `RUST_LOG` environment variable overrides the log filter when set.

## `set`

```text
ec-secrets set <NAME> [VALUE] [--from-file <FILE> | --stdin] [--content-type <TYPE>]
```

| Argument / option | Meaning |
|-------------------|---------|
| `<NAME>` | The caller-facing key (e.g. `db/password`, `tls/cip-client`). |
| `[VALUE]` | The value, inline. Mutually exclusive with `--from-file` and `--stdin`. |
| `--from-file <FILE>` | Read the value as raw bytes from a file. |
| `--stdin` | Read the value as raw bytes from standard input. |
| `--content-type <TYPE>` | Content-type label stored with the secret (default `application/octet-stream`). |

Exactly one value source is required. `set` stores a new version and prints the version id.

## `get`

```text
ec-secrets get <NAME> [--version <VERSION>] [--field <KEY>] [--no-reveal]
```

| Option | Meaning |
|--------|---------|
| `--version <VERSION>` | Read a specific version id instead of the latest. |
| `--field <KEY>` | Extract a single string field from a JSON secret (the `$secret` `field` model). |
| `--no-reveal` | Print only metadata (name, version, created, source, content-type); never the value. |

A UTF-8 value prints as text; a non-UTF-8 (binary) value is written to stdout as raw bytes. Exit `1`
if the secret (or requested version) is absent.

## `list`

```text
ec-secrets list [--prefix <PREFIX>]
```

Prints one line per secret — `name`, version, and source — or, with `--json`, an array of
`{name, version, createdMs, source}`. Values are never printed. `--prefix` filters to names starting
with the given string.

## `delete`

```text
ec-secrets delete <NAME>
```

Removes the secret entirely. Exit `1` if it did not exist.

## `import`

```text
ec-secrets import <FILE> [--format json|env]
```

Bulk-seeds many secrets. The format is inferred from the extension (`.json` → JSON object, `.env` →
dotenv) and then the content (a leading `{` is JSON), or forced with `--format`.

- **JSON object** — a top-level object of name → value. A string value is stored as-is; a nested
  object or array is stored as JSON and tagged `application/json`.
- **dotenv** — `KEY=VALUE` lines. Blank lines and `#` comments are skipped, an `export` prefix is
  allowed, whitespace is trimmed, one layer of matching quotes is stripped, and a ` #` after an
  unquoted value starts a trailing comment.

## rotate-kek

```text
ec-secrets rotate-kek [--new-key-provider file|env|kms]
                      [--new-keyfile <PATH>] [--new-kek-env <VAR>]
                      [--new-kms-key-id <ID>] [--new-region <REGION>] [--new-endpoint-url <URL>]
```

Rotates the vault's KEK. The SOURCE vault and current KEK are selected by the global flags
(`--vault`, `--key-provider`, `--keyfile`/`--kek-env`/…); the `--new-*` options select the NEW
custodian, mirroring the global ones.

| Option | Meaning |
|--------|---------|
| `--new-key-provider <KIND>` | The new KEK custodian: `file`, `env`, or `kms`. Defaults to the provider implied by whichever `--new-*` selector is given (`--new-keyfile` ⇒ `file`, `--new-kek-env` ⇒ `env`, `--new-kms-key-id` ⇒ `kms`), else `file`. |
| `--new-keyfile <PATH>` | New keyfile (32 raw bytes) for `--new-key-provider file`. Generated if absent (as the vault-open path does); an existing file is loaded as the new KEK. Defaults to `<vault>.key` — which is refused when it is the current keyfile. |
| `--new-kek-env <VAR>` | Env var holding the base64 32-byte new KEK for `--new-key-provider env`. |
| `--new-kms-key-id <ID>` / `--new-region <REGION>` / `--new-endpoint-url <URL>` | New `kms` custodian selection (needs the `kms` build feature). |

**How it works — a re-encrypt-all rotation.** The EdgeCommons library exposes no public in-place DEK
re-wrap, so `ec-secrets` performs the rotation itself over the library's public vault APIs: it opens
the source vault with the current KEK, decrypts the latest version of every secret (across all
namespaces), builds a brand-new vault under the new KEK at a temp path on the same filesystem, writes
every secret into it, and then **atomically** renames the new vault over the original — backing the
original up to `<vault>.bak` first and rolling back on any failure, so a vault is never left
half-rotated. For the `file` custodian a freshly generated new keyfile is installed alongside the
vault in the same swap.

This means each secret is **briefly decrypted in process** and re-sealed under the new KEK; it is not
an envelope-only re-wrap of the untouched ciphertext. A true in-place DEK re-wrap would require a new
`pub` method in the credentials library (a four-language parity change) — a follow-up. Only the
**latest version** of each secret is carried over: the library's public `put` mints a fresh version
id and timestamp, so historical versions and original `createdMs` are not reproduced.

After rotation the vault opens **only** under the new KEK — reopen it with the `--new-*` key material
you chose (`--keyfile <new>` / `--kek-env <VAR>` / …); the old KEK no longer decrypts it. The
`<vault>.bak` (encrypted under the old KEK) is left for rollback.

A failure before the swap (an unavailable new provider — a missing `env` KEK, or `kms` without the
build feature — or a no-op rotation to the current keyfile) leaves the original vault untouched and
exits `3`.

## The vault and key provider

`ec-secrets` opens the vault through `edgecommons::credentials::open_namespaced_with_default` — the
same call a component's runtime makes. The vault is a single encrypted JSON file in the normative
cross-language format; a per-vault Data Encryption Key seals each record with AES-256-GCM, and that
DEK is wrapped by the KEK from the selected key provider:

- `file` — the KEK is 32 raw bytes in a key file. The offline / standalone custodian.
- `env` — the KEK is a base64 32-byte value in an environment variable (typically a mounted
  Kubernetes Secret). Cryptographically identical to `file`.
- `kms` — the KEK is an AWS KMS CMK; the DEK is wrapped by KMS. Needs the `kms` build feature and
  live AWS credentials.

A wrong KEK, a tampered file, or an unavailable provider fails closed (exit `3`) — the vault never
returns plaintext under the wrong key.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The operation succeeded. |
| `1` | The secret was not found, or the operation was refused. |
| `2` | Usage / argument error (missing/duplicate value source, bad flag, malformed import). |
| `3` | A vault or key-provider error (wrong KEK, tampered file, unavailable provider, I/O). |

## Output streams

stdout carries only the command output (values, listings, JSON), so the tool composes in pipelines.
Logs, diagnostics, and error summaries go to stderr.

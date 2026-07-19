# Tutorial: seed your first vault

This tutorial creates a local EdgeCommons credentials vault with `ec-secrets`, stores a few secrets,
and reads one back to prove that a component decrypts what you seeded. By the end you understand the
vault, the key provider, and the `$secret` reference a component uses.

You need only a Rust toolchain — no broker, no AWS, no Greengrass.

## 1. Build ec-secrets

```bash
cargo build --release
# binary at target/release/ec-secrets
```

## 2. Store your first secret

Pick a vault path. On the first write, the `file` key provider generates a 32-byte KEK at
`<vault>.key` and creates the vault file:

```bash
ec-secrets --vault ./vault set db/password 's3cr3t'
```

```text
set db/password (version 00000001, 7 bytes)
```

Two files now exist: `./vault` (the encrypted secret store) and `./vault.key` (the KEK). The vault
is unreadable without the keyfile.

## 3. Store a JSON secret

A secret value can be any bytes, including a JSON document. Store a TLS bundle — the shape a
component reads through a typed view:

```bash
ec-secrets --vault ./vault set tls/cip-client \
  '{"certPem":"-----BEGIN CERTIFICATE-----\n…","keyPem":"-----BEGIN PRIVATE KEY-----\n…"}' \
  --content-type application/json
```

## 4. Import a batch

Real provisioning seeds many secrets at once. Create a dotenv file:

```bash
cat > plant.env <<'EOF'
# line-1 credentials
export DB_PASSWORD=pgpw
API_KEY="a b c"
EOF

ec-secrets --vault ./vault import plant.env
```

```text
imported 2 secret(s) from plant.env
```

`import` also accepts a JSON object file (`{"name": "value", …}`); see the
[how-to guides](how-to-guides.md).

## 5. See what is in the vault

`list` prints names and metadata only — never values, so it is safe to run and log:

```bash
ec-secrets --vault ./vault list
```

```text
API_KEY         (version 00000001, source local)
DB_PASSWORD     (version 00000001, source local)
db/password     (version 00000001, source local)
tls/cip-client  (version 00000001, source local)
```

## 6. Read one back

`get` decrypts and prints a value, so you can verify a component will decrypt it:

```bash
ec-secrets --vault ./vault get db/password
```

```text
s3cr3t
```

Extract a single field from a JSON secret:

```bash
ec-secrets --vault ./vault get tls/cip-client --field certPem
```

## 7. How a component reads it

A component opens the same vault through the EdgeCommons library — the `gg.credentials()` service —
and either reads a value directly or lets a `$secret` config reference resolve it:

```json
{ "sink": { "password": { "$secret": "db/password" } } }
```

Because `ec-secrets` wrote through the library's own vault, the value the component decrypts is
exactly the `s3cr3t` you stored — same encryption, same KEK, same format.

## Where to go next

- The [how-to guides](how-to-guides.md) cover JSON import, TLS bundles for CIP Security, namespacing
  a shared device vault, the env and KMS key providers, and CI seeding.
- The [CLI reference](reference/cli.md) documents every command, flag, and exit code.

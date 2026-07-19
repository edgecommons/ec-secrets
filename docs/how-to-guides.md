# How-to guides

Task recipes for `ec-secrets`. Each assumes a vault at `./vault` with the default `file` key
provider unless stated otherwise. See the [CLI reference](reference/cli.md) for every flag.

## Store a value from a file or stdin

Avoid putting a secret in your shell history or process list by reading it from a file or a pipe:

```bash
ec-secrets --vault ./vault set tls/key --from-file ./client.key
printf '%s' "$TOKEN" | ec-secrets --vault ./vault set api/token --stdin
```

The file or stream is stored as raw bytes, so binary values (a DER certificate, a keystore)
round-trip exactly.

## Import from a JSON object

A JSON import is a top-level object mapping name → value. A string value is stored as-is; a nested
object or array is stored as JSON (tagged `application/json`), so a component reads it back through a
typed view:

```json
{
  "svc/token": "tok-123",
  "kafka/sasl": { "username": "ku", "password": "kp" },
  "aws/main": { "accessKeyId": "AKIA…", "secretAccessKey": "…" }
}
```

```bash
ec-secrets --vault ./vault import secrets.json
```

The format is inferred from the `.json` extension; force it with `--format json` for an unusual
filename.

## Import from a dotenv file

A dotenv import reads `KEY=VALUE` lines. Blank lines and `#` comments are skipped, an `export`
prefix is allowed, surrounding whitespace is trimmed, one layer of matching quotes is stripped, and a
` #` after an unquoted value begins a trailing comment:

```bash
cat > plant.env <<'EOF'
export DB_PASSWORD=pgpw
API_KEY="a b c"
ENDPOINT=10.0.0.5   # the historian
EOF

ec-secrets --vault ./vault import plant.env
```

The format is inferred from `.env` in the filename; force it with `--format env`.

## Provision a TLS bundle for CIP Security

The `ethernet-ip-adapter`'s CIP Security reads its client certificate, private key, and CA from the
vault. Store them as one JSON bundle:

```bash
ec-secrets --vault ./vault set tls/cip-client \
  "$(jq -n --arg c "$(cat client.crt)" --arg k "$(cat client.key)" --arg ca "$(cat ca.crt)" \
     '{certPem:$c, keyPem:$k, caPem:$ca}')" \
  --content-type application/json
```

Then reference it from the adapter config:

```json
{ "cipSecurity": { "$secret": "tls/cip-client" } }
```

`ec-secrets` provisions the bundle; the adapter consumes it at startup.

## Namespace a shared device vault

Several components on one device can share a single vault file without colliding by using a
transparent namespace — typically `<thingName>/<componentName>`. Seed each component's secrets under
its namespace:

```bash
ec-secrets --vault /var/edgecommons/vault --namespace gw-01/opcua-adapter set db/password 's3cr3t'
ec-secrets --vault /var/edgecommons/vault --namespace gw-01/modbus-adapter set db/password 'other'
```

Each component, opening the vault with its own namespace, sees only its own `db/password`. On disk
the keys are fully qualified (`gw-01/opcua-adapter/db/password`), so they never collide.

## Use the env key provider

On Kubernetes the KEK is usually a mounted Secret projected into an environment variable. Seed the
vault with the same custodian a component uses:

```bash
export EDGECOMMONS_VAULT_KEK="$(head -c 32 /dev/urandom | base64)"
ec-secrets --vault ./vault --key-provider env set db/password 's3cr3t'
```

Point at a differently named variable with `--kek-env MY_KEK`. The `env` provider is
cryptographically identical to `file` given the same 32 raw bytes, so a vault seeded one way opens
the other way with the matching key.

## Use the AWS KMS key provider

Build with the `kms` feature and select the KMS custodian (this needs live AWS credentials):

```bash
cargo build --release --features kms
ec-secrets --vault ./vault --key-provider kms --kms-key-id alias/edgecommons-vault \
  --region us-east-1 set db/password 's3cr3t'
```

Without the `kms` feature, `--key-provider kms` reports that the provider is unavailable and exits
`3`.

## Reuse a component's config

Instead of repeating `--vault`/`--key-provider` flags, point `ec-secrets` at an existing component
config file; it reads the vault path and key provider from that file's `credentials` block:

```bash
ec-secrets --config ./component-config.json set db/password 's3cr3t'
```

Individual flags still override the config (for example, add `--vault ./other` to redirect the path).

## Seed in a CI pipeline

`ec-secrets` writes only its command output to stdout and returns a meaningful exit code, so it
composes in scripts:

```bash
set -euo pipefail
ec-secrets --vault "$VAULT" --key-provider env import ./ci-secrets.json
ec-secrets --vault "$VAULT" --key-provider env --json list
```

Read a value into a variable for a later step (its exit code is `1` if the secret is absent):

```bash
password="$(ec-secrets --vault "$VAULT" --key-provider env get db/password)"
```

## Get JSON output

Add `--json` to any command for machine-readable output:

```bash
ec-secrets --vault ./vault --json get db/password
# { "name": "db/password", "value": "s3cr3t", "version": "00000001" }
ec-secrets --vault ./vault --json list
# [ { "name": "db/password", "version": "00000001", "createdMs": …, "source": "local" }, … ]
```

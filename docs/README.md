# ec-secrets documentation

`ec-secrets` seeds and inspects a local EdgeCommons credentials vault from the command line. It is a
thin CLI over the EdgeCommons library's own vault, so everything it writes is byte-compatible with
what a component decrypts (`gg.credentials()`, `$secret` config references) — the same envelope
encryption, KeyProvider/KEK, on-disk format, and key namespacing.

Components read secrets from the vault, but there is no in-band way to populate one. `ec-secrets`
opens the vault exactly as a component would and stores, reads, lists, deletes, and bulk-imports
secrets. Its scope is the local vault only — AWS Secrets Manager has its own console and CLI, and
EdgeCommons syncs from it at runtime.

## Pages

- **[Tutorial](tutorial.md)** — a guided first session: create a vault, store a secret, import a
  batch, and read one back to prove a component decrypts it.
- **[How-to guides](how-to-guides.md)** — task recipes: import from JSON and dotenv, store a TLS
  bundle for CIP Security, namespace a shared device vault, use the env or KMS key provider, reuse a
  component config, and seed in a CI pipeline.
- **[CLI reference](reference/cli.md)** — every command, flag, exit code, and the vault/key-provider
  model.

## The secret model

A secret is a **named, versioned, opaque byte blob**. `ec-secrets` stores the bytes you give it; the
library encrypts them with the vault's Data Encryption Key (AES-256-GCM) and persists them in the
normative cross-language vault format. A value may be any bytes: a password, a token, or a JSON
document such as a TLS bundle or a set of AWS credentials that a component later reads through a typed
view.

## `$secret` references

Once a secret is seeded, any subsystem's config references it instead of embedding the value:

```json
{ "sink": { "password": { "$secret": "db/password" } } }
```

```json
{ "tls": { "$secret": "tls/cip-client", "field": "certPem" } }
```

The library resolves these at subsystem-init time, so the value never lands in a logged or templated
config snapshot.

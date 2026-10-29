# Secrets

The `secrets-rs` crate: how a service turns a credential item into the values a script or a
login needs. The principle every service follows: **configuration never holds a secret**.

A credential describes *where* each value lives, and the infrastructure (env vars, mounted files,
Vault) delivers it. The YAML fields a person writes are documented in each service's own docs
(`docs/secrets.md` in unified-api and unified-gitops); this page is the crate behind them.

- [Modules](#modules)
- [The credential item](#the-credential-item)
- [Building the chain](#building-the-chain)
- [Resolution and caching](#resolution-and-caching)
- [Reloading](#reloading)
- [Testing with the mock](#testing-with-the-mock)

---

## Modules

The crate is a port, its adapters, and the one function that wires them together.

| Module | What it holds |
|---|---|
| `credential` | `Credential` and `CredentialType`, as the YAML declares them; `delivery_id`, `variable_part` |
| `port` | `SecretsPort` (resolve a credential id to its values), `SecretsSwapPort`, `SecretsError` |
| `env` | `EnvSecrets`: environment variables (`env_vars`, or the deprecated `env_prefix`) and JSON files |
| `vault` | `VaultSecrets` and `VaultConfig`: KV v2 over HTTP, token or Kubernetes auth |
| `cache` | `CachedSecrets`: a TTL in front of any `SecretsPort`; errors are never cached |
| `reloadable` | `ReloadableSecrets`: a chain that a configuration reload can replace |
| `chain` | `build_chain` and `SecretsConfig`, the deprecated `secrets:` block of `config.yaml` |
| `mock` | `MockSecrets`, the test double |

The names a service uses most are re-exported at the crate root: `secrets_rs::{Credential,
CredentialType, SecretsPort, SecretsError, SecretsConfig, build_chain}`.

---

## The credential item

`Credential` is one entry of a service's `credentials` items, strict like every configuration struct.

The identity is not a field: it is the key of the map the credentials live in, and what references
and cache keys use. The two labels are for people, and each service fills the one it shows:

| Field | Filled by | Used by |
|---|---|---|
| `name` | unified-api's loader: the item's `description`, falling back to its identity | unified-api's credentials API |
| `description` | the YAML as written | unified-gitops' credentials API |

Both default, so the YAML a person writes is the same for either service. What a credential may
combine (`env_vars` beside a `vault_path`, a Vault without an address) is checked by each service
when it loads its configuration, in the service's own words.

`backend()` says where the values are read from (`vault`, `env`, `file`, or `files` for a credential
made only of `file_keys`), and `env_var_names()` lists the variables an env credential reads, spelled
exactly as the resolver reads them.

---

## Building the chain

A service builds one `SecretsPort` from its loaded credentials, and resolves everything through it.

```rust
let secrets: Arc<dyn SecretsPort> =
    secrets_rs::build_chain(&config.credentials, &config.secrets_config);
let values = secrets.resolve("cred-vcenter-aa1").await?; // {"username": ..., "password": ...}
```

`build_chain` routes each credential to where its values live:

1. A `type: vault` credential is a Vault connection, not a login: resolving it only checks that its
   token variable is set.
2. A credential with `vault_path` and `vault: <name>` reads from that Vault's client. Each Vault
   gets its own client, behind its own `cache_ttl_seconds` (default 60).
3. A credential with `vault_path` and no `vault:` reads from the deprecated `secrets.vault` block,
   which keeps the 60-second cache it always had.
4. Anything else reads from environment variables or its JSON file, fresh on every resolution.

While the deprecated `secrets.cache_ttl_seconds` is set, it wraps the whole chain in one cache in
place of each Vault's own, as it did before Vaults were credentials.

---

## Resolution and caching

Environment variables and files are read on every resolution; only a Vault's answers are cached.

Env vars cannot change under a running process, and a file is a cheap local read that should pick a
rotation up at once, so neither is worth caching. A Vault is a network round trip on every sync of
every source, so its values are reused for `cache_ttl_seconds` — which is also the rotation latency.
`0` reads Vault on every resolution.

A failed resolution is never cached: the next one asks again. The error names the credential and
what was missing (`Env var 'D42_PASSWORD' not set`), and a service reports it where the run that
needed it failed.

---

## Reloading

A configuration reload replaces the chain under a running process, without a restart.

`ReloadableSecrets` implements both ports: everything in the service resolves through it as a
`SecretsPort`, and exactly one thing, the reload, holds it as a `SecretsSwapPort` to `replace` the
chain with one built from the new configuration. Resolutions already running finish on the old one.

---

## Testing with the mock

`MockSecrets` answers from a map, so a service's tests need no environment variables or Vault.

```rust
let secrets = secrets_rs::mock::MockSecrets::new()
    .with("cred-ldap", [("username", "CN=svc"), ("password", "secret")]);
```

An id it was not given fails like a missing credential does, which is how a test checks the error a
service shows.

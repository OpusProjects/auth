# Development

How the workspace is laid out, what CI checks, and how a service depends on these crates — including
building a service against a local copy before anything is released.

- [Layout](#layout)
- [CI gates](#ci-gates)
- [How a service depends on the crates](#how-a-service-depends-on-the-crates)
- [Working on a service against a local copy](#working-on-a-service-against-a-local-copy)
- [Where new code goes](#where-new-code-goes)
- [Tests and coverage](#tests-and-coverage)

---

## Layout

One Cargo workspace with two crates, sharing one version and one `Cargo.lock`.

```
Cargo.toml                    # the workspace: members, shared version, shared dependency versions
crates/
├── unified-secrets/src/      # credential, port, env, vault, cache, reloadable, chain, mock
└── unified-auth/src/         # directory, ldap_directory, ldap, login, http/ (auth, session)
docs/                         # this documentation
release-please-config.json    # release-please: version files, changelog sections
.release-please-manifest.json # the last released version
```

`unified-auth` depends on `unified-secrets` (the LDAP bind credential is resolved through it), never
the reverse, so a tool that only needs secrets can depend on `unified-secrets` alone.

---

## CI gates

`.github/workflows/build.yaml` runs these on every pull request; `test` is the required check.

| Job | What it checks |
|---|---|
| `test` | `cargo fmt --check`, clippy with warnings as errors, a check under the MSRV, tests with 100% line coverage |
| `audit` | `cargo audit`: no RUSTSEC advisory in `Cargo.lock` (also nightly, on `main`) |
| `deny` | `cargo deny check`: licenses, sources and advisories, per `deny.toml` (also nightly) |

The MSRV is `rust-version` in `Cargo.toml`, the same as the services': a language feature newer
than their pinned toolchain must fail here, not in their builds.

---

## How a service depends on the crates

unified-api and unified-gitops name a release tag of this repository in their `Cargo.toml`.

```toml
unified-secrets = { git = "https://github.com/OpusProjects/unified-auth", tag = "v0.1.0" }
unified-auth = { git = "https://github.com/OpusProjects/unified-auth", tag = "v0.1.0" }
```

Both lines name the same tag: the crates are released together. The services' `deny.toml` allows
this one git source (`[sources] allow-git`), which every other git dependency is refused by.

Moving a service to a new release is a `build:` pull request in the service that changes both tags
and its `Cargo.lock` (`cargo update -p unified-secrets -p unified-auth`).

---

## Working on a service against a local copy

A change here is a change in both services, so build them against it before it is merged.

With unified-auth checked out next to the service, add a `[patch]` section to the service's
`Cargo.toml` **without committing it**:

```toml
[patch."https://github.com/OpusProjects/unified-auth"]
unified-secrets = { path = "../unified-auth/crates/unified-secrets" }
unified-auth = { path = "../unified-auth/crates/unified-auth" }
```

Then run the service's own gates (`cargo clippy --all-targets -- -D warnings` and `cargo test`):
its integration tests are what prove a change here did not alter what the service does. Remove the
section before committing anything in the service.

---

## Where new code goes

New code goes in the crate whose job it is, with its tests in the same file.

- **A new secrets backend:** a `SecretsPort` adapter in `unified-secrets`, and a route to it in
  `chain.rs`. The YAML fields it adds belong on `Credential`, strict like the rest.
- **A new way to sign in:** a `DirectoryPort` adapter, or a new use case beside `login.rs`, in
  `unified-auth`; a new way to authenticate a request belongs in its `http` module.
- **Anything one service needs and the other does not:** in that service, not here.

Every new line comes with the test that runs it; see [Tests and coverage](#tests-and-coverage).

---

## Tests and coverage

Every line of both crates runs in a test, and the `test` check fails a pull request that changes that.

| Where | What goes there |
|---|---|
| `#[cfg(test)] mod tests` at the bottom of a file in `src/` | Unit tests of that file, including its private functions |
| `crates/unified-secrets/tests/vault_test.rs` | The Vault adapter against a fake Vault: a few axum routes on `127.0.0.1` |
| `crates/unified-auth/tests/ldap_directory_test.rs` | The LDAP adapter against a fake directory that speaks just enough LDAP (bind, search, unbind) |

The suite needs no directory, Vault or network. Test code under `tests/` is not counted by
`cargo llvm-cov`, which is why the two fakes live there: their own error handling would otherwise
be lines no test reaches.

```bash
cargo llvm-cov --workspace --summary-only          # the number CI checks (lines: 100%)
cargo llvm-cov --workspace --html --open           # which lines a change left uncovered
```

Two habits keep the number honest. A value logged as a field is computed into a local first
(`let groups = user.member_of.len(); tracing::warn!(groups, ...)`), because `tracing` expands a field
expression twice and one copy only runs without a subscriber. And a failure that cannot happen with
the dependencies as configured is an `expect` naming why, not an error path no test can reach.

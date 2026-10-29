# Unified Auth

[![unified-auth CI](https://github.com/OpusProjects/unified-auth/actions/workflows/build.yaml/badge.svg)](https://github.com/OpusProjects/unified-auth/actions/workflows/build.yaml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg?logo=rust)](https://www.rust-lang.org/)

Secrets and sign-in shared by the unified tools, written in Rust.

Unified Auth holds the code [unified-api](https://github.com/OpusProjects/unified-api) and
[unified-gitops](https://github.com/OpusProjects/unified-gitops) both need to read a credential and
to sign a person in, so a fix to either lands in both tools at once instead of being copied by hand.

Two crates in one workspace, released together under one tag: `unified-secrets` resolves credentials
from environment variables, JSON files or HashiCorp Vault, and `unified-auth` signs people in with
their directory account or an API key and keeps them signed in with a browser session.

---

## ✨ Features

- **One credential model**: env vars, a JSON file or Vault KV v2, chosen per credential
- **Native Vault**: token or Kubernetes auth, several Vaults side by side, each with its own cache
- **Read fresh, cache briefly**: env and files on every use; Vault for `cache_ttl_seconds`
- **Swappable chain**: a configuration reload replaces the resolver under a running process
- **LDAP / Active Directory sign-in**: search-then-bind, StartTLS or LDAPS, a private CA
- **Access rules stay the service's own**: any rule type, matched by user name or group
- **Login throttle**: per-account failure limit, equal timing for wrong users and passwords
- **API key middleware**: constant-time key check, keys swappable by a reload, open when none
- **Browser sessions**: in memory, revoked with their key or the LDAP block, CSRF on every write
- **Pinned by tag**: the services depend on a `vX.Y.Z` tag of this repository, never on `main`

---

## 📚 Documentation

| Document | What it covers |
|---|---|
| [Secrets](docs/secrets.md) | The `unified-secrets` crate: credentials, the backends, `build_chain` and caching |
| [Sign-in](docs/sign-in.md) | The `unified-auth` crate: LDAP, access rules, the login, API keys, sessions |
| [Development](docs/development.md) | The workspace, the CI gates, and working on a service against a local copy |
| [Releasing](docs/releasing.md) | How release-please cuts a version, and how the services move to it |

---

## 🤝 Contributing

Contributions are welcome: [CONTRIBUTING.md](CONTRIBUTING.md) covers the PR workflow, commit style, CI gates and design rules.

Security issues: see [SECURITY.md](SECURITY.md) for private reporting.

---

## 👥 Authors

- [Fernando Roca](https://github.com/fernandorocagonzalez)
- [Blai Peidro](https://github.com/blaipr)

---

## ⚖️ License

[Apache 2.0](LICENSE)

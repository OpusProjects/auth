# Contributing to Unified Auth

Thanks for helping out! This is a small project with a few firm conventions —
following them keeps the history clean and the two services that use it safe.

## Workflow: one logical change per PR

`main` moves only through squash-merged pull requests, one **logical change** per PR —
a fix, a dependency bump, a doc edit each get their own. This keeps every change
independently reviewable, bisectable, and revertable.

```bash
git checkout main && git pull
git checkout -b <type>/<short-name>       # e.g. fix/vault-token-renewal
# ...make exactly one change, test it...
git commit -am "Short imperative title"
git push -u origin <type>/<short-name>
gh pr create --base main
```

### Commit / PR message style

Commit and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
release-please reads them to pick the next version and to write the CHANGELOG.

- Title: `<type>: short imperative summary`, lowercase after the colon —
  `feat: read a credential from a second Vault mount`, `fix: renew a
  Kubernetes Vault token before its lease ends`. Types in use: `feat`, `fix`,
  `perf`, `refactor`, `docs`, `test`, `build`, `chore`.
- A breaking change adds `!` after the type (`feat!: ...`) or a
  `BREAKING CHANGE:` footer in the body.
- The squashed title is the CHANGELOG line and decides the next version, so
  write it for someone reading the release notes: what changes for them. See
  [docs/releasing.md](docs/releasing.md).
- Body (when the change needs explaining): plain prose, *what* and *why*, wrapped
  at ~72 columns. The problem first, then the change.

## CI gates

Every PR must pass, in this order (run them locally before pushing):

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Design rules

These crates are libraries two services build on; three rules keep them that way:

1. **Nothing service-specific.** A source, an endpoint or an application never
   appears here. What differs between the services — the label a credential
   shows, what an access rule grants — stays in the service, behind a generic
   parameter or a trait (`LdapConfig<R>`, `AccessRule`).
2. **Configuration stays strict.** Every struct a service deserializes from
   YAML carries `deny_unknown_fields`, as the services' own do: a typo fails
   the load naming the key.
3. **A change here is a change in both services.** Before merging, build
   unified-api and unified-gitops against your branch (see
   [docs/development.md](docs/development.md#working-on-a-service-against-a-local-copy)).

`unified-auth` depends on `unified-secrets`, never the reverse.

## Code comments

The codebase carries **teaching comments** that explain Rust concepts to the
maintainers. They are intentional — do not strip them when refactoring; move them
with the code they explain. When you add a non-obvious Rust construct, a comment in
the same spirit is welcome. Beyond those, comment only when the *why* is non-obvious.

## Releases

Releases are cut by release-please; no one bumps a version, edits the CHANGELOG
or pushes a tag by hand. Every merge into `main` updates one open
`chore: release vX.Y.Z` pull request, and merging it creates the tag the
services pin and the GitHub Release. See [docs/releasing.md](docs/releasing.md).

## Running the test suite

```bash
cargo test --workspace    # both crates; no directory, Vault or network needed
```

The Vault tests answer from a local socket and the LDAP tests stop before any
connection is made, so the suite needs no external services. See
[docs/development.md](docs/development.md) for the layout and where new tests belong.

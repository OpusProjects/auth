<!--
One logical change per PR (see CONTRIBUTING.md). Describe the problem first,
then the change. Delete sections that don't apply.
-->

## Problem

What's wrong or missing today?

## Change

What this PR does, and why this approach.

## Compatibility

Any change for the services that pin this repository, or for their
configuration? Note breaking changes here (and mark the title with `!`,
e.g. `feat!: ...`).

## Checklist

- [ ] `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` pass locally
- [ ] Tests added or updated for the change
- [ ] Docs updated (`README.md`, `docs/`) if behavior or config changed
- [ ] The title reads as a CHANGELOG line for users (it becomes one: see `docs/releasing.md`)

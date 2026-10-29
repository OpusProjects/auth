# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0](https://github.com/OpusProjects/auth/compare/v0.2.0...v0.3.0) (2026-10-29)


### ⚠ BREAKING CHANGES

* a service depends on auth-rs and secrets-rs instead of unified-auth and unified-secrets, and imports auth_rs:: and secrets_rs::.

### Added

* rename the crates to auth-rs and secrets-rs ([#8](https://github.com/OpusProjects/auth/issues/8)) ([529bdb9](https://github.com/OpusProjects/auth/commit/529bdb9222122daefb1daf335a532771b8dd6f85))

## [0.2.0](https://github.com/OpusProjects/unified-auth/compare/v0.1.0...v0.2.0) (2026-10-29)


### Added

* share API key authentication and browser sessions ([#5](https://github.com/OpusProjects/unified-auth/issues/5)) ([76ba507](https://github.com/OpusProjects/unified-auth/commit/76ba5071da452e9250fe3e83009ca63f1e1d9352))

## 0.1.0 (2026-10-29)


### Added

* secrets and LDAP sign-in shared by unified-api and unified-gitops ([3a0daa8](https://github.com/OpusProjects/unified-auth/commit/3a0daa8ede8a6b2791ce4d1c211d2d47a379c5b6))

# Security Policy

## Supported versions

Only the latest release line receives security fixes.

| Version | Supported |
|---|---|
| 0.x (latest release) | Yes |
| older tags | No |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting instead:
[Report a vulnerability](https://github.com/OpusProjects/auth/security/advisories/new)
— it opens a private thread with the maintainers.

Include what you can: affected crate or module, the service and version you saw
it in, reproduction steps, and impact. You should hear back within a week. Once
a fix ships, the advisory is published and credited unless you prefer otherwise.

## Scope notes

- This repository is the secrets and sign-in code of unified-api and
  unified-gitops: a vulnerability here is one in both. A fix is released here
  first, then each service moves to the new tag; the advisory names the
  service versions that carry it.
- **Secrets are never stored.** A credential names where its values live
  (environment variables, a JSON file, a Vault KV v2 path); they are read when
  a service asks. Environment and file credentials are read on every use; a
  value read from Vault is held in memory for the Vault credential's
  `cache_ttl_seconds` (default 60), which is also how long a rotation takes to
  be seen.
- **Vault access is read-only:** KV v2 `GET` requests only, logged in with a
  token from an environment variable or with Kubernetes auth. Give the token or
  role a policy that can read exactly the paths the credentials name.
- **LDAP sign-in** refuses an empty password before contacting the directory
  (an unauthenticated bind would otherwise succeed) and escapes the typed
  username in the search filter (RFC 4515). The services refuse a plain
  `ldap://` URL without StartTLS when they load their configuration, since it
  would send every password in the clear.
- The directory only says who someone is; **access comes from the service's
  rules**, and a person no rule names is refused even with a correct password.
- The login throttle refuses an account after 5 failed passwords in 15 minutes
  without asking the directory, well under any sensible directory lockout, and
  answers every failure after the same delay, so timing does not reveal which
  usernames exist. It is per process and in memory.

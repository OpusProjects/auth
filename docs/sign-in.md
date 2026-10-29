# Sign-in

The `auth-rs` crate: signing a person in with their directory account (LDAP or Active
Directory), deciding what that gets them through the service's own access rules, and authenticating
every request after that, by API key or by browser session.

The YAML a person writes (`server.ui.ldap` in a service's `config.yaml`) is documented in each
service's `docs/ldap-login.md`; this page is the crate behind it.

- [Modules](#modules)
- [The LDAP block and a service's rules](#the-ldap-block-and-a-services-rules)
- [Implementing AccessRule](#implementing-accessrule)
- [The login use case](#the-login-use-case)
- [The throttle](#the-throttle)
- [The directory adapter](#the-directory-adapter)
- [API keys and the middleware](#api-keys-and-the-middleware)
- [Browser sessions](#browser-sessions)
- [Mounting it in a service](#mounting-it-in-a-service)

---

## Modules

A port, its LDAP adapter, the configuration block and the use case that joins them, then the HTTP side.

| Module | What it holds |
|---|---|
| `directory` | `DirectoryPort`: check a password, name the person's groups; `DirectoryUser`, `DirectoryError` |
| `ldap_directory` | `LdapDirectory`, the `DirectoryPort` that talks to an LDAP server through `ldap3` |
| `ldap` | `LdapConfig<R>`, `LdapServer`, the `AccessRule` trait, `rule_names` and `user_filter` |
| `login` | `ldap_login`, `throttled_ldap_login`, `LoginThrottle`, `LoggedIn<G>`, `LoginError` |
| `http::auth` | `ResolvedApiKey<P>`, `ApiKeyRegistry<P>`, `require_api_key`, `AuthContext<P>`, `Rejection` |
| `http::session` | `SessionStore<P>`, `SessionKind`, `form_action`, `csrf_matches`, `cookie_value`, `new_token` |
| `http` | The `Permission` trait each service's permissions type implements |

The bind credential is resolved through a `secrets_rs::SecretsPort`, like any other credential.

---

## The LDAP block and a service's rules

`LdapConfig<R>` is the `server.ui.ldap` block; `R` is the type of one entry of its `access:` list.

The connection fields (`url`, `starttls`, `ca_file`, `bind_credential`, `search_base`, `user_filter`,
`group_attribute`, `username_attribute`, `timeout_seconds`) are the same in every service. What a
rule grants is not: unified-api's restricted rules list `sources` and `endpoints`, unified-gitops'
list `applications`. So each service keeps its own rule struct and names the block with it:

```rust
pub type LdapConfig = auth_rs::LdapConfig<AccessRule>; // in the service's domain/ldap.rs
```

The block stays strict: it carries `deny_unknown_fields`, and so should the service's rule type.
`server()` borrows the connection part as an `LdapServer`, which is all the directory adapter sees.

---

## Implementing AccessRule

A service's rule type implements one trait: given every rule and one person, what do they get.

```rust
impl auth_rs::AccessRule for AccessRule {
    type Grant = Grant; // the service's own: Admin, or the ids a restricted rule lists

    fn grant_for(rules: &[Self], username: &str, member_of: &[String]) -> Option<Grant> {
        // for each rule with auth_rs::rule_names(&rule.users, &rule.groups, username, member_of):
        // admin anywhere is admin; otherwise union the scoped lists
    }
}
```

`rule_names` is the matching every service uses, so it cannot drift between them. A user matches by
account name, case-insensitively. A group written as a CN (`DL-ops`) matches any group with that CN,
while a full DN matches only that group; an escaped comma stays inside the CN. `None` from
`grant_for` means no rule names the person, and the login is refused even with the right password.

---

## The login use case

`ldap_login` joins the three parts; a service's HTTP handler only translates the form and the result.

1. Resolve the LDAP block's `bind_credential` through the secrets chain. It must give `username`
   (the bind DN) and `password`, or the login is `Unavailable`, naming the credential.
2. Ask the directory to check the password. A wrong password and an unknown user are one answer,
   `InvalidCredentials`, because the difference is what someone guessing usernames wants to learn.
3. Apply the rules to the account name **the directory returned**, not the one typed. With a filter
   that matches an e-mail address too, what was typed is not the account's name, and must not match a
   rule written for someone else.

The result is `LoggedIn<G>`: the account name, its DN, and the service's grant, for the session.

---

## The throttle

`throttled_ldap_login` wraps the use case in a `LoginThrottle` the service keeps for its lifetime.

| Guard | Behaviour |
|---|---|
| Failures per account | 5 wrong passwords in 15 minutes and the account is refused without asking the directory |
| Concurrent logins | 4 directory logins at once; a fifth waits up to 5 seconds, then gets `Busy` |
| Equal timing | Every wrong password answers after the same 1.5 seconds, however far the login got |

The failure limit sits well under any sensible directory lockout, so the form cannot be used to
lock a real account out. Accounts are counted case-insensitively. The throttle is in memory and
per process: it forgets on restart, which is acceptable for a rate limit.

---

## The directory adapter

`LdapDirectory` does the usual search-then-bind, on a fresh connection per login.

1. Bind as the service account, which may read users (a person may not know their own DN).
2. Search under `search_base` for exactly one entry matching `user_filter`, with the typed username
   escaped (RFC 4515), so `*` or `)` cannot rewrite the filter.
3. Bind as that entry with the typed password: the directory checks it, so no password or hash
   ever needs to be readable by the service.

An empty password is refused before any connection, because many directories accept it as an
unauthenticated bind. `ldaps://` and `starttls: true` use rustls; `ca_file` trusts exactly the CAs
in that PEM file for a private CA, and is otherwise the system's trust store. One connection per
login, closed straight after: logins are rare, and a pooled connection would sit bound as the last
person who logged in.

---

## API keys and the middleware

`require_api_key` authenticates every request and leaves an `AuthContext<P>` for the handlers to check.

| The request carries | It authenticates as |
|---|---|
| `X-API-Key: <secret>` or `Authorization: Bearer <secret>` | That key, compared in constant time against every key |
| The session cookie, and no key | The session; a write (or a `refresh=true` read) also needs its CSRF token |
| Nothing, with no keys configured | Everyone, as `P::admin()`: the instance runs open |
| Anything else | Refused: `Rejection::MissingApiKey`, `InvalidApiKey` or `CsrfRequired` |

The keys live in an `ApiKeyRegistry<P>` read on every request, so a reload that calls `replace` is
in force on the next one. A key has an `id` (its `name` in api_keys.yaml) and a `name` (its label);
the label is what the access log and `AuthContext::key_name` show. The middleware never decides
what a key may touch: a handler asks the permissions in `AuthContext` about the id it serves.

---

## Browser sessions

A browser cannot attach a header to a navigation, so signing in to the console opens a session.

`SessionStore<P>` keeps them in memory, so a restart signs everyone out and a key revoked while
the process was down stays revoked. Each session has a random 256-bit token (the cookie) and a
separate CSRF token, and records how it was opened, which decides what ends it:

- **`SessionKind::ApiKey`**: ended by `retain_keys` when its key's `id` leaves the configuration.
- **`SessionKind::Directory`**: ended by `end_directory_sessions` when the LDAP block changes.

`form_action` makes an HTML form usable against the API: it lifts `_csrf` out of the body for the
middleware, moves the other fields to the query, and turns `_method=DELETE` into a DELETE, but only
for a request that carries the session cookie, so a cross-site form cannot reach a DELETE route.

---

## Mounting it in a service

A service names its own permissions type and cookie, and keeps its error shape and its pages.

```rust
impl auth_rs::http::Permission for Permissions {
    fn admin() -> Self {
        Permissions::Admin
    }
}

pub type ApiKeys = auth_rs::http::ApiKeys<Permissions>;
pub type AuthContext = auth_rs::http::AuthContext<Permissions>;

// `middleware::from_fn` takes a function of the request and `next`: this
// passes the cookie name and renders a refusal as the service's ApiError.
pub async fn require_api_key(request: Request, next: Next) -> Result<Response, ApiError> {
    auth_rs::http::require_api_key::<Permissions>(COOKIE_NAME, request, next)
        .await
        .map_err(ApiError::from)
}
```

What stays in the service: how api_keys.yaml becomes `ResolvedApiKey`s (its fields and the legacy
admin-key variable), the sign-in page and its routes, and the Users page. They show the service's
own names and scopes, so they are not generic.

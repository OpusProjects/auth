# Sign-in

The `unified-auth` crate: signing a person in with their directory account (LDAP or Active
Directory), and deciding what that gets them through the service's own access rules.

The YAML a person writes (`server.ui.ldap` in a service's `config.yaml`) is documented in each
service's `docs/ldap-login.md`; this page is the crate behind it.

- [Modules](#modules)
- [The LDAP block and a service's rules](#the-ldap-block-and-a-services-rules)
- [Implementing AccessRule](#implementing-accessrule)
- [The login use case](#the-login-use-case)
- [The throttle](#the-throttle)
- [The directory adapter](#the-directory-adapter)

---

## Modules

Four modules: a port, its LDAP adapter, the configuration block, and the use case that joins them.

| Module | What it holds |
|---|---|
| `directory` | `DirectoryPort`: check a password, name the person's groups; `DirectoryUser`, `DirectoryError` |
| `ldap_directory` | `LdapDirectory`, the `DirectoryPort` that talks to an LDAP server through `ldap3` |
| `ldap` | `LdapConfig<R>`, `LdapServer`, the `AccessRule` trait, `rule_names` and `user_filter` |
| `login` | `ldap_login`, `throttled_ldap_login`, `LoginThrottle`, `LoggedIn<G>`, `LoginError` |

The bind credential is resolved through a `unified_secrets::SecretsPort`, like any other credential.

---

## The LDAP block and a service's rules

`LdapConfig<R>` is the `server.ui.ldap` block; `R` is the type of one entry of its `access:` list.

The connection fields (`url`, `starttls`, `ca_file`, `bind_credential`, `search_base`, `user_filter`,
`group_attribute`, `username_attribute`, `timeout_seconds`) are the same in every service. What a
rule grants is not: unified-api's restricted rules list `sources` and `endpoints`, unified-gitops'
list `applications`. So each service keeps its own rule struct and names the block with it:

```rust
pub type LdapConfig = unified_auth::LdapConfig<AccessRule>; // in the service's domain/ldap.rs
```

The block stays strict: it carries `deny_unknown_fields`, and so should the service's rule type.
`server()` borrows the connection part as an `LdapServer`, which is all the directory adapter sees.

---

## Implementing AccessRule

A service's rule type implements one trait: given every rule and one person, what do they get.

```rust
impl unified_auth::AccessRule for AccessRule {
    type Grant = Grant; // the service's own: Admin, or the ids a restricted rule lists

    fn grant_for(rules: &[Self], username: &str, member_of: &[String]) -> Option<Grant> {
        // for each rule with unified_auth::rule_names(&rule.users, &rule.groups, username, member_of):
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

// build_chain routes each credential to the adapter its values live in:
// `env` (env vars / JSON files) or a `vault` client, each Vault behind its own
// `cache`. The one place the chain is wired; services call it with their
// loaded credentials and the deprecated `secrets:` block of their config.yaml.
use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::credential::{Credential, CredentialType};
use crate::port::{SecretsError, SecretsFuture, SecretsPort};
use crate::{cache, env, vault};

// Secrets behavior — a service's config.yaml, `secrets:` section (optional).
// Strict like every config struct: a typo'd key fails the load naming it.
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    // How long a resolved credential may be reused before the backend is asked
    // again. The TTL is also the rotation latency. 0 disables the cache.
    //
    // DEPRECATED, like the whole block: a Vault is now a `type: vault`
    // credential with its own cache_ttl_seconds, and env and file credentials
    // are read fresh. Set here, it still wraps every credential in one cache,
    // as before, in place of each Vault's own. Absent = no such cache, except
    // that the `vault` below keeps the 60 seconds this used to default to.
    #[serde(default)]
    pub cache_ttl_seconds: Option<u64>,

    // Native Vault resolution (KV v2). Credentials that carry `vault_path`
    // without `vault:` read from this Vault; those without keep resolving
    // from env/files, so adoption is per credential.
    #[serde(default)]
    pub vault: Option<vault::VaultConfig>,
}

// The chain: each credential goes to where its values live. One with a
// vault_path reads from the `type: vault` credential it names — each Vault
// its own client, behind its own cache_ttl_seconds (default 60) — or from
// the deprecated config.yaml secrets.vault when it names none. Every other
// one reads env vars or files, uncached: a process's environment cannot
// change under it, and a file is a cheap local read that should pick a
// rotation up at once.
//
// The deprecated config.yaml `secrets.cache_ttl_seconds`, when set, still
// wraps the whole chain in one cache, as it did.
//
// In the library rather than in main because a reload has to build exactly
// the same chain from the new credentials, and two copies of this wiring
// would be two chances for the reloaded one to differ from the booted one.
pub fn build_chain(
    credentials: &HashMap<String, Credential>,
    settings: &SecretsConfig,
) -> Arc<dyn SecretsPort> {
    // The deprecated outer cache, while set, decides for every credential,
    // Vaults included: a Vault's own cache under it would only add its TTL
    // to the time a rotation takes, and an explicit 0 means no cache at all,
    // as it did in 0.36.
    let deprecated_ttl = settings.cache_ttl_seconds;
    let outer = deprecated_ttl.filter(|ttl| *ttl > 0);
    let vaults = credentials
        .iter()
        .filter(|(_, c)| c.credential_type == CredentialType::Vault)
        .map(|(id, c)| {
            (
                id.clone(),
                vault_client(c, credentials, deprecated_ttl.is_none()),
            )
        })
        .collect();
    // The deprecated config.yaml Vault keeps the 60s cache 0.36 gave it by
    // default (secrets.cache_ttl_seconds defaulted to 60 and covered it):
    // without it, a configuration that has not moved yet turns every sync into
    // a Vault request. An explicit cache_ttl_seconds is the outer cache below.
    let legacy = settings.vault.as_ref().map(|config| {
        let client = Box::new(vault::VaultSecrets::new(
            config.clone(),
            credentials.clone(),
            Box::new(env::EnvSecrets::new(credentials.clone())),
        ));
        match settings.cache_ttl_seconds {
            None => Arc::new(cache::CachedSecrets::new(
                client,
                std::time::Duration::from_secs(60),
            )) as Arc<dyn SecretsPort>,
            Some(_) => Arc::from(client as Box<dyn SecretsPort>),
        }
    });
    let routed = Routed {
        credentials: credentials.clone(),
        env: env::EnvSecrets::new(credentials.clone()),
        vaults,
        legacy,
    };
    match outer {
        None => Arc::new(routed),
        Some(ttl) => Arc::new(cache::CachedSecrets::new(
            Box::new(routed),
            std::time::Duration::from_secs(ttl),
        )),
    }
}

// One `type: vault` credential as a client, behind its own cache (unless an
// outer one covers it).
fn vault_client(
    vault: &Credential,
    credentials: &HashMap<String, Credential>,
    own_cache: bool,
) -> Arc<dyn SecretsPort> {
    let config = vault::VaultConfig {
        address: vault.address.clone().unwrap_or_default(),
        mount: vault.mount.clone().unwrap_or_else(|| "secret".to_string()),
        token_env: vault.env_vars.get("token").cloned().unwrap_or_default(),
        kubernetes_role: vault.kubernetes_role.clone(),
        jwt_path: vault
            .jwt_path
            .clone()
            .unwrap_or_else(|| vault::DEFAULT_JWT_PATH.to_string()),
        timeout_seconds: vault.timeout_seconds.unwrap_or(10),
    };
    let client = Box::new(vault::VaultSecrets::new(
        config,
        credentials.clone(),
        Box::new(env::EnvSecrets::new(credentials.clone())),
    ));
    match vault.cache_ttl_seconds.unwrap_or(60) {
        _ if !own_cache => Arc::from(client as Box<dyn SecretsPort>),
        0 => Arc::from(client as Box<dyn SecretsPort>),
        ttl => Arc::new(cache::CachedSecrets::new(
            client,
            std::time::Duration::from_secs(ttl),
        )),
    }
}

struct Routed {
    credentials: HashMap<String, Credential>,
    env: env::EnvSecrets,
    vaults: HashMap<String, Arc<dyn SecretsPort>>,
    legacy: Option<Arc<dyn SecretsPort>>,
}

impl SecretsPort for Routed {
    fn resolve(&self, credential_id: &str) -> SecretsFuture<'_> {
        let credential_id = credential_id.to_string();
        Box::pin(async move {
            let Some(credential) = self.credentials.get(&credential_id) else {
                return self.env.resolve(&credential_id).await;
            };
            // A Vault connection resolves to nothing a script could use: it
            // "resolves" when it can log in, which for token auth means its
            // variable is set. Asked only by the credentials page's check.
            if credential.credential_type == CredentialType::Vault {
                return match credential.env_vars.get("token") {
                    Some(var) if std::env::var(var).is_err() => Err(SecretsError {
                        message: format!("Env var '{var}' not set"),
                    }),
                    _ => Ok(HashMap::new()),
                };
            }
            if credential.vault_path.is_none() {
                return self.env.resolve(&credential_id).await;
            }
            let vault = match &credential.vault {
                Some(name) => self.vaults.get(name),
                None => self.legacy.as_ref(),
            };
            match vault {
                Some(vault) => vault.resolve(&credential_id).await,
                // Refused at load; reachable only if validation is bypassed.
                None => Err(SecretsError {
                    message: format!("Credential '{credential_id}' names no Vault to read from"),
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(id: &str, yaml: &str) -> HashMap<String, Credential> {
        HashMap::from([(id.to_string(), serde_saphyr::from_str(yaml).unwrap())])
    }

    // No config.yaml cache any more: an env credential is read on every
    // resolution, so a changed value is seen at once.
    #[tokio::test]
    async fn an_env_credential_is_read_fresh_every_time() {
        let credentials = credentials(
            "cred-a",
            "type: token\nenv_vars:\n  token: UNIFIED_SECRETS_TEST_FRESH_TOKEN\n",
        );
        let chain = build_chain(&credentials, &SecretsConfig::default());

        // SAFETY: a variable no other test reads; set before each resolve.
        unsafe { std::env::set_var("UNIFIED_SECRETS_TEST_FRESH_TOKEN", "one") };
        assert_eq!(chain.resolve("cred-a").await.unwrap()["token"], "one");
        unsafe { std::env::set_var("UNIFIED_SECRETS_TEST_FRESH_TOKEN", "two") };
        assert_eq!(chain.resolve("cred-a").await.unwrap()["token"], "two");
    }

    // A configuration still on the deprecated config.yaml Vault, with no
    // cache_ttl_seconds, keeps the 60s cache 0.36 gave it by default: two
    // resolutions, one read from Vault.
    #[tokio::test]
    async fn the_deprecated_vault_keeps_its_default_cache() {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                counted.fetch_add(1, Ordering::SeqCst);
                let body = r#"{"data":{"data":{"token":"t"}}}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });

        let credentials = credentials("cred-a", "type: token\nvault_path: team/a\n");
        let settings: SecretsConfig = serde_saphyr::from_str(&format!(
            "vault:\n  address: {address}\n  token_env: UNIFIED_SECRETS_TEST_LEGACY_VAULT_TOKEN\n"
        ))
        .unwrap();
        // SAFETY: a variable no other test reads.
        unsafe { std::env::set_var("UNIFIED_SECRETS_TEST_LEGACY_VAULT_TOKEN", "x") };
        let chain = build_chain(&credentials, &settings);

        assert_eq!(chain.resolve("cred-a").await.unwrap()["token"], "t");
        assert_eq!(chain.resolve("cred-a").await.unwrap()["token"], "t");
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    // A fake Vault that answers every read with {token: "t"} and counts the
    // reads, so a test can tell a cached answer from a fresh one.
    fn counting_vault() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        use std::sync::atomic::Ordering;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                counted.fetch_add(1, Ordering::SeqCst);
                let body = r#"{"data":{"data":{"token":"t"}}}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (address, reads)
    }

    fn many(entries: &[(&str, String)]) -> HashMap<String, Credential> {
        entries
            .iter()
            .map(|(id, yaml)| (id.to_string(), serde_saphyr::from_str(yaml).unwrap()))
            .collect()
    }

    fn reads(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    // A `type: vault` credential is a connection, not a login: resolving it
    // only checks its token variable is there.
    #[tokio::test]
    async fn a_vault_credential_resolves_to_nothing_but_needs_its_token() {
        let chain = build_chain(
            &many(&[(
                "vault-main",
                "type: vault\naddress: https://v\nenv_vars:\n  token: UNIFIED_SECRETS_TEST_VAULT_TOKEN_ROUTE\n".to_string(),
            )]),
            &SecretsConfig::default(),
        );
        let err = chain.resolve("vault-main").await.unwrap_err();
        assert_eq!(
            err.message,
            "Env var 'UNIFIED_SECRETS_TEST_VAULT_TOKEN_ROUTE' not set"
        );
        // SAFETY: a variable no other test reads.
        unsafe { std::env::set_var("UNIFIED_SECRETS_TEST_VAULT_TOKEN_ROUTE", "x") };
        assert!(chain.resolve("vault-main").await.unwrap().is_empty());
    }

    // Each named Vault reads through its own client, behind its own cache:
    // 60 seconds unless it says otherwise, none at 0.
    #[tokio::test]
    async fn each_named_vault_has_its_own_cache() {
        let (address, counter) = counting_vault();
        // SAFETY: a variable no other test reads.
        unsafe { std::env::set_var("UNIFIED_SECRETS_TEST_NAMED_VAULT_TOKEN", "x") };
        let vault = |cache: &str| {
            format!(
                "type: vault\naddress: {address}\nenv_vars:\n  token: UNIFIED_SECRETS_TEST_NAMED_VAULT_TOKEN\n{cache}"
            )
        };
        let chain = build_chain(
            &many(&[
                ("vault-cached", vault("")),
                ("vault-fresh", vault("cache_ttl_seconds: 0\n")),
                (
                    "cred-cached",
                    "type: token\nvault: vault-cached\nvault_path: a\n".to_string(),
                ),
                (
                    "cred-fresh",
                    "type: token\nvault: vault-fresh\nvault_path: a\n".to_string(),
                ),
            ]),
            &SecretsConfig::default(),
        );

        assert_eq!(chain.resolve("cred-cached").await.unwrap()["token"], "t");
        assert_eq!(chain.resolve("cred-cached").await.unwrap()["token"], "t");
        assert_eq!(reads(&counter), 1);

        chain.resolve("cred-fresh").await.unwrap();
        chain.resolve("cred-fresh").await.unwrap();
        assert_eq!(reads(&counter), 3);
    }

    // The deprecated outer TTL, while set, is the only cache: one in front of
    // the whole chain, Vaults' own dropped (and the legacy Vault's default).
    #[tokio::test]
    async fn the_deprecated_ttl_wraps_the_whole_chain_instead() {
        let (address, counter) = counting_vault();
        // SAFETY: a variable no other test reads.
        unsafe { std::env::set_var("UNIFIED_SECRETS_TEST_OUTER_VAULT_TOKEN", "x") };
        let settings: SecretsConfig = serde_saphyr::from_str(&format!(
            "cache_ttl_seconds: 30\nvault:\n  address: {address}\n  token_env: UNIFIED_SECRETS_TEST_OUTER_VAULT_TOKEN\n"
        ))
        .unwrap();
        let chain = build_chain(
            &many(&[
                (
                    "vault-main",
                    format!(
                        "type: vault\naddress: {address}\nenv_vars:\n  token: UNIFIED_SECRETS_TEST_OUTER_VAULT_TOKEN\n"
                    ),
                ),
                (
                    "cred-named",
                    "type: token\nvault: vault-main\nvault_path: a\n".to_string(),
                ),
                ("cred-legacy", "type: token\nvault_path: b\n".to_string()),
            ]),
            &settings,
        );

        for _ in 0..2 {
            chain.resolve("cred-named").await.unwrap();
            chain.resolve("cred-legacy").await.unwrap();
        }
        assert_eq!(reads(&counter), 2);
    }

    #[tokio::test]
    async fn a_vault_path_with_no_vault_to_read_from_is_named() {
        let chain = build_chain(
            &credentials("cred-a", "type: token\nvault_path: team/a\n"),
            &SecretsConfig::default(),
        );
        let err = chain.resolve("cred-a").await.unwrap_err();
        assert_eq!(
            err.message,
            "Credential 'cred-a' names no Vault to read from"
        );
    }

    // An id the configuration does not have gets the env adapter's answer.
    #[tokio::test]
    async fn an_unknown_credential_is_not_found() {
        let chain = build_chain(&HashMap::new(), &SecretsConfig::default());
        let err = chain.resolve("cred-ghost").await.unwrap_err();
        assert_eq!(err.message, "Credential 'cred-ghost' not found in config");
    }
}

use std::sync::{Arc, RwLock};

use crate::port::{SecretsFuture, SecretsPort, SecretsSwapPort};

// The resolver chain, behind one pointer that a reload can replace.
//
// Everything else in the process holds this, not the chain underneath it, so
// changing credentials.yaml (or the whole `secrets:` block, Vault included)
// means building a fresh chain and swapping it here — no restart, and no
// caller anywhere that has to be told.
//
// A resolution already in flight keeps the chain it started with: it holds an
// Arc, and the swap only changes what the NEXT resolution reads.
pub struct ReloadableSecrets {
    inner: RwLock<Arc<dyn SecretsPort>>,
}

impl ReloadableSecrets {
    pub fn new(inner: Arc<dyn SecretsPort>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    fn current(&self) -> Arc<dyn SecretsPort> {
        Arc::clone(&self.inner.read().expect("secrets chain lock"))
    }
}

impl SecretsPort for ReloadableSecrets {
    fn resolve(&self, credential_id: &str) -> SecretsFuture<'_> {
        let chain = self.current();
        let credential_id = credential_id.to_string();
        // The chain is resolved BEFORE the future is awaited and moved into
        // it, so a swap landing mid-resolution cannot pull it out from under
        // a request that already started.
        Box::pin(async move { chain.resolve(&credential_id).await })
    }
}

impl SecretsSwapPort for ReloadableSecrets {
    fn replace(&self, next: Arc<dyn SecretsPort>) {
        *self.inner.write().expect("secrets chain lock") = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockSecrets;

    // A swap changes what the next resolution reads; nothing else moves.
    #[tokio::test]
    async fn a_replaced_chain_answers_the_next_resolution() {
        let chain = ReloadableSecrets::new(Arc::new(
            MockSecrets::new().with("cred-a", [("token", "old")]),
        ));
        assert_eq!(chain.resolve("cred-a").await.unwrap()["token"], "old");

        chain.replace(Arc::new(
            MockSecrets::new().with("cred-a", [("token", "new")]),
        ));
        assert_eq!(chain.resolve("cred-a").await.unwrap()["token"], "new");
    }

    // A resolution already started keeps the chain it started with.
    #[tokio::test]
    async fn a_resolution_in_flight_keeps_its_chain() {
        let chain = ReloadableSecrets::new(Arc::new(
            MockSecrets::new().with("cred-a", [("token", "old")]),
        ));
        let pending = chain.resolve("cred-a");
        chain.replace(Arc::new(MockSecrets::new()));
        assert_eq!(pending.await.unwrap()["token"], "old");
        assert!(chain.resolve("cred-a").await.is_err());
    }
}

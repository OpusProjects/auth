use std::collections::HashMap;

use crate::port::{SecretsError, SecretsFuture, SecretsPort};

// Implementation of SecretsPort for tests and local development: no
// secrets store, only what is manually provided. It is the default of
// AppBuilder — production replaces it with EnvSecrets.
//
// Lives in its own module (and not inside secrets/env.rs) to make it
// clear what it is: a test double, not a variant of the real adapter.
pub struct MockSecrets {
    secrets: HashMap<String, HashMap<String, String>>,
}

impl MockSecrets {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    // A credential the double resolves, e.g. the LDAP service account.
    pub fn with<const N: usize>(mut self, credential_id: &str, fields: [(&str, &str); N]) -> Self {
        self.secrets.insert(
            credential_id.to_string(),
            fields
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        );
        self
    }
}

impl Default for MockSecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretsPort for MockSecrets {
    fn resolve(&self, credential_id: &str) -> SecretsFuture<'_> {
        let credential_id = credential_id.to_string();

        Box::pin(async move {
            self.secrets
                .get(&credential_id)
                .cloned()
                .ok_or(SecretsError {
                    message: format!("Mock: credential '{}' not found", credential_id),
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An id it was not given fails like a missing credential does.
    #[tokio::test]
    async fn answers_what_it_was_given_and_nothing_else() {
        let secrets = MockSecrets::default().with("cred-a", [("token", "t")]);
        assert_eq!(secrets.resolve("cred-a").await.unwrap()["token"], "t");
        let err = secrets.resolve("cred-b").await.unwrap_err();
        assert_eq!(err.message, "Mock: credential 'cred-b' not found");
    }
}

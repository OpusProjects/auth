// secrets-rs — resolving credentials for a service.
//
// A credential is a reference written in configuration: it says WHERE its
// values live (environment variables, a JSON file, a HashiCorp Vault KV v2
// path), never the values themselves. This crate reads them when asked:
//
// - `credential`: the credential item as the YAML declares it
// - `port`: SecretsPort, the one trait everything else resolves through
// - `env`, `vault`: the adapters that read the values
// - `cache`, `reloadable`: wrappers (a TTL cache, a swappable chain)
// - `chain`: build_chain, which routes each credential to its adapter
// - `mock`: a test double for the services' own tests
//
// Shared by unified-api and unified-gitops: a fix here lands in both.

pub mod cache;
pub mod chain;
pub mod credential;
pub mod env;
pub mod mock;
pub mod port;
pub mod reloadable;
pub mod vault;

// The names a service uses most, at the crate root.
pub use chain::{SecretsConfig, build_chain};
pub use credential::{Credential, CredentialType};
pub use port::{SecretsError, SecretsFuture, SecretsPort, SecretsSwapPort};

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    UsernamePassword,
    Token,
    SshKey,
    // Not a login a script uses: the connection to a Vault that other
    // credentials read from (they name it with `vault:`), as AWX models a
    // HashiCorp Vault lookup as a credential of its own.
    Vault,
}

// Reference to a credential — comes from configuration YAML.
// Does not store secrets, only knows WHERE to read them from the environment.
// The infrastructure (ESO, docker secrets, .env) is responsible for injecting them.
// Unknown keys are config typos: fail startup naming the key instead of
// silently applying a default (the policy is explained once, in config.rs).
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    // The identity is not a field: it is the key of the map the credentials
    // live in — what references, URLs and cache keys use. These two are for
    // people, and each service fills the one it shows: `name`, a display label
    // its loader derives (the item's `description`, falling back to its
    // identity), or `description`, the text as written. Both default, so the
    // YAML a person writes is the same either way.
    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(rename = "type")]
    pub credential_type: CredentialType,

    // KV v2 path (under the Vault's `mount`) to read this credential from.
    // When set, `secret_keys` maps our names to fields of that secret (empty
    // = every field verbatim) and env_vars/env_prefix/secret_file are not
    // consulted. `vault` names the `type: vault` credential to read it from
    // (absent = the deprecated `secrets.vault:` block in config.yaml) —
    // validated at startup, so a vault_path without a Vault fails the deploy
    // rather than the first sync.
    #[serde(default)]
    pub vault_path: Option<String>,

    #[serde(default)]
    pub vault: Option<String>,

    // A `type: vault` credential's own settings: where the Vault is and how
    // to log in to it (a token in env_vars.token, or Kubernetes auth). Refused
    // on any other type.
    #[serde(default)]
    pub address: Option<String>,

    // The KV v2 mount the vault_path values live under (default "secret")
    #[serde(default)]
    pub mount: Option<String>,

    // Kubernetes auth: the pod's service-account JWT (at jwt_path) is
    // exchanged for a client token under this role, instead of env_vars.token.
    #[serde(default)]
    pub kubernetes_role: Option<String>,

    #[serde(default)]
    pub jwt_path: Option<String>,

    // Bound on every request to this Vault (default 10)
    #[serde(default)]
    pub timeout_seconds: Option<u64>,

    // How long a value read from this Vault is reused (default 60; 0 = read
    // on every resolution) — also how long a rotation takes to be seen. Only
    // a Vault has one: env vars cannot change under a running process, and a
    // file is a cheap local read that should pick a rotation up at once.
    #[serde(default)]
    pub cache_ttl_seconds: Option<u64>,

    // Our field name → the full name of the environment variable holding it.
    // ex: {"username": "SECTION9_USERNAME"} → reads SECTION9_USERNAME and
    // delivers it as `username`. The full name rather than a prefix, so a
    // search for the variable finds the credential that reads it.
    #[serde(default)]
    pub env_vars: HashMap<String, String>,

    // DEPRECATED, still read: the older env form, a prefix joined to each
    // secret_keys value — "SECTION9" + {"username": "USERNAME"} reads
    // SECTION9_USERNAME. `deprecation` says what env_vars to write instead.
    pub env_prefix: Option<String>,

    // Path to a JSON file with secrets — ex: "/run/secrets/section9-api.json"
    pub secret_file: Option<String>,

    // Mapping: our name → field name in the store: the Vault secret, the JSON
    // file, or (deprecated) the suffix after env_prefix.
    // ex: {"username": "USERNAME", "password": "PASSWORD"}
    #[serde(default)]
    pub secret_keys: HashMap<String, String>,

    // Paths to files that the script consumes directly (SSH keys, certificates, etc.)
    // ex: {"ssh_key": "/run/secrets/id_rsa"} → CREDENTIAL_SSH_KEY_PATH=/run/secrets/id_rsa
    #[serde(default)]
    pub file_keys: HashMap<String, String>,
}

impl CredentialType {
    // As written after `type:` in credentials.yaml.
    pub fn name(&self) -> &'static str {
        match self {
            CredentialType::UsernamePassword => "username_password",
            CredentialType::Token => "token",
            CredentialType::SshKey => "ssh_key",
            CredentialType::Vault => "vault",
        }
    }
}

impl Credential {
    // Where the secret values are read from, in the order the resolver
    // chain decides it: a Vault path wins over everything, then env vars,
    // then a JSON file. "files" is a credential made only of file_keys
    // (paths handed to the script, an SSH key, a certificate).
    pub fn backend(&self) -> &'static str {
        if self.vault_path.is_some() || self.credential_type == CredentialType::Vault {
            "vault"
        } else if !self.env_vars.is_empty() || self.env_prefix.is_some() {
            "env"
        } else if self.secret_file.is_some() {
            "file"
        } else {
            "files"
        }
    }

    // The environment variables an env-backed credential reads, sorted and
    // spelled exactly as the env resolver reads them. Empty for any other
    // backend.
    pub fn env_var_names(&self) -> Vec<String> {
        if self.vault_path.is_some() {
            return Vec::new();
        }
        let mut vars: Vec<String> = if !self.env_vars.is_empty() {
            self.env_vars.values().cloned().collect()
        } else if let Some(prefix) = &self.env_prefix {
            self.secret_keys
                .values()
                .map(|suffix| format!("{}_{}", prefix, suffix))
                .collect()
        } else {
            return Vec::new();
        };
        vars.sort();
        vars
    }
}

// A credential's name as the part of a variable name its fields are also
// delivered under (CREDENTIAL_<ID>_<FIELD>): lower case, a leading `cred-` or
// `cred_` (the naming convention every example uses) dropped, and anything
// that cannot appear in an environment variable name written as `_`.
// `cred-vcenter-aa1` → `vcenter_aa1`. Also what config validation compares,
// so two credentials of one source can never be delivered under one id.
pub fn delivery_id(credential_id: &str) -> String {
    let id = variable_part(credential_id);
    id.strip_prefix("cred_").map(str::to_string).unwrap_or(id)
}

// Any name as it reads inside a variable name: lower case, anything outside
// [a-z0-9] as `_`. A field is compared with a delivery id in this form, so
// `AVAMAR_AA1_URL` and `avamar_aa1_url` are the same field.
pub fn variable_part(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(yaml: &str) -> Credential {
        serde_saphyr::from_str(yaml).unwrap()
    }

    #[test]
    fn env_vars_are_spelled_as_the_resolver_reads_them() {
        let c = credential(
            "type: username_password\nenv_prefix: D42\nsecret_keys:\n  username: USER\n  password: PASS\n",
        );
        assert_eq!(c.backend(), "env");
        assert_eq!(c.env_var_names(), vec!["D42_PASS", "D42_USER"]);
    }

    #[test]
    fn env_vars_name_each_variable_in_full() {
        let c = credential(
            "type: username_password\nenv_vars:\n  username: D42_USER\n  password: D42_PASS\n",
        );
        assert_eq!(c.backend(), "env");
        assert_eq!(c.env_var_names(), vec!["D42_PASS", "D42_USER"]);
    }

    #[test]
    fn a_vault_path_wins_and_reads_no_env_vars() {
        let c = credential(
            "type: token\nvault_path: pcd/github\nenv_prefix: GH\nsecret_keys:\n  token: TOKEN\n",
        );
        assert_eq!(c.backend(), "vault");
        assert!(c.env_var_names().is_empty());
    }

    #[test]
    fn a_vault_credential_is_its_own_backend() {
        let c = credential("type: vault\naddress: https://v\nenv_vars:\n  token: T\n");
        assert_eq!(c.backend(), "vault");
        assert_eq!(c.credential_type.name(), "vault");
    }

    // Either label a service shows may be written; neither is required.
    #[test]
    fn name_and_description_are_both_optional() {
        let c = credential("type: token\nenv_vars:\n  token: T\n");
        assert_eq!(c.name, "");
        assert_eq!(c.description, None);
        let c = credential("description: GitHub\ntype: token\nenv_vars:\n  token: T\n");
        assert_eq!(c.description.as_deref(), Some("GitHub"));
    }

    #[test]
    fn a_delivery_id_drops_the_cred_prefix() {
        assert_eq!(delivery_id("cred-vcenter-aa1"), "vcenter_aa1");
        assert_eq!(delivery_id("cred_portainer"), "portainer");
        assert_eq!(variable_part("AVAMAR-AA1.url"), "avamar_aa1_url");
    }

    // Typos fail the load, naming the key, as everywhere else in the config.
    #[test]
    fn an_unknown_key_is_refused() {
        let result: Result<Credential, _> = serde_saphyr::from_str("type: token\nenv_var: {}\n");
        assert!(result.is_err());
    }
}

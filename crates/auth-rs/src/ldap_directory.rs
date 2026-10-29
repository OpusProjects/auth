use std::sync::Arc;
use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use crate::directory::{
    DirectoryError, DirectoryFuture, DirectoryLogin, DirectoryPort, DirectoryUser,
};
use crate::ldap::user_filter;

// LDAP result code for a wrong password or an unknown bind DN.
const INVALID_CREDENTIALS: u32 = 49;

// DirectoryPort → an LDAP server, with the usual search-then-bind:
//
//   1. bind as the service account (it may read users; a person may not
//      know their own DN),
//   2. search for exactly one entry matching the user filter,
//   3. bind AS that entry with the password typed: the directory itself
//      checks it, so no password or hash ever needs to be readable here.
//
// One connection per login, closed straight after. Logins are rare and a
// pooled connection would sit bound as the last person who logged in.
pub struct LdapDirectory;

impl DirectoryPort for LdapDirectory {
    fn authenticate<'a>(&'a self, request: DirectoryLogin<'a>) -> DirectoryFuture<'a> {
        Box::pin(authenticate(request))
    }
}

async fn authenticate(request: DirectoryLogin<'_>) -> Result<DirectoryUser, DirectoryError> {
    // An empty password is not a wrong password to LDAP: a simple bind with
    // a DN and no password is an "unauthenticated bind", which many servers,
    // Active Directory included, answer with SUCCESS. Without this check an
    // empty password field logs anyone in as anyone.
    if request.password.is_empty() || request.username.trim().is_empty() {
        return Err(DirectoryError::InvalidCredentials);
    }

    let config = request.server;
    let timeout = Duration::from_secs(config.timeout_seconds);
    let unavailable = |what: &str, e: ldap3::LdapError| {
        DirectoryError::Unavailable(format!("{what} ({}): {e}", config.url))
    };

    let mut settings = LdapConnSettings::new()
        .set_conn_timeout(timeout)
        .set_starttls(config.starttls);
    if let Some(ca_file) = config.ca_file {
        settings = settings.set_config(tls_config(ca_file).map_err(DirectoryError::Unavailable)?);
    }

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, config.url)
        .await
        .map_err(|e| unavailable("connect", e))?;
    // The connection is driven by its own task; it ends when `ldap` is dropped.
    ldap3::drive!(conn);

    ldap.with_timeout(timeout)
        .simple_bind(request.bind_dn, request.bind_password)
        .await
        .and_then(|result| result.success())
        .map_err(|e| unavailable("service account bind", e))?;

    let filter = user_filter(config.user_filter, request.username);
    let (entries, _) = ldap
        .with_timeout(timeout)
        .search(
            config.search_base,
            Scope::Subtree,
            &filter,
            vec![config.group_attribute, config.username_attribute],
        )
        .await
        .and_then(|result| result.success())
        .map_err(|e| unavailable("user search", e))?;

    // Zero is an unknown user; more than one is a filter too loose to say
    // WHO is logging in, and picking the first would be a guess.
    let [entry] = entries.as_slice() else {
        let _ = ldap.unbind().await;
        if entries.len() > 1 {
            let matches = entries.len();
            tracing::warn!(
                matches,
                "LDAP user filter matched more than one entry; refusing the login"
            );
        }
        return Err(DirectoryError::InvalidCredentials);
    };
    let entry = SearchEntry::construct(entry.clone());

    let user_bind = ldap
        .with_timeout(timeout)
        .simple_bind(&entry.dn, request.password)
        .await
        .map_err(|e| unavailable("user bind", e))?;
    let _ = ldap.unbind().await;

    match user_bind.rc {
        0 => {}
        INVALID_CREDENTIALS => return Err(DirectoryError::InvalidCredentials),
        rc => {
            return Err(DirectoryError::Unavailable(format!(
                "user bind ({}): result code {rc} {}",
                config.url, user_bind.text
            )));
        }
    }

    // Attribute names are case-insensitive in LDAP, and servers echo them
    // back in whatever case they store.
    let attribute = |wanted: &str| {
        entry
            .attrs
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, values)| values.clone())
            .unwrap_or_default()
    };
    let member_of = attribute(config.group_attribute);
    let username = attribute(config.username_attribute).into_iter().next();

    Ok(DirectoryUser {
        dn: entry.dn,
        username,
        member_of,
    })
}

// A TLS configuration that trusts exactly the CAs in `ca_file`, for a
// directory signed by a private CA. Built per login: the file is small, and
// reading it each time means a rotated CA needs no restart.
fn tls_config(ca_file: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;

    let mut roots = rustls::RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(ca_file)
        .map_err(|e| format!("ldap.ca_file '{ca_file}': {e}"))?;
    for cert in certs {
        let cert = cert.map_err(|e| format!("ldap.ca_file '{ca_file}': {e}"))?;
        roots
            .add(cert)
            .map_err(|e| format!("ldap.ca_file '{ca_file}': {e}"))?;
    }
    if roots.is_empty() {
        return Err(format!("ldap.ca_file '{ca_file}' holds no certificate"));
    }

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    // ring implements every protocol version rustls considers safe, so this
    // cannot fail with this provider; a failure would be a build of rustls
    // without TLS 1.2 and 1.3, which is a programming error, not a login's.
    .with_safe_default_protocol_versions()
    .expect("the ring provider supports rustls' default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_ca_file_is_named() {
        let err = tls_config("/nonexistent/ca.pem").unwrap_err();
        assert!(err.contains("/nonexistent/ca.pem"), "{err}");
    }

    // ---------------------------------------------------------------------
    // ca_file: a private CA, trusted alone
    // ---------------------------------------------------------------------

    // A throwaway self-signed CA, generated for these tests only.
    const TEST_CA: &str = include_str!("../tests/fixtures/test-ca.pem");

    fn pem_file(content: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), content).unwrap();
        file
    }

    #[test]
    fn a_ca_file_with_a_certificate_builds_a_tls_config() {
        let ca = pem_file(TEST_CA);
        assert!(tls_config(&ca.path().display().to_string()).is_ok());
    }

    #[test]
    fn a_ca_file_without_a_certificate_is_refused() {
        let empty = pem_file("no certificates here\n");
        let err = tls_config(&empty.path().display().to_string()).unwrap_err();
        assert!(err.ends_with("holds no certificate"), "{err}");
    }

    // A CERTIFICATE block whose bytes are not a certificate.
    #[test]
    fn a_ca_file_with_a_broken_certificate_is_refused() {
        let broken = pem_file("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        let path = broken.path().display().to_string();
        let err = tls_config(&path).unwrap_err();
        assert!(err.starts_with(&format!("ldap.ca_file '{path}'")), "{err}");
    }

    #[test]
    fn a_ca_file_that_is_not_pem_is_refused() {
        let garbled = pem_file("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n");
        let path = garbled.path().display().to_string();
        let err = tls_config(&path).unwrap_err();
        assert!(err.starts_with(&format!("ldap.ca_file '{path}'")), "{err}");
    }
}

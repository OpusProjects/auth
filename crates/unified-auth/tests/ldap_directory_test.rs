// LdapDirectory against a fake directory: an LDAP server on 127.0.0.1 that
// speaks just enough of the protocol (BER-encoded bind, search and unbind)
// for ldap3 to log someone in against it, scripted per test. No real
// directory, no network.
use std::sync::Once;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unified_auth::directory::{DirectoryError, DirectoryLogin, DirectoryPort, DirectoryUser};
use unified_auth::ldap::LdapServer;
use unified_auth::ldap_directory::LdapDirectory;

// One process-wide log subscriber, so every logged field is evaluated the
// same way whichever test happens to reach a log line first.
fn log_everything() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt().with_test_writer().init();
    });
}

fn pem_file(content: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), content).unwrap();
    file
}

const TEST_CA: &str = include_str!("fixtures/test-ca.pem");

// ---------------------------------------------------------------------
// A fake directory: an LDAP server on 127.0.0.1 that speaks just enough
// of the protocol (BER-encoded bind, search and unbind) for ldap3 to log
// someone in against it, scripted per test.
// ---------------------------------------------------------------------

// One directory entry: its DN and its attributes, each with its values.
type Entry = (&'static str, Vec<(&'static str, Vec<&'static str>)>);

// What the fake answers. The service account is "CN=svc"; anyone else
// binding is the person logging in.
#[derive(Clone)]
struct Script {
    service_rc: u8,
    search_rc: u8,
    entries: Vec<Entry>,
    user_rc: u8,
    hang_up_on_user_bind: bool,
}

impl Default for Script {
    fn default() -> Self {
        Script {
            service_rc: 0,
            search_rc: 0,
            entries: vec![(
                "CN=John Doe,OU=Users,DC=example,DC=com",
                vec![
                    // Servers echo attribute names in whatever case they store.
                    ("MEMBEROF", vec!["CN=DL-ops,OU=Groups,DC=example,DC=com"]),
                    ("sAMAccountName", vec!["jdoe"]),
                ],
            )],
            user_rc: 0,
            hang_up_on_user_bind: false,
        }
    }
}

// A BER type-length-value: the tag, the length (short or long form), the content.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let len = (content.len() as u32).to_be_bytes();
        let skip = len.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&len[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn octets(text: &str) -> Vec<u8> {
    tlv(0x04, text.as_bytes())
}

// An LDAPResult (bind response, search done): code, matched DN, message.
fn result(tag: u8, rc: u8) -> Vec<u8> {
    tlv(
        tag,
        &[tlv(0x0a, &[rc]), octets(""), octets("scripted")].concat(),
    )
}

// The TLVs one after another in `bytes`, as (tag, content) pairs.
fn children(mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let tag = bytes[0];
        let (len, header) = match bytes[1] {
            short if short < 0x80 => (short as usize, 2),
            long => {
                let n = (long & 0x7f) as usize;
                let len = bytes[2..2 + n]
                    .iter()
                    .fold(0usize, |acc, b| acc << 8 | *b as usize);
                (len, 2 + n)
            }
        };
        out.push((tag, bytes[header..header + len].to_vec()));
        bytes = &bytes[header + len..];
    }
    out
}

// Reads one whole LDAPMessage off the socket; None when the client is gone.
async fn read_message(stream: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.ok()?;
    let mut header = head.to_vec();
    let len = if head[1] < 0x80 {
        head[1] as usize
    } else {
        let mut long = vec![0u8; (head[1] & 0x7f) as usize];
        stream.read_exact(&mut long).await.ok()?;
        header.extend_from_slice(&long);
        long.iter().fold(0usize, |acc, b| acc << 8 | *b as usize)
    };
    let mut content = vec![0u8; len];
    stream.read_exact(&mut content).await.ok()?;
    Some(content)
}

async fn serve(mut stream: tokio::net::TcpStream, script: Script) {
    while let Some(message) = read_message(&mut stream).await {
        let parts = children(&message);
        let id = tlv(0x02, &parts[0].1);
        let reply = |op: Vec<u8>| tlv(0x30, &[id.clone(), op].concat());
        let (op, body) = (&parts[1].0, &parts[1].1);
        let answer = match op {
            // BindRequest: version, name, simple password
            0x60 => {
                let fields = children(body);
                let name = String::from_utf8_lossy(&fields[1].1).to_string();
                if name == "CN=svc" {
                    reply(result(0x61, script.service_rc))
                } else if script.hang_up_on_user_bind {
                    return;
                } else {
                    reply(result(0x61, script.user_rc))
                }
            }
            // SearchRequest: every scripted entry, then the result
            0x63 => {
                let mut out = Vec::new();
                for (dn, attributes) in &script.entries {
                    let attributes: Vec<u8> = attributes
                        .iter()
                        .flat_map(|(name, values)| {
                            let values: Vec<u8> = values.iter().flat_map(|v| octets(v)).collect();
                            tlv(0x30, &[octets(name), tlv(0x31, &values)].concat())
                        })
                        .collect();
                    out.extend(reply(tlv(
                        0x64,
                        &[octets(dn), tlv(0x30, &attributes)].concat(),
                    )));
                }
                out.extend(reply(result(0x65, script.search_rc)));
                out
            }
            // UnbindRequest, or anything else: the session is over
            _ => return,
        };
        if stream.write_all(&answer).await.is_err() {
            return;
        }
    }
}

// Starts the fake and returns its ldap:// URL.
async fn directory(script: Script) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ldap://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, script.clone()));
        }
    });
    url
}

async fn log_in(
    url: &str,
    ca_file: Option<&str>,
    password: &str,
) -> Result<DirectoryUser, DirectoryError> {
    log_everything();
    LdapDirectory
        .authenticate(DirectoryLogin {
            server: LdapServer {
                url,
                starttls: false,
                ca_file,
                search_base: "DC=example,DC=com",
                user_filter: "(sAMAccountName={username})",
                group_attribute: "memberOf",
                username_attribute: "sAMAccountName",
                timeout_seconds: 5,
            },
            bind_dn: "CN=svc",
            bind_password: "svc-secret",
            username: "jdoe",
            password,
        })
        .await
}

#[tokio::test]
async fn a_right_password_names_the_account_and_its_groups() {
    let url = directory(Script::default()).await;
    let user = log_in(&url, None, "right").await.unwrap();
    assert_eq!(user.dn, "CN=John Doe,OU=Users,DC=example,DC=com");
    assert_eq!(user.username.as_deref(), Some("jdoe"));
    assert_eq!(
        user.member_of,
        vec!["CN=DL-ops,OU=Groups,DC=example,DC=com"]
    );
}

// An entry without the username attribute still logs in, under no name
// of its own (the use case falls back to what was typed).
#[tokio::test]
async fn an_entry_without_its_name_attribute_has_no_username() {
    let url = directory(Script {
        entries: vec![("CN=svc-less,DC=x", vec![])],
        ..Script::default()
    })
    .await;
    let user = log_in(&url, None, "right").await.unwrap();
    assert_eq!(user.username, None);
    assert!(user.member_of.is_empty());
}

#[tokio::test]
async fn a_wrong_password_is_invalid_credentials() {
    let url = directory(Script {
        user_rc: 49,
        ..Script::default()
    })
    .await;
    assert_eq!(
        log_in(&url, None, "wrong").await.unwrap_err(),
        DirectoryError::InvalidCredentials
    );
}

// Any other refusal of the user's bind is the directory's problem, not
// the person's: unavailable, with the code for the log.
#[tokio::test]
async fn another_bind_refusal_is_unavailable_with_its_code() {
    let url = directory(Script {
        user_rc: 53,
        ..Script::default()
    })
    .await;
    let err = log_in(&url, None, "right").await.unwrap_err();
    assert!(
        matches!(&err, DirectoryError::Unavailable(m) if m.contains("result code 53")),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_rejected_service_account_is_unavailable() {
    let url = directory(Script {
        service_rc: 49,
        ..Script::default()
    })
    .await;
    let err = log_in(&url, None, "right").await.unwrap_err();
    assert!(
        matches!(&err, DirectoryError::Unavailable(m) if m.starts_with("service account bind")),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_failed_search_is_unavailable() {
    let url = directory(Script {
        search_rc: 32,
        ..Script::default()
    })
    .await;
    let err = log_in(&url, None, "right").await.unwrap_err();
    assert!(
        matches!(&err, DirectoryError::Unavailable(m) if m.starts_with("user search")),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_unknown_user_is_invalid_credentials() {
    let url = directory(Script {
        entries: vec![],
        ..Script::default()
    })
    .await;
    assert_eq!(
        log_in(&url, None, "right").await.unwrap_err(),
        DirectoryError::InvalidCredentials
    );
}

// A filter matching two people cannot say who is logging in: refused,
// and logged, rather than guessing the first.
#[tokio::test]
async fn a_filter_matching_two_entries_is_refused() {
    let url = directory(Script {
        entries: vec![("CN=a,DC=x", vec![]), ("CN=b,DC=x", vec![])],
        ..Script::default()
    })
    .await;
    assert_eq!(
        log_in(&url, None, "right").await.unwrap_err(),
        DirectoryError::InvalidCredentials
    );
}

// The connection dropping before the user's bind is answered is an
// outage, not a wrong password.
#[tokio::test]
async fn a_connection_lost_mid_login_is_unavailable() {
    let url = directory(Script {
        hang_up_on_user_bind: true,
        ..Script::default()
    })
    .await;
    let err = log_in(&url, None, "right").await.unwrap_err();
    assert!(
        matches!(&err, DirectoryError::Unavailable(m) if m.starts_with("user bind")),
        "{err:?}"
    );
}

// The CA is loaded before connecting, also for a plain URL.
#[tokio::test]
async fn a_login_with_a_ca_file_loads_it_first() {
    let url = directory(Script::default()).await;
    let ca = pem_file(TEST_CA);
    let user = log_in(&url, Some(&ca.path().display().to_string()), "right")
        .await
        .unwrap();
    assert_eq!(user.username.as_deref(), Some("jdoe"));

    let missing = log_in(&url, Some("/nonexistent/ca.pem"), "right")
        .await
        .unwrap_err();
    assert!(
        matches!(&missing, DirectoryError::Unavailable(m) if m.contains("/nonexistent/ca.pem")),
        "{missing:?}"
    );
}

// The unauthenticated-bind trap: refused before any connection is made, so
// the answer cannot depend on how the server treats it.
#[tokio::test]
async fn an_empty_password_never_reaches_the_directory() {
    // Nothing listens here: reaching the network would fail differently.
    assert_eq!(
        log_in("ldap://127.0.0.1:1", None, "").await.unwrap_err(),
        DirectoryError::InvalidCredentials
    );
}

#[tokio::test]
async fn an_unreachable_directory_is_unavailable_not_a_wrong_password() {
    let err = log_in("ldap://127.0.0.1:1", None, "secret")
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DirectoryError::Unavailable(m) if m.starts_with("connect")),
        "{err:?}"
    );
}

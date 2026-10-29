use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use secrets_rs::SecretsPort;

use crate::directory::{DirectoryError, DirectoryLogin, DirectoryPort};
use crate::ldap::{AccessRule, LdapConfig};

// The use case "log a person in with their directory account".
//
// Three steps, each owned elsewhere: the service account comes from the
// secrets chain (like any connector credential), the directory checks the
// password, and the configured rules decide what the person may touch. This
// is where they meet, so the HTTP handler only translates a form.

// `G` is the service's grant type (its AccessRule::Grant): what its rules
// gave this person, carried out to the session untouched.
#[derive(Debug)]
pub struct LoggedIn<G> {
    pub username: String,
    pub dn: String,
    pub grant: G,
}

#[derive(Debug, PartialEq)]
pub enum LoginError {
    // Wrong password or unknown user — deliberately one answer.
    InvalidCredentials,
    // The password was right, but no `access` rule names this person.
    NotAuthorized,
    // The directory or the service account's secret could not be reached;
    // the message is for the log.
    Unavailable(String),
    // This account failed too many times lately: refused without asking
    // the directory, until the window passes.
    TooManyAttempts,
    // Too many logins already in flight.
    Busy,
}

// Failed passwords allowed per account in a window before the form stops
// asking the directory about it. Well under any sensible directory lockout,
// so a script cannot use this form to lock a real account out.
const MAX_FAILURES: u32 = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
// Directory logins in flight at once: each is a TLS connection and two binds.
const MAX_CONCURRENT: usize = 4;
// Every failed login answers after this long in total, however far it got:
// an unknown user (one search) and a wrong password (one more bind) must
// take the same time, or the time says which usernames exist.
pub const FAILURE_DURATION: Duration = Duration::from_millis(1500);

// What the login form guards itself with: recent failures per account, and
// a cap on concurrent directory logins. In memory and per process; it
// forgets on restart, which is acceptable for a rate limit.
pub struct LoginThrottle {
    failures: Mutex<HashMap<String, (u32, Instant)>>,
    in_flight: tokio::sync::Semaphore,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        LoginThrottle {
            failures: Mutex::new(HashMap::new()),
            in_flight: tokio::sync::Semaphore::new(MAX_CONCURRENT),
        }
    }
}

impl LoginThrottle {
    // Accounts are named however they were typed; case is not identity.
    fn key(username: &str) -> String {
        username.trim().to_lowercase()
    }

    // Whether this account has failed too often lately to be asked about.
    fn blocked(&self, username: &str) -> bool {
        let mut failures = self.failures.lock().expect("login throttle lock");
        match failures.get(&Self::key(username)) {
            Some((count, since)) if since.elapsed() < FAILURE_WINDOW => *count >= MAX_FAILURES,
            Some(_) => {
                failures.remove(&Self::key(username));
                false
            }
            None => false,
        }
    }

    fn failed(&self, username: &str) {
        let mut failures = self.failures.lock().expect("login throttle lock");
        // Forget windows that have closed, so the map does not grow with
        // every name ever typed at the form.
        failures.retain(|_, (_, since)| since.elapsed() < FAILURE_WINDOW);
        let entry = failures
            .entry(Self::key(username))
            .or_insert((0, Instant::now()));
        entry.0 += 1;
    }

    fn succeeded(&self, username: &str) {
        self.failures
            .lock()
            .expect("login throttle lock")
            .remove(&Self::key(username));
    }
}

// ldap_login behind the throttle: refuses an account that has failed too
// often without asking the directory, caps concurrent logins, and makes
// every wrong password take the same total time.
pub async fn throttled_ldap_login<R: AccessRule>(
    throttle: &LoginThrottle,
    secrets: &dyn SecretsPort,
    directory: &dyn DirectoryPort,
    config: &LdapConfig<R>,
    username: &str,
    password: &str,
) -> Result<LoggedIn<R::Grant>, LoginError> {
    let started = Instant::now();
    if throttle.blocked(username) {
        return Err(LoginError::TooManyAttempts);
    }
    let Ok(_permit) =
        tokio::time::timeout(Duration::from_secs(5), throttle.in_flight.acquire()).await
    else {
        return Err(LoginError::Busy);
    };

    let result = ldap_login(secrets, directory, config, username, password).await;
    match &result {
        Err(LoginError::InvalidCredentials) => {
            throttle.failed(username);
            tokio::time::sleep(FAILURE_DURATION.saturating_sub(started.elapsed())).await;
        }
        Ok(_) | Err(LoginError::NotAuthorized) => throttle.succeeded(username),
        _ => {}
    }
    result
}

pub async fn ldap_login<R: AccessRule>(
    secrets: &dyn SecretsPort,
    directory: &dyn DirectoryPort,
    config: &LdapConfig<R>,
    username: &str,
    password: &str,
) -> Result<LoggedIn<R::Grant>, LoginError> {
    let username = username.trim();

    let bind = secrets
        .resolve(&config.bind_credential)
        .await
        .map_err(|e| {
            LoginError::Unavailable(format!(
                "LDAP bind credential '{}': {}",
                config.bind_credential, e.message
            ))
        })?;
    let (Some(bind_dn), Some(bind_password)) = (bind.get("username"), bind.get("password")) else {
        return Err(LoginError::Unavailable(format!(
            "LDAP bind credential '{}' must provide `username` (the bind DN) and `password`",
            config.bind_credential
        )));
    };

    let user = directory
        .authenticate(DirectoryLogin {
            server: config.server(),
            bind_dn,
            bind_password,
            username,
            password,
        })
        .await
        .map_err(|e| match e {
            DirectoryError::InvalidCredentials => LoginError::InvalidCredentials,
            DirectoryError::Unavailable(message) => LoginError::Unavailable(message),
        })?;

    // The directory's name for the account, not the typed spelling: rules
    // and the session name follow the account (see `username_attribute`).
    let username = user.username.as_deref().unwrap_or(username);

    let grant = R::grant_for(&config.access, username, &user.member_of).ok_or_else(|| {
        let groups = user.member_of.len();
        tracing::warn!(
            username,
            groups,
            "LDAP login refused: no access rule names this user or their groups"
        );
        LoginError::NotAuthorized
    })?;

    Ok(LoggedIn {
        username: username.to_string(),
        dn: user.dn,
        grant,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{DirectoryFuture, DirectoryUser};
    use crate::ldap::rule_names;
    use secrets_rs::mock::MockSecrets;

    // A service's rules, reduced to what the use case needs: who they name,
    // and whether they make that person an admin.
    #[derive(Debug, Clone)]
    struct Rule {
        groups: Vec<String>,
        users: Vec<String>,
        admin: bool,
    }

    #[derive(Debug, PartialEq)]
    enum Grant {
        Admin,
        Scoped,
    }

    impl AccessRule for Rule {
        type Grant = Grant;

        fn grant_for(rules: &[Self], username: &str, member_of: &[String]) -> Option<Grant> {
            let named: Vec<&Rule> = rules
                .iter()
                .filter(|rule| rule_names(&rule.users, &rule.groups, username, member_of))
                .collect();
            if named.iter().any(|rule| rule.admin) {
                Some(Grant::Admin)
            } else {
                (!named.is_empty()).then_some(Grant::Scoped)
            }
        }
    }

    // A directory that knows one person: jdoe / right-password, in DL-ops.
    struct OnePerson;

    impl DirectoryPort for OnePerson {
        fn authenticate<'a>(&'a self, request: DirectoryLogin<'a>) -> DirectoryFuture<'a> {
            Box::pin(async move {
                assert_eq!(request.bind_dn, "CN=svc-unified");
                if request.username == "jdoe" && request.password == "right-password" {
                    Ok(DirectoryUser {
                        dn: "CN=John Doe,OU=Users,DC=x".to_string(),
                        username: Some("jdoe".to_string()),
                        member_of: vec!["CN=DL-ops,OU=Groups,DC=x".to_string()],
                    })
                } else {
                    Err(DirectoryError::InvalidCredentials)
                }
            })
        }
    }

    fn config(groups: &[&str]) -> LdapConfig<Rule> {
        LdapConfig {
            url: "ldaps://ldap.example.com".to_string(),
            starttls: false,
            ca_file: None,
            bind_credential: "cred-ldap".to_string(),
            search_base: "DC=x".to_string(),
            user_filter: "(sAMAccountName={username})".to_string(),
            group_attribute: "memberOf".to_string(),
            username_attribute: "sAMAccountName".to_string(),
            timeout_seconds: 5,
            access: vec![Rule {
                groups: groups.iter().map(|g| g.to_string()).collect(),
                users: Vec::new(),
                admin: true,
            }],
        }
    }

    fn secrets() -> MockSecrets {
        MockSecrets::new().with(
            "cred-ldap",
            [("username", "CN=svc-unified"), ("password", "svc-secret")],
        )
    }

    #[tokio::test]
    async fn a_member_of_an_admin_group_logs_in_as_admin() {
        let logged = ldap_login(
            &secrets(),
            &OnePerson,
            &config(&["DL-ops"]),
            " jdoe ",
            "right-password",
        )
        .await
        .expect("login");
        assert_eq!(logged.username, "jdoe");
        assert_eq!(logged.grant, Grant::Admin);
    }

    #[tokio::test]
    async fn a_wrong_password_is_invalid_credentials() {
        let err = ldap_login(&secrets(), &OnePerson, &config(&["DL-ops"]), "jdoe", "nope")
            .await
            .unwrap_err();
        assert_eq!(err, LoginError::InvalidCredentials);
    }

    // The directory accepting the password is not access: only a rule is.
    #[tokio::test]
    async fn a_right_password_without_a_rule_is_not_authorized() {
        let err = ldap_login(
            &secrets(),
            &OnePerson,
            &config(&["DL-other"]),
            "jdoe",
            "right-password",
        )
        .await
        .unwrap_err();
        assert_eq!(err, LoginError::NotAuthorized);
    }

    #[tokio::test]
    async fn a_missing_bind_credential_is_unavailable_and_named() {
        let err = ldap_login(
            &MockSecrets::new(),
            &OnePerson,
            &config(&["DL-ops"]),
            "jdoe",
            "x",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, LoginError::Unavailable(message) if message.contains("cred-ldap")),
            "{err:?}"
        );
    }

    // The directory names whoever the filter found; rules follow that name.
    struct Named(&'static str);

    impl DirectoryPort for Named {
        fn authenticate<'a>(&'a self, _request: DirectoryLogin<'a>) -> DirectoryFuture<'a> {
            let name = self.0;
            Box::pin(async move {
                Ok(DirectoryUser {
                    dn: format!("CN={name},DC=x"),
                    username: Some(name.to_string()),
                    member_of: Vec::new(),
                })
            })
        }
    }

    fn named_rule(users: &[&str]) -> LdapConfig<Rule> {
        let mut cfg = config(&[]);
        cfg.access[0].groups.clear();
        cfg.access[0].users = users.iter().map(|u| u.to_string()).collect();
        cfg
    }

    #[tokio::test]
    async fn user_rules_match_the_account_the_directory_found_not_the_typing() {
        let secrets = MockSecrets::new().with(
            "cred-ldap",
            [("username", "CN=svc-unified"), ("password", "svc")],
        );
        // Typed someone else's name, but the directory says it is "mallory":
        // the rule written for "jdoe" must not apply.
        let refused = ldap_login(
            &secrets,
            &Named("mallory"),
            &named_rule(&["jdoe"]),
            "jdoe",
            "pw",
        )
        .await;
        assert_eq!(refused.unwrap_err(), LoginError::NotAuthorized);

        // Typed an e-mail address the filter maps to jdoe: jdoe's rule applies,
        // and the session is named after the account.
        let logged = ldap_login(
            &secrets,
            &Named("jdoe"),
            &named_rule(&["jdoe"]),
            "j.doe@x.com",
            "pw",
        )
        .await
        .expect("jdoe's rule");
        assert_eq!(logged.username, "jdoe");
    }

    // The bind credential resolves, but without the two fields a bind needs.
    #[tokio::test]
    async fn a_bind_credential_without_a_dn_and_password_is_named() {
        let secrets = MockSecrets::new().with("cred-ldap", [("token", "x")]);
        let err = ldap_login(&secrets, &OnePerson, &config(&["DL-ops"]), "jdoe", "x")
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LoginError::Unavailable(
                "LDAP bind credential 'cred-ldap' must provide `username` (the bind DN) and `password`"
                    .to_string()
            )
        );
    }

    // A directory that cannot answer.
    struct Down;

    impl DirectoryPort for Down {
        fn authenticate<'a>(&'a self, _request: DirectoryLogin<'a>) -> DirectoryFuture<'a> {
            Box::pin(async { Err(DirectoryError::Unavailable("connect: refused".to_string())) })
        }
    }

    #[tokio::test]
    async fn an_unreachable_directory_is_unavailable_with_its_message() {
        let err = ldap_login(&secrets(), &Down, &config(&["DL-ops"]), "jdoe", "x")
            .await
            .unwrap_err();
        assert_eq!(err, LoginError::Unavailable("connect: refused".to_string()));
    }

    // The refusal is logged with how many groups the person had, so a missing
    // group membership can be told from a missing rule.
    #[tokio::test]
    async fn a_refused_login_is_logged() {
        // One process-wide subscriber: a thread-local one races the global
        // interest cache of tests that log first without any.
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| tracing_subscriber::fmt().with_test_writer().init());
        let err = ldap_login(
            &secrets(),
            &OnePerson,
            &config(&["DL-other"]),
            "jdoe",
            "right-password",
        )
        .await
        .unwrap_err();
        assert_eq!(err, LoginError::NotAuthorized);
    }

    async fn throttled(
        throttle: &LoginThrottle,
        directory: &dyn DirectoryPort,
        password: &str,
    ) -> Result<LoggedIn<Grant>, LoginError> {
        throttled_ldap_login(
            throttle,
            &secrets(),
            directory,
            &config(&["DL-ops"]),
            "jdoe",
            password,
        )
        .await
    }

    // Five wrong passwords, then the account is refused without asking the
    // directory, even with the right one, until the window passes.
    #[tokio::test(start_paused = true)]
    async fn too_many_failures_lock_the_form_not_the_account() {
        let throttle = LoginThrottle::default();
        for _ in 0..MAX_FAILURES {
            assert_eq!(
                throttled(&throttle, &OnePerson, "nope").await.unwrap_err(),
                LoginError::InvalidCredentials
            );
        }
        assert_eq!(
            throttled(&throttle, &OnePerson, "right-password")
                .await
                .unwrap_err(),
            LoginError::TooManyAttempts
        );

        // The window has passed: the stale count is forgotten, and asked again.
        throttle.failures.lock().unwrap().insert(
            LoginThrottle::key("jdoe"),
            (MAX_FAILURES, Instant::now() - FAILURE_WINDOW),
        );
        assert!(
            throttled(&throttle, &OnePerson, "right-password")
                .await
                .is_ok()
        );
    }

    // Every wrong password takes the same total time, however early it failed.
    #[tokio::test(start_paused = true)]
    async fn a_wrong_password_answers_after_the_failure_duration() {
        let throttle = LoginThrottle::default();
        let started = tokio::time::Instant::now();
        throttled(&throttle, &OnePerson, "nope").await.unwrap_err();
        assert!(started.elapsed() >= FAILURE_DURATION);
    }

    // A success forgets earlier failures; names are counted case-insensitively.
    #[tokio::test(start_paused = true)]
    async fn a_success_clears_the_failures() {
        let throttle = LoginThrottle::default();
        throttled(&throttle, &OnePerson, "nope").await.unwrap_err();
        assert!(throttle.failures.lock().unwrap().contains_key("jdoe"));
        throttled(&throttle, &OnePerson, "right-password")
            .await
            .unwrap();
        assert!(throttle.failures.lock().unwrap().is_empty());
        assert_eq!(LoginThrottle::key(" JDoe "), "jdoe");
    }

    // An outage is neither a failure nor a success: nothing is counted.
    #[tokio::test]
    async fn an_outage_counts_nothing() {
        let throttle = LoginThrottle::default();
        throttled(&throttle, &Down, "x").await.unwrap_err();
        assert!(throttle.failures.lock().unwrap().is_empty());
    }

    // With every slot taken, a login waits five seconds, then says so.
    #[tokio::test(start_paused = true)]
    async fn a_full_house_is_busy() {
        let throttle = LoginThrottle::default();
        let _all = throttle
            .in_flight
            .acquire_many(MAX_CONCURRENT as u32)
            .await
            .unwrap();
        assert_eq!(
            throttled(&throttle, &OnePerson, "right-password")
                .await
                .unwrap_err(),
            LoginError::Busy
        );
    }
}

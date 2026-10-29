use serde::{Deserialize, Serialize};

// LDAP login for a service's web UI — its config.yaml, `server.ui.ldap`.
//
// People log in with their directory account; what they may touch is decided
// by the `access` rules, in the same vocabulary the service's API keys use
// (admin, or restricted to what that service has: sources and endpoints in
// unified-api, applications in unified-gitops). The rule type is the
// service's own — `R` below, an `AccessRule` — and this module only says
// whether a rule names someone. The directory says who someone is and which
// groups they belong to; it never decides access on its own, so a new group in
// AD grants nothing until a rule names it.
//
// The service account's password is not in this block: `bind_credential`
// names a credentials.yaml entry, resolved through the same secrets chain
// (env, file, Vault) every connector credential goes through.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LdapConfig<R> {
    // ldaps://host:636, or ldap://host:389 with `starttls: true`. A plain
    // ldap:// without StartTLS is refused at validation: it would send every
    // password that logs in across the network in the clear.
    pub url: String,

    #[serde(default)]
    pub starttls: bool,

    // PEM file with the CA that signed the directory's certificate, for a
    // private CA. Unset = the system's trust store.
    #[serde(default)]
    pub ca_file: Option<String>,

    // credentials.yaml id whose `username` is the bind DN of the service
    // account that looks users up, and whose `password` is its password.
    pub bind_credential: String,

    // Where users are searched for, e.g. "OU=Users,DC=example,DC=com".
    pub search_base: String,

    // `{username}` is replaced by what was typed, escaped (RFC 4515) so a
    // username cannot rewrite the filter. Active Directory's default.
    #[serde(default = "default_user_filter")]
    pub user_filter: String,

    // Attribute listing the DNs of the user's groups.
    #[serde(default = "default_group_attribute")]
    pub group_attribute: String,
    // Attribute holding the account's own name. Access rules' `users:` and
    // the session's name use ITS value, not what was typed: with a filter
    // that matches on several attributes (an e-mail address, say), what was
    // typed is not the account's name, and must not be able to match a rule
    // written for someone else's.
    #[serde(default = "default_username_attribute")]
    pub username_attribute: String,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    // Who may log in, and with what. Evaluated top to bottom, all matches
    // combined: admin anywhere is admin; otherwise the scoped lists are
    // unioned. Matching nothing means the login is refused, even with a
    // correct password.
    //
    // `default = "Vec::new"` rather than plain `default`: the plain form makes
    // serde require `R: Default`, which a rule type has no reason to be.
    #[serde(default = "Vec::new")]
    pub access: Vec<R>,
}

impl<R> LdapConfig<R> {
    // The part of the block the directory adapter needs: where the server is
    // and how to find someone in it. Borrowed, so the port stays free of the
    // service's rule type.
    pub fn server(&self) -> LdapServer<'_> {
        LdapServer {
            url: &self.url,
            starttls: self.starttls,
            ca_file: self.ca_file.as_deref(),
            search_base: &self.search_base,
            user_filter: &self.user_filter,
            group_attribute: &self.group_attribute,
            username_attribute: &self.username_attribute,
            timeout_seconds: self.timeout_seconds,
        }
    }
}

// Where the directory is and how to search it — LdapConfig without the bind
// credential (resolved by the caller) and the access rules (the service's).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LdapServer<'a> {
    pub url: &'a str,
    pub starttls: bool,
    pub ca_file: Option<&'a str>,
    pub search_base: &'a str,
    pub user_filter: &'a str,
    pub group_attribute: &'a str,
    pub username_attribute: &'a str,
    pub timeout_seconds: u64,
}

fn default_user_filter() -> String {
    "(sAMAccountName={username})".to_string()
}

fn default_username_attribute() -> String {
    "sAMAccountName".to_string()
}

fn default_group_attribute() -> String {
    "memberOf".to_string()
}

fn default_timeout_seconds() -> u64 {
    10
}

// A service's access rule: what one entry of `access:` grants. Each service
// writes its own (the lists a restricted rule names differ), and implements
// this so the login use case can ask it without knowing its fields.
//
// A trait with an associated type: `Grant` is whatever the service's rules
// produce (admin, or a set of ids), named by the implementation, so
// `LoggedIn<R::Grant>` carries the service's own type back out.
pub trait AccessRule: Sized {
    type Grant;

    // The rules applied to one authenticated person. None = no rule names
    // them, and the login is refused even with a correct password.
    fn grant_for(rules: &[Self], username: &str, member_of: &[String]) -> Option<Self::Grant>;
}

// Whether a rule naming these users and groups names this person: by account
// name (case-insensitive), or by one of their groups. The one matching rule
// every service's grant_for uses, so group matching cannot drift between them.
pub fn rule_names(
    users: &[String],
    groups: &[String],
    username: &str,
    member_of: &[String],
) -> bool {
    users.iter().any(|u| u.eq_ignore_ascii_case(username))
        || groups.iter().any(|g| group_matches(g, member_of))
}

// The CN of a DN: "CN=DL-ops,OU=Groups,DC=x" → "DL-ops". Escaped commas
// ("CN=Smith\, Jo,...") stay part of the value.
fn common_name(dn: &str) -> Option<&str> {
    let first = split_rdn(dn);
    let (attr, value) = first.split_once('=')?;
    attr.trim()
        .eq_ignore_ascii_case("cn")
        .then_some(value.trim())
}

fn split_rdn(dn: &str) -> &str {
    let mut escaped = false;
    for (index, ch) in dn.char_indices() {
        match ch {
            '\\' if !escaped => escaped = true,
            ',' if !escaped => return &dn[..index],
            _ => escaped = false,
        }
    }
    dn
}

fn group_matches(wanted: &str, member_of: &[String]) -> bool {
    if wanted.contains('=') {
        member_of.iter().any(|dn| dn.eq_ignore_ascii_case(wanted))
    } else {
        member_of
            .iter()
            .filter_map(|dn| common_name(dn))
            .any(|cn| cn.eq_ignore_ascii_case(wanted))
    }
}

// The user filter with the username substituted, escaped so `*`, `(` or `\`
// in a username are literals rather than filter syntax: without it, typing
// `*` as a username would match the first account the search returns.
pub fn user_filter(template: &str, username: &str) -> String {
    template.replace("{username}", &escape_filter_value(username))
}

// RFC 4515: the five characters with a meaning inside a filter value become
// \XX. Written here rather than borrowed from the LDAP client so the domain
// keeps no dependency on an adapter's crate.
fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPS: &str = "CN=DL-pcol2operations,OU=Groups,DC=example,DC=com";

    fn names(users: &[&str], groups: &[&str], username: &str) -> bool {
        let users: Vec<String> = users.iter().map(|u| u.to_string()).collect();
        let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
        rule_names(&users, &groups, username, &[OPS.to_string()])
    }

    #[test]
    fn a_group_cn_matches_the_users_group_dn() {
        assert!(names(&[], &["dl-PCOL2operations"], "jdoe"));
    }

    #[test]
    fn a_full_dn_matches_only_that_group() {
        assert!(!names(
            &[],
            &["CN=DL-pcol2operations,OU=Other,DC=example,DC=com"],
            "jdoe"
        ));
        assert!(names(&[], &[OPS], "jdoe"));
    }

    #[test]
    fn a_user_is_named_whatever_the_case() {
        assert!(names(&["JDoe"], &[], "jdoe"));
        assert!(!names(&["jdoe"], &["DL-other"], "mallory"));
    }

    #[test]
    fn an_escaped_comma_stays_inside_the_cn() {
        assert_eq!(
            common_name("CN=Ops\\, Spain,OU=Groups,DC=x"),
            Some("Ops\\, Spain")
        );
        assert_eq!(common_name("OU=Groups,DC=x"), None);
        assert_eq!(common_name("CN=standalone"), Some("standalone"));
        assert_eq!(common_name("no attribute at all"), None);
    }

    #[test]
    fn filter_syntax_in_a_username_is_escaped() {
        assert_eq!(
            user_filter("(sAMAccountName={username})", "*)(uid=*"),
            "(sAMAccountName=\\2a\\29\\28uid=\\2a)"
        );
        assert_eq!(
            user_filter("(uid={username})", "a\\b\0c"),
            "(uid=a\\5cb\\00c)"
        );
    }

    // The service's own rules ride along untouched; unknown keys still fail.
    #[test]
    fn the_access_rules_are_the_services_type() {
        #[derive(Debug, serde::Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct Rule {
            name: String,
        }
        let config: LdapConfig<Rule> = serde_saphyr::from_str(
            "url: ldaps://x\nbind_credential: cred-ldap\nsearch_base: DC=x\naccess:\n  - name: ops\n",
        )
        .unwrap();
        assert_eq!(
            config.access,
            vec![Rule {
                name: "ops".to_string()
            }]
        );
        assert_eq!(config.server().user_filter, "(sAMAccountName={username})");
        let typo: Result<LdapConfig<Rule>, _> = serde_saphyr::from_str(
            "url: ldaps://x\nbind_credential: c\nsearch_base: DC=x\nstart_tls: true\n",
        );
        assert!(typo.is_err());
    }
}

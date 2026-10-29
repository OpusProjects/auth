// auth-rs — signing people in to a web service.
//
// A person logs in with their directory account (LDAP / Active Directory);
// the directory says who they are and which groups they belong to, and the
// service's own access rules say what that gets them. This crate holds the
// parts every service shares:
//
// - `directory`: DirectoryPort, "check this password, name these groups"
// - `ldap_directory`: the DirectoryPort that talks to an LDAP server
// - `ldap`: the `server.ui.ldap` block, the AccessRule trait each service's
//   rules implement, and the group matching they all use
// - `login`: the use case — bind credential, directory, rules — behind a
//   throttle that slows password guessing
// - `http`: what a signed-in request carries — API keys and the middleware
//   that checks them, browser sessions, CSRF — generic over each service's
//   permissions type
//
// The service account's password comes through secrets-rs, like any
// other credential. Shared by unified-api and unified-gitops: a fix here
// lands in both.

pub mod directory;
pub mod http;
pub mod ldap;
pub mod ldap_directory;
pub mod login;

pub use directory::{DirectoryError, DirectoryLogin, DirectoryPort, DirectoryUser};
pub use ldap::{AccessRule, LdapConfig, LdapServer, rule_names};
pub use login::{LoggedIn, LoginError, LoginThrottle, ldap_login, throttled_ldap_login};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

use super::Permission;

// Browser sessions, for the browsable API.
//
// Why a session at all, when the API already has keys: Swagger's Authorize
// button works because Swagger never navigates — it holds the key in
// JavaScript and attaches it to the `fetch` calls it makes itself. A browsable
// API is the opposite. Every click is a document navigation, and a document
// navigation carries no custom headers. That is the whole reason AWX has a
// login form and a session cookie rather than a header box.
//
// What a session is NOT: a second credential store. Logging in means presenting
// an existing API key, validated by exactly the same constant-time compare as a
// header would be, or a directory account checked by the directory itself.
// The session is a short-lived handle on what that login granted.
//
// The cookie that carries it is named by each service (`uapi_session`,
// `ugitops_session`), so two of them on one host never overwrite each other.

// How a session was opened, which decides what revokes it: an API key session
// ends when its key leaves api_keys.yaml, an LDAP one when the LDAP
// configuration (the directory or its access rules) changes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SessionKind {
    ApiKey,
    Directory,
}

pub struct Session<P> {
    // Who this session is: the key's name, or `ldap:<username>`. Named in the
    // access log exactly as a header-authenticated request is.
    pub key_name: String,
    pub kind: SessionKind,
    // The key's identity (its api_keys `name`) for a key session: what a
    // reload revokes it by. Its label (key_name, the description) is for
    // people and need not be unique — two keys described alike, one removed,
    // and revoking by label kept the removed key's sessions working.
    key_id: Option<String>,
    pub permissions: P,
    // Paired with the session and required on every unsafe request that
    // authenticates by cookie. See `auth::require_api_key` for why.
    pub csrf: String,
    expires_at: Instant,
}

// Generic over the service's permissions type: the store only keeps it and
// hands a clone back, so it never needs to know what a scope looks like.
pub struct SessionStore<P> {
    sessions: DashMap<String, Session<P>>,
}

impl<P: Permission> Default for SessionStore<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Permission> SessionStore<P> {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    // In memory, deliberately: a restart invalidating every session is correct
    // behaviour for an operator console, and it keeps the promise that this
    // service has no external data dependency. The alternative — signed cookies
    // that survive a restart — means a key revoked while the process was down
    // comes back to life with it.
    pub fn create(
        &self,
        key_name: String,
        kind: SessionKind,
        key_id: Option<String>,
        permissions: P,
        ttl: Duration,
    ) -> Issued {
        // Expired entries are normally dropped when looked up, but a browser
        // that logs in and is never used again is never looked up. Sweeping on
        // login bounds the map by "sessions in use" instead of "logins since
        // the process started", and it costs a walk of a map that is small by
        // construction.
        self.sessions
            .retain(|_, session| Instant::now() < session.expires_at);

        let token = random_token();
        let csrf = random_token();
        self.sessions.insert(
            token.clone(),
            Session {
                key_name,
                kind,
                key_id,
                permissions,
                csrf: csrf.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
        Issued { token, csrf }
    }

    // Returns the session's identity, or None when the token is unknown or
    // expired. An expired entry is removed on the way out rather than by a
    // sweeper task: the map only grows with logins, and every login eventually
    // gets looked up or outlives the process.
    pub fn get(&self, token: &str) -> Option<Authenticated<P>> {
        // The map's read guard is dropped at the end of this block, before
        // `remove` takes the write lock on the same shard — holding both
        // would deadlock.
        let live = {
            let session = self.sessions.get(token)?;
            (Instant::now() < session.expires_at).then(|| Authenticated {
                key_name: session.key_name.clone(),
                kind: session.kind,
                permissions: session.permissions.clone(),
                csrf: session.csrf.clone(),
            })
        };
        if live.is_none() {
            self.sessions.remove(token);
        }
        live
    }

    pub fn remove(&self, token: &str) {
        self.sessions.remove(token);
    }

    // A configuration reload can rewrite api_keys.yaml. Without this, a key
    // revoked by that reload keeps working in every browser that logged in
    // before it — the console would outlive the revocation, which is exactly
    // the property a revocation is for.
    // `live` holds key identities (ResolvedApiKey::id), never labels.
    pub fn retain_keys(&self, live: &[String]) {
        self.sessions.retain(|_, session| {
            session.kind != SessionKind::ApiKey
                || session.key_id.as_ref().is_some_and(|id| live.contains(id))
        });
    }

    // Every LDAP session, ended. Returns how many there were, for the log.
    pub fn end_directory_sessions(&self) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| session.kind != SessionKind::Directory);
        before - self.sessions.len()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

pub struct Issued {
    pub token: String,
    pub csrf: String,
}

pub struct Authenticated<P> {
    pub key_name: String,
    pub kind: SessionKind,
    pub permissions: P,
    pub csrf: String,
}

// 256 bits from the OS, hex-encoded. Never the API key itself: a key in a
// cookie is a key in a browser profile, in a backup, and in every screenshot of
// devtools someone pastes into a ticket.
pub fn new_token() -> String {
    random_token()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random source");
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

// The CSRF token is compared the same way the API key is: a token that is
// checked with `==` leaks its bytes through timing, and this one guards every
// write the console can make.
pub fn csrf_matches(expected: &str, presented: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}

// The session cookie out of a Cookie header. Written by hand rather than with a
// cookie crate: one name, no attributes to parse on the way in, and the jar
// crates bring a dependency tree for a `split(';')`.
pub fn cookie_value<'h>(header: &'h str, name: &str) -> Option<&'h str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then_some(value.trim())
    })
}

// The store, injected as a router Extension the way the key registry is.
// `new` rather than the tuple constructor, so a service's type alias
// (`Sessions = unified_auth::http::Sessions<Permissions>`) can build one: Rust
// lets an alias name a type, but not call a tuple struct's constructor.
pub struct Sessions<P>(pub Arc<SessionStore<P>>);

impl<P> Sessions<P> {
    pub fn new(store: Arc<SessionStore<P>>) -> Self {
        Self(store)
    }
}

// By hand: `#[derive(Clone)]` would demand `P: Clone` for what is a pointer
// copy whatever P is.
impl<P> Clone for Sessions<P> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

// What a browser form said, lifted out of the body before anything downstream
// reads the request. Absent for every request that is not a form post.
#[derive(Clone, Default)]
pub struct FormControls {
    pub csrf: Option<String>,
}

// Browser forms, translated into what the API already speaks.
//
// Two jobs, both of which exist because an HTML form is a poor HTTP client:
//
//   - It can only send GET and POST. The DELETE routes are reached with a POST
//     carrying `_method=DELETE`, translated here and NOWHERE else — the JSON
//     API keeps its real verbs, and a JSON client never goes through this path
//     because it does not post urlencoded bodies.
//   - It cannot set a header, so its CSRF token travels in the body. Lifting it
//     out here keeps the auth middleware from having to parse bodies, which is
//     not its job and would make it the one place that buffers a request.
//
//   - Its real fields (`host`, `group`, …) are what the operator typed, and the
//     handlers read those from the QUERY. They are moved there, because a form
//     cannot put them in a URL by itself once it is POSTing.
//
// The body is then replaced with an empty one: every route a form can reach
// (sync, run, evict, delete) takes no body at all, so once the fields are
// lifted out there is nothing left to carry. A JSON client never passes
// through here — it does not post this content-type.
//
// `cookie` is the service's session cookie name. A service mounts this through
// a two-line wrapper that passes its own, since `middleware::from_fn` takes a
// function of the request and `next` only.
pub async fn form_action(cookie: &str, request: Request, next: Next) -> Response {
    let is_form = request.method() == Method::POST
        && request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));

    if !is_form {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();
    // Small by construction: a couple of control fields. A form body larger
    // than this is not one of ours.
    let Ok(bytes) = axum::body::to_bytes(body, 8 * 1024).await else {
        // Say what went wrong. Falling through with an empty body used to
        // reach the auth middleware with no CSRF token and answer 403, which
        // sends whoever hit it looking for a permissions problem that is not
        // there.
        return (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "form body too large",
        )
            .into_response();
    };

    let mut csrf = None;
    let mut method_override = None;
    // Everything that is not a control field is a real parameter the operator
    // typed, and the handlers read those from the QUERY — `?host=`, `?group=`.
    // Moving them there is the whole point of the form: without this, typing a
    // hostname into the Sync field and pressing the button re-gathered the
    // entire source, silently doing far more work than was asked for.
    let mut passthrough: Vec<String> = Vec::new();
    for pair in String::from_utf8_lossy(&bytes).split('&') {
        match pair.split_once('=') {
            Some(("_csrf", value)) => csrf = Some(value.to_string()),
            Some(("_method", value)) => method_override = Some(value.to_ascii_uppercase()),
            // A browser submits every field, empty ones included; an empty
            // `?host=` is not the same request as no `host` at all.
            Some((name, value)) if !name.starts_with('_') && !value.is_empty() => {
                passthrough.push(format!("{name}={value}"));
            }
            _ => {}
        }
    }

    if !passthrough.is_empty() {
        parts.uri = merge_query(&parts.uri, &passthrough);
    }

    parts.extensions.insert(FormControls { csrf });

    // Only DELETE, and only for a request that carries a session cookie.
    //
    // The cookie requirement is the important half. Without it, ANY urlencoded
    // POST could become a DELETE — including one from a page on the internet
    // aimed at an instance with no API keys configured, where every caller is
    // admin and no CSRF token is demanded. A browser form cannot otherwise
    // reach a DELETE route at all, so honouring `_method` unconditionally
    // handed the web a write primitive it did not have before. A caller
    // holding an API key loses nothing: it can send a real DELETE.
    let from_a_session = parts
        .headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| cookie_value(c, cookie).is_some());

    if from_a_session && method_override.as_deref() == Some("DELETE") {
        parts.method = Method::DELETE;
        parts.headers.remove(header::CONTENT_TYPE);
    }
    parts.headers.remove(header::CONTENT_LENGTH);

    next.run(Request::from_parts(parts, Body::empty())).await
}

// Put the form's fields into the request's query string, keeping whatever was
// already there. The values arrive percent-encoded from the browser and go
// back out the same way, so they are moved verbatim rather than decoded and
// re-encoded — this is a transport change, not a parse.
fn merge_query(uri: &axum::http::Uri, extra: &[String]) -> axum::http::Uri {
    let mut query: Vec<String> = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    query.extend(extra.iter().cloned());

    let mut parts = uri.clone().into_parts();
    let path = parts
        .path_and_query
        .as_ref()
        .map_or("/", |pq| pq.path())
        .to_string();

    match format!("{path}?{}", query.join("&")).parse() {
        Ok(path_and_query) => {
            parts.path_and_query = Some(path_and_query);
            // Only the path and query changed, and they just parsed: the
            // parts are those of a URI that was already valid.
            axum::http::Uri::from_parts(parts).expect("a valid URI with a new valid query")
        }
        // A field the browser encoded in a way we cannot put back into a URI:
        // the request proceeds without it rather than failing, and the handler
        // answers for the scope it can see.
        Err(_) => uri.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use axum::routing::post;
    use tower::ServiceExt;

    // A stand-in for a service's permissions: the store never looks inside.
    #[derive(Clone, Debug, PartialEq)]
    enum Perm {
        Admin,
    }

    impl Permission for Perm {
        fn admin() -> Self {
            Perm::Admin
        }
    }

    const COOKIE: &str = "test_session";

    fn store() -> SessionStore<Perm> {
        SessionStore::default()
    }

    fn admin() -> Perm {
        Perm::admin()
    }

    #[test]
    fn a_session_authenticates_as_its_key() {
        let store = store();
        let issued = store.create(
            "AWX".into(),
            SessionKind::ApiKey,
            Some("AWX".into()),
            admin(),
            Duration::from_secs(60),
        );
        let found = store.get(&issued.token).expect("session");
        assert_eq!(found.key_name, "AWX");
        assert_eq!(found.kind, SessionKind::ApiKey);
        assert_eq!(found.permissions, Perm::Admin);
        assert_eq!(found.csrf, issued.csrf);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn an_unknown_token_authenticates_nothing() {
        let store = store();
        assert!(store.get("nope").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn an_expired_session_stops_working_and_is_dropped() {
        let store = store();
        let issued = store.create(
            "AWX".into(),
            SessionKind::ApiKey,
            Some("AWX".into()),
            admin(),
            Duration::from_secs(0),
        );
        assert!(store.get(&issued.token).is_none());
        assert_eq!(store.len(), 0, "the expired entry must not be kept");
    }

    // A browser that logged in and never came back is never looked up; the
    // next login sweeps it.
    #[test]
    fn a_login_sweeps_expired_sessions() {
        let store = store();
        store.create(
            "old".into(),
            SessionKind::ApiKey,
            Some("old".into()),
            admin(),
            Duration::from_secs(0),
        );
        store.create(
            "new".into(),
            SessionKind::ApiKey,
            Some("new".into()),
            admin(),
            Duration::from_secs(60),
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn logout_ends_the_session() {
        let store = store();
        let issued = store.create(
            "AWX".into(),
            SessionKind::ApiKey,
            Some("AWX".into()),
            admin(),
            Duration::from_secs(60),
        );
        store.remove(&issued.token);
        assert!(store.get(&issued.token).is_none());
    }

    // The reload case: a key that disappears from api_keys.yaml must not keep
    // a browser logged in.
    #[test]
    fn revoking_a_key_ends_its_sessions_only() {
        let store = store();
        let stays = store.create(
            "AWX".into(),
            SessionKind::ApiKey,
            Some("AWX".into()),
            admin(),
            Duration::from_secs(60),
        );
        let goes = store.create(
            "Retired".into(),
            SessionKind::ApiKey,
            Some("Retired".into()),
            admin(),
            Duration::from_secs(60),
        );

        store.retain_keys(&["AWX".to_string()]);

        assert!(store.get(&stays.token).is_some());
        assert!(store.get(&goes.token).is_none());
    }

    // Revoked by identity, not by label: two keys described alike, and the
    // one removed takes only its own sessions with it.
    #[test]
    fn a_key_is_revoked_by_its_identity_not_its_label() {
        let store = store();
        let stays = store.create(
            "Automation".into(),
            SessionKind::ApiKey,
            Some("key-awx".into()),
            admin(),
            Duration::from_secs(60),
        );
        let goes = store.create(
            "Automation".into(),
            SessionKind::ApiKey,
            Some("key-old".into()),
            admin(),
            Duration::from_secs(60),
        );

        store.retain_keys(&["key-awx".to_string()]);

        assert!(store.get(&stays.token).is_some());
        assert!(store.get(&goes.token).is_none());
    }

    // An LDAP session is not a key: a key reload must leave it alone, and an
    // LDAP change must end it without touching the key sessions.
    #[test]
    fn each_kind_of_session_is_revoked_by_its_own_change() {
        let store = store();
        let key = store.create(
            "AWX".into(),
            SessionKind::ApiKey,
            Some("AWX".into()),
            admin(),
            Duration::from_secs(60),
        );
        let person = store.create(
            "ldap:jdoe".into(),
            SessionKind::Directory,
            None,
            admin(),
            Duration::from_secs(60),
        );

        store.retain_keys(&["AWX".to_string()]);
        assert!(
            store.get(&person.token).is_some(),
            "a key reload ended an LDAP session"
        );

        assert_eq!(store.end_directory_sessions(), 1);
        assert!(store.get(&person.token).is_none());
        assert!(store.get(&key.token).is_some());
    }

    #[test]
    fn tokens_are_unique_and_long() {
        let store = store();
        let a = store.create(
            "k".into(),
            SessionKind::ApiKey,
            Some("k".into()),
            admin(),
            Duration::from_secs(60),
        );
        let b = store.create(
            "k".into(),
            SessionKind::ApiKey,
            Some("k".into()),
            admin(),
            Duration::from_secs(60),
        );
        assert_ne!(a.token, b.token);
        assert_ne!(a.token, a.csrf, "the CSRF token is not the session token");
        assert_eq!(a.token.len(), 64);
        assert!(a.token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(new_token().len(), 64);
    }

    #[test]
    fn csrf_compare_accepts_only_the_exact_token() {
        assert!(csrf_matches("abc", "abc"));
        assert!(!csrf_matches("abc", "abd"));
        assert!(!csrf_matches("abc", "ab"));
        assert!(!csrf_matches("abc", ""));
    }

    #[test]
    fn cookie_is_found_among_others() {
        let header = "theme=dark; test_session=deadbeef; other=1";
        assert_eq!(cookie_value(header, COOKIE), Some("deadbeef"));
        assert_eq!(cookie_value("theme=dark", COOKIE), None);
        assert_eq!(cookie_value("garbage", COOKIE), None);
        // A cookie whose name merely ends with ours must not match
        assert_eq!(cookie_value("not_test_session=x", COOKIE), None);
    }

    #[test]
    fn the_extension_is_a_shared_handle_on_one_store() {
        let sessions = Sessions::new(Arc::new(store()));
        let copy = sessions.clone();
        copy.0.create(
            "k".into(),
            SessionKind::ApiKey,
            Some("k".into()),
            admin(),
            Duration::from_secs(60),
        );
        assert_eq!(sessions.0.len(), 1);
    }

    // ------------------------------------------------------- form_action

    // Echoes what reached the handler: the method, the query, and the CSRF
    // token the layer lifted out of the body.
    async fn echo(request: Request) -> String {
        let csrf = request
            .extensions()
            .get::<FormControls>()
            .and_then(|controls| controls.csrf.clone())
            .unwrap_or_default();
        format!(
            "{} {} {}",
            request.method(),
            request.uri().query().unwrap_or(""),
            csrf
        )
    }

    fn form_app() -> axum::Router {
        axum::Router::new()
            .route("/x", post(echo).delete(echo).get(echo))
            .layer(axum::middleware::from_fn(|request, next| {
                form_action(COOKIE, request, next)
            }))
    }

    fn form(body: &str, cookie: Option<&str>) -> HttpRequest<Body> {
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            req = req.header("cookie", cookie);
        }
        req.body(Body::from(body.to_string())).unwrap()
    }

    async fn body(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    // A cross-site form must not be able to reach a DELETE route. The override
    // exists for a browser session and nothing else.
    #[tokio::test]
    async fn the_method_override_needs_a_session_cookie() {
        let resp = form_app()
            .oneshot(form("_method=DELETE", None))
            .await
            .unwrap();
        assert_eq!(body(resp).await, "POST  ");

        let resp = form_app()
            .oneshot(form("_method=delete", Some("test_session=abc")))
            .await
            .unwrap();
        assert_eq!(body(resp).await, "DELETE  ");
    }

    #[tokio::test]
    async fn a_form_hands_its_token_and_fields_on() {
        let resp = form_app()
            .oneshot(form("_csrf=tok&host=a&group=&_other=x&junk", None))
            .await
            .unwrap();
        // The empty `group` and the unknown control field stay behind
        assert_eq!(body(resp).await, "POST host=a tok");
    }

    #[tokio::test]
    async fn a_request_that_is_not_a_form_is_left_alone() {
        let get = HttpRequest::builder()
            .uri("/x?host=a")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            body(form_app().oneshot(get).await.unwrap()).await,
            "GET host=a "
        );

        let json = HttpRequest::builder()
            .method("POST")
            .uri("/x")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            body(form_app().oneshot(json).await.unwrap()).await,
            "POST  "
        );
    }

    #[tokio::test]
    async fn an_oversized_form_is_refused_by_name() {
        let big = "a=".to_string() + &"x".repeat(9 * 1024);
        let resp = form_app().oneshot(form(&big, None)).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body(resp).await, "form body too large");
    }

    #[test]
    fn form_fields_become_query_parameters() {
        let uri: axum::http::Uri = "/api/v1/sources/src-d42/sync".parse().unwrap();
        let merged = merge_query(&uri, &["host=motoko.section9.net".to_string()]);
        assert_eq!(
            merged.to_string(),
            "/api/v1/sources/src-d42/sync?host=motoko.section9.net"
        );
    }

    #[test]
    fn form_fields_keep_an_existing_query() {
        let uri: axum::http::Uri = "/api/v1/sources/src-d42/sync?refresh_depth=2"
            .parse()
            .unwrap();
        let merged = merge_query(&uri, &["host=a".to_string(), "group=b".to_string()]);
        assert_eq!(merged.query(), Some("refresh_depth=2&host=a&group=b"));
    }

    // A value no URI can carry (a raw space) leaves the request as it was.
    #[test]
    fn a_field_that_cannot_be_a_query_is_dropped() {
        let uri: axum::http::Uri = "/x?keep=1".parse().unwrap();
        let merged = merge_query(&uri, &["host=a b".to_string()]);
        assert_eq!(merged, uri);
    }
}

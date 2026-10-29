use std::sync::{Arc, RwLock};

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;

use super::Permission;
use super::session::{
    Authenticated, FormControls, SessionKind, Sessions, cookie_value, csrf_matches,
};

// A configured key with its secret already resolved from the environment
// (the service resolves it at the boundary; nothing here touches env vars).
#[derive(Clone)]
pub struct ResolvedApiKey<P> {
    // The key's identity: its `name` in the api_keys item. What a reload
    // revokes a key's sessions by.
    pub id: String,
    // Its label (`description`, falling back to the name): logs, Users page.
    pub name: String,
    pub secret: String,
    pub permissions: P,
}

// The keys in force right now, behind one pointer a reload can replace.
//
// The middleware reads this on every request rather than holding a list, so
// rewriting api_keys.yaml takes effect on the next request — the one thing
// that would otherwise still need a restart on a system whose whole point is
// that a configuration push does not need one. A request already in flight
// keeps the set it authenticated against.
pub struct ApiKeyRegistry<P> {
    keys: RwLock<Arc<[ResolvedApiKey<P>]>>,
}

impl<P: Permission> ApiKeyRegistry<P> {
    pub fn new(keys: Vec<ResolvedApiKey<P>>) -> Self {
        Self {
            keys: RwLock::new(keys.into()),
        }
    }

    pub fn load(&self) -> Arc<[ResolvedApiKey<P>]> {
        Arc::clone(&self.keys.read().expect("api key registry lock"))
    }

    pub fn replace(&self, keys: Vec<ResolvedApiKey<P>>) {
        *self.keys.write().expect("api key registry lock") = keys.into();
    }

    pub fn len(&self) -> usize {
        self.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.load().is_empty()
    }
}

// A browser session's identity, published on the response for the HTML layer.
#[derive(Clone)]
pub struct BrowserIdentity {
    pub key_name: String,
    pub csrf: String,
}

// Who authenticated this request. The middleware inserts it into the request
// extensions; handlers extract it with Extension<AuthContext> and enforce the
// permissions for the specific id they operate on (the middleware cannot — it
// would have to parse ids out of URLs, which breaks the moment a route moves).
#[derive(Clone)]
pub struct AuthContext<P> {
    // None when the API runs open (no keys configured)
    pub key_name: Option<String>,
    // The key's identity (its api_keys name), when a key was presented
    // with the request; None open, or through a browser session.
    pub key_id: Option<String>,
    pub permissions: P,
    pub method: AuthMethod,
}

// How the caller proved who they are: what the Users page shows as "you",
// and what decides which change revokes them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AuthMethod {
    // No keys configured: everyone is admin.
    Open,
    ApiKey,
    Ldap,
}

// The registry, injected as a router Extension. The middleware clones the
// Arc (a pointer copy) on every request and reads the current key list
// through it, so a reload that replaces the list is picked up without
// rebuilding the router. `new`, and Clone by hand, for the same reasons as
// `Sessions`.
pub struct ApiKeys<P>(pub Arc<ApiKeyRegistry<P>>);

impl<P> ApiKeys<P> {
    pub fn new(registry: Arc<ApiKeyRegistry<P>>) -> Self {
        Self(registry)
    }
}

impl<P> Clone for ApiKeys<P> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

// Why the middleware turned a request away. The service renders it in its own
// error shape (`{"error": ...}`), so this says only which refusal it is.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Rejection {
    // No key in either header, and no session cookie.
    MissingApiKey,
    // A key was offered and none matched.
    InvalidApiKey,
    // A session-authenticated write without its CSRF token.
    CsrfRequired,
}

impl Rejection {
    pub fn status(self) -> StatusCode {
        match self {
            Rejection::MissingApiKey | Rejection::InvalidApiKey => StatusCode::UNAUTHORIZED,
            Rejection::CsrfRequired => StatusCode::FORBIDDEN,
        }
    }
}

// The credential a request offers, from either accepted header. Shared by the
// middleware and the services' /metrics handlers, which enforce auth
// themselves (their route is always public in the router so the flag can
// reload).
pub fn presented_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
}

// The browser session behind this request, if it has one and the store is
// mounted. Returns the session's identity, never the session token.
fn session_auth<P: Permission>(cookie: &str, request: &Request) -> Option<Authenticated<P>> {
    let sessions = request.extensions().get::<Sessions<P>>()?;
    let header = request
        .headers()
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    sessions.0.get(cookie_value(header, cookie)?)
}

// Constant-time comparison per key, and no early break: the scan always
// visits every key so the response time does not reveal WHICH key matched,
// only that one did.
pub fn match_token<'k, P>(
    token: &str,
    keys: &'k [ResolvedApiKey<P>],
) -> Option<&'k ResolvedApiKey<P>> {
    let mut matched: Option<&ResolvedApiKey<P>> = None;
    for key in keys.iter() {
        // ct_eq always compares all bytes (if lengths match) — a normal ==
        // short-circuits on the first different byte and that time delta
        // leaks info to guess the secret byte-by-byte.
        if bool::from(token.as_bytes().ct_eq(key.secret.as_bytes())) {
            matched = Some(key);
        }
    }
    matched
}

// Every request through the API, authenticated: by a key in a header, by a
// browser session, or — with no keys configured at all — not at all, as admin.
//
// `cookie` is the service's session cookie name; a service mounts this through
// a short wrapper that passes it and renders a Rejection in its own error
// shape, so a 401 carries the same {"error": ...} body as every other failure.
pub async fn require_api_key<P: Permission>(
    cookie: &str,
    mut request: Request,
    next: Next,
) -> Result<Response, Rejection> {
    let keys = request
        .extensions()
        .get::<ApiKeys<P>>()
        .expect("ApiKeys extension missing")
        .0
        .load();

    // No keys configured = open API (the service warns loudly about this).
    // Everything is admin so handlers don't need a special "no auth" path.
    if keys.is_empty() {
        request.extensions_mut().insert(AuthContext {
            key_name: None,
            key_id: None,
            permissions: P::admin(),
            method: AuthMethod::Open,
        });
        let mut response = next.run(request).await;
        // The console works here too. There is no ambient credential on an
        // open instance — nothing to forge, and nothing a CSRF token would
        // protect — so the pages get an identity with an empty token and their
        // action buttons render. Without this the browsable API silently lost
        // its action buttons on exactly the setup people try it on first, with
        // nothing on the page to say why.
        response.extensions_mut().insert(BrowserIdentity {
            key_name: "open (no API keys configured)".to_string(),
            csrf: String::new(),
        });
        return Ok(response);
    }

    // A browser session, when no header was offered. Checked second on
    // purpose: a request that carries an explicit key is a machine's, and it
    // should authenticate as that key even from inside a browser that happens
    // to hold a cookie.
    if presented_token(request.headers()).is_none()
        && let Some(auth) = session_auth::<P>(cookie, &request)
    {
        // CSRF, and only here. A cookie is an AMBIENT credential: the browser
        // attaches it to any request any page can cause, so a page on the
        // internet could otherwise make your browser POST a sync — or a
        // DELETE — to this API and succeed. SameSite=Strict on the cookie
        // blocks the cross-site navigation case, but that is one attribute
        // standing between an admin session and a write, so the token is
        // required as well.
        //
        // Header-authenticated requests skip this entirely: they carry nothing
        // ambient, there is nothing to forge, and demanding a token from them
        // would break every existing consumer on the next upgrade.
        // "Safe method" by intent, not by verb. GET is exempt because a GET
        // should not change anything — but a read can: unified-api's
        // `/dataset?refresh=true` runs a connector script. A read that can SSH
        // into a datacenter is a write for this purpose, and the ambient
        // credential makes it reachable from a page that merely gets an
        // operator to click a link.
        let side_effecting_read = request
            .uri()
            .query()
            .is_some_and(|q| q.split('&').any(|p| p == "refresh=true"));

        if side_effecting_read || !matches!(*request.method(), Method::GET | Method::HEAD) {
            let presented = request
                .headers()
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .or_else(|| {
                    request
                        .extensions()
                        .get::<FormControls>()
                        .and_then(|controls| controls.csrf.clone())
                });

            let ok = presented.is_some_and(|presented| csrf_matches(&auth.csrf, &presented));

            if !ok {
                return Err(Rejection::CsrfRequired);
            }
        }

        tracing::Span::current().record("key_name", auth.key_name.as_str());
        let identity = BrowserIdentity {
            key_name: auth.key_name.clone(),
            csrf: auth.csrf,
        };
        // On the request as well: `GET /auth` hands the token to a script
        // (the UI), which has no HTML form to read it from.
        request.extensions_mut().insert(identity.clone());
        request.extensions_mut().insert(AuthContext {
            key_name: Some(auth.key_name),
            key_id: None,
            permissions: auth.permissions,
            method: match auth.kind {
                SessionKind::ApiKey => AuthMethod::ApiKey,
                SessionKind::Directory => AuthMethod::Ldap,
            },
        });
        let mut response = next.run(request).await;
        // On the RESPONSE, not the request: the HTML layer runs OUTSIDE this
        // middleware, so by the time it can look, the request is gone. This is
        // how the page knows whose session it is rendering for, and which CSRF
        // token its action forms must carry.
        response.extensions_mut().insert(identity);
        return Ok(response);
    }

    let Some(token) = presented_token(request.headers()) else {
        return Err(Rejection::MissingApiKey);
    };

    match match_token(token, &keys) {
        Some(key) => {
            // The trace layer declared this span field Empty; filling it here
            // puts the authenticated key on the request's access-log line.
            // (An open API and a public route leave it empty — absence means
            // nobody authenticated, not somebody anonymous.)
            tracing::Span::current().record("key_name", key.name.as_str());
            request.extensions_mut().insert(AuthContext {
                key_name: Some(key.name.clone()),
                key_id: Some(key.id.clone()),
                permissions: key.permissions.clone(),
                method: AuthMethod::ApiKey,
            });
            Ok(next.run(request).await)
        }
        None => Err(Rejection::InvalidApiKey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::session::SessionStore;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use std::time::Duration;
    use tower::ServiceExt;

    // A stand-in for a service's permissions: an admin, or one named scope.
    #[derive(Clone, Debug, PartialEq)]
    enum Perm {
        Admin,
        Only(&'static str),
    }

    impl Permission for Perm {
        fn admin() -> Self {
            Perm::Admin
        }
    }

    const COOKIE: &str = "test_session";

    // The handler echoes who authenticated and how, so tests can assert the
    // middleware attached the right AuthContext, not just that it let us in.
    async fn whoami(axum::Extension(auth): axum::Extension<AuthContext<Perm>>) -> String {
        format!(
            "{} {} {:?} {:?}",
            auth.key_name.unwrap_or_else(|| "open".to_string()),
            auth.key_id.unwrap_or_else(|| "-".to_string()),
            auth.method,
            auth.permissions,
        )
    }

    fn key(id: &str, name: &str, secret: &str, permissions: Perm) -> ResolvedApiKey<Perm> {
        ResolvedApiKey {
            id: id.to_string(),
            name: name.to_string(),
            secret: secret.to_string(),
            permissions,
        }
    }

    fn admin_key(name: &str, secret: &str) -> ResolvedApiKey<Perm> {
        key(name, name, secret, Perm::Admin)
    }

    // The middleware as a service mounts it: the cookie name passed in, and a
    // Rejection rendered as a response (here, its bare status).
    fn guarded(router: Router) -> Router {
        router.layer(middleware::from_fn(|request, next| async move {
            require_api_key::<Perm>(COOKIE, request, next)
                .await
                .map_err(|rejection| rejection.status().into_response())
        }))
    }

    fn app_with(keys: Vec<ResolvedApiKey<Perm>>, sessions: &Arc<SessionStore<Perm>>) -> Router {
        guarded(Router::new().route("/protected", get(whoami).post(whoami)))
            .layer(axum::Extension(ApiKeys::new(Arc::new(
                ApiKeyRegistry::new(keys),
            ))))
            .layer(axum::Extension(Sessions::new(Arc::clone(sessions))))
    }

    fn test_app(keys: Vec<ResolvedApiKey<Perm>>) -> Router {
        app_with(keys, &Arc::new(SessionStore::new()))
    }

    fn ask(header: Option<(&str, &str)>) -> HttpRequest<Body> {
        let mut req = HttpRequest::builder().uri("/protected");
        if let Some((name, value)) = header {
            req = req.header(name, value);
        }
        req.body(Body::empty()).unwrap()
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn no_keys_configured_allows_all_as_admin() {
        let resp = test_app(vec![]).oneshot(ask(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // The pages of an open instance still get an identity to render for
        let identity = resp.extensions().get::<BrowserIdentity>().unwrap();
        assert!(identity.key_name.starts_with("open"));
        assert_eq!(identity.csrf, "");
        assert_eq!(body_string(resp).await, "open - Open Admin");
    }

    #[tokio::test]
    async fn valid_bearer_token_passes() {
        let app = test_app(vec![key(
            "id-1",
            "Automation",
            "secret123",
            Perm::Only("a"),
        )]);
        let resp = app
            .oneshot(ask(Some(("authorization", "Bearer secret123"))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_string(resp).await,
            "Automation id-1 ApiKey Only(\"a\")"
        );
    }

    #[tokio::test]
    async fn valid_x_api_key_header_passes() {
        let app = test_app(vec![admin_key("default", "secret123")]);
        let resp = app
            .oneshot(ask(Some(("x-api-key", "secret123"))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_wrong_or_missing_key_is_refused() {
        let app = test_app(vec![admin_key("default", "secret123")]);
        for header in [
            Some(("authorization", "Bearer wrongtoken")),
            Some(("x-api-key", "wrongkey")),
        ] {
            let resp = app.clone().oneshot(ask(header)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        // A scheme other than Bearer is no key at all
        for header in [None, Some(("authorization", "Basic dXNlcjpwYXNz"))] {
            let resp = app.clone().oneshot(ask(header)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn each_refusal_has_its_status() {
        assert_eq!(Rejection::MissingApiKey.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Rejection::InvalidApiKey.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Rejection::CsrfRequired.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn each_key_authenticates_as_itself() {
        let app = test_app(vec![admin_key("awx", "key-a"), admin_key("forms", "key-b")]);
        let resp = app
            .oneshot(ask(Some(("x-api-key", "key-b"))))
            .await
            .unwrap();
        assert_eq!(body_string(resp).await, "forms forms ApiKey Admin");
    }

    // A reload rewrites api_keys.yaml under a running process. The middleware
    // reads the registry per request rather than holding a list, so the new
    // set is in force on the very next one — without this, rotating a key
    // would be the one configuration change that still needed a restart.
    #[tokio::test]
    async fn replacing_the_registry_changes_who_authenticates() {
        let registry = Arc::new(ApiKeyRegistry::new(vec![admin_key("before", "secret-a")]));
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        let keys = ApiKeys::new(Arc::clone(&registry));
        let app = guarded(Router::new().route("/protected", get(whoami)))
            .layer(axum::Extension(keys.clone()));

        let resp = app
            .clone()
            .oneshot(ask(Some(("x-api-key", "secret-a"))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        registry.replace(vec![admin_key("after", "secret-b")]);

        let resp = app
            .clone()
            .oneshot(ask(Some(("x-api-key", "secret-b"))))
            .await
            .unwrap();
        assert_eq!(body_string(resp).await, "after after ApiKey Admin");

        let resp = app
            .oneshot(ask(Some(("x-api-key", "secret-a"))))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the replaced key must stop working"
        );
    }

    // ------------------------------------------------------- sessions

    fn with_session(kind: SessionKind) -> (Router, crate::http::session::Issued) {
        let sessions = Arc::new(SessionStore::new());
        let issued = sessions.create(
            "ldap:jdoe".into(),
            kind,
            None,
            Perm::Only("a"),
            Duration::from_secs(60),
        );
        (app_with(vec![admin_key("k", "secret")], &sessions), issued)
    }

    fn by_cookie(method: &str, uri: &str, token: &str) -> axum::http::request::Builder {
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header("cookie", format!("theme=dark; {COOKIE}={token}"))
    }

    #[tokio::test]
    async fn a_session_cookie_authenticates_a_read() {
        let (app, issued) = with_session(SessionKind::Directory);
        let resp = app
            .oneshot(
                by_cookie("GET", "/protected", &issued.token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // The page layer learns whose session it renders, and the token its
        // forms must carry
        let identity = resp.extensions().get::<BrowserIdentity>().unwrap();
        assert_eq!(identity.key_name, "ldap:jdoe");
        assert_eq!(identity.csrf, issued.csrf);
        assert_eq!(body_string(resp).await, "ldap:jdoe - Ldap Only(\"a\")");
    }

    #[tokio::test]
    async fn a_key_session_reports_its_method() {
        let (app, issued) = with_session(SessionKind::ApiKey);
        let resp = app
            .oneshot(
                by_cookie("GET", "/protected", &issued.token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(body_string(resp).await.contains("ApiKey"));
    }

    // An unknown or expired cookie is no session: without a key the request
    // is refused as one that offered nothing.
    #[tokio::test]
    async fn an_unknown_cookie_is_no_credential() {
        let (app, _) = with_session(SessionKind::ApiKey);
        let resp = app
            .oneshot(
                by_cookie("GET", "/protected", "stale")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // A key in a header wins over a cookie the browser happens to hold.
    #[tokio::test]
    async fn a_presented_key_wins_over_a_cookie() {
        let (app, issued) = with_session(SessionKind::Directory);
        let resp = app
            .oneshot(
                by_cookie("POST", "/protected", &issued.token)
                    .header("x-api-key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_string(resp).await, "k k ApiKey Admin");
    }

    #[tokio::test]
    async fn a_session_write_needs_its_csrf_token() {
        let (app, issued) = with_session(SessionKind::Directory);

        let none = by_cookie("POST", "/protected", &issued.token)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(none).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let wrong = by_cookie("POST", "/protected", &issued.token)
            .header("x-csrf-token", "not-it")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(wrong).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let header = by_cookie("POST", "/protected", &issued.token)
            .header("x-csrf-token", issued.csrf.as_str())
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(header).await.unwrap().status(),
            StatusCode::OK
        );

        // From a form, the token arrives lifted out of the body by form_action
        let mut form = by_cookie("POST", "/protected", &issued.token)
            .body(Body::empty())
            .unwrap();
        form.extensions_mut().insert(FormControls {
            csrf: Some(issued.csrf.clone()),
        });
        assert_eq!(app.oneshot(form).await.unwrap().status(), StatusCode::OK);
    }

    // A GET that runs something is a write for CSRF purposes.
    #[tokio::test]
    async fn a_refreshing_read_needs_the_token_too() {
        let (app, issued) = with_session(SessionKind::Directory);
        let refresh = by_cookie("GET", "/protected?x=1&refresh=true", &issued.token)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(refresh).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let plain = by_cookie("GET", "/protected?refresh=false", &issued.token)
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(plain).await.unwrap().status(), StatusCode::OK);
    }
}

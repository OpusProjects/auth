// The HTTP side of signing in: who a request is, and the browser session that
// remembers it.
//
// - `auth`: API keys (resolved, in a registry a reload can replace), the
//   middleware that authenticates every request by key or by session, and the
//   AuthContext it leaves for handlers
// - `session`: the in-memory session store, its tokens and cookie, CSRF, and
//   the layer that turns a browser form into a request the API understands
//
// What a caller may touch differs between the services (sources and endpoints
// in one, applications in the other), so everything here is generic over the
// service's own permissions type through the `Permission` trait. The cookie a
// service sets carries its own name, so it is passed in rather than fixed here.

pub mod auth;
pub mod session;

pub use auth::{
    ApiKeyRegistry, ApiKeys, AuthContext, AuthMethod, BrowserIdentity, Rejection, ResolvedApiKey,
    match_token, presented_token, require_api_key,
};
pub use session::{
    Authenticated, FormControls, Issued, SessionKind, SessionStore, Sessions, cookie_value,
    csrf_matches, form_action, new_token,
};

// What a service's permissions type must offer this module: a value to clone
// into every request, and the one grant an open instance hands everybody.
//
// A trait rather than an enum here, for the same reason as `AccessRule`: what a
// restricted caller is scoped to is the service's business, and the code below
// never needs to look inside — it only stores, clones and hands it on.
// `Send + Sync + 'static` because it lives in a shared map and in request
// extensions, both of which cross threads.
pub trait Permission: Clone + Send + Sync + 'static {
    // Everything allowed: what an instance with no API keys grants every
    // caller, so handlers need no special "no auth" path.
    fn admin() -> Self;
}

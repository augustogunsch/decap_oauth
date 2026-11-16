//! External OAuth provider for Decap CMS. The following environment variables must be set for it to
//! work:
//!
//! ```shell
//! OAUTH_CLIENT_ID=(insert_the_client_id)
//! OAUTH_SECRET=(insert_the_secret)
//! OAUTH_ORIGINS=www.example.com,oauth.mysite.com
//! ```
//!
//! Additionaly, when using a host provider other than GitHub, such as Gitlab, the following
//! environment variables must be set:
//!
//! ```shell
//! OAUTH_PROVIDER=gitlab
//! OAUTH_HOSTNAME=https://gitlab.com
//! OAUTH_TOKEN_PATH=/oauth/token
//! OAUTH_AUTHORIZE_PATH=/oauth/authorize
//! OAUTH_SCOPES=api
//! ```
//!
//! When using GitHub Enterprise, please set `OAUTH_HOSTNAME` to the proper value.
//!
//! The redirect URI sent to the provider is derived from the request's `Host`
//! header and `X-Forwarded-Proto`, so running behind a TLS-terminating reverse
//! proxy works without further configuration. Set `PUBLIC_URL` (for example
//! `https://www.example.com`) to override that detection, which is required
//! when the proxy rewrites the `Host` header. `PUBLIC_URL` must be an origin:
//! a scheme and a host, with no path, query or fragment.

use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing, Router,
};
use oauth2::{
    basic::BasicClient, AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use std::collections::HashMap;
use std::env;
use std::sync::LazyLock;

const OAUTH_HOSTNAME: &str = "https://github.com";
const OAUTH_TOKEN_PATH: &str = "/login/oauth/access_token";
const OAUTH_AUTHORIZE_PATH: &str = "/login/oauth/authorize";
const OAUTH_PROVIDER: &str = "github";
const OAUTH_SCOPES: &str = "repo";

/// Shared token-exchange client. Redirects are disabled because following them
/// on a token request would allow a malicious provider to be used as an SSRF
/// proxy (see the `oauth2` crate documentation).
static HTTP_CLIENT: LazyLock<oauth2::reqwest::Client> = LazyLock::new(|| {
    oauth2::reqwest::ClientBuilder::new()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client should build")
});

fn get_var(var: &str) -> String {
    env::var(var).unwrap_or_else(|_| panic!("{} environment variable should be defined", var))
}

fn get_var_or(var: &str, default: &str) -> String {
    env::var(var).unwrap_or(default.to_string())
}

/// Provider requested by this authorization, falling back to the configured one.
fn provider_from(params: &HashMap<String, String>) -> String {
    params
        .get("provider")
        .cloned()
        .unwrap_or_else(|| get_var_or("OAUTH_PROVIDER", OAUTH_PROVIDER))
}

/// Validate an operator-provided `PUBLIC_URL`.
///
/// Only an absolute `http(s)` origin is usable: the scheme and host are kept,
/// and a trailing slash is dropped. Anything with a path, query or fragment is
/// rejected rather than silently producing a callback URL that the provider
/// will not match against the registered one.
pub fn normalize_public_url(raw: &str) -> Option<String> {
    let url = raw.trim().trim_end_matches('/');
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();

    if authority.is_empty()
        || authority.len() != rest.len()
        || authority.contains(char::is_whitespace)
    {
        return None;
    }

    Some(url.to_string())
}

/// Base URL (`scheme://host`) the browser used to reach this service.
///
/// The service normally sits behind a reverse proxy that terminates TLS and
/// forwards the request over plain HTTP, so the scheme has to come from
/// `X-Forwarded-Proto`. `PUBLIC_URL` overrides host detection entirely.
fn base_url(headers: &HeaderMap, public_url: Option<&str>) -> Option<String> {
    if let Some(url) = public_url.and_then(normalize_public_url) {
        return Some(url);
    }

    let host = headers.get("host")?.to_str().ok()?;
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }

    // Scheme tokens are case-insensitive; proxies are not guaranteed to
    // forward them lowercased.
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| value == "http" || value == "https")
        .unwrap_or_else(|| "https".to_string());

    Some(format!("{}://{}", scheme, host))
}

fn public_base_url(headers: &HeaderMap) -> Option<String> {
    let public_url = env::var("PUBLIC_URL").ok();
    base_url(headers, public_url.as_deref())
}

/// Callback URL registered with the provider.
///
/// Must be byte-for-byte what the authorization request used, and must not
/// carry extra parameters: providers compare it against the registered URL.
fn callback_url(base: &str) -> String {
    format!("{}/callback", base)
}

/// The client has an authorization and a token endpoint configured, hence the
/// typestate parameters.
type OAuthClient = BasicClient<
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

fn create_client(redirect_url: String) -> Result<OAuthClient, String> {
    let client_id = get_var("OAUTH_CLIENT_ID");
    let secret = get_var("OAUTH_SECRET");
    let hostname = get_var_or("OAUTH_HOSTNAME", OAUTH_HOSTNAME);
    let token_path = get_var_or("OAUTH_TOKEN_PATH", OAUTH_TOKEN_PATH);
    let auth_path = get_var_or("OAUTH_AUTHORIZE_PATH", OAUTH_AUTHORIZE_PATH);

    let auth_url =
        AuthUrl::new(format!("{}{}", hostname, auth_path)).map_err(|error| error.to_string())?;
    let token_url =
        TokenUrl::new(format!("{}{}", hostname, token_path)).map_err(|error| error.to_string())?;
    let redirect_url = RedirectUrl::new(redirect_url).map_err(|error| error.to_string())?;

    Ok(BasicClient::new(ClientId::new(client_id))
        .set_client_secret(ClientSecret::new(secret))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url))
}

/// The auth route.
pub async fn auth(Query(params): Query<HashMap<String, String>>, headers: HeaderMap) -> Response {
    let expected_provider = get_var_or("OAUTH_PROVIDER", OAUTH_PROVIDER);

    let provider = provider_from(&params);

    // This check is not strictly needed
    if provider != expected_provider {
        return (
            StatusCode::BAD_REQUEST,
            format!("Unexpected provider `{}`", provider),
        )
            .into_response();
    }

    let scope = match params.get("scope") {
        Some(scope) => scope.to_owned(),
        None => get_var_or("OAUTH_SCOPES", OAUTH_SCOPES),
    };

    let base = match public_base_url(&headers) {
        Some(base) => base,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Cannot determine public URL".to_string(),
            )
                .into_response()
        }
    };

    // No query string: providers compare the redirect URI against the
    // registered callback URL, and an extra parameter breaks that match.
    let redirect_url = callback_url(&base);

    let client = match create_client(redirect_url) {
        Ok(client) => client,
        Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
    };

    let (auth_url, _csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(scope))
        .url();

    Redirect::to(auth_url.as_str()).into_response()
}

/// `OAUTH_ORIGINS` as a JSON array literal for the postMessage handshake.
///
/// Entries are restricted to characters that can appear in a host or an
/// origin, so a typo in the configuration cannot inject JavaScript. Entries
/// may be a bare host (`example.com`, `localhost:8080`) or a full origin.
fn origin_allow_list(raw: &str) -> String {
    let entries: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| {
            !entry.is_empty()
                && entry.chars().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '[' | ']' | '/')
                })
        })
        .map(|entry| format!("\"{}\"", entry))
        .collect();

    format!("[{}]", entries.join(","))
}

fn login_response(provider: &str, status: &str, token: &AccessToken) -> Html<String> {
    let origins = origin_allow_list(&get_var("OAUTH_ORIGINS"));

    Html(format!(
        r#"
    <script>
      const allowedOrigins = {};
      const matchesOrigin = (origin) => {{
        try {{
          const url = new URL(origin);
          return allowedOrigins.some(
            (allowed) => allowed === origin || allowed === url.host || allowed === url.hostname
          );
        }} catch (error) {{
          return false;
        }}
      }};

      const receiveMessage = (e) => {{
        if (!matchesOrigin(e.origin)) {{
          return;
        }}

        window.opener.postMessage(
          'authorization:{}:{}:{{"token":"{}","provider":"{}"}}',
          e.origin
        );

        window.removeEventListener('message', receiveMessage, false);
      }}
      window.addEventListener('message', receiveMessage, false);

      window.opener.postMessage('authorizing:{}', '*');
    </script>
    "#,
        origins,
        provider,
        status,
        token.secret(),
        provider,
        provider,
    ))
}

/// The callback route.
pub async fn callback(
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let provider = provider_from(&params);

    let code = match params.get("code") {
        Some(code) => AuthorizationCode::new(code.to_string()),
        None => return (StatusCode::BAD_REQUEST, "Code is required".to_string()).into_response(),
    };

    let base = match public_base_url(&headers) {
        Some(base) => base,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Cannot determine public URL".to_string(),
            )
                .into_response()
        }
    };

    // Must be byte-for-byte what the authorization request used.
    let redirect_url = callback_url(&base);

    let client = match create_client(redirect_url) {
        Ok(client) => client,
        Err(message) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
    };

    match client
        .exchange_code(code)
        .request_async(&*HTTP_CLIENT)
        .await
    {
        Ok(token) => (
            StatusCode::OK,
            login_response(&provider, "success", token.access_token()),
        )
            .into_response(),
        Err(e) => {
            eprintln!("{:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

/// Return a full Axum router with both routes used by OAuth.
pub fn oauth_router() -> Router {
    Router::new()
        .route("/auth", routing::get(auth))
        .route("/callback", routing::get(callback))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(host: Option<&str>, proto: Option<&str>) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Some(host) = host {
            map.insert("host", HeaderValue::from_str(host).unwrap());
        }
        if let Some(proto) = proto {
            map.insert("x-forwarded-proto", HeaderValue::from_str(proto).unwrap());
        }
        map
    }

    #[test]
    fn public_url_takes_precedence_and_loses_trailing_slash() {
        let map = headers(Some("localhost:8080"), Some("http"));
        assert_eq!(
            base_url(&map, Some("https://example.com/")).as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn public_url_without_a_scheme_is_rejected() {
        let map = headers(Some("example.com"), None);
        assert_eq!(
            base_url(&map, Some("example.com")).as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn public_url_with_a_path_is_rejected() {
        let map = headers(Some("example.com"), None);
        assert_eq!(
            base_url(&map, Some("https://example.com/sub")).as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            base_url(&map, Some("https://example.com?x=1")).as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn public_url_of_the_wrong_scheme_is_rejected() {
        assert_eq!(normalize_public_url("ftp://example.com"), None);
        assert_eq!(normalize_public_url(""), None);
        assert_eq!(normalize_public_url("   "), None);
    }

    #[test]
    fn empty_public_url_is_ignored() {
        let map = headers(Some("example.com"), None);
        assert_eq!(
            base_url(&map, Some("  ")).as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn forwarded_proto_is_honoured() {
        let map = headers(Some("localhost:8080"), Some("http"));
        assert_eq!(
            base_url(&map, None).as_deref(),
            Some("http://localhost:8080")
        );
    }

    #[test]
    fn forwarded_proto_is_case_insensitive() {
        let map = headers(Some("localhost:8080"), Some("HTTP"));
        assert_eq!(
            base_url(&map, None).as_deref(),
            Some("http://localhost:8080")
        );
    }

    #[test]
    fn scheme_defaults_to_https() {
        let map = headers(Some("example.com"), None);
        assert_eq!(base_url(&map, None).as_deref(), Some("https://example.com"));
    }

    #[test]
    fn unexpected_scheme_falls_back_to_https() {
        let map = headers(Some("example.com"), Some("gopher"));
        assert_eq!(base_url(&map, None).as_deref(), Some("https://example.com"));
    }

    #[test]
    fn first_value_of_a_forwarded_chain_is_used() {
        let map = headers(Some("example.com"), Some("https, http"));
        assert_eq!(base_url(&map, None).as_deref(), Some("https://example.com"));
    }

    #[test]
    fn missing_host_has_no_base_url() {
        assert_eq!(base_url(&headers(None, None), None), None);
    }

    #[test]
    fn unusable_host_has_no_base_url() {
        assert_eq!(base_url(&headers(Some("a b"), None), None), None);
        assert_eq!(base_url(&headers(Some(""), None), None), None);
    }

    #[test]
    fn callback_url_carries_no_query_string() {
        assert_eq!(
            callback_url("https://example.com"),
            "https://example.com/callback"
        );
        assert!(!callback_url("https://example.com").contains('?'));
    }

    #[test]
    fn origin_allow_list_is_a_json_array() {
        assert_eq!(
            origin_allow_list("localhost:8080, dev.example.com"),
            r#"["localhost:8080","dev.example.com"]"#
        );
        assert_eq!(origin_allow_list(""), "[]");
        assert_eq!(origin_allow_list(" , ,"), "[]");
    }

    #[test]
    fn origin_allow_list_drops_entries_that_could_inject_script() {
        assert_eq!(
            origin_allow_list(r#"example.com'); alert(1);//, good.example"#),
            r#"["good.example"]"#
        );
        assert_eq!(
            origin_allow_list(r#"https://example.com"#),
            r#"["https://example.com"]"#
        );
    }
}

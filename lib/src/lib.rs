//! Decap CMS OAuth provider for GitHub.
//! The following environment variables must be set for it to work properly:
//! `CLIENT_ID`  and `SECRET`. For instructions on how to set up an OAuth app and get these values, refer to
//! [GitHub's documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app).
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing, Router,
};
use oauth2::{
    basic::BasicClient, reqwest::http_client, AccessToken, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use std::collections::HashMap;
use std::env;

const TOKEN_HOST: &str = "https://github.com";
const TOKEN_PATH: &str = "/login/oauth/access_token";
const AUTH_PATH: &str = "/login/oauth/authorize";

fn create_client() -> BasicClient {
    let client_id = env::var("CLIENT_ID").expect("CLIENT_ID env variable should be defined");
    let secret = env::var("SECRET").expect("SECRET env variable should be defined");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(secret)),
        AuthUrl::new(format!("{}{}", TOKEN_HOST, AUTH_PATH))
            .expect("Auth URL should be a valid URL"),
        Some(
            TokenUrl::new(format!("{}{}", TOKEN_HOST, TOKEN_PATH))
                .expect("Token URL should be a valid URL"),
        ),
    )
}

/// The auth route.
pub async fn auth(Query(params): Query<HashMap<String, String>>, headers: HeaderMap) -> Response {
    let provider = match params.get("provider") {
        Some(provider) => provider,
        None => {
            return (StatusCode::BAD_REQUEST, "No provider specified".to_string()).into_response()
        }
    };

    if provider != "github" {
        return (
            StatusCode::BAD_REQUEST,
            format!("Invalid provider {:?}", provider),
        )
            .into_response();
    }

    let scope = match params.get("scope") {
        Some(scope) => scope.to_owned(),
        None => "repo".to_string(),
    };

    let host = match headers.get("host") {
        Some(host) => host.to_str().unwrap(),
        None => return (StatusCode::BAD_REQUEST, "No host header".to_string()).into_response(),
    };

    let redirect_url = format!("https://{}/callback?provider={}", host, provider);

    let client = create_client()
        .set_redirect_uri(RedirectUrl::new(redirect_url).expect("Invalid redirect URL"));

    let (auth_url, _csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(scope))
        .url();

    Redirect::to(&auth_url.to_string()).into_response()
}

fn login_response(provider: &str, status: &str, token: &AccessToken) -> Html<String> {
    Html(format!(
        r#"
    <script>
      const receiveMessage = (message) => {{
        window.opener.postMessage(
          'authorization:{}:{}:{{"token":"{}","provider":"{}"}}',
          message.origin
        );

        window.removeEventListener("message", receiveMessage, false);
      }}
      window.addEventListener("message", receiveMessage, false);

      window.opener.postMessage("authorizing:{}", "*");
    </script>
    "#,
        provider,
        status,
        token.secret(),
        provider,
        provider,
    ))
}

/// The callback route.
pub async fn callback(Query(params): Query<HashMap<String, String>>) -> Response {
    let provider = match params.get("provider") {
        Some(provider) => provider,
        None => {
            return (StatusCode::BAD_REQUEST, "No provider specified".to_string()).into_response()
        }
    };

    if provider != "github" {
        return (
            StatusCode::BAD_REQUEST,
            format!("Invalid provider {:?}", provider),
        )
            .into_response();
    }

    let code = match params.get("code") {
        Some(code) => AuthorizationCode::new(code.to_string()),
        None => return (StatusCode::BAD_REQUEST, "Code is required".to_string()).into_response(),
    };

    let client = create_client();

    match client.exchange_code(code).request(http_client) {
        Ok(token) => (
            StatusCode::OK,
            login_response(provider, "success", token.access_token()),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Return a full Axum router with both routes used by OAuth.
pub fn oauth_router() -> Router {
    Router::new()
        .route("/auth", routing::get(auth))
        .route("/callback", routing::get(callback))
}

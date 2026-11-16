# decap_oauth

OAuth provider glue for [Decap CMS](https://decapcms.org/) (formerly Netlify CMS).

Decap's admin panel opens a popup, asks this service for an authorization URL,
and posts the resulting access token back to the admin window. GitHub is the
default provider; GitLab and GitHub Enterprise work with the variables below.

## Configuration

Required:

| Variable | Meaning |
|---|---|
| `OAUTH_CLIENT_ID` | Client ID of the OAuth app (or GitHub App) |
| `OAUTH_SECRET` | Client secret |
| `OAUTH_ORIGINS` | Comma-separated allow-list of origins the token may be posted to. Bare hosts are allowed: `dev.example.com,localhost:8080` |

Optional:

| Variable | Default | Meaning |
|---|---|---|
| `OAUTH_PROVIDER` | `github` | Provider used when the request does not name one |
| `OAUTH_HOSTNAME` | `https://github.com` | Provider base URL (GitHub Enterprise, GitLab) |
| `OAUTH_AUTHORIZE_PATH` | `/login/oauth/authorize` | |
| `OAUTH_TOKEN_PATH` | `/login/oauth/access_token` | |
| `OAUTH_SCOPES` | `repo` | Scopes requested from the provider |
| `PUBLIC_URL` | derived | Public origin of this service, e.g. `https://oauth.example.com` |

The listening port is set with `--port` (default `3005`).

## Redirect URI

The redirect URI sent to the provider is `{origin}/callback`, with no query
string — providers compare it against the registered callback URL, so anything
extra breaks login.

The origin comes from `PUBLIC_URL` when set. Otherwise it is derived per
request from the `Host` header plus `X-Forwarded-Proto`, which means running
behind a TLS-terminating proxy needs no extra configuration. Set `PUBLIC_URL`
when the proxy rewrites `Host`, and always register exactly
`{PUBLIC_URL}/callback` on the provider.

`PUBLIC_URL` is validated at startup: it must be an absolute `http(s)` origin
without a path, query or fragment.

For a local setup over plain HTTP, either send `X-Forwarded-Proto: http` from
the proxy or set `PUBLIC_URL=http://localhost:3005`.

## Running locally

```sh
OAUTH_CLIENT_ID=... \
OAUTH_SECRET=... \
OAUTH_ORIGINS=localhost:3005 \
cargo run -- --port 3005
```

Then `http://localhost:3005/auth` redirects to the provider. Decap should be
configured with `base_url` / `auth_endpoint` pointing at this service, and the
provider app must have `http://localhost:3005/callback` registered.

## Docker

Images are published to `ghcr.io/somniumensemble/decap_oauth` on every `v*` tag
by `.github/workflows/release.yml`, after `cargo fmt`, `clippy -D warnings`,
`cargo test` and a container smoke test pass.

```sh
just docker-build   # local build
just docker-push    # push the tag from the Justfile
```

The container listens on `0.0.0.0:3005` as an unprivileged user and needs only
`OAUTH_CLIENT_ID`, `OAUTH_SECRET` and `OAUTH_ORIGINS`.

## Provider notes

- **OAuth App**: `repo` scope. Token expiry is off by default.
- **GitHub App**: needs Contents read/write and Metadata read (plus Pull
  requests for editorial workflow) as *permissions*, not scopes. User access
  tokens expire after 8h by default; this service does not refresh them, so
  uncheck "Expire user access tokens" or editors will be logged out mid-session.

## Known limitations

- The `state` parameter is generated but not verified on callback, so there is
  no CSRF protection for the authorization response.
- Refresh tokens are not used; an expired access token means logging in again.

## License

MIT, see [LICENSE](LICENSE).

# `dev.mcpg.credential.oauth-token-exchange`

OAuth 2.0 **token-exchange** credential-issuer plugin (RFC 8693).
Exchanges the *caller's* subject token for a downstream access token so the
gateway can act **on-behalf-of the end user** (impersonation), rather than
authenticating as itself (that's the `oauth-client-credentials` issuer).

Callers reference an exchanged token via the standard URI:

```
cred://dev.mcpg.credential.oauth-token-exchange/<provider>
```

## How the subject token reaches the plugin

`CredentialIssuer::issue(identity, target, _config)` reads the caller's raw
subject token from `identity.attributes["subject_token"]`. Its type is the
provider's `subject_token_type` (default `access_token`), unless
`identity.attributes["subject_token_type"]` overrides it. Federation's
`oauth_impersonation` auth mode populates the token from the inbound caller
bearer; any other caller may do the same. The subject token is used
transiently and never logged.

If `subject_token` is absent the plugin returns a `Misconfigured` error rather
than exchanging an empty token. A caller whose bearer the gateway process
minted is refused before any request: `auth_provider: ema` (the embedded
authorization server's access tokens), `auth_provider: inspector_supervisor`
(the supervised inspector's credential), and any caller with
`attributes["token_issuer"]`, which the embedded authorization server sets on
its callers also when a `principal_issuer` changes their `auth_provider`. No
external STS can validate these bearers.

The exception is `attributes["subject_token_source"] = "idp_vault"`: the
subject token is then the caller's enterprise IdP sign-in the gateway keeps
(a federation with `upstream.auth.subject_token: idp_refresh_token` or
`idp_id_token`), not the gateway's bearer, and any caller may present it. It
goes only to the token endpoint that issued it, by the client it was issued
to: the call is refused with `Misconfigured` before any request unless
`attributes["subject_token_endpoint"]` equals `token_url`,
`attributes["subject_token_client_id"]` equals `client_id`, and, when
`sts_issuer` is set, `attributes["subject_token_issuer"]` equals it. Only the
gateway's federation engine sets these attributes: it drops every
`subject_token*` attribute the caller carries, and no claim mapping can
produce one.

`subject_token_type` and `actor_token_type` take a short name or the RFC 8693
URN: `access_token`, `id_token`, `refresh_token`, `saml2` or `jwt`
(`urn:ietf:params:oauth:token-type:<name>`). Any other value refuses to load,
and the per-request override is validated the same way.

## No in-plugin cache

Exchanged tokens are **per-caller** — each subject token yields a distinct
exchange — so caching is left to the **host credential cache**, which is keyed
per `(identity_hash, plugin_id, target)`. A provider-keyed in-plugin cache
would serve one caller's token to another, so it is deliberately omitted; the
host cache deduplicates per caller using the reported `ttl_seconds`.

## Operator config

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-token-exchange
    class: credential_issuer
    config:
      providers:
        notion:
          token_url: https://sts.example.com/oauth/token   # the STS endpoint
          client_id: mcpg-gateway
          client_secret: "${secret.STS_CLIENT_SECRET}"     # optional
          client_auth: client_secret_basic                # optional; see below
          audience: https://notion-mcp.example.com          # optional
          # subject_token_type / requested_token_type default to
          # urn:ietf:params:oauth:token-type:access_token
```

Used by a federation:

```yaml
mcp:
  federations:
    - name: notion
      upstream:
        url: https://notion-mcp.example.com/mcp
        auth:
          mode: oauth_impersonation
          credential: cred://dev.mcpg.credential.oauth-token-exchange/notion
```

At **dispatch** the caller's bearer is exchanged and forwarded to the upstream;
at **import / listen** (no caller) the upstream is listed anonymously, like
`pass_through`.

## Client authentication

| `client_auth` | Sends | Requires |
|---|---|---|
| unset | `client_id`, and `client_secret` when set, in the form body | nothing extra |
| `client_secret_post` | `client_id` and `client_secret` in the form body | both |
| `client_secret_basic` | `Authorization: Basic`, id and secret form-encoded first (RFC 6749 §2.3.1) | both |
| `private_key_jwt` | `client_id`, `client_assertion_type` and a signed `client_assertion` (RFC 7523 §2.2) | `client_id`, `private_key`; no `client_secret` |

For `private_key_jwt`, `private_key` is a PKCS#8 PEM (PKCS#1 also works for
RSA) sourced with `${secret.NAME}` or `${env.X}`; `signing_alg` is `RS256`,
`RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384` or `EdDSA`, and
unset it is the one the key type implies (RSA: `RS256`, P-256: `ES256`,
P-384: `ES384`, Ed25519: `EdDSA`); `key_id` sets the `kid` header;
`assertion_audience` is `token_endpoint` (default) or `issuer`, which needs
`sts_issuer`. Each assertion is freshly signed with `iss` = `sub` = the client
id, a new `jti`, and a two-minute lifetime. A `signing_alg` the key cannot sign
with, or a key of another type, refuses to load.

## Egress policy

`token_url` must be `https` and must not target a private, loopback or
link-local address. It is checked at load and before every exchange, and name
resolution for every connection drops private addresses. Redirects are never
followed: an STS that answers 3xx fails with `Misconfigured` ("configure the
final URL"). `allow_insecure_http: true` permits `http://` (local
development); `allow_private_network: true` permits private destinations.

An egress proxy from `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` works without
either opt-in, also on a private address: its host resolves unfiltered. Through
a proxy the proxy resolves `token_url`, so the name-resolution guard does not
apply to it; the URL check still refuses private IP literals and
`localhost` names. Enforce destination policy at the proxy.

## Migration (breaking)

The egress policy above is new. Configurations that loaded before can now fail:

- An `http://` `token_url` refuses to load. Set `allow_insecure_http: true`
  (local development only) or move the STS to `https`.
- A `token_url` whose host resolves only to private addresses loads, but every
  exchange fails with `Misconfigured` naming `allow_private_network`. This is
  the usual in-cluster STS (for example Keycloak at `*.svc.cluster.local`):
  set `allow_private_network: true` for that provider.
- A `token_url` that redirects fails instead of being followed. Configure the
  final URL.
- A caller authenticated by a gateway-minted token (`ema`,
  `inspector_supervisor`, or a `token_issuer` attribute) is refused, unless
  the subject token is its stored IdP sign-in (`subject_token_source =
  idp_vault`) bound to this provider's `token_url` and `client_id`.

## Actor token

`actor_token` with `actor_token_type` adds an RFC 8693 actor to the exchange.
They are set together or not at all.

## Fleet template (`target_template`)

For a fleet of servers behind one STS (e.g. an auto-federated MCP
registry), a `target_template` derives a provider for any allowlisted
target instead of one `providers` entry per server. `{target}` expands to
the requested target name and `{target_slug}` to a hostname-safe form of it
(`com.acme/crm` becomes `com-acme-crm`):

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-token-exchange
    config:
      target_template:
        allowed_targets: ["com.acme/*"]     # exact or trailing-* globs; required
        token_url: https://sts.acme.example/oauth/token
        client_id: mcpg-fleet
        client_secret: "${secret.STS_SECRET}"
        audience_template: "https://{target_slug}.mcp.acme.example"       # optional
        resource_template: "https://{target_slug}.mcp.acme.example/mcp"   # optional
```

An exact `providers` entry always wins over the template; targets outside
`allowed_targets` fail closed. The engine's per-call issuer config may
override `audience` and `resource` for a single exchange (the STS
endpoint itself is never overridable per call).

## Security notes

- The exchanged token is *user-scoped* — audit the STS-side scope/audience and
  the caller-trust requirements before enabling impersonation against an
  upstream.
- Neither the subject token, the exchanged token, the client secret, nor the
  private key is logged, and STS response bodies are never echoed into error
  reasons.

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```

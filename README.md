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
subject token from `identity.attributes["subject_token"]` (and an optional
`identity.attributes["subject_token_type"]`, otherwise the provider default).
Federation's `oauth_impersonation` auth mode populates these from the inbound
caller bearer; any other caller may do the same. The subject token is used
transiently and never logged.

If `subject_token` is absent the plugin returns a `Misconfigured` error rather
than exchanging an empty token.

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
          client_secret: "${env.STS_CLIENT_SECRET}"        # optional
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

## Fleet template (`target_template`)

For a fleet of servers behind one STS (e.g. an auto-federated MCP
registry), a `target_template` derives a provider for any allowlisted
target instead of one `providers` entry per server — `{target}` expands
to the requested target name:

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-token-exchange
    config:
      target_template:
        allowed_targets: ["com.acme/*"]     # exact or trailing-* globs; required
        token_url: https://sts.acme.example/oauth/token
        client_id: mcpg-fleet
        client_secret: "${env.STS_SECRET}"
        audience_template: "https://{target}.mcp.acme.internal"       # optional
        resource_template: "https://{target}.mcp.acme.internal/mcp"   # optional
```

An exact `providers` entry always wins over the template; targets outside
`allowed_targets` fail closed. The engine's per-call issuer config may
override `audience` and `resource` for a single exchange (the STS
endpoint itself is never overridable per call).

## Security notes

- The exchanged token is *user-scoped* — audit the STS-side scope/audience and
  the caller-trust requirements before enabling impersonation against an
  upstream.
- Neither the subject token nor the exchanged token is logged.

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```

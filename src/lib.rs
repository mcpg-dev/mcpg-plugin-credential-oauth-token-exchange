//! `dev.mcpg.credential.oauth-token-exchange` — outbound OAuth 2.0
//! token-exchange credential_issuer plugin (RFC 8693).
//!
//! Exchanges the *caller's* subject token for a downstream access token
//! so a gateway can act on-behalf-of the end user (impersonation).
//! Operators declare named STS providers; callers reference an exchanged
//! token via `cred://<plugin_id>/<provider>`.
//!
//! ## Subject token
//!
//! The subject token to exchange is read from the resolved identity's
//! `attributes["subject_token"]` (and `subject_token_type`, falling back
//! to the provider default). Federation's `oauth_impersonation` mode
//! populates these from the inbound caller bearer. The subject token is
//! used transiently and never logged.
//!
//! ## No in-plugin cache
//!
//! Unlike the `client_credentials` issuer, exchanged tokens are
//! per-caller — caching belongs in the host credential cache, keyed per
//! `(identity_hash, plugin_id, target)`. A provider-keyed in-plugin cache
//! would serve one caller's token to another, so it is deliberately
//! omitted; every `issue` performs a fresh exchange and the host cache
//! deduplicates per caller.

mod config;

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::Value;
use tokio::runtime::Runtime;

pub use config::{ConfigError, ProviderConfig, TokenExchangeConfig, TokenExchangeTargetTemplate};

const PLUGIN_ID: &str = "dev.mcpg.credential.oauth-token-exchange";

/// RFC 8693 §2.1 grant type.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Identity-attribute key carrying the caller's raw subject token to
/// exchange. Populated by federation `oauth_impersonation` (and any other
/// caller); never logged.
const SUBJECT_TOKEN_ATTR: &str = "subject_token";
/// Optional per-request override of the subject token's type.
const SUBJECT_TOKEN_TYPE_ATTR: &str = "subject_token_type";

#[derive(serde::Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
    #[serde(default = "default_token_type")]
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    issued_token_type: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_owned()
}

pub struct OAuthTokenExchangePlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: TokenExchangeConfig,
    http_client: reqwest::Client,
    /// Tokio runtime for the SyncCredentialIssuer FFI path; lazily built
    /// on first sync call (see the client_credentials issuer for rationale).
    sync_runtime: OnceLock<Runtime>,
}

impl OAuthTokenExchangePlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = TokenExchangeConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "oauth-token-exchange: config parse failed; refusing to register"
            );
            panic!(
                "oauth-token-exchange config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: TokenExchangeConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .build()
            .expect("oauth-token-exchange: failed to build HTTP client");
        tracing::info!(
            plugin_id = PLUGIN_ID,
            provider_count = cfg.providers.len(),
            "oauth-token-exchange: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "OAuth 2.0 Token Exchange Issuer".into(),
                    plugin_class: PluginClass::CredentialIssuer,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                http_client,
                sync_runtime: OnceLock::new(),
            }),
        }
    }
}

/// Per-call issuer config (the engine's 4th `issue` argument). Lets the
/// caller — e.g. registry-sync OAuth discovery — override the token's
/// destination without minting a provider entry per server. The STS
/// endpoint itself is NOT overridable: it is the operator's trust anchor.
#[derive(Debug, Default, serde::Deserialize)]
struct CallOverrides {
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    resource: Option<String>,
}

impl CallOverrides {
    fn parse(config: &Value) -> Result<Self, CredentialError> {
        if config.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value(config.clone()).map_err(|e| CredentialError::Misconfigured {
            reason: format!("invalid per-call issuer config: {e}"),
        })
    }

    fn apply(self, mut provider: ProviderConfig) -> ProviderConfig {
        if let Some(audience) = self.audience.filter(|a| !a.is_empty()) {
            provider.audience = Some(audience);
        }
        if let Some(resource) = self.resource.filter(|r| !r.is_empty()) {
            provider.resource = Some(resource);
        }
        provider
    }
}

async fn issue_inner(
    inner: &Inner,
    identity: &PluginIdentity,
    provider_name: &str,
    call_config: &Value,
) -> Result<IssuedCredential, CredentialError> {
    // Token exchange is on-behalf-of impersonation: it mints a
    // downstream token from the *caller's* subject token. Honour it only
    // for a cryptographically Verified caller. Today the transport drops
    // `attributes` for non-Verified identities (so `subject_token` would
    // be absent), but that is an upstream coincidence — a custom identity
    // plugin emitting non-verified trust with populated attributes must
    // not be able to drive impersonation. Gate explicitly here.
    if !mcpg_plugin_protocol::catalog::trust_level_meets(
        identity.trust_level.as_str(),
        mcpg_plugin_protocol::catalog::TRUST_LEVEL_VERIFIED,
    ) {
        return Err(CredentialError::NotAuthorized {
            reason: format!(
                "token exchange for `{provider_name}` requires a Verified caller; \
                 trust is `{}`",
                identity.trust_level
            ),
        });
    }

    // Exact provider entry wins; otherwise derive one from the fleet
    // template when the target is allowlisted. Fail closed on anything else.
    let provider = match inner.config.providers.get(provider_name) {
        Some(p) => p.clone(),
        None => inner
            .config
            .target_template
            .as_ref()
            .and_then(|t| t.expand(provider_name))
            .ok_or_else(|| CredentialError::Misconfigured {
                reason: format!(
                    "unknown provider `{provider_name}` (no exact entry; target_template \
                     absent or target not in allowed_targets)"
                ),
            })?,
    };
    let provider = CallOverrides::parse(call_config)?.apply(provider);

    let subject_token = identity
        .attributes
        .get(SUBJECT_TOKEN_ATTR)
        .map(String::as_str)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| CredentialError::Misconfigured {
            reason: format!(
                "token exchange for `{provider_name}` requires the caller's subject token in \
                 identity.attributes[\"{SUBJECT_TOKEN_ATTR}\"]"
            ),
        })?;
    let subject_token_type = identity
        .attributes
        .get(SUBJECT_TOKEN_TYPE_ATTR)
        .map(String::as_str)
        .unwrap_or(provider.subject_token_type.as_str());

    exchange(
        inner,
        provider_name,
        &provider,
        subject_token,
        subject_token_type,
    )
    .await
}

async fn exchange(
    inner: &Inner,
    provider_name: &str,
    provider: &ProviderConfig,
    subject_token: &str,
    subject_token_type: &str,
) -> Result<IssuedCredential, CredentialError> {
    let timeout = Duration::from_millis(provider.timeout_ms);
    let scope_joined = provider.scopes.join(" ");
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", GRANT_TYPE),
        ("subject_token", subject_token),
        ("subject_token_type", subject_token_type),
        (
            "requested_token_type",
            provider.requested_token_type.as_str(),
        ),
        ("client_id", provider.client_id.as_str()),
    ];
    if let Some(secret) = provider.client_secret.as_deref().filter(|s| !s.is_empty()) {
        form.push(("client_secret", secret));
    }
    if !provider.scopes.is_empty() {
        form.push(("scope", scope_joined.as_str()));
    }
    if let Some(aud) = provider.audience.as_deref() {
        form.push(("audience", aud));
    }
    if let Some(res) = provider.resource.as_deref() {
        form.push(("resource", res));
    }

    let started = Instant::now();
    let response = inner
        .http_client
        .post(&provider.token_url)
        .timeout(timeout)
        .form(&form)
        .send()
        .await
        .map_err(|e| CredentialError::Backend {
            reason: format!("token-exchange endpoint unreachable for `{provider_name}`: {e}"),
        })?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    metrics::histogram!(
        "mcpg_oauth_token_exchange_latency_ms",
        "provider" => provider_name.to_owned(),
    )
    .record(elapsed_ms as f64);

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".to_owned());
        // SECURITY: never embed the raw token-endpoint response body in the
        // error reason. It is upstream-internal detail that propagates into
        // logs / audit (and, before the federation-error opacity fix, toward
        // callers), and a misbehaving STS could echo the caller's subject
        // token or other secrets into it. Surface only the standard
        // RFC 6749 §5.2 `error` code (a fixed, non-sensitive enum) when the
        // body parses as an OAuth error response; otherwise just status +
        // provider. Drop `error_description` / raw body entirely.
        let oauth_error = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            });
        let reason = match oauth_error.as_deref() {
            Some(code) => format!(
                "token-exchange endpoint returned HTTP {status} for `{provider_name}` (error: {code})"
            ),
            None => {
                format!("token-exchange endpoint returned HTTP {status} for `{provider_name}`")
            }
        };
        metrics::counter!(
            "mcpg_oauth_token_exchange_error_total",
            "provider" => provider_name.to_owned(),
        )
        .increment(1);
        return Err(match status.as_u16() {
            429 => CredentialError::Throttled { reason },
            // 4xx is a config / subject-token problem — not retryable.
            400..=499 => CredentialError::Misconfigured { reason },
            // 5xx is STS-side; surface as a transient backend outage.
            _ => CredentialError::Backend { reason },
        });
    }

    let token_resp: TokenExchangeResponse =
        response
            .json()
            .await
            .map_err(|e| CredentialError::Backend {
                reason: format!(
                    "failed to parse token-exchange response for `{provider_name}`: {e}"
                ),
            })?;
    metrics::counter!(
        "mcpg_oauth_token_exchange_total",
        "provider" => provider_name.to_owned(),
    )
    .increment(1);

    // ttl from the STS; the host credential cache enforces
    // min(ttl, max_cache_ttl). Default one hour when absent.
    let ttl_seconds = token_resp.expires_in.unwrap_or(3600);
    let mut parts = BTreeMap::new();
    parts.insert("access_token".to_owned(), token_resp.access_token.clone());
    parts.insert("token_type".to_owned(), token_resp.token_type.clone());
    let mut metadata = BTreeMap::new();
    metadata.insert("oauth.token_type".to_owned(), token_resp.token_type.clone());
    if let Some(itt) = token_resp.issued_token_type {
        metadata.insert("oauth.issued_token_type".to_owned(), itt);
    }
    Ok(IssuedCredential {
        value: Some(token_resp.access_token),
        parts,
        ttl_seconds,
        lease_id: None,
        issued_at: now_rfc3339(),
        metadata,
    })
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[async_trait]
impl CredentialIssuer for OAuthTokenExchangePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_inner(&self.inner, identity, target, config).await
    }

    // Exchanged tokens carry the STS's own expiry; no per-token lease to
    // revoke. No-op revoke.
}

impl SyncCredentialIssuer for OAuthTokenExchangePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        let runtime = self.inner.sync_runtime.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("oauth-token-exchange: failed to build tokio runtime")
        });
        let inner = Arc::clone(&self.inner);
        let identity = identity.clone();
        let target = target.to_owned();
        let config = config.clone();
        runtime.block_on(async move { issue_inner(&inner, &identity, &target, &config).await })
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: OAuthTokenExchangePlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> OAuthTokenExchangePlugin {
                OAuthTokenExchangePlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Identity carrying a subject token in `attributes` — what federation
    /// `oauth_impersonation` builds from the inbound caller bearer.
    fn identity_with_subject(token: &str) -> PluginIdentity {
        let mut attributes = BTreeMap::new();
        if !token.is_empty() {
            attributes.insert(SUBJECT_TOKEN_ATTR.to_owned(), token.to_owned());
        }
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some("alice".into()),
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes,
        }
    }

    fn build_with_token_url(url: &str) -> OAuthTokenExchangePlugin {
        let cfg = json!({
            "providers": {
                "notion": {
                    "token_url": url,
                    "client_id": "mcpg",
                    "client_secret": "csecret",
                    "audience": "https://notion-mcp.example.com",
                    "scopes": ["read"]
                }
            }
        });
        OAuthTokenExchangePlugin::from_config_json(&cfg.to_string())
    }

    #[test]
    fn from_config_json_succeeds() {
        let plugin = build_with_token_url("https://example.com/token");
        assert_eq!(plugin.inner.manifest.id, PLUGIN_ID);
        assert_eq!(plugin.inner.config.providers.len(), 1);
    }

    #[test]
    #[should_panic(expected = "oauth-token-exchange config parse failed")]
    fn malformed_config_panics_at_construction() {
        OAuthTokenExchangePlugin::from_config_json("{ not json");
    }

    #[tokio::test]
    async fn exchanges_caller_subject_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            ))
            .and(body_string_contains("subject_token=caller-bearer-xyz"))
            .and(body_string_contains("client_id=mcpg"))
            .and(body_string_contains("audience="))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "exchanged-tok",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "notion",
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(cred.value.as_deref(), Some("exchanged-tok"));
        assert_eq!(cred.ttl_seconds, 600);
        assert_eq!(
            cred.metadata
                .get("oauth.issued_token_type")
                .map(String::as_str),
            Some("urn:ietf:params:oauth:token-type:access_token")
        );
    }

    #[tokio::test]
    async fn missing_subject_token_is_misconfigured() {
        // No live endpoint needed — the check happens before any HTTP.
        let plugin = build_with_token_url("https://example.com/token");
        let err =
            CredentialIssuer::issue(&plugin, &identity_with_subject(""), "notion", &json!({}))
                .await
                .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("subject_token"), "got: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_verified_identity_is_not_authorized() {
        // L-44: on-behalf-of token exchange requires a Verified caller.
        // A non-verified identity with a populated subject token must be
        // refused before any STS call — the check precedes HTTP.
        let plugin = build_with_token_url("https://example.com/token");
        let mut identity = identity_with_subject("caller-bearer-xyz");
        identity.trust_level = "header_asserted".into();
        identity.kind = "header_asserted".into();
        let err = CredentialIssuer::issue(&plugin, &identity, "notion", &json!({}))
            .await
            .unwrap_err();
        match err {
            CredentialError::NotAuthorized { reason } => {
                assert!(reason.contains("Verified"), "got: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_provider_is_misconfigured() {
        let plugin = build_with_token_url("https://example.com/token");
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("tok"),
            "missing",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CredentialError::Misconfigured { .. }));
    }

    #[tokio::test]
    async fn sts_4xx_surfaces_as_misconfigured() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_request",
                "error_description": "subject_token LEAKED_SECRET_abc123 rejected"
            })))
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let err =
            CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "notion", &json!({}))
                .await
                .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("400"), "status preserved: {reason}");
                // Standard RFC 6749 error code is surfaced (actionable).
                assert!(
                    reason.contains("invalid_request"),
                    "OAuth error code should be surfaced: {reason}"
                );
                // SECURITY: the raw STS response body / error_description must
                // NOT leak into the error reason (it could echo the subject
                // token or other secrets).
                assert!(
                    !reason.contains("LEAKED_SECRET_abc123"),
                    "STS error body leaked into the reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn subject_token_type_override_from_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(
                "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok",
                "expires_in": 300
            })))
            .expect(1)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let mut identity = identity_with_subject("caller-bearer");
        identity.attributes.insert(
            SUBJECT_TOKEN_TYPE_ATTR.to_owned(),
            "urn:ietf:params:oauth:token-type:jwt".to_owned(),
        );
        let cred = CredentialIssuer::issue(&plugin, &identity, "notion", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("tok"));
    }

    /// Build a plugin with NO exact providers — only a target template
    /// whose audience/resource expand `{target}`.
    fn build_template_with_token_url(url: &str) -> OAuthTokenExchangePlugin {
        let cfg = json!({
            "target_template": {
                "allowed_targets": ["srv-*"],
                "token_url": url,
                "client_id": "mcpg-fleet",
                "audience_template": "https://{target}.mcp.example.com",
                "resource_template": "https://{target}.mcp.example.com/mcp"
            }
        });
        OAuthTokenExchangePlugin::from_config_json(&cfg.to_string())
    }

    #[tokio::test]
    async fn template_expands_target_through_exchange() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(
                "audience=https%3A%2F%2Fsrv-crm.mcp.example.com",
            ))
            .and(body_string_contains(
                "resource=https%3A%2F%2Fsrv-crm.mcp.example.com%2Fmcp",
            ))
            .and(body_string_contains("client_id=mcpg-fleet"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "exchanged-tok",
                "expires_in": 600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let plugin = build_template_with_token_url(&format!("{}/token", server.uri()));
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "srv-crm",
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(cred.value.as_deref(), Some("exchanged-tok"));
        assert_eq!(cred.ttl_seconds, 600);
    }

    #[tokio::test]
    async fn template_target_outside_allowlist_is_misconfigured() {
        // Must fail closed before any HTTP: the target is not allowlisted.
        let plugin = build_template_with_token_url("https://example.com/token");
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("tok"),
            "other-app",
            &json!({}),
        )
        .await
        .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("other-app"), "got: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn call_config_overrides_take_precedence() {
        let server = MockServer::start().await;
        // Must carry the OVERRIDDEN audience/resource, not the provider's.
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(
                "audience=https%3A%2F%2Fdiscovered.example.com",
            ))
            .and(body_string_contains(
                "resource=https%3A%2F%2Fdiscovered.example.com%2Fmcp",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "exchanged-tok",
                "expires_in": 300
            })))
            .expect(1)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let call_config = json!({
            "audience": "https://discovered.example.com",
            "resource": "https://discovered.example.com/mcp",
        });
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "notion",
            &call_config,
        )
        .await
        .unwrap();
        assert_eq!(cred.value.as_deref(), Some("exchanged-tok"));
    }

    #[tokio::test]
    async fn malformed_call_config_is_misconfigured() {
        let plugin = build_with_token_url("https://example.com/token");
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("tok"),
            "notion",
            &json!({ "audience": 5 }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CredentialError::Misconfigured { .. }));
    }
}

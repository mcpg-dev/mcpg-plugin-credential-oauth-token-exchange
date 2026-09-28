//! `dev.mcpg.credential.oauth-token-exchange` — outbound OAuth 2.0
//! token-exchange credential_issuer plugin (RFC 8693).
//!
//! Exchanges the *caller's* subject token for a downstream access token
//! so a gateway can act on-behalf-of the end user (impersonation).
//! Operators declare named STS providers; callers reference an exchanged
//! token via `cred://<plugin_id>/<provider>`.
//!
//! The plugin authenticates to the STS with `client_secret_post`,
//! `client_secret_basic` or `private_key_jwt`. The token endpoint must be
//! https and must not resolve to a private address unless the provider
//! opts in.
//!
//! ## Subject token
//!
//! The subject token to exchange is read from the resolved identity's
//! `attributes["subject_token"]`; its type is the provider's
//! `subject_token_type` unless `attributes["subject_token_type"]`
//! overrides it. Federation's `oauth_impersonation` mode populates the
//! token from the inbound caller bearer. A bearer the gateway process
//! minted (`auth_provider` `ema` or `inspector_supervisor`, or any
//! `attributes["token_issuer"]`) is refused: no external STS can validate
//! it.
//!
//! The exception is a subject token from the caller's enterprise IdP
//! sign-in the gateway keeps (`attributes["subject_token_source"] =
//! "idp_vault"`), whatever bearer the caller presented. It is exchanged
//! only at the token endpoint that issued it, by the client it was issued
//! to: `attributes["subject_token_endpoint"]` must equal `token_url`,
//! `attributes["subject_token_client_id"]` must equal `client_id`, and,
//! when `sts_issuer` is set, `attributes["subject_token_issuer"]` must
//! equal it. Otherwise the call is refused before any request.
//!
//! The subject token is used transiently and never logged.
//!
//! ## No in-plugin cache
//!
//! Unlike the `client_credentials` issuer, exchanged tokens are
//! per-caller — caching belongs in the host credential cache, keyed per
//! `(identity_hash, plugin_id, target)`. A provider-keyed in-plugin cache
//! would serve one caller's token to another, so it is deliberately
//! omitted; every `issue` performs a fresh exchange and the host cache
//! deduplicates per caller.

mod client_auth;
mod config;
mod egress;

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

use client_auth::ClientAuth;
pub use client_auth::{AssertionAudience, ClientAuthMethod, SigningAlg};
pub use config::{
    ConfigError, ExpandError, ProviderConfig, TokenExchangeConfig, TokenExchangeTargetTemplate,
    normalize_token_type, target_slug,
};

const PLUGIN_ID: &str = "dev.mcpg.credential.oauth-token-exchange";

/// RFC 8693 §2.1 grant type.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Identity-attribute key carrying the caller's raw subject token to
/// exchange. Populated by federation `oauth_impersonation` (and any other
/// caller); never logged.
const SUBJECT_TOKEN_ATTR: &str = "subject_token";
/// Optional per-request override of the subject token's type.
const SUBJECT_TOKEN_TYPE_ATTR: &str = "subject_token_type";

/// `auth_provider` values of callers whose bearer the gateway process
/// minted: the embedded authorization server and the supervised inspector.
const GATEWAY_MINTED_AUTH_PROVIDERS: [&str; 2] = ["ema", "inspector_supervisor"];
/// Attribute the embedded authorization server sets on every caller of a
/// token it minted. A `principal_issuer` alias rewrites `auth_provider`
/// but leaves this in place.
const TOKEN_ISSUER_ATTR: &str = "token_issuer";
/// Attribute naming where the subject token came from.
const SUBJECT_TOKEN_SOURCE_ATTR: &str = "subject_token_source";
/// The caller's enterprise IdP sign-in the gateway stored: an IdP token,
/// exchangeable even when the caller presented a gateway-minted bearer.
const SUBJECT_TOKEN_SOURCE_IDP_VAULT: &str = "idp_vault";
/// The token endpoint, client and issuer a stored sign-in was issued by.
const SUBJECT_TOKEN_ENDPOINT_ATTR: &str = "subject_token_endpoint";
const SUBJECT_TOKEN_CLIENT_ID_ATTR: &str = "subject_token_client_id";
const SUBJECT_TOKEN_ISSUER_ATTR: &str = "subject_token_issuer";

fn is_gateway_minted(identity: &PluginIdentity) -> bool {
    let minted_provider = identity.auth_provider.as_deref().is_some_and(|p| {
        GATEWAY_MINTED_AUTH_PROVIDERS
            .iter()
            .any(|minted| p.eq_ignore_ascii_case(minted))
    });
    minted_provider || identity.attributes.contains_key(TOKEN_ISSUER_ATTR)
}

fn from_idp_vault(identity: &PluginIdentity) -> bool {
    identity
        .attributes
        .get(SUBJECT_TOKEN_SOURCE_ATTR)
        .is_some_and(|source| source == SUBJECT_TOKEN_SOURCE_IDP_VAULT)
}

/// Refuse a stored-sign-in subject token that `provider` would send to
/// another token endpoint than the one that issued it, or present with
/// another client.
fn check_idp_vault_binding(
    provider_name: &str,
    provider: &ProviderConfig,
    identity: &PluginIdentity,
) -> Result<(), CredentialError> {
    let attribute = |name: &str| identity.attributes.get(name).map(String::as_str);
    let bound = attribute(SUBJECT_TOKEN_ENDPOINT_ATTR) == Some(provider.token_url.as_str())
        && attribute(SUBJECT_TOKEN_CLIENT_ID_ATTR) == Some(provider.client_id.as_str())
        && provider
            .sts_issuer
            .as_deref()
            .is_none_or(|issuer| attribute(SUBJECT_TOKEN_ISSUER_ATTR) == Some(issuer));
    if bound {
        return Ok(());
    }
    Err(CredentialError::Misconfigured {
        reason: format!(
            "token exchange for `{provider_name}`: the stored enterprise sign-in may only be \
             exchanged at the IdP that issued it, by the client it was issued to; token_url and \
             client_id must be the gateway's login client's, and sts_issuer, when set, its IdP"
        ),
    })
}

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
    provider_auth: BTreeMap<String, Arc<ClientAuth>>,
    template_auth: Option<Arc<ClientAuth>>,
    /// Refuses private, loopback and link-local destinations.
    guarded_client: reqwest::Client,
    /// For providers with `allow_private_network: true`.
    open_client: reqwest::Client,
    /// Tokio runtime for the SyncCredentialIssuer FFI path; lazily built
    /// on first sync call (see the client_credentials issuer for rationale).
    sync_runtime: OnceLock<Runtime>,
}

impl Inner {
    fn client(&self, provider: &ProviderConfig) -> &reqwest::Client {
        if provider.allow_private_network {
            &self.open_client
        } else {
            &self.guarded_client
        }
    }
}

fn refuse_to_load(err: &dyn std::fmt::Display) -> ! {
    tracing::error!(
        plugin_id = PLUGIN_ID,
        error = %err,
        "oauth-token-exchange: config parse failed; refusing to register"
    );
    panic!(
        "oauth-token-exchange config parse failed: {err}. A misconfigured \
         credential issuer is a security hole; refusing to load."
    )
}

impl OAuthTokenExchangePlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg =
            TokenExchangeConfig::parse(config_json).unwrap_or_else(|err| refuse_to_load(&err));
        Self::from_validated_config(cfg).unwrap_or_else(|err| refuse_to_load(&err))
    }

    fn from_validated_config(cfg: TokenExchangeConfig) -> Result<Self, String> {
        let mut provider_auth = BTreeMap::new();
        for (name, provider) in &cfg.providers {
            let auth = provider
                .client_auth()
                .map_err(|e| format!("provider `{name}` {e}"))?;
            provider_auth.insert(name.clone(), Arc::new(auth));
        }
        let template_auth = match &cfg.target_template {
            Some(template) => {
                let probe = template.probe().map_err(|e| e.to_string())?;
                let auth = probe
                    .client_auth()
                    .map_err(|e| format!("target_template {e}"))?;
                Some(Arc::new(auth))
            }
            None => None,
        };
        tracing::info!(
            plugin_id = PLUGIN_ID,
            provider_count = cfg.providers.len(),
            "oauth-token-exchange: configured"
        );
        Ok(Self {
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
                provider_auth,
                template_auth,
                guarded_client: egress::build_client(true),
                open_client: egress::build_client(false),
                sync_runtime: OnceLock::new(),
            }),
        })
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

fn unknown_provider(provider_name: &str) -> CredentialError {
    CredentialError::Misconfigured {
        reason: format!(
            "unknown provider `{provider_name}` (no exact entry; target_template \
             absent or target not in allowed_targets)"
        ),
    }
}

/// The provider for `provider_name` and its compiled client authentication.
/// Exact provider entries win; the fleet template serves allowlisted
/// targets; anything else fails closed.
fn resolve_provider(
    inner: &Inner,
    provider_name: &str,
) -> Result<(ProviderConfig, Arc<ClientAuth>), CredentialError> {
    if let Some(provider) = inner.config.providers.get(provider_name) {
        let auth = inner
            .provider_auth
            .get(provider_name)
            .cloned()
            .ok_or_else(|| unknown_provider(provider_name))?;
        return Ok((provider.clone(), auth));
    }
    let (Some(template), Some(auth)) = (&inner.config.target_template, &inner.template_auth) else {
        return Err(unknown_provider(provider_name));
    };
    match template.expand(provider_name) {
        Ok(provider) => Ok((provider, Arc::clone(auth))),
        Err(ExpandError::NotAllowed(_)) => Err(unknown_provider(provider_name)),
        Err(e) => Err(CredentialError::Misconfigured {
            reason: e.to_string(),
        }),
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

    // A bearer the gateway minted is valid only at this gateway, so posting
    // one to an STS can never succeed and hands a live gateway credential to
    // a third party. A stored IdP sign-in is an IdP token whoever the caller
    // is, and is checked against the provider below instead.
    let from_vault = from_idp_vault(identity);
    if !from_vault && is_gateway_minted(identity) {
        return Err(CredentialError::Misconfigured {
            reason: format!(
                "token exchange for `{provider_name}`: a token minted by this gateway \
                 cannot be exchanged at an external token service"
            ),
        });
    }

    let (provider, auth) = resolve_provider(inner, provider_name)?;
    let provider = CallOverrides::parse(call_config)?.apply(provider);
    if from_vault {
        check_idp_vault_binding(provider_name, &provider, identity)?;
    }

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
    let subject_token_type = match identity.attributes.get(SUBJECT_TOKEN_TYPE_ATTR) {
        Some(raw) => normalize_token_type(raw).ok_or_else(|| CredentialError::Misconfigured {
            reason: format!(
                "token exchange for `{provider_name}`: identity.attributes\
                 [\"{SUBJECT_TOKEN_TYPE_ATTR}\"] is not a supported token type"
            ),
        })?,
        None => provider.subject_token_type.clone(),
    };

    exchange(
        inner,
        provider_name,
        &provider,
        &auth,
        subject_token,
        &subject_token_type,
    )
    .await
}

async fn exchange(
    inner: &Inner,
    provider_name: &str,
    provider: &ProviderConfig,
    auth: &ClientAuth,
    subject_token: &str,
    subject_token_type: &str,
) -> Result<IssuedCredential, CredentialError> {
    egress::check_endpoint(&provider.token_url, provider.egress()).map_err(|reason| {
        CredentialError::Misconfigured {
            reason: format!("token-exchange endpoint for `{provider_name}` {reason}"),
        }
    })?;
    let mut form: Vec<(&'static str, String)> = vec![
        ("grant_type", GRANT_TYPE.to_owned()),
        ("subject_token", subject_token.to_owned()),
        ("subject_token_type", subject_token_type.to_owned()),
        (
            "requested_token_type",
            provider.requested_token_type.clone(),
        ),
    ];
    if !provider.scopes.is_empty() {
        form.push(("scope", provider.scopes.join(" ")));
    }
    if let Some(aud) = provider.audience.as_deref() {
        form.push(("audience", aud.to_owned()));
    }
    if let Some(res) = provider.resource.as_deref() {
        form.push(("resource", res.to_owned()));
    }
    if let (Some(token), Some(token_type)) = (
        provider.actor_token.as_deref().filter(|t| !t.is_empty()),
        provider.actor_token_type.as_deref(),
    ) {
        form.push(("actor_token", token.to_owned()));
        form.push(("actor_token_type", token_type.to_owned()));
    }

    let request = inner
        .client(provider)
        .post(&provider.token_url)
        .timeout(Duration::from_millis(provider.timeout_ms));
    let request = auth
        .authenticate(
            request,
            &mut form,
            &provider.token_url,
            provider.sts_issuer.as_deref(),
        )
        .map_err(|reason| CredentialError::Misconfigured {
            reason: format!("token-exchange client authentication for `{provider_name}`: {reason}"),
        })?;

    let started = Instant::now();
    let response = request.form(&form).send().await.map_err(|e| {
        if egress::is_private_address_refusal(&e) {
            CredentialError::Misconfigured {
                reason: format!(
                    "token-exchange endpoint for `{provider_name}` resolves only to private, \
                     loopback or link-local addresses (set allow_private_network: true to permit)"
                ),
            }
        } else {
            CredentialError::Backend {
                reason: format!("token-exchange endpoint unreachable for `{provider_name}`: {e}"),
            }
        }
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
        // logs / audit, and a misbehaving STS could echo the caller's subject
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
            300..=399 => CredentialError::Misconfigured {
                reason: format!(
                    "token-exchange endpoint for `{provider_name}` redirected (HTTP {status}); \
                     redirects are not followed, configure the final URL"
                ),
            },
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
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use serde_json::json;
    use wiremock::matchers::{any, body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const RSA_PRIV: &str = include_str!("../tests/fixtures/rsa_priv.pem");
    const RSA_PUB: &str = include_str!("../tests/fixtures/rsa_pub.pem");
    const EC_PRIV: &str = include_str!("../tests/fixtures/ec_priv.pem");
    const EC_PUB: &str = include_str!("../tests/fixtures/ec_pub.pem");

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
            auth_provider: Some("oidc".into()),
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes,
        }
    }

    /// The `notion` provider pointed at `url`. A wiremock server listens on
    /// loopback over plain http, so both egress opt-ins are set.
    fn notion_config(url: &str) -> Value {
        json!({
            "providers": {
                "notion": {
                    "token_url": url,
                    "client_id": "mcpg",
                    "client_secret": "csecret",
                    "audience": "https://notion-mcp.example.com",
                    "scopes": ["read"],
                    "allow_insecure_http": true,
                    "allow_private_network": true
                }
            }
        })
    }

    fn build_with_token_url(url: &str) -> OAuthTokenExchangePlugin {
        OAuthTokenExchangePlugin::from_config_json(&notion_config(url).to_string())
    }

    fn exchanged() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "exchanged-tok",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 600
        }))
    }

    async fn form_sent(server: &MockServer) -> BTreeMap<String, String> {
        let requests: Vec<Request> = server.received_requests().await.unwrap();
        let request = requests.first().expect("one request");
        url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect()
    }

    fn decode_assertion(
        form: &BTreeMap<String, String>,
        alg: Algorithm,
        key: &DecodingKey,
        aud: &str,
    ) -> Value {
        assert_eq!(
            form.get("client_assertion_type").map(String::as_str),
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        );
        assert!(!form.contains_key("client_secret"));
        let mut validation = Validation::new(alg);
        validation.set_audience(&[aud]);
        validation.set_issuer(&["mcpg"]);
        let claims = jsonwebtoken::decode::<Value>(&form["client_assertion"], key, &validation)
            .expect("client assertion verifies")
            .claims;
        assert_eq!(claims["sub"], "mcpg");
        let lifetime = claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap();
        assert!(lifetime <= 300, "lifetime {lifetime}s exceeds five minutes");
        claims
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
            .and(body_string_contains("client_secret=csecret"))
            .and(body_string_contains("audience="))
            .respond_with(exchanged())
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
    async fn client_secret_basic_uses_the_header_only() {
        let server = MockServer::start().await;
        // base64("mcpg:csecret")
        Mock::given(path("/token"))
            .and(header("authorization", "Basic bWNwZzpjc2VjcmV0"))
            .respond_with(exchanged())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = notion_config(&format!("{}/token", server.uri()));
        cfg["providers"]["notion"]["client_auth"] = json!("client_secret_basic");
        let plugin = OAuthTokenExchangePlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "notion", &json!({}))
            .await
            .unwrap();
        let form = form_sent(&server).await;
        assert!(!form.contains_key("client_id") && !form.contains_key("client_secret"));
    }

    #[tokio::test]
    async fn private_key_jwt_targets_the_token_endpoint() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(exchanged())
            .expect(1)
            .mount(&server)
            .await;
        let token_url = format!("{}/token", server.uri());
        let mut cfg = notion_config(&token_url);
        let notion = cfg["providers"]["notion"].as_object_mut().unwrap();
        notion.remove("client_secret");
        notion.insert("client_auth".into(), json!("private_key_jwt"));
        notion.insert("private_key".into(), json!(RSA_PRIV));
        notion.insert("key_id".into(), json!("sts-key-1"));
        let plugin = OAuthTokenExchangePlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "notion", &json!({}))
            .await
            .unwrap();
        let form = form_sent(&server).await;
        let claims = decode_assertion(
            &form,
            Algorithm::RS256,
            &DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap(),
            &token_url,
        );
        assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
        let header = jsonwebtoken::decode_header(&form["client_assertion"]).unwrap();
        assert_eq!(header.kid.as_deref(), Some("sts-key-1"));
    }

    #[tokio::test]
    async fn private_key_jwt_can_target_the_sts_issuer() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(exchanged())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = notion_config(&format!("{}/token", server.uri()));
        let notion = cfg["providers"]["notion"].as_object_mut().unwrap();
        notion.remove("client_secret");
        notion.insert("client_auth".into(), json!("private_key_jwt"));
        notion.insert("private_key".into(), json!(EC_PRIV));
        notion.insert("signing_alg".into(), json!("ES256"));
        notion.insert("assertion_audience".into(), json!("issuer"));
        notion.insert("sts_issuer".into(), json!("https://sts.example.com"));
        let plugin = OAuthTokenExchangePlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "notion", &json!({}))
            .await
            .unwrap();
        decode_assertion(
            &form_sent(&server).await,
            Algorithm::ES256,
            &DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap(),
            "https://sts.example.com",
        );
    }

    #[tokio::test]
    async fn actor_token_is_sent_when_configured() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .and(body_string_contains("actor_token=gateway-actor"))
            .and(body_string_contains(
                "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
            ))
            .respond_with(exchanged())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = notion_config(&format!("{}/token", server.uri()));
        cfg["providers"]["notion"]["actor_token"] = json!("gateway-actor");
        cfg["providers"]["notion"]["actor_token_type"] = json!("jwt");
        let plugin = OAuthTokenExchangePlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "notion", &json!({}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn gateway_minted_caller_is_refused_without_any_request() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        for provider in ["ema", "inspector_supervisor", "Inspector_Supervisor"] {
            let mut identity = identity_with_subject("gateway-minted-token");
            identity.auth_provider = Some(provider.into());
            let err = CredentialIssuer::issue(&plugin, &identity, "notion", &json!({}))
                .await
                .unwrap_err();
            match err {
                CredentialError::Misconfigured { reason } => {
                    assert!(
                        reason.contains("a token minted by this gateway cannot be exchanged"),
                        "{provider}: {reason}"
                    );
                    assert!(!reason.contains("gateway-minted-token"), "{reason}");
                }
                other => panic!("{provider}: unexpected error: {other:?}"),
            }
        }
    }

    /// An EMA caller whose IdP sets `principal_issuer` reports the SSO
    /// provider's `auth_provider`; the `token_issuer` attribute still marks
    /// its bearer as gateway-minted.
    #[tokio::test]
    async fn token_issuer_attribute_is_refused_without_any_request() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let sources = [None, Some("caller_bearer"), Some("IDP_VAULT"), Some("")];
        for source in sources {
            let mut identity = identity_with_subject("gateway-minted-token");
            identity.auth_provider = Some("oidc_oauth:https://acme.okta.com/oauth2/default".into());
            identity.attributes.insert(
                TOKEN_ISSUER_ATTR.to_owned(),
                "https://mcp.acme.example".to_owned(),
            );
            if let Some(source) = source {
                identity
                    .attributes
                    .insert(SUBJECT_TOKEN_SOURCE_ATTR.to_owned(), source.to_owned());
            }
            let err = CredentialIssuer::issue(&plugin, &identity, "notion", &json!({}))
                .await
                .unwrap_err();
            match err {
                CredentialError::Misconfigured { reason } => {
                    assert!(
                        reason.contains("a token minted by this gateway cannot be exchanged"),
                        "{source:?}: {reason}"
                    );
                    assert!(!reason.contains("gateway-minted-token"), "{reason}");
                }
                other => panic!("{source:?}: unexpected error: {other:?}"),
            }
        }
    }

    /// A caller the gateway minted a token for, whose subject token is the
    /// refresh token of their stored IdP sign-in at `token_url`, issued to
    /// the provider's `client_id`.
    fn idp_vault_identity(token_url: &str, auth_provider: &str) -> PluginIdentity {
        let mut identity = identity_with_subject("idp-refresh-token");
        identity.auth_provider = Some(auth_provider.into());
        for (name, value) in [
            (TOKEN_ISSUER_ATTR, "https://mcp.acme.example"),
            (SUBJECT_TOKEN_SOURCE_ATTR, SUBJECT_TOKEN_SOURCE_IDP_VAULT),
            (
                SUBJECT_TOKEN_TYPE_ATTR,
                "urn:ietf:params:oauth:token-type:refresh_token",
            ),
            (SUBJECT_TOKEN_ENDPOINT_ATTR, token_url),
            (SUBJECT_TOKEN_CLIENT_ID_ATTR, "mcpg"),
            (SUBJECT_TOKEN_ISSUER_ATTR, "https://sts.example.com"),
            ("subject_token_binding", "vault:p:mcpg:refresh_token"),
        ] {
            identity
                .attributes
                .insert(name.to_owned(), value.to_owned());
        }
        identity
    }

    /// A subject token from the stored IdP sign-in is an IdP token, so it
    /// is exchanged for a caller whose bearer the gateway minted, at the
    /// token endpoint and with the client that issued it.
    #[tokio::test]
    async fn idp_vault_subject_token_is_exchanged_for_a_gateway_minted_caller() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("subject_token=idp-refresh-token"))
            .and(body_string_contains(
                "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token",
            ))
            .respond_with(exchanged())
            .expect(3)
            .mount(&server)
            .await;
        let token_url = format!("{}/token", server.uri());
        let plugin = build_with_token_url(&token_url);
        for auth_provider in [
            "ema",
            "inspector_supervisor",
            "oidc_oauth:https://sso.example",
        ] {
            let identity = idp_vault_identity(&token_url, auth_provider);
            let cred = CredentialIssuer::issue(&plugin, &identity, "notion", &json!({}))
                .await
                .unwrap_or_else(|e| panic!("{auth_provider}: {e:?}"));
            assert_eq!(cred.value.as_deref(), Some("exchanged-tok"));
        }
    }

    /// The stored sign-in goes to no other token endpoint than the one that
    /// issued it, with no other client, and from no other IdP than the
    /// provider's `sts_issuer`; a vault token without those attributes is
    /// refused too. Nothing is sent.
    #[tokio::test]
    async fn idp_vault_subject_token_bound_elsewhere_is_refused_without_any_request() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let token_url = format!("{}/token", server.uri());
        let mut config = notion_config(&token_url);
        config["providers"]["notion"]["sts_issuer"] = json!("https://sts.example.com");
        let plugin = OAuthTokenExchangePlugin::from_config_json(&config.to_string());
        let cases: [(&str, Option<String>); 7] = [
            (
                SUBJECT_TOKEN_ENDPOINT_ATTR,
                Some(format!("{}/other", server.uri())),
            ),
            (SUBJECT_TOKEN_ENDPOINT_ATTR, Some(format!("{token_url}/"))),
            (SUBJECT_TOKEN_ENDPOINT_ATTR, None),
            (
                SUBJECT_TOKEN_CLIENT_ID_ATTR,
                Some("another-client".to_owned()),
            ),
            (SUBJECT_TOKEN_CLIENT_ID_ATTR, None),
            (
                SUBJECT_TOKEN_ISSUER_ATTR,
                Some("https://other-idp.example".to_owned()),
            ),
            (SUBJECT_TOKEN_ISSUER_ATTR, None),
        ];
        for (attribute, value) in cases {
            let mut identity = idp_vault_identity(&token_url, "ema");
            match value {
                Some(ref value) => {
                    identity
                        .attributes
                        .insert(attribute.to_owned(), value.clone());
                }
                None => {
                    identity.attributes.remove(attribute);
                }
            }
            match CredentialIssuer::issue(&plugin, &identity, "notion", &json!({})).await {
                Err(CredentialError::Misconfigured { reason }) => {
                    assert!(
                        reason.contains("may only be exchanged at the IdP that issued it"),
                        "{attribute}={value:?}: {reason}"
                    );
                    assert!(!reason.contains("idp-refresh-token"), "{reason}");
                }
                other => panic!("{attribute}={value:?}: unexpected {other:?}"),
            }
        }
    }

    /// Without `sts_issuer` on the provider, the endpoint and client decide.
    #[tokio::test]
    async fn idp_vault_issuer_is_checked_only_when_the_provider_names_one() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(exchanged())
            .expect(1)
            .mount(&server)
            .await;
        let token_url = format!("{}/token", server.uri());
        let plugin = build_with_token_url(&token_url);
        let mut identity = idp_vault_identity(&token_url, "ema");
        identity.attributes.insert(
            SUBJECT_TOKEN_ISSUER_ATTR.to_owned(),
            "https://any-idp.example".to_owned(),
        );
        CredentialIssuer::issue(&plugin, &identity, "notion", &json!({}))
            .await
            .expect("exchanged");
    }

    #[tokio::test]
    async fn unsupported_subject_token_type_attribute_is_refused_before_http() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let mut identity = identity_with_subject("tok");
        identity.attributes.insert(
            SUBJECT_TOKEN_TYPE_ATTR.to_owned(),
            "urn:example:custom".into(),
        );
        let err = CredentialIssuer::issue(&plugin, &identity, "notion", &json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(err, CredentialError::Misconfigured { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn redirect_from_the_sts_is_not_followed() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", "/collector"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/collector"))
            .respond_with(exchanged())
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_token_url(&format!("{}/token", server.uri()));
        let err =
            CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "notion", &json!({}))
                .await
                .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("redirects are not followed"), "{reason}");
                assert!(reason.contains("configure the final URL"), "{reason}");
                assert!(!reason.contains("/collector"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
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
        // On-behalf-of token exchange requires a Verified caller. A
        // non-verified identity with a populated subject token must be
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
    /// whose audience/resource expand the target.
    fn build_template_with_token_url(url: &str) -> OAuthTokenExchangePlugin {
        let cfg = json!({
            "target_template": {
                "allowed_targets": ["srv-*", "com.acme/*"],
                "token_url": url,
                "client_id": "mcpg-fleet",
                "audience_template": "https://{target_slug}.mcp.example.com",
                "resource_template": "https://{target_slug}.mcp.example.com/mcp",
                "allow_insecure_http": true,
                "allow_private_network": true
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
                "audience=https%3A%2F%2Fcom-acme-crm.mcp.example.com",
            ))
            .and(body_string_contains(
                "resource=https%3A%2F%2Fcom-acme-crm.mcp.example.com%2Fmcp",
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
            "com.acme/crm",
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

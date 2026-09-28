//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.oauth-token-exchange`.
//!
//! ```yaml
//! plugins:
//!   - id: dev.mcpg.credential.oauth-token-exchange
//!     config:
//!       providers:
//!         notion:
//!           token_url: https://sts.example.com/oauth/token
//!           client_id: mcpg-gateway
//!           client_secret: ${env.STS_CLIENT_SECRET}   # optional
//!           client_auth: client_secret_basic          # optional; or client_secret_post / private_key_jwt
//!           audience: https://notion-mcp.example.com
//!           subject_token_type: access_token          # the default
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::client_auth::{
    AssertionAudience, ClientAuth, ClientAuthMethod, ClientAuthSettings, SigningAlg,
};
use crate::egress::{EgressPolicy, check_endpoint};

/// URN prefix of the RFC 8693 §3 token type identifiers.
const TOKEN_TYPE_URN_PREFIX: &str = "urn:ietf:params:oauth:token-type:";

/// Subject and actor token types the plugin sends, by short name.
const SUPPORTED_TOKEN_TYPES: [&str; 5] =
    ["access_token", "id_token", "refresh_token", "saml2", "jwt"];

/// Map a token type to its RFC 8693 URN. Accepts the short name
/// (`access_token`) or the URN; returns `None` for anything else.
pub fn normalize_token_type(value: &str) -> Option<String> {
    let value = value.trim();
    let short = value.strip_prefix(TOKEN_TYPE_URN_PREFIX).unwrap_or(value);
    SUPPORTED_TOKEN_TYPES
        .contains(&short)
        .then(|| format!("{TOKEN_TYPE_URN_PREFIX}{short}"))
}

fn unsupported_token_type<E: serde::de::Error>() -> E {
    E::custom(
        "unsupported token type; expected access_token, id_token, refresh_token, saml2 or jwt \
         (short name or urn:ietf:params:oauth:token-type:<name>)",
    )
}

fn de_token_type<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let raw = String::deserialize(d)?;
    normalize_token_type(&raw).ok_or_else(unsupported_token_type)
}

fn de_opt_token_type<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|raw| normalize_token_type(&raw).ok_or_else(unsupported_token_type))
        .transpose()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenExchangeConfig {
    /// Named token-exchange providers. The map key is the provider
    /// name; callers reference an exchanged token via the URI
    /// `cred://dev.mcpg.credential.oauth-token-exchange/<name>`.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,

    /// Fleet template: derive a provider for any allowlisted target that
    /// has no exact `providers` entry, expanding `{target}` or
    /// `{target_slug}` into the audience/resource. One block serves a
    /// whole registry of servers behind a single STS.
    #[serde(default)]
    pub target_template: Option<TokenExchangeTargetTemplate>,
}

/// Template that derives a [`ProviderConfig`] per target. In the
/// `*_template` fields `{target}` is replaced with the requested target
/// name and `{target_slug}` with [`target_slug`] of it; only targets
/// matching `allowed_targets` (exact or trailing-`*` glob) expand —
/// anything else fails closed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenExchangeTargetTemplate {
    /// Targets the template may serve. Exact names or trailing-`*`
    /// prefix globs. Required non-empty: an unbounded template would
    /// mint a token for any caller-chosen audience.
    pub allowed_targets: Vec<String>,

    /// STS token endpoint URL (RFC 8693 §2) — one STS for the fleet.
    pub token_url: String,

    /// STS issuer identifier, used as the client assertion audience when
    /// `assertion_audience: issuer`.
    #[serde(default)]
    pub sts_issuer: Option<String>,

    /// OAuth client ID MCPG presents to the STS.
    pub client_id: String,

    /// OAuth client secret (optional; source via `${env.VAR}` / `${secret.NAME}`).
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Client authentication. Unset: `client_id`, and `client_secret` when
    /// present, in the form body.
    #[serde(default)]
    pub client_auth: Option<ClientAuthMethod>,

    /// PEM private key for `client_auth: private_key_jwt`.
    #[serde(default)]
    pub private_key: Option<String>,

    /// `kid` header of the client assertion.
    #[serde(default)]
    pub key_id: Option<String>,

    /// Client assertion algorithm. Default RS256.
    #[serde(default)]
    pub signing_alg: Option<SigningAlg>,

    /// Client assertion `aud`. Default the token endpoint URL.
    #[serde(default)]
    pub assertion_audience: Option<AssertionAudience>,

    /// Scopes to request for the exchanged token.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// `subject_token_type` for the exchange (RFC 8693 §2.1).
    #[serde(
        default = "default_subject_token_type",
        deserialize_with = "de_token_type"
    )]
    pub subject_token_type: String,

    /// `requested_token_type` for the exchanged token (RFC 8693 §2.1).
    #[serde(default = "default_subject_token_type")]
    pub requested_token_type: String,

    /// `audience` template; `{target}` / `{target_slug}` expand per target.
    #[serde(default)]
    pub audience_template: Option<String>,

    /// `resource` template; `{target}` / `{target_slug}` expand per target.
    #[serde(default)]
    pub resource_template: Option<String>,

    /// Optional RFC 8693 `actor_token`.
    #[serde(default)]
    pub actor_token: Option<String>,

    /// `actor_token_type`; required with `actor_token`.
    #[serde(default, deserialize_with = "de_opt_token_type")]
    pub actor_token_type: Option<String>,

    /// Permit a plain-http token endpoint. Local development only.
    #[serde(default)]
    pub allow_insecure_http: bool,

    /// Permit a token endpoint on a private, loopback or link-local address.
    #[serde(default)]
    pub allow_private_network: bool,

    /// Per-request timeout for the STS endpoint. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Why a template does not expand for a target.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpandError {
    #[error("target `{0}` is not in target_template.allowed_targets")]
    NotAllowed(String),
    #[error("target `{0}` has no hostname characters for {{target_slug}}")]
    EmptySlug(String),
}

/// `target` reduced to hostname-safe characters: every character outside
/// `[A-Za-z0-9-]` (`/` and `.` included) becomes `-`, and leading or
/// trailing `-` are dropped. `com.acme/crm` becomes `com-acme-crm`.
pub fn target_slug(target: &str) -> String {
    let mapped: String = target
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    mapped.trim_matches('-').to_owned()
}

fn substitute(template: &str, target: &str, slug: &str) -> String {
    template
        .replace("{target_slug}", slug)
        .replace("{target}", target)
}

/// A representative target for an `allowed_targets` pattern.
fn probe_target(pattern: &str) -> String {
    match pattern.strip_suffix('*') {
        Some(prefix) => format!("{prefix}probe"),
        None => pattern.to_owned(),
    }
}

impl TokenExchangeTargetTemplate {
    /// Expand the template for `target`.
    pub fn expand(&self, target: &str) -> Result<ProviderConfig, ExpandError> {
        if !self.allowed_targets.iter().any(|p| glob_match(p, target)) {
            return Err(ExpandError::NotAllowed(target.to_owned()));
        }
        let slug = target_slug(target);
        let uses_slug = [&self.audience_template, &self.resource_template]
            .into_iter()
            .flatten()
            .any(|t| t.contains("{target_slug}"));
        if uses_slug && slug.is_empty() {
            return Err(ExpandError::EmptySlug(target.to_owned()));
        }
        let fill = |t: &str| substitute(t, target, &slug);
        Ok(ProviderConfig {
            token_url: self.token_url.clone(),
            sts_issuer: self.sts_issuer.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            client_auth: self.client_auth,
            private_key: self.private_key.clone(),
            key_id: self.key_id.clone(),
            signing_alg: self.signing_alg,
            assertion_audience: self.assertion_audience,
            scopes: self.scopes.clone(),
            subject_token_type: self.subject_token_type.clone(),
            requested_token_type: self.requested_token_type.clone(),
            audience: self.audience_template.as_deref().map(fill),
            resource: self.resource_template.as_deref().map(fill),
            actor_token: self.actor_token.clone(),
            actor_token_type: self.actor_token_type.clone(),
            allow_insecure_http: self.allow_insecure_http,
            allow_private_network: self.allow_private_network,
            timeout_ms: self.timeout_ms,
        })
    }

    /// The expansion for a representative target of the first
    /// `allowed_targets` pattern. Client authentication does not depend on
    /// the target, so this is what it is compiled from.
    pub(crate) fn probe(&self) -> Result<ProviderConfig, ExpandError> {
        let pattern = self.allowed_targets.first().map_or("", String::as_str);
        self.expand(&probe_target(pattern))
    }
}

/// Exact-name or trailing-`*` prefix match.
fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// STS token endpoint URL (RFC 8693 §2).
    pub token_url: String,

    /// STS issuer identifier, used as the client assertion audience when
    /// `assertion_audience: issuer`.
    #[serde(default)]
    pub sts_issuer: Option<String>,

    /// OAuth client ID MCPG presents to the STS.
    pub client_id: String,

    /// OAuth client secret. Optional — token-exchange clients may be
    /// public or authenticate by other means. Source from a secret
    /// backend via `${env.VAR}` / `${secret.NAME}` so the literal
    /// never appears in YAML or logs.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Client authentication. Unset: `client_id`, and `client_secret` when
    /// present, in the form body.
    #[serde(default)]
    pub client_auth: Option<ClientAuthMethod>,

    /// PEM private key for `client_auth: private_key_jwt`.
    #[serde(default)]
    pub private_key: Option<String>,

    /// `kid` header of the client assertion.
    #[serde(default)]
    pub key_id: Option<String>,

    /// Client assertion algorithm. Default RS256.
    #[serde(default)]
    pub signing_alg: Option<SigningAlg>,

    /// Client assertion `aud`. Default the token endpoint URL.
    #[serde(default)]
    pub assertion_audience: Option<AssertionAudience>,

    /// Scopes to request for the exchanged token (space-joined, RFC 6749 §3.3).
    #[serde(default)]
    pub scopes: Vec<String>,

    /// `subject_token_type` for the exchange (RFC 8693 §2.1), as a short
    /// name or URN. The caller may override it per request via
    /// `identity.attributes["subject_token_type"]`.
    #[serde(
        default = "default_subject_token_type",
        deserialize_with = "de_token_type"
    )]
    pub subject_token_type: String,

    /// `requested_token_type` for the exchanged token (RFC 8693 §2.1).
    #[serde(default = "default_subject_token_type")]
    pub requested_token_type: String,

    /// Optional `audience` — the logical target the exchanged token is for.
    #[serde(default)]
    pub audience: Option<String>,

    /// Optional `resource` — the target URI the exchanged token is for.
    #[serde(default)]
    pub resource: Option<String>,

    /// Optional RFC 8693 `actor_token`.
    #[serde(default)]
    pub actor_token: Option<String>,

    /// `actor_token_type`; required with `actor_token`.
    #[serde(default, deserialize_with = "de_opt_token_type")]
    pub actor_token_type: Option<String>,

    /// Permit a plain-http token endpoint. Local development only.
    #[serde(default)]
    pub allow_insecure_http: bool,

    /// Permit a token endpoint on a private, loopback or link-local address.
    #[serde(default)]
    pub allow_private_network: bool,

    /// Per-request timeout for the STS endpoint. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl ProviderConfig {
    pub(crate) fn egress(&self) -> EgressPolicy {
        EgressPolicy {
            allow_insecure_http: self.allow_insecure_http,
            allow_private_network: self.allow_private_network,
        }
    }

    pub(crate) fn client_auth(&self) -> Result<ClientAuth, String> {
        ClientAuth::compile(&ClientAuthSettings {
            prefix: "",
            method: self.client_auth,
            client_id: Some(self.client_id.as_str()),
            client_secret: self.client_secret.as_deref(),
            private_key: self.private_key.as_deref(),
            key_id: self.key_id.as_deref(),
            signing_alg: self.signing_alg,
            assertion_audience: self.assertion_audience,
            issuer_available: self
                .sts_issuer
                .as_deref()
                .is_some_and(|i| !i.trim().is_empty()),
            issuer_setting: "sts_issuer",
        })
    }
}

fn default_subject_token_type() -> String {
    "urn:ietf:params:oauth:token-type:access_token".to_owned()
}

fn default_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.oauth-token-exchange config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error(
        "credential.oauth-token-exchange: providers must be non-empty (or set target_template)"
    )]
    EmptyProviders,
    #[error("credential.oauth-token-exchange: target_template.allowed_targets must be non-empty")]
    EmptyAllowedTargets,
    #[error("credential.oauth-token-exchange: target_template: {0}")]
    Template(#[from] ExpandError),
    #[error("credential.oauth-token-exchange: provider `{name}` token_url is empty")]
    EmptyTokenUrl { name: String },
    #[error("credential.oauth-token-exchange: provider `{name}` token_url {reason}")]
    InvalidTokenUrl { name: String, reason: String },
    #[error("credential.oauth-token-exchange: provider `{name}` client_id is empty")]
    EmptyClientId { name: String },
    #[error("credential.oauth-token-exchange: provider `{name}` {reason}")]
    ClientAuth { name: String, reason: String },
    #[error(
        "credential.oauth-token-exchange: provider `{name}` actor_token and actor_token_type \
         go together"
    )]
    ActorTokenPairing { name: String },
    #[error(
        "credential.oauth-token-exchange: provider `{name}` timeout_ms={timeout}; must be 100..=60_000"
    )]
    InvalidTimeoutMs { name: String, timeout: u64 },
}

impl TokenExchangeConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.providers.is_empty() && self.target_template.is_none() {
            return Err(ConfigError::EmptyProviders);
        }
        for (name, provider) in &self.providers {
            validate_provider(name, provider)?;
            validate_client_auth(name, provider)?;
        }
        if let Some(template) = &self.target_template {
            if template.allowed_targets.is_empty() {
                return Err(ConfigError::EmptyAllowedTargets);
            }
            // Every pattern's representative target must expand, and the
            // expansion is exactly a provider, so the provider rules apply.
            for pattern in &template.allowed_targets {
                let probe = template.expand(&probe_target(pattern))?;
                validate_provider("target_template", &probe)?;
            }
            validate_client_auth("target_template", &template.probe()?)?;
        }
        Ok(())
    }
}

fn validate_provider(name: &str, provider: &ProviderConfig) -> Result<(), ConfigError> {
    if provider.token_url.trim().is_empty() {
        return Err(ConfigError::EmptyTokenUrl {
            name: name.to_owned(),
        });
    }
    check_endpoint(&provider.token_url, provider.egress()).map_err(|reason| {
        ConfigError::InvalidTokenUrl {
            name: name.to_owned(),
            reason,
        }
    })?;
    if provider.client_id.trim().is_empty() {
        return Err(ConfigError::EmptyClientId {
            name: name.to_owned(),
        });
    }
    let has_actor_token = provider
        .actor_token
        .as_deref()
        .is_some_and(|t| !t.trim().is_empty());
    if has_actor_token != provider.actor_token_type.is_some() {
        return Err(ConfigError::ActorTokenPairing {
            name: name.to_owned(),
        });
    }
    if provider.timeout_ms < 100 || provider.timeout_ms > 60_000 {
        return Err(ConfigError::InvalidTimeoutMs {
            name: name.to_owned(),
            timeout: provider.timeout_ms,
        });
    }
    Ok(())
}

fn validate_client_auth(name: &str, provider: &ProviderConfig) -> Result<(), ConfigError> {
    provider
        .client_auth()
        .map(|_| ())
        .map_err(|reason| ConfigError::ClientAuth {
            name: name.to_owned(),
            reason,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RSA_PRIV: &str = include_str!("../tests/fixtures/rsa_priv.pem");

    fn minimal() -> serde_json::Value {
        json!({
            "providers": {
                "notion": {
                    "token_url": "https://sts.example.com/oauth/token",
                    "client_id": "mcpg",
                    "audience": "https://notion-mcp.example.com"
                }
            }
        })
    }

    fn parse_err(v: &serde_json::Value) -> ConfigError {
        TokenExchangeConfig::parse(&v.to_string()).unwrap_err()
    }

    #[test]
    fn parses_minimal_with_defaults() {
        let cfg = TokenExchangeConfig::parse(&minimal().to_string()).unwrap();
        let p = cfg.providers.get("notion").unwrap();
        assert_eq!(
            p.subject_token_type,
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(
            p.requested_token_type,
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(p.timeout_ms, 5_000);
        assert!(p.client_secret.is_none());
        assert!(p.client_auth.is_none());
        assert!(!p.allow_insecure_http);
        assert!(!p.allow_private_network);
    }

    #[test]
    fn rejects_empty_providers() {
        let v = json!({ "providers": {} });
        assert!(matches!(parse_err(&v), ConfigError::EmptyProviders));
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut v = minimal();
        v["providers"]["notion"]["clinet_auth"] = json!("client_secret_basic");
        assert!(matches!(parse_err(&v), ConfigError::InvalidJson(_)));
    }

    #[test]
    fn subject_token_type_is_normalised_and_validated() {
        let mut v = minimal();
        v["providers"]["notion"]["subject_token_type"] = json!("id_token");
        let cfg = TokenExchangeConfig::parse(&v.to_string()).unwrap();
        assert_eq!(
            cfg.providers["notion"].subject_token_type,
            "urn:ietf:params:oauth:token-type:id_token"
        );
        for bad in ["urn:example:custom", "bearer", ""] {
            v["providers"]["notion"]["subject_token_type"] = json!(bad);
            assert!(
                matches!(parse_err(&v), ConfigError::InvalidJson(_)),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_unknown_token_url_scheme() {
        let mut v = minimal();
        v["providers"]["notion"]["token_url"] = json!("file:///etc/oauth");
        assert!(matches!(parse_err(&v), ConfigError::InvalidTokenUrl { .. }));
    }

    #[test]
    fn http_token_url_needs_allow_insecure_http() {
        let mut v = minimal();
        v["providers"]["notion"]["token_url"] = json!("http://sts.example.com/token");
        match parse_err(&v) {
            ConfigError::InvalidTokenUrl { reason, .. } => {
                assert!(reason.contains("allow_insecure_http"), "{reason}");
            }
            other => panic!("unexpected: {other}"),
        }
        v["providers"]["notion"]["allow_insecure_http"] = json!(true);
        assert!(TokenExchangeConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn private_token_url_needs_allow_private_network() {
        let mut v = minimal();
        v["providers"]["notion"]["token_url"] = json!("https://10.2.3.4/token");
        match parse_err(&v) {
            ConfigError::InvalidTokenUrl { reason, .. } => {
                assert!(reason.contains("allow_private_network"), "{reason}");
            }
            other => panic!("unexpected: {other}"),
        }
        v["providers"]["notion"]["allow_private_network"] = json!(true);
        assert!(TokenExchangeConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn rejects_empty_client_id() {
        let mut v = minimal();
        v["providers"]["notion"]["client_id"] = json!("");
        assert!(matches!(parse_err(&v), ConfigError::EmptyClientId { .. }));
    }

    #[test]
    fn rejects_oversize_timeout() {
        let mut v = minimal();
        v["providers"]["notion"]["timeout_ms"] = json!(120_000);
        assert!(matches!(
            parse_err(&v),
            ConfigError::InvalidTimeoutMs { .. }
        ));
    }

    #[test]
    fn client_auth_is_validated() {
        let mut v = minimal();
        v["providers"]["notion"]["client_auth"] = json!("client_secret_basic");
        assert!(matches!(parse_err(&v), ConfigError::ClientAuth { .. }));
        v["providers"]["notion"]["client_secret"] = json!("sts-secret");
        assert!(TokenExchangeConfig::parse(&v.to_string()).is_ok());

        let mut v = minimal();
        v["providers"]["notion"]["client_auth"] = json!("private_key_jwt");
        v["providers"]["notion"]["private_key"] = json!(RSA_PRIV);
        v["providers"]["notion"]["assertion_audience"] = json!("issuer");
        match parse_err(&v) {
            ConfigError::ClientAuth { reason, .. } => {
                assert!(reason.contains("sts_issuer"), "{reason}");
                assert!(!reason.contains("BEGIN"), "{reason}");
            }
            other => panic!("unexpected: {other}"),
        }
        v["providers"]["notion"]["sts_issuer"] = json!("https://sts.example.com");
        assert!(TokenExchangeConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn actor_token_needs_its_type() {
        let mut v = minimal();
        v["providers"]["notion"]["actor_token"] = json!("gateway-actor");
        assert!(matches!(
            parse_err(&v),
            ConfigError::ActorTokenPairing { .. }
        ));
        v["providers"]["notion"]["actor_token_type"] = json!("access_token");
        assert!(TokenExchangeConfig::parse(&v.to_string()).is_ok());
    }

    fn template_only() -> serde_json::Value {
        json!({
            "target_template": {
                "allowed_targets": ["com.acme/*"],
                "token_url": "https://sts.acme.example/oauth/token",
                "client_id": "mcpg-fleet",
                "audience_template": "https://{target_slug}.mcp.acme.example",
                "resource_template": "https://mcp.acme.example/{target}"
            }
        })
    }

    #[test]
    fn target_slug_maps_non_hostname_characters() {
        assert_eq!(target_slug("com.acme/crm"), "com-acme-crm");
        assert_eq!(target_slug("/srv.1/"), "srv-1");
        assert_eq!(target_slug("./"), "");
    }

    #[test]
    fn template_only_config_validates_and_expands() {
        let cfg = TokenExchangeConfig::parse(&template_only().to_string()).unwrap();
        let template = cfg.target_template.as_ref().unwrap();
        let expanded = template.expand("com.acme/crm").expect("allowlisted target");
        assert_eq!(
            expanded.audience.as_deref(),
            Some("https://com-acme-crm.mcp.acme.example")
        );
        assert_eq!(
            expanded.resource.as_deref(),
            Some("https://mcp.acme.example/com.acme/crm")
        );
        assert_eq!(expanded.token_url, "https://sts.acme.example/oauth/token");
        assert_eq!(expanded.timeout_ms, 5_000);

        // Outside the allowlist: no expansion.
        assert_eq!(
            template.expand("io.github.evil/exfil"),
            Err(ExpandError::NotAllowed("io.github.evil/exfil".into()))
        );
    }

    #[test]
    fn template_requires_allowed_targets() {
        let mut v = template_only();
        v["target_template"]["allowed_targets"] = json!([]);
        assert!(matches!(parse_err(&v), ConfigError::EmptyAllowedTargets));
    }

    #[test]
    fn template_url_scheme_validated() {
        let mut v = template_only();
        v["target_template"]["token_url"] = json!("ftp://sts.example/token");
        assert!(matches!(parse_err(&v), ConfigError::InvalidTokenUrl { .. }));
    }

    #[test]
    fn exact_provider_and_template_coexist() {
        let mut v = template_only();
        v["providers"] = minimal()["providers"].clone();
        let cfg = TokenExchangeConfig::parse(&v.to_string()).unwrap();
        assert_eq!(cfg.providers.len(), 1);
        assert!(cfg.target_template.is_some());
    }
}

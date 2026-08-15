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
//!           audience: https://notion-mcp.example.com
//!           subject_token_type: urn:ietf:params:oauth:token-type:access_token
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenExchangeConfig {
    /// Named token-exchange providers. The map key is the provider
    /// name; callers reference an exchanged token via the URI
    /// `cred://dev.mcpg.credential.oauth-token-exchange/<name>`.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,

    /// Fleet template: derive a provider for any allowlisted target that
    /// has no exact `providers` entry, expanding `{target}` into the
    /// audience/resource. One block serves a whole registry of servers
    /// behind a single STS.
    #[serde(default)]
    pub target_template: Option<TokenExchangeTargetTemplate>,
}

/// Template that derives a [`ProviderConfig`] per target. `{target}` in
/// the `*_template` fields is replaced with the requested target name;
/// only targets matching `allowed_targets` (exact or trailing-`*` glob)
/// expand — anything else fails closed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenExchangeTargetTemplate {
    /// Targets the template may serve. Exact names or trailing-`*`
    /// prefix globs. Required non-empty: an unbounded template would
    /// mint a token for any caller-chosen audience.
    pub allowed_targets: Vec<String>,

    /// STS token endpoint URL (RFC 8693 §2) — one STS for the fleet.
    pub token_url: String,

    /// OAuth client ID MCPG presents to the STS.
    pub client_id: String,

    /// OAuth client secret (optional; source via `${env.VAR}`).
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Scopes to request for the exchanged token.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// `subject_token_type` for the exchange (RFC 8693 §2.1).
    #[serde(default = "default_token_type_urn")]
    pub subject_token_type: String,

    /// `requested_token_type` for the exchanged token (RFC 8693 §2.1).
    #[serde(default = "default_token_type_urn")]
    pub requested_token_type: String,

    /// `audience` template; `{target}` expands to the target name.
    #[serde(default)]
    pub audience_template: Option<String>,

    /// `resource` template; `{target}` expands to the target name.
    #[serde(default)]
    pub resource_template: Option<String>,

    /// Per-request timeout for the STS endpoint. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl TokenExchangeTargetTemplate {
    /// Expand the template for `target`. Returns `None` when the target
    /// is not allowlisted.
    pub fn expand(&self, target: &str) -> Option<ProviderConfig> {
        if !self.allowed_targets.iter().any(|p| glob_match(p, target)) {
            return None;
        }
        let fill = |t: &str| t.replace("{target}", target);
        Some(ProviderConfig {
            token_url: self.token_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            scopes: self.scopes.clone(),
            subject_token_type: self.subject_token_type.clone(),
            requested_token_type: self.requested_token_type.clone(),
            audience: self.audience_template.as_deref().map(fill),
            resource: self.resource_template.as_deref().map(fill),
            timeout_ms: self.timeout_ms,
        })
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

    /// OAuth client ID MCPG presents to the STS.
    pub client_id: String,

    /// OAuth client secret. Optional — token-exchange clients may be
    /// public or authenticate by other means. Source from a secret
    /// backend via `${env.VAR}` / `cred://...` so the literal
    /// never appears in YAML or logs.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Scopes to request for the exchanged token (space-joined, RFC 6749 §3.3).
    #[serde(default)]
    pub scopes: Vec<String>,

    /// `subject_token_type` for the exchange (RFC 8693 §2.1). The caller
    /// may override per-request via `identity.attributes["subject_token_type"]`.
    #[serde(default = "default_token_type_urn")]
    pub subject_token_type: String,

    /// `requested_token_type` for the exchanged token (RFC 8693 §2.1).
    #[serde(default = "default_token_type_urn")]
    pub requested_token_type: String,

    /// Optional `audience` — the logical target the exchanged token is for.
    #[serde(default)]
    pub audience: Option<String>,

    /// Optional `resource` — the target URI the exchanged token is for.
    #[serde(default)]
    pub resource: Option<String>,

    /// Per-request timeout for the STS endpoint. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_token_type_urn() -> String {
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
    #[error("credential.oauth-token-exchange: provider `{name}` token_url is empty")]
    EmptyTokenUrl { name: String },
    #[error(
        "credential.oauth-token-exchange: provider `{name}` token_url must start with http:// or https://"
    )]
    InvalidTokenUrlScheme { name: String },
    #[error("credential.oauth-token-exchange: provider `{name}` client_id is empty")]
    EmptyClientId { name: String },
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
        }
        if let Some(template) = &self.target_template {
            if template.allowed_targets.is_empty() {
                return Err(ConfigError::EmptyAllowedTargets);
            }
            // Validate the template through a representative expansion —
            // the expanded shape is exactly a provider, so the provider
            // rules apply verbatim.
            let probe = template
                .expand(template.allowed_targets[0].trim_end_matches('*'))
                .expect("first allowed target expands");
            validate_provider("target_template", &probe)?;
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
    if !provider.token_url.starts_with("http://") && !provider.token_url.starts_with("https://") {
        return Err(ConfigError::InvalidTokenUrlScheme {
            name: name.to_owned(),
        });
    }
    if provider.client_id.trim().is_empty() {
        return Err(ConfigError::EmptyClientId {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    }

    #[test]
    fn rejects_empty_providers() {
        let v = json!({ "providers": {} });
        assert!(matches!(
            TokenExchangeConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyProviders
        ));
    }

    #[test]
    fn rejects_unknown_token_url_scheme() {
        let mut v = minimal();
        v["providers"]["notion"]["token_url"] = json!("file:///etc/oauth");
        assert!(matches!(
            TokenExchangeConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidTokenUrlScheme { .. }
        ));
    }

    #[test]
    fn rejects_empty_client_id() {
        let mut v = minimal();
        v["providers"]["notion"]["client_id"] = json!("");
        assert!(matches!(
            TokenExchangeConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyClientId { .. }
        ));
    }

    #[test]
    fn rejects_oversize_timeout() {
        let mut v = minimal();
        v["providers"]["notion"]["timeout_ms"] = json!(120_000);
        assert!(matches!(
            TokenExchangeConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidTimeoutMs { .. }
        ));
    }

    fn template_only() -> serde_json::Value {
        json!({
            "target_template": {
                "allowed_targets": ["com.acme/*"],
                "token_url": "https://sts.acme.example/oauth/token",
                "client_id": "mcpg-fleet",
                "audience_template": "https://{target}.mcp.acme.internal",
                "resource_template": "https://{target}.mcp.acme.internal/mcp"
            }
        })
    }

    #[test]
    fn template_only_config_validates_and_expands() {
        let cfg = TokenExchangeConfig::parse(&template_only().to_string()).unwrap();
        let template = cfg.target_template.as_ref().unwrap();
        let expanded = template.expand("com.acme/crm").expect("allowlisted target");
        assert_eq!(
            expanded.audience.as_deref(),
            Some("https://com.acme/crm.mcp.acme.internal")
        );
        assert_eq!(
            expanded.resource.as_deref(),
            Some("https://com.acme/crm.mcp.acme.internal/mcp")
        );
        assert_eq!(expanded.token_url, "https://sts.acme.example/oauth/token");
        assert_eq!(expanded.timeout_ms, 5_000);

        // Outside the allowlist: no expansion.
        assert!(template.expand("io.github.evil/exfil").is_none());
    }

    #[test]
    fn template_requires_allowed_targets() {
        let mut v = template_only();
        v["target_template"]["allowed_targets"] = json!([]);
        assert!(matches!(
            TokenExchangeConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyAllowedTargets
        ));
    }

    #[test]
    fn template_url_scheme_validated() {
        let mut v = template_only();
        v["target_template"]["token_url"] = json!("ftp://sts.example/token");
        assert!(matches!(
            TokenExchangeConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidTokenUrlScheme { .. }
        ));
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

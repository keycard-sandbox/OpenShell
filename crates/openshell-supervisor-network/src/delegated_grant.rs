// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Delegated credential grant.
//!
//! The gateway names one authorization server for requests to selected hosts.
//! For each such request the supervisor obtains a token for the request
//! origin, sent as the RFC 8707 `resource`, and replaces `Authorization` with
//! it. The authorization server decides whether the sandbox may reach the
//! resource and which credential it gets. A refusal denies the request.
//!
//! The supervisor authenticates with the sandbox instance's SPIFFE JWT-SVID in
//! `client_assertion`. With token exchange, the user-delegated access token
//! the workload sends in `Authorization` is the `subject_token`.
use openshell_core::host_pattern::HostSelector;
use openshell_core::oauth;
use openshell_core::proto::{
    DelegatedCredentialGrant, DelegatedGrantAssertionSource, DelegatedGrantType,
};

/// A validated delegated grant.
#[derive(Clone)]
pub struct DelegatedGrant {
    selector: HostSelector,
    grant_type: DelegatedGrantType,
}

impl DelegatedGrant {
    /// Validate a grant received from the gateway.
    pub fn from_proto(config: DelegatedCredentialGrant) -> Result<Self, &'static str> {
        oauth::parse_token_endpoint_url(&config.token_endpoint)
            .map_err(|_| "token_endpoint is not an allowed token endpoint URL")?;
        let selector = HostSelector::new(&config.include_hosts, &config.exclude_hosts)
            .map_err(|_| "include_hosts or exclude_hosts is not a valid host selector")?;
        match config.assertion_source() {
            DelegatedGrantAssertionSource::Spiffe => {}
            DelegatedGrantAssertionSource::Unspecified => {
                return Err("assertion_source is unspecified");
            }
        }
        let grant_type = match config.grant_type() {
            DelegatedGrantType::Unspecified => DelegatedGrantType::ClientCredentials,
            grant_type => grant_type,
        };
        if grant_type != DelegatedGrantType::TokenExchange && !config.subject_token_type.is_empty()
        {
            return Err("subject_token_type requires token_exchange");
        }
        Ok(Self {
            selector,
            grant_type,
        })
    }

    /// Whether requests to `host` use this grant.
    #[must_use]
    pub fn selects(&self, host: &str) -> bool {
        self.selector.matches(normalized_host(host))
    }

    /// Whether each request must present a user-delegated subject token.
    #[must_use]
    pub fn requires_subject_token(&self) -> bool {
        self.grant_type == DelegatedGrantType::TokenExchange
    }
}

/// The RFC 8707 resource indicator for a request: its origin, with the
/// scheme's default port omitted.
#[must_use]
pub fn resource_for(scheme: &str, host: &str, port: u16) -> String {
    let host = normalized_host(host).to_ascii_lowercase();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let default_port = match scheme {
        "http" => 80,
        _ => 443,
    };
    if port == default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

fn normalized_host(host: &str) -> &str {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

    fn grant_config(token_endpoint: &str) -> DelegatedCredentialGrant {
        DelegatedCredentialGrant {
            token_endpoint: token_endpoint.to_string(),
            assertion_source: DelegatedGrantAssertionSource::Spiffe.into(),
            include_hosts: vec!["api.example.com".to_string(), "*.example.org".to_string()],
            exclude_hosts: vec!["internal.example.org".to_string()],
            scopes: vec!["read".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn from_proto_validates_the_grant() {
        let valid = grant_config("https://as.example.com/token");
        let cases: [(&str, DelegatedCredentialGrant, Option<&str>); 6] = [
            ("valid", valid.clone(), None),
            (
                "plain http endpoint",
                DelegatedCredentialGrant {
                    token_endpoint: "http://as.example.com/token".into(),
                    ..valid.clone()
                },
                Some("token_endpoint is not an allowed token endpoint URL"),
            ),
            (
                "no hosts",
                DelegatedCredentialGrant {
                    include_hosts: vec![],
                    ..valid.clone()
                },
                Some("include_hosts or exclude_hosts is not a valid host selector"),
            ),
            (
                "unspecified source",
                DelegatedCredentialGrant {
                    assertion_source: DelegatedGrantAssertionSource::Unspecified.into(),
                    ..valid.clone()
                },
                Some("assertion_source is unspecified"),
            ),
            (
                "subject token type without token exchange",
                DelegatedCredentialGrant {
                    subject_token_type: JWT_TOKEN_TYPE.into(),
                    ..valid.clone()
                },
                Some("subject_token_type requires token_exchange"),
            ),
            (
                "subject token type with token exchange",
                DelegatedCredentialGrant {
                    grant_type: DelegatedGrantType::TokenExchange.into(),
                    subject_token_type: JWT_TOKEN_TYPE.into(),
                    ..valid
                },
                None,
            ),
        ];
        for (label, config, expected) in cases {
            assert_eq!(
                DelegatedGrant::from_proto(config).err(),
                expected,
                "{label}"
            );
        }
    }

    #[test]
    fn selects_included_hosts_unless_excluded() {
        let grant =
            DelegatedGrant::from_proto(grant_config("https://as.example.com/token")).unwrap();
        for (host, expected) in [
            ("api.example.com", true),
            ("API.Example.com.", true),
            ("web.example.org", true),
            ("internal.example.org", false),
            ("example.org", false),
            ("other.example.com", false),
        ] {
            assert_eq!(grant.selects(host), expected, "{host}");
        }
    }

    #[test]
    fn resource_is_the_request_origin() {
        for (scheme, host, port, expected) in [
            ("https", "api.example.com", 443, "https://api.example.com"),
            ("https", "API.example.com.", 443, "https://api.example.com"),
            (
                "https",
                "api.example.com",
                8443,
                "https://api.example.com:8443",
            ),
            ("http", "api.example.com", 80, "http://api.example.com"),
            ("http", "api.example.com", 443, "http://api.example.com:443"),
            ("https", "2001:db8::1", 443, "https://[2001:db8::1]"),
            ("https", "[2001:db8::1]", 8443, "https://[2001:db8::1]:8443"),
        ] {
            assert_eq!(resource_for(scheme, host, port), expected);
        }
    }
}

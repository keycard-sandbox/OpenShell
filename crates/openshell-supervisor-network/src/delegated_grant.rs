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
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use openshell_core::host_pattern::HostSelector;
use openshell_core::oauth::{
    self, ACCESS_TOKEN_TYPE, OAuthTokenResponse, TokenExchangeParams, TokenGrantClient,
    TokenGrantParams,
};
use openshell_core::proto::{
    DelegatedCredentialGrant, DelegatedGrantAssertionSource, DelegatedGrantType,
};
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};

use crate::token_grant::{effective_jwt_svid_audience, validate_access_token};

/// A validated delegated grant.
#[derive(Clone)]
pub struct DelegatedGrant {
    config: DelegatedCredentialGrant,
    selector: HostSelector,
    grant_type: DelegatedGrantType,
    /// Trusts the platform roots.
    client: Arc<TokenGrantClient>,
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
        let client = TokenGrantClient::new().map_err(|_| "the token client could not be built")?;
        Ok(Self {
            config,
            selector,
            grant_type,
            client: Arc::new(client),
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

    fn assertion_audience(&self) -> String {
        effective_jwt_svid_audience(&self.config.token_endpoint, &self.config.assertion_audience)
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

type GrantFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TokenGrantFailure>> + Send + 'a>>;

/// Obtains the workload assertion, a signed JWT, for a delegated grant.
/// Never log the assertion.
pub trait AssertionFetcher: Send + Sync {
    fn fetch<'a>(&'a self, grant: &'a DelegatedGrant) -> GrantFuture<'a, String>;
}

/// Fetches JWT-SVIDs from the sandbox instance's SPIFFE Workload API socket.
/// Without a socket, every fetch fails closed.
pub struct WorkloadAssertionFetcher {
    workload_api_socket: Option<PathBuf>,
}

impl AssertionFetcher for WorkloadAssertionFetcher {
    fn fetch<'a>(&'a self, grant: &'a DelegatedGrant) -> GrantFuture<'a, String> {
        Box::pin(async move {
            let socket = self.workload_api_socket.as_deref().ok_or_else(|| {
                TokenGrantFailure::new(
                    TokenGrantFailureKind::Configuration,
                    TokenGrantStage::WorkloadIdentity,
                )
            })?;
            crate::token_grant::fetch_jwt_svid_from_socket(socket, &grant.assertion_audience())
                .await
        })
    }
}

/// One delegated token request.
pub struct DelegatedTokenRequest<'a> {
    /// RFC 8707 resource indicator: the request origin.
    pub resource: &'a str,
    /// User-delegated access token from the workload's `Authorization`.
    /// Present exactly when the grant is a token exchange.
    pub subject_token: Option<&'a str>,
    /// Supervisor-minted ID of the HTTP exchange that needs the token.
    pub request_id: &'a str,
}

/// Obtains delegated grant tokens.
pub trait DelegatedGrantResolver: Send + Sync {
    /// Obtain a token, or the bounded failure that refused it.
    fn obtain<'a>(
        &'a self,
        grant: &'a DelegatedGrant,
        request: DelegatedTokenRequest<'a>,
    ) -> GrantFuture<'a, String>;
}

/// Asks the token endpoint for every request, with a new assertion.
///
/// NEVER cache tokens or assertions here. Every request must get the
/// authorization server's current decision. The server owns any caching.
pub struct TokenEndpointResolver<F> {
    fetcher: F,
}

impl<F: AssertionFetcher> TokenEndpointResolver<F> {
    pub fn new(fetcher: F) -> Self {
        Self { fetcher }
    }

    async fn assertion(&self, grant: &DelegatedGrant) -> Result<String, TokenGrantFailure> {
        let assertion = self.fetcher.fetch(grant).await?;
        if assertion.is_empty() {
            return Err(TokenGrantFailure::new(
                TokenGrantFailureKind::Unclassified,
                TokenGrantStage::WorkloadIdentity,
            ));
        }
        Ok(assertion)
    }

    async fn request_token(
        grant: &DelegatedGrant,
        assertion: &str,
        request: &DelegatedTokenRequest<'_>,
    ) -> Result<OAuthTokenResponse, TokenGrantFailure> {
        let client = grant.client.as_ref();
        let config = &grant.config;
        match (grant.grant_type, request.subject_token) {
            (DelegatedGrantType::TokenExchange, Some(subject_token)) => {
                oauth::post_oauth_token_exchange(
                    client,
                    &config.token_endpoint,
                    &TokenExchangeParams {
                        client_assertion: assertion,
                        client_assertion_type: &config.client_assertion_type,
                        subject_token,
                        subject_token_type: &config.subject_token_type,
                        audience: "",
                        resource: request.resource,
                        scopes: &config.scopes,
                        requested_token_type: ACCESS_TOKEN_TYPE,
                    },
                    Some(request.request_id),
                )
                .await
            }
            (DelegatedGrantType::TokenExchange, None) | (_, Some(_)) => {
                Err(TokenGrantFailure::new(
                    TokenGrantFailureKind::Configuration,
                    TokenGrantStage::Injection,
                ))
            }
            (_, None) => {
                oauth::post_oauth_token_grant(
                    client,
                    &config.token_endpoint,
                    &TokenGrantParams {
                        client_assertion: assertion,
                        client_assertion_type: &config.client_assertion_type,
                        audience: "",
                        resource: request.resource,
                        scopes: &config.scopes,
                    },
                    Some(request.request_id),
                )
                .await
            }
        }
    }
}

impl<F: AssertionFetcher> DelegatedGrantResolver for TokenEndpointResolver<F> {
    fn obtain<'a>(
        &'a self,
        grant: &'a DelegatedGrant,
        request: DelegatedTokenRequest<'a>,
    ) -> GrantFuture<'a, String> {
        Box::pin(async move {
            let assertion = self.assertion(grant).await?;
            let response = Self::request_token(grant, &assertion, &request).await?;
            validate_access_token(&response.access_token)?;
            Ok(response.access_token)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    /// Returns a fixed assertion and counts fetches.
    struct FixedAssertion {
        fetches: AtomicUsize,
    }

    impl AssertionFetcher for FixedAssertion {
        fn fetch<'a>(&'a self, _grant: &'a DelegatedGrant) -> GrantFuture<'a, String> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok("workload-assertion".to_string()) })
        }
    }

    fn parse_form(body: &[u8]) -> HashMap<String, String> {
        let decode = |value: &str| {
            let bytes = value.replace('+', " ").into_bytes();
            let mut decoded = Vec::with_capacity(bytes.len());
            let mut index = 0;
            while index < bytes.len() {
                if bytes[index] == b'%' && index + 2 < bytes.len() {
                    let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
                    decoded.push(u8::from_str_radix(hex, 16).unwrap());
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            String::from_utf8(decoded).unwrap()
        };
        std::str::from_utf8(body)
            .unwrap()
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, value)| (decode(name), decode(value)))
            .collect()
    }

    /// Serves one canned response per connection and records each form body.
    async fn token_endpoint(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (
        String,
        tokio::task::JoinHandle<Vec<HashMap<String, String>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut forms = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let n = stream.read(&mut chunk).await.unwrap();
                    request.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&request);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            forms.push(parse_form(&request[end + 4..]));
                            break;
                        }
                    }
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            forms
        });
        (format!("http://{addr}/token"), handle)
    }

    fn request<'a>(resource: &'a str, subject_token: Option<&'a str>) -> DelegatedTokenRequest<'a> {
        DelegatedTokenRequest {
            resource,
            subject_token,
            request_id: "req-1",
        }
    }

    fn sorted_fields(form: &HashMap<String, String>) -> Vec<String> {
        let mut fields = form
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
        fields.sort();
        fields
    }

    #[tokio::test]
    async fn client_credentials_ask_for_the_resource_on_every_request() {
        // The repeated resource and a long `expires_in` would hit a cache, so
        // the third request reaching the endpoint shows there is none.
        let (endpoint, server) = token_endpoint(vec![
            (
                "200 OK",
                r#"{"access_token":"github-token-1","expires_in":600}"#,
            ),
            (
                "200 OK",
                r#"{"access_token":"linear-token","expires_in":600}"#,
            ),
            (
                "200 OK",
                r#"{"access_token":"github-token-2","expires_in":600}"#,
            ),
        ])
        .await;
        let grant = DelegatedGrant::from_proto(grant_config(&endpoint)).unwrap();
        let resolver = TokenEndpointResolver::new(FixedAssertion {
            fetches: AtomicUsize::new(0),
        });
        let mut tokens = Vec::new();
        for resource in [
            "https://api.github.com",
            "https://api.linear.app",
            "https://api.github.com",
        ] {
            tokens.push(
                resolver
                    .obtain(&grant, request(resource, None))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(tokens, ["github-token-1", "linear-token", "github-token-2"]);
        assert_eq!(resolver.fetcher.fetches.load(Ordering::SeqCst), 3);

        let forms = server.await.unwrap();
        let expected = |resource: &str| {
            vec![
                "client_assertion=workload-assertion".to_string(),
                format!(
                    "client_assertion_type={}",
                    oauth::DEFAULT_CLIENT_ASSERTION_TYPE
                ),
                "grant_type=client_credentials".to_string(),
                format!("resource={resource}"),
                "scope=read".to_string(),
            ]
        };
        assert_eq!(
            forms.iter().map(sorted_fields).collect::<Vec<_>>(),
            [
                expected("https://api.github.com"),
                expected("https://api.linear.app"),
                expected("https://api.github.com")
            ]
        );
    }

    #[tokio::test]
    async fn token_exchange_sends_the_user_token_as_subject_on_every_request() {
        let (endpoint, server) = token_endpoint(vec![
            (
                "200 OK",
                r#"{"access_token":"alice-github-1","expires_in":600}"#,
            ),
            (
                "200 OK",
                r#"{"access_token":"bob-github","expires_in":600}"#,
            ),
            (
                "200 OK",
                r#"{"access_token":"alice-github-2","expires_in":600}"#,
            ),
        ])
        .await;
        let grant = DelegatedGrant::from_proto(DelegatedCredentialGrant {
            grant_type: DelegatedGrantType::TokenExchange.into(),
            scopes: vec![],
            ..grant_config(&endpoint)
        })
        .unwrap();
        let resolver = TokenEndpointResolver::new(FixedAssertion {
            fetches: AtomicUsize::new(0),
        });
        let mut tokens = Vec::new();
        for subject in ["alice-token", "bob-token", "alice-token"] {
            tokens.push(
                resolver
                    .obtain(&grant, request("https://api.github.com", Some(subject)))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(tokens, ["alice-github-1", "bob-github", "alice-github-2"]);

        let forms = server.await.unwrap();
        let expected = |subject: &str| {
            vec![
                "client_assertion=workload-assertion".to_string(),
                format!(
                    "client_assertion_type={}",
                    oauth::DEFAULT_CLIENT_ASSERTION_TYPE
                ),
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                format!("requested_token_type={ACCESS_TOKEN_TYPE}"),
                "resource=https://api.github.com".to_string(),
                format!("subject_token={subject}"),
                format!("subject_token_type={ACCESS_TOKEN_TYPE}"),
            ]
        };
        assert_eq!(
            forms.iter().map(sorted_fields).collect::<Vec<_>>(),
            [
                expected("alice-token"),
                expected("bob-token"),
                expected("alice-token")
            ]
        );
    }

    #[tokio::test]
    async fn subject_token_must_match_the_grant_type() {
        let client_credentials =
            DelegatedGrant::from_proto(grant_config("https://as.example.com/token")).unwrap();
        let token_exchange = DelegatedGrant::from_proto(DelegatedCredentialGrant {
            grant_type: DelegatedGrantType::TokenExchange.into(),
            ..grant_config("https://as.example.com/token")
        })
        .unwrap();
        let resolver = TokenEndpointResolver::new(FixedAssertion {
            fetches: AtomicUsize::new(0),
        });
        for (grant, subject) in [
            (&client_credentials, Some("user-token")),
            (&token_exchange, None),
        ] {
            let failure = resolver
                .obtain(grant, request("https://api.github.com", subject))
                .await
                .unwrap_err();
            assert_eq!(
                failure,
                TokenGrantFailure::new(
                    TokenGrantFailureKind::Configuration,
                    TokenGrantStage::Injection
                )
            );
        }
    }

    #[tokio::test]
    async fn a_refusal_does_not_affect_the_next_request() {
        let (endpoint, server) = token_endpoint(vec![
            ("400 Bad Request", r#"{"error":"invalid_target"}"#),
            ("200 OK", r#"{"access_token":"granted","expires_in":600}"#),
        ])
        .await;
        let grant = DelegatedGrant::from_proto(grant_config(&endpoint)).unwrap();
        let resolver = TokenEndpointResolver::new(FixedAssertion {
            fetches: AtomicUsize::new(0),
        });
        // A plaintext token endpoint cannot authenticate a refusal, so it
        // stays unclassified rather than access_denied.
        let refused = resolver
            .obtain(&grant, request("https://api.github.com", None))
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), TokenGrantFailureKind::Unclassified);
        assert_eq!(refused.upstream_status(), Some(400));
        let token = resolver
            .obtain(&grant, request("https://api.github.com", None))
            .await
            .unwrap();
        assert_eq!(token, "granted");
        assert_eq!(resolver.fetcher.fetches.load(Ordering::SeqCst), 2);
        assert_eq!(server.await.unwrap().len(), 2);
    }
}

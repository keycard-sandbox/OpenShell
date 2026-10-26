// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Delegated grant injection. Every case runs one request through
//! `inject_if_needed` and pins the full outcome: the rewritten credential
//! headers or the refusal, and every token request the resolver received.

use super::test_support::{TokenGrantTestFixture, inject_if_needed};
use super::*;
use crate::delegated_grant::{
    DelegatedGrant, DelegatedGrantBinding, DelegatedGrantResolver, DelegatedGrantSlot,
    DelegatedGrantState, DelegatedTokenRequest,
};
use crate::l7::provider::BodyLength;
use openshell_core::proto::{
    DelegatedCredentialGrant, DelegatedGrantAssertionSource, DelegatedGrantType,
};
use std::sync::Mutex;

const REQUEST_ID: &str = "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d";
const SERVICE: &str = "api.example.com\t443\t/v1/**\trev:7\tprovider:service";
const IDENTITY: &str = "api.example.com\t443\t/v1/**\trev:7\tprovider:identity";

/// One token request the resolver received: resource and subject token.
type Received = (String, Option<String>);

/// Records each token request and returns a fixed result.
struct FakeResolver {
    result: Result<&'static str, TokenGrantFailure>,
    received: Mutex<Vec<Received>>,
}

impl DelegatedGrantResolver for FakeResolver {
    fn obtain<'a>(
        &'a self,
        _grant: &'a DelegatedGrant,
        request: DelegatedTokenRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<String, TokenGrantFailure>> + Send + 'a>> {
        assert_eq!(request.request_id, REQUEST_ID);
        self.received.lock().unwrap().push((
            request.resource.to_string(),
            request.subject_token.map(str::to_string),
        ));
        let result = self.result.map(str::to_string);
        Box::pin(async move { result })
    }
}

fn request(authorization: &[&str]) -> L7Request {
    let mut raw = "GET /v1/projects HTTP/1.1\r\nHost: api.example.com\r\n".to_string();
    for value in authorization {
        raw.push_str("Authorization: ");
        raw.push_str(value);
        raw.push_str("\r\n");
    }
    raw.push_str("X-Workload-Jwt: agent-identity\r\n\r\n");
    L7Request {
        action: "GET".into(),
        target: "/v1/projects".into(),
        query_params: HashMap::default(),
        raw_header: raw.into_bytes(),
        body_length: BodyLength::None,
    }
}

fn active(grant_type: DelegatedGrantType, resolver: Arc<FakeResolver>) -> DelegatedGrantState {
    DelegatedGrantState::Active(DelegatedGrantBinding {
        grant: Arc::new(
            DelegatedGrant::from_proto(DelegatedCredentialGrant {
                token_endpoint: "https://as.example.com/token".into(),
                assertion_source: DelegatedGrantAssertionSource::Spiffe.into(),
                grant_type: grant_type.into(),
                include_hosts: vec!["api.example.com".into()],
                ..Default::default()
            })
            .unwrap(),
        ),
        resolver,
    })
}

/// Provider grants for `Authorization` and `X-Workload-Jwt` on the same host.
fn provider_fixture() -> TokenGrantTestFixture {
    let fixture = TokenGrantTestFixture::success(SERVICE, "provider-token");
    let mut identity = fixture.dynamic_credentials().read().unwrap()[SERVICE].clone();
    identity.name = "identity".into();
    identity.auth_style = "header".into();
    identity.header_name = "X-Workload-Jwt".into();
    fixture.add_credential(IDENTITY, identity, Ok("identity-token"));
    fixture
}

fn credential_headers(raw_header: &[u8]) -> Vec<String> {
    String::from_utf8(raw_header.to_vec())
        .unwrap()
        .split("\r\n")
        .filter(|line| {
            let name = line
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            name == "authorization" || name == "x-workload-jwt"
        })
        .map(str::to_string)
        .collect()
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Headers(Vec<String>),
    Refused {
        denial: bool,
        kind: TokenGrantFailureKind,
    },
}

#[derive(Clone, Copy)]
enum Grant {
    ClientCredentials,
    TokenExchange,
    Rejected,
}

struct Case {
    name: &'static str,
    grant: Grant,
    host: &'static str,
    port: u16,
    default_port: u16,
    authorization: &'static [&'static str],
    providers: bool,
    result: Result<&'static str, TokenGrantFailure>,
    outcome: Outcome,
    received: &'static [(&'static str, Option<&'static str>)],
    provider_requests: &'static [&'static str],
}

impl Default for Case {
    fn default() -> Self {
        Self {
            name: "",
            grant: Grant::ClientCredentials,
            host: "api.example.com",
            port: 443,
            default_port: 443,
            authorization: &["Bearer agent-token"],
            providers: false,
            result: Ok("delegated-token"),
            outcome: Outcome::Headers(Vec::new()),
            received: &[],
            provider_requests: &[],
        }
    }
}

fn headers(lines: &[&str]) -> Outcome {
    Outcome::Headers(lines.iter().map(ToString::to_string).collect())
}

fn refused(denial: bool, kind: TokenGrantFailureKind) -> Outcome {
    Outcome::Refused { denial, kind }
}

const GITHUB: &str = "https://api.example.com";

#[tokio::test]
async fn delegated_grant_outcomes() {
    let failure = |kind| TokenGrantFailure::new(kind, TokenGrantStage::TokenEndpoint);
    let delegated = &[
        "X-Workload-Jwt: agent-identity",
        "Authorization: Bearer delegated-token",
    ];
    let cases = [
        Case {
            name: "selected host replaces Authorization",
            outcome: headers(delegated),
            received: &[(GITHUB, None)],
            ..Case::default()
        },
        Case {
            name: "non-default port is part of the resource",
            port: 8443,
            outcome: headers(delegated),
            received: &[("https://api.example.com:8443", None)],
            ..Case::default()
        },
        Case {
            name: "unselected host is untouched",
            host: "other.example.com",
            outcome: headers(&[
                "Authorization: Bearer agent-token",
                "X-Workload-Jwt: agent-identity",
            ]),
            ..Case::default()
        },
        Case {
            name: "authorization server denial",
            result: Err(failure(TokenGrantFailureKind::AccessDenied)),
            outcome: refused(true, TokenGrantFailureKind::AccessDenied),
            received: &[(GITHUB, None)],
            ..Case::default()
        },
        Case {
            name: "user has not authorized the resource",
            result: Err(failure(
                TokenGrantFailureKind::ProviderAuthorizationRequired,
            )),
            outcome: refused(true, TokenGrantFailureKind::ProviderAuthorizationRequired),
            received: &[(GITHUB, None)],
            ..Case::default()
        },
        Case {
            name: "authorization server outage is not a denial",
            result: Err(failure(TokenGrantFailureKind::Unavailable)),
            outcome: refused(false, TokenGrantFailureKind::Unavailable),
            received: &[(GITHUB, None)],
            ..Case::default()
        },
        Case {
            name: "plaintext to a selected host is denied without a grant request",
            port: 80,
            default_port: 80,
            outcome: refused(true, TokenGrantFailureKind::AccessDenied),
            ..Case::default()
        },
        Case {
            name: "rejected grant refuses every host",
            grant: Grant::Rejected,
            host: "other.example.com",
            outcome: refused(false, TokenGrantFailureKind::Configuration),
            ..Case::default()
        },
        Case {
            name: "token exchange sends the workload's bearer token as subject",
            grant: Grant::TokenExchange,
            authorization: &["bearer user-delegated-token"],
            outcome: headers(delegated),
            received: &[(GITHUB, Some("user-delegated-token"))],
            ..Case::default()
        },
        Case {
            name: "token exchange without Authorization is denied",
            grant: Grant::TokenExchange,
            authorization: &[],
            outcome: refused(true, TokenGrantFailureKind::ProviderAuthorizationRequired),
            ..Case::default()
        },
        Case {
            name: "token exchange with a non-bearer credential is denied",
            grant: Grant::TokenExchange,
            authorization: &["Basic dXNlcjpwYXNz"],
            outcome: refused(true, TokenGrantFailureKind::ProviderAuthorizationRequired),
            ..Case::default()
        },
        Case {
            name: "token exchange with two Authorization headers is denied",
            grant: Grant::TokenExchange,
            authorization: &["Bearer first", "Bearer second"],
            outcome: refused(true, TokenGrantFailureKind::ProviderAuthorizationRequired),
            ..Case::default()
        },
        Case {
            name: "delegated grant owns Authorization over a provider grant",
            providers: true,
            outcome: headers(&[
                "X-Workload-Jwt: identity-token",
                "Authorization: Bearer delegated-token",
            ]),
            received: &[(GITHUB, None)],
            provider_requests: &[IDENTITY],
            ..Case::default()
        },
        Case {
            name: "denial stops provider grants too",
            providers: true,
            result: Err(failure(TokenGrantFailureKind::AccessDenied)),
            outcome: refused(true, TokenGrantFailureKind::AccessDenied),
            received: &[(GITHUB, None)],
            ..Case::default()
        },
    ];
    for case in cases {
        let resolver = Arc::new(FakeResolver {
            result: case.result,
            received: Mutex::new(Vec::new()),
        });
        let state = match case.grant {
            Grant::ClientCredentials => {
                active(DelegatedGrantType::ClientCredentials, resolver.clone())
            }
            Grant::TokenExchange => active(DelegatedGrantType::TokenExchange, resolver.clone()),
            Grant::Rejected => DelegatedGrantState::Rejected,
        };
        let fixture = case.providers.then(provider_fixture);
        let ctx = L7EvalContext {
            host: case.host.into(),
            port: case.port,
            request_default_port: Some(case.default_port),
            provider_credentials: fixture
                .as_ref()
                .map(TokenGrantTestFixture::provider_credentials),
            token_grant_resolver: fixture.as_ref().map(TokenGrantTestFixture::resolver),
            delegated_grant: Some(DelegatedGrantSlot::holding(state)),
            ..Default::default()
        };
        let outcome = match inject_if_needed(request(case.authorization), &ctx, REQUEST_ID).await {
            Ok(rewritten) => Outcome::Headers(credential_headers(&rewritten.raw_header)),
            Err(refusal) => Outcome::Refused {
                denial: refusal.is_denial(),
                kind: refusal.failure().kind(),
            },
        };
        assert_eq!(outcome, case.outcome, "{}", case.name);
        let expected: Vec<Received> = case
            .received
            .iter()
            .map(|(resource, subject)| (resource.to_string(), subject.map(str::to_string)))
            .collect();
        assert_eq!(
            *resolver.received.lock().unwrap(),
            expected,
            "{}",
            case.name
        );
        if let Some(fixture) = fixture {
            fixture.assert_requested_keys(case.provider_requests);
        }
    }
}

#[tokio::test]
async fn each_request_reads_the_installed_grant() {
    let slot = Arc::new(DelegatedGrantSlot::default());
    let ctx = L7EvalContext {
        host: "api.example.com".into(),
        port: 443,
        request_default_port: Some(443),
        delegated_grant: Some(slot.clone()),
        ..Default::default()
    };
    let first = inject_if_needed(request(&["Bearer agent-token"]), &ctx, REQUEST_ID)
        .await
        .unwrap();
    assert_eq!(
        credential_headers(&first.raw_header),
        [
            "Authorization: Bearer agent-token",
            "X-Workload-Jwt: agent-identity"
        ]
    );
    // A grant the supervisor rejects takes effect on the same context.
    slot.install(Some(&DelegatedCredentialGrant {
        token_endpoint: "http://as.example.com/token".into(),
        include_hosts: vec!["api.example.com".into()],
        ..Default::default()
    }));
    let refusal = inject_if_needed(request(&["Bearer agent-token"]), &ctx, REQUEST_ID)
        .await
        .unwrap_err();
    assert_eq!(
        refusal.failure(),
        TokenGrantFailure::new(
            TokenGrantFailureKind::Configuration,
            TokenGrantStage::Configuration
        )
    );
    assert!(!refusal.is_denial());
}

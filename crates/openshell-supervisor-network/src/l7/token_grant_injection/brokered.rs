// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential broker decisions combined with provider token grants.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use openshell_core::host_pattern::HostSelector;
use openshell_core::proto::credential_broker::v1::{
    CredentialDeny, CredentialGrant, CredentialPass, CredentialPlacement, DenyReason,
    HttpCredentialRequest, HttpCredentialResult, http_credential_result,
};
use tonic::Status;

use super::test_support::{TokenGrantTestFixture, inject_if_needed};
use super::*;
use crate::credential_broker::{
    BrokerEndpoint, BrokerState, CredentialBroker, CredentialBrokerSlot,
};
use crate::l7::provider::BodyLength;

const SERVICE: &str = "api.example.com\t443\t/v1/**\trev:7\tprovider:service";
const IDENTITY: &str = "api.example.com\t443\t/v1/**\trev:7\tprovider:identity";
const REQUEST_ID: &str = "5b4a3f2e-1d0c-4b9a-8f7e-6d5c4b3a2f1e";

/// Answers every call with one decision and counts the calls.
struct FixedBroker {
    decision: http_credential_result::Decision,
    calls: Mutex<usize>,
}

#[tonic::async_trait]
impl BrokerEndpoint for FixedBroker {
    async fn grant_http_request(
        &self,
        _request: HttpCredentialRequest,
        _timeout: Duration,
    ) -> Result<HttpCredentialResult, Status> {
        *self.calls.lock().unwrap() += 1;
        Ok(HttpCredentialResult {
            decision: Some(self.decision.clone()),
        })
    }
}

fn broker_slot(
    decision: http_credential_result::Decision,
) -> (Arc<CredentialBrokerSlot>, Arc<FixedBroker>) {
    let endpoint = Arc::new(FixedBroker {
        decision,
        calls: Mutex::new(0),
    });
    let broker = CredentialBroker::new(
        HostSelector::new(&["api.example.com".to_string()], &[]).unwrap(),
        Duration::from_secs(1),
        "sandbox-1",
        endpoint.clone(),
    );
    (
        CredentialBrokerSlot::holding(BrokerState::Active(Arc::new(broker))),
        endpoint,
    )
}

fn grant_authorization_and_key() -> http_credential_result::Decision {
    http_credential_result::Decision::Grant(CredentialGrant {
        placements: vec![
            CredentialPlacement {
                auth_style: "bearer".to_string(),
                value: "broker-token".to_string(),
                ..Default::default()
            },
            CredentialPlacement {
                auth_style: "query".to_string(),
                query_param: "api_key".to_string(),
                value: "broker key".to_string(),
                ..Default::default()
            },
        ],
    })
}

fn request() -> L7Request {
    L7Request {
        action: "GET".into(),
        target: "/v1/items?api_key=agent&page=2".into(),
        query_params: HashMap::from([
            ("api_key".to_string(), vec!["agent".to_string()]),
            ("page".to_string(), vec!["2".to_string()]),
        ]),
        raw_header: b"GET /v1/items?api_key=agent&page=2 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer agent-token\r\nauthorization: duplicate\r\nX-Workload-Jwt: agent-identity\r\n\r\n".to_vec(),
        body_length: BodyLength::None,
    }
}

/// A context with two provider grants: `Authorization` from SERVICE and
/// `X-Workload-Jwt` from IDENTITY.
fn provider_context(
    host: &str,
    broker: Option<Arc<CredentialBrokerSlot>>,
) -> (TokenGrantTestFixture, L7EvalContext) {
    let fixture = TokenGrantTestFixture::success(SERVICE, "service-token");
    let mut identity = fixture.dynamic_credentials().read().unwrap()[SERVICE].clone();
    identity.name = "identity".into();
    identity.auth_style = "header".into();
    identity.header_name = "X-Workload-Jwt".into();
    fixture.add_credential(IDENTITY, identity, Ok("identity-token"));
    let ctx = L7EvalContext {
        host: host.into(),
        port: 443,
        provider_credentials: Some(fixture.provider_credentials()),
        token_grant_resolver: Some(fixture.resolver()),
        credential_broker: broker,
        ..Default::default()
    };
    (fixture, ctx)
}

fn header_block(request: &L7Request) -> String {
    String::from_utf8(request.raw_header.clone()).unwrap()
}

#[tokio::test]
async fn grant_without_provider_credentials_replaces_headers_and_query() {
    let (slot, endpoint) = broker_slot(grant_authorization_and_key());
    let ctx = L7EvalContext {
        host: "api.example.com".into(),
        port: 443,
        credential_broker: Some(slot),
        ..Default::default()
    };
    let rewritten = inject_if_needed(request(), &ctx, REQUEST_ID).await.unwrap();
    assert_eq!(
        header_block(&rewritten),
        "GET /v1/items?page=2&api_key=broker%20key HTTP/1.1\r\nHost: api.example.com\r\nX-Workload-Jwt: agent-identity\r\nAuthorization: Bearer broker-token\r\n\r\n"
    );
    assert_eq!(rewritten.target, "/v1/items?page=2&api_key=broker%20key");
    assert_eq!(
        rewritten.query_params["api_key"],
        vec!["broker key".to_string()]
    );
    assert_eq!(*endpoint.calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn broker_owns_the_headers_it_writes_and_provider_grants_fill_the_rest() {
    let (slot, _) = broker_slot(grant_authorization_and_key());
    let (fixture, ctx) = provider_context("api.example.com", Some(slot));
    let rewritten = inject_if_needed(request(), &ctx, REQUEST_ID).await.unwrap();
    let block = header_block(&rewritten);
    assert_eq!(
        block
            .matches("Authorization: Bearer broker-token\r\n")
            .count(),
        1
    );
    assert!(block.contains("X-Workload-Jwt: identity-token\r\n"));
    assert!(!block.contains("service-token"));
    fixture.assert_requested_keys(&[IDENTITY]);
}

#[tokio::test]
async fn pass_leaves_provider_grants_unchanged() {
    let (slot, endpoint) = broker_slot(http_credential_result::Decision::Pass(CredentialPass {}));
    let (fixture, ctx) = provider_context("api.example.com", Some(slot));
    let rewritten = inject_if_needed(request(), &ctx, REQUEST_ID).await.unwrap();
    let block = header_block(&rewritten);
    assert!(block.contains("Authorization: Bearer service-token\r\n"));
    assert!(block.contains("X-Workload-Jwt: identity-token\r\n"));
    assert_eq!(rewritten.target, request().target);
    fixture.assert_requested_keys(&[SERVICE, IDENTITY]);
    assert_eq!(*endpoint.calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn denial_stops_every_grant() {
    for (reason, kind) in [
        (
            DenyReason::AccessDenied,
            TokenGrantFailureKind::AccessDenied,
        ),
        (
            DenyReason::AuthorizationRequired,
            TokenGrantFailureKind::ProviderAuthorizationRequired,
        ),
    ] {
        let (slot, _) = broker_slot(http_credential_result::Decision::Deny(CredentialDeny {
            reason: reason.into(),
        }));
        let (fixture, ctx) = provider_context("api.example.com", Some(slot));
        let refusal = inject_if_needed(request(), &ctx, REQUEST_ID)
            .await
            .expect_err("denied");
        assert!(refusal.is_denial(), "{reason:?}");
        assert_eq!(refusal.failure().kind(), kind);
        assert_eq!(refusal.failure().stage(), TokenGrantStage::CredentialBroker);
        fixture.assert_no_requests();
    }
}

#[tokio::test]
async fn unselected_hosts_do_not_call_the_broker() {
    let (slot, endpoint) = broker_slot(grant_authorization_and_key());
    let (fixture, mut ctx) = provider_context("api.example.com", Some(slot));
    ctx.host = "other.example.com".into();
    // The provider grants are bound to api.example.com, so nothing applies.
    let rewritten = inject_if_needed(request(), &ctx, REQUEST_ID).await.unwrap();
    assert_eq!(rewritten.raw_header, request().raw_header);
    assert_eq!(*endpoint.calls.lock().unwrap(), 0);
    fixture.assert_no_requests();
}

#[tokio::test]
async fn rejected_registration_refuses_without_a_denial() {
    let slot = CredentialBrokerSlot::holding(BrokerState::Rejected);
    let (fixture, ctx) = provider_context("api.example.com", Some(slot));
    let refusal = inject_if_needed(request(), &ctx, REQUEST_ID)
        .await
        .expect_err("rejected registration refuses");
    assert!(!refusal.is_denial());
    assert_eq!(
        refusal.failure().kind(),
        TokenGrantFailureKind::Configuration
    );
    fixture.assert_no_requests();
}

// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-registered credential broker.
//!
//! The gateway names one broker for requests to selected hosts. For each such
//! inspected HTTP request the supervisor asks the broker for a decision:
//! replace credentials, send the request on, or deny it with 403. The broker
//! authenticates the call with the sandbox's extension token.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use openshell_core::credential_broker::{
    EXTENSION_CREDENTIAL_NAME, MAX_PLACEMENT_VALUE_BYTES, MAX_PLACEMENTS,
};
use openshell_core::host_pattern::HostSelector;
use openshell_core::proto::SupervisorCredentialBroker;
use openshell_core::proto::credential_broker::v1::credential_broker_client::CredentialBrokerClient;
use openshell_core::proto::credential_broker::v1::{
    CredentialPlacement, DenyReason, HttpCredentialRequest, HttpCredentialResult,
    http_credential_result,
};
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};
use openshell_extension_core::{
    BearerTokenInterceptor, ExtensionChannelConfig, ExtensionCredentialStore, ExtensionServerTrust,
    connect_channel_lazy,
};
use openshell_ocsf::{
    ConfigStateChangeBuilder, DetectionFindingBuilder, FindingInfo, SeverityId, StateId, StatusId,
    ctx::ctx as ocsf_ctx, ocsf_emit,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Status};

pub use crate::l7::credential_placement::Placement;
use crate::l7::credential_placement::{self, AuthStyle};

/// Longest query parameter name a placement may target.
const MAX_QUERY_PARAMETER_NAME_BYTES: usize = 256;

/// Headers a placement must not write: routing, framing, and hop-by-hop
/// fields. `x-openshell-*` and `Connection`-nominated headers are refused too.
const PROTECTED_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// What the broker decided for a request it did not deny.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerDecision {
    /// Replace these request fields.
    Grant(Vec<Placement>),
    /// Send the request without a broker credential.
    Pass,
}

/// The request fields the broker sees.
pub struct BrokerRequest<'a> {
    pub request_id: &'a str,
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    /// Raw request header block, used for `Authorization` and
    /// `Connection`-nominated headers.
    pub raw_header: &'a [u8],
}

/// Sends one decision request to the broker.
#[tonic::async_trait]
pub trait BrokerEndpoint: Send + Sync {
    async fn grant_http_request(
        &self,
        request: HttpCredentialRequest,
        timeout: Duration,
    ) -> Result<HttpCredentialResult, Status>;
}

/// The broker reached over gRPC with the sandbox's extension token.
struct GrpcBrokerEndpoint {
    channel: Channel,
    /// `None` when the registration opts out of extension authentication.
    credentials: Option<ExtensionCredentialStore>,
}

#[tonic::async_trait]
impl BrokerEndpoint for GrpcBrokerEndpoint {
    async fn grant_http_request(
        &self,
        request: HttpCredentialRequest,
        timeout: Duration,
    ) -> Result<HttpCredentialResult, Status> {
        let interceptor = match &self.credentials {
            None => BearerTokenInterceptor::disabled(),
            Some(store) => store
                .get(EXTENSION_CREDENTIAL_NAME)
                .ok_or_else(|| Status::unavailable("credential broker token is not installed"))?
                .interceptor(),
        };
        let mut client =
            CredentialBrokerClient::new(InterceptedService::new(self.channel.clone(), interceptor));
        let mut request = tonic::Request::new(request);
        request.set_timeout(timeout);
        tokio::time::timeout(timeout, client.grant_http_request(request))
            .await
            .map_err(|_| Status::deadline_exceeded("credential broker timed out"))?
            .map(tonic::Response::into_inner)
    }
}

/// A validated broker registration for one sandbox instance.
pub struct CredentialBroker {
    selector: HostSelector,
    timeout: Duration,
    forward_authorization: bool,
    sandbox_id: String,
    endpoint: Arc<dyn BrokerEndpoint>,
}

impl CredentialBroker {
    /// Validate a registration and build a channel that connects on first use.
    fn connect(
        registration: &SupervisorCredentialBroker,
        sandbox_id: &str,
        credentials: &ExtensionCredentialStore,
    ) -> Result<Self, &'static str> {
        let validated = openshell_core::credential_broker::validate(registration)?;
        let mut channel_config = ExtensionChannelConfig::new(&registration.grpc_endpoint);
        if !registration.tls_ca_cert_pem.is_empty() {
            channel_config = channel_config.with_server_trust(ExtensionServerTrust::CustomCaPem(
                registration.tls_ca_cert_pem.clone(),
            ));
        }
        let channel = connect_channel_lazy(&channel_config)
            .map_err(|_| "grpc_endpoint is not a usable gRPC endpoint")?;
        let endpoint = GrpcBrokerEndpoint {
            channel,
            credentials: (!registration.allow_insecure_transport).then(|| credentials.clone()),
        };
        Ok(Self::new(
            validated.selector,
            validated.timeout,
            registration.forward_authorization,
            sandbox_id,
            Arc::new(endpoint),
        ))
    }

    /// A broker that sends its requests to `endpoint`.
    #[must_use]
    pub fn new(
        selector: HostSelector,
        timeout: Duration,
        forward_authorization: bool,
        sandbox_id: &str,
        endpoint: Arc<dyn BrokerEndpoint>,
    ) -> Self {
        Self {
            selector,
            timeout,
            forward_authorization,
            sandbox_id: sandbox_id.to_string(),
            endpoint,
        }
    }

    /// Whether requests to `host` go to the broker.
    #[must_use]
    pub fn selects(&self, host: &str) -> bool {
        self.selector.matches(normalized_host(host))
    }

    /// Ask the broker for a decision.
    ///
    /// A denial is a failure of kind `AccessDenied` or
    /// `ProviderAuthorizationRequired`. Every failure has stage
    /// `CredentialBroker`.
    pub async fn decide(
        &self,
        request: BrokerRequest<'_>,
    ) -> Result<BrokerDecision, TokenGrantFailure> {
        let failure = |kind| TokenGrantFailure::new(kind, TokenGrantStage::CredentialBroker);
        let authorization = if self.forward_authorization {
            header_values(request.raw_header, "authorization")
        } else {
            Vec::new()
        };
        let result = self
            .endpoint
            .grant_http_request(
                HttpCredentialRequest {
                    request_id: request.request_id.to_string(),
                    sandbox_id: self.sandbox_id.clone(),
                    method: request.method.to_string(),
                    scheme: request.scheme.to_string(),
                    host: normalized_host(request.host).to_ascii_lowercase(),
                    port: u32::from(request.port),
                    path: request.path.to_string(),
                    authorization,
                },
                self.timeout,
            )
            .await
            .map_err(|status| failure(status_failure_kind(status.code())))?;
        match result.decision {
            Some(http_credential_result::Decision::Pass(_)) => Ok(BrokerDecision::Pass),
            Some(http_credential_result::Decision::Deny(deny)) => {
                Err(failure(match deny.reason() {
                    DenyReason::AuthorizationRequired => {
                        TokenGrantFailureKind::ProviderAuthorizationRequired
                    }
                    DenyReason::Unspecified | DenyReason::AccessDenied => {
                        TokenGrantFailureKind::AccessDenied
                    }
                }))
            }
            Some(http_credential_result::Decision::Grant(grant)) => {
                let placements = validate_placements(
                    grant.placements,
                    &connection_nominated(request.raw_header),
                )
                .map_err(|()| failure(TokenGrantFailureKind::Unclassified))?;
                // NEVER send a broker credential in cleartext.
                if request.scheme != "https" {
                    return Err(failure(TokenGrantFailureKind::Configuration));
                }
                Ok(BrokerDecision::Grant(placements))
            }
            None => Err(failure(TokenGrantFailureKind::Unclassified)),
        }
    }
}

/// The failure kind for a gRPC error from the broker.
fn status_failure_kind(code: Code) -> TokenGrantFailureKind {
    match code {
        Code::Unavailable | Code::ResourceExhausted => TokenGrantFailureKind::Unavailable,
        Code::DeadlineExceeded => TokenGrantFailureKind::Timeout,
        Code::Unauthenticated | Code::PermissionDenied => {
            TokenGrantFailureKind::WorkloadIdentityRejected
        }
        Code::InvalidArgument | Code::FailedPrecondition => TokenGrantFailureKind::Configuration,
        _ => TokenGrantFailureKind::Unclassified,
    }
}

/// Check a grant's placements. Every rule must hold or the grant is invalid.
fn validate_placements(
    placements: Vec<CredentialPlacement>,
    connection_nominated: &[String],
) -> Result<Vec<Placement>, ()> {
    if placements.is_empty() || placements.len() > MAX_PLACEMENTS {
        return Err(());
    }
    let mut validated: Vec<Placement> = Vec::with_capacity(placements.len());
    for placement in placements {
        if placement.value.len() > MAX_PLACEMENT_VALUE_BYTES
            || placement.value.chars().any(char::is_control)
        {
            return Err(());
        }
        let style = AuthStyle::parse(&placement.auth_style).ok_or(())?;
        // A field the style does not use is invalid, so a broker mistake
        // cannot silently land the credential somewhere else.
        let unused_field = if style == AuthStyle::Query {
            &placement.header_name
        } else {
            &placement.query_param
        };
        if !unused_field.is_empty() {
            return Err(());
        }
        let placed = credential_placement::place(
            style,
            &placement.header_name,
            &placement.query_param,
            &placement.value,
        )?;
        match &placed {
            Placement::Header { name, .. } => {
                let lower = name.to_ascii_lowercase();
                if PROTECTED_HEADERS.contains(&lower.as_str())
                    || lower.starts_with("x-openshell-")
                    || connection_nominated.contains(&lower)
                {
                    return Err(());
                }
            }
            Placement::QueryParameter { name, .. } => {
                if name.len() > MAX_QUERY_PARAMETER_NAME_BYTES || name.chars().any(char::is_control)
                {
                    return Err(());
                }
            }
        }
        let duplicate = validated.iter().any(|existing| match (existing, &placed) {
            (Placement::Header { name: a, .. }, Placement::Header { name: b, .. }) => {
                a.eq_ignore_ascii_case(b)
            }
            (
                Placement::QueryParameter { name: a, .. },
                Placement::QueryParameter { name: b, .. },
            ) => a == b,
            _ => false,
        });
        if duplicate {
            return Err(());
        }
        validated.push(placed);
    }
    Ok(validated)
}

/// Header lines of a raw request header block, after the request line.
fn header_lines(raw_header: &[u8]) -> impl Iterator<Item = (&str, &str)> {
    let end = raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(raw_header.len());
    std::str::from_utf8(&raw_header[..end])
        .unwrap_or_default()
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim(), value.trim()))
}

/// Values of every `name` header, in wire order.
fn header_values(raw_header: &[u8], name: &str) -> Vec<String> {
    header_lines(raw_header)
        .filter(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.to_string())
        .collect()
}

/// Lowercase header names listed in `Connection`.
fn connection_nominated(raw_header: &[u8]) -> Vec<String> {
    header_values(raw_header, "connection")
        .iter()
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn normalized_host(host: &str) -> &str {
    host.trim().trim_start_matches('[').trim_end_matches(']')
}

/// The installed broker as requests see it.
pub enum BrokerState {
    /// A valid registration.
    Active(Arc<CredentialBroker>),
    /// The gateway sent a registration this supervisor rejected. Every request
    /// is refused, because the hosts it should govern are unknown.
    Rejected,
}

impl BrokerState {
    /// Whether a request to `host` needs the broker's decision.
    #[must_use]
    pub fn governs(&self, host: &str) -> bool {
        match self {
            Self::Active(broker) => broker.selects(host),
            Self::Rejected => true,
        }
    }
}

/// Holds one sandbox instance's installed broker. Requests read it each time,
/// so a registration change applies to the next request on every connection.
pub struct CredentialBrokerSlot {
    installed: RwLock<Option<(SupervisorCredentialBroker, Arc<BrokerState>)>>,
    sandbox_id: String,
    credentials: ExtensionCredentialStore,
}

impl CredentialBrokerSlot {
    /// An empty slot. Calls authenticate with the broker token in `credentials`.
    #[must_use]
    pub fn new(sandbox_id: &str, credentials: ExtensionCredentialStore) -> Self {
        Self {
            installed: RwLock::default(),
            sandbox_id: sandbox_id.to_string(),
            credentials,
        }
    }

    /// A slot holding `state`, for tests of the request path.
    #[cfg(test)]
    pub(crate) fn holding(state: BrokerState) -> Arc<Self> {
        Arc::new(Self {
            installed: RwLock::new(Some((
                SupervisorCredentialBroker::default(),
                Arc::new(state),
            ))),
            sandbox_id: String::new(),
            credentials: ExtensionCredentialStore::new(),
        })
    }

    /// The installed broker, if any. A poisoned lock reads as rejected.
    #[must_use]
    pub fn current(&self) -> Option<Arc<BrokerState>> {
        self.installed.read().map_or_else(
            |_| Some(Arc::new(BrokerState::Rejected)),
            |installed| installed.as_ref().map(|(_, state)| state.clone()),
        )
    }

    /// Whether a request to `host` needs the broker's decision.
    #[must_use]
    pub fn governs(&self, host: &str) -> bool {
        self.current().is_some_and(|state| state.governs(host))
    }

    /// Install the gateway's current registration. An unchanged registration
    /// is not reinstalled.
    ///
    /// NEVER keep serving a previous registration when the new one is invalid.
    /// The new one may select hosts the old one did not. An invalid
    /// registration installs [`BrokerState::Rejected`], which refuses every
    /// request.
    pub fn install(&self, registration: Option<&SupervisorCredentialBroker>) {
        let mut installed = match self.installed.write() {
            Ok(installed) => installed,
            Err(poisoned) => poisoned.into_inner(),
        };
        if installed.as_ref().map(|(current, _)| current) == registration {
            return;
        }
        let Some(registration) = registration else {
            *installed = None;
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Disabled, "disabled")
                    .message("credential broker removed")
                    .build()
            );
            return;
        };
        let state =
            match CredentialBroker::connect(registration, &self.sandbox_id, &self.credentials) {
                Ok(broker) => {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "enabled")
                            .message(format!(
                                "credential broker {} installed for {} host pattern(s)",
                                registration.name,
                                registration.include_hosts.len()
                            ))
                            .build()
                    );
                    BrokerState::Active(Arc::new(broker))
                }
                Err(reason) => {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .state(StateId::Other, "rejected")
                            .message(format!(
                                "credential broker rejected, refusing all requests: {reason}"
                            ))
                            .build()
                    );
                    BrokerState::Rejected
                }
            };
        *installed = Some((registration.clone(), Arc::new(state)));
    }
}

/// Whether raw relay to `host` must be refused.
///
/// Raw bytes cannot receive the broker's credential or its decision, so a
/// selected host is never relayed uninspected. A refusal emits a High
/// detection finding naming `detail`.
#[must_use]
pub fn refuses_raw_relay(slot: Option<&CredentialBrokerSlot>, host: &str, detail: &str) -> bool {
    if !slot.is_some_and(|slot| slot.governs(host)) {
        return false;
    }
    ocsf_emit!(
        DetectionFindingBuilder::new(ocsf_ctx())
            .severity(SeverityId::High)
            .finding_info(FindingInfo::new(
                "openshell.credential_broker.traffic_uninspectable",
                "Credential broker cannot apply to this traffic",
            ))
            .evidence_pairs(&[
                ("host", host),
                ("protocol", detail),
                ("disposition", "denied")
            ])
            .message("Uninspectable traffic to a host selected by the credential broker; denied")
            .build()
    );
    true
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use openshell_core::proto::credential_broker::v1::{
        CredentialDeny, CredentialGrant, CredentialPass,
    };

    use super::*;

    const RAW: &[u8] = b"GET /v1/items?x=1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer user-token\r\nConnection: keep-alive, x-trace\r\n\r\n";

    /// Returns one scripted answer and records every request.
    struct ScriptedBroker {
        answer: Result<HttpCredentialResult, Code>,
        requests: Mutex<Vec<HttpCredentialRequest>>,
    }

    #[tonic::async_trait]
    impl BrokerEndpoint for ScriptedBroker {
        async fn grant_http_request(
            &self,
            request: HttpCredentialRequest,
            _timeout: Duration,
        ) -> Result<HttpCredentialResult, Status> {
            self.requests.lock().unwrap().push(request);
            self.answer
                .clone()
                .map_err(|code| Status::new(code, "broker detail that must not be logged"))
        }
    }

    fn broker(
        answer: Result<HttpCredentialResult, Code>,
        forward_authorization: bool,
    ) -> (CredentialBroker, Arc<ScriptedBroker>) {
        let endpoint = Arc::new(ScriptedBroker {
            answer,
            requests: Mutex::new(Vec::new()),
        });
        let selector = HostSelector::new(&["**.example.com".to_string()], &[]).unwrap();
        (
            CredentialBroker::new(
                selector,
                Duration::from_secs(1),
                forward_authorization,
                "sandbox-1",
                endpoint.clone(),
            ),
            endpoint,
        )
    }

    fn request(scheme: &'static str) -> BrokerRequest<'static> {
        BrokerRequest {
            request_id: "req-1",
            method: "GET",
            scheme,
            host: "API.example.com",
            port: 443,
            path: "/v1/items",
            raw_header: RAW,
        }
    }

    fn placement(
        auth_style: &str,
        header_name: &str,
        query_param: &str,
        value: &str,
    ) -> CredentialPlacement {
        CredentialPlacement {
            auth_style: auth_style.to_string(),
            header_name: header_name.to_string(),
            query_param: query_param.to_string(),
            value: value.to_string(),
        }
    }

    fn bearer(value: &str) -> CredentialPlacement {
        placement("bearer", "", "", value)
    }

    fn header(name: &str, value: &str) -> CredentialPlacement {
        placement("header", name, "", value)
    }

    fn query(name: &str, value: &str) -> CredentialPlacement {
        placement("query", "", name, value)
    }

    fn grant(placements: Vec<CredentialPlacement>) -> HttpCredentialResult {
        HttpCredentialResult {
            decision: Some(http_credential_result::Decision::Grant(CredentialGrant {
                placements,
            })),
        }
    }

    fn deny(reason: DenyReason) -> HttpCredentialResult {
        HttpCredentialResult {
            decision: Some(http_credential_result::Decision::Deny(CredentialDeny {
                reason: reason.into(),
            })),
        }
    }

    type DecisionCase = (
        &'static str,
        Result<HttpCredentialResult, Code>,
        &'static str,
        Result<BrokerDecision, TokenGrantFailure>,
    );

    #[tokio::test]
    async fn decisions_and_failures() {
        use TokenGrantFailureKind as Kind;
        let failed = |kind| {
            Err(TokenGrantFailure::new(
                kind,
                TokenGrantStage::CredentialBroker,
            ))
        };
        let pass = Ok(HttpCredentialResult {
            decision: Some(http_credential_result::Decision::Pass(CredentialPass {})),
        });
        let cases: Vec<DecisionCase> = vec![
            (
                "bearer and query grant",
                Ok(grant(vec![bearer("t"), query("api_key", "k")])),
                "https",
                Ok(BrokerDecision::Grant(vec![
                    Placement::Header {
                        name: "Authorization".into(),
                        value: "Bearer t".into(),
                    },
                    Placement::QueryParameter {
                        name: "api_key".into(),
                        value: "k".into(),
                    },
                ])),
            ),
            (
                "basic and custom header grant",
                Ok(grant(vec![
                    placement("basic", "", "", "user:pass"),
                    header("X-Api-Key", "k"),
                ])),
                "https",
                Ok(BrokerDecision::Grant(vec![
                    Placement::Header {
                        name: "Authorization".into(),
                        value: "Basic dXNlcjpwYXNz".into(),
                    },
                    Placement::Header {
                        name: "X-Api-Key".into(),
                        value: "k".into(),
                    },
                ])),
            ),
            ("pass", pass.clone(), "https", Ok(BrokerDecision::Pass)),
            (
                "pass over plaintext",
                pass,
                "http",
                Ok(BrokerDecision::Pass),
            ),
            (
                "grant over plaintext",
                Ok(grant(vec![bearer("t")])),
                "http",
                failed(Kind::Configuration),
            ),
            (
                "deny",
                Ok(deny(DenyReason::AccessDenied)),
                "https",
                failed(Kind::AccessDenied),
            ),
            (
                "deny without a reason",
                Ok(deny(DenyReason::Unspecified)),
                "https",
                failed(Kind::AccessDenied),
            ),
            (
                "authorization required",
                Ok(deny(DenyReason::AuthorizationRequired)),
                "https",
                failed(Kind::ProviderAuthorizationRequired),
            ),
            (
                "no decision",
                Ok(HttpCredentialResult { decision: None }),
                "https",
                failed(Kind::Unclassified),
            ),
            (
                "unavailable",
                Err(Code::Unavailable),
                "https",
                failed(Kind::Unavailable),
            ),
            (
                "resource exhausted",
                Err(Code::ResourceExhausted),
                "https",
                failed(Kind::Unavailable),
            ),
            (
                "deadline",
                Err(Code::DeadlineExceeded),
                "https",
                failed(Kind::Timeout),
            ),
            (
                "unauthenticated",
                Err(Code::Unauthenticated),
                "https",
                failed(Kind::WorkloadIdentityRejected),
            ),
            (
                "permission denied",
                Err(Code::PermissionDenied),
                "https",
                failed(Kind::WorkloadIdentityRejected),
            ),
            (
                "invalid argument",
                Err(Code::InvalidArgument),
                "https",
                failed(Kind::Configuration),
            ),
            (
                "failed precondition",
                Err(Code::FailedPrecondition),
                "https",
                failed(Kind::Configuration),
            ),
            (
                "internal",
                Err(Code::Internal),
                "https",
                failed(Kind::Unclassified),
            ),
        ];
        for (name, answer, scheme, expected) in cases {
            let (broker, _) = broker(answer, false);
            assert_eq!(broker.decide(request(scheme)).await, expected, "{name}");
        }
    }

    #[tokio::test]
    async fn invalid_grants_are_unclassified_failures() {
        let long = "v".repeat(MAX_PLACEMENT_VALUE_BYTES + 1);
        let nine = (0..9).map(|i| header(&format!("x-key-{i}"), "v")).collect();
        let cases: Vec<(&str, Vec<CredentialPlacement>)> = vec![
            ("empty grant", vec![]),
            ("more than eight placements", nine),
            ("value too long", vec![bearer(&long)]),
            ("control character", vec![bearer("a\r\nb")]),
            ("unknown auth style", vec![placement("digest", "", "", "v")]),
            ("path auth style", vec![placement("path", "", "", "v")]),
            ("empty auth style", vec![placement("", "", "", "v")]),
            (
                "header without a name",
                vec![placement("header", "", "", "v")],
            ),
            ("query without a name", vec![query("", "v")]),
            (
                "query with a header name",
                vec![placement("query", "X-A", "k", "v")],
            ),
            (
                "bearer with a query name",
                vec![placement("bearer", "", "k", "v")],
            ),
            ("invalid header name", vec![header("bad header", "v")]),
            ("routing header", vec![header("Host", "evil.example")]),
            (
                "framing header",
                vec![header("Transfer-Encoding", "chunked")],
            ),
            ("hop-by-hop header", vec![header("Upgrade", "h2c")]),
            (
                "openshell header",
                vec![header("X-OpenShell-Request-Id", "v")],
            ),
            ("connection-nominated header", vec![header("X-Trace", "v")]),
            (
                "duplicate header",
                vec![bearer("a"), header("authorization", "b")],
            ),
            ("duplicate query", vec![query("k", "a"), query("k", "b")]),
        ];
        for (name, placements) in cases {
            let (broker, _) = broker(Ok(grant(placements)), false);
            assert_eq!(
                broker.decide(request("https")).await,
                Err(TokenGrantFailure::new(
                    TokenGrantFailureKind::Unclassified,
                    TokenGrantStage::CredentialBroker
                )),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn the_broker_sees_the_target_and_only_opted_in_authorization() {
        for forward in [false, true] {
            let (broker, endpoint) = broker(Ok(deny(DenyReason::AccessDenied)), forward);
            let _ = broker.decide(request("https")).await;
            let sent = endpoint.requests.lock().unwrap().pop().unwrap();
            assert_eq!(
                sent,
                HttpCredentialRequest {
                    request_id: "req-1".into(),
                    sandbox_id: "sandbox-1".into(),
                    method: "GET".into(),
                    scheme: "https".into(),
                    host: "api.example.com".into(),
                    port: 443,
                    path: "/v1/items".into(),
                    authorization: if forward {
                        vec!["Bearer user-token".into()]
                    } else {
                        vec![]
                    },
                },
                "forward_authorization={forward}"
            );
        }
    }

    #[test]
    fn rejected_registration_governs_every_host() {
        let slot = CredentialBrokerSlot::holding(BrokerState::Rejected);
        assert!(slot.governs("anything.example.org"));
        assert!(refuses_raw_relay(
            Some(&slot),
            "anything.example.org",
            "tls-skip tunnel"
        ));
        assert!(!refuses_raw_relay(
            None,
            "anything.example.org",
            "tls-skip tunnel"
        ));
    }

    #[tokio::test]
    async fn install_validates_and_selects() {
        let slot = CredentialBrokerSlot::new("sandbox-1", ExtensionCredentialStore::new());
        assert!(slot.current().is_none());
        assert!(!slot.governs("api.example.com"));

        let registration = SupervisorCredentialBroker {
            name: "corp-broker".into(),
            grpc_endpoint: "https://broker.example:8443".into(),
            audience: "urn:openshell:extension:credential-broker:corp-broker".into(),
            include_hosts: vec!["**.example.com".into()],
            exclude_hosts: vec!["status.example.com".into()],
            ..Default::default()
        };
        slot.install(Some(&registration));
        assert!(matches!(
            slot.current().as_deref(),
            Some(BrokerState::Active(_))
        ));
        assert!(slot.governs("api.example.com"));
        assert!(!slot.governs("status.example.com"));
        assert!(!slot.governs("example.org"));

        let invalid = SupervisorCredentialBroker {
            include_hosts: vec![],
            ..registration
        };
        slot.install(Some(&invalid));
        assert!(matches!(
            slot.current().as_deref(),
            Some(BrokerState::Rejected)
        ));
        assert!(slot.governs("example.org"));

        slot.install(None);
        assert!(slot.current().is_none());
    }
}

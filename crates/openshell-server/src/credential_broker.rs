// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup checks for the operator-registered credential broker.
//!
//! The gateway calls `Describe` once at startup and refuses to start when the
//! broker is unreachable or incompatible. Supervisors call the broker on the
//! request path. The gateway does not.

use std::time::Duration;

use openshell_core::extension_protocol::{
    ExtensionFamily, NegotiatedExtension, gateway_metadata, negotiate,
};
use openshell_core::proto::SupervisorCredentialBroker;
use openshell_core::proto::credential_broker::v1::credential_broker_client::CredentialBrokerClient;
use openshell_core::proto::credential_broker::v1::{BrokerDescribeRequest, BrokerManifest};
use openshell_extension_core::{
    BearerTokenInterceptor, BearerTokenSlot, ExtensionChannelConfig, ExtensionServerTrust,
    connect_channel,
};
use tonic::service::interceptor::InterceptedService;

const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(10);

/// A registration whose broker answered `Describe` with a compatible manifest.
#[derive(Clone, Debug)]
pub struct CredentialBroker {
    pub registration: SupervisorCredentialBroker,
    pub negotiated: NegotiatedExtension,
}

/// Connect to the broker and check its manifest.
///
/// `bearer` is the gateway-caller credential, or `None` when the registration
/// opts out of extension authentication.
pub async fn connect(
    registration: SupervisorCredentialBroker,
    bearer: Option<BearerTokenSlot>,
) -> Result<CredentialBroker, String> {
    let name = registration.name.clone();
    let mut channel_config = ExtensionChannelConfig::new(&registration.grpc_endpoint);
    if !registration.tls_ca_cert_pem.is_empty() {
        channel_config = channel_config.with_server_trust(ExtensionServerTrust::CustomCaPem(
            registration.tls_ca_cert_pem.clone(),
        ));
    }
    let channel = connect_channel(&channel_config)
        .await
        .map_err(|error| format!("credential broker '{name}' could not connect: {error}"))?;
    let authenticated = bearer.is_some();
    let interceptor =
        bearer.map_or_else(BearerTokenInterceptor::disabled, |slot| slot.interceptor());
    let mut client = CredentialBrokerClient::new(InterceptedService::new(channel, interceptor));
    let mut request = tonic::Request::new(BrokerDescribeRequest {
        gateway: Some(gateway_metadata(ExtensionFamily::CredentialBroker)),
    });
    request.set_timeout(DESCRIBE_TIMEOUT);
    let manifest = client
        .describe(request)
        .await
        .map_err(|status| {
            format!(
                "credential broker '{name}' Describe failed: {}",
                status.code().description()
            )
        })?
        .into_inner();
    let negotiated = check_manifest(&registration, manifest, authenticated)?;
    Ok(CredentialBroker {
        registration,
        negotiated,
    })
}

/// Check protocol metadata and, for an authenticated registration, that the
/// broker expects the audience the gateway mints.
fn check_manifest(
    registration: &SupervisorCredentialBroker,
    manifest: BrokerManifest,
    authenticated: bool,
) -> Result<NegotiatedExtension, String> {
    let negotiated = negotiate(
        ExtensionFamily::CredentialBroker,
        &registration.name,
        &gateway_metadata(ExtensionFamily::CredentialBroker),
        manifest.extension,
    )
    .map_err(|error| error.to_string())?;
    if authenticated
        && !manifest.expected_audience.is_empty()
        && manifest.expected_audience != registration.audience
    {
        return Err(format!(
            "credential broker '{}' expects audience '{}' but the gateway is configured to mint '{}'",
            registration.name, manifest.expected_audience, registration.audience
        ));
    }
    Ok(negotiated)
}

#[cfg(test)]
mod tests {
    use openshell_core::extension_protocol::extension_metadata;
    use openshell_core::proto::credential_broker::v1::credential_broker_server::{
        CredentialBroker as BrokerService, CredentialBrokerServer,
    };
    use openshell_core::proto::credential_broker::v1::{
        HttpCredentialRequest, HttpCredentialResult,
    };
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    use super::*;

    const AUDIENCE: &str = "urn:openshell:extension:credential-broker:corp-broker";

    fn registration(endpoint: &str) -> SupervisorCredentialBroker {
        SupervisorCredentialBroker {
            name: "corp-broker".to_string(),
            grpc_endpoint: endpoint.to_string(),
            audience: AUDIENCE.to_string(),
            include_hosts: vec!["**".to_string()],
            ..Default::default()
        }
    }

    fn broker_metadata() -> openshell_core::proto::extension::v1::PeerMetadata {
        extension_metadata(ExtensionFamily::CredentialBroker, "test/broker", "1.0", [])
    }

    #[test]
    fn manifest_checks() {
        let compatible = || BrokerManifest {
            name: "test/broker".to_string(),
            expected_audience: AUDIENCE.to_string(),
            extension: Some(broker_metadata()),
        };
        let cases: [(&str, BrokerManifest, bool, bool); 6] = [
            ("compatible", compatible(), true, true),
            (
                "unadvertised audience",
                BrokerManifest {
                    expected_audience: String::new(),
                    ..compatible()
                },
                true,
                true,
            ),
            (
                "audience mismatch",
                BrokerManifest {
                    expected_audience: "urn:example:other".to_string(),
                    ..compatible()
                },
                true,
                false,
            ),
            (
                "audience mismatch without authentication",
                BrokerManifest {
                    expected_audience: "urn:example:other".to_string(),
                    ..compatible()
                },
                false,
                true,
            ),
            (
                "missing metadata",
                BrokerManifest {
                    extension: None,
                    ..compatible()
                },
                true,
                false,
            ),
            (
                "wrong family",
                BrokerManifest {
                    extension: Some(extension_metadata(
                        ExtensionFamily::SupervisorMiddleware,
                        "test/broker",
                        "1.0",
                        [],
                    )),
                    ..compatible()
                },
                true,
                false,
            ),
        ];
        for (name, manifest, authenticated, accepted) in cases {
            let result = check_manifest(&registration("https://unused"), manifest, authenticated);
            assert_eq!(result.is_ok(), accepted, "{name}: {result:?}");
        }
    }

    struct DescribeOnly;

    #[tonic::async_trait]
    impl BrokerService for DescribeOnly {
        async fn describe(
            &self,
            request: Request<BrokerDescribeRequest>,
        ) -> Result<Response<BrokerManifest>, Status> {
            let gateway = request.into_inner().gateway.expect("gateway metadata");
            assert_eq!(
                gateway.required_capabilities,
                vec!["openshell.credential-broker.contract".to_string()]
            );
            Ok(Response::new(BrokerManifest {
                name: "test/broker".to_string(),
                expected_audience: String::new(),
                extension: Some(broker_metadata()),
            }))
        }

        async fn grant_http_request(
            &self,
            _request: Request<HttpCredentialRequest>,
        ) -> Result<Response<HttpCredentialResult>, Status> {
            Err(Status::unimplemented("not called at startup"))
        }
    }

    #[tokio::test]
    async fn connect_negotiates_with_a_running_broker() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(CredentialBrokerServer::new(DescribeOnly))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let mut plaintext = registration(&format!("http://{address}"));
        plaintext.allow_insecure_transport = true;
        let broker = connect(plaintext, None).await.expect("broker connects");
        assert_eq!(broker.negotiated.family, ExtensionFamily::CredentialBroker);
        assert_eq!(broker.negotiated.configured_name, "corp-broker");
        assert_eq!(broker.negotiated.implementation_name, "test/broker");
    }

    #[tokio::test]
    async fn connect_fails_when_the_broker_is_down() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut plaintext = registration(&format!("http://{address}"));
        plaintext.allow_insecure_transport = true;
        let error = connect(plaintext, None).await.expect_err("nothing listens");
        assert!(
            error.starts_with("credential broker 'corp-broker' could not connect"),
            "{error}"
        );
    }
}

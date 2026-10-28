// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential broker registration rules shared by the gateway and supervisor.
//!
//! The gateway validates the registration at startup and the supervisor
//! validates it again on install, with this code. A supervisor that rejects a
//! registration refuses every request.

use std::time::Duration;

use crate::host_pattern::HostSelector;
use crate::proto::{SupervisorCredentialBroker, SupervisorMiddlewareService};

/// Name under which supervisors request and store the broker's extension
/// credential. Middleware registration names cannot use the `openshell/`
/// namespace, so it does not collide with a middleware service.
pub const EXTENSION_CREDENTIAL_NAME: &str = "openshell/credential-broker";

/// Per-call deadline when the registration does not set one.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Placements one grant may make.
pub const MAX_PLACEMENTS: usize = 8;

/// Bytes in one placement value.
pub const MAX_PLACEMENT_VALUE_BYTES: usize = 8 * 1024;

/// Combined include and exclude host patterns.
pub const MAX_HOST_PATTERNS: usize = 32;

/// A registration that passed validation.
#[derive(Clone)]
pub struct ValidatedRegistration {
    pub selector: HostSelector,
    pub timeout: Duration,
}

/// Validate a registration. Errors are fixed strings that are safe to log.
pub fn validate(
    registration: &SupervisorCredentialBroker,
) -> Result<ValidatedRegistration, &'static str> {
    if registration.name.trim().is_empty() {
        return Err("name must not be empty");
    }
    let endpoint = registration.grpc_endpoint.as_str();
    if registration.allow_insecure_transport {
        if !endpoint.starts_with("https://") && !endpoint.starts_with("http://") {
            return Err("grpc_endpoint must use https:// or http://");
        }
    } else {
        if !endpoint.starts_with("https://") {
            return Err(
                "grpc_endpoint must use https://; set allow_insecure_transport = true to use http://",
            );
        }
        if registration.audience.is_empty() {
            return Err("audience must not be empty");
        }
    }
    if !registration.tls_ca_cert_pem.is_empty() && !endpoint.starts_with("https://") {
        return Err("tls_ca_cert_path requires an https:// grpc_endpoint");
    }
    if registration.include_hosts.len() + registration.exclude_hosts.len() > MAX_HOST_PATTERNS {
        return Err("include_hosts and exclude_hosts allow at most 32 patterns");
    }
    let selector = HostSelector::new(&registration.include_hosts, &registration.exclude_hosts)
        .map_err(|_| "include_hosts or exclude_hosts is not a valid host selector")?;
    let timeout = match &registration.request_timeout {
        None => DEFAULT_TIMEOUT,
        Some(timeout) => {
            let timeout = Duration::try_from(*timeout)
                .map_err(|_| "request_timeout must be between 10ms and 30s")?;
            if timeout < crate::middleware::MIN_MIDDLEWARE_TIMEOUT
                || timeout > crate::middleware::MAX_MIDDLEWARE_TIMEOUT
            {
                return Err("request_timeout must be between 10ms and 30s");
            }
            timeout
        }
    };
    Ok(ValidatedRegistration { selector, timeout })
}

/// The entry supervisors pass when they request extension credentials, so
/// the broker's credential is fetched and rotated with middleware credentials.
#[must_use]
pub fn credential_service(
    registration: &SupervisorCredentialBroker,
) -> SupervisorMiddlewareService {
    SupervisorMiddlewareService {
        name: EXTENSION_CREDENTIAL_NAME.to_string(),
        audience: registration.audience.clone(),
        allow_insecure_transport: registration.allow_insecure_transport,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> SupervisorCredentialBroker {
        SupervisorCredentialBroker {
            name: "corp-broker".to_string(),
            grpc_endpoint: "https://broker.example:8443".to_string(),
            audience: "urn:openshell:extension:credential-broker:corp-broker".to_string(),
            include_hosts: vec!["**".to_string()],
            ..Default::default()
        }
    }

    type Mutation = fn(&mut SupervisorCredentialBroker);

    #[test]
    fn validation_table() {
        let duration = |millis: i64| prost_types::Duration {
            seconds: millis / 1000,
            nanos: i32::try_from((millis % 1000) * 1_000_000).unwrap(),
        };
        let cases: Vec<(&str, Mutation, Result<Duration, &str>)> = vec![
            ("default timeout", |_| {}, Ok(DEFAULT_TIMEOUT)),
            (
                "explicit timeout",
                |r| {
                    r.request_timeout = Some(prost_types::Duration {
                        seconds: 2,
                        nanos: 0,
                    });
                },
                Ok(Duration::from_secs(2)),
            ),
            (
                "plaintext needs the opt-out",
                |r| r.grpc_endpoint = "http://broker.example".to_string(),
                Err(
                    "grpc_endpoint must use https://; set allow_insecure_transport = true to use http://",
                ),
            ),
            (
                "plaintext with the opt-out",
                |r| {
                    r.grpc_endpoint = "http://broker.example".to_string();
                    r.allow_insecure_transport = true;
                    r.audience.clear();
                },
                Ok(DEFAULT_TIMEOUT),
            ),
            (
                "unix socket",
                |r| {
                    r.grpc_endpoint = "unix:///run/broker.sock".to_string();
                    r.allow_insecure_transport = true;
                },
                Err("grpc_endpoint must use https:// or http://"),
            ),
            (
                "authenticated without an audience",
                |r| r.audience.clear(),
                Err("audience must not be empty"),
            ),
            (
                "custom CA over plaintext",
                |r| {
                    r.grpc_endpoint = "http://broker.example".to_string();
                    r.allow_insecure_transport = true;
                    r.tls_ca_cert_pem = b"pem".to_vec();
                },
                Err("tls_ca_cert_path requires an https:// grpc_endpoint"),
            ),
            (
                "no include hosts",
                |r| r.include_hosts.clear(),
                Err("include_hosts or exclude_hosts is not a valid host selector"),
            ),
            (
                "too many patterns",
                |r| r.exclude_hosts = vec!["a.example".to_string(); 32],
                Err("include_hosts and exclude_hosts allow at most 32 patterns"),
            ),
            (
                "empty name",
                |r| r.name.clear(),
                Err("name must not be empty"),
            ),
        ];
        for (name, mutate, expected) in cases {
            let mut candidate = registration();
            mutate(&mut candidate);
            let actual = validate(&candidate).map(|validated| validated.timeout);
            assert_eq!(actual, expected, "{name}");
        }
        for (millis, valid) in [(9, false), (10, true), (30_000, true), (30_001, false)] {
            let mut candidate = registration();
            candidate.request_timeout = Some(duration(millis));
            assert_eq!(validate(&candidate).is_ok(), valid, "{millis}ms");
        }
    }

    #[test]
    fn selector_applies_exclusions() {
        let mut candidate = registration();
        candidate.include_hosts = vec!["**.example.com".to_string()];
        candidate.exclude_hosts = vec!["status.example.com".to_string()];
        let validated = validate(&candidate).unwrap();
        assert!(validated.selector.matches("api.example.com"));
        assert!(!validated.selector.matches("status.example.com"));
        assert!(!validated.selector.matches("example.org"));
    }

    #[test]
    fn credential_service_uses_the_reserved_name_and_registration_auth() {
        let service = credential_service(&registration());
        assert_eq!(service.name, EXTENSION_CREDENTIAL_NAME);
        assert_eq!(service.audience, registration().audience);
        assert!(!service.allow_insecure_transport);
    }
}

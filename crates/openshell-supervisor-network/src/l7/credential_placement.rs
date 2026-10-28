// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential placement in the terms of a provider profile credential:
//! `auth_style`, `header_name`, and `query_param`.
//!
//! Provider token grants and the credential broker both place credentials
//! with [`place`], so one placement writes the same bytes on either path.
//! Path placement is not supported, because request paths appear in access
//! logs.

use std::fmt::Write as _;

use base64::Engine as _;

const AUTHORIZATION: &str = "Authorization";

/// A profile `auth_style` that writes a credential into a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthStyle {
    /// `Bearer <credential>` in `header_name`, default `Authorization`.
    Bearer,
    /// `Basic <base64(credential)>` in `header_name`, default `Authorization`.
    /// The credential is `user:password`.
    Basic,
    /// The credential unchanged in `header_name`, which is required.
    Header,
    /// The credential unchanged in query parameter `query_param`, which is
    /// required.
    Query,
}

impl AuthStyle {
    /// Parse a profile `auth_style`. Case and surrounding space are ignored.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "bearer" => Some(Self::Bearer),
            "basic" => Some(Self::Basic),
            "header" => Some(Self::Header),
            "query" => Some(Self::Query),
            _ => None,
        }
    }
}

/// The request field a credential replaces and the value written there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placement {
    Header { name: String, value: String },
    QueryParameter { name: String, value: String },
}

/// The header a header style writes: `header_name`, or `Authorization` for
/// bearer and basic when it is empty. Fails for query, for header without a
/// name, and for a name that is not a valid field name or is a framing or
/// connection header.
pub fn header_name(style: AuthStyle, header_name: &str) -> Result<&str, ()> {
    let header_name = header_name.trim();
    let name = match style {
        AuthStyle::Bearer | AuthStyle::Basic if header_name.is_empty() => AUTHORIZATION,
        AuthStyle::Bearer | AuthStyle::Basic | AuthStyle::Header if !header_name.is_empty() => {
            header_name
        }
        _ => return Err(()),
    };
    let lower = name.to_ascii_lowercase();
    if !is_field_name(name)
        || matches!(
            lower.as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection"
        )
    {
        return Err(());
    }
    Ok(name)
}

/// Place `credential` as `style` describes.
pub fn place(
    style: AuthStyle,
    header: &str,
    query_param: &str,
    credential: &str,
) -> Result<Placement, ()> {
    let header_value = match style {
        AuthStyle::Bearer => format!("Bearer {credential}"),
        AuthStyle::Basic => format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credential)
        ),
        AuthStyle::Header => credential.to_string(),
        AuthStyle::Query => {
            let name = query_param.trim();
            if name.is_empty() {
                return Err(());
            }
            return Ok(Placement::QueryParameter {
                name: name.to_string(),
                value: credential.to_string(),
            });
        }
    };
    Ok(Placement::Header {
        name: header_name(style, header)?.to_string(),
        value: header_value,
    })
}

fn is_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Replace every `name` query parameter in the request line with one
/// `name=value` pair. Returns the new raw header and request target.
pub fn replace_query_parameter(
    raw_header: &[u8],
    name: &str,
    value: &str,
) -> Result<(Vec<u8>, String), ()> {
    let line_end = raw_header
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(())?;
    let request_line = std::str::from_utf8(&raw_header[..line_end]).map_err(|_| ())?;
    let mut parts = request_line.splitn(3, ' ');
    let (method, target, version) = (
        parts.next().ok_or(())?,
        parts.next().ok_or(())?,
        parts.next().ok_or(())?,
    );
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut pairs = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let key = pair.split_once('=').map_or(pair, |(key, _)| key);
        let decoded = crate::l7::rest::decode_query_component(key).map_err(|_| ())?;
        if decoded != name {
            pairs.push(pair.to_string());
        }
    }
    pairs.push(format!(
        "{}={}",
        percent_encode_query_component(name),
        percent_encode_query_component(value)
    ));
    let target = format!("{path}?{}", pairs.join("&"));
    let mut rewritten = format!("{method} {target} {version}").into_bytes();
    rewritten.extend_from_slice(&raw_header[line_end..]);
    Ok((rewritten, target))
}

/// Percent-encode everything except RFC 3986 unreserved characters.
fn percent_encode_query_component(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> Placement {
        Placement::Header {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn auth_styles_follow_provider_profiles() {
        let cases = [
            (
                "bearer",
                "",
                "",
                Ok(header("Authorization", "Bearer secret")),
            ),
            (
                "Bearer ",
                "X-Token",
                "",
                Ok(header("X-Token", "Bearer secret")),
            ),
            (
                "basic",
                "",
                "",
                Ok(header("Authorization", "Basic c2VjcmV0")),
            ),
            (
                "basic",
                "Proxy-Auth",
                "",
                Ok(header("Proxy-Auth", "Basic c2VjcmV0")),
            ),
            ("header", "X-Api-Key", "", Ok(header("X-Api-Key", "secret"))),
            ("header", "", "", Err(())),
            (
                "query",
                "",
                "api_key",
                Ok(Placement::QueryParameter {
                    name: "api_key".to_string(),
                    value: "secret".to_string(),
                }),
            ),
            ("query", "", "", Err(())),
            ("bearer", "bad header", "", Err(())),
            ("bearer", "Host", "", Err(())),
            ("header", "Content-Length", "", Err(())),
            ("header", "Transfer-Encoding", "", Err(())),
            ("header", "connection", "", Err(())),
        ];
        for (style, header_name, query_param, expected) in cases {
            let style_parsed = AuthStyle::parse(style).expect(style);
            assert_eq!(
                place(style_parsed, header_name, query_param, "secret"),
                expected,
                "{style} {header_name:?} {query_param:?}"
            );
        }
        for unsupported in ["", "path", "digest"] {
            assert_eq!(AuthStyle::parse(unsupported), None, "{unsupported}");
        }
    }

    #[test]
    fn query_parameter_replacement() {
        let cases = [
            (
                "GET /v1/items HTTP/1.1\r\nHost: a\r\n\r\n",
                "GET /v1/items?api_key=s%20k HTTP/1.1\r\nHost: a\r\n\r\n",
            ),
            (
                "GET /v1/items?x=1&api_key=old&api%5Fkey=old2&y HTTP/1.1\r\n\r\n",
                "GET /v1/items?x=1&y&api_key=s%20k HTTP/1.1\r\n\r\n",
            ),
            (
                "GET https://a.example/v1?api_key=old HTTP/1.1\r\n\r\nbody",
                "GET https://a.example/v1?api_key=s%20k HTTP/1.1\r\n\r\nbody",
            ),
        ];
        for (input, expected) in cases {
            let (rewritten, target) =
                replace_query_parameter(input.as_bytes(), "api_key", "s k").unwrap();
            assert_eq!(String::from_utf8(rewritten).unwrap(), expected, "{input}");
            assert_eq!(
                target,
                expected.split(' ').nth(1).unwrap(),
                "target of {input}"
            );
        }
        assert!(replace_query_parameter(b"GET /v1?%zz=1 HTTP/1.1\r\n\r\n", "k", "v").is_err());
    }
}

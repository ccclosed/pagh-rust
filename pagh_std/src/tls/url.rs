//! The pure part of the HTTPS URL subset `https_get` accepts.
//!
//! `core` + `alloc` only, deliberately: the parser is the one piece of
//! [`super::https_get`] that can be exercised by the host test gate
//! (`hostcheck`, `#[path]`-included like the other pure modules), and a URL
//! parser feeding a TLS client is exactly the code that must not guess. It
//! understands `https://host[:port][/path]` and refuses everything else —
//! no userinfo, no IPv6 literals (the ABI is IPv4-only), no scheme-relative
//! forms.

use alloc::string::String;

/// The IANA port for HTTPS, which is the only one this API defaults to.
///
/// It lives here, with the parser that applies it, so a URL that omits the port
/// means the same thing in the SDK and in the host tests.
pub const HTTPS_PORT: u16 = 443;

/// A parsed `https://host[:port][/path]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The host name the certificate must authorize (SNI and the SAN check).
    pub host: String,
    /// The TCP port.
    pub port: u16,
    /// The request path, always beginning with `/`.
    pub path: String,
}

/// Why a URL was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    /// The URL does not start with `https://`.
    NotHttps,
    /// The authority is empty (`https:///x`).
    NoHost,
    /// The port is not a number in `0..=65535`.
    BadPort,
    /// The authority carries userinfo (`user@host`): the ABI has no way to send
    /// credentials, and guessing which half is the host is worse than refusing.
    Malformed,
}

impl UrlError {
    /// A `'static` explanation for the SDK error.
    pub const fn message(self) -> &'static str {
        match self {
            UrlError::NotHttps => "tls: only https:// URLs are accepted",
            UrlError::NoHost => "tls: the URL has no host",
            UrlError::BadPort => "tls: the URL port is not a number in 0..=65535",
            UrlError::Malformed => "tls: the URL authority is malformed",
        }
    }
}

impl Target {
    /// Parse `url`, refusing anything outside the accepted subset.
    pub fn parse(url: &str) -> core::result::Result<Target, UrlError> {
        let rest = url.strip_prefix("https://").ok_or(UrlError::NotHttps)?;
        // The path begins at the first `/`; without one the request targets
        // `/`, which is what every origin's root document is.
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        // Userinfo (`user@host`) would make the authority ambiguous, and the
        // ABI has no way to send credentials anyway: refuse rather than pick a
        // side.
        if authority.contains('@') {
            return Err(UrlError::Malformed);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().map_err(|_| UrlError::BadPort)?),
            None => (authority, HTTPS_PORT),
        };
        if host.is_empty() {
            return Err(UrlError::NoHost);
        }
        Ok(Target {
            host: String::from(host),
            port,
            path: String::from(path),
        })
    }

    /// The `host:port` text [`TlsStream::connect`](super::TlsStream::connect)
    /// takes.
    pub fn host_port(&self) -> String {
        alloc::format!("{}:{}", self.host, self.port)
    }

    /// The `GET` request for this target: path, `Host` and `Connection: close`.
    pub fn get_request(&self) -> alloc::vec::Vec<u8> {
        super::http::build_get_request(&self.host, &self.path)
    }
}

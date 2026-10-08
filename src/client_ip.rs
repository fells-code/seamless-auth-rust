use std::fmt;
use std::net::IpAddr;

use axum::http::HeaderMap;
use axum::http::header::USER_AGENT;

const MAX_USER_AGENT_LENGTH: usize = 512;

/// A subnet, or single address, of a proxy in front of the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Prefix {
    addr: IpAddr,
    bits: u8,
}

impl Prefix {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                masked(u32::from(net).into(), self.bits, 32)
                    == masked(u32::from(ip).into(), self.bits, 32)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                masked(u128::from(net), self.bits, 128) == masked(u128::from(ip), self.bits, 128)
            }
            _ => false,
        }
    }
}

fn masked(value: u128, bits: u8, width: u8) -> u128 {
    if bits == 0 {
        return 0;
    }
    value >> (width - bits)
}

/// A proxy address [`TrustedProxies::new`] could not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidProxy(pub String);

impl fmt::Display for InvalidProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seamless-auth: {:?} is not an address or CIDR subnet",
            self.0
        )
    }
}

impl std::error::Error for InvalidProxy {}

/// Resolves the end user's address for an app behind proxies with known
/// addresses or subnets (`"10.0.0.0/8"`, `"127.0.0.1"`).
///
/// It walks `X-Forwarded-For` from the right, skipping trusted proxies, and
/// returns the first address that is not one. There is deliberately no hop
/// count: it cannot tell a proxy from a client that sent its own header.
#[derive(Clone, Debug)]
pub struct TrustedProxies {
    prefixes: Vec<Prefix>,
}

impl TrustedProxies {
    pub fn new<I, S>(proxies: I) -> Result<Self, InvalidProxy>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut prefixes = Vec::new();
        for proxy in proxies {
            let raw = proxy.as_ref().trim();
            let prefix = match raw.split_once('/') {
                Some((addr, bits)) => {
                    let addr: IpAddr = addr.parse().map_err(|_| InvalidProxy(raw.to_string()))?;
                    let bits: u8 = bits.parse().map_err(|_| InvalidProxy(raw.to_string()))?;
                    if bits > width(addr) {
                        return Err(InvalidProxy(raw.to_string()));
                    }
                    Prefix { addr, bits }
                }
                None => {
                    let addr: IpAddr = raw.parse().map_err(|_| InvalidProxy(raw.to_string()))?;
                    Prefix {
                        addr,
                        bits: width(addr),
                    }
                }
            };
            prefixes.push(prefix);
        }
        Ok(TrustedProxies { prefixes })
    }

    fn trusted(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.prefixes.iter().any(|p| p.contains(ip))
    }

    /// The end user's address, given the request headers and the connecting peer.
    pub fn resolve(&self, headers: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
        let peer = peer?;
        if !self.trusted(peer) {
            return Some(peer);
        }

        let hops: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|hop| !hop.is_empty())
            .collect();

        for hop in hops.iter().rev() {
            match hop.parse::<IpAddr>() {
                Ok(ip) if self.trusted(ip) => continue,
                Ok(ip) => return Some(ip),
                // Not an address, so not a trusted proxy either: whoever wrote it
                // is the client, and it has no usable address.
                Err(_) => return None,
            }
        }
        match hops.first() {
            Some(first) => first.parse().ok(),
            None => Some(peer),
        }
    }
}

fn width(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// The address forwarded to the auth API, in canonical form.
pub(crate) fn canonical(ip: IpAddr) -> String {
    ip.to_canonical().to_string()
}

/// The user agent forwarded to the auth API, trimmed and capped.
pub(crate) fn client_user_agent(headers: &HeaderMap) -> Option<Vec<u8>> {
    let raw = headers.get(USER_AGENT)?.as_bytes();
    let trimmed = raw.trim_ascii();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed[..trimmed.len().min(MAX_USER_AGENT_LENGTH)].to_vec())
}

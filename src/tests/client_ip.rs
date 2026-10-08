use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderValue};

use crate::TrustedProxies;

fn forwarded(values: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for v in values {
        headers.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
    }
    headers
}

fn ip(s: &str) -> Option<IpAddr> {
    Some(s.parse().unwrap())
}

#[test]
fn walks_x_forwarded_for_from_the_right() {
    let proxies = TrustedProxies::new(["10.0.0.0/8", "192.0.2.1", "2001:db8::/32"]).unwrap();

    // An untrusted peer is the client, whatever it claims.
    assert_eq!(
        proxies.resolve(&forwarded(&["1.1.1.1"]), ip("203.0.113.9")),
        ip("203.0.113.9")
    );
    // A client-supplied left-most entry is ignored past the first untrusted hop.
    assert_eq!(
        proxies.resolve(
            &forwarded(&["6.6.6.6, 203.0.113.50, 10.1.2.3"]),
            ip("192.0.2.1")
        ),
        ip("203.0.113.50")
    );
    // Several headers read as one list.
    assert_eq!(
        proxies.resolve(&forwarded(&["6.6.6.6", "203.0.113.50"]), ip("10.0.0.1")),
        ip("203.0.113.50")
    );
    // Every hop trusted: the left-most.
    assert_eq!(
        proxies.resolve(&forwarded(&["10.0.0.5, 10.0.0.6"]), ip("10.0.0.1")),
        ip("10.0.0.5")
    );
    // A trusted peer with no header.
    assert_eq!(
        proxies.resolve(&HeaderMap::new(), ip("10.0.0.1")),
        ip("10.0.0.1")
    );
    // A hop that is not an address gives no address rather than a guess.
    assert_eq!(
        proxies.resolve(&forwarded(&["203.0.113.50, garbage"]), ip("10.0.0.1")),
        None
    );
    // IPv4-mapped peers match IPv4 proxies.
    assert_eq!(
        proxies.resolve(&forwarded(&["203.0.113.50"]), ip("::ffff:10.0.0.1")),
        ip("203.0.113.50")
    );
    assert_eq!(
        proxies.resolve(&forwarded(&["2001:db8::1, 2001:db9::7"]), ip("2001:db8::2")),
        ip("2001:db9::7")
    );
    assert_eq!(proxies.resolve(&forwarded(&["1.1.1.1"]), None), None);
}

#[test]
fn refuses_what_it_cannot_read() {
    for bad in ["10.0.0.0/33", "not-an-ip", "10.0.0.0/x", "::/129", ""] {
        assert!(TrustedProxies::new([bad]).is_err(), "{bad}");
    }
    assert!(TrustedProxies::new(["0.0.0.0/0", "::/0"]).is_ok());
}

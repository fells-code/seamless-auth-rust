use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

/// The error a delivery callback reports.
pub type DeliveryError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) type DeliveryFuture = Pin<Box<dyn Future<Output = Result<(), DeliveryError>> + Send>>;

/// A message the auth API hands back for the application to send.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Delivery {
    /// `otp_email`, `otp_sms`, `magic_link_email` or `enrollment_invite_email`.
    pub kind: String,
    /// An email address or phone number.
    pub to: String,
    /// The one-time code, or the magic link's token.
    pub token: Option<String>,
    pub magic_link_url: Option<String>,
    pub sign_in_url: Option<String>,
}

// The code and link are one-time credentials, so they stay out of logs that
// print a Delivery.
impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |v: &Option<String>| v.as_ref().map(|_| "[redacted]");
        f.debug_struct("Delivery")
            .field("kind", &self.kind)
            .field("to", &self.to)
            .field("token", &redacted(&self.token))
            .field("magic_link_url", &redacted(&self.magic_link_url))
            .field("sign_in_url", &self.sign_in_url)
            .finish()
    }
}

pub(crate) fn parse_delivery(raw: &Value) -> Result<Delivery, String> {
    let obj = raw.as_object().ok_or("delivery is not an object")?;
    let text = |name: &str| {
        obj.get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    let delivery = Delivery {
        kind: text("kind").unwrap_or_default(),
        to: text("to").unwrap_or_default(),
        // An SMS code can arrive as a number.
        token: match obj.get("token") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        },
        magic_link_url: text("magicLinkUrl"),
        sign_in_url: text("signInUrl"),
    };
    if delivery.kind.is_empty() || delivery.to.is_empty() {
        return Err("delivery has no kind or recipient".into());
    }
    Ok(delivery)
}

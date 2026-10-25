use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

/// The error a delivery callback reports.
pub type DeliveryError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) type DeliveryFuture = Pin<Box<dyn Future<Output = Result<(), DeliveryError>> + Send>>;

/// The kinds of message the adapter hands to the application. Any other kind
/// is logged and skipped, so an API newer than this crate cannot break delivery.
pub(crate) const KNOWN_KINDS: &[&str] = &[
    "otp_email",
    "otp_sms",
    "magic_link_email",
    "enrollment_invite_email",
    "account_notice_email",
    "account_notice_sms",
];

/// A message the auth API hands back for the application to send.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Delivery {
    /// `otp_email`, `otp_sms`, `magic_link_email`, `enrollment_invite_email`,
    /// `account_notice_email` or `account_notice_sms`.
    pub kind: String,
    /// An email address or phone number.
    pub to: String,
    /// The one-time code, or the magic link's token.
    pub token: Option<String>,
    pub magic_link_url: Option<String>,
    pub sign_in_url: Option<String>,
    /// Why an OTP code was sent, when it is not an ordinary sign-in code.
    /// `account_recovery` means someone is recovering the account: word the
    /// message as a recovery code, so an owner who did not ask for it knows.
    pub purpose: Option<String>,
    /// Which account notice this is, such as `account_recovery_opened`, for an
    /// application that uses its own template.
    pub notice: Option<String>,
    /// A notice's email subject, ready to send.
    pub subject: Option<String>,
    /// A notice's message, ready to send. It can hold the cancel link.
    pub text: Option<String>,
    /// Cancels the recovery a notice reports. It is a credential: send it to
    /// [`to`](Self::to) only, and never log it.
    pub cancel_url: Option<String>,
}

impl Delivery {
    /// An OTP code sent to recover the account rather than to sign in.
    pub fn is_account_recovery(&self) -> bool {
        self.purpose.as_deref() == Some("account_recovery")
    }
}

// The code, the links and a notice's text (which can hold the cancel link) are
// credentials, so they stay out of logs that print a Delivery.
impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |v: &Option<String>| v.as_ref().map(|_| "[redacted]");
        f.debug_struct("Delivery")
            .field("kind", &self.kind)
            .field("to", &self.to)
            .field("token", &redacted(&self.token))
            .field("magic_link_url", &redacted(&self.magic_link_url))
            .field("sign_in_url", &self.sign_in_url)
            .field("purpose", &self.purpose)
            .field("notice", &self.notice)
            .field("subject", &self.subject)
            .field("text", &redacted(&self.text))
            .field("cancel_url", &redacted(&self.cancel_url))
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
        purpose: text("purpose"),
        notice: text("notice"),
        subject: text("subject"),
        text: text("text"),
        cancel_url: text("cancelUrl"),
    };
    if delivery.kind.is_empty() || delivery.to.is_empty() {
        return Err("delivery has no kind or recipient".into());
    }
    Ok(delivery)
}

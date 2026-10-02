//! Age and expiry hints for access tokens held only in memory.

use chrono::{DateTime, Duration, Utc};

/// Assumed token lifetime. The server is authoritative; this only drives a
/// local heads-up before a request.
pub const TOKEN_VALIDITY_HOURS: i64 = 24;

/// Age of a captured token, clamped to be non-negative. Returns `None` when the
/// capture time is unknown or implausibly in the future (clock change).
pub fn token_age(captured_at: Option<DateTime<Utc>>) -> Option<Duration> {
    let captured_at = captured_at?;
    let age = Utc::now() - captured_at;
    if age < Duration::minutes(-5) {
        None
    } else if age < Duration::zero() {
        Some(Duration::zero())
    } else {
        Some(age)
    }
}

/// Whether the token is past its assumed validity window. Unknown => `false`.
pub fn is_token_expired(captured_at: Option<DateTime<Utc>>) -> bool {
    match token_age(captured_at) {
        Some(age) => age >= Duration::hours(TOKEN_VALIDITY_HOURS),
        None => false,
    }
}

/// User-facing message for an invalid/expired token, including its age if known.
pub fn token_expiry_message(captured_at: Option<DateTime<Utc>>) -> String {
    match token_age(captured_at) {
        Some(age) => {
            let hours = age.num_hours();
            if hours >= 1 {
                format!(
                    "Access token invalid or expired (captured {hours}h ago) - launch the game to refresh."
                )
            } else {
                "Access token invalid or expired (captured under an hour ago) - launch the game to refresh."
                    .to_string()
            }
        }
        None => "Access token invalid or expired - launch the game to refresh.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_capture_time_is_never_expired() {
        assert!(!is_token_expired(None));
        assert!(token_age(None).is_none());
    }

    #[test]
    fn fresh_token_is_not_expired() {
        assert!(!is_token_expired(Some(Utc::now())));
    }

    #[test]
    fn old_token_is_expired() {
        let old = Some(Utc::now() - Duration::hours(TOKEN_VALIDITY_HOURS + 1));
        assert!(is_token_expired(old));
    }

    #[test]
    fn boundary_token_at_window_is_expired() {
        let boundary =
            Some(Utc::now() - Duration::hours(TOKEN_VALIDITY_HOURS) - Duration::seconds(1));
        assert!(is_token_expired(boundary));
    }

    #[test]
    fn future_timestamp_is_treated_as_unknown() {
        let future = Some(Utc::now() + Duration::hours(2));
        assert!(token_age(future).is_none());
        assert!(!is_token_expired(future));
    }

    #[test]
    fn slightly_future_timestamp_clamps_to_zero() {
        let slight = Some(Utc::now() + Duration::minutes(1));
        assert_eq!(token_age(slight), Some(Duration::zero()));
    }

    #[test]
    fn expiry_message_includes_age_when_known() {
        let old = Some(Utc::now() - Duration::hours(27));
        assert!(token_expiry_message(old).contains("27h ago"));
    }

    #[test]
    fn expiry_message_omits_age_when_unknown() {
        assert!(!token_expiry_message(None).contains("captured"));
    }
}

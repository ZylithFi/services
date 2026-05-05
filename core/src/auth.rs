use crate::hash::tagged_sha256_hex;

pub const CONTROL_PLANE_TOKEN_ENV: &str = "ZYLITH_CONTROL_PLANE_TOKEN";
pub const RECOVERY_AUTH_HEADER: &str = "x-zylith-recovery-auth";

pub fn format_bearer_token(token: &str) -> String {
    format!("Bearer {token}")
}

pub fn extract_bearer_token(header_value: &str) -> Option<&str> {
    header_value.strip_prefix("Bearer ").map(str::trim)
}

pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        diff |= (left_byte ^ right_byte) as usize;
    }

    diff == 0
}

pub fn derive_recovery_auth_tag(account_id: &str, recovery_key_hex: &str) -> String {
    tagged_sha256_hex(
        "zylith/recovery-auth:",
        format!("{account_id}:{recovery_key_hex}").as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, derive_recovery_auth_tag, extract_bearer_token, format_bearer_token,
    };

    #[test]
    fn bearer_roundtrip_extracts_original_token() {
        let token = "secret-token";
        let header = format_bearer_token(token);
        assert_eq!(extract_bearer_token(&header), Some(token));
    }

    #[test]
    fn recovery_auth_tag_is_deterministic() {
        let a = derive_recovery_auth_tag("account-1", "deadbeef");
        let b = derive_recovery_auth_tag("account-1", "deadbeef");
        let c = derive_recovery_auth_tag("account-1", "cafebabe");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn constant_time_eq_matches_string_equality_semantics() {
        assert!(constant_time_eq("secret-token", "secret-token"));
        assert!(!constant_time_eq("secret-token", "secret-tokem"));
        assert!(!constant_time_eq("secret-token", "secret-token-extra"));
        assert!(!constant_time_eq("", "secret-token"));
    }

    #[test]
    fn recovery_auth_tag_matches_client_vector() {
        assert_eq!(
            derive_recovery_auth_tag(
                "account-1",
                "91e7fb7e163abc840faedd0c354d4e048ead61efab9bd14f7966c19f1ef44624"
            ),
            "8907823a9cfe812c9cca507d8f3d52b7b872b2f105c383c172baa3239c456395"
        );
    }
}

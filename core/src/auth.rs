use crate::hash::tagged_sha256_hex;

pub const CONTROL_PLANE_TOKEN_ENV: &str = "ZYLITH_CONTROL_PLANE_TOKEN";
pub const RECOVERY_AUTH_HEADER: &str = "x-zylith-recovery-auth";

pub fn format_bearer_token(token: &str) -> String {
    format!("Bearer {token}")
}

pub fn extract_bearer_token(header_value: &str) -> Option<&str> {
    header_value.strip_prefix("Bearer ").map(str::trim)
}

pub fn derive_recovery_auth_tag(account_id: &str, recovery_key_hex: &str) -> String {
    tagged_sha256_hex(
        "zylith/recovery-auth",
        format!("{account_id}:{recovery_key_hex}").as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::{derive_recovery_auth_tag, extract_bearer_token, format_bearer_token};

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
}

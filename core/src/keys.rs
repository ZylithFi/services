use rand::random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

use crate::ProtocolError;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct RecoverySeed(pub [u8; 32]);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct UserKeys {
    pub spend_auth_key: [u8; 32],
    pub view_key: [u8; 32],
    pub recovery_key: [u8; 32],
    pub note_recognition_key: [u8; 32],
    pub order_cancellation_key: [u8; 32],
    pub withdraw_auth_key: [u8; 32],
}

impl fmt::Debug for RecoverySeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecoverySeed").field(&"<redacted>").finish()
    }
}

impl fmt::Debug for UserKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserKeys")
            .field("spend_auth_key", &"<redacted>")
            .field("view_key", &"<redacted>")
            .field("recovery_key", &"<redacted>")
            .field("note_recognition_key", &"<redacted>")
            .field("order_cancellation_key", &"<redacted>")
            .field("withdraw_auth_key", &"<redacted>")
            .finish()
    }
}

impl RecoverySeed {
    pub fn generate() -> Self {
        Self(random())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(encoded: &str) -> Result<Self, ProtocolError> {
        let mut decoded = hex::decode(encoded)?;
        if decoded.len() != 32 {
            let len = decoded.len();
            decoded.zeroize();
            return Err(ProtocolError::InvalidSeedLength(len));
        }

        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&decoded);
        decoded.zeroize();
        Ok(Self(seed))
    }
}

pub fn derive_user_keys(seed: &RecoverySeed) -> UserKeys {
    UserKeys {
        spend_auth_key: derive_labeled_key(&seed.0, "zylith/spend-auth"),
        view_key: derive_labeled_key(&seed.0, "zylith/view"),
        recovery_key: derive_labeled_key(&seed.0, "zylith/recovery"),
        note_recognition_key: derive_labeled_key(&seed.0, "zylith/note-recognition"),
        order_cancellation_key: derive_labeled_key(&seed.0, "zylith/order-cancel"),
        withdraw_auth_key: derive_labeled_key(&seed.0, "zylith/withdraw-auth"),
    }
}

fn derive_labeled_key(seed: &[u8; 32], label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{RecoverySeed, derive_user_keys};

    #[test]
    fn seed_roundtrip_is_stable() {
        let seed = RecoverySeed::generate();
        let encoded = seed.to_hex();
        let decoded = RecoverySeed::from_hex(&encoded).expect("seed hex should parse");
        assert_eq!(seed, decoded);
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let seed = RecoverySeed([7_u8; 32]);
        let keys_a = derive_user_keys(&seed);
        let keys_b = derive_user_keys(&seed);
        assert_eq!(keys_a, keys_b);
    }

    #[test]
    fn debug_redacts_seed_and_user_keys() {
        let seed = RecoverySeed([7_u8; 32]);
        let keys = derive_user_keys(&seed);
        let seed_debug = format!("{seed:?}");
        let keys_debug = format!("{keys:?}");

        assert!(seed_debug.contains("<redacted>"));
        assert!(!seed_debug.contains("7, 7"));
        assert!(keys_debug.contains("<redacted>"));
        assert!(!keys_debug.contains(&hex::encode(keys.spend_auth_key)));
        assert!(!keys_debug.contains(&hex::encode(keys.withdraw_auth_key)));
    }
}

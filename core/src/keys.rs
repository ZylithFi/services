use bip39::{Language, Mnemonic};
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

    pub fn to_mnemonic(&self) -> Result<String, ProtocolError> {
        Mnemonic::from_entropy_in(Language::English, &self.0)
            .map(|mnemonic| mnemonic.to_string())
            .map_err(|error| ProtocolError::InvalidRecoveryPhrase(error.to_string()))
    }

    pub fn from_hex(encoded: &str) -> Result<Self, ProtocolError> {
        let decoded = hex::decode(encoded)?;
        if decoded.len() != 32 {
            return Err(ProtocolError::InvalidSeedLength(decoded.len()));
        }

        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&decoded);
        Ok(Self(seed))
    }

    pub fn from_mnemonic(phrase: &str) -> Result<Self, ProtocolError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|error| ProtocolError::InvalidRecoveryPhrase(error.to_string()))?;
        let entropy = mnemonic.to_entropy();
        if entropy.len() != 32 {
            return Err(ProtocolError::InvalidSeedLength(entropy.len()));
        }

        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&entropy);
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
    fn mnemonic_roundtrip_is_stable_and_uses_24_words() {
        let seed = RecoverySeed([11_u8; 32]);
        let phrase = seed.to_mnemonic().expect("mnemonic");
        assert_eq!(phrase.split_whitespace().count(), 24);
        let decoded = RecoverySeed::from_mnemonic(&phrase).expect("seed from phrase");
        assert_eq!(seed, decoded);
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let seed = RecoverySeed([7_u8; 32]);
        let keys_a = derive_user_keys(&seed);
        let keys_b = derive_user_keys(&seed);
        assert_eq!(keys_a, keys_b);
    }
}

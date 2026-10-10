use rand::random;
use std::fmt;
use zeroize::Zeroize;

use crate::ProtocolError;

#[derive(PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct RecoverySeed(pub(crate) [u8; 32]);

impl fmt::Debug for RecoverySeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecoverySeed").field(&"<redacted>").finish()
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

    /// imports one owned raw seed buffer and wipes that buffer before returning.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        if bytes.len() != 32 {
            let len = bytes.len();
            bytes.zeroize();
            return Err(ProtocolError::InvalidSeedLength(len));
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self(seed))
    }
}

#[cfg(test)]
mod tests {
    use super::RecoverySeed;

    #[test]
    fn seed_roundtrip_is_stable() {
        let seed = RecoverySeed::generate();
        let encoded = seed.to_hex();
        let decoded = RecoverySeed::from_hex(&encoded).expect("seed hex should parse");
        assert_eq!(seed, decoded);
    }

    #[test]
    fn raw_seed_import_requires_exactly_thirty_two_bytes() {
        assert_eq!(
            RecoverySeed::from_bytes(vec![0x5a; 32]).unwrap(),
            RecoverySeed::from_hex(&"5a".repeat(32)).unwrap()
        );
        for length in [0, 31, 33] {
            assert!(RecoverySeed::from_bytes(vec![0x5a; length]).is_err());
        }
    }

    #[test]
    fn debug_redacts_seed() {
        let seed = RecoverySeed([7_u8; 32]);
        let seed_debug = format!("{seed:?}");

        assert!(seed_debug.contains("<redacted>"));
        assert!(!seed_debug.contains("7, 7"));
    }
}

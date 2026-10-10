//! the fixed hpke profile used by private request envelopes.

use std::convert::Infallible;

use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open, single_shot_seal_with_rng,
};
use rand::{CryptoRng, RngCore};
use starknet_crypto::Felt;

use crate::ProtocolError;

type EnvelopeKem = X25519HkdfSha256;
type EnvelopeKdf = HkdfSha256;
type EnvelopeAead = ChaCha20Poly1305;

pub const HPKE_ENVELOPE_VERSION: u16 = 3;
pub const HPKE_PROFILE_ID: &str = "DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305/base";

const X25519_KEY_BYTES: usize = 32;
const HPKE_INFO_MAX_BYTES: usize = (u16::MAX as usize) - 5;
const X25519_FIELD_PRIME: [u8; X25519_KEY_BYTES] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
const X25519_LOW_ORDER_KEYS: [[u8; X25519_KEY_BYTES]; 4] = [
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
];

/// the public deployment context every private envelope is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateEnvelopeContext {
    pub chain_id: Felt,
    pub deployment_id: Felt,
}

// hpke 0.14 uses rand_core 0.10 while this workspace currently uses rand 0.9. the adapter keeps
// that dependency boundary private and preserves the crypto-rng requirement at this public seam.
struct HpkeRngAdapter<'a, R>(&'a mut R);

impl<R: RngCore> hpke::rand_core::TryRng for HpkeRngAdapter<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(destination);
        Ok(())
    }
}

impl<R: CryptoRng + RngCore> hpke::rand_core::TryCryptoRng for HpkeRngAdapter<'_, R> {}

fn validate_info(info: &[u8]) -> Result<(), ProtocolError> {
    if info.len() > HPKE_INFO_MAX_BYTES {
        return Err(ProtocolError::Crypto(
            "hpke info exceeds the rfc 9180 length limit".into(),
        ));
    }
    Ok(())
}

fn validate_x25519_bytes(bytes: &[u8], description: &str) -> Result<(), ProtocolError> {
    if bytes.len() != X25519_KEY_BYTES {
        return Err(ProtocolError::Crypto(format!(
            "{description} must be exactly 32 nonzero bytes"
        )));
    }
    let any_nonzero = bytes.iter().fold(0_u8, |acc, byte| acc | byte);
    if any_nonzero == 0 {
        return Err(ProtocolError::Crypto(format!(
            "{description} must be exactly 32 nonzero bytes"
        )));
    }
    Ok(())
}

pub(crate) fn validate_x25519_public_bytes(
    bytes: &[u8],
    description: &str,
) -> Result<(), ProtocolError> {
    validate_x25519_bytes(bytes, description)?;
    // Comparing the full little-endian encoding with p also rejects every
    // high-bit-set encoding, so a separate top-bit branch would be redundant.
    if bytes.iter().rev().cmp(X25519_FIELD_PRIME.iter().rev()) != std::cmp::Ordering::Less
        || X25519_LOW_ORDER_KEYS
            .iter()
            .any(|key| key.as_slice() == bytes)
    {
        return Err(ProtocolError::Crypto(format!(
            "{description} must be a canonical usable x25519 key"
        )));
    }
    Ok(())
}

/// seals one plaintext with the only private-envelope hpke ciphersuite and mode.
pub fn seal_hpke(
    recipient: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    validate_x25519_public_bytes(recipient, "hpke recipient public key")?;
    validate_info(info)?;
    let recipient = <EnvelopeKem as hpke::Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| ProtocolError::Crypto("invalid hpke recipient public key".into()))?;
    let mut rng = HpkeRngAdapter(rng);
    let (encapsulated_key, ciphertext) =
        single_shot_seal_with_rng::<EnvelopeAead, EnvelopeKdf, EnvelopeKem>(
            &OpModeS::Base,
            &recipient,
            info,
            plaintext,
            aad,
            &mut rng,
        )
        .map_err(|_| ProtocolError::Crypto("hpke seal failed".into()))?;

    Ok((encapsulated_key.to_bytes().to_vec(), ciphertext))
}

/// opens one ciphertext with the only private-envelope hpke ciphersuite and mode.
pub fn open_hpke(
    recipient_secret: &[u8],
    info: &[u8],
    aad: &[u8],
    encapsulated_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    validate_x25519_bytes(recipient_secret, "hpke recipient private key")?;
    validate_x25519_public_bytes(encapsulated_key, "hpke encapsulated key")?;
    validate_info(info)?;
    let recipient_secret = <EnvelopeKem as hpke::Kem>::PrivateKey::from_bytes(recipient_secret)
        .map_err(|_| ProtocolError::Crypto("invalid hpke recipient private key".into()))?;
    let encapsulated_key = <EnvelopeKem as hpke::Kem>::EncappedKey::from_bytes(encapsulated_key)
        .map_err(|_| ProtocolError::Crypto("invalid hpke encapsulated key".into()))?;

    single_shot_open::<EnvelopeAead, EnvelopeKdf, EnvelopeKem>(
        &OpModeR::Base,
        &recipient_secret,
        &encapsulated_key,
        info,
        ciphertext,
        aad,
    )
    .map_err(|_| ProtocolError::Crypto("hpke open failed".into()))
}

#[cfg(test)]
mod tests {
    use hpke::rand_core::TryRng;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    const RFC_RECIPIENT_PRIVATE_KEY: &str =
        "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb";
    const RFC_RECIPIENT_PUBLIC_KEY: &str =
        "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a";
    const RFC_ENCAPSULATED_KEY: &str =
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a";
    const RFC_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const RFC_AAD: &str = "436f756e742d30";
    const RFC_PLAINTEXT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    const RFC_CIPHERTEXT: &str = "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28";

    fn bytes(hex_value: &str) -> Vec<u8> {
        hex::decode(hex_value).unwrap()
    }

    fn crypto_error(error: ProtocolError) -> String {
        match error {
            ProtocolError::Crypto(message) => message,
            other => panic!("expected protocol cryptography error, got {other}"),
        }
    }

    #[test]
    fn hpke_rng_adapter_delegates_byte_fills() {
        let mut source = StdRng::seed_from_u64(0x5a17_2026);
        let mut expected_source = source.clone();
        let mut expected = [0_u8; 96];
        expected_source.fill_bytes(&mut expected);

        let mut actual = [0_u8; 96];
        HpkeRngAdapter(&mut source)
            .try_fill_bytes(&mut actual)
            .unwrap();

        assert_eq!(actual, expected);
        assert_ne!(actual, [0_u8; 96]);
    }

    #[test]
    fn hpke_info_validation_enforces_the_exact_rfc_boundary() {
        assert!(validate_info(&vec![0_u8; HPKE_INFO_MAX_BYTES]).is_ok());
        let error = validate_info(&vec![0_u8; HPKE_INFO_MAX_BYTES + 1]).unwrap_err();
        assert_eq!(
            crypto_error(error),
            "hpke info exceeds the rfc 9180 length limit"
        );
    }

    #[test]
    fn x25519_validation_enforces_length_nonzero_and_canonicality() {
        assert!(validate_x25519_bytes(&[1_u8; X25519_KEY_BYTES], "private").is_ok());
        assert_eq!(
            crypto_error(validate_x25519_bytes(&[1_u8; 31], "private").unwrap_err()),
            "private must be exactly 32 nonzero bytes"
        );
        assert_eq!(
            crypto_error(validate_x25519_bytes(&[1_u8; 33], "private").unwrap_err()),
            "private must be exactly 32 nonzero bytes"
        );
        assert_eq!(
            crypto_error(validate_x25519_bytes(&[0_u8; 32], "private").unwrap_err()),
            "private must be exactly 32 nonzero bytes"
        );

        let mut largest_canonical = X25519_FIELD_PRIME;
        // p - 1 is an explicitly rejected low-order point; p - 2 exercises the
        // canonical-field boundary without selecting that point.
        largest_canonical[0] -= 2;
        assert!(validate_x25519_public_bytes(&largest_canonical, "public").is_ok());
        assert_eq!(
            crypto_error(validate_x25519_public_bytes(&X25519_FIELD_PRIME, "public").unwrap_err()),
            "public must be a canonical usable x25519 key"
        );

        let mut high_bit = largest_canonical;
        high_bit[31] |= 0x80;
        assert_eq!(
            crypto_error(validate_x25519_public_bytes(&high_bit, "public").unwrap_err()),
            "public must be a canonical usable x25519 key"
        );

        for low_order in X25519_LOW_ORDER_KEYS {
            assert_eq!(
                crypto_error(validate_x25519_public_bytes(&low_order, "public").unwrap_err()),
                "public must be a canonical usable x25519 key"
            );
        }
    }

    #[test]
    fn hpke_open_reports_precondition_failures_before_library_parsing() {
        let valid_private = bytes(RFC_RECIPIENT_PRIVATE_KEY);
        let valid_encapsulated = bytes(RFC_ENCAPSULATED_KEY);
        let ciphertext = bytes(RFC_CIPHERTEXT);

        assert_eq!(
            crypto_error(
                open_hpke(
                    &[0_u8; 32],
                    b"info",
                    b"aad",
                    &valid_encapsulated,
                    &ciphertext
                )
                .unwrap_err()
            ),
            "hpke recipient private key must be exactly 32 nonzero bytes"
        );
        assert_eq!(
            crypto_error(
                open_hpke(&valid_private, b"info", b"aad", &[0_u8; 32], &ciphertext).unwrap_err()
            ),
            "hpke encapsulated key must be exactly 32 nonzero bytes"
        );
        assert_eq!(
            crypto_error(
                open_hpke(
                    &valid_private,
                    &vec![0_u8; HPKE_INFO_MAX_BYTES + 1],
                    b"aad",
                    &valid_encapsulated,
                    &ciphertext,
                )
                .unwrap_err()
            ),
            "hpke info exceeds the rfc 9180 length limit"
        );
    }

    #[test]
    fn hpke_profile_is_frozen() {
        assert_eq!(HPKE_ENVELOPE_VERSION, 3);
        assert_eq!(
            HPKE_PROFILE_ID,
            "DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305/base"
        );
    }

    #[test]
    fn hpke_opens_rfc_9180_a_2_1_vector() {
        let plaintext = open_hpke(
            &bytes(RFC_RECIPIENT_PRIVATE_KEY),
            &bytes(RFC_INFO),
            &bytes(RFC_AAD),
            &bytes(RFC_ENCAPSULATED_KEY),
            &bytes(RFC_CIPHERTEXT),
        )
        .unwrap();

        assert_eq!(plaintext, bytes(RFC_PLAINTEXT));
    }

    #[test]
    fn hpke_round_trip_uses_the_fixed_profile() {
        let mut rng = StdRng::from_seed([0x42; 32]);
        let info = b"zylith private envelope v2";
        let aad = b"deployment-bound aad";
        let plaintext = b"private request";

        let (encapsulated_key, ciphertext) = seal_hpke(
            &bytes(RFC_RECIPIENT_PUBLIC_KEY),
            info,
            aad,
            plaintext,
            &mut rng,
        )
        .unwrap();
        let opened = open_hpke(
            &bytes(RFC_RECIPIENT_PRIVATE_KEY),
            info,
            aad,
            &encapsulated_key,
            &ciphertext,
        )
        .unwrap();

        assert_eq!(encapsulated_key.len(), 32);
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn hpke_rejects_every_authenticated_input_tamper() {
        let mut rng = StdRng::from_seed([0x24; 32]);
        let public_key = bytes(RFC_RECIPIENT_PUBLIC_KEY);
        let private_key = bytes(RFC_RECIPIENT_PRIVATE_KEY);
        let info = b"info";
        let aad = b"aad";
        let plaintext = b"plaintext";
        let (encapsulated_key, ciphertext) =
            seal_hpke(&public_key, info, aad, plaintext, &mut rng).unwrap();

        let mut tampered_ciphertext = ciphertext.clone();
        tampered_ciphertext[0] ^= 1;
        assert!(
            open_hpke(
                &private_key,
                info,
                aad,
                &encapsulated_key,
                &tampered_ciphertext,
            )
            .is_err()
        );

        let mut tampered_encapsulated_key = encapsulated_key.clone();
        tampered_encapsulated_key[0] ^= 1;
        assert!(
            open_hpke(
                &private_key,
                info,
                aad,
                &tampered_encapsulated_key,
                &ciphertext,
            )
            .is_err()
        );
        assert!(
            open_hpke(
                &private_key,
                b"changed info",
                aad,
                &encapsulated_key,
                &ciphertext,
            )
            .is_err()
        );
        assert!(
            open_hpke(
                &private_key,
                info,
                b"changed aad",
                &encapsulated_key,
                &ciphertext,
            )
            .is_err()
        );
    }

    #[test]
    fn hpke_rejects_malformed_or_all_zero_keys() {
        let mut rng = StdRng::from_seed([0x66; 32]);
        let info = b"info";
        let aad = b"aad";
        let plaintext = b"plaintext";

        assert!(seal_hpke(&[1; 31], info, aad, plaintext, &mut rng).is_err());
        assert!(seal_hpke(&[0; 32], info, aad, plaintext, &mut rng).is_err());
        assert!(open_hpke(&[1; 31], info, aad, &[1; 32], &[1; 16]).is_err());
        assert!(open_hpke(&[0; 32], info, aad, &[1; 32], &[1; 16]).is_err());
        assert!(
            open_hpke(
                &bytes(RFC_RECIPIENT_PRIVATE_KEY),
                info,
                aad,
                &[1; 31],
                &[1; 16],
            )
            .is_err()
        );
        assert!(
            open_hpke(
                &bytes(RFC_RECIPIENT_PRIVATE_KEY),
                info,
                aad,
                &[0; 32],
                &[1; 16],
            )
            .is_err()
        );
    }

    #[test]
    fn hpke_rejects_low_order_and_noncanonical_public_keys() {
        let mut rng = StdRng::from_seed([0x68; 32]);
        let info = b"info";
        let aad = b"aad";
        let plaintext = b"plaintext";
        let low_order_keys = [
            {
                let mut key = [0_u8; 32];
                key[0] = 1;
                key
            },
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
        ];
        for key in low_order_keys {
            assert!(seal_hpke(&key, info, aad, plaintext, &mut rng).is_err());
            assert!(
                open_hpke(&bytes(RFC_RECIPIENT_PRIVATE_KEY), info, aad, &key, &[1; 16]).is_err()
            );
        }

        let mut high_bit = bytes(RFC_RECIPIENT_PUBLIC_KEY);
        high_bit[31] |= 0x80;
        assert!(seal_hpke(&high_bit, info, aad, plaintext, &mut rng).is_err());
        assert!(
            open_hpke(
                &bytes(RFC_RECIPIENT_PRIVATE_KEY),
                info,
                aad,
                &high_bit,
                &[1; 16],
            )
            .is_err()
        );

        let p = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(seal_hpke(&p, info, aad, plaintext, &mut rng).is_err());
        assert!(open_hpke(&bytes(RFC_RECIPIENT_PRIVATE_KEY), info, aad, &p, &[1; 16]).is_err());
    }

    #[test]
    fn hpke_rejects_oversized_info_without_panicking() {
        let mut rng = StdRng::from_seed([0x77; 32]);
        let oversized_info = vec![0; HPKE_INFO_MAX_BYTES + 1];

        assert!(
            seal_hpke(
                &bytes(RFC_RECIPIENT_PUBLIC_KEY),
                &oversized_info,
                b"aad",
                b"plaintext",
                &mut rng,
            )
            .is_err()
        );
        assert!(
            open_hpke(
                &bytes(RFC_RECIPIENT_PRIVATE_KEY),
                &oversized_info,
                b"aad",
                &bytes(RFC_ENCAPSULATED_KEY),
                &bytes(RFC_CIPHERTEXT),
            )
            .is_err()
        );
    }
}

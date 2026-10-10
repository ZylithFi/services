use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use starknet_crypto::Felt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ProtocolError, RecoverySeed};

pub const WALLET_KEY_SCHEDULE_ID: &str = "zylith-wallet-hkdf-sha256-v2";
pub const WALLET_KEY_SCHEDULE_VERSION: u16 = 2;

pub fn deserialize_wallet_key_schedule_version<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = <u16 as serde::Deserialize>::deserialize(deserializer)?;
    if version != WALLET_KEY_SCHEDULE_VERSION {
        return Err(serde::de::Error::custom("wallet migration required"));
    }
    Ok(version)
}

const ROOT_SALT: &[u8] = b"zylith/wallet-root/hkdf-sha256/v2";
const KEY_PROTOCOL: &[u8] = b"zylith/wallet-key/v2";
const FIELD_PROTOCOL: &[u8] = b"zylith/wallet-field/v2";
const DEPOSIT_BLINDING_PROTOCOL: &[u8] = b"zylith/deposit-blinding/hmac-sha256/v2";

#[inline(always)]
fn require_zeroize_on_drop<T: ZeroizeOnDrop>(_: &T) {}

// the field modulus and curve order are distinct 252-bit integers, encoded big-endian.
const FIELD_MODULUS: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const STARK_CURVE_ORDER: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xb7, 0x81, 0x12, 0x6d, 0xca, 0xe7, 0xb2, 0x32, 0x1e, 0x66, 0xa2, 0x41, 0xad, 0xc6, 0x4d, 0x2f,
];

/// closed purposes for nonzero field elements and stark signing scalars.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletFieldPurpose {
    SpendAuthorization,
    WithdrawAuthorization,
    Cancellation,
    OwnerTag,
    DepositBlinding,
    ProofSignerKey,
    ProofSignerSalt,
}

impl WalletFieldPurpose {
    fn purpose(self) -> Purpose {
        match self {
            Self::SpendAuthorization => Purpose::SpendAuthorization,
            Self::WithdrawAuthorization => Purpose::WithdrawAuthorization,
            Self::Cancellation => Purpose::Cancellation,
            Self::OwnerTag => Purpose::OwnerTag,
            Self::DepositBlinding => Purpose::DepositBlinding,
            Self::ProofSignerKey => Purpose::ProofSignerKey,
            Self::ProofSignerSalt => Purpose::ProofSignerSalt,
        }
    }
}

/// the mandatory public deployment context for the embedded proof signer.
pub struct ProofSignerDerivationContext {
    chain_id: [u8; 32],
    proof_signer_class_hash: [u8; 32],
}

impl ProofSignerDerivationContext {
    pub fn from_hex(chain_id: &str, proof_signer_class_hash: &str) -> Result<Self, ProtocolError> {
        let chain_id = parse_canonical_field_hex(chain_id)?;
        let proof_signer_class_hash = parse_canonical_field_hex(proof_signer_class_hash)?;
        if chain_id == Felt::ZERO || proof_signer_class_hash == Felt::ZERO {
            return Err(ProtocolError::Crypto(
                "proof signer context must be nonzero".into(),
            ));
        }
        Ok(Self {
            chain_id: chain_id.to_bytes_be(),
            proof_signer_class_hash: proof_signer_class_hash.to_bytes_be(),
        })
    }

    pub fn parts(&self) -> [&[u8]; 2] {
        [&self.chain_id, &self.proof_signer_class_hash]
    }
}

#[derive(Clone, Copy)]
enum NumericTarget {
    Field,
    StarkScalar,
}

impl NumericTarget {
    fn identifier(self) -> &'static [u8] {
        match self {
            Self::Field => b"field",
            Self::StarkScalar => b"stark-scalar",
        }
    }

    fn modulus(self) -> &'static [u8; 32] {
        match self {
            Self::Field => &FIELD_MODULUS,
            Self::StarkScalar => &STARK_CURVE_ORDER,
        }
    }
}

/// a child key whose owned bytes are wiped on drop and redacted in debug output.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct WalletKeyBytes([u8; 32]);

impl WalletKeyBytes {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for WalletKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WalletKeyBytes")
            .field(&"<redacted>")
            .finish()
    }
}

/// the canonical byte-key schedule, retaining only its private pseudorandom key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WalletKeyScheduleV2 {
    prk: WalletKeyBytes,
}

impl fmt::Debug for WalletKeyScheduleV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletKeyScheduleV2")
            .field("prk", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy)]
enum Purpose {
    SpendAuthorization,
    WithdrawAuthorization,
    Cancellation,
    #[cfg(test)]
    View,
    RecoveryEncryption,
    DepositBlinding,
    OwnerTag,
    LocalStore,
    AccountId,
    ProofSignerKey,
    ProofSignerSalt,
}

impl Purpose {
    fn identifier(self) -> &'static [u8] {
        match self {
            Self::SpendAuthorization => b"spend-authorization",
            Self::WithdrawAuthorization => b"withdraw-authorization",
            Self::Cancellation => b"cancellation",
            #[cfg(test)]
            Self::View => b"view",
            Self::RecoveryEncryption => b"recovery-encryption",
            Self::DepositBlinding => b"deposit-blinding",
            Self::OwnerTag => b"owner-tag",
            Self::LocalStore => b"local-store",
            Self::AccountId => b"account-id",
            Self::ProofSignerKey => b"proof-signer-key",
            Self::ProofSignerSalt => b"proof-signer-salt",
        }
    }
}

impl WalletKeyScheduleV2 {
    pub fn from_seed(seed: &RecoverySeed) -> Self {
        let (extracted, _) = Hkdf::<Sha256>::extract(Some(ROOT_SALT), &seed.0);
        let extracted = Zeroizing::new(extracted);
        require_zeroize_on_drop(&extracted);
        let mut prk = WalletKeyBytes([0; 32]);
        prk.0.copy_from_slice(&extracted);
        Self { prk }
    }

    #[cfg(test)]
    fn spend_authorization_key(&self) -> WalletKeyBytes {
        self.fixed_key(Purpose::SpendAuthorization)
    }

    #[cfg(test)]
    fn withdraw_authorization_key(&self) -> WalletKeyBytes {
        self.fixed_key(Purpose::WithdrawAuthorization)
    }

    #[cfg(test)]
    fn cancellation_key(&self) -> WalletKeyBytes {
        self.fixed_key(Purpose::Cancellation)
    }

    #[cfg(test)]
    fn view_key(&self) -> WalletKeyBytes {
        self.fixed_key(Purpose::View)
    }

    pub(crate) fn recovery_encryption_key(&self) -> WalletKeyBytes {
        self.fixed_key(Purpose::RecoveryEncryption)
    }

    pub(crate) fn deposit_blinding_key(&self) -> WalletKeyBytes {
        self.fixed_key(Purpose::DepositBlinding)
    }

    pub(crate) fn deposit_blinding(&self, fields: [&[u8]; 8]) -> Result<Felt, ProtocolError> {
        let key = self.deposit_blinding_key();
        sample_nonzero(NumericTarget::Field, |counter| {
            let counter_bytes = counter.to_be_bytes();
            let mut parts: [&[u8]; 10] = [&[]; 10];
            parts[0] = DEPOSIT_BLINDING_PROTOCOL;
            parts[1..9].copy_from_slice(&fields);
            parts[9] = &counter_bytes;
            let encoded = encode_context(&parts)?;
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
                .map_err(|_| ProtocolError::Crypto("invalid deposit blinding key length".into()))?;
            mac.update(&encoded);
            let digest = Zeroizing::new(mac.finalize().into_bytes());
            require_zeroize_on_drop(&digest);
            let mut candidate = WalletKeyBytes([0; 32]);
            candidate.0.copy_from_slice(&digest);
            Ok(candidate)
        })
    }

    #[cfg(test)]
    fn owner_tag_key(&self) -> WalletKeyBytes {
        self.fixed_key(Purpose::OwnerTag)
    }

    /// the public pseudonymous field identifier carried by this wallet's notes.
    pub fn owner_tag(&self) -> Result<Felt, ProtocolError> {
        self.derive_nonzero_field(WalletFieldPurpose::OwnerTag, &[])
    }

    /// the closed wallet-state key binds this schedule's own account child and purpose.
    pub(crate) fn wallet_state_key(&self) -> WalletKeyBytes {
        let account = self.fixed_key(Purpose::AccountId);
        self.derive_key(Purpose::LocalStore, &[account.as_bytes(), b"wallet-state"])
            .expect("fixed wallet state key derivation has valid lengths")
    }

    #[cfg(test)]
    fn local_store_key(&self, context: &[&[u8]]) -> Result<WalletKeyBytes, ProtocolError> {
        self.derive_key(Purpose::LocalStore, context)
    }

    /// the public account identifier, encoded as lowercase hex without a prefix.
    pub fn account_id(&self) -> String {
        hex::encode(self.fixed_key(Purpose::AccountId).as_bytes())
    }

    /// derives a nonzero field element from its purpose child and ordered binary context.
    pub fn derive_nonzero_field(
        &self,
        purpose: WalletFieldPurpose,
        context: &[&[u8]],
    ) -> Result<Felt, ProtocolError> {
        let child = self.derive_key(purpose.purpose(), &[])?;
        derive_nonzero_from_key(child.as_bytes(), purpose, context, NumericTarget::Field)
    }

    /// derives a nonzero signing scalar strictly below the stark curve order.
    pub fn derive_nonzero_stark_scalar(
        &self,
        purpose: WalletFieldPurpose,
        context: &[&[u8]],
    ) -> Result<Felt, ProtocolError> {
        let child = self.derive_key(purpose.purpose(), &[])?;
        derive_nonzero_stark_scalar_from_key(child.as_bytes(), purpose, context)
    }

    fn fixed_key(&self, purpose: Purpose) -> WalletKeyBytes {
        self.derive_key(purpose, &[])
            .expect("fixed wallet key derivation has valid lengths")
    }

    fn derive_key(
        &self,
        purpose: Purpose,
        context: &[&[u8]],
    ) -> Result<WalletKeyBytes, ProtocolError> {
        let part_count = context
            .len()
            .checked_add(2)
            .ok_or_else(context_size_error)?;
        u32::try_from(part_count).map_err(|_| context_size_error())?;
        let mut parts = Vec::new();
        parts
            .try_reserve_exact(part_count)
            .map_err(|_| context_size_error())?;
        parts.push(KEY_PROTOCOL);
        parts.push(purpose.identifier());
        parts.extend_from_slice(context);
        let info = encode_context(&parts)?;
        let hkdf = Hkdf::<Sha256>::from_prk(self.prk.as_bytes())
            .map_err(|_| ProtocolError::Crypto("invalid wallet pseudorandom key length".into()))?;
        let mut output = WalletKeyBytes([0; 32]);
        hkdf.expand(&info, &mut output.0)
            .map_err(|_| ProtocolError::Crypto("wallet key expansion failed".into()))?;
        Ok(output)
    }
}

// the compatibility seam consumes an already-derived purpose child, never a recovery seed.
pub(crate) fn derive_nonzero_stark_scalar_from_key(
    child: &[u8; 32],
    purpose: WalletFieldPurpose,
    context: &[&[u8]],
) -> Result<Felt, ProtocolError> {
    derive_nonzero_from_key(child, purpose, context, NumericTarget::StarkScalar)
}

fn derive_nonzero_from_key(
    child: &[u8; 32],
    purpose: WalletFieldPurpose,
    context: &[&[u8]],
    target: NumericTarget,
) -> Result<Felt, ProtocolError> {
    let hkdf = Hkdf::<Sha256>::from_prk(child)
        .map_err(|_| ProtocolError::Crypto("invalid wallet child key length".into()))?;
    sample_nonzero(target, |counter| {
        let part_count = context
            .len()
            .checked_add(4)
            .ok_or_else(context_size_error)?;
        u32::try_from(part_count).map_err(|_| context_size_error())?;
        let mut parts = Vec::new();
        parts
            .try_reserve_exact(part_count)
            .map_err(|_| context_size_error())?;
        let counter_bytes = counter.to_be_bytes();
        parts.push(FIELD_PROTOCOL);
        parts.push(target.identifier());
        parts.push(purpose.purpose().identifier());
        parts.extend_from_slice(context);
        parts.push(&counter_bytes);
        let info = encode_context(&parts)?;
        let mut candidate = WalletKeyBytes([0; 32]);
        hkdf.expand(&info, &mut candidate.0)
            .map_err(|_| ProtocolError::Crypto("wallet numeric expansion failed".into()))?;
        Ok(candidate)
    })
}

fn sample_nonzero(
    target: NumericTarget,
    mut candidate_source: impl FnMut(u32) -> Result<WalletKeyBytes, ProtocolError>,
) -> Result<Felt, ProtocolError> {
    for counter in 0_u32..=255 {
        let mut candidate = candidate_source(counter)?;
        // both target moduli use 252 bits; clearing only the four unused bits is unbiased.
        candidate.0[0] &= 0x0f;
        if candidate.0 != [0; 32] && &candidate.0 < target.modulus() {
            // conversion is safe only after the byte comparison, as felt conversion reduces.
            return Ok(Felt::from_bytes_be(candidate.as_bytes()));
        }
    }
    Err(ProtocolError::Crypto(
        "wallet numeric derivation exhausted".into(),
    ))
}

fn context_size_error() -> ProtocolError {
    ProtocolError::Crypto("wallet key context exceeds encoding or allocation limits".into())
}

pub(crate) fn encode_context(parts: &[&[u8]]) -> Result<Vec<u8>, ProtocolError> {
    let part_count = u32::try_from(parts.len()).map_err(|_| context_size_error())?;
    let encoded_len = parts.iter().try_fold(4_usize, |length, part| {
        u32::try_from(part.len()).map_err(|_| context_size_error())?;
        length
            .checked_add(4)
            .and_then(|length| length.checked_add(part.len()))
            .ok_or_else(context_size_error)
    })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| context_size_error())?;
    encoded.extend_from_slice(&part_count.to_be_bytes());
    for part in parts {
        let part_len = u32::try_from(part.len()).map_err(|_| context_size_error())?;
        encoded.extend_from_slice(&part_len.to_be_bytes());
        encoded.extend_from_slice(part);
    }
    Ok(encoded)
}

// parse without reduction so deployment and note fields have one canonical numeric meaning.
pub(crate) fn parse_canonical_field_hex(value: &str) -> Result<Felt, ProtocolError> {
    let invalid = || ProtocolError::Crypto("invalid canonical felt hex".into());
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|digit| digit.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let digits = digits.trim_start_matches('0');
    if digits.len() > 64 {
        return Err(invalid());
    }
    let mut bytes = [0_u8; 32];
    for (index, digit) in digits.bytes().rev().enumerate() {
        let nibble = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return Err(invalid()),
        };
        bytes[31 - index / 2] |= nibble << ((index % 2) * 4);
    }
    if bytes >= FIELD_MODULUS {
        return Err(invalid());
    }
    Ok(Felt::from_bytes_be(&bytes))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde::Deserialize;
    use starknet_crypto::Felt;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{
        FIELD_MODULUS, NumericTarget, ProofSignerDerivationContext, WalletFieldPurpose,
        WalletKeyBytes, WalletKeyScheduleV2, derive_nonzero_stark_scalar_from_key, encode_context,
        parse_canonical_field_hex, sample_nonzero,
    };
    use crate::{ProtocolError, RecoverySeed};

    fn candidate(encoded: &str) -> WalletKeyBytes {
        WalletKeyBytes(hex::decode(encoded).unwrap().try_into().unwrap())
    }

    #[test]
    fn wallet_key_schedule_deserialization_accepts_only_v2() {
        #[derive(Debug, Deserialize)]
        struct Versioned {
            #[serde(deserialize_with = "super::deserialize_wallet_key_schedule_version")]
            version: u16,
        }

        assert_eq!(
            serde_json::from_str::<Versioned>(r#"{"version":2}"#)
                .unwrap()
                .version,
            2
        );
        for version in [0, 1, 3, u16::MAX] {
            let error = serde_json::from_str::<Versioned>(&format!(r#"{{"version":{version}}}"#))
                .unwrap_err();
            assert!(error.to_string().contains("wallet migration required"));
        }
    }

    #[test]
    fn proof_signer_context_requires_canonical_nonzero_fields() {
        let valid =
            ProofSignerDerivationContext::from_hex("0x534e5f5345504f4c4941", "0x123").unwrap();
        assert_eq!(valid.parts()[0].len(), 32);
        assert_eq!(valid.parts()[1].len(), 32);

        for (chain, class_hash) in [("0x0", "0x123"), ("0x1", "0x0")] {
            assert_eq!(
                ProofSignerDerivationContext::from_hex(chain, class_hash)
                    .err()
                    .unwrap()
                    .to_string(),
                "protocol cryptography error: proof signer context must be nonzero"
            );
        }
        for invalid in ["", "0x", "-1", "0xgg"] {
            assert!(ProofSignerDerivationContext::from_hex(invalid, "0x123").is_err());
            assert!(ProofSignerDerivationContext::from_hex("0x1", invalid).is_err());
        }
    }

    #[test]
    fn deposit_blinding_matches_the_independent_v2_vector() {
        let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([1; 32]));
        let chain = hex::decode("00000000000000000000000000000000000000000000534e5f5345504f4c4941")
            .unwrap();
        let bridge =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000123")
                .unwrap();
        let amount = 10_u128.to_be_bytes();
        let nonce = 42_u64.to_be_bytes();
        let owner = hex::decode("000000000000000000000000000000000000000000000000000000000000000a")
            .unwrap();
        let spend = hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
        let withdraw =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();
        let fields = [
            chain.as_slice(),
            bridge.as_slice(),
            b"STRK".as_slice(),
            amount.as_slice(),
            nonce.as_slice(),
            owner.as_slice(),
            spend.as_slice(),
            withdraw.as_slice(),
        ];

        let blinding = schedule.deposit_blinding(fields).unwrap();
        assert_eq!(
            hex::encode(blinding.to_bytes_be()),
            "02b64f4e0730aed11055c198140b6faf543f2ccc3d9978ed1079e7a469eab861"
        );

        for field in 0..fields.len() {
            let mut changed_storage = fields.map(<[u8]>::to_vec);
            changed_storage[field].push(0xff);
            let changed = changed_storage
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let changed: [&[u8]; 8] = changed.try_into().unwrap();
            assert_ne!(schedule.deposit_blinding(changed).unwrap(), blinding);
        }
    }

    #[test]
    fn canonical_field_hex_parser_rejects_reduction_and_malformed_encodings() {
        assert_eq!(parse_canonical_field_hex("0x0").unwrap(), Felt::ZERO);
        assert_eq!(parse_canonical_field_hex("0001").unwrap(), Felt::ONE);
        assert_eq!(
            parse_canonical_field_hex(&format!("{}1", "0".repeat(100))).unwrap(),
            Felt::ONE
        );

        let mut maximum = FIELD_MODULUS;
        maximum[31] -= 1;
        assert_eq!(
            parse_canonical_field_hex(&hex::encode(maximum))
                .unwrap()
                .to_bytes_be(),
            maximum
        );
        assert!(parse_canonical_field_hex(&hex::encode(FIELD_MODULUS)).is_err());
        let mut above_modulus = FIELD_MODULUS;
        above_modulus[31] += 1;
        assert!(parse_canonical_field_hex(&hex::encode(above_modulus)).is_err());
        for invalid in [
            "",
            "0x",
            "-1",
            "0xgg",
            "10000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(
                parse_canonical_field_hex(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn wallet_state_closed_key_known_answer() {
        for (byte, key) in [
            (
                0,
                "044a198931c2c41525ee84bf1181f3d15aca1760521c4a9d088882f472e08edf",
            ),
            (
                1,
                "a8ca913b1785cf51307dfda4f676ea649281e17c9f0f123908b897c821f3b22d",
            ),
        ] {
            let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([byte; 32]));
            assert_eq!(hex::encode(schedule.wallet_state_key().as_bytes()), key);
            let account = hex::decode(schedule.account_id()).unwrap();
            for context in [
                &[][..],
                &[b"wallet-state".as_slice()][..],
                &[account.as_slice(), b"orders".as_slice()][..],
                &[&[byte; 32][..], b"wallet-state".as_slice()][..],
                &[b"wallet-state".as_slice(), account.as_slice()][..],
            ] {
                assert_ne!(
                    schedule.wallet_state_key().as_bytes(),
                    schedule.local_store_key(context).unwrap().as_bytes()
                );
            }
        }
    }

    #[test]
    fn owner_tag_known_answers_are_nonzero_canonical_fields() {
        let modulus: [u8; 32] =
            hex::decode("0800000000000011000000000000000000000000000000000000000000000001")
                .unwrap()
                .try_into()
                .unwrap();
        let mut tags = Vec::new();
        for (seed_byte, expected) in [
            (
                0_u8,
                "073b806154cbf359afe4adfd1c35c4b517227becc6342fc58627b3cbde7695be",
            ),
            (
                1_u8,
                "028204bd403e2e99dbbbc654d2cc20f3a0ec2a15d43f58235b8a5dfb02f6c0d1",
            ),
        ] {
            let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([seed_byte; 32]));
            let tag = schedule.owner_tag().unwrap();
            assert_eq!(hex::encode(tag.to_bytes_be()), expected);
            assert_ne!(tag, Felt::ZERO);
            assert!(tag.to_bytes_be() < modulus);
            assert_eq!(tag, schedule.owner_tag().unwrap());
            assert_eq!(
                tag,
                schedule
                    .derive_nonzero_field(WalletFieldPurpose::OwnerTag, &[])
                    .unwrap()
            );
            tags.push(tag);
        }
        assert_ne!(tags[0], tags[1]);
    }

    #[test]
    fn derive_nonzero_field_rejects_zero_and_out_of_range_candidates() {
        let candidates = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0800000000000011000000000000000000000000000000000000000000000001",
            "0800000000000011000000000000000000000000000000000000000000000002",
            "000000000000000000000000000000000000000000000000000000000000002a",
        ];
        let mut counters = Vec::new();
        let actual = sample_nonzero(NumericTarget::Field, |counter| {
            counters.push(counter);
            Ok(candidate(candidates[counter as usize]))
        })
        .unwrap();
        assert_eq!(actual, Felt::from(42_u8));
        assert_eq!(counters, [0, 1, 2, 3]);
    }

    #[test]
    fn derive_nonzero_stark_scalar_rejects_zero_and_out_of_range_candidates() {
        let candidates = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
            "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d30",
            "000000000000000000000000000000000000000000000000000000000000002a",
        ];
        let mut counters = Vec::new();
        let actual = sample_nonzero(NumericTarget::StarkScalar, |counter| {
            counters.push(counter);
            Ok(candidate(candidates[counter as usize]))
        })
        .unwrap();
        assert_eq!(actual, Felt::from(42_u8));
        assert_eq!(counters, [0, 1, 2, 3]);
    }

    #[test]
    fn derive_nonzero_preserves_bit_251_and_masks_only_unused_bits() {
        for (target, raw, expected) in [
            (
                NumericTarget::Field,
                "f800000000000011000000000000000000000000000000000000000000000000",
                "0800000000000011000000000000000000000000000000000000000000000000",
            ),
            (
                NumericTarget::StarkScalar,
                "f800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2e",
                "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2e",
            ),
        ] {
            let actual = sample_nonzero(target, |counter| {
                assert_eq!(counter, 0);
                Ok(candidate(raw))
            })
            .unwrap();
            assert_eq!(hex::encode(actual.to_bytes_be()), expected);
        }
    }

    #[test]
    fn derive_nonzero_exhaustion_stops_after_counter_255() {
        for target in [NumericTarget::Field, NumericTarget::StarkScalar] {
            let mut counters = Vec::new();
            let error = sample_nonzero(target, |counter| {
                counters.push(counter);
                Ok(WalletKeyBytes([0; 32]))
            })
            .unwrap_err();
            assert_eq!(counters, (0_u32..=255).collect::<Vec<_>>());
            assert!(matches!(error, ProtocolError::Crypto(_)));
            assert_eq!(
                error.to_string(),
                "protocol cryptography error: wallet numeric derivation exhausted"
            );
        }
    }

    #[test]
    fn derive_nonzero_accepts_a_valid_candidate_at_counter_255() {
        for target in [NumericTarget::Field, NumericTarget::StarkScalar] {
            let mut counters = Vec::new();
            let actual = sample_nonzero(target, |counter| {
                counters.push(counter);
                let mut bytes = [0; 32];
                if counter == 255 {
                    bytes[31] = 42;
                }
                Ok(WalletKeyBytes(bytes))
            })
            .unwrap();
            assert_eq!(actual, Felt::from(42_u8));
            assert_eq!(counters, (0_u32..=255).collect::<Vec<_>>());
        }
    }

    #[test]
    fn derive_nonzero_candidate_errors_stop_without_retry() {
        let mut counters = Vec::new();
        let error = sample_nonzero(NumericTarget::Field, |counter| {
            counters.push(counter);
            Err(ProtocolError::Crypto("candidate expansion failed".into()))
        })
        .unwrap_err();
        assert_eq!(counters, [0]);
        assert_eq!(
            error.to_string(),
            "protocol cryptography error: candidate expansion failed"
        );
    }

    #[test]
    fn derive_nonzero_proof_signer_known_answer_vectors_are_stable() {
        for (seed_byte, context, expected_key, expected_salt) in [
            (
                0_u8,
                &[][..],
                "06ecdfbfb252201909e4af612fc297ae96b2aa6a3fd68dd79823d0f583baeec7",
                "02d0a80229ebacfb1eb00af83e7abacdf521a33ccf2a618e04d4a31263b56e96",
            ),
            (
                1_u8,
                &[][..],
                "0040f2bce806c309fe8f925beefeeb37c79a4df6111ccbb7da2d8d8c6cb92d44",
                "04d464cd9db984eff4e382a2649481988d500523a8e2060f96706667d7bf5ff9",
            ),
            (
                0_u8,
                &[b"chain".as_slice(), &[0, 1]][..],
                "0676b3552ca5c7af1aa4453f97bfaaeeef699299b012a35c39c853af0cd84842",
                "06330abd0a05d20f56193328dc282882517ba692a95bec1ccf54bfc8a00ad168",
            ),
            (
                1_u8,
                &[b"chain".as_slice(), &[0, 1]][..],
                "020b0db44d7e0ba516f6bd5c13365d191e63883f299d08fa861bcbc3b78bd32e",
                "073840b7b0a23fa8ccaf4a516c25b15e3de8115abb18b367dc47ca129e4bbca9",
            ),
        ] {
            let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([seed_byte; 32]));
            let key = schedule
                .derive_nonzero_stark_scalar(WalletFieldPurpose::ProofSignerKey, context)
                .unwrap();
            let salt = schedule
                .derive_nonzero_field(WalletFieldPurpose::ProofSignerSalt, context)
                .unwrap();
            assert_eq!(hex::encode(key.to_bytes_be()), expected_key);
            assert_eq!(hex::encode(salt.to_bytes_be()), expected_salt);
        }
    }

    #[test]
    fn derive_nonzero_separates_targets_purposes_and_canonical_context() {
        let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([1; 32]));
        let context = &[b"ab".as_slice(), b"c".as_slice()];
        let scalar = schedule
            .derive_nonzero_stark_scalar(WalletFieldPurpose::ProofSignerKey, context)
            .unwrap();
        assert_eq!(
            scalar,
            schedule
                .derive_nonzero_stark_scalar(WalletFieldPurpose::ProofSignerKey, context)
                .unwrap()
        );
        assert_ne!(
            scalar,
            schedule
                .derive_nonzero_field(WalletFieldPurpose::ProofSignerKey, context)
                .unwrap()
        );
        assert_ne!(
            scalar,
            schedule
                .derive_nonzero_stark_scalar(WalletFieldPurpose::ProofSignerSalt, context)
                .unwrap()
        );
        assert_ne!(
            scalar,
            schedule
                .derive_nonzero_stark_scalar(
                    WalletFieldPurpose::ProofSignerKey,
                    &[b"a".as_slice(), b"bc"],
                )
                .unwrap()
        );
        assert_ne!(
            scalar,
            schedule
                .derive_nonzero_stark_scalar(
                    WalletFieldPurpose::ProofSignerKey,
                    &[b"c".as_slice(), b"ab"],
                )
                .unwrap()
        );
        assert_ne!(
            schedule
                .derive_nonzero_field(WalletFieldPurpose::ProofSignerSalt, &[])
                .unwrap(),
            schedule
                .derive_nonzero_field(WalletFieldPurpose::ProofSignerSalt, &[b""])
                .unwrap()
        );
    }

    #[test]
    fn derive_nonzero_stark_scalar_from_child_matches_the_schedule() {
        let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([1; 32]));
        for (purpose, child) in [
            (
                WalletFieldPurpose::SpendAuthorization,
                schedule.spend_authorization_key(),
            ),
            (
                WalletFieldPurpose::WithdrawAuthorization,
                schedule.withdraw_authorization_key(),
            ),
            (
                WalletFieldPurpose::Cancellation,
                schedule.cancellation_key(),
            ),
        ] {
            let child: WalletKeyBytes = child;
            assert_eq!(
                derive_nonzero_stark_scalar_from_key(child.as_bytes(), purpose, &[]).unwrap(),
                schedule.derive_nonzero_stark_scalar(purpose, &[]).unwrap()
            );
        }
    }

    fn child_keys(schedule: &WalletKeyScheduleV2) -> [WalletKeyBytes; 8] {
        [
            schedule.spend_authorization_key(),
            schedule.withdraw_authorization_key(),
            schedule.cancellation_key(),
            schedule.view_key(),
            schedule.recovery_encryption_key(),
            schedule.deposit_blinding_key(),
            schedule.owner_tag_key(),
            schedule
                .local_store_key(&[b"chain".as_slice(), &[0, 1]])
                .unwrap(),
        ]
    }

    #[test]
    fn wallet_v2_known_answer_vector_is_stable() {
        let vectors = [
            (
                0_u8,
                [
                    "03944500c6f568bde0e70fcd94936fc8457f375bbeb57fb8be60bfb1bf09f3b0",
                    "f4d6aa7c265eacd9a87877447c7ba6d706d89c49d22916e9acc470a83356f600",
                    "23e5bd1b95e3995bb6ec160565a9a6ff334fb66b20ae919ceadc451d6a1ba721",
                    "cdcabf109b6051a7e1a7947df2e8fc4646c58ef3fb8cf95faf396a4fde088800",
                    "1dc5e04360ef8c1f81f463abe33571c2824540de20822b6931cb69bf64d4902b",
                    "d33804e7850c30a3977e05b230d5544775ab9e79cb3bddd320f42d1f38fff62e",
                    "b749c11e554bdfe4baf6f5f64e7c75eb18603ce848523c18b6bd36acbfc70a1d",
                    "244ab601a0b17222d4d7e1a4967eb34edf4fbef5285587f1450085529a9ee196",
                ],
                "572a6b66c69d65e185bb78512b704b47be6d75b2595df4aeea988bffaa9889be",
            ),
            (
                1_u8,
                [
                    "f07f8dc8cd367cd662042778946a24edf5d2eca9bc781637cbca71baf770ba14",
                    "346ccf7f26a0fc5044d833818a6719c3967d049aa1412b1584712750d6fad646",
                    "4713afea3915415685cb26e1005ed42f79270535938c1446b326bdaa290651ae",
                    "fb6d6236bd5f7d06930bb20ce8c14b22a8a3de5267e9f7f2f864a4f851ed23c8",
                    "1b9a6ca6ab55f1a08a0e08527ff74b927ece1c3ebcd153d41752587cf023b0ae",
                    "ee1397757b07de19dcabad56918afac1186dbe7e8ab545db6f10ca0f6346dad3",
                    "a16a3ec48ebb57b4ad7eb7635dc7c78289227f4cd46db77711dfbfbb2ba0e24b",
                    "03d0f58051235889c8b17217b4b3dd4bc87f1414a7743ecdffcde0cf4b1a435a",
                ],
                "3142846eff7f5cd3bea9c020fcf9eb1e07554647daa520b0d065a0ac86292bc0",
            ),
        ];

        for (seed_byte, expected_keys, expected_account_id) in vectors {
            let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([seed_byte; 32]));
            for (actual, expected) in child_keys(&schedule).iter().zip(expected_keys) {
                let actual: &WalletKeyBytes = actual;
                assert_eq!(hex::encode(actual.as_bytes()), expected);
            }
            assert_eq!(schedule.account_id(), expected_account_id);
        }
    }

    #[test]
    fn wallet_v2_purposes_are_distinct() {
        let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([1; 32]));
        let mut keys: Vec<String> = child_keys(&schedule)
            .iter()
            .map(|key: &WalletKeyBytes| hex::encode(key.as_bytes()))
            .collect();
        keys.push(schedule.account_id());
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 9);
    }

    #[test]
    fn wallet_v2_context_is_length_delimited() {
        let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([1; 32]));
        let left = schedule.local_store_key(&[b"ab".as_slice(), b"c"]).unwrap();
        let right = schedule.local_store_key(&[b"a".as_slice(), b"bc"]).unwrap();
        assert_ne!(left.as_bytes(), right.as_bytes());
        assert_ne!(
            schedule.local_store_key(&[]).unwrap().as_bytes(),
            schedule.local_store_key(&[b""]).unwrap().as_bytes(),
        );
        assert_ne!(
            schedule
                .local_store_key(&[b"ab".as_slice(), b"c"])
                .unwrap()
                .as_bytes(),
            schedule
                .local_store_key(&[b"c".as_slice(), b"ab"])
                .unwrap()
                .as_bytes(),
        );
        assert_eq!(
            hex::encode(encode_context(&[b"ab".as_slice(), b"c"]).unwrap()),
            "000000020000000261620000000163",
        );
        assert_eq!(hex::encode(encode_context(&[]).unwrap()), "00000000",);
        assert_eq!(
            hex::encode(encode_context(&[&[0, 255][..], b""]).unwrap()),
            "000000020000000200ff00000000",
        );
    }

    #[test]
    fn wallet_v2_debug_redacts_all_secret_material() {
        let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([1; 32]));
        let schedule_debug = format!("{schedule:?}");
        assert!(schedule_debug.contains("<redacted>"));
        assert!(!schedule_debug.contains("b45e29f6e5fa6b55"));
        assert!(!schedule_debug.contains("180, 94, 41"));
        for key in child_keys(&schedule) {
            let key: WalletKeyBytes = key;
            let debug = format!("{key:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains(&hex::encode(key.as_bytes())));
            assert!(!debug.contains(&format!("{:?}", key.as_bytes())));
        }
    }

    #[test]
    fn wallet_v2_secret_buffers_zeroize() {
        fn requires_zeroize_on_drop<T: ZeroizeOnDrop>(_: &T) {}

        let mut schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed([1; 32]));
        let mut key = schedule.spend_authorization_key();
        requires_zeroize_on_drop(&schedule);
        requires_zeroize_on_drop(&key);
        key.zeroize();
        assert_eq!(key.as_bytes(), &[0; 32]);
        schedule.zeroize();
        assert_eq!(schedule.prk.as_bytes(), &[0; 32]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn context_frame_roundtrips_arbitrary_binary_parts(
            parts in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=64), 0..=8),
        ) {
            let borrowed = parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let encoded = encode_context(&borrowed).unwrap();
            let mut offset = 0_usize;
            let read_u32 = |bytes: &[u8], offset: &mut usize| {
                let end = *offset + 4;
                let value = u32::from_be_bytes(bytes[*offset..end].try_into().unwrap()) as usize;
                *offset = end;
                value
            };
            let count = read_u32(&encoded, &mut offset);
            prop_assert_eq!(count, parts.len());
            for expected in &parts {
                let length = read_u32(&encoded, &mut offset);
                prop_assert_eq!(length, expected.len());
                let end = offset + length;
                prop_assert_eq!(&encoded[offset..end], expected.as_slice());
                offset = end;
            }
            prop_assert_eq!(offset, encoded.len());
            prop_assert_eq!(encode_context(&borrowed).unwrap(), encoded);
        }

        #[test]
        fn wallet_numeric_derivations_are_deterministic_nonzero_and_in_range(
            seed in any::<[u8; 32]>(),
            context in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=64), 0..=4),
        ) {
            let borrowed = context.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let schedule = WalletKeyScheduleV2::from_seed(&RecoverySeed(seed));
            let field = schedule
                .derive_nonzero_field(WalletFieldPurpose::OwnerTag, &borrowed)
                .unwrap();
            let scalar = schedule
                .derive_nonzero_stark_scalar(WalletFieldPurpose::ProofSignerKey, &borrowed)
                .unwrap();

            prop_assert_ne!(field, Felt::ZERO);
            prop_assert_ne!(scalar, Felt::ZERO);
            prop_assert!(field.to_bytes_be() < super::FIELD_MODULUS);
            prop_assert!(scalar.to_bytes_be() < super::STARK_CURVE_ORDER);
            prop_assert_eq!(
                field,
                schedule
                    .derive_nonzero_field(WalletFieldPurpose::OwnerTag, &borrowed)
                    .unwrap(),
            );
            prop_assert_eq!(
                scalar,
                schedule
                    .derive_nonzero_stark_scalar(WalletFieldPurpose::ProofSignerKey, &borrowed)
                    .unwrap(),
            );
        }
    }
}

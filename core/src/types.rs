use std::collections::{BTreeMap, BTreeSet};

use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use starknet_crypto::get_public_key;
use starknet_crypto::poseidon_hash;

use crate::{
    ProtocolError,
    hash::{
        domain_felt, encode_starknet_felt, felt_from_hex_str, field_from_bool, field_from_u64,
        field_from_u128, poseidon_chain_hex, tagged_commitment_sha256,
    },
    keys::UserKeys,
};

pub const NOTE_RECOGNITION_ALGORITHM: &str =
    "ecdh-p256+hkdf-sha256+aes-256-gcm/note-recognition-v2";
pub const OUTPUT_NOTE_PLAINTEXT_PADDED_LEN: usize = 4096;
pub const OUTPUT_NOTE_CIPHERTEXT_LEN: usize = OUTPUT_NOTE_PLAINTEXT_PADDED_LEN + 16;
pub const OUTPUT_RECOVERY_FIELD_COUNT: usize = 21;
pub const OUTPUT_RECOVERY_PROOF_SLOTS: usize = 4;
pub const MAX_ORDER_FUNDING_INPUTS: usize = 4;
pub const MIN_MAKER_CURVE_POINTS: usize = 3;
pub const MAX_MAKER_CURVE_POINTS: usize = 8;
pub const MAKER_CURVE_MIN_SPREAD_BPS_STABLE_CONVERSION: u128 = 5;
pub const MAKER_CURVE_MIN_SPREAD_BPS_CONVERSION: u128 = 10;
pub const MAKER_CURVE_MIN_SPREAD_BPS_SPECULATIVE: u128 = 20;
const BPS_DENOMINATOR: u128 = 10_000;
const OUTPUT_RECOVERY_BUNDLE_DOMAIN_HEX: &str = "0x7a796c6974685f6f75745f62756e646c655f7631";
const OUTPUT_RECOVERY_RECORD_DOMAIN_HEX: &str = "0x7a796c6974685f6f75745f7265635f7631";
const FUNDING_INPUT_SET_DOMAIN_HEX: &str = "0x7a796c6974685f66756e64696e675f7365745f7631";
const FUNDING_NULLIFIER_SET_DOMAIN_HEX: &str = "0x7a796c6974685f66756e64696e675f6e756c6c5f7631";
const RENEWAL_CHILD_NULLIFIER_DOMAIN_HEX: &str =
    "0x362b534b676bb36e394d08e276c8e64e65e3733e5d517a7eb6f438eafe54b61";
const RENEWAL_PARENT_SECRET_DOMAIN_HEX: &str =
    "0x7d7cdc3705c6b67855258ca803ee7b93dd4092346289da942f337b30d857667";
const RENEWAL_PARENT_DOMAIN_HEX: &str =
    "0x3c16da1b34d6fcc6f6ea27674de3b6cead275b20c1dfafa4abb43515a8974b4";
pub const RENEWAL_PARENT_CANCEL_DOMAIN_HEX: &str =
    "0x26f84b60309c08d4030876815edb467f89f78e5a5f62823af4521f1be502ca3";

mod serde_u128_decimal {
    use std::fmt;

    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(U128DecimalVisitor)
    }

    pub fn serialize_option<S>(value: &Option<u128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize_option<'de, D>(deserializer: D) -> Result<Option<u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_option(OptionU128DecimalVisitor)
    }

    struct U128DecimalVisitor;

    impl<'de> Visitor<'de> for U128DecimalVisitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a u128 decimal string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_decimal_u128(value).map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }
    }

    struct OptionU128DecimalVisitor;

    impl<'de> Visitor<'de> for OptionU128DecimalVisitor {
        type Value = Option<u128>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("null or a u128 decimal string")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize(deserializer).map(Some)
        }
    }

    fn parse_decimal_u128(value: &str) -> Result<u128, String> {
        if value != value.trim() {
            return Err("u128 decimal string must not include surrounding whitespace".into());
        }
        if value.is_empty() {
            return Err("empty u128 decimal string".into());
        }
        if value.starts_with('-') || value.starts_with('+') {
            return Err("u128 decimal string must not include a sign".into());
        }
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("invalid u128 decimal string '{value}'"));
        }
        value
            .parse::<u128>()
            .map_err(|error| format!("u128 decimal string out of range: {error}"))
    }
}

mod serde_u64_decimal {
    use std::fmt;

    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(U64DecimalVisitor)
    }

    struct U64DecimalVisitor;

    impl<'de> Visitor<'de> for U64DecimalVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a u64 decimal string or integer")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value != value.trim() {
                return Err(E::custom(
                    "u64 string must not include surrounding whitespace",
                ));
            }
            if value.is_empty() {
                return Err(E::custom("empty u64 string"));
            }
            value
                .parse::<u64>()
                .map_err(|error| E::custom(format!("invalid u64: {error}")))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nullifier(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderCommitment(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderType {
    #[default]
    LimitBatch,
    MakerCurve,
    HeartbeatCover,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayMode {
    #[default]
    SelfRelay,
    ZylithRelay,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeInForce {
    #[default]
    CurrentBatchOnly,
    FillOrKill,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerCurvePoint {
    #[serde(with = "serde_u128_decimal")]
    pub price: u128,
    #[serde(with = "serde_u128_decimal")]
    pub base_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerBandFillAttribution {
    pub band_index: u64,
    #[serde(with = "serde_u128_decimal")]
    pub band_price: u128,
    #[serde(with = "serde_u128_decimal")]
    pub band_base_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub filled_base_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerBandAttribution {
    pub version: u32,
    pub pair_id: PairId,
    pub order_commitment: OrderCommitment,
    pub funding_note_ref: NoteCommitment,
    pub side: OrderSide,
    #[serde(with = "serde_u128_decimal")]
    pub clearing_price: u128,
    #[serde(with = "serde_u128_decimal")]
    pub filled_base_amount: u128,
    pub bands: Vec<MakerBandFillAttribution>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerAttributionPlaintext {
    pub version: u32,
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub epoch_id: u64,
    pub maker_public_key: String,
    pub curve_commitment: String,
    pub output_note_commitment: NoteCommitment,
    pub attribution: MakerBandAttribution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerAttributionReceipt {
    pub version: u32,
    pub signer_public_key: String,
    pub issued_at_unix_ms: u64,
    pub payload_commitment: String,
    pub signature_r: String,
    pub signature_s: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMakerAttributionArtifact {
    pub version: u32,
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub epoch_id: u64,
    pub maker_public_key: String,
    pub curve_commitment: String,
    pub output_note_commitment: NoteCommitment,
    pub order_commitment: OrderCommitment,
    pub algorithm: String,
    pub key_id: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
    pub receipt: MakerAttributionReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerAttributionBundle {
    pub version: u32,
    pub batch_id: BatchId,
    pub artifacts: Vec<EncryptedMakerAttributionArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerAttributionArtifactList {
    pub batch_id: BatchId,
    pub maker_public_key: String,
    pub artifacts: Vec<EncryptedMakerAttributionArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenMakerCurve {
    pub points: Vec<MakerCurvePoint>,
}

impl HiddenMakerCurve {
    pub fn commitment(&self) -> Result<String, ProtocolError> {
        let mut fields = Vec::with_capacity(1 + self.points.len() * 2);
        fields.push(field_from_u64(self.points.len() as u64));
        for point in &self.points {
            fields.push(field_from_u128(point.price));
            fields.push(field_from_u128(point.base_amount));
        }
        Ok(poseidon_chain_hex(
            domain_felt("zylith/maker-curve"),
            &fields,
        ))
    }

    pub fn total_base_amount(&self) -> Result<u128, ProtocolError> {
        self.points.iter().try_fold(0u128, |total, point| {
            total.checked_add(point.base_amount).ok_or_else(|| {
                ProtocolError::InvalidOrder("maker curve base amount overflows u128".into())
            })
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.points.len() < MIN_MAKER_CURVE_POINTS {
            return Err(ProtocolError::InvalidOrder(format!(
                "maker curve must contain at least {MIN_MAKER_CURVE_POINTS} points"
            )));
        }
        if self.points.len() > MAX_MAKER_CURVE_POINTS {
            return Err(ProtocolError::InvalidOrder(format!(
                "maker curve uses {} points, maximum is {}",
                self.points.len(),
                MAX_MAKER_CURVE_POINTS
            )));
        }

        let mut previous_price = None;
        for point in &self.points {
            if point.price == 0 || point.base_amount == 0 {
                return Err(ProtocolError::InvalidOrder(
                    "maker curve prices and base amounts must be positive".into(),
                ));
            }
            if previous_price.is_some_and(|price| point.price <= price) {
                return Err(ProtocolError::InvalidOrder(
                    "maker curve points must be strictly increasing by price".into(),
                ));
            }
            previous_price = Some(point.price);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    pub owner_public_key: String,
    pub spend_authority: String,
    pub withdraw_authority: String,
    pub blinding: String,
    #[serde(with = "serde_u64_decimal")]
    pub nonce: u64,
    pub metadata_commitment: String,
}

impl Note {
    pub fn commitment(&self) -> Result<NoteCommitment, ProtocolError> {
        let asset_id = felt_from_hex_str(&encode_starknet_felt("asset-id", &self.asset_id.0))?;
        let owner_public_key = felt_from_hex_str(&encode_starknet_felt(
            "owner-public-key",
            &self.owner_public_key,
        ))?;
        let blinding = felt_from_hex_str(&self.blinding)?;
        let nonce = field_from_u64(self.nonce);
        let metadata_commitment = felt_from_hex_str(&self.metadata_commitment)?;
        let amount = field_from_u128(self.amount);
        let spend_authority = felt_from_hex_str(&self.spend_authority)?;
        let withdraw_authority = felt_from_hex_str(&self.withdraw_authority)?;

        Ok(NoteCommitment(poseidon_chain_hex(
            domain_felt("zylith/note"),
            &[
                asset_id,
                amount,
                owner_public_key,
                spend_authority,
                withdraw_authority,
                blinding,
                nonce,
                metadata_commitment,
            ],
        )))
    }

    pub fn nullifier(&self, keys: &UserKeys) -> Result<Nullifier, ProtocolError> {
        let expected_spend_authority =
            spend_authority_from_raw_key_hex(&hex::encode(keys.spend_auth_key))?;
        if felt_from_hex_str(&self.spend_authority)?
            != felt_from_hex_str(&expected_spend_authority)?
        {
            return Err(ProtocolError::InvalidOrder(
                "note spend authority does not match supplied spend key".into(),
            ));
        }
        let note_commitment = self.commitment()?;
        nullifier_from_note_secret(&note_commitment, &self.blinding)
    }
}

pub fn spend_auth_key_felt_from_raw_key_hex(spend_auth_key_hex: &str) -> String {
    encode_starknet_felt("spend-auth-key", spend_auth_key_hex)
}

pub fn spend_authority_from_spend_auth_key_felt(
    spend_auth_key_felt: &str,
) -> Result<String, ProtocolError> {
    let spend_auth_key = felt_from_hex_str(spend_auth_key_felt)?;
    Ok(crate::hash::felt_hex(&get_public_key(&spend_auth_key)))
}

pub fn spend_authority_from_raw_key_hex(spend_auth_key_hex: &str) -> Result<String, ProtocolError> {
    spend_authority_from_spend_auth_key_felt(&spend_auth_key_felt_from_raw_key_hex(
        spend_auth_key_hex,
    ))
}

pub fn nullifier_from_note_secret(
    note_commitment: &NoteCommitment,
    note_secret: &str,
) -> Result<Nullifier, ProtocolError> {
    let note_commitment = felt_from_hex_str(&note_commitment.0)?;
    let note_secret = felt_from_hex_str(note_secret)?;
    Ok(Nullifier(poseidon_chain_hex(
        domain_felt("zylith/nullifier"),
        &[note_commitment, note_secret],
    )))
}

pub fn funding_input_set_commitment(
    commitments: &[NoteCommitment],
) -> Result<NoteCommitment, ProtocolError> {
    if commitments.is_empty() {
        return Err(ProtocolError::InvalidOrder(
            "funding input set cannot be empty".into(),
        ));
    }
    if commitments.len() > MAX_ORDER_FUNDING_INPUTS {
        return Err(ProtocolError::InvalidOrder(format!(
            "funding input count {} exceeds maximum {}",
            commitments.len(),
            MAX_ORDER_FUNDING_INPUTS
        )));
    }
    if commitments.len() == 1 {
        return Ok(commitments[0].clone());
    }
    let mut state = felt_from_hex_str(FUNDING_INPUT_SET_DOMAIN_HEX)?;
    for commitment in commitments {
        state = poseidon_hash(state, felt_from_hex_str(&commitment.0)?);
    }
    state = poseidon_hash(state, field_from_u64(commitments.len() as u64));
    Ok(NoteCommitment(crate::hash::felt_hex(&state)))
}

pub fn funding_nullifier_set_commitment(
    nullifiers: &[Nullifier],
) -> Result<Nullifier, ProtocolError> {
    if nullifiers.is_empty() {
        return Err(ProtocolError::InvalidOrder(
            "funding nullifier set cannot be empty".into(),
        ));
    }
    if nullifiers.len() > MAX_ORDER_FUNDING_INPUTS {
        return Err(ProtocolError::InvalidOrder(format!(
            "funding nullifier count {} exceeds maximum {}",
            nullifiers.len(),
            MAX_ORDER_FUNDING_INPUTS
        )));
    }
    if nullifiers.len() == 1 {
        return Ok(nullifiers[0].clone());
    }
    let mut state = felt_from_hex_str(FUNDING_NULLIFIER_SET_DOMAIN_HEX)?;
    for nullifier in nullifiers {
        state = poseidon_hash(state, felt_from_hex_str(&nullifier.0)?);
    }
    state = poseidon_hash(state, field_from_u64(nullifiers.len() as u64));
    Ok(Nullifier(crate::hash::felt_hex(&state)))
}

pub fn renewal_parent_secret_commitment(
    parent_authorization_secret: &str,
) -> Result<String, ProtocolError> {
    let parent_authorization_secret = felt_from_hex_str(parent_authorization_secret)?;
    Ok(poseidon_chain_hex(
        felt_from_hex_str(RENEWAL_PARENT_SECRET_DOMAIN_HEX)?,
        &[parent_authorization_secret],
    ))
}

pub fn renewal_parent_commitment(
    parent_secret_commitment: &str,
    parent_cancel_authority: &str,
) -> Result<String, ProtocolError> {
    let parent_secret_commitment = felt_from_hex_str(parent_secret_commitment)?;
    let parent_cancel_authority = felt_from_hex_str(parent_cancel_authority)?;
    Ok(poseidon_chain_hex(
        felt_from_hex_str(RENEWAL_PARENT_DOMAIN_HEX)?,
        &[parent_secret_commitment, parent_cancel_authority],
    ))
}

pub fn renewal_child_nullifier(
    parent_order_commitment: &str,
    parent_child_index: u64,
    parent_authorization_secret: &str,
) -> Result<String, ProtocolError> {
    if parent_child_index == 0 {
        return Err(ProtocolError::InvalidOrder(
            "renewal child nullifier requires a non-zero child index".into(),
        ));
    }
    let parent_order_commitment = felt_from_hex_str(parent_order_commitment)?;
    if parent_order_commitment == field_from_u64(0) {
        return Err(ProtocolError::InvalidOrder(
            "renewal child nullifier requires a non-zero parent commitment".into(),
        ));
    }
    let parent_authorization_secret = felt_from_hex_str(parent_authorization_secret)?;
    if parent_authorization_secret == field_from_u64(0) {
        return Err(ProtocolError::InvalidOrder(
            "renewal child nullifier requires a non-zero parent authorization secret".into(),
        ));
    }
    Ok(poseidon_chain_hex(
        felt_from_hex_str(RENEWAL_CHILD_NULLIFIER_DOMAIN_HEX)?,
        &[
            parent_order_commitment,
            field_from_u64(parent_child_index),
            parent_authorization_secret,
        ],
    ))
}

pub fn renewal_parent_cancel_marker(
    parent_secret_commitment: &str,
    parent_cancel_authority: &str,
) -> Result<String, ProtocolError> {
    let parent_secret_commitment = felt_from_hex_str(parent_secret_commitment)?;
    let parent_cancel_authority = felt_from_hex_str(parent_cancel_authority)?;
    Ok(poseidon_chain_hex(
        felt_from_hex_str(RENEWAL_PARENT_CANCEL_DOMAIN_HEX)?,
        &[parent_secret_commitment, parent_cancel_authority],
    ))
}

pub fn renewal_cancel_auth_key_felt_from_raw_key_hex(order_cancellation_key_hex: &str) -> String {
    encode_starknet_felt("renewal-cancel-auth-key", order_cancellation_key_hex)
}

pub fn renewal_cancel_auth_key_felt_for_parent_from_raw_key_hex(
    order_cancellation_key_hex: &str,
    parent_secret_commitment: &str,
) -> String {
    encode_starknet_felt(
        "renewal-cancel-auth-key-v2",
        &format!("{order_cancellation_key_hex}:{parent_secret_commitment}"),
    )
}

pub fn renewal_cancel_authority_from_renewal_cancel_auth_key_felt(
    renewal_cancel_auth_key_felt: &str,
) -> Result<String, ProtocolError> {
    let renewal_cancel_auth_key = felt_from_hex_str(renewal_cancel_auth_key_felt)?;
    Ok(crate::hash::felt_hex(&get_public_key(
        &renewal_cancel_auth_key,
    )))
}

pub fn renewal_cancel_authority_from_raw_key_hex(
    order_cancellation_key_hex: &str,
) -> Result<String, ProtocolError> {
    renewal_cancel_authority_from_renewal_cancel_auth_key_felt(
        &renewal_cancel_auth_key_felt_from_raw_key_hex(order_cancellation_key_hex),
    )
}

pub fn renewal_cancel_authority_for_parent_from_raw_key_hex(
    order_cancellation_key_hex: &str,
    parent_secret_commitment: &str,
) -> Result<String, ProtocolError> {
    renewal_cancel_authority_from_renewal_cancel_auth_key_felt(
        &renewal_cancel_auth_key_felt_for_parent_from_raw_key_hex(
            order_cancellation_key_hex,
            parent_secret_commitment,
        ),
    )
}

pub fn withdraw_auth_key_felt_from_raw_key_hex(withdraw_auth_key_hex: &str) -> String {
    encode_starknet_felt("withdraw-auth-key", withdraw_auth_key_hex)
}

pub fn withdraw_authority_from_withdraw_auth_key_felt(
    withdraw_auth_key_felt: &str,
) -> Result<String, ProtocolError> {
    let withdraw_auth_key = felt_from_hex_str(withdraw_auth_key_felt)?;
    Ok(crate::hash::felt_hex(&get_public_key(&withdraw_auth_key)))
}

pub fn withdraw_authority_from_raw_key_hex(
    withdraw_auth_key_hex: &str,
) -> Result<String, ProtocolError> {
    withdraw_authority_from_withdraw_auth_key_felt(&withdraw_auth_key_felt_from_raw_key_hex(
        withdraw_auth_key_hex,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositIntent {
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    #[serde(with = "serde_u64_decimal")]
    pub deposit_nonce: u64,
    pub recipient_owner_public_key: String,
    pub recipient_spend_authority: String,
    pub recipient_withdraw_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderIntent {
    pub pair_id: PairId,
    pub batch_id: BatchId,
    pub side: OrderSide,
    #[serde(default)]
    pub order_type: OrderType,
    #[serde(default)]
    pub relay_mode: RelayMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maker_curve: Option<HiddenMakerCurve>,
    #[serde(with = "serde_u128_decimal")]
    pub limit_price: u128,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub min_fill: u128,
    #[serde(default)]
    pub time_in_force: TimeInForce,
    #[serde(with = "serde_u64_decimal")]
    pub expiry_epoch: u64,
    #[serde(with = "serde_u64_decimal")]
    pub order_nonce: u64,
    #[serde(default = "zero_felt_string")]
    pub parent_order_commitment: String,
    #[serde(default, with = "serde_u64_decimal")]
    pub parent_child_index: u64,
    #[serde(default = "zero_felt_string")]
    pub parent_secret_commitment: String,
    #[serde(default = "zero_felt_string")]
    pub parent_cancel_authority: String,
    #[serde(default = "zero_felt_string")]
    pub parent_authorization_secret: String,
    pub funding_note_ref: NoteCommitment,
    pub funding_nullifier: Nullifier,
    pub recipient_owner_public_key: String,
    pub recipient_spend_authority: String,
    pub recipient_withdraw_authority: String,
    pub recipient_residual_withdraw_authority: String,
    pub auditor_view_allowed: bool,
}

impl OrderIntent {
    pub fn commitment(&self) -> Result<OrderCommitment, ProtocolError> {
        self.validate_parent_link()?;
        let pair_id = felt_from_hex_str(&encode_starknet_felt("pair-id", &self.pair_id.0))?;
        let batch_id = felt_from_hex_str(&encode_starknet_felt("batch-id", &self.batch_id.0))?;
        let side = match self.side {
            OrderSide::Buy => field_from_u64(0),
            OrderSide::Sell => field_from_u64(1),
        };
        let order_type = match self.order_type {
            OrderType::LimitBatch => field_from_u64(0),
            OrderType::MakerCurve => field_from_u64(1),
            OrderType::HeartbeatCover => field_from_u64(2),
        };
        let relay_mode = match self.relay_mode {
            RelayMode::SelfRelay => field_from_u64(0),
            RelayMode::ZylithRelay => field_from_u64(1),
        };
        let maker_curve_commitment = match self.order_type {
            OrderType::MakerCurve => {
                let commitment = self
                    .maker_curve
                    .as_ref()
                    .ok_or_else(|| {
                        ProtocolError::InvalidOrder("maker curve order missing curve".into())
                    })?
                    .commitment()?;
                felt_from_hex_str(&commitment)?
            }
            _ => field_from_u64(0),
        };
        let limit_price = field_from_u128(self.limit_price);
        let amount = field_from_u128(self.amount);
        let min_fill = field_from_u128(self.min_fill);
        let time_in_force = match self.time_in_force {
            TimeInForce::CurrentBatchOnly => field_from_u64(0),
            TimeInForce::FillOrKill => field_from_u64(1),
        };
        let expiry_epoch = field_from_u64(self.expiry_epoch);
        let order_nonce = field_from_u64(self.order_nonce);
        let parent_order_commitment = felt_from_hex_str(&self.parent_order_commitment)?;
        let parent_child_index = field_from_u64(self.parent_child_index);
        let parent_secret_commitment = felt_from_hex_str(&self.parent_secret_commitment)?;
        let parent_cancel_authority = felt_from_hex_str(&self.parent_cancel_authority)?;
        let parent_authorization_secret = felt_from_hex_str(&self.parent_authorization_secret)?;
        let funding_note_ref = felt_from_hex_str(&self.funding_note_ref.0)?;
        let funding_nullifier = felt_from_hex_str(&self.funding_nullifier.0)?;
        let recipient_owner_public_key = felt_from_hex_str(&encode_starknet_felt(
            "owner-public-key",
            &self.recipient_owner_public_key,
        ))?;
        let recipient_spend_authority = felt_from_hex_str(&self.recipient_spend_authority)?;
        let recipient_withdraw_authority = felt_from_hex_str(&self.recipient_withdraw_authority)?;
        let recipient_residual_withdraw_authority =
            felt_from_hex_str(&self.recipient_residual_withdraw_authority)?;
        let auditor_view_allowed = field_from_bool(self.auditor_view_allowed);

        Ok(OrderCommitment(poseidon_chain_hex(
            domain_felt("zylith/order"),
            &[
                pair_id,
                batch_id,
                side,
                order_type,
                relay_mode,
                maker_curve_commitment,
                limit_price,
                amount,
                min_fill,
                time_in_force,
                expiry_epoch,
                order_nonce,
                parent_order_commitment,
                parent_child_index,
                parent_secret_commitment,
                parent_cancel_authority,
                parent_authorization_secret,
                funding_note_ref,
                funding_nullifier,
                recipient_owner_public_key,
                recipient_spend_authority,
                recipient_withdraw_authority,
                recipient_residual_withdraw_authority,
                auditor_view_allowed,
            ],
        )))
    }

    pub fn validate_parent_link(&self) -> Result<(), ProtocolError> {
        let normalized_parent = felt_from_hex_str(&self.parent_order_commitment)?;
        let normalized_parent_secret_commitment =
            felt_from_hex_str(&self.parent_secret_commitment)?;
        let normalized_parent_cancel_authority = felt_from_hex_str(&self.parent_cancel_authority)?;
        let normalized_parent_authorization_secret =
            felt_from_hex_str(&self.parent_authorization_secret)?;
        let has_parent = normalized_parent != field_from_u64(0);
        if has_parent && self.parent_child_index == 0 {
            return Err(ProtocolError::InvalidOrder(
                "parent order commitment requires a non-zero parent child index".into(),
            ));
        }
        if !has_parent && self.parent_child_index != 0 {
            return Err(ProtocolError::InvalidOrder(
                "parent child index requires a parent order commitment".into(),
            ));
        }
        if !has_parent {
            if normalized_parent_secret_commitment != field_from_u64(0)
                || normalized_parent_cancel_authority != field_from_u64(0)
                || normalized_parent_authorization_secret != field_from_u64(0)
            {
                return Err(ProtocolError::InvalidOrder(
                    "parent authority fields require a parent order commitment".into(),
                ));
            }
            return Ok(());
        }

        if normalized_parent_secret_commitment == field_from_u64(0)
            || normalized_parent_cancel_authority == field_from_u64(0)
            || normalized_parent_authorization_secret == field_from_u64(0)
        {
            return Err(ProtocolError::InvalidOrder(
                "parent order commitment requires parent authority fields".into(),
            ));
        }
        let expected_secret_commitment =
            renewal_parent_secret_commitment(&self.parent_authorization_secret)?;
        if felt_from_hex_str(&expected_secret_commitment)? != normalized_parent_secret_commitment {
            return Err(ProtocolError::InvalidOrder(
                "parent secret commitment does not match parent authorization secret".into(),
            ));
        }
        let expected_parent = renewal_parent_commitment(
            &self.parent_secret_commitment,
            &self.parent_cancel_authority,
        )?;
        if felt_from_hex_str(&expected_parent)? != normalized_parent {
            return Err(ProtocolError::InvalidOrder(
                "parent order commitment does not match parent authority".into(),
            ));
        }
        Ok(())
    }

    pub fn is_renewal_backed_child(&self) -> Result<bool, ProtocolError> {
        self.validate_parent_link()?;
        Ok(felt_from_hex_str(&self.parent_order_commitment)? != field_from_u64(0))
    }

    pub fn validate_relay_mode(&self) -> Result<(), ProtocolError> {
        match self.relay_mode {
            RelayMode::SelfRelay => Ok(()),
            RelayMode::ZylithRelay => {
                if !matches!(self.order_type, OrderType::MakerCurve) {
                    return Err(ProtocolError::InvalidOrder(
                        "Zylith relay mode requires a maker curve order".into(),
                    ));
                }
                if !self.is_renewal_backed_child()? {
                    return Err(ProtocolError::InvalidOrder(
                        "Zylith relay mode requires renewal child parent fields".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOrderPayload {
    pub order: OrderIntent,
    pub funding_note: Note,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub funding_notes: Vec<Note>,
    pub funding_authorization: SpendAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_maker_authorization: Option<ManagedMakerAuthorization>,
}

impl PrivateOrderPayload {
    pub fn effective_funding_notes(&self) -> Vec<&Note> {
        if self.funding_notes.is_empty() {
            vec![&self.funding_note]
        } else {
            self.funding_notes.iter().collect()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendAuthorization {
    pub signature_r: String,
    pub signature_s: String,
}

pub const MANAGED_MAKER_POLICY_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedMakerPolicy {
    pub version: u32,
    pub delegate_public_key: String,
    pub pair_id: PairId,
    pub allow_buy: bool,
    pub allow_sell: bool,
    #[serde(with = "serde_u128_decimal")]
    pub max_epoch_base: u128,
    #[serde(with = "serde_u128_decimal")]
    pub min_price: u128,
    #[serde(with = "serde_u128_decimal")]
    pub max_price: u128,
    #[serde(with = "serde_u64_decimal")]
    pub valid_from_epoch: u64,
    #[serde(with = "serde_u64_decimal")]
    pub valid_until_epoch: u64,
    pub relay_mode: RelayMode,
    pub parent_order_commitment: String,
    pub recipient_owner_public_key: String,
    pub recipient_spend_authority: String,
    pub recipient_withdraw_authority: String,
    pub recipient_residual_withdraw_authority: String,
    pub auditor_view_allowed: bool,
    #[serde(with = "serde_u64_decimal")]
    pub policy_nonce: u64,
}

impl ManagedMakerPolicy {
    pub fn commitment(&self) -> Result<String, ProtocolError> {
        let pair_id = felt_from_hex_str(&encode_starknet_felt("pair-id", &self.pair_id.0))?;
        let relay_mode = match self.relay_mode {
            RelayMode::SelfRelay => field_from_u64(0),
            RelayMode::ZylithRelay => field_from_u64(1),
        };
        let fields = [
            field_from_u64(u64::from(self.version)),
            felt_from_hex_str(&self.delegate_public_key)?,
            pair_id,
            field_from_u64(u64::from(self.allow_buy)),
            field_from_u64(u64::from(self.allow_sell)),
            field_from_u128(self.max_epoch_base),
            field_from_u128(self.min_price),
            field_from_u128(self.max_price),
            field_from_u64(self.valid_from_epoch),
            field_from_u64(self.valid_until_epoch),
            relay_mode,
            felt_from_hex_str(&self.parent_order_commitment)?,
            felt_from_hex_str(&encode_starknet_felt(
                "owner-public-key",
                &self.recipient_owner_public_key,
            ))?,
            felt_from_hex_str(&self.recipient_spend_authority)?,
            felt_from_hex_str(&self.recipient_withdraw_authority)?,
            felt_from_hex_str(&self.recipient_residual_withdraw_authority)?,
            field_from_u64(u64::from(self.auditor_view_allowed)),
            field_from_u64(self.policy_nonce),
        ];
        Ok(poseidon_chain_hex(
            domain_felt("zylith/managed-maker-policy-v1"),
            &fields,
        ))
    }

    pub fn validate_order(&self, order: &OrderIntent) -> Result<(), ProtocolError> {
        if self.version != MANAGED_MAKER_POLICY_VERSION {
            return Err(ProtocolError::InvalidOrder(
                "unsupported managed maker policy version".into(),
            ));
        }
        if felt_from_hex_str(&self.delegate_public_key)? == field_from_u64(0)
            || self.policy_nonce == 0
            || self.max_epoch_base == 0
            || self.min_price == 0
            || self.max_price < self.min_price
            || self.valid_from_epoch == 0
            || self.valid_until_epoch < self.valid_from_epoch
        {
            return Err(ProtocolError::InvalidOrder(
                "managed maker policy bounds are invalid".into(),
            ));
        }
        if order.order_type != OrderType::MakerCurve {
            return Err(ProtocolError::InvalidOrder(
                "managed maker delegation only authorizes maker curves".into(),
            ));
        }
        if order.time_in_force != TimeInForce::CurrentBatchOnly {
            return Err(ProtocolError::InvalidOrder(
                "managed maker delegation requires current-batch orders".into(),
            ));
        }
        if order.pair_id != self.pair_id {
            return Err(ProtocolError::InvalidOrder(
                "managed maker pair is not authorized".into(),
            ));
        }
        if (order.side == OrderSide::Buy && !self.allow_buy)
            || (order.side == OrderSide::Sell && !self.allow_sell)
        {
            return Err(ProtocolError::InvalidOrder(
                "managed maker side is not authorized".into(),
            ));
        }
        if order.amount == 0 || order.amount > self.max_epoch_base {
            return Err(ProtocolError::InvalidOrder(
                "managed maker order exceeds the authorized epoch size".into(),
            ));
        }
        if order.expiry_epoch < self.valid_from_epoch || order.expiry_epoch > self.valid_until_epoch
        {
            return Err(ProtocolError::InvalidOrder(
                "managed maker order is outside the authorized epoch range".into(),
            ));
        }
        if order.relay_mode != self.relay_mode {
            return Err(ProtocolError::InvalidOrder(
                "managed maker relay mode is not authorized".into(),
            ));
        }
        if felt_from_hex_str(&order.parent_order_commitment)?
            != felt_from_hex_str(&self.parent_order_commitment)?
        {
            return Err(ProtocolError::InvalidOrder(
                "managed maker renewal parent is not authorized".into(),
            ));
        }
        if order.recipient_owner_public_key != self.recipient_owner_public_key
            || order.recipient_spend_authority != self.recipient_spend_authority
            || order.recipient_withdraw_authority != self.recipient_withdraw_authority
            || order.recipient_residual_withdraw_authority
                != self.recipient_residual_withdraw_authority
            || order.auditor_view_allowed != self.auditor_view_allowed
        {
            return Err(ProtocolError::InvalidOrder(
                "managed maker output authority is not authorized".into(),
            ));
        }
        if order.limit_price < self.min_price || order.limit_price > self.max_price {
            return Err(ProtocolError::InvalidOrder(
                "managed maker limit price is outside the authorized range".into(),
            ));
        }
        let curve = order.maker_curve.as_ref().ok_or_else(|| {
            ProtocolError::InvalidOrder("managed maker order is missing its curve".into())
        })?;
        if curve
            .points
            .iter()
            .any(|point| point.price < self.min_price || point.price > self.max_price)
        {
            return Err(ProtocolError::InvalidOrder(
                "managed maker curve price is outside the authorized range".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedMakerAuthorization {
    pub policy: ManagedMakerPolicy,
    pub owner_authorization: SpendAuthorization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputRecoveryRecord {
    pub key_tag: String,
    pub ciphertext_fields: Vec<String>,
    pub auth_tag: String,
    pub commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub algorithm: String,
    pub key_id: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<OutputRecoveryRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderShare {
    pub execution_key_id: String,
    pub encrypted_share: EncryptedBlob,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderIngressReceipt {
    pub version: u32,
    pub ingress_id: String,
    pub order_commitment: OrderCommitment,
    pub pair_id: PairId,
    pub batch_id: BatchId,
    pub epoch_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_mode: Option<RelayMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_package_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_package_commitment: Option<String>,
    pub payload_commitment: String,
    pub issued_at_unix_ms: u64,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrderIngressReceiptAttestation {
    pub relay_mode: Option<RelayMode>,
    pub renewal_package_id: Option<String>,
    pub renewal_package_commitment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderShareBundle {
    pub order_commitment: OrderCommitment,
    pub cancellation_auth_tag: String,
    pub pair_id: PairId,
    pub batch_id: BatchId,
    pub epoch_id: u64,
    pub transport_envelope: Option<EncryptedBlob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_receipt: Option<OrderIngressReceipt>,
    #[serde(default)]
    pub shares: Vec<OrderShare>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderSubmission {
    pub order_bundle: OrderShareBundle,
}

fn zero_felt_string() -> String {
    "0x0".into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderIngressClientTelemetry {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_build_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_submission_delay_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_elapsed_before_private_ingress_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_ingress_roundtrip_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_elapsed_before_coordinator_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_time_remaining_before_private_ingress_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_time_remaining_before_coordinator_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_safety_buffer_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedOrderIngressRequest {
    pub order_submission: OrderSubmission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_package_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_package_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_relay_mode: Option<RelayMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_telemetry: Option<OrderIngressClientTelemetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedOrderIngressResponse {
    pub receipt: OrderIngressReceipt,
    pub coordinator_submission: OrderSubmission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderSubmissionAccepted {
    pub batch_id: BatchId,
    pub order_commitment: OrderCommitment,
    pub accepted_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderCancellationRequest {
    pub batch_id: BatchId,
    pub order_commitment: OrderCommitment,
    pub cancellation_secret: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderCancellationAccepted {
    pub batch_id: BatchId,
    pub order_commitment: OrderCommitment,
    pub cancelled_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionKeyPublicConfig {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionKeyPrivateConfig {
    pub key_id: String,
    pub private_key: String,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExecutionKeyRegistry {
    pub keys: Vec<PrivateExecutionKeyPublicConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptedOrderShare {
    pub key_id: String,
    pub order_commitment: OrderCommitment,
    pub share_index: u64,
    pub share_count: u64,
    pub plaintext_len: u64,
    pub share_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchShareContributions {
    pub batch_id: BatchId,
    pub shares: Vec<DecryptedOrderShare>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmittedOrderRecord {
    pub received_at_unix_ms: u64,
    pub order_bundle: OrderShareBundle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchStatus {
    Open,
    Closed,
    Clearing,
    Settled,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub epoch_id: u64,
    pub close_time_unix_ms: u64,
    pub status: BatchStatus,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSummary {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub epoch_id: u64,
    pub close_time_unix_ms: u64,
    pub status: BatchStatus,
    pub order_count: u64,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicBatchSummary {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub epoch_id: u64,
    pub close_time_unix_ms: u64,
    pub status: BatchStatus,
    pub order_count_bucket: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchOrderSet {
    pub batch: BatchSummary,
    pub orders: Vec<SubmittedOrderRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedOrder {
    pub order_commitment: OrderCommitment,
    #[serde(with = "serde_u128_decimal")]
    pub filled_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderExecutionReport {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub order_commitment: OrderCommitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_report_auth_tag: Option<String>,
    pub funding_note_commitment: NoteCommitment,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub funding_note_commitments: Vec<NoteCommitment>,
    pub status: String,
    pub side: OrderSide,
    #[serde(default)]
    pub order_type: OrderType,
    pub time_in_force: TimeInForce,
    #[serde(with = "serde_u128_decimal")]
    pub submitted_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub filled_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub unfilled_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub limit_price: u128,
    #[serde(
        default,
        serialize_with = "serde_u128_decimal::serialize_option",
        deserialize_with = "serde_u128_decimal::deserialize_option"
    )]
    pub execution_price: Option<u128>,
    pub fee_asset_id: Option<AssetId>,
    #[serde(with = "serde_u128_decimal")]
    pub fee_amount: u128,
    pub output_note_commitment: Option<NoteCommitment>,
    pub output_asset_id: Option<AssetId>,
    #[serde(with = "serde_u128_decimal")]
    pub output_amount: u128,
    pub residual_note_commitment: Option<NoteCommitment>,
    pub residual_asset_id: Option<AssetId>,
    #[serde(with = "serde_u128_decimal")]
    pub residual_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedOrderWitness {
    pub order_commitment: OrderCommitment,
    pub funding_note: Note,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub funding_notes: Vec<Note>,
    pub funding_note_ref: NoteCommitment,
    pub funding_nullifier: Nullifier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub funding_nullifiers: Vec<Nullifier>,
    pub funding_authorization: SpendAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_maker_authorization: Option<ManagedMakerAuthorization>,
    pub side: OrderSide,
    pub order_type: OrderType,
    #[serde(default)]
    pub relay_mode: RelayMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maker_curve: Option<HiddenMakerCurve>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maker_band_attribution: Option<MakerBandAttribution>,
    #[serde(with = "serde_u128_decimal")]
    pub limit_price: u128,
    #[serde(with = "serde_u128_decimal")]
    pub order_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub min_fill: u128,
    pub time_in_force: TimeInForce,
    pub expiry_epoch: u64,
    pub order_nonce: u64,
    #[serde(default = "zero_felt_string")]
    pub parent_order_commitment: String,
    #[serde(default)]
    pub parent_child_index: u64,
    #[serde(default = "zero_felt_string")]
    pub parent_secret_commitment: String,
    #[serde(default = "zero_felt_string")]
    pub parent_cancel_authority: String,
    #[serde(default = "zero_felt_string")]
    pub parent_authorization_secret: String,
    pub auditor_view_allowed: bool,
    pub recipient_owner_public_key: String,
    pub recipient_spend_authority: String,
    pub recipient_withdraw_authority: String,
    pub recipient_residual_withdraw_authority: String,
    #[serde(with = "serde_u128_decimal")]
    pub filled_amount: u128,
    pub output_note: Note,
    pub residual_note: Option<Note>,
}

impl MatchedOrderWitness {
    pub fn effective_funding_notes(&self) -> Vec<&Note> {
        if self.funding_notes.is_empty() {
            vec![&self.funding_note]
        } else {
            self.funding_notes.iter().collect()
        }
    }

    pub fn effective_funding_nullifiers(&self) -> Vec<&Nullifier> {
        if self.funding_nullifiers.is_empty() {
            vec![&self.funding_nullifier]
        } else {
            self.funding_nullifiers.iter().collect()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionOrderWitness {
    pub order_commitment: OrderCommitment,
    pub order: OrderIntent,
    pub funding_note: Note,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub funding_notes: Vec<Note>,
    pub funding_authorization: SpendAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_maker_authorization: Option<ManagedMakerAuthorization>,
}

impl AuctionOrderWitness {
    pub fn effective_funding_notes(&self) -> Vec<&Note> {
        if self.funding_notes.is_empty() {
            vec![&self.funding_note]
        } else {
            self.funding_notes.iter().collect()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumedInput {
    pub note_commitment: NoteCommitment,
    pub nullifier: Nullifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalChildUse {
    pub parent_order_commitment: String,
    pub child_nullifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEntry {
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    pub recipient: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputNoteRecord {
    pub note_commitment: NoteCommitment,
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    pub withdraw_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedOutputNotePayload {
    pub version: u32,
    pub batch_id: BatchId,
    pub output_index: u64,
    pub note: Note,
    pub output_note: OutputNoteRecord,
    pub output_proof: OutputNoteMerkleProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputCiphertextBundle {
    pub batch_id: BatchId,
    pub bundle_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_envelope_commitment: Option<String>,
    pub data_availability_ref: String,
    #[serde(default)]
    pub ciphertext_count_bucket: String,
    #[serde(default)]
    pub padded_ciphertext_count: u64,
    pub ciphertexts: Vec<EncryptedBlob>,
}

impl OutputCiphertextBundle {
    pub fn from_ciphertexts(
        batch_id: BatchId,
        data_availability_ref: impl Into<String>,
        mut ciphertexts: Vec<EncryptedBlob>,
    ) -> Result<Self, ProtocolError> {
        let original_ciphertext_count = ciphertexts.len();
        let padded_ciphertext_count = output_bundle_bucket_size(original_ciphertext_count);
        for index in ciphertexts.len()..padded_ciphertext_count {
            ciphertexts.push(dummy_output_ciphertext(&batch_id, index)?);
        }
        let recovery_bundle_root = output_recovery_bundle_root_from_ciphertexts(&ciphertexts)?;
        let ciphertext_envelope_commitment = output_ciphertext_envelope_commitment(&ciphertexts)?;
        let bundle_commitment =
            recovery_bundle_root.unwrap_or_else(|| ciphertext_envelope_commitment.clone());
        Ok(Self {
            batch_id,
            bundle_commitment,
            ciphertext_envelope_commitment: Some(ciphertext_envelope_commitment),
            data_availability_ref: data_availability_ref.into(),
            ciphertext_count_bucket: output_bundle_count_bucket_label(original_ciphertext_count),
            padded_ciphertext_count: padded_ciphertext_count as u64,
            ciphertexts,
        })
    }
}

pub fn output_ciphertext_envelope_commitment(
    ciphertexts: &[EncryptedBlob],
) -> Result<String, ProtocolError> {
    tagged_commitment_sha256("zylith/output-bundle", &ciphertexts.to_vec())
}

pub fn output_recovery_bundle_root_from_ciphertexts(
    ciphertexts: &[EncryptedBlob],
) -> Result<Option<String>, ProtocolError> {
    let mut commitments = Vec::with_capacity(ciphertexts.len());
    for ciphertext in ciphertexts {
        let Some(recovery) = ciphertext.recovery.as_ref() else {
            return Ok(None);
        };
        let recomputed = output_recovery_record_commitment(recovery)?;
        if felt_from_hex_str(&recomputed)? != felt_from_hex_str(&recovery.commitment)? {
            return Err(ProtocolError::Crypto(
                "output recovery record commitment mismatch".into(),
            ));
        }
        commitments.push(recovery.commitment.clone());
    }
    Ok(Some(output_recovery_bundle_root(&commitments)?))
}

pub fn output_recovery_bundle_root(commitments: &[String]) -> Result<String, ProtocolError> {
    let mut state = felt_from_hex_str(OUTPUT_RECOVERY_BUNDLE_DOMAIN_HEX)?;
    for commitment in commitments {
        state = poseidon_hash(state, felt_from_hex_str(commitment)?);
    }
    Ok(crate::hash::felt_hex(&poseidon_hash(
        state,
        field_from_u64(commitments.len() as u64),
    )))
}

pub fn output_recovery_record_commitment(
    record: &OutputRecoveryRecord,
) -> Result<String, ProtocolError> {
    if record.ciphertext_fields.len() != OUTPUT_RECOVERY_FIELD_COUNT {
        return Err(ProtocolError::Crypto(format!(
            "output recovery record must have {OUTPUT_RECOVERY_FIELD_COUNT} fields"
        )));
    }
    let mut state = felt_from_hex_str(OUTPUT_RECOVERY_RECORD_DOMAIN_HEX)?;
    state = poseidon_hash(state, felt_from_hex_str(&record.key_tag)?);
    state = poseidon_hash(state, felt_from_hex_str(&record.auth_tag)?);
    for field in &record.ciphertext_fields {
        state = poseidon_hash(state, felt_from_hex_str(field)?);
    }
    Ok(crate::hash::felt_hex(&state))
}

pub fn output_bundle_count_bucket_label(count: usize) -> String {
    match count {
        0..=4 => "0-4".into(),
        5..=8 => "5-8".into(),
        9..=16 => "9-16".into(),
        17..=32 => "17-32".into(),
        33..=64 => "33-64".into(),
        65..=128 => "65-128".into(),
        _ => "129+".into(),
    }
}

pub fn count_bucket_label(count: u64) -> String {
    match count {
        0..=7 => "0-7".into(),
        8..=31 => "8-31".into(),
        32..=127 => "32-127".into(),
        128..=511 => "128-511".into(),
        _ => "512+".into(),
    }
}

pub fn output_bundle_bucket_size(count: usize) -> usize {
    match count {
        0..=4 => 4,
        5..=8 => 8,
        9..=16 => 16,
        17..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => count.next_power_of_two(),
    }
}

fn dummy_output_ciphertext(
    _batch_id: &BatchId,
    _output_index: usize,
) -> Result<EncryptedBlob, ProtocolError> {
    let mut key_id = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    let mut ciphertext = vec![0_u8; OUTPUT_NOTE_CIPHERTEXT_LEN];
    OsRng.fill_bytes(&mut key_id);
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(ciphertext.as_mut_slice());
    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let ephemeral_public_key = hex::encode(
        ephemeral_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    Ok(EncryptedBlob {
        algorithm: NOTE_RECOGNITION_ALGORITHM.into(),
        key_id: hex::encode(key_id),
        ephemeral_public_key,
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
        recovery: Some(dummy_output_recovery_record()?),
    })
}

fn dummy_output_recovery_record() -> Result<OutputRecoveryRecord, ProtocolError> {
    let key_tag = random_field_hex();
    let auth_tag = random_field_hex();
    let ciphertext_fields = (0..OUTPUT_RECOVERY_FIELD_COUNT)
        .map(|_| random_field_hex())
        .collect::<Vec<_>>();
    let mut record = OutputRecoveryRecord {
        key_tag,
        ciphertext_fields,
        auth_tag,
        commitment: "0x0".into(),
    };
    record.commitment = output_recovery_record_commitment(&record)?;
    Ok(record)
}

fn random_field_hex() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("0x{}", hex::encode(bytes))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementTranscript {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub batch_epoch: u64,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
    #[serde(default = "zero_felt_string")]
    pub prior_note_root: String,
    #[serde(default = "zero_felt_string")]
    pub prior_nullifier_root: String,
    #[serde(default = "zero_felt_string")]
    pub prior_renewal_root: String,
    #[serde(default = "zero_felt_string")]
    pub prior_fee_root: String,
    #[serde(default = "zero_felt_string")]
    pub new_nullifier_root: String,
    #[serde(default = "zero_felt_string")]
    pub new_renewal_root: String,
    #[serde(with = "serde_u128_decimal")]
    pub clearing_price: u128,
    #[serde(default = "default_price_base_scale", with = "serde_u128_decimal")]
    pub price_base_scale: u128,
    #[serde(default = "default_speculative_taker_fee_bps")]
    pub taker_fee_bps: u16,
    #[serde(default)]
    pub maker_fee_bps: u16,
    #[serde(default)]
    pub relay_fee_bps: u16,
    #[serde(default = "default_protocol_fee_recipient")]
    pub protocol_fee_recipient: String,
    #[serde(default = "default_relay_fee_recipient")]
    pub relay_fee_recipient: String,
    pub matched_orders: Vec<MatchedOrder>,
    pub consumed_inputs: Vec<ConsumedInput>,
    #[serde(default)]
    pub renewal_child_uses: Vec<RenewalChildUse>,
    pub fees: Vec<FeeEntry>,
    pub output_notes: Vec<OutputNoteRecord>,
    #[serde(default)]
    pub output_note_preimages: Vec<Note>,
    #[serde(default)]
    pub output_recovery_records: Vec<OutputRecoveryRecord>,
    #[serde(default)]
    pub output_recovery_dummy_commitments: Vec<String>,
    pub output_ciphertext_bundle_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootOnlySettlementCommitments {
    pub prior_note_root: String,
    pub prior_nullifier_root: String,
    pub prior_renewal_root: String,
    pub prior_fee_root: String,
    pub consumed_note_root: String,
    pub consumed_nullifier_root: String,
    pub renewal_child_root: String,
    pub output_note_root: String,
    pub fee_root: String,
    pub new_note_root: String,
    pub new_nullifier_root: String,
    pub new_renewal_root: String,
    pub new_fee_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteMembershipKind {
    Deposit,
    SettlementOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteMembershipWitness {
    pub kind: NoteMembershipKind,
    pub prefix_root: String,
    pub batch_root: String,
    #[serde(default)]
    pub merkle_path: Vec<String>,
    #[serde(default)]
    pub merkle_directions: Vec<String>,
    #[serde(default)]
    pub suffix_batch_roots: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierHistoryBatch {
    #[serde(default = "one_u64")]
    pub repeat_count: u64,
    pub nullifiers: Vec<Nullifier>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalStateHistoryBatch {
    #[serde(default = "one_u64")]
    pub repeat_count: u64,
    pub entries: Vec<String>,
}

fn one_u64() -> u64 {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierSparseUpdateWitness {
    pub key_low: String,
    pub key_high: String,
    pub merkle_path: Vec<String>,
    pub merkle_directions: Vec<String>,
}

pub const TRANSCRIPT_SHAPE_POLICY_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptShapeMetadata {
    pub policy_version: u32,
    pub matched_order_count_bucket: String,
    pub consumed_input_count_bucket: String,
    pub renewal_child_count_bucket: String,
    pub fee_count_bucket: String,
    pub output_note_count_bucket: String,
    pub output_ciphertext_count_bucket: String,
    pub padded_output_ciphertext_count: u64,
}

pub fn transcript_shape_metadata(
    transcript: &SettlementTranscript,
    output_bundle: &OutputCiphertextBundle,
) -> TranscriptShapeMetadata {
    TranscriptShapeMetadata {
        policy_version: TRANSCRIPT_SHAPE_POLICY_VERSION,
        matched_order_count_bucket: count_bucket_label(transcript.matched_orders.len() as u64),
        consumed_input_count_bucket: count_bucket_label(transcript.consumed_inputs.len() as u64),
        renewal_child_count_bucket: count_bucket_label(transcript.renewal_child_uses.len() as u64),
        fee_count_bucket: count_bucket_label(transcript.fees.len() as u64),
        output_note_count_bucket: output_bundle_count_bucket_label(transcript.output_notes.len()),
        output_ciphertext_count_bucket: output_bundle.ciphertext_count_bucket.clone(),
        padded_output_ciphertext_count: output_bundle.padded_ciphertext_count,
    }
}

pub fn validate_transcript_shape_policy(
    transcript: &SettlementTranscript,
    output_bundle: &OutputCiphertextBundle,
) -> Result<TranscriptShapeMetadata, ProtocolError> {
    if transcript.batch_id != output_bundle.batch_id {
        return Err(ProtocolError::InvalidSettlementProof(
            "output bundle batch_id does not match transcript batch_id".into(),
        ));
    }
    if transcript.output_ciphertext_bundle_ref != output_bundle.bundle_commitment {
        return Err(ProtocolError::InvalidSettlementProof(
            "transcript output bundle ref does not match output bundle commitment".into(),
        ));
    }
    let output_count = transcript.output_notes.len();
    let expected_padded_count = output_bundle_bucket_size(output_count);
    let expected_count_bucket = output_bundle_count_bucket_label(output_count);
    if output_bundle.ciphertexts.len() != expected_padded_count {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "output bundle ciphertext length must be padded to {expected_padded_count}, got {}",
            output_bundle.ciphertexts.len()
        )));
    }
    if output_bundle.padded_ciphertext_count != expected_padded_count as u64 {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "output bundle padded_ciphertext_count must be {expected_padded_count}, got {}",
            output_bundle.padded_ciphertext_count
        )));
    }
    if output_bundle.ciphertext_count_bucket != expected_count_bucket {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "output bundle ciphertext_count_bucket must be {expected_count_bucket}, got {}",
            output_bundle.ciphertext_count_bucket
        )));
    }
    validate_output_ciphertext_bundle_shape(output_bundle)?;
    let recomputed_bundle = OutputCiphertextBundle::from_ciphertexts(
        output_bundle.batch_id.clone(),
        output_bundle.data_availability_ref.clone(),
        output_bundle.ciphertexts.clone(),
    )?;
    if recomputed_bundle.bundle_commitment != output_bundle.bundle_commitment {
        return Err(ProtocolError::InvalidSettlementProof(
            "output bundle commitment does not match ciphertext contents".into(),
        ));
    }
    match (
        output_bundle.ciphertext_envelope_commitment.as_ref(),
        recomputed_bundle.ciphertext_envelope_commitment.as_ref(),
    ) {
        (Some(actual), Some(expected)) if actual == expected => {}
        (Some(_), Some(_)) => {
            return Err(ProtocolError::InvalidSettlementProof(
                "output bundle envelope commitment does not match ciphertext contents".into(),
            ));
        }
        _ => {
            return Err(ProtocolError::InvalidSettlementProof(
                "output bundle envelope commitment is missing".into(),
            ));
        }
    }

    Ok(transcript_shape_metadata(transcript, output_bundle))
}

fn validate_output_ciphertext_bundle_shape(
    output_bundle: &OutputCiphertextBundle,
) -> Result<(), ProtocolError> {
    let mut seen_envelopes = BTreeSet::new();
    for (index, blob) in output_bundle.ciphertexts.iter().enumerate() {
        if blob.algorithm != NOTE_RECOGNITION_ALGORITHM {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "output ciphertext {index} uses unsupported algorithm"
            )));
        }
        let key_id = hex::decode(&blob.key_id).map_err(|_| {
            ProtocolError::InvalidSettlementProof(format!("output ciphertext {index} bad key_id"))
        })?;
        if key_id.len() != 32 || key_id.iter().all(|byte| *byte == 0) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "output ciphertext {index} key_id must be a nonzero 32-byte value"
            )));
        }
        let ephemeral_public_key = hex::decode(&blob.ephemeral_public_key).map_err(|_| {
            ProtocolError::InvalidSettlementProof(format!(
                "output ciphertext {index} bad ephemeral public key"
            ))
        })?;
        if ephemeral_public_key.len() != 65 || ephemeral_public_key.first() != Some(&4) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "output ciphertext {index} ephemeral public key must be uncompressed P-256"
            )));
        }
        let nonce = hex::decode(&blob.nonce).map_err(|_| {
            ProtocolError::InvalidSettlementProof(format!("output ciphertext {index} bad nonce"))
        })?;
        if nonce.len() != 12 || nonce.iter().all(|byte| *byte == 0) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "output ciphertext {index} nonce must be a nonzero 12-byte value"
            )));
        }
        let ciphertext = hex::decode(&blob.ciphertext).map_err(|_| {
            ProtocolError::InvalidSettlementProof(format!(
                "output ciphertext {index} bad ciphertext"
            ))
        })?;
        if ciphertext.len() != OUTPUT_NOTE_CIPHERTEXT_LEN {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "output ciphertext {index} ciphertext length must be {OUTPUT_NOTE_CIPHERTEXT_LEN}"
            )));
        }
        let envelope_id = (
            blob.key_id.clone(),
            blob.ephemeral_public_key.clone(),
            blob.nonce.clone(),
        );
        if !seen_envelopes.insert(envelope_id) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "output ciphertext {index} reuses an encryption envelope"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifacts {
    pub transcript: SettlementTranscript,
    pub output_bundle: OutputCiphertextBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maker_attribution_bundle: Option<MakerAttributionBundle>,
    pub settlement_witness: SettlementWitness,
    #[serde(default)]
    pub published_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_transaction_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_contract_address: Option<String>,
    #[serde(default)]
    pub order_execution_reports: Vec<OrderExecutionReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_shape: Option<TranscriptShapeMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementReportQuery {
    #[serde(default)]
    pub output_recovery_key_tags: Vec<String>,
    #[serde(default)]
    pub order_commitments: Vec<OrderCommitment>,
    #[serde(default)]
    pub order_report_auths: Vec<OrderReportAuthRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderReportAuthRequest {
    pub order_commitment: OrderCommitment,
    pub order_report_auth_tag: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementOutputRecoveryRecord {
    pub output_index: u64,
    pub recovery: OutputRecoveryRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementReport {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub batch_epoch: u64,
    pub settled_at_unix_ms: u64,
    pub output_note_root: String,
    #[serde(with = "serde_u128_decimal")]
    pub clearing_price: u128,
    #[serde(with = "serde_u128_decimal")]
    pub price_base_scale: u128,
    pub matched_order_count: u64,
    pub output_recovery_records: Vec<PrivateSettlementOutputRecoveryRecord>,
    pub order_execution_reports: Vec<OrderExecutionReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSettlementTranscript {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub batch_epoch: u64,
    #[serde(default)]
    pub published_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at_unix_ms: Option<u64>,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
    pub transcript_commitment: String,
    #[serde(with = "serde_u128_decimal")]
    pub clearing_price: u128,
    #[serde(default = "default_price_base_scale", with = "serde_u128_decimal")]
    pub price_base_scale: u128,
    #[serde(default = "default_speculative_taker_fee_bps")]
    pub taker_fee_bps: u16,
    #[serde(default)]
    pub maker_fee_bps: u16,
    #[serde(default)]
    pub relay_fee_bps: u16,
    #[serde(default = "default_protocol_fee_recipient")]
    pub protocol_fee_recipient: String,
    #[serde(default = "default_relay_fee_recipient")]
    pub relay_fee_recipient: String,
    pub output_bundle_ref: String,
    pub prior_note_root: String,
    pub prior_nullifier_root: String,
    pub prior_renewal_root: String,
    pub prior_fee_root: String,
    pub consumed_note_root: String,
    pub consumed_nullifier_root: String,
    pub renewal_child_root: String,
    pub output_note_root: String,
    pub fee_root: String,
    pub new_note_root: String,
    pub new_nullifier_root: String,
    pub new_renewal_root: String,
    pub new_fee_root: String,
    pub transcript_shape: TranscriptShapeMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRootHistoryBatch {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub batch_epoch: u64,
    pub prior_note_root: String,
    pub prior_nullifier_root: String,
    pub prior_renewal_root: String,
    pub prior_fee_root: String,
    pub output_note_root: String,
    pub consumed_nullifier_root: String,
    pub new_note_root: String,
    pub new_nullifier_root: String,
    pub new_renewal_root: String,
    #[serde(default)]
    pub consumed_inputs: Vec<ConsumedInput>,
    #[serde(default)]
    pub renewal_entries: Vec<String>,
    #[serde(default)]
    pub output_notes: Vec<OutputNoteRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalCancelMarkerRecord {
    pub cancel_marker: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(default)]
    pub recorded_at_unix_ms: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalCancelMarkerList {
    pub records: Vec<RenewalCancelMarkerRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRootHistoryArchive {
    pub batches: Vec<SettlementRootHistoryBatch>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifactSummary {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub batch_epoch: u64,
    #[serde(default)]
    pub published_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at_unix_ms: Option<u64>,
    pub transcript_commitment: String,
    pub output_bundle_ref: String,
    pub output_note_root: String,
    pub bundle_commitment: String,
    pub data_availability_ref: String,
    pub ciphertext_count_bucket: String,
    pub padded_ciphertext_count: u64,
    pub matched_order_count_bucket: String,
    pub consumed_input_count_bucket: String,
    pub renewal_child_count_bucket: String,
    pub fee_count_bucket: String,
    pub output_note_count_bucket: String,
    pub transcript_shape_policy_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifactList {
    pub batches: Vec<PublishedBatchArtifactSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete_through_epoch: Option<u64>,
}

pub const ARTIFACT_AGGREGATION_POLICY_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactAggregationPolicy {
    pub policy_version: u32,
    pub public_artifact_delay_epochs: u64,
    #[serde(default)]
    pub public_artifact_delay_min_epochs: u64,
    #[serde(default)]
    pub public_artifact_delay_max_epochs: u64,
    pub epoch_bucket_size: u64,
    pub aggregation_scope: String,
    pub proof_aggregation_mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiPairArtifactBundleSummary {
    pub bundle_id: String,
    pub epoch_start: u64,
    pub epoch_end: u64,
    pub delayed_until_epoch: u64,
    pub artifact_count_bucket: String,
    pub pair_count_bucket: String,
    pub padded_artifact_count: u64,
    pub aggregate_commitment: String,
    pub transcript_commitment_root: String,
    pub output_bundle_root: String,
    pub data_availability_root: String,
    pub transcript_shape_policy_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiPairArtifactBundleList {
    pub policy: ArtifactAggregationPolicy,
    pub bundles: Vec<MultiPairArtifactBundleSummary>,
}

pub fn artifact_epoch_bucket_start(
    epoch: u64,
    epoch_bucket_size: u64,
) -> Result<u64, ProtocolError> {
    if epoch_bucket_size == 0 {
        return Err(ProtocolError::InvalidProductConfig(
            "artifact epoch bucket size must be non-zero".into(),
        ));
    }
    Ok(epoch - (epoch % epoch_bucket_size))
}

pub fn artifact_epoch_bucket_end(
    epoch_start: u64,
    epoch_bucket_size: u64,
) -> Result<u64, ProtocolError> {
    if epoch_bucket_size == 0 {
        return Err(ProtocolError::InvalidProductConfig(
            "artifact epoch bucket size must be non-zero".into(),
        ));
    }
    Ok(epoch_start.saturating_add(epoch_bucket_size.saturating_sub(1)))
}

pub fn artifact_bundle_padded_count(count: usize) -> usize {
    match count {
        0..=8 => 8,
        9..=16 => 16,
        17..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => count.next_power_of_two(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorStatus {
    pub service: String,
    pub current_batch_id: Option<BatchId>,
    pub tracked_batches_bucket: String,
    pub batch_window_ms: u64,
    pub batch_close_jitter_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchLiquidityReport {
    pub status: String,
    pub reason: Option<String>,
    #[serde(
        default,
        serialize_with = "serde_u128_decimal::serialize_option",
        deserialize_with = "serde_u128_decimal::deserialize_option"
    )]
    pub diagnostic_price: Option<u128>,
    #[serde(with = "serde_u128_decimal")]
    pub buy_base_demand: u128,
    #[serde(with = "serde_u128_decimal")]
    pub sell_base_supply: u128,
    #[serde(with = "serde_u128_decimal")]
    pub matched_base_volume: u128,
    pub crossing_order_count: u64,
    #[serde(with = "serde_u128_decimal")]
    pub min_base_liquidity: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedBatchStatus {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub order_count: u64,
    pub state: String,
    #[serde(
        default,
        serialize_with = "serde_u128_decimal::serialize_option",
        deserialize_with = "serde_u128_decimal::deserialize_option"
    )]
    pub candidate_clearing_price: Option<u128>,
    #[serde(with = "serde_u128_decimal")]
    pub matched_volume: u128,
    pub transcript_available: bool,
    pub liquidity: BatchLiquidityReport,
    #[serde(default)]
    pub order_execution_reports: Vec<OrderExecutionReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobStatus {
    pub batch_id: BatchId,
    pub state: String,
    pub transcript_commitment: String,
    pub matched_order_count: u64,
    pub settlement_plan_available: bool,
    pub witness_available: bool,
    pub proof_artifact_available: bool,
    pub onchain_submission_available: bool,
    pub proof_artifact_id: Option<String>,
    pub onchain_submission_id: Option<String>,
    pub prover_backend: String,
    pub last_error: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub settlement_contract_address: String,
    pub settlement_entrypoint: String,
    pub settlement_calldata_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifactRecord {
    pub artifact_id: String,
    pub batch_id: BatchId,
    pub proof_system: String,
    pub proof_format: String,
    pub prover_backend: String,
    pub created_at_unix_ms: u64,
    pub proof_artifact_commitment: String,
    pub proof_path: String,
    pub public_inputs_path: String,
    pub prover_stdout_path: String,
    pub prover_stderr_path: String,
    pub proof_sha256: String,
    pub public_inputs_sha256: String,
    pub native_proof_file_path: Option<String>,
    pub native_proof_facts_file_path: Option<String>,
    pub native_execution_request_path: Option<String>,
    #[serde(default)]
    pub native_nullifier_proof_file_path: Option<String>,
    #[serde(default)]
    pub native_nullifier_proof_facts_file_path: Option<String>,
    #[serde(default)]
    pub native_nullifier_execution_request_path: Option<String>,
    #[serde(default)]
    pub native_renewal_proof_file_path: Option<String>,
    #[serde(default)]
    pub native_renewal_proof_facts_file_path: Option<String>,
    #[serde(default)]
    pub native_renewal_execution_request_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnchainSubmissionRecord {
    pub submission_id: String,
    pub batch_id: BatchId,
    pub transaction_hash: String,
    pub submitted_at_unix_ms: u64,
    pub receipt_checked_at_unix_ms: Option<u64>,
    pub confirmed_at_unix_ms: Option<u64>,
    pub finality_status: Option<String>,
    pub execution_status: Option<String>,
    pub revert_reason: Option<String>,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub block_timestamp_unix_ms: Option<u64>,
    pub submission_mode: String,
    pub settlement_contract_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementTimestampUpdate {
    pub settled_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_contract_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_note_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_commitment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarknetCall {
    pub contract_address: String,
    pub entrypoint: String,
    pub calldata: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalParentCancelPlanRequest {
    pub chain_id: String,
    pub auction_verifier_address: String,
    pub parent_secret_commitment: String,
    pub parent_cancel_authority: String,
    pub renewal_cancel_auth_key: String,
    #[serde(default)]
    pub prior_renewal_entries: Vec<String>,
    #[serde(default)]
    pub renewal_cancel_sparse_witness: Option<NullifierSparseUpdateWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalParentCancelCallArguments {
    pub cancel_marker: String,
    pub cancel_authority: String,
    pub sparse_key_low: String,
    pub sparse_key_high: String,
    pub merkle_path: Vec<String>,
    pub merkle_directions: Vec<String>,
    pub signature_r: String,
    pub signature_s: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalParentCancelSubmissionPlan {
    pub starknet_call: StarknetCall,
    pub encoded_args: RenewalParentCancelCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCallArguments {
    pub funding_commitments: Vec<String>,
    pub deposit_roots: Vec<String>,
    pub encrypted_note_activations: Vec<String>,
    pub note_commitments: Vec<String>,
    pub asset_ids: Vec<String>,
    pub amounts: Vec<String>,
    pub withdraw_authorities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositSubmissionPlan {
    pub funding_rail: FundingRailKind,
    pub note: Note,
    pub note_commitment: NoteCommitment,
    pub funding_commitment: String,
    pub deposit_root: String,
    pub encrypted_note_activation: String,
    pub encoded_args: DepositCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositActivationRecord {
    pub activation_id: u64,
    pub funding_commitment: String,
    pub deposit_root: String,
    pub encrypted_note_activation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalCallArguments {
    pub note_commitment: String,
    pub withdraw_authorization_r: String,
    pub withdraw_authorization_s: String,
    pub recipient: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalSubmissionPlan {
    pub funding_rail: FundingRailKind,
    pub note_commitment: NoteCommitment,
    pub starknet_call: StarknetCall,
    pub encoded_args: WithdrawalCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputNoteMerkleProof {
    pub merkle_path: Vec<String>,
    pub merkle_directions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementOutputWithdrawalCallArguments {
    pub batch_id: String,
    pub proof_artifact_commitment: String,
    pub prior_nullifier_root: String,
    pub consumed_nullifier_root: String,
    pub new_nullifier_root: String,
    pub note_commitment: String,
    pub asset_id: String,
    pub amount: String,
    pub withdraw_authority: String,
    pub merkle_path: Vec<String>,
    pub merkle_directions: Vec<String>,
    pub withdraw_authorization_r: String,
    pub withdraw_authorization_s: String,
    pub recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strk20_exit_commitment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementOutputWithdrawalSubmissionPlan {
    pub funding_rail: FundingRailKind,
    pub batch_id: BatchId,
    pub note_commitment: NoteCommitment,
    pub withdrawal_commitment: String,
    pub proof_artifact_commitment: String,
    pub starknet_call: StarknetCall,
    pub encoded_args: SettlementOutputWithdrawalCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteConsolidationCallArguments {
    pub consolidation_id: String,
    pub proof_artifact_commitment: String,
    pub output_bundle_ref: String,
    pub prior_note_root: String,
    pub prior_nullifier_root: String,
    pub consumed_note_root: String,
    pub consumed_nullifier_root: String,
    pub output_note_root: String,
    pub new_note_root: String,
    pub new_nullifier_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteConsolidationSubmissionPlan {
    pub consolidation_id: BatchId,
    pub consolidation_commitment: String,
    pub proof_artifact_commitment: String,
    pub consolidation_call: StarknetCall,
    pub encoded_args: NoteConsolidationCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementOutputWithdrawalWitness {
    pub batch_id: BatchId,
    pub auction_verifier_address: String,
    pub shielded_asset_adapter_address: String,
    pub chain_id: String,
    pub recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strk20_exit_commitment: Option<String>,
    pub prior_nullifier_root: String,
    pub output_note: OutputNoteRecord,
    pub output_note_preimage: Note,
    pub output_proof: OutputNoteMerkleProof,
    pub withdraw_authorization: SpendAuthorization,
    #[serde(default)]
    pub nullifier_history: Vec<NullifierHistoryBatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier_sparse_witness: Option<NullifierSparseUpdateWitness>,
    pub new_nullifier_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRecord {
    pub withdrawal_id: u64,
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    pub recipient: String,
    pub note_commitment: NoteCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositSyncStatus {
    pub service: String,
    pub rpc_configured: bool,
    pub shielded_asset_adapter_configured: bool,
    pub cached_deposits_bucket: String,
    pub synced_deposit_count_bucket: String,
    pub cached_withdrawals_bucket: String,
    pub synced_withdrawal_count_bucket: String,
    #[serde(default)]
    pub last_successful_sync_unix_ms: u64,
    #[serde(default)]
    pub sync_lag_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositConfirmationRequest {
    pub funding_commitments: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositConfirmationList {
    pub confirmed: Vec<DepositActivationRecord>,
    #[serde(default)]
    pub last_successful_sync_unix_ms: u64,
    #[serde(default)]
    pub sync_lag_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositActivationRecordList {
    pub start: u64,
    pub end: u64,
    pub count_bucket: String,
    pub records: Vec<DepositActivationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRecordList {
    pub start: u64,
    pub end: u64,
    pub count_bucket: String,
    pub records: Vec<WithdrawalRecord>,
}

pub const CLAIM_WINDOW_POLICY_VERSION: u32 = 1;
pub const WITHDRAWAL_AMOUNT_BUCKET_POLICY_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimWindowPolicy {
    pub policy_version: u32,
    pub min_delay_seconds: u64,
    pub window_seconds: u64,
    pub max_jitter_seconds: u64,
    pub urgent_exit_allowed: bool,
}

impl Default for ClaimWindowPolicy {
    fn default() -> Self {
        Self {
            policy_version: CLAIM_WINDOW_POLICY_VERSION,
            min_delay_seconds: 300,
            window_seconds: 900,
            max_jitter_seconds: 300,
            urgent_exit_allowed: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalWindowPlan {
    pub note_commitment: NoteCommitment,
    pub policy_version: u32,
    pub settlement_time_unix_ms: u64,
    pub earliest_withdrawal_unix_ms: u64,
    pub recommended_withdrawal_unix_ms: u64,
    pub window_id: u64,
    pub urgent_exit_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalAmountBucketPolicy {
    pub policy_version: u32,
    pub mode: String,
    pub asset_buckets: BTreeMap<String, Vec<String>>,
    pub urgent_exit_allowed: bool,
}

impl Default for WithdrawalAmountBucketPolicy {
    fn default() -> Self {
        let mut asset_buckets = BTreeMap::new();
        for asset in ["STRK", "ETH", "USDC", "strkBTC", "WBTC", "USDT"] {
            asset_buckets.insert(asset.into(), default_withdrawal_amount_buckets());
        }
        Self {
            policy_version: WITHDRAWAL_AMOUNT_BUCKET_POLICY_VERSION,
            mode: "standard_amount_buckets".into(),
            asset_buckets,
            urgent_exit_allowed: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalAmountBucketPlan {
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub requested_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub nearest_bucket_amount: u128,
    pub exact_bucket: bool,
    pub policy_version: u32,
    pub urgent_exit_allowed: bool,
}

pub fn default_withdrawal_amount_buckets() -> Vec<String> {
    [
        1_000_000_u128,
        10_000_000,
        100_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
        1_000_000_000_000,
        10_000_000_000_000,
        100_000_000_000_000,
        1_000_000_000_000_000,
        10_000_000_000_000_000,
        100_000_000_000_000_000,
    ]
    .into_iter()
    .map(|amount| amount.to_string())
    .collect()
}

pub fn plan_withdrawal_amount_bucket(
    asset_id: &AssetId,
    requested_amount: u128,
    policy: &WithdrawalAmountBucketPolicy,
) -> Result<WithdrawalAmountBucketPlan, ProtocolError> {
    if requested_amount == 0 {
        return Err(ProtocolError::InvalidProductConfig(
            "withdrawal amount must be non-zero".into(),
        ));
    }
    let buckets = policy
        .asset_buckets
        .get(&asset_id.0)
        .ok_or_else(|| {
            ProtocolError::InvalidProductConfig(format!(
                "withdrawal bucket policy does not include asset {}",
                asset_id.0
            ))
        })?
        .iter()
        .map(|amount| {
            amount.parse::<u128>().map_err(|err| {
                ProtocolError::InvalidProductConfig(format!(
                    "withdrawal bucket amount '{amount}' is not a decimal u128: {err}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if buckets.is_empty() {
        return Err(ProtocolError::InvalidProductConfig(
            "withdrawal bucket policy must include at least one bucket".into(),
        ));
    }

    let mut sorted = buckets;
    sorted.sort_unstable();
    sorted.dedup();
    let exact_bucket = sorted.binary_search(&requested_amount).is_ok();
    let nearest_bucket_amount = sorted
        .iter()
        .copied()
        .min_by_key(|bucket| bucket.abs_diff(requested_amount))
        .ok_or_else(|| {
            ProtocolError::InvalidProductConfig(
                "withdrawal bucket policy must include at least one bucket".into(),
            )
        })?;

    Ok(WithdrawalAmountBucketPlan {
        asset_id: asset_id.clone(),
        requested_amount,
        nearest_bucket_amount,
        exact_bucket,
        policy_version: policy.policy_version,
        urgent_exit_allowed: policy.urgent_exit_allowed,
    })
}

pub fn plan_withdrawal_window(
    note_commitment: &NoteCommitment,
    settlement_time_unix_ms: u64,
    policy: &ClaimWindowPolicy,
) -> Result<WithdrawalWindowPlan, ProtocolError> {
    if policy.window_seconds == 0 {
        return Err(ProtocolError::InvalidProductConfig(
            "claim window policy window_seconds must be non-zero".into(),
        ));
    }

    let earliest_withdrawal_unix_ms =
        settlement_time_unix_ms.saturating_add(policy.min_delay_seconds.saturating_mul(1_000));
    let jitter_bound = policy.max_jitter_seconds.min(policy.window_seconds);
    let jitter_seconds = if jitter_bound == 0 {
        0
    } else {
        let seed = tagged_commitment_sha256(
            "zylith/withdrawal-window-jitter",
            &serde_json::json!({
                "note_commitment": note_commitment.0,
                "settlement_time_unix_ms": settlement_time_unix_ms,
                "policy_version": policy.policy_version,
            }),
        )?;
        let prefix = seed.get(..16).ok_or_else(|| {
            ProtocolError::Crypto("withdrawal window jitter seed was malformed".into())
        })?;
        u64::from_str_radix(prefix, 16)
            .map_err(|err| ProtocolError::Crypto(format!("invalid jitter seed: {err}")))?
            % (jitter_bound + 1)
    };
    let recommended_withdrawal_unix_ms =
        earliest_withdrawal_unix_ms.saturating_add(jitter_seconds.saturating_mul(1_000));
    let window_ms = policy.window_seconds.saturating_mul(1_000);

    Ok(WithdrawalWindowPlan {
        note_commitment: note_commitment.clone(),
        policy_version: policy.policy_version,
        settlement_time_unix_ms,
        earliest_withdrawal_unix_ms,
        recommended_withdrawal_unix_ms,
        window_id: recommended_withdrawal_unix_ms / window_ms,
        urgent_exit_allowed: policy.urgent_exit_allowed,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementCallArguments {
    pub batch_id: String,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
    pub transcript_commitment: String,
    pub proof_artifact_commitment: String,
    pub clearing_price: String,
    pub price_base_scale: String,
    pub taker_fee_bps: String,
    pub maker_fee_bps: String,
    pub relay_fee_bps: String,
    pub protocol_fee_recipient: String,
    pub relay_fee_recipient: String,
    pub output_bundle_ref: String,
    pub prior_note_root: String,
    pub prior_nullifier_root: String,
    pub prior_renewal_root: String,
    pub prior_fee_root: String,
    pub consumed_note_root: String,
    pub consumed_nullifier_root: String,
    pub renewal_child_root: String,
    pub output_note_root: String,
    pub fee_root: String,
    pub new_note_root: String,
    pub new_nullifier_root: String,
    pub new_renewal_root: String,
    pub new_fee_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementSubmissionPlan {
    pub batch_id: BatchId,
    pub transcript_commitment: String,
    pub proof_artifact_commitment: String,
    pub settlement_call: StarknetCall,
    pub encoded_args: SettlementCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementWitness {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub batch_epoch: u64,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
    pub transcript_commitment: String,
    pub auction_verifier_address: String,
    pub prior_note_root: String,
    pub prior_nullifier_root: String,
    pub prior_renewal_root: String,
    pub prior_fee_root: String,
    #[serde(default = "zero_felt_string")]
    pub new_nullifier_root: String,
    #[serde(default = "zero_felt_string")]
    pub new_renewal_root: String,
    #[serde(with = "serde_u128_decimal")]
    pub clearing_price: u128,
    #[serde(default = "default_price_base_scale", with = "serde_u128_decimal")]
    pub price_base_scale: u128,
    #[serde(default = "default_speculative_taker_fee_bps")]
    pub taker_fee_bps: u16,
    #[serde(default)]
    pub maker_fee_bps: u16,
    #[serde(default)]
    pub relay_fee_bps: u16,
    #[serde(default = "default_protocol_fee_recipient")]
    pub protocol_fee_recipient: String,
    #[serde(default = "default_relay_fee_recipient")]
    pub relay_fee_recipient: String,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub matched_orders: Vec<MatchedOrder>,
    pub matched_order_witnesses: Vec<MatchedOrderWitness>,
    pub consumed_inputs: Vec<ConsumedInput>,
    #[serde(default)]
    pub note_membership_witnesses: Vec<NoteMembershipWitness>,
    #[serde(default)]
    pub nullifier_history: Vec<NullifierHistoryBatch>,
    #[serde(default)]
    pub nullifier_sparse_witnesses: Vec<NullifierSparseUpdateWitness>,
    #[serde(default)]
    pub renewal_history: Vec<RenewalStateHistoryBatch>,
    #[serde(default)]
    pub renewal_child_sparse_witnesses: Vec<NullifierSparseUpdateWitness>,
    #[serde(default)]
    pub renewal_cancel_sparse_witnesses: Vec<NullifierSparseUpdateWitness>,
    pub renewal_child_uses: Vec<RenewalChildUse>,
    pub fees: Vec<FeeEntry>,
    pub output_notes: Vec<OutputNoteRecord>,
    #[serde(default)]
    pub output_note_preimages: Vec<Note>,
    #[serde(default)]
    pub output_recovery_records: Vec<OutputRecoveryRecord>,
    #[serde(default)]
    pub output_recovery_dummy_commitments: Vec<String>,
    pub output_ciphertext_bundle_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteConsolidationWitness {
    pub consolidation_id: BatchId,
    pub auction_verifier_address: String,
    pub prior_note_root: String,
    pub prior_nullifier_root: String,
    pub input_notes: Vec<Note>,
    pub spend_authorization: SpendAuthorization,
    #[serde(default)]
    pub note_membership_witnesses: Vec<NoteMembershipWitness>,
    #[serde(default)]
    pub nullifier_history: Vec<NullifierHistoryBatch>,
    #[serde(default)]
    pub nullifier_sparse_witnesses: Vec<NullifierSparseUpdateWitness>,
    pub output_notes: Vec<OutputNoteRecord>,
    pub output_note_preimages: Vec<Note>,
    pub output_recovery_records: Vec<OutputRecoveryRecord>,
    #[serde(default)]
    pub output_recovery_dummy_commitments: Vec<String>,
    pub output_ciphertext_bundle_ref: String,
    pub new_nullifier_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub snapshot_id: String,
    pub latest_batch_id: Option<BatchId>,
    pub notes: Vec<Note>,
    pub spent_nullifiers: Vec<Nullifier>,
    pub tracked_orders: Vec<OrderCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletEventKind {
    NoteReceived { commitment: NoteCommitment },
    NoteSpent { nullifier: Nullifier },
    OrderSubmitted { commitment: OrderCommitment },
    OrderCancelled { commitment: OrderCommitment },
    BatchSettled { batch_id: BatchId },
    SnapshotCreated { snapshot_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletEvent {
    pub event_id: String,
    pub timestamp_unix_ms: u64,
    pub kind: WalletEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryArtifactKind {
    Snapshot,
    WalletEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRecoveryPayload {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArtifact {
    pub artifact_id: String,
    pub account_id: String,
    pub kind: RecoveryArtifactKind,
    pub sequence: u64,
    pub created_at_unix_ms: u64,
    pub payload: EncryptedRecoveryPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArtifactUpload {
    pub artifact: RecoveryArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArtifactList {
    pub account_id: String,
    #[serde(default)]
    pub sequence_start: u64,
    #[serde(default)]
    pub sequence_end: u64,
    #[serde(default)]
    pub artifact_count_bucket: String,
    pub artifacts: Vec<RecoveryArtifact>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingRailKind {
    #[default]
    StarknetPrivacy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingRailCapabilities {
    pub private_deposits: bool,
    pub private_withdrawals: bool,
    pub private_transfers: bool,
    pub discovery_sync: bool,
    pub proof_bearing_transactions: bool,
    pub paymaster_ready: bool,
    pub user_controlled_disclosure: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarknetPrivacyFundingRail {
    pub privacy_pool: String,
    #[serde(default)]
    pub bridge_adapter: Option<String>,
    #[serde(default)]
    pub shielded_asset_adapter: Option<String>,
    pub discovery_url: String,
    pub proving_url: String,
    pub paymaster_address: Option<String>,
    pub paymaster_url: Option<String>,
    pub sdk_package: String,
    pub sdk_version: String,
    pub min_proving_delay_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingRailAssetConfig {
    pub asset_id: AssetId,
    pub token_address: String,
    pub rail_token_address: String,
    #[serde(with = "serde_u128_decimal")]
    pub min_trade_amount: u128,
    pub enabled_pairs: Vec<PairId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingRailConfig {
    pub primary: FundingRailKind,
    pub capabilities: FundingRailCapabilities,
    pub starknet_privacy: Option<StarknetPrivacyFundingRail>,
    pub assets: BTreeMap<String, FundingRailAssetConfig>,
}

impl Default for FundingRailConfig {
    fn default() -> Self {
        Self {
            primary: FundingRailKind::StarknetPrivacy,
            capabilities: FundingRailCapabilities {
                private_deposits: false,
                private_withdrawals: false,
                private_transfers: false,
                discovery_sync: false,
                proof_bearing_transactions: false,
                paymaster_ready: false,
                user_controlled_disclosure: false,
            },
            starknet_privacy: None,
            assets: BTreeMap::new(),
        }
    }
}

impl FundingRailConfig {
    pub fn active_rail(&self) -> Result<FundingRailKind, ProtocolError> {
        if self.starknet_privacy_configured() {
            Ok(FundingRailKind::StarknetPrivacy)
        } else {
            Err(ProtocolError::InvalidFundingRailConfig(
                "Starknet Privacy funding is not fully configured".into(),
            ))
        }
    }

    pub fn starknet_privacy_configured(&self) -> bool {
        self.starknet_privacy.as_ref().is_some_and(|config| {
            !config.privacy_pool.trim().is_empty()
                && config
                    .bridge_adapter
                    .as_ref()
                    .is_some_and(|address| !address.trim().is_empty())
                && !config.discovery_url.trim().is_empty()
                && !config.proving_url.trim().is_empty()
                && config
                    .paymaster_address
                    .as_ref()
                    .is_some_and(|address| !address.trim().is_empty())
                && config
                    .paymaster_url
                    .as_ref()
                    .is_some_and(|url| !url.trim().is_empty())
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductAssetConfig {
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub min_trade_amount: u128,
    #[serde(default = "default_asset_decimals")]
    pub decimals: u8,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductPairConfig {
    pub pair_id: PairId,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub min_order_amount: u128,
    #[serde(default = "default_price_base_scale", with = "serde_u128_decimal")]
    pub price_base_scale: u128,
    #[serde(default = "default_heartbeat_cover_price", with = "serde_u128_decimal")]
    pub heartbeat_cover_price: u128,
    #[serde(default = "default_speculative_taker_fee_bps")]
    pub taker_fee_bps: u16,
    #[serde(default)]
    pub maker_fee_bps: u16,
    #[serde(default)]
    pub relay_fee_bps: u16,
    pub enabled: bool,
}

impl ProductPairConfig {
    pub fn funding_asset_for_side(&self, side: &OrderSide) -> &AssetId {
        match side {
            OrderSide::Buy => &self.quote_asset_id,
            OrderSide::Sell => &self.base_asset_id,
        }
    }

    pub fn output_asset_for_side(&self, side: &OrderSide) -> &AssetId {
        match side {
            OrderSide::Buy => &self.base_asset_id,
            OrderSide::Sell => &self.quote_asset_id,
        }
    }

    pub fn fee_bps_for_order(&self, order: &OrderIntent) -> Result<u16, ProtocolError> {
        Ok(match order.order_type {
            OrderType::HeartbeatCover => 0,
            OrderType::MakerCurve => {
                order.validate_parent_link()?;
                self.maker_fee_bps
            }
            OrderType::LimitBatch => self.taker_fee_bps,
        })
    }

    pub fn relay_fee_bps_for_order(&self, order: &OrderIntent) -> Result<u16, ProtocolError> {
        order.validate_relay_mode()?;
        Ok(match order.relay_mode {
            RelayMode::ZylithRelay => self.relay_fee_bps,
            RelayMode::SelfRelay => 0,
        })
    }
}

fn default_heartbeat_cover_price() -> u128 {
    1
}

fn default_speculative_taker_fee_bps() -> u16 {
    4
}

fn default_protocol_fee_recipient() -> String {
    "zylith-protocol-treasury".into()
}

fn default_relay_fee_recipient() -> String {
    "zylith-renewal-relay".into()
}

pub fn default_pair_fee_bps(pair_id: &PairId) -> (u16, u16, u16) {
    if is_conversion_pair(pair_id) {
        (2, 0, 1)
    } else {
        (4, 0, 2)
    }
}

pub fn is_conversion_pair(pair_id: &PairId) -> bool {
    matches!(pair_id.0.as_str(), "WBTC/strkBTC" | "USDC/USDT")
}

pub fn maker_curve_min_spread_bps(pair_id: &PairId) -> u128 {
    match pair_id.0.as_str() {
        "USDC/USDT" => MAKER_CURVE_MIN_SPREAD_BPS_STABLE_CONVERSION,
        _ if is_conversion_pair(pair_id) => MAKER_CURVE_MIN_SPREAD_BPS_CONVERSION,
        _ => MAKER_CURVE_MIN_SPREAD_BPS_SPECULATIVE,
    }
}

pub fn maker_curve_min_band_base_amount(pair_id: &PairId) -> u128 {
    match pair_id.0.as_str() {
        "ETH/USDC" => 1_000_000_000_000_000,
        "strkBTC/USDC" | "WBTC/strkBTC" => 100_000,
        "USDC/USDT" => 1_000_000,
        "STRK/USDC" | "STRK/ETH" | "STRK/strkBTC" => 1_000_000_000_000_000_000,
        _ => 1,
    }
}

pub fn default_min_order_amount(pair_id: &PairId) -> u128 {
    maker_curve_min_band_base_amount(pair_id)
}

fn validate_maker_curve_pair_shape(
    pair_id: &PairId,
    curve: &HiddenMakerCurve,
) -> Result<(), ProtocolError> {
    let min_band_amount = maker_curve_min_band_base_amount(pair_id);
    for point in &curve.points {
        if point.base_amount < min_band_amount {
            return Err(ProtocolError::InvalidOrder(format!(
                "maker curve band depth {} is below pair minimum {}",
                point.base_amount, min_band_amount
            )));
        }
    }

    let first_price = curve
        .points
        .first()
        .map(|point| point.price)
        .ok_or_else(|| ProtocolError::InvalidOrder("maker curve missing first price".into()))?;
    let last_price = curve
        .points
        .last()
        .map(|point| point.price)
        .ok_or_else(|| ProtocolError::InvalidOrder("maker curve missing last price".into()))?;
    let min_spread_bps = maker_curve_min_spread_bps(pair_id);
    let actual = last_price
        .checked_mul(BPS_DENOMINATOR)
        .ok_or_else(|| ProtocolError::InvalidOrder("maker curve spread overflows u128".into()))?;
    let required = first_price
        .checked_mul(BPS_DENOMINATOR + min_spread_bps)
        .ok_or_else(|| ProtocolError::InvalidOrder("maker curve spread overflows u128".into()))?;
    if actual < required {
        return Err(ProtocolError::InvalidOrder(format!(
            "maker curve outer bands must span at least {min_spread_bps} bps"
        )));
    }
    Ok(())
}

fn default_price_base_scale() -> u128 {
    1
}

fn default_asset_decimals() -> u8 {
    18
}

pub fn known_asset_decimals(asset_id: &AssetId) -> u8 {
    match asset_id.0.as_str() {
        "USDC" | "USDT" => 6,
        "strkBTC" | "WBTC" => 8,
        "STRK" | "ETH" => 18,
        _ => default_asset_decimals(),
    }
}

pub fn asset_amount_scale(asset_id: &AssetId) -> u128 {
    10_u128.pow(u32::from(known_asset_decimals(asset_id)))
}

pub fn quote_amount_for_base_amount(
    base_amount: u128,
    price: u128,
    price_base_scale: u128,
) -> Result<u128, ProtocolError> {
    if price_base_scale == 0 {
        return Err(ProtocolError::InvalidProductConfig(
            "price_base_scale must be non-zero".into(),
        ));
    }
    base_amount
        .checked_mul(price)
        .and_then(|value| value.checked_div(price_base_scale))
        .ok_or_else(|| ProtocolError::InvalidOrder("quote amount overflows u128".into()))
}

pub fn base_amount_affordable_for_quote(
    quote_amount: u128,
    price: u128,
    price_base_scale: u128,
) -> Result<u128, ProtocolError> {
    if price == 0 || price_base_scale == 0 {
        return Ok(0);
    }
    quote_amount
        .checked_mul(price_base_scale)
        .and_then(|value| value.checked_div(price))
        .ok_or_else(|| ProtocolError::InvalidOrder("affordable base amount overflows u128".into()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductConfig {
    pub assets: BTreeMap<String, ProductAssetConfig>,
    pub pairs: BTreeMap<String, ProductPairConfig>,
}

impl Default for ProductConfig {
    fn default() -> Self {
        Self::default_v1()
    }
}

impl ProductConfig {
    pub fn default_v1() -> Self {
        let mut assets = BTreeMap::new();
        for asset_id in ["STRK", "ETH", "USDC", "strkBTC", "WBTC", "USDT"] {
            assets.insert(
                asset_id.to_owned(),
                ProductAssetConfig {
                    asset_id: AssetId(asset_id.to_owned()),
                    min_trade_amount: 1,
                    decimals: known_asset_decimals(&AssetId(asset_id.to_owned())),
                    enabled: true,
                },
            );
        }

        let mut pairs = BTreeMap::new();
        for (pair_id, base_asset_id, quote_asset_id) in [
            ("STRK/USDC", "STRK", "USDC"),
            ("ETH/USDC", "ETH", "USDC"),
            ("strkBTC/USDC", "strkBTC", "USDC"),
            ("STRK/ETH", "STRK", "ETH"),
            ("STRK/strkBTC", "STRK", "strkBTC"),
            ("WBTC/strkBTC", "WBTC", "strkBTC"),
            ("USDC/USDT", "USDC", "USDT"),
        ] {
            let pair_id_value = PairId(pair_id.to_owned());
            let (taker_fee_bps, maker_fee_bps, relay_fee_bps) =
                default_pair_fee_bps(&pair_id_value);
            pairs.insert(
                pair_id.to_owned(),
                ProductPairConfig {
                    pair_id: pair_id_value,
                    base_asset_id: AssetId(base_asset_id.to_owned()),
                    quote_asset_id: AssetId(quote_asset_id.to_owned()),
                    min_order_amount: default_min_order_amount(&PairId(pair_id.to_owned())),
                    price_base_scale: asset_amount_scale(&AssetId(base_asset_id.to_owned())),
                    heartbeat_cover_price: default_heartbeat_cover_price(),
                    taker_fee_bps,
                    maker_fee_bps,
                    relay_fee_bps,
                    enabled: true,
                },
            );
        }

        Self { assets, pairs }
    }

    pub fn from_enabled_pair_ids_csv(value: &str) -> Result<Self, ProtocolError> {
        let pair_ids = value
            .split(',')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
            .map(|pair| PairId(pair.to_owned()))
            .collect::<Vec<_>>();
        Self::from_enabled_pair_ids(pair_ids)
    }

    pub fn from_enabled_pair_ids(pair_ids: Vec<PairId>) -> Result<Self, ProtocolError> {
        if pair_ids.is_empty() {
            return Err(ProtocolError::InvalidProductConfig(
                "at least one enabled pair is required".into(),
            ));
        }

        let mut assets = BTreeMap::new();
        let mut pairs = BTreeMap::new();
        for pair_id in pair_ids {
            let pair = Self::pair_from_id(pair_id, true)?;
            for asset_id in [&pair.base_asset_id, &pair.quote_asset_id] {
                assets
                    .entry(asset_id.0.clone())
                    .or_insert_with(|| ProductAssetConfig {
                        asset_id: asset_id.clone(),
                        min_trade_amount: 1,
                        decimals: known_asset_decimals(asset_id),
                        enabled: true,
                    });
            }
            pairs.insert(pair.pair_id.0.clone(), pair);
        }

        Ok(Self { assets, pairs })
    }

    pub fn apply_heartbeat_cover_prices_csv(&mut self, value: &str) -> Result<(), ProtocolError> {
        for entry in value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (pair_id, price) = entry.split_once('=').ok_or_else(|| {
                ProtocolError::InvalidProductConfig(format!(
                    "heartbeat cover price entry '{entry}' must use PAIR=PRICE format"
                ))
            })?;
            let price = price.trim().parse::<u128>().map_err(|_| {
                ProtocolError::InvalidProductConfig(format!(
                    "heartbeat cover price for '{}' must be a decimal u128",
                    pair_id.trim()
                ))
            })?;
            if price == 0 {
                return Err(ProtocolError::InvalidProductConfig(format!(
                    "heartbeat cover price for '{}' must be positive",
                    pair_id.trim()
                )));
            }
            let pair_id = pair_id.trim();
            let pair = self.pairs.get_mut(pair_id).ok_or_else(|| {
                ProtocolError::InvalidProductConfig(format!(
                    "heartbeat cover price configured for unknown pair '{pair_id}'"
                ))
            })?;
            pair.heartbeat_cover_price = price;
        }
        Ok(())
    }

    pub fn enabled_pairs(&self) -> Vec<PairId> {
        self.pairs
            .values()
            .filter(|pair| pair.enabled)
            .map(|pair| pair.pair_id.clone())
            .collect()
    }

    pub fn enabled_pair(&self, pair_id: &PairId) -> Option<&ProductPairConfig> {
        self.pairs
            .get(&pair_id.0)
            .filter(|pair| pair.enabled && pair.pair_id == *pair_id)
    }

    pub fn validate_order_funding(
        &self,
        order: &OrderIntent,
        funding_note: &Note,
    ) -> Result<(), ProtocolError> {
        self.validate_order_funding_notes(order, std::slice::from_ref(funding_note))
    }

    pub fn validate_order_funding_notes(
        &self,
        order: &OrderIntent,
        funding_notes: &[Note],
    ) -> Result<(), ProtocolError> {
        let pair = self
            .enabled_pair(&order.pair_id)
            .ok_or_else(|| ProtocolError::UnsupportedPair(order.pair_id.0.clone()))?;

        order.validate_parent_link()?;
        order.validate_relay_mode()?;

        if order.amount == 0 {
            return Err(ProtocolError::InvalidOrder(
                "order amount must be positive".into(),
            ));
        }
        if order.limit_price == 0 {
            return Err(ProtocolError::InvalidOrder(
                "limit_price must be positive".into(),
            ));
        }
        if order.min_fill == 0 || order.min_fill > order.amount {
            return Err(ProtocolError::InvalidOrder(
                "min_fill must be positive and no larger than amount".into(),
            ));
        }
        match (&order.order_type, order.maker_curve.as_ref()) {
            (OrderType::HeartbeatCover, _) => {
                return Err(ProtocolError::InvalidOrder(
                    "heartbeat cover orders are protocol-generated".into(),
                ));
            }
            (OrderType::MakerCurve, Some(curve)) => {
                curve.validate()?;
                validate_maker_curve_pair_shape(&order.pair_id, curve)?;
                let curve_base_amount = curve.total_base_amount()?;
                if order.amount != curve_base_amount {
                    return Err(ProtocolError::InvalidOrder(
                        "maker curve order amount must equal the sum of curve base amounts".into(),
                    ));
                }
                let envelope_price = match order.side {
                    OrderSide::Buy => curve.points.last().map(|point| point.price),
                    OrderSide::Sell => curve.points.first().map(|point| point.price),
                }
                .ok_or_else(|| {
                    ProtocolError::InvalidOrder(
                        "maker curve must contain at least one point".into(),
                    )
                })?;
                if order.limit_price != envelope_price {
                    return Err(ProtocolError::InvalidOrder(
                        "maker curve limit_price must equal the curve envelope price".into(),
                    ));
                }
            }
            (OrderType::MakerCurve, None) => {
                return Err(ProtocolError::InvalidOrder(
                    "maker curve order missing curve".into(),
                ));
            }
            (_, Some(_)) => {
                return Err(ProtocolError::InvalidOrder(
                    "maker curve can only be attached to maker curve orders".into(),
                ));
            }
            _ => {}
        }
        if matches!(order.time_in_force, TimeInForce::FillOrKill) && order.min_fill != order.amount
        {
            return Err(ProtocolError::InvalidOrder(
                "fill-or-kill orders must set min_fill equal to amount".into(),
            ));
        }
        if order.amount < pair.min_order_amount {
            return Err(ProtocolError::InvalidOrder(format!(
                "order amount is below pair minimum {}",
                pair.min_order_amount
            )));
        }

        let expected_funding_asset = pair.funding_asset_for_side(&order.side);
        if funding_notes.is_empty() {
            return Err(ProtocolError::InvalidOrder(
                "order requires at least one funding note".into(),
            ));
        }
        if funding_notes.len() > MAX_ORDER_FUNDING_INPUTS {
            return Err(ProtocolError::InvalidOrder(format!(
                "order uses {} funding notes, maximum is {}",
                funding_notes.len(),
                MAX_ORDER_FUNDING_INPUTS
            )));
        }
        let first_spend_authority = &funding_notes[0].spend_authority;
        let first_owner_public_key = &funding_notes[0].owner_public_key;
        let mut total_funding = 0u128;
        let mut commitments = Vec::with_capacity(funding_notes.len());
        let mut nullifiers = Vec::with_capacity(funding_notes.len());
        let mut seen_commitments = BTreeSet::new();
        for funding_note in funding_notes {
            if funding_note.asset_id != *expected_funding_asset {
                return Err(ProtocolError::InvalidOrder(format!(
                    "funding note asset {} does not match expected {}",
                    funding_note.asset_id.0, expected_funding_asset.0
                )));
            }
            if &funding_note.spend_authority != first_spend_authority {
                return Err(ProtocolError::InvalidOrder(
                    "multi-note funding requires a common spend authority".into(),
                ));
            }
            if &funding_note.owner_public_key != first_owner_public_key {
                return Err(ProtocolError::InvalidOrder(
                    "multi-note funding requires a common note owner".into(),
                ));
            }
            total_funding = total_funding
                .checked_add(funding_note.amount)
                .ok_or_else(|| {
                    ProtocolError::InvalidOrder("funding note total overflows u128".into())
                })?;
            let commitment = funding_note.commitment()?;
            if !seen_commitments.insert(commitment.0.clone()) {
                return Err(ProtocolError::InvalidOrder(
                    "funding notes must be unique".into(),
                ));
            }
            nullifiers.push(nullifier_from_note_secret(
                &commitment,
                &funding_note.blinding,
            )?);
            commitments.push(commitment);
        }

        let minimum_funding = match order.side {
            OrderSide::Buy if matches!(order.order_type, OrderType::MakerCurve) => {
                let Some(curve) = order.maker_curve.as_ref() else {
                    return Err(ProtocolError::InvalidOrder(
                        "maker curve order missing curve".into(),
                    ));
                };
                curve.points.iter().try_fold(0u128, |total, point| {
                    let quote_amount = quote_amount_for_base_amount(
                        point.base_amount,
                        point.price,
                        pair.price_base_scale,
                    )?;
                    total.checked_add(quote_amount).ok_or_else(|| {
                        ProtocolError::InvalidOrder("maker curve buy funding overflows u128".into())
                    })
                })?
            }
            OrderSide::Buy => quote_amount_for_base_amount(
                order.min_fill,
                order.limit_price,
                pair.price_base_scale,
            )?,
            OrderSide::Sell if matches!(order.order_type, OrderType::MakerCurve) => order.amount,
            OrderSide::Sell => order.min_fill,
        };
        if total_funding < minimum_funding {
            return Err(ProtocolError::InvalidOrder(format!(
                "funding note total {} is below minimum required {}",
                total_funding, minimum_funding
            )));
        }

        if funding_input_set_commitment(&commitments)? != order.funding_note_ref {
            return Err(ProtocolError::InvalidOrder(
                "funding note set commitment mismatch".into(),
            ));
        }
        if funding_nullifier_set_commitment(&nullifiers)? != order.funding_nullifier {
            return Err(ProtocolError::InvalidOrder(
                "funding nullifier set commitment mismatch".into(),
            ));
        }

        Ok(())
    }

    fn pair_from_id(pair_id: PairId, enabled: bool) -> Result<ProductPairConfig, ProtocolError> {
        let (base, quote) = pair_id.0.split_once('/').ok_or_else(|| {
            ProtocolError::InvalidProductConfig(format!(
                "pair '{}' must use BASE/QUOTE format",
                pair_id.0
            ))
        })?;
        if base.trim().is_empty() || quote.trim().is_empty() {
            return Err(ProtocolError::InvalidProductConfig(format!(
                "pair '{}' has an empty asset id",
                pair_id.0
            )));
        }
        let base_asset_id = AssetId(base.to_owned());
        let quote_asset_id = AssetId(quote.to_owned());
        let price_base_scale = asset_amount_scale(&base_asset_id);
        let (taker_fee_bps, maker_fee_bps, relay_fee_bps) = default_pair_fee_bps(&pair_id);

        Ok(ProductPairConfig {
            min_order_amount: default_min_order_amount(&pair_id),
            pair_id,
            base_asset_id,
            quote_asset_id,
            price_base_scale,
            heartbeat_cover_price: default_heartbeat_cover_price(),
            taker_fee_bps,
            maker_fee_bps,
            relay_fee_bps,
            enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentContracts {
    pub commitment_registry: String,
    pub batch_registry: String,
    pub shielded_asset_adapter: String,
    #[serde(default)]
    pub privacy_deposit_bridge: String,
    #[serde(default)]
    pub auction_verifier: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentProofConfig {
    #[serde(default)]
    pub settlement_entrypoint: String,
    #[serde(default)]
    pub proof_entrypoint: String,
    #[serde(default)]
    pub proof_program_address: String,
    #[serde(default)]
    pub proof_program_hash: String,
    #[serde(default)]
    pub proof_account_address: String,
    #[serde(default)]
    pub settlement_statement_program_address: String,
    #[serde(default)]
    pub nullifier_statement_program_address: String,
    #[serde(default)]
    pub renewal_statement_program_address: String,
    #[serde(default)]
    pub note_consolidation_statement_program_address: String,
    #[serde(default)]
    pub withdrawal_statement_program_address: String,
    #[serde(default)]
    pub settlement_account_address: String,
    #[serde(default)]
    pub proof_validity_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentManifest {
    pub network: String,
    pub rpc_url: String,
    pub chain_id: String,
    pub contracts: DeploymentContracts,
    pub token_addresses: BTreeMap<String, String>,
    #[serde(default)]
    pub funding: FundingRailConfig,
    #[serde(default)]
    pub product: ProductConfig,
    #[serde(default)]
    pub proof: DeploymentProofConfig,
}

#[cfg(test)]
mod tests {
    use super::{
        AssetId, BatchId, BatchLiquidityReport, BatchStatus, BatchSummary, ClaimWindowPolicy,
        DeploymentManifest, DepositIntent, FeeEntry, FundingRailConfig, FundingRailKind,
        HiddenMakerCurve, MAX_MAKER_CURVE_POINTS, MakerCurvePoint, NOTE_RECOGNITION_ALGORITHM,
        Note, NoteCommitment, Nullifier, OUTPUT_NOTE_CIPHERTEXT_LEN, OrderIngressClientTelemetry,
        OrderIntent, OrderShareBundle, OrderSide, OrderSubmission, OutputCiphertextBundle,
        OutputNoteRecord, PairId, ProductConfig, RelayMode, SettlementTranscript,
        StarknetPrivacyFundingRail, TRANSCRIPT_SHAPE_POLICY_VERSION, TrustedOrderIngressRequest,
        funding_input_set_commitment, funding_nullifier_set_commitment, renewal_parent_commitment,
        renewal_parent_secret_commitment,
    };

    use crate::EncryptedBlob;
    use crate::{
        RecoverySeed, derive_user_keys, nullifier_from_note_secret,
        spend_authority_from_raw_key_hex,
    };

    fn test_note_nullifier(note: &Note) -> Nullifier {
        let commitment = note.commitment().expect("test note commitment");
        nullifier_from_note_secret(&commitment, &note.blinding).expect("test note nullifier")
    }

    fn test_funding_note(asset_id: &str, amount: u128) -> Note {
        Note {
            asset_id: AssetId(asset_id.into()),
            amount,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        }
    }

    fn test_limit_order(
        pair_id: &str,
        side: OrderSide,
        amount: u128,
        min_fill: u128,
        funding_note: &Note,
    ) -> OrderIntent {
        OrderIntent {
            pair_id: PairId(pair_id.into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side,
            order_type: crate::OrderType::LimitBatch,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: None,
            limit_price: 145,
            amount,
            min_fill,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: test_note_nullifier(funding_note),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        }
    }

    #[test]
    fn note_commitments_are_deterministic() {
        let note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 10,
            owner_public_key: "owner".into(),
            spend_authority: "0x111".into(),
            withdraw_authority: "0x111".into(),
            blinding: "0x111".into(),
            nonce: 1,
            metadata_commitment: "0x222".into(),
        };

        let a = note.commitment().expect("note commitment");
        let b = note.commitment().expect("note commitment");
        assert_eq!(a, b);
    }

    #[test]
    fn nullifier_derivation_uses_note_secret() {
        let seed = RecoverySeed([3_u8; 32]);
        let keys = derive_user_keys(&seed);
        let spend_authority =
            spend_authority_from_raw_key_hex(&hex::encode(keys.spend_auth_key)).unwrap();
        let note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 25,
            owner_public_key: "owner".into(),
            spend_authority,
            withdraw_authority: "0x222".into(),
            blinding: "0x333".into(),
            nonce: 2,
            metadata_commitment: "0x444".into(),
        };

        let nullifier = note.nullifier(&keys).expect("nullifier");
        let commitment = note.commitment().expect("commitment");
        let expected = nullifier_from_note_secret(&commitment, &note.blinding).expect("expected");

        assert_eq!(nullifier, expected);
        assert_ne!(nullifier.0, commitment.0);
    }

    #[test]
    fn maker_curve_rejects_too_many_points() {
        let curve = HiddenMakerCurve {
            points: (0..=MAX_MAKER_CURVE_POINTS)
                .map(|index| MakerCurvePoint {
                    price: 100 + index as u128,
                    base_amount: 10,
                })
                .collect(),
        };

        assert!(curve.validate().is_err());
    }

    #[test]
    fn order_commitments_are_deterministic() {
        let funding_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 200_000,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side: OrderSide::Buy,
            order_type: crate::OrderType::LimitBatch,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: None,
            limit_price: 145,
            amount: 1_000,
            min_fill: 100,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: test_note_nullifier(&funding_note),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        };

        let a = order.commitment().expect("order commitment");
        let b = order.commitment().expect("order commitment");
        assert_eq!(a, b);
    }

    #[test]
    fn parent_order_link_is_bound_into_order_commitment() {
        let funding_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 1_000,
            owner_public_key: "owner".into(),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let mut order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side: OrderSide::Buy,
            order_type: crate::OrderType::LimitBatch,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: None,
            limit_price: 145,
            amount: 1_000,
            min_fill: 100,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: test_note_nullifier(&funding_note),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        };

        let direct_commitment = order.commitment().expect("direct order commitment");
        order.parent_order_commitment = "0x1234".into();
        assert!(order.commitment().is_err());
        order.parent_child_index = 3;
        order.parent_authorization_secret = "0x7777".into();
        order.parent_secret_commitment =
            renewal_parent_secret_commitment(&order.parent_authorization_secret)
                .expect("parent secret commitment");
        order.parent_cancel_authority = "0x8888".into();
        order.parent_order_commitment = renewal_parent_commitment(
            &order.parent_secret_commitment,
            &order.parent_cancel_authority,
        )
        .expect("parent commitment");
        let child_commitment = order.commitment().expect("child order commitment");

        assert_ne!(direct_commitment, child_commitment);
    }

    #[test]
    fn deposit_intents_serialize_predictably() {
        let deposit = DepositIntent {
            asset_id: AssetId("USDC".into()),
            amount: 1_000,
            deposit_nonce: 7,
            recipient_owner_public_key: "owner-key".into(),
            recipient_spend_authority: "0x123".into(),
            recipient_withdraw_authority: "0x555".into(),
        };

        let json = serde_json::to_value(deposit).expect("serialize deposit");
        assert_eq!(json["asset_id"], "USDC");
        assert_eq!(json["amount"], "1000");
        assert_eq!(json["deposit_nonce"], "7");
    }

    #[test]
    fn protocol_integer_fields_use_decimal_strings_at_wire_boundary() {
        let deposit = serde_json::json!({
            "asset_id": "USDC",
            "amount": "000100",
            "deposit_nonce": "18446744073709551615",
            "recipient_owner_public_key": "owner-key",
            "recipient_spend_authority": "0x123",
            "recipient_withdraw_authority": "0x555"
        });
        let parsed: DepositIntent = serde_json::from_value(deposit).expect("decimal string amount");
        assert_eq!(parsed.amount, 100);
        assert_eq!(parsed.deposit_nonce, u64::MAX);

        let note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 100,
            owner_public_key: "owner-key".into(),
            spend_authority: "0x123".into(),
            withdraw_authority: "0x555".into(),
            blinding: "0xabc".into(),
            nonce: u64::MAX,
            metadata_commitment: "0xdef".into(),
        };
        let note_json = serde_json::to_value(&note).expect("serialize note");
        assert_eq!(note_json["nonce"], "18446744073709551615");
        let reparsed_note: Note = serde_json::from_value(note_json).expect("parse note");
        assert_eq!(reparsed_note.nonce, u64::MAX);

        let order = serde_json::json!({
            "pair_id": "STRK/ETH",
            "batch_id": "STRK-ETH-7",
            "side": "Buy",
            "order_type": "MakerCurve",
            "relay_mode": "ZylithRelay",
            "limit_price": "120000000000000",
            "amount": "3000000000000000000",
            "min_fill": "0",
            "time_in_force": "CurrentBatchOnly",
            "expiry_epoch": "42",
            "order_nonce": "18446744073709551615",
            "parent_order_commitment": "0x123",
            "parent_child_index": "7",
            "parent_secret_commitment": "0x456",
            "parent_cancel_authority": "0x789",
            "parent_authorization_secret": "0xabc",
            "funding_note_ref": "0xdef",
            "funding_nullifier": "0x0",
            "recipient_owner_public_key": "",
            "recipient_spend_authority": "0x0",
            "recipient_withdraw_authority": "0x0",
            "recipient_residual_withdraw_authority": "0x0",
            "auditor_view_allowed": false
        });
        let parsed_order: OrderIntent =
            serde_json::from_value(order).expect("decimal string u64 order fields");
        assert_eq!(parsed_order.expiry_epoch, 42);
        assert_eq!(parsed_order.order_nonce, u64::MAX);
        assert_eq!(parsed_order.parent_child_index, 7);
        let order_json = serde_json::to_value(&parsed_order).expect("serialize order");
        assert_eq!(order_json["expiry_epoch"], "42");
        assert_eq!(order_json["order_nonce"], "18446744073709551615");
        assert_eq!(order_json["parent_child_index"], "7");

        let numeric_amount = serde_json::json!({
            "asset_id": "USDC",
            "amount": 100,
            "deposit_nonce": 7,
            "recipient_owner_public_key": "owner-key",
            "recipient_spend_authority": "0x123",
            "recipient_withdraw_authority": "0x555"
        });
        assert!(
            serde_json::from_value::<DepositIntent>(numeric_amount).is_err(),
            "numeric protocol amounts must be rejected"
        );

        let liquidity = BatchLiquidityReport {
            status: "ok".into(),
            reason: None,
            diagnostic_price: Some(145),
            buy_base_demand: 1_000,
            sell_base_supply: 900,
            matched_base_volume: 900,
            crossing_order_count: 2,
            min_base_liquidity: 1,
        };
        let json = serde_json::to_value(liquidity).expect("serialize liquidity");
        assert_eq!(json["diagnostic_price"], "145");
        assert_eq!(json["buy_base_demand"], "1000");
        assert_eq!(json["matched_base_volume"], "900");

        let invalid = serde_json::json!({
            "asset_id": "USDC",
            "amount": " 100",
            "deposit_nonce": 7,
            "recipient_owner_public_key": "owner-key",
            "recipient_spend_authority": "0x123",
            "recipient_withdraw_authority": "0x555"
        });
        assert!(serde_json::from_value::<DepositIntent>(invalid).is_err());
    }

    #[test]
    fn deployment_manifest_defaults_to_starknet_privacy_funding() {
        let manifest = serde_json::json!({
            "network": "local",
            "rpc_url": "http://127.0.0.1:5050",
            "chain_id": "0x1",
            "contracts": {
                "commitment_registry": "0x1",
                "batch_registry": "0x2",
                "shielded_asset_adapter": "0x4",
                "privacy_deposit_bridge": "0x55",
                "auction_verifier": "0x6"
            },
            "token_addresses": {
                "STRK": "0x8"
            }
        });

        let manifest: DeploymentManifest =
            serde_json::from_value(manifest).expect("deserialize manifest");
        assert_eq!(manifest.funding.primary, FundingRailKind::StarknetPrivacy);
        assert!(manifest.funding.active_rail().is_err());
        assert!(!manifest.funding.capabilities.private_deposits);
        assert!(!manifest.funding.capabilities.discovery_sync);
        assert!(manifest.proof.settlement_entrypoint.is_empty());
        assert_eq!(manifest.proof.proof_validity_blocks, 0);
    }

    #[test]
    fn starknet_privacy_funding_only_activates_when_configured() {
        let mut funding = FundingRailConfig {
            primary: FundingRailKind::StarknetPrivacy,
            starknet_privacy: Some(StarknetPrivacyFundingRail {
                privacy_pool: String::new(),
                bridge_adapter: None,
                shielded_asset_adapter: None,
                discovery_url: "https://discovery.example".into(),
                proving_url: "https://prover.example".into(),
                paymaster_address: None,
                paymaster_url: None,
                sdk_package: "@starkware-libs/starknet-privacy-sdk".into(),
                sdk_version: "0.14.2".into(),
                min_proving_delay_blocks: 20,
            }),
            ..FundingRailConfig::default()
        };

        assert!(funding.active_rail().is_err());

        funding
            .starknet_privacy
            .as_mut()
            .expect("privacy config")
            .privacy_pool = "0x123".into();
        assert!(funding.active_rail().is_err());

        funding
            .starknet_privacy
            .as_mut()
            .expect("privacy config")
            .bridge_adapter = Some("0xb00".into());
        assert!(funding.active_rail().is_err());

        let privacy_config = funding.starknet_privacy.as_mut().expect("privacy config");
        privacy_config.shielded_asset_adapter = Some("0xa00".into());
        privacy_config.paymaster_address = Some("0xabc".into());
        privacy_config.paymaster_url = Some("https://paymaster.example/execute-outside".into());
        assert_eq!(
            funding.active_rail().expect("privacy rail"),
            FundingRailKind::StarknetPrivacy
        );
    }

    #[test]
    fn product_config_parses_enabled_pairs_and_assets() {
        let product =
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC, STRK/ETH").expect("product");

        assert!(product.enabled_pair(&PairId("STRK/USDC".into())).is_some());
        assert!(product.enabled_pair(&PairId("STRK/ETH".into())).is_some());
        assert!(product.assets.contains_key("STRK"));
        assert!(product.assets.contains_key("USDC"));
        assert!(product.assets.contains_key("ETH"));
    }

    #[test]
    fn product_config_rejects_unsupported_pair_before_client_assumptions() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let funding_note = test_funding_note("USDC", 1_000_000_000_000_000_000);
        let order = test_limit_order(
            "STRK/ETH",
            OrderSide::Buy,
            1_000_000_000_000_000_000,
            1_000_000_000_000_000_000,
            &funding_note,
        );

        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("unsupported pair must fail");
        assert!(error.to_string().contains("unsupported pair"));
    }

    #[test]
    fn product_config_rejects_zero_and_under_minimum_order_amounts() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let funding_note = test_funding_note("USDC", 2_000_000_000_000_000_000);
        let mut order = test_limit_order(
            "STRK/USDC",
            OrderSide::Buy,
            1_000_000_000_000_000_000,
            1_000_000_000_000_000_000,
            &funding_note,
        );

        order.amount = 0;
        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("zero amount must fail");
        assert!(error.to_string().contains("amount must be positive"));

        order.amount = 1;
        order.min_fill = 1;
        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("under-minimum amount must fail");
        assert!(error.to_string().contains("below pair minimum"));
    }

    #[test]
    fn product_config_rejects_zylith_relay_on_direct_orders() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let funding_note = test_funding_note("USDC", 2_000_000_000_000_000_000);
        let mut order = test_limit_order(
            "STRK/USDC",
            OrderSide::Buy,
            1_000_000_000_000_000_000,
            1_000_000_000_000_000_000,
            &funding_note,
        );
        order.relay_mode = RelayMode::ZylithRelay;

        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("direct zylith relay mode must fail");
        assert!(error.to_string().contains("maker curve order"));
    }

    #[test]
    fn product_config_rejects_wrong_funding_asset() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let funding_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 1_000,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side: OrderSide::Buy,
            order_type: crate::OrderType::LimitBatch,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: None,
            limit_price: 145,
            amount: 1_000_000_000_000_000_000,
            min_fill: 1_000_000_000_000_000_000,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: test_note_nullifier(&funding_note),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        };

        assert!(
            product
                .validate_order_funding(&order, &funding_note)
                .is_err()
        );
    }

    #[test]
    fn product_config_rejects_duplicate_funding_inputs() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let funding_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 1_000_000_000_000_000_000,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let duplicated_notes = vec![funding_note.clone(), funding_note.clone()];
        let commitments = duplicated_notes
            .iter()
            .map(|note| note.commitment().expect("funding note commitment"))
            .collect::<Vec<_>>();
        let nullifiers = duplicated_notes
            .iter()
            .map(test_note_nullifier)
            .collect::<Vec<_>>();
        let order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side: OrderSide::Sell,
            order_type: crate::OrderType::LimitBatch,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: None,
            limit_price: 145,
            amount: 1_000_000_000_000_000_000,
            min_fill: 1_000_000_000_000_000_000,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_input_set_commitment(&commitments).expect("funding ref"),
            funding_nullifier: funding_nullifier_set_commitment(&nullifiers)
                .expect("funding nullifier"),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        };

        let error = product
            .validate_order_funding_notes(&order, &duplicated_notes)
            .expect_err("duplicate funding inputs must fail");
        assert!(error.to_string().contains("unique"));
    }

    #[test]
    fn product_config_enforces_fill_or_kill_full_size() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let funding_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 1_000,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let base_order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side: OrderSide::Buy,
            order_type: crate::OrderType::LimitBatch,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: None,
            limit_price: 145,
            amount: 2_000_000_000_000_000_000,
            min_fill: 1_000_000_000_000_000_000,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: test_note_nullifier(&funding_note),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        };

        let mut fok_order = base_order;
        fok_order.time_in_force = crate::TimeInForce::FillOrKill;
        assert!(
            product
                .validate_order_funding(&fok_order, &funding_note)
                .is_err()
        );
        fok_order.min_fill = fok_order.amount;
        assert!(
            product
                .validate_order_funding(&fok_order, &funding_note)
                .is_ok()
        );
    }

    #[test]
    fn product_config_enforces_maker_curve_envelope_price() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let funding_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 3_000_000_000_000_000_000,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let mut order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side: OrderSide::Sell,
            order_type: crate::OrderType::MakerCurve,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: Some(HiddenMakerCurve {
                points: vec![
                    MakerCurvePoint {
                        price: 1_000_000_000_000_000_000,
                        base_amount: 1_000_000_000_000_000_000,
                    },
                    MakerCurvePoint {
                        price: 1_001_000_000_000_000_000,
                        base_amount: 1_000_000_000_000_000_000,
                    },
                    MakerCurvePoint {
                        price: 1_002_000_000_000_000_000,
                        base_amount: 1_000_000_000_000_000_000,
                    },
                ],
            }),
            limit_price: 1_001_000_000_000_000_000,
            amount: 3_000_000_000_000_000_000,
            min_fill: 1_000_000_000_000_000_000,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: test_note_nullifier(&funding_note),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        };

        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("mismatched maker curve envelope must fail");
        assert!(error.to_string().contains("curve envelope price"));

        order.limit_price = 1_000_000_000_000_000_000;
        assert!(
            product
                .validate_order_funding(&order, &funding_note)
                .is_ok()
        );

        order.amount -= 1;
        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("maker curve amount mismatch must fail");
        assert!(error.to_string().contains("sum of curve base amounts"));
    }

    #[test]
    fn product_config_enforces_maker_curve_band_count_depth_and_spread() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let funding_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 3_000_000_000_000_000_000,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let mut order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side: OrderSide::Sell,
            order_type: crate::OrderType::MakerCurve,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: Some(HiddenMakerCurve {
                points: vec![
                    MakerCurvePoint {
                        price: 1_000_000_000_000_000_000,
                        base_amount: 1_000_000_000_000_000_000,
                    },
                    MakerCurvePoint {
                        price: 1_001_000_000_000_000_000,
                        base_amount: 1_000_000_000_000_000_000,
                    },
                ],
            }),
            limit_price: 1_000_000_000_000_000_000,
            amount: 2_000_000_000_000_000_000,
            min_fill: 1_000_000_000_000_000_000,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: test_note_nullifier(&funding_note),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        };

        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("two-band maker curve must fail");
        assert!(error.to_string().contains("at least 3"));

        order.maker_curve = Some(HiddenMakerCurve {
            points: vec![
                MakerCurvePoint {
                    price: 1_000_000_000_000_000_000,
                    base_amount: 1_000_000_000_000_000_000,
                },
                MakerCurvePoint {
                    price: 1_001_000_000_000_000_000,
                    base_amount: 999_999_999_999_999_999,
                },
                MakerCurvePoint {
                    price: 1_002_000_000_000_000_000,
                    base_amount: 1_000_000_000_000_000_000,
                },
            ],
        });
        order.amount = 2_999_999_999_999_999_999;
        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("sub-minimum maker band must fail");
        assert!(error.to_string().contains("below pair minimum"));

        order.maker_curve = Some(HiddenMakerCurve {
            points: vec![
                MakerCurvePoint {
                    price: 1_000_000_000_000_000_000,
                    base_amount: 1_000_000_000_000_000_000,
                },
                MakerCurvePoint {
                    price: 1_001_000_000_000_000_000,
                    base_amount: 1_000_000_000_000_000_000,
                },
                MakerCurvePoint {
                    price: 1_001_999_999_999_999_999,
                    base_amount: 1_000_000_000_000_000_000,
                },
            ],
        });
        order.amount = 3_000_000_000_000_000_000;
        let error = product
            .validate_order_funding(&order, &funding_note)
            .expect_err("under-spread maker curve must fail");
        assert!(error.to_string().contains("at least 20 bps"));
    }

    #[test]
    fn maker_fee_applies_to_maker_curve_without_renewal_fee_gate() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let pair = product
            .enabled_pair(&PairId("STRK/USDC".into()))
            .expect("pair");
        let funding_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 3_000_000_000_000_000_000,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x333".into(),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let mut order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-42".into()),
            side: OrderSide::Sell,
            order_type: crate::OrderType::MakerCurve,
            relay_mode: RelayMode::SelfRelay,
            maker_curve: Some(HiddenMakerCurve {
                points: vec![
                    MakerCurvePoint {
                        price: 1_000_000_000_000_000_000,
                        base_amount: 1_000_000_000_000_000_000,
                    },
                    MakerCurvePoint {
                        price: 1_001_000_000_000_000_000,
                        base_amount: 1_000_000_000_000_000_000,
                    },
                    MakerCurvePoint {
                        price: 1_002_000_000_000_000_000,
                        base_amount: 1_000_000_000_000_000_000,
                    },
                ],
            }),
            limit_price: 1_000_000_000_000_000_000,
            amount: 3_000_000_000_000_000_000,
            min_fill: 1_000_000_000_000_000_000,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: test_note_nullifier(&funding_note),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_spend_authority: "0x333".into(),
            recipient_withdraw_authority: "0x444".into(),
            recipient_residual_withdraw_authority: "0x445".into(),
            auditor_view_allowed: false,
        };

        let self_relay_parent_commitment = order.commitment().expect("self relay commitment");
        assert_eq!(pair.fee_bps_for_order(&order).expect("fee bps"), 0);
        assert_eq!(
            pair.relay_fee_bps_for_order(&order)
                .expect("self relay fee bps"),
            0
        );
        order.relay_mode = RelayMode::ZylithRelay;
        assert!(
            pair.relay_fee_bps_for_order(&order)
                .expect_err("zylith relay requires renewal child")
                .to_string()
                .contains("renewal child parent fields")
        );
        order.relay_mode = RelayMode::SelfRelay;

        order.parent_authorization_secret = "0x7777".into();
        order.parent_secret_commitment =
            renewal_parent_secret_commitment(&order.parent_authorization_secret)
                .expect("parent secret commitment");
        order.parent_cancel_authority = "0x8888".into();
        order.parent_order_commitment = renewal_parent_commitment(
            &order.parent_secret_commitment,
            &order.parent_cancel_authority,
        )
        .expect("parent commitment");
        order.parent_child_index = 1;

        assert_eq!(pair.fee_bps_for_order(&order).expect("fee bps"), 0);
        assert_eq!(
            pair.relay_fee_bps_for_order(&order)
                .expect("self relay child fee bps"),
            0
        );
        order.relay_mode = RelayMode::ZylithRelay;
        assert_ne!(
            self_relay_parent_commitment,
            order.commitment().expect("zylith relay commitment")
        );
        assert_eq!(
            pair.relay_fee_bps_for_order(&order)
                .expect("zylith relay fee bps"),
            pair.relay_fee_bps
        );
    }

    #[test]
    fn newtypes_serialize_as_plain_strings() {
        let summary = BatchSummary {
            batch_id: BatchId("batch-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            epoch_id: 1,
            close_time_unix_ms: 1234,
            status: BatchStatus::Open,
            order_count: 0,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
        };

        let json = serde_json::to_value(summary).expect("serialize batch summary");
        assert_eq!(json["batch_id"], "batch-1");
        assert_eq!(json["pair_id"], "STRK/USDC");
    }

    #[test]
    fn order_submission_shape_is_client_friendly() {
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: crate::OrderCommitment("commitment-1".into()),
                cancellation_auth_tag: "cancel-tag-1".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: BatchId("batch-strk-usdc-0".into()),
                epoch_id: 0,
                transport_envelope: Some(EncryptedBlob {
                    algorithm: "ecdh-p256+hkdf-sha256+aes-256-gcm/private-order-v1".into(),
                    key_id: "execution-key-0".into(),
                    ephemeral_public_key: "04abcdef".into(),
                    nonce: "00".into(),
                    ciphertext: "11".into(),
                    recovery: None,
                }),
                ingress_receipt: None,
                shares: vec![],
            },
        };

        let json = serde_json::to_value(submission).expect("serialize order submission");
        assert_eq!(json["order_bundle"]["order_commitment"], "commitment-1");
        assert_eq!(
            json["order_bundle"]["cancellation_auth_tag"],
            "cancel-tag-1"
        );
        assert_eq!(json["order_bundle"]["pair_id"], "STRK/USDC");
    }

    #[test]
    fn output_ciphertext_bundle_pads_to_bucket_size() {
        let ciphertext = EncryptedBlob {
            algorithm: NOTE_RECOGNITION_ALGORITHM.into(),
            key_id: "01".repeat(32),
            ephemeral_public_key: "04".to_string() + &"11".repeat(64),
            nonce: "02".repeat(12),
            ciphertext: "11".repeat(OUTPUT_NOTE_CIPHERTEXT_LEN),
            recovery: None,
        };

        let bundle = crate::OutputCiphertextBundle::from_ciphertexts(
            BatchId("batch-1".into()),
            "da://bundle",
            vec![ciphertext],
        )
        .expect("bundle");

        assert_eq!(bundle.padded_ciphertext_count, 4);
        assert_eq!(bundle.ciphertext_count_bucket, "0-4");
        assert_eq!(bundle.ciphertexts.len(), 4);
        for blob in bundle.ciphertexts.iter() {
            assert_eq!(blob.algorithm, NOTE_RECOGNITION_ALGORITHM);
            assert_eq!(hex::decode(&blob.key_id).expect("key id").len(), 32);
            assert_eq!(hex::decode(&blob.nonce).expect("nonce").len(), 12);
            assert_eq!(
                hex::decode(&blob.ciphertext).expect("ciphertext").len(),
                OUTPUT_NOTE_CIPHERTEXT_LEN
            );
            assert!(!blob.ephemeral_public_key.is_empty());
        }
    }

    #[test]
    fn empty_output_ciphertext_bundle_is_padded_to_first_bucket() {
        let bundle = crate::OutputCiphertextBundle::from_ciphertexts(
            BatchId("batch-empty".into()),
            "da://empty-bundle",
            vec![],
        )
        .expect("bundle");

        assert_eq!(bundle.padded_ciphertext_count, 4);
        assert_eq!(bundle.ciphertext_count_bucket, "0-4");
        assert_eq!(bundle.ciphertexts.len(), 4);
        assert!(bundle.ciphertexts.iter().all(|blob| {
            blob.algorithm == NOTE_RECOGNITION_ALGORITHM
                && blob.ephemeral_public_key.starts_with("04")
                && hex::decode(&blob.ciphertext)
                    .map(|ciphertext| ciphertext.len() == OUTPUT_NOTE_CIPHERTEXT_LEN)
                    .unwrap_or(false)
        }));
    }

    #[test]
    fn transcript_shape_metadata_uses_public_buckets() {
        let bundle = crate::OutputCiphertextBundle::from_ciphertexts(
            BatchId("batch-1".into()),
            "da://bundle",
            vec![EncryptedBlob {
                algorithm: NOTE_RECOGNITION_ALGORITHM.into(),
                key_id: "01".repeat(32),
                ephemeral_public_key: "04".to_string() + &"11".repeat(64),
                nonce: "02".repeat(12),
                ciphertext: "11".repeat(OUTPUT_NOTE_CIPHERTEXT_LEN),
                recovery: None,
            }],
        )
        .expect("bundle");
        let transcript = SettlementTranscript {
            batch_id: BatchId("batch-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 7,
            order_commitment_root: "0x1".into(),
            encrypted_order_set_commitment: "0x2".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 100,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: "0x123".into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![FeeEntry {
                asset_id: AssetId("USDC".into()),
                amount: 1,
                recipient: "0x123".into(),
            }],
            output_notes: vec![OutputNoteRecord {
                note_commitment: NoteCommitment("0x456".into()),
                asset_id: AssetId("USDC".into()),
                amount: 10,
                withdraw_authority: "0x789".into(),
            }],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: bundle.bundle_commitment.clone(),
        };

        let shape = crate::transcript_shape_metadata(&transcript, &bundle);

        assert_eq!(shape.policy_version, TRANSCRIPT_SHAPE_POLICY_VERSION);
        assert_eq!(shape.matched_order_count_bucket, "0-7");
        assert_eq!(shape.fee_count_bucket, "0-7");
        assert_eq!(shape.output_note_count_bucket, "0-4");
        assert_eq!(shape.output_ciphertext_count_bucket, "0-4");
        assert_eq!(shape.padded_output_ciphertext_count, 4);
        crate::validate_transcript_shape_policy(&transcript, &bundle).expect("shape policy");
    }

    #[test]
    fn transcript_shape_policy_recomputes_output_bundle_commitment() {
        let bundle = crate::OutputCiphertextBundle::from_ciphertexts(
            BatchId("batch-commitment".into()),
            "da://bundle",
            vec![EncryptedBlob {
                algorithm: NOTE_RECOGNITION_ALGORITHM.into(),
                key_id: "01".repeat(32),
                ephemeral_public_key: "04".to_string() + &"11".repeat(64),
                nonce: "02".repeat(12),
                ciphertext: "11".repeat(OUTPUT_NOTE_CIPHERTEXT_LEN),
                recovery: None,
            }],
        )
        .expect("bundle");
        let transcript = SettlementTranscript {
            batch_id: BatchId("batch-commitment".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 7,
            order_commitment_root: "0x1".into(),
            encrypted_order_set_commitment: "0x2".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 100,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: "0x123".into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![OutputNoteRecord {
                note_commitment: NoteCommitment("0x456".into()),
                asset_id: AssetId("USDC".into()),
                amount: 10,
                withdraw_authority: "0x789".into(),
            }],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: bundle.bundle_commitment.clone(),
        };
        let mut substituted_bundle = bundle;
        substituted_bundle.ciphertexts[0].ciphertext = "22".repeat(OUTPUT_NOTE_CIPHERTEXT_LEN);

        let error = crate::validate_transcript_shape_policy(&transcript, &substituted_bundle)
            .expect_err("substituted ciphertexts must fail");

        assert!(
            error
                .to_string()
                .contains("output bundle commitment does not match ciphertext contents")
        );
    }

    #[test]
    fn transcript_shape_policy_recomputes_recovery_backed_output_bundle_commitment() {
        let batch_id = BatchId("batch-recovery-commitment".into());
        let bundle = crate::OutputCiphertextBundle::from_ciphertexts(
            batch_id.clone(),
            "da://bundle",
            vec![super::dummy_output_ciphertext(&batch_id, 0).expect("dummy ciphertext")],
        )
        .expect("bundle");
        assert!(bundle.ciphertexts[0].recovery.is_some());
        let transcript = SettlementTranscript {
            batch_id,
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 7,
            order_commitment_root: "0x1".into(),
            encrypted_order_set_commitment: "0x2".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 100,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: "0x123".into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![OutputNoteRecord {
                note_commitment: NoteCommitment("0x456".into()),
                asset_id: AssetId("USDC".into()),
                amount: 10,
                withdraw_authority: "0x789".into(),
            }],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: bundle.bundle_commitment.clone(),
        };
        type BlobMutation = (&'static str, Box<dyn Fn(&mut EncryptedBlob)>);
        let substitutions: Vec<BlobMutation> = vec![
            (
                "algorithm",
                Box::new(|blob| blob.algorithm = "zylith.note_recognition.v2".into()),
            ),
            ("key_id", Box::new(|blob| blob.key_id = "aa".repeat(32))),
            (
                "ephemeral_public_key",
                Box::new(|blob| blob.ephemeral_public_key = "04".to_string() + &"22".repeat(64)),
            ),
            ("nonce", Box::new(|blob| blob.nonce = "bb".repeat(12))),
            (
                "ciphertext",
                Box::new(|blob| blob.ciphertext = "cc".repeat(OUTPUT_NOTE_CIPHERTEXT_LEN)),
            ),
        ];

        for (field, mutate) in substitutions {
            let mut substituted_bundle = bundle.clone();
            mutate(&mut substituted_bundle.ciphertexts[0]);
            let error =
                match crate::validate_transcript_shape_policy(&transcript, &substituted_bundle) {
                    Ok(_) => panic!("substituted recovery-backed ciphertext {field} must fail"),
                    Err(error) => error,
                };
            assert!(
                error.to_string().contains(
                    "output bundle envelope commitment does not match ciphertext contents"
                ) || error.to_string().contains("uses unsupported algorithm"),
                "unexpected {field} error: {error}"
            );
        }
    }

    #[test]
    fn transcript_shape_policy_rejects_missing_recovery_backed_envelope_commitment() {
        let batch_id = BatchId("batch-recovery-missing-envelope".into());
        let mut bundle = crate::OutputCiphertextBundle::from_ciphertexts(
            batch_id.clone(),
            "da://bundle",
            vec![super::dummy_output_ciphertext(&batch_id, 0).expect("dummy ciphertext")],
        )
        .expect("bundle");
        let transcript = SettlementTranscript {
            batch_id,
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 7,
            order_commitment_root: "0x1".into(),
            encrypted_order_set_commitment: "0x2".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 100,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: "0x123".into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![OutputNoteRecord {
                note_commitment: NoteCommitment("0x456".into()),
                asset_id: AssetId("USDC".into()),
                amount: 10,
                withdraw_authority: "0x789".into(),
            }],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: bundle.bundle_commitment.clone(),
        };
        bundle.ciphertext_envelope_commitment = None;

        let error = crate::validate_transcript_shape_policy(&transcript, &bundle)
            .expect_err("missing envelope commitment must fail");

        assert!(
            error
                .to_string()
                .contains("output bundle envelope commitment is missing")
        );
    }

    #[test]
    fn transcript_shape_policy_rejects_unpadded_output_bundles() {
        let output_note = OutputNoteRecord {
            note_commitment: NoteCommitment("0x123".into()),
            asset_id: AssetId("USDC".into()),
            amount: 10,
            withdraw_authority: "0x456".into(),
        };
        let bundle = OutputCiphertextBundle {
            batch_id: BatchId("batch-1".into()),
            bundle_commitment: "bundle-ref".into(),
            ciphertext_envelope_commitment: Some("envelope-ref".into()),
            data_availability_ref: "da://bundle".into(),
            ciphertext_count_bucket: "0-4".into(),
            padded_ciphertext_count: 4,
            ciphertexts: vec![],
        };
        let transcript = SettlementTranscript {
            batch_id: BatchId("batch-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 7,
            order_commitment_root: "0x1".into(),
            encrypted_order_set_commitment: "0x2".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 100,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: "zylith-protocol-treasury".into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            fees: vec![],
            output_notes: vec![output_note],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "bundle-ref".into(),
        };

        let error = crate::validate_transcript_shape_policy(&transcript, &bundle)
            .expect_err("unpadded bundle must fail");

        assert!(
            error
                .to_string()
                .contains("output bundle ciphertext length must be padded")
        );
    }

    #[test]
    fn withdrawal_window_plan_is_delayed_and_deterministic() {
        let policy = ClaimWindowPolicy {
            min_delay_seconds: 30,
            window_seconds: 120,
            max_jitter_seconds: 10,
            ..ClaimWindowPolicy::default()
        };
        let note_commitment = NoteCommitment("0xabc".into());

        let first = crate::plan_withdrawal_window(&note_commitment, 1_000_000, &policy)
            .expect("first plan");
        let second = crate::plan_withdrawal_window(&note_commitment, 1_000_000, &policy)
            .expect("second plan");

        assert_eq!(first, second);
        assert_eq!(first.earliest_withdrawal_unix_ms, 1_030_000);
        assert!(first.recommended_withdrawal_unix_ms >= first.earliest_withdrawal_unix_ms);
        assert!(first.recommended_withdrawal_unix_ms <= 1_040_000);
    }

    #[test]
    fn withdrawal_amount_bucket_plan_flags_non_standard_exits() {
        let policy = crate::WithdrawalAmountBucketPolicy::default();
        let exact =
            crate::plan_withdrawal_amount_bucket(&AssetId("USDC".into()), 1_000_000, &policy)
                .expect("exact bucket");
        assert!(exact.exact_bucket);
        assert_eq!(exact.nearest_bucket_amount, 1_000_000);

        let off_bucket =
            crate::plan_withdrawal_amount_bucket(&AssetId("USDC".into()), 1_500_000, &policy)
                .expect("off bucket");
        assert!(!off_bucket.exact_bucket);
        assert_eq!(off_bucket.nearest_bucket_amount, 1_000_000);
    }

    #[test]
    fn trusted_order_ingress_telemetry_is_optional_and_out_of_band() {
        let json = serde_json::json!({
            "order_submission": {
                "order_bundle": {
                    "order_commitment": "0xabc",
                    "cancellation_auth_tag": "cancel",
                    "pair_id": "STRK/USDC",
                    "batch_id": "batch-strk-usdc-1",
                    "epoch_id": 1,
                    "transport_envelope": null,
                    "shares": []
                }
            }
        });
        let request: TrustedOrderIngressRequest =
            serde_json::from_value(json).expect("legacy ingress request");
        assert!(request.ingress_telemetry.is_none());

        let request = TrustedOrderIngressRequest {
            ingress_telemetry: Some(OrderIngressClientTelemetry {
                version: 1,
                client_build_ms: Some(25),
                private_submission_delay_ms: Some(7_000),
                client_elapsed_before_private_ingress_ms: Some(7_025),
                private_ingress_roundtrip_ms: Some(120),
                client_elapsed_before_coordinator_ms: Some(7_145),
                batch_time_remaining_before_private_ingress_ms: Some(25_000),
                batch_time_remaining_before_coordinator_ms: Some(24_850),
                submission_safety_buffer_ms: Some(15_000),
            }),
            ..request
        };
        let serialized = serde_json::to_value(&request).expect("telemetry request");
        assert_eq!(serialized["ingress_telemetry"]["version"], 1);
        assert_eq!(
            serialized["order_submission"]["order_bundle"]["order_commitment"],
            "0xabc"
        );
    }
}

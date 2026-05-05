use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use starknet_crypto::get_public_key;

use crate::{
    ProtocolError,
    hash::{
        domain_felt, encode_starknet_felt, felt_from_hex_str, field_from_bool, field_from_u64,
        field_from_u128, poseidon_chain_hex, tagged_commitment_sha256,
    },
    keys::UserKeys,
};

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
            formatter.write_str("a u128 decimal string or unsigned JSON integer")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value.into())
        }

        fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
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
            formatter.write_str("null or a u128 decimal string/unsigned JSON integer")
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
        if self.points.is_empty() {
            return Err(ProtocolError::InvalidOrder(
                "maker curve must contain at least one point".into(),
            ));
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
        let note_commitment = felt_from_hex_str(&self.commitment()?.0)?;
        let spend_auth_key = felt_from_hex_str(&spend_auth_key_felt_from_raw_key_hex(
            &hex::encode(keys.spend_auth_key),
        ))?;

        Ok(Nullifier(poseidon_chain_hex(
            domain_felt("zylith/nullifier"),
            &[note_commitment, spend_auth_key],
        )))
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

pub fn nullifier_from_spend_auth_key_felt(
    note_commitment: &NoteCommitment,
    spend_auth_key_felt: &str,
) -> Result<Nullifier, ProtocolError> {
    let note_commitment = felt_from_hex_str(&note_commitment.0)?;
    let spend_auth_key = felt_from_hex_str(spend_auth_key_felt)?;
    Ok(Nullifier(poseidon_chain_hex(
        domain_felt("zylith/nullifier"),
        &[note_commitment, spend_auth_key],
    )))
}

pub fn renewal_parent_secret_commitment(
    parent_authorization_secret: &str,
) -> Result<String, ProtocolError> {
    let parent_authorization_secret = felt_from_hex_str(parent_authorization_secret)?;
    Ok(poseidon_chain_hex(
        domain_felt("zylith/renewal-parent-secret"),
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
        domain_felt("zylith/renewal-parent"),
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
        domain_felt("zylith/renewal-child-nullifier"),
        &[
            parent_order_commitment,
            field_from_u64(parent_child_index),
            parent_authorization_secret,
        ],
    ))
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOrderPayload {
    pub order: OrderIntent,
    pub funding_note: Note,
    pub funding_authorization: SpendAuthorization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendAuthorization {
    pub signature_r: String,
    pub signature_s: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub algorithm: String,
    pub key_id: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
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
    pub payload_commitment: String,
    pub issued_at_unix_ms: u64,
    pub signer: String,
    pub signature: String,
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
pub struct TrustedOrderIngressRequest {
    pub order_submission: OrderSubmission,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedOrderIngressResponse {
    pub receipt: OrderIngressReceipt,
    pub coordinator_submission: OrderSubmission,
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
    pub funding_note_commitment: NoteCommitment,
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
    pub funding_note_ref: NoteCommitment,
    pub funding_nullifier: Nullifier,
    pub funding_authorization: SpendAuthorization,
    pub side: OrderSide,
    pub order_type: OrderType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maker_curve: Option<HiddenMakerCurve>,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionOrderWitness {
    pub order_commitment: OrderCommitment,
    pub order: OrderIntent,
    pub funding_note: Note,
    pub funding_authorization: SpendAuthorization,
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
pub struct OutputCiphertextBundle {
    pub batch_id: BatchId,
    pub bundle_commitment: String,
    pub data_availability_ref: String,
    pub ciphertexts: Vec<EncryptedBlob>,
}

impl OutputCiphertextBundle {
    pub fn from_ciphertexts(
        batch_id: BatchId,
        data_availability_ref: impl Into<String>,
        ciphertexts: Vec<EncryptedBlob>,
    ) -> Result<Self, ProtocolError> {
        let bundle_commitment = tagged_commitment_sha256("zylith/output-bundle", &ciphertexts)?;
        Ok(Self {
            batch_id,
            bundle_commitment,
            data_availability_ref: data_availability_ref.into(),
            ciphertexts,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementTranscript {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub batch_epoch: u64,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
    #[serde(with = "serde_u128_decimal")]
    pub clearing_price: u128,
    pub matched_orders: Vec<MatchedOrder>,
    pub consumed_inputs: Vec<ConsumedInput>,
    #[serde(default)]
    pub renewal_child_uses: Vec<RenewalChildUse>,
    pub fees: Vec<FeeEntry>,
    pub output_notes: Vec<OutputNoteRecord>,
    pub output_ciphertext_bundle_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifacts {
    pub transcript: SettlementTranscript,
    pub output_bundle: OutputCiphertextBundle,
    pub settlement_witness: SettlementWitness,
    #[serde(default)]
    pub order_execution_reports: Vec<OrderExecutionReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifactSummary {
    pub batch_id: BatchId,
    pub transcript_commitment: String,
    pub output_bundle_ref: String,
    pub bundle_commitment: String,
    pub data_availability_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifactList {
    pub batches: Vec<PublishedBatchArtifactSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorStatus {
    pub service: String,
    pub current_batch_id: Option<BatchId>,
    pub tracked_batches: u64,
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
    pub submission_mode: String,
    pub settlement_contract_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarknetCall {
    pub contract_address: String,
    pub entrypoint: String,
    pub calldata: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalCallArguments {
    pub spender: String,
    pub amount: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCallArguments {
    pub asset_id: String,
    pub amount: String,
    pub deposit_nonce: String,
    pub note_commitment: String,
    pub withdraw_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositSubmissionPlan {
    pub funding_rail: FundingRailKind,
    pub note: Note,
    pub note_commitment: NoteCommitment,
    pub approval_call: StarknetCall,
    pub starknet_call: StarknetCall,
    pub starknet_calls: Vec<StarknetCall>,
    pub approval_args: ApprovalCallArguments,
    pub encoded_args: DepositCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositRecord {
    pub deposit_id: u64,
    pub asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub amount: u128,
    pub deposit_nonce: u64,
    pub note_commitment: NoteCommitment,
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
    pub rpc_url: String,
    pub shielded_asset_adapter_address: String,
    pub cached_deposits: u64,
    pub synced_deposit_count: u64,
    pub cached_withdrawals: u64,
    pub synced_withdrawal_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositConfirmationRequest {
    pub note_commitments: Vec<NoteCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositConfirmationList {
    pub confirmed: Vec<DepositRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementCallArguments {
    pub batch_id: String,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
    pub transcript_commitment: String,
    pub proof_artifact_commitment: String,
    pub clearing_price: String,
    pub matched_order_count: String,
    pub output_bundle_ref: String,
    pub consumed_note_commitments: Vec<String>,
    pub consumed_nullifiers: Vec<String>,
    #[serde(default)]
    pub renewal_parent_order_commitments: Vec<String>,
    #[serde(default)]
    pub renewal_child_nullifiers: Vec<String>,
    pub output_note_commitments: Vec<String>,
    pub output_note_asset_ids: Vec<String>,
    pub output_note_amounts: Vec<String>,
    pub output_note_withdraw_authorities: Vec<String>,
    pub fee_asset_ids: Vec<String>,
    pub fee_recipients: Vec<String>,
    pub fee_amounts: Vec<String>,
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
    #[serde(with = "serde_u128_decimal")]
    pub clearing_price: u128,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub matched_orders: Vec<MatchedOrder>,
    pub matched_order_witnesses: Vec<MatchedOrderWitness>,
    pub consumed_inputs: Vec<ConsumedInput>,
    #[serde(default)]
    pub renewal_child_uses: Vec<RenewalChildUse>,
    pub fees: Vec<FeeEntry>,
    pub output_notes: Vec<OutputNoteRecord>,
    pub output_ciphertext_bundle_ref: String,
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
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductPairConfig {
    pub pair_id: PairId,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub min_order_amount: u128,
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
        for asset_id in ["STRK", "ETH", "USDC", "strkBTC"] {
            assets.insert(
                asset_id.to_owned(),
                ProductAssetConfig {
                    asset_id: AssetId(asset_id.to_owned()),
                    min_trade_amount: 1,
                    enabled: true,
                },
            );
        }

        let mut pairs = BTreeMap::new();
        for (pair_id, base_asset_id, quote_asset_id) in [
            ("STRK/ETH", "STRK", "ETH"),
            ("STRK/USDC", "STRK", "USDC"),
            ("STRK/strkBTC", "STRK", "strkBTC"),
        ] {
            pairs.insert(
                pair_id.to_owned(),
                ProductPairConfig {
                    pair_id: PairId(pair_id.to_owned()),
                    base_asset_id: AssetId(base_asset_id.to_owned()),
                    quote_asset_id: AssetId(quote_asset_id.to_owned()),
                    min_order_amount: 1,
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
                        enabled: true,
                    });
            }
            pairs.insert(pair.pair_id.0.clone(), pair);
        }

        Ok(Self { assets, pairs })
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
        let pair = self
            .enabled_pair(&order.pair_id)
            .ok_or_else(|| ProtocolError::UnsupportedPair(order.pair_id.0.clone()))?;

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
            (OrderType::MakerCurve, Some(curve)) => {
                curve.validate()?;
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
        if funding_note.asset_id != *expected_funding_asset {
            return Err(ProtocolError::InvalidOrder(format!(
                "funding note asset {} does not match expected {}",
                funding_note.asset_id.0, expected_funding_asset.0
            )));
        }

        let minimum_funding = match order.side {
            OrderSide::Buy if matches!(order.order_type, OrderType::MakerCurve) => {
                let Some(curve) = order.maker_curve.as_ref() else {
                    return Err(ProtocolError::InvalidOrder(
                        "maker curve order missing curve".into(),
                    ));
                };
                curve.points.iter().try_fold(0u128, |total, point| {
                    let quote_amount =
                        point.price.checked_mul(point.base_amount).ok_or_else(|| {
                            ProtocolError::InvalidOrder(
                                "maker curve buy funding overflows u128".into(),
                            )
                        })?;
                    total.checked_add(quote_amount).ok_or_else(|| {
                        ProtocolError::InvalidOrder("maker curve buy funding overflows u128".into())
                    })
                })?
            }
            OrderSide::Buy => order
                .min_fill
                .checked_mul(order.limit_price)
                .ok_or_else(|| {
                    ProtocolError::InvalidOrder("minimum buy funding overflows u128".into())
                })?,
            OrderSide::Sell if matches!(order.order_type, OrderType::MakerCurve) => order.amount,
            OrderSide::Sell => order.min_fill,
        };
        if funding_note.amount < minimum_funding {
            return Err(ProtocolError::InvalidOrder(format!(
                "funding note amount {} is below minimum required {}",
                funding_note.amount, minimum_funding
            )));
        }

        if funding_note.commitment()? != order.funding_note_ref {
            return Err(ProtocolError::InvalidOrder(
                "funding note commitment mismatch".into(),
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

        Ok(ProductPairConfig {
            pair_id,
            base_asset_id,
            quote_asset_id,
            min_order_amount: 1,
            enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentContracts {
    pub commitment_registry: String,
    pub batch_registry: String,
    pub fee_ledger: String,
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
    pub proof_account_address: String,
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
        AssetId, BatchId, BatchLiquidityReport, BatchStatus, BatchSummary, DeploymentManifest,
        DepositIntent, FundingRailConfig, FundingRailKind, HiddenMakerCurve, MakerCurvePoint, Note,
        Nullifier, OrderIntent, OrderShareBundle, OrderSide, OrderSubmission, PairId,
        ProductConfig, StarknetPrivacyFundingRail, renewal_parent_commitment,
        renewal_parent_secret_commitment,
    };

    use crate::EncryptedBlob;
    use crate::{RecoverySeed, derive_user_keys, spend_authority_from_raw_key_hex};

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
    fn nullifier_derivation_uses_spend_key() {
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

        assert_ne!(nullifier.0, commitment.0);
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
            funding_nullifier: Nullifier("0x333".into()),
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
            funding_nullifier: Nullifier("0x333".into()),
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
        assert_eq!(json["deposit_nonce"], 7);
    }

    #[test]
    fn protocol_u128_fields_use_decimal_strings_at_wire_boundary() {
        let deposit = serde_json::json!({
            "asset_id": "USDC",
            "amount": "000100",
            "deposit_nonce": 7,
            "recipient_owner_public_key": "owner-key",
            "recipient_spend_authority": "0x123",
            "recipient_withdraw_authority": "0x555"
        });
        let parsed: DepositIntent = serde_json::from_value(deposit).expect("decimal string amount");
        assert_eq!(parsed.amount, 100);

        let legacy_number = serde_json::json!({
            "asset_id": "USDC",
            "amount": 100,
            "deposit_nonce": 7,
            "recipient_owner_public_key": "owner-key",
            "recipient_spend_authority": "0x123",
            "recipient_withdraw_authority": "0x555"
        });
        let parsed: DepositIntent =
            serde_json::from_value(legacy_number).expect("legacy numeric amount");
        assert_eq!(parsed.amount, 100);

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
                "fee_ledger": "0x3",
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
                discovery_url: "https://discovery.example".into(),
                proving_url: "https://prover.example".into(),
                paymaster_address: None,
                paymaster_url: None,
                sdk_package: "@starkware-libs/starknet-privacy-sdk".into(),
                sdk_version: "0.14.2".into(),
                min_proving_delay_blocks: 10,
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

        let privacy_config = funding.starknet_privacy.as_mut().expect("privacy config");
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
            maker_curve: None,
            limit_price: 145,
            amount: 1,
            min_fill: 1,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: Nullifier("0x333".into()),
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
            maker_curve: None,
            limit_price: 145,
            amount: 2,
            min_fill: 1,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: Nullifier("0x333".into()),
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
            asset_id: AssetId("USDC".into()),
            amount: 2_000,
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
            side: OrderSide::Buy,
            order_type: crate::OrderType::MakerCurve,
            maker_curve: Some(HiddenMakerCurve {
                points: vec![
                    MakerCurvePoint {
                        price: 10,
                        base_amount: 50,
                    },
                    MakerCurvePoint {
                        price: 12,
                        base_amount: 50,
                    },
                ],
            }),
            limit_price: 11,
            amount: 100,
            min_fill: 50,
            time_in_force: crate::TimeInForce::CurrentBatchOnly,
            expiry_epoch: 42,
            order_nonce: 9,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: Nullifier("0x333".into()),
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

        order.limit_price = 12;
        assert!(
            product
                .validate_order_funding(&order, &funding_note)
                .is_ok()
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
}

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use starknet_crypto::{Felt, poseidon_hash};

use crate::{
    AssetId, BatchId, LiquidityAttributionPlaintext, LiquidityBandAttribution, LiquidityCurve,
    LiquidityCurvePoint, LiquidityPositionCommitment, LiquidityPositionCurveKind,
    LiquidityPositionFillDelta, LiquidityPositionRootTransition, LiquidityPositionStatus,
    LiquidityPositionTransitionKind, Note, NoteCommitment, OrderSide, PrivateLiquidityPosition,
    ProtocolError, SpendAuthorization, base_amount_affordable_for_quote, build_spend_authorization,
    hash::{
        domain_felt, encode_starknet_felt, felt_from_hex_str, felt_hex, field_from_u64,
        field_from_u128, normalize_felt_hex, ordered_felt_list_commitment, poseidon_chain_hex,
    },
    quote_amount_for_base_amount, spend_authority_from_spend_auth_key_felt,
    verify_spend_authorization,
};

pub const LIQUIDITY_POSITION_SPARSE_TREE_DEPTH: usize = 128;
const BPS_DENOMINATOR: u128 = 10_000;
const BPS_X100_DENOMINATOR: u128 = BPS_DENOMINATOR * 100;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionMarketContext {
    pub epoch: u64,
    pub observed_at_unix_ms: u64,
    pub current_time_unix_ms: u64,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub reference_price: u128,
    #[serde(
        default,
        serialize_with = "crate::types::serde_u128_decimal::serialize_option",
        deserialize_with = "crate::types::serde_u128_decimal::deserialize_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub confirmation_price: Option<u128>,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub price_base_scale: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionCurveSlice {
    pub epoch: u64,
    pub skipped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bid: Option<LiquidityCurve>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask: Option<LiquidityCurve>,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub effective_reference_price: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionSparseUpdateWitness {
    pub key_low: String,
    pub key_high: String,
    pub merkle_path: Vec<String>,
    pub merkle_directions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionStateUpdate {
    pub position_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_commitment: Option<LiquidityPositionCommitment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_commitment: Option<LiquidityPositionCommitment>,
    pub sparse_witness: LiquidityPositionSparseUpdateWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionSettlementFill {
    pub market_context: LiquidityPositionMarketContext,
    pub position_side: OrderSide,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub filled_base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub clearing_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub price_base_scale: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionTransitionWitness {
    pub transition: LiquidityPositionRootTransition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_position: Option<PrivateLiquidityPosition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_position: Option<PrivateLiquidityPosition>,
    pub state_update: LiquidityPositionStateUpdate,
    #[serde(with = "crate::types::serde_u64_decimal")]
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill: Option<LiquidityPositionSettlementFill>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_funding: Option<LiquidityPositionOpenFunding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_notes: Vec<Note>,
    #[serde(
        default,
        with = "crate::types::serde_u128_decimal",
        skip_serializing_if = "is_zero_u128"
    )]
    pub base_amount: u128,
    #[serde(
        default,
        with = "crate::types::serde_u128_decimal",
        skip_serializing_if = "is_zero_u128"
    )]
    pub quote_amount: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_authorization: Option<LiquidityPositionLifecycleAuthorization>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLiquidityPositionTransition {
    pub new_root: String,
    pub position_side: Option<OrderSide>,
    pub filled_base_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionProofWitness {
    pub prior_root: String,
    pub transitions: Vec<LiquidityPositionTransitionWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLiquidityPositionProof {
    pub prior_root: String,
    pub transition_root: String,
    pub new_root: String,
    pub transition_count: usize,
    pub buy_filled_base_amount: u128,
    pub sell_filled_base_amount: u128,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionLifecycleAuthorization {
    pub signature_r: String,
    pub signature_s: String,
}

impl std::fmt::Debug for LiquidityPositionLifecycleAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiquidityPositionLifecycleAuthorization")
            .field("signature_r", &"<redacted>")
            .field("signature_s", &"<redacted>")
            .finish()
    }
}

impl From<SpendAuthorization> for LiquidityPositionLifecycleAuthorization {
    fn from(value: SpendAuthorization) -> Self {
        Self {
            signature_r: value.signature_r,
            signature_s: value.signature_s,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionOpenFunding {
    pub input_notes: Vec<Note>,
    pub change_notes: Vec<Note>,
    pub authorization: LiquidityPositionLifecycleAuthorization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityPositionCloseResult {
    pub output_notes: Vec<Note>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityRewardPolicy {
    pub version: u32,
    pub protocol_fee_bps_x100: u128,
    pub max_rebate_bps_x100: u128,
    pub full_rebate_edge_bps_x100: u128,
    pub zero_rebate_edge_bps_x100: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityRewardAssessment {
    pub version: u32,
    pub pair_id: crate::PairId,
    pub side: OrderSide,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub filled_base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub filled_quote_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub reference_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub clearing_price: u128,
    pub edge_bps_x100: u128,
    pub quality_bps: u128,
    pub rebate_bps_x100: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub rebate_quote_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityRewardEntry {
    pub version: u32,
    pub batch_id: BatchId,
    pub epoch_id: u64,
    pub pair_id: crate::PairId,
    pub liquidity_provider_public_key: String,
    pub output_note_commitment: NoteCommitment,
    pub attribution_commitment: String,
    pub reward_asset_id: AssetId,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub reward_amount: u128,
    pub edge_bps_x100: u128,
    pub rebate_bps_x100: u128,
    pub quality_bps: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityRewardEpoch {
    pub version: u32,
    pub epoch_id: u64,
    pub reward_root: String,
    pub entries: Vec<LiquidityRewardEntry>,
}

impl LiquidityRewardPolicy {
    pub fn standard_pair() -> Self {
        Self {
            version: 1,
            protocol_fee_bps_x100: 400,
            max_rebate_bps_x100: 150,
            full_rebate_edge_bps_x100: 300,
            zero_rebate_edge_bps_x100: 800,
        }
    }

    pub fn conversion_pair() -> Self {
        Self {
            version: 1,
            protocol_fee_bps_x100: 100,
            max_rebate_bps_x100: 40,
            full_rebate_edge_bps_x100: 40,
            zero_rebate_edge_bps_x100: 120,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != 1 {
            return Err(ProtocolError::InvalidOrder(
                "unsupported liquidity reward policy version".into(),
            ));
        }
        if self.protocol_fee_bps_x100 > BPS_X100_DENOMINATOR
            || self.max_rebate_bps_x100 > self.protocol_fee_bps_x100
            || self.zero_rebate_edge_bps_x100 < self.full_rebate_edge_bps_x100
        {
            return Err(ProtocolError::InvalidOrder(
                "liquidity reward policy bounds are invalid".into(),
            ));
        }
        Ok(())
    }
}

pub fn assess_liquidity_reward(
    attribution: &LiquidityBandAttribution,
    reference_price: u128,
    price_base_scale: u128,
    policy: &LiquidityRewardPolicy,
) -> Result<LiquidityRewardAssessment, ProtocolError> {
    policy.validate()?;
    crate::crypto::validate_liquidity_band_attribution_payload(attribution)?;
    if reference_price == 0 || price_base_scale == 0 {
        return Err(ProtocolError::InvalidOrder(
            "liquidity reward assessment requires positive reference price and price scale".into(),
        ));
    }
    let filled_quote_amount = quote_amount_for_base_amount(
        attribution.filled_base_amount,
        attribution.clearing_price,
        price_base_scale,
    )?;
    let edge_bps_x100 = liquidity_reward_edge_bps_x100(
        attribution.side.clone(),
        attribution.clearing_price,
        reference_price,
    )?;
    let quality_bps = liquidity_reward_quality_bps(edge_bps_x100, policy)?;
    let rebate_bps_x100 = mul_div_floor(policy.max_rebate_bps_x100, quality_bps, BPS_DENOMINATOR)?;
    let rebate_quote_amount =
        mul_div_floor(filled_quote_amount, rebate_bps_x100, BPS_X100_DENOMINATOR)?;

    Ok(LiquidityRewardAssessment {
        version: 1,
        pair_id: attribution.pair_id.clone(),
        side: attribution.side.clone(),
        filled_base_amount: attribution.filled_base_amount,
        filled_quote_amount,
        reference_price,
        clearing_price: attribution.clearing_price,
        edge_bps_x100,
        quality_bps,
        rebate_bps_x100,
        rebate_quote_amount,
    })
}

pub fn build_liquidity_reward_entry(
    plaintext: &LiquidityAttributionPlaintext,
    reward_asset_id: AssetId,
    reference_price: u128,
    price_base_scale: u128,
    policy: &LiquidityRewardPolicy,
) -> Result<LiquidityRewardEntry, ProtocolError> {
    if plaintext.version != 1
        || plaintext.batch_id.0.trim().is_empty()
        || plaintext.pair_id.0.trim().is_empty()
        || plaintext.liquidity_provider_public_key.trim().is_empty()
        || plaintext.output_note_commitment.0.trim().is_empty()
        || plaintext.attribution.pair_id != plaintext.pair_id
    {
        return Err(ProtocolError::InvalidOrder(
            "liquidity reward attribution plaintext is invalid".into(),
        ));
    }
    let assessment = assess_liquidity_reward(
        &plaintext.attribution,
        reference_price,
        price_base_scale,
        policy,
    )?;
    Ok(LiquidityRewardEntry {
        version: 1,
        batch_id: plaintext.batch_id.clone(),
        epoch_id: plaintext.epoch_id,
        pair_id: plaintext.pair_id.clone(),
        liquidity_provider_public_key: plaintext.liquidity_provider_public_key.clone(),
        output_note_commitment: plaintext.output_note_commitment.clone(),
        attribution_commitment: crate::crypto::liquidity_band_attribution_commitment(
            &plaintext.attribution,
        )?,
        reward_asset_id,
        reward_amount: assessment.rebate_quote_amount,
        edge_bps_x100: assessment.edge_bps_x100,
        rebate_bps_x100: assessment.rebate_bps_x100,
        quality_bps: assessment.quality_bps,
    })
}

pub fn build_liquidity_reward_epoch(
    epoch_id: u64,
    entries: &[LiquidityRewardEntry],
) -> Result<LiquidityRewardEpoch, ProtocolError> {
    for entry in entries {
        validate_liquidity_reward_entry(entry)?;
        if entry.epoch_id != epoch_id {
            return Err(ProtocolError::InvalidOrder(
                "liquidity reward entry epoch does not match reward epoch".into(),
            ));
        }
    }
    let reward_root = liquidity_reward_epoch_root(entries)?;
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by_key(liquidity_reward_entry_sort_key);
    Ok(LiquidityRewardEpoch {
        version: 1,
        epoch_id,
        reward_root,
        entries: sorted_entries,
    })
}

pub fn liquidity_reward_epoch_root(
    entries: &[LiquidityRewardEntry],
) -> Result<String, ProtocolError> {
    let mut commitments = Vec::with_capacity(entries.len());
    let mut seen = BTreeSet::new();
    for entry in entries {
        validate_liquidity_reward_entry(entry)?;
        let commitment = liquidity_reward_entry_commitment(entry)?;
        if !seen.insert(commitment.clone()) {
            return Err(ProtocolError::InvalidOrder(
                "duplicate liquidity reward entry".into(),
            ));
        }
        commitments.push(commitment);
    }
    commitments.sort();
    ordered_felt_list_commitment("zylith/root/liquidity-reward-epoch-v1", &commitments)
}

pub fn liquidity_reward_entry_commitment(
    entry: &LiquidityRewardEntry,
) -> Result<String, ProtocolError> {
    validate_liquidity_reward_entry(entry)?;
    Ok(poseidon_chain_hex(
        domain_felt("zylith/liquidity-reward-entry-v1"),
        &[
            field_from_u64(entry.version as u64),
            encoded_string_felt("batch-id", &entry.batch_id.0)?,
            field_from_u64(entry.epoch_id),
            encoded_string_felt("pair-id", &entry.pair_id.0)?,
            encoded_string_felt(
                "liquidity-provider-public-key",
                &entry.liquidity_provider_public_key,
            )?,
            felt_from_hex_str(&normalize_felt_hex(&entry.output_note_commitment.0)?)?,
            felt_from_hex_str(&normalize_felt_hex(&entry.attribution_commitment)?)?,
            encoded_string_felt("reward-asset-id", &entry.reward_asset_id.0)?,
            field_from_u128(entry.reward_amount),
            field_from_u128(entry.edge_bps_x100),
            field_from_u128(entry.rebate_bps_x100),
            field_from_u128(entry.quality_bps),
        ],
    ))
}

#[derive(Clone, Debug, Default)]
pub struct LiquidityPositionState {
    entries: BTreeMap<Vec<bool>, PositionLeaf>,
}

#[derive(Clone, Debug)]
struct PositionLeaf {
    commitment: LiquidityPositionCommitment,
    hash: Felt,
}

impl LiquidityPositionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_positions(positions: &[PrivateLiquidityPosition]) -> Result<Self, ProtocolError> {
        let mut state = Self::new();
        for position in positions {
            state.insert_without_witness(position)?;
        }
        Ok(state)
    }

    pub fn root(&self) -> Result<String, ProtocolError> {
        position_sparse_root(&self.entries)
    }

    pub fn contains(&self, position_id: &str) -> Result<bool, ProtocolError> {
        Ok(self.entries.contains_key(&position_key_bits(position_id)?))
    }

    pub fn insertion_update(
        &self,
        position_id: &str,
        output_commitment: LiquidityPositionCommitment,
    ) -> Result<(String, String, LiquidityPositionStateUpdate), ProtocolError> {
        let normalized_id = normalize_felt_hex(position_id)?;
        let prior_root = self.root()?;
        let key = position_key_bits(&normalized_id)?;
        if self.entries.contains_key(&key) {
            return Err(ProtocolError::Crypto(
                "liquidity position id already exists in active state".into(),
            ));
        }
        let witness = position_sparse_witness(&self.entries, &normalized_id)?;
        let update = LiquidityPositionStateUpdate {
            position_id: normalized_id,
            prior_commitment: None,
            output_commitment: Some(output_commitment),
            sparse_witness: witness,
        };
        let new_root = verify_liquidity_position_state_update(&prior_root, &update)?;
        Ok((prior_root, new_root, update))
    }

    pub fn replacement_update(
        &self,
        position_id: &str,
        prior_commitment: LiquidityPositionCommitment,
        output_commitment: LiquidityPositionCommitment,
    ) -> Result<(String, String, LiquidityPositionStateUpdate), ProtocolError> {
        let normalized_id = normalize_felt_hex(position_id)?;
        let prior_root = self.root()?;
        let key = position_key_bits(&normalized_id)?;
        let existing = self.entries.get(&key).ok_or_else(|| {
            ProtocolError::Crypto("liquidity position is absent from active state".into())
        })?;
        let normalized_prior =
            LiquidityPositionCommitment(normalize_felt_hex(&prior_commitment.0)?);
        if existing.commitment != normalized_prior {
            return Err(ProtocolError::Crypto(
                "liquidity position prior commitment does not match active state".into(),
            ));
        }
        let normalized_output =
            LiquidityPositionCommitment(normalize_felt_hex(&output_commitment.0)?);
        let witness = position_sparse_witness(&self.entries, &normalized_id)?;
        let update = LiquidityPositionStateUpdate {
            position_id: normalized_id,
            prior_commitment: Some(normalized_prior),
            output_commitment: Some(normalized_output),
            sparse_witness: witness,
        };
        let new_root = verify_liquidity_position_state_update(&prior_root, &update)?;
        Ok((prior_root, new_root, update))
    }

    pub fn removal_update(
        &self,
        position_id: &str,
        prior_commitment: LiquidityPositionCommitment,
    ) -> Result<(String, String, LiquidityPositionStateUpdate), ProtocolError> {
        let normalized_id = normalize_felt_hex(position_id)?;
        let prior_root = self.root()?;
        let key = position_key_bits(&normalized_id)?;
        let existing = self.entries.get(&key).ok_or_else(|| {
            ProtocolError::Crypto("liquidity position is absent from active state".into())
        })?;
        let normalized_prior =
            LiquidityPositionCommitment(normalize_felt_hex(&prior_commitment.0)?);
        if existing.commitment != normalized_prior {
            return Err(ProtocolError::Crypto(
                "liquidity position prior commitment does not match active state".into(),
            ));
        }
        let witness = position_sparse_witness(&self.entries, &normalized_id)?;
        let update = LiquidityPositionStateUpdate {
            position_id: normalized_id,
            prior_commitment: Some(normalized_prior),
            output_commitment: None,
            sparse_witness: witness,
        };
        let new_root = verify_liquidity_position_state_update(&prior_root, &update)?;
        Ok((prior_root, new_root, update))
    }

    pub fn open(
        &mut self,
        position: &PrivateLiquidityPosition,
    ) -> Result<(String, String, LiquidityPositionStateUpdate), ProtocolError> {
        validate_live_position(position)?;
        let prior_root = self.root()?;
        let key = position_key_bits(&position.position_id)?;
        if self.entries.contains_key(&key) {
            return Err(ProtocolError::Crypto(
                "liquidity position id already exists in active state".into(),
            ));
        }
        let witness = position_sparse_witness(&self.entries, &position.position_id)?;
        let commitment = position.commitment()?;
        let update = LiquidityPositionStateUpdate {
            position_id: normalize_felt_hex(&position.position_id)?,
            prior_commitment: None,
            output_commitment: Some(commitment.clone()),
            sparse_witness: witness,
        };
        let expected_new_root = verify_liquidity_position_state_update(&prior_root, &update)?;
        self.insert_leaf(&position.position_id, commitment)?;
        let new_root = self.root()?;
        if new_root != expected_new_root {
            return Err(ProtocolError::Crypto(
                "liquidity position open witness produced an inconsistent root".into(),
            ));
        }
        Ok((prior_root, new_root, update))
    }

    pub fn replace(
        &mut self,
        prior: &PrivateLiquidityPosition,
        output: &PrivateLiquidityPosition,
    ) -> Result<(String, String, LiquidityPositionStateUpdate), ProtocolError> {
        validate_live_position(prior)?;
        validate_live_position(output)?;
        if normalize_felt_hex(&prior.position_id)? != normalize_felt_hex(&output.position_id)? {
            return Err(ProtocolError::InvalidOrder(
                "liquidity position update cannot change position id".into(),
            ));
        }
        let prior_root = self.root()?;
        let key = position_key_bits(&prior.position_id)?;
        let existing = self.entries.get(&key).ok_or_else(|| {
            ProtocolError::Crypto("liquidity position is absent from active state".into())
        })?;
        let prior_commitment = prior.commitment()?;
        if existing.commitment != prior_commitment {
            return Err(ProtocolError::Crypto(
                "liquidity position prior commitment does not match active state".into(),
            ));
        }
        let witness = position_sparse_witness(&self.entries, &prior.position_id)?;
        let output_commitment = output.commitment()?;
        let update = LiquidityPositionStateUpdate {
            position_id: normalize_felt_hex(&prior.position_id)?,
            prior_commitment: Some(prior_commitment),
            output_commitment: Some(output_commitment.clone()),
            sparse_witness: witness,
        };
        let expected_new_root = verify_liquidity_position_state_update(&prior_root, &update)?;
        self.entries.remove(&key);
        self.insert_leaf(&output.position_id, output_commitment)?;
        let new_root = self.root()?;
        if new_root != expected_new_root {
            return Err(ProtocolError::Crypto(
                "liquidity position replacement witness produced an inconsistent root".into(),
            ));
        }
        Ok((prior_root, new_root, update))
    }

    pub fn close(
        &mut self,
        position: &PrivateLiquidityPosition,
    ) -> Result<(String, String, LiquidityPositionStateUpdate), ProtocolError> {
        validate_live_position(position)?;
        let prior_root = self.root()?;
        let key = position_key_bits(&position.position_id)?;
        let existing = self.entries.get(&key).ok_or_else(|| {
            ProtocolError::Crypto("liquidity position is absent from active state".into())
        })?;
        let commitment = position.commitment()?;
        if existing.commitment != commitment {
            return Err(ProtocolError::Crypto(
                "liquidity position close commitment does not match active state".into(),
            ));
        }
        let witness = position_sparse_witness(&self.entries, &position.position_id)?;
        let update = LiquidityPositionStateUpdate {
            position_id: normalize_felt_hex(&position.position_id)?,
            prior_commitment: Some(commitment),
            output_commitment: None,
            sparse_witness: witness,
        };
        let expected_new_root = verify_liquidity_position_state_update(&prior_root, &update)?;
        self.entries.remove(&key);
        let new_root = self.root()?;
        if new_root != expected_new_root {
            return Err(ProtocolError::Crypto(
                "liquidity position close witness produced an inconsistent root".into(),
            ));
        }
        Ok((prior_root, new_root, update))
    }

    fn insert_without_witness(
        &mut self,
        position: &PrivateLiquidityPosition,
    ) -> Result<(), ProtocolError> {
        validate_live_position(position)?;
        self.insert_leaf(&position.position_id, position.commitment()?)
    }

    fn insert_leaf(
        &mut self,
        position_id: &str,
        commitment: LiquidityPositionCommitment,
    ) -> Result<(), ProtocolError> {
        let normalized_id = normalize_felt_hex(position_id)?;
        let key = position_key_bits(&normalized_id)?;
        if self.entries.contains_key(&key) {
            return Err(ProtocolError::Crypto(
                "liquidity position sparse-key collision".into(),
            ));
        }
        let hash = position_sparse_leaf(&normalized_id, &commitment)?;
        self.entries.insert(key, PositionLeaf { commitment, hash });
        Ok(())
    }
}

pub fn open_liquidity_position(
    position: &PrivateLiquidityPosition,
    funding: &LiquidityPositionOpenFunding,
) -> Result<(), ProtocolError> {
    validate_live_position(position)?;
    if funding.input_notes.is_empty() {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position open requires private funding notes".into(),
        ));
    }
    let owner = normalize_felt_hex(&position.owner_authority)?;
    let (input_base, input_quote) = sum_position_assets(position, &funding.input_notes, &owner)?;
    let (change_base, change_quote) = sum_position_assets(position, &funding.change_notes, &owner)?;
    if input_base != checked_add(position.base_reserve, change_base, "base funding")?
        || input_quote != checked_add(position.quote_reserve, change_quote, "quote funding")?
    {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position funding is not asset-conserving".into(),
        ));
    }
    verify_liquidity_position_transition_authorization(
        &owner,
        LiquidityPositionTransitionKind::Open,
        &position.position_id,
        None,
        Some(&position.commitment()?),
        position.opened_epoch,
        0,
        0,
        &funding.authorization,
    )
}

pub fn reconfigure_liquidity_position(
    prior: &PrivateLiquidityPosition,
    output: &PrivateLiquidityPosition,
    epoch: u64,
    authorization: &LiquidityPositionLifecycleAuthorization,
) -> Result<(), ProtocolError> {
    validate_live_position(prior)?;
    validate_live_position(output)?;
    if prior.position_id != output.position_id
        || prior.backing != output.backing
        || prior.status != output.status
        || prior.pair_id != output.pair_id
        || prior.base_asset_id != output.base_asset_id
        || prior.quote_asset_id != output.quote_asset_id
        || prior.owner_authority != output.owner_authority
        || prior.base_reserve != output.base_reserve
        || prior.quote_reserve != output.quote_reserve
        || prior.opened_epoch != output.opened_epoch
    {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position reconfiguration may only change policy, bounds, caps, expiry, metadata, and blinding".into(),
        ));
    }
    require_fresh_blinding(prior, output)?;
    verify_liquidity_position_transition_authorization(
        &prior.owner_authority,
        LiquidityPositionTransitionKind::Reconfigure,
        &prior.position_id,
        Some(&prior.commitment()?),
        Some(&output.commitment()?),
        epoch,
        0,
        0,
        authorization,
    )
}

pub fn close_liquidity_position(
    position: &PrivateLiquidityPosition,
    epoch: u64,
    output_notes: Vec<Note>,
    authorization: &LiquidityPositionLifecycleAuthorization,
) -> Result<LiquidityPositionCloseResult, ProtocolError> {
    validate_live_position(position)?;
    let expected_base = position.base_reserve;
    let expected_quote = position.quote_reserve;
    validate_owner_output_notes(position, &output_notes, expected_base, expected_quote)?;
    verify_liquidity_position_transition_authorization(
        &position.owner_authority,
        LiquidityPositionTransitionKind::Close,
        &position.position_id,
        Some(&position.commitment()?),
        None,
        epoch,
        expected_base,
        expected_quote,
        authorization,
    )?;
    Ok(LiquidityPositionCloseResult { output_notes })
}

pub fn derive_liquidity_position_curve_slice(
    position: &PrivateLiquidityPosition,
    context: &LiquidityPositionMarketContext,
) -> Result<LiquidityPositionCurveSlice, ProtocolError> {
    validate_live_position(position)?;
    if context.epoch < position.opened_epoch || context.epoch > position.expiry_epoch {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position is not active in the requested epoch".into(),
        ));
    }
    if context.price_base_scale == 0 {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position market context requires a positive price scale".into(),
        ));
    }
    let reference_price = committed_position_reference_price(position, context)?;

    let rotation_seed = rotation_seed(position, context.epoch)?;
    if rotation_seed % BPS_DENOMINATOR < position.rotation_policy.skip_epoch_bps {
        return Ok(LiquidityPositionCurveSlice {
            epoch: context.epoch,
            skipped: true,
            bid: None,
            ask: None,
            effective_reference_price: reference_price,
        });
    }
    let inventory_adjusted_price =
        inventory_adjusted_reference_price(position, reference_price, context.price_base_scale)?;
    let effective_reference_price =
        rotated_reference_price(position, inventory_adjusted_price, rotation_seed)?;
    let half_width_bps = position.curve_policy.spread_bps.div_ceil(2);
    if half_width_bps >= BPS_DENOMINATOR {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position spread leaves no executable price".into(),
        ));
    }
    let bid_high = position.price_upper_bound.min(mul_div_floor(
        effective_reference_price,
        BPS_DENOMINATOR - half_width_bps,
        BPS_DENOMINATOR,
    )?);
    let ask_low = position.price_lower_bound.max(mul_div_ceil(
        effective_reference_price,
        BPS_DENOMINATOR + half_width_bps,
        BPS_DENOMINATOR,
    )?);
    let bid = if position.quote_reserve > 0 && bid_high > position.price_lower_bound {
        build_bid_curve(
            position,
            position.price_lower_bound,
            bid_high,
            context.price_base_scale,
            rotation_seed,
        )?
    } else {
        None
    };
    let ask = if position.base_reserve > 0 && position.price_upper_bound > ask_low {
        build_ask_curve(position, ask_low, position.price_upper_bound, rotation_seed)?
    } else {
        None
    };
    if bid.is_none() && ask.is_none() {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position has no executable curve side in this epoch".into(),
        ));
    }
    Ok(LiquidityPositionCurveSlice {
        epoch: context.epoch,
        skipped: false,
        bid,
        ask,
        effective_reference_price,
    })
}

pub fn apply_liquidity_position_fill(
    position: &PrivateLiquidityPosition,
    position_side: OrderSide,
    filled_base_amount: u128,
    clearing_price: u128,
    price_base_scale: u128,
    next_blinding: &str,
) -> Result<(PrivateLiquidityPosition, LiquidityPositionFillDelta), ProtocolError> {
    validate_live_position(position)?;
    if clearing_price < position.price_lower_bound || clearing_price > position.price_upper_bound {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position fill price is outside the committed range".into(),
        ));
    }
    let quote_amount =
        quote_amount_for_base_amount(filled_base_amount, clearing_price, price_base_scale)?;
    let delta = LiquidityPositionFillDelta {
        position_side,
        filled_base_amount,
        quote_amount,
    };
    let next = position.apply_fill(&delta, next_blinding)?;
    Ok((next, delta))
}

pub fn liquidity_position_transition_message_hash(
    kind: LiquidityPositionTransitionKind,
    position_id: &str,
    prior_commitment: Option<&LiquidityPositionCommitment>,
    output_commitment: Option<&LiquidityPositionCommitment>,
    epoch: u64,
    base_amount: u128,
    quote_amount: u128,
) -> Result<String, ProtocolError> {
    Ok(poseidon_chain_hex(
        domain_felt("zylith/liquidity-position-lifecycle-authorization-v1"),
        &[
            transition_kind_field(&kind),
            felt_from_hex_str(&normalize_felt_hex(position_id)?)?,
            optional_commitment_felt(prior_commitment)?,
            optional_commitment_felt(output_commitment)?,
            field_from_u64(epoch),
            field_from_u128(base_amount),
            field_from_u128(quote_amount),
        ],
    ))
}

pub fn liquidity_position_private_authority(
    private_authority_secret: &str,
) -> Result<String, ProtocolError> {
    if felt_from_hex_str(&normalize_felt_hex(private_authority_secret)?)? == Felt::ZERO {
        return Err(ProtocolError::Crypto(
            "liquidity position authority secret cannot be zero".into(),
        ));
    }
    spend_authority_from_spend_auth_key_felt(private_authority_secret)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_liquidity_position_transition(
    private_authority_secret: &str,
    kind: LiquidityPositionTransitionKind,
    position_id: &str,
    prior_commitment: Option<&LiquidityPositionCommitment>,
    output_commitment: Option<&LiquidityPositionCommitment>,
    epoch: u64,
    base_amount: u128,
    quote_amount: u128,
) -> Result<LiquidityPositionLifecycleAuthorization, ProtocolError> {
    let authority_secret = normalize_felt_hex(private_authority_secret)?;
    if felt_from_hex_str(&authority_secret)? == Felt::ZERO {
        return Err(ProtocolError::Crypto(
            "liquidity position authority secret cannot be zero".into(),
        ));
    }
    let message = liquidity_position_transition_message_hash(
        kind,
        position_id,
        prior_commitment,
        output_commitment,
        epoch,
        base_amount,
        quote_amount,
    )?;
    let authorization = build_spend_authorization(&authority_secret, &message)?;
    Ok(LiquidityPositionLifecycleAuthorization {
        signature_r: authorization.signature_r,
        signature_s: authorization.signature_s,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_liquidity_position_transition_authorization(
    owner_authority: &str,
    kind: LiquidityPositionTransitionKind,
    position_id: &str,
    prior_commitment: Option<&LiquidityPositionCommitment>,
    output_commitment: Option<&LiquidityPositionCommitment>,
    epoch: u64,
    base_amount: u128,
    quote_amount: u128,
    authorization: &LiquidityPositionLifecycleAuthorization,
) -> Result<(), ProtocolError> {
    let message = liquidity_position_transition_message_hash(
        kind,
        position_id,
        prior_commitment,
        output_commitment,
        epoch,
        base_amount,
        quote_amount,
    )?;
    let spend_authorization = SpendAuthorization {
        signature_r: authorization.signature_r.clone(),
        signature_s: authorization.signature_s.clone(),
    };
    if !verify_spend_authorization(owner_authority, &message, &spend_authorization)? {
        return Err(ProtocolError::Crypto(
            "liquidity position lifecycle authorization mismatch".into(),
        ));
    }
    Ok(())
}

pub fn verify_liquidity_position_state_update(
    prior_root: &str,
    update: &LiquidityPositionStateUpdate,
) -> Result<String, ProtocolError> {
    let normalized_id = normalize_felt_hex(&update.position_id)?;
    if normalized_id == "0x0" {
        return Err(ProtocolError::Crypto(
            "liquidity position state update id cannot be zero".into(),
        ));
    }
    if update.prior_commitment.is_none() && update.output_commitment.is_none() {
        return Err(ProtocolError::Crypto(
            "liquidity position state update cannot be empty".into(),
        ));
    }
    let (expected_low, expected_high) = position_key_low_high(&normalized_id)?;
    if normalize_felt_hex(&update.sparse_witness.key_low)? != felt_hex(&Felt::from(expected_low))
        || normalize_felt_hex(&update.sparse_witness.key_high)?
            != felt_hex(&Felt::from(expected_high))
    {
        return Err(ProtocolError::Crypto(
            "liquidity position sparse witness key does not match position id".into(),
        ));
    }
    let prior_root = normalize_felt_hex(prior_root)?;
    let path = &update.sparse_witness.merkle_path;
    let directions = &update.sparse_witness.merkle_directions;
    if prior_root == "0x0" {
        if update.prior_commitment.is_some() || !path.is_empty() || !directions.is_empty() {
            return Err(ProtocolError::Crypto(
                "empty position root only permits an insertion with an empty path".into(),
            ));
        }
        let output = update.output_commitment.as_ref().ok_or_else(|| {
            ProtocolError::Crypto("empty position root update must insert a position".into())
        })?;
        return sparse_root_from_empty(&normalized_id, output);
    }
    if path.len() != LIQUIDITY_POSITION_SPARSE_TREE_DEPTH
        || directions.len() != LIQUIDITY_POSITION_SPARSE_TREE_DEPTH
    {
        return Err(ProtocolError::Crypto(
            "liquidity position sparse path length is invalid".into(),
        ));
    }
    verify_directions(expected_low, directions)?;
    let prior_leaf = update
        .prior_commitment
        .as_ref()
        .map(|commitment| position_sparse_leaf(&normalized_id, commitment))
        .transpose()?
        .unwrap_or(Felt::ZERO);
    let reconstructed_prior = root_from_path(prior_leaf, path, directions)?;
    if felt_hex(&reconstructed_prior) != prior_root {
        return Err(ProtocolError::Crypto(
            "liquidity position sparse witness does not reconstruct prior root".into(),
        ));
    }
    let output_leaf = update
        .output_commitment
        .as_ref()
        .map(|commitment| position_sparse_leaf(&normalized_id, commitment))
        .transpose()?
        .unwrap_or(Felt::ZERO);
    let output_root = root_from_path(output_leaf, path, directions)?;
    if update.output_commitment.is_none() && path_is_canonical_empty(path)? {
        return Ok("0x0".into());
    }
    Ok(felt_hex(&output_root))
}

pub fn liquidity_position_nullifier(
    position: &PrivateLiquidityPosition,
) -> Result<String, ProtocolError> {
    let commitment = position.commitment()?;
    Ok(poseidon_chain_hex(
        domain_felt("zylith/liquidity-position-nullifier-v1"),
        &[
            felt_from_hex_str(&commitment.0)?,
            felt_from_hex_str(&normalize_felt_hex(&position.blinding)?)?,
        ],
    ))
}

pub fn liquidity_position_root_transition(
    kind: LiquidityPositionTransitionKind,
    prior_position: Option<&PrivateLiquidityPosition>,
    output_position: Option<&PrivateLiquidityPosition>,
) -> Result<LiquidityPositionRootTransition, ProtocolError> {
    let transition = LiquidityPositionRootTransition {
        kind,
        consumed_position_commitment: prior_position
            .map(PrivateLiquidityPosition::commitment)
            .transpose()?,
        position_nullifier: prior_position
            .map(liquidity_position_nullifier)
            .transpose()?,
        output_position_commitment: output_position
            .map(PrivateLiquidityPosition::commitment)
            .transpose()?,
    };
    transition.validate()?;
    Ok(transition)
}

pub fn liquidity_position_transition_summary_root(
    transitions: &[LiquidityPositionRootTransition],
) -> Result<String, ProtocolError> {
    let mut state = domain_felt("zylith/root/liquidity-position-transitions-v1");
    for transition in transitions {
        transition.validate()?;
        state = poseidon_hash(state, transition_kind_field(&transition.kind));
        state = poseidon_hash(
            state,
            optional_commitment_felt(transition.consumed_position_commitment.as_ref())?,
        );
        state = poseidon_hash(
            state,
            transition
                .position_nullifier
                .as_ref()
                .map(|nullifier| felt_from_hex_str(&normalize_felt_hex(nullifier)?))
                .transpose()?
                .unwrap_or(Felt::ZERO),
        );
        state = poseidon_hash(
            state,
            optional_commitment_felt(transition.output_position_commitment.as_ref())?,
        );
    }
    Ok(felt_hex(&poseidon_hash(
        state,
        field_from_u64(transitions.len() as u64),
    )))
}

pub fn verify_liquidity_position_proof_witness(
    witness: &LiquidityPositionProofWitness,
) -> Result<VerifiedLiquidityPositionProof, ProtocolError> {
    let prior_root = normalize_felt_hex(&witness.prior_root)?;
    let mut running_root = prior_root.clone();
    let mut summaries = Vec::with_capacity(witness.transitions.len());
    let mut seen_nullifiers = BTreeSet::new();
    let mut seen_outputs = BTreeSet::new();
    let mut buy_filled_base_amount = 0_u128;
    let mut sell_filled_base_amount = 0_u128;

    for transition_witness in &witness.transitions {
        let verified =
            verify_liquidity_position_transition_witness(&running_root, transition_witness)?;
        if let Some(nullifier) = &transition_witness.transition.position_nullifier {
            let normalized = normalize_felt_hex(nullifier)?;
            if !seen_nullifiers.insert(normalized) {
                return Err(ProtocolError::Crypto(
                    "duplicate liquidity position nullifier in proof witness".into(),
                ));
            }
        }
        if let Some(commitment) = &transition_witness.transition.output_position_commitment {
            let normalized = normalize_felt_hex(&commitment.0)?;
            if !seen_outputs.insert(normalized) {
                return Err(ProtocolError::Crypto(
                    "duplicate liquidity position output commitment in proof witness".into(),
                ));
            }
        }
        match verified.position_side {
            Some(OrderSide::Buy) => {
                buy_filled_base_amount = checked_add(
                    buy_filled_base_amount,
                    verified.filled_base_amount,
                    "proof buy fill",
                )?;
            }
            Some(OrderSide::Sell) => {
                sell_filled_base_amount = checked_add(
                    sell_filled_base_amount,
                    verified.filled_base_amount,
                    "proof sell fill",
                )?;
            }
            None => {}
        }
        running_root = verified.new_root;
        summaries.push(transition_witness.transition.clone());
    }

    Ok(VerifiedLiquidityPositionProof {
        prior_root,
        transition_root: liquidity_position_transition_summary_root(&summaries)?,
        new_root: running_root,
        transition_count: summaries.len(),
        buy_filled_base_amount,
        sell_filled_base_amount,
    })
}

pub fn verify_liquidity_position_transition_witness(
    prior_root: &str,
    witness: &LiquidityPositionTransitionWitness,
) -> Result<VerifiedLiquidityPositionTransition, ProtocolError> {
    witness.transition.validate()?;
    assert_transition_preimages_match_summary(witness)?;
    assert_state_update_matches_transition(witness)?;
    let new_root = verify_liquidity_position_state_update(prior_root, &witness.state_update)?;

    let mut verified = VerifiedLiquidityPositionTransition {
        new_root,
        position_side: None,
        filled_base_amount: 0,
    };
    match witness.transition.kind {
        LiquidityPositionTransitionKind::Open => verify_open_transition(witness)?,
        LiquidityPositionTransitionKind::Update => {
            let fill = verify_fill_transition(witness)?;
            verified.position_side = Some(fill.position_side.clone());
            verified.filled_base_amount = fill.filled_base_amount;
        }
        LiquidityPositionTransitionKind::Reconfigure => verify_reconfigure_transition(witness)?,
        LiquidityPositionTransitionKind::Close => verify_close_transition(witness)?,
    }
    Ok(verified)
}

fn assert_transition_preimages_match_summary(
    witness: &LiquidityPositionTransitionWitness,
) -> Result<(), ProtocolError> {
    let expected = liquidity_position_root_transition(
        witness.transition.kind.clone(),
        witness.prior_position.as_ref(),
        witness.output_position.as_ref(),
    )?;
    if expected != witness.transition {
        return Err(ProtocolError::Crypto(
            "liquidity position transition summary does not match its private preimages".into(),
        ));
    }
    Ok(())
}

fn assert_state_update_matches_transition(
    witness: &LiquidityPositionTransitionWitness,
) -> Result<(), ProtocolError> {
    let position_id = witness
        .prior_position
        .as_ref()
        .or(witness.output_position.as_ref())
        .ok_or_else(|| ProtocolError::Crypto("position transition has no preimage".into()))?
        .position_id
        .as_str();
    if normalize_felt_hex(&witness.state_update.position_id)? != normalize_felt_hex(position_id)?
        || witness.state_update.prior_commitment != witness.transition.consumed_position_commitment
        || witness.state_update.output_commitment != witness.transition.output_position_commitment
    {
        return Err(ProtocolError::Crypto(
            "liquidity position sparse update does not match transition summary".into(),
        ));
    }
    if let (Some(prior), Some(output)) = (
        witness.prior_position.as_ref(),
        witness.output_position.as_ref(),
    ) && normalize_felt_hex(&prior.position_id)? != normalize_felt_hex(&output.position_id)?
    {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position transition cannot change position id".into(),
        ));
    }
    Ok(())
}

fn verify_open_transition(
    witness: &LiquidityPositionTransitionWitness,
) -> Result<(), ProtocolError> {
    let position = witness.output_position.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position open is missing its output preimage".into())
    })?;
    let funding = witness.open_funding.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position open is missing its funding witness".into())
    })?;
    if witness.epoch != position.opened_epoch
        || witness.prior_position.is_some()
        || witness.fill.is_some()
        || witness.lifecycle_authorization.is_some()
        || !witness.output_notes.is_empty()
        || witness.base_amount != 0
        || witness.quote_amount != 0
    {
        return Err(ProtocolError::InvalidOrder(
            "position open contains incompatible transition fields".into(),
        ));
    }
    open_liquidity_position(position, funding)
}

fn verify_fill_transition(
    witness: &LiquidityPositionTransitionWitness,
) -> Result<&LiquidityPositionSettlementFill, ProtocolError> {
    let prior = witness.prior_position.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position fill is missing its prior preimage".into())
    })?;
    let output = witness.output_position.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position fill is missing its output preimage".into())
    })?;
    let fill = witness
        .fill
        .as_ref()
        .ok_or_else(|| ProtocolError::Crypto("position fill witness is missing".into()))?;
    if witness.epoch != fill.market_context.epoch
        || fill.price_base_scale != fill.market_context.price_base_scale
        || witness.open_funding.is_some()
        || witness.lifecycle_authorization.is_some()
        || !witness.output_notes.is_empty()
        || witness.base_amount != 0
        || witness.quote_amount != 0
    {
        return Err(ProtocolError::InvalidOrder(
            "position fill contains incompatible transition fields".into(),
        ));
    }
    let curve = derive_liquidity_position_curve_slice(prior, &fill.market_context)?;
    if curve.skipped {
        return Err(ProtocolError::InvalidOrder(
            "a skipped liquidity position cannot be filled".into(),
        ));
    }
    let side_curve = match fill.position_side {
        OrderSide::Buy => curve.bid.as_ref(),
        OrderSide::Sell => curve.ask.as_ref(),
    }
    .ok_or_else(|| {
        ProtocolError::InvalidOrder("position has no curve on the filled side".into())
    })?;
    let capacity = curve_capacity_at_price(side_curve, &fill.position_side, fill.clearing_price)?;
    if fill.filled_base_amount == 0 || fill.filled_base_amount > capacity {
        return Err(ProtocolError::InvalidOrder(
            "position fill exceeds canonical curve capacity at the clearing price".into(),
        ));
    }
    let (expected_output, _) = apply_liquidity_position_fill(
        prior,
        fill.position_side.clone(),
        fill.filled_base_amount,
        fill.clearing_price,
        fill.price_base_scale,
        &output.blinding,
    )?;
    if expected_output != *output {
        return Err(ProtocolError::InvalidOrder(
            "position fill output does not match canonical reserve accounting".into(),
        ));
    }
    Ok(fill)
}

fn verify_reconfigure_transition(
    witness: &LiquidityPositionTransitionWitness,
) -> Result<(), ProtocolError> {
    let prior = witness.prior_position.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position reconfiguration is missing its prior preimage".into())
    })?;
    let output = witness.output_position.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position reconfiguration is missing its output preimage".into())
    })?;
    let authorization = witness.lifecycle_authorization.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position reconfiguration is missing owner authorization".into())
    })?;
    assert_no_incompatible_lifecycle_fields(witness)?;
    reconfigure_liquidity_position(prior, output, witness.epoch, authorization)
}

fn verify_close_transition(
    witness: &LiquidityPositionTransitionWitness,
) -> Result<(), ProtocolError> {
    let prior = witness.prior_position.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position close is missing its prior preimage".into())
    })?;
    let authorization = witness.lifecycle_authorization.as_ref().ok_or_else(|| {
        ProtocolError::Crypto("position close is missing owner authorization".into())
    })?;
    if witness.output_position.is_some()
        || witness.fill.is_some()
        || witness.open_funding.is_some()
        || witness.base_amount != 0
        || witness.quote_amount != 0
    {
        return Err(ProtocolError::InvalidOrder(
            "position close contains incompatible transition fields".into(),
        ));
    }
    close_liquidity_position(
        prior,
        witness.epoch,
        witness.output_notes.clone(),
        authorization,
    )?;
    Ok(())
}

fn assert_no_incompatible_lifecycle_fields(
    witness: &LiquidityPositionTransitionWitness,
) -> Result<(), ProtocolError> {
    if witness.fill.is_some()
        || witness.open_funding.is_some()
        || !witness.output_notes.is_empty()
        || witness.base_amount != 0
        || witness.quote_amount != 0
    {
        return Err(ProtocolError::InvalidOrder(
            "position lifecycle transition contains incompatible fields".into(),
        ));
    }
    Ok(())
}

fn curve_capacity_at_price(
    curve: &LiquidityCurve,
    side: &OrderSide,
    clearing_price: u128,
) -> Result<u128, ProtocolError> {
    curve.points.iter().try_fold(0_u128, |capacity, point| {
        let eligible = match side {
            OrderSide::Buy => point.price >= clearing_price,
            OrderSide::Sell => point.price <= clearing_price,
        };
        if !eligible {
            return Ok(capacity);
        }
        checked_add(capacity, point.base_amount, "position curve capacity")
    })
}

fn is_zero_u128(value: &u128) -> bool {
    *value == 0
}

fn validate_live_position(position: &PrivateLiquidityPosition) -> Result<(), ProtocolError> {
    position.validate()?;
    if position.status != LiquidityPositionStatus::Active {
        return Err(ProtocolError::InvalidOrder(
            "active position state may only contain active liquidity positions".into(),
        ));
    }
    Ok(())
}

fn require_fresh_blinding(
    prior: &PrivateLiquidityPosition,
    output: &PrivateLiquidityPosition,
) -> Result<(), ProtocolError> {
    let prior_blinding = normalize_felt_hex(&prior.blinding)?;
    let output_blinding = normalize_felt_hex(&output.blinding)?;
    if output_blinding == "0x0" || output_blinding == prior_blinding {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position state transition requires a fresh blinding".into(),
        ));
    }
    Ok(())
}

fn sum_position_assets(
    position: &PrivateLiquidityPosition,
    notes: &[Note],
    owner: &str,
) -> Result<(u128, u128), ProtocolError> {
    let mut base = 0_u128;
    let mut quote = 0_u128;
    for note in notes {
        note.commitment()?;
        if normalize_felt_hex(&note.spend_authority)? != owner {
            return Err(ProtocolError::InvalidOrder(
                "position lifecycle notes must share the position owner authority".into(),
            ));
        }
        add_asset_amount(
            &note.asset_id,
            note.amount,
            &position.base_asset_id,
            &position.quote_asset_id,
            &mut base,
            &mut quote,
        )?;
    }
    Ok((base, quote))
}

fn validate_owner_output_notes(
    position: &PrivateLiquidityPosition,
    output_notes: &[Note],
    expected_base: u128,
    expected_quote: u128,
) -> Result<(), ProtocolError> {
    let owner = normalize_felt_hex(&position.owner_authority)?;
    let (actual_base, actual_quote) = sum_position_assets(position, output_notes, &owner)?;
    if actual_base != expected_base || actual_quote != expected_quote {
        return Err(ProtocolError::InvalidOrder(
            "position lifecycle output notes do not conserve position assets".into(),
        ));
    }
    Ok(())
}

fn add_asset_amount(
    asset_id: &AssetId,
    amount: u128,
    base_asset_id: &AssetId,
    quote_asset_id: &AssetId,
    base_total: &mut u128,
    quote_total: &mut u128,
) -> Result<(), ProtocolError> {
    if asset_id == base_asset_id {
        *base_total = checked_add(*base_total, amount, "base amount")?;
    } else if asset_id == quote_asset_id {
        *quote_total = checked_add(*quote_total, amount, "quote amount")?;
    } else {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position operation contains an unrelated asset".into(),
        ));
    }
    Ok(())
}

fn checked_add(left: u128, right: u128, label: &str) -> Result<u128, ProtocolError> {
    left.checked_add(right)
        .ok_or_else(|| ProtocolError::InvalidOrder(format!("liquidity position {label} overflow")))
}

fn transition_kind_field(kind: &LiquidityPositionTransitionKind) -> Felt {
    field_from_u64(match kind {
        LiquidityPositionTransitionKind::Open => 0,
        LiquidityPositionTransitionKind::Update => 1,
        LiquidityPositionTransitionKind::Close => 2,
        LiquidityPositionTransitionKind::Reconfigure => 4,
    })
}

fn optional_commitment_felt(
    commitment: Option<&LiquidityPositionCommitment>,
) -> Result<Felt, ProtocolError> {
    commitment
        .map(|value| felt_from_hex_str(&normalize_felt_hex(&value.0)?))
        .transpose()
        .map(|value| value.unwrap_or(Felt::ZERO))
}

fn rotation_seed(position: &PrivateLiquidityPosition, epoch: u64) -> Result<u128, ProtocolError> {
    let commitment = poseidon_chain_hex(
        domain_felt("zylith/liquidity-position-curve-rotation-v1"),
        &[
            felt_from_hex_str(&normalize_felt_hex(&position.position_id)?)?,
            felt_from_hex_str(&normalize_felt_hex(&position.blinding)?)?,
            field_from_u64(epoch),
        ],
    );
    let normalized = normalize_felt_hex(&commitment)?;
    let hex = normalized.trim_start_matches("0x");
    let low = &hex[hex.len().saturating_sub(32)..];
    u128::from_str_radix(low, 16)
        .map_err(|error| ProtocolError::Crypto(format!("invalid position rotation seed: {error}")))
}

fn rotated_reference_price(
    position: &PrivateLiquidityPosition,
    reference_price: u128,
    seed: u128,
) -> Result<u128, ProtocolError> {
    if position.curve_policy.kind == LiquidityPositionCurveKind::StaticRange
        && position.rotation_policy.max_price_rotation_bps == 0
    {
        return Ok(reference_price);
    }
    let max_rotation = position.rotation_policy.max_price_rotation_bps;
    if max_rotation == 0 {
        return Ok(reference_price);
    }
    let width = max_rotation
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| ProtocolError::InvalidOrder("position rotation overflow".into()))?;
    let sample = seed % width;
    let (increase, bps) = if sample >= max_rotation {
        (true, sample - max_rotation)
    } else {
        (false, max_rotation - sample)
    };
    let delta = mul_div_floor(reference_price, bps, BPS_DENOMINATOR)?;
    let rotated = if increase {
        checked_add(reference_price, delta, "rotated price")?
    } else {
        reference_price.saturating_sub(delta).max(1)
    };
    Ok(rotated.clamp(position.price_lower_bound, position.price_upper_bound))
}

fn validate_oracle_context(
    position: &PrivateLiquidityPosition,
    context: &LiquidityPositionMarketContext,
) -> Result<(), ProtocolError> {
    let Some(guard) = &position.oracle_guard else {
        return Ok(());
    };
    if context.current_time_unix_ms < context.observed_at_unix_ms
        || u128::from(context.current_time_unix_ms - context.observed_at_unix_ms)
            > guard.max_staleness_ms
    {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position oracle observation is stale".into(),
        ));
    }
    let confirmation = context.confirmation_price.ok_or_else(|| {
        ProtocolError::InvalidOrder(
            "oracle-guarded liquidity position requires a confirmation price".into(),
        )
    })?;
    if confirmation == 0 {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position confirmation price must be positive".into(),
        ));
    }
    let divergence = relative_difference_bps(context.reference_price, confirmation)?;
    let policy_limit = if position.curve_policy.max_price_deviation_bps == 0 {
        guard.max_divergence_bps
    } else {
        guard
            .max_divergence_bps
            .min(position.curve_policy.max_price_deviation_bps)
    };
    if divergence > policy_limit {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position oracle sources diverge beyond policy".into(),
        ));
    }
    Ok(())
}

fn committed_position_reference_price(
    position: &PrivateLiquidityPosition,
    context: &LiquidityPositionMarketContext,
) -> Result<u128, ProtocolError> {
    if position.oracle_guard.is_some() {
        if context.reference_price == 0 {
            return Err(ProtocolError::InvalidOrder(
                "oracle-guarded liquidity positions require a positive reference price".into(),
            ));
        }
        validate_oracle_context(position, context)?;
        return Ok(context.reference_price);
    }
    if position.curve_policy.kind == LiquidityPositionCurveKind::OraclePegged
        && position.oracle_guard.is_none()
    {
        return Err(ProtocolError::InvalidOrder(
            "oracle-pegged liquidity positions require an oracle guard".into(),
        ));
    }
    position
        .price_lower_bound
        .checked_add((position.price_upper_bound - position.price_lower_bound) / 2)
        .ok_or_else(|| ProtocolError::InvalidOrder("position midpoint overflow".into()))
}

fn inventory_adjusted_reference_price(
    position: &PrivateLiquidityPosition,
    reference_price: u128,
    price_base_scale: u128,
) -> Result<u128, ProtocolError> {
    if position.curve_policy.kind != LiquidityPositionCurveKind::InventorySkewed
        || position.curve_policy.inventory_skew_bps == 0
    {
        return Ok(reference_price);
    }
    let base_value =
        quote_amount_for_base_amount(position.base_reserve, reference_price, price_base_scale)?;
    let total_value = checked_add(base_value, position.quote_reserve, "inventory value")?;
    if total_value == 0 {
        return Ok(reference_price);
    }
    let actual_base_ratio = mul_div_floor(base_value, BPS_DENOMINATOR, total_value)?;
    let target = position.curve_policy.target_base_ratio_bps;
    let imbalance = actual_base_ratio.abs_diff(target);
    let shift_bps = mul_div_floor(
        imbalance,
        position.curve_policy.inventory_skew_bps,
        BPS_DENOMINATOR,
    )?
    .min(position.curve_policy.max_price_deviation_bps);
    let delta = mul_div_floor(reference_price, shift_bps, BPS_DENOMINATOR)?;
    let adjusted = if actual_base_ratio > target {
        reference_price.saturating_sub(delta).max(1)
    } else {
        checked_add(reference_price, delta, "inventory-skewed price")?
    };
    Ok(adjusted.clamp(position.price_lower_bound, position.price_upper_bound))
}

fn relative_difference_bps(left: u128, right: u128) -> Result<u128, ProtocolError> {
    let denominator = left.min(right);
    if denominator == 0 {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position price comparison contains zero".into(),
        ));
    }
    mul_div_ceil(left.abs_diff(right), BPS_DENOMINATOR, denominator)
}

fn liquidity_reward_edge_bps_x100(
    side: OrderSide,
    clearing_price: u128,
    reference_price: u128,
) -> Result<u128, ProtocolError> {
    if reference_price == 0 {
        return Err(ProtocolError::InvalidOrder(
            "liquidity reward reference price is zero".into(),
        ));
    }
    let edge = match side {
        OrderSide::Buy => reference_price.saturating_sub(clearing_price),
        OrderSide::Sell => clearing_price.saturating_sub(reference_price),
    };
    mul_div_floor(edge, BPS_X100_DENOMINATOR, reference_price)
}

fn liquidity_reward_quality_bps(
    edge_bps_x100: u128,
    policy: &LiquidityRewardPolicy,
) -> Result<u128, ProtocolError> {
    if edge_bps_x100 <= policy.full_rebate_edge_bps_x100 {
        return Ok(BPS_DENOMINATOR);
    }
    if edge_bps_x100 >= policy.zero_rebate_edge_bps_x100 {
        return Ok(0);
    }
    let width = policy.zero_rebate_edge_bps_x100 - policy.full_rebate_edge_bps_x100;
    if width == 0 {
        return Ok(0);
    }
    mul_div_floor(
        policy.zero_rebate_edge_bps_x100 - edge_bps_x100,
        BPS_DENOMINATOR,
        width,
    )
}

fn validate_liquidity_reward_entry(entry: &LiquidityRewardEntry) -> Result<(), ProtocolError> {
    if entry.version != 1
        || entry.batch_id.0.trim().is_empty()
        || entry.pair_id.0.trim().is_empty()
        || entry.liquidity_provider_public_key.trim().is_empty()
        || entry.reward_asset_id.0.trim().is_empty()
        || entry.reward_amount == 0
        || entry.quality_bps > BPS_DENOMINATOR
        || entry.rebate_bps_x100 > BPS_X100_DENOMINATOR
    {
        return Err(ProtocolError::InvalidOrder(
            "liquidity reward entry is invalid".into(),
        ));
    }
    normalize_felt_hex(&entry.output_note_commitment.0)?;
    normalize_felt_hex(&entry.attribution_commitment)?;
    Ok(())
}

fn liquidity_reward_entry_sort_key(entry: &LiquidityRewardEntry) -> String {
    format!(
        "{}:{}:{}:{}",
        entry.epoch_id, entry.batch_id.0, entry.pair_id.0, entry.output_note_commitment.0
    )
}

fn encoded_string_felt(kind: &str, value: &str) -> Result<Felt, ProtocolError> {
    felt_from_hex_str(&encode_starknet_felt(kind, value))
}

fn build_bid_curve(
    position: &PrivateLiquidityPosition,
    low: u128,
    high: u128,
    price_base_scale: u128,
    seed: u128,
) -> Result<Option<LiquidityCurve>, ProtocolError> {
    let prices = rotated_price_ladder(position, low, high, seed)?;
    let available_quote = rotated_depth(
        position.quote_reserve,
        position.rotation_policy.max_depth_rotation_bps,
        seed.rotate_left(41),
    )?;
    let allocations = split_amount(available_quote, prices.len());
    let mut points = Vec::with_capacity(prices.len());
    for (price, quote_amount) in prices.into_iter().zip(allocations) {
        let base_amount = base_amount_affordable_for_quote(quote_amount, price, price_base_scale)?;
        if base_amount > 0 {
            points.push(LiquidityCurvePoint { price, base_amount });
        }
    }
    cap_curve_points(&mut points, position.max_fill_base_per_batch)?;
    curve_or_none(points)
}

fn build_ask_curve(
    position: &PrivateLiquidityPosition,
    low: u128,
    high: u128,
    seed: u128,
) -> Result<Option<LiquidityCurve>, ProtocolError> {
    let prices = rotated_price_ladder(position, low, high, seed.rotate_left(17))?;
    let available_base = rotated_depth(
        position.base_reserve,
        position.rotation_policy.max_depth_rotation_bps,
        seed.rotate_left(73),
    )?;
    let allocations = split_amount(available_base, prices.len());
    let mut points = prices
        .into_iter()
        .zip(allocations)
        .filter_map(|(price, base_amount)| {
            (base_amount > 0).then_some(LiquidityCurvePoint { price, base_amount })
        })
        .collect::<Vec<_>>();
    cap_curve_points(&mut points, position.max_fill_base_per_batch)?;
    curve_or_none(points)
}

fn rotated_price_ladder(
    position: &PrivateLiquidityPosition,
    low: u128,
    high: u128,
    seed: u128,
) -> Result<Vec<u128>, ProtocolError> {
    let count = position.curve_policy.band_count as usize;
    if count < 2 || low >= high {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position curve range cannot form a ladder".into(),
        ));
    }
    let denominator = (count - 1) as u128;
    let mut prices = Vec::with_capacity(count);
    for index in 0..count {
        let distance = high
            .checked_sub(low)
            .and_then(|width| width.checked_mul(index as u128))
            .and_then(|value| value.checked_div(denominator))
            .ok_or_else(|| ProtocolError::InvalidOrder("position ladder overflow".into()))?;
        let mut price = checked_add(low, distance, "ladder price")?;
        if index > 0 && index + 1 < count && position.rotation_policy.max_price_rotation_bps > 0 {
            let max_jitter = ((high - low) / (denominator * 4).max(1)).max(1);
            let jitter = seed.rotate_left(index as u32) % max_jitter;
            price = price.saturating_add(jitter).min(high - 1);
        }
        if prices.last().is_some_and(|previous| *previous >= price) {
            return Err(ProtocolError::InvalidOrder(
                "liquidity position range is too narrow for its band count".into(),
            ));
        }
        prices.push(price);
    }
    Ok(prices)
}

fn split_amount(total: u128, count: usize) -> Vec<u128> {
    if count == 0 {
        return Vec::new();
    }
    let divisor = count as u128;
    let quotient = total / divisor;
    let remainder = total % divisor;
    (0..count)
        .map(|index| quotient + u128::from((index as u128) < remainder))
        .collect()
}

fn rotated_depth(total: u128, max_reduction_bps: u128, seed: u128) -> Result<u128, ProtocolError> {
    if max_reduction_bps == 0 {
        return Ok(total);
    }
    let reduction_bps = seed % (max_reduction_bps + 1);
    mul_div_floor(total, BPS_DENOMINATOR - reduction_bps, BPS_DENOMINATOR)
}

fn cap_curve_points(
    points: &mut Vec<LiquidityCurvePoint>,
    max_total_base: u128,
) -> Result<(), ProtocolError> {
    let total = points.iter().try_fold(0_u128, |sum, point| {
        checked_add(sum, point.base_amount, "curve total")
    })?;
    if total <= max_total_base {
        return Ok(());
    }
    let mut used = 0_u128;
    for point in points.iter_mut() {
        point.base_amount = mul_div_floor(point.base_amount, max_total_base, total)?;
        used = checked_add(used, point.base_amount, "capped curve total")?;
    }
    let mut remainder = max_total_base - used;
    for point in points.iter_mut() {
        if remainder == 0 {
            break;
        }
        point.base_amount = checked_add(point.base_amount, 1, "curve remainder")?;
        remainder -= 1;
    }
    points.retain(|point| point.base_amount > 0);
    Ok(())
}

fn curve_or_none(
    points: Vec<LiquidityCurvePoint>,
) -> Result<Option<LiquidityCurve>, ProtocolError> {
    if points.len() < crate::types::MIN_LIQUIDITY_CURVE_POINTS {
        return Ok(None);
    }
    let curve = LiquidityCurve { points };
    curve.validate()?;
    Ok(Some(curve))
}

fn mul_div_floor(left: u128, right: u128, denominator: u128) -> Result<u128, ProtocolError> {
    if denominator == 0 {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position arithmetic denominator is zero".into(),
        ));
    }
    left.checked_mul(right)
        .and_then(|value| value.checked_div(denominator))
        .ok_or_else(|| ProtocolError::InvalidOrder("liquidity position arithmetic overflow".into()))
}

fn mul_div_ceil(left: u128, right: u128, denominator: u128) -> Result<u128, ProtocolError> {
    if denominator == 0 {
        return Err(ProtocolError::InvalidOrder(
            "liquidity position arithmetic denominator is zero".into(),
        ));
    }
    let product = left.checked_mul(right).ok_or_else(|| {
        ProtocolError::InvalidOrder("liquidity position arithmetic overflow".into())
    })?;
    if product == 0 {
        return Ok(0);
    }
    product
        .checked_add(denominator - 1)
        .and_then(|value| value.checked_div(denominator))
        .ok_or_else(|| ProtocolError::InvalidOrder("liquidity position arithmetic overflow".into()))
}

fn position_sparse_leaf(
    position_id: &str,
    commitment: &LiquidityPositionCommitment,
) -> Result<Felt, ProtocolError> {
    let mut state = poseidon_hash(
        domain_felt("zylith/liquidity-position-sparse-leaf-v1"),
        felt_from_hex_str(&normalize_felt_hex(position_id)?)?,
    );
    state = poseidon_hash(
        state,
        felt_from_hex_str(&normalize_felt_hex(&commitment.0)?)?,
    );
    Ok(state)
}

fn position_sparse_node(left: Felt, right: Felt, level: usize) -> Felt {
    let mut state = poseidon_hash(
        domain_felt("zylith/liquidity-position-sparse-node-v1"),
        Felt::from(level as u64),
    );
    state = poseidon_hash(state, left);
    poseidon_hash(state, right)
}

fn empty_subtrees() -> Vec<Felt> {
    let mut empty = Vec::with_capacity(LIQUIDITY_POSITION_SPARSE_TREE_DEPTH + 1);
    empty.push(Felt::ZERO);
    for level in 0..LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        empty.push(position_sparse_node(empty[level], empty[level], level));
    }
    empty
}

fn position_sparse_levels(
    entries: &BTreeMap<Vec<bool>, PositionLeaf>,
) -> Result<Vec<BTreeMap<Vec<bool>, Felt>>, ProtocolError> {
    let empty = empty_subtrees();
    let mut levels: Vec<BTreeMap<Vec<bool>, Felt>> =
        Vec::with_capacity(LIQUIDITY_POSITION_SPARSE_TREE_DEPTH + 1);
    levels.push(
        entries
            .iter()
            .map(|(key, leaf)| (key.clone(), leaf.hash))
            .collect(),
    );
    for level in 0..LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        let current = levels
            .last()
            .ok_or_else(|| ProtocolError::Crypto("position sparse tree level is missing".into()))?;
        let mut parent_pairs = BTreeMap::<Vec<bool>, (Felt, Felt)>::new();
        for (key, value) in current {
            if key.is_empty() {
                return Err(ProtocolError::Crypto(
                    "position sparse tree key underflow".into(),
                ));
            }
            let entry = parent_pairs
                .entry(key[1..].to_vec())
                .or_insert((empty[level], empty[level]));
            if key[0] {
                entry.1 = *value;
            } else {
                entry.0 = *value;
            }
        }
        levels.push(
            parent_pairs
                .into_iter()
                .filter_map(|(key, (left, right))| {
                    let node = position_sparse_node(left, right, level);
                    (node != empty[level + 1]).then_some((key, node))
                })
                .collect(),
        );
    }
    Ok(levels)
}

fn position_sparse_root(
    entries: &BTreeMap<Vec<bool>, PositionLeaf>,
) -> Result<String, ProtocolError> {
    if entries.is_empty() {
        return Ok("0x0".into());
    }
    let levels = position_sparse_levels(entries)?;
    let root = levels
        .last()
        .and_then(|level| level.get(&Vec::<bool>::new()))
        .copied()
        .ok_or_else(|| ProtocolError::Crypto("position sparse root is missing".into()))?;
    Ok(felt_hex(&root))
}

fn position_sparse_witness(
    entries: &BTreeMap<Vec<bool>, PositionLeaf>,
    position_id: &str,
) -> Result<LiquidityPositionSparseUpdateWitness, ProtocolError> {
    let normalized_id = normalize_felt_hex(position_id)?;
    let key = position_key_bits(&normalized_id)?;
    let (low, high) = position_key_low_high(&normalized_id)?;
    if entries.is_empty() {
        return Ok(LiquidityPositionSparseUpdateWitness {
            key_low: felt_hex(&Felt::from(low)),
            key_high: felt_hex(&Felt::from(high)),
            merkle_path: Vec::new(),
            merkle_directions: Vec::new(),
        });
    }
    let empty = empty_subtrees();
    let levels = position_sparse_levels(entries)?;
    let mut merkle_path = Vec::with_capacity(LIQUIDITY_POSITION_SPARSE_TREE_DEPTH);
    let mut merkle_directions = Vec::with_capacity(LIQUIDITY_POSITION_SPARSE_TREE_DEPTH);
    for level in 0..LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        let mut sibling_key = key[level..].to_vec();
        sibling_key[0] = !sibling_key[0];
        let sibling = levels[level]
            .get(&sibling_key)
            .copied()
            .unwrap_or(empty[level]);
        merkle_path.push(felt_hex(&sibling));
        merkle_directions.push(if key[level] {
            "0x1".into()
        } else {
            "0x0".into()
        });
    }
    Ok(LiquidityPositionSparseUpdateWitness {
        key_low: felt_hex(&Felt::from(low)),
        key_high: felt_hex(&Felt::from(high)),
        merkle_path,
        merkle_directions,
    })
}

fn position_key_bits(position_id: &str) -> Result<Vec<bool>, ProtocolError> {
    let (low, _) = position_key_low_high(position_id)?;
    Ok((0..LIQUIDITY_POSITION_SPARSE_TREE_DEPTH)
        .map(|index| ((low >> index) & 1) == 1)
        .collect())
}

fn position_key_low_high(position_id: &str) -> Result<(u128, u128), ProtocolError> {
    let normalized = normalize_felt_hex(position_id)?;
    let hex = normalized.trim_start_matches("0x");
    let low_start = hex.len().saturating_sub(32);
    let low = u128::from_str_radix(&hex[low_start..], 16).map_err(|error| {
        ProtocolError::Crypto(format!("invalid liquidity position id low limb: {error}"))
    })?;
    let high = if low_start == 0 {
        0
    } else {
        u128::from_str_radix(&hex[..low_start], 16).map_err(|error| {
            ProtocolError::Crypto(format!("invalid liquidity position id high limb: {error}"))
        })?
    };
    Ok((low, high))
}

fn sparse_root_from_empty(
    position_id: &str,
    commitment: &LiquidityPositionCommitment,
) -> Result<String, ProtocolError> {
    let (mut remaining_key, _) = position_key_low_high(position_id)?;
    let mut root = position_sparse_leaf(position_id, commitment)?;
    let mut empty = Felt::ZERO;
    for level in 0..LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        root = if remaining_key % 2 == 0 {
            position_sparse_node(root, empty, level)
        } else {
            position_sparse_node(empty, root, level)
        };
        remaining_key /= 2;
        empty = position_sparse_node(empty, empty, level);
    }
    Ok(felt_hex(&root))
}

fn root_from_path(
    mut root: Felt,
    path: &[String],
    directions: &[String],
) -> Result<Felt, ProtocolError> {
    for level in 0..LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        let sibling = felt_from_hex_str(&normalize_felt_hex(&path[level])?)?;
        root = match normalize_felt_hex(&directions[level])?.as_str() {
            "0x0" => position_sparse_node(root, sibling, level),
            "0x1" => position_sparse_node(sibling, root, level),
            _ => {
                return Err(ProtocolError::Crypto(
                    "liquidity position sparse direction must be zero or one".into(),
                ));
            }
        };
    }
    Ok(root)
}

fn verify_directions(expected_low: u128, directions: &[String]) -> Result<(), ProtocolError> {
    let mut reconstructed = 0_u128;
    for (level, direction) in directions.iter().enumerate() {
        match normalize_felt_hex(direction)?.as_str() {
            "0x0" => {}
            "0x1" => reconstructed |= 1_u128 << level,
            _ => {
                return Err(ProtocolError::Crypto(
                    "liquidity position sparse direction must be zero or one".into(),
                ));
            }
        }
    }
    if reconstructed != expected_low {
        return Err(ProtocolError::Crypto(
            "liquidity position sparse directions reconstruct another key".into(),
        ));
    }
    Ok(())
}

fn path_is_canonical_empty(path: &[String]) -> Result<bool, ProtocolError> {
    let empty = empty_subtrees();
    if path.len() != LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        return Ok(false);
    }
    path.iter()
        .enumerate()
        .try_fold(true, |all_empty, (level, value)| {
            Ok(all_empty && felt_from_hex_str(&normalize_felt_hex(value)?)? == empty[level])
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AssetId, LIQUIDITY_POSITION_VERSION, LiquidityBandAttribution,
        LiquidityBandFillAttribution, LiquidityPositionBacking, LiquidityPositionCurvePolicy,
        LiquidityPositionFillDelta, LiquidityPositionOracleGuard, LiquidityPositionRotationPolicy,
        NoteCommitment, OrderCommitment, OrderSide, PairId,
        settlement_liquidity_position_transition_root,
    };

    const TEST_LP_AUTHORITY_SECRET: &str = "0x1e240";

    fn position(id: &str, blinding: &str) -> PrivateLiquidityPosition {
        PrivateLiquidityPosition {
            version: LIQUIDITY_POSITION_VERSION,
            position_id: id.into(),
            backing: LiquidityPositionBacking::PrivateReserve,
            status: LiquidityPositionStatus::Active,
            pair_id: PairId("ETH-USDC".into()),
            base_asset_id: AssetId("ETH".into()),
            quote_asset_id: AssetId("USDC".into()),
            owner_authority: liquidity_position_private_authority(TEST_LP_AUTHORITY_SECRET)
                .unwrap(),
            base_reserve: 10_000_000_000_000_000_000,
            quote_reserve: 25_000_000_000,
            price_lower_bound: 2_000_000_000,
            price_upper_bound: 3_000_000_000,
            max_fill_base_per_batch: 1_000_000_000_000_000_000,
            curve_policy: LiquidityPositionCurvePolicy {
                kind: LiquidityPositionCurveKind::InventorySkewed,
                band_count: 5,
                spread_bps: 20,
                target_base_ratio_bps: 5_000,
                inventory_skew_bps: 100,
                max_price_deviation_bps: 500,
            },
            oracle_guard: None,
            rotation_policy: LiquidityPositionRotationPolicy {
                max_price_rotation_bps: 25,
                max_depth_rotation_bps: 25,
                skip_epoch_bps: 0,
            },
            opened_epoch: 10,
            expiry_epoch: 1_000,
            blinding: blinding.into(),
            metadata_commitment: "0x55".into(),
        }
    }

    fn note(asset: &str, amount: u128, owner: &str, nonce: u64) -> Note {
        Note {
            asset_id: AssetId(asset.into()),
            amount,
            owner_public_key: "ab".repeat(32),
            spend_authority: owner.into(),
            withdraw_authority: owner.into(),
            blinding: format!("0x{:x}", 10_000 + nonce),
            nonce,
            metadata_commitment: "0x77".into(),
        }
    }

    fn reward_attribution(
        order_commitment: &str,
        funding_note_ref: &str,
        pair_id: PairId,
        side: OrderSide,
        clearing_price: u128,
        filled_base_amount: u128,
    ) -> LiquidityBandAttribution {
        LiquidityBandAttribution {
            version: 1,
            pair_id,
            order_commitment: OrderCommitment(order_commitment.into()),
            funding_note_ref: NoteCommitment(funding_note_ref.into()),
            side,
            clearing_price,
            filled_base_amount,
            bands: vec![LiquidityBandFillAttribution {
                band_index: 0,
                band_price: clearing_price,
                band_base_amount: filled_base_amount,
                filled_base_amount,
            }],
        }
    }

    fn reward_plaintext(
        batch_id: &str,
        epoch_id: u64,
        liquidity_provider_public_key: &str,
        output_note_commitment: &str,
        attribution: LiquidityBandAttribution,
    ) -> LiquidityAttributionPlaintext {
        LiquidityAttributionPlaintext {
            version: 1,
            batch_id: BatchId(batch_id.into()),
            pair_id: attribution.pair_id.clone(),
            epoch_id,
            liquidity_provider_public_key: liquidity_provider_public_key.into(),
            curve_commitment: "0xabc".into(),
            output_note_commitment: NoteCommitment(output_note_commitment.into()),
            attribution,
        }
    }

    #[test]
    fn active_position_sparse_state_supports_open_replace_and_close() {
        let first = position("0x101", "0x201");
        let second = position("0x102", "0x202");
        let mut state = LiquidityPositionState::new();

        let (empty_root, first_root, open_first) = state.open(&first).expect("open first");
        assert_eq!(empty_root, "0x0");
        assert_eq!(
            verify_liquidity_position_state_update(&empty_root, &open_first).unwrap(),
            first_root
        );
        let (_, two_root, _) = state.open(&second).expect("open second");
        assert_ne!(first_root, two_root);

        let next_first = first
            .apply_fill(
                &LiquidityPositionFillDelta {
                    position_side: OrderSide::Sell,
                    filled_base_amount: 1_000_000_000_000_000_000,
                    quote_amount: 2_500_000_000,
                },
                "0x301",
            )
            .expect("fill");
        let (replace_prior, replace_root, replace) =
            state.replace(&first, &next_first).expect("replace first");
        assert_eq!(replace_prior, two_root);
        assert_eq!(
            verify_liquidity_position_state_update(&replace_prior, &replace).unwrap(),
            replace_root
        );
        let (close_prior, close_root, close) = state.close(&second).expect("close second");
        assert_eq!(
            verify_liquidity_position_state_update(&close_prior, &close).unwrap(),
            close_root
        );
        let (_, empty_again, close_last) = state.close(&next_first).expect("close last");
        assert_eq!(empty_again, "0x0");
        assert_eq!(
            verify_liquidity_position_state_update(&close_root, &close_last).unwrap(),
            "0x0"
        );
    }

    #[test]
    fn active_position_sparse_state_builds_nonempty_insertion_witness() {
        let first = position("0x101", "0x201");
        let second = position("0x102", "0x202");
        let mut expected_state = LiquidityPositionState::new();
        let (_empty_root, first_root, _) = expected_state.open(&first).unwrap();
        let state_service =
            LiquidityPositionState::from_positions(std::slice::from_ref(&first)).unwrap();

        let second_commitment = second.commitment().unwrap();
        let (prior_root, new_root, update) = state_service
            .insertion_update(&second.position_id, second_commitment.clone())
            .expect("non-empty insertion witness");

        assert_eq!(prior_root, first_root);
        assert_eq!(update.prior_commitment, None);
        assert_eq!(update.output_commitment, Some(second_commitment));
        let (_, expected_new_root, _) = expected_state.open(&second).unwrap();
        assert_eq!(new_root, expected_new_root);
        assert_eq!(
            verify_liquidity_position_state_update(&first_root, &update).unwrap(),
            expected_new_root
        );
    }

    #[test]
    fn active_position_sparse_state_builds_replacement_and_removal_witnesses() {
        let first = position("0x101", "0x201");
        let second = position("0x102", "0x202");
        let next_first = first
            .apply_fill(
                &LiquidityPositionFillDelta {
                    position_side: OrderSide::Sell,
                    filled_base_amount: 1_000,
                    quote_amount: 2_500,
                },
                "0x301",
            )
            .expect("fill");
        let mut expected_state =
            LiquidityPositionState::from_positions(&[first.clone(), second.clone()]).unwrap();
        let prior_root = expected_state.root().unwrap();
        let service = LiquidityPositionState::from_positions(&[first.clone(), second.clone()])
            .expect("state service");

        let (replacement_prior_root, replacement_root, replacement_update) = service
            .replacement_update(
                &first.position_id,
                first.commitment().unwrap(),
                next_first.commitment().unwrap(),
            )
            .expect("replacement witness");
        let (_, expected_replacement_root, _) =
            expected_state.replace(&first, &next_first).unwrap();

        assert_eq!(replacement_prior_root, prior_root);
        assert_eq!(replacement_root, expected_replacement_root);
        assert_eq!(
            verify_liquidity_position_state_update(&prior_root, &replacement_update).unwrap(),
            expected_replacement_root
        );

        let removal_service =
            LiquidityPositionState::from_positions(&[next_first.clone(), second.clone()])
                .expect("replacement state service");
        let (removal_prior_root, removal_root, removal_update) = removal_service
            .removal_update(&second.position_id, second.commitment().unwrap())
            .expect("removal witness");
        let (_, expected_removal_root, _) = expected_state.close(&second).unwrap();

        assert_eq!(removal_prior_root, expected_replacement_root);
        assert_eq!(removal_root, expected_removal_root);
        assert_eq!(
            verify_liquidity_position_state_update(&expected_replacement_root, &removal_update)
                .unwrap(),
            expected_removal_root
        );
    }

    #[test]
    fn active_position_sparse_state_rejects_stale_lifecycle_witness_inputs() {
        let first = position("0x101", "0x201");
        let second = position("0x102", "0x202");
        let state = LiquidityPositionState::from_positions(std::slice::from_ref(&first)).unwrap();

        let wrong_commitment = second.commitment().unwrap();
        assert!(
            state
                .replacement_update(
                    &first.position_id,
                    wrong_commitment.clone(),
                    first.commitment().unwrap(),
                )
                .unwrap_err()
                .to_string()
                .contains("prior commitment")
        );
        assert!(
            state
                .removal_update(&first.position_id, wrong_commitment)
                .unwrap_err()
                .to_string()
                .contains("prior commitment")
        );
        assert!(
            state
                .replacement_update(
                    &second.position_id,
                    second.commitment().unwrap(),
                    first.commitment().unwrap(),
                )
                .unwrap_err()
                .to_string()
                .contains("absent")
        );
    }

    #[test]
    fn state_update_rejects_a_mutated_prior_commitment() {
        let first = position("0x101", "0x201");
        let second = position("0x102", "0x202");
        let mut state = LiquidityPositionState::from_positions(&[first]).unwrap();
        let (prior_root, _, mut update) = state.open(&second).unwrap();
        update.prior_commitment = Some(LiquidityPositionCommitment("0x123".into()));
        assert!(verify_liquidity_position_state_update(&prior_root, &update).is_err());
    }

    #[test]
    fn curve_slice_is_deterministic_reserve_bounded_and_two_sided() {
        let position = position("0x101", "0x201");
        let context = LiquidityPositionMarketContext {
            epoch: 20,
            observed_at_unix_ms: 1_000,
            current_time_unix_ms: 1_001,
            reference_price: 2_500_000_000,
            confirmation_price: None,
            price_base_scale: 1_000_000_000_000_000_000,
        };
        let first = derive_liquidity_position_curve_slice(&position, &context).unwrap();
        let second = derive_liquidity_position_curve_slice(&position, &context).unwrap();
        assert_eq!(first, second);
        assert!(!first.skipped);
        let bid = first.bid.expect("bid");
        let ask = first.ask.expect("ask");
        assert!(bid.total_base_amount().unwrap() <= position.max_fill_base_per_batch);
        assert!(ask.total_base_amount().unwrap() <= position.max_fill_base_per_batch);
        assert!(bid.points.last().unwrap().price < ask.points.first().unwrap().price);
    }

    #[test]
    fn open_and_close_require_asset_conservation_and_owner_authorizations() {
        let position = position("0x101", "0x201");
        let owner = position.owner_authority.clone();
        let commitment = position.commitment().unwrap();
        let open_auth = sign_liquidity_position_transition(
            TEST_LP_AUTHORITY_SECRET,
            LiquidityPositionTransitionKind::Open,
            &position.position_id,
            None,
            Some(&commitment),
            position.opened_epoch,
            0,
            0,
        )
        .unwrap();
        let funding = LiquidityPositionOpenFunding {
            input_notes: vec![
                note("ETH", position.base_reserve, &owner, 1),
                note("USDC", position.quote_reserve + 10, &owner, 2),
            ],
            change_notes: vec![note("USDC", 10, &owner, 3)],
            authorization: open_auth,
        };
        open_liquidity_position(&position, &funding).unwrap();

        let close_base = position.base_reserve;
        let close_quote = position.quote_reserve;
        let close_auth = sign_liquidity_position_transition(
            TEST_LP_AUTHORITY_SECRET,
            LiquidityPositionTransitionKind::Close,
            &position.position_id,
            Some(&commitment),
            None,
            30,
            close_base,
            close_quote,
        )
        .unwrap();
        close_liquidity_position(
            &position,
            30,
            vec![
                note("ETH", close_base, &owner, 4),
                note("USDC", close_quote, &owner, 5),
            ],
            &close_auth,
        )
        .unwrap();
    }

    #[test]
    fn canonical_transition_witness_verifies_open_and_auction_fill() {
        let position = position("0x101", "0x201");
        let owner = position.owner_authority.clone();
        let open_transition = liquidity_position_root_transition(
            LiquidityPositionTransitionKind::Open,
            None,
            Some(&position),
        )
        .unwrap();
        let open_auth = sign_liquidity_position_transition(
            TEST_LP_AUTHORITY_SECRET,
            LiquidityPositionTransitionKind::Open,
            &position.position_id,
            None,
            open_transition.output_position_commitment.as_ref(),
            position.opened_epoch,
            0,
            0,
        )
        .unwrap();
        let open_funding = LiquidityPositionOpenFunding {
            input_notes: vec![
                note("ETH", position.base_reserve, &owner, 1),
                note("USDC", position.quote_reserve, &owner, 2),
            ],
            change_notes: vec![],
            authorization: open_auth,
        };
        let mut state = LiquidityPositionState::new();
        let (empty_root, position_root, open_update) = state.open(&position).unwrap();
        let open_witness = LiquidityPositionTransitionWitness {
            transition: open_transition,
            prior_position: None,
            output_position: Some(position.clone()),
            state_update: open_update,
            epoch: position.opened_epoch,
            fill: None,
            open_funding: Some(open_funding),
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        };
        assert_eq!(
            verify_liquidity_position_transition_witness(&empty_root, &open_witness)
                .unwrap()
                .new_root,
            position_root
        );

        let market_context = LiquidityPositionMarketContext {
            epoch: 20,
            observed_at_unix_ms: 1_000,
            current_time_unix_ms: 1_001,
            reference_price: 2_500_000_000,
            confirmation_price: None,
            price_base_scale: 1_000_000_000_000_000_000,
        };
        let slice = derive_liquidity_position_curve_slice(&position, &market_context).unwrap();
        let ask = slice.ask.unwrap();
        let clearing_price = ask.points[0].price;
        let filled_base_amount = ask.points[0].base_amount;
        let (next, _) = apply_liquidity_position_fill(
            &position,
            OrderSide::Sell,
            filled_base_amount,
            clearing_price,
            market_context.price_base_scale,
            "0x301",
        )
        .unwrap();
        let fill_transition = liquidity_position_root_transition(
            LiquidityPositionTransitionKind::Update,
            Some(&position),
            Some(&next),
        )
        .unwrap();
        let (prior_root, next_root, fill_update) = state.replace(&position, &next).unwrap();
        let fill_witness = LiquidityPositionTransitionWitness {
            transition: fill_transition,
            prior_position: Some(position),
            output_position: Some(next),
            state_update: fill_update,
            epoch: market_context.epoch,
            fill: Some(LiquidityPositionSettlementFill {
                market_context: market_context.clone(),
                position_side: OrderSide::Sell,
                filled_base_amount,
                clearing_price,
                price_base_scale: market_context.price_base_scale,
            }),
            open_funding: None,
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        };
        let verified =
            verify_liquidity_position_transition_witness(&prior_root, &fill_witness).unwrap();
        assert_eq!(verified.new_root, next_root);
        assert_eq!(verified.position_side, Some(OrderSide::Sell));
        assert_eq!(verified.filled_base_amount, filled_base_amount);

        let expected_transition_root = settlement_liquidity_position_transition_root(&[
            open_witness.transition.clone(),
            fill_witness.transition.clone(),
        ])
        .unwrap();
        let proof = verify_liquidity_position_proof_witness(&LiquidityPositionProofWitness {
            prior_root: empty_root,
            transitions: vec![open_witness, fill_witness],
        })
        .unwrap();
        assert_eq!(proof.new_root, next_root);
        assert_eq!(proof.transition_count, 2);
        assert_eq!(proof.sell_filled_base_amount, filled_base_amount);
        assert_eq!(proof.buy_filled_base_amount, 0);
        assert_eq!(proof.transition_root, expected_transition_root);
    }

    #[test]
    fn canonical_transition_witness_rejects_fill_beyond_derived_curve() {
        let position = position("0x101", "0x201");
        let market_context = LiquidityPositionMarketContext {
            epoch: 20,
            observed_at_unix_ms: 1_000,
            current_time_unix_ms: 1_001,
            reference_price: 2_500_000_000,
            confirmation_price: None,
            price_base_scale: 1_000_000_000_000_000_000,
        };
        let slice = derive_liquidity_position_curve_slice(&position, &market_context).unwrap();
        let ask = slice.ask.unwrap();
        let clearing_price = ask.points[0].price;
        let capacity = curve_capacity_at_price(&ask, &OrderSide::Sell, clearing_price).unwrap();
        let impossible_fill = capacity + 1;
        let mut next = position.clone();
        next.blinding = "0x301".into();
        let mut state =
            LiquidityPositionState::from_positions(std::slice::from_ref(&position)).unwrap();
        let (prior_root, _, update) = state.replace(&position, &next).unwrap();
        let witness = LiquidityPositionTransitionWitness {
            transition: liquidity_position_root_transition(
                LiquidityPositionTransitionKind::Update,
                Some(&position),
                Some(&next),
            )
            .unwrap(),
            prior_position: Some(position),
            output_position: Some(next),
            state_update: update,
            epoch: market_context.epoch,
            fill: Some(LiquidityPositionSettlementFill {
                market_context: market_context.clone(),
                position_side: OrderSide::Sell,
                filled_base_amount: impossible_fill,
                clearing_price,
                price_base_scale: market_context.price_base_scale,
            }),
            open_funding: None,
            output_notes: vec![],
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        };
        assert!(
            verify_liquidity_position_transition_witness(&prior_root, &witness)
                .unwrap_err()
                .to_string()
                .contains("capacity")
        );
    }

    #[test]
    fn fill_requires_fresh_blinding() {
        let position = position("0x101", "0x201");
        let error = position
            .apply_fill(
                &LiquidityPositionFillDelta {
                    position_side: OrderSide::Sell,
                    filled_base_amount: 1,
                    quote_amount: 2,
                },
                &position.blinding,
            )
            .unwrap_err();
        assert!(error.to_string().contains("fresh"));
    }

    #[test]
    fn canonical_fill_derives_quote_without_additive_fee() {
        let position = position("0x101", "0x201");
        let (next, delta) = apply_liquidity_position_fill(
            &position,
            OrderSide::Sell,
            1_000_000_000_000_000_000,
            2_500_000_000,
            1_000_000_000_000_000_000,
            "0x301",
        )
        .unwrap();

        assert_eq!(delta.quote_amount, 2_500_000_000);
        assert_eq!(
            next.quote_reserve,
            position.quote_reserve + delta.quote_amount
        );
    }

    #[test]
    fn standard_reward_assessment_pays_full_rebate_for_tight_lp_edge() {
        let attribution = reward_attribution(
            "0x11",
            "0x22",
            PairId("ETH/USDC".into()),
            OrderSide::Sell,
            2_500_750_000,
            1_000_000_000_000_000_000,
        );

        let assessment = assess_liquidity_reward(
            &attribution,
            2_500_000_000,
            1_000_000_000_000_000_000,
            &LiquidityRewardPolicy::standard_pair(),
        )
        .unwrap();

        assert_eq!(assessment.edge_bps_x100, 300);
        assert_eq!(assessment.quality_bps, 10_000);
        assert_eq!(assessment.rebate_bps_x100, 150);
        assert_eq!(assessment.filled_quote_amount, 2_500_750_000);
        assert_eq!(assessment.rebate_quote_amount, 375_112);
    }

    #[test]
    fn conversion_reward_assessment_decays_rebate_for_wider_edge() {
        let attribution = reward_attribution(
            "0x33",
            "0x44",
            PairId("USDC/USDT".into()),
            OrderSide::Buy,
            999_940,
            100_000_000_000,
        );

        let assessment = assess_liquidity_reward(
            &attribution,
            1_000_000,
            1_000_000,
            &LiquidityRewardPolicy::conversion_pair(),
        )
        .unwrap();

        assert_eq!(assessment.edge_bps_x100, 60);
        assert_eq!(assessment.quality_bps, 7_500);
        assert_eq!(assessment.rebate_bps_x100, 30);
        assert_eq!(assessment.filled_quote_amount, 99_994_000_000);
        assert_eq!(assessment.rebate_quote_amount, 2_999_820);
    }

    #[test]
    fn reward_epoch_root_is_order_independent_over_signed_attribution_entries() {
        let first_plaintext = reward_plaintext(
            "batch-reward-a",
            42,
            "lp-key-a",
            "0x51",
            reward_attribution(
                "0x101",
                "0x201",
                PairId("ETH/USDC".into()),
                OrderSide::Sell,
                2_500_750_000,
                1_000_000_000_000_000_000,
            ),
        );
        let second_plaintext = reward_plaintext(
            "batch-reward-b",
            42,
            "lp-key-b",
            "0x52",
            reward_attribution(
                "0x102",
                "0x202",
                PairId("ETH/USDC".into()),
                OrderSide::Buy,
                2_499_250_000,
                1_000_000_000_000_000_000,
            ),
        );
        let first = build_liquidity_reward_entry(
            &first_plaintext,
            AssetId("USDC".into()),
            2_500_000_000,
            1_000_000_000_000_000_000,
            &LiquidityRewardPolicy::standard_pair(),
        )
        .unwrap();
        let second = build_liquidity_reward_entry(
            &second_plaintext,
            AssetId("USDC".into()),
            2_500_000_000,
            1_000_000_000_000_000_000,
            &LiquidityRewardPolicy::standard_pair(),
        )
        .unwrap();

        let forward = build_liquidity_reward_epoch(42, &[first.clone(), second.clone()]).unwrap();
        let reverse = build_liquidity_reward_epoch(42, &[second, first]).unwrap();

        assert_eq!(forward.reward_root, reverse.reward_root);
        assert_eq!(forward.entries[0].batch_id.0, "batch-reward-a");
        assert_eq!(forward.entries[1].batch_id.0, "batch-reward-b");
        assert_eq!(forward.entries[0].reward_amount, 375_112);
    }

    #[test]
    fn oracle_guard_rejects_stale_and_divergent_market_contexts() {
        let mut position = position("0x101", "0x201");
        position.curve_policy.kind = LiquidityPositionCurveKind::OraclePegged;
        position.oracle_guard = Some(LiquidityPositionOracleGuard {
            oracle_id: "pragma-eth-usdc".into(),
            max_staleness_ms: 1_000,
            max_divergence_bps: 50,
        });
        let stale = LiquidityPositionMarketContext {
            epoch: 20,
            observed_at_unix_ms: 1_000,
            current_time_unix_ms: 2_001,
            reference_price: 2_500_000_000,
            confirmation_price: Some(2_500_000_000),
            price_base_scale: 1_000_000_000_000_000_000,
        };
        assert!(
            derive_liquidity_position_curve_slice(&position, &stale)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );

        let divergent = LiquidityPositionMarketContext {
            current_time_unix_ms: 1_500,
            confirmation_price: Some(2_450_000_000),
            ..stale
        };
        assert!(
            derive_liquidity_position_curve_slice(&position, &divergent)
                .unwrap_err()
                .to_string()
                .contains("diverge")
        );
    }

    #[test]
    fn position_commitment_matches_cairo_vector() {
        let position = position("0x101", "0x201");
        assert_eq!(
            position.commitment().unwrap().0,
            "0x419df9b341d3ed21b80239329b06eff0968a48ec181286e520435fcde3643cc"
        );
    }
}

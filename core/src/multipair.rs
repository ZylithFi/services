use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    ProtocolError,
    hash::{field_from_u64, normalize_felt_hex},
    types::{AssetId, BatchId, OrderCommitment, OrderSide, PairId, quote_amount_for_base_amount},
};

pub const MAX_MULTI_PAIR_FILLS: usize = 64;
pub const MAX_MULTI_PAIR_ASSETS: usize = 8;
pub const MAX_MULTI_PAIR_ASSET_DELTAS: usize = 256;
pub const MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS: usize = 64;

type AssetTotals = BTreeMap<String, u128>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiPairAssetDeltaDirection {
    In,
    Out,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiPairAssetDeltaSource {
    User,
    LiquidityPosition,
    ProtocolBackstop,
    Fee,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairAssetDelta {
    pub asset_id: AssetId,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub amount: u128,
    pub direction: MultiPairAssetDeltaDirection,
    pub source: MultiPairAssetDeltaSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_commitment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairFill {
    pub order_commitment: OrderCommitment,
    pub pair_id: PairId,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub side: OrderSide,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub submitted_base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub min_fill_base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub limit_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub price_base_scale: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub filled_base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub quote_amount: u128,
    #[serde(default, with = "crate::types::serde_u128_decimal")]
    pub fee_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairFeasibilityProblem {
    pub batch_id: BatchId,
    pub fills: Vec<MultiPairFill>,
    pub asset_deltas: Vec<MultiPairAssetDelta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairFeasibilityReport {
    pub batch_id: BatchId,
    pub fill_count: usize,
    pub asset_count: usize,
    #[serde(with = "crate::multipair::serde_btreemap_u128_decimal")]
    pub asset_inputs: BTreeMap<String, u128>,
    #[serde(with = "crate::multipair::serde_btreemap_u128_decimal")]
    pub asset_outputs: BTreeMap<String, u128>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairObjectiveWeight {
    pub asset_id: AssetId,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub numerator: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub denominator: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairCandidateSolution {
    pub solution_id: String,
    pub fills: Vec<MultiPairFill>,
    pub asset_deltas: Vec<MultiPairAssetDelta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairOptimalityProblem {
    pub chosen: MultiPairFeasibilityProblem,
    pub eligible_order_commitments: Vec<OrderCommitment>,
    pub objective_weights: Vec<MultiPairObjectiveWeight>,
    pub candidate_solutions: Vec<MultiPairCandidateSolution>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairOptimalityReport {
    pub feasibility: MultiPairFeasibilityReport,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub chosen_objective: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub best_candidate_objective: u128,
    pub candidate_count: usize,
    pub objective_asset_count: usize,
}

pub fn verify_multi_pair_feasibility(
    problem: &MultiPairFeasibilityProblem,
) -> Result<MultiPairFeasibilityReport, ProtocolError> {
    validate_problem_shape(problem)?;
    validate_fills(&problem.fills)?;
    validate_bound_asset_deltas(&problem.fills, &problem.asset_deltas)?;
    let (asset_inputs, asset_outputs) = aggregate_asset_deltas(&problem.asset_deltas)?;
    assert_asset_conservation(&asset_inputs, &asset_outputs)?;

    Ok(MultiPairFeasibilityReport {
        batch_id: problem.batch_id.clone(),
        fill_count: problem.fills.len(),
        asset_count: asset_inputs.len(),
        asset_inputs,
        asset_outputs,
    })
}

pub fn verify_multi_pair_optimality(
    problem: &MultiPairOptimalityProblem,
) -> Result<MultiPairOptimalityReport, ProtocolError> {
    let feasibility = verify_multi_pair_feasibility(&problem.chosen)?;
    validate_candidate_shape(problem)?;
    let eligible = normalized_commitment_set(&problem.eligible_order_commitments)?;
    assert_fills_are_eligible(&problem.chosen.fills, &eligible, "chosen multi-pair fill")?;
    let objective_weights = validate_objective_weights(&problem.objective_weights)?;
    let chosen_objective = score_multi_pair_solution(&problem.chosen.fills, &objective_weights)?;
    let mut best_candidate_objective = chosen_objective;

    for (index, candidate) in problem.candidate_solutions.iter().enumerate() {
        if candidate.solution_id.trim().is_empty() {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair candidate {index} requires a solution id"
            )));
        }
        assert_fills_are_eligible(&candidate.fills, &eligible, "candidate multi-pair fill")?;
        verify_multi_pair_feasibility(&MultiPairFeasibilityProblem {
            batch_id: problem.chosen.batch_id.clone(),
            fills: candidate.fills.clone(),
            asset_deltas: candidate.asset_deltas.clone(),
        })?;
        let candidate_objective = score_multi_pair_solution(&candidate.fills, &objective_weights)?;
        if candidate_objective > chosen_objective {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair candidate {} beats chosen objective",
                candidate.solution_id
            )));
        }
        if candidate_objective > best_candidate_objective {
            best_candidate_objective = candidate_objective;
        }
    }

    Ok(MultiPairOptimalityReport {
        feasibility,
        chosen_objective,
        best_candidate_objective,
        candidate_count: problem.candidate_solutions.len(),
        objective_asset_count: objective_weights.len(),
    })
}

fn validate_candidate_shape(problem: &MultiPairOptimalityProblem) -> Result<(), ProtocolError> {
    if problem.eligible_order_commitments.is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair optimality requires eligible order commitments".into(),
        ));
    }
    if problem.candidate_solutions.is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair optimality requires candidate solutions".into(),
        ));
    }
    if problem.candidate_solutions.len() > MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair candidate solution count {} exceeds maximum {}",
            problem.candidate_solutions.len(),
            MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS
        )));
    }
    Ok(())
}

fn normalized_commitment_set(
    commitments: &[OrderCommitment],
) -> Result<BTreeSet<String>, ProtocolError> {
    let mut normalized = BTreeSet::new();
    for (index, commitment) in commitments.iter().enumerate() {
        let value = normalize_felt_hex(&commitment.0)?;
        if value == crate::hash::felt_hex(&field_from_u64(0)) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair eligible order {index} has a zero commitment"
            )));
        }
        if !normalized.insert(value) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair eligible order {index} duplicates a commitment"
            )));
        }
    }
    Ok(normalized)
}

fn assert_fills_are_eligible(
    fills: &[MultiPairFill],
    eligible: &BTreeSet<String>,
    label: &str,
) -> Result<(), ProtocolError> {
    for (index, fill) in fills.iter().enumerate() {
        let commitment = normalize_felt_hex(&fill.order_commitment.0)?;
        if !eligible.contains(&commitment) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "{label} {index} is not in the eligible order set"
            )));
        }
    }
    Ok(())
}

fn validate_objective_weights(
    weights: &[MultiPairObjectiveWeight],
) -> Result<BTreeMap<String, (u128, u128)>, ProtocolError> {
    if weights.is_empty() || weights.len() > MAX_MULTI_PAIR_ASSETS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair objective weight count must be between 1 and {MAX_MULTI_PAIR_ASSETS}"
        )));
    }
    let mut normalized = BTreeMap::new();
    for (index, weight) in weights.iter().enumerate() {
        if weight.asset_id.0.trim().is_empty() {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair objective weight {index} has no asset id"
            )));
        }
        if weight.numerator == 0 || weight.denominator == 0 {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair objective weight {index} must be positive"
            )));
        }
        if normalized
            .insert(
                weight.asset_id.0.clone(),
                (weight.numerator, weight.denominator),
            )
            .is_some()
        {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair objective weight {index} duplicates an asset"
            )));
        }
    }
    Ok(normalized)
}

fn score_multi_pair_solution(
    fills: &[MultiPairFill],
    weights: &BTreeMap<String, (u128, u128)>,
) -> Result<u128, ProtocolError> {
    let mut score = 0_u128;
    for (index, fill) in fills.iter().enumerate() {
        let (output_asset, gross_output_amount) = match fill.side {
            OrderSide::Buy => (&fill.base_asset_id, fill.filled_base_amount),
            OrderSide::Sell => (&fill.quote_asset_id, fill.quote_amount),
        };
        let net_output_amount = gross_output_amount
            .checked_sub(fill.fee_amount)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(format!(
                    "multi-pair fill {index} fee exceeds output"
                ))
            })?;
        let (numerator, denominator) = weights.get(&output_asset.0).copied().ok_or_else(|| {
            ProtocolError::InvalidSettlementProof(format!(
                "multi-pair fill {index} output asset {} has no objective weight",
                output_asset.0
            ))
        })?;
        let weighted = net_output_amount.checked_mul(numerator).ok_or_else(|| {
            ProtocolError::InvalidSettlementProof(format!(
                "multi-pair fill {index} objective overflows"
            ))
        })? / denominator;
        score = score.checked_add(weighted).ok_or_else(|| {
            ProtocolError::InvalidSettlementProof("multi-pair objective overflows".into())
        })?;
    }
    Ok(score)
}

fn validate_problem_shape(problem: &MultiPairFeasibilityProblem) -> Result<(), ProtocolError> {
    if problem.batch_id.0.trim().is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair feasibility requires a batch id".into(),
        ));
    }
    if problem.fills.is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair feasibility requires at least one fill".into(),
        ));
    }
    if problem.fills.len() > MAX_MULTI_PAIR_FILLS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill count {} exceeds maximum {}",
            problem.fills.len(),
            MAX_MULTI_PAIR_FILLS
        )));
    }
    if problem.asset_deltas.is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair feasibility requires asset deltas".into(),
        ));
    }
    if problem.asset_deltas.len() > MAX_MULTI_PAIR_ASSET_DELTAS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair asset delta count {} exceeds maximum {}",
            problem.asset_deltas.len(),
            MAX_MULTI_PAIR_ASSET_DELTAS
        )));
    }
    Ok(())
}

fn validate_fills(fills: &[MultiPairFill]) -> Result<(), ProtocolError> {
    let mut seen_commitments = BTreeSet::new();
    for (index, fill) in fills.iter().enumerate() {
        let commitment = normalize_felt_hex(&fill.order_commitment.0)?;
        if commitment == crate::hash::felt_hex(&field_from_u64(0)) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair fill {index} has zero order commitment"
            )));
        }
        if !seen_commitments.insert(commitment) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair fill {index} duplicates an order commitment"
            )));
        }
        validate_fill_bounds(index, fill)?;
    }
    Ok(())
}

fn validate_fill_bounds(index: usize, fill: &MultiPairFill) -> Result<(), ProtocolError> {
    if fill.pair_id.0.trim().is_empty()
        || fill.base_asset_id.0.trim().is_empty()
        || fill.quote_asset_id.0.trim().is_empty()
    {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill {index} has incomplete pair metadata"
        )));
    }
    if fill.base_asset_id == fill.quote_asset_id {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill {index} uses identical base and quote assets"
        )));
    }
    if fill.submitted_base_amount == 0 || fill.filled_base_amount == 0 || fill.quote_amount == 0 {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill {index} amounts must be positive"
        )));
    }
    if fill.min_fill_base_amount > fill.submitted_base_amount {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill {index} min fill exceeds submitted amount"
        )));
    }
    if fill.filled_base_amount > fill.submitted_base_amount {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill {index} exceeds submitted amount"
        )));
    }
    if fill.filled_base_amount < fill.min_fill_base_amount {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill {index} violates min fill"
        )));
    }
    if fill.limit_price == 0 || fill.price_base_scale == 0 {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill {index} has invalid price bounds"
        )));
    }
    let gross_output_amount = match fill.side {
        OrderSide::Buy => fill.filled_base_amount,
        OrderSide::Sell => fill.quote_amount,
    };
    if fill.fee_amount >= gross_output_amount {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill {index} fee consumes its output"
        )));
    }

    let limit_quote_amount = quote_amount_for_base_amount(
        fill.filled_base_amount,
        fill.limit_price,
        fill.price_base_scale,
    )?;
    match fill.side {
        OrderSide::Buy => {
            if fill.quote_amount > limit_quote_amount {
                return Err(ProtocolError::InvalidSettlementProof(format!(
                    "multi-pair buy fill {index} exceeds max price"
                )));
            }
        }
        OrderSide::Sell => {
            if fill.quote_amount < limit_quote_amount {
                return Err(ProtocolError::InvalidSettlementProof(format!(
                    "multi-pair sell fill {index} is below min price"
                )));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BoundAssetDeltaKey {
    source_commitment: String,
    asset_id: String,
    direction: u8,
}

fn validate_bound_asset_deltas(
    fills: &[MultiPairFill],
    asset_deltas: &[MultiPairAssetDelta],
) -> Result<(), ProtocolError> {
    let mut expected_user = BTreeMap::new();
    let mut expected_fees = BTreeMap::new();
    for fill in fills {
        let commitment = normalize_felt_hex(&fill.order_commitment.0)?;
        let (input_asset, input_amount, output_asset, gross_output_amount) = match fill.side {
            OrderSide::Buy => (
                &fill.quote_asset_id,
                fill.quote_amount,
                &fill.base_asset_id,
                fill.filled_base_amount,
            ),
            OrderSide::Sell => (
                &fill.base_asset_id,
                fill.filled_base_amount,
                &fill.quote_asset_id,
                fill.quote_amount,
            ),
        };
        add_bound_delta(
            &mut expected_user,
            &commitment,
            &input_asset.0,
            MultiPairAssetDeltaDirection::In,
            input_amount,
        )?;
        add_bound_delta(
            &mut expected_user,
            &commitment,
            &output_asset.0,
            MultiPairAssetDeltaDirection::Out,
            gross_output_amount - fill.fee_amount,
        )?;
        if fill.fee_amount > 0 {
            add_bound_delta(
                &mut expected_fees,
                &commitment,
                &output_asset.0,
                MultiPairAssetDeltaDirection::Out,
                fill.fee_amount,
            )?;
        }
    }

    let mut actual_user = BTreeMap::new();
    let mut actual_fees = BTreeMap::new();
    for (index, delta) in asset_deltas.iter().enumerate() {
        let commitment = delta
            .source_commitment
            .as_deref()
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(format!(
                    "multi-pair asset delta {index} is missing its source commitment"
                ))
            })
            .and_then(normalize_felt_hex)?;
        if commitment == crate::hash::felt_hex(&field_from_u64(0)) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair asset delta {index} has a zero source commitment"
            )));
        }
        match delta.source {
            MultiPairAssetDeltaSource::User => add_bound_delta(
                &mut actual_user,
                &commitment,
                &delta.asset_id.0,
                delta.direction.clone(),
                delta.amount,
            )?,
            MultiPairAssetDeltaSource::Fee => add_bound_delta(
                &mut actual_fees,
                &commitment,
                &delta.asset_id.0,
                delta.direction.clone(),
                delta.amount,
            )?,
            MultiPairAssetDeltaSource::LiquidityPosition
            | MultiPairAssetDeltaSource::ProtocolBackstop => {}
        }
    }

    if actual_user != expected_user {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair user asset deltas do not match the declared fills".into(),
        ));
    }
    if actual_fees != expected_fees {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair fee asset deltas do not match the declared fills".into(),
        ));
    }
    Ok(())
}

fn add_bound_delta(
    deltas: &mut BTreeMap<BoundAssetDeltaKey, u128>,
    source_commitment: &str,
    asset_id: &str,
    direction: MultiPairAssetDeltaDirection,
    amount: u128,
) -> Result<(), ProtocolError> {
    if amount == 0 {
        return Ok(());
    }
    let key = BoundAssetDeltaKey {
        source_commitment: source_commitment.to_owned(),
        asset_id: asset_id.to_owned(),
        direction: match direction {
            MultiPairAssetDeltaDirection::In => 0,
            MultiPairAssetDeltaDirection::Out => 1,
        },
    };
    let total = deltas.entry(key).or_default();
    *total = total.checked_add(amount).ok_or_else(|| {
        ProtocolError::InvalidSettlementProof("multi-pair bound asset delta total overflows".into())
    })?;
    Ok(())
}

fn aggregate_asset_deltas(
    asset_deltas: &[MultiPairAssetDelta],
) -> Result<(AssetTotals, AssetTotals), ProtocolError> {
    let mut inputs = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    for (index, delta) in asset_deltas.iter().enumerate() {
        if delta.asset_id.0.trim().is_empty() {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair asset delta {index} has no asset id"
            )));
        }
        if delta.amount == 0 {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair asset delta {index} amount must be positive"
            )));
        }
        let map = match delta.direction {
            MultiPairAssetDeltaDirection::In => &mut inputs,
            MultiPairAssetDeltaDirection::Out => &mut outputs,
        };
        let total = map.entry(delta.asset_id.0.clone()).or_insert(0u128);
        *total = total.checked_add(delta.amount).ok_or_else(|| {
            ProtocolError::InvalidSettlementProof(format!(
                "multi-pair asset delta {index} overflows asset total"
            ))
        })?;
    }
    if inputs.len() > MAX_MULTI_PAIR_ASSETS || outputs.len() > MAX_MULTI_PAIR_ASSETS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair asset count exceeds maximum {MAX_MULTI_PAIR_ASSETS}"
        )));
    }
    Ok((inputs, outputs))
}

fn assert_asset_conservation(
    inputs: &BTreeMap<String, u128>,
    outputs: &BTreeMap<String, u128>,
) -> Result<(), ProtocolError> {
    for (asset_id, input_amount) in inputs {
        let output_amount = outputs.get(asset_id).copied().unwrap_or(0);
        if output_amount != *input_amount {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair asset {asset_id} is not conserved"
            )));
        }
    }
    for asset_id in outputs.keys() {
        if !inputs.contains_key(asset_id) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair asset {asset_id} has output without input"
            )));
        }
    }
    Ok(())
}

pub(crate) mod serde_btreemap_u128_decimal {
    use std::collections::BTreeMap;

    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &BTreeMap<String, u128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(value.len()))?;
        for (key, amount) in value {
            map.serialize_entry(key, &amount.to_string())?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<String, u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = BTreeMap::<String, String>::deserialize(deserializer)?;
        raw.into_iter()
            .map(|(key, value)| {
                let amount = value
                    .parse::<u128>()
                    .map_err(|error| serde::de::Error::custom(format!("invalid u128: {error}")))?;
                Ok((key, amount))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MultiPairAssetDelta, MultiPairAssetDeltaDirection, MultiPairAssetDeltaSource,
        MultiPairCandidateSolution, MultiPairFeasibilityProblem, MultiPairFill,
        MultiPairObjectiveWeight, MultiPairOptimalityProblem, verify_multi_pair_feasibility,
        verify_multi_pair_optimality,
    };
    use crate::{AssetId, BatchId, OrderCommitment, OrderSide, PairId};

    #[test]
    fn accepts_feasible_three_asset_cycle() {
        let problem = MultiPairFeasibilityProblem {
            batch_id: BatchId("epoch-42".into()),
            fills: vec![
                buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 50_000, 5_000),
                sell("0x2", "ETH/STRK", "ETH", "STRK", 10, 50_000, 5_000),
                sell("0x3", "STRK/USDC", "STRK", "USDC", 50_000, 50_000, 1),
            ],
            asset_deltas: vec![
                user_delta("0x1", "USDC", 50_000, MultiPairAssetDeltaDirection::In),
                user_delta("0x2", "ETH", 10, MultiPairAssetDeltaDirection::In),
                user_delta("0x3", "STRK", 50_000, MultiPairAssetDeltaDirection::In),
                user_delta("0x1", "ETH", 10, MultiPairAssetDeltaDirection::Out),
                user_delta("0x2", "STRK", 50_000, MultiPairAssetDeltaDirection::Out),
                user_delta("0x3", "USDC", 50_000, MultiPairAssetDeltaDirection::Out),
            ],
        };

        let report = verify_multi_pair_feasibility(&problem).expect("feasible cycle");

        assert_eq!(report.fill_count, 3);
        assert_eq!(report.asset_count, 3);
        assert_eq!(report.asset_inputs.get("USDC"), Some(&50_000));
        assert_eq!(report.asset_outputs.get("STRK"), Some(&50_000));
    }

    #[test]
    fn rejects_non_conserved_asset() {
        let mut problem = simple_buy_problem();
        problem.asset_deltas[2].amount = 9;

        let error = verify_multi_pair_feasibility(&problem).expect_err("must reject");

        assert!(error.to_string().contains("asset ETH is not conserved"));
    }

    #[test]
    fn rejects_buy_above_limit_price() {
        let mut problem = simple_buy_problem();
        problem.fills[0].quote_amount = 25_001;
        problem.asset_deltas[0].amount = 25_001;
        problem.asset_deltas[1].amount = 10;

        let error = verify_multi_pair_feasibility(&problem).expect_err("must reject");

        assert!(error.to_string().contains("exceeds max price"));
    }

    #[test]
    fn rejects_sell_below_limit_price() {
        let problem = MultiPairFeasibilityProblem {
            batch_id: BatchId("epoch-42".into()),
            fills: vec![sell("0x1", "ETH/USDC", "ETH", "USDC", 10, 24_000, 2_500)],
            asset_deltas: vec![
                user_delta("0x1", "ETH", 10, MultiPairAssetDeltaDirection::In),
                user_delta("0x1", "USDC", 24_000, MultiPairAssetDeltaDirection::Out),
                liquidity_delta("0x99", "USDC", 24_000, MultiPairAssetDeltaDirection::In),
                liquidity_delta("0x99", "ETH", 10, MultiPairAssetDeltaDirection::Out),
            ],
        };

        let error = verify_multi_pair_feasibility(&problem).expect_err("must reject");

        assert!(error.to_string().contains("below min price"));
    }

    #[test]
    fn rejects_duplicate_order_commitments_after_normalization() {
        let mut problem = simple_buy_problem();
        problem
            .fills
            .push(buy("0x01", "ETH/USDC", "ETH", "USDC", 1, 2_500, 2_500));

        let error = verify_multi_pair_feasibility(&problem).expect_err("must reject");

        assert!(error.to_string().contains("duplicates an order commitment"));
    }

    #[test]
    fn rejects_balanced_user_deltas_that_are_not_bound_to_the_fill() {
        let mut problem = simple_buy_problem();
        problem.asset_deltas[0].source_commitment = Some("0x2".into());

        let error = verify_multi_pair_feasibility(&problem).expect_err("must reject");

        assert!(
            error
                .to_string()
                .contains("do not match the declared fills")
        );
    }

    #[test]
    fn accepts_output_fees_bound_to_the_originating_fill() {
        let mut problem = simple_buy_problem();
        problem.fills[0].fee_amount = 1;
        problem.asset_deltas[1].amount = 9;
        problem.asset_deltas.insert(
            2,
            delta(
                "0x1",
                "ETH",
                1,
                MultiPairAssetDeltaDirection::Out,
                MultiPairAssetDeltaSource::Fee,
            ),
        );

        let report = verify_multi_pair_feasibility(&problem).expect("fee-bound fill");

        assert_eq!(report.asset_inputs.get("ETH"), Some(&10));
        assert_eq!(report.asset_outputs.get("ETH"), Some(&10));
    }

    #[test]
    fn accepts_solution_that_beats_declared_multi_pair_candidates() {
        let chosen = MultiPairFeasibilityProblem {
            batch_id: BatchId("epoch-42".into()),
            fills: vec![
                buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 25_000, 2_500),
                sell("0x2", "STRK/USDC", "STRK", "USDC", 10_000, 10_000, 1),
            ],
            asset_deltas: vec![
                user_delta("0x1", "USDC", 25_000, MultiPairAssetDeltaDirection::In),
                user_delta("0x1", "ETH", 10, MultiPairAssetDeltaDirection::Out),
                user_delta("0x2", "STRK", 10_000, MultiPairAssetDeltaDirection::In),
                user_delta("0x2", "USDC", 10_000, MultiPairAssetDeltaDirection::Out),
                liquidity_delta("0x99", "ETH", 10, MultiPairAssetDeltaDirection::In),
                liquidity_delta("0x99", "USDC", 25_000, MultiPairAssetDeltaDirection::Out),
                liquidity_delta("0x9a", "USDC", 10_000, MultiPairAssetDeltaDirection::In),
                liquidity_delta("0x9a", "STRK", 10_000, MultiPairAssetDeltaDirection::Out),
            ],
        };
        let problem = MultiPairOptimalityProblem {
            chosen: chosen.clone(),
            eligible_order_commitments: vec![
                OrderCommitment("0x1".into()),
                OrderCommitment("0x2".into()),
            ],
            objective_weights: objective_weights(),
            candidate_solutions: vec![
                MultiPairCandidateSolution {
                    solution_id: "chosen".into(),
                    fills: chosen.fills.clone(),
                    asset_deltas: chosen.asset_deltas.clone(),
                },
                MultiPairCandidateSolution {
                    solution_id: "eth-only".into(),
                    fills: vec![chosen.fills[0].clone()],
                    asset_deltas: vec![
                        user_delta("0x1", "USDC", 25_000, MultiPairAssetDeltaDirection::In),
                        user_delta("0x1", "ETH", 10, MultiPairAssetDeltaDirection::Out),
                        liquidity_delta("0x99", "ETH", 10, MultiPairAssetDeltaDirection::In),
                        liquidity_delta("0x99", "USDC", 25_000, MultiPairAssetDeltaDirection::Out),
                    ],
                },
            ],
        };

        let report = verify_multi_pair_optimality(&problem).expect("optimal solution");

        assert_eq!(report.chosen_objective, 35_000);
        assert_eq!(report.best_candidate_objective, 35_000);
        assert_eq!(report.candidate_count, 2);
    }

    #[test]
    fn rejects_feasible_candidate_with_better_objective() {
        let chosen = simple_buy_problem();
        let better = MultiPairCandidateSolution {
            solution_id: "double-size".into(),
            fills: vec![buy("0x2", "ETH/USDC", "ETH", "USDC", 20, 50_000, 2_500)],
            asset_deltas: vec![
                user_delta("0x2", "USDC", 50_000, MultiPairAssetDeltaDirection::In),
                user_delta("0x2", "ETH", 20, MultiPairAssetDeltaDirection::Out),
                liquidity_delta("0x99", "ETH", 20, MultiPairAssetDeltaDirection::In),
                liquidity_delta("0x99", "USDC", 50_000, MultiPairAssetDeltaDirection::Out),
            ],
        };
        let problem = MultiPairOptimalityProblem {
            chosen,
            eligible_order_commitments: vec![
                OrderCommitment("0x1".into()),
                OrderCommitment("0x2".into()),
            ],
            objective_weights: objective_weights(),
            candidate_solutions: vec![better],
        };

        let error = verify_multi_pair_optimality(&problem).expect_err("better candidate rejected");

        assert!(error.to_string().contains("beats chosen objective"));
    }

    #[test]
    fn rejects_optimality_without_weight_for_output_asset() {
        let problem = MultiPairOptimalityProblem {
            chosen: simple_buy_problem(),
            eligible_order_commitments: vec![OrderCommitment("0x1".into())],
            objective_weights: vec![MultiPairObjectiveWeight {
                asset_id: AssetId("USDC".into()),
                numerator: 1,
                denominator: 1,
            }],
            candidate_solutions: vec![MultiPairCandidateSolution {
                solution_id: "chosen".into(),
                fills: simple_buy_problem().fills,
                asset_deltas: simple_buy_problem().asset_deltas,
            }],
        };

        let error = verify_multi_pair_optimality(&problem).expect_err("missing weight rejected");

        assert!(error.to_string().contains("has no objective weight"));
    }

    fn simple_buy_problem() -> MultiPairFeasibilityProblem {
        MultiPairFeasibilityProblem {
            batch_id: BatchId("epoch-42".into()),
            fills: vec![buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 25_000, 2_500)],
            asset_deltas: vec![
                user_delta("0x1", "USDC", 25_000, MultiPairAssetDeltaDirection::In),
                user_delta("0x1", "ETH", 10, MultiPairAssetDeltaDirection::Out),
                liquidity_delta("0x99", "ETH", 10, MultiPairAssetDeltaDirection::In),
                liquidity_delta("0x99", "USDC", 25_000, MultiPairAssetDeltaDirection::Out),
            ],
        }
    }

    fn buy(
        commitment: &str,
        pair: &str,
        base: &str,
        quote: &str,
        base_amount: u128,
        quote_amount: u128,
        limit_price: u128,
    ) -> MultiPairFill {
        fill(
            commitment,
            pair,
            (base, quote),
            OrderSide::Buy,
            (base_amount, quote_amount),
            limit_price,
        )
    }

    fn sell(
        commitment: &str,
        pair: &str,
        base: &str,
        quote: &str,
        base_amount: u128,
        quote_amount: u128,
        limit_price: u128,
    ) -> MultiPairFill {
        fill(
            commitment,
            pair,
            (base, quote),
            OrderSide::Sell,
            (base_amount, quote_amount),
            limit_price,
        )
    }

    fn fill(
        commitment: &str,
        pair: &str,
        assets: (&str, &str),
        side: OrderSide,
        amounts: (u128, u128),
        limit_price: u128,
    ) -> MultiPairFill {
        let (base, quote) = assets;
        let (base_amount, quote_amount) = amounts;
        MultiPairFill {
            order_commitment: OrderCommitment(commitment.into()),
            pair_id: PairId(pair.into()),
            base_asset_id: AssetId(base.into()),
            quote_asset_id: AssetId(quote.into()),
            side,
            submitted_base_amount: base_amount,
            min_fill_base_amount: 1,
            limit_price,
            price_base_scale: 1,
            filled_base_amount: base_amount,
            quote_amount,
            fee_amount: 0,
        }
    }

    fn user_delta(
        commitment: &str,
        asset: &str,
        amount: u128,
        direction: MultiPairAssetDeltaDirection,
    ) -> MultiPairAssetDelta {
        delta(
            commitment,
            asset,
            amount,
            direction,
            MultiPairAssetDeltaSource::User,
        )
    }

    fn liquidity_delta(
        commitment: &str,
        asset: &str,
        amount: u128,
        direction: MultiPairAssetDeltaDirection,
    ) -> MultiPairAssetDelta {
        delta(
            commitment,
            asset,
            amount,
            direction,
            MultiPairAssetDeltaSource::LiquidityPosition,
        )
    }

    fn delta(
        commitment: &str,
        asset: &str,
        amount: u128,
        direction: MultiPairAssetDeltaDirection,
        source: MultiPairAssetDeltaSource,
    ) -> MultiPairAssetDelta {
        MultiPairAssetDelta {
            asset_id: AssetId(asset.into()),
            amount,
            direction,
            source,
            source_commitment: Some(commitment.into()),
        }
    }

    fn objective_weights() -> Vec<MultiPairObjectiveWeight> {
        vec![
            MultiPairObjectiveWeight {
                asset_id: AssetId("ETH".into()),
                numerator: 2_500,
                denominator: 1,
            },
            MultiPairObjectiveWeight {
                asset_id: AssetId("USDC".into()),
                numerator: 1,
                denominator: 1,
            },
            MultiPairObjectiveWeight {
                asset_id: AssetId("STRK".into()),
                numerator: 1,
                denominator: 1,
            },
        ]
    }
}

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use serde::{Deserialize, Serialize};

use crate::{
    ProtocolError,
    hash::{field_from_u64, normalize_felt_hex},
    types::{
        AssetId, BatchId, ExecutionPreference, OrderCommitment, OrderSide, PairId,
        base_amount_affordable_for_quote, quote_amount_for_base_amount,
    },
};

pub const MAX_MULTI_PAIR_FILLS: usize = 64;
pub const MAX_MULTI_PAIR_ASSETS: usize = 8;
pub const MAX_MULTI_PAIR_ASSET_DELTAS: usize = 256;
pub const MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS: usize = 64;
pub const DEFAULT_MULTI_PAIR_MAX_CYCLE_LEN: usize = 4;
const MAX_MULTI_PAIR_ROUNDING_SEARCH_STEPS: usize = 4096;
const MAX_MULTI_PAIR_PACKAGE_SEARCH_NODES: usize = 4096;
const MAX_MULTI_PAIR_PACKAGE_CYCLES: usize = 8;

type AssetTotals = BTreeMap<String, u128>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiPairAssetDeltaDirection {
    In,
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiPairAssetDeltaSource {
    User,
    ExternalCompletion,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairExecutableOrder {
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
    pub available_input_amount: u128,
    pub taker_fee_bps: u16,
    pub execution_preference: ExecutionPreference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairNettingConfig {
    pub max_cycle_len: usize,
}

impl Default for MultiPairNettingConfig {
    fn default() -> Self {
        Self {
            max_cycle_len: DEFAULT_MULTI_PAIR_MAX_CYCLE_LEN,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairNettingPlan {
    pub problem: MultiPairOptimalityProblem,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiPairExternalCompletionObligation {
    pub pair_id: PairId,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub side: OrderSide,
    pub input_asset_id: AssetId,
    pub output_asset_id: AssetId,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub input_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub gross_output_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub limit_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub price_base_scale: u128,
    pub order_commitments: Vec<OrderCommitment>,
}

pub fn plan_multi_pair_netting(
    batch_id: BatchId,
    orders: &[MultiPairExecutableOrder],
    objective_weights: Vec<MultiPairObjectiveWeight>,
    config: MultiPairNettingConfig,
) -> Result<Option<MultiPairNettingPlan>, ProtocolError> {
    validate_multi_pair_netting_config(&config)?;
    validate_executable_orders(orders)?;
    let objective_weight_map = validate_objective_weights(&objective_weights)?;
    let graph_candidates = enumerate_multi_pair_graph_candidates(&batch_id, orders, &config)?;
    let graph_candidates = deduplicate_multi_pair_graph_candidates(graph_candidates)?;
    let graph_candidates = compose_multi_pair_graph_candidate_packages(
        &batch_id,
        graph_candidates,
        &objective_weight_map,
    )?;
    if graph_candidates.is_empty() {
        return Ok(None);
    }
    if graph_candidates.len() > MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair planner found {} candidate solutions, maximum is {}",
            graph_candidates.len(),
            MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS
        )));
    }

    let mut chosen_index = 0usize;
    let mut chosen_score =
        score_multi_pair_solution(&graph_candidates[0].solution.fills, &objective_weight_map)?;
    for (index, candidate) in graph_candidates.iter().enumerate().skip(1) {
        let score = score_multi_pair_solution(&candidate.solution.fills, &objective_weight_map)?;
        if score > chosen_score
            || (score == chosen_score
                && candidate.solution.solution_id
                    < graph_candidates[chosen_index].solution.solution_id)
        {
            chosen_index = index;
            chosen_score = score;
        }
    }

    let candidates = graph_candidates
        .into_iter()
        .map(|candidate| candidate.solution)
        .collect::<Vec<_>>();
    let chosen_candidate = candidates[chosen_index].clone();
    let chosen = MultiPairFeasibilityProblem {
        batch_id,
        fills: chosen_candidate.fills,
        asset_deltas: chosen_candidate.asset_deltas,
    };
    let problem = MultiPairOptimalityProblem {
        chosen,
        eligible_order_commitments: orders
            .iter()
            .map(|order| order.order_commitment.clone())
            .collect(),
        objective_weights,
        candidate_solutions: candidates,
    };
    verify_multi_pair_optimality(&problem)?;
    Ok(Some(MultiPairNettingPlan { problem }))
}

pub fn derive_multi_pair_external_completion_obligations(
    orders: &[MultiPairExecutableOrder],
    private_plan: Option<&MultiPairNettingPlan>,
) -> Result<Vec<MultiPairExternalCompletionObligation>, ProtocolError> {
    validate_executable_orders(orders)?;
    let mut order_inputs = BTreeMap::<String, &MultiPairExecutableOrder>::new();
    for order in orders {
        order_inputs.insert(normalize_felt_hex(&order.order_commitment.0)?, order);
    }

    let mut filled_base_by_commitment = BTreeMap::<String, u128>::new();
    let mut consumed_input_by_commitment = BTreeMap::<String, u128>::new();
    if let Some(plan) = private_plan {
        for fill in &plan.problem.chosen.fills {
            let commitment = normalize_felt_hex(&fill.order_commitment.0)?;
            let order = order_inputs.get(&commitment).ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "multi-pair private plan contains fill for unknown order".into(),
                )
            })?;
            let consumed_input = match fill.side {
                OrderSide::Buy => fill.quote_amount,
                OrderSide::Sell => fill.filled_base_amount,
            };
            if fill.side != order.side
                || fill.pair_id != order.pair_id
                || fill.base_asset_id != order.base_asset_id
                || fill.quote_asset_id != order.quote_asset_id
                || fill.limit_price != order.limit_price
                || fill.price_base_scale != order.price_base_scale
            {
                return Err(ProtocolError::InvalidSettlementProof(
                    "multi-pair private plan fill does not match executable order metadata".into(),
                ));
            }
            let filled_base = filled_base_by_commitment
                .get(&commitment)
                .copied()
                .unwrap_or(0)
                .checked_add(fill.filled_base_amount)
                .ok_or_else(|| {
                    ProtocolError::InvalidSettlementProof(
                        "multi-pair private fill total overflows".into(),
                    )
                })?;
            filled_base_by_commitment.insert(commitment.clone(), filled_base);
            let consumed_input_total = consumed_input_by_commitment
                .get(&commitment)
                .copied()
                .unwrap_or(0)
                .checked_add(consumed_input)
                .ok_or_else(|| {
                    ProtocolError::InvalidSettlementProof(
                        "multi-pair private input total overflows".into(),
                    )
                })?;
            consumed_input_by_commitment.insert(commitment, consumed_input_total);
        }
    }

    let mut grouped =
        BTreeMap::<MultiPairExternalCompletionKey, MultiPairExternalCompletionObligation>::new();
    for order in orders {
        if !order.execution_preference.allows_external_completion() {
            continue;
        }
        let commitment = normalize_felt_hex(&order.order_commitment.0)?;
        let filled_base = filled_base_by_commitment
            .get(&commitment)
            .copied()
            .unwrap_or(0);
        if filled_base > order.submitted_base_amount {
            return Err(ProtocolError::InvalidSettlementProof(
                "multi-pair private fill exceeds submitted order amount".into(),
            ));
        }
        let consumed_input = consumed_input_by_commitment
            .get(&commitment)
            .copied()
            .unwrap_or(0);
        if consumed_input > order.available_input_amount {
            return Err(ProtocolError::InvalidSettlementProof(
                "multi-pair private fill exceeds available input".into(),
            ));
        }

        let remaining_base = order.submitted_base_amount - filled_base;
        let remaining_input_capacity = order.available_input_amount - consumed_input;
        if remaining_base == 0 || remaining_input_capacity == 0 {
            continue;
        }

        let (input_asset_id, output_asset_id, input_amount, gross_output_amount) = match order.side
        {
            OrderSide::Buy => {
                let limit_quote = quote_amount_for_base_amount(
                    remaining_base,
                    order.limit_price,
                    order.price_base_scale,
                )?;
                let input_amount = remaining_input_capacity.min(limit_quote);
                let gross_output_amount = base_amount_affordable_for_quote(
                    input_amount,
                    order.limit_price,
                    order.price_base_scale,
                )?
                .min(remaining_base);
                (
                    order.quote_asset_id.clone(),
                    order.base_asset_id.clone(),
                    input_amount,
                    gross_output_amount,
                )
            }
            OrderSide::Sell => {
                let input_amount = remaining_input_capacity.min(remaining_base);
                let gross_output_amount = quote_amount_for_base_amount(
                    input_amount,
                    order.limit_price,
                    order.price_base_scale,
                )?;
                (
                    order.base_asset_id.clone(),
                    order.quote_asset_id.clone(),
                    input_amount,
                    gross_output_amount,
                )
            }
        };
        if input_amount == 0 || gross_output_amount == 0 {
            continue;
        }

        let key = MultiPairExternalCompletionKey {
            pair_id: order.pair_id.0.clone(),
            base_asset_id: order.base_asset_id.0.clone(),
            quote_asset_id: order.quote_asset_id.0.clone(),
            side_key: order_side_key(&order.side),
            limit_price: order.limit_price,
            price_base_scale: order.price_base_scale,
        };
        match grouped.entry(key) {
            Entry::Occupied(mut entry) => {
                let obligation = entry.get_mut();
                obligation.input_amount = obligation
                    .input_amount
                    .checked_add(input_amount)
                    .ok_or_else(|| {
                        ProtocolError::InvalidSettlementProof(
                            "multi-pair external completion input overflows".into(),
                        )
                    })?;
                obligation.gross_output_amount = obligation
                    .gross_output_amount
                    .checked_add(gross_output_amount)
                    .ok_or_else(|| {
                        ProtocolError::InvalidSettlementProof(
                            "multi-pair external completion output overflows".into(),
                        )
                    })?;
                obligation
                    .order_commitments
                    .push(OrderCommitment(commitment));
            }
            Entry::Vacant(entry) => {
                entry.insert(MultiPairExternalCompletionObligation {
                    pair_id: order.pair_id.clone(),
                    base_asset_id: order.base_asset_id.clone(),
                    quote_asset_id: order.quote_asset_id.clone(),
                    side: order.side,
                    input_asset_id,
                    output_asset_id,
                    input_amount,
                    gross_output_amount,
                    limit_price: order.limit_price,
                    price_base_scale: order.price_base_scale,
                    order_commitments: vec![OrderCommitment(commitment)],
                });
            }
        }
    }
    Ok(grouped.into_values().collect())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MultiPairExternalCompletionKey {
    pair_id: String,
    base_asset_id: String,
    quote_asset_id: String,
    side_key: u8,
    limit_price: u128,
    price_base_scale: u128,
}

pub fn verify_multi_pair_feasibility(
    problem: &MultiPairFeasibilityProblem,
) -> Result<MultiPairFeasibilityReport, ProtocolError> {
    verify_multi_pair_feasibility_parts(&problem.batch_id, &problem.fills, &problem.asset_deltas)
}

fn verify_multi_pair_feasibility_parts(
    batch_id: &BatchId,
    fills: &[MultiPairFill],
    asset_deltas: &[MultiPairAssetDelta],
) -> Result<MultiPairFeasibilityReport, ProtocolError> {
    validate_problem_shape(batch_id, fills, asset_deltas)?;
    validate_fills(fills)?;
    validate_bound_asset_deltas(fills, asset_deltas)?;
    let (asset_inputs, asset_outputs) = aggregate_asset_deltas(asset_deltas)?;
    assert_asset_conservation(&asset_inputs, &asset_outputs)?;

    Ok(MultiPairFeasibilityReport {
        batch_id: batch_id.clone(),
        fill_count: fills.len(),
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
        verify_multi_pair_feasibility_parts(
            &problem.chosen.batch_id,
            &candidate.fills,
            &candidate.asset_deltas,
        )?;
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

fn validate_multi_pair_netting_config(
    config: &MultiPairNettingConfig,
) -> Result<(), ProtocolError> {
    if !(2..=DEFAULT_MULTI_PAIR_MAX_CYCLE_LEN).contains(&config.max_cycle_len) {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair max cycle length must be between 2 and {DEFAULT_MULTI_PAIR_MAX_CYCLE_LEN}"
        )));
    }
    Ok(())
}

fn validate_executable_orders(orders: &[MultiPairExecutableOrder]) -> Result<(), ProtocolError> {
    if orders.len() > MAX_MULTI_PAIR_FILLS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair executable order count {} exceeds maximum {}",
            orders.len(),
            MAX_MULTI_PAIR_FILLS
        )));
    }
    let mut seen = BTreeSet::new();
    let zero_commitment = crate::hash::felt_hex(&field_from_u64(0));
    for (index, order) in orders.iter().enumerate() {
        let commitment = normalize_felt_hex(&order.order_commitment.0)?;
        if commitment == zero_commitment {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair executable order {index} has a zero commitment"
            )));
        }
        if !seen.insert(commitment) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair executable order {index} duplicates a commitment"
            )));
        }
        if order.pair_id.0.trim().is_empty()
            || order.base_asset_id.0.trim().is_empty()
            || order.quote_asset_id.0.trim().is_empty()
            || order.base_asset_id == order.quote_asset_id
        {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair executable order {index} has invalid pair metadata"
            )));
        }
        if order.submitted_base_amount == 0
            || order.min_fill_base_amount == 0
            || order.min_fill_base_amount > order.submitted_base_amount
            || order.limit_price == 0
            || order.price_base_scale == 0
            || order.available_input_amount == 0
        {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair executable order {index} has invalid amount or price fields"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum MultiPairGraphEdge<'a> {
    User(&'a MultiPairExecutableOrder),
}

#[derive(Clone, Debug)]
struct MultiPairGraphEdgeFillPlan {
    input_asset: AssetId,
    input_amount: u128,
    output_asset: AssetId,
    gross_output_amount: u128,
    user_fill: Option<MultiPairFill>,
}

#[derive(Clone, Debug)]
struct MultiPairGraphCandidate {
    solution: MultiPairCandidateSolution,
}

#[derive(Clone, Debug)]
struct MultiPairGraphCandidateUsage {
    order_commitments: BTreeSet<String>,
    fill_count: usize,
    delta_count: usize,
}

#[derive(Clone, Debug)]
struct ScoredMultiPairGraphCandidate {
    candidate: MultiPairGraphCandidate,
    usage: MultiPairGraphCandidateUsage,
    score: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MultiPairCandidateKey {
    fills: Vec<MultiPairFillKey>,
    deltas: Vec<MultiPairDeltaKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MultiPairFillKey {
    order_commitment: String,
    pair_id: String,
    base_asset_id: String,
    quote_asset_id: String,
    side_key: u8,
    submitted_base_amount: u128,
    min_fill_base_amount: u128,
    limit_price: u128,
    price_base_scale: u128,
    filled_base_amount: u128,
    quote_amount: u128,
    fee_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MultiPairDeltaKey {
    source_commitment: String,
    asset_id: String,
    amount: u128,
    direction_key: u8,
    source_key: u8,
}

struct MultiPairPackageSearch<'a> {
    batch_id: &'a BatchId,
    scored: &'a [ScoredMultiPairGraphCandidate],
    visited_nodes: usize,
    unique: &'a mut BTreeMap<MultiPairCandidateKey, MultiPairGraphCandidate>,
}

#[derive(Default)]
struct MultiPairPackageState {
    selected_indices: Vec<usize>,
    used_orders: BTreeSet<String>,
    fill_count: usize,
    delta_count: usize,
    score: u128,
}

struct MultiPairGraphSearch<'a> {
    batch_id: &'a BatchId,
    edges: &'a [MultiPairGraphEdge<'a>],
    next_indices_by_input_asset: &'a BTreeMap<&'a str, Vec<usize>>,
    config: &'a MultiPairNettingConfig,
}

fn enumerate_multi_pair_graph_candidates(
    batch_id: &BatchId,
    orders: &[MultiPairExecutableOrder],
    config: &MultiPairNettingConfig,
) -> Result<Vec<MultiPairGraphCandidate>, ProtocolError> {
    let mut edges = Vec::with_capacity(orders.len());
    edges.extend(orders.iter().map(MultiPairGraphEdge::User));
    if edges.len() < 2 {
        return Ok(Vec::new());
    }

    let mut next_indices_by_input_asset = BTreeMap::<&str, Vec<usize>>::new();
    for (index, edge) in edges.iter().enumerate() {
        next_indices_by_input_asset
            .entry(graph_edge_input_asset(edge).0.as_str())
            .or_default()
            .push(index);
    }

    let mut candidates = Vec::with_capacity(edges.len());
    let mut path = Vec::with_capacity(config.max_cycle_len.min(edges.len()));
    let mut used = vec![false; edges.len()];
    let search = MultiPairGraphSearch {
        batch_id,
        edges: &edges,
        next_indices_by_input_asset: &next_indices_by_input_asset,
        config,
    };
    for start_index in 0..edges.len() {
        path.clear();
        used.fill(false);
        path.push(start_index);
        used[start_index] = true;
        extend_graph_candidate_path(&search, start_index, &mut path, &mut used, &mut candidates)?;
    }
    Ok(candidates)
}

fn extend_graph_candidate_path(
    search: &MultiPairGraphSearch<'_>,
    start_index: usize,
    path: &mut Vec<usize>,
    used: &mut [bool],
    candidates: &mut Vec<MultiPairGraphCandidate>,
) -> Result<(), ProtocolError> {
    if path.len() > search.config.max_cycle_len {
        return Ok(());
    }
    let current_index = *path
        .last()
        .ok_or_else(|| ProtocolError::InvalidSettlementProof("empty multi-pair path".into()))?;
    let current_output_asset = graph_edge_output_asset(&search.edges[current_index]);
    if path.len() >= 2
        && current_output_asset == graph_edge_input_asset(&search.edges[start_index])
        && let Some(candidate) = build_graph_cycle_candidate(search.batch_id, search.edges, path)?
    {
        candidates.push(candidate);
    }
    if path.len() == search.config.max_cycle_len {
        return Ok(());
    }
    let Some(next_indices) = search
        .next_indices_by_input_asset
        .get(current_output_asset.0.as_str())
    else {
        return Ok(());
    };
    for next_index in next_indices.iter().copied() {
        if used[next_index] {
            continue;
        }
        used[next_index] = true;
        path.push(next_index);
        extend_graph_candidate_path(search, start_index, path, used, candidates)?;
        path.pop();
        used[next_index] = false;
    }
    Ok(())
}

fn build_graph_cycle_candidate(
    batch_id: &BatchId,
    edges: &[MultiPairGraphEdge<'_>],
    path: &[usize],
) -> Result<Option<MultiPairGraphCandidate>, ProtocolError> {
    let Some(edge_fill_plans) = graph_fill_plans_for_largest_feasible_fill(edges, path)? else {
        return Ok(None);
    };

    let mut fills = Vec::with_capacity(path.len());
    let mut deltas = Vec::with_capacity(path.len() * 3);
    for fill_plan in edge_fill_plans {
        if let Some(fill) = fill_plan.user_fill {
            let commitment = normalize_felt_hex(&fill.order_commitment.0)?;
            push_cycle_delta(
                &mut deltas,
                fill_plan.input_asset.clone(),
                fill_plan.input_amount,
                MultiPairAssetDeltaDirection::In,
                MultiPairAssetDeltaSource::User,
                &commitment,
            );
            let net_output = fill_plan
                .gross_output_amount
                .checked_sub(fill.fee_amount)
                .ok_or_else(|| {
                    ProtocolError::InvalidSettlementProof(
                        "multi-pair cycle fee exceeds output".into(),
                    )
                })?;
            push_cycle_delta(
                &mut deltas,
                fill_plan.output_asset.clone(),
                net_output,
                MultiPairAssetDeltaDirection::Out,
                MultiPairAssetDeltaSource::User,
                &commitment,
            );
            push_cycle_delta(
                &mut deltas,
                fill_plan.output_asset.clone(),
                fill.fee_amount,
                MultiPairAssetDeltaDirection::Out,
                MultiPairAssetDeltaSource::Fee,
                &commitment,
            );
            fills.push(fill);
        }
    }
    if fills.is_empty() {
        return Ok(None);
    }
    verify_multi_pair_feasibility_parts(batch_id, &fills, &deltas)?;
    Ok(Some(MultiPairGraphCandidate {
        solution: MultiPairCandidateSolution {
            solution_id: graph_cycle_solution_id(edges, path)?,
            fills,
            asset_deltas: deltas,
        },
    }))
}

fn graph_fill_plans_for_largest_feasible_fill(
    edges: &[MultiPairGraphEdge<'_>],
    path: &[usize],
) -> Result<Option<Vec<MultiPairGraphEdgeFillPlan>>, ProtocolError> {
    let mut prefixes = Vec::with_capacity(path.len());
    let mut prefix_num = 1_u128;
    let mut prefix_den = 1_u128;
    for edge_index in path.iter().copied() {
        prefixes.push((prefix_num, prefix_den));
        let (rate_num, rate_den) = graph_edge_limit_rate(&edges[edge_index])?;
        multiply_ratio_checked(&mut prefix_num, &mut prefix_den, rate_num, rate_den)?;
    }
    if prefix_num > prefix_den {
        return Ok(None);
    }

    let mut edge_max_inputs = Vec::with_capacity(path.len());
    for edge_index in path.iter().copied() {
        edge_max_inputs.push(max_cycle_input_for_graph_edge(&edges[edge_index])?);
    }
    let mut max_start_input = None::<u128>;
    for ((prefix_num, prefix_den), max_input) in prefixes
        .iter()
        .copied()
        .zip(edge_max_inputs.iter().copied())
    {
        let candidate_start = mul_div_floor_checked(max_input, prefix_den, prefix_num)?;
        max_start_input = Some(match max_start_input {
            Some(current) => current.min(candidate_start),
            None => candidate_start,
        });
    }
    if let Some(last_index) = path.last().copied()
        && let Some(max_output) = max_cycle_output_for_graph_edge(&edges[last_index])
    {
        max_start_input = Some(match max_start_input {
            Some(current) => current.min(max_output),
            None => max_output,
        });
    }
    let start_input_ceiling = max_start_input.unwrap_or_default();
    for offset in 0..MAX_MULTI_PAIR_ROUNDING_SEARCH_STEPS {
        let Some(start_input) = start_input_ceiling.checked_sub(offset as u128) else {
            break;
        };
        if start_input == 0 {
            break;
        }
        if let Some(plans) =
            graph_fill_plans_for_start_input(edges, path, &edge_max_inputs, start_input)?
        {
            return Ok(Some(plans));
        }
    }
    Ok(None)
}

fn graph_fill_plans_for_start_input(
    edges: &[MultiPairGraphEdge<'_>],
    path: &[usize],
    edge_max_inputs: &[u128],
    start_input: u128,
) -> Result<Option<Vec<MultiPairGraphEdgeFillPlan>>, ProtocolError> {
    if path.is_empty() || start_input == 0 {
        return Ok(None);
    }
    if path.len() != edge_max_inputs.len() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair graph path capacity mismatch".into(),
        ));
    }
    let mut plans = Vec::with_capacity(path.len());
    let mut input_amount = start_input;
    for (path_index, edge_index) in path.iter().copied().enumerate() {
        let edge = &edges[edge_index];
        if input_amount > edge_max_inputs[path_index] {
            return Ok(None);
        }
        let is_last = path_index + 1 == path.len();
        let (filled_base_amount, quote_amount) = if is_last {
            let Some(amounts) =
                cycle_graph_edge_amounts_from_input_and_output(edge, input_amount, start_input)?
            else {
                return Ok(None);
            };
            amounts
        } else {
            cycle_graph_edge_amounts_from_input(edge, input_amount)?
        };
        let gross_output_amount = match graph_edge_side(edge) {
            OrderSide::Buy => filled_base_amount,
            OrderSide::Sell => quote_amount,
        };
        if gross_output_amount == 0 {
            return Ok(None);
        }
        let Some(plan) = graph_edge_fill_plan(
            edge,
            path_index,
            input_amount,
            filled_base_amount,
            quote_amount,
        )?
        else {
            return Ok(None);
        };
        plans.push(plan);
        input_amount = gross_output_amount;
    }
    if input_amount != start_input {
        return Ok(None);
    }
    Ok(Some(plans))
}

fn graph_edge_fill_plan(
    edge: &MultiPairGraphEdge<'_>,
    path_index: usize,
    input_amount: u128,
    filled_base_amount: u128,
    quote_amount: u128,
) -> Result<Option<MultiPairGraphEdgeFillPlan>, ProtocolError> {
    match edge {
        MultiPairGraphEdge::User(order) => {
            let gross_output_amount = match order.side {
                OrderSide::Buy => filled_base_amount,
                OrderSide::Sell => quote_amount,
            };
            let fee_amount = ceil_bps_amount(gross_output_amount, u128::from(order.taker_fee_bps))?;
            let fill = MultiPairFill {
                order_commitment: order.order_commitment.clone(),
                pair_id: order.pair_id.clone(),
                base_asset_id: order.base_asset_id.clone(),
                quote_asset_id: order.quote_asset_id.clone(),
                side: order.side,
                submitted_base_amount: order.submitted_base_amount,
                min_fill_base_amount: order.min_fill_base_amount,
                limit_price: order.limit_price,
                price_base_scale: order.price_base_scale,
                filled_base_amount,
                quote_amount,
                fee_amount,
            };
            if validate_fill_bounds(path_index, &fill).is_err() {
                return Ok(None);
            }
            Ok(Some(MultiPairGraphEdgeFillPlan {
                input_asset: graph_edge_input_asset(edge).clone(),
                input_amount,
                output_asset: graph_edge_output_asset(edge).clone(),
                gross_output_amount,
                user_fill: Some(fill),
            }))
        }
    }
}

fn cycle_graph_edge_amounts_from_input(
    edge: &MultiPairGraphEdge<'_>,
    input_amount: u128,
) -> Result<(u128, u128), ProtocolError> {
    match graph_edge_side(edge) {
        OrderSide::Buy => {
            let filled_base_amount = min_base_amount_for_quote_at_limit(
                input_amount,
                graph_edge_limit_price(edge),
                graph_edge_price_base_scale(edge),
            )?;
            Ok((filled_base_amount, input_amount))
        }
        OrderSide::Sell => {
            let quote_amount = quote_amount_for_base_amount(
                input_amount,
                graph_edge_limit_price(edge),
                graph_edge_price_base_scale(edge),
            )?;
            Ok((input_amount, quote_amount))
        }
    }
}

fn cycle_graph_edge_amounts_from_input_and_output(
    edge: &MultiPairGraphEdge<'_>,
    input_amount: u128,
    gross_output_amount: u128,
) -> Result<Option<(u128, u128)>, ProtocolError> {
    if input_amount == 0 || gross_output_amount == 0 {
        return Ok(None);
    }
    Ok(Some(match graph_edge_side(edge) {
        OrderSide::Buy => (gross_output_amount, input_amount),
        OrderSide::Sell => (input_amount, gross_output_amount),
    }))
}

fn graph_edge_limit_rate(edge: &MultiPairGraphEdge<'_>) -> Result<(u128, u128), ProtocolError> {
    let limit_price = graph_edge_limit_price(edge);
    let price_base_scale = graph_edge_price_base_scale(edge);
    if limit_price == 0 || price_base_scale == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair cycle rate requires nonzero price fields".into(),
        ));
    }
    Ok(match graph_edge_side(edge) {
        OrderSide::Buy => reduce_ratio(price_base_scale, limit_price),
        OrderSide::Sell => reduce_ratio(limit_price, price_base_scale),
    })
}

fn max_cycle_input_for_graph_edge(edge: &MultiPairGraphEdge<'_>) -> Result<u128, ProtocolError> {
    match edge {
        MultiPairGraphEdge::User(order) => max_cycle_input_for_order(order),
    }
}

fn max_cycle_output_for_graph_edge(edge: &MultiPairGraphEdge<'_>) -> Option<u128> {
    match edge {
        MultiPairGraphEdge::User(order) => max_cycle_output_for_order(order),
    }
}

fn graph_edge_input_asset<'a>(edge: &MultiPairGraphEdge<'a>) -> &'a AssetId {
    match edge {
        MultiPairGraphEdge::User(order) => order_input_asset(order),
    }
}

fn graph_edge_output_asset<'a>(edge: &MultiPairGraphEdge<'a>) -> &'a AssetId {
    match edge {
        MultiPairGraphEdge::User(order) => order_output_asset(order),
    }
}

fn graph_edge_side(edge: &MultiPairGraphEdge<'_>) -> OrderSide {
    match edge {
        MultiPairGraphEdge::User(order) => order.side,
    }
}

fn graph_edge_limit_price(edge: &MultiPairGraphEdge<'_>) -> u128 {
    match edge {
        MultiPairGraphEdge::User(order) => order.limit_price,
    }
}

fn graph_edge_price_base_scale(edge: &MultiPairGraphEdge<'_>) -> u128 {
    match edge {
        MultiPairGraphEdge::User(order) => order.price_base_scale,
    }
}

fn graph_cycle_solution_id(
    edges: &[MultiPairGraphEdge<'_>],
    path: &[usize],
) -> Result<String, ProtocolError> {
    let mut solution_id = String::from("cycle:");
    for (path_index, edge_index) in path.iter().copied().enumerate() {
        if path_index > 0 {
            solution_id.push('>');
        }
        push_graph_edge_solution_id(&mut solution_id, &edges[edge_index])?;
    }
    Ok(solution_id)
}

fn push_graph_edge_solution_id(
    solution_id: &mut String,
    edge: &MultiPairGraphEdge<'_>,
) -> Result<(), ProtocolError> {
    match edge {
        MultiPairGraphEdge::User(order) => {
            solution_id.push_str("user:");
            solution_id.push_str(&normalize_felt_hex(&order.order_commitment.0)?);
        }
    }
    Ok(())
}

fn deduplicate_multi_pair_graph_candidates(
    candidates: Vec<MultiPairGraphCandidate>,
) -> Result<Vec<MultiPairGraphCandidate>, ProtocolError> {
    let mut unique = BTreeMap::<MultiPairCandidateKey, MultiPairGraphCandidate>::new();
    for candidate in candidates {
        insert_multi_pair_graph_candidate(&mut unique, candidate)?;
    }
    let mut candidates = unique.into_values().collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.solution.solution_id.cmp(&right.solution.solution_id));
    Ok(candidates)
}

fn compose_multi_pair_graph_candidate_packages(
    batch_id: &BatchId,
    candidates: Vec<MultiPairGraphCandidate>,
    objective_weight_map: &BTreeMap<String, (u128, u128)>,
) -> Result<Vec<MultiPairGraphCandidate>, ProtocolError> {
    if candidates.len() <= 1 {
        return Ok(candidates);
    }

    let mut scored = candidates
        .into_iter()
        .map(|candidate| {
            Ok(ScoredMultiPairGraphCandidate {
                usage: multi_pair_graph_candidate_usage(&candidate)?,
                score: score_multi_pair_solution(&candidate.solution.fills, objective_weight_map)?,
                candidate,
            })
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    scored.sort_by(|left, right| {
        right.score.cmp(&left.score).then_with(|| {
            left.candidate
                .solution
                .solution_id
                .cmp(&right.candidate.solution.solution_id)
        })
    });

    let mut unique = BTreeMap::<MultiPairCandidateKey, MultiPairGraphCandidate>::new();
    let mut search = MultiPairPackageSearch {
        batch_id,
        scored: &scored,
        visited_nodes: 0,
        unique: &mut unique,
    };
    let mut state = MultiPairPackageState::default();
    extend_multi_pair_graph_candidate_package(&mut search, 0, &mut state)?;

    let mut ranked = unique
        .into_values()
        .map(|candidate| {
            let score = score_multi_pair_solution(&candidate.solution.fills, objective_weight_map)?;
            Ok((candidate, score))
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    ranked.sort_by(|(left, left_score), (right, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left.solution.solution_id.cmp(&right.solution.solution_id))
    });
    if ranked.len() > MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS {
        ranked.truncate(MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS);
    }
    let mut candidates = ranked
        .into_iter()
        .map(|(candidate, _)| candidate)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.solution.solution_id.cmp(&right.solution.solution_id));
    Ok(candidates)
}

fn extend_multi_pair_graph_candidate_package(
    search: &mut MultiPairPackageSearch<'_>,
    start_index: usize,
    state: &mut MultiPairPackageState,
) -> Result<(), ProtocolError> {
    if search.visited_nodes >= MAX_MULTI_PAIR_PACKAGE_SEARCH_NODES
        || state.selected_indices.len() >= MAX_MULTI_PAIR_PACKAGE_CYCLES
    {
        return Ok(());
    }

    for index in start_index..search.scored.len() {
        if search.visited_nodes >= MAX_MULTI_PAIR_PACKAGE_SEARCH_NODES {
            break;
        }
        let candidate = &search.scored[index];
        if !multi_pair_graph_candidate_usage_is_compatible(&candidate.usage, &state.used_orders) {
            continue;
        }
        let next_fill_count = state
            .fill_count
            .checked_add(candidate.usage.fill_count)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "multi-pair package fill count overflows".into(),
                )
            })?;
        let next_delta_count = state
            .delta_count
            .checked_add(candidate.usage.delta_count)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "multi-pair package delta count overflows".into(),
                )
            })?;
        let next_score = state.score.checked_add(candidate.score).ok_or_else(|| {
            ProtocolError::InvalidSettlementProof("multi-pair objective overflows".into())
        })?;
        if next_fill_count > MAX_MULTI_PAIR_FILLS || next_delta_count > MAX_MULTI_PAIR_ASSET_DELTAS
        {
            continue;
        }

        search.visited_nodes += 1;
        state.selected_indices.push(index);
        let prior_fill_count = state.fill_count;
        let prior_delta_count = state.delta_count;
        let prior_score = state.score;
        state.fill_count = next_fill_count;
        state.delta_count = next_delta_count;
        state.score = next_score;
        let packaged = build_multi_pair_graph_candidate_package(
            search.batch_id,
            search.scored,
            &state.selected_indices,
            state.fill_count,
            state.delta_count,
        )?;
        insert_multi_pair_graph_candidate(search.unique, packaged)?;

        for commitment in &candidate.usage.order_commitments {
            state.used_orders.insert(commitment.clone());
        }
        extend_multi_pair_graph_candidate_package(search, index + 1, state)?;
        for commitment in &candidate.usage.order_commitments {
            state.used_orders.remove(commitment);
        }
        state.fill_count = prior_fill_count;
        state.delta_count = prior_delta_count;
        state.score = prior_score;
        state.selected_indices.pop();
    }

    Ok(())
}

fn build_multi_pair_graph_candidate_package(
    batch_id: &BatchId,
    scored: &[ScoredMultiPairGraphCandidate],
    selected_indices: &[usize],
    fill_count: usize,
    delta_count: usize,
) -> Result<MultiPairGraphCandidate, ProtocolError> {
    if selected_indices.len() == 1 {
        return Ok(scored[selected_indices[0]].candidate.clone());
    }

    let mut solution_id = String::from("package:");
    let mut fills = Vec::with_capacity(fill_count);
    let mut asset_deltas = Vec::with_capacity(delta_count);
    for (path_index, index) in selected_indices.iter().copied().enumerate() {
        let candidate = &scored[index].candidate;
        if path_index > 0 {
            solution_id.push('+');
        }
        solution_id.push_str(&candidate.solution.solution_id);
        fills.extend(candidate.solution.fills.iter().cloned());
        asset_deltas.extend(candidate.solution.asset_deltas.iter().cloned());
    }
    verify_multi_pair_feasibility_parts(batch_id, &fills, &asset_deltas)?;
    Ok(MultiPairGraphCandidate {
        solution: MultiPairCandidateSolution {
            solution_id,
            fills,
            asset_deltas,
        },
    })
}

fn multi_pair_graph_candidate_usage(
    candidate: &MultiPairGraphCandidate,
) -> Result<MultiPairGraphCandidateUsage, ProtocolError> {
    let order_commitments = candidate
        .solution
        .fills
        .iter()
        .map(|fill| normalize_felt_hex(&fill.order_commitment.0))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if order_commitments.len() != candidate.solution.fills.len() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair package candidate has duplicate sources".into(),
        ));
    }
    Ok(MultiPairGraphCandidateUsage {
        order_commitments,
        fill_count: candidate.solution.fills.len(),
        delta_count: candidate.solution.asset_deltas.len(),
    })
}

fn multi_pair_graph_candidate_usage_is_compatible(
    candidate: &MultiPairGraphCandidateUsage,
    used_orders: &BTreeSet<String>,
) -> bool {
    candidate
        .order_commitments
        .iter()
        .all(|commitment| !used_orders.contains(commitment))
}

fn insert_multi_pair_graph_candidate(
    unique: &mut BTreeMap<MultiPairCandidateKey, MultiPairGraphCandidate>,
    candidate: MultiPairGraphCandidate,
) -> Result<(), ProtocolError> {
    let key = multi_pair_candidate_key(&candidate.solution)?;
    match unique.entry(key) {
        Entry::Occupied(mut entry) => {
            if candidate.solution.solution_id < entry.get().solution.solution_id {
                entry.insert(candidate);
            }
        }
        Entry::Vacant(entry) => {
            entry.insert(candidate);
        }
    }
    Ok(())
}

fn max_cycle_input_for_order(order: &MultiPairExecutableOrder) -> Result<u128, ProtocolError> {
    let max_order_input = match order.side {
        OrderSide::Buy => quote_amount_for_base_amount(
            order.submitted_base_amount,
            order.limit_price,
            order.price_base_scale,
        )?,
        OrderSide::Sell => order.submitted_base_amount,
    };
    Ok(max_order_input.min(order.available_input_amount))
}

fn max_cycle_output_for_order(order: &MultiPairExecutableOrder) -> Option<u128> {
    match order.side {
        OrderSide::Buy => Some(order.submitted_base_amount),
        OrderSide::Sell => None,
    }
}

fn min_base_amount_for_quote_at_limit(
    quote_amount: u128,
    price: u128,
    price_base_scale: u128,
) -> Result<u128, ProtocolError> {
    if price == 0 || price_base_scale == 0 {
        return Ok(0);
    }
    quote_amount
        .checked_mul(price_base_scale)
        .and_then(|value| value.checked_add(price.saturating_sub(1)))
        .and_then(|value| value.checked_div(price))
        .ok_or_else(|| ProtocolError::InvalidOrder("base amount overflows u128".into()))
}

fn multiply_ratio_checked(
    numerator: &mut u128,
    denominator: &mut u128,
    factor_num: u128,
    factor_den: u128,
) -> Result<(), ProtocolError> {
    let (mut factor_num, mut factor_den) = reduce_ratio(factor_num, factor_den);
    let cross_a = gcd(*numerator, factor_den);
    *numerator /= cross_a;
    factor_den /= cross_a;
    let cross_b = gcd(factor_num, *denominator);
    factor_num /= cross_b;
    *denominator /= cross_b;
    *numerator = numerator.checked_mul(factor_num).ok_or_else(|| {
        ProtocolError::InvalidSettlementProof("multi-pair cycle numerator overflows".into())
    })?;
    *denominator = denominator.checked_mul(factor_den).ok_or_else(|| {
        ProtocolError::InvalidSettlementProof("multi-pair cycle denominator overflows".into())
    })?;
    let normalized = reduce_ratio(*numerator, *denominator);
    *numerator = normalized.0;
    *denominator = normalized.1;
    Ok(())
}

fn mul_div_floor_checked(
    amount: u128,
    numerator: u128,
    denominator: u128,
) -> Result<u128, ProtocolError> {
    if denominator == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair ratio denominator is zero".into(),
        ));
    }
    if amount == 0 || numerator == 0 {
        return Ok(0);
    }
    let cross_a = gcd(amount, denominator);
    let reduced_amount = amount / cross_a;
    let reduced_denominator = denominator / cross_a;
    let cross_b = gcd(numerator, reduced_denominator);
    let reduced_numerator = numerator / cross_b;
    let reduced_denominator = reduced_denominator / cross_b;
    reduced_amount
        .checked_mul(reduced_numerator)
        .map(|value| value / reduced_denominator)
        .ok_or_else(|| {
            ProtocolError::InvalidSettlementProof(
                "multi-pair ratio multiplication overflows".into(),
            )
        })
}

fn reduce_ratio(numerator: u128, denominator: u128) -> (u128, u128) {
    let divisor = gcd(numerator, denominator);
    (numerator / divisor, denominator / divisor)
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

fn order_input_asset(order: &MultiPairExecutableOrder) -> &AssetId {
    match order.side {
        OrderSide::Buy => &order.quote_asset_id,
        OrderSide::Sell => &order.base_asset_id,
    }
}

fn order_output_asset(order: &MultiPairExecutableOrder) -> &AssetId {
    match order.side {
        OrderSide::Buy => &order.base_asset_id,
        OrderSide::Sell => &order.quote_asset_id,
    }
}

fn multi_pair_candidate_key(
    candidate: &MultiPairCandidateSolution,
) -> Result<MultiPairCandidateKey, ProtocolError> {
    let mut fill_keys = candidate
        .fills
        .iter()
        .map(|fill| {
            Ok(MultiPairFillKey {
                order_commitment: normalize_felt_hex(&fill.order_commitment.0)?,
                pair_id: fill.pair_id.0.clone(),
                base_asset_id: fill.base_asset_id.0.clone(),
                quote_asset_id: fill.quote_asset_id.0.clone(),
                side_key: order_side_key(&fill.side),
                submitted_base_amount: fill.submitted_base_amount,
                min_fill_base_amount: fill.min_fill_base_amount,
                limit_price: fill.limit_price,
                price_base_scale: fill.price_base_scale,
                filled_base_amount: fill.filled_base_amount,
                quote_amount: fill.quote_amount,
                fee_amount: fill.fee_amount,
            })
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    fill_keys.sort();
    let mut delta_keys = candidate
        .asset_deltas
        .iter()
        .map(|delta| {
            Ok(MultiPairDeltaKey {
                source_commitment: normalize_felt_hex(
                    delta.source_commitment.as_deref().unwrap_or("0x0"),
                )?,
                asset_id: delta.asset_id.0.clone(),
                amount: delta.amount,
                direction_key: asset_delta_direction_key(&delta.direction),
                source_key: asset_delta_source_key(&delta.source),
            })
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    delta_keys.sort();
    Ok(MultiPairCandidateKey {
        fills: fill_keys,
        deltas: delta_keys,
    })
}

fn order_side_key(side: &OrderSide) -> u8 {
    match side {
        OrderSide::Buy => 0,
        OrderSide::Sell => 1,
    }
}

fn asset_delta_direction_key(direction: &MultiPairAssetDeltaDirection) -> u8 {
    match direction {
        MultiPairAssetDeltaDirection::In => 0,
        MultiPairAssetDeltaDirection::Out => 1,
    }
}

fn asset_delta_source_key(source: &MultiPairAssetDeltaSource) -> u8 {
    match source {
        MultiPairAssetDeltaSource::User => 0,
        MultiPairAssetDeltaSource::ExternalCompletion => 1,
        MultiPairAssetDeltaSource::Fee => 2,
    }
}

fn ceil_bps_amount(amount: u128, bps: u128) -> Result<u128, ProtocolError> {
    if amount == 0 || bps == 0 {
        return Ok(0);
    }
    amount
        .checked_mul(bps)
        .and_then(|value| value.checked_add(9_999))
        .map(|value| value / 10_000)
        .ok_or_else(|| ProtocolError::InvalidSettlementProof("multi-pair fee overflows".into()))
}

fn push_cycle_delta(
    deltas: &mut Vec<MultiPairAssetDelta>,
    asset_id: AssetId,
    amount: u128,
    direction: MultiPairAssetDeltaDirection,
    source: MultiPairAssetDeltaSource,
    normalized_source_commitment: &str,
) {
    if amount == 0 {
        return;
    }
    deltas.push(MultiPairAssetDelta {
        asset_id,
        amount,
        direction,
        source,
        source_commitment: Some(normalized_source_commitment.to_owned()),
    });
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
    let zero_commitment = crate::hash::felt_hex(&field_from_u64(0));
    for (index, commitment) in commitments.iter().enumerate() {
        let value = normalize_felt_hex(&commitment.0)?;
        if value == zero_commitment {
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

fn validate_problem_shape(
    batch_id: &BatchId,
    fills: &[MultiPairFill],
    asset_deltas: &[MultiPairAssetDelta],
) -> Result<(), ProtocolError> {
    if batch_id.0.trim().is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair feasibility requires a batch id".into(),
        ));
    }
    if fills.is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair feasibility requires at least one fill".into(),
        ));
    }
    if fills.len() > MAX_MULTI_PAIR_FILLS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair fill count {} exceeds maximum {}",
            fills.len(),
            MAX_MULTI_PAIR_FILLS
        )));
    }
    if asset_deltas.is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "multi-pair feasibility requires asset deltas".into(),
        ));
    }
    if asset_deltas.len() > MAX_MULTI_PAIR_ASSET_DELTAS {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "multi-pair asset delta count {} exceeds maximum {}",
            asset_deltas.len(),
            MAX_MULTI_PAIR_ASSET_DELTAS
        )));
    }
    Ok(())
}

fn validate_fills(fills: &[MultiPairFill]) -> Result<(), ProtocolError> {
    let mut seen_commitments = BTreeSet::new();
    let zero_commitment = crate::hash::felt_hex(&field_from_u64(0));
    for (index, fill) in fills.iter().enumerate() {
        let commitment = normalize_felt_hex(&fill.order_commitment.0)?;
        if commitment == zero_commitment {
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
    let zero_commitment = crate::hash::felt_hex(&field_from_u64(0));
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
        if commitment == zero_commitment {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "multi-pair asset delta {index} has a zero source commitment"
            )));
        }
        match delta.source {
            MultiPairAssetDeltaSource::User => add_bound_delta(
                &mut actual_user,
                &commitment,
                &delta.asset_id.0,
                delta.direction,
                delta.amount,
            )?,
            MultiPairAssetDeltaSource::Fee => add_bound_delta(
                &mut actual_fees,
                &commitment,
                &delta.asset_id.0,
                delta.direction,
                delta.amount,
            )?,
            MultiPairAssetDeltaSource::ExternalCompletion => {}
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
        MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS, MultiPairAssetDelta, MultiPairAssetDeltaDirection,
        MultiPairAssetDeltaSource, MultiPairCandidateSolution, MultiPairExecutableOrder,
        MultiPairFeasibilityProblem, MultiPairFill, MultiPairNettingConfig,
        MultiPairObjectiveWeight, MultiPairOptimalityProblem,
        derive_multi_pair_external_completion_obligations, plan_multi_pair_netting,
        verify_multi_pair_feasibility, verify_multi_pair_optimality,
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
                external_completion_delta("0x99", "USDC", 24_000, MultiPairAssetDeltaDirection::In),
                external_completion_delta("0x99", "ETH", 10, MultiPairAssetDeltaDirection::Out),
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
                external_completion_delta("0x99", "ETH", 10, MultiPairAssetDeltaDirection::In),
                external_completion_delta(
                    "0x99",
                    "USDC",
                    25_000,
                    MultiPairAssetDeltaDirection::Out,
                ),
                external_completion_delta("0x9a", "USDC", 10_000, MultiPairAssetDeltaDirection::In),
                external_completion_delta(
                    "0x9a",
                    "STRK",
                    10_000,
                    MultiPairAssetDeltaDirection::Out,
                ),
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
                        external_completion_delta(
                            "0x99",
                            "ETH",
                            10,
                            MultiPairAssetDeltaDirection::In,
                        ),
                        external_completion_delta(
                            "0x99",
                            "USDC",
                            25_000,
                            MultiPairAssetDeltaDirection::Out,
                        ),
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
                external_completion_delta("0x99", "ETH", 20, MultiPairAssetDeltaDirection::In),
                external_completion_delta(
                    "0x99",
                    "USDC",
                    50_000,
                    MultiPairAssetDeltaDirection::Out,
                ),
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

    #[test]
    fn planner_discovers_full_size_three_asset_user_cycle() {
        let plan = plan_multi_pair_netting(
            BatchId("epoch-42".into()),
            &[
                executable_buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 50_000, 5_000),
                executable_sell("0x2", "ETH/STRK", "ETH", "STRK", 10, 50_000, 5_000),
                executable_sell("0x3", "STRK/USDC", "STRK", "USDC", 50_000, 50_000, 1),
            ],
            objective_weights(),
            MultiPairNettingConfig::default(),
        )
        .expect("planner succeeds")
        .expect("cycle is feasible");

        let report = verify_multi_pair_optimality(&plan.problem).expect("plan verifies");

        assert_eq!(report.feasibility.fill_count, 3);
        assert_eq!(report.chosen_objective, 125_000);
        assert_eq!(report.candidate_count, 1);
        assert_eq!(plan.problem.chosen.asset_deltas.len(), 6);
    }

    #[test]
    fn planner_rejects_cycle_when_buy_leg_exceeds_limit_price() {
        let plan = plan_multi_pair_netting(
            BatchId("epoch-42".into()),
            &[
                executable_buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 50_000, 4_999),
                executable_sell("0x2", "ETH/STRK", "ETH", "STRK", 10, 50_000, 5_000),
                executable_sell("0x3", "STRK/USDC", "STRK", "USDC", 50_000, 50_000, 1),
            ],
            objective_weights(),
            MultiPairNettingConfig::default(),
        )
        .expect("planner succeeds");

        assert!(plan.is_none());
    }

    #[test]
    fn planner_accepts_cycle_when_final_leg_receives_price_improvement() {
        let plan = plan_multi_pair_netting(
            BatchId("epoch-42".into()),
            &[
                executable_buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 50_000, 6_000),
                executable_sell("0x2", "ETH/STRK", "ETH", "STRK", 10, 50_000, 5_000),
                executable_sell("0x3", "STRK/USDC", "STRK", "USDC", 50_000, 50_000, 1),
            ],
            objective_weights(),
            MultiPairNettingConfig::default(),
        )
        .expect("planner succeeds")
        .expect("price-improved cycle is feasible");

        let fills = plan
            .problem
            .chosen
            .fills
            .iter()
            .map(|fill| {
                (
                    fill.order_commitment.0.as_str(),
                    fill.filled_base_amount,
                    fill.quote_amount,
                )
            })
            .collect::<Vec<_>>();
        let report = verify_multi_pair_optimality(&plan.problem).expect("plan verifies");

        assert_eq!(report.feasibility.fill_count, 3);
        assert_eq!(report.candidate_count, 3);
        assert_eq!(
            fills,
            vec![
                ("0x2", 10, 50_000),
                ("0x3", 50_000, 50_000),
                ("0x1", 10, 50_000),
            ]
        );
    }

    #[test]
    fn planner_partially_fills_cycle_when_one_leg_is_smaller() {
        let plan = plan_multi_pair_netting(
            BatchId("epoch-42".into()),
            &[
                executable_buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 50_000, 5_000),
                executable_sell("0x2", "ETH/STRK", "ETH", "STRK", 4, 4, 5_000),
                executable_sell("0x3", "STRK/USDC", "STRK", "USDC", 20_000, 20_000, 1),
            ],
            objective_weights(),
            MultiPairNettingConfig::default(),
        )
        .expect("planner succeeds")
        .expect("partial cycle is feasible");

        let report = verify_multi_pair_optimality(&plan.problem).expect("plan verifies");
        let fills = plan
            .problem
            .chosen
            .fills
            .iter()
            .map(|fill| (fill.order_commitment.0.as_str(), fill.filled_base_amount))
            .collect::<Vec<_>>();

        assert_eq!(report.feasibility.fill_count, 3);
        assert_eq!(fills, vec![("0x1", 4), ("0x2", 4), ("0x3", 20_000)]);
        assert_eq!(report.feasibility.asset_inputs.get("USDC"), Some(&20_000));
        assert_eq!(report.feasibility.asset_outputs.get("USDC"), Some(&20_000));
    }

    #[test]
    fn planner_packs_compatible_cycles_from_discovered_candidates() {
        let plan = plan_multi_pair_netting(
            BatchId("epoch-42".into()),
            &[
                executable_buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 50_000, 5_000),
                executable_sell("0x2", "ETH/STRK", "ETH", "STRK", 10, 50_000, 5_000),
                executable_sell("0x3", "STRK/USDC", "STRK", "USDC", 50_000, 50_000, 1),
                executable_buy("0x4", "ETH/USDC", "ETH", "USDC", 20, 100_000, 5_000),
                executable_sell("0x5", "ETH/STRK", "ETH", "STRK", 20, 100_000, 5_000),
                executable_sell("0x6", "STRK/USDC", "STRK", "USDC", 100_000, 100_000, 1),
            ],
            objective_weights(),
            MultiPairNettingConfig::default(),
        )
        .expect("planner succeeds")
        .expect("cycles are feasible");

        let selected = plan
            .problem
            .chosen
            .fills
            .iter()
            .map(|fill| fill.order_commitment.0.as_str())
            .collect::<Vec<_>>();

        assert_eq!(selected, vec!["0x4", "0x5", "0x6", "0x1", "0x2", "0x3"]);
        assert!(
            plan.problem
                .candidate_solutions
                .iter()
                .any(|candidate| candidate.solution_id.starts_with("package:")),
            "planner should expose packed candidate bundles to the proof",
        );
        assert!(plan.problem.candidate_solutions.len() <= MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS);
    }

    #[test]
    fn external_completion_obligation_covers_order_when_no_private_plan_exists() {
        let obligations = derive_multi_pair_external_completion_obligations(
            &[executable_buy(
                "0x1", "ETH/USDC", "ETH", "USDC", 10, 25_000, 2_500,
            )],
            None,
        )
        .expect("obligations");

        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].pair_id, PairId("ETH/USDC".into()));
        assert_eq!(obligations[0].side, OrderSide::Buy);
        assert_eq!(obligations[0].input_asset_id, AssetId("USDC".into()));
        assert_eq!(obligations[0].output_asset_id, AssetId("ETH".into()));
        assert_eq!(obligations[0].input_amount, 25_000);
        assert_eq!(obligations[0].gross_output_amount, 10);
        assert_eq!(
            obligations[0].order_commitments,
            vec![OrderCommitment("0x1".into())]
        );
    }

    #[test]
    fn external_completion_obligation_skips_private_only_residual() {
        let mut order = executable_buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 25_000, 2_500);
        order.execution_preference = crate::ExecutionPreference::PrivateOnly;

        let obligations =
            derive_multi_pair_external_completion_obligations(&[order], None).expect("obligations");

        assert!(
            obligations.is_empty(),
            "private-only residuals must not become external completion obligations"
        );
    }

    #[test]
    fn external_completion_obligation_excludes_private_cycle_fills() {
        let orders = vec![
            executable_buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 50_000, 5_000),
            executable_sell("0x2", "ETH/STRK", "ETH", "STRK", 10, 50_000, 5_000),
            executable_sell("0x3", "STRK/USDC", "STRK", "USDC", 50_000, 50_000, 1),
        ];
        let plan = plan_multi_pair_netting(
            BatchId("epoch-42".into()),
            &orders,
            objective_weights(),
            MultiPairNettingConfig::default(),
        )
        .expect("planner succeeds")
        .expect("cycle is feasible");

        let obligations = derive_multi_pair_external_completion_obligations(&orders, Some(&plan))
            .expect("obligations");

        assert!(obligations.is_empty());
    }

    #[test]
    fn external_completion_obligation_covers_only_private_remainder() {
        let orders = vec![
            executable_buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 50_000, 5_000),
            executable_sell("0x2", "ETH/STRK", "ETH", "STRK", 4, 4, 5_000),
            executable_sell("0x3", "STRK/USDC", "STRK", "USDC", 20_000, 20_000, 1),
        ];
        let plan = plan_multi_pair_netting(
            BatchId("epoch-42".into()),
            &orders,
            objective_weights(),
            MultiPairNettingConfig::default(),
        )
        .expect("planner succeeds")
        .expect("partial cycle is feasible");

        let obligations = derive_multi_pair_external_completion_obligations(&orders, Some(&plan))
            .expect("obligations");

        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].side, OrderSide::Buy);
        assert_eq!(obligations[0].input_asset_id, AssetId("USDC".into()));
        assert_eq!(obligations[0].output_asset_id, AssetId("ETH".into()));
        assert_eq!(obligations[0].input_amount, 30_000);
        assert_eq!(obligations[0].gross_output_amount, 6);
        assert_eq!(
            obligations[0].order_commitments,
            vec![OrderCommitment("0x1".into())]
        );
    }

    #[test]
    fn external_completion_obligation_is_capped_by_remaining_buy_input() {
        let obligations = derive_multi_pair_external_completion_obligations(
            &[executable_buy(
                "0x1", "ETH/USDC", "ETH", "USDC", 10, 20_000, 2_500,
            )],
            None,
        )
        .expect("obligations");

        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].input_amount, 20_000);
        assert_eq!(obligations[0].gross_output_amount, 8);
    }

    fn simple_buy_problem() -> MultiPairFeasibilityProblem {
        MultiPairFeasibilityProblem {
            batch_id: BatchId("epoch-42".into()),
            fills: vec![buy("0x1", "ETH/USDC", "ETH", "USDC", 10, 25_000, 2_500)],
            asset_deltas: vec![
                user_delta("0x1", "USDC", 25_000, MultiPairAssetDeltaDirection::In),
                user_delta("0x1", "ETH", 10, MultiPairAssetDeltaDirection::Out),
                external_completion_delta("0x99", "ETH", 10, MultiPairAssetDeltaDirection::In),
                external_completion_delta(
                    "0x99",
                    "USDC",
                    25_000,
                    MultiPairAssetDeltaDirection::Out,
                ),
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

    fn executable_buy(
        commitment: &str,
        pair: &str,
        base: &str,
        quote: &str,
        base_amount: u128,
        quote_funding: u128,
        limit_price: u128,
    ) -> MultiPairExecutableOrder {
        executable(
            commitment,
            pair,
            (base, quote),
            OrderSide::Buy,
            base_amount,
            quote_funding,
            limit_price,
        )
    }

    fn executable_sell(
        commitment: &str,
        pair: &str,
        base: &str,
        quote: &str,
        base_amount: u128,
        available_base: u128,
        limit_price: u128,
    ) -> MultiPairExecutableOrder {
        executable(
            commitment,
            pair,
            (base, quote),
            OrderSide::Sell,
            base_amount,
            available_base,
            limit_price,
        )
    }

    fn executable(
        commitment: &str,
        pair: &str,
        assets: (&str, &str),
        side: OrderSide,
        base_amount: u128,
        available_input_amount: u128,
        limit_price: u128,
    ) -> MultiPairExecutableOrder {
        let (base, quote) = assets;
        MultiPairExecutableOrder {
            order_commitment: OrderCommitment(commitment.into()),
            pair_id: PairId(pair.into()),
            base_asset_id: AssetId(base.into()),
            quote_asset_id: AssetId(quote.into()),
            side,
            submitted_base_amount: base_amount,
            min_fill_base_amount: 1,
            limit_price,
            price_base_scale: 1,
            available_input_amount,
            taker_fee_bps: 0,
            execution_preference: crate::ExecutionPreference::PrivateThenExternal,
        }
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

    fn external_completion_delta(
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
            MultiPairAssetDeltaSource::ExternalCompletion,
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

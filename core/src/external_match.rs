use serde::{Deserialize, Serialize};

use crate::{
    AssetId, BatchId, OrderCommitment, OrderSide, PairId, ProtocolError, StarknetCall,
    base_amount_affordable_for_quote,
    hash::{domain_felt, encode_starknet_felt, felt_from_hex_str, felt_hex, normalize_felt_hex},
    multipair::{
        MultiPairExecutableOrder, MultiPairExternalMatchObligation, MultiPairNettingPlan,
        derive_multi_pair_external_match_obligations,
    },
    quote_amount_for_base_amount,
};
use starknet_crypto::{Felt, poseidon_hash};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMatchRequest {
    pub request_id: String,
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub side: OrderSide,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub max_base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub reference_midpoint_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub price_base_scale: u128,
    pub valid_until_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMatchFill {
    pub request_id: String,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub fill_base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub fill_quote_amount: u128,
    pub net_profit_quote_amount: i128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMatchSettlementRecord {
    pub request: ExternalMatchRequest,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub consumed_base_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMatchOrderAllocation {
    pub request_id: String,
    pub order_commitment: OrderCommitment,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub quote_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalMatchSettlementReport {
    pub request_count: usize,
    pub filled_request_count: usize,
    pub total_consumed_base_amount: u128,
    pub commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMatchAuthorizationWitness {
    pub batch_id: BatchId,
    pub auction_verifier_address: String,
    pub reference_price_signer: String,
    pub multi_pair_problem: Option<crate::multipair::MultiPairCandidateSetProblem>,
    pub orders: Vec<MultiPairExecutableOrder>,
    pub reference_price_attestations: Vec<crate::ReferencePriceAttestation>,
    pub requests: Vec<ExternalMatchRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMatchAuthorizationReport {
    pub multi_pair_commitment: String,
    pub request_root: String,
    pub request_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMatchRouteQuote {
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub fill_base_amount: u128,
    pub hedge: ExternalHedgeQuote,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalHedgeQuote {
    BuyBase {
        #[serde(with = "crate::types::serde_u128_decimal")]
        quote_cost_amount: u128,
    },
    SellBase {
        #[serde(with = "crate::types::serde_u128_decimal")]
        quote_proceeds_amount: u128,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchProfitabilityCosts {
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub rebate_quote_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub gas_quote_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub tip_quote_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub safety_buffer_quote_amount: u128,
    pub min_profit_quote_amount: i128,
}

pub fn external_match_request_from_obligation(
    batch_id: &BatchId,
    obligation: &MultiPairExternalMatchObligation,
    reference_midpoint_price: u128,
    valid_until_unix_ms: u64,
) -> Result<Option<ExternalMatchRequest>, ProtocolError> {
    external_match_request_from_obligations(
        batch_id,
        std::slice::from_ref(obligation),
        reference_midpoint_price,
        valid_until_unix_ms,
    )
}

pub fn external_match_request_from_obligations(
    batch_id: &BatchId,
    obligations: &[MultiPairExternalMatchObligation],
    reference_midpoint_price: u128,
    valid_until_unix_ms: u64,
) -> Result<Option<ExternalMatchRequest>, ProtocolError> {
    if reference_midpoint_price == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match midpoint price must be non-zero".into(),
        ));
    }
    let Some(first) = obligations.first() else {
        return Ok(None);
    };
    if first.price_base_scale == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match price scale must be non-zero".into(),
        ));
    }
    let mut max_base_amount = 0_u128;
    let mut order_commitments = Vec::new();
    for obligation in obligations {
        if obligation.pair_id != first.pair_id
            || obligation.base_asset_id != first.base_asset_id
            || obligation.quote_asset_id != first.quote_asset_id
            || obligation.side != first.side
            || obligation.price_base_scale != first.price_base_scale
        {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match request cannot aggregate different pair, side, or price-scale buckets"
                    .into(),
            ));
        }
        let bucket_max_base = match obligation.side {
            OrderSide::Buy => {
                if reference_midpoint_price > obligation.limit_price {
                    continue;
                }
                base_amount_affordable_for_quote(
                    obligation.input_amount,
                    reference_midpoint_price,
                    obligation.price_base_scale,
                )?
                .min(obligation.gross_output_amount)
            }
            OrderSide::Sell => {
                if reference_midpoint_price < obligation.limit_price {
                    continue;
                }
                obligation.input_amount
            }
        };
        if bucket_max_base == 0 {
            continue;
        }
        max_base_amount = max_base_amount
            .checked_add(bucket_max_base)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "external match aggregate request amount overflows".into(),
                )
            })?;
        order_commitments.extend(obligation.order_commitments.iter().cloned());
    }
    if max_base_amount == 0 {
        return Ok(None);
    }
    order_commitments.sort_by(|left, right| left.0.cmp(&right.0));
    if order_commitments.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match aggregate request contains a duplicate order commitment".into(),
        ));
    }
    let quote_amount = quote_amount_for_base_amount(
        max_base_amount,
        reference_midpoint_price,
        first.price_base_scale,
    )?;
    if quote_amount == 0 {
        return Ok(None);
    }
    let mut request = ExternalMatchRequest {
        request_id: "0x0".into(),
        batch_id: batch_id.clone(),
        pair_id: first.pair_id.clone(),
        base_asset_id: first.base_asset_id.clone(),
        quote_asset_id: first.quote_asset_id.clone(),
        side: first.side,
        max_base_amount,
        reference_midpoint_price,
        price_base_scale: first.price_base_scale,
        valid_until_unix_ms,
    };
    request.request_id = external_match_request_id(&request, &order_commitments)?;
    Ok(Some(request))
}

pub fn external_match_request_id(
    request: &ExternalMatchRequest,
    order_commitments: &[OrderCommitment],
) -> Result<String, ProtocolError> {
    let mut normalized_order_commitments = order_commitments
        .iter()
        .map(|commitment| normalize_felt_hex(&commitment.0))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    normalized_order_commitments.sort();
    if normalized_order_commitments
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match request id contains duplicate order commitments".into(),
        ));
    }
    let mut state = poseidon_hash(
        domain_felt("zylith/external-match-request-v3"),
        felt_from_hex_str(&encode_starknet_felt("batch-id", &request.batch_id.0))?,
    );
    for value in [
        encode_starknet_felt("pair-id", &request.pair_id.0),
        encode_external_match_asset_id(&request.base_asset_id)?,
        encode_external_match_asset_id(&request.quote_asset_id)?,
        encode_u64_hex(match request.side {
            OrderSide::Buy => 0,
            OrderSide::Sell => 1,
        }),
        encode_u128_hex(request.max_base_amount),
        encode_u128_hex(request.reference_midpoint_price),
        encode_u128_hex(request.price_base_scale),
        encode_u64_hex(request.valid_until_unix_ms),
        encode_u64_hex(normalized_order_commitments.len() as u64),
    ] {
        state = poseidon_hash(state, felt_from_hex_str(&value)?);
    }
    let order_leaf_domain = domain_felt("zylith/external-match-order-leaf-v1");
    let mut order_accumulator = Felt::ZERO;
    for commitment in normalized_order_commitments {
        order_accumulator += poseidon_hash(order_leaf_domain, felt_from_hex_str(&commitment)?);
    }
    Ok(felt_hex(&poseidon_hash(state, order_accumulator)))
}

pub fn validate_external_match_fill_amounts(
    request: &ExternalMatchRequest,
    fill_base_amount: u128,
    fill_quote_amount: u128,
) -> Result<(), ProtocolError> {
    if fill_base_amount == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match fill amount must be non-zero".into(),
        ));
    }
    if fill_base_amount > request.max_base_amount {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match fill exceeds request amount".into(),
        ));
    }
    let expected_quote_amount = midpoint_quote_amount(request, fill_base_amount)?;
    if fill_quote_amount != expected_quote_amount {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match fill does not match midpoint".into(),
        ));
    }
    Ok(())
}

pub fn build_external_match_authorization_call(
    auction_verifier_address: &str,
    witness: &ExternalMatchAuthorizationWitness,
) -> Result<StarknetCall, ProtocolError> {
    let report = validate_external_match_authorization_witness(witness)?;
    let auction_verifier_address =
        normalize_felt_hex(auction_verifier_address).map_err(|error| {
            ProtocolError::InvalidSettlementProof(format!(
                "auction verifier address is invalid: {error}"
            ))
        })?;
    if normalize_felt_hex(&witness.auction_verifier_address)? != auction_verifier_address {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match authorization targets a different verifier".into(),
        ));
    }
    let mut requests = witness.requests.iter().collect::<Vec<_>>();
    requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    let mut calldata = vec![
        encode_starknet_felt("batch-id", &witness.batch_id.0),
        normalize_felt_hex(&report.multi_pair_commitment)?,
        normalize_felt_hex(&report.request_root)?,
        normalize_felt_hex(&witness.reference_price_signer)?,
    ];
    let mut push_request_span = |values: Vec<String>| {
        calldata.push(encode_u64_hex(values.len() as u64));
        calldata.extend(values);
    };
    push_request_span(
        requests
            .iter()
            .map(|request| normalize_felt_hex(&request.request_id))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_request_span(
        requests
            .iter()
            .map(|request| encode_starknet_felt("pair-id", &request.pair_id.0))
            .collect(),
    );
    push_request_span(
        requests
            .iter()
            .map(|request| encode_external_match_asset_id(&request.base_asset_id))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_request_span(
        requests
            .iter()
            .map(|request| encode_external_match_asset_id(&request.quote_asset_id))
            .collect::<Result<Vec<_>, ProtocolError>>()?,
    );
    push_request_span(
        requests
            .iter()
            .map(|request| {
                encode_u64_hex(match request.side {
                    OrderSide::Buy => 0,
                    OrderSide::Sell => 1,
                })
            })
            .collect(),
    );
    push_request_span(
        requests
            .iter()
            .map(|request| encode_u128_hex(request.max_base_amount))
            .collect(),
    );
    push_request_span(
        requests
            .iter()
            .map(|request| encode_u128_hex(request.reference_midpoint_price))
            .collect(),
    );
    push_request_span(
        requests
            .iter()
            .map(|request| encode_u128_hex(request.price_base_scale))
            .collect(),
    );
    push_request_span(
        requests
            .iter()
            .map(|request| encode_u64_hex(request.valid_until_unix_ms))
            .collect(),
    );
    Ok(StarknetCall {
        contract_address: auction_verifier_address,
        entrypoint: "authorize_external_match_requests_with_proof_facts".into(),
        calldata,
    })
}

pub fn build_external_match_close_call(
    executor_contract_address: &str,
    request_id: &str,
) -> Result<StarknetCall, ProtocolError> {
    let executor_contract_address =
        normalize_felt_hex(executor_contract_address).map_err(|error| {
            ProtocolError::InvalidSettlementProof(format!(
                "external match executor address is invalid: {error}"
            ))
        })?;
    let request_id = normalize_felt_hex(request_id).map_err(|error| {
        ProtocolError::InvalidSettlementProof(format!(
            "external match request id is invalid: {error}"
        ))
    })?;
    Ok(StarknetCall {
        contract_address: executor_contract_address,
        entrypoint: "close_external_match_request".into(),
        calldata: vec![request_id],
    })
}

pub fn validate_external_match_settlement_records(
    batch_id: &BatchId,
    orders: &[MultiPairExecutableOrder],
    private_plan: Option<&MultiPairNettingPlan>,
    records: &[ExternalMatchSettlementRecord],
) -> Result<ExternalMatchSettlementReport, ProtocolError> {
    let obligations = derive_multi_pair_external_match_obligations(orders, private_plan)?;
    let mut seen = BTreeSet::new();
    let mut previous_request_id: Option<String> = None;
    let mut filled_request_count = 0usize;
    let mut total_consumed_base_amount = 0u128;

    for record in records {
        let request_id = normalize_felt_hex(&record.request.request_id)?;
        if previous_request_id
            .as_ref()
            .is_some_and(|previous| previous >= &request_id)
        {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match settlement records are not in canonical request-id order".into(),
            ));
        }
        previous_request_id = Some(request_id.clone());
        if !seen.insert(request_id) {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match settlement duplicates request id".into(),
            ));
        }
        if record.request.batch_id != *batch_id {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match settlement request has the wrong batch id".into(),
            ));
        }
        if record.consumed_base_amount > record.request.max_base_amount {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match settlement exceeds request amount".into(),
            ));
        }
        let compatible_obligations = obligations
            .iter()
            .filter(|obligation| {
                obligation.pair_id == record.request.pair_id
                    && obligation.base_asset_id == record.request.base_asset_id
                    && obligation.quote_asset_id == record.request.quote_asset_id
                    && obligation.side == record.request.side
                    && obligation.price_base_scale == record.request.price_base_scale
            })
            .cloned()
            .collect::<Vec<_>>();
        let matches_derived_obligation = external_match_request_from_obligations(
            batch_id,
            &compatible_obligations,
            record.request.reference_midpoint_price,
            record.request.valid_until_unix_ms,
        )
        .ok()
        .flatten()
        .is_some_and(|expected| expected == record.request);
        if !matches_derived_obligation {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match settlement request is not a derived private residual".into(),
            ));
        }
        if record.consumed_base_amount != 0 {
            filled_request_count += 1;
            total_consumed_base_amount = total_consumed_base_amount
                .checked_add(record.consumed_base_amount)
                .ok_or_else(|| {
                    ProtocolError::InvalidSettlementProof(
                        "external match settlement consumed amount overflows".into(),
                    )
                })?;
        }
    }

    Ok(ExternalMatchSettlementReport {
        request_count: records.len(),
        filled_request_count,
        total_consumed_base_amount,
        commitment: external_match_settlement_commitment(records)?,
    })
}

pub fn validate_external_match_authorization_witness(
    witness: &ExternalMatchAuthorizationWitness,
) -> Result<ExternalMatchAuthorizationReport, ProtocolError> {
    let plan = witness
        .multi_pair_problem
        .as_ref()
        .map(|problem| {
            if witness.batch_id != problem.chosen.batch_id {
                return Err(ProtocolError::InvalidSettlementProof(
                    "external match authorization batch does not match multi-pair solution".into(),
                ));
            }
            crate::multipair::verify_multi_pair_candidate_set(problem)?;
            Ok(MultiPairNettingPlan {
                problem: problem.clone(),
            })
        })
        .transpose()?;
    let expected_requests = derive_external_match_requests(
        &witness.batch_id,
        &witness.orders,
        plan.as_ref(),
        &witness.reference_price_attestations,
        &witness.reference_price_signer,
        &witness.auction_verifier_address,
    )?;
    let mut actual_requests = witness.requests.clone();
    actual_requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    if actual_requests != expected_requests {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match authorization requests do not equal the complete private residual set"
                .into(),
        ));
    }
    Ok(ExternalMatchAuthorizationReport {
        multi_pair_commitment: witness
            .multi_pair_problem
            .as_ref()
            .map(crate::multi_pair_statement_commitment)
            .transpose()?
            .unwrap_or_else(|| "0x0".into()),
        request_root: external_match_request_root(&actual_requests)?,
        request_count: actual_requests.len(),
    })
}

pub fn derive_external_match_requests(
    batch_id: &BatchId,
    orders: &[MultiPairExecutableOrder],
    private_plan: Option<&MultiPairNettingPlan>,
    reference_price_attestations: &[crate::ReferencePriceAttestation],
    reference_price_signer: &str,
    auction_verifier_address: &str,
) -> Result<Vec<ExternalMatchRequest>, ProtocolError> {
    let obligations = derive_multi_pair_external_match_obligations(orders, private_plan)?;
    let attestations = reference_price_attestations
        .iter()
        .map(|attestation| (attestation.envelope.pair_id.0.clone(), attestation))
        .collect::<BTreeMap<_, _>>();
    if attestations.len() != reference_price_attestations.len() {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match authorization has duplicate pair attestations".into(),
        ));
    }
    let mut expected_requests = Vec::new();
    let mut grouped =
        BTreeMap::<(String, u8, String), Vec<MultiPairExternalMatchObligation>>::new();
    for obligation in obligations {
        grouped
            .entry((
                obligation.pair_id.0.clone(),
                match obligation.side {
                    OrderSide::Buy => 0,
                    OrderSide::Sell => 1,
                },
                obligation.price_base_scale.to_string(),
            ))
            .or_default()
            .push(obligation);
    }
    for ((pair_id, _, _), pair_obligations) in grouped {
        let attestation = attestations.get(&pair_id).ok_or_else(|| {
            ProtocolError::InvalidSettlementProof(
                "external match residual has no signed midpoint attestation".into(),
            )
        })?;
        if !crate::verify_reference_price_attestation(
            attestation,
            reference_price_signer,
            auction_verifier_address,
            attestation.envelope.observed_at_unix_ms,
        )? {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match midpoint attestation signature is invalid".into(),
            ));
        }
        if normalize_felt_hex(&attestation.auction_verifier_address)?
            != normalize_felt_hex(auction_verifier_address)?
        {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match midpoint attestation targets the wrong verifier".into(),
            ));
        }
        let valid_until = attestation.valid_until_unix_ms;
        if let Some(request) = external_match_request_from_obligations(
            batch_id,
            &pair_obligations,
            attestation.envelope.midpoint_price,
            valid_until,
        )? {
            expected_requests.push(request);
        }
    }
    expected_requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(expected_requests)
}

pub fn external_match_request_root(
    requests: &[ExternalMatchRequest],
) -> Result<String, ProtocolError> {
    let mut normalized = requests
        .iter()
        .map(|request| Ok((normalize_felt_hex(&request.request_id)?, request)))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    normalized.sort_by(|left, right| left.0.cmp(&right.0));
    if normalized.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match authorization duplicates request id".into(),
        ));
    }
    let state = poseidon_hash(
        domain_felt("zylith/external-match-authorization-v2"),
        Felt::from(normalized.len() as u64),
    );
    let request_leaf_domain = domain_felt("zylith/external-match-request-leaf-v1");
    let mut request_accumulator = Felt::ZERO;
    for (_, request) in normalized {
        let mut leaf = poseidon_hash(
            request_leaf_domain,
            felt_from_hex_str(&normalize_felt_hex(&request.request_id)?)?,
        );
        for value in [
            encode_starknet_felt("batch-id", &request.batch_id.0),
            encode_starknet_felt("pair-id", &request.pair_id.0),
            encode_external_match_asset_id(&request.base_asset_id)?,
            encode_external_match_asset_id(&request.quote_asset_id)?,
            encode_u64_hex(match request.side {
                OrderSide::Buy => 0,
                OrderSide::Sell => 1,
            }),
            encode_u128_hex(request.max_base_amount),
            encode_u128_hex(request.reference_midpoint_price),
            encode_u128_hex(request.price_base_scale),
            encode_u64_hex(request.valid_until_unix_ms),
        ] {
            leaf = poseidon_hash(leaf, felt_from_hex_str(&value)?);
        }
        request_accumulator += leaf;
    }
    Ok(felt_hex(&poseidon_hash(state, request_accumulator)))
}

pub fn allocate_external_match_settlements(
    batch_id: &BatchId,
    orders: &[MultiPairExecutableOrder],
    private_plan: Option<&MultiPairNettingPlan>,
    records: &[ExternalMatchSettlementRecord],
) -> Result<Vec<ExternalMatchOrderAllocation>, ProtocolError> {
    validate_external_match_settlement_records(batch_id, orders, private_plan, records)?;
    let private_fills = private_fill_totals(orders, private_plan)?;
    let mut allocations = Vec::new();

    for record in records {
        if record.consumed_base_amount == 0 {
            continue;
        }
        let request = &record.request;
        let mut capacities = orders
            .iter()
            .filter(|order| {
                order.execution_preference.allows_external_match()
                    && order.pair_id == request.pair_id
                    && order.base_asset_id == request.base_asset_id
                    && order.quote_asset_id == request.quote_asset_id
                    && order.side == request.side
                    && order.price_base_scale == request.price_base_scale
            })
            .map(|order| {
                let commitment = normalize_felt_hex(&order.order_commitment.0)?;
                let filled_base = private_fills
                    .base_by_order
                    .get(&commitment)
                    .copied()
                    .unwrap_or(0);
                let consumed_input = private_fills
                    .input_by_order
                    .get(&commitment)
                    .copied()
                    .unwrap_or(0);
                let remaining_base = order
                    .submitted_base_amount
                    .checked_sub(filled_base)
                    .ok_or_else(|| {
                        ProtocolError::InvalidSettlementProof(
                            "private fill exceeds order while allocating external match".into(),
                        )
                    })?;
                let remaining_input = order
                    .available_input_amount
                    .checked_sub(consumed_input)
                    .ok_or_else(|| {
                        ProtocolError::InvalidSettlementProof(
                            "private input exceeds funding while allocating external match".into(),
                        )
                    })?;
                let capacity = match order.side {
                    OrderSide::Buy if request.reference_midpoint_price <= order.limit_price => {
                        base_amount_affordable_for_quote(
                            remaining_input,
                            request.reference_midpoint_price,
                            request.price_base_scale,
                        )?
                        .min(remaining_base)
                    }
                    OrderSide::Sell if request.reference_midpoint_price >= order.limit_price => {
                        remaining_input.min(remaining_base)
                    }
                    _ => 0,
                };
                Ok((commitment, order.order_commitment.clone(), capacity))
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        capacities.retain(|(_, _, capacity)| *capacity != 0);
        capacities.sort_by(|left, right| left.0.cmp(&right.0));
        let total_capacity = capacities.iter().try_fold(0_u128, |total, item| {
            total.checked_add(item.2).ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "external match allocation capacity overflows".into(),
                )
            })
        })?;
        if total_capacity != request.max_base_amount {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match request amount does not equal private per-order capacity".into(),
            ));
        }

        let mut request_allocations = Vec::with_capacity(capacities.len());
        let mut allocated_base = 0_u128;
        for (commitment, order_commitment, capacity) in capacities {
            let product = record
                .consumed_base_amount
                .checked_mul(capacity)
                .ok_or_else(|| {
                    ProtocolError::InvalidSettlementProof(
                        "external match pro-rata multiplication overflows".into(),
                    )
                })?;
            let base_amount = product / total_capacity;
            let base_remainder = product % total_capacity;
            allocated_base = allocated_base.checked_add(base_amount).ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "external match allocated base overflows".into(),
                )
            })?;
            request_allocations.push((
                commitment,
                order_commitment,
                capacity,
                base_amount,
                base_remainder,
            ));
        }
        let mut base_dust = record.consumed_base_amount - allocated_base;
        request_allocations
            .sort_by(|left, right| right.4.cmp(&left.4).then_with(|| left.0.cmp(&right.0)));
        for allocation in &mut request_allocations {
            if base_dust == 0 {
                break;
            }
            if allocation.3 < allocation.2 {
                allocation.3 += 1;
                base_dust -= 1;
            }
        }
        if base_dust != 0 {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match pro-rata base dust could not be allocated".into(),
            ));
        }

        let aggregate_quote = midpoint_quote_amount(request, record.consumed_base_amount)?;
        let mut allocated_quote = 0_u128;
        let mut finalized = request_allocations
            .into_iter()
            .filter(|allocation| allocation.3 != 0)
            .map(|(commitment, order_commitment, _, base_amount, _)| {
                let product = base_amount
                    .checked_mul(request.reference_midpoint_price)
                    .ok_or_else(|| {
                        ProtocolError::InvalidSettlementProof(
                            "external match allocation quote multiplication overflows".into(),
                        )
                    })?;
                let quote_amount = product / request.price_base_scale;
                let quote_remainder = product % request.price_base_scale;
                allocated_quote = allocated_quote.checked_add(quote_amount).ok_or_else(|| {
                    ProtocolError::InvalidSettlementProof(
                        "external match allocated quote overflows".into(),
                    )
                })?;
                Ok((
                    commitment,
                    order_commitment,
                    base_amount,
                    quote_amount,
                    quote_remainder,
                ))
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        let mut quote_dust = aggregate_quote
            .checked_sub(allocated_quote)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "external match per-order quote exceeds aggregate midpoint quote".into(),
                )
            })?;
        finalized.sort_by(|left, right| right.4.cmp(&left.4).then_with(|| left.0.cmp(&right.0)));
        for allocation in &mut finalized {
            if quote_dust == 0 {
                break;
            }
            allocation.3 = allocation.3.checked_add(1).ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "external match quote dust allocation overflows".into(),
                )
            })?;
            quote_dust -= 1;
        }
        if quote_dust != 0 {
            return Err(ProtocolError::InvalidSettlementProof(
                "external match midpoint quote dust could not be allocated".into(),
            ));
        }
        finalized.sort_by(|left, right| left.0.cmp(&right.0));
        allocations.extend(finalized.into_iter().map(
            |(_, order_commitment, base_amount, quote_amount, _)| ExternalMatchOrderAllocation {
                request_id: request.request_id.clone(),
                order_commitment,
                base_amount,
                quote_amount,
            },
        ));
    }
    Ok(allocations)
}

pub fn final_multi_pair_fills_with_external_matches(
    batch_id: &BatchId,
    orders: &[MultiPairExecutableOrder],
    private_plan: Option<&MultiPairNettingPlan>,
    records: &[ExternalMatchSettlementRecord],
) -> Result<Vec<crate::MultiPairFill>, ProtocolError> {
    let allocations = allocate_external_match_settlements(batch_id, orders, private_plan, records)?;
    let mut private_by_order = BTreeMap::new();
    if let Some(plan) = private_plan {
        for fill in &plan.problem.chosen.fills {
            let commitment = normalize_felt_hex(&fill.order_commitment.0)?;
            if private_by_order.insert(commitment, fill).is_some() {
                return Err(ProtocolError::InvalidSettlementProof(
                    "private multi-pair plan fills an order more than once".into(),
                ));
            }
        }
    }
    let mut external_by_order = BTreeMap::<String, (u128, u128)>::new();
    for allocation in allocations {
        let commitment = normalize_felt_hex(&allocation.order_commitment.0)?;
        let totals = external_by_order.entry(commitment).or_default();
        totals.0 = totals
            .0
            .checked_add(allocation.base_amount)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof("external base allocation overflows".into())
            })?;
        totals.1 = totals
            .1
            .checked_add(allocation.quote_amount)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof("external quote allocation overflows".into())
            })?;
    }

    let mut fills = Vec::new();
    let mut seen = BTreeSet::new();
    let mut sorted_orders = orders
        .iter()
        .map(|order| Ok((normalize_felt_hex(&order.order_commitment.0)?, order)))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    sorted_orders.sort_by(|left, right| left.0.cmp(&right.0));
    for (commitment, order) in sorted_orders {
        if !seen.insert(commitment.clone()) {
            return Err(ProtocolError::InvalidSettlementProof(
                "external settlement order commitment is duplicated".into(),
            ));
        }
        let private = private_by_order.get(&commitment).copied();
        let (external_base, external_quote) = external_by_order
            .get(&commitment)
            .copied()
            .unwrap_or_default();
        let private_base = private.map(|fill| fill.filled_base_amount).unwrap_or(0);
        let private_quote = private.map(|fill| fill.quote_amount).unwrap_or(0);
        let filled_base_amount = private_base.checked_add(external_base).ok_or_else(|| {
            ProtocolError::InvalidSettlementProof("final base fill overflows".into())
        })?;
        if filled_base_amount == 0 {
            continue;
        }
        let quote_amount = private_quote.checked_add(external_quote).ok_or_else(|| {
            ProtocolError::InvalidSettlementProof("final quote fill overflows".into())
        })?;
        let gross_output = match order.side {
            OrderSide::Buy => filled_base_amount,
            OrderSide::Sell => quote_amount,
        };
        let fee_amount = ceil_bps(gross_output, u128::from(order.taker_fee_bps))?;
        if fee_amount >= gross_output {
            return Err(ProtocolError::InvalidSettlementProof(
                "final external match fee consumes order output".into(),
            ));
        }
        fills.push(crate::MultiPairFill {
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
            taker_fee_bps: order.taker_fee_bps,
            fee_amount,
        });
    }
    if private_by_order
        .keys()
        .any(|commitment| !seen.contains(commitment))
        || external_by_order
            .keys()
            .any(|commitment| !seen.contains(commitment))
    {
        return Err(ProtocolError::InvalidSettlementProof(
            "final fill references an unknown admitted order".into(),
        ));
    }
    Ok(fills)
}

fn ceil_bps(amount: u128, bps: u128) -> Result<u128, ProtocolError> {
    let numerator = amount.checked_mul(bps).ok_or_else(|| {
        ProtocolError::InvalidSettlementProof("external match fee multiplication overflows".into())
    })?;
    Ok(numerator.checked_add(9_999).ok_or_else(|| {
        ProtocolError::InvalidSettlementProof("external match fee rounding overflows".into())
    })? / 10_000)
}

struct PrivateFillTotals {
    base_by_order: BTreeMap<String, u128>,
    input_by_order: BTreeMap<String, u128>,
}

fn private_fill_totals(
    orders: &[MultiPairExecutableOrder],
    private_plan: Option<&MultiPairNettingPlan>,
) -> Result<PrivateFillTotals, ProtocolError> {
    let known = orders
        .iter()
        .map(|order| Ok((normalize_felt_hex(&order.order_commitment.0)?, order)))
        .collect::<Result<BTreeMap<_, _>, ProtocolError>>()?;
    let mut base = BTreeMap::new();
    let mut input = BTreeMap::new();
    if let Some(plan) = private_plan {
        for fill in &plan.problem.chosen.fills {
            let commitment = normalize_felt_hex(&fill.order_commitment.0)?;
            let order = known.get(&commitment).ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "external allocation references private fill for unknown order".into(),
                )
            })?;
            if fill.side != order.side || fill.pair_id != order.pair_id {
                return Err(ProtocolError::InvalidSettlementProof(
                    "external allocation private fill metadata mismatch".into(),
                ));
            }
            let consumed = match fill.side {
                OrderSide::Buy => fill.quote_amount,
                OrderSide::Sell => fill.filled_base_amount,
            };
            *base.entry(commitment.clone()).or_insert(0_u128) = base
                .get(&commitment)
                .copied()
                .unwrap_or(0)
                .checked_add(fill.filled_base_amount)
                .ok_or_else(|| {
                    ProtocolError::InvalidSettlementProof(
                        "external allocation private base total overflows".into(),
                    )
                })?;
            *input.entry(commitment.clone()).or_insert(0_u128) = input
                .get(&commitment)
                .copied()
                .unwrap_or(0)
                .checked_add(consumed)
                .ok_or_else(|| {
                    ProtocolError::InvalidSettlementProof(
                        "external allocation private input total overflows".into(),
                    )
                })?;
        }
    }
    Ok(PrivateFillTotals {
        base_by_order: base,
        input_by_order: input,
    })
}

pub fn external_match_settlement_commitment(
    records: &[ExternalMatchSettlementRecord],
) -> Result<String, ProtocolError> {
    let mut normalized = records
        .iter()
        .map(|record| Ok((normalize_felt_hex(&record.request.request_id)?, record)))
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    normalized.sort_by(|left, right| left.0.cmp(&right.0));
    let mut state = poseidon_hash(
        domain_felt("zylith/external-match-settlement-v1"),
        Felt::from(records.len() as u64),
    );
    for (_, record) in normalized {
        let request = &record.request;
        for value in [
            normalize_felt_hex(&request.request_id)?,
            encode_starknet_felt("batch-id", &request.batch_id.0),
            encode_starknet_felt("pair-id", &request.pair_id.0),
            encode_external_match_asset_id(&request.base_asset_id)?,
            encode_external_match_asset_id(&request.quote_asset_id)?,
            encode_u64_hex(match request.side {
                OrderSide::Buy => 0,
                OrderSide::Sell => 1,
            }),
            encode_u128_hex(request.max_base_amount),
            encode_u128_hex(request.reference_midpoint_price),
            encode_u128_hex(request.price_base_scale),
            encode_u64_hex(request.valid_until_unix_ms),
            encode_u128_hex(record.consumed_base_amount),
        ] {
            state = poseidon_hash(state, felt_from_hex_str(&value)?);
        }
    }
    Ok(felt_hex(&state))
}

pub fn optimal_external_match_fill(
    request: &ExternalMatchRequest,
    routes: &[ExternalMatchRouteQuote],
    costs: MatchProfitabilityCosts,
) -> Option<ExternalMatchFill> {
    routes
        .iter()
        .filter_map(|route| external_match_fill_candidate(request, route, costs))
        .filter(|fill| fill.net_profit_quote_amount >= costs.min_profit_quote_amount)
        .max_by_key(|fill| (fill.net_profit_quote_amount, fill.fill_base_amount))
}

fn external_match_fill_candidate(
    request: &ExternalMatchRequest,
    route: &ExternalMatchRouteQuote,
    costs: MatchProfitabilityCosts,
) -> Option<ExternalMatchFill> {
    let fill_base_amount = route.fill_base_amount;
    if fill_base_amount == 0 || fill_base_amount > request.max_base_amount {
        return None;
    }
    let fill_quote_amount = midpoint_quote_amount(request, fill_base_amount).ok()?;
    let gross_profit = match (&request.side, &route.hedge) {
        (OrderSide::Buy, ExternalHedgeQuote::BuyBase { quote_cost_amount }) => {
            checked_i128(fill_quote_amount)?.checked_sub(checked_i128(*quote_cost_amount)?)?
        }
        (
            OrderSide::Sell,
            ExternalHedgeQuote::SellBase {
                quote_proceeds_amount,
            },
        ) => checked_i128(*quote_proceeds_amount)?.checked_sub(checked_i128(fill_quote_amount)?)?,
        _ => return None,
    };
    let total_costs = checked_i128(costs.gas_quote_amount)?
        .checked_add(checked_i128(costs.tip_quote_amount)?)?
        .checked_add(checked_i128(costs.safety_buffer_quote_amount)?)?;
    let net_profit = gross_profit
        .checked_add(checked_i128(costs.rebate_quote_amount)?)?
        .checked_sub(total_costs)?;
    Some(ExternalMatchFill {
        request_id: request.request_id.clone(),
        fill_base_amount,
        fill_quote_amount,
        net_profit_quote_amount: net_profit,
    })
}

fn midpoint_quote_amount(
    request: &ExternalMatchRequest,
    fill_base_amount: u128,
) -> Result<u128, ProtocolError> {
    quote_amount_for_base_amount(
        fill_base_amount,
        request.reference_midpoint_price,
        request.price_base_scale,
    )
}

fn checked_i128(value: u128) -> Option<i128> {
    i128::try_from(value).ok()
}

pub fn encode_external_match_asset_id(asset_id: &AssetId) -> Result<String, ProtocolError> {
    let trimmed = asset_id.0.trim();
    if trimmed.is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "external match asset id is empty".into(),
        ));
    }
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        normalize_felt_hex(trimmed).map_err(|error| {
            ProtocolError::InvalidSettlementProof(format!(
                "external match asset id is invalid: {error}"
            ))
        })
    } else {
        Ok(encode_starknet_felt("asset-id", trimmed))
    }
}

fn encode_u128_hex(value: u128) -> String {
    format!("0x{value:x}")
}

fn encode_u64_hex(value: u64) -> String {
    format!("0x{value:x}")
}

#[cfg(test)]
mod tests {
    use crate::{
        AssetId, BatchId, ExecutionPreference, OrderCommitment, OrderSide, PairId,
        external_match::{
            ExternalHedgeQuote, ExternalMatchAuthorizationWitness, ExternalMatchRequest,
            ExternalMatchRouteQuote, ExternalMatchSettlementRecord, MatchProfitabilityCosts,
            allocate_external_match_settlements, build_external_match_authorization_call,
            build_external_match_close_call, external_match_request_from_obligation,
            external_match_request_from_obligations, external_match_settlement_commitment,
            final_multi_pair_fills_with_external_matches, optimal_external_match_fill,
            validate_external_match_authorization_witness, validate_external_match_fill_amounts,
            validate_external_match_settlement_records,
        },
        hash::encode_starknet_felt,
        multipair::{MultiPairExecutableOrder, MultiPairExternalMatchObligation},
        reference_price::ReferencePriceEnvelope,
        reference_price_source_set_commitment, sign_reference_price_attestation,
    };

    fn request(side: OrderSide, max_base_amount: u128) -> ExternalMatchRequest {
        ExternalMatchRequest {
            request_id: "req-1".into(),
            batch_id: BatchId("batch-1".into()),
            pair_id: PairId("ETH/USDC".into()),
            base_asset_id: AssetId("ETH".into()),
            quote_asset_id: AssetId("USDC".into()),
            side,
            max_base_amount,
            reference_midpoint_price: 4_000_000_000,
            price_base_scale: 1_000_000,
            valid_until_unix_ms: 1_900_000_000_000,
        }
    }

    #[test]
    fn buy_residual_profit_is_midpoint_proceeds_minus_external_base_cost() {
        let request = request(OrderSide::Buy, 100);
        let fill = optimal_external_match_fill(
            &request,
            &[ExternalMatchRouteQuote {
                fill_base_amount: 100,
                hedge: ExternalHedgeQuote::BuyBase {
                    quote_cost_amount: 396_000,
                },
            }],
            MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 1_000,
                tip_quote_amount: 500,
                safety_buffer_quote_amount: 500,
                min_profit_quote_amount: 1,
            },
        )
        .expect("profitable buy residual");

        assert_eq!(fill.fill_base_amount, 100);
        assert_eq!(fill.fill_quote_amount, 400_000);
        assert_eq!(fill.net_profit_quote_amount, 2_000);
    }

    #[test]
    fn sell_residual_profit_is_external_base_sale_proceeds_minus_midpoint_purchase_cost() {
        let request = request(OrderSide::Sell, 100);
        let fill = optimal_external_match_fill(
            &request,
            &[ExternalMatchRouteQuote {
                fill_base_amount: 100,
                hedge: ExternalHedgeQuote::SellBase {
                    quote_proceeds_amount: 403_000,
                },
            }],
            MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 1_000,
                tip_quote_amount: 500,
                safety_buffer_quote_amount: 500,
                min_profit_quote_amount: 1,
            },
        )
        .expect("profitable sell residual");

        assert_eq!(fill.fill_base_amount, 100);
        assert_eq!(fill.fill_quote_amount, 400_000);
        assert_eq!(fill.net_profit_quote_amount, 1_000);
    }

    #[test]
    fn chooses_profitable_partial_fill_instead_of_larger_unprofitable_size() {
        let request = request(OrderSide::Buy, 500);
        let fill = optimal_external_match_fill(
            &request,
            &[
                ExternalMatchRouteQuote {
                    fill_base_amount: 500,
                    hedge: ExternalHedgeQuote::BuyBase {
                        quote_cost_amount: 2_001_000,
                    },
                },
                ExternalMatchRouteQuote {
                    fill_base_amount: 100,
                    hedge: ExternalHedgeQuote::BuyBase {
                        quote_cost_amount: 399_000,
                    },
                },
            ],
            MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 100,
                tip_quote_amount: 100,
                safety_buffer_quote_amount: 100,
                min_profit_quote_amount: 1,
            },
        )
        .expect("profitable partial fill");

        assert_eq!(fill.fill_base_amount, 100);
        assert_eq!(fill.net_profit_quote_amount, 700);
    }

    #[test]
    fn rebate_is_explicit_and_zero_baseline_can_reject_subsidized_only_fill() {
        let request = request(OrderSide::Buy, 100);
        let candidate = ExternalMatchRouteQuote {
            fill_base_amount: 100,
            hedge: ExternalHedgeQuote::BuyBase {
                quote_cost_amount: 400_100,
            },
        };

        assert!(
            optimal_external_match_fill(
                &request,
                std::slice::from_ref(&candidate),
                MatchProfitabilityCosts {
                    rebate_quote_amount: 0,
                    gas_quote_amount: 0,
                    tip_quote_amount: 0,
                    safety_buffer_quote_amount: 0,
                    min_profit_quote_amount: 1,
                },
            )
            .is_none()
        );

        let subsidized = optimal_external_match_fill(
            &request,
            &[candidate],
            MatchProfitabilityCosts {
                rebate_quote_amount: 200,
                gas_quote_amount: 0,
                tip_quote_amount: 0,
                safety_buffer_quote_amount: 0,
                min_profit_quote_amount: 1,
            },
        )
        .expect("rebate makes the fill profitable");

        assert_eq!(subsidized.net_profit_quote_amount, 100);
    }

    #[test]
    fn fill_amounts_must_match_committed_midpoint() {
        let request = request(OrderSide::Buy, 100);

        assert!(validate_external_match_fill_amounts(&request, 100, 400_000).is_ok());
        assert!(validate_external_match_fill_amounts(&request, 100, 400_001).is_err());
    }

    fn obligation(side: OrderSide) -> MultiPairExternalMatchObligation {
        MultiPairExternalMatchObligation {
            pair_id: PairId("ETH/USDC".into()),
            base_asset_id: AssetId("ETH".into()),
            quote_asset_id: AssetId("USDC".into()),
            side,
            input_asset_id: match side {
                OrderSide::Buy => AssetId("USDC".into()),
                OrderSide::Sell => AssetId("ETH".into()),
            },
            output_asset_id: match side {
                OrderSide::Buy => AssetId("ETH".into()),
                OrderSide::Sell => AssetId("USDC".into()),
            },
            input_amount: match side {
                OrderSide::Buy => 4_000_000,
                OrderSide::Sell => 1_000,
            },
            gross_output_amount: match side {
                OrderSide::Buy => 1_000,
                OrderSide::Sell => 4_000_000,
            },
            limit_price: 4_100,
            price_base_scale: 1,
            order_commitments: vec![OrderCommitment("0x1".into())],
        }
    }

    #[test]
    fn external_match_request_uses_reference_midpoint_not_user_limit() {
        let request = external_match_request_from_obligation(
            &BatchId("batch-1".into()),
            &obligation(OrderSide::Buy),
            4_000,
            1_900_000_000_000,
        )
        .expect("request derivation succeeds")
        .expect("midpoint-valid request");

        assert_eq!(request.side, OrderSide::Buy);
        assert_eq!(request.max_base_amount, 1_000);
        assert_eq!(request.reference_midpoint_price, 4_000);
        assert_eq!(request.price_base_scale, 1);
        assert!(request.request_id.starts_with("0x"));
    }

    #[test]
    fn external_match_request_aggregates_compatible_limit_buckets_at_midpoint() {
        let mut tighter = obligation(OrderSide::Buy);
        tighter.limit_price = 4_050;
        tighter.input_amount = 1_600_000;
        tighter.gross_output_amount = 400;
        tighter.order_commitments = vec![OrderCommitment("0x2".into())];
        let mut wider = obligation(OrderSide::Buy);
        wider.limit_price = 4_100;
        wider.input_amount = 2_400_000;
        wider.gross_output_amount = 600;
        wider.order_commitments = vec![OrderCommitment("0x1".into())];

        let request = external_match_request_from_obligations(
            &BatchId("batch-1".into()),
            &[tighter, wider],
            4_000,
            1_900_000_000_000,
        )
        .expect("aggregate request derivation succeeds")
        .expect("both buckets are midpoint-compatible");

        assert_eq!(request.max_base_amount, 1_000);

        let reversed = external_match_request_from_obligations(
            &BatchId("batch-1".into()),
            &[
                {
                    let mut item = obligation(OrderSide::Buy);
                    item.limit_price = 4_100;
                    item.input_amount = 2_400_000;
                    item.gross_output_amount = 600;
                    item.order_commitments = vec![OrderCommitment("0x1".into())];
                    item
                },
                {
                    let mut item = obligation(OrderSide::Buy);
                    item.limit_price = 4_050;
                    item.input_amount = 1_600_000;
                    item.gross_output_amount = 400;
                    item.order_commitments = vec![OrderCommitment("0x2".into())];
                    item
                },
            ],
            4_000,
            1_900_000_000_000,
        )
        .expect("reversed request derivation succeeds")
        .expect("reversed request remains fillable");
        assert_eq!(request.request_id, reversed.request_id);
    }

    #[test]
    fn external_match_request_excludes_limit_bucket_incompatible_with_midpoint() {
        let compatible = obligation(OrderSide::Buy);
        let mut incompatible = obligation(OrderSide::Buy);
        incompatible.limit_price = 3_900;
        incompatible.order_commitments = vec![OrderCommitment("0x2".into())];

        let request = external_match_request_from_obligations(
            &BatchId("batch-1".into()),
            &[compatible],
            4_000,
            1_900_000_000_000,
        )
        .unwrap()
        .unwrap();
        let with_incompatible = external_match_request_from_obligations(
            &BatchId("batch-1".into()),
            &[obligation(OrderSide::Buy), incompatible],
            4_000,
            1_900_000_000_000,
        )
        .unwrap()
        .unwrap();

        assert_eq!(with_incompatible, request);
    }

    #[test]
    fn close_call_freezes_request_before_final_settlement_proving() {
        let call = build_external_match_close_call("0x123", "0xabc").expect("close call");
        assert_eq!(call.contract_address, "0x123");
        assert_eq!(call.entrypoint, "close_external_match_request");
        assert_eq!(call.calldata, vec!["0xabc"]);
    }

    fn executable_buy_order() -> MultiPairExecutableOrder {
        MultiPairExecutableOrder {
            order_commitment: OrderCommitment("0x1".into()),
            pair_id: PairId("ETH/USDC".into()),
            base_asset_id: AssetId("ETH".into()),
            quote_asset_id: AssetId("USDC".into()),
            side: OrderSide::Buy,
            submitted_base_amount: 1_000,
            min_fill_base_amount: 1,
            limit_price: 4_100,
            price_base_scale: 1,
            available_input_amount: 4_000_000,
            taker_fee_bps: 4,
            execution_preference: ExecutionPreference::PrivateThenExternal,
        }
    }

    #[test]
    fn settlement_record_is_bound_to_the_derived_private_residual() {
        let batch_id = BatchId("batch-1".into());
        let orders = vec![executable_buy_order()];
        let obligation = crate::derive_multi_pair_external_match_obligations(&orders, None)
            .expect("obligation")
            .remove(0);
        let request = external_match_request_from_obligation(
            &batch_id,
            &obligation,
            4_000,
            1_900_000_000_000,
        )
        .expect("request")
        .expect("fillable request");
        let records = vec![ExternalMatchSettlementRecord {
            request,
            consumed_base_amount: 600,
        }];

        let report = validate_external_match_settlement_records(&batch_id, &orders, None, &records)
            .expect("valid frozen residual");

        assert_eq!(report.request_count, 1);
        assert_eq!(report.filled_request_count, 1);
        assert_eq!(report.total_consumed_base_amount, 600);
        assert_eq!(
            report.commitment,
            external_match_settlement_commitment(&records).unwrap()
        );
    }

    #[test]
    fn settlement_record_accepts_one_aggregate_request_for_different_user_limits() {
        let batch_id = BatchId("batch-1".into());
        let first = executable_buy_order();
        let mut second = executable_buy_order();
        second.order_commitment = OrderCommitment("0x2".into());
        second.submitted_base_amount = 500;
        second.available_input_amount = 2_000_000;
        second.limit_price = 4_050;
        let orders = vec![first, second];
        let obligations = crate::derive_multi_pair_external_match_obligations(&orders, None)
            .expect("residual obligations");
        assert_eq!(
            obligations.len(),
            2,
            "private limits remain private buckets"
        );
        let request = external_match_request_from_obligations(
            &batch_id,
            &obligations,
            4_000,
            1_900_000_000_000,
        )
        .expect("aggregate request")
        .expect("aggregate request is fillable");
        assert_eq!(request.max_base_amount, 1_500);

        let report = validate_external_match_settlement_records(
            &batch_id,
            &orders,
            None,
            &[ExternalMatchSettlementRecord {
                request,
                consumed_base_amount: 900,
            }],
        )
        .expect("aggregate request is derived from all compatible private residuals");

        assert_eq!(report.total_consumed_base_amount, 900);
    }

    #[test]
    fn aggregate_external_fill_is_allocated_pro_rata_to_private_orders() {
        let batch_id = BatchId("batch-1".into());
        let first = executable_buy_order();
        let mut second = executable_buy_order();
        second.order_commitment = OrderCommitment("0x2".into());
        second.submitted_base_amount = 500;
        second.available_input_amount = 2_000_000;
        second.limit_price = 4_050;
        let orders = vec![first, second];
        let obligations = crate::derive_multi_pair_external_match_obligations(&orders, None)
            .expect("residual obligations");
        let request = external_match_request_from_obligations(
            &batch_id,
            &obligations,
            4_000,
            1_900_000_000_000,
        )
        .unwrap()
        .unwrap();
        let allocations = allocate_external_match_settlements(
            &batch_id,
            &orders,
            None,
            &[ExternalMatchSettlementRecord {
                request,
                consumed_base_amount: 900,
            }],
        )
        .expect("deterministic pro-rata allocation");

        assert_eq!(allocations.len(), 2);
        assert_eq!(
            allocations[0].order_commitment,
            OrderCommitment("0x1".into())
        );
        assert_eq!(allocations[0].base_amount, 600);
        assert_eq!(allocations[0].quote_amount, 2_400_000);
        assert_eq!(
            allocations[1].order_commitment,
            OrderCommitment("0x2".into())
        );
        assert_eq!(allocations[1].base_amount, 300);
        assert_eq!(allocations[1].quote_amount, 1_200_000);
    }

    #[test]
    fn final_fills_include_external_only_orders_and_recompute_total_fee() {
        let batch_id = BatchId("batch-1".into());
        let first = executable_buy_order();
        let mut second = executable_buy_order();
        second.order_commitment = OrderCommitment("0x2".into());
        second.submitted_base_amount = 500;
        second.available_input_amount = 2_000_000;
        second.limit_price = 4_050;
        let orders = vec![first, second];
        let obligations = crate::derive_multi_pair_external_match_obligations(&orders, None)
            .expect("residual obligations");
        let request = external_match_request_from_obligations(
            &batch_id,
            &obligations,
            4_000,
            1_900_000_000_000,
        )
        .unwrap()
        .unwrap();
        let fills = final_multi_pair_fills_with_external_matches(
            &batch_id,
            &orders,
            None,
            &[ExternalMatchSettlementRecord {
                request,
                consumed_base_amount: 900,
            }],
        )
        .expect("final external-only fills");

        assert_eq!(fills.len(), 2);
        assert_eq!(fills[0].order_commitment, OrderCommitment("0x1".into()));
        assert_eq!(fills[0].filled_base_amount, 600);
        assert_eq!(fills[0].quote_amount, 2_400_000);
        assert_eq!(fills[0].fee_amount, 1);
        assert_eq!(fills[1].order_commitment, OrderCommitment("0x2".into()));
        assert_eq!(fills[1].filled_base_amount, 300);
        assert_eq!(fills[1].quote_amount, 1_200_000);
        assert_eq!(fills[1].fee_amount, 1);
    }

    #[test]
    fn final_fills_merge_private_and_external_execution_per_order() {
        let batch_id = BatchId("batch-1".into());
        let first = executable_buy_order();
        let mut second = executable_buy_order();
        second.order_commitment = OrderCommitment("0x2".into());
        second.submitted_base_amount = 500;
        second.available_input_amount = 2_000_000;
        second.limit_price = 4_050;
        let orders = vec![first.clone(), second];
        let private_fill = crate::MultiPairFill {
            order_commitment: first.order_commitment.clone(),
            pair_id: first.pair_id.clone(),
            base_asset_id: first.base_asset_id.clone(),
            quote_asset_id: first.quote_asset_id.clone(),
            side: first.side,
            submitted_base_amount: first.submitted_base_amount,
            min_fill_base_amount: first.min_fill_base_amount,
            limit_price: first.limit_price,
            price_base_scale: first.price_base_scale,
            filled_base_amount: 400,
            quote_amount: 1_600_000,
            taker_fee_bps: first.taker_fee_bps,
            fee_amount: 1,
        };
        let plan = crate::MultiPairNettingPlan {
            problem: crate::MultiPairCandidateSetProblem {
                chosen: crate::MultiPairFeasibilityProblem {
                    batch_id: batch_id.clone(),
                    fills: vec![private_fill],
                    asset_deltas: vec![],
                },
                eligible_order_commitments: orders
                    .iter()
                    .map(|order| order.order_commitment.clone())
                    .collect(),
                objective_weights: vec![],
                candidate_solutions: vec![],
            },
        };
        let obligations = crate::derive_multi_pair_external_match_obligations(&orders, Some(&plan))
            .expect("residual obligations");
        let request = external_match_request_from_obligations(
            &batch_id,
            &obligations,
            4_000,
            1_900_000_000_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.max_base_amount, 1_100);

        let fills = final_multi_pair_fills_with_external_matches(
            &batch_id,
            &orders,
            Some(&plan),
            &[ExternalMatchSettlementRecord {
                request,
                consumed_base_amount: 550,
            }],
        )
        .expect("mixed private and external fills");

        assert_eq!(fills.len(), 2);
        assert_eq!(fills[0].order_commitment, OrderCommitment("0x1".into()));
        assert_eq!(fills[0].filled_base_amount, 700);
        assert_eq!(fills[0].quote_amount, 2_800_000);
        assert_eq!(fills[0].fee_amount, 1);
        assert_eq!(fills[1].order_commitment, OrderCommitment("0x2".into()));
        assert_eq!(fills[1].filled_base_amount, 250);
        assert_eq!(fills[1].quote_amount, 1_000_000);
        assert_eq!(fills[1].fee_amount, 1);
    }

    #[test]
    fn pro_rata_base_dust_is_allocated_once_and_conserved() {
        let batch_id = BatchId("batch-1".into());
        let first = executable_buy_order();
        let mut second = executable_buy_order();
        second.order_commitment = OrderCommitment("0x2".into());
        let orders = vec![first, second];
        let obligations = crate::derive_multi_pair_external_match_obligations(&orders, None)
            .expect("residual obligations");
        let request = external_match_request_from_obligations(
            &batch_id,
            &obligations,
            4_000,
            1_900_000_000_000,
        )
        .unwrap()
        .unwrap();
        let allocations = allocate_external_match_settlements(
            &batch_id,
            &orders,
            None,
            &[ExternalMatchSettlementRecord {
                request,
                consumed_base_amount: 1,
            }],
        )
        .expect("single-unit pro-rata allocation");

        assert_eq!(
            allocations
                .iter()
                .map(|entry| entry.base_amount)
                .sum::<u128>(),
            1
        );
        assert_eq!(
            allocations
                .iter()
                .map(|entry| entry.quote_amount)
                .sum::<u128>(),
            4_000
        );
    }

    #[test]
    fn authorization_proves_complete_one_sided_residual_at_signed_midpoint() {
        let batch_id = BatchId("batch-1".into());
        let verifier = "0x456";
        let mut order = executable_buy_order();
        order.submitted_base_amount = 1_000_000_000_000_000_000;
        order.limit_price = 4_100_000_000;
        order.price_base_scale = 1_000_000_000_000_000_000;
        order.available_input_amount = 4_000_000_000;
        let obligations =
            crate::derive_multi_pair_external_match_obligations(std::slice::from_ref(&order), None)
                .unwrap();
        let sources = reference_price_source_set_commitment(&serde_json::json!({
            "binance": [3999, 4001],
            "coinbase": [3998, 4002],
            "kraken": [3999, 4002]
        }))
        .unwrap();
        let attestation = sign_reference_price_attestation(
            "0x123456789",
            verifier,
            ReferencePriceEnvelope {
                pair_id: PairId("ETH/USDC".into()),
                base_asset_id: AssetId("ETH".into()),
                quote_asset_id: AssetId("USDC".into()),
                midpoint_price: 4_000_000_000,
                lower_price: 3_994_000_000,
                upper_price: 4_006_000_000,
                price_base_scale: 1_000_000_000_000_000_000,
                source_count: 3,
                observed_at_unix_ms: 1_000,
            },
            &sources,
            6_000,
            7,
        )
        .unwrap();
        let request = external_match_request_from_obligations(
            &batch_id,
            &obligations,
            attestation.envelope.midpoint_price,
            attestation.valid_until_unix_ms,
        )
        .unwrap()
        .unwrap();
        let witness = ExternalMatchAuthorizationWitness {
            batch_id,
            auction_verifier_address: verifier.into(),
            reference_price_signer: attestation.signer_public_key.clone(),
            multi_pair_problem: None,
            orders: vec![order],
            reference_price_attestations: vec![attestation],
            requests: vec![request],
        };

        let report = validate_external_match_authorization_witness(&witness)
            .expect("one-sided residual authorization");
        assert_eq!(report.request_count, 1);
        assert_eq!(report.multi_pair_commitment, "0x0");
        assert_ne!(report.request_root, "0x0");
        let serialized = crate::build_external_match_authorization_serialized_input(&witness)
            .expect("serialize authorization witness");
        assert_eq!(serialized.len(), 80);
        let call = build_external_match_authorization_call(verifier, &witness)
            .expect("proof-gated authorization call");
        assert_eq!(call.contract_address, verifier);
        assert_eq!(
            call.entrypoint,
            "authorize_external_match_requests_with_proof_facts"
        );
        assert_eq!(
            call.calldata[0],
            encode_starknet_felt("batch-id", "batch-1")
        );
        assert_eq!(call.calldata[1], "0x0");
        assert_eq!(call.calldata[2], report.request_root);
    }

    #[test]
    fn settlement_record_rejects_request_not_derived_from_private_residual() {
        let batch_id = BatchId("batch-1".into());
        let orders = vec![executable_buy_order()];
        let obligation = crate::derive_multi_pair_external_match_obligations(&orders, None)
            .expect("obligation")
            .remove(0);
        let mut request = external_match_request_from_obligation(
            &batch_id,
            &obligation,
            4_000,
            1_900_000_000_000,
        )
        .expect("request")
        .expect("fillable request");
        request.max_base_amount += 1;

        let error = validate_external_match_settlement_records(
            &batch_id,
            &orders,
            None,
            &[ExternalMatchSettlementRecord {
                request,
                consumed_base_amount: 1,
            }],
        )
        .expect_err("tampered request must fail");

        assert!(error.to_string().contains("not a derived private residual"));
    }

    #[test]
    fn external_match_request_skips_buy_when_midpoint_exceeds_limit() {
        let request = external_match_request_from_obligation(
            &BatchId("batch-1".into()),
            &obligation(OrderSide::Buy),
            4_200,
            1_900_000_000_000,
        )
        .expect("request derivation succeeds");

        assert_eq!(request, None);
    }

    #[test]
    fn external_match_request_caps_buy_by_available_quote_at_midpoint() {
        let mut obligation = obligation(OrderSide::Buy);
        obligation.input_amount = 2_000_000;
        let request = external_match_request_from_obligation(
            &BatchId("batch-1".into()),
            &obligation,
            4_000,
            1_900_000_000_000,
        )
        .expect("request derivation succeeds")
        .expect("midpoint-valid request");

        assert_eq!(request.max_base_amount, 500);
    }

    #[test]
    fn external_match_request_skips_sell_when_midpoint_is_below_limit() {
        let request = external_match_request_from_obligation(
            &BatchId("batch-1".into()),
            &obligation(OrderSide::Sell),
            3_900,
            1_900_000_000_000,
        )
        .expect("request derivation succeeds");

        assert_eq!(request, None);
    }
}

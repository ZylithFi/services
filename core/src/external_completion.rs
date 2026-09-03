use serde::{Deserialize, Serialize};

use crate::{
    ProtocolError,
    hash::{normalize_felt_hex, tagged_field_hex},
    multipair::{
        MultiPairAssetDelta, MultiPairAssetDeltaDirection, MultiPairAssetDeltaSource,
        MultiPairExternalCompletionObligation,
    },
    types::{AssetId, OrderSide, PairId},
};

const BPS_DENOMINATOR: u128 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencePricePolicy {
    #[serde(default = "default_reference_primary_source")]
    pub primary_source: String,
    pub min_sources: usize,
    pub max_age_ms: u64,
    pub max_source_spread_bps: u32,
    pub max_cross_source_deviation_bps: u32,
    pub envelope_bps: u32,
}

impl Default for ReferencePricePolicy {
    fn default() -> Self {
        Self {
            primary_source: default_reference_primary_source(),
            min_sources: 3,
            max_age_ms: 5_000,
            max_source_spread_bps: 20,
            max_cross_source_deviation_bps: 30,
            envelope_bps: 15,
        }
    }
}

fn default_reference_primary_source() -> String {
    "binance".into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencePriceSample {
    pub source: String,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub bid_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub ask_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub price_base_scale: u128,
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencePriceEnvelope {
    pub pair_id: PairId,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub midpoint_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub lower_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub upper_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub price_base_scale: u128,
    pub source_count: usize,
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCompletionQuote {
    pub obligation: MultiPairExternalCompletionObligation,
    pub venue: String,
    pub quote_id: String,
    pub executor_address: String,
    pub sell_token_address: String,
    pub buy_token_address: String,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub input_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub expected_output_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub min_output_amount: u128,
    pub quoted_at_unix_ms: u64,
    pub quote_expiry_unix_ms: u64,
    pub route_commitment: String,
    pub private_executor: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCompletionQuotePolicy {
    pub max_quote_age_ms: u64,
    pub min_quote_ttl_ms: u64,
    pub require_private_executor: bool,
}

impl Default for ExternalCompletionQuotePolicy {
    fn default() -> Self {
        Self {
            max_quote_age_ms: 7_500,
            min_quote_ttl_ms: 2_000,
            require_private_executor: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCompletionQuoteReport {
    pub quote_commitment: String,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub worst_case_effective_price: u128,
    pub asset_deltas: Vec<MultiPairAssetDelta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectedExecutionPrice {
    pub pair_id: PairId,
    pub side: OrderSide,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub total_base_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub total_quote_amount: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub effective_price: u128,
    #[serde(with = "crate::types::serde_u128_decimal")]
    pub price_base_scale: u128,
}

pub fn build_reference_price_envelope(
    pair_id: PairId,
    base_asset_id: AssetId,
    quote_asset_id: AssetId,
    price_base_scale: u128,
    now_unix_ms: u64,
    samples: &[ReferencePriceSample],
    policy: &ReferencePricePolicy,
) -> Result<ReferencePriceEnvelope, ProtocolError> {
    if price_base_scale == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "reference price scale must be non-zero".into(),
        ));
    }
    if policy.min_sources == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "reference price policy requires at least one source".into(),
        ));
    }
    if policy.envelope_bps as u128 >= BPS_DENOMINATOR {
        return Err(ProtocolError::InvalidSettlementProof(
            "reference price envelope is too wide".into(),
        ));
    }

    let primary_source = policy.primary_source.trim().to_lowercase();
    if primary_source.is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(
            "reference price policy requires a primary source".into(),
        ));
    }
    let mut fresh_midpoints = Vec::<(String, u128)>::new();
    let mut primary_midpoint = None::<u128>;
    let mut newest_observed_at = 0_u64;
    for sample in samples {
        validate_reference_source_name(&sample.source)?;
        if is_disallowed_reference_source(&sample.source) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "reference source {} is not allowed for benchmark pricing",
                sample.source
            )));
        }
        if sample.bid_price == 0 || sample.ask_price == 0 || sample.price_base_scale == 0 {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "reference source {} has a zero price or scale",
                sample.source
            )));
        }
        if sample.bid_price > sample.ask_price {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "reference source {} has crossed bid/ask",
                sample.source
            )));
        }
        let age = now_unix_ms
            .checked_sub(sample.observed_at_unix_ms)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(format!(
                    "reference source {} is from the future",
                    sample.source
                ))
            })?;
        if age > policy.max_age_ms {
            continue;
        }
        let bid = rescale_price(sample.bid_price, sample.price_base_scale, price_base_scale)?;
        let ask = rescale_price(sample.ask_price, sample.price_base_scale, price_base_scale)?;
        let mid = midpoint_price(bid, ask)?;
        let spread_bps = if mid == 0 {
            0
        } else {
            ceil_mul_div(ask - bid, BPS_DENOMINATOR, mid)?
        };
        if spread_bps > policy.max_source_spread_bps as u128 {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "reference source {} spread exceeds policy",
                sample.source
            )));
        }
        newest_observed_at = newest_observed_at.max(sample.observed_at_unix_ms);
        let source = sample.source.trim().to_lowercase();
        if is_primary_reference_source(&source, &primary_source) {
            if primary_midpoint.is_some() {
                return Err(ProtocolError::InvalidSettlementProof(format!(
                    "reference price includes multiple fresh primary {} samples",
                    policy.primary_source
                )));
            }
            primary_midpoint = Some(mid);
        }
        fresh_midpoints.push((source, mid));
    }

    if fresh_midpoints.len() < policy.min_sources {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "reference price requires {} fresh sources, got {}",
            policy.min_sources,
            fresh_midpoints.len()
        )));
    }

    let midpoint = primary_midpoint.ok_or_else(|| {
        ProtocolError::InvalidSettlementProof(format!(
            "reference price requires fresh primary {} source",
            policy.primary_source
        ))
    })?;
    for (source, mid) in &fresh_midpoints {
        let deviation = abs_diff(*mid, midpoint);
        let deviation_bps = if midpoint == 0 {
            0
        } else {
            ceil_mul_div(deviation, BPS_DENOMINATOR, midpoint)?
        };
        if deviation_bps > policy.max_cross_source_deviation_bps as u128 {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "reference source {source} diverges from primary {} beyond policy",
                policy.primary_source
            )));
        }
    }

    let lower_price = midpoint
        .checked_mul(BPS_DENOMINATOR - policy.envelope_bps as u128)
        .map(|value| value / BPS_DENOMINATOR)
        .ok_or_else(|| {
            ProtocolError::InvalidSettlementProof("reference lower envelope overflows".into())
        })?;
    let upper_price = ceil_mul_div(
        midpoint,
        BPS_DENOMINATOR + policy.envelope_bps as u128,
        BPS_DENOMINATOR,
    )?;

    Ok(ReferencePriceEnvelope {
        pair_id,
        base_asset_id,
        quote_asset_id,
        midpoint_price: midpoint,
        lower_price,
        upper_price,
        price_base_scale,
        source_count: fresh_midpoints.len(),
        observed_at_unix_ms: newest_observed_at,
    })
}

pub fn external_completion_quote_commitment(
    quote: &ExternalCompletionQuote,
) -> Result<String, ProtocolError> {
    tagged_field_hex("zylith/external-completion-quote-v1", quote)
}

pub fn validate_external_completion_quote(
    obligation: &MultiPairExternalCompletionObligation,
    quote: &ExternalCompletionQuote,
    envelope: &ReferencePriceEnvelope,
    now_unix_ms: u64,
    policy: &ExternalCompletionQuotePolicy,
) -> Result<ExternalCompletionQuoteReport, ProtocolError> {
    if &quote.obligation != obligation {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion quote is for a different obligation".into(),
        ));
    }
    validate_obligation_matches_envelope(obligation, envelope)?;
    validate_non_empty_label("venue", &quote.venue)?;
    validate_non_empty_label("quote id", &quote.quote_id)?;
    normalize_felt_hex(&quote.executor_address)?;
    normalize_felt_hex(&quote.route_commitment)?;
    normalize_felt_hex(&quote.sell_token_address)?;
    normalize_felt_hex(&quote.buy_token_address)?;

    if policy.require_private_executor && !quote.private_executor {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion quote must use private executor".into(),
        ));
    }
    if quote.input_amount > obligation.input_amount {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion quote input exceeds obligation".into(),
        ));
    }
    if quote.expected_output_amount < quote.min_output_amount {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion quote expected output is below minimum output".into(),
        ));
    }
    if quote.min_output_amount < obligation.gross_output_amount {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion quote does not satisfy user limit output".into(),
        ));
    }
    let age = now_unix_ms
        .checked_sub(quote.quoted_at_unix_ms)
        .ok_or_else(|| {
            ProtocolError::InvalidSettlementProof(
                "external completion quote is from the future".into(),
            )
        })?;
    if age > policy.max_quote_age_ms {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion quote is stale".into(),
        ));
    }
    let ttl = quote
        .quote_expiry_unix_ms
        .checked_sub(now_unix_ms)
        .ok_or_else(|| {
            ProtocolError::InvalidSettlementProof("external completion quote is expired".into())
        })?;
    if ttl < policy.min_quote_ttl_ms {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion quote expires too soon".into(),
        ));
    }

    let worst_case_effective_price = price_from_amounts(
        obligation.side,
        quote.input_amount,
        quote.min_output_amount,
        obligation.price_base_scale,
    )?;
    match obligation.side {
        OrderSide::Buy => {
            if worst_case_effective_price > envelope.upper_price {
                return Err(ProtocolError::InvalidSettlementProof(
                    "external completion buy quote exceeds reference envelope".into(),
                ));
            }
        }
        OrderSide::Sell => {
            if worst_case_effective_price < envelope.lower_price {
                return Err(ProtocolError::InvalidSettlementProof(
                    "external completion sell quote is below reference envelope".into(),
                ));
            }
        }
    }

    let quote_commitment = external_completion_quote_commitment(quote)?;
    let asset_deltas = external_completion_asset_deltas(quote, &quote_commitment)?;
    Ok(ExternalCompletionQuoteReport {
        quote_commitment,
        worst_case_effective_price,
        asset_deltas,
    })
}

pub fn external_completion_asset_deltas(
    quote: &ExternalCompletionQuote,
    quote_commitment: &str,
) -> Result<Vec<MultiPairAssetDelta>, ProtocolError> {
    let normalized_commitment = normalize_felt_hex(quote_commitment)?;
    Ok(vec![
        MultiPairAssetDelta {
            asset_id: quote.obligation.output_asset_id.clone(),
            amount: quote.min_output_amount,
            direction: MultiPairAssetDeltaDirection::In,
            source: MultiPairAssetDeltaSource::ExternalCompletion,
            source_commitment: Some(normalized_commitment.clone()),
        },
        MultiPairAssetDelta {
            asset_id: quote.obligation.input_asset_id.clone(),
            amount: quote.input_amount,
            direction: MultiPairAssetDeltaDirection::Out,
            source: MultiPairAssetDeltaSource::ExternalCompletion,
            source_commitment: Some(normalized_commitment),
        },
    ])
}

pub fn directed_execution_price(
    pair_id: PairId,
    side: OrderSide,
    internal_base_amount: u128,
    reference_midpoint_price: u128,
    price_base_scale: u128,
    external_quote: Option<&ExternalCompletionQuote>,
) -> Result<DirectedExecutionPrice, ProtocolError> {
    if price_base_scale == 0 || reference_midpoint_price == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "directed execution price requires non-zero price and scale".into(),
        ));
    }
    let internal_quote_amount = ceil_mul_div(
        internal_base_amount,
        reference_midpoint_price,
        price_base_scale,
    )?;
    let (external_base_amount, external_quote_amount) = match external_quote {
        Some(quote) => match side {
            OrderSide::Buy => (quote.min_output_amount, quote.input_amount),
            OrderSide::Sell => (quote.input_amount, quote.min_output_amount),
        },
        None => (0, 0),
    };
    let total_base_amount = internal_base_amount
        .checked_add(external_base_amount)
        .ok_or_else(|| ProtocolError::InvalidSettlementProof("base total overflows".into()))?;
    let total_quote_amount = internal_quote_amount
        .checked_add(external_quote_amount)
        .ok_or_else(|| ProtocolError::InvalidSettlementProof("quote total overflows".into()))?;
    if total_base_amount == 0 || total_quote_amount == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "directed execution price requires non-zero executed amounts".into(),
        ));
    }
    let effective_price = match side {
        OrderSide::Buy => ceil_mul_div(total_quote_amount, price_base_scale, total_base_amount)?,
        OrderSide::Sell => total_quote_amount
            .checked_mul(price_base_scale)
            .map(|value| value / total_base_amount)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof("directed sell price overflows".into())
            })?,
    };
    Ok(DirectedExecutionPrice {
        pair_id,
        side,
        total_base_amount,
        total_quote_amount,
        effective_price,
        price_base_scale,
    })
}

fn validate_obligation_matches_envelope(
    obligation: &MultiPairExternalCompletionObligation,
    envelope: &ReferencePriceEnvelope,
) -> Result<(), ProtocolError> {
    if obligation.pair_id != envelope.pair_id
        || obligation.base_asset_id != envelope.base_asset_id
        || obligation.quote_asset_id != envelope.quote_asset_id
        || obligation.price_base_scale != envelope.price_base_scale
    {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion obligation does not match reference envelope".into(),
        ));
    }
    Ok(())
}

fn validate_reference_source_name(source: &str) -> Result<(), ProtocolError> {
    validate_non_empty_label("reference source", source)
}

fn is_primary_reference_source(source: &str, primary_source: &str) -> bool {
    source == primary_source || source.starts_with(&format!("{primary_source}:"))
}

fn is_disallowed_reference_source(source: &str) -> bool {
    let source = source.trim().to_lowercase();
    matches!(source.as_str(), "avnu" | "ekubo" | "pragma")
        || source.starts_with("avnu:")
        || source.starts_with("ekubo:")
        || source.starts_with("pragma:")
}

fn validate_non_empty_label(kind: &str, value: &str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() {
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "{kind} must be non-empty"
        )));
    }
    Ok(())
}

fn midpoint_price(bid: u128, ask: u128) -> Result<u128, ProtocolError> {
    bid.checked_add(ask)
        .map(|value| value / 2)
        .ok_or_else(|| ProtocolError::InvalidSettlementProof("midpoint overflows".into()))
}

fn rescale_price(price: u128, from_scale: u128, to_scale: u128) -> Result<u128, ProtocolError> {
    if from_scale == 0 || to_scale == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "price scale must be non-zero".into(),
        ));
    }
    price
        .checked_mul(to_scale)
        .map(|value| value / from_scale)
        .ok_or_else(|| ProtocolError::InvalidSettlementProof("price rescale overflows".into()))
}

fn price_from_amounts(
    side: OrderSide,
    input_amount: u128,
    output_amount: u128,
    price_base_scale: u128,
) -> Result<u128, ProtocolError> {
    if input_amount == 0 || output_amount == 0 || price_base_scale == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "external completion price requires non-zero amounts".into(),
        ));
    }
    match side {
        OrderSide::Buy => ceil_mul_div(input_amount, price_base_scale, output_amount),
        OrderSide::Sell => output_amount
            .checked_mul(price_base_scale)
            .map(|value| value / input_amount)
            .ok_or_else(|| {
                ProtocolError::InvalidSettlementProof(
                    "external completion sell price overflows".into(),
                )
            }),
    }
}

fn ceil_mul_div(left: u128, right: u128, denominator: u128) -> Result<u128, ProtocolError> {
    if denominator == 0 {
        return Err(ProtocolError::InvalidSettlementProof(
            "division by zero".into(),
        ));
    }
    if left == 0 || right == 0 {
        return Ok(0);
    }
    left.checked_mul(right)
        .and_then(|value| value.checked_add(denominator - 1))
        .map(|value| value / denominator)
        .ok_or_else(|| ProtocolError::InvalidSettlementProof("multiplication overflows".into()))
}

fn abs_diff(left: u128, right: u128) -> u128 {
    left.abs_diff(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MultiPairExecutableOrder, OrderCommitment,
        multipair::{
            MultiPairExternalCompletionObligation,
            derive_multi_pair_external_completion_obligations,
        },
        types::{AssetId, OrderSide, PairId},
    };

    const SCALE: u128 = 1_000_000;

    #[test]
    fn reference_envelope_uses_fresh_primary_midpoint_source() {
        let envelope = build_reference_price_envelope(
            PairId("ETH/USDC".into()),
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample("binance", 3_999_000_000, 4_001_000_000, 9_990),
                sample("coinbase", 4_000_500_000, 4_001_500_000, 9_980),
                sample("stale", 3_000_000_000, 3_010_000_000, 1_000),
            ],
            &ReferencePricePolicy {
                primary_source: "binance".into(),
                min_sources: 2,
                max_age_ms: 100,
                max_source_spread_bps: 10,
                max_cross_source_deviation_bps: 10,
                envelope_bps: 5,
            },
        )
        .expect("reference envelope");

        assert_eq!(envelope.midpoint_price, 4_000_000_000);
        assert_eq!(envelope.lower_price, 3_998_000_000);
        assert_eq!(envelope.upper_price, 4_002_000_000);
        assert_eq!(envelope.source_count, 2);
    }

    #[test]
    fn reference_envelope_rejects_divergent_sources() {
        let err = build_reference_price_envelope(
            PairId("ETH/USDC".into()),
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample("binance", 3_999_000_000, 4_001_000_000, 9_990),
                sample("bad", 4_199_000_000, 4_201_000_000, 9_990),
            ],
            &ReferencePricePolicy {
                primary_source: "binance".into(),
                min_sources: 2,
                max_age_ms: 100,
                max_source_spread_bps: 10,
                max_cross_source_deviation_bps: 20,
                envelope_bps: 5,
            },
        )
        .expect_err("divergent source rejected");
        assert!(err.to_string().contains("diverge"));
    }

    #[test]
    fn reference_envelope_rejects_aggregator_or_amm_sources() {
        let err = build_reference_price_envelope(
            PairId("ETH/USDC".into()),
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample(
                    "binance:ETHUSDC:bookTicker",
                    3_999_000_000,
                    4_001_000_000,
                    9_990,
                ),
                sample("coinbase:ETH-USD:book", 3_999_000_000, 4_001_000_000, 9_990),
                sample(
                    "avnu:ETH/USDC:exact-output-check",
                    3_999_000_000,
                    4_001_000_000,
                    9_990,
                ),
            ],
            &ReferencePricePolicy {
                primary_source: "binance".into(),
                min_sources: 3,
                max_age_ms: 100,
                max_source_spread_bps: 10,
                max_cross_source_deviation_bps: 20,
                envelope_bps: 5,
            },
        )
        .expect_err("aggregator source rejected");
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn avnu_residual_quote_must_satisfy_user_limit_and_reference_envelope() {
        let obligation = buy_obligation(400_000_000_000, 100_000_000);
        let envelope = envelope(4_000_000_000, 3_995_000_000, 4_005_000_000);
        let quote = quote(obligation.clone(), 400_000_000_000, 100_000_000);
        let report = validate_external_completion_quote(
            &obligation,
            &quote,
            &envelope,
            10_000,
            &ExternalCompletionQuotePolicy::default(),
        )
        .expect("quote accepted");

        assert_eq!(report.asset_deltas.len(), 2);
        assert_eq!(report.asset_deltas[0].asset_id, AssetId("ETH".into()));
        assert_eq!(
            report.asset_deltas[0].direction,
            MultiPairAssetDeltaDirection::In
        );
        assert_eq!(report.asset_deltas[1].asset_id, AssetId("USDC".into()));
        assert_eq!(
            report.asset_deltas[1].direction,
            MultiPairAssetDeltaDirection::Out
        );
        assert_eq!(report.worst_case_effective_price, 4_000_000_000);
    }

    #[test]
    fn residual_quote_below_limit_is_rejected_even_if_executor_is_private() {
        let obligation = buy_obligation(400_000_000_000, 100_000_000);
        let envelope = envelope(4_000_000_000, 3_995_000_000, 4_005_000_000);
        let quote = quote(obligation.clone(), 400_000_000_000, 99_900_000);
        let err = validate_external_completion_quote(
            &obligation,
            &quote,
            &envelope,
            10_000,
            &ExternalCompletionQuotePolicy::default(),
        )
        .expect_err("insufficient output rejected");
        assert!(err.to_string().contains("does not satisfy user limit"));
    }

    #[test]
    fn residual_quote_may_consume_less_than_obligation_when_exact_output_is_met() {
        let obligation = buy_obligation(400_000_000_000, 100_000_000);
        let envelope = envelope(4_000_000_000, 3_995_000_000, 4_005_000_000);
        let quote = quote(obligation.clone(), 399_000_000_000, 100_000_000);
        let report = validate_external_completion_quote(
            &obligation,
            &quote,
            &envelope,
            10_000,
            &ExternalCompletionQuotePolicy::default(),
        )
        .expect("price-improved quote accepted");

        assert_eq!(report.worst_case_effective_price, 3_990_000_000);
        assert_eq!(report.asset_deltas[1].amount, 399_000_000_000);
    }

    #[test]
    fn external_completion_obligations_ignore_private_only_residual() {
        let mut private_only = executable_order(ExecutableOrderParams {
            commitment: "0x1",
            pair: "ETH/USDC",
            base: "ETH",
            quote: "USDC",
            side: OrderSide::Buy,
            base_amount: 10,
            available_input_amount: 25_000,
            limit_price: 2_500,
        });
        private_only.execution_preference = crate::ExecutionPreference::PrivateOnly;

        let obligations = derive_multi_pair_external_completion_obligations(&[private_only], None)
            .expect("private-only residual needs no external obligation");

        assert!(obligations.is_empty());
    }

    #[test]
    fn directed_buy_execution_price_blends_midpoint_cross_and_residual_cost() {
        let obligation = buy_obligation(82_000_000_000, 20_000_000);
        let quote = quote(obligation, 82_000_000_000, 20_000_000);
        let price = directed_execution_price(
            PairId("ETH/USDC".into()),
            OrderSide::Buy,
            80_000_000,
            4_000_000_000,
            SCALE,
            Some(&quote),
        )
        .expect("directed price");

        assert_eq!(price.total_base_amount, 100_000_000);
        assert_eq!(price.total_quote_amount, 402_000_000_000);
        assert_eq!(price.effective_price, 4_020_000_000);
    }

    #[test]
    fn sell_residual_quote_is_validated_against_reference_floor() {
        let obligation = sell_obligation(20_000_000, 80_000_000_000);
        let envelope = envelope(4_000_000_000, 3_995_000_000, 4_005_000_000);
        let quote = quote(obligation.clone(), 20_000_000, 80_000_000_000);
        let report = validate_external_completion_quote(
            &obligation,
            &quote,
            &envelope,
            10_000,
            &ExternalCompletionQuotePolicy::default(),
        )
        .expect("sell quote accepted");

        assert_eq!(report.worst_case_effective_price, 4_000_000_000);
    }

    fn sample(
        source: &str,
        bid_price: u128,
        ask_price: u128,
        observed_at_unix_ms: u64,
    ) -> ReferencePriceSample {
        ReferencePriceSample {
            source: source.into(),
            bid_price,
            ask_price,
            price_base_scale: SCALE,
            observed_at_unix_ms,
        }
    }

    fn envelope(midpoint: u128, lower: u128, upper: u128) -> ReferencePriceEnvelope {
        ReferencePriceEnvelope {
            pair_id: PairId("ETH/USDC".into()),
            base_asset_id: AssetId("ETH".into()),
            quote_asset_id: AssetId("USDC".into()),
            midpoint_price: midpoint,
            lower_price: lower,
            upper_price: upper,
            price_base_scale: SCALE,
            source_count: 2,
            observed_at_unix_ms: 10_000,
        }
    }

    fn buy_obligation(
        input_amount: u128,
        output_amount: u128,
    ) -> MultiPairExternalCompletionObligation {
        MultiPairExternalCompletionObligation {
            pair_id: PairId("ETH/USDC".into()),
            base_asset_id: AssetId("ETH".into()),
            quote_asset_id: AssetId("USDC".into()),
            side: OrderSide::Buy,
            input_asset_id: AssetId("USDC".into()),
            output_asset_id: AssetId("ETH".into()),
            input_amount,
            gross_output_amount: output_amount,
            limit_price: 4_000_000_000,
            price_base_scale: SCALE,
            order_commitments: vec![OrderCommitment("0x1".into())],
        }
    }

    fn sell_obligation(
        input_amount: u128,
        output_amount: u128,
    ) -> MultiPairExternalCompletionObligation {
        MultiPairExternalCompletionObligation {
            pair_id: PairId("ETH/USDC".into()),
            base_asset_id: AssetId("ETH".into()),
            quote_asset_id: AssetId("USDC".into()),
            side: OrderSide::Sell,
            input_asset_id: AssetId("ETH".into()),
            output_asset_id: AssetId("USDC".into()),
            input_amount,
            gross_output_amount: output_amount,
            limit_price: 4_000_000_000,
            price_base_scale: SCALE,
            order_commitments: vec![OrderCommitment("0x1".into())],
        }
    }

    fn quote(
        obligation: MultiPairExternalCompletionObligation,
        input_amount: u128,
        min_output_amount: u128,
    ) -> ExternalCompletionQuote {
        ExternalCompletionQuote {
            obligation,
            venue: "avnu".into(),
            quote_id: "quote-1".into(),
            executor_address: "0x123".into(),
            sell_token_address: "0x100".into(),
            buy_token_address: "0x200".into(),
            input_amount,
            expected_output_amount: min_output_amount,
            min_output_amount,
            quoted_at_unix_ms: 9_900,
            quote_expiry_unix_ms: 20_000,
            route_commitment: "0x456".into(),
            private_executor: true,
        }
    }

    struct ExecutableOrderParams<'a> {
        commitment: &'a str,
        pair: &'a str,
        base: &'a str,
        quote: &'a str,
        side: OrderSide,
        base_amount: u128,
        available_input_amount: u128,
        limit_price: u128,
    }

    fn executable_order(params: ExecutableOrderParams<'_>) -> MultiPairExecutableOrder {
        let ExecutableOrderParams {
            commitment,
            pair,
            base,
            quote,
            side,
            base_amount,
            available_input_amount,
            limit_price,
        } = params;
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
}

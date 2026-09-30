use std::collections::BTreeSet;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use crate::{
    ProtocolError,
    types::{AssetId, PairId, SpendAuthorization},
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
    pub derivation: ReferencePriceDerivation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "methodology", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReferencePriceDerivation {
    DirectBbo {
        #[serde(with = "crate::types::serde_u128_decimal")]
        bid_price: u128,
        #[serde(with = "crate::types::serde_u128_decimal")]
        ask_price: u128,
    },
    SyntheticCrossBbo {
        base_market_id: PairId,
        quote_market_id: PairId,
        max_leg_skew_ms: u64,
        #[serde(with = "crate::types::serde_u128_decimal")]
        base_bid_price: u128,
        #[serde(with = "crate::types::serde_u128_decimal")]
        base_ask_price: u128,
        #[serde(with = "crate::types::serde_u128_decimal")]
        quote_bid_price: u128,
        #[serde(with = "crate::types::serde_u128_decimal")]
        quote_ask_price: u128,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencePriceAttestation {
    pub envelope: ReferencePriceEnvelope,
    pub exchange_address: String,
    pub source_set_commitment: String,
    pub valid_until_unix_ms: u64,
    pub nonce: u64,
    pub price_batch_commitment: String,
    pub signer_public_key: String,
    pub signature: SpendAuthorization,
}

impl std::fmt::Debug for ReferencePriceAttestation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReferencePriceAttestation")
            .field("envelope", &self.envelope)
            .field("exchange_address", &self.exchange_address)
            .field("source_set_commitment", &self.source_set_commitment)
            .field("valid_until_unix_ms", &self.valid_until_unix_ms)
            .field("nonce", &self.nonce)
            .field("price_batch_commitment", &self.price_batch_commitment)
            .field("signer_public_key", &self.signer_public_key)
            .field("signature", &"<redacted>")
            .finish()
    }
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
    let mut fresh_venues = BTreeSet::<String>::new();
    let mut primary = None::<(u128, u128, u128, u64)>;
    for sample in samples {
        validate_reference_source_name(&sample.source)?;
        if !is_allowed_reference_source(&sample.source) {
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
            continue;
        }
        let source = sample.source.trim().to_lowercase();
        let venue = canonical_reference_venue(&source);
        if !fresh_venues.insert(venue.clone()) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "reference price includes duplicate venue {venue}"
            )));
        }
        if venue == primary_source {
            if primary.is_some() {
                return Err(ProtocolError::InvalidSettlementProof(format!(
                    "reference price includes multiple fresh primary {} samples",
                    policy.primary_source
                )));
            }
            primary = Some((bid, ask, mid, sample.observed_at_unix_ms));
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

    let (primary_bid, primary_ask, midpoint, primary_observed_at) = primary.ok_or_else(|| {
        ProtocolError::InvalidSettlementProof(format!(
            "reference price requires fresh primary {} source",
            policy.primary_source
        ))
    })?;
    let mut corroborating_source_count = 0_usize;
    let mut first_divergent_source = None;
    for (source, mid) in &fresh_midpoints {
        let deviation = abs_diff(*mid, midpoint);
        let deviation_bps = if midpoint == 0 {
            0
        } else {
            ceil_mul_div(deviation, BPS_DENOMINATOR, midpoint)?
        };
        if deviation_bps > policy.max_cross_source_deviation_bps as u128 {
            first_divergent_source.get_or_insert(source);
        } else {
            corroborating_source_count = corroborating_source_count.saturating_add(1);
        }
    }
    if corroborating_source_count < policy.min_sources {
        let source = first_divergent_source.ok_or_else(|| {
            ProtocolError::InvalidSettlementProof(format!(
                "reference price requires {} corroborating sources, got {}",
                policy.min_sources, corroborating_source_count
            ))
        })?;
        return Err(ProtocolError::InvalidSettlementProof(format!(
            "reference source {source} diverges from primary {} beyond policy",
            policy.primary_source
        )));
    }

    let (lower_price, upper_price) = price_envelope(midpoint, policy.envelope_bps)?;

    Ok(ReferencePriceEnvelope {
        pair_id,
        base_asset_id,
        quote_asset_id,
        midpoint_price: midpoint,
        lower_price,
        upper_price,
        price_base_scale,
        source_count: corroborating_source_count,
        observed_at_unix_ms: primary_observed_at,
        derivation: ReferencePriceDerivation::DirectBbo {
            bid_price: primary_bid,
            ask_price: primary_ask,
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_synthetic_cross_envelope(
    pair_id: PairId,
    base_asset_id: AssetId,
    quote_asset_id: AssetId,
    price_base_scale: u128,
    base_market_id: PairId,
    quote_market_id: PairId,
    base_leg: &ReferencePriceEnvelope,
    quote_leg: &ReferencePriceEnvelope,
    now_unix_ms: u64,
    max_leg_skew_ms: u64,
    max_age_ms: u64,
    envelope_bps: u32,
) -> Result<ReferencePriceEnvelope, ProtocolError> {
    if price_base_scale == 0
        || base_leg.price_base_scale != price_base_scale
        || quote_leg.price_base_scale != price_base_scale
        || base_leg.pair_id != base_market_id
        || quote_leg.pair_id != quote_market_id
        || base_leg.base_asset_id != base_asset_id
        || quote_leg.base_asset_id != quote_asset_id
        || base_leg.quote_asset_id != quote_leg.quote_asset_id
    {
        return Err(invalid_reference(
            "synthetic cross legs do not match the market",
        ));
    }
    let ReferencePriceDerivation::DirectBbo {
        bid_price: base_bid,
        ask_price: base_ask,
    } = base_leg.derivation
    else {
        return Err(invalid_reference("synthetic base leg is not a direct bbo"));
    };
    let ReferencePriceDerivation::DirectBbo {
        bid_price: quote_bid,
        ask_price: quote_ask,
    } = quote_leg.derivation
    else {
        return Err(invalid_reference("synthetic quote leg is not a direct bbo"));
    };
    let skew = base_leg
        .observed_at_unix_ms
        .abs_diff(quote_leg.observed_at_unix_ms);
    if max_leg_skew_ms == 0 || skew > max_leg_skew_ms {
        return Err(invalid_reference(
            "synthetic cross legs exceed the timestamp skew bound",
        ));
    }
    let observed_at_unix_ms = base_leg
        .observed_at_unix_ms
        .min(quote_leg.observed_at_unix_ms);
    let age = now_unix_ms
        .checked_sub(observed_at_unix_ms)
        .ok_or_else(|| invalid_reference("synthetic cross is from the future"))?;
    if max_age_ms == 0 || age > max_age_ms {
        return Err(invalid_reference("synthetic cross is stale"));
    }
    let (bid, ask) =
        derive_synthetic_cross_bbo(base_bid, base_ask, quote_bid, quote_ask, price_base_scale)?;
    if bid == 0 || bid > ask {
        return Err(invalid_reference("synthetic cross produced an invalid bbo"));
    }
    let midpoint = midpoint_price(bid, ask)?;
    let (lower_price, upper_price) = price_envelope(midpoint, envelope_bps)?;
    Ok(ReferencePriceEnvelope {
        pair_id,
        base_asset_id,
        quote_asset_id,
        midpoint_price: midpoint,
        lower_price,
        upper_price,
        price_base_scale,
        source_count: base_leg.source_count.min(quote_leg.source_count),
        observed_at_unix_ms,
        derivation: ReferencePriceDerivation::SyntheticCrossBbo {
            base_market_id,
            quote_market_id,
            max_leg_skew_ms,
            base_bid_price: base_bid,
            base_ask_price: base_ask,
            quote_bid_price: quote_bid,
            quote_ask_price: quote_ask,
        },
    })
}

pub fn derive_synthetic_cross_bbo(
    base_bid: u128,
    base_ask: u128,
    quote_bid: u128,
    quote_ask: u128,
    price_base_scale: u128,
) -> Result<(u128, u128), ProtocolError> {
    if base_bid == 0
        || quote_bid == 0
        || base_bid > base_ask
        || quote_bid > quote_ask
        || price_base_scale == 0
    {
        return Err(invalid_reference(
            "synthetic cross has an invalid component bbo",
        ));
    }
    let bid = mul_div(base_bid, price_base_scale, quote_ask, false)?;
    let ask = mul_div(base_ask, price_base_scale, quote_bid, true)?;
    if bid == 0 || bid > ask {
        return Err(invalid_reference("synthetic cross produced an invalid bbo"));
    }
    Ok((bid, ask))
}

fn validate_reference_source_name(source: &str) -> Result<(), ProtocolError> {
    validate_non_empty_label("reference source", source)
}

fn canonical_reference_venue(source: &str) -> String {
    source
        .split_once(':')
        .map_or(source, |(venue, _)| venue)
        .trim()
        .to_lowercase()
}

fn is_allowed_reference_source(source: &str) -> bool {
    matches!(
        canonical_reference_venue(source).as_str(),
        "binance" | "coinbase" | "kraken" | "okx"
    )
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

fn invalid_reference(message: &str) -> ProtocolError {
    ProtocolError::InvalidSettlementProof(message.into())
}

fn mul_div(
    left: u128,
    right: u128,
    denominator: u128,
    round_up: bool,
) -> Result<u128, ProtocolError> {
    if denominator == 0 {
        return Err(invalid_reference("reference price division by zero"));
    }
    let numerator = BigUint::from(left) * BigUint::from(right);
    let denominator = BigUint::from(denominator);
    let value = if round_up {
        numerator.div_ceil(&denominator)
    } else {
        numerator / denominator
    };
    value
        .to_u128()
        .ok_or_else(|| invalid_reference("reference price multiplication overflows"))
}

fn price_envelope(midpoint: u128, envelope_bps: u32) -> Result<(u128, u128), ProtocolError> {
    if envelope_bps as u128 >= BPS_DENOMINATOR {
        return Err(invalid_reference("reference price envelope is too wide"));
    }
    let lower = mul_div(
        midpoint,
        BPS_DENOMINATOR - envelope_bps as u128,
        BPS_DENOMINATOR,
        false,
    )?;
    let upper = mul_div(
        midpoint,
        BPS_DENOMINATOR + envelope_bps as u128,
        BPS_DENOMINATOR,
        true,
    )?;
    Ok((lower, upper))
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
    use crate::types::{AssetId, PairId};

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
                sample("kraken", 3_000_000_000, 3_010_000_000, 1_000),
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
    fn reference_envelope_uses_the_primary_observation_time() {
        let envelope = build_reference_price_envelope(
            PairId("ETH/USDC".into()),
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample("binance", 3_999_000_000, 4_001_000_000, 9_950),
                sample("coinbase", 3_999_500_000, 4_000_500_000, 9_999),
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

        assert_eq!(envelope.observed_at_unix_ms, 9_950);
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
                sample("coinbase", 4_199_000_000, 4_201_000_000, 9_990),
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
    fn reference_envelope_excludes_divergent_optional_source_when_quorum_remains() {
        let envelope = build_reference_price_envelope(
            PairId("ETH/USDC".into()),
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample("binance", 3_999_000_000, 4_001_000_000, 9_990),
                sample("coinbase", 3_999_500_000, 4_000_500_000, 9_990),
                sample("kraken", 3_999_250_000, 4_000_750_000, 9_990),
                sample("okx", 4_199_000_000, 4_201_000_000, 9_990),
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
        .expect("three-source quorum should survive one optional outlier");

        assert_eq!(envelope.midpoint_price, 4_000_000_000);
        assert_eq!(envelope.source_count, 3);
    }

    #[test]
    fn reference_envelope_excludes_wide_optional_source_when_quorum_remains() {
        let envelope = build_reference_price_envelope(
            PairId("ETH/USDC".into()),
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample("binance", 3_999_000_000, 4_001_000_000, 9_990),
                sample("kraken", 3_999_500_000, 4_000_500_000, 9_990),
                sample("okx", 3_999_250_000, 4_000_750_000, 9_990),
                sample("coinbase", 3_900_000_000, 4_100_000_000, 9_990),
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
        .expect("wide optional source is excluded");

        assert_eq!(envelope.midpoint_price, 4_000_000_000);
        assert_eq!(envelope.source_count, 3);
    }

    #[test]
    fn reference_envelope_rejects_when_wide_sources_break_quorum() {
        let err = build_reference_price_envelope(
            PairId("ETH/USDC".into()),
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample("binance", 3_999_000_000, 4_001_000_000, 9_990),
                sample("kraken", 3_999_500_000, 4_000_500_000, 9_990),
                sample("coinbase", 3_900_000_000, 4_100_000_000, 9_990),
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
        .expect_err("quorum remains fail closed");

        assert!(err.to_string().contains("requires 3 fresh sources, got 2"));
    }

    #[test]
    fn reference_envelope_rejects_wide_primary_even_with_secondary_quorum() {
        let err = build_reference_price_envelope(
            PairId("ETH/USDC".into()),
            AssetId("ETH".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample("binance", 3_900_000_000, 4_100_000_000, 9_990),
                sample("kraken", 3_999_500_000, 4_000_500_000, 9_990),
                sample("coinbase", 3_999_250_000, 4_000_750_000, 9_990),
                sample("okx", 3_999_000_000, 4_001_000_000, 9_990),
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
        .expect_err("wide primary remains fail closed");

        assert!(
            err.to_string()
                .contains("requires fresh primary binance source")
        );
    }

    #[test]
    fn reference_envelope_rejects_duplicate_venue_identities() {
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
                    "coinbase:ETH-USDC:duplicate",
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
        .expect_err("duplicate venue identity rejected");

        assert!(err.to_string().contains("duplicate venue"));
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
                    "router:ETH/USDC:execution-check",
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
    fn reference_envelope_rejects_unconfigured_cex_sources() {
        let err = build_reference_price_envelope(
            PairId("STRK/USDC".into()),
            AssetId("STRK".into()),
            AssetId("USDC".into()),
            SCALE,
            10_000,
            &[
                sample("binance", 39_990, 40_010, 9_990),
                sample("coinbase", 39_995, 40_005, 9_990),
                sample("bybit", 39_995, 40_005, 9_990),
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
        .expect_err("unconfigured cex source rejected");

        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn synthetic_cross_uses_executable_bbo_bounds_and_rejects_skew() {
        let direct = |pair: &str, base: &str, bid, ask, observed| ReferencePriceEnvelope {
            pair_id: PairId(pair.into()),
            base_asset_id: AssetId(base.into()),
            quote_asset_id: AssetId("USDC".into()),
            midpoint_price: (bid + ask) / 2,
            lower_price: bid,
            upper_price: ask,
            price_base_scale: SCALE,
            source_count: 3,
            observed_at_unix_ms: observed,
            derivation: ReferencePriceDerivation::DirectBbo {
                bid_price: bid,
                ask_price: ask,
            },
        };
        let strk = direct("STRK/USDC", "STRK", 39_990, 40_010, 9_900);
        let eth = direct("ETH/USDC", "ETH", 3_999_000_000, 4_001_000_000, 9_950);
        let cross = build_synthetic_cross_envelope(
            PairId("STRK/ETH".into()),
            AssetId("STRK".into()),
            AssetId("ETH".into()),
            SCALE,
            PairId("STRK/USDC".into()),
            PairId("ETH/USDC".into()),
            &strk,
            &eth,
            10_000,
            100,
            500,
            5,
        )
        .expect("synthetic cross");
        assert_eq!(cross.midpoint_price, 10);
        assert!(matches!(
            cross.derivation,
            ReferencePriceDerivation::SyntheticCrossBbo {
                max_leg_skew_ms: 100,
                ..
            }
        ));
        assert!(
            build_synthetic_cross_envelope(
                PairId("STRK/ETH".into()),
                AssetId("STRK".into()),
                AssetId("ETH".into()),
                SCALE,
                PairId("STRK/USDC".into()),
                PairId("ETH/USDC".into()),
                &strk,
                &eth,
                10_000,
                10,
                500,
                5,
            )
            .unwrap_err()
            .to_string()
            .contains("skew")
        );
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
}

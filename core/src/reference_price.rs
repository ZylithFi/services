use std::collections::BTreeSet;

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

pub fn reference_price_policy_for_pair(pair_id: &PairId) -> ReferencePricePolicy {
    let mut policy = ReferencePricePolicy::default();
    if pair_id.0 == "USDC/USDT" {
        policy.max_cross_source_deviation_bps = 20;
    }
    policy
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencePriceAttestation {
    pub envelope: ReferencePriceEnvelope,
    pub auction_verifier_address: String,
    pub source_set_commitment: String,
    pub valid_until_unix_ms: u64,
    pub nonce: u64,
    pub signer_public_key: String,
    pub signature: SpendAuthorization,
}

impl std::fmt::Debug for ReferencePriceAttestation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReferencePriceAttestation")
            .field("envelope", &self.envelope)
            .field("auction_verifier_address", &self.auction_verifier_address)
            .field("source_set_commitment", &self.source_set_commitment)
            .field("valid_until_unix_ms", &self.valid_until_unix_ms)
            .field("nonce", &self.nonce)
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
    let mut primary_midpoint = None::<u128>;
    let mut newest_observed_at = 0_u64;
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
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "reference source {} spread exceeds policy",
                sample.source
            )));
        }
        newest_observed_at = newest_observed_at.max(sample.observed_at_unix_ms);
        let source = sample.source.trim().to_lowercase();
        let venue = canonical_reference_venue(&source);
        if !fresh_venues.insert(venue.clone()) {
            return Err(ProtocolError::InvalidSettlementProof(format!(
                "reference price includes duplicate venue {venue}"
            )));
        }
        if venue == primary_source {
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
        "binance" | "bybit" | "coinbase" | "kraken" | "okx"
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
    fn correlated_pair_reference_policy_is_stricter_than_default() {
        let standard = reference_price_policy_for_pair(&PairId("ETH/USDC".into()));
        let correlated = reference_price_policy_for_pair(&PairId("USDC/USDT".into()));

        assert_eq!(standard.max_cross_source_deviation_bps, 30);
        assert_eq!(correlated.max_cross_source_deviation_bps, 20);
        assert_eq!(correlated.max_age_ms, standard.max_age_ms);
        assert_eq!(correlated.envelope_bps, standard.envelope_bps);
    }

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

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AssetId, PairId, ReferencePricePolicy, types::serde_u128_decimal};

pub const MARKET_REGISTRY_SCHEMA_VERSION: u32 = 1;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const STARKNET_FIELD_PRIME_DECIMAL: &str =
    "3618502788666131213697322783095070105623107215331596699973092056135872020481";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OhttpPolicy {
    Disabled,
    #[default]
    BestEffort,
    Required,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceRelationship {
    Native,
    WrappedOneToOne,
    StableOneToOne,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceIdentity {
    pub reference_asset_id: String,
    pub relationship: ReferenceRelationship,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueAdapter {
    Binance,
    Coinbase,
    Kraken,
    Okx,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VenueObservation {
    Direct {
        adapter: VenueAdapter,
        symbol: String,
    },
    SameVenueRatio {
        adapter: VenueAdapter,
        base_symbol: String,
        quote_symbol: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferencePriceMethodology {
    DirectBboMidpoint,
    SyntheticCrossBboMidpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "methodology", rename_all = "snake_case", deny_unknown_fields)]
pub enum MarketReferencePrice {
    DirectBboMidpoint {
        primary: VenueObservation,
        corroborating: Vec<VenueObservation>,
        min_sources: usize,
        max_age_ms: u64,
        max_source_spread_bps: u32,
        max_cross_source_deviation_bps: u32,
        envelope_bps: u32,
        attestation_ttl_ms: u64,
    },
    SyntheticCrossBboMidpoint {
        base_market_id: PairId,
        quote_market_id: PairId,
        max_leg_skew_ms: u64,
        max_age_ms: u64,
        envelope_bps: u32,
        attestation_ttl_ms: u64,
    },
}

impl MarketReferencePrice {
    pub fn methodology(&self) -> ReferencePriceMethodology {
        match self {
            Self::DirectBboMidpoint { .. } => ReferencePriceMethodology::DirectBboMidpoint,
            Self::SyntheticCrossBboMidpoint { .. } => {
                ReferencePriceMethodology::SyntheticCrossBboMidpoint
            }
        }
    }

    pub fn envelope_bps(&self) -> u32 {
        match self {
            Self::DirectBboMidpoint { envelope_bps, .. }
            | Self::SyntheticCrossBboMidpoint { envelope_bps, .. } => *envelope_bps,
        }
    }

    pub fn attestation_ttl_ms(&self) -> u64 {
        match self {
            Self::DirectBboMidpoint {
                attestation_ttl_ms, ..
            }
            | Self::SyntheticCrossBboMidpoint {
                attestation_ttl_ms, ..
            } => *attestation_ttl_ms,
        }
    }

    pub fn max_age_ms(&self) -> u64 {
        match self {
            Self::DirectBboMidpoint { max_age_ms, .. }
            | Self::SyntheticCrossBboMidpoint { max_age_ms, .. } => *max_age_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketRegistryAsset {
    pub asset_id: AssetId,
    pub token_address: String,
    pub decimals: u8,
    #[serde(with = "serde_u128_decimal")]
    pub min_trade_amount: u128,
    pub erc20_behavior: String,
    pub enabled: bool,
    pub funding_enabled: bool,
    pub reference_identity: ReferenceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketCapabilities {
    pub market_data: bool,
    pub external_matching: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketRegistryMarket {
    pub market_id: PairId,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub min_order_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub min_order_quote_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub price_base_scale: u128,
    pub taker_fee_bps: u16,
    pub enabled: bool,
    pub capabilities: MarketCapabilities,
    #[serde(with = "serde_u128_decimal")]
    pub external_settlement_support_quote: u128,
    #[serde(with = "serde_u128_decimal")]
    pub external_min_profit_quote: u128,
    pub reference_price: MarketReferencePrice,
}

impl MarketRegistryMarket {
    pub fn reference_price_policy(&self) -> Option<ReferencePricePolicy> {
        let MarketReferencePrice::DirectBboMidpoint {
            primary,
            min_sources,
            max_age_ms,
            max_source_spread_bps,
            max_cross_source_deviation_bps,
            envelope_bps,
            ..
        } = &self.reference_price
        else {
            return None;
        };
        Some(ReferencePricePolicy {
            primary_source: observation_adapter(primary).as_str().to_owned(),
            min_sources: *min_sources,
            max_age_ms: *max_age_ms,
            max_source_spread_bps: *max_source_spread_bps,
            max_cross_source_deviation_bps: *max_cross_source_deviation_bps,
            envelope_bps: *envelope_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketRegistry {
    pub schema_version: u32,
    pub registry_version: u64,
    pub registry_hash: String,
    pub network: String,
    pub chain_id: String,
    pub gas_fee_asset_id: AssetId,
    #[serde(with = "serde_u128_decimal")]
    pub connected_wallet_fee_reserve_amount: u128,
    pub objective_numeraire_asset_id: AssetId,
    pub assets: Vec<MarketRegistryAsset>,
    pub markets: Vec<MarketRegistryMarket>,
}

impl MarketRegistry {
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let registry: Self =
            serde_json::from_str(raw).map_err(|error| format!("market registry: {error}"))?;
        registry.validate()?;
        Ok(registry)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != MARKET_REGISTRY_SCHEMA_VERSION {
            return Err(format!(
                "unsupported market registry schema version {}",
                self.schema_version
            ));
        }
        if self.registry_version == 0 || self.registry_version > MAX_SAFE_JSON_INTEGER {
            return Err("market registry version must be a positive json-safe integer".into());
        }
        if self.network.is_empty()
            || self.network.len() > 32
            || !self.network.chars().all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '_' | '-')
            })
            || normalize_felt(&self.chain_id).is_err()
            || normalize_felt(&self.chain_id)? == "0x0"
        {
            return Err("market registry network or chain id is invalid".into());
        }
        if self.assets.is_empty() || self.markets.is_empty() {
            return Err("market registry must contain assets and markets".into());
        }
        if self.connected_wallet_fee_reserve_amount == 0 {
            return Err("connected-wallet fee reserve must be positive".into());
        }
        ensure_sorted_unique(
            self.assets.iter().map(|asset| asset.asset_id.0.as_str()),
            "asset",
        )?;
        ensure_sorted_unique(
            self.markets
                .iter()
                .map(|market| market.market_id.0.as_str()),
            "market",
        )?;
        let enabled_asset_count = self.assets.iter().filter(|asset| asset.enabled).count();
        let enabled_market_count = self.markets.iter().filter(|market| market.enabled).count();
        if enabled_asset_count == 0
            || enabled_asset_count > crate::exact_clearing::MAX_CLEARING_ASSETS
        {
            return Err(format!(
                "enabled asset count must be in [1, {}]",
                crate::exact_clearing::MAX_CLEARING_ASSETS
            ));
        }
        if enabled_market_count == 0 || enabled_market_count > crate::exchange::MAX_MARKETS {
            return Err(format!(
                "enabled market count must be in [1, {}]",
                crate::exchange::MAX_MARKETS
            ));
        }

        let mut token_addresses = BTreeSet::new();
        let assets = self
            .assets
            .iter()
            .map(|asset| {
                validate_identifier(&asset.asset_id.0, "asset")?;
                let normalized = normalize_felt(&asset.token_address)?;
                if normalized == "0x0" {
                    return Err(format!(
                        "asset {} has an invalid token address",
                        asset.asset_id.0
                    ));
                }
                if !token_addresses.insert(normalized) {
                    return Err("market registry contains a duplicate token address".into());
                }
                if asset.decimals > 36 || asset.min_trade_amount == 0 {
                    return Err(format!("asset {} has invalid units", asset.asset_id.0));
                }
                if asset.erc20_behavior != "vanilla_exact_delta" {
                    return Err(format!(
                        "asset {} uses unsupported erc20 behavior",
                        asset.asset_id.0
                    ));
                }
                if !asset.enabled && asset.funding_enabled {
                    return Err(format!(
                        "disabled asset {} cannot enable funding",
                        asset.asset_id.0
                    ));
                }
                validate_reference_identity(asset)?;
                Ok((asset.asset_id.0.as_str(), asset))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;

        let numeraire = assets
            .get(self.objective_numeraire_asset_id.0.as_str())
            .ok_or("objective numeraire is not a registered asset")?;
        if !numeraire.enabled {
            return Err("objective numeraire must be enabled".into());
        }
        let gas_asset = assets
            .get(self.gas_fee_asset_id.0.as_str())
            .ok_or("gas fee asset is not a registered asset")?;
        if !gas_asset.enabled {
            return Err("gas fee asset must be enabled".into());
        }

        for market in &self.markets {
            validate_market(market, &assets)?;
        }
        let markets = self
            .markets
            .iter()
            .map(|market| (market.market_id.0.as_str(), market))
            .collect::<BTreeMap<_, _>>();
        for market in &self.markets {
            validate_synthetic_market(market, &markets, &self.objective_numeraire_asset_id)?;
        }
        for asset in self.assets.iter().filter(|asset| asset.enabled) {
            let used = self.markets.iter().any(|market| {
                market.enabled
                    && (market.base_asset_id == asset.asset_id
                        || market.quote_asset_id == asset.asset_id)
            });
            if !used {
                return Err(format!(
                    "enabled asset {} is not used by an enabled market",
                    asset.asset_id.0
                ));
            }
            if !asset.funding_enabled {
                return Err(format!(
                    "enabled asset {} is missing funding capability",
                    asset.asset_id.0
                ));
            }
            let direct_numeraire_markets = self
                .markets
                .iter()
                .filter(|market| {
                    market.enabled
                        && ((market.base_asset_id == asset.asset_id
                            && market.quote_asset_id == self.objective_numeraire_asset_id)
                            || (market.quote_asset_id == asset.asset_id
                                && market.base_asset_id == self.objective_numeraire_asset_id))
                })
                .count();
            if asset.asset_id != self.objective_numeraire_asset_id && direct_numeraire_markets != 1
            {
                return Err(format!(
                    "enabled asset {} must have exactly one direct objective-numeraire market",
                    asset.asset_id.0
                ));
            }
        }

        let computed = self.computed_hash()?;
        if self.registry_hash != computed {
            return Err(format!(
                "market registry hash mismatch: declared {}, computed {computed}",
                self.registry_hash
            ));
        }
        Ok(())
    }

    pub fn computed_hash(&self) -> Result<String, String> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| format!("market registry serialization: {error}"))?;
        value
            .as_object_mut()
            .ok_or("market registry must serialize as an object")?
            .remove("registry_hash");
        let mut bytes = Vec::new();
        write_canonical_json(&value, &mut bytes)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn asset(&self, asset_id: &str) -> Option<&MarketRegistryAsset> {
        self.assets
            .binary_search_by(|asset| asset.asset_id.0.as_str().cmp(asset_id))
            .ok()
            .map(|index| &self.assets[index])
    }

    pub fn market(&self, market_id: &str) -> Option<&MarketRegistryMarket> {
        self.markets
            .binary_search_by(|market| market.market_id.0.as_str().cmp(market_id))
            .ok()
            .map(|index| &self.markets[index])
    }

    pub fn enabled_markets(&self) -> impl Iterator<Item = &MarketRegistryMarket> {
        self.markets.iter().filter(|market| market.enabled)
    }

    pub fn hash_limbs(&self) -> Result<(u128, u128), String> {
        let bytes = hex::decode(&self.registry_hash)
            .map_err(|error| format!("market registry hash: {error}"))?;
        if bytes.len() != 32 {
            return Err("market registry hash must contain 32 bytes".into());
        }
        let high = u128::from_be_bytes(bytes[..16].try_into().expect("hash half"));
        let low = u128::from_be_bytes(bytes[16..].try_into().expect("hash half"));
        Ok((high, low))
    }
}

fn validate_market(
    market: &MarketRegistryMarket,
    assets: &BTreeMap<&str, &MarketRegistryAsset>,
) -> Result<(), String> {
    validate_identifier(&market.market_id.0, "market")?;
    let base = assets
        .get(market.base_asset_id.0.as_str())
        .ok_or_else(|| format!("market {} has an unknown base asset", market.market_id.0))?;
    let quote = assets
        .get(market.quote_asset_id.0.as_str())
        .ok_or_else(|| format!("market {} has an unknown quote asset", market.market_id.0))?;
    if base.asset_id == quote.asset_id
        || market.market_id.0 != format!("{}/{}", base.asset_id.0, quote.asset_id.0)
    {
        return Err(format!(
            "market {} has an invalid identity",
            market.market_id.0
        ));
    }
    if market.enabled && (!base.enabled || !quote.enabled) {
        return Err(format!(
            "market {} uses a disabled asset",
            market.market_id.0
        ));
    }
    if market.min_order_amount < base.min_trade_amount
        || market.min_order_quote_amount < quote.min_trade_amount
        || market.price_base_scale == 0
        || market.taker_fee_bps == 0
        || market.taker_fee_bps > 100
    {
        return Err(format!(
            "market {} has invalid economic parameters",
            market.market_id.0
        ));
    }
    if market.capabilities.external_matching
        != (market.external_settlement_support_quote > 0 && market.external_min_profit_quote > 0)
    {
        return Err(format!(
            "market {} has inconsistent external matching configuration",
            market.market_id.0
        ));
    }
    if !market.enabled && market.capabilities.external_matching {
        return Err(format!(
            "disabled market {} cannot enable external matching",
            market.market_id.0
        ));
    }
    if market.enabled && !market.capabilities.market_data {
        return Err(format!(
            "market {} has no market-data capability",
            market.market_id.0
        ));
    }
    validate_reference_policy(market)?;
    Ok(())
}

fn valid_common_reference_policy(max_age_ms: u64, envelope_bps: u32, ttl_ms: u64) -> bool {
    max_age_ms > 0
        && max_age_ms <= 15_000
        && envelope_bps > 0
        && envelope_bps < 10_000
        && ttl_ms > 0
        && ttl_ms <= 15_000
}

fn validate_reference_policy(market: &MarketRegistryMarket) -> Result<(), String> {
    let MarketReferencePrice::DirectBboMidpoint {
        primary,
        corroborating,
        min_sources,
        max_age_ms,
        max_source_spread_bps,
        max_cross_source_deviation_bps,
        envelope_bps,
        attestation_ttl_ms,
    } = &market.reference_price
    else {
        let MarketReferencePrice::SyntheticCrossBboMidpoint {
            max_leg_skew_ms,
            max_age_ms,
            envelope_bps,
            attestation_ttl_ms,
            ..
        } = &market.reference_price
        else {
            unreachable!()
        };
        if *max_leg_skew_ms == 0
            || *max_leg_skew_ms > *max_age_ms
            || !valid_common_reference_policy(*max_age_ms, *envelope_bps, *attestation_ttl_ms)
        {
            return Err(format!(
                "market {} has invalid synthetic reference-price policy",
                market.market_id.0
            ));
        }
        return Ok(());
    };
    validate_observation(primary)?;
    if !matches!(
        primary,
        VenueObservation::Direct {
            adapter: VenueAdapter::Binance,
            ..
        }
    ) {
        return Err(format!(
            "market {} primary price must be a direct binance observation",
            market.market_id.0
        ));
    }
    if corroborating.len() < 2 {
        return Err(format!(
            "market {} has insufficient reference sources",
            market.market_id.0
        ));
    }
    let available_sources = 1 + corroborating.len();
    if *min_sources < 3
        || *min_sources > available_sources
        || *max_source_spread_bps == 0
        || *max_source_spread_bps >= 10_000
        || *max_cross_source_deviation_bps == 0
        || *max_cross_source_deviation_bps >= 10_000
        || !valid_common_reference_policy(*max_age_ms, *envelope_bps, *attestation_ttl_ms)
    {
        return Err(format!(
            "market {} has invalid reference-price policy",
            market.market_id.0
        ));
    }
    let mut adapters = BTreeSet::from([observation_adapter(primary)]);
    for observation in corroborating {
        validate_observation(observation)?;
        if !matches!(observation, VenueObservation::SameVenueRatio { .. }) {
            return Err(format!(
                "market {} has an unsupported corroborating source shape",
                market.market_id.0
            ));
        }
        if !adapters.insert(observation_adapter(observation)) {
            return Err(format!(
                "market {} repeats a reference-price venue adapter",
                market.market_id.0
            ));
        }
    }
    for required in [VenueAdapter::Coinbase, VenueAdapter::Kraken] {
        if !adapters.contains(&required) {
            return Err(format!(
                "market {} is missing a required corroborating venue",
                market.market_id.0
            ));
        }
    }
    Ok(())
}

fn validate_synthetic_market(
    market: &MarketRegistryMarket,
    markets: &BTreeMap<&str, &MarketRegistryMarket>,
    numeraire: &AssetId,
) -> Result<(), String> {
    let MarketReferencePrice::SyntheticCrossBboMidpoint {
        base_market_id,
        quote_market_id,
        ..
    } = &market.reference_price
    else {
        if market.quote_asset_id != *numeraire {
            return Err(format!(
                "direct market {} must quote the objective numeraire",
                market.market_id.0
            ));
        }
        return Ok(());
    };
    if market.base_asset_id == *numeraire || market.quote_asset_id == *numeraire {
        return Err(format!(
            "synthetic market {} must connect two non-numeraire assets",
            market.market_id.0
        ));
    }
    let base_leg = markets
        .get(base_market_id.0.as_str())
        .ok_or_else(|| format!("market {} has an unknown base leg", market.market_id.0))?;
    let quote_leg = markets
        .get(quote_market_id.0.as_str())
        .ok_or_else(|| format!("market {} has an unknown quote leg", market.market_id.0))?;
    let valid_leg = |leg: &MarketRegistryMarket, asset: &AssetId| {
        leg.enabled
            && leg.base_asset_id == *asset
            && leg.quote_asset_id == *numeraire
            && matches!(
                leg.reference_price,
                MarketReferencePrice::DirectBboMidpoint { .. }
            )
    };
    if !valid_leg(base_leg, &market.base_asset_id)
        || !valid_leg(quote_leg, &market.quote_asset_id)
        || market.price_base_scale != base_leg.price_base_scale
        || market.price_base_scale != quote_leg.price_base_scale
        || base_market_id == quote_market_id
        || base_market_id == &market.market_id
        || quote_market_id == &market.market_id
    {
        return Err(format!(
            "market {} has invalid synthetic reference legs",
            market.market_id.0
        ));
    }
    Ok(())
}

fn validate_reference_identity(asset: &MarketRegistryAsset) -> Result<(), String> {
    let reference = asset.reference_identity.reference_asset_id.as_str();
    validate_identifier(reference, "reference asset")?;
    match asset.reference_identity.relationship {
        ReferenceRelationship::Native if reference != asset.asset_id.0 => Err(format!(
            "native asset {} must reference itself",
            asset.asset_id.0
        )),
        ReferenceRelationship::WrappedOneToOne | ReferenceRelationship::StableOneToOne
            if reference == asset.asset_id.0 =>
        {
            Err(format!(
                "non-native asset {} must explicitly name a different reference identity",
                asset.asset_id.0
            ))
        }
        _ => Ok(()),
    }
}

fn validate_observation(observation: &VenueObservation) -> Result<(), String> {
    let symbols: Vec<&str> = match observation {
        VenueObservation::Direct { symbol, .. } => vec![symbol],
        VenueObservation::SameVenueRatio {
            base_symbol,
            quote_symbol,
            ..
        } => vec![base_symbol, quote_symbol],
    };
    if symbols.into_iter().any(|symbol| {
        symbol.is_empty()
            || symbol.len() > 40
            || !symbol.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            })
    }) {
        return Err("market registry contains an invalid venue symbol".into());
    }
    Ok(())
}

fn observation_adapter(observation: &VenueObservation) -> VenueAdapter {
    match observation {
        VenueObservation::Direct { adapter, .. }
        | VenueObservation::SameVenueRatio { adapter, .. } => *adapter,
    }
}

impl VenueAdapter {
    fn as_str(self) -> &'static str {
        match self {
            Self::Binance => "binance",
            Self::Coinbase => "coinbase",
            Self::Kraken => "kraken",
            Self::Okx => "okx",
        }
    }
}

fn ensure_sorted_unique<'a>(
    values: impl Iterator<Item = &'a str>,
    label: &str,
) -> Result<(), String> {
    let values = values.collect::<Vec<_>>();
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(format!(
            "market registry {label}s must be strictly sorted and unique"
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '/' | '_' | '-')
        })
    {
        return Err(format!("invalid {label} identifier {value:?}"));
    }
    Ok(())
}

fn normalize_felt(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .ok_or("felt must use 0x-prefixed hexadecimal encoding")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid felt encoding".into());
    }
    let parsed = BigUint::parse_bytes(digits.as_bytes(), 16).ok_or("invalid felt encoding")?;
    let prime = BigUint::parse_bytes(STARKNET_FIELD_PRIME_DECIMAL.as_bytes(), 10)
        .expect("starknet field prime constant");
    if parsed >= prime {
        return Err("felt is outside the starknet field".into());
    }
    let normalized = if parsed.is_zero() {
        "0".to_owned()
    } else {
        parsed.to_str_radix(16)
    };
    Ok(format!("0x{normalized}"))
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|error| error.to_string())?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|error| error.to_string())?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_reference_mut(
        market: &mut MarketRegistryMarket,
    ) -> (
        &mut VenueObservation,
        &mut Vec<VenueObservation>,
        &mut usize,
    ) {
        let MarketReferencePrice::DirectBboMidpoint {
            primary,
            corroborating,
            min_sources,
            ..
        } = &mut market.reference_price
        else {
            panic!("expected direct reference policy")
        };
        (primary, corroborating, min_sources)
    }

    fn registry() -> MarketRegistry {
        let mut registry: MarketRegistry =
            serde_json::from_str(include_str!("../../config/market-registry.json")).unwrap();
        registry.registry_hash = registry.computed_hash().unwrap();
        registry
    }

    #[test]
    fn canonical_hash_is_stable_across_json_object_order() {
        let registry = registry();
        let hash = registry.computed_hash().unwrap();
        let value = serde_json::to_value(&registry).unwrap();
        let reparsed: MarketRegistry = serde_json::from_str(&value.to_string()).unwrap();
        assert_eq!(hash, reparsed.computed_hash().unwrap());
    }

    #[test]
    fn production_registry_is_valid_and_self_identifying() {
        MarketRegistry::from_json(include_str!("../../config/market-registry.json")).unwrap();
    }

    #[test]
    fn duplicates_missing_assets_and_bad_wrapped_identity_fail_closed() {
        let mut value = registry();
        value.assets.push(value.assets[0].clone());
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("sorted and unique"));

        let mut value = registry();
        value.assets[1].token_address = value.assets[0].token_address.clone();
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("duplicate token"));

        let mut value = registry();
        value.markets[0].base_asset_id = AssetId("UNKNOWN".into());
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("unknown base"));

        let mut value = registry();
        value.assets[0].reference_identity.relationship = ReferenceRelationship::WrappedOneToOne;
        value.registry_hash = value.computed_hash().unwrap();
        assert!(
            value
                .validate()
                .unwrap_err()
                .contains("different reference")
        );
    }

    #[test]
    fn missing_funding_and_external_prerequisites_fail_closed() {
        let mut value = registry();
        value.assets[0].funding_enabled = false;
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("funding capability"));

        let mut value = registry();
        value.markets[0].capabilities.external_matching = true;
        value.markets[0].external_settlement_support_quote = 0;
        value.markets[0].external_min_profit_quote = 1;
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("external matching"));
    }

    #[test]
    fn synthetic_markets_require_the_exact_direct_numeraire_legs() {
        let mut value = registry();
        let synthetic = value
            .markets
            .iter_mut()
            .find(|market| market.market_id.0 == "STRK/ETH")
            .unwrap();
        let MarketReferencePrice::SyntheticCrossBboMidpoint { base_market_id, .. } =
            &mut synthetic.reference_price
        else {
            panic!("expected synthetic market")
        };
        *base_market_id = PairId("ETH/USDC".into());
        value.registry_hash = value.computed_hash().unwrap();
        assert!(
            value
                .validate()
                .unwrap_err()
                .contains("invalid synthetic reference legs")
        );

        let mut value = registry();
        value
            .markets
            .iter_mut()
            .find(|market| market.market_id.0 == "STRK/ETH")
            .unwrap()
            .price_base_scale = 1_000_000;
        value.registry_hash = value.computed_hash().unwrap();
        assert!(
            value
                .validate()
                .unwrap_err()
                .contains("invalid synthetic reference legs")
        );

        let mut value = registry();
        let synthetic = value
            .markets
            .iter_mut()
            .find(|market| market.market_id.0 == "STRK/ETH")
            .unwrap();
        synthetic.capabilities.external_matching = true;
        synthetic.external_settlement_support_quote = 1;
        synthetic.external_min_profit_quote = 1;
        value.registry_hash = value.computed_hash().unwrap();
        value.validate().unwrap();
    }

    #[test]
    fn malformed_addresses_sources_and_objective_paths_fail_closed() {
        let mut value = registry();
        value.assets[0].token_address = "0x00".into();
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("token address"));

        let mut value = registry();
        value.assets[0].token_address = format!(
            "0x{:x}",
            BigUint::parse_bytes(STARKNET_FIELD_PRIME_DECIMAL.as_bytes(), 10,).unwrap()
        );
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("starknet field"));

        let mut value = registry();
        direct_reference_mut(&mut value.markets[0]).1[0] = VenueObservation::SameVenueRatio {
            adapter: VenueAdapter::Binance,
            base_symbol: "ETHUSDC".into(),
            quote_symbol: "USDCUSDC".into(),
        };
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("repeats"));

        let mut value = registry();
        *direct_reference_mut(&mut value.markets[0]).0 = VenueObservation::Direct {
            adapter: VenueAdapter::Binance,
            symbol: "https://untrusted.example".into(),
        };
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("venue symbol"));

        let mut value = registry();
        *direct_reference_mut(&mut value.markets[0]).0 = VenueObservation::Direct {
            adapter: VenueAdapter::Coinbase,
            symbol: "ETH-USDC".into(),
        };
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("direct binance"));

        let mut value = registry();
        direct_reference_mut(&mut value.markets[0]).1[0] = VenueObservation::Direct {
            adapter: VenueAdapter::Coinbase,
            symbol: "ETH-USDC".into(),
        };
        value.registry_hash = value.computed_hash().unwrap();
        assert!(
            value
                .validate()
                .unwrap_err()
                .contains("corroborating source shape")
        );

        let mut value = registry();
        direct_reference_mut(&mut value.markets[0])
            .1
            .retain(|source| {
                !matches!(
                    source,
                    VenueObservation::SameVenueRatio {
                        adapter: VenueAdapter::Coinbase,
                        ..
                    }
                )
            });
        value.registry_hash = value.computed_hash().unwrap();
        assert!(
            value
                .validate()
                .unwrap_err()
                .contains("required corroborating venue")
        );

        let raw = include_str!("../../config/market-registry.json")
            .replace(r#""adapter": "binance""#, r#""adapter": "untrusted""#);
        assert!(
            MarketRegistry::from_json(&raw)
                .unwrap_err()
                .contains("unknown variant")
        );

        let mut value = registry();
        *direct_reference_mut(&mut value.markets[0]).2 = 5;
        value.registry_hash = value.computed_hash().unwrap();
        assert!(
            value
                .validate()
                .unwrap_err()
                .contains("reference-price policy")
        );

        let mut value = registry();
        value.objective_numeraire_asset_id = AssetId("STRK".into());
        value.registry_hash = value.computed_hash().unwrap();
        assert!(value.validate().unwrap_err().contains("direct market"));
    }
}

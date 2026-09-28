//! prices the operator needs: attested midpoints from the reference-price attestor (m0 at the
//! close, a fresh m1 for an external fill) and ekubo hedge routes for its own searcher leg.

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use starknet_rust_core::types::{Call, Felt};
use zylith_core::ReferencePriceAttestation;
use zylith_core::exchange::{MarketAttestation, price_batch_commitment};

use crate::config::{Config, PairRuntime, from_core, to_core};
use crate::snip36::call;

#[derive(Serialize)]
struct AttestationRequest<'a> {
    pair_id: &'a str,
    base_asset_id: &'a str,
    quote_asset_id: &'a str,
    price_base_scale: u128,
    exchange_address: String,
}

#[derive(Deserialize)]
struct AttestationResponse {
    attestation: ReferencePriceAttestation,
}

#[derive(Serialize)]
struct PriceBatchRequest<'a> {
    markets: Vec<AttestationRequest<'a>>,
}

#[derive(Deserialize)]
struct PriceBatchResponse {
    attestations: Vec<ReferencePriceAttestation>,
}

/// an attested rate: `midpoint` quote atoms per `scale` base atoms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    pub base: Felt,
    pub quote: Felt,
    pub midpoint: u128,
    pub scale: u128,
}

/// `value * numerator / denominator` over a 256-bit product, as the contract computes it, rounded
/// down or up; nothing when the denominator is zero or the result leaves u128.
pub fn mul_div(value: u128, numerator: u128, denominator: u128, up: bool) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    let product = num_bigint::BigUint::from(value) * num_bigint::BigUint::from(numerator);
    let denominator = num_bigint::BigUint::from(denominator);
    let mut quotient = &product / &denominator;
    if up && (&product % &denominator) != num_bigint::BigUint::ZERO {
        quotient += 1_u8;
    }
    u128::try_from(quotient).ok()
}

/// how a converted amount rounds: a value (a fee received, a profit) down, a cost up, so every
/// conversion errs against the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Round {
    Value,
    Cost,
}

/// converts `amount` of asset `from` into asset `to` through at most two attested rates, every
/// step rounded as `round` says; nothing when no rate connects them.
pub fn convert(rates: &[Rate], from: Felt, to: Felt, amount: u128, round: Round) -> Option<u128> {
    if from == to {
        return Some(amount);
    }
    let up = round == Round::Cost;
    let step = |rate: &Rate, from: Felt, amount: u128| -> Option<(Felt, u128)> {
        if rate.base == from {
            Some((rate.quote, mul_div(amount, rate.midpoint, rate.scale, up)?))
        } else if rate.quote == from {
            Some((rate.base, mul_div(amount, rate.scale, rate.midpoint, up)?))
        } else {
            None
        }
    };
    let direct = rates
        .iter()
        .filter_map(|rate| step(rate, from, amount))
        .find(|(asset, _)| *asset == to);
    if let Some((_, value)) = direct {
        return Some(value);
    }
    rates.iter().find_map(|first| {
        let (middle, value) = step(first, from, amount)?;
        rates
            .iter()
            .filter(|second| *second != first)
            .filter_map(|second| step(second, middle, value))
            .find(|(asset, _)| *asset == to)
            .map(|(_, value)| value)
    })
}

/// the l2 gas a searcher leg is expected to burn: the router's fixed cost plus its swaps, from
/// the route's shape or ekubo's own estimate, whichever is larger.
#[derive(Clone, Copy, Debug)]
pub struct LegGas {
    pub base: u64,
    pub per_split: u64,
    pub per_hop: u64,
}

impl LegGas {
    fn of(&self, splits: &[Split], quoted_estimate: u64) -> u64 {
        let hops = splits
            .iter()
            .map(|split| split.route.len() as u64)
            .sum::<u64>();
        let shape = self
            .per_split
            .saturating_mul(splits.len() as u64)
            .saturating_add(self.per_hop.saturating_mul(hops));
        self.base.saturating_add(shape.max(quoted_estimate))
    }
}

pub struct Market {
    http: Client,
    attestor_url: String,
    attestor_token: String,
    exchange: Felt,
    router: Felt,
    quoter_url: Option<String>,
    chain_name: String,
    tokens: std::collections::BTreeMap<String, Felt>,
    /// the margin a leg must clear beyond its gas, in atoms of each quote asset: raw amounts of
    /// different assets are never compared.
    min_profit: std::collections::BTreeMap<Felt, u128>,
    leg_gas: LegGas,
    /// the price move, in basis points of the escrow's side, a chosen leg must survive.
    headroom_bps: u128,
    /// the latest attestation of each pair, which serves the public reference price until it
    /// lapses.
    latest: tokio::sync::Mutex<std::collections::HashMap<Felt, MarketAttestation>>,
}

impl Market {
    pub fn new(config: &Config) -> Result<Self, String> {
        let tokens = config
            .manifest
            .token_addresses
            .iter()
            .map(|(name, address)| {
                Ok((name.clone(), crate::config::felt(address, "token address")?))
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            http: Client::builder()
                .timeout(Duration::from_secs(4))
                .build()
                .expect("http client"),
            attestor_url: config.attestor_url.trim_end_matches('/').to_owned(),
            attestor_token: config.attestor_token.clone(),
            exchange: config.exchange,
            router: config.router,
            quoter_url: config.route_service_url.clone(),
            // the quoter names chains by their decimal id.
            chain_name: config.chain_id.to_biguint().to_string(),
            tokens,
            min_profit: config.searcher_min_profit.clone(),
            leg_gas: config.leg_gas,
            headroom_bps: config.searcher_headroom_bps,
            latest: Default::default(),
        })
    }

    /// a fresh attested reference price for `pair`, bound to the exchange.
    pub async fn attest(&self, pair: &PairRuntime) -> Result<MarketAttestation, String> {
        let response = self
            .http
            .post(format!(
                "{}/api/v1/reference-price-attestations",
                self.attestor_url
            ))
            .bearer_auth(&self.attestor_token)
            .json(&AttestationRequest {
                pair_id: &pair.name,
                base_asset_id: &pair.base_name,
                quote_asset_id: &pair.quote_name,
                price_base_scale: pair.scale,
                exchange_address: format!("{:#x}", self.exchange),
            })
            .send()
            .await
            .map_err(|error| format!("attestor {}: {error}", pair.name))?;
        if !response.status().is_success() {
            return Err(format!(
                "attestor {} returned {}",
                pair.name,
                response.status()
            ));
        }
        let response: AttestationResponse = response
            .json()
            .await
            .map_err(|error| format!("attestor {}: {error}", pair.name))?;
        let attestation = MarketAttestation::from_reference(&response.attestation)
            .map_err(|error| error.to_string())?;
        if from_core(attestation.pair_id) != pair.pair_id || attestation.scale != pair.scale {
            return Err(format!(
                "attestor returned a different market for {}",
                pair.name
            ));
        }
        self.latest
            .lock()
            .await
            .insert(pair.pair_id, attestation.clone());
        Ok(attestation)
    }

    /// one authenticated batch for an epoch: every direct market observation and the usdc
    /// objective vector derived from its direct asset/usdc members share one commitment.
    pub async fn attest_batch(
        &self,
        pairs: &[PairRuntime],
    ) -> Result<Vec<MarketAttestation>, String> {
        let response = self
            .http
            .post(format!(
                "{}/api/v1/reference-price-batches",
                self.attestor_url
            ))
            .bearer_auth(&self.attestor_token)
            .json(&PriceBatchRequest {
                markets: pairs
                    .iter()
                    .map(|pair| AttestationRequest {
                        pair_id: &pair.name,
                        base_asset_id: &pair.base_name,
                        quote_asset_id: &pair.quote_name,
                        price_base_scale: pair.scale,
                        exchange_address: format!("{:#x}", self.exchange),
                    })
                    .collect(),
            })
            .send()
            .await
            .map_err(|error| format!("price batch: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("price batch returned {}", response.status()));
        }
        let response: PriceBatchResponse = response
            .json()
            .await
            .map_err(|error| format!("price batch: {error}"))?;
        if response.attestations.len() != pairs.len() {
            return Err("price batch returned a different market count".into());
        }
        let mut attestations = response
            .attestations
            .iter()
            .map(MarketAttestation::from_reference)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        attestations.sort_by_key(|attestation| from_core(attestation.pair_id).to_bytes_be());
        for (attestation, pair) in attestations.iter().zip(pairs) {
            if from_core(attestation.pair_id) != pair.pair_id
                || attestation.scale != pair.scale
                || !attestation.verify(to_core(self.exchange))
            {
                return Err(format!("price batch mismatches {}", pair.name));
            }
        }
        let commitment = price_batch_commitment(to_core(self.exchange), &attestations);
        if attestations
            .iter()
            .any(|attestation| attestation.price_batch_commitment != commitment)
        {
            return Err("price batch commitment does not match its members".into());
        }
        let mut latest = self.latest.lock().await;
        for attestation in &attestations {
            latest.insert(from_core(attestation.pair_id), attestation.clone());
        }
        Ok(attestations)
    }

    /// the pair's current attested price: the latest attestation while it is valid, a fresh one
    /// otherwise.
    pub async fn reference(
        &self,
        pair: &PairRuntime,
        now_ms: u64,
    ) -> Result<MarketAttestation, String> {
        if let Some(attestation) = self
            .latest
            .lock()
            .await
            .get(&pair.pair_id)
            .filter(|attestation| attestation.valid_until_ms > now_ms)
        {
            return Ok(attestation.clone());
        }
        self.attest(pair).await
    }

    /// the attested rate of every traded pair, from the latest valid attestations.
    pub async fn rates(&self, pairs: &[PairRuntime], now_ms: u64) -> Vec<Rate> {
        let mut rates = Vec::new();
        for pair in pairs {
            if let Ok(attestation) = self.reference(pair, now_ms).await {
                rates.push(Rate {
                    base: pair.base_asset_id,
                    quote: pair.quote_asset_id,
                    midpoint: attestation.midpoint,
                    scale: attestation.scale,
                });
            }
        }
        rates
    }

    /// the router call for the most profitable external fill of a capacity, if one clears the
    /// leg's gas cost (`gas_cost` prices l2 gas in quote atoms, rounded up; each candidate's gas
    /// follows its route's splits and hops): the escrow trades up to `total` of the residual at
    /// a fresh m1 inside the bound, and the router hedges it on ekubo. profit is rarely linear
    /// in size (the pool's
    /// price moves with the trade), so a coarse grid of sizes is quoted at once and the best is
    /// refined between its neighbours. the call carries the cost plus the margin as its on-chain
    /// minimum profit, so a route gone stale by execution reverts the leg instead of losing money.
    /// every compared size is quoted against one ekubo block no older than `chain_tip` allows, so
    /// the best size is chosen by size and not by pool state moving between quotes.
    #[allow(clippy::too_many_arguments)]
    pub async fn external_leg(
        &self,
        pair: &PairRuntime,
        seq: u32,
        sell: bool,
        bound: u128,
        total: u128,
        gas_cost: &(dyn Fn(u64) -> Option<u128> + Send + Sync),
        chain_tip: u64,
    ) -> Result<Option<ExternalLeg>, String> {
        let Some(&min_profit) = self.min_profit.get(&pair.quote_asset_id) else {
            return Ok(None);
        };
        if self.quoter_url.is_none()
            || !pair.external_enabled
            || self.router == Felt::ZERO
            || total == 0
            || min_profit == 0
        {
            return Ok(None);
        }
        let m1 = self.attest(pair).await?;
        if (sell && m1.midpoint < bound) || (!sell && m1.midpoint > bound) {
            return Ok(None);
        }
        let tokens = (
            *self
                .tokens
                .get(&pair.base_name)
                .ok_or("base token is not configured")?,
            *self
                .tokens
                .get(&pair.quote_name)
                .ok_or("quote token is not configured")?,
        );
        // each candidate's profit net of its own gas, all in checked arithmetic: an amount that
        // leaves range drops the candidate instead of wrapping.
        let evaluate = |size: u128| {
            let m1 = &m1;
            async move {
                let Some(mut quote) = self.quote(tokens, size, sell).await? else {
                    return Ok::<_, String>(None);
                };
                let Some(escrow) = escrow_quote(size, m1.midpoint, m1.scale, sell) else {
                    return Ok(None);
                };
                let gas = self.leg_gas.of(&quote.splits, quote.estimated_gas);
                let Some(cost) = gas_cost(gas) else {
                    return Ok(None);
                };
                let (received, paid) = if sell {
                    (quote.calculated, escrow)
                } else {
                    (escrow, quote.calculated)
                };
                let net = i128::try_from(received)
                    .ok()
                    .zip(i128::try_from(paid).ok())
                    .zip(i128::try_from(cost).ok())
                    .and_then(|((received, paid), cost)| {
                        received.checked_sub(paid)?.checked_sub(cost)
                    });
                quote.cost = cost;
                Ok(net.map(|net| (size, net, quote)))
            }
        };
        let grid = [16_u128, 12, 8, 4, 2, 1]
            .into_iter()
            .map(|sixteenths| total * sixteenths / 16)
            .filter(|size| *size > 0)
            .collect::<std::collections::BTreeSet<_>>();
        let mut sweep = None;
        for _ in 0..SWEEP_ATTEMPTS {
            let quoted = futures::future::join_all(grid.iter().map(|size| evaluate(*size)))
                .await
                .into_iter()
                .filter_map(Result::transpose)
                .collect::<Result<Vec<_>, _>>()?;
            let Some(block) = quoted.first().map(|(_, _, quote)| quote.block) else {
                return Ok(None);
            };
            if quoted.iter().all(|(_, _, quote)| quote.block == block) {
                sweep = Some((block, quoted));
                break;
            }
        }
        let Some((block, mut quoted)) = sweep else {
            return Err("ekubo quoted the candidate sizes at different blocks".into());
        };
        if block.0.saturating_add(MAX_QUOTE_AGE_BLOCKS) < chain_tip {
            return Err(format!(
                "ekubo quote at block {} is behind the chain tip {chain_tip}",
                block.0
            ));
        }
        for _ in 0..REFINE_ROUNDS {
            quoted.sort_by_key(|(size, _, _)| *size);
            let Some(best) = best_index(&quoted) else {
                break;
            };
            let low = if best == 0 { 0 } else { quoted[best - 1].0 };
            let high = quoted.get(best + 1).map_or(quoted[best].0, |next| next.0);
            let probes = [(low + quoted[best].0) / 2, (quoted[best].0 + high) / 2]
                .into_iter()
                .filter(|size| *size > 0 && !quoted.iter().any(|(quoted, _, _)| quoted == size))
                .collect::<Vec<_>>();
            if probes.is_empty() {
                break;
            }
            let refined = futures::future::join_all(probes.into_iter().map(evaluate))
                .await
                .into_iter()
                .filter_map(Result::transpose)
                .collect::<Result<Vec<_>, _>>()?;
            // a probe from another block cannot be compared with the sweep, so refining stops.
            if refined.iter().any(|(_, _, quote)| quote.block != block) {
                break;
            }
            quoted.extend(refined);
        }
        let Some((size, net, quote)) = best_index(&quoted).map(|best| quoted.swap_remove(best))
        else {
            return Ok(None);
        };
        // the quote is a block old by execution: the leg must clear the margin with headroom for
        // the pool moving by `headroom_bps` of the escrow's side.
        let required = escrow_quote(size, m1.midpoint, m1.scale, sell)
            .and_then(|escrow| mul_div(escrow, self.headroom_bps, 10_000, true))
            .and_then(|headroom| headroom.checked_add(min_profit))
            .and_then(|required| i128::try_from(required).ok());
        if required.is_none_or(|required| net < required) {
            return Ok(None);
        }
        let cost = quote.cost;
        let minimum_profit = cost
            .checked_add(min_profit)
            .ok_or("the leg's minimum profit overflows")?;
        let leg_net = u128::try_from(net).map_err(|_| "negative profit")?;
        let mut calldata = vec![
            self.exchange,
            Felt::from(seq),
            pair.pair_id,
            Felt::from(u8::from(sell)),
            Felt::from(size),
            Felt::from(minimum_profit),
        ];
        calldata.extend(m1.calldata().into_iter().map(from_core));
        calldata.extend(encode_swaps(
            &quote.splits,
            tokens.0,
            tokens.1,
            size,
            !sell,
        )?);
        Ok(Some(ExternalLeg {
            call: call(self.router, "execute_external_fill", calldata),
            sell,
            bound,
            calculated: quote.calculated,
            cost,
            fill_base: size,
            net_profit_quote: leg_net,
            gross_profit_quote: leg_net
                .checked_add(cost)
                .ok_or("the leg's profit overflows")?,
            outcome_support: 0,
        }))
    }

    /// re-attests m1 immediately before a leg is sent and re-prices the leg on its route: m1 ages
    /// through the quotes and simulations that chose it, and the contract checks its validity at
    /// inclusion. the call takes the fresh m1 and keeps its on-chain minimum profit; false when
    /// the leg no longer clears its margin and headroom at the fresh price.
    pub async fn refresh_leg(
        &self,
        pair: &PairRuntime,
        leg: &mut ExternalLeg,
        now_ms: u64,
    ) -> Result<bool, String> {
        let m1 = self.attest(pair).await?;
        if m1.valid_until_ms < now_ms.saturating_add(MIN_M1_LIFETIME_MS) {
            return Err("the fresh m1 lapses before the leg could land".into());
        }
        let Some(&min_profit) = self.min_profit.get(&pair.quote_asset_id) else {
            return Ok(false);
        };
        if (leg.sell && m1.midpoint < leg.bound) || (!leg.sell && m1.midpoint > leg.bound) {
            return Ok(false);
        }
        let Some(escrow) = escrow_quote(leg.fill_base, m1.midpoint, m1.scale, leg.sell) else {
            return Ok(false);
        };
        let (received, paid) = if leg.sell {
            (leg.calculated, escrow)
        } else {
            (escrow, leg.calculated)
        };
        let floor = leg
            .call
            .calldata
            .get(LEG_MIN_PROFIT_INDEX)
            .and_then(|floor| u128::try_from(*floor).ok())
            .ok_or("the leg carries no minimum profit")?;
        let required = mul_div(escrow, self.headroom_bps, 10_000, true)
            .and_then(|headroom| headroom.checked_add(min_profit));
        let Some(gross) = received.checked_sub(paid) else {
            return Ok(false);
        };
        let Some(net) = gross
            .checked_sub(leg.cost)
            .and_then(|net| net.checked_sub(leg.outcome_support))
        else {
            return Ok(false);
        };
        if required.is_none_or(|required| net < required) || gross < floor {
            return Ok(false);
        }
        let fields = m1.calldata();
        let slot = leg
            .call
            .calldata
            .get_mut(LEG_M1_INDEX..LEG_M1_INDEX + fields.len())
            .ok_or("the leg carries no m1")?;
        for (slot, field) in slot.iter_mut().zip(fields) {
            *slot = from_core(field);
        }
        leg.net_profit_quote = gross - leg.cost;
        leg.gross_profit_quote = gross;
        Ok(true)
    }

    /// ekubo's route for selling (`sell`) or buying `size` base, or nothing without a route.
    async fn quote(
        &self,
        (base, quote): (Felt, Felt),
        size: u128,
        sell: bool,
    ) -> Result<Option<Quote>, String> {
        let quoter = self.quoter_url.as_deref().ok_or("no quoter")?;
        let signed_amount = if sell {
            size.to_string()
        } else {
            format!("-{size}")
        };
        let url = format!(
            "{}/{}/{}/{:#x}/{:#x}",
            quoter.trim_end_matches('/'),
            self.chain_name,
            signed_amount,
            base,
            quote
        );
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| format!("ekubo quote: {error}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let mut response = response
            .error_for_status()
            .map_err(|error| format!("ekubo quote: {error}"))?;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("ekubo quote: {error}"))?
        {
            if body.len() + chunk.len() > MAX_QUOTE_BYTES {
                return Err("ekubo quote response is too large".into());
            }
            body.extend_from_slice(&chunk);
        }
        let response: QuoteResponse =
            serde_json::from_slice(&body).map_err(|error| format!("ekubo quote: {error}"))?;
        validate_quote(&response, sell)?;
        Ok(Some(Quote {
            calculated: magnitude(&response.total_calculated)?,
            block: (response.block_number, route_felt(&response.block_hash)?),
            estimated_gas: response.estimated_gas_cost,
            splits: response.splits,
            cost: 0,
        }))
    }
}

const REFINE_ROUNDS: usize = 2;
/// how many times a sweep is re-quoted when its sizes come back from different blocks.
const SWEEP_ATTEMPTS: usize = 2;
/// how far a quote's block may trail the chain tip.
const MAX_QUOTE_AGE_BLOCKS: u64 = 3;
/// caps on a quote response, far above any real route, that keep a faulty quoter from producing
/// an unbounded download or router call.
const MAX_QUOTE_BYTES: usize = 256 * 1024;
const MAX_SPLITS: usize = 16;
const MAX_HOPS: usize = 8;

/// a profitable external fill: the router call, its size, and its profit before and after the
/// leg's estimated gas, with what re-pricing it at a fresh m1 needs.
pub struct ExternalLeg {
    pub call: Call,
    pub fill_base: u128,
    pub net_profit_quote: u128,
    pub gross_profit_quote: u128,
    sell: bool,
    /// the capacity's price bound.
    bound: u128,
    /// what ekubo pays for a sell or asks for a buy, on the chosen route.
    calculated: u128,
    /// the leg's estimated gas in quote atoms.
    cost: u128,
    /// the share of the later settlement transition this leg funds, in quote atoms: set when the
    /// leg is kept, for the one leg of a transition that pays for its settlement.
    pub(crate) outcome_support: u128,
}

/// where the router call carries m1.
const LEG_M1_INDEX: usize = 6;
/// the least validity a fresh m1 must have left when a leg is sent: simulation, submission and
/// inclusion all happen inside it.
const MIN_M1_LIFETIME_MS: u64 = 3_000;

/// where the router call carries its on-chain minimum profit.
pub const LEG_MIN_PROFIT_INDEX: usize = 5;

struct Quote {
    calculated: u128,
    block: (u64, Felt),
    /// ekubo's own gas estimate for the swaps.
    estimated_gas: u64,
    splits: Vec<Split>,
    /// the leg's gas in quote atoms, once priced.
    cost: u128,
}

/// the escrow's side of a fill of `size` base at m1, over a 256-bit product and rounded as the
/// contract rounds it: down for what a sell receives, up for what a buy pays.
fn escrow_quote(size: u128, midpoint: u128, scale: u128, sell: bool) -> Option<u128> {
    mul_div(size, midpoint, scale, !sell)
}

/// the most profitable quoted size, ties to the smaller.
fn best_index<T>(quoted: &[(u128, i128, T)]) -> Option<usize> {
    quoted
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| left.1.cmp(&right.1).then(right.0.cmp(&left.0)))
        .map(|(index, _)| index)
}

#[derive(Deserialize)]
struct QuoteResponse {
    block_number: u64,
    block_hash: String,
    #[serde(default)]
    estimated_gas_cost: u64,
    total_calculated: String,
    splits: Vec<Split>,
}

#[derive(Deserialize)]
struct Split {
    amount_specified: String,
    amount_calculated: String,
    route: Vec<RouteNode>,
}

/// the response's shape and totals: bounded splits and hops, and split calculated amounts that
/// add up, sign included, to the quote's total. the specified amounts and the route itself are
/// checked where the call is encoded.
fn validate_quote(response: &QuoteResponse, sell: bool) -> Result<(), String> {
    if response.splits.is_empty() || response.splits.len() > MAX_SPLITS {
        return Err("ekubo returned an unusable number of splits".into());
    }
    if response
        .splits
        .iter()
        .any(|split| split.route.is_empty() || split.route.len() > MAX_HOPS)
    {
        return Err("ekubo returned an unusable route length".into());
    }
    // exact input (a sell) calculates the output, positive; exact output (a buy) calculates the
    // input, negative. every split calculates in the same direction as the total.
    let total = signed(&response.total_calculated)?;
    if (total > 0) != sell {
        return Err("ekubo quoted the wrong direction".into());
    }
    let mut sum = 0_i128;
    for split in &response.splits {
        let calculated = signed(&split.amount_calculated)?;
        if calculated != 0 && (calculated > 0) != sell {
            return Err("ekubo split calculates in the wrong direction".into());
        }
        sum = sum
            .checked_add(calculated)
            .ok_or("ekubo calculated amounts overflow")?;
    }
    if total == 0 || sum != total {
        return Err("ekubo split calculated amounts do not match its total".into());
    }
    Ok(())
}

fn signed(value: &str) -> Result<i128, String> {
    value.parse().map_err(|_| format!("invalid amount {value}"))
}

#[derive(Deserialize)]
struct RouteNode {
    pool_key: PoolKey,
    sqrt_ratio_limit: String,
    skip_ahead: u128,
}

#[derive(Deserialize)]
struct PoolKey {
    token0: String,
    token1: String,
    fee: String,
    tick_spacing: u128,
    extension: String,
}

fn magnitude(value: &str) -> Result<u128, String> {
    value
        .trim_start_matches('-')
        .parse()
        .map_err(|_| format!("invalid amount {value}"))
}

fn route_felt(value: &str) -> Result<Felt, String> {
    if value.starts_with("0x") {
        Felt::from_hex(value)
    } else {
        Felt::from_dec_str(value)
    }
    .map_err(|error| error.to_string())
}

/// the router's swap array: each split's route and its signed base amount.
fn encode_swaps(
    splits: &[Split],
    base_token: Felt,
    quote_token: Felt,
    total: u128,
    exact_output: bool,
) -> Result<Vec<Felt>, String> {
    let mut calldata = vec![Felt::from(splits.len() as u64)];
    let mut specified = 0_u128;
    for split in splits {
        if split.route.is_empty() || split.amount_specified.starts_with('-') != exact_output {
            return Err("ekubo returned an unusable route".into());
        }
        calldata.push(Felt::from(split.route.len() as u64));
        let mut token = base_token;
        for node in &split.route {
            let (token0, token1) = (
                route_felt(&node.pool_key.token0)?,
                route_felt(&node.pool_key.token1)?,
            );
            token = if token == token0 {
                token1
            } else if token == token1 {
                token0
            } else {
                return Err("ekubo route is not continuous".into());
            };
            let limit = route_felt(&node.sqrt_ratio_limit)?.to_bytes_be();
            calldata.extend([
                token0,
                token1,
                route_felt(&node.pool_key.fee)?,
                Felt::from(node.pool_key.tick_spacing),
                route_felt(&node.pool_key.extension)?,
                Felt::from(u128::from_be_bytes(
                    limit[16..].try_into().expect("16 bytes"),
                )),
                Felt::from(u128::from_be_bytes(
                    limit[..16].try_into().expect("16 bytes"),
                )),
                Felt::from(node.skip_ahead),
            ]);
        }
        if token != quote_token {
            return Err("ekubo route does not end in the quote token".into());
        }
        let amount = magnitude(&split.amount_specified)?;
        specified = specified
            .checked_add(amount)
            .ok_or("route amounts overflow")?;
        calldata.extend([
            base_token,
            Felt::from(amount),
            Felt::from(u8::from(exact_output)),
        ]);
    }
    if specified != total {
        return Err("ekubo routes do not cover the fill".into());
    }
    Ok(calldata)
}

#[cfg(test)]
mod tests {
    use axum::Json;
    use axum::extract::Path;
    use axum::routing::{get, post};
    use serde_json::{Value, json};
    use zylith_core::{AssetId, PairId, ReferencePriceEnvelope, sign_reference_price_attestation};

    use super::*;
    use crate::config::{asset_felt, pair_felt};

    const POOL_BASE: u128 = 1_000;
    const POOL_QUOTE: u128 = 1_100_000;
    const M1: u128 = 1_000;

    fn pair() -> PairRuntime {
        PairRuntime {
            name: "STRK/USDC".into(),
            base_name: "STRK".into(),
            quote_name: "USDC".into(),
            pair_id: pair_felt("STRK/USDC"),
            base_asset_id: asset_felt("STRK"),
            quote_asset_id: asset_felt("USDC"),
            scale: 1,
            fee_bps: 4,
            external_enabled: true,
            min_order_amount: 1,
        }
    }

    /// an attestor and a constant-product ekubo quoter priced above m1, so profit rises and then
    /// falls with size. `block` picks the ekubo block each quoted size reports.
    async fn market() -> Market {
        market_at(|_| QUOTE_BLOCK).await
    }

    const QUOTE_BLOCK: u64 = 100;

    async fn market_at(block: fn(u128) -> u64) -> Market {
        let attestation = sign_reference_price_attestation(
            "0x5167",
            "0xe",
            ReferencePriceEnvelope {
                pair_id: PairId("STRK/USDC".into()),
                base_asset_id: AssetId("STRK".into()),
                quote_asset_id: AssetId("USDC".into()),
                midpoint_price: M1,
                lower_price: M1,
                upper_price: M1,
                price_base_scale: 1,
                source_count: 3,
                observed_at_unix_ms: 1,
            },
            "0x5e7",
            u64::MAX / 2,
            1,
        )
        .unwrap();
        let (base, quote) = (Felt::from(0xba5e_u16), Felt::from(0x9a07e_u32));
        let app = axum::Router::new()
            .route(
                "/api/v1/reference-price-attestations",
                post(move || {
                    let attestation = attestation.clone();
                    async move { Json(json!({ "attestation": attestation })) }
                }),
            )
            .route(
                "/{chain}/{amount}/{base}/{quote}",
                get(move |Path((_, amount, _, _)): Path<(String, String, String, String)>| async move {
                    // a sell quotes the quote it receives, positive; a buy the quote it pays,
                    // negative.
                    let size: u128 = amount.trim_start_matches('-').parse().unwrap();
                    let out = if amount.starts_with('-') {
                        format!("-{}", (POOL_QUOTE * size).div_ceil(POOL_BASE - size))
                    } else {
                        (POOL_QUOTE * size / (POOL_BASE + size)).to_string()
                    };
                    Json::<Value>(json!({
                        "block_number": block(size),
                        "block_hash": format!("{:#x}", block(size)),
                        "estimated_gas_cost": 1,
                        "price_impact": 0.0,
                        "total_calculated": out.clone(),
                        "splits": [{
                            "amount_specified": amount,
                            "amount_calculated": out,
                            "route": [{
                                "pool_key": {
                                    "token0": format!("{base:#x}"),
                                    "token1": format!("{quote:#x}"),
                                    "fee": "0x0",
                                    "tick_spacing": 1,
                                    "extension": "0x0",
                                },
                                "sqrt_ratio_limit": "0x1",
                                "skip_ahead": 0,
                            }],
                        }],
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Market {
            http: Client::new(),
            attestor_url: url.clone(),
            attestor_token: "token".into(),
            exchange: Felt::from(0xe_u8),
            router: Felt::from(0x7_u8),
            quoter_url: Some(url),
            chain_name: "1".into(),
            tokens: [("STRK".to_string(), base), ("USDC".to_string(), quote)].into(),
            min_profit: [(asset_felt("USDC"), 1)].into(),
            leg_gas: LegGas {
                base: 0,
                per_split: 0,
                per_hop: 0,
            },
            headroom_bps: 0,
            latest: Default::default(),
        }
    }

    fn profit(size: u128) -> i128 {
        (POOL_QUOTE * size / (POOL_BASE + size)) as i128 - (size * M1) as i128
    }

    #[tokio::test]
    async fn the_leg_fills_the_most_profitable_size_not_the_whole_capacity() {
        let market = market().await;
        // the whole 800 would lose money; the optimum is near 49.
        assert!(profit(800) < 0);
        let leg = market
            .external_leg(&pair(), 3, true, 900, 800, &|_| Some(0), QUOTE_BLOCK)
            .await
            .unwrap()
            .unwrap();
        let best = (1..=800).map(profit).max().unwrap();
        assert!(
            profit(leg.fill_base) * 100 >= best * 95,
            "{} is far from the optimum",
            leg.fill_base
        );
        assert_eq!(leg.net_profit_quote as i128, profit(leg.fill_base));
        // the call's on-chain minimum profit is the leg's cost plus the margin.
        assert_eq!(leg.call.calldata[4], Felt::from(leg.fill_base));
        assert_eq!(leg.call.calldata[5], Felt::from(1_u8));

        // a leg whose gas exceeds every size's profit is not sent.
        assert!(
            market
                .external_leg(
                    &pair(),
                    3,
                    true,
                    900,
                    800,
                    &|_| Some(best as u128),
                    QUOTE_BLOCK
                )
                .await
                .unwrap()
                .is_none()
        );
        // an m1 outside the reserved bound is not sent either.
        assert!(
            market
                .external_leg(&pair(), 3, true, M1 + 1, 800, &|_| Some(0), QUOTE_BLOCK)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_leg_is_repriced_at_a_fresh_m1_before_it_is_sent() {
        let mut market = market().await;
        let mut leg = market
            .external_leg(&pair(), 3, true, 900, 800, &|_| Some(0), QUOTE_BLOCK)
            .await
            .unwrap()
            .unwrap();
        let before = leg.call.calldata.clone();
        assert!(market.refresh_leg(&pair(), &mut leg, 0).await.unwrap());
        // the on-chain floor and route stay; only m1 is replaced.
        assert_eq!(leg.call.calldata.len(), before.len());
        assert_eq!(
            leg.call.calldata[LEG_MIN_PROFIT_INDEX],
            before[LEG_MIN_PROFIT_INDEX]
        );
        // a floor above what the leg now earns would only revert on chain.
        leg.call.calldata[LEG_MIN_PROFIT_INDEX] = Felt::from(u64::MAX);
        assert!(!market.refresh_leg(&pair(), &mut leg, 0).await.unwrap());
        leg.call.calldata[LEG_MIN_PROFIT_INDEX] = before[LEG_MIN_PROFIT_INDEX];
        // the leg that funds the settlement must still earn it at the fresh price.
        leg.outcome_support = leg.net_profit_quote;
        assert!(!market.refresh_leg(&pair(), &mut leg, 0).await.unwrap());
        leg.outcome_support = leg.net_profit_quote - 1;
        assert!(market.refresh_leg(&pair(), &mut leg, 0).await.unwrap());
        leg.outcome_support = 0;
        // a leg the fresh price no longer pays for is dropped.
        market.headroom_bps = 10_000;
        assert!(!market.refresh_leg(&pair(), &mut leg, 0).await.unwrap());
        // an m1 about to lapse is not used.
        market.headroom_bps = 0;
        assert!(
            market
                .refresh_leg(&pair(), &mut leg, u64::MAX / 2)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_leg_without_price_headroom_is_not_sent() {
        let mut market = market().await;
        // the best size earns well under 100% of its escrow side, so full headroom rules it out.
        market.headroom_bps = 10_000;
        assert!(
            market
                .external_leg(&pair(), 3, true, 900, 800, &|_| Some(0), QUOTE_BLOCK)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn sizes_quoted_at_different_blocks_are_not_compared() {
        let market = market_at(|size| if size > 400 { 101 } else { 100 }).await;
        assert!(
            market
                .external_leg(&pair(), 3, true, 900, 800, &|_| Some(0), 101)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_quote_behind_the_chain_tip_is_not_used() {
        let market = market().await;
        assert!(
            market
                .external_leg(
                    &pair(),
                    3,
                    true,
                    900,
                    800,
                    &|_| Some(0),
                    QUOTE_BLOCK + MAX_QUOTE_AGE_BLOCKS
                )
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            market
                .external_leg(
                    &pair(),
                    3,
                    true,
                    900,
                    800,
                    &|_| Some(0),
                    QUOTE_BLOCK + MAX_QUOTE_AGE_BLOCKS + 1
                )
                .await
                .is_err()
        );
    }

    #[test]
    fn quotes_with_inconsistent_splits_are_rejected() {
        let quote = |total: &str, calculated: &[&str], hops: usize| QuoteResponse {
            block_number: 1,
            block_hash: "0x1".into(),
            estimated_gas_cost: 0,
            total_calculated: total.into(),
            splits: calculated
                .iter()
                .map(|amount| Split {
                    amount_specified: "1".into(),
                    amount_calculated: (*amount).into(),
                    route: (0..hops)
                        .map(|_| RouteNode {
                            pool_key: PoolKey {
                                token0: "0x1".into(),
                                token1: "0x2".into(),
                                fee: "0x0".into(),
                                tick_spacing: 1,
                                extension: "0x0".into(),
                            },
                            sqrt_ratio_limit: "0x1".into(),
                            skip_ahead: 0,
                        })
                        .collect(),
                })
                .collect(),
        };
        let validate_quote_buy = |response: &QuoteResponse| validate_quote(response, false);
        assert!(validate_quote_buy(&quote("-30", &["-10", "-20"], 1)).is_ok());
        // a sell is exact input: the total and every split calculate a positive output.
        assert!(validate_quote(&quote("30", &["10", "20"], 1), true).is_ok());
        assert!(validate_quote(&quote("-30", &["-10", "-20"], 1), true).is_err());
        assert!(validate_quote(&quote("30", &["40", "-10"], 1), true).is_err());
        // the splits must add up to the total, sign included.
        assert!(validate_quote_buy(&quote("-30", &["-10", "-21"], 1)).is_err());
        assert!(validate_quote_buy(&quote("30", &["-10", "-20"], 1)).is_err());
        assert!(validate_quote_buy(&quote("0", &["0"], 1)).is_err());
        // bounded shape.
        assert!(validate_quote_buy(&quote("-1", &[], 1)).is_err());
        assert!(validate_quote_buy(&quote("-1", &["-1"], 0)).is_err());
        assert!(validate_quote_buy(&quote("-1", &["-1"], MAX_HOPS + 1)).is_err());
        assert!(validate_quote_buy(&quote("-17", &["-1"; MAX_SPLITS + 1], 1)).is_err());
    }

    #[test]
    fn amounts_convert_through_one_or_two_rates() {
        let (strk, usdc, eth) = (Felt::from(1_u8), Felt::from(2_u8), Felt::from(3_u8));
        let rates = [
            // 0.5 usdc per strk, 3000 usdc per eth.
            Rate {
                base: strk,
                quote: usdc,
                midpoint: 5,
                scale: 10,
            },
            Rate {
                base: eth,
                quote: usdc,
                midpoint: 3_000,
                scale: 1,
            },
        ];
        let value = |from, to, amount| convert(&rates, from, to, amount, Round::Value);
        assert_eq!(value(strk, usdc, 100), Some(50));
        assert_eq!(value(usdc, strk, 50), Some(100));
        assert_eq!(value(eth, strk, 1), Some(6_000));
        assert_eq!(value(strk, strk, 7), Some(7));
        assert_eq!(value(Felt::from(9_u8), strk, 1), None);
        // a value rounds down and a cost up, so neither understates what the operator pays.
        assert_eq!(value(strk, usdc, 3), Some(1));
        assert_eq!(convert(&rates, strk, usdc, 3, Round::Cost), Some(2));
    }

    #[test]
    fn wide_products_match_the_contract_and_overflow_is_refused() {
        // the contract multiplies in 256 bits: a product past u128 still divides exactly.
        let big = u128::MAX / 3;
        assert_eq!(mul_div(big, 6, 3, false), Some(big * 2));
        assert_eq!(escrow_quote(big, 1 << 20, 1 << 20, true), Some(big));
        // a result past u128 is refused, not saturated.
        assert_eq!(mul_div(u128::MAX, 2, 1, false), None);
        assert_eq!(mul_div(1, 1, 0, false), None);
        // the escrow rounds as the contract does: down for a sell, up for a buy.
        assert_eq!(escrow_quote(3, 1, 2, true), Some(1));
        assert_eq!(escrow_quote(3, 1, 2, false), Some(2));
    }

    #[test]
    fn a_legs_gas_follows_its_route() {
        let gas = LegGas {
            base: 10,
            per_split: 100,
            per_hop: 1_000,
        };
        let split = |hops: usize| Split {
            amount_specified: "1".into(),
            amount_calculated: "1".into(),
            route: (0..hops)
                .map(|_| RouteNode {
                    pool_key: PoolKey {
                        token0: "0x1".into(),
                        token1: "0x2".into(),
                        fee: "0x0".into(),
                        tick_spacing: 1,
                        extension: "0x0".into(),
                    },
                    sqrt_ratio_limit: "0x1".into(),
                    skip_ahead: 0,
                })
                .collect(),
        };
        assert_eq!(gas.of(&[split(1)], 0), 10 + 100 + 1_000);
        assert_eq!(gas.of(&[split(1), split(2)], 0), 10 + 200 + 3_000);
        // ekubo's estimate wins when it is larger.
        assert_eq!(gas.of(&[split(1)], 50_000), 10 + 50_000);
    }
}

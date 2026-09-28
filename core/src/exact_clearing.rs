//! global clearing with a dual optimality certificate. the solver is exact over the rational
//! relaxation; the executed allocation is integral, so the certificate proves it optimal within a
//! protocol-fixed rounding tolerance. residual maximality separately rejects every skipped direct
//! cross and prevents a zero-fill allocation from hiding a consistent multi-market circulation.
//!
//! model: markets price their base asset in their quote asset at a committed midpoint
//! `midpoint / scale`. every eligible order `i` may fill `x_i` base units, `0 <= x_i <= u_i`
//! (the caller folds limit eligibility and funding into the capacity `u_i`). buyers pay
//! `ceil(x * midpoint / scale)` quote and receive `x` base; sellers give `x` base and receive
//! `floor(x * midpoint / scale)` quote. an allocation is feasible when, for every asset, inputs
//! are at least outputs; the surplus is protocol dust. the objective values every fill at the
//! committed weight of its market's base asset: `sum_i weight(base(i)) * x_i`.
//!
//! certificate: any asset prices `pi >= 0` bound every feasible allocation,
//!
//! ```text
//! objective(x) <= ub(pi) = sum_i u_i * max(0, c_i - a_i . pi) + sum_a pi_a * r_a
//! ```
//!
//! where `a_i` is order `i`'s exact (unrounded) net output vector and `r_a` counts the orders
//! whose rounded quote leg touches asset `a` (each rounding moves a flow by less than one unit).
//! proof: for feasible `x` the rounded net output `o(x) <= 0`, so with `pi >= 0`,
//! `c.x <= c.x - pi.o(x) = sum_i (c_i - a_i.pi) x_i + pi.(a x - o(x)) <= ub(pi)`.
//! the prover publishes `pi` on a fixed grid `p_a / denominator`; a verifier (and the close air)
//! recomputes `ub` and accepts when `ub - objective(x) <= tolerance(instance)`. the optimizer
//! finds `pi` from an exact rational bounded-variable simplex over the relaxation.

use std::cmp::Ordering;

use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::ProtocolError;

pub const MAX_CLEARING_ASSETS: usize = 8;
pub const MAX_CLEARING_ORDERS: usize = 1_024;
/// grid denominator of certified asset prices.
pub const CLEARING_PRICE_DENOMINATOR: u128 = 1 << 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearingMarket {
    pub base_asset: usize,
    pub quote_asset: usize,
    pub midpoint: u128,
    pub scale: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearingOrder {
    pub market: usize,
    pub sell: bool,
    /// maximum base fill after limit eligibility and funding; zero excludes the order.
    pub capacity: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearingInstance {
    /// objective value of one unit of each asset, in a common integer numeraire.
    pub asset_weights: Vec<u128>,
    pub markets: Vec<ClearingMarket>,
    pub orders: Vec<ClearingOrder>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearingCertificate {
    /// asset prices on the grid `price / 2^64`, the fixed clearing price denominator.
    pub asset_prices: Vec<u128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateReport {
    pub objective: BigUint,
    /// ceiling of the certified upper bound on every feasible allocation.
    pub upper_bound: BigUint,
    pub tolerance: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactClearing {
    pub fills: Vec<u128>,
    pub quote_amounts: Vec<u128>,
    /// per-asset inputs minus outputs, retained by the protocol.
    pub dust: Vec<u128>,
    pub certificate: ClearingCertificate,
    pub report: CertificateReport,
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidSettlementProof(message.into())
}

/// exact rational with a positive denominator.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Q {
    n: BigInt,
    d: BigInt,
}

impl Q {
    fn zero() -> Self {
        Self::int(BigInt::zero())
    }

    fn int(n: BigInt) -> Self {
        Self {
            n,
            d: BigInt::one(),
        }
    }

    fn from_u128(value: u128) -> Self {
        Self::int(BigInt::from(value))
    }

    fn new(n: BigInt, d: BigInt) -> Self {
        debug_assert!(!d.is_zero());
        let (n, d) = if d.is_negative() { (-n, -d) } else { (n, d) };
        let g = n.gcd(&d);
        if g.is_one() || g.is_zero() {
            Self { n, d }
        } else {
            Self {
                n: n / &g,
                d: d / g,
            }
        }
    }

    fn add(&self, other: &Q) -> Q {
        Q::new(&self.n * &other.d + &other.n * &self.d, &self.d * &other.d)
    }

    fn sub(&self, other: &Q) -> Q {
        Q::new(&self.n * &other.d - &other.n * &self.d, &self.d * &other.d)
    }

    fn mul(&self, other: &Q) -> Q {
        Q::new(&self.n * &other.n, &self.d * &other.d)
    }

    fn div(&self, other: &Q) -> Q {
        Q::new(&self.n * &other.d, &self.d * &other.n)
    }

    fn is_zero(&self) -> bool {
        self.n.is_zero()
    }

    fn is_positive(&self) -> bool {
        self.n.is_positive()
    }

    fn is_negative(&self) -> bool {
        self.n.is_negative()
    }

    fn floor(&self) -> BigInt {
        self.n.div_floor(&self.d)
    }
}

impl PartialOrd for Q {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Q {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.n * &other.d).cmp(&(&other.n * &self.d))
    }
}

fn validate(instance: &ClearingInstance) -> Result<(), ProtocolError> {
    let assets = instance.asset_weights.len();
    if assets == 0 || assets > MAX_CLEARING_ASSETS {
        return Err(invalid("clearing instance must have 1..=8 assets"));
    }
    if instance.orders.len() > MAX_CLEARING_ORDERS {
        return Err(invalid("clearing instance exceeds 1024 orders"));
    }
    for market in &instance.markets {
        if market.base_asset >= assets
            || market.quote_asset >= assets
            || market.base_asset == market.quote_asset
            || market.midpoint == 0
            || market.scale == 0
        {
            return Err(invalid("clearing market is malformed"));
        }
    }
    if instance
        .orders
        .iter()
        .any(|order| order.market >= instance.markets.len())
    {
        return Err(invalid("clearing order references an unknown market"));
    }
    for order in &instance.orders {
        let market = &instance.markets[order.market];
        let product = BigUint::from(order.capacity) * BigUint::from(market.midpoint);
        let scale = BigUint::from(market.scale);
        let quote = if order.sell {
            product / scale
        } else {
            product.div_ceil(&scale)
        };
        if quote > BigUint::from(u128::MAX) {
            return Err(invalid("clearing order quote exceeds u128"));
        }
    }
    Ok(())
}

/// exact net output vector entries of one base unit of order `i`: (asset, coefficient).
fn order_column(instance: &ClearingInstance, order: &ClearingOrder) -> [(usize, Q); 2] {
    let market = &instance.markets[order.market];
    let rate = Q::new(BigInt::from(market.midpoint), BigInt::from(market.scale));
    let zero = Q::zero();
    if order.sell {
        [
            (market.base_asset, zero.sub(&Q::from_u128(1))),
            (market.quote_asset, rate),
        ]
    } else {
        [
            (market.base_asset, Q::from_u128(1)),
            (market.quote_asset, zero.sub(&rate)),
        ]
    }
}

fn order_weight(instance: &ClearingInstance, order: &ClearingOrder) -> Q {
    Q::from_u128(instance.asset_weights[instance.markets[order.market].base_asset])
}

/// rounded quote leg of a fill: buyers pay the ceiling, sellers receive the floor.
pub fn clearing_quote_amount(market: &ClearingMarket, sell: bool, fill: u128) -> u128 {
    let product = BigUint::from(fill) * BigUint::from(market.midpoint);
    let scale = BigUint::from(market.scale);
    let quote = if sell {
        product / scale
    } else {
        product.div_ceil(&scale)
    };
    quote
        .to_u128()
        .expect("validated clearing capacities have u128 quote amounts")
}

/// per-asset (inputs, outputs) of an integer allocation under the rounding rules.
pub fn clearing_flows(instance: &ClearingInstance, fills: &[u128]) -> (Vec<BigUint>, Vec<BigUint>) {
    let assets = instance.asset_weights.len();
    let mut inputs = vec![BigUint::zero(); assets];
    let mut outputs = vec![BigUint::zero(); assets];
    for (order, fill) in instance.orders.iter().zip(fills) {
        let market = &instance.markets[order.market];
        let quote = BigUint::from(clearing_quote_amount(market, order.sell, *fill));
        let base = BigUint::from(*fill);
        if order.sell {
            inputs[market.base_asset] += base;
            outputs[market.quote_asset] += quote;
        } else {
            inputs[market.quote_asset] += quote;
            outputs[market.base_asset] += base;
        }
    }
    (inputs, outputs)
}

pub fn clearing_objective(instance: &ClearingInstance, fills: &[u128]) -> BigUint {
    instance
        .orders
        .iter()
        .zip(fills)
        .map(|(order, fill)| {
            BigUint::from(instance.asset_weights[instance.markets[order.market].base_asset])
                * BigUint::from(*fill)
        })
        .sum()
}

/// multiplier of the protocol-fixed optimality tolerance: at most this many units of integer
/// rounding per participating order in each of its two assets, valued at their weights.
pub const CLEARING_TOLERANCE_UNITS: u128 = MAX_CLEARING_ASSETS as u128 + 2;
/// canonical asset weights lie between one and this bound; the most valuable asset of every
/// component of the market graph carries the bound less one. the range must span the
/// value of one atom of the cheapest asset against the dearest: an 18-decimal token worth a few
/// cents against a 6-decimal dollar is already a ratio near 2^45, and a clamped weight misprices
/// the certificate's rounding slack beyond the tolerance. `weight * denominator` fits 124 bits,
/// so the certificate arithmetic stays within u128.
pub const MAX_CLEARING_WEIGHT: u128 = 1 << 60;
/// numerators and denominators of canonical reference values stay below this bound, so the
/// cross products compared by the close air and the settlement statement fit u128.
pub const MAX_REFERENCE_COMPONENT: u128 = u64::MAX as u128;

/// a market as the canonical weight derivation sees it: the attested midpoint prices one base
/// unit at `midpoint / scale` quote units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightMarket {
    pub base_asset: usize,
    pub quote_asset: usize,
    pub midpoint: u128,
    pub scale: u128,
}

/// the canonical clearing weights of a close together with the witness the close air checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalWeights {
    /// reduced reference value `numerator / denominator` of each asset, relative to the root of
    /// its component.
    pub values: Vec<(u128, u128)>,
    /// the lowest asset index of each asset's component (its root).
    pub roots: Vec<usize>,
    /// breadth-first distance of each asset from its root.
    pub depths: Vec<u32>,
    /// the lowest-index market that links each non-root asset to an asset one level closer to
    /// the root.
    pub parent_markets: Vec<Option<usize>>,
    /// the lowest-index most valuable asset of each asset's component.
    pub maxima: Vec<usize>,
    pub weights: Vec<u128>,
}

fn reduce(numerator: BigUint, denominator: BigUint) -> (BigUint, BigUint) {
    let divisor = numerator.gcd(&denominator);
    (numerator / &divisor, denominator / divisor)
}

/// derives the auction objective from authenticated direct asset/usdc observations. every market
/// still executes at its own direct midpoint; these weights only compare matched value.
pub fn usdc_clearing_weights(
    asset_ids: &[starknet_crypto::Felt],
    usdc: starknet_crypto::Felt,
    markets: &[WeightMarket],
) -> Result<CanonicalWeights, ProtocolError> {
    let numeraire = asset_ids
        .iter()
        .position(|asset| *asset == usdc)
        .ok_or_else(|| invalid("the objective batch has no USDC asset"))?;
    let asset_count = asset_ids.len();
    if asset_count == 0 || asset_count > MAX_CLEARING_ASSETS {
        return Err(invalid("USDC weights need 1..=8 assets"));
    }
    let mut values = vec![None; asset_count];
    let mut parents = vec![None; asset_count];
    values[numeraire] = Some((BigUint::one(), BigUint::one()));
    for asset in 0..asset_count {
        if asset == numeraire {
            continue;
        }
        for (index, market) in markets.iter().enumerate() {
            let value = if market.base_asset == asset && market.quote_asset == numeraire {
                Some((BigUint::from(market.midpoint), BigUint::from(market.scale)))
            } else if market.quote_asset == asset && market.base_asset == numeraire {
                Some((BigUint::from(market.scale), BigUint::from(market.midpoint)))
            } else {
                None
            };
            if let Some((numerator, denominator)) = value {
                if numerator.is_zero() || denominator.is_zero() {
                    return Err(invalid("the direct USDC observation is malformed"));
                }
                values[asset] = Some(reduce(numerator, denominator));
                parents[asset] = Some(index);
                break;
            }
        }
        if values[asset].is_none() {
            return Err(invalid("an asset has no direct USDC observation"));
        }
    }
    let values = values
        .into_iter()
        .map(|value| {
            let (numerator, denominator) = value.expect("every objective asset has a value");
            match (numerator.to_u128(), denominator.to_u128()) {
                (Some(numerator), Some(denominator))
                    if numerator <= MAX_REFERENCE_COMPONENT
                        && denominator <= MAX_REFERENCE_COMPONENT =>
                {
                    Ok((numerator, denominator))
                }
                _ => Err(invalid("USDC reference value exceeds 64 bits")),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let greater = |left: usize, right: usize| {
        BigUint::from(values[left].0) * BigUint::from(values[right].1)
            > BigUint::from(values[right].0) * BigUint::from(values[left].1)
    };
    let maximum = (0..asset_count)
        .max_by(|left, right| {
            if greater(*left, *right) {
                Ordering::Greater
            } else if greater(*right, *left) {
                Ordering::Less
            } else {
                right.cmp(left)
            }
        })
        .expect("there is at least one asset");
    let weights = (0..asset_count)
        .map(|asset| {
            let (numerator, denominator) = values[asset];
            let (max_numerator, max_denominator) = values[maximum];
            ((BigUint::from(MAX_CLEARING_WEIGHT - 1)
                * BigUint::from(numerator)
                * BigUint::from(max_denominator))
                / (BigUint::from(denominator) * BigUint::from(max_numerator)))
            .to_u128()
            .expect("weights stay below the maximum")
            .max(1)
        })
        .collect();
    Ok(CanonicalWeights {
        values,
        roots: vec![numeraire; asset_count],
        depths: (0..asset_count)
            .map(|asset| u32::from(asset != numeraire))
            .collect(),
        parent_markets: parents,
        maxima: vec![maximum; asset_count],
        weights,
    })
}

/// the numeric tolerance covers only certificate-grid and quote-rounding error. it cannot hide a
/// crossing because residual maximality is checked independently below.
pub fn clearing_tolerance(instance: &ClearingInstance) -> BigUint {
    let mut units = BigUint::zero();
    let mut market_capacity = vec![BigUint::zero(); instance.markets.len()];
    for order in instance.orders.iter().filter(|order| order.capacity > 0) {
        units += order_tolerance_weight(instance, order);
        market_capacity[order.market] += BigUint::from(order.capacity);
    }
    for (market, capacity) in instance.markets.iter().zip(market_capacity) {
        units += market_precision_allowance(market, &capacity);
    }
    units * BigUint::from(CLEARING_TOLERANCE_UNITS)
}

pub fn order_tolerance_weight(instance: &ClearingInstance, order: &ClearingOrder) -> BigUint {
    let market = &instance.markets[order.market];
    BigUint::from(instance.asset_weights[market.base_asset])
        + BigUint::from(instance.asset_weights[market.quote_asset])
        + BigUint::one()
}

pub fn market_precision_allowance(market: &ClearingMarket, capacity: &BigUint) -> BigUint {
    let scale = BigUint::from(market.scale);
    let spread = &scale * 2_u32 + BigUint::from(market.midpoint);
    (capacity * spread).div_ceil(&(scale * BigUint::from(CLEARING_PRICE_DENOMINATOR)))
}

fn verify_residual_maximality(
    instance: &ClearingInstance,
    fills: &[u128],
) -> Result<(), ProtocolError> {
    let mut residual_sides = vec![[false; 2]; instance.markets.len()];
    let mut filled_sides = vec![[false; 2]; instance.markets.len()];
    for (order, fill) in instance.orders.iter().zip(fills) {
        if *fill > 0 {
            filled_sides[order.market][usize::from(order.sell)] = true;
        }
        if *fill >= order.capacity {
            continue;
        }
        residual_sides[order.market][usize::from(order.sell)] = true;
    }
    if residual_sides
        .iter()
        .zip(filled_sides)
        .any(|(residual, filled)| residual[0] && residual[1] && !filled[0] && !filled[1])
    {
        return Err(invalid("clearing leaves a direct cross unfilled"));
    }
    Ok(())
}

fn u128_or(value: BigUint, message: &str) -> Result<u128, ProtocolError> {
    value.to_u128().ok_or_else(|| invalid(message))
}

/// the certified upper bound exactly as the close air computes it, in u128 arithmetic with
/// every rounding taken upwards (so it is never below the exact bound `ub(pi)`):
///
/// ```text
/// m_buy(m)  = ceil(midpoint * p_quote / scale)      m_sell(m) = floor(midpoint * p_quote / scale)
/// r_i       = max(0, w_base * 2^64 + m_buy - p_base)          for a buy
///           = max(0, w_base * 2^64 + p_base - m_sell)         for a sell
/// ub        = sum_i ceil(u_i * r_i / 2^64) + sum_a ceil(p_a * r_a / 2^64)
/// ```
pub fn certified_upper_bound(
    instance: &ClearingInstance,
    certificate: &ClearingCertificate,
) -> Result<BigUint, ProtocolError> {
    let denominator = BigUint::from(CLEARING_PRICE_DENOMINATOR);
    let prices = &certificate.asset_prices;
    // each term fits u128, but with weights up to 2^60 their sum does not; the statement sums
    // them in a felt.
    let mut bound = BigUint::zero();
    for order in instance.orders.iter().filter(|order| order.capacity > 0) {
        let market = &instance.markets[order.market];
        let weight = instance.asset_weights[market.base_asset];
        let scaled_weight = weight
            .checked_mul(CLEARING_PRICE_DENOMINATOR)
            .ok_or_else(|| invalid("clearing weight exceeds its bound"))?;
        let quote_value =
            BigUint::from(market.midpoint) * BigUint::from(prices[market.quote_asset]);
        let scale = BigUint::from(market.scale);
        let base_price = prices[market.base_asset];
        let (positive, negative) = if order.sell {
            let floor = u128_or(quote_value / scale, "clearing price term overflows")?;
            (
                scaled_weight
                    .checked_add(base_price)
                    .ok_or_else(|| invalid("clearing reduced cost overflows"))?,
                floor,
            )
        } else {
            let ceil = u128_or(
                quote_value.div_ceil(&scale),
                "clearing price term overflows",
            )?;
            (
                scaled_weight
                    .checked_add(ceil)
                    .ok_or_else(|| invalid("clearing reduced cost overflows"))?,
                base_price,
            )
        };
        let reduced = positive.saturating_sub(negative);
        bound += (BigUint::from(order.capacity) * BigUint::from(reduced)).div_ceil(&denominator);
    }
    for (price, count) in prices.iter().zip(rounding_slack(instance)) {
        bound += (BigUint::from(*price) * BigUint::from(count)).div_ceil(&denominator);
    }
    Ok(bound)
}

/// checks feasibility of `fills` and the certificate's bound, returning the certified gap data.
pub fn verify_clearing_certificate(
    instance: &ClearingInstance,
    fills: &[u128],
    certificate: &ClearingCertificate,
) -> Result<CertificateReport, ProtocolError> {
    validate(instance)?;
    if fills.len() != instance.orders.len()
        || certificate.asset_prices.len() != instance.asset_weights.len()
    {
        return Err(invalid("clearing certificate shape mismatch"));
    }
    for (order, fill) in instance.orders.iter().zip(fills) {
        if *fill > order.capacity {
            return Err(invalid("clearing fill exceeds order capacity"));
        }
    }
    let (inputs, outputs) = clearing_flows(instance, fills);
    if inputs
        .iter()
        .zip(&outputs)
        .any(|(input, output)| input < output)
    {
        return Err(invalid("clearing allocation does not conserve assets"));
    }
    verify_residual_maximality(instance, fills)?;
    if instance
        .asset_weights
        .iter()
        .any(|weight| *weight >= MAX_CLEARING_WEIGHT)
    {
        return Err(invalid("clearing weight exceeds its bound"));
    }
    let upper_bound = certified_upper_bound(instance, certificate)?;
    let objective = clearing_objective(instance, fills);
    let tolerance = clearing_tolerance(instance);
    if upper_bound > &objective + &tolerance {
        return Err(invalid("clearing allocation is not certified optimal"));
    }
    Ok(CertificateReport {
        objective,
        upper_bound,
        tolerance,
    })
}

/// per asset, the number of participating orders whose rounded quote leg touches it; each
/// rounding moves that asset's net flow by less than one unit.
fn rounding_slack(instance: &ClearingInstance) -> Vec<u64> {
    let mut slack = vec![0_u64; instance.asset_weights.len()];
    for order in instance.orders.iter().filter(|order| order.capacity > 0) {
        slack[instance.markets[order.market].quote_asset] += 1;
    }
    slack
}

/// the exact rational bound `ub(pi)`; the test suite checks its soundness for arbitrary prices.
#[cfg(test)]
fn certificate_upper_bound(instance: &ClearingInstance, prices: &[Q]) -> Q {
    let mut bound = Q::zero();
    for order in &instance.orders {
        if order.capacity == 0 {
            continue;
        }
        let mut reduced = order_weight(instance, order);
        for (asset, coefficient) in order_column(instance, order) {
            reduced = reduced.sub(&coefficient.mul(&prices[asset]));
        }
        if reduced.is_positive() {
            bound = bound.add(&reduced.mul(&Q::from_u128(order.capacity)));
        }
    }
    for (price, count) in prices.iter().zip(rounding_slack(instance)) {
        bound = bound.add(&price.mul(&Q::int(BigInt::from(count))));
    }
    bound
}

/// exact bounded-variable primal simplex over `max c.x, a x <= r, 0 <= x <= u` with bland's
/// rule, where `r` is the per-asset rounding slack. by strong duality its optimal duals
/// `pi >= 0` minimize `ub(pi)`, so they give the tightest certificate.
struct Simplex {
    rows: usize,
    columns: Vec<[(usize, Q); 2]>,
    costs: Vec<Q>,
    uppers: Vec<Q>,
    /// basis inverse, `rows x rows`.
    inverse: Vec<Vec<Q>>,
    /// basic variable per row: `< n` is an order, `n + a` is asset `a`'s slack.
    basis: Vec<usize>,
    /// values of basic variables.
    values: Vec<Q>,
    at_upper: Vec<bool>,
}

impl Simplex {
    fn new(instance: &ClearingInstance, rhs: Vec<Q>) -> Self {
        let rows = instance.asset_weights.len();
        let columns = instance
            .orders
            .iter()
            .map(|order| order_column(instance, order))
            .collect::<Vec<_>>();
        let costs = instance
            .orders
            .iter()
            .map(|order| order_weight(instance, order))
            .collect::<Vec<_>>();
        let uppers = instance
            .orders
            .iter()
            .map(|order| Q::from_u128(order.capacity))
            .collect::<Vec<_>>();
        let inverse = (0..rows)
            .map(|row| {
                (0..rows)
                    .map(|col| {
                        if row == col {
                            Q::from_u128(1)
                        } else {
                            Q::zero()
                        }
                    })
                    .collect()
            })
            .collect();
        let n = columns.len();
        Self {
            rows,
            at_upper: vec![false; n + rows],
            columns,
            costs,
            uppers,
            inverse,
            basis: (0..rows).map(|row| n + row).collect(),
            values: rhs,
        }
    }

    fn n(&self) -> usize {
        self.columns.len()
    }

    fn cost(&self, var: usize) -> Q {
        if var < self.n() {
            self.costs[var].clone()
        } else {
            Q::zero()
        }
    }

    fn upper(&self, var: usize) -> Option<&Q> {
        (var < self.n()).then(|| &self.uppers[var])
    }

    /// duals `y = c_b^t b^-1`.
    fn duals(&self) -> Vec<Q> {
        (0..self.rows)
            .map(|col| {
                self.basis
                    .iter()
                    .enumerate()
                    .fold(Q::zero(), |acc, (row, var)| {
                        acc.add(&self.cost(*var).mul(&self.inverse[row][col]))
                    })
            })
            .collect()
    }

    /// `b^-1 a_var`.
    fn column(&self, var: usize) -> Vec<Q> {
        (0..self.rows)
            .map(|row| {
                if var < self.n() {
                    self.columns[var]
                        .iter()
                        .fold(Q::zero(), |acc, (asset, coefficient)| {
                            acc.add(&self.inverse[row][*asset].mul(coefficient))
                        })
                } else {
                    self.inverse[row][var - self.n()].clone()
                }
            })
            .collect()
    }

    fn reduced_cost(&self, var: usize, duals: &[Q]) -> Q {
        if var < self.n() {
            self.columns[var]
                .iter()
                .fold(self.costs[var].clone(), |acc, (asset, coefficient)| {
                    acc.sub(&coefficient.mul(&duals[*asset]))
                })
        } else {
            Q::zero().sub(&duals[var - self.n()])
        }
    }

    fn solve(&mut self) {
        let total = self.n() + self.rows;
        loop {
            let duals = self.duals();
            let basic = {
                let mut basic = vec![false; total];
                self.basis.iter().for_each(|var| basic[*var] = true);
                basic
            };
            // bland: the lowest-index improving nonbasic variable enters.
            let entering = (0..total).find(|var| {
                if basic[*var] {
                    return false;
                }
                let reduced = self.reduced_cost(*var, &duals);
                if self.at_upper[*var] {
                    reduced.is_negative()
                } else {
                    reduced.is_positive() && self.upper(*var).is_none_or(|upper| !upper.is_zero())
                }
            });
            let Some(entering) = entering else { return };
            let increasing = !self.at_upper[entering];
            let direction = self.column(entering);
            // step t along the entering variable; basic values move by -sign * direction * t.
            let mut best: Option<(Q, Option<usize>)> =
                self.upper(entering).map(|upper| (upper.clone(), None));
            for (row, towards) in direction.iter().enumerate().take(self.rows) {
                let rate = if increasing {
                    towards.clone()
                } else {
                    Q::zero().sub(towards)
                };
                if rate.is_zero() {
                    continue;
                }
                let var = self.basis[row];
                let limit = if rate.is_positive() {
                    // the basic variable decreases towards zero.
                    self.values[row].div(&rate)
                } else {
                    match self.upper(var) {
                        Some(upper) => upper.sub(&self.values[row]).div(&Q::zero().sub(&rate)),
                        None => continue,
                    }
                };
                let replace = match &best {
                    None => true,
                    Some((current, current_row)) => match limit.cmp(current) {
                        Ordering::Less => true,
                        Ordering::Equal => match current_row {
                            None => false,
                            Some(current_row) => var < self.basis[*current_row],
                        },
                        Ordering::Greater => false,
                    },
                };
                if replace {
                    best = Some((limit, Some(row)));
                }
            }
            let (step, leaving_row) = best.expect("capacities bound every order variable");
            for (value, towards) in self.values.iter_mut().zip(&direction).take(self.rows) {
                let delta = towards.mul(&step);
                *value = if increasing {
                    value.sub(&delta)
                } else {
                    value.add(&delta)
                };
            }
            match leaving_row {
                None => {
                    self.at_upper[entering] = !self.at_upper[entering];
                }
                Some(row) => {
                    let leaving = self.basis[row];
                    let entering_value = if increasing {
                        if self.at_upper[entering] {
                            unreachable!("an increasing variable starts at its lower bound")
                        }
                        step.clone()
                    } else {
                        self.upper(entering)
                            .expect("decreasing from an upper bound")
                            .sub(&step)
                    };
                    // the leaving variable lands on the bound it reached.
                    self.at_upper[leaving] = self
                        .upper(leaving)
                        .is_some_and(|upper| self.values[row] == *upper);
                    let pivot = direction[row].clone();
                    let pivot_row = self.inverse[row]
                        .iter()
                        .map(|value| value.div(&pivot))
                        .collect::<Vec<_>>();
                    for (other, factor) in direction.iter().enumerate().take(self.rows) {
                        if other == row || factor.is_zero() {
                            continue;
                        }
                        for (value, pivot) in self.inverse[other]
                            .iter_mut()
                            .zip(&pivot_row)
                            .take(self.rows)
                        {
                            *value = value.sub(&factor.mul(pivot));
                        }
                    }
                    self.inverse[row] = pivot_row;
                    self.basis[row] = entering;
                    self.values[row] = entering_value;
                    self.at_upper[entering] = false;
                }
            }
        }
    }

    fn solution(&self) -> Vec<Q> {
        let mut values = (0..self.n())
            .map(|var| {
                if self.at_upper[var] {
                    self.uppers[var].clone()
                } else {
                    Q::zero()
                }
            })
            .collect::<Vec<_>>();
        for (row, var) in self.basis.iter().enumerate() {
            if *var < self.n() {
                values[*var] = self.values[row].clone();
            }
        }
        values
    }
}

/// rounds the relaxed optimum down to integers, then trims fills until every asset's rounded
/// inputs cover its outputs. trimming only lowers fills, so it terminates.
/// the fill that lowers an order's output of its produced asset by at least `deficit` (or to
/// zero), and the resulting drop of its input.
fn trim_for_deficit(
    market: &ClearingMarket,
    sell: bool,
    fill: u128,
    deficit: &BigUint,
) -> (u128, BigUint) {
    let current = BigUint::from(fill);
    let midpoint = BigUint::from(market.midpoint);
    let scale = BigUint::from(market.scale);
    let trimmed = if sell {
        // the largest fill whose floored quote output is at least `deficit` lower.
        let output = (&current * &midpoint) / &scale;
        if &output < deficit {
            BigUint::zero()
        } else {
            let allowed = output - deficit;
            ((allowed + BigUint::one()) * &scale - BigUint::one()) / &midpoint
        }
    } else if &current > deficit {
        &current - deficit
    } else {
        BigUint::zero()
    };
    let trimmed = trimmed.min(current.clone());
    let input_drop = if sell {
        &current - &trimmed
    } else {
        (&current * &midpoint).div_ceil(&scale) - (&trimmed * &midpoint).div_ceil(&scale)
    };
    (trimmed.to_u128().expect("trimmed fill fits"), input_drop)
}

/// the most fractional fills whose floor-or-ceil choices are enumerated; a vertex of the relaxation
/// has at most one fractional fill per asset, so this covers every protocol close.
const MAX_ENUMERATED_FRACTIONAL_FILLS: usize = 10;
/// how many of the least-deficit roundings the repair is tried from when none is feasible.
const REPAIRED_ROUNDING_CANDIDATES: usize = 16;

/// rounds a relaxed allocation to integers. a vertex of the relaxation has at most one
/// fractional fill per asset, and flooring all of them can leave a deficit worth more than any
/// rounding dust can absorb (a unit of a valuable base asset), which trimming alone then passes
/// around a trading cycle until the cycle is empty. so every floor-or-ceil choice of the
/// fractional fills is tried: the feasible one of largest objective wins; if none is feasible,
/// the repair runs from the least-deficit choices and the best repaired allocation wins. ties go
/// to the first choice in enumeration order, which is canonical.
fn round_to_feasible(instance: &ClearingInstance, relaxed: &[Q]) -> Option<Vec<u128>> {
    let floors = relaxed
        .iter()
        .zip(&instance.orders)
        .map(|(value, order)| value.floor().to_u128().unwrap_or(0).min(order.capacity))
        .collect::<Vec<_>>();
    let fractional = relaxed
        .iter()
        .zip(&instance.orders)
        .enumerate()
        .filter(|(index, (value, order))| {
            Q::from_u128(floors[*index]) != **value && floors[*index] < order.capacity
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if fractional.is_empty() || fractional.len() > MAX_ENUMERATED_FRACTIONAL_FILLS {
        return repair_deficits(instance, floors);
    }
    let weights = instance
        .asset_weights
        .iter()
        .map(|weight| BigInt::from(*weight))
        .collect::<Vec<_>>();
    let mut best: Option<(BigUint, Vec<u128>)> = None;
    let mut infeasible = Vec::new();
    for mask in 0_u32..(1 << fractional.len()) {
        let mut fills = floors.clone();
        for (bit, index) in fractional.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                fills[*index] += 1;
            }
        }
        let (inputs, outputs) = clearing_flows(instance, &fills);
        let deficit_value = inputs
            .iter()
            .zip(&outputs)
            .zip(&weights)
            .map(|((input, output), weight)| {
                let net = BigInt::from(output.clone()) - BigInt::from(input.clone());
                if net.is_positive() {
                    net * weight
                } else {
                    BigInt::zero()
                }
            })
            .sum::<BigInt>();
        if deficit_value.is_zero() {
            let objective = clearing_objective(instance, &fills);
            if best.as_ref().is_none_or(|(value, _)| objective > *value) {
                best = Some((objective, fills));
            }
        } else {
            infeasible.push((deficit_value, mask, fills));
        }
    }
    if let Some((_, fills)) = best {
        return Some(fills);
    }
    infeasible.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    infeasible
        .into_iter()
        .take(REPAIRED_ROUNDING_CANDIDATES)
        .filter_map(|(_, _, fills)| repair_deficits(instance, fills))
        .map(|fills| (clearing_objective(instance, &fills), fills))
        .fold(None::<(BigUint, Vec<u128>)>, |best, candidate| match best {
            Some(best) if best.0 >= candidate.0 => Some(best),
            _ => Some(candidate),
        })
        .map(|(_, fills)| fills)
}

/// repairs the small deficits a rounding leaves. integer fills always leave non-negative
/// rounding surplus in total value (base legs are exact, quote legs round in the protocol's
/// favour), so every deficit can be moved onto surplus. each step takes the asset with the
/// largest deficit value and trims, by exactly the amount needed, the producer whose trim leaves
/// the least total deficit value (valued at the asset weights); ties go to the lowest index.
fn repair_deficits(instance: &ClearingInstance, mut fills: Vec<u128>) -> Option<Vec<u128>> {
    let weights = instance
        .asset_weights
        .iter()
        .map(|weight| BigInt::from(*weight))
        .collect::<Vec<_>>();
    let deficit_value = |net: &BigInt, asset: usize| {
        if net.is_positive() {
            net * &weights[asset]
        } else {
            BigInt::zero()
        }
    };
    let steps = 64 * (fills.len() + instance.asset_weights.len());
    for _ in 0..steps {
        let (inputs, outputs) = clearing_flows(instance, &fills);
        let net = inputs
            .iter()
            .zip(&outputs)
            .map(|(input, output)| BigInt::from(output.clone()) - BigInt::from(input.clone()))
            .collect::<Vec<_>>();
        let Some(asset) = (0..net.len())
            .filter(|asset| net[*asset].is_positive())
            .max_by(|left, right| {
                deficit_value(&net[*left], *left)
                    .cmp(&deficit_value(&net[*right], *right))
                    .then(right.cmp(left))
            })
        else {
            return Some(fills);
        };
        let deficit = net[asset].to_biguint().expect("positive deficit");
        let mut best: Option<(BigInt, usize, u128)> = None;
        for (index, (order, &fill)) in instance.orders.iter().zip(fills.iter()).enumerate() {
            let market = &instance.markets[order.market];
            let (produced, consumed) = if order.sell {
                (market.quote_asset, market.base_asset)
            } else {
                (market.base_asset, market.quote_asset)
            };
            if fill == 0 || produced != asset {
                continue;
            }
            let (trimmed, input_drop) = trim_for_deficit(market, order.sell, fill, &deficit);
            let output_drop = BigInt::from(clearing_quote_or_base(market, order.sell, fill))
                - BigInt::from(clearing_quote_or_base(market, order.sell, trimmed));
            let new_asset = &net[asset] - output_drop;
            let new_consumed = &net[consumed] + BigInt::from(input_drop);
            let change = deficit_value(&new_asset, asset) - deficit_value(&net[asset], asset)
                + deficit_value(&new_consumed, consumed)
                - deficit_value(&net[consumed], consumed);
            if best.as_ref().is_none_or(|(value, _, _)| change < *value) {
                best = Some((change, index, trimmed));
            }
        }
        let Some((_, index, trimmed)) = best else {
            break;
        };
        fills[index] = trimmed;
    }
    // the repair did not settle.
    None
}

/// an lp dive: while the balanced relaxation's vertex cannot be rounded, caps its first
/// fractional fill at its floor and re-solves. each dive tightens one bound, so it ends; an
/// integral vertex of the balanced relaxation is feasible as it stands, because base legs are
/// exact and every rounded quote leg favours the pool.
fn dive_to_integral(instance: &ClearingInstance, mut relaxed: Vec<Q>) -> Vec<u128> {
    let mut capped = instance.clone();
    let rows = vec![Q::zero(); instance.asset_weights.len()];
    loop {
        if let Some(fills) = round_to_feasible(&capped, &relaxed) {
            return fills;
        }
        let fractional = relaxed
            .iter()
            .position(|value| Q::from_u128(value.floor().to_u128().unwrap_or(0)) != *value);
        let Some(index) = fractional else {
            // unreachable for a balanced vertex; the empty allocation is always feasible.
            return vec![0; instance.orders.len()];
        };
        capped.orders[index].capacity = relaxed[index].floor().to_u128().unwrap_or(0);
        let mut lp = Simplex::new(&capped, rows.clone());
        lp.solve();
        relaxed = lp.solution();
    }
}

/// the amount of an order's produced asset for a fill: quote output for a sell, base for a buy.
fn clearing_quote_or_base(market: &ClearingMarket, sell: bool, fill: u128) -> u128 {
    if sell {
        clearing_quote_amount(market, true, fill)
    } else {
        fill
    }
}

/// grid prices `floor(pi * denominator)`; any non-negative prices form a valid certificate.
fn grid_prices(duals: &[Q]) -> Vec<u128> {
    let denominator = Q::from_u128(CLEARING_PRICE_DENOMINATOR);
    duals
        .iter()
        .map(|dual| {
            if dual.is_negative() {
                0
            } else {
                dual.mul(&denominator)
                    .floor()
                    .to_u128()
                    .unwrap_or(u128::MAX)
            }
        })
        .collect()
}

/// solves the global clearing exactly and returns the executed allocation with its certificate.
pub fn solve_exact_clearing(instance: &ClearingInstance) -> Result<ExactClearing, ProtocolError> {
    validate(instance)?;
    // the certificate's prices come from the relaxation that grants every asset its rounding
    // slack, so they price that slack sensibly; the allocation comes from the exactly balanced
    // relaxation, whose flows round down without systematic deficits.
    let slack = rounding_slack(instance)
        .into_iter()
        .map(|count| Q::int(BigInt::from(count)))
        .collect::<Vec<_>>();
    let mut priced = Simplex::new(instance, slack);
    priced.solve();
    let mut balanced = Simplex::new(instance, vec![Q::zero(); instance.asset_weights.len()]);
    balanced.solve();
    let certificate = ClearingCertificate {
        asset_prices: grid_prices(&priced.duals()),
    };
    // if the balanced relaxation's rounding cannot be repaired, retry from the slack relaxation's
    // allocation, then dive: the dive always ends at a feasible integral allocation.
    let fills = round_to_feasible(instance, &balanced.solution())
        .or_else(|| round_to_feasible(instance, &priced.solution()))
        .unwrap_or_else(|| dive_to_integral(instance, balanced.solution()));
    let report = verify_clearing_certificate(instance, &fills, &certificate)?;
    let quote_amounts = instance
        .orders
        .iter()
        .zip(&fills)
        .map(|(order, fill)| {
            clearing_quote_amount(&instance.markets[order.market], order.sell, *fill)
        })
        .collect();
    let (inputs, outputs) = clearing_flows(instance, &fills);
    let dust = inputs
        .iter()
        .zip(&outputs)
        .map(|(input, output)| (input - output).to_u128().unwrap_or(u128::MAX))
        .collect();
    Ok(ExactClearing {
        fills,
        quote_amounts,
        dust,
        certificate,
        report,
    })
}

/// solves `instance` in a canonical order fixed by caller-supplied asset and order keys (their
/// commitments), so every party clearing the same orders obtains the same fills and prices in
/// whatever order it lists them. ties between otherwise identical orders are broken by key.
pub fn solve_canonical_clearing(
    instance: &ClearingInstance,
    asset_keys: &[[u8; 32]],
    order_keys: &[[u8; 32]],
) -> Result<ExactClearing, ProtocolError> {
    validate(instance)?;
    let assets = instance.asset_weights.len();
    if asset_keys.len() != assets || order_keys.len() != instance.orders.len() {
        return Err(invalid("clearing keys do not match the instance"));
    }
    let mut asset_order = (0..assets).collect::<Vec<_>>();
    asset_order.sort_by_key(|index| asset_keys[*index]);
    if asset_order
        .windows(2)
        .any(|pair| asset_keys[pair[0]] == asset_keys[pair[1]])
    {
        return Err(invalid("clearing asset keys are not unique"));
    }
    let mut asset_rank = vec![0; assets];
    for (rank, index) in asset_order.iter().enumerate() {
        asset_rank[*index] = rank;
    }
    let mut market_order = (0..instance.markets.len()).collect::<Vec<_>>();
    market_order.sort_by_key(|index| {
        let market = &instance.markets[*index];
        (
            asset_rank[market.base_asset],
            asset_rank[market.quote_asset],
            market.midpoint,
            market.scale,
        )
    });
    let mut market_rank = vec![0; instance.markets.len()];
    for (rank, index) in market_order.iter().enumerate() {
        market_rank[*index] = rank;
    }
    let mut order_order = (0..instance.orders.len()).collect::<Vec<_>>();
    order_order.sort_by_key(|index| {
        let order = &instance.orders[*index];
        (market_rank[order.market], order.sell, order_keys[*index])
    });
    if order_order
        .windows(2)
        .any(|pair| order_keys[pair[0]] == order_keys[pair[1]])
    {
        return Err(invalid("clearing order keys are not unique"));
    }
    let canonical = ClearingInstance {
        asset_weights: asset_order
            .iter()
            .map(|index| instance.asset_weights[*index])
            .collect(),
        markets: market_order
            .iter()
            .map(|index| {
                let market = &instance.markets[*index];
                ClearingMarket {
                    base_asset: asset_rank[market.base_asset],
                    quote_asset: asset_rank[market.quote_asset],
                    midpoint: market.midpoint,
                    scale: market.scale,
                }
            })
            .collect(),
        orders: order_order
            .iter()
            .map(|index| {
                let order = &instance.orders[*index];
                ClearingOrder {
                    market: market_rank[order.market],
                    sell: order.sell,
                    capacity: order.capacity,
                }
            })
            .collect(),
    };
    let solved = solve_exact_clearing(&canonical)?;
    let mut fills = vec![0; instance.orders.len()];
    let mut quote_amounts = vec![0; instance.orders.len()];
    for (position, index) in order_order.iter().enumerate() {
        fills[*index] = solved.fills[position];
        quote_amounts[*index] = solved.quote_amounts[position];
    }
    let dust = (0..assets)
        .map(|index| solved.dust[asset_rank[index]])
        .collect();
    let asset_prices = (0..assets)
        .map(|index| solved.certificate.asset_prices[asset_rank[index]])
        .collect();
    Ok(ExactClearing {
        fills,
        quote_amounts,
        dust,
        certificate: ClearingCertificate { asset_prices },
        report: solved.report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_crypto::Felt;

    fn market(base: usize, quote: usize, midpoint: u128, scale: u128) -> ClearingMarket {
        ClearingMarket {
            base_asset: base,
            quote_asset: quote,
            midpoint,
            scale,
        }
    }

    fn order(market: usize, sell: bool, capacity: u128) -> ClearingOrder {
        ClearingOrder {
            market,
            sell,
            capacity,
        }
    }

    fn feasible(instance: &ClearingInstance, fills: &[u128]) -> bool {
        let (inputs, outputs) = clearing_flows(instance, fills);
        fills
            .iter()
            .zip(&instance.orders)
            .all(|(fill, order)| *fill <= order.capacity)
            && inputs
                .iter()
                .zip(&outputs)
                .all(|(input, output)| input >= output)
    }

    /// the exact integer optimum by exhaustive enumeration.
    fn brute_force(instance: &ClearingInstance) -> BigUint {
        let mut best = BigUint::zero();
        let mut fills = vec![0_u128; instance.orders.len()];
        loop {
            if feasible(instance, &fills) {
                best = best.max(clearing_objective(instance, &fills));
            }
            let mut index = 0;
            loop {
                if index == fills.len() {
                    return best;
                }
                if fills[index] < instance.orders[index].capacity {
                    fills[index] += 1;
                    break;
                }
                fills[index] = 0;
                index += 1;
            }
        }
    }

    fn weight_market(base: usize, quote: usize, midpoint: u128, scale: u128) -> WeightMarket {
        WeightMarket {
            base_asset: base,
            quote_asset: quote,
            midpoint,
            scale,
        }
    }

    #[test]
    fn usdc_objective_accepts_divergent_direct_cross_markets() {
        let asset = |name| {
            crate::hash::felt_from_hex_str(&crate::hash::encode_starknet_felt("asset-id", name))
                .unwrap()
        };
        let assets = vec![asset("ETH"), asset("STRK"), asset("USDC")];
        let markets = vec![
            weight_market(0, 2, 2_500, 1),
            weight_market(1, 2, 2, 1),
            // the direct eth/strk book need not equal the usdc-implied cross of 1,250.
            weight_market(0, 1, 1_300, 1),
        ];
        let weights =
            usdc_clearing_weights(&assets, asset("USDC"), &markets).expect("usdc objective");
        assert_eq!(weights.values, vec![(2_500, 1), (2, 1), (1, 1)]);
        assert_eq!(weights.weights[0], MAX_CLEARING_WEIGHT - 1);
        assert_eq!(weights.weights[1], (MAX_CLEARING_WEIGHT - 1) * 2 / 2_500);
        assert_eq!(weights.weights[2], (MAX_CLEARING_WEIGHT - 1) / 2_500);
    }

    #[test]
    fn realistic_magnitudes_clear_whole_cycles_and_certify() {
        // eth (0) / strk (1) / usdc (2) at 2500 usdc per eth and 2 usdc per strk.
        let markets = vec![
            market(0, 2, 2_500, 1),
            market(0, 1, 1_250, 1),
            market(1, 2, 4, 2),
        ];
        let weights = usdc_clearing_weights(
            &[Felt::from(1_u8), Felt::from(2_u8), Felt::from(3_u8)],
            Felt::from(3_u8),
            &markets
                .iter()
                .map(|market| WeightMarket {
                    base_asset: market.base_asset,
                    quote_asset: market.quote_asset,
                    midpoint: market.midpoint,
                    scale: market.scale,
                })
                .collect::<Vec<_>>(),
        )
        .expect("weights")
        .weights;
        for unit in [1_u128, 1_000_000, 1_000_000_000_000_000_000] {
            let instance = ClearingInstance {
                asset_weights: weights.clone(),
                markets: markets.clone(),
                orders: vec![
                    order(0, false, 9 * unit),
                    order(0, true, 3 * unit),
                    order(1, true, 5 * unit),
                    order(2, true, 7_001 * unit),
                ],
            };
            let clearing = solve_exact_clearing(&instance).expect("certified");
            assert_eq!(
                clearing.fills,
                vec![8 * unit, 3 * unit, 5 * unit, 6_250 * unit],
                "unit {unit}"
            );
        }
    }

    /// a random close in the protocol's domain: direct usdc observations determine weights, with
    /// capacities of every magnitude up to 10^21 units.
    fn random_canonical_instance(rng: &mut Rng) -> ClearingInstance {
        let assets = 2 + rng.next(4) as usize;
        let usdc = assets - 1;
        let mut values = (0..usdc)
            .map(|_| (1 + rng.next(10_000) as u128, 1 + rng.next(10_000) as u128))
            .collect::<Vec<_>>();
        values.push((1, 1));
        let mut markets = (0..usdc)
            .map(|asset| market(asset, usdc, values[asset].0, values[asset].1))
            .collect::<Vec<_>>();
        let extra_markets = 1 + rng.next(4) as usize;
        for _ in 0..extra_markets {
            let base = rng.next(assets as u64) as usize;
            let quote = (base + 1 + rng.next(assets as u64 - 1) as usize) % assets;
            if markets.iter().any(|market: &ClearingMarket| {
                market.base_asset == base && market.quote_asset == quote
            }) {
                continue;
            }
            // keep the stress generator arbitrage-neutral; divergent cycles have a focused test.
            markets.push(market(
                base,
                quote,
                values[base].0 * values[quote].1,
                values[base].1 * values[quote].0,
            ));
        }
        let asset_ids = (0..assets)
            .map(|index| Felt::from(index as u64 + 1))
            .collect::<Vec<_>>();
        let weights = usdc_clearing_weights(
            &asset_ids,
            asset_ids[usdc],
            &markets
                .iter()
                .map(|market| WeightMarket {
                    base_asset: market.base_asset,
                    quote_asset: market.quote_asset,
                    midpoint: market.midpoint,
                    scale: market.scale,
                })
                .collect::<Vec<_>>(),
        )
        .expect("direct usdc observations")
        .weights;
        let magnitude = 10_u128.pow(rng.next(19) as u32);
        let orders = (0..1 + rng.next(40))
            .map(|_| {
                let capacity =
                    rng.next(1_000) as u128 * magnitude + rng.next(magnitude as u64) as u128;
                order(
                    rng.next(markets.len() as u64) as usize,
                    rng.next(2) == 1,
                    capacity,
                )
            })
            .collect();
        ClearingInstance {
            asset_weights: weights,
            markets,
            orders,
        }
    }

    /// how often the rounding repair fails to certify, by capacity digits and order count; the
    /// known residual is a rare dust-scale close with many orders across high-rate markets.
    #[test]
    #[ignore]
    fn failure_census() {
        let mut rng = Rng(0x1357_9bdf_2468_ace0);
        let mut failures = std::collections::BTreeMap::<(u32, usize), (u32, u32)>::new();
        for _ in 0..20_000 {
            let instance = random_canonical_instance(&mut rng);
            let magnitude = instance
                .orders
                .iter()
                .map(|o| o.capacity)
                .max()
                .unwrap_or(0)
                .to_string()
                .len() as u32;
            let entry = failures
                .entry((magnitude, instance.orders.len() / 10))
                .or_default();
            entry.1 += 1;
            if solve_exact_clearing(&instance).is_err() {
                entry.0 += 1;
            }
        }
        for ((magnitude, orders), (failed, total)) in failures {
            if failed > 0 {
                eprintln!("digits {magnitude} orders {}0s: {failed}/{total}", orders);
            }
        }
    }

    /// a dust-scale close across high-rate markets: every rounding of its lp vertex leaves about
    /// one unit of the valuable asset in deficit, which no rounding dust can absorb; the dive must
    /// still reach a certified allocation.
    #[test]
    fn dust_scale_cycle_certifies_through_the_dive() {
        let orders = [
            (2, true, 590),
            (3, false, 930),
            (2, true, 707),
            (3, false, 120),
            (0, false, 876),
            (1, false, 622),
            (1, true, 187),
            (1, false, 555),
            (0, true, 890),
            (2, false, 179),
            (3, false, 672),
            (0, true, 277),
            (0, true, 585),
            (4, false, 444),
            (3, false, 823),
            (0, false, 517),
            (2, false, 109),
            (2, false, 135),
            (0, true, 826),
            (0, true, 345),
            (4, false, 204),
            (1, false, 864),
            (3, true, 357),
            (3, true, 17),
            (3, true, 544),
            (4, false, 40),
            (4, false, 936),
            (2, false, 530),
            (3, true, 980),
            (3, true, 909),
            (4, false, 436),
            (1, true, 110),
            (1, false, 150),
            (2, false, 63),
        ];
        let instance = ClearingInstance {
            asset_weights: vec![29015497534, 59918892839, 2790332008, 1099511627775],
            markets: vec![
                ClearingMarket {
                    base_asset: 1,
                    quote_asset: 2,
                    midpoint: 23184564,
                    scale: 1079670,
                },
                ClearingMarket {
                    base_asset: 1,
                    quote_asset: 0,
                    midpoint: 39871200,
                    scale: 19307478,
                },
                ClearingMarket {
                    base_asset: 3,
                    quote_asset: 2,
                    midpoint: 27311141,
                    scale: 69310,
                },
                ClearingMarket {
                    base_asset: 3,
                    quote_asset: 0,
                    midpoint: 46967800,
                    scale: 1239454,
                },
                ClearingMarket {
                    base_asset: 3,
                    quote_asset: 1,
                    midpoint: 23629881,
                    scale: 1287732,
                },
            ],
            orders: orders
                .iter()
                .map(|(market, sell, capacity)| ClearingOrder {
                    market: *market,
                    sell: *sell,
                    capacity: *capacity,
                })
                .collect(),
        };
        let clearing = solve_exact_clearing(&instance).expect("the dive certifies");
        assert!(feasible(&instance, &clearing.fills));
        assert!(clearing.report.objective > BigUint::zero());
    }

    /// the census over fresh seeds: every random protocol close certifies.
    #[test]
    #[ignore]
    fn failure_census_fresh_seeds() {
        for seed in [
            0x0123_4567_89ab_cdef_u64,
            0xfedc_ba98_7654_3210,
            0x0f0f_f0f0_1234_4321,
        ] {
            let mut rng = Rng(seed);
            for case in 0..20_000 {
                let instance = random_canonical_instance(&mut rng);
                let clearing = solve_exact_clearing(&instance).unwrap_or_else(|error| {
                    panic!("seed {seed:x} case {case}: {error:?} {instance:?}")
                });
                assert!(feasible(&instance, &clearing.fills));
            }
        }
    }

    #[test]
    fn random_protocol_closes_always_certify() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for case in 0..5_000 {
            let instance = random_canonical_instance(&mut rng);
            let clearing = solve_exact_clearing(&instance)
                .unwrap_or_else(|error| panic!("case {case}: {error:?} {instance:?}"));
            assert!(
                feasible(&instance, &clearing.fills),
                "case {case}: infeasible"
            );
        }
    }

    #[test]
    fn direct_cross_repair_preserves_conservation_regression() {
        let mut rng = Rng(0xfedc_ba98_7654_3210);
        let mut instance = random_canonical_instance(&mut rng);
        for _ in 0..3_150 {
            instance = random_canonical_instance(&mut rng);
        }
        let clearing = solve_exact_clearing(&instance)
            .unwrap_or_else(|error| panic!("{error:?} {instance:?}"));
        assert!(feasible(&instance, &clearing.fills));
    }

    #[test]
    fn canonical_clearing_is_invariant_under_relisting() {
        // identical competing sellers make the optimum non-unique; keys must break the tie.
        let instance = ClearingInstance {
            asset_weights: vec![5, 1, 2],
            markets: vec![market(0, 1, 7, 3), market(2, 1, 5, 2)],
            orders: vec![
                order(0, true, 9),
                order(0, true, 9),
                order(0, false, 11),
                order(1, true, 6),
                order(1, false, 4),
                order(1, false, 4),
            ],
        };
        let asset_keys = [[3_u8; 32], [1_u8; 32], [2_u8; 32]];
        let order_keys = (0..6_u8).map(|key| [key + 10; 32]).collect::<Vec<_>>();
        let base = solve_canonical_clearing(&instance, &asset_keys, &order_keys).expect("solve");
        // reverse the orders and rotate the assets and markets.
        let order_permutation = [5_usize, 4, 3, 2, 1, 0];
        let asset_permutation = [2_usize, 0, 1];
        let asset_position = |asset: usize| {
            asset_permutation
                .iter()
                .position(|candidate| *candidate == asset)
                .unwrap()
        };
        let relisted = ClearingInstance {
            asset_weights: asset_permutation
                .iter()
                .map(|asset| instance.asset_weights[*asset])
                .collect(),
            markets: instance
                .markets
                .iter()
                .rev()
                .map(|market| ClearingMarket {
                    base_asset: asset_position(market.base_asset),
                    quote_asset: asset_position(market.quote_asset),
                    midpoint: market.midpoint,
                    scale: market.scale,
                })
                .collect(),
            orders: order_permutation
                .iter()
                .map(|index| {
                    let order = &instance.orders[*index];
                    ClearingOrder {
                        market: 1 - order.market,
                        ..order.clone()
                    }
                })
                .collect(),
        };
        let relisted_asset_keys = asset_permutation
            .iter()
            .map(|asset| asset_keys[*asset])
            .collect::<Vec<_>>();
        let relisted_order_keys = order_permutation
            .iter()
            .map(|index| order_keys[*index])
            .collect::<Vec<_>>();
        let other = solve_canonical_clearing(&relisted, &relisted_asset_keys, &relisted_order_keys)
            .expect("solve");
        for (position, index) in order_permutation.iter().enumerate() {
            assert_eq!(other.fills[position], base.fills[*index]);
        }
        for (position, asset) in asset_permutation.iter().enumerate() {
            assert_eq!(
                other.certificate.asset_prices[position],
                base.certificate.asset_prices[*asset]
            );
            assert_eq!(other.dust[position], base.dust[*asset]);
        }
        assert!(base.fills.iter().any(|fill| *fill > 0));
    }

    #[test]
    fn single_market_matches_the_crossable_volume() {
        let instance = ClearingInstance {
            asset_weights: vec![3, 1],
            markets: vec![market(0, 1, 3, 2)],
            orders: vec![order(0, false, 5), order(0, false, 4), order(0, true, 7)],
        };
        let clearing = solve_exact_clearing(&instance).expect("solve");
        assert!(feasible(&instance, &clearing.fills));
        assert_eq!(clearing.fills.iter().sum::<u128>(), 14);
        assert_eq!(clearing.report.objective, brute_force(&instance));
    }

    #[test]
    fn three_asset_cycle_is_cleared_globally() {
        // a -> b -> c -> a through three markets; no pairwise match exists.
        let instance = ClearingInstance {
            asset_weights: vec![6, 3, 2],
            markets: vec![market(0, 1, 2, 1), market(1, 2, 3, 2), market(2, 0, 1, 3)],
            orders: vec![order(0, true, 6), order(1, true, 12), order(2, true, 18)],
        };
        let clearing = solve_exact_clearing(&instance).expect("solve");
        assert!(feasible(&instance, &clearing.fills));
        assert!(
            clearing.report.objective > BigUint::zero(),
            "the cycle must clear"
        );
        assert!(clearing.report.upper_bound >= brute_force(&instance));
    }

    #[test]
    fn certificate_rejects_suboptimal_allocations_and_bad_shapes() {
        let instance = ClearingInstance {
            asset_weights: vec![1, 1],
            markets: vec![market(0, 1, 1, 1)],
            orders: (0..20).map(|index| order(0, index % 2 == 1, 50)).collect(),
        };
        let clearing = solve_exact_clearing(&instance).expect("solve");
        assert!(
            verify_clearing_certificate(&instance, &vec![0; 20], &clearing.certificate).is_err()
        );
        let mut over = clearing.fills.clone();
        over[0] += 1;
        assert!(verify_clearing_certificate(&instance, &over, &clearing.certificate).is_err());
        assert!(
            verify_clearing_certificate(
                &instance,
                &clearing.fills,
                &ClearingCertificate {
                    asset_prices: vec![0]
                }
            )
            .is_err()
        );
    }

    #[test]
    fn rounding_tolerance_cannot_hide_a_one_atom_cross() {
        let instance = ClearingInstance {
            asset_weights: vec![3, 1],
            markets: vec![market(0, 1, 1, 1)],
            orders: vec![order(0, false, 1), order(0, true, 1)],
        };
        let clearing = solve_exact_clearing(&instance).expect("solve");
        assert_eq!(clearing.fills, vec![1, 1]);
        assert!(
            verify_clearing_certificate(&instance, &[0, 0], &clearing.certificate).is_err(),
            "a one-atom direct cross is not rounding dust"
        );
    }

    #[test]
    fn an_unrepresentable_quote_is_rejected_instead_of_panicking() {
        let instance = ClearingInstance {
            asset_weights: vec![1, 1],
            markets: vec![market(0, 1, u128::MAX, 1)],
            orders: vec![order(0, true, 2)],
        };
        assert!(solve_exact_clearing(&instance).is_err());
    }

    /// deterministic xorshift for reproducible random instances.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self, bound: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % bound
        }
    }

    fn random_instance(rng: &mut Rng, max_orders: u64, max_capacity: u64) -> ClearingInstance {
        let assets = 2 + rng.next(2) as usize;
        let market_count = 1 + rng.next(3) as usize;
        let markets = (0..market_count)
            .map(|_| {
                let base = rng.next(assets as u64) as usize;
                let quote = (base + 1 + rng.next(assets as u64 - 1) as usize) % assets;
                market(
                    base,
                    quote,
                    1 + rng.next(5) as u128,
                    1 + rng.next(3) as u128,
                )
            })
            .collect::<Vec<_>>();
        let orders = (0..1 + rng.next(max_orders))
            .map(|_| {
                order(
                    rng.next(market_count as u64) as usize,
                    rng.next(2) == 1,
                    rng.next(max_capacity + 1) as u128,
                )
            })
            .collect();
        ClearingInstance {
            asset_weights: (0..assets).map(|_| 1 + rng.next(6) as u128).collect(),
            markets,
            orders,
        }
    }

    #[test]
    fn differential_against_exhaustive_integer_optimum() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for case in 0..2_000 {
            let instance = random_instance(&mut rng, 5, 5);
            let clearing = solve_exact_clearing(&instance)
                .unwrap_or_else(|error| panic!("case {case}: {error:?} {instance:?}"));
            let optimum = brute_force(&instance);
            assert!(
                feasible(&instance, &clearing.fills),
                "case {case}: infeasible"
            );
            // soundness: the certified bound covers the true integer optimum.
            assert!(
                clearing.report.upper_bound >= optimum,
                "case {case}: bound {} below optimum {optimum} for {instance:?}",
                clearing.report.upper_bound
            );
            // optimality within the protocol tolerance.
            assert!(
                &clearing.report.objective + &clearing.report.tolerance >= optimum,
                "case {case}: objective too far from optimum"
            );
            assert!(clearing.report.objective <= optimum);
        }
    }

    #[test]
    fn any_nonnegative_prices_bound_the_integer_optimum() {
        // the air accepts prover-chosen prices, so the bound must hold for every price vector.
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for case in 0..1_000 {
            let instance = random_instance(&mut rng, 4, 5);
            let optimum = brute_force(&instance);
            let prices = (0..instance.asset_weights.len())
                .map(|_| {
                    let whole = rng.next(8) as u128;
                    let fraction = (rng.next(u64::MAX) as u128) & (CLEARING_PRICE_DENOMINATOR - 1);
                    whole * CLEARING_PRICE_DENOMINATOR + fraction
                })
                .collect::<Vec<_>>();
            let denominator = BigInt::from(CLEARING_PRICE_DENOMINATOR);
            let prices_q = prices
                .iter()
                .map(|price| Q::new(BigInt::from(*price), denominator.clone()))
                .collect::<Vec<_>>();
            let bound = certificate_upper_bound(&instance, &prices_q);
            assert!(
                bound >= Q::int(BigInt::from(optimum.clone())),
                "case {case}: prices {prices:?} bound below optimum {optimum}"
            );
        }
    }

    #[test]
    fn scales_to_1024_orders() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let markets = vec![
            market(0, 1, 3_512_345, 100_000_000),
            market(2, 1, 250_000_000_000, 100_000_000),
            market(3, 1, 6_400_000_000_000, 100_000_000),
            market(2, 0, 71_000_000_000, 1_000_000_000),
        ];
        let orders = (0..1_024)
            .map(|_| {
                order(
                    rng.next(4) as usize,
                    rng.next(2) == 1,
                    1 + rng.next(10_000_000_000) as u128,
                )
            })
            .collect();
        let instance = ClearingInstance {
            asset_weights: vec![35, 1_000, 25_000, 640_000],
            markets,
            orders,
        };
        let started = std::time::Instant::now();
        let clearing = solve_exact_clearing(&instance).expect("solve");
        let elapsed = started.elapsed();
        assert!(feasible(&instance, &clearing.fills));
        assert!(
            clearing.report.upper_bound <= &clearing.report.objective + &clearing.report.tolerance
        );
        eprintln!("1024-order exact clearing solved in {elapsed:?}");
    }
}

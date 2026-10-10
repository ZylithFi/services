//! the reference transition: what one proof-bearing transaction does to the book, and the witness
//! the cairo transition statement checks.
//!
//! a transition, in stream order over the book's `(pair_id, side)` groups:
//!
//! 1. applies the external outcomes of earlier transitions to the orders they reserved;
//! 2. removes cancelled and expired orders;
//! 3. admits the new orders, locking their funding notes;
//! 4. crosses every participating order at m0 under the global clearing certificate, optimal
//!    within the protocol's rounding tolerance;
//! 5. settles proceeds net of fees, refunds finished orders and reserves external capacity;
//! 6. rebuilds the book.
//!
//! orders whose pair has no market in this transition pass through untouched.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use starknet_crypto::Felt;

use super::model::*;
use crate::ProtocolError;
use crate::exact_clearing::{
    CLEARING_PRICE_DENOMINATOR, ClearingInstance, ClearingMarket, ClearingOrder, WeightMarket,
    solve_canonical_clearing, usdc_clearing_weights,
};

pub const STATEMENT_TYPE_TRANSITION: u64 = 14;

/// one attested midpoint and the pair's fee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Market {
    #[serde(with = "felt_hex_serde")]
    pub pair_id: Felt,
    #[serde(with = "felt_hex_serde")]
    pub base_asset_id: Felt,
    #[serde(with = "felt_hex_serde")]
    pub quote_asset_id: Felt,
    #[serde(with = "u128_decimal_serde")]
    pub midpoint: u128,
    #[serde(with = "u128_decimal_serde")]
    pub scale: u128,
    pub observed_at_ms: u64,
    pub valid_until_ms: u64,
    #[serde(with = "u128_decimal_serde")]
    pub fee_bps: u128,
    #[serde(with = "u128_decimal_serde")]
    pub min_order_quote_amount: u128,
    pub reference_methodology: u8,
    #[serde(with = "felt_hex_serde")]
    pub derivation_base_market_id: Felt,
    #[serde(with = "felt_hex_serde")]
    pub derivation_quote_market_id: Felt,
    #[serde(with = "u128_decimal_serde")]
    pub derivation_base_bid: u128,
    #[serde(with = "u128_decimal_serde")]
    pub derivation_base_ask: u128,
    #[serde(with = "u128_decimal_serde")]
    pub derivation_quote_bid: u128,
    #[serde(with = "u128_decimal_serde")]
    pub derivation_quote_ask: u128,
    pub max_leg_skew_ms: u64,
}

impl Market {
    pub fn fields(&self) -> [Felt; 17] {
        [
            self.pair_id,
            self.base_asset_id,
            self.quote_asset_id,
            felt_u128(self.midpoint),
            felt_u128(self.scale),
            felt_u64(self.observed_at_ms),
            felt_u64(self.valid_until_ms),
            felt_u128(self.fee_bps),
            felt_u128(self.min_order_quote_amount),
            felt_u64(u64::from(self.reference_methodology)),
            self.derivation_base_market_id,
            self.derivation_quote_market_id,
            felt_u128(self.derivation_base_bid),
            felt_u128(self.derivation_base_ask),
            felt_u128(self.derivation_quote_bid),
            felt_u128(self.derivation_quote_ask),
            felt_u64(self.max_leg_skew_ms),
        ]
    }
}

/// the recorded result of an earlier transition's external leg on one capacity slot. every
/// capacity gets one, zero when nothing executed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub seq: u32,
    #[serde(with = "felt_hex_serde")]
    pub pair_id: Felt,
    pub sell: bool,
    #[serde(with = "u128_decimal_serde")]
    pub consumed_base: u128,
    /// quote the pool received (sells) or paid (buys).
    #[serde(with = "u128_decimal_serde")]
    pub pool_quote: u128,
    #[serde(with = "u128_decimal_serde")]
    pub m1: u128,
    #[serde(with = "u128_decimal_serde")]
    pub m1_scale: u128,
}

impl Outcome {
    /// the outcome of a capacity as the contract records it. a capacity may be filled several
    /// times, at different m1s, until it is used up or its window closes; its orders then share
    /// the fills at their average price, `pool_quote` per `consumed_base`, which every fill
    /// already kept on the right side of the capacity's bound. an unfilled capacity keeps its
    /// bound over the market scale, which prices nothing.
    pub fn from_capacity(
        seq: u32,
        pair_id: Felt,
        sell: bool,
        consumed_base: u128,
        pool_quote: u128,
        bound: u128,
        scale: u128,
    ) -> Self {
        let (m1, m1_scale) = if consumed_base == 0 {
            (bound, scale)
        } else {
            (pool_quote, consumed_base)
        };
        Self {
            seq,
            pair_id,
            sell,
            consumed_base,
            pool_quote,
            m1,
            m1_scale,
        }
    }

    pub fn fields(&self) -> [Felt; 7] {
        [
            felt_u64(u64::from(self.seq)),
            self.pair_id,
            felt_bool(self.sell),
            felt_u128(self.consumed_base),
            felt_u128(self.pool_quote),
            felt_u128(self.m1),
            felt_u128(self.m1_scale),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingNote {
    pub note: NoteFields,
    pub membership: NoteMembership,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewOrder {
    pub terms: OrderTerms,
    pub funding: Vec<FundingNote>,
    pub authorization: Signature,
}

impl NewOrder {
    pub fn funding_total(&self) -> u128 {
        self.funding.iter().map(|funding| funding.note.amount).sum()
    }

    pub fn authorization_message(&self, chain_context: Felt) -> Felt {
        let commitments = self
            .funding
            .iter()
            .map(|funding| funding.note.commitment())
            .collect::<Vec<_>>();
        order_authorization_message(
            chain_context,
            self.terms.order_id(),
            funding_set_commitment(&commitments),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cancellation {
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionInput {
    #[serde(with = "felt_hex_serde")]
    pub chain_context: Felt,
    pub seq: u32,
    pub close_time_ms: u64,
    #[serde(with = "felt_hex_serde")]
    pub fee_recipient: Felt,
    /// the operator's secret behind fee-note blindings: it pads a fee note's published amount
    /// as an order's secret nonce pads its outputs, so no fee total is readable on chain.
    #[serde(with = "felt_hex_serde")]
    pub fee_key: Felt,
    /// a known accumulator root every admitted funding note is a member of; zero without
    /// admissions.
    #[serde(with = "felt_hex_serde")]
    pub note_root: Felt,
    #[serde(with = "felt_hex_serde")]
    pub objective_numeraire_asset_id: Felt,
    pub markets: Vec<Market>,
    pub book: Vec<BookEntry>,
    pub new_orders: Vec<NewOrder>,
    pub cancellations: Vec<Cancellation>,
    #[serde(default, with = "felt_vec_hex_serde")]
    pub recovered_order_ids: Vec<Felt>,
    pub outcomes: Vec<Outcome>,
    #[serde(with = "felt_hex_serde")]
    pub padding_seed: Felt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    #[serde(with = "felt_hex_serde")]
    pub pair_id: Felt,
    pub sell: bool,
    #[serde(with = "u128_decimal_serde")]
    pub bound: u128,
    #[serde(with = "u128_decimal_serde")]
    pub total: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputRecord {
    #[serde(with = "felt_hex_serde")]
    pub leaf: Felt,
    #[serde(with = "felt_hex_serde")]
    pub enc: Felt,
    #[serde(with = "felt_hex_serde")]
    pub enc_remaining: Felt,
    #[serde(with = "felt_hex_serde")]
    pub enc_reserved: Felt,
    #[serde(with = "felt_hex_serde")]
    pub enc_reserved_offset: Felt,
}

/// a note this transition created, with where it sits in the padded output list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputNote {
    /// the order it belongs to; zero for a fee note.
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    pub kind: u64,
    pub index: usize,
    pub note: NoteFields,
}

/// a shielded residual-order authority created by this transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualOutput {
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    pub index: usize,
    pub note: ResidualNote,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Removal {
    Completed,
    Cancelled,
    Expired,
    Recovered,
}

/// what happened to one order, for the operator and the order's owner.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderReport {
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    pub admitted: bool,
    #[serde(with = "u128_decimal_serde")]
    pub external_base: u128,
    #[serde(with = "u128_decimal_serde")]
    pub external_quote: u128,
    #[serde(with = "u128_decimal_serde")]
    pub fill_base: u128,
    #[serde(with = "u128_decimal_serde")]
    pub fill_quote: u128,
    #[serde(with = "u128_decimal_serde")]
    pub fee: u128,
    #[serde(with = "u128_decimal_serde")]
    pub proceeds: u128,
    #[serde(with = "u128_decimal_serde")]
    pub refund: u128,
    #[serde(with = "u128_decimal_serde")]
    pub reserved: u128,
    pub removal: Option<Removal>,
}

/// every value the contract checks, and the lists it receives as calldata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionPublic {
    #[serde(with = "felt_hex_serde")]
    pub chain_context: Felt,
    pub seq: u32,
    pub close_time_ms: u64,
    #[serde(with = "felt_hex_serde")]
    pub prior_book_root: Felt,
    #[serde(with = "felt_hex_serde")]
    pub new_book_root: Felt,
    #[serde(with = "felt_hex_serde")]
    pub note_root: Felt,
    pub markets: Vec<Market>,
    #[serde(with = "felt_hex_serde")]
    pub markets_commitment: Felt,
    pub outcomes: Vec<Outcome>,
    #[serde(with = "felt_hex_serde")]
    pub outcomes_commitment: Felt,
    pub capacities: Vec<Capacity>,
    #[serde(with = "felt_hex_serde")]
    pub capacity_commitment: Felt,
    #[serde(with = "felt_vec_hex_serde")]
    pub nullifiers: Vec<Felt>,
    #[serde(with = "felt_hex_serde")]
    pub nullifiers_commitment: Felt,
    #[serde(with = "felt_vec_hex_serde")]
    pub retired_nullifiers: Vec<Felt>,
    #[serde(with = "felt_hex_serde")]
    pub retired_nullifiers_commitment: Felt,
    pub output_records: Vec<OutputRecord>,
    #[serde(with = "felt_hex_serde")]
    pub outputs_commitment: Felt,
    #[serde(with = "felt_hex_serde")]
    pub output_root: Felt,
    #[serde(with = "felt_hex_serde")]
    pub fee_recipient: Felt,
    #[serde(with = "felt_hex_serde")]
    pub commitment: Felt,
}

/// where each part of the witness starts, for tooling and tamper tests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessLayout {
    pub groups: Vec<usize>,
    pub orders: Vec<OrderLayout>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderLayout {
    #[serde(with = "felt_hex_serde")]
    pub order_id: Felt,
    pub existing: bool,
    pub start: usize,
    /// the outcome index and removal flag of an existing order.
    pub outcome: Option<usize>,
    pub removal: Option<usize>,
    /// the authorization signature of a new order.
    pub authorization: Option<usize>,
    /// fill, quote, clearing capacity, external amount.
    pub allocation: usize,
    /// admission work omitted by the old step estimate.
    pub funding_notes: u64,
    pub membership_path_elements: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransitionResult {
    pub public: TransitionPublic,
    pub new_book: Vec<BookEntry>,
    pub outputs: Vec<OutputNote>,
    pub residual_outputs: Vec<ResidualOutput>,
    pub reports: Vec<OrderReport>,
    /// cancellations that could not apply yet (reserved order or no market this transition).
    #[serde(with = "felt_vec_hex_serde")]
    pub deferred_cancellations: Vec<Felt>,
    #[serde(with = "felt_vec_hex_serde")]
    pub witness: Vec<Felt>,
    pub layout: WitnessLayout,
}

pub fn markets_commitment(
    chain_context: Felt,
    seq: u32,
    close_time_ms: u64,
    objective_numeraire_asset_id: Felt,
    markets: &[Market],
) -> Felt {
    let mut values = vec![
        short_string(M0_DOMAIN),
        chain_context,
        felt_u64(u64::from(seq)),
        felt_u64(close_time_ms),
        objective_numeraire_asset_id,
        felt_u64(markets.len() as u64),
    ];
    for market in markets {
        values.extend_from_slice(&market.fields());
    }
    sponge(&values)
}

/// list commitments put the count last, so the statement absorbs them as it streams.
pub fn outcomes_commitment(outcomes: &[Outcome]) -> Felt {
    let mut values = vec![short_string(OUTCOMES_DOMAIN)];
    for outcome in outcomes {
        values.extend_from_slice(&outcome.fields());
    }
    values.push(felt_u64(outcomes.len() as u64));
    sponge(&values)
}

pub fn capacity_commitment(chain_context: Felt, capacities: &[Capacity]) -> Felt {
    let mut values = vec![short_string(CAPACITY_DOMAIN), chain_context];
    for capacity in capacities {
        values.extend_from_slice(&[
            capacity.pair_id,
            felt_bool(capacity.sell),
            felt_u128(capacity.bound),
            felt_u128(capacity.total),
        ]);
    }
    values.push(felt_u64(capacities.len() as u64));
    sponge(&values)
}

/// a hash chain, so the statement carries one felt while it streams the nullifiers.
pub fn nullifiers_commitment(chain_context: Felt, nullifiers: &[Felt]) -> Felt {
    let mut state = starknet_crypto::poseidon_hash(short_string(NULLIFIERS_DOMAIN), chain_context);
    for nullifier in nullifiers {
        state = starknet_crypto::poseidon_hash(state, *nullifier);
    }
    starknet_crypto::poseidon_hash(state, felt_u64(nullifiers.len() as u64))
}

pub fn retired_nullifiers_commitment(chain_context: Felt, nullifiers: &[Felt]) -> Felt {
    let mut state =
        starknet_crypto::poseidon_hash(short_string(RETIRED_NULLIFIERS_DOMAIN), chain_context);
    for nullifier in nullifiers {
        state = starknet_crypto::poseidon_hash(state, *nullifier);
    }
    starknet_crypto::poseidon_hash(state, felt_u64(nullifiers.len() as u64))
}

pub fn outputs_commitment(chain_context: Felt, records: &[OutputRecord]) -> Felt {
    let mut values = vec![short_string(OUTPUTS_DOMAIN), chain_context];
    for record in records {
        values.push(record.leaf);
        values.push(record.enc);
        values.push(record.enc_remaining);
        values.push(record.enc_reserved);
        values.push(record.enc_reserved_offset);
    }
    values.push(felt_u64(records.len() as u64));
    sponge(&values)
}

impl TransitionPublic {
    pub fn transition_commitment(&self) -> Felt {
        sponge(&[
            short_string(TRANSITION_DOMAIN),
            self.chain_context,
            felt_u64(u64::from(self.seq)),
            felt_u64(self.close_time_ms),
            self.prior_book_root,
            self.new_book_root,
            self.note_root,
            self.markets_commitment,
            self.outcomes_commitment,
            self.capacity_commitment,
            self.nullifiers_commitment,
            self.retired_nullifiers_commitment,
            self.outputs_commitment,
            self.output_root,
            self.fee_recipient,
        ])
    }
}

pub fn output_blinding(key: Felt, seq: u32, kind: OutputKind, asset_id: Felt) -> Felt {
    match kind {
        OutputKind::Fee => sponge(&[
            short_string(OUTPUT_BLINDING_DOMAIN),
            key,
            felt_u64(u64::from(seq)),
            felt_u64(kind.as_u64()),
            asset_id,
        ]),
        OutputKind::Proceeds => order_output_blindings(key, seq)[0],
        OutputKind::Refund => order_output_blindings(key, seq)[1],
        OutputKind::Residual => order_output_blindings(key, seq)[2],
    }
}

/// an order output as its owner can rebuild it from the order and the transition: its blinding
/// derives from the order's secret nonce, its metadata names the order, and the published
/// amount is padded by the blinding, which only the owner and the operator know.
pub fn order_output_note(
    owner: &OrderOwner,
    order_id: Felt,
    asset_id: Felt,
    amount: u128,
    seq: u32,
    kind: OutputKind,
) -> NoteFields {
    NoteFields {
        asset_id,
        amount,
        owner_public_key: owner.owner_public_key,
        spend_authority: owner.spend_authority,
        withdraw_authority: owner.withdraw_authority,
        blinding: output_blinding(owner.nonce, seq, kind, Felt::ZERO),
        nonce: u64::from(seq),
        metadata_commitment: order_id,
    }
}

pub fn fee_output_note(
    fee_recipient: Felt,
    fee_key: Felt,
    asset_id: Felt,
    amount: u128,
    seq: u32,
) -> NoteFields {
    NoteFields {
        asset_id,
        amount,
        owner_public_key: fee_recipient,
        spend_authority: fee_recipient,
        withdraw_authority: fee_recipient,
        blinding: output_blinding(fee_key, seq, OutputKind::Fee, asset_id),
        nonce: u64::from(seq),
        metadata_commitment: asset_id,
    }
}

fn mul_div_floor(left: u128, right: u128, denominator: u128) -> u128 {
    ((BigUint::from(left) * BigUint::from(right)) / BigUint::from(denominator))
        .to_u128()
        .expect("mul-div quotient fits u128")
}

fn mul_div_ceil(left: u128, right: u128, denominator: u128) -> u128 {
    (BigUint::from(left) * BigUint::from(right))
        .div_ceil(&BigUint::from(denominator))
        .to_u128()
        .expect("mul-div quotient fits u128")
}

fn fee_amount(gross: u128, fee_bps: u128) -> u128 {
    if gross == 0 || fee_bps == 0 {
        return 0;
    }
    mul_div_ceil(gross, fee_bps, FEE_BPS_DENOMINATOR)
}

/// one order of the transition stream while it is processed.
struct StreamOrder {
    /// the order as the prior book held it; unset for a new order.
    prior: Option<BookOrder>,
    order: BookOrder,
    owner: OrderOwner,
    existing: bool,
    new_order: Option<NewOrder>,
    outcome: Option<usize>,
    external_base: u128,
    external_quote: u128,
    external_fee: u128,
    removal: Option<Removal>,
    cancel_signature: Option<Signature>,
    fill: u128,
    quote: u128,
    clearing_capacity: u128,
    external_amount: u128,
    fee: u128,
    proceeds: u128,
    refund: u128,
}

struct Group {
    pair_id: Felt,
    sell: bool,
    market: Option<usize>,
    existing: usize,
    orders: Vec<StreamOrder>,
}

struct Assets {
    ids: Vec<Felt>,
    base: Vec<usize>,
    quote: Vec<usize>,
}

fn market_assets(markets: &[Market]) -> Result<Assets, ProtocolError> {
    let mut ids = BTreeSet::new();
    for market in markets {
        ids.insert(felt_to_u256_bytes(&market.base_asset_id));
        ids.insert(felt_to_u256_bytes(&market.quote_asset_id));
    }
    let ids = ids
        .into_iter()
        .map(|bytes| Felt::from_bytes_be(&bytes))
        .collect::<Vec<_>>();
    if ids.len() < 2 || ids.len() > MAX_ASSETS {
        return Err(invalid("a transition needs 2..=8 assets"));
    }
    let index = |id: &Felt| {
        ids.iter()
            .position(|asset| asset == id)
            .expect("asset is listed")
    };
    Ok(Assets {
        base: markets
            .iter()
            .map(|market| index(&market.base_asset_id))
            .collect(),
        quote: markets
            .iter()
            .map(|market| index(&market.quote_asset_id))
            .collect(),
        ids,
    })
}

fn validate_markets(input: &TransitionInput) -> Result<(), ProtocolError> {
    if input.markets.is_empty() || input.markets.len() > MAX_MARKETS {
        return Err(invalid("a transition needs 1..=8 markets"));
    }
    let mut pairs = BTreeSet::new();
    for (index, market) in input.markets.iter().enumerate() {
        if index > 0 && !felt_lt(&input.markets[index - 1].pair_id, &market.pair_id) {
            return Err(invalid("markets are not in strictly increasing pair order"));
        }
        if market.pair_id == Felt::ZERO
            || market.base_asset_id == Felt::ZERO
            || market.quote_asset_id == Felt::ZERO
        {
            return Err(invalid("market ids must be nonzero"));
        }
        if market.base_asset_id == market.quote_asset_id {
            return Err(invalid("market base and quote coincide"));
        }
        if market.midpoint == 0
            || market.midpoint >= AMOUNT_BOUND
            || market.scale == 0
            || market.scale >= AMOUNT_BOUND
        {
            return Err(invalid("market midpoint or scale is out of range"));
        }
        if market.observed_at_ms == 0
            || market.observed_at_ms > input.close_time_ms
            || input.close_time_ms > market.valid_until_ms
            || market.valid_until_ms >= EXPIRY_BOUND_MS
        {
            return Err(invalid("market midpoint is not valid at the close"));
        }
        if market.fee_bps > MAX_FEE_BPS {
            return Err(invalid("market fee exceeds the maximum"));
        }
        match market.reference_methodology {
            super::calldata::REFERENCE_METHOD_DIRECT_BBO => {
                if market.derivation_base_market_id != Felt::ZERO
                    || market.derivation_quote_market_id != Felt::ZERO
                    || market.derivation_base_bid == 0
                    || market.derivation_base_bid > market.derivation_base_ask
                    || market.derivation_quote_bid != 0
                    || market.derivation_quote_ask != 0
                    || market.max_leg_skew_ms != 0
                    || market
                        .derivation_base_bid
                        .checked_add(market.derivation_base_ask)
                        .map(|sum| sum / 2)
                        != Some(market.midpoint)
                {
                    return Err(invalid("direct market has an invalid bbo derivation"));
                }
            }
            super::calldata::REFERENCE_METHOD_SYNTHETIC_CROSS_BBO => {
                if market.derivation_base_market_id == Felt::ZERO
                    || market.derivation_quote_market_id == Felt::ZERO
                    || market.derivation_base_market_id == market.derivation_quote_market_id
                    || market.max_leg_skew_ms == 0
                {
                    return Err(invalid("synthetic market has invalid reference legs"));
                }
            }
            _ => return Err(invalid("market reference methodology is unsupported")),
        }
        if !pairs.insert((
            felt_to_u256_bytes(&market.base_asset_id),
            felt_to_u256_bytes(&market.quote_asset_id),
        )) {
            return Err(invalid("two markets share an asset pair"));
        }
    }
    for market in input.markets.iter().filter(|market| {
        market.reference_methodology == super::calldata::REFERENCE_METHOD_SYNTHETIC_CROSS_BBO
    }) {
        let base = input
            .markets
            .iter()
            .find(|candidate| candidate.pair_id == market.derivation_base_market_id)
            .ok_or_else(|| invalid("synthetic base market is missing"))?;
        let quote = input
            .markets
            .iter()
            .find(|candidate| candidate.pair_id == market.derivation_quote_market_id)
            .ok_or_else(|| invalid("synthetic quote market is missing"))?;
        if base.reference_methodology != super::calldata::REFERENCE_METHOD_DIRECT_BBO
            || quote.reference_methodology != super::calldata::REFERENCE_METHOD_DIRECT_BBO
            || base.base_asset_id != market.base_asset_id
            || quote.base_asset_id != market.quote_asset_id
            || base.quote_asset_id != quote.quote_asset_id
            || base.scale != market.scale
            || quote.scale != market.scale
            || market.derivation_base_bid != base.derivation_base_bid
            || market.derivation_base_ask != base.derivation_base_ask
            || market.derivation_quote_bid != quote.derivation_base_bid
            || market.derivation_quote_ask != quote.derivation_base_ask
            || base.observed_at_ms.abs_diff(quote.observed_at_ms) > market.max_leg_skew_ms
            || market.observed_at_ms != base.observed_at_ms.min(quote.observed_at_ms)
        {
            return Err(invalid(
                "synthetic market derivation does not match its direct legs",
            ));
        }
        let (bid, ask) = crate::derive_synthetic_cross_bbo(
            market.derivation_base_bid,
            market.derivation_base_ask,
            market.derivation_quote_bid,
            market.derivation_quote_ask,
            market.scale,
        )?;
        if bid.checked_add(ask).map(|sum| sum / 2) != Some(market.midpoint) {
            return Err(invalid("synthetic market midpoint is incorrect"));
        }
    }
    Ok(())
}

/// the transition the operator proves: validates the input, clears the book and returns the new
/// state, the public values and the statement witness.
pub fn build_transition(input: &TransitionInput) -> Result<TransitionResult, ProtocolError> {
    if input.seq == 0 || input.close_time_ms == 0 || input.close_time_ms >= EXPIRY_BOUND_MS {
        return Err(invalid("transition seq and close time must be positive"));
    }
    if input.chain_context == Felt::ZERO
        || input.fee_recipient == Felt::ZERO
        || input.fee_key == Felt::ZERO
        || input.padding_seed == Felt::ZERO
        || input.objective_numeraire_asset_id == Felt::ZERO
    {
        return Err(invalid(
            "transition context, fee recipient, private seeds and numeraire must be nonzero",
        ));
    }
    validate_markets(input)?;
    let assets = market_assets(&input.markets)?;
    let market_index = |pair_id: &Felt| {
        input
            .markets
            .iter()
            .position(|market| market.pair_id == *pair_id)
    };

    let book_orders = input
        .book
        .iter()
        .map(|entry| entry.order.clone())
        .collect::<Vec<_>>();
    assert_canonical_book(&book_orders)?;
    for entry in &input.book {
        if entry.owner.digest() != entry.order.owner_digest {
            return Err(invalid("book owner preimage does not match its digest"));
        }
    }
    let prior_book_root = book_root(input.chain_context, &book_orders);

    // outcomes: unique per (seq, slot), from earlier transitions, on markets present now.
    let mut outcome_keys = BTreeSet::new();
    for outcome in &input.outcomes {
        if outcome.seq == 0 || outcome.seq >= input.seq {
            return Err(invalid("an outcome must come from an earlier transition"));
        }
        if market_index(&outcome.pair_id).is_none() {
            return Err(invalid("an outcome's market must be in the transition"));
        }
        if outcome.m1 == 0
            || outcome.m1 >= AMOUNT_BOUND
            || outcome.m1_scale == 0
            || outcome.m1_scale >= AMOUNT_BOUND
        {
            return Err(invalid("outcome price is out of range"));
        }
        if outcome.consumed_base >= AMOUNT_BOUND || outcome.pool_quote >= AMOUNT_BOUND {
            return Err(invalid("outcome amounts are out of range"));
        }
        if !outcome_keys.insert((
            outcome.seq,
            felt_to_u256_bytes(&outcome.pair_id),
            outcome.sell,
        )) {
            return Err(invalid("duplicate outcome"));
        }
    }

    // new orders: valid terms, a market now, fully funded and authorized.
    let book_ids = input
        .book
        .iter()
        .map(|entry| entry.order.order_id)
        .collect::<BTreeSet<_>>();
    let mut new_ids = BTreeSet::new();
    let mut nullifier_set = BTreeSet::new();
    for new_order in &input.new_orders {
        let terms = &new_order.terms;
        terms.validate()?;
        if input.close_time_ms >= terms.expiry_ms {
            return Err(invalid("a new order is already expired"));
        }
        if terms.expiry_ms
            > input
                .close_time_ms
                .checked_add(MAX_ORDER_LIFETIME_MS)
                .ok_or_else(|| invalid("the order lifetime overflows"))?
        {
            return Err(invalid("a new order expires too far after admission"));
        }
        let Some(market) = market_index(&terms.pair_id) else {
            return Err(invalid("a new order's market must be in the transition"));
        };
        let order_id = terms.order_id();
        if book_ids.contains(&order_id) || !new_ids.insert(order_id) {
            return Err(invalid("a new order is already in the book"));
        }
        if new_order.funding.is_empty() || new_order.funding.len() > MAX_FUNDING_NOTES {
            return Err(invalid("an order is funded by 1..=4 notes"));
        }
        let input_asset = if terms.sell {
            input.markets[market].base_asset_id
        } else {
            input.markets[market].quote_asset_id
        };
        let spend_authority = new_order.funding[0].note.spend_authority;
        let mut total = 0_u128;
        for funding in &new_order.funding {
            let note = &funding.note;
            if note.asset_id != input_asset {
                return Err(invalid("a funding note is not in the order's input asset"));
            }
            if note.spend_authority != spend_authority {
                return Err(invalid("funding notes must share one spend authority"));
            }
            if note.amount == 0 || note.nonce == 0 || note.blinding == Felt::ZERO {
                return Err(invalid("a funding note is malformed"));
            }
            total = total
                .checked_add(note.amount)
                .ok_or_else(|| invalid("funding overflows"))?;
            if input.note_root == Felt::ZERO
                || funding.membership.root(note.output_leaf())? != input.note_root
            {
                return Err(invalid("a funding note is not in the note root"));
            }
            if !nullifier_set.insert(note.nullifier()) {
                return Err(invalid("a funding note is spent twice"));
            }
        }
        let quote_value = mul_div_ceil(terms.amount, terms.limit, input.markets[market].scale);
        let required_funding = if terms.sell {
            terms.amount
        } else {
            quote_value
        };
        if total > super::MAX_ORDER_AMOUNT
            || total < required_funding
            || quote_value < input.markets[market].min_order_quote_amount
        {
            return Err(invalid("order funding or value is out of range"));
        }
        if !verify_message(
            &spend_authority,
            &new_order.authorization_message(input.chain_context),
            &new_order.authorization,
        ) {
            return Err(invalid("order authorization signature is invalid"));
        }
    }
    if input.new_orders.is_empty() != (input.note_root == Felt::ZERO) {
        return Err(invalid(
            "the note root is set exactly when orders are admitted",
        ));
    }

    let cancellations = input
        .cancellations
        .iter()
        .map(|cancellation| (cancellation.order_id, cancellation.signature))
        .collect::<BTreeMap<_, _>>();
    let recovered = input
        .recovered_order_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if recovered.len() != input.recovered_order_ids.len() {
        return Err(invalid("duplicate recovered order"));
    }
    let mut deferred_cancellations = Vec::new();

    // the stream: book groups with this transition's new orders appended to their group.
    let mut groups: Vec<Group> = Vec::new();
    let mut group_keys = Vec::new();
    for entry in &input.book {
        if groups.last().map(|group| (group.pair_id, group.sell)) != Some(entry.order.group()) {
            groups.push(Group {
                pair_id: entry.order.pair_id,
                sell: entry.order.sell,
                market: market_index(&entry.order.pair_id),
                existing: 0,
                orders: Vec::new(),
            });
            group_keys.push(entry.order.group());
        }
        let group = groups.last_mut().expect("group was pushed");
        group.existing += 1;
        group.orders.push(stream_order(
            entry.order.clone(),
            entry.owner.clone(),
            true,
            None,
        ));
    }
    for new_order in &input.new_orders {
        let key = (new_order.terms.pair_id, new_order.terms.sell);
        let position = match group_keys.iter().position(|existing| *existing == key) {
            Some(position) => position,
            None => {
                let position = group_keys
                    .iter()
                    .position(|existing| group_lt(&key, existing))
                    .unwrap_or(group_keys.len());
                group_keys.insert(position, key);
                groups.insert(
                    position,
                    Group {
                        pair_id: key.0,
                        sell: key.1,
                        market: market_index(&key.0),
                        existing: 0,
                        orders: Vec::new(),
                    },
                );
                position
            }
        };
        let order = BookOrder::admitted(&new_order.terms, new_order.funding_total());
        groups[position].orders.push(stream_order(
            order,
            new_order.terms.owner.clone(),
            false,
            Some(new_order.clone()),
        ));
    }

    // 1. external outcomes, allocated greedily in book order within their slot.
    let mut outcome_remaining = input
        .outcomes
        .iter()
        .map(|outcome| outcome.consumed_base)
        .collect::<Vec<_>>();
    let mut outcome_user_quote = vec![0_u128; input.outcomes.len()];
    for group in &mut groups {
        for stream in &mut group.orders {
            if stream.order.reserved == 0 {
                continue;
            }
            let Some(index) = input.outcomes.iter().position(|outcome| {
                outcome.seq == stream.order.reserved_seq
                    && outcome.pair_id == group.pair_id
                    && outcome.sell == group.sell
            }) else {
                continue;
            };
            let outcome = &input.outcomes[index];
            let consumed = stream.order.reserved.min(outcome_remaining[index]);
            outcome_remaining[index] -= consumed;
            let quote = if group.sell {
                mul_div_floor(consumed, outcome.m1, outcome.m1_scale)
            } else {
                mul_div_ceil(consumed, outcome.m1, outcome.m1_scale)
            };
            stream.outcome = Some(index);
            stream.external_base = consumed;
            stream.external_quote = quote;
            stream.order.remaining -= consumed;
            if group.sell {
                stream.order.funding -= consumed;
            } else {
                stream.order.funding = stream
                    .order
                    .funding
                    .checked_sub(quote)
                    .ok_or_else(|| invalid("an external buy exceeds its funding"))?;
            }
            outcome_user_quote[index] += quote;
            stream.order.reserved = 0;
            stream.order.reserved_offset = 0;
            stream.order.reserved_seq = 0;
        }
    }
    if outcome_remaining.iter().any(|remaining| *remaining != 0) {
        return Err(invalid(
            "an outcome is not fully allocated to its reservations",
        ));
    }

    // 2. cancellations and expiry, for unreserved orders on a market present now.
    for group in &mut groups {
        for stream in &mut group.orders {
            if !stream.existing {
                continue;
            }
            let removable = group.market.is_some() && stream.order.reserved == 0;
            if recovered.contains(&stream.order.order_id) {
                if !removable {
                    return Err(invalid("a recovered order is not ready to retire"));
                }
                stream.removal = Some(Removal::Recovered);
            } else if let Some(signature) = cancellations.get(&stream.order.order_id) {
                if !removable {
                    deferred_cancellations.push(stream.order.order_id);
                    continue;
                }
                if !verify_message(
                    &stream.owner.cancel_authority,
                    &cancel_message(input.chain_context, stream.order.order_id),
                    signature,
                ) {
                    return Err(invalid("cancellation signature is invalid"));
                }
                stream.removal = Some(Removal::Cancelled);
                stream.cancel_signature = Some(*signature);
            } else if removable && input.close_time_ms >= stream.order.expiry_ms {
                stream.removal = Some(Removal::Expired);
            }
        }
    }
    let known_ids = groups
        .iter()
        .flat_map(|group| group.orders.iter().map(|stream| stream.order.order_id))
        .collect::<BTreeSet<_>>();
    if cancellations
        .keys()
        .any(|order_id| !known_ids.contains(order_id))
    {
        return Err(invalid("a cancellation names no book order"));
    }
    if recovered
        .iter()
        .any(|order_id| !known_ids.contains(order_id))
    {
        return Err(invalid("a recovered order names no book order"));
    }

    // 3-4. the global clearing over participating orders, certified within tolerance.
    let weights = usdc_clearing_weights(
        &assets.ids,
        input.objective_numeraire_asset_id,
        &input
            .markets
            .iter()
            .enumerate()
            .map(|(index, market)| WeightMarket {
                base_asset: assets.base[index],
                quote_asset: assets.quote[index],
                midpoint: market.midpoint,
                scale: market.scale,
            })
            .collect::<Vec<_>>(),
    )?;
    let clearing_markets = input
        .markets
        .iter()
        .enumerate()
        .map(|(index, market)| ClearingMarket {
            base_asset: assets.base[index],
            quote_asset: assets.quote[index],
            midpoint: market.midpoint,
            scale: market.scale,
        })
        .collect::<Vec<_>>();
    let mut participants = Vec::new();
    let mut clearing_orders = Vec::new();
    let mut order_keys = Vec::new();
    for (group_index, group) in groups.iter_mut().enumerate() {
        let Some(market) = group.market else { continue };
        let market_data = &input.markets[market];
        for (order_index, stream) in group.orders.iter_mut().enumerate() {
            if stream.removal.is_some() || stream.order.reserved != 0 {
                continue;
            }
            let eligible = if group.sell {
                stream.order.limit <= market_data.midpoint
            } else {
                market_data.midpoint <= stream.order.limit
            };
            stream.clearing_capacity = if !eligible {
                0
            } else if group.sell {
                stream.order.remaining.min(stream.order.funding)
            } else {
                stream.order.remaining.min(
                    (BigUint::from(stream.order.funding) * BigUint::from(market_data.scale)
                        / BigUint::from(market_data.midpoint))
                    .to_u128()
                    .unwrap_or(u128::MAX),
                )
            };
            participants.push((group_index, order_index));
            clearing_orders.push(ClearingOrder {
                market,
                sell: group.sell,
                capacity: stream.clearing_capacity,
            });
            order_keys.push(felt_to_u256_bytes(&stream.order.order_id));
        }
    }
    if clearing_orders.len() > crate::exact_clearing::MAX_CLEARING_ORDERS {
        return Err(invalid("a transition crosses at most 1024 orders"));
    }
    let prices = if clearing_orders.iter().any(|order| order.capacity > 0) {
        let clearing = solve_canonical_clearing(
            &ClearingInstance {
                asset_weights: weights.weights.clone(),
                markets: clearing_markets.clone(),
                orders: clearing_orders.clone(),
            },
            &assets
                .ids
                .iter()
                .map(felt_to_u256_bytes)
                .collect::<Vec<_>>(),
            &order_keys,
        )?;
        for ((group_index, order_index), (fill, quote)) in participants
            .iter()
            .zip(clearing.fills.iter().zip(&clearing.quote_amounts))
        {
            let stream = &mut groups[*group_index].orders[*order_index];
            stream.fill = *fill;
            stream.quote = *quote;
        }
        clearing.certificate.asset_prices
    } else {
        vec![0; assets.ids.len()]
    };

    // 5. settle: consume funding, reserve residuals, proceeds, fees and refunds.
    let mut fee_totals = vec![0_u128; assets.ids.len()];
    let mut asset_in = vec![0_u128; assets.ids.len()];
    let mut asset_out = vec![0_u128; assets.ids.len()];
    let mut capacities = Vec::new();
    for group in &mut groups {
        let Some(market) = group.market else { continue };
        let market_data = &input.markets[market];
        let (base, quote) = (assets.base[market], assets.quote[market]);
        for stream in group.orders.iter_mut() {
            if stream.fill > 0 {
                let consumed = if group.sell {
                    stream.fill
                } else {
                    stream.quote
                };
                stream.order.remaining -= stream.fill;
                stream.order.funding -= consumed;
                if group.sell {
                    asset_in[base] = asset_in[base]
                        .checked_add(stream.fill)
                        .ok_or_else(|| invalid("asset input aggregate overflows"))?;
                    asset_out[quote] = asset_out[quote]
                        .checked_add(stream.quote)
                        .ok_or_else(|| invalid("asset output aggregate overflows"))?;
                } else {
                    asset_in[quote] = asset_in[quote]
                        .checked_add(stream.quote)
                        .ok_or_else(|| invalid("asset input aggregate overflows"))?;
                    asset_out[base] = asset_out[base]
                        .checked_add(stream.fill)
                        .ok_or_else(|| invalid("asset output aggregate overflows"))?;
                }
            }
        }
        // the slot's external capacity: every reservable residual at the slot's bound.
        let reservable = |stream: &StreamOrder| {
            stream.order.external
                && stream.removal.is_none()
                && stream.order.reserved == 0
                && stream.order.remaining != 0
                && if group.sell {
                    stream.order.funding != 0
                } else {
                    BigUint::from(stream.order.funding) * BigUint::from(market_data.scale)
                        >= BigUint::from(stream.order.limit)
                }
        };
        let bound = group
            .orders
            .iter()
            .filter(|stream| reservable(stream))
            .map(|stream| stream.order.limit)
            .reduce(|left, right| {
                if group.sell {
                    left.max(right)
                } else {
                    left.min(right)
                }
            });
        let mut total = 0_u128;
        if let Some(bound) = bound {
            for stream in group.orders.iter_mut() {
                if !reservable(stream) {
                    continue;
                }
                let available = if group.sell {
                    stream.order.funding
                } else {
                    mul_div_floor(stream.order.funding, market_data.scale, bound)
                };
                stream.external_amount = available.min(stream.order.remaining);
                stream.order.reserved_offset = total;
                total = total
                    .checked_add(stream.external_amount)
                    .ok_or_else(|| invalid("external capacity aggregate overflows"))?;
            }
            capacities.push(Capacity {
                pair_id: group.pair_id,
                sell: group.sell,
                bound,
                total,
            });
        }
        for stream in group.orders.iter_mut() {
            let output_asset = if group.sell { quote } else { base };
            let internal = if group.sell {
                stream.quote
            } else {
                stream.fill
            };
            let external = if group.sell {
                stream.external_quote
            } else {
                stream.external_base
            };
            stream.fee = fee_amount(internal, market_data.fee_bps);
            let recovered = stream.removal == Some(Removal::Recovered);
            let unsettled_external = if recovered { 0 } else { external };
            stream.external_fee = fee_amount(unsettled_external, market_data.fee_bps);
            let gross = internal + unsettled_external;
            let fee = stream.fee + stream.external_fee;
            fee_totals[output_asset] = fee_totals[output_asset]
                .checked_add(fee)
                .ok_or_else(|| invalid("fee aggregate overflows"))?;
            stream.proceeds = gross - fee;
            if stream.external_amount > 0 {
                stream.order.reserved = stream.external_amount;
                stream.order.reserved_seq = input.seq;
            }
            if stream.order.reserved == 0
                && stream.removal.is_none()
                && (stream.order.remaining == 0 || stream.order.funding == 0)
            {
                stream.removal = Some(Removal::Completed);
            }
            if stream.removal.is_some() {
                stream.refund = stream.order.funding;
            }
        }
    }
    // outcome rounding favours the pool: sellers' quote is floored below what the pool received
    // and buyers pay at least what the pool paid. the dust joins the fees.
    for (index, outcome) in input.outcomes.iter().enumerate() {
        let market = market_index(&outcome.pair_id).expect("checked above");
        let quote = assets.quote[market];
        let dust = if outcome.sell {
            outcome.pool_quote.checked_sub(outcome_user_quote[index])
        } else {
            outcome_user_quote[index].checked_sub(outcome.pool_quote)
        }
        .ok_or_else(|| invalid("an outcome's quote does not cover its allocation"))?;
        fee_totals[quote] = fee_totals[quote]
            .checked_add(dust)
            .ok_or_else(|| invalid("outcome dust aggregate overflows"))?;
    }
    for asset in 0..assets.ids.len() {
        let dust = asset_in[asset]
            .checked_sub(asset_out[asset])
            .ok_or_else(|| invalid("the clearing does not conserve an asset"))?;
        fee_totals[asset] = fee_totals[asset]
            .checked_add(dust)
            .ok_or_else(|| invalid("conservation dust aggregate overflows"))?;
    }

    // 6. outputs, the new book and the public lists.
    let mut outputs = Vec::new();
    let mut residual_outputs = Vec::new();
    let mut records = Vec::new();
    let mut new_book = Vec::new();
    let mut reports = Vec::new();
    let mut nullifiers = Vec::new();
    let mut retired_nullifiers = Vec::new();
    for group in &mut groups {
        for stream in &mut group.orders {
            if let Some(new_order) = &stream.new_order {
                nullifiers.extend(
                    new_order
                        .funding
                        .iter()
                        .map(|funding| funding.note.nullifier()),
                );
            }
            let market = group.market;
            let (output_asset, input_asset) = match market {
                Some(market) if group.sell => (
                    input.markets[market].quote_asset_id,
                    input.markets[market].base_asset_id,
                ),
                Some(market) => (
                    input.markets[market].base_asset_id,
                    input.markets[market].quote_asset_id,
                ),
                None => (Felt::ZERO, Felt::ZERO),
            };
            let state_changed = stream
                .prior
                .as_ref()
                .is_some_and(|prior| !same_persisted_state(prior, &stream.order));
            if stream.existing && (state_changed || stream.removal.is_some()) {
                let prior = stream
                    .prior
                    .as_ref()
                    .expect("existing order has prior state");
                let old = ResidualNote::from_order(
                    input.chain_context,
                    input_asset,
                    prior,
                    &stream.owner,
                    prior.residual_generation,
                );
                if !old.matches_order(prior) {
                    return Err(invalid("book residual authority does not match its order"));
                }
                if stream.removal == Some(Removal::Recovered) {
                    retired_nullifiers.push(old.nullifier());
                } else {
                    nullifiers.push(old.nullifier());
                }
            }
            for (kind, asset_id, amount) in [
                (OutputKind::Proceeds, output_asset, stream.proceeds),
                (OutputKind::Refund, input_asset, stream.refund),
            ] {
                if amount == 0 || stream.removal == Some(Removal::Recovered) {
                    continue;
                }
                let note = order_output_note(
                    &stream.owner,
                    stream.order.order_id,
                    asset_id,
                    amount,
                    input.seq,
                    kind,
                );
                let [enc_remaining, enc_reserved, enc_reserved_offset] =
                    output_aux_blindings(note.blinding);
                records.push(OutputRecord {
                    leaf: note.output_leaf(),
                    enc: felt_u128(amount) + note.blinding,
                    enc_remaining,
                    enc_reserved,
                    enc_reserved_offset,
                });
                outputs.push(OutputNote {
                    order_id: stream.order.order_id,
                    kind: kind.as_u64(),
                    index: records.len() - 1,
                    note,
                });
            }
            if stream.removal.is_none() {
                if !stream.existing || state_changed {
                    let note = ResidualNote::from_order(
                        input.chain_context,
                        input_asset,
                        &stream.order,
                        &stream.owner,
                        input.seq,
                    );
                    stream.order.residual_commitment = note.commitment();
                    stream.order.residual_generation = input.seq;
                    let [remaining_blinding, reserved_blinding, offset_blinding] =
                        output_aux_blindings(note.blinding);
                    records.push(OutputRecord {
                        leaf: note.output_leaf(),
                        enc: felt_u128(note.funding) + note.blinding,
                        enc_remaining: felt_u128(note.remaining) + remaining_blinding,
                        enc_reserved: felt_u128(note.reserved) + reserved_blinding,
                        enc_reserved_offset: felt_u128(note.reserved_offset) + offset_blinding,
                    });
                    residual_outputs.push(ResidualOutput {
                        order_id: stream.order.order_id,
                        index: records.len() - 1,
                        note,
                    });
                }
                new_book.push(BookEntry {
                    order: stream.order.clone(),
                    owner: stream.owner.clone(),
                });
            }
            reports.push(OrderReport {
                order_id: stream.order.order_id,
                admitted: !stream.existing,
                external_base: stream.external_base,
                external_quote: stream.external_quote,
                fill_base: stream.fill,
                fill_quote: stream.quote,
                fee: stream.fee + stream.external_fee,
                proceeds: stream.proceeds,
                refund: stream.refund,
                reserved: stream.order.reserved,
                removal: stream.removal.clone(),
            });
        }
    }
    for (asset, total) in fee_totals.iter().enumerate() {
        if *total == 0 {
            continue;
        }
        let note = fee_output_note(
            input.fee_recipient,
            input.fee_key,
            assets.ids[asset],
            *total,
            input.seq,
        );
        let [enc_remaining, enc_reserved, enc_reserved_offset] =
            output_aux_blindings(note.blinding);
        records.push(OutputRecord {
            leaf: note.output_leaf(),
            enc: felt_u128(*total) + note.blinding,
            enc_remaining,
            enc_reserved,
            enc_reserved_offset,
        });
        outputs.push(OutputNote {
            order_id: Felt::ZERO,
            kind: OUTPUT_KIND_FEE,
            index: records.len() - 1,
            note,
        });
    }
    let real_outputs = records.len();
    for index in real_outputs..padded_len(real_outputs, MIN_OUTPUT_BUCKET) {
        let [leaf, enc, enc_remaining, enc_reserved, enc_reserved_offset] =
            output_padding_record(input.padding_seed, index);
        records.push(OutputRecord {
            leaf,
            enc,
            enc_remaining,
            enc_reserved,
            enc_reserved_offset,
        });
    }
    let real_nullifiers = nullifiers.len();
    for index in real_nullifiers..padded_len(real_nullifiers, MIN_NULLIFIER_BUCKET) {
        nullifiers.push(nullifier_padding_value(input.padding_seed, index));
    }
    if new_book.len() > MAX_BOOK_ORDERS {
        return Err(invalid("the book exceeds its maximum size"));
    }
    let new_book_orders = new_book
        .iter()
        .map(|entry| entry.order.clone())
        .collect::<Vec<_>>();
    let leaves = records.iter().map(|record| record.leaf).collect::<Vec<_>>();
    let mut public = TransitionPublic {
        chain_context: input.chain_context,
        seq: input.seq,
        close_time_ms: input.close_time_ms,
        prior_book_root,
        new_book_root: book_root(input.chain_context, &new_book_orders),
        note_root: input.note_root,
        markets: input.markets.clone(),
        markets_commitment: markets_commitment(
            input.chain_context,
            input.seq,
            input.close_time_ms,
            input.objective_numeraire_asset_id,
            &input.markets,
        ),
        outcomes: input.outcomes.clone(),
        outcomes_commitment: outcomes_commitment(&input.outcomes),
        capacity_commitment: capacity_commitment(input.chain_context, &capacities),
        capacities,
        nullifiers_commitment: nullifiers_commitment(input.chain_context, &nullifiers),
        nullifiers,
        retired_nullifiers_commitment: retired_nullifiers_commitment(
            input.chain_context,
            &retired_nullifiers,
        ),
        retired_nullifiers,
        outputs_commitment: outputs_commitment(input.chain_context, &records),
        output_root: output_tree_root(&leaves),
        output_records: records,
        fee_recipient: input.fee_recipient,
        commitment: Felt::ZERO,
    };
    public.commitment = public.transition_commitment();

    let (witness, layout) = serialize_witness(input, &assets, &weights, &prices, &groups, &public);
    Ok(TransitionResult {
        public,
        new_book,
        outputs,
        residual_outputs,
        reports,
        deferred_cancellations,
        witness,
        layout,
    })
}

fn stream_order(
    order: BookOrder,
    owner: OrderOwner,
    existing: bool,
    new_order: Option<NewOrder>,
) -> StreamOrder {
    StreamOrder {
        prior: existing.then(|| order.clone()),
        order,
        owner,
        existing,
        new_order,
        outcome: None,
        external_base: 0,
        external_quote: 0,
        external_fee: 0,
        removal: None,
        cancel_signature: None,
        fill: 0,
        quote: 0,
        clearing_capacity: 0,
        external_amount: 0,
        fee: 0,
        proceeds: 0,
        refund: 0,
    }
}

fn same_persisted_state(left: &BookOrder, right: &BookOrder) -> bool {
    left.pair_id == right.pair_id
        && left.sell == right.sell
        && left.external == right.external
        && left.remaining == right.remaining
        && left.limit == right.limit
        && left.funding == right.funding
        && left.reserved == right.reserved
        && left.reserved_offset == right.reserved_offset
        && left.reserved_seq == right.reserved_seq
        && left.expiry_ms == right.expiry_ms
        && left.owner_digest == right.owner_digest
        && left.order_id == right.order_id
}

/// the felt input of the cairo transition statement (`stwo_statement/src/exchange/transition.cairo`).
fn serialize_witness(
    input: &TransitionInput,
    assets: &Assets,
    weights: &crate::exact_clearing::CanonicalWeights,
    prices: &[u128],
    groups: &[Group],
    public: &TransitionPublic,
) -> (Vec<Felt>, WitnessLayout) {
    let mut layout = WitnessLayout::default();
    let mut data = vec![
        felt_u64(STATEMENT_TYPE_TRANSITION),
        input.chain_context,
        felt_u64(u64::from(input.seq)),
        felt_u64(input.close_time_ms),
        input.fee_recipient,
        input.fee_key,
        input.padding_seed,
        input.note_root,
        public.prior_book_root,
        public.output_root,
    ];
    data.push(felt_u64(assets.ids.len() as u64));
    for (index, asset) in assets.ids.iter().enumerate() {
        data.extend_from_slice(&[
            *asset,
            felt_u128(weights.weights[index]),
            felt_u128(prices[index]),
        ]);
    }
    data.push(input.objective_numeraire_asset_id);
    data.push(felt_u64(input.markets.len() as u64));
    for (index, market) in input.markets.iter().enumerate() {
        data.extend_from_slice(&[
            market.pair_id,
            felt_u64(assets.base[index] as u64),
            felt_u64(assets.quote[index] as u64),
            felt_u128(market.midpoint),
            felt_u128(market.scale),
            felt_u64(market.observed_at_ms),
            felt_u64(market.valid_until_ms),
            felt_u128(market.fee_bps),
            felt_u128(market.min_order_quote_amount),
            felt_u64(u64::from(market.reference_methodology)),
            market.derivation_base_market_id,
            market.derivation_quote_market_id,
            felt_u128(market.derivation_base_bid),
            felt_u128(market.derivation_base_ask),
            felt_u128(market.derivation_quote_bid),
            felt_u128(market.derivation_quote_ask),
            felt_u64(market.max_leg_skew_ms),
        ]);
    }
    for index in 0..assets.ids.len() {
        let (numerator, denominator) = weights.values[index];
        data.extend_from_slice(&[
            felt_u128(numerator),
            felt_u128(denominator),
            felt_u64(weights.roots[index] as u64),
            felt_u64(u64::from(weights.depths[index])),
            felt_u64(weights.parent_markets[index].unwrap_or(0) as u64),
            felt_u64(weights.maxima[index] as u64),
        ]);
    }
    data.push(felt_u64(input.outcomes.len() as u64));
    for outcome in &input.outcomes {
        data.extend_from_slice(&outcome.fields());
    }
    // the claimed capacity of every slot, zero where nothing is reserved.
    for market in &input.markets {
        for sell in [false, true] {
            match public
                .capacities
                .iter()
                .find(|capacity| capacity.pair_id == market.pair_id && capacity.sell == sell)
            {
                Some(capacity) => {
                    data.extend_from_slice(&[felt_u128(capacity.bound), felt_u128(capacity.total)])
                }
                None => data.extend_from_slice(&[Felt::ZERO, Felt::ZERO]),
            }
        }
    }
    data.push(felt_u64(groups.len() as u64));
    for group in groups {
        layout.groups.push(data.len());
        data.extend_from_slice(&[
            group.pair_id,
            felt_bool(group.sell),
            felt_u64(group.market.map_or(0, |market| market as u64 + 1)),
            felt_u64(group.existing as u64),
            felt_u64((group.orders.len() - group.existing) as u64),
        ]);
        for stream in &group.orders {
            let mut order_layout = OrderLayout {
                order_id: stream.order.order_id,
                existing: stream.existing,
                start: data.len(),
                ..OrderLayout::default()
            };
            if stream.existing {
                serialize_existing(&mut data, stream, &mut order_layout);
            } else {
                serialize_new(&mut data, stream, &mut order_layout);
            }
            layout.orders.push(order_layout);
        }
    }
    (data, layout)
}

fn serialize_existing(data: &mut Vec<Felt>, stream: &StreamOrder, layout: &mut OrderLayout) {
    // a fixed record the statement reads in one step, then the owner when needed.
    let order = stream
        .prior
        .as_ref()
        .expect("existing orders come from the book");
    data.extend_from_slice(&[
        felt_bool(order.external),
        felt_u128(order.remaining),
        felt_u128(order.limit),
        felt_u128(order.funding),
        felt_u128(order.reserved),
        felt_u128(order.reserved_offset),
        felt_u64(u64::from(order.reserved_seq)),
        felt_u64(order.expiry_ms),
        order.owner_digest,
        order.order_id,
        order.residual_commitment,
        felt_u64(u64::from(order.residual_generation)),
    ]);
    layout.outcome = Some(data.len());
    data.push(felt_u64(stream.outcome.map_or(0, |index| index as u64 + 1)));
    layout.removal = Some(data.len());
    match (&stream.removal, &stream.cancel_signature) {
        (Some(Removal::Cancelled), Some(signature)) => {
            data.extend_from_slice(&[Felt::ONE, signature.r, signature.s])
        }
        (Some(Removal::Expired), _) => data.extend_from_slice(&[Felt::TWO, Felt::ZERO, Felt::ZERO]),
        (Some(Removal::Recovered), _) => {
            data.extend_from_slice(&[felt_u64(3), Felt::ZERO, Felt::ZERO])
        }
        _ => data.extend_from_slice(&[Felt::ZERO, Felt::ZERO, Felt::ZERO]),
    }
    layout.allocation = data.len();
    serialize_allocation(data, stream);
    let owner_needed = stream.proceeds > 0
        || stream.refund > 0
        || stream.cancel_signature.is_some()
        || stream.removal == Some(Removal::Recovered)
        || stream
            .prior
            .as_ref()
            .is_some_and(|prior| !same_persisted_state(prior, &stream.order));
    data.push(felt_bool(owner_needed));
    if owner_needed {
        data.extend_from_slice(&stream.owner.fields());
    }
}

fn serialize_new(data: &mut Vec<Felt>, stream: &StreamOrder, layout: &mut OrderLayout) {
    let new_order = stream
        .new_order
        .as_ref()
        .expect("new orders carry their admission");
    let terms = &new_order.terms;
    data.extend_from_slice(&[
        felt_bool(terms.external),
        felt_u128(terms.amount),
        felt_u128(terms.limit),
        felt_u64(terms.expiry_ms),
    ]);
    data.extend_from_slice(&terms.owner.fields());
    data.push(felt_u64(new_order.funding.len() as u64));
    layout.funding_notes = new_order.funding.len() as u64;
    for funding in &new_order.funding {
        let note = &funding.note;
        data.extend_from_slice(&[
            felt_u128(note.amount),
            note.owner_public_key,
            note.spend_authority,
            note.withdraw_authority,
            note.blinding,
            felt_u64(note.nonce),
            note.metadata_commitment,
            felt_u64(funding.membership.subtree_path.len() as u64),
        ]);
        for (sibling, right) in funding
            .membership
            .subtree_path
            .iter()
            .zip(&funding.membership.subtree_directions)
        {
            data.push(*sibling);
            data.push(felt_bool(*right));
        }
        layout.membership_path_elements += funding.membership.subtree_path.len() as u64;
        for (sibling, right) in funding
            .membership
            .accumulator_path
            .iter()
            .zip(&funding.membership.accumulator_directions)
        {
            data.push(*sibling);
            data.push(felt_bool(*right));
        }
        layout.membership_path_elements += funding.membership.accumulator_path.len() as u64;
    }
    layout.authorization = Some(data.len());
    data.extend_from_slice(&[new_order.authorization.r, new_order.authorization.s]);
    layout.allocation = data.len();
    serialize_allocation(data, stream);
}

fn serialize_allocation(data: &mut Vec<Felt>, stream: &StreamOrder) {
    data.extend_from_slice(&[
        felt_u128(stream.fill),
        felt_u128(stream.quote),
        felt_u128(stream.clearing_capacity),
        felt_u128(stream.external_amount),
    ]);
}

/// The shape that drives a transition statement's Cairo steps. This deliberately models only the
/// statement and is an early trimming guard, not a full SNIP-36/STWO capacity guarantee; release
/// admission must also use measured virtual-OS, account, builtin and component-domain evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepShape {
    pub markets: u64,
    pub resting: u64,
    pub admissions: u64,
    pub crossing: u64,
    pub nullifiers: u64,
    pub retired_nullifiers: u64,
    pub outputs: u64,
    pub funding_notes: u64,
    pub membership_path_elements: u64,
}

impl StepShape {
    pub fn of(result: &TransitionResult) -> Self {
        let admissions = result
            .layout
            .orders
            .iter()
            .filter(|order| !order.existing)
            .count() as u64;
        Self {
            markets: result.public.markets.len() as u64,
            resting: result.layout.orders.len() as u64 - admissions,
            admissions,
            crossing: result
                .reports
                .iter()
                .filter(|report| report.fill_base != 0)
                .count() as u64,
            nullifiers: result.public.nullifiers.len() as u64,
            retired_nullifiers: result.public.retired_nullifiers.len() as u64,
            outputs: result.public.output_records.len() as u64,
            funding_notes: result
                .layout
                .orders
                .iter()
                .map(|order| order.funding_notes)
                .sum(),
            membership_path_elements: result
                .layout
                .orders
                .iter()
                .map(|order| order.membership_path_elements)
                .sum(),
        }
    }

    /// an upper bound on the statement's cairo steps, fitted to the differential vectors (whose
    /// runner fails if a measured count ever exceeds it), so the operator can keep every
    /// transition inside its statement-step guard before proving it. A full-proof capacity
    /// profile remains mandatory because this estimate excludes SNOS and component domains.
    pub fn estimated_steps(&self) -> u64 {
        STEPS_FIXED
            + STEPS_PER_MARKET * self.markets
            + STEPS_PER_RESTING * self.resting
            + STEPS_PER_ADMISSION * self.admissions
            + STEPS_PER_ORDER_ID * (self.resting + self.admissions)
            + STEPS_PER_CROSSING * self.crossing
            + STEPS_PER_NULLIFIER * self.nullifiers
            + STEPS_PER_NULLIFIER * self.retired_nullifiers
            + STEPS_PER_OUTPUT * self.outputs
            + STEPS_PER_FUNDING_NOTE * self.funding_notes
            + STEPS_PER_MEMBERSHIP_PATH_ELEMENT * self.membership_path_elements
    }

    /// the largest book that stays within `budget` steps even when every order crosses at once
    /// across the most markets and assets a transition may carry.
    pub fn max_book_orders(budget: u64) -> usize {
        let worst = |orders: usize| Self {
            markets: MAX_MARKETS as u64,
            resting: orders as u64,
            admissions: 0,
            crossing: orders as u64,
            nullifiers: MIN_NULLIFIER_BUCKET as u64,
            retired_nullifiers: 0,
            outputs: padded_len(2 * orders + MAX_ASSETS, MIN_OUTPUT_BUCKET) as u64,
            funding_notes: 0,
            membership_path_elements: 0,
        };
        (0..=MAX_BOOK_ORDERS)
            .rev()
            .find(|orders| worst(*orders).estimated_steps() <= budget)
            .unwrap_or(0)
    }

    /// the largest all-crossing admission batch that fits even when every order spends the
    /// maximum four notes and every membership path has its full protocol depth.
    pub fn max_admissions(budget: u64) -> usize {
        let worst = |orders: usize| Self {
            markets: MAX_MARKETS as u64,
            admissions: orders as u64,
            crossing: orders as u64,
            nullifiers: (MAX_FUNDING_NOTES * orders).max(MIN_NULLIFIER_BUCKET) as u64,
            outputs: padded_len(2 * orders + MAX_ASSETS, MIN_OUTPUT_BUCKET) as u64,
            funding_notes: (MAX_FUNDING_NOTES * orders) as u64,
            membership_path_elements: (MAX_FUNDING_NOTES
                * orders
                * (NOTE_ACCUMULATOR_DEPTH + MAX_OUTPUT_SUBTREE_DEPTH))
                as u64,
            ..Default::default()
        };
        (0..=MAX_BOOK_ORDERS)
            .rev()
            .find(|orders| worst(*orders).estimated_steps() <= budget)
            .unwrap_or(0)
    }
}

// fitted to the vectors with a few percent of headroom. order ids have a separate cost because
// the statement checks their uniqueness for both resting orders and admissions.
const STEPS_FIXED: u64 = 3_000;
const STEPS_PER_MARKET: u64 = 5_500;
const STEPS_PER_RESTING: u64 = 580;
const STEPS_PER_ADMISSION: u64 = 2_000;
const STEPS_PER_ORDER_ID: u64 = 52;
const STEPS_PER_CROSSING: u64 = 520;
const STEPS_PER_NULLIFIER: u64 = 64;
const STEPS_PER_OUTPUT: u64 = 100;
const STEPS_PER_FUNDING_NOTE: u64 = 500;
const STEPS_PER_MEMBERSHIP_PATH_ELEMENT: u64 = 15;

/// the certificate's grid denominator, re-exported for the statement tests.
pub const PRICE_DENOMINATOR: u128 = CLEARING_PRICE_DENOMINATOR;

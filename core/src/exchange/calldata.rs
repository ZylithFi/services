//! the exchange contract's calldata: what the operator submits for a transition and a user for a
//! withdrawal, in the contract's serde layout, and the attested midpoints it verifies.

use serde::{Deserialize, Serialize};
use starknet_crypto::{Felt, poseidon_hash, poseidon_hash_many};

use super::model::*;
use super::transition::{Market, TransitionPublic};
use super::withdrawal::WithdrawalPublic;
use crate::{ProtocolError, ReferencePriceDerivation};

pub const REFERENCE_PRICE_ATTESTATION_DOMAIN_HEX: &str =
    "0x79508ce25b318644e4a7aea66c1edc2342856b522eb62152b5c118fc1ef3e67";
pub const REFERENCE_PRICE_BATCH_DOMAIN: &str = "zylith_price_batch_v1";
pub const TRANSITION_MESSAGE_DOMAIN: &str = "zylith_transition_msg_v1";
pub const WITHDRAWAL_MESSAGE_DOMAIN: &str = "zylith_withdraw_msg_v1";
pub const MARKET_ATTESTATION_CALLDATA_LENGTH: usize = 21;
pub const REFERENCE_METHOD_DIRECT_BBO: u8 = 0;
pub const REFERENCE_METHOD_SYNTHETIC_CROSS_BBO: u8 = 1;

/// one market's attested reference price, as the reference-price attestor signs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketAttestation {
    #[serde(with = "felt_hex_serde")]
    pub pair_id: Felt,
    #[serde(with = "felt_hex_serde")]
    pub base_asset_id: Felt,
    #[serde(with = "felt_hex_serde")]
    pub quote_asset_id: Felt,
    #[serde(with = "u128_decimal_serde")]
    pub midpoint: u128,
    #[serde(with = "u128_decimal_serde")]
    pub lower_price: u128,
    #[serde(with = "u128_decimal_serde")]
    pub upper_price: u128,
    #[serde(with = "u128_decimal_serde")]
    pub scale: u128,
    pub methodology: u8,
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
    pub source_count: u64,
    pub observed_at_ms: u64,
    pub valid_until_ms: u64,
    #[serde(with = "felt_hex_serde")]
    pub source_set_commitment: Felt,
    pub nonce: u64,
    #[serde(with = "felt_hex_serde")]
    pub price_batch_commitment: Felt,
    #[serde(with = "felt_hex_serde")]
    pub signer: Felt,
    pub signature: Signature,
}

impl MarketAttestation {
    /// the message the attestor signs; `verifier` is the exchange contract.
    pub fn message(&self, verifier: Felt) -> Felt {
        let mut state = poseidon_hash(domain_hex(REFERENCE_PRICE_ATTESTATION_DOMAIN_HEX), verifier);
        for value in [
            self.pair_id,
            self.base_asset_id,
            self.quote_asset_id,
            felt_u128(self.midpoint),
            felt_u128(self.lower_price),
            felt_u128(self.upper_price),
            felt_u128(self.scale),
            felt_u64(u64::from(self.methodology)),
            self.derivation_base_market_id,
            self.derivation_quote_market_id,
            felt_u128(self.derivation_base_bid),
            felt_u128(self.derivation_base_ask),
            felt_u128(self.derivation_quote_bid),
            felt_u128(self.derivation_quote_ask),
            felt_u64(self.max_leg_skew_ms),
            felt_u64(self.source_count),
            felt_u64(self.observed_at_ms),
            felt_u64(self.valid_until_ms),
            self.source_set_commitment,
            felt_u64(self.nonce),
            self.price_batch_commitment,
            self.signer,
        ] {
            state = poseidon_hash(state, value);
        }
        state
    }

    pub fn sign(&mut self, verifier: Felt, private_key: &Felt) -> Result<(), ProtocolError> {
        if self.price_batch_commitment == Felt::ZERO {
            self.price_batch_commitment =
                price_batch_commitment(verifier, std::slice::from_ref(self));
        }
        self.signer = public_key(private_key);
        self.signature = sign_message(private_key, &self.message(verifier))?;
        Ok(())
    }

    pub fn verify(&self, verifier: Felt) -> bool {
        verify_message(&self.signer, &self.message(verifier), &self.signature)
    }

    /// the attestor's signed reference price, as the exchange verifies it.
    pub fn from_reference(
        attestation: &crate::ReferencePriceAttestation,
    ) -> Result<Self, ProtocolError> {
        use crate::hash::{encode_starknet_felt, felt_from_hex_str};
        let envelope = &attestation.envelope;
        let (
            methodology,
            derivation_base_market_id,
            derivation_quote_market_id,
            derivation_base_bid,
            derivation_base_ask,
            derivation_quote_bid,
            derivation_quote_ask,
            max_leg_skew_ms,
        ) = match &envelope.derivation {
            ReferencePriceDerivation::DirectBbo {
                bid_price,
                ask_price,
            } => (
                REFERENCE_METHOD_DIRECT_BBO,
                Felt::ZERO,
                Felt::ZERO,
                *bid_price,
                *ask_price,
                0,
                0,
                0,
            ),
            ReferencePriceDerivation::SyntheticCrossBbo {
                base_market_id,
                quote_market_id,
                base_bid_price,
                base_ask_price,
                quote_bid_price,
                quote_ask_price,
                max_leg_skew_ms,
            } => (
                REFERENCE_METHOD_SYNTHETIC_CROSS_BBO,
                felt_from_hex_str(&encode_starknet_felt("pair-id", &base_market_id.0))?,
                felt_from_hex_str(&encode_starknet_felt("pair-id", &quote_market_id.0))?,
                *base_bid_price,
                *base_ask_price,
                *quote_bid_price,
                *quote_ask_price,
                *max_leg_skew_ms,
            ),
        };
        Ok(Self {
            pair_id: felt_from_hex_str(&encode_starknet_felt("pair-id", &envelope.pair_id.0))?,
            base_asset_id: felt_from_hex_str(&encode_starknet_felt(
                "asset-id",
                &envelope.base_asset_id.0,
            ))?,
            quote_asset_id: felt_from_hex_str(&encode_starknet_felt(
                "asset-id",
                &envelope.quote_asset_id.0,
            ))?,
            midpoint: envelope.midpoint_price,
            lower_price: envelope.lower_price,
            upper_price: envelope.upper_price,
            scale: envelope.price_base_scale,
            methodology,
            derivation_base_market_id,
            derivation_quote_market_id,
            derivation_base_bid,
            derivation_base_ask,
            derivation_quote_bid,
            derivation_quote_ask,
            max_leg_skew_ms,
            source_count: envelope.source_count as u64,
            observed_at_ms: envelope.observed_at_unix_ms,
            valid_until_ms: attestation.valid_until_unix_ms,
            source_set_commitment: felt_from_hex_str(&attestation.source_set_commitment)?,
            nonce: attestation.nonce,
            price_batch_commitment: felt_from_hex_str(&attestation.price_batch_commitment)?,
            signer: felt_from_hex_str(&attestation.signer_public_key)?,
            signature: Signature {
                r: felt_from_hex_str(&attestation.signature.signature_r)?,
                s: felt_from_hex_str(&attestation.signature.signature_s)?,
            },
        })
    }

    /// the transition statement's view of this market.
    pub fn market(&self, fee_bps: u128) -> Market {
        Market {
            pair_id: self.pair_id,
            base_asset_id: self.base_asset_id,
            quote_asset_id: self.quote_asset_id,
            midpoint: self.midpoint,
            scale: self.scale,
            observed_at_ms: self.observed_at_ms,
            valid_until_ms: self.valid_until_ms,
            fee_bps,
            reference_methodology: self.methodology,
            derivation_base_market_id: self.derivation_base_market_id,
            derivation_quote_market_id: self.derivation_quote_market_id,
            derivation_base_bid: self.derivation_base_bid,
            derivation_base_ask: self.derivation_base_ask,
            derivation_quote_bid: self.derivation_quote_bid,
            derivation_quote_ask: self.derivation_quote_ask,
            max_leg_skew_ms: self.max_leg_skew_ms,
        }
    }

    /// the contract's market attestation serde layout.
    pub fn calldata(&self) -> [Felt; MARKET_ATTESTATION_CALLDATA_LENGTH] {
        [
            self.pair_id,
            felt_u128(self.midpoint),
            felt_u128(self.lower_price),
            felt_u128(self.upper_price),
            felt_u128(self.scale),
            felt_u64(u64::from(self.methodology)),
            self.derivation_base_market_id,
            self.derivation_quote_market_id,
            felt_u128(self.derivation_base_bid),
            felt_u128(self.derivation_base_ask),
            felt_u128(self.derivation_quote_bid),
            felt_u128(self.derivation_quote_ask),
            felt_u64(self.max_leg_skew_ms),
            felt_u64(self.source_count),
            felt_u64(self.observed_at_ms),
            felt_u64(self.valid_until_ms),
            self.source_set_commitment,
            felt_u64(self.nonce),
            self.price_batch_commitment,
            self.signature.r,
            self.signature.s,
        ]
    }
}

pub fn price_batch_commitment(verifier: Felt, attestations: &[MarketAttestation]) -> Felt {
    let mut state = poseidon_hash(short_string(REFERENCE_PRICE_BATCH_DOMAIN), verifier);
    state = poseidon_hash(state, felt_u64(attestations.len() as u64));
    for market in attestations {
        for value in [
            market.pair_id,
            market.base_asset_id,
            market.quote_asset_id,
            felt_u128(market.midpoint),
            felt_u128(market.lower_price),
            felt_u128(market.upper_price),
            felt_u128(market.scale),
            felt_u64(u64::from(market.methodology)),
            market.derivation_base_market_id,
            market.derivation_quote_market_id,
            felt_u128(market.derivation_base_bid),
            felt_u128(market.derivation_base_ask),
            felt_u128(market.derivation_quote_bid),
            felt_u128(market.derivation_quote_ask),
            felt_u64(market.max_leg_skew_ms),
            felt_u64(market.source_count),
            felt_u64(market.observed_at_ms),
            felt_u64(market.valid_until_ms),
            market.source_set_commitment,
            felt_u64(market.nonce),
        ] {
            state = poseidon_hash(state, value);
        }
    }
    state
}

pub fn sign_price_batch(
    verifier: Felt,
    attestations: &mut [MarketAttestation],
    private_key: &Felt,
) -> Result<(), ProtocolError> {
    let commitment = price_batch_commitment(verifier, attestations);
    for attestation in attestations {
        attestation.price_batch_commitment = commitment;
        attestation.sign(verifier, private_key)?;
    }
    Ok(())
}

/// `h(h(domain, contract), commitment)`: the statement message the proof program emits.
pub fn bound_statement_message(domain: &str, chain_context: Felt, commitment: Felt) -> Felt {
    poseidon_hash(
        poseidon_hash(short_string(domain), chain_context),
        commitment,
    )
}

/// the l1 message hash the proof facts carry for a statement message from `proof_program`.
pub fn proof_message_hash(proof_program: Felt, domain: &str, statement_message: Felt) -> Felt {
    poseidon_hash_many(&[
        proof_program,
        Felt::ZERO,
        Felt::TWO,
        short_string(domain),
        statement_message,
    ])
}

/// `submit_transition(header, markets, outcomes, capacities, nullifiers, outputs)`.
pub fn transition_calldata(
    public: &TransitionPublic,
    attestations: &[MarketAttestation],
) -> Result<Vec<Felt>, ProtocolError> {
    let batch_commitment = price_batch_commitment(public.chain_context, attestations);
    if attestations.len() != public.markets.len()
        || attestations
            .iter()
            .zip(&public.markets)
            .any(|(attestation, market)| {
                attestation.pair_id != market.pair_id
                    || attestation.base_asset_id != market.base_asset_id
                    || attestation.quote_asset_id != market.quote_asset_id
                    || attestation.midpoint != market.midpoint
                    || attestation.scale != market.scale
                    || attestation.observed_at_ms != market.observed_at_ms
                    || attestation.valid_until_ms != market.valid_until_ms
                    || attestation.methodology != market.reference_methodology
                    || attestation.derivation_base_market_id != market.derivation_base_market_id
                    || attestation.derivation_quote_market_id != market.derivation_quote_market_id
                    || attestation.derivation_base_bid != market.derivation_base_bid
                    || attestation.derivation_base_ask != market.derivation_base_ask
                    || attestation.derivation_quote_bid != market.derivation_quote_bid
                    || attestation.derivation_quote_ask != market.derivation_quote_ask
                    || attestation.max_leg_skew_ms != market.max_leg_skew_ms
                    || attestation.price_batch_commitment != batch_commitment
            })
    {
        return Err(invalid(
            "attestations do not match the transition's markets",
        ));
    }
    let mut data = vec![
        felt_u64(u64::from(public.seq)),
        felt_u64(public.close_time_ms),
        public.prior_book_root,
        public.new_book_root,
        public.note_root,
        public.output_root,
        felt_u64(attestations.len() as u64),
    ];
    for attestation in attestations {
        data.extend_from_slice(&attestation.calldata());
    }
    data.push(felt_u64(public.outcomes.len() as u64));
    for outcome in &public.outcomes {
        data.extend_from_slice(&outcome.fields());
    }
    data.push(felt_u64(public.capacities.len() as u64));
    for capacity in &public.capacities {
        data.extend_from_slice(&[
            capacity.pair_id,
            felt_bool(capacity.sell),
            felt_u128(capacity.bound),
            felt_u128(capacity.total),
        ]);
    }
    data.push(felt_u64(public.nullifiers.len() as u64));
    data.extend_from_slice(&public.nullifiers);
    data.push(felt_u64(public.retired_nullifiers.len() as u64));
    data.extend_from_slice(&public.retired_nullifiers);
    data.push(felt_u64(public.output_records.len() as u64));
    for record in &public.output_records {
        data.push(record.leaf);
        data.push(record.enc);
        data.push(record.enc_remaining);
        data.push(record.enc_reserved);
        data.push(record.enc_reserved_offset);
    }
    Ok(data)
}

/// `request_withdrawal(note_root, nullifier, asset_id, amount, exit_commitment, exit_authority)`.
pub fn withdrawal_calldata(public: &WithdrawalPublic) -> Vec<Felt> {
    vec![
        public.note_root,
        public.nullifier,
        public.asset_id,
        felt_u128(public.amount),
        public.exit_commitment,
        public.exit_authority,
    ]
}

/// the arguments of the call to `to`'s `selector` inside an account's multicall calldata
/// `[call count, (to, selector, length, arguments..)..]`.
pub fn multicall_arguments(
    calldata: &[Felt],
    to: Felt,
    selector: Felt,
) -> Result<Vec<Felt>, ProtocolError> {
    let fail = || invalid("multicall calldata is malformed");
    let small = |value: &Felt| usize::try_from(*value).map_err(|_| fail());
    let calls = small(calldata.first().ok_or_else(fail)?)?;
    let mut index = 1;
    for _ in 0..calls {
        let target = *calldata.get(index).ok_or_else(fail)?;
        let entrypoint = *calldata.get(index + 1).ok_or_else(fail)?;
        let length = small(calldata.get(index + 2).ok_or_else(fail)?)?;
        let arguments = calldata
            .get(index + 3..index + 3 + length)
            .ok_or_else(fail)?;
        if target == to && entrypoint == selector {
            return Ok(arguments.to_vec());
        }
        index += 3 + length;
    }
    Err(invalid("the transaction does not call the exchange"))
}

/// the output records of `submit_transition`'s calldata: the header, markets, outcomes,
/// capacities and nullifiers are skipped.
pub fn transition_output_records(
    arguments: &[Felt],
) -> Result<Vec<super::transition::OutputRecord>, ProtocolError> {
    let fail = || invalid("transition calldata is malformed");
    let length =
        |index: usize| usize::try_from(*arguments.get(index).ok_or_else(fail)?).map_err(|_| fail());
    let mut index = 6;
    for width in [MARKET_ATTESTATION_CALLDATA_LENGTH, 7, 4, 1, 1] {
        index += 1 + length(index)? * width;
    }
    let count = length(index)?;
    index += 1;
    let records = arguments.get(index..index + 5 * count).ok_or_else(fail)?;
    Ok(records
        .chunks(5)
        .map(|record| super::transition::OutputRecord {
            leaf: record[0],
            enc: record[1],
            enc_remaining: record[2],
            enc_reserved: record[3],
            enc_reserved_offset: record[4],
        })
        .collect())
}

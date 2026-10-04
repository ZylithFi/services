//! permissionless recovery of the latest authenticated residual order state.

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use starknet_crypto::Felt;

use super::model::*;
use crate::ProtocolError;

pub const STATEMENT_TYPE_RESIDUAL_RECOVERY: u64 = 16;
pub const RESIDUAL_RECOVERY_AUTH_DOMAIN: &str = "zylith_res_recover_auth_v1";
pub const RESIDUAL_RECOVERY_DOMAIN: &str = "zylith_res_recovery_v1";
pub const RESIDUAL_RECOVERY_MESSAGE_DOMAIN: &str = "zylith_res_recover_msg_v1";
pub const CAPACITY_STATUS_FILLED: u8 = 2;
pub const CAPACITY_STATUS_FROZEN: u8 = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCapacity {
    pub generation: u64,
    pub status: u8,
    #[serde(with = "u128_decimal_serde")]
    pub total: u128,
    #[serde(with = "u128_decimal_serde")]
    pub consumed_base: u128,
    #[serde(with = "u128_decimal_serde")]
    pub pool_quote: u128,
    #[serde(with = "u128_decimal_serde")]
    pub scale: u128,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryExit {
    #[serde(with = "felt_hex_serde")]
    pub commitment: Felt,
    #[serde(with = "felt_hex_serde")]
    pub authority: Felt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualRecoveryInput {
    #[serde(with = "felt_hex_serde")]
    pub note_root: Felt,
    pub note: ResidualNote,
    pub membership: NoteMembership,
    #[serde(with = "felt_hex_serde")]
    pub output_asset_id: Felt,
    #[serde(with = "u128_decimal_serde")]
    pub fee_bps: u128,
    pub capacity: RecoveryCapacity,
    pub input_exit: RecoveryExit,
    pub output_exit: RecoveryExit,
    pub authorization: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualRecoveryPublic {
    #[serde(with = "felt_hex_serde")]
    pub chain_context: Felt,
    #[serde(with = "felt_hex_serde")]
    pub note_root: Felt,
    #[serde(with = "felt_hex_serde")]
    pub nullifier: Felt,
    #[serde(with = "felt_hex_serde")]
    pub pair_id: Felt,
    pub sell: bool,
    #[serde(with = "u128_decimal_serde")]
    pub fee_bps: u128,
    pub reserved_seq: u32,
    pub capacity: RecoveryCapacity,
    #[serde(with = "felt_hex_serde")]
    pub input_asset_id: Felt,
    #[serde(with = "u128_decimal_serde")]
    pub input_amount: u128,
    #[serde(with = "felt_hex_serde")]
    pub output_asset_id: Felt,
    #[serde(with = "u128_decimal_serde")]
    pub output_amount: u128,
    #[serde(with = "u128_decimal_serde")]
    pub fee_amount: u128,
    pub input_exit: RecoveryExit,
    pub output_exit: RecoveryExit,
    #[serde(with = "felt_hex_serde")]
    pub commitment: Felt,
}

pub fn residual_recovery_authorization_message(commitment: Felt) -> Felt {
    sponge(&[short_string(RESIDUAL_RECOVERY_AUTH_DOMAIN), commitment])
}

fn ceil_fee(amount: u128, fee_bps: u128) -> Result<u128, ProtocolError> {
    if amount == 0 || fee_bps == 0 {
        return Ok(0);
    }
    amount
        .checked_mul(fee_bps)
        .and_then(|value| value.checked_add(9_999))
        .map(|value| value / 10_000)
        .ok_or_else(|| ProtocolError::InvalidWithdrawal("recovery fee overflows".into()))
}

fn mul_div_floor(left: u128, right: u128, divisor: u128) -> Result<u128, ProtocolError> {
    let value = BigUint::from(left) * BigUint::from(right);
    let result = value / BigUint::from(divisor);
    result
        .to_u128()
        .ok_or(())
        .map_err(|_| ProtocolError::InvalidWithdrawal("recovery quote overflows".into()))
}

fn mul_div_ceil(left: u128, right: u128, divisor: u128) -> Result<u128, ProtocolError> {
    let value = BigUint::from(left) * BigUint::from(right);
    let divisor = BigUint::from(divisor);
    let result = (value + &divisor - BigUint::from(1_u8)) / divisor;
    result
        .to_u128()
        .ok_or(())
        .map_err(|_| ProtocolError::InvalidWithdrawal("recovery quote overflows".into()))
}

fn validate_exit(exit: RecoveryExit, amount: u128) -> Result<(), ProtocolError> {
    if (amount == 0) != (exit.commitment == Felt::ZERO && exit.authority == Felt::ZERO) {
        return Err(ProtocolError::InvalidWithdrawal(
            "a recovery exit is present exactly when its amount is nonzero".into(),
        ));
    }
    Ok(())
}

pub fn residual_recovery_amounts(
    note: &ResidualNote,
    capacity: RecoveryCapacity,
    fee_bps: u128,
) -> Result<(u128, u128, u128), ProtocolError> {
    if fee_bps > 100 {
        return Err(ProtocolError::InvalidWithdrawal(
            "residual recovery fee is out of range".into(),
        ));
    }
    let (allocated, quote) = if note.reserved == 0 {
        if note.reserved_seq != 0
            || note.reserved_offset != 0
            || capacity != RecoveryCapacity::default()
        {
            return Err(ProtocolError::InvalidWithdrawal(
                "unreserved recovery carries a capacity".into(),
            ));
        }
        (0, 0)
    } else {
        if note.reserved_seq == 0
            || !matches!(
                capacity.status,
                CAPACITY_STATUS_FILLED | CAPACITY_STATUS_FROZEN
            )
            || capacity.generation == 0
            || capacity.total >= AMOUNT_BOUND
            || capacity.consumed_base >= AMOUNT_BOUND
            || capacity.pool_quote >= AMOUNT_BOUND
            || capacity.scale >= AMOUNT_BOUND
            || capacity.scale == 0
            || capacity.total == 0
            || capacity.consumed_base > capacity.total
            || note
                .reserved_offset
                .checked_add(note.reserved)
                .is_none_or(|end| end > capacity.total)
        {
            return Err(ProtocolError::InvalidWithdrawal(
                "reserved recovery capacity is malformed or not final".into(),
            ));
        }
        let allocated = capacity
            .consumed_base
            .saturating_sub(note.reserved_offset)
            .min(note.reserved);
        let quote = if allocated == 0 {
            0
        } else if note.sell {
            mul_div_floor(allocated, capacity.pool_quote, capacity.consumed_base)?
        } else {
            mul_div_ceil(allocated, capacity.pool_quote, capacity.consumed_base)?
        };
        (allocated, quote)
    };
    let (input_amount, gross_output) = if note.sell {
        (
            note.funding.checked_sub(allocated).ok_or_else(|| {
                ProtocolError::InvalidWithdrawal("recovery exceeds sell funding".into())
            })?,
            quote,
        )
    } else {
        (
            note.funding.checked_sub(quote).ok_or_else(|| {
                ProtocolError::InvalidWithdrawal("recovery exceeds buy funding".into())
            })?,
            allocated,
        )
    };
    let fee_amount = ceil_fee(gross_output, fee_bps)?;
    let output_amount = gross_output
        .checked_sub(fee_amount)
        .ok_or_else(|| ProtocolError::InvalidWithdrawal("recovery fee exceeds output".into()))?;
    Ok((input_amount, output_amount, fee_amount))
}

/// the statement's commitment: its domain and chain context over the contract calldata.
fn public_commitment(public: &ResidualRecoveryPublic) -> Felt {
    let mut fields = vec![short_string(RESIDUAL_RECOVERY_DOMAIN), public.chain_context];
    fields.extend(residual_recovery_calldata(public));
    sponge(&fields)
}

fn build_residual_recovery_inner(
    input: &ResidualRecoveryInput,
    verify_authorization: bool,
) -> Result<(ResidualRecoveryPublic, Vec<Felt>), ProtocolError> {
    let note = &input.note;
    if note.chain_context == Felt::ZERO
        || input.note_root == Felt::ZERO
        || note.input_asset_id == Felt::ZERO
        || input.output_asset_id == Felt::ZERO
        || note.owner.withdraw_authority == Felt::ZERO
        || note.blinding == Felt::ZERO
        || note.generation == 0
    {
        return Err(ProtocolError::InvalidWithdrawal(
            "residual recovery header is malformed".into(),
        ));
    }
    if input.membership.root(note.output_leaf())? != input.note_root {
        return Err(ProtocolError::InvalidWithdrawal(
            "residual authority is not in the claimed root".into(),
        ));
    }
    let (input_amount, output_amount, fee_amount) =
        residual_recovery_amounts(note, input.capacity, input.fee_bps)?;
    validate_exit(input.input_exit, input_amount)?;
    validate_exit(input.output_exit, output_amount)?;
    let mut public = ResidualRecoveryPublic {
        chain_context: note.chain_context,
        note_root: input.note_root,
        nullifier: note.nullifier(),
        pair_id: note.pair_id,
        sell: note.sell,
        fee_bps: input.fee_bps,
        reserved_seq: note.reserved_seq,
        capacity: input.capacity,
        input_asset_id: note.input_asset_id,
        input_amount,
        output_asset_id: input.output_asset_id,
        output_amount,
        fee_amount,
        input_exit: input.input_exit,
        output_exit: input.output_exit,
        commitment: Felt::ZERO,
    };
    public.commitment = public_commitment(&public);
    if verify_authorization
        && !verify_message(
            &note.owner.withdraw_authority,
            &residual_recovery_authorization_message(public.commitment),
            &input.authorization,
        )
    {
        return Err(ProtocolError::InvalidWithdrawal(
            "residual recovery authorization is invalid".into(),
        ));
    }
    let mut witness = vec![
        felt_u64(STATEMENT_TYPE_RESIDUAL_RECOVERY),
        public.chain_context,
        public.note_root,
        public.output_asset_id,
        felt_u128(input.fee_bps),
        felt_u64(public.capacity.generation),
        felt_u64(u64::from(public.capacity.status)),
        felt_u128(public.capacity.total),
        felt_u128(public.capacity.consumed_base),
        felt_u128(public.capacity.pool_quote),
        felt_u128(public.capacity.scale),
        public.input_exit.commitment,
        public.input_exit.authority,
        public.output_exit.commitment,
        public.output_exit.authority,
        note.input_asset_id,
        note.pair_id,
        felt_bool(note.sell),
        felt_bool(note.external),
        felt_u128(note.remaining),
        felt_u128(note.limit),
        felt_u128(note.funding),
        felt_u128(note.reserved),
        felt_u128(note.reserved_offset),
        felt_u64(u64::from(note.reserved_seq)),
        felt_u64(note.expiry_ms),
        note.order_id,
        felt_u64(u64::from(note.generation)),
    ];
    witness.extend_from_slice(&note.owner.fields());
    witness.push(note.blinding);
    witness.push(felt_u64(input.membership.subtree_path.len() as u64));
    for (sibling, right) in input
        .membership
        .subtree_path
        .iter()
        .zip(&input.membership.subtree_directions)
    {
        witness.extend_from_slice(&[*sibling, felt_bool(*right)]);
    }
    for (sibling, right) in input
        .membership
        .accumulator_path
        .iter()
        .zip(&input.membership.accumulator_directions)
    {
        witness.extend_from_slice(&[*sibling, felt_bool(*right)]);
    }
    witness.extend_from_slice(&[input.authorization.r, input.authorization.s]);
    Ok((public, witness))
}

pub fn preview_residual_recovery(
    input: &ResidualRecoveryInput,
) -> Result<ResidualRecoveryPublic, ProtocolError> {
    Ok(build_residual_recovery_inner(input, false)?.0)
}

pub fn build_residual_recovery(
    input: &ResidualRecoveryInput,
) -> Result<(ResidualRecoveryPublic, Vec<Felt>), ProtocolError> {
    build_residual_recovery_inner(input, true)
}

pub fn residual_recovery_calldata(public: &ResidualRecoveryPublic) -> Vec<Felt> {
    vec![
        public.note_root,
        public.nullifier,
        public.pair_id,
        felt_bool(public.sell),
        felt_u128(public.fee_bps),
        felt_u64(u64::from(public.reserved_seq)),
        felt_u64(public.capacity.generation),
        felt_u64(u64::from(public.capacity.status)),
        felt_u128(public.capacity.total),
        felt_u128(public.capacity.consumed_base),
        felt_u128(public.capacity.pool_quote),
        felt_u128(public.capacity.scale),
        public.input_asset_id,
        felt_u128(public.input_amount),
        public.output_asset_id,
        felt_u128(public.output_amount),
        felt_u128(public.fee_amount),
        public.input_exit.commitment,
        public.input_exit.authority,
        public.output_exit.commitment,
        public.output_exit.authority,
    ]
}

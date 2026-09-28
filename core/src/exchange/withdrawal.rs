//! the user's withdrawal: proves a note is in a known accumulator root and reveals only its
//! nullifier, asset, amount and exit. the withdraw authority signs inside the proof, so it never
//! becomes public and withdrawals by one key stay unlinkable.

use serde::{Deserialize, Serialize};
use starknet_crypto::Felt;

use super::model::*;
use crate::ProtocolError;

pub const STATEMENT_TYPE_WITHDRAWAL_V2: u64 = 15;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalInput {
    #[serde(with = "felt_hex_serde")]
    pub chain_context: Felt,
    #[serde(with = "felt_hex_serde")]
    pub note_root: Felt,
    /// where the staged exit is claimable in the strk20 pool.
    #[serde(with = "felt_hex_serde")]
    pub exit_commitment: Felt,
    /// a fresh key that signs the strk20 claim; the note's own withdraw authority stays private.
    #[serde(with = "felt_hex_serde")]
    pub exit_authority: Felt,
    pub note: NoteFields,
    pub membership: NoteMembership,
    pub authorization: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalPublic {
    #[serde(with = "felt_hex_serde")]
    pub chain_context: Felt,
    #[serde(with = "felt_hex_serde")]
    pub note_root: Felt,
    #[serde(with = "felt_hex_serde")]
    pub nullifier: Felt,
    #[serde(with = "felt_hex_serde")]
    pub asset_id: Felt,
    #[serde(with = "u128_decimal_serde")]
    pub amount: u128,
    #[serde(with = "felt_hex_serde")]
    pub exit_commitment: Felt,
    #[serde(with = "felt_hex_serde")]
    pub exit_authority: Felt,
    #[serde(with = "felt_hex_serde")]
    pub commitment: Felt,
}

pub fn withdrawal_authorization_message(
    chain_context: Felt,
    nullifier: Felt,
    exit_commitment: Felt,
    exit_authority: Felt,
) -> Felt {
    sponge(&[
        short_string(WITHDRAW_AUTH_DOMAIN),
        chain_context,
        nullifier,
        exit_commitment,
        exit_authority,
    ])
}

pub fn withdrawal_commitment(
    chain_context: Felt,
    note_root: Felt,
    nullifier: Felt,
    asset_id: Felt,
    amount: u128,
    exit_commitment: Felt,
    exit_authority: Felt,
) -> Felt {
    sponge(&[
        short_string(WITHDRAWAL_DOMAIN),
        chain_context,
        note_root,
        nullifier,
        asset_id,
        felt_u128(amount),
        exit_commitment,
        exit_authority,
    ])
}

/// the public withdrawal and the felt input of the cairo withdrawal statement.
pub fn build_withdrawal(
    input: &WithdrawalInput,
) -> Result<(WithdrawalPublic, Vec<Felt>), ProtocolError> {
    let note = &input.note;
    if input.chain_context == Felt::ZERO
        || input.exit_commitment == Felt::ZERO
        || input.exit_authority == Felt::ZERO
    {
        return Err(ProtocolError::InvalidWithdrawal(
            "withdrawal context and exit must be nonzero".into(),
        ));
    }
    if note.amount == 0
        || note.amount >= AMOUNT_BOUND
        || note.nonce == 0
        || note.blinding == Felt::ZERO
    {
        return Err(ProtocolError::InvalidWithdrawal(
            "withdrawn note is malformed".into(),
        ));
    }
    if input.membership.root(note.output_leaf())? != input.note_root {
        return Err(ProtocolError::InvalidWithdrawal(
            "note is not in the claimed root".into(),
        ));
    }
    let nullifier = note.nullifier();
    let message = withdrawal_authorization_message(
        input.chain_context,
        nullifier,
        input.exit_commitment,
        input.exit_authority,
    );
    if !verify_message(&note.withdraw_authority, &message, &input.authorization) {
        return Err(ProtocolError::InvalidWithdrawal(
            "withdraw authorization is invalid".into(),
        ));
    }
    let public = WithdrawalPublic {
        chain_context: input.chain_context,
        note_root: input.note_root,
        nullifier,
        asset_id: note.asset_id,
        amount: note.amount,
        exit_commitment: input.exit_commitment,
        exit_authority: input.exit_authority,
        commitment: withdrawal_commitment(
            input.chain_context,
            input.note_root,
            nullifier,
            note.asset_id,
            note.amount,
            input.exit_commitment,
            input.exit_authority,
        ),
    };
    let mut witness = vec![
        felt_u64(STATEMENT_TYPE_WITHDRAWAL_V2),
        input.chain_context,
        input.note_root,
        input.exit_commitment,
        input.exit_authority,
        note.asset_id,
        felt_u128(note.amount),
        note.owner_public_key,
        note.spend_authority,
        note.withdraw_authority,
        note.blinding,
        felt_u64(note.nonce),
        note.metadata_commitment,
        felt_u64(input.membership.subtree_path.len() as u64),
    ];
    for (sibling, right) in input
        .membership
        .subtree_path
        .iter()
        .zip(&input.membership.subtree_directions)
    {
        witness.push(*sibling);
        witness.push(felt_bool(*right));
    }
    for (sibling, right) in input
        .membership
        .accumulator_path
        .iter()
        .zip(&input.membership.accumulator_directions)
    {
        witness.push(*sibling);
        witness.push(felt_bool(*right));
    }
    witness.push(input.authorization.r);
    witness.push(input.authorization.s);
    Ok((public, witness))
}

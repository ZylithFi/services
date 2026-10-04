//! the exchange from a wallet's side: the keys it derives from its recovery seed, the requests it
//! signs, and the outputs it recovers from the chain's transition records.

use std::fmt;

use starknet_crypto::{Felt, poseidon_hash};

use super::envelope::{CancelRequest, OrderRequest, WithdrawRequest};
use super::model::*;
use super::transition::{OutputRecord, order_output_note, output_blinding};
use super::withdrawal::withdrawal_authorization_message;
use crate::hash::{encode_starknet_felt, felt_from_hex_str};
use crate::keys::{RecoverySeed, derive_user_keys};
use crate::{ProtocolError, note_recognition_public_key_from_raw_key_hex};

/// the stark keys behind a wallet's notes and orders.
#[derive(Clone)]
pub struct WalletKeys {
    pub spend_key: Felt,
    pub withdraw_key: Felt,
    pub cancel_key: Felt,
    /// the note recognition key's public half, as notes carry it.
    pub owner_public_key: Felt,
}

impl fmt::Debug for WalletKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletKeys")
            .field("owner_public_key", &self.owner_public_key)
            .finish_non_exhaustive()
    }
}

impl WalletKeys {
    pub fn from_seed(seed: &RecoverySeed) -> Result<Self, ProtocolError> {
        let keys = derive_user_keys(seed);
        let stark_key = |kind: &str, raw: &[u8; 32]| {
            felt_from_hex_str(&encode_starknet_felt(kind, &hex::encode(raw)))
        };
        let recognition =
            note_recognition_public_key_from_raw_key_hex(&hex::encode(keys.note_recognition_key))?;
        // the same encodings the deposit flow gives a note's owner, spend and withdraw fields.
        Ok(Self {
            spend_key: stark_key("spend-auth-key", &keys.spend_auth_key)?,
            withdraw_key: stark_key("withdraw-auth-key", &keys.withdraw_auth_key)?,
            cancel_key: stark_key("cancel-auth-key", &keys.order_cancellation_key)?,
            owner_public_key: felt_from_hex_str(&encode_starknet_felt(
                "owner-public-key",
                &recognition,
            ))?,
        })
    }

    /// an order's owner record under a fresh secret nonce.
    pub fn owner(&self, nonce: Felt) -> OrderOwner {
        OrderOwner {
            owner_public_key: self.owner_public_key,
            spend_authority: public_key(&self.spend_key),
            withdraw_authority: public_key(&self.withdraw_key),
            cancel_authority: public_key(&self.cancel_key),
            nonce,
        }
    }

    pub fn owns(&self, note: &NoteFields) -> bool {
        note.owner_public_key == self.owner_public_key
            && note.spend_authority == public_key(&self.spend_key)
            && note.withdraw_authority == public_key(&self.withdraw_key)
    }

    /// a deterministic one-time key for one withdrawal. `exit_nonce` is the wire field currently
    /// named `exit_commitment`; retries reuse it, while every new withdrawal samples a new value.
    pub fn exit_key(&self, chain_context: Felt, exit_nonce: Felt) -> Felt {
        let domain = Felt::from_bytes_be_slice(b"zylith-exit-v1");
        let derived = poseidon_hash(
            poseidon_hash(poseidon_hash(domain, self.withdraw_key), chain_context),
            exit_nonce,
        );
        // stark ecdsa private keys must be below the curve order. values below 2^251 are valid.
        let mut bytes = derived.to_bytes_be();
        bytes[0] &= 0x07;
        let derived = Felt::from_bytes_be(&bytes);
        if derived == Felt::ZERO {
            Felt::ONE
        } else {
            derived
        }
    }

    /// signs a new order funded by `funding`, all of which must be this wallet's notes of the
    /// order's input asset.
    #[allow(clippy::too_many_arguments)]
    pub fn order(
        &self,
        chain_context: Felt,
        pair_id: Felt,
        sell: bool,
        external: bool,
        amount: u128,
        limit: u128,
        expiry_ms: u64,
        funding: Vec<NoteFields>,
    ) -> Result<OrderRequest, ProtocolError> {
        if funding.iter().any(|note| !self.owns(note)) {
            return Err(invalid("a funding note does not belong to this wallet"));
        }
        let terms = OrderTerms {
            pair_id,
            sell,
            external,
            amount,
            limit,
            expiry_ms,
            owner: self.owner(random_felt()),
        };
        terms.validate()?;
        let mut request = OrderRequest {
            terms,
            funding,
            authorization: Signature {
                r: Felt::ZERO,
                s: Felt::ZERO,
            },
        };
        request.authorization = sign_message(
            &self.spend_key,
            &request.authorization_message(chain_context),
        )?;
        Ok(request)
    }

    pub fn cancel(
        &self,
        chain_context: Felt,
        order_id: Felt,
    ) -> Result<CancelRequest, ProtocolError> {
        Ok(CancelRequest {
            order_id,
            signature: sign_message(&self.cancel_key, &cancel_message(chain_context, order_id))?,
        })
    }

    /// authorizes the exit with the note's long-lived withdrawal key while assigning a fresh,
    /// unlinkable authority that alone can claim this exit from the privacy pool.
    pub fn withdraw(
        &self,
        chain_context: Felt,
        note: NoteFields,
        exit_commitment: Felt,
    ) -> Result<WithdrawRequest, ProtocolError> {
        if !self.owns(&note) {
            return Err(invalid("the note does not belong to this wallet"));
        }
        let exit_authority = public_key(&self.exit_key(chain_context, exit_commitment));
        let message = withdrawal_authorization_message(
            chain_context,
            note.nullifier(),
            exit_commitment,
            exit_authority,
        );
        let authorization = sign_message(&self.withdraw_key, &message)?;
        let request = WithdrawRequest {
            note,
            exit_commitment,
            exit_authority,
            authorization,
        };
        request.validate(chain_context)?;
        Ok(request)
    }
}

/// a traded pair's id, from its manifest name (such as strk/usdc).
pub fn pair_id(name: &str) -> Felt {
    felt_from_hex_str(&encode_starknet_felt("pair-id", name)).expect("the encoding is a felt")
}

/// an asset's id, from its manifest name (such as strk), as notes carry it.
pub fn asset_id(name: &str) -> Felt {
    felt_from_hex_str(&encode_starknet_felt("asset-id", name)).expect("the encoding is a felt")
}

/// a random nonzero felt below 2^251.
pub fn random_felt() -> Felt {
    let mut bytes: [u8; 32] = rand::random();
    bytes[0] &= 0x07;
    let value = Felt::from_bytes_be(&bytes);
    if value == Felt::ZERO {
        Felt::ONE
    } else {
        value
    }
}

/// an output recovered from a transition's records.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveredOutput {
    pub seq: u32,
    pub kind: u64,
    pub index: usize,
    pub note: NoteFields,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveredResidual {
    pub seq: u32,
    pub index: usize,
    pub note: ResidualNote,
}

/// the order's outputs among one transition's records: its proceeds in the other asset and its
/// refund in the input asset. an amount is the record's padded value less the blinding only the
/// order's owner can derive, and a candidate counts only when its leaf is the record's.
pub fn recover_order_outputs(
    terms: &OrderTerms,
    base_asset_id: Felt,
    quote_asset_id: Felt,
    seq: u32,
    records: &[OutputRecord],
) -> Vec<RecoveredOutput> {
    let order_id = terms.order_id();
    let (input_asset, output_asset) = if terms.sell {
        (base_asset_id, quote_asset_id)
    } else {
        (quote_asset_id, base_asset_id)
    };
    let bound = Felt::from(u128::MAX);
    let mut recovered = Vec::new();
    for (kind, asset_id) in [
        (OUTPUT_KIND_PROCEEDS, output_asset),
        (OUTPUT_KIND_REFUND, input_asset),
    ] {
        let blinding = output_blinding(terms.owner.nonce, seq, kind, Felt::ZERO);
        for (index, record) in records.iter().enumerate() {
            let amount = record.enc - blinding;
            if amount > bound {
                continue;
            }
            let amount = u128::try_from(amount).expect("the amount is bounded");
            let note = order_output_note(&terms.owner, order_id, asset_id, amount, seq, kind);
            if note.output_leaf() == record.leaf {
                recovered.push(RecoveredOutput {
                    seq,
                    kind,
                    index,
                    note,
                });
                break;
            }
        }
    }
    recovered
}

/// recovers the latest residual-order state created for this order in one transition. every
/// private scalar is independently padded; the distinct residual leaf domain prevents this
/// record from being redeemed through the ordinary value-note withdrawal statement.
pub fn recover_order_residual(
    chain_context: Felt,
    terms: &OrderTerms,
    base_asset_id: Felt,
    quote_asset_id: Felt,
    seq: u32,
    records: &[OutputRecord],
) -> Option<RecoveredResidual> {
    let input_asset_id = if terms.sell {
        base_asset_id
    } else {
        quote_asset_id
    };
    let decode = |value: Felt, kind: u64| {
        let blinding = output_blinding(terms.owner.nonce, seq, kind, Felt::ZERO);
        let decoded = value - blinding;
        (decoded <= Felt::from(u128::MAX)).then(|| u128::try_from(decoded).expect("bounded"))
    };
    for (index, record) in records.iter().enumerate() {
        let Some(funding) = decode(record.enc, OUTPUT_KIND_RESIDUAL) else {
            continue;
        };
        let Some(remaining) = decode(record.enc_remaining, OUTPUT_KIND_RESIDUAL + 1) else {
            continue;
        };
        let Some(reserved) = decode(record.enc_reserved, OUTPUT_KIND_RESIDUAL + 2) else {
            continue;
        };
        let Some(reserved_offset) = decode(record.enc_reserved_offset, OUTPUT_KIND_RESIDUAL + 3)
        else {
            continue;
        };
        let order = BookOrder {
            pair_id: terms.pair_id,
            sell: terms.sell,
            external: terms.external,
            remaining,
            limit: terms.limit,
            funding,
            reserved,
            reserved_offset,
            reserved_seq: if reserved == 0 { 0 } else { seq },
            expiry_ms: terms.expiry_ms,
            owner_digest: terms.owner.digest(),
            order_id: terms.order_id(),
            residual_commitment: Felt::ZERO,
            residual_generation: seq,
        };
        let note =
            ResidualNote::from_order(chain_context, input_asset_id, &order, &terms.owner, seq);
        if note.output_leaf() == record.leaf {
            return Some(RecoveredResidual { seq, index, note });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::super::*;
    use super::*;

    fn wallet(byte: u8) -> WalletKeys {
        WalletKeys::from_seed(&RecoverySeed([byte; 32])).unwrap()
    }

    fn note(keys: &WalletKeys, asset: u64, amount: u128, salt: u64) -> NoteFields {
        NoteFields {
            asset_id: Felt::from(asset),
            amount,
            owner_public_key: keys.owner_public_key,
            spend_authority: public_key(&keys.spend_key),
            withdraw_authority: public_key(&keys.withdraw_key),
            blinding: Felt::from(salt * 7 + 11),
            nonce: salt,
            metadata_commitment: Felt::from(salt),
        }
    }

    #[test]
    fn wallet_keys_match_the_deposit_encoding() {
        let seed = RecoverySeed([3; 32]);
        let keys = WalletKeys::from_seed(&seed).unwrap();
        let raw = derive_user_keys(&seed);
        let spend =
            crate::spend_authority_from_raw_key_hex(&hex::encode(raw.spend_auth_key)).unwrap();
        let withdraw =
            crate::withdraw_authority_from_raw_key_hex(&hex::encode(raw.withdraw_auth_key))
                .unwrap();
        assert_eq!(
            felt_from_hex_str(&spend).unwrap(),
            public_key(&keys.spend_key)
        );
        assert_eq!(
            felt_from_hex_str(&withdraw).unwrap(),
            public_key(&keys.withdraw_key)
        );
        assert!(
            format!("{keys:?}")
                .find(&format!("{:#x}", keys.spend_key))
                .is_none()
        );
    }

    #[test]
    fn wallet_requests_pass_the_operators_checks_and_outputs_recover_from_records() {
        let (seller, buyer) = (wallet(1), wallet(2));
        let (base, quote) = (note(&seller, BASE, 10, 1), note(&buyer, QUOTE, 2_000, 2));
        let chain = Felt::from(CHAIN);
        let sell = seller
            .order(
                chain,
                Felt::from(PAIR),
                true,
                false,
                10,
                95,
                1_000_000,
                vec![base.clone()],
            )
            .unwrap();
        let buy = buyer
            .order(
                chain,
                Felt::from(PAIR),
                false,
                false,
                10,
                105,
                1_000_000,
                vec![quote.clone()],
            )
            .unwrap();
        sell.validate(chain, Felt::from(BASE), 1, 1, 1).unwrap();
        buy.validate(chain, Felt::from(QUOTE), 1, 1, 1).unwrap();
        // below the pair's minimum size the operator refuses it.
        assert!(
            sell.validate(chain, Felt::from(BASE), sell.terms.amount + 1, 1, 1)
                .is_err()
        );
        assert!(
            seller
                .order(
                    chain,
                    Felt::from(PAIR),
                    true,
                    false,
                    10,
                    95,
                    1_000_000,
                    vec![quote.clone()]
                )
                .is_err()
        );

        let mut notes = Notes::default();
        notes.add_deposit(&base);
        notes.add_deposit(&quote);
        let orders = [&sell, &buy].map(|request| {
            let membership = notes.membership(&request.funding[0]);
            request.clone().into_new_order(vec![membership])
        });
        let result =
            build_transition(&input(1, vec![], orders.to_vec(), notes.root(), 100)).unwrap();
        for request in [&sell, &buy] {
            let recovered = recover_order_outputs(
                &request.terms,
                Felt::from(BASE),
                Felt::from(QUOTE),
                1,
                &result.public.output_records,
            );
            let expected = result
                .outputs
                .iter()
                .filter(|output| output.order_id == request.order_id())
                .map(|output| (output.kind, output.index, output.note.clone()))
                .collect::<Vec<_>>();
            assert!(!expected.is_empty());
            assert_eq!(
                recovered
                    .into_iter()
                    .map(|output| (output.kind, output.index, output.note))
                    .collect::<Vec<_>>(),
                expected
            );
        }
        // another seq's blinding recovers nothing.
        assert!(
            recover_order_outputs(
                &sell.terms,
                Felt::from(BASE),
                Felt::from(QUOTE),
                2,
                &result.public.output_records
            )
            .is_empty()
        );

        let cancel = seller.cancel(chain, sell.order_id()).unwrap();
        assert!(verify_message(
            &sell.terms.owner.cancel_authority,
            &cancel_message(chain, cancel.order_id),
            &cancel.signature
        ));
        let exit = seller
            .withdraw(chain, base.clone(), Felt::from(0xe817_u64))
            .unwrap();
        exit.validate(chain).unwrap();
        assert_ne!(exit.exit_authority, base.withdraw_authority);
        assert_eq!(
            exit.exit_authority,
            public_key(&seller.exit_key(chain, Felt::from(0xe817_u64)))
        );
        assert_ne!(
            exit.exit_authority,
            public_key(&seller.exit_key(chain, Felt::from(0xe818_u64)))
        );
        assert!(buyer.withdraw(chain, base, Felt::ONE).is_err());
    }
}

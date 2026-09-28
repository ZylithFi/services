//! what the operator reads from the chain: the exchange's views and its events, folded into the
//! note index every funding note and withdrawal proves membership against.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use starknet_rust_core::types::{BlockId, EventFilter, Felt, InvokeTransaction, Transaction};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::Provider;
use zylith_core::exchange::NoteMembership;

use crate::config::{from_core, to_core};
use crate::snip36::Snip36;

const EVENT_PAGE: u64 = 512;

/// one batch appended to the note accumulator: a deposit's single leaf or a transition's padded
/// output leaves.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NoteBatch {
    pub root: Felt,
    pub leaves: Vec<Felt>,
    /// the transition that produced it, if any.
    pub seq: Option<u32>,
    /// the block that appended it, so a reorganization can rewind past it.
    #[serde(default)]
    pub block: u64,
}

/// every note leaf the chain holds, in accumulator order.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NoteIndex {
    pub batches: Vec<NoteBatch>,
    pub next_block: u64,
    /// the hash of block `next_block - 1` when it was scanned; zero before the first scan.
    #[serde(default)]
    pub cursor_hash: Felt,
    #[serde(skip)]
    positions: BTreeMap<[u8; 32], (usize, usize)>,
    #[serde(skip)]
    tree: Option<zylith_core::exchange::NoteAccumulator>,
}

impl NoteIndex {
    pub fn starting_at(block: u64) -> Self {
        Self {
            next_block: block,
            ..Self::default()
        }
    }

    /// rebuilds the lookup and the accumulator after loading from storage.
    pub fn reindex(&mut self) -> Result<(), String> {
        let mut tree = zylith_core::exchange::NoteAccumulator::default();
        self.positions.clear();
        for (batch_index, batch) in self.batches.iter().enumerate() {
            tree.append(to_core(batch.root));
            for (leaf_index, leaf) in batch.leaves.iter().enumerate() {
                self.positions
                    .entry(leaf.to_bytes_be())
                    .or_insert((batch_index, leaf_index));
            }
        }
        self.tree = Some(tree);
        Ok(())
    }

    /// forgets every batch appended at or after `block` and rescans from there.
    pub fn rewind(&mut self, block: u64) -> Result<(), String> {
        self.batches.retain(|batch| batch.block < block);
        self.next_block = self.next_block.min(block);
        self.cursor_hash = Felt::ZERO;
        self.reindex()
    }

    pub fn append(&mut self, batch: NoteBatch) -> Result<Felt, String> {
        if self.tree.is_none() {
            self.reindex()?;
        }
        let tree = self.tree.as_mut().expect("reindexed");
        let root = from_core(tree.append(to_core(batch.root)));
        let batch_index = self.batches.len();
        for (leaf_index, leaf) in batch.leaves.iter().enumerate() {
            self.positions
                .entry(leaf.to_bytes_be())
                .or_insert((batch_index, leaf_index));
        }
        self.batches.push(batch);
        Ok(root)
    }

    pub fn root(&self) -> Felt {
        self.tree
            .as_ref()
            .map_or(Felt::ZERO, |tree| from_core(tree.root()))
    }

    /// the membership of `leaf` against the current root.
    pub fn membership(&self, leaf: Felt) -> Option<NoteMembership> {
        let (batch_index, leaf_index) = *self.positions.get(&leaf.to_bytes_be())?;
        let leaves = self.batches[batch_index]
            .leaves
            .iter()
            .map(|leaf| to_core(*leaf))
            .collect::<Vec<_>>();
        self.tree
            .as_ref()?
            .membership(batch_index, &leaves, leaf_index)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExchangeView {
    pub seq: u32,
    pub book_root: Felt,
    pub last_close_ms: u64,
    pub note_root: Felt,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapacityView {
    pub bound: u128,
    pub total: u128,
    pub scale: u128,
    pub opened_at: u64,
    pub consumed_base: u128,
    pub pool_quote: u128,
    pub m1: u128,
    pub status: u8,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingExitView {
    pub asset_id: Felt,
    pub amount: u128,
    pub exit_commitment: Felt,
    pub exit_authority: Felt,
    /// starknet block timestamp, in seconds.
    pub matures_at: u64,
}

/// a chain event the operator reacts to, in chain order.
#[derive(Clone, Debug)]
pub enum ChainEvent {
    Deposit {
        deposit_root: Felt,
    },
    Transition {
        seq: u32,
        output_root: Felt,
        transaction_hash: Felt,
    },
    WithdrawalFinalized {
        nullifier: Felt,
    },
}

fn u128_of(value: Felt) -> Result<u128, String> {
    value
        .try_into()
        .map_err(|_| "value exceeds u128".to_string())
}

fn u64_of(value: Felt) -> Result<u64, String> {
    value
        .try_into()
        .map_err(|_| "value exceeds u64".to_string())
}

pub struct Chain<'a> {
    pub snip36: &'a Snip36,
    pub exchange: Felt,
}

impl Chain<'_> {
    pub async fn exchange_view(&self) -> Result<ExchangeView, String> {
        self.exchange_view_at(BlockId::Tag(
            starknet_rust_core::types::BlockTag::PreConfirmed,
        ))
        .await
    }

    /// reads the authoritative exchange state below the configured confirmation frontier.
    pub async fn confirmed_exchange_view(
        &self,
        confirmations: u64,
    ) -> Result<ExchangeView, String> {
        let (tip, _) = self.snip36.latest_block().await?;
        self.exchange_view_at(BlockId::Number(tip.saturating_sub(confirmations)))
            .await
    }

    async fn exchange_view_at(&self, block: BlockId) -> Result<ExchangeView, String> {
        let one = |values: Vec<Felt>| {
            values
                .first()
                .copied()
                .ok_or_else(|| "empty view".to_string())
        };
        Ok(ExchangeView {
            seq: u64_of(one(self
                .snip36
                .view_at(self.exchange, "transition_seq", vec![], block)
                .await?)?)? as u32,
            book_root: one(self
                .snip36
                .view_at(self.exchange, "book_root", vec![], block)
                .await?)?,
            last_close_ms: u64_of(one(self
                .snip36
                .view_at(self.exchange, "last_close_time_ms", vec![], block)
                .await?)?)?,
            note_root: one(self
                .snip36
                .view_at(self.exchange, "note_root", vec![], block)
                .await?)?,
        })
    }

    pub async fn nullifier_state(&self, nullifier: Felt) -> Result<u8, String> {
        let values = self
            .snip36
            .view(self.exchange, "nullifier_state", vec![nullifier])
            .await?;
        Ok(u64_of(*values.first().ok_or("empty view")?)? as u8)
    }

    pub async fn pending_exit(&self, nullifier: Felt) -> Result<PendingExitView, String> {
        let values = self
            .snip36
            .view(self.exchange, "pending_exit", vec![nullifier])
            .await?;
        if values.len() != 5 {
            return Err("pending exit view has an unexpected shape".into());
        }
        Ok(PendingExitView {
            asset_id: values[0],
            amount: u128_of(values[1])?,
            exit_commitment: values[2],
            exit_authority: values[3],
            matures_at: u64_of(values[4])?,
        })
    }

    pub async fn capacity(
        &self,
        seq: u32,
        pair_id: Felt,
        sell: bool,
    ) -> Result<CapacityView, String> {
        let values = self
            .snip36
            .view(
                self.exchange,
                "capacity",
                vec![Felt::from(seq), pair_id, Felt::from(u8::from(sell))],
            )
            .await?;
        if values.len() != 9 {
            return Err("capacity view has an unexpected shape".into());
        }
        Ok(CapacityView {
            bound: u128_of(values[0])?,
            total: u128_of(values[1])?,
            scale: u128_of(values[2])?,
            opened_at: u64_of(values[3])?,
            consumed_base: u128_of(values[4])?,
            pool_quote: u128_of(values[5])?,
            m1: u128_of(values[6])?,
            status: u64_of(values[7])? as u8,
            generation: u64_of(values[8])?,
        })
    }

    /// the exchange's events from `from_block` through the block `confirmations` below the tip,
    /// each with its block, and the scanned tip's number and hash.
    pub async fn events(
        &self,
        from_block: u64,
        confirmations: u64,
    ) -> Result<(Vec<(u64, ChainEvent)>, Option<(u64, Felt)>), String> {
        let (tip, _) = self.snip36.latest_block().await?;
        let Some(latest) = tip
            .checked_sub(confirmations)
            .filter(|latest| *latest >= from_block)
        else {
            return Ok((Vec::new(), None));
        };
        let deposit = get_selector_from_name("DepositActivated").expect("event name");
        let transition = get_selector_from_name("TransitionSettled").expect("event name");
        let finalized = get_selector_from_name("WithdrawalFinalized").expect("event name");
        let mut events = Vec::new();
        let mut continuation = None;
        loop {
            let page = self
                .snip36
                .provider
                .get_events(
                    EventFilter {
                        from_block: Some(BlockId::Number(from_block)),
                        to_block: Some(BlockId::Number(latest)),
                        address: Some(starknet_rust_core::types::AddressFilter::Single(
                            self.exchange,
                        )),
                        keys: None,
                    },
                    continuation.clone(),
                    EVENT_PAGE,
                )
                .await
                .map_err(|error| format!("exchange events: {error}"))?;
            for event in page.events {
                let Some(selector) = event.keys.first().copied() else {
                    continue;
                };
                let block = event.block_number.ok_or("an event has no block")?;
                let field = |index: usize| {
                    event
                        .data
                        .get(index)
                        .copied()
                        .ok_or_else(|| "event is truncated".to_string())
                };
                if selector == deposit {
                    events.push((
                        block,
                        ChainEvent::Deposit {
                            deposit_root: field(1)?,
                        },
                    ));
                } else if selector == transition {
                    let seq = u64_of(*event.keys.get(1).ok_or("event is truncated")?)? as u32;
                    events.push((
                        block,
                        ChainEvent::Transition {
                            seq,
                            output_root: field(1)?,
                            transaction_hash: event.transaction_hash,
                        },
                    ));
                } else if selector == finalized {
                    events.push((
                        block,
                        ChainEvent::WithdrawalFinalized {
                            nullifier: *event.keys.get(1).ok_or("event is truncated")?,
                        },
                    ));
                }
            }
            continuation = page.continuation_token;
            if continuation.is_none() {
                break;
            }
        }
        Ok((events, Some((latest, self.block_hash(latest).await?))))
    }

    pub async fn block_hash(&self, number: u64) -> Result<Felt, String> {
        self.snip36.block_hash(number).await
    }

    /// the output leaves of a transition, decoded from its transaction's calldata: the recovery
    /// path when the operator did not record them itself.
    pub async fn transition_leaves(&self, transaction_hash: Felt) -> Result<Vec<Felt>, String> {
        let transaction = self
            .snip36
            .provider
            .get_transaction_by_hash(transaction_hash, None)
            .await
            .map_err(|error| format!("transition transaction: {error}"))?;
        let calldata = match transaction {
            Transaction::Invoke(InvokeTransaction::V3(invoke)) => invoke.calldata,
            _ => return Err("the transition was not an invoke v3".into()),
        };
        let selector = get_selector_from_name("submit_transition").expect("entrypoint name");
        let calldata = calldata.into_iter().map(to_core).collect::<Vec<_>>();
        let arguments = zylith_core::exchange::multicall_arguments(
            &calldata,
            to_core(self.exchange),
            to_core(selector),
        )
        .map_err(|error| error.to_string())?;
        decode_output_leaves(&arguments.into_iter().map(from_core).collect::<Vec<_>>())
    }
}

/// the output leaves of `submit_transition`'s calldata.
pub fn decode_output_leaves(arguments: &[Felt]) -> Result<Vec<Felt>, String> {
    let arguments = arguments
        .iter()
        .map(|felt| to_core(*felt))
        .collect::<Vec<_>>();
    Ok(zylith_core::exchange::transition_output_records(&arguments)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|record| from_core(record.leaf))
        .collect())
}

/// the chain batch for a transition's outputs, checked against its published root.
pub fn transition_batch(
    seq: u32,
    output_root: Felt,
    leaves: Vec<Felt>,
    block: u64,
) -> Result<NoteBatch, String> {
    let core_leaves = leaves.iter().map(|leaf| to_core(*leaf)).collect::<Vec<_>>();
    if !core_leaves.len().is_power_of_two()
        || from_core(zylith_core::exchange::output_tree_root(&core_leaves)) != output_root
    {
        return Err(format!(
            "transition {seq}'s leaves do not match its output root"
        ));
    }
    Ok(NoteBatch {
        root: output_root,
        leaves,
        seq: Some(seq),
        block,
    })
}

#[cfg(test)]
mod tests {
    use zylith_core::exchange::fixtures::*;
    use zylith_core::exchange::*;

    use super::*;
    use crate::config::from_core;

    #[test]
    fn output_leaves_decode_from_the_submitted_calldata() {
        let result = crossed();
        let mut attestations = attestations(&result.public);
        sign_price_batch(
            result.public.chain_context,
            &mut attestations,
            &starknet_crypto::Felt::ONE,
        )
        .unwrap();
        let calldata = transition_calldata(&result.public, &attestations)
            .unwrap()
            .into_iter()
            .map(from_core)
            .collect::<Vec<_>>();
        let leaves = decode_output_leaves(&calldata).unwrap();
        assert_eq!(
            leaves,
            result
                .public
                .output_records
                .iter()
                .map(|record| from_core(record.leaf))
                .collect::<Vec<_>>()
        );
        assert!(
            transition_batch(1, from_core(result.public.output_root), leaves.clone(), 0).is_ok()
        );
        assert!(
            transition_batch(
                1,
                from_core(result.public.output_root) + Felt::ONE,
                leaves,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn the_note_index_proves_membership_of_every_output() {
        let result = crossed();
        let mut index = NoteIndex::default();
        index
            .append(NoteBatch {
                root: Felt::from(7_u8),
                leaves: vec![Felt::from(7_u8)],
                seq: None,
                block: 0,
            })
            .unwrap();
        let leaves = result
            .public
            .output_records
            .iter()
            .map(|record| from_core(record.leaf))
            .collect::<Vec<_>>();
        let root = index
            .append(transition_batch(1, from_core(result.public.output_root), leaves, 0).unwrap())
            .unwrap();
        for output in &result.outputs {
            let membership = index
                .membership(from_core(output.note.output_leaf()))
                .expect("output is indexed");
            assert_eq!(
                from_core(membership.root(output.note.output_leaf()).unwrap()),
                root
            );
        }
    }

    #[test]
    fn a_rewind_drops_the_batches_of_reorganized_blocks() {
        let mut index = NoteIndex::starting_at(0);
        for (block, root) in [(5_u64, 7_u8), (9, 8), (12, 9)] {
            index
                .append(NoteBatch {
                    root: Felt::from(root),
                    leaves: vec![Felt::from(root)],
                    seq: None,
                    block,
                })
                .unwrap();
        }
        index.next_block = 13;
        index.cursor_hash = Felt::ONE;
        let before = index.root();
        index.rewind(9).unwrap();
        assert_eq!(index.batches.len(), 1);
        assert_eq!((index.next_block, index.cursor_hash), (9, Felt::ZERO));
        assert!(index.membership(Felt::from(8_u8)).is_none());
        index
            .append(NoteBatch {
                root: Felt::from(8_u8),
                leaves: vec![Felt::from(8_u8)],
                seq: None,
                block: 9,
            })
            .unwrap();
        index
            .append(NoteBatch {
                root: Felt::from(9_u8),
                leaves: vec![Felt::from(9_u8)],
                seq: None,
                block: 12,
            })
            .unwrap();
        assert_eq!(index.root(), before);
    }
}

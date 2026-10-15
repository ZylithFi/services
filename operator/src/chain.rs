//! what the operator reads from the chain: the exchange's views and its events, folded into the
//! note index every funding note and withdrawal proves membership against.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
    #[serde(with = "note_batches")]
    pub batches: Vec<Arc<NoteBatch>>,
    pub next_block: u64,
    /// the hash of block `next_block - 1` when it was scanned; zero before the first scan.
    #[serde(default)]
    pub cursor_hash: Felt,
    #[serde(skip)]
    positions: BTreeMap<[u8; 32], (usize, usize)>,
    #[serde(skip)]
    tree: Option<zylith_core::exchange::NoteAccumulator>,
}

mod note_batches {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        batches: &[Arc<NoteBatch>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(batches.iter().map(Arc::as_ref))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Arc<NoteBatch>>, D::Error> {
        Vec::<NoteBatch>::deserialize(deserializer)
            .map(|batches| batches.into_iter().map(Arc::new).collect())
    }
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
        self.batches.push(Arc::new(batch));
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

    /// shares each requested immutable batch and captures its path against this exact root. no
    /// leaf conversion or output-subtree hashing occurs until the snapshot is built.
    pub fn prepare_memberships(
        &self,
        leaves: impl IntoIterator<Item = Felt>,
    ) -> PreparedNoteMemberships {
        let mut requested: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for leaf in leaves {
            if let Some((batch, index)) = self.positions.get(&leaf.to_bytes_be()) {
                requested.entry(*batch).or_default().insert(*index);
            }
        }
        let mut batches = BTreeMap::new();
        let mut positions = BTreeMap::new();
        if let Some(tree) = &self.tree {
            for (batch, indices) in requested {
                if let Some(snapshot) = tree.prepare_memberships(batch) {
                    for index in &indices {
                        positions.insert(self.batches[batch].leaves[*index].to_bytes_be(), batch);
                    }
                    batches.insert(
                        batch,
                        (
                            Arc::clone(&self.batches[batch]),
                            indices.into_iter().collect(),
                            snapshot,
                        ),
                    );
                }
            }
        }
        PreparedNoteMemberships {
            root: self.root(),
            batches,
            positions,
            memberships: BTreeMap::new(),
        }
    }
}

pub struct PreparedNoteMemberships {
    root: Felt,
    batches: BTreeMap<
        usize,
        (
            Arc<NoteBatch>,
            Vec<usize>,
            zylith_core::exchange::NoteMembershipBatch,
        ),
    >,
    positions: BTreeMap<[u8; 32], usize>,
    memberships: BTreeMap<[u8; 32], NoteMembership>,
}

impl PreparedNoteMemberships {
    pub fn root(&self) -> Felt {
        self.root
    }

    fn build_batch(&mut self, batch_index: usize) {
        if let Some((batch, indices, snapshot)) = self.batches.remove(&batch_index) {
            let leaves = batch.leaves.iter().copied().map(to_core).collect();
            if let Some(paths) = snapshot.build(leaves, indices) {
                for (leaf, membership) in paths {
                    self.memberships.insert(leaf.to_bytes_be(), membership);
                }
            }
        }
    }

    /// builds a batch only when a candidate needs it, then reuses its exact-root paths.
    pub fn membership(&mut self, leaf: Felt) -> Option<NoteMembership> {
        let key = leaf.to_bytes_be();
        let batch_index = *self.positions.get(&key)?;
        self.build_batch(batch_index);
        self.memberships.get(&key).cloned()
    }

    #[cfg(test)]
    pub fn build(mut self) -> (Felt, BTreeMap<[u8; 32], NoteMembership>) {
        while let Some(batch_index) = self.batches.keys().next().copied() {
            self.build_batch(batch_index);
        }
        (self.root, self.memberships)
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
    ResidualRecoveryRequested {
        nullifier: Felt,
        matures_at: u64,
    },
    ResidualRecoveryFinalized {
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
        let residual_requested =
            get_selector_from_name("ResidualRecoveryRequested").expect("event name");
        let residual_finalized =
            get_selector_from_name("ResidualRecoveryFinalized").expect("event name");
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
                } else if selector == residual_requested {
                    events.push((
                        block,
                        ChainEvent::ResidualRecoveryRequested {
                            nullifier: *event.keys.get(1).ok_or("event is truncated")?,
                            matures_at: u64_of(field(0)?)?,
                        },
                    ));
                } else if selector == residual_finalized {
                    events.push((
                        block,
                        ChainEvent::ResidualRecoveryFinalized {
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
    fn prepared_memberships_match_individual_paths_and_deduplicate_requests() {
        let mut index = NoteIndex::default();
        let mut leaves = Vec::new();
        for (batch, depth) in [0_usize, 2, 5].into_iter().enumerate() {
            let batch_leaves = (0..1_usize << depth)
                .map(|leaf| Felt::from((100 * batch + leaf + 1) as u64))
                .collect::<Vec<_>>();
            let core_leaves = batch_leaves
                .iter()
                .copied()
                .map(to_core)
                .collect::<Vec<_>>();
            index
                .append(NoteBatch {
                    root: from_core(output_tree_root(&core_leaves)),
                    leaves: batch_leaves.clone(),
                    seq: Some(batch as u32 + 1),
                    block: batch as u64 + 1,
                })
                .unwrap();
            leaves.extend(batch_leaves);
        }
        let expected = leaves
            .iter()
            .map(|leaf| (leaf.to_bytes_be(), index.membership(*leaf).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let mut requested = leaves.clone();
        requested.extend(leaves.iter().rev().copied());
        requested.push(Felt::from(999_u64));
        let snapshot = index.prepare_memberships(requested);
        assert_eq!(snapshot.batches.len(), 3);
        for (position, (batch, _, _)) in snapshot.batches.values().enumerate() {
            assert!(Arc::ptr_eq(batch, &index.batches[position]));
        }
        let (root, actual) = snapshot.build();
        assert_eq!(root, index.root());
        assert_eq!(actual, expected);
        for leaf in &leaves {
            assert_eq!(
                from_core(actual[&leaf.to_bytes_be()].root(to_core(*leaf)).unwrap()),
                root
            );
        }
        assert!(index.prepare_memberships([]).build().1.is_empty());
        assert!(
            index
                .prepare_memberships([Felt::from(999_u64)])
                .build()
                .1
                .is_empty()
        );
    }

    #[tokio::test]
    async fn prepared_memberships_keep_their_snapshot_after_rewind_without_holding_the_lock() {
        let mut index = NoteIndex::default();
        for (leaf, block) in [(7_u64, 5), (8, 9)] {
            index
                .append(NoteBatch {
                    root: Felt::from(leaf),
                    leaves: vec![Felt::from(leaf)],
                    seq: None,
                    block,
                })
                .unwrap();
        }
        let original_root = index.root();
        let expected = index.membership(Felt::from(8_u64)).unwrap();
        let shared = std::sync::Arc::new(tokio::sync::Mutex::new(index));
        let mut locked = shared.lock().await;
        let snapshot = locked.prepare_memberships([Felt::from(8_u64)]);
        locked.rewind(9).unwrap();
        locked
            .append(NoteBatch {
                root: Felt::from(9_u64),
                leaves: vec![Felt::from(9_u64)],
                seq: None,
                block: 9,
            })
            .unwrap();
        let replacement_root = locked.root();
        assert_ne!(replacement_root, original_root);
        let (root, memberships) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::task::spawn_blocking(move || snapshot.build()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(root, original_root);
        let removed = Felt::from(8_u64);
        assert_eq!(memberships[&removed.to_bytes_be()], expected);
        assert_eq!(from_core(expected.root(to_core(removed)).unwrap()), root);
        assert!(locked.prepare_memberships([removed]).build().1.is_empty());
        let replacement = Felt::from(9_u64);
        let (new_root, new_memberships) = locked.prepare_memberships([replacement]).build();
        assert_eq!(new_root, replacement_root);
        assert_eq!(
            from_core(
                new_memberships[&replacement.to_bytes_be()]
                    .root(to_core(replacement))
                    .unwrap()
            ),
            new_root
        );
    }

    #[test]
    fn lazy_memberships_build_only_requested_batches_and_reuse_cached_paths() {
        let mut index = NoteIndex::default();
        for batch in 0..3_u64 {
            let leaves = (0..4)
                .map(|leaf| Felt::from(10 * batch + leaf + 1))
                .collect::<Vec<_>>();
            let root = output_tree_root(&leaves.iter().copied().map(to_core).collect::<Vec<_>>());
            index
                .append(NoteBatch {
                    root: from_core(root),
                    leaves,
                    seq: Some(batch as u32),
                    block: batch,
                })
                .unwrap();
        }
        let requested = [1_u64, 2, 11, 21].map(Felt::from);
        let expected = requested.map(|leaf| index.membership(leaf).unwrap());
        let mut snapshot = index.prepare_memberships(requested);
        assert_eq!(snapshot.batches.len(), 3);
        assert!(snapshot.memberships.is_empty());
        assert!(snapshot.membership(Felt::from(999_u64)).is_none());
        assert_eq!(snapshot.batches.len(), 3);
        assert_eq!(snapshot.membership(requested[0]), Some(expected[0].clone()));
        assert_eq!(snapshot.batches.len(), 2);
        assert_eq!(snapshot.memberships.len(), 2);
        assert_eq!(snapshot.membership(requested[1]), Some(expected[1].clone()));
        assert_eq!(snapshot.membership(requested[0]), Some(expected[0].clone()));
        assert_eq!(snapshot.batches.len(), 2);
        let root = snapshot.root();
        index.rewind(1).unwrap();
        assert_ne!(index.root(), root);
        assert_eq!(snapshot.membership(requested[3]), Some(expected[3].clone()));
        assert_eq!(snapshot.batches.len(), 1);
        assert_eq!(
            from_core(expected[3].root(to_core(requested[3])).unwrap()),
            root
        );
    }

    #[test]
    fn lazy_memberships_do_not_retry_or_relabel_a_malformed_batch() {
        let mut index = NoteIndex::default();
        index
            .append(NoteBatch {
                root: Felt::ONE,
                leaves: vec![Felt::ONE, Felt::TWO, Felt::from(3_u64)],
                seq: None,
                block: 0,
            })
            .unwrap();
        let mut snapshot = index.prepare_memberships([Felt::ONE]);
        let root = snapshot.root();
        assert!(snapshot.membership(Felt::ONE).is_none());
        assert!(snapshot.batches.is_empty());
        assert!(snapshot.membership(Felt::ONE).is_none());
        assert!(snapshot.memberships.is_empty());
        assert_eq!(snapshot.root(), root);
    }

    #[test]
    fn prepared_memberships_survive_reindex_and_preserve_first_duplicate_position() {
        #[derive(Serialize)]
        struct LegacyNoteIndex {
            batches: Vec<NoteBatch>,
            next_block: u64,
            cursor_hash: Felt,
        }

        let mut index = NoteIndex::default();
        let leaf = Felt::from(7_u64);
        for block in 1..=2 {
            index
                .append(NoteBatch {
                    root: leaf,
                    leaves: vec![leaf],
                    seq: None,
                    block,
                })
                .unwrap();
        }
        let expected = index.membership(leaf).unwrap();
        let legacy = LegacyNoteIndex {
            batches: index
                .batches
                .iter()
                .map(|batch| batch.as_ref().clone())
                .collect(),
            next_block: index.next_block,
            cursor_hash: index.cursor_hash,
        };
        let saved = serde_json::to_vec(&legacy).unwrap();
        assert_eq!(serde_json::to_vec(&index).unwrap(), saved);
        let mut restored: NoteIndex = serde_json::from_slice(&saved).unwrap();
        assert!(restored.prepare_memberships([leaf]).build().1.is_empty());
        restored.reindex().unwrap();
        let (root, memberships) = restored.prepare_memberships([leaf, leaf]).build();
        assert_eq!(root, index.root());
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[&leaf.to_bytes_be()], expected);
        assert_eq!(from_core(expected.root(to_core(leaf)).unwrap()), root);
    }

    #[test]
    fn prepared_funding_paths_leave_the_transition_witness_and_commitment_unchanged() {
        let buyer = user(41);
        let funding = (0..4)
            .map(|i| deposit(&buyer, QUOTE, 300, 4100 + i))
            .collect::<Vec<_>>();
        let mut leaves = funding
            .iter()
            .map(NoteFields::output_leaf)
            .collect::<Vec<_>>();
        leaves.extend(
            (leaves.len()..16).map(|i| zylith_core::exchange::short_string(&format!("pad-{i}"))),
        );
        let batch_root = output_tree_root(&leaves);
        let mut notes = Notes::default();
        notes.tree.append(batch_root);
        for note in &funding {
            notes.located.push((note.output_leaf(), 0, leaves.clone()));
        }
        let admission = new_order(&notes, &buyer, false, true, 5, 105, &funding);
        let original_input = input(1, vec![], vec![admission], notes.root(), 100);
        let original = build_transition(&original_input).unwrap();
        let mut index = NoteIndex::default();
        index
            .append(NoteBatch {
                root: from_core(batch_root),
                leaves: leaves.into_iter().map(from_core).collect(),
                seq: Some(1),
                block: 1,
            })
            .unwrap();
        let mut memberships =
            index.prepare_memberships(funding.iter().map(|note| from_core(note.output_leaf())));
        let root = memberships.root();
        let mut shared_input = original_input.clone();
        assert_eq!(root, from_core(shared_input.note_root));
        for funding in &mut shared_input.new_orders[0].funding {
            funding.membership = memberships
                .membership(from_core(funding.note.output_leaf()))
                .unwrap();
        }
        let shared = build_transition(&shared_input).unwrap();
        assert_eq!(shared.witness, original.witness);
        assert_eq!(
            serde_json::to_value(shared.public).unwrap(),
            serde_json::to_value(original.public).unwrap()
        );
        shared_input.new_orders[0].funding[0]
            .membership
            .accumulator_path[0] += zylith_core::exchange::short_string("tampered");
        assert!(build_transition(&shared_input).is_err());
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

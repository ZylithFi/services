//! the operator's durable state and its encrypted store.
//!
//! the operator is the only party that sees the book in the clear; everything here is sealed
//! with aes-256-gcm under the data key and replaced atomically after every change.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use starknet_rust_core::types::Felt;
use zeroize::Zeroizing;
use zylith_core::exchange::{
    BookEntry, CancelRequest, OrderReport, OrderRequest, TransitionResult, WithdrawRequest,
};

use crate::chain::NoteIndex;
use crate::snip36::{PreparedSubmission, Proof};

const STATE_FILE: &str = "operator-state.bin";
const STATE_VERSION: u32 = 2;

/// an order the operator accepted and will admit when it can participate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingOrder {
    pub request: OrderRequest,
    pub received_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancellationTombstone {
    pub cancel_authority: Felt,
    pub cancelled_at_ms: u64,
    pub expires_at_ms: u64,
    pub effective_after_seq: u32,
}

/// an external capacity opened by a confirmed transition, until a later transition applies its
/// outcome.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenCapacity {
    pub seq: u32,
    pub pair_id: Felt,
    pub sell: bool,
    pub opened_at_ms: u64,
    /// whether the searcher leg for it is finished: it landed with its transition or as a
    /// follow-up, the capacity closed, or its follow-ups ran out.
    #[serde(default)]
    pub leg_attempted: bool,
    /// a follow-up leg sent and not yet final.
    #[serde(default)]
    pub leg_transaction: Option<Felt>,
    /// follow-up legs sent so far.
    #[serde(default)]
    pub leg_submissions: u8,
    /// when the follow-up leg may be tried again.
    #[serde(default)]
    pub leg_retry_at_ms: u64,
    /// when the chain stops accepting a fill, from its open time and the external window; zero
    /// until the capacity is first read.
    #[serde(default)]
    pub window_closes_ms: u64,
    /// whether a fill of this transition already funded the transition that settles its fills.
    #[serde(default)]
    pub outcome_funded: bool,
}

impl OpenCapacity {
    /// the same capacity: the chain keys it by transition, pair and side.
    pub fn same(&self, other: &Self) -> bool {
        (self.seq, self.pair_id, self.sell) == (other.seq, other.pair_id, other.sell)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransitionStage {
    Proving,
    Proven,
    Submitted { transaction_hash: Felt },
}

/// the private padding stream key assigned once to one logical transition.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransitionPaddingSeed(Felt);

impl TransitionPaddingSeed {
    pub fn new(value: Felt) -> Result<Self, String> {
        if value == Felt::ZERO {
            return Err("a transition padding seed cannot be zero".into());
        }
        Ok(Self(value))
    }

    pub fn expose(self) -> Felt {
        self.0
    }
}

impl fmt::Debug for TransitionPaddingSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransitionPaddingSeed([redacted])")
    }
}

/// a transition built on the book the chain will hold once its predecessors land.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InFlight {
    pub seq: u32,
    pub close_time_ms: u64,
    pub padding_seed: TransitionPaddingSeed,
    pub result: TransitionResult,
    pub calldata: Vec<Felt>,
    pub admitted: Vec<Felt>,
    pub cancelled: Vec<Felt>,
    pub applied_capacities: Vec<OpenCapacity>,
    pub stage: TransitionStage,
    pub proof: Option<Proof>,
    /// the exact signed settlement transaction, durably stored before its first broadcast.
    #[serde(default)]
    pub prepared_submission: Option<PreparedSubmission>,
    /// the external legs carried by `prepared_submission`.
    #[serde(default)]
    pub prepared_legged: Vec<(Felt, bool)>,
    pub built_at_ms: u64,
    /// the capacities, by pair and side, whose legs the submitted transaction carries.
    #[serde(default)]
    pub legged: Vec<(Felt, bool)>,
    /// the leg made a submission revert: the same proven transition goes without it.
    #[serde(default)]
    pub leg_dropped: bool,
    /// sent only for the searcher legs its reservations enable: it is dropped, never sent,
    /// when those legs are gone, and its first leg pays for it.
    #[serde(default)]
    pub for_legs: bool,
}

/// one line of an order's history, served to its owner. output notes are not kept: the wallet
/// recovers them from the public transition records.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderEvent {
    pub seq: u32,
    pub close_time_ms: u64,
    pub report: OrderReport,
}

/// what outlives a closed order's pruned history: that it closed, when and how, so a wallet
/// restored long after still sees it as closed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClosedOrder {
    pub seq: u32,
    pub close_time_ms: u64,
    pub removal: zylith_core::exchange::Removal,
}

/// a withdrawal's progress. the proving stage is also where a job resumes after a restart: the driver
/// restarts proving for every proving job that has no task running.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WithdrawalStage {
    Proving,
    Requested {
        transaction_hash: Felt,
        matures_at_ms: u64,
    },
    Finalizing {
        transaction_hash: Felt,
    },
    Finalized {
        transaction_hash: Felt,
    },
    Failed {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalJob {
    pub request: WithdrawRequest,
    pub nullifier: Felt,
    pub stage: WithdrawalStage,
    /// the exact signed request transaction, retained until chain reconciliation proves it
    /// landed or reverted.
    #[serde(default)]
    pub prepared_submission: Option<PreparedSubmission>,
    pub updated_at_ms: u64,
}

/// a permissionless recovery request the operator will finalize if its owner goes offline.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingResidualRecovery {
    pub nullifier: Felt,
    pub requested_at_ms: u64,
    pub matures_at_ms: u64,
    pub requested_block: u64,
    #[serde(default)]
    pub retired: bool,
    #[serde(default)]
    pub finalization_transaction: Option<Felt>,
    #[serde(default)]
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorState {
    pub version: u32,
    /// the chain's seq and book as of the last confirmed transition.
    pub confirmed_seq: u32,
    pub confirmed_close_ms: u64,
    pub book: Vec<BookEntry>,
    pub notes: NoteIndex,
    pub pending_orders: BTreeMap<String, PendingOrder>,
    /// durable cancellation tombstones. the order id is a content hash, so it is also the
    /// immutable generation identifier for every retry. a tombstone remains through the signed
    /// order expiry, preventing a cancelled pending order from being replayed later.
    #[serde(default)]
    pub cancelled_orders: BTreeMap<String, CancellationTombstone>,
    pub cancellations: BTreeMap<String, (CancelRequest, u64)>,
    pub capacities: Vec<OpenCapacity>,
    pub in_flight: Vec<InFlight>,
    pub orders: BTreeMap<String, Vec<OrderEvent>>,
    /// closed orders whose history was pruned.
    #[serde(default)]
    pub closed_orders: BTreeMap<String, ClosedOrder>,
    pub withdrawals: BTreeMap<String, WithdrawalJob>,
    /// finalized permissionless residual exits, retained with their block for reorg-safe cleanup.
    #[serde(default)]
    pub recovered_residuals: BTreeMap<String, u64>,
    /// accepted residual exits, finalized by the operator only as a liveness service.
    #[serde(default)]
    pub pending_residual_recoveries: BTreeMap<String, PendingResidualRecovery>,
    /// output leaves of our own transitions, by seq, until the chain sync folds them in.
    pub transition_leaves: BTreeMap<u32, Vec<Felt>>,
    /// the l2 gas a transition costs, learned from the fees of landed transitions.
    #[serde(default)]
    pub transition_gas: u64,
    /// since when a crossing has waited for its fees to cover a transition.
    #[serde(default)]
    pub uneconomic_since_ms: Option<u64>,
    /// Release-bound adaptive ceiling learned only from a structured permanent capacity failure.
    /// It monotonically decreases for one capacity profile and is reset when that profile changes.
    #[serde(default)]
    pub proof_capacity_profile_id: Option<String>,
    #[serde(default)]
    pub proof_capacity_admission_limit: Option<usize>,
}

impl OperatorState {
    pub fn new(sync_from_block: u64) -> Self {
        Self {
            version: STATE_VERSION,
            confirmed_seq: 0,
            confirmed_close_ms: 0,
            book: Vec::new(),
            notes: NoteIndex::starting_at(sync_from_block),
            pending_orders: BTreeMap::new(),
            cancelled_orders: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            capacities: Vec::new(),
            in_flight: Vec::new(),
            orders: BTreeMap::new(),
            closed_orders: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            recovered_residuals: BTreeMap::new(),
            pending_residual_recoveries: BTreeMap::new(),
            transition_leaves: BTreeMap::new(),
            transition_gas: 0,
            uneconomic_since_ms: None,
            proof_capacity_profile_id: None,
            proof_capacity_admission_limit: None,
        }
    }
}

pub fn key(felt: &Felt) -> String {
    format!("{felt:#x}")
}

/// the sealed state on disk: a primary file and, when configured, a replica on another volume.
/// every write is flushed to disk before the rename that publishes it, and the directory entry
/// after it, so a crash leaves either the old state or the new one.
pub struct Store {
    path: PathBuf,
    replica: Option<PathBuf>,
    cipher: Aes256Gcm,
}

impl Store {
    pub fn open(
        data_dir: &Path,
        replica_dir: Option<&Path>,
        key: &[u8; 32],
    ) -> Result<Self, String> {
        for dir in std::iter::once(data_dir).chain(replica_dir) {
            fs::create_dir_all(dir)
                .map_err(|error| format!("data dir {}: {error}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("data dir {}: {error}", dir.display()))?;
            }
        }
        Ok(Self {
            path: data_dir.join(STATE_FILE),
            replica: replica_dir.map(|dir| dir.join(STATE_FILE)),
            cipher: Aes256Gcm::new_from_slice(key).expect("32-byte key"),
        })
    }

    /// the primary state, or the replica when the primary is missing or unreadable.
    pub fn load(&self) -> Result<Option<OperatorState>, String> {
        let primary = self.load_from(&self.path);
        let Some(replica) = &self.replica else {
            return primary;
        };
        match primary {
            Ok(Some(state)) => Ok(Some(state)),
            primary => match self.load_from(replica) {
                Ok(Some(state)) => {
                    eprintln!("operator state restored from the replica");
                    Ok(Some(state))
                }
                _ => primary,
            },
        }
    }

    fn load_from(&self, path: &Path) -> Result<Option<OperatorState>, String> {
        let sealed = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("state read: {error}")),
        };
        if sealed.len() < 12 {
            return Err("state file is truncated".into());
        }
        let (nonce, ciphertext) = sealed.split_at(12);
        let plaintext = Zeroizing::new(
            self.cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| "state file does not decrypt under the data key".to_string())?,
        );
        let mut state: OperatorState =
            serde_json::from_slice(&plaintext).map_err(|error| format!("state decode: {error}"))?;
        if state.version != STATE_VERSION {
            return Err(format!("state version {} is not supported", state.version));
        }
        state.notes.reindex()?;
        Ok(Some(state))
    }

    pub fn save(&self, state: &OperatorState) -> Result<(), String> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(state).map_err(|error| format!("state encode: {error}"))?,
        );
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| "state encryption failed".to_string())?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);
        write_durably(&self.path, &sealed)?;
        if let Some(replica) = &self.replica {
            write_durably(replica, &sealed)?;
        }
        Ok(())
    }
}

fn write_durably(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary).map_err(|error| format!("state write: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("state write: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("state commit: {error}"))?;
    if let Some(dir) = path.parent() {
        fs::File::open(dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| format!("state commit: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use starknet_rust_core::types::{
        BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV3, DataAvailabilityMode,
        ResourceBounds, ResourceBoundsMapping,
    };
    use zylith_core::exchange::fixtures::{BASE, Notes, deposit, input, new_order, user};
    use zylith_core::exchange::{Signature, WithdrawRequest, build_transition};

    use super::*;

    fn directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zylith-operator-{name}-{}", std::process::id()))
    }

    #[test]
    fn the_store_round_trips_and_rejects_another_key() {
        let dir = directory("roundtrip");
        let store = Store::open(&dir, None, &[7; 32]).unwrap();
        let mut state = OperatorState::new(5);
        state.confirmed_seq = 3;
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().unwrap().confirmed_seq, 3);
        assert!(!dir.join("operator-state.tmp").exists());
        assert!(Store::open(&dir, None, &[8; 32]).unwrap().load().is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_lost_or_corrupted_primary_restores_from_the_replica() {
        let (dir, replica) = (directory("primary"), directory("replica"));
        let store = Store::open(&dir, Some(&replica), &[7; 32]).unwrap();
        let mut state = OperatorState::new(5);
        state.confirmed_seq = 9;
        store.save(&state).unwrap();

        fs::write(dir.join(STATE_FILE), b"garbage").unwrap();
        assert_eq!(store.load().unwrap().unwrap().confirmed_seq, 9);
        fs::remove_file(dir.join(STATE_FILE)).unwrap();
        assert_eq!(store.load().unwrap().unwrap().confirmed_seq, 9);
        // a readable primary wins over the replica.
        state.confirmed_seq = 10;
        Store::open(&dir, None, &[7; 32])
            .unwrap()
            .save(&state)
            .unwrap();
        assert_eq!(store.load().unwrap().unwrap().confirmed_seq, 10);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&replica);
    }

    #[test]
    fn a_restart_preserves_the_latest_residual_authority_and_recovery_events() {
        let dir = directory("residual-restart");
        let store = Store::open(&dir, None, &[7; 32]).unwrap();
        let owner = user(88);
        let funding = deposit(&owner, BASE, 10, 88);
        let mut notes = Notes::default();
        notes.add_deposit(&funding);
        let transition = build_transition(&input(
            1,
            vec![],
            vec![new_order(
                &notes,
                &owner,
                true,
                false,
                10,
                110,
                std::slice::from_ref(&funding),
            )],
            notes.root(),
            100,
        ))
        .unwrap();
        let nullifier = transition.residual_outputs[0].note.nullifier();
        let mut state = OperatorState::new(5);
        state.book = transition.new_book.clone();
        let prepared = PreparedSubmission {
            expected_hash: Felt::from(90_u8),
            request: BroadcastedInvokeTransaction {
                broadcasted_invoke_txn_v3: BroadcastedInvokeTransactionV3 {
                    sender_address: Felt::from(91_u8),
                    calldata: vec![Felt::from(92_u8)],
                    signature: vec![Felt::from(93_u8)],
                    nonce: Felt::ONE,
                    resource_bounds: ResourceBoundsMapping {
                        l1_gas: ResourceBounds {
                            max_amount: 1,
                            max_price_per_unit: 2,
                        },
                        l1_data_gas: ResourceBounds {
                            max_amount: 3,
                            max_price_per_unit: 4,
                        },
                        l2_gas: ResourceBounds {
                            max_amount: 5,
                            max_price_per_unit: 6,
                        },
                    },
                    tip: 0,
                    paymaster_data: Vec::new(),
                    account_deployment_data: Vec::new(),
                    nonce_data_availability_mode: DataAvailabilityMode::L1,
                    fee_data_availability_mode: DataAvailabilityMode::L1,
                    proof_facts: None,
                    is_query: false,
                },
                proof: None,
            },
        };
        let padding_seed =
            TransitionPaddingSeed::new(Felt::from_bytes_be(&transition.witness[6].to_bytes_be()))
                .unwrap();
        state.in_flight.push(InFlight {
            seq: 1,
            close_time_ms: 6_000,
            padding_seed,
            result: transition,
            calldata: vec![Felt::from(94_u8)],
            admitted: Vec::new(),
            cancelled: Vec::new(),
            applied_capacities: Vec::new(),
            stage: TransitionStage::Proven,
            proof: None,
            prepared_submission: Some(prepared.clone()),
            prepared_legged: Vec::new(),
            built_at_ms: 6_001,
            legged: Vec::new(),
            leg_dropped: false,
            for_legs: false,
        });
        state.withdrawals.insert(
            key(&funding.nullifier()),
            WithdrawalJob {
                request: WithdrawRequest {
                    note: funding,
                    exit_commitment: Felt::from(95_u8),
                    exit_authority: Felt::from(96_u8),
                    authorization: Signature {
                        r: Felt::from(97_u8),
                        s: Felt::from(98_u8),
                    },
                },
                nullifier: Felt::from(99_u8),
                stage: WithdrawalStage::Proving,
                prepared_submission: Some(prepared.clone()),
                updated_at_ms: 6_002,
            },
        );
        state.recovered_residuals.insert(key(&nullifier), 19);
        state.proof_capacity_profile_id = Some("ab".repeat(32));
        state.proof_capacity_admission_limit = Some(7);
        state.pending_residual_recoveries.insert(
            key(&Felt::from(77_u8)),
            PendingResidualRecovery {
                nullifier: Felt::from(77_u8),
                requested_at_ms: 1_000,
                matures_at_ms: 2_000,
                requested_block: 20,
                retired: true,
                finalization_transaction: Some(Felt::from(78_u8)),
                updated_at_ms: 1_500,
            },
        );
        store.save(&state).unwrap();

        let restored = store.load().unwrap().unwrap();
        assert_eq!(restored.book, state.book);
        assert_eq!(restored.in_flight[0].padding_seed, padding_seed);
        assert_eq!(
            serde_json::to_value(restored.in_flight[0].prepared_submission.as_ref().unwrap())
                .unwrap(),
            serde_json::to_value(&prepared).unwrap()
        );
        assert_eq!(restored.recovered_residuals, state.recovered_residuals);
        assert_eq!(
            restored.proof_capacity_profile_id,
            state.proof_capacity_profile_id
        );
        assert_eq!(restored.proof_capacity_admission_limit, Some(7));
        assert_eq!(restored.withdrawals.len(), 1);
        assert_eq!(
            serde_json::to_value(
                restored
                    .withdrawals
                    .values()
                    .next()
                    .unwrap()
                    .prepared_submission
                    .as_ref()
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(&prepared).unwrap()
        );
        assert_eq!(
            restored.pending_residual_recoveries,
            state.pending_residual_recoveries
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

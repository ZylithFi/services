//! the operator's pipeline.
//!
//! every epoch close freezes the pending orders, cancellations and applicable outcomes and builds
//! a transition on the book the chain will hold once the transitions already in flight land. a
//! close with nothing worth settling sends nothing: the orders simply stay for the next close.
//! a worthwhile transition is proven at once, so proving overlaps the following epochs; the
//! driver submits proven transitions strictly in seq order, adds the searcher leg for profitable
//! external capacity, and commits or rolls back as receipts arrive. a failed transition drops
//! itself and everything built on it, and the next close rebuilds from the confirmed book.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use starknet_rust_core::types::Felt;
use tokio::sync::Mutex;
use tokio::time::sleep;
use zylith_core::exchange::{
    Cancellation, OUTPUT_KIND_FEE, Outcome as ChainOutcome, ResidualNote,
    TRANSITION_MESSAGE_DOMAIN, TransitionInput, TransitionResult, WITHDRAWAL_MESSAGE_DOMAIN,
    WithdrawalInput, bound_statement_message, build_transition, build_withdrawal,
    proof_message_hash, transition_calldata, withdrawal_calldata,
};
use zylith_proof_job::ProofStatementKind;

use crate::chain::{CapacityView, Chain, ChainEvent, transition_batch};
use crate::config::{Config, from_core, to_core};
use crate::market::{LEG_MIN_PROFIT_INDEX, Market, Rate, Round};
use crate::snip36::{
    Outcome, ProofJobContext, Snip36, call, canonical_witness_hash, is_retryable_proving_error,
};
use crate::state::{
    CancellationTombstone, ClosedOrder, InFlight, OpenCapacity, OperatorState, OrderEvent,
    PendingOrder, PendingResidualRecovery, Store, TransitionStage, WithdrawalJob, WithdrawalStage,
    key,
};

const DRIVER_INTERVAL_MS: u64 = 250;
/// how long a closed order's history and a finished withdrawal stay queryable; wallets recover
/// their notes from the chain, so this only bounds the state the operator rewrites.
const HISTORY_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// how long a closed order's tombstone is kept: far past any order's lifetime, so a wallet
/// restored from an old backup still learns its orders closed.
const TOMBSTONE_RETENTION_MS: u64 = 400 * 24 * 60 * 60 * 1000;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as u64
}

fn private_padding_seed() -> starknet_crypto::Felt {
    loop {
        let mut bytes = [0_u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes[1..]);
        let seed = starknet_crypto::Felt::from_bytes_be(&bytes);
        if seed != starknet_crypto::Felt::ZERO {
            return seed;
        }
    }
}

pub struct Operator {
    pub config: Config,
    pub snip36: Snip36,
    pub market: Market,
    pub store: Store,
    pub state: Mutex<OperatorState>,
    /// withdrawals with a proving task running, so each job proves once.
    pub withdrawals_running: std::sync::Mutex<BTreeSet<String>>,
    /// transition commitments with a proving task running. this is intentionally ephemeral:
    /// persisted proving jobs restart from their encrypted witness after a process restart.
    pub transitions_running: std::sync::Mutex<BTreeSet<String>>,
    /// order ids captured by an epoch close but not yet persisted as an in-flight transition.
    /// cancellation consults this cutoff so a post-close request cannot rewrite that auction.
    /// the aligned close currently being prepared. receipt timestamps, not lock acquisition
    /// order, decide whether an order or cancellation belongs before this cutoff.
    pub closing_epoch: std::sync::Mutex<Option<u64>>,
    /// latched by a failed state write: nothing further is acknowledged, proven or sent.
    pub halted: AtomicBool,
}

impl Operator {
    pub fn chain(&self) -> Chain<'_> {
        Chain {
            snip36: &self.snip36,
            exchange: self.config.exchange,
        }
    }

    /// writes the state durably. a request is acknowledged, and a transaction built on the
    /// state is sent, only after this succeeds; a failure halts the operator for good.
    pub async fn save(&self, state: &OperatorState) -> Result<(), String> {
        persist(&self.store, &self.halted, state)
    }

    pub fn running(&self) -> Result<(), String> {
        running(&self.halted)
    }
}

/// fail-stop persistence: a failed write latches `halted`, and every later write and action is
/// refused until a restart reloads the last durable state.
pub fn persist(store: &Store, halted: &AtomicBool, state: &OperatorState) -> Result<(), String> {
    running(halted)?;
    store.save(state).map_err(|error| {
        halted.store(true, Ordering::SeqCst);
        eprintln!("operator state write failed, halting: {error}");
        format!("the operator could not persist its state: {error}")
    })
}

fn running(halted: &AtomicBool) -> Result<(), String> {
    if halted.load(Ordering::SeqCst) {
        return Err("the operator halted after a failed state write".into());
    }
    Ok(())
}

pub fn spawn(operator: Arc<Operator>) {
    let epochs = operator.clone();
    tokio::spawn(async move { epoch_loop(epochs).await });
    tokio::spawn(async move { driver_loop(operator).await });
}

async fn epoch_loop(operator: Arc<Operator>) {
    let epoch_ms = operator.config.policy.epoch_ms;
    let prepare_ms = operator.config.policy.epoch_prepare_ms;
    while operator.running().is_ok() {
        let now = now_ms();
        let close = (now / epoch_ms + 1) * epoch_ms;
        sleep(Duration::from_millis(
            close.saturating_sub(now).saturating_sub(prepare_ms),
        ))
        .await;
        if let Err(error) = close_epoch(&operator, close).await {
            eprintln!(
                "epoch close at {close} skipped: {}",
                crate::snip36::sanitize(&error)
            );
        }
        let remaining = close.saturating_sub(now_ms());
        if remaining != 0 {
            sleep(Duration::from_millis(remaining)).await;
        }
    }
}

fn scheduled_epoch_close(close_ms: u64, epoch_ms: u64) -> bool {
    epoch_ms != 0 && close_ms.is_multiple_of(epoch_ms)
}

fn reference_windows_cover_close(
    windows: impl IntoIterator<Item = (u64, u64)>,
    close_ms: u64,
) -> bool {
    windows.into_iter().all(|(observed_at_ms, valid_until_ms)| {
        observed_at_ms <= close_ms && close_ms <= valid_until_ms
    })
}

fn eligible_before_close(received_at_ms: u64, close_time_ms: u64) -> bool {
    received_at_ms < close_time_ms
}

struct ClosingEpoch<'a> {
    operator: &'a Operator,
    close_time_ms: u64,
}

impl Drop for ClosingEpoch<'_> {
    fn drop(&mut self) {
        if let Ok(mut closing) = self.operator.closing_epoch.lock()
            && *closing == Some(self.close_time_ms)
        {
            *closing = None;
        }
    }
}

impl<'a> ClosingEpoch<'a> {
    fn begin(operator: &'a Operator, close_time_ms: u64) -> Result<Self, String> {
        let mut closing = operator
            .closing_epoch
            .lock()
            .map_err(|_| "the closing-epoch cutoff lock is poisoned")?;
        if closing.is_some() {
            return Err("another epoch close is already active".into());
        }
        *closing = Some(close_time_ms);
        Ok(Self {
            operator,
            close_time_ms,
        })
    }
}

fn protected_by_closing_epoch(
    order: &PendingOrder,
    cancelled_at_ms: u64,
    closing_epoch: Option<u64>,
) -> bool {
    closing_epoch.is_some_and(|close_time_ms| {
        eligible_before_close(order.received_at_ms, close_time_ms)
            && !eligible_before_close(cancelled_at_ms, close_time_ms)
    })
}

pub(crate) fn active_closing_epoch(operator: &Operator) -> Result<Option<u64>, String> {
    operator
        .closing_epoch
        .lock()
        .map(|closing| *closing)
        .map_err(|_| "the closing-epoch cutoff lock is poisoned".into())
}

fn admitted_in_flight(state: &OperatorState, order_id: &str) -> bool {
    state
        .in_flight
        .iter()
        .any(|transition| transition.admitted.iter().map(key).any(|id| id == order_id))
}

pub(crate) fn cancellation_can_settle_offchain(
    state: &OperatorState,
    order_id: &str,
    cancelled_at_ms: u64,
    closing_epoch: Option<u64>,
) -> bool {
    state.pending_orders.get(order_id).is_some_and(|order| {
        !admitted_in_flight(state, order_id)
            && !protected_by_closing_epoch(order, cancelled_at_ms, closing_epoch)
    })
}

fn settle_pending_cancellations(state: &mut OperatorState, closing_epoch: Option<u64>) -> bool {
    let order_ids = state
        .pending_orders
        .iter()
        .filter_map(|(order_id, order)| {
            let (_, cancelled_at_ms) = state.cancellations.get(order_id)?;
            (!admitted_in_flight(state, order_id)
                && !protected_by_closing_epoch(order, *cancelled_at_ms, closing_epoch))
            .then(|| order_id.clone())
        })
        .collect::<Vec<_>>();
    for order_id in &order_ids {
        let Some(order) = state.pending_orders.remove(order_id) else {
            continue;
        };
        let Some((_, cancelled_at_ms)) = state.cancellations.remove(order_id) else {
            continue;
        };
        state.cancelled_orders.insert(
            order_id.clone(),
            CancellationTombstone {
                cancel_authority: from_core(order.request.terms.owner.cancel_authority),
                cancelled_at_ms,
                expires_at_ms: order.request.terms.expiry_ms,
                effective_after_seq: state.confirmed_seq,
            },
        );
    }
    !order_ids.is_empty()
}

async fn driver_loop(operator: Arc<Operator>) {
    loop {
        if let Err(error) = drive(&operator).await {
            eprintln!("operator driver: {}", crate::snip36::sanitize(&error));
        }
        // a halted operator exits so its supervisor restarts it from the last durable state.
        if operator.running().is_err() {
            std::process::exit(75);
        }
        sleep(Duration::from_millis(DRIVER_INTERVAL_MS)).await;
    }
}

/// how far back a detected reorganization rewinds the note index before rescanning.
const REORG_REWIND_BLOCKS: u64 = 64;

/// folds new confirmed chain events into the note index and the withdrawal jobs. a scanned block
/// whose hash changed means the chain reorganized below the confirmation depth: the index
/// rewinds and rescans, and `reconcile` halts if a confirmed transition disappeared.
async fn sync(operator: &Operator, state: &mut OperatorState) -> Result<bool, String> {
    let chain = operator.chain();
    if state.notes.cursor_hash != Felt::ZERO {
        let scanned = state.notes.next_block - 1;
        if chain.block_hash(scanned).await? != state.notes.cursor_hash {
            let rewind_to = scanned.saturating_sub(REORG_REWIND_BLOCKS);
            eprintln!("block {scanned} was reorganized; rescanning from block {rewind_to}");
            state.notes.rewind(rewind_to)?;
            state
                .recovered_residuals
                .retain(|_, block| *block < rewind_to);
            state
                .pending_residual_recoveries
                .retain(|_, recovery| recovery.requested_block < rewind_to);
            return Ok(true);
        }
    }
    let (events, tip) = chain
        .events(state.notes.next_block, operator.config.confirmation_blocks)
        .await?;
    let Some((tip, tip_hash)) = tip else {
        return Ok(false);
    };
    for (block, event) in events {
        match event {
            ChainEvent::Deposit { deposit_root } => {
                state.notes.append(crate::chain::NoteBatch {
                    root: deposit_root,
                    leaves: vec![deposit_root],
                    seq: None,
                    block,
                })?;
            }
            ChainEvent::Transition {
                seq,
                output_root,
                transaction_hash,
            } => {
                let leaves = match state.transition_leaves.remove(&seq) {
                    Some(leaves) => leaves,
                    None => chain.transition_leaves(transaction_hash).await?,
                };
                state
                    .notes
                    .append(transition_batch(seq, output_root, leaves, block)?)?;
            }
            ChainEvent::WithdrawalFinalized { nullifier } => {
                // anyone may finalize a matured exit; the job is done either way.
                if let Some(job) = state.withdrawals.get_mut(&key(&nullifier))
                    && !matches!(job.stage, WithdrawalStage::Finalized { .. })
                {
                    job.stage = WithdrawalStage::Finalized {
                        transaction_hash: Felt::ZERO,
                    };
                    job.updated_at_ms = now_ms();
                }
            }
            ChainEvent::ResidualRecoveryRequested {
                nullifier,
                matures_at,
            } => {
                let requested_at = matures_at
                    .checked_sub(operator.config.manifest.runtime.withdrawal_delay_seconds)
                    .ok_or("residual recovery maturity precedes its configured delay")?;
                state.pending_residual_recoveries.insert(
                    key(&nullifier),
                    PendingResidualRecovery {
                        nullifier,
                        requested_at_ms: requested_at
                            .checked_mul(1_000)
                            .ok_or("residual recovery request overflows milliseconds")?,
                        matures_at_ms: matures_at
                            .checked_mul(1_000)
                            .ok_or("residual recovery maturity overflows milliseconds")?,
                        requested_block: block,
                        retired: false,
                        finalization_transaction: None,
                        updated_at_ms: now_ms(),
                    },
                );
            }
            ChainEvent::ResidualRecoveryFinalized { nullifier } => {
                let recovery_key = key(&nullifier);
                let pending = state.pending_residual_recoveries.remove(&recovery_key);
                if pending.is_none_or(|recovery| !recovery.retired) {
                    state.recovered_residuals.insert(recovery_key, block);
                }
            }
        }
    }
    state.notes.next_block = tip + 1;
    state.notes.cursor_hash = tip_hash;
    Ok(true)
}

/// commits in-flight transitions by their receipts, in seq order, and drops the whole pipeline
/// when one fails: everything after it was built on its book.
async fn reconcile(operator: &Operator, state: &mut OperatorState) -> Result<bool, String> {
    let mut changed = false;
    while let Some(first) = state.in_flight.first() {
        let TransitionStage::Submitted { transaction_hash } = &first.stage else {
            break;
        };
        match operator.snip36.receipt(*transaction_hash).await {
            Some(Outcome::Accepted { block_number, fee }) => {
                // a transition commits only once it is as deep as the events the index folds in.
                let (tip, [_, l2_price, _]) = operator.snip36.latest_block().await?;
                if block_number + operator.config.confirmation_blocks > tip {
                    break;
                }
                let landed = state.in_flight.remove(0);
                // a transaction that carried searcher legs says nothing clean about what a
                // settlement alone costs, so only leg-free transitions teach the estimate.
                if landed.legged.is_empty() {
                    learn_transition_gas(
                        state,
                        fee,
                        l2_price,
                        operator.config.transition_gas_estimate,
                    );
                }
                eprintln!("transition {} settled", landed.seq);
                commit(state, landed);
                changed = true;
            }
            // the searcher leg is optional: the same proven transition goes again without it,
            // and everything built on it stays valid.
            // a transition sent only for its legs is not worth sending without them, unless
            // another transition was built on it.
            Some(Outcome::Reverted { reason })
                if !first.legged.is_empty() && first.for_legs && state.in_flight.len() == 1 =>
            {
                eprintln!(
                    "transition {} reverted with the searcher legs it was sent for: {reason}; dropping it",
                    first.seq
                );
                state.in_flight.clear();
                return Ok(true);
            }
            Some(Outcome::Reverted { reason }) if !first.legged.is_empty() => {
                eprintln!(
                    "transition {} reverted with its searcher leg: {reason}; resubmitting without it",
                    first.seq
                );
                let first = &mut state.in_flight[0];
                first.stage = TransitionStage::Proven;
                first.legged.clear();
                first.leg_dropped = true;
                first.prepared_submission = None;
                first.prepared_legged.clear();
                return Ok(true);
            }
            Some(Outcome::Reverted { reason }) => {
                eprintln!("transition {} reverted: {reason}; rebuilding", first.seq);
                state.in_flight.clear();
                return Ok(true);
            }
            None => break,
        }
    }
    let view = operator
        .chain()
        .confirmed_exchange_view(operator.config.confirmation_blocks)
        .await?;
    if view.seq < state.confirmed_seq {
        return Err(format!(
            "the chain regressed to transition {} below the confirmed {}; the operator halts until its state is restored to the chain",
            view.seq, state.confirmed_seq
        ));
    }
    // the process may have stopped after the transaction landed but before its hash/stage was
    // persisted. recover only from the exact confirmed resulting state; seq equality alone is
    // insufficient because another operator transition could have won the same prior state.
    if view.seq > state.confirmed_seq {
        let Some(first) = state.in_flight.first() else {
            return Err(format!(
                "the chain is at transition {} but the operator at {}",
                view.seq, state.confirmed_seq
            ));
        };
        let expected_root = from_core(first.result.public.new_book_root);
        if view.seq != first.seq || view.book_root != expected_root {
            return Err(format!(
                "the confirmed chain state ({}, {:#x}) does not match pending transition {} ({:#x})",
                view.seq, view.book_root, first.seq, expected_root
            ));
        }
        let landed = state.in_flight.remove(0);
        eprintln!(
            "transition {} recovered from confirmed chain state",
            landed.seq
        );
        commit(state, landed);
        changed = true;
    }
    if state.in_flight.is_empty() && view.seq != state.confirmed_seq {
        return Err(format!(
            "the chain is at transition {} but the operator at {}",
            view.seq, state.confirmed_seq
        ));
    }
    Ok(changed)
}

fn commit(state: &mut OperatorState, landed: InFlight) {
    let public = &landed.result.public;
    state.confirmed_seq = landed.seq;
    state.confirmed_close_ms = landed.close_time_ms;
    for order_id in &landed.admitted {
        state.pending_orders.remove(&key(order_id));
    }
    for order_id in &landed.cancelled {
        let order_key = key(order_id);
        if let Some(entry) = state
            .book
            .iter()
            .find(|entry| from_core(entry.order.order_id) == *order_id)
        {
            state.cancelled_orders.insert(
                order_key.clone(),
                CancellationTombstone {
                    cancel_authority: from_core(entry.owner.cancel_authority),
                    cancelled_at_ms: landed.close_time_ms,
                    expires_at_ms: entry.order.expiry_ms,
                    effective_after_seq: landed.seq,
                },
            );
        }
        state.cancellations.remove(&order_key);
    }
    state.book = landed.result.new_book.clone();
    for nullifier in &landed.result.public.retired_nullifiers {
        let nullifier = key(&from_core(*nullifier));
        state.recovered_residuals.remove(&nullifier);
        if let Some(recovery) = state.pending_residual_recoveries.get_mut(&nullifier) {
            recovery.retired = true;
        }
    }
    for nullifier in &landed.result.public.nullifiers {
        state
            .pending_residual_recoveries
            .remove(&key(&from_core(*nullifier)));
    }
    let live_order_ids = state
        .book
        .iter()
        .map(|entry| key(&from_core(entry.order.order_id)))
        .collect::<BTreeSet<_>>();
    // a cancellation submitted after the transition was already firm loses to a completion or
    // expiry in that transition. do not let the now-stale request poison the next close.
    state
        .cancellations
        .retain(|order_id, _| live_order_ids.contains(order_id));
    state.capacities.retain(|capacity| {
        !landed
            .applied_capacities
            .iter()
            .any(|applied| applied.same(capacity))
    });
    for capacity in &public.capacities {
        let pair_id = from_core(capacity.pair_id);
        state.capacities.push(OpenCapacity {
            seq: landed.seq,
            pair_id,
            sell: capacity.sell,
            opened_at_ms: now_ms(),
            // a leg that rode with the transition may have filled only part: the chain says
            // what is left, and follow-ups fill it while the window lasts.
            leg_attempted: false,
            // a leg that rode with the transition funded its settlement.
            outcome_funded: !landed.legged.is_empty(),
            leg_transaction: None,
            leg_submissions: 0,
            leg_retry_at_ms: 0,
            window_closes_ms: 0,
        });
    }
    state.transition_leaves.insert(
        landed.seq,
        public
            .output_records
            .iter()
            .map(|record| from_core(record.leaf))
            .collect(),
    );
    let paid = landed
        .result
        .outputs
        .iter()
        .filter(|output| output.kind != OUTPUT_KIND_FEE)
        .map(|output| output.order_id)
        .collect::<BTreeSet<_>>();
    for report in &landed.result.reports {
        let touched = report.admitted
            || report.fill_base != 0
            || report.external_base != 0
            || report.removal.is_some()
            || paid.contains(&report.order_id);
        if touched {
            let order = key(&from_core(report.order_id));
            state.orders.entry(order).or_default().push(OrderEvent {
                seq: landed.seq,
                close_time_ms: landed.close_time_ms,
                report: report.clone(),
            });
        }
    }
}

async fn drive(operator: &Arc<Operator>) -> Result<(), String> {
    operator.running()?;
    let mut state = operator.state.lock().await;
    let mut changed = sync(operator, &mut state).await?;
    changed |= reconcile(operator, &mut state).await?;
    changed |= settle_pending_cancellations(&mut state, active_closing_epoch(operator)?);

    let proving = state
        .in_flight
        .iter()
        .filter(|entry| entry.stage == TransitionStage::Proving)
        .map(|entry| entry.seq)
        .collect::<Vec<_>>();
    drop(state);
    for seq in proving {
        start_transition_proof(operator, seq).await?;
    }
    state = operator.state.lock().await;

    // a proven transition that can no longer land inside the contract's close delay would only
    // revert: drop it, and the next close rebuilds with fresh midpoints.
    if let Some(first) = state.in_flight.first()
        && first.stage == TransitionStage::Proven
        && first.prepared_submission.is_none()
        && now_ms() + 5_000 > first.close_time_ms + operator.config.policy.max_close_delay_ms
    {
        eprintln!(
            "transition {} proved too late to land; rebuilding",
            first.seq
        );
        state.in_flight.clear();
        changed = true;
    }

    // submit the oldest proven transition: its predecessors have all landed.
    if let Some(first) = state.in_flight.first()
        && first.stage == TransitionStage::Proven
    {
        let first = first.clone();
        // a transition sent only for its legs is dropped when they are gone, unless another
        // transition was already built on it: then sending it alone costs less than throwing
        // away the proof of a transition that settles real fills.
        let must_pay = first.for_legs && state.in_flight.len() == 1;
        drop(state);
        let submitted = submit_transition(operator, &first, must_pay).await;
        state = operator.state.lock().await;
        match submitted {
            Ok((transaction_hash, legged)) => {
                let expected_commitment = first.result.public.commitment;
                if let Some(entry) = state.in_flight.iter_mut().find(|entry| {
                    entry.seq == first.seq && entry.result.public.commitment == expected_commitment
                }) {
                    entry.stage = TransitionStage::Submitted { transaction_hash };
                    entry.legged = legged;
                }
            }
            Err(error) => {
                let expected_commitment = first.result.public.commitment;
                let journaled = state
                    .in_flight
                    .iter()
                    .find(|entry| {
                        entry.seq == first.seq
                            && entry.result.public.commitment == expected_commitment
                    })
                    .is_some_and(|entry| entry.prepared_submission.is_some());
                if journaled {
                    eprintln!(
                        "transition {} submission is unresolved and will rebroadcast its journaled transaction: {}",
                        first.seq,
                        crate::snip36::sanitize(&error)
                    );
                } else {
                    eprintln!(
                        "transition {} is not submit-ready and will be rebuilt: {}",
                        first.seq,
                        crate::snip36::sanitize(&error)
                    );
                    state.in_flight.clear();
                }
            }
        }
        changed = true;
    }

    changed |= drive_withdrawals(operator, &mut state).await;
    changed |= drive_residual_recoveries(operator, &mut state).await;
    changed |= prune(&mut state, now_ms());
    if changed {
        operator.save(&state).await?;
    }
    drop(state);
    drive_external(operator).await
}

async fn start_transition_proof(operator: &Arc<Operator>, seq: u32) -> Result<(), String> {
    let (witness, expected, commitment, context) = {
        let state = operator.state.lock().await;
        let Some(entry) = state
            .in_flight
            .iter()
            .find(|entry| entry.seq == seq && entry.stage == TransitionStage::Proving)
        else {
            return Ok(());
        };
        let commitment = from_core(entry.result.public.commitment);
        let running_key = key(&commitment);
        let mut running = operator
            .transitions_running
            .lock()
            .map_err(|_| "transition proving lock poisoned")?;
        if !running.insert(running_key) {
            return Ok(());
        }
        let witness = entry
            .result
            .witness
            .iter()
            .copied()
            .map(from_core)
            .collect::<Vec<_>>();
        let expected = from_core(proof_message_hash(
            to_core(operator.config.transition_proof_program),
            TRANSITION_MESSAGE_DOMAIN,
            bound_statement_message(
                TRANSITION_MESSAGE_DOMAIN,
                operator.config.chain_context(),
                entry.result.public.commitment,
            ),
        ));
        let context = ProofJobContext {
            statement_kind: ProofStatementKind::Transition,
            transition_id: format!("transition:{commitment:#x}"),
            epoch_id: Some(u64::from(entry.seq)),
            exchange_address: format!("{:#x}", operator.config.exchange),
            input_state_root: Some(format!(
                "{:#x}",
                from_core(entry.result.public.prior_book_root)
            )),
            expected_output_state_root: Some(format!(
                "{:#x}",
                from_core(entry.result.public.new_book_root)
            )),
            statement_commitment: format!("{commitment:#x}"),
            witness_hash: canonical_witness_hash(&witness),
            program_entrypoint: "compile_transition_proof".into(),
        };
        (witness, expected, commitment, context)
    };

    let operator = operator.clone();
    tokio::spawn(async move {
        let mut calldata = vec![operator.config.exchange, Felt::from(witness.len() as u64)];
        calldata.extend(witness);
        let proof = operator
            .snip36
            .prove(
                vec![call(
                    operator.config.transition_proof_program,
                    "compile_transition_proof",
                    calldata,
                )],
                expected,
                context,
            )
            .await;
        let mut state = operator.state.lock().await;
        let current = state.in_flight.iter().position(|entry| {
            entry.seq == seq && from_core(entry.result.public.commitment) == commitment
        });
        match (proof, current) {
            (Ok(proof), Some(position)) => {
                let entry = &mut state.in_flight[position];
                entry.proof = Some(proof);
                entry.stage = TransitionStage::Proven;
                eprintln!(
                    "transition {seq} proven in {}ms",
                    now_ms() - entry.built_at_ms
                );
            }
            (Err(error), Some(_)) if is_retryable_proving_error(&error) => {
                eprintln!(
                    "transition {seq} proof job remains pending: {}",
                    crate::snip36::sanitize(&error)
                );
            }
            (Err(error), Some(_)) => {
                eprintln!(
                    "transition {seq} proving failed: {}",
                    crate::snip36::sanitize(&error)
                );
                state.in_flight.retain(|entry| entry.seq < seq);
            }
            _ => {}
        }
        let _ = operator.save(&state).await;
        if let Ok(mut running) = operator.transitions_running.lock() {
            running.remove(&key(&commitment));
        }
    });
    Ok(())
}

/// drops closed orders' histories and finished withdrawals past their retention.
fn prune(state: &mut OperatorState, now: u64) -> bool {
    let (orders, closed, cancelled, withdrawals) = (
        state.orders.len(),
        state.closed_orders.len(),
        state.cancelled_orders.len(),
        state.withdrawals.len(),
    );
    let cutoff = now.saturating_sub(HISTORY_RETENTION_MS);
    // a pruned history leaves a tombstone, which lasts far longer than any order lives.
    let mut tombstones = Vec::new();
    state.orders.retain(|order_id, events| {
        let Some(last) = events.last() else {
            return false;
        };
        match &last.report.removal {
            Some(removal) if last.close_time_ms < cutoff => {
                tombstones.push((
                    order_id.clone(),
                    ClosedOrder {
                        seq: last.seq,
                        close_time_ms: last.close_time_ms,
                        removal: removal.clone(),
                    },
                ));
                false
            }
            _ => true,
        }
    });
    state.closed_orders.extend(tombstones);
    let tombstone_cutoff = now.saturating_sub(TOMBSTONE_RETENTION_MS);
    state
        .closed_orders
        .retain(|_, closed| closed.close_time_ms >= tombstone_cutoff);
    state.cancelled_orders.retain(|_, tombstone| {
        tombstone.expires_at_ms > now || tombstone.cancelled_at_ms >= tombstone_cutoff
    });
    state.withdrawals.retain(|_, job| {
        !matches!(
            job.stage,
            WithdrawalStage::Finalized { .. } | WithdrawalStage::Failed { .. }
        ) || job.updated_at_ms >= cutoff
    });
    orders != state.orders.len()
        || closed != state.closed_orders.len()
        || cancelled != state.cancelled_orders.len()
        || withdrawals != state.withdrawals.len()
}

/// submits a proven transition with the searcher legs its transaction can carry. routes quoted
/// independently can compete for the same ekubo liquidity, so legs join one at a time, most
/// profitable first, each only if the transaction still succeeds with it and its profit covers
/// the fee it adds. a node that cannot simulate a proof-bearing transaction sends the transition
/// alone. capacities left without a leg stay open, and `drive_external` tries them as follow-up
/// transactions once the transition has landed.
async fn submit_transition(
    operator: &Operator,
    transition: &InFlight,
    must_pay: bool,
) -> Result<(Felt, Vec<(Felt, bool)>), String> {
    let proof = transition.proof.as_ref().ok_or("transition has no proof")?;
    if let Some(prepared) = transition.prepared_submission.clone() {
        let hash = operator
            .snip36
            .submit_with_gas_durable(Vec::new(), None, None, Some(prepared), |_| async { Ok(()) })
            .await?;
        return Ok((hash, transition.prepared_legged.clone()));
    }
    let settle = call(
        operator.config.exchange,
        "submit_transition",
        transition.calldata.clone(),
    );
    let alone = match operator
        .snip36
        .simulate(vec![settle.clone()], Some(proof))
        .await
    {
        Ok(simulation) if simulation.reverted.is_none() => simulation,
        // the transition alone would revert: sending it would only burn gas.
        Ok(simulation) => {
            return Err(format!(
                "transition would revert: {}",
                simulation.reverted.unwrap_or_default()
            ));
        }
        Err(error) => {
            return Err(format!(
                "transition {} cannot be simulated and will not be submitted: {}",
                transition.seq,
                crate::snip36::sanitize(&error)
            ));
        }
    };
    let (mut legs, rates) = if transition.leg_dropped {
        (Vec::new(), Vec::new())
    } else {
        external_legs(
            operator,
            transition.seq,
            transition.result.public.capacities.iter().map(|capacity| {
                (
                    from_core(capacity.pair_id),
                    capacity.sell,
                    capacity.bound,
                    capacity.total,
                )
            }),
        )
        .await
    };
    // raw amounts of different quote assets are not comparable: legs rank by worth in strk, and
    // a leg that cannot be valued goes last.
    legs.sort_by(|left, right| right.value_strk.cmp(&left.value_strk));
    let mut calls = vec![settle.clone()];
    let mut kept: Vec<PlannedLeg> = Vec::new();
    let mut fee = alone.fee;
    for mut leg in legs {
        let mut trial = calls.clone();
        trial.push(leg.leg.call.clone());
        match operator.snip36.simulate(trial, Some(proof)).await {
            Ok(simulation) if simulation.reverted.is_none() => {
                // the first leg kept funds the transition that later settles every fill of
                // this one, and this one too when it is sent only for its legs.
                let first = kept.is_empty();
                if price_leg(
                    operator,
                    &rates,
                    &mut leg,
                    simulation.fee.saturating_sub(fee),
                    first,
                    if first && transition.for_legs {
                        alone.fee
                    } else {
                        0
                    },
                ) {
                    calls.push(leg.leg.call.clone());
                    kept.push(leg);
                    fee = simulation.fee;
                } else {
                    eprintln!(
                        "transition {} searcher leg does not cover its simulated fee; left out",
                        transition.seq
                    );
                }
            }
            Ok(simulation) => eprintln!(
                "transition {} searcher leg would revert ({}); left out",
                transition.seq,
                simulation.reverted.unwrap_or_default()
            ),
            Err(error) => eprintln!(
                "transition {} searcher leg cannot be simulated ({}); left out",
                transition.seq,
                crate::snip36::sanitize(&error)
            ),
        }
    }
    // m1 has aged through the quotes and simulations: each kept leg takes a fresh m1 and is
    // re-priced now, and one the fresh price no longer pays for is dropped.
    let mut legged = Vec::new();
    calls.truncate(1);
    for mut leg in kept {
        let Some(pair) = operator.config.pair(leg.capacity.0) else {
            continue;
        };
        match operator
            .market
            .refresh_leg(pair, &mut leg.leg, now_ms())
            .await
        {
            Ok(true) => {
                calls.push(leg.leg.call);
                legged.push(leg.capacity);
            }
            result => {
                match result {
                    Ok(_) => eprintln!(
                        "transition {} searcher leg no longer pays at a fresh m1; left out",
                        transition.seq
                    ),
                    Err(error) => eprintln!(
                        "transition {} searcher leg left out: {}",
                        transition.seq,
                        crate::snip36::sanitize(&error)
                    ),
                }
                // the other legs ride on the one that funds the settlement: without it they
                // wait for follow-ups, the first of which funds it again.
                if leg.leg.outcome_support != 0 {
                    calls.truncate(1);
                    legged.clear();
                    break;
                }
            }
        }
    }
    if must_pay && legged.is_empty() {
        return Err(format!(
            "transition {} was sent for searcher legs that no longer pay; dropping it",
            transition.seq
        ));
    }
    // the kept legs carry raised on-chain floors and fresh m1s, so the final set is simulated
    // once more.
    let mut gas = alone.l2_gas;
    if !legged.is_empty() {
        match operator.snip36.simulate(calls.clone(), Some(proof)).await {
            Ok(simulation) if simulation.reverted.is_none() => gas = simulation.l2_gas,
            _ if must_pay => {
                return Err(format!(
                    "transition {} fails with the searcher legs it was sent for; dropping it",
                    transition.seq
                ));
            }
            _ => {
                eprintln!(
                    "transition {} searcher legs fail at their realized floors; sending it alone",
                    transition.seq
                );
                calls.truncate(1);
                legged.clear();
            }
        }
    }
    let seq = transition.seq;
    let commitment = from_core(transition.result.public.commitment);
    let prepared_legged = legged.clone();
    let hash = operator
        .snip36
        .submit_with_gas_durable(calls, Some(proof), Some(gas), None, |prepared| async move {
            let mut state = operator.state.lock().await;
            let entry = state
                .in_flight
                .iter_mut()
                .find(|entry| {
                    entry.seq == seq
                        && from_core(entry.result.public.commitment) == commitment
                        && entry.stage == TransitionStage::Proven
                })
                .ok_or("the transition changed before its signed transaction was journaled")?;
            entry.prepared_submission = Some(prepared);
            entry.prepared_legged = prepared_legged;
            operator.save(&state).await
        })
        .await?;
    Ok((hash, legged))
}

/// a searcher leg planned for one capacity.
struct PlannedLeg {
    capacity: (Felt, bool),
    leg: crate::market::ExternalLeg,
    /// the net profit's worth in strk, the common unit legs are ranked in.
    value_strk: Option<u128>,
    quote_asset: Felt,
    /// the settlement transition's cost in the quote asset, which the one leg that funds it
    /// carries in its on-chain minimum profit.
    settlement_quote: u128,
    /// the quote amount the router always diverts to the settlement account before paying the
    /// searcher. this is configured onchain, so third-party fills fund settlement too.
    external_support_quote: u128,
}

/// the profitable searcher legs for capacities, each net of its estimated gas, with the rates
/// that price their realized fee.
async fn external_legs(
    operator: &Operator,
    seq: u32,
    capacities: impl Iterator<Item = (Felt, bool, u128, u128)>,
) -> (Vec<PlannedLeg>, Vec<Rate>) {
    let now = now_ms();
    let rates = operator.market.rates(&operator.config.pairs, now).await;
    let (tip, [_, l2_price, _]) = match operator.snip36.latest_block().await {
        Ok(block) => block,
        Err(error) => {
            eprintln!("external legs skipped: {}", crate::snip36::sanitize(&error));
            return (Vec::new(), rates);
        }
    };
    let mut legs = Vec::new();
    let transition_gas = {
        let state = operator.state.lock().await;
        if state.transition_gas == 0 {
            operator.config.transition_gas_estimate
        } else {
            state.transition_gas
        }
    };
    // what the transition that later settles the fills to their orders costs, in fri: one per
    // transition, whatever the number of fills.
    let settlement_fri = crate::market::mul_div(
        u128::from(transition_gas).saturating_mul(l2_price),
        u128::from(operator.config.fee_cover_percent),
        100,
        true,
    )
    .unwrap_or(u128::MAX)
    .max(operator.config.min_transition_fee_strk);
    for (pair_id, sell, bound, total) in capacities {
        let Some(pair) = operator.config.pair(pair_id) else {
            continue;
        };
        // gas in fri (strk atoms), priced in the pair's quote asset and rounded up.
        let strk = operator.config.gas_fee_asset;
        let quote_asset = pair.quote_asset_id;
        let gas_cost = |gas: u64| {
            let fri = u128::from(gas).checked_mul(l2_price)?;
            crate::market::convert(&rates, strk, quote_asset, fri, Round::Cost)
        };
        let Some(settlement_quote) =
            crate::market::convert(&rates, strk, quote_asset, settlement_fri, Round::Cost)
        else {
            continue;
        };
        match operator
            .market
            .external_leg(pair, seq, sell, bound, total, &gas_cost, tip)
            .await
        {
            Ok(Some(leg)) => {
                eprintln!(
                    "transition {seq} fills {} of {} externally for {} quote net profit",
                    leg.fill_base, pair.name, leg.net_profit_quote
                );
                legs.push(PlannedLeg {
                    capacity: (pair_id, sell),
                    // legs in different quote assets are ranked by their worth in strk.
                    value_strk: crate::market::convert(
                        &rates,
                        quote_asset,
                        strk,
                        leg.net_profit_quote,
                        Round::Value,
                    ),
                    leg,
                    quote_asset,
                    settlement_quote,
                    external_support_quote: pair.external_settlement_support_quote,
                });
            }
            Ok(None) => {}
            Err(error) => eprintln!(
                "external leg for {} skipped: {}",
                pair.name,
                crate::snip36::sanitize(&error)
            ),
        }
    }
    (legs, rates)
}

/// keeps a leg only if its quoted profit covers `fee_fri`, the fee its simulation adds, the
/// settlement transition when this leg is the one that `funds_settlement`, and the margin, and
/// raises its on-chain minimum profit to that realized floor. external fills pay no taker fee,
/// so nothing else funds the settlement: one fill per transition carries it, and the rest of
/// that transition's fills ride on it.
fn price_leg(
    operator: &Operator,
    rates: &[Rate],
    leg: &mut PlannedLeg,
    fee_fri: u128,
    funds_settlement: bool,
    opening_fri: u128,
) -> bool {
    let config = &operator.config;
    let cost = crate::market::convert(
        rates,
        config.gas_fee_asset,
        leg.quote_asset,
        fee_fri,
        Round::Cost,
    );
    let Some(&margin) = config.searcher_min_profit.get(&leg.quote_asset) else {
        return false;
    };
    // the settlement transition, and a transition sent only for this leg: their fees, in the
    // leg's quote asset, rounded up.
    let opening = crate::market::convert(
        rates,
        config.gas_fee_asset,
        leg.quote_asset,
        opening_fri,
        Round::Cost,
    );
    let Some(required_support) = leg_support(opening, leg.settlement_quote, funds_settlement)
    else {
        return false;
    };
    if leg.external_support_quote < required_support {
        return false;
    }
    match realized_floor(
        leg.leg.gross_profit_quote,
        cost,
        leg.external_support_quote,
        margin,
    ) {
        Some(floor) => {
            let Some(searcher_floor) = floor.checked_sub(leg.external_support_quote) else {
                return false;
            };
            raise_min_profit(&mut leg.leg.call, searcher_floor);
            leg.leg.outcome_support = leg.external_support_quote;
            true
        }
        None => false,
    }
}

/// what a leg pays for beyond its own gas and margin: the transition sent only for it (`opening`,
/// zero otherwise) and, when it funds the outcome, both settlement and a possible capacity
/// freeze. an expired window avoids the freeze, but charging the bound keeps external execution
/// from becoming a protocol subsidy in the conflicting-order case.
fn leg_support(opening: Option<u128>, settlement: u128, funds_settlement: bool) -> Option<u128> {
    opening?.checked_add(if funds_settlement {
        settlement.checked_mul(2)?
    } else {
        0
    })
}

/// the on-chain minimum profit a leg needs to cover its realized fee, the settlement transition
/// it funds (zero when another fill funds it), and the margin, or nothing when its quoted profit
/// does not reach it.
fn realized_floor(
    gross_profit_quote: u128,
    fee_quote: Option<u128>,
    outcome_support: u128,
    margin: u128,
) -> Option<u128> {
    let floor = fee_quote?
        .checked_add(outcome_support)?
        .checked_add(margin)?;
    (gross_profit_quote >= floor).then_some(floor)
}

/// raises, never lowers, the router call's on-chain minimum profit.
fn raise_min_profit(call: &mut starknet_rust_core::types::Call, floor: u128) {
    if let Some(current) = call.calldata.get_mut(LEG_MIN_PROFIT_INDEX)
        && u128::try_from(*current).is_ok_and(|current| current < floor)
    {
        *current = Felt::from(floor);
    }
}

/// how long a follow-up leg waits after a failed or unprofitable try: short against the external
/// window, which is seconds long.
const LEG_RETRY_MS: u64 = 2_000;
/// how long past its window a sent follow-up leg may stay without a receipt before it counts as
/// lost: after the window it can only revert, so waiting longer gains nothing.
const LEG_INCLUSION_GRACE_MS: u64 = 30_000;
/// how long a sent leg is followed when its capacity's window is not known.
const LEG_PENDING_MS: u64 = 5 * 60 * 1_000;
/// follow-up legs sent for one capacity, fills and failures alike, before it is given up.
const MAX_LEG_SUBMISSIONS: u8 = 8;
/// capacities worked on at once: quotes and simulations overlap, submissions still go one at a
/// time from the settlement account.
const LEG_CONCURRENCY: usize = 4;

/// drives each confirmed capacity still without a finished leg: a sent follow-up is settled by
/// its receipt, and otherwise a new one is tried when its retry time comes.
/// quotes, simulations and receipts run without the state lock, so orders and status requests
/// are not held up by the network; a capacity that changed meanwhile keeps its newer state.
async fn drive_external(operator: &Operator) -> Result<(), String> {
    let now = now_ms();
    let due = operator
        .state
        .lock()
        .await
        .capacities
        .iter()
        .filter(|capacity| {
            !capacity.leg_attempted
                && (capacity.leg_transaction.is_some() || capacity.leg_retry_at_ms <= now)
        })
        .cloned()
        .collect::<Vec<_>>();
    if due.is_empty() {
        return Ok(());
    }
    use futures::stream::StreamExt;
    let updates = futures::stream::iter(due)
        .map(|capacity| async move {
            let next = match capacity.leg_transaction {
                Some(hash) => settle_leg(&capacity, operator.snip36.receipt(hash).await, now),
                None => try_leg(operator, &capacity, now).await,
            };
            (capacity, next)
        })
        .buffer_unordered(LEG_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut state = operator.state.lock().await;
    let mut changed = false;
    // one settlement serves every capacity of a transition: once a fill funds it, none of that
    // transition's later fills pays for it again.
    let funded = updates
        .iter()
        .filter(|(_, next)| next.outcome_funded)
        .map(|(capacity, _)| capacity.seq)
        .collect::<BTreeSet<_>>();
    for (capacity, next) in updates {
        if let Some(entry) = state
            .capacities
            .iter_mut()
            .find(|entry| entry.same(&capacity))
            && *entry == capacity
            && *entry != next
        {
            *entry = next;
            changed = true;
        }
    }
    for entry in state.capacities.iter_mut() {
        if funded.contains(&entry.seq) && !entry.outcome_funded {
            entry.outcome_funded = true;
            changed = true;
        }
    }
    if changed {
        operator.save(&state).await?;
    }
    Ok(())
}

/// a sent follow-up leg after its receipt: accepted, the capacity's remainder is tried at once
/// (a capacity fills in parts until it is used up or its window closes); a revert or a
/// transaction that never landed frees it for another try until its submissions run out.
fn settle_leg(capacity: &OpenCapacity, receipt: Option<Outcome>, now: u64) -> OpenCapacity {
    let mut next = capacity.clone();
    let failed = match receipt {
        Some(Outcome::Accepted { .. }) => {
            next.leg_transaction = None;
            next.leg_retry_at_ms = now;
            // a landed follow-up funded its transition's settlement.
            next.outcome_funded = true;
            return next;
        }
        Some(Outcome::Reverted { reason }) => {
            eprintln!(
                "follow-up searcher leg for transition {} reverted: {reason}",
                capacity.seq
            );
            true
        }
        None if capacity.window_closes_ms != 0 => {
            now > capacity
                .window_closes_ms
                .saturating_add(LEG_INCLUSION_GRACE_MS)
        }
        None => now > capacity.leg_retry_at_ms.saturating_add(LEG_PENDING_MS),
    };
    if failed {
        next.leg_transaction = None;
        next.leg_retry_at_ms = now + LEG_RETRY_MS;
        next.leg_attempted = capacity.leg_submissions >= MAX_LEG_SUBMISSIONS
            || (capacity.window_closes_ms != 0 && now >= capacity.window_closes_ms);
    }
    next
}

/// tries a follow-up leg for an open capacity. it is sent only when its simulation succeeds and
/// its profit covers the simulated fee; anything else waits for the next retry.
async fn try_leg(operator: &Operator, capacity: &OpenCapacity, now: u64) -> OpenCapacity {
    let mut next = capacity.clone();
    next.leg_retry_at_ms = now + LEG_RETRY_MS;
    let Ok(view) = operator
        .chain()
        .capacity(capacity.seq, capacity.pair_id, capacity.sell)
        .await
    else {
        return next;
    };
    next.window_closes_ms = view
        .opened_at
        .saturating_add(operator.config.policy.external_window_seconds)
        .saturating_mul(1_000);
    // a fill past the window only reverts: the capacity is finished once its window closes or
    // nothing of it is left.
    let remaining = view.total.saturating_sub(view.consumed_base);
    if view.status != CAPACITY_OPEN || remaining == 0 || now >= next.window_closes_ms {
        next.leg_attempted = true;
        return next;
    }
    let (legs, rates) = external_legs(
        operator,
        capacity.seq,
        std::iter::once((capacity.pair_id, capacity.sell, view.bound, remaining)),
    )
    .await;
    for mut leg in legs {
        let priced = match operator
            .snip36
            .simulate(vec![leg.leg.call.clone()], None)
            .await
        {
            Ok(simulation) if simulation.reverted.is_none() => price_leg(
                operator,
                &rates,
                &mut leg,
                simulation.fee,
                !capacity.outcome_funded,
                0,
            ),
            _ => false,
        };
        // a fresh m1 just before sending, as for a leg that rides with its transition.
        let fresh = priced
            && match operator.config.pair(capacity.pair_id) {
                Some(pair) => matches!(
                    operator
                        .market
                        .refresh_leg(pair, &mut leg.leg, now_ms())
                        .await,
                    Ok(true)
                ),
                None => false,
            };
        // the raised floor and fresh m1 change the call, so it is simulated again for its gas.
        let gas = match fresh {
            true => match operator
                .snip36
                .simulate(vec![leg.leg.call.clone()], None)
                .await
            {
                Ok(simulation) if simulation.reverted.is_none() => Some(simulation.l2_gas),
                _ => None,
            },
            false => None,
        };
        let Some(gas) = gas else {
            eprintln!(
                "follow-up searcher leg for transition {} would not succeed profitably",
                capacity.seq
            );
            continue;
        };
        match operator
            .snip36
            .submit_with_gas(vec![leg.leg.call], None, Some(gas))
            .await
        {
            Ok(hash) => {
                next.leg_transaction = Some(hash);
                next.leg_submissions = next.leg_submissions.saturating_add(1);
            }
            Err(error) => eprintln!(
                "follow-up searcher leg failed: {}",
                crate::snip36::sanitize(&error)
            ),
        }
    }
    next
}

/// what one admission adds to a transition's steps, for trimming a close to its budget.
const ADMISSION_STEPS: u64 = 2_064;

const CAPACITY_OPEN: u8 = 1;
const CAPACITY_FILLED: u8 = 2;
const CAPACITY_FROZEN: u8 = 4;
const FREEZE_RETRIES: usize = 8;

fn external_window_open(
    view: &CapacityView,
    now_seconds: u64,
    window_seconds: u64,
) -> Result<bool, String> {
    let closes_at = view
        .opened_at
        .checked_add(window_seconds)
        .ok_or("external-capacity window overflows")?;
    Ok(view.status == CAPACITY_OPEN && now_seconds <= closes_at)
}

/// establishes the chain-ordered cutoff for every prior capacity before constructing the next
/// private auction. a fill that lands first changes the generation and remains firm; the batch
/// then retries from the canonical state. once frozen, no fill can overlap the remainder that
/// returns to internal clearing.
async fn freeze_capacities(
    operator: &Operator,
    capacities: &[OpenCapacity],
) -> Result<Vec<(OpenCapacity, CapacityView)>, String> {
    for _ in 0..FREEZE_RETRIES {
        let now_seconds = now_ms() / 1_000;
        let mut snapshots = Vec::with_capacity(capacities.len());
        let mut calls = Vec::new();
        for capacity in capacities {
            let view = operator
                .chain()
                .capacity(capacity.seq, capacity.pair_id, capacity.sell)
                .await?;
            // once the external window has elapsed the contract already rejects fills, so its
            // totals are immutable and a separate freeze transaction would be pure waste.
            if external_window_open(
                &view,
                now_seconds,
                operator.config.policy.external_window_seconds,
            )? {
                calls.push(call(
                    operator.config.exchange,
                    "freeze_capacity",
                    vec![
                        Felt::from(capacity.seq),
                        capacity.pair_id,
                        Felt::from(u8::from(capacity.sell)),
                        Felt::from(view.generation),
                    ],
                ));
            }
            snapshots.push((capacity.clone(), view));
        }
        if calls.is_empty() {
            if snapshots.iter().any(|(_, view)| {
                view.status != CAPACITY_OPEN
                    && view.status != CAPACITY_FILLED
                    && view.status != CAPACITY_FROZEN
            }) {
                return Err("an external capacity has an unknown state".into());
            }
            return Ok(snapshots);
        }

        let simulation = operator.snip36.simulate(calls.clone(), None).await?;
        if simulation.reverted.is_some() {
            // a searcher may have won ordering between the reads and simulation. re-read the
            // generations instead of weakening the cutoff.
            continue;
        }
        let hash = operator
            .snip36
            .submit_with_gas(calls, None, Some(simulation.l2_gas))
            .await?;
        match operator.snip36.wait(hash).await {
            Some(Outcome::Accepted { block_number, .. }) => {
                let required = block_number.saturating_add(operator.config.confirmation_blocks);
                for _ in 0..60 {
                    if operator.snip36.latest_block().await?.0 >= required {
                        break;
                    }
                    sleep(Duration::from_millis(500)).await;
                }
                if operator.snip36.latest_block().await?.0 < required {
                    return Err(
                        "capacity freeze did not reach the configured confirmation depth".into(),
                    );
                }
            }
            Some(Outcome::Reverted { .. }) => continue,
            None => return Err("capacity freeze receipt was not observed".into()),
        }
    }
    Err("external capacity kept changing while the auction cutoff was established".into())
}

/// folds a landed transition's fee into the running estimate of a transition's l2 gas.
fn learn_transition_gas(state: &mut OperatorState, fee: u128, l2_price: u128, initial: u64) {
    if l2_price == 0 || fee == 0 {
        return;
    }
    let observed = u64::try_from(fee / l2_price).unwrap_or(u64::MAX);
    let current = if state.transition_gas == 0 {
        initial
    } else {
        state.transition_gas
    };
    // an exponential average that follows a new cost level within a few transitions.
    state.transition_gas = current - current / 4 + observed / 4;
}

/// what the next transition may consume that no transition in flight already consumes.
struct Frontier {
    seq: u32,
    close_after_ms: u64,
    book: Vec<zylith_core::exchange::BookEntry>,
    consumed_orders: BTreeSet<String>,
    consumed_cancels: BTreeSet<String>,
    consumed_capacities: Vec<OpenCapacity>,
    spent_nullifiers: BTreeSet<[u8; 32]>,
    recovered_residuals: BTreeSet<String>,
    pending_residual_recoveries: BTreeMap<String, PendingResidualRecovery>,
}

impl Frontier {
    /// the confirmed capacities no transition in flight applies yet.
    fn open_capacities(&self, state: &OperatorState) -> Vec<OpenCapacity> {
        state
            .capacities
            .iter()
            .filter(|capacity| {
                !self
                    .consumed_capacities
                    .iter()
                    .any(|consumed| consumed.same(capacity))
            })
            .cloned()
            .collect()
    }
}

fn frontier(state: &OperatorState) -> Frontier {
    let mut frontier = Frontier {
        seq: state.confirmed_seq + 1,
        close_after_ms: state.confirmed_close_ms,
        book: state.book.clone(),
        consumed_orders: BTreeSet::new(),
        consumed_cancels: BTreeSet::new(),
        consumed_capacities: Vec::new(),
        spent_nullifiers: BTreeSet::new(),
        recovered_residuals: state.recovered_residuals.keys().cloned().collect(),
        pending_residual_recoveries: state.pending_residual_recoveries.clone(),
    };
    for in_flight in &state.in_flight {
        frontier.seq = in_flight.seq + 1;
        frontier.close_after_ms = in_flight.close_time_ms;
        frontier.book = in_flight.result.new_book.clone();
        frontier
            .consumed_orders
            .extend(in_flight.admitted.iter().map(key));
        frontier
            .consumed_cancels
            .extend(in_flight.cancelled.iter().map(key));
        frontier
            .consumed_capacities
            .extend(in_flight.applied_capacities.iter().cloned());
        frontier.spent_nullifiers.extend(
            in_flight
                .result
                .public
                .nullifiers
                .iter()
                .map(|felt| felt.to_bytes_be()),
        );
    }
    frontier
}

/// how many nullifier reads a close runs at once.
const NULLIFIER_READ_CONCURRENCY: usize = 16;

/// the chain state of each nullifier, read concurrently. a read that fails is left out, so the
/// order it funds simply waits for a later close.
async fn nullifier_states(
    operator: &Operator,
    nullifiers: BTreeSet<[u8; 32]>,
) -> BTreeMap<[u8; 32], u8> {
    use futures::StreamExt;
    futures::stream::iter(nullifiers)
        .map(|nullifier| async move {
            let state = operator
                .chain()
                .nullifier_state(Felt::from_bytes_be(&nullifier))
                .await;
            (nullifier, state)
        })
        .buffer_unordered(NULLIFIER_READ_CONCURRENCY)
        .filter_map(|(nullifier, state)| async move { state.ok().map(|state| (nullifier, state)) })
        .collect()
        .await
}

/// pending orders that can never join: expired by this close, or funded by a note the chain
/// already shows spent. a note spent by a transition still in flight is not read, since that
/// transition may yet roll back, so its order waits.
fn stale_pending(
    pending: &[PendingOrder],
    close_time_ms: u64,
    in_flight_spent: &BTreeSet<[u8; 32]>,
    chain_nullifiers: &BTreeMap<[u8; 32], u8>,
) -> Vec<String> {
    pending
        .iter()
        .filter(|order| {
            close_time_ms >= order.request.terms.expiry_ms
                || order.request.funding.iter().any(|note| {
                    let nullifier = from_core(note.nullifier()).to_bytes_be();
                    !in_flight_spent.contains(&nullifier)
                        && chain_nullifiers
                            .get(&nullifier)
                            .is_some_and(|state| *state != 0)
                })
        })
        .map(|order| key(&from_core(order.request.order_id())))
        .collect()
}

/// one epoch close: build, decide, and start proving.
async fn close_epoch(operator: &Arc<Operator>, close_ms: u64) -> Result<(), String> {
    operator.running()?;
    let policy = &operator.config.policy;
    if !scheduled_epoch_close(close_ms, policy.epoch_ms) {
        return Err("the scheduled close is not aligned to the epoch".into());
    }
    let _closing_epoch = ClosingEpoch::begin(operator, close_ms)?;
    let (prepared_seq, open_capacities) = {
        let state = operator.state.lock().await;
        if state.in_flight.len() >= policy.pipeline_depth {
            return Ok(());
        }
        let frontier = frontier(&state);
        let open_capacities = frontier.open_capacities(&state);
        (frontier.seq, open_capacities)
    };
    let pairs = operator.config.pairs.clone();
    // establish the external cutoff before sampling. all orders accepted until the aligned
    // boundary are still included when the private state snapshot is taken below.
    let capacity_views = freeze_capacities(operator, &open_capacities).await?;
    let attestations = operator.market.attest_batch(&pairs).await?;
    if !reference_windows_cover_close(
        attestations
            .iter()
            .map(|attestation| (attestation.observed_at_ms, attestation.valid_until_ms)),
        close_ms,
    ) {
        return Err("the authenticated midpoint does not cover the scheduled epoch close".into());
    }
    let now = now_ms();
    if now > close_ms {
        return Err("epoch preparation missed the scheduled close".into());
    }
    sleep(Duration::from_millis(close_ms - now)).await;

    let (frontier, pending, cancels, open_capacities, note_root, memberships) = {
        let state = operator.state.lock().await;
        if state.in_flight.len() >= policy.pipeline_depth {
            return Ok(());
        }
        let frontier = frontier(&state);
        if frontier.seq != prepared_seq {
            return Ok(());
        }
        let pending = state
            .pending_orders
            .iter()
            .filter(|(order_id, order)| {
                !frontier.consumed_orders.contains(*order_id)
                    && eligible_before_close(order.received_at_ms, close_ms)
            })
            .map(|(_, order)| order.clone())
            .collect::<Vec<_>>();
        let cancels = state
            .cancellations
            .iter()
            .filter(|(order_id, (_, received_at_ms))| {
                !frontier.consumed_cancels.contains(*order_id)
                    && eligible_before_close(*received_at_ms, close_ms)
            })
            .map(|(_, cancel)| cancel.clone())
            .collect::<Vec<_>>();
        let open_capacities = frontier.open_capacities(&state);
        let mut memberships = BTreeMap::new();
        for order in &pending {
            for note in &order.request.funding {
                let leaf = from_core(note.output_leaf());
                if let Some(membership) = state.notes.membership(leaf) {
                    memberships.insert(leaf.to_bytes_be(), membership);
                }
            }
        }
        (
            frontier,
            pending,
            cancels,
            open_capacities,
            state.notes.root(),
            memberships,
        )
    };
    if open_capacities.len() != capacity_views.len()
        || open_capacities.iter().any(|capacity| {
            !capacity_views
                .iter()
                .any(|(prepared, _)| prepared.same(capacity))
        })
    {
        return Ok(());
    }

    // the markets this close touches: every pair with a resting order, a new order or an
    // outcome to settle.
    let mut pair_ids = BTreeSet::new();
    pair_ids.extend(
        frontier
            .book
            .iter()
            .map(|entry| from_core(entry.order.pair_id).to_bytes_be()),
    );
    pair_ids.extend(
        pending
            .iter()
            .map(|order| from_core(order.request.terms.pair_id).to_bytes_be()),
    );
    pair_ids.extend(
        open_capacities
            .iter()
            .map(|capacity| capacity.pair_id.to_bytes_be()),
    );
    if pair_ids.is_empty() {
        return Ok(());
    }
    // every active epoch authenticates the full enabled market set. this makes the direct
    // asset/usdc observations used by the objective part of the same batch as every direct
    // execution midpoint, without changing any market's execution price.
    let close_time_ms = close_ms;
    if close_time_ms <= frontier.close_after_ms {
        return Err("the midpoints are not newer than the previous close".into());
    }
    let markets = attestations
        .iter()
        .zip(&pairs)
        .map(|(attestation, pair)| attestation.market(pair.fee_bps, pair.min_order_quote_amount))
        .collect::<Vec<_>>();
    let market_pairs = pairs
        .iter()
        .map(|pair| pair.pair_id.to_bytes_be())
        .collect::<BTreeSet<_>>();

    // outcomes whose external window has closed, read from the chain.
    let mut outcomes = Vec::new();
    let mut applied_capacities = Vec::new();
    for capacity in &open_capacities {
        if !market_pairs.contains(&capacity.pair_id.to_bytes_be()) {
            continue;
        }
        let view = capacity_views
            .iter()
            .find(|(candidate, _)| candidate.same(capacity))
            .map(|(_, view)| *view)
            .ok_or("capacity cutoff omitted an open capacity")?;
        let window_closed =
            now_ms() / 1000 > view.opened_at + operator.config.policy.external_window_seconds;
        // filled and frozen totals are immutable. a legacy open capacity may also settle once
        // its window has elapsed.
        if view.status == CAPACITY_FILLED
            || view.status == CAPACITY_FROZEN
            || (view.status == CAPACITY_OPEN && window_closed)
        {
            outcomes.push(ChainOutcome::from_capacity(
                capacity.seq,
                to_core(capacity.pair_id),
                capacity.sell,
                view.consumed_base,
                view.pool_quote,
                view.bound,
                view.scale,
            ));
            applied_capacities.push(capacity.clone());
        }
    }

    // accepted permissionless residual exits retire after their request cutoff. the proof
    // authenticates the exact book authority, while the contract requires the matching pending
    // request or a finalized nullifier, so this cleanup cannot remove a live order.
    let mut recovered_order_ids = Vec::new();
    for entry in &frontier.book {
        let Some(market) = markets
            .iter()
            .find(|market| market.pair_id == entry.order.pair_id)
        else {
            continue;
        };
        let input_asset = if entry.order.sell {
            market.base_asset_id
        } else {
            market.quote_asset_id
        };
        let note = ResidualNote::from_order(
            operator.config.chain_context(),
            input_asset,
            &entry.order,
            &entry.owner,
            entry.order.residual_generation,
        );
        if note.matches_order(&entry.order)
            && (frontier
                .recovered_residuals
                .contains(&key(&from_core(note.nullifier())))
                || frontier
                    .pending_residual_recoveries
                    .get(&key(&from_core(note.nullifier())))
                    .is_some_and(|recovery| close_time_ms > recovery.requested_at_ms))
        {
            recovered_order_ids.push(entry.order.order_id);
        }
    }

    // new orders that can join: funded by known, unspent notes, one order per note. their
    // funding nullifiers are read together, and orders that can never join leave the pending set.
    let mut new_orders = Vec::new();
    let mut admitted = Vec::new();
    let mut used = frontier.spent_nullifiers.clone();
    let room = policy
        .max_admissions
        .min(policy.max_book_orders.saturating_sub(frontier.book.len()));
    let candidates = pending
        .iter()
        .filter(|order| {
            market_pairs.contains(&from_core(order.request.terms.pair_id).to_bytes_be())
                && close_time_ms < order.request.terms.expiry_ms
        })
        .collect::<Vec<_>>();
    let chain_nullifiers = if room == 0 {
        BTreeMap::new()
    } else {
        nullifier_states(
            operator,
            candidates
                .iter()
                .flat_map(|order| &order.request.funding)
                .map(|note| from_core(note.nullifier()).to_bytes_be())
                .filter(|nullifier| !used.contains(nullifier))
                .collect(),
        )
        .await
    };
    let stale = stale_pending(
        &pending,
        close_time_ms,
        &frontier.spent_nullifiers,
        &chain_nullifiers,
    );
    if !stale.is_empty() {
        let mut state = operator.state.lock().await;
        for order_id in &stale {
            state.pending_orders.remove(order_id);
        }
        operator.save(&state).await?;
    }
    for order in candidates {
        if new_orders.len() >= room {
            break;
        }
        let mut notes = Vec::new();
        let mut usable = true;
        for note in &order.request.funding {
            let nullifier = from_core(note.nullifier()).to_bytes_be();
            let membership = memberships
                .get(&from_core(note.output_leaf()).to_bytes_be())
                .cloned();
            let fresh = !used.contains(&nullifier) && chain_nullifiers.get(&nullifier) == Some(&0);
            match (membership, fresh) {
                (Some(membership), true) => notes.push(membership),
                _ => usable = false,
            }
        }
        if !usable {
            continue;
        }
        for note in &order.request.funding {
            used.insert(from_core(note.nullifier()).to_bytes_be());
        }
        admitted.push(from_core(order.request.order_id()));
        new_orders.push(order.request.clone().into_new_order(notes));
    }

    let book_ids = frontier
        .book
        .iter()
        .map(|entry| entry.order.order_id)
        .collect::<BTreeSet<_>>();
    let cancellations = cancels
        .iter()
        .filter(|(cancel, _)| book_ids.contains(&cancel.order_id))
        .map(|(cancel, _)| Cancellation {
            order_id: cancel.order_id,
            signature: cancel.signature,
        })
        .collect::<Vec<_>>();
    let input = TransitionInput {
        chain_context: operator.config.chain_context(),
        seq: frontier.seq,
        close_time_ms,
        fee_recipient: to_core(operator.config.fee_recipient),
        fee_key: to_core(operator.config.fee_key),
        note_root: if new_orders.is_empty() {
            starknet_crypto::Felt::ZERO
        } else {
            to_core(note_root)
        },
        objective_numeraire_asset_id: to_core(operator.config.objective_numeraire_asset),
        markets,
        book: frontier.book.clone(),
        new_orders,
        cancellations,
        recovered_order_ids,
        outcomes,
        padding_seed: private_padding_seed(),
    };
    // a transition must prove in one snip-36 transaction: past the step budget, the newest
    // admissions wait for a later close.
    let budget = operator.config.policy.step_budget;
    let mut input = input;
    let (input, result) = loop {
        let attempt = input.clone();
        let result = tokio::task::spawn_blocking(move || build_transition(&attempt))
            .await
            .map_err(|error| format!("transition build panicked: {error}"))?
            .map_err(|error| format!("transition build: {error}"))?;
        let steps = zylith_core::exchange::StepShape::of(&result).estimated_steps();
        if steps <= budget {
            break (input, result);
        }
        if input.new_orders.is_empty() {
            return Err(format!(
                "transition {} needs about {steps} steps, beyond the {budget} step budget",
                input.seq
            ));
        }
        let drop =
            ((steps - budget).div_ceil(ADMISSION_STEPS) as usize + 1).min(input.new_orders.len());
        let keep = input.new_orders.len() - drop;
        input.new_orders.truncate(keep);
        admitted.truncate(keep);
        if keep == 0 {
            input.note_root = starknet_crypto::Felt::ZERO;
        }
    };
    let Some(for_legs) = worth_sending(operator, &input, &result, &cancels).await else {
        return Ok(());
    };

    let calldata = transition_calldata(&result.public, &attestations)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(from_core)
        .collect::<Vec<_>>();
    let cancelled = result
        .reports
        .iter()
        .filter(|report| report.removal == Some(zylith_core::exchange::Removal::Cancelled))
        .map(|report| from_core(report.order_id))
        .collect::<Vec<_>>();
    let snapshot_cancellations = cancels
        .iter()
        .map(|(cancel, _)| key(&from_core(cancel.order_id)))
        .collect::<BTreeSet<_>>();
    let transition_orders = result
        .reports
        .iter()
        .map(|report| key(&from_core(report.order_id)))
        .collect::<BTreeSet<_>>();
    let seq = frontier.seq;
    {
        let mut state = operator.state.lock().await;
        // the pipeline may have been rolled back while we built: only extend the same frontier.
        if frontier.seq != self::frontier(&state).seq {
            return Ok(());
        }
        // a cancellation timestamped before this close wins even if it arrived while the build
        // ran. a request after the cutoff applies only to a later epoch.
        let pending_cancel_won = admitted.iter().any(|order_id| {
            state
                .cancelled_orders
                .get(&key(order_id))
                .is_some_and(|cancel| eligible_before_close(cancel.cancelled_at_ms, close_time_ms))
                || state
                    .cancellations
                    .get(&key(order_id))
                    .is_some_and(|(_, received_at_ms)| {
                        eligible_before_close(*received_at_ms, close_time_ms)
                    })
        });
        let live_cancel_won = state
            .cancellations
            .iter()
            .any(|(order_id, (_, received_at_ms))| {
                transition_orders.contains(order_id)
                    && !snapshot_cancellations.contains(order_id)
                    && eligible_before_close(*received_at_ms, close_time_ms)
            });
        let residual_recovery_won = result.public.nullifiers.iter().any(|nullifier| {
            state
                .pending_residual_recoveries
                .get(&key(&from_core(*nullifier)))
                .is_some_and(|recovery| close_time_ms > recovery.requested_at_ms)
        });
        if pending_cancel_won || live_cancel_won || residual_recovery_won {
            return Ok(());
        }
        state.in_flight.push(InFlight {
            seq,
            close_time_ms,
            result,
            calldata,
            admitted,
            cancelled,
            applied_capacities,
            stage: TransitionStage::Proving,
            proof: None,
            prepared_submission: None,
            prepared_legged: Vec::new(),
            built_at_ms: now_ms(),
            legged: Vec::new(),
            leg_dropped: false,
            for_legs,
        });
        operator.save(&state).await?;
    }

    start_transition_proof(operator, seq).await?;
    Ok(())
}

/// the operator policy: whether a transition is sent (nothing when it is not), and whether it
/// is sent only for the searcher legs it makes possible. a transition is sent when its fees,
/// valued in strk at the attested midpoints, cover it; when a fill's settlement was funded by
/// that fill; when a cancellation or an expiry has waited long enough; or when the searcher legs
/// its reservations enable are expected to pay for it and for the transition that settles them.
/// an uneconomic internal crossing waits only to the configured liveness bound, after which the
/// fee reserve covers it. every external fill carries on-chain settlement support. an unfilled
/// reservation forces nothing; its release rides on the next transition sent.
async fn worth_sending(
    operator: &Operator,
    input: &TransitionInput,
    result: &TransitionResult,
    cancels: &[(zylith_core::exchange::CancelRequest, u64)],
) -> Option<bool> {
    let policy = &operator.config.policy;
    let now = now_ms();
    let forced_cancel = cancels
        .iter()
        .any(|(_, received_at)| now.saturating_sub(*received_at) >= policy.force_after_ms);
    let forced_expiry = result
        .reports
        .iter()
        .any(|report| report.removal == Some(zylith_core::exchange::Removal::Expired));
    let forced_recovery = result
        .reports
        .iter()
        .any(|report| report.removal == Some(zylith_core::exchange::Removal::Recovered));
    let funded_fill = fill_funding(&input.outcomes);
    let crossing = result.reports.iter().any(|report| report.fill_base != 0);
    let reserving = !result.public.capacities.is_empty();
    let forced = forced_cancel || forced_expiry || forced_recovery || funded_fill;
    let pays = crossing && fees_cover_cost(operator, result, 0, 1).await;
    // sent only for its searcher legs: their expected profit must pay for this transition and
    // for the one that later settles their fills.
    let for_legs = !forced
        && !pays
        && reserving
        && fees_cover_cost(
            operator,
            result,
            expected_leg_value(operator, input.seq, result).await,
            3,
        )
        .await;

    let mut state = operator.state.lock().await;
    if pays || forced || for_legs || !crossing {
        state.uneconomic_since_ms = None;
        return (pays || forced || for_legs).then_some(for_legs);
    }
    let since = *state.uneconomic_since_ms.get_or_insert(now);
    let covered = now.saturating_sub(since) >= policy.uneconomic_max_wait_ms;
    if covered {
        eprintln!(
            "an uneconomic internal crossing waited {} ms; the fee reserve covers it",
            now - since
        );
        state.uneconomic_since_ms = None;
    }
    covered.then_some(false)
}

/// whether the outcomes settle any external fill. the router diverts the market's configured
/// support to the settlement account for every fill, including fills submitted by third parties.
fn fill_funding(outcomes: &[ChainOutcome]) -> bool {
    outcomes.iter().any(|outcome| outcome.consumed_base != 0)
}

/// what the searcher legs for a transition's capacities are expected to earn, in strk, net of
/// their own gas: priced now, at a fresh m1 and ekubo's current routes.
async fn expected_leg_value(operator: &Operator, seq: u32, result: &TransitionResult) -> u128 {
    let (legs, _) = external_legs(
        operator,
        seq,
        result.public.capacities.iter().map(|capacity| {
            (
                from_core(capacity.pair_id),
                capacity.sell,
                capacity.bound,
                capacity.total,
            )
        }),
    )
    .await;
    legs.iter()
        .filter_map(|leg| leg.value_strk)
        .fold(0, u128::saturating_add)
}

/// whether the transition's fee notes, valued in strk at attested rates less a haircut, cover
/// the gas a transition costs times the cover ratio, and never less than the configured floor.
/// a fee note whose asset has no rate right now is worth nothing.
async fn fees_cover_cost(
    operator: &Operator,
    result: &TransitionResult,
    extra_strk: u128,
    transitions: u64,
) -> bool {
    let config = &operator.config;
    let rates = operator.market.rates(&config.pairs, now_ms()).await;
    let gas = {
        let state = operator.state.lock().await;
        if state.transition_gas == 0 {
            config.transition_gas_estimate
        } else {
            state.transition_gas
        }
    };
    let Ok(l2_price) = operator.snip36.l2_gas_price().await else {
        return false;
    };
    let fees = result
        .outputs
        .iter()
        .filter(|output| output.kind == OUTPUT_KIND_FEE)
        .map(|output| (from_core(output.note.asset_id), output.note.amount));
    fees_cover(
        fees,
        &rates,
        config.gas_fee_asset,
        gas,
        l2_price,
        config.fee_cover_percent,
        config.min_transition_fee_strk,
        config.fee_rate_haircut_bps,
        extra_strk,
        transitions,
    )
}

#[allow(clippy::too_many_arguments)]
fn fees_cover(
    fees: impl Iterator<Item = (Felt, u128)>,
    rates: &[Rate],
    strk: Felt,
    gas: u64,
    l2_price: u128,
    cover_percent: u64,
    floor_strk: u128,
    haircut_bps: u128,
    extra_strk: u128,
    transitions: u64,
) -> bool {
    let Some(cost) = crate::market::mul_div(
        u128::from(gas).saturating_mul(l2_price),
        u128::from(cover_percent),
        100,
        true,
    ) else {
        return false;
    };
    let cost = cost
        .max(floor_strk)
        .saturating_mul(u128::from(transitions.max(1)));
    let mut value = extra_strk;
    for (asset, amount) in fees {
        let worth = crate::market::convert(rates, asset, strk, amount, Round::Value)
            .and_then(|worth| crate::market::mul_div(worth, 10_000 - haircut_bps, 10_000, false))
            .unwrap_or(0);
        value = value.saturating_add(worth);
    }
    value >= cost
}

/// advances every withdrawal: starts proving for jobs without a running task, finalizes matured
/// exits, and settles finalizations by their receipts.
async fn drive_withdrawals(operator: &Arc<Operator>, state: &mut OperatorState) -> bool {
    let mut changed = false;
    let now = now_ms();
    let jobs = state.withdrawals.values().cloned().collect::<Vec<_>>();
    for job in jobs {
        let next = match job.stage {
            WithdrawalStage::Proving => {
                start_proving(operator, state, &job);
                None
            }
            WithdrawalStage::Requested {
                transaction_hash,
                matures_at_ms,
            } => match operator.chain().nullifier_state(job.nullifier).await {
                Ok(NULLIFIER_EXITED) => Some(WithdrawalStage::Finalized {
                    transaction_hash: Felt::ZERO,
                }),
                Ok(NULLIFIER_UNUSED) => Some(WithdrawalStage::Proving),
                Ok(NULLIFIER_EXIT_PENDING) => {
                    match pending_exit_maturity_ms(operator, &job).await {
                        Ok(chain_maturity) if chain_maturity != matures_at_ms => {
                            Some(WithdrawalStage::Requested {
                                transaction_hash,
                                matures_at_ms: chain_maturity,
                            })
                        }
                        Ok(chain_maturity) if now >= chain_maturity => {
                            let finalize = vec![call(
                                operator.config.exchange,
                                "finalize_withdrawal",
                                vec![job.nullifier],
                            )];
                            match operator.snip36.submit(finalize, None).await {
                                Ok(transaction_hash) => {
                                    Some(WithdrawalStage::Finalizing { transaction_hash })
                                }
                                Err(error) => {
                                    eprintln!(
                                        "withdrawal finalization failed: {}",
                                        crate::snip36::sanitize(&error)
                                    );
                                    None
                                }
                            }
                        }
                        Ok(_) => None,
                        Err(error) => Some(WithdrawalStage::Failed {
                            reason: crate::snip36::sanitize(&error),
                        }),
                    }
                }
                Ok(_) => Some(WithdrawalStage::Failed {
                    reason: "the withdrawal nullifier was spent by another transition".into(),
                }),
                Err(_) => None,
            },
            WithdrawalStage::Finalizing { transaction_hash } => {
                match operator.snip36.receipt(transaction_hash).await {
                    Some(Outcome::Accepted { .. }) => {
                        Some(WithdrawalStage::Finalized { transaction_hash })
                    }
                    // someone else may have finalized first; otherwise try again.
                    Some(Outcome::Reverted { .. }) => {
                        match operator.chain().nullifier_state(job.nullifier).await {
                            Ok(NULLIFIER_EXITED) => Some(WithdrawalStage::Finalized {
                                transaction_hash: Felt::ZERO,
                            }),
                            Ok(NULLIFIER_EXIT_PENDING) => pending_exit_maturity_ms(operator, &job)
                                .await
                                .ok()
                                .map(|matures_at_ms| WithdrawalStage::Requested {
                                    transaction_hash,
                                    matures_at_ms,
                                }),
                            Ok(NULLIFIER_UNUSED) => Some(WithdrawalStage::Proving),
                            Ok(_) => Some(WithdrawalStage::Failed {
                                reason: "the withdrawal nullifier was spent by another transition"
                                    .into(),
                            }),
                            Err(_) => None,
                        }
                    }
                    // a gateway can lose a submitted finalization. reconcile it against chain
                    // state after the receipt window instead of stranding the job forever.
                    None if now.saturating_sub(job.updated_at_ms) >= 60_000 => {
                        match operator.chain().nullifier_state(job.nullifier).await {
                            Ok(NULLIFIER_EXITED) => Some(WithdrawalStage::Finalized {
                                transaction_hash: Felt::ZERO,
                            }),
                            Ok(NULLIFIER_EXIT_PENDING) => pending_exit_maturity_ms(operator, &job)
                                .await
                                .ok()
                                .map(|matures_at_ms| WithdrawalStage::Requested {
                                    transaction_hash,
                                    matures_at_ms,
                                }),
                            Ok(NULLIFIER_UNUSED) => Some(WithdrawalStage::Proving),
                            Ok(_) => Some(WithdrawalStage::Failed {
                                reason: "the withdrawal nullifier was spent by another transition"
                                    .into(),
                            }),
                            Err(_) => None,
                        }
                    }
                    None => None,
                }
            }
            _ => None,
        };
        if let Some(stage) = next
            && let Some(entry) = state.withdrawals.get_mut(&key(&job.nullifier))
        {
            entry.stage = stage;
            entry.updated_at_ms = now;
            changed = true;
        }
    }
    changed
}

/// finalizes accepted residual exits after their delay so an offline user still receives funds.
async fn drive_residual_recoveries(operator: &Arc<Operator>, state: &mut OperatorState) -> bool {
    let now = now_ms();
    let recoveries = state
        .pending_residual_recoveries
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut changed = false;
    for recovery in recoveries {
        let Ok(nullifier_state) = operator.chain().nullifier_state(recovery.nullifier).await else {
            continue;
        };
        if nullifier_state != NULLIFIER_EXIT_PENDING || now < recovery.matures_at_ms {
            continue;
        }
        let mut transaction = recovery.finalization_transaction;
        if let Some(transaction_hash) = transaction {
            match operator.snip36.receipt(transaction_hash).await {
                Some(Outcome::Accepted { .. }) => continue,
                Some(Outcome::Reverted { .. }) => transaction = None,
                None if now.saturating_sub(recovery.updated_at_ms) >= 60_000 => {
                    transaction = None;
                }
                None => continue,
            }
        }
        if transaction.is_none() && now.saturating_sub(recovery.updated_at_ms) >= 5_000 {
            match operator
                .snip36
                .submit(
                    vec![call(
                        operator.config.exchange,
                        "finalize_residual_recovery",
                        vec![recovery.nullifier],
                    )],
                    None,
                )
                .await
            {
                Ok(transaction_hash) => transaction = Some(transaction_hash),
                Err(error) => eprintln!(
                    "residual recovery finalization failed: {}",
                    crate::snip36::sanitize(&error)
                ),
            }
            if let Some(entry) = state
                .pending_residual_recoveries
                .get_mut(&key(&recovery.nullifier))
            {
                entry.finalization_transaction = transaction;
                entry.updated_at_ms = now;
                changed = true;
            }
        }
    }
    changed
}

async fn pending_exit_maturity_ms(operator: &Operator, job: &WithdrawalJob) -> Result<u64, String> {
    let exit = operator.chain().pending_exit(job.nullifier).await?;
    if exit.asset_id != from_core(job.request.note.asset_id)
        || exit.amount != job.request.note.amount
        || exit.exit_commitment != from_core(job.request.exit_commitment)
        || exit.exit_authority != from_core(job.request.exit_authority)
    {
        return Err("the pending exit does not match the withdrawal request".into());
    }
    exit.matures_at
        .checked_mul(1_000)
        .ok_or_else(|| "the pending exit maturity overflows milliseconds".into())
}

const NULLIFIER_UNUSED: u8 = 0;
const NULLIFIER_EXIT_PENDING: u8 = 2;
const NULLIFIER_EXITED: u8 = 3;

/// queues a withdrawal after checking that its note can still exit; proving starts on the next
/// driver pass.
pub async fn start_withdrawal(
    operator: &Arc<Operator>,
    request: zylith_core::exchange::WithdrawRequest,
) -> Result<Felt, String> {
    request
        .validate(operator.config.chain_context())
        .map_err(|error| error.to_string())?;
    let nullifier = from_core(request.note.nullifier());
    {
        let state = operator.state.lock().await;
        if state
            .withdrawals
            .get(&key(&nullifier))
            .is_some_and(|job| !matches!(job.stage, WithdrawalStage::Failed { .. }))
        {
            return Ok(nullifier);
        }
        if state
            .notes
            .membership(from_core(request.note.output_leaf()))
            .is_none()
        {
            return Err("the note is not on chain yet".into());
        }
    }
    if operator.chain().nullifier_state(nullifier).await? != NULLIFIER_UNUSED {
        return Err("the note is already spent".into());
    }
    let mut state = operator.state.lock().await;
    state.withdrawals.insert(
        key(&nullifier),
        WithdrawalJob {
            request,
            nullifier,
            stage: WithdrawalStage::Proving,
            prepared_submission: None,
            updated_at_ms: now_ms(),
        },
    );
    operator.save(&state).await?;
    Ok(nullifier)
}

/// proves a withdrawal and submits its request in the background, once per job.
fn start_proving(operator: &Arc<Operator>, state: &OperatorState, job: &WithdrawalJob) {
    let job_key = key(&job.nullifier);
    if !operator
        .withdrawals_running
        .lock()
        .expect("withdrawal task set")
        .insert(job_key.clone())
    {
        return;
    }
    let request = job.request.clone();
    let nullifier = job.nullifier;
    let prepared_submission = job.prepared_submission.clone();
    let membership = state
        .notes
        .membership(from_core(request.note.output_leaf()));
    let note_root = state.notes.root();
    let operator = operator.clone();
    tokio::spawn(async move {
        let outcome = prove_and_request(
            &operator,
            request,
            nullifier,
            membership,
            note_root,
            prepared_submission,
        )
        .await;
        let mut state = operator.state.lock().await;
        if let Some(job) = state.withdrawals.get_mut(&job_key) {
            let (stage, retain_prepared) = match outcome {
                Ok(stage) => (stage, false),
                Err((reason, true)) => {
                    eprintln!(
                        "withdrawal submission remains pending: {}",
                        crate::snip36::sanitize(&reason)
                    );
                    (WithdrawalStage::Proving, true)
                }
                Err((reason, false)) if is_retryable_proving_error(&reason) => {
                    eprintln!(
                        "withdrawal proof job remains pending: {}",
                        crate::snip36::sanitize(&reason)
                    );
                    (WithdrawalStage::Proving, false)
                }
                Err((reason, false)) => (
                    WithdrawalStage::Failed {
                        reason: crate::snip36::sanitize(&reason),
                    },
                    false,
                ),
            };
            job.stage = stage;
            if !retain_prepared {
                job.prepared_submission = None;
            }
            job.updated_at_ms = now_ms();
        }
        // a failed write halts the operator; the job resumes from its durable stage.
        let _ = operator.save(&state).await;
        drop(state);
        operator
            .withdrawals_running
            .lock()
            .expect("withdrawal task set")
            .remove(&job_key);
    });
}

async fn prove_and_request(
    operator: &Arc<Operator>,
    request: zylith_core::exchange::WithdrawRequest,
    nullifier: Felt,
    membership: Option<zylith_core::exchange::NoteMembership>,
    note_root: Felt,
    prepared_submission: Option<crate::snip36::PreparedSubmission>,
) -> Result<WithdrawalStage, (String, bool)> {
    // a job resumed after a restart may already have landed.
    match operator
        .chain()
        .nullifier_state(nullifier)
        .await
        .map_err(|error| (error, prepared_submission.is_some()))?
    {
        NULLIFIER_UNUSED => {}
        NULLIFIER_EXIT_PENDING => {
            let job = WithdrawalJob {
                request,
                nullifier,
                stage: WithdrawalStage::Proving,
                prepared_submission: None,
                updated_at_ms: now_ms(),
            };
            return Ok(WithdrawalStage::Requested {
                transaction_hash: Felt::ZERO,
                matures_at_ms: pending_exit_maturity_ms(operator, &job)
                    .await
                    .map_err(|error| (error, true))?,
            });
        }
        NULLIFIER_EXITED => {
            return Ok(WithdrawalStage::Finalized {
                transaction_hash: Felt::ZERO,
            });
        }
        _ => return Err(("the note is already spent".into(), false)),
    }
    if let Some(prepared) = prepared_submission {
        let transaction_hash = operator
            .snip36
            .submit_with_gas_durable(Vec::new(), None, None, Some(prepared), |_| async { Ok(()) })
            .await
            .map_err(|error| (error, true))?;
        return settle_withdrawal_request(operator, request, nullifier, transaction_hash).await;
    }
    let (public, witness) = build_withdrawal(&WithdrawalInput {
        chain_context: operator.config.chain_context(),
        note_root: to_core(note_root),
        exit_commitment: request.exit_commitment,
        exit_authority: request.exit_authority,
        note: request.note.clone(),
        membership: membership
            .ok_or_else(|| ("the note is not on chain yet".to_string(), false))?,
        authorization: request.authorization,
    })
    .map_err(|error| (error.to_string(), false))?;
    let expected = from_core(proof_message_hash(
        to_core(operator.config.withdrawal_proof_program),
        WITHDRAWAL_MESSAGE_DOMAIN,
        bound_statement_message(
            WITHDRAWAL_MESSAGE_DOMAIN,
            public.chain_context,
            public.commitment,
        ),
    ));
    let witness = witness.into_iter().map(from_core).collect::<Vec<_>>();
    let context = ProofJobContext {
        statement_kind: ProofStatementKind::Withdrawal,
        transition_id: format!("withdrawal:{:#x}", from_core(public.commitment)),
        epoch_id: None,
        exchange_address: format!("{:#x}", operator.config.exchange),
        input_state_root: Some(format!("{note_root:#x}")),
        expected_output_state_root: None,
        statement_commitment: format!("{:#x}", from_core(public.commitment)),
        witness_hash: canonical_witness_hash(&witness),
        program_entrypoint: "compile_withdrawal_proof".into(),
    };
    let mut calldata = vec![operator.config.exchange, Felt::from(witness.len() as u64)];
    calldata.extend(witness);
    let proof = operator
        .snip36
        .prove(
            vec![call(
                operator.config.withdrawal_proof_program,
                "compile_withdrawal_proof",
                calldata,
            )],
            expected,
            context,
        )
        .await
        .map_err(|error| (error, false))?;
    let request_calldata = withdrawal_calldata(&public)
        .into_iter()
        .map(from_core)
        .collect();
    let calls = vec![call(
        operator.config.exchange,
        "request_withdrawal",
        request_calldata,
    )];
    let simulation = operator
        .snip36
        .simulate(calls.clone(), Some(&proof))
        .await
        .map_err(|error| (error, false))?;
    if let Some(reason) = simulation.reverted {
        return Err((
            format!("withdrawal proof simulation reverted: {reason}"),
            false,
        ));
    }
    let durable_operator = operator.clone();
    let durable_key = key(&nullifier);
    let transaction_hash = operator
        .snip36
        .submit_with_gas_durable(
            calls,
            Some(&proof),
            Some(simulation.l2_gas),
            None,
            move |prepared| async move {
                let mut state = durable_operator.state.lock().await;
                let job = state
                    .withdrawals
                    .get_mut(&durable_key)
                    .ok_or_else(|| "withdrawal job disappeared before submission".to_string())?;
                if !matches!(job.stage, WithdrawalStage::Proving) {
                    return Err("withdrawal job changed before submission".into());
                }
                job.prepared_submission = Some(prepared);
                job.updated_at_ms = now_ms();
                durable_operator.save(&state).await
            },
        )
        .await
        .map_err(|error| (error, true))?;
    settle_withdrawal_request(operator, request, nullifier, transaction_hash).await
}

async fn settle_withdrawal_request(
    operator: &Operator,
    request: zylith_core::exchange::WithdrawRequest,
    nullifier: Felt,
    transaction_hash: Felt,
) -> Result<WithdrawalStage, (String, bool)> {
    match operator.snip36.wait(transaction_hash).await {
        Some(Outcome::Accepted { .. }) => {
            let job = WithdrawalJob {
                request,
                nullifier,
                stage: WithdrawalStage::Proving,
                prepared_submission: None,
                updated_at_ms: now_ms(),
            };
            Ok(WithdrawalStage::Requested {
                transaction_hash,
                matures_at_ms: pending_exit_maturity_ms(operator, &job)
                    .await
                    .map_err(|error| (error, true))?,
            })
        }
        Some(Outcome::Reverted { reason }) => {
            Err((format!("withdrawal reverted: {reason}"), false))
        }
        None => Err(("withdrawal was not included".to_string(), true)),
    }
}

#[cfg(test)]
mod tests {
    use zylith_core::exchange::fixtures::*;
    use zylith_core::exchange::*;

    use super::*;
    use crate::state::PendingOrder;

    #[test]
    fn scheduled_closes_and_reference_windows_are_exact() {
        assert!(scheduled_epoch_close(12_000, 6_000));
        assert!(!scheduled_epoch_close(12_001, 6_000));
        assert!(!scheduled_epoch_close(12_000, 0));
        assert!(eligible_before_close(11_999, 12_000));
        assert!(!eligible_before_close(12_000, 12_000));
        assert!(!eligible_before_close(12_001, 12_000));
        assert!(reference_windows_cover_close([(11_999, 12_001)], 12_000));
        assert!(reference_windows_cover_close([(12_000, 12_000)], 12_000));
        assert!(!reference_windows_cover_close([(12_001, 13_000)], 12_000));
        assert!(!reference_windows_cover_close([(11_000, 11_999)], 12_000));
        assert!(!reference_windows_cover_close(
            [(11_000, 13_000), (12_001, 13_000)],
            12_000,
        ));
    }

    #[test]
    fn fees_cover_only_what_they_are_worth_in_strk() {
        let (strk, usdc, unpriced) = (Felt::from(1_u8), Felt::from(2_u8), Felt::from(3_u8));
        // two strk atoms per usdc atom.
        let rates = [Rate {
            base: usdc,
            quote: strk,
            midpoint: 2,
            scale: 1,
        }];
        let covers = |fees: &[(Felt, u128)], floor, haircut, extra, transitions| {
            fees_cover(
                fees.iter().copied(),
                &rates,
                strk,
                100,
                10,
                100,
                floor,
                haircut,
                extra,
                transitions,
            )
        };
        let cover = |fees: &[(Felt, u128)], floor, haircut| covers(fees, floor, haircut, 0, 1);
        // the transition costs 1000 strk atoms.
        assert!(cover(&[(usdc, 500)], 1, 0));
        assert!(!cover(&[(usdc, 499)], 1, 0));
        // the haircut values fees below their attested rate.
        assert!(!cover(&[(usdc, 500)], 1, 100));
        assert!(cover(&[(usdc, 506)], 1, 100));
        // an asset without a rate is worth nothing, however large the note.
        assert!(!cover(&[(unpriced, u128::MAX)], 1, 0));
        // the floor holds when it is above what gas costs.
        assert!(!covers(&[(strk, 1_099)], 1_100, 0, 0, 1));
        assert!(covers(&[(strk, 1_100)], 1_100, 0, 0, 1));
        // a reservation's expected searcher profit counts, and must pay for the transition
        // that later settles its fills as well.
        assert!(!covers(&[], 1, 0, 1_999, 2));
        assert!(covers(&[], 1, 0, 2_000, 2));
        assert!(covers(&[(usdc, 250)], 1, 0, 1_500, 2));
    }

    #[test]
    fn a_failed_state_write_halts_every_later_write() {
        let dir = std::env::temp_dir().join(format!("zylith-halt-{}", std::process::id()));
        let store = Store::open(&dir, None, &[7; 32]).unwrap();
        let halted = AtomicBool::new(false);
        let state = OperatorState::new(0);
        persist(&store, &halted, &state).unwrap();
        // the disk goes away: the write fails and the operator halts.
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(persist(&store, &halted, &state).is_err());
        assert!(running(&halted).is_err());
        // the disk coming back does not resume it: only a restart reloads durable state.
        std::fs::create_dir_all(&dir).unwrap();
        assert!(persist(&store, &halted, &state).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_landed_transition_commits_its_book_capacities_and_order_history() {
        let mut notes = Notes::default();
        let seller = user(4);
        let note = deposit(&seller, BASE, 10, 4);
        notes.add_deposit(&note);
        let order = new_order(
            &notes,
            &seller,
            true,
            true,
            10,
            95,
            std::slice::from_ref(&note),
        );
        let request = OrderRequest {
            terms: order.terms.clone(),
            funding: vec![note],
            authorization: order.authorization,
        };
        let result = build_transition(&input(1, vec![], vec![order], notes.root(), 100)).unwrap();
        let order_id = from_core(request.order_id());

        let mut state = OperatorState::new(0);
        state.pending_orders.insert(
            key(&order_id),
            PendingOrder {
                request: request.clone(),
                received_at_ms: 0,
            },
        );
        let landed = InFlight {
            seq: 1,
            close_time_ms: 10_001,
            result: result.clone(),
            calldata: vec![],
            admitted: vec![order_id],
            cancelled: vec![],
            applied_capacities: vec![],
            stage: TransitionStage::Submitted {
                transaction_hash: Felt::ONE,
            },
            proof: None,
            prepared_submission: None,
            prepared_legged: Vec::new(),
            built_at_ms: 0,
            legged: Vec::new(),
            leg_dropped: false,
            for_legs: false,
        };
        state.in_flight.push(landed.clone());
        assert_eq!(frontier(&state).seq, 2);
        assert!(frontier(&state).consumed_orders.contains(&key(&order_id)));
        state.cancellations.insert(
            key(&order_id),
            (
                CancelRequest {
                    order_id: request.order_id(),
                    signature: sign_message(
                        &seller.cancel_key,
                        &cancel_message(Felt::from(CHAIN), request.order_id()),
                    )
                    .unwrap(),
                },
                10_002,
            ),
        );
        assert!(!settle_pending_cancellations(&mut state, None));
        assert!(state.pending_orders.contains_key(&key(&order_id)));
        state.cancellations.clear();

        state.in_flight.clear();
        let capacity = &result.public.capacities[0];
        let (pair_id, sell) = (from_core(capacity.pair_id), capacity.sell);
        // a leg that rode with the transition may have filled only part of its capacity, so
        // every capacity stays open for follow-ups, which read what is left from the chain.
        let mut carried = state.clone();
        commit(
            &mut carried,
            InFlight {
                legged: vec![(pair_id, sell)],
                ..landed.clone()
            },
        );
        assert!(!carried.capacities[0].leg_attempted);
        // the leg that rode with it funded the settlement.
        assert!(carried.capacities[0].outcome_funded);
        commit(&mut state, landed);
        assert!(!state.capacities[0].outcome_funded);
        assert!(!state.capacities[0].leg_attempted);
        assert_eq!(state.confirmed_seq, 1);
        assert_eq!(state.book.len(), 1);
        assert!(state.pending_orders.is_empty());
        assert_eq!(state.capacities.len(), 1);
        assert_eq!(state.capacities[0].seq, 1);
        let history = &state.orders[&key(&order_id)];
        assert!(history[0].report.admitted);
        assert_eq!(history[0].report.reserved, 10);
        assert_eq!(
            state.transition_leaves[&1].len(),
            result.public.output_records.len()
        );
    }

    #[test]
    fn a_follow_up_leg_retries_until_it_lands_or_runs_out() {
        let sent = OpenCapacity {
            seq: 1,
            pair_id: Felt::ONE,
            sell: true,
            opened_at_ms: 0,
            leg_attempted: false,
            leg_transaction: Some(Felt::TWO),
            leg_submissions: 1,
            leg_retry_at_ms: 1_000,
            window_closes_ms: 0,
            outcome_funded: false,
        };
        let accepted = settle_leg(
            &sent,
            Some(crate::snip36::Outcome::Accepted {
                block_number: 1,
                fee: 1,
            }),
            2_000,
        );
        // a landed fill leaves the capacity open: its remainder is tried at once.
        assert!(!accepted.leg_attempted && accepted.leg_transaction.is_none());
        assert_eq!(accepted.leg_retry_at_ms, 2_000);
        // and it funded the settlement, so later fills of the transition do not pay again.
        assert!(accepted.outcome_funded);
        let reverted_first = settle_leg(
            &sent,
            Some(crate::snip36::Outcome::Reverted {
                reason: "stale".into(),
            }),
            2_000,
        );
        assert!(!reverted_first.outcome_funded);

        let reverted = Some(crate::snip36::Outcome::Reverted {
            reason: "stale".into(),
        });
        let retry = settle_leg(&sent, reverted.clone(), 2_000);
        assert!(!retry.leg_attempted && retry.leg_transaction.is_none());
        assert_eq!(retry.leg_retry_at_ms, 2_000 + LEG_RETRY_MS);
        let exhausted = OpenCapacity {
            leg_submissions: MAX_LEG_SUBMISSIONS,
            ..sent.clone()
        };
        assert!(settle_leg(&exhausted, reverted.clone(), 2_000).leg_attempted);

        // no receipt yet: it waits, then counts as lost.
        assert_eq!(settle_leg(&sent, None, 2_000), sent);
        let lost = settle_leg(&sent, None, 1_001 + LEG_PENDING_MS);
        assert!(!lost.leg_attempted && lost.leg_transaction.is_none());

        // with its window known, a leg is retried within the window and given up after it.
        let windowed = OpenCapacity {
            window_closes_ms: 12_000,
            ..sent.clone()
        };
        let early = settle_leg(&windowed, reverted.clone(), 4_000);
        assert!(!early.leg_attempted && early.leg_retry_at_ms == 4_000 + LEG_RETRY_MS);
        assert!(settle_leg(&windowed, reverted, 12_000).leg_attempted);
        // an unanswered leg counts as lost soon after the window, not minutes later.
        assert_eq!(
            settle_leg(&windowed, None, 12_000 + LEG_INCLUSION_GRACE_MS),
            windowed
        );
        let gone = settle_leg(&windowed, None, 12_001 + LEG_INCLUSION_GRACE_MS);
        assert!(gone.leg_attempted && gone.leg_transaction.is_none());
    }

    #[test]
    fn a_legs_floor_pays_for_what_it_was_sent_for() {
        // the first leg of a transition sent only for its legs pays for that transition, the
        // settlement and a possible freeze; a later leg pays for none of those shared costs.
        assert_eq!(leg_support(Some(30), 20, true), Some(70));
        assert_eq!(leg_support(Some(0), 20, true), Some(40));
        assert_eq!(leg_support(Some(0), 20, false), Some(0));
        // a fee that cannot be priced keeps the leg out.
        assert_eq!(leg_support(None, 20, true), None);
    }

    #[test]
    fn every_external_fill_funds_its_settlement() {
        let outcome = |seq, consumed_base| {
            ChainOutcome::from_capacity(seq, to_core(Felt::ONE), true, consumed_base, 5, 1, 1)
        };
        assert!(fill_funding(&[outcome(1, 3)]));
        // an unfilled capacity forces nothing: its release rides on the next transition.
        assert!(!fill_funding(&[outcome(2, 0)]));
        assert!(!fill_funding(&[]));
    }

    #[test]
    fn an_expired_external_window_needs_no_freeze_transaction() {
        let view = CapacityView {
            opened_at: 100,
            status: CAPACITY_OPEN,
            ..Default::default()
        };
        assert!(external_window_open(&view, 106, 6).unwrap());
        assert!(!external_window_open(&view, 107, 6).unwrap());
        assert!(
            !external_window_open(
                &CapacityView {
                    status: CAPACITY_FILLED,
                    ..view
                },
                101,
                6,
            )
            .unwrap()
        );
        assert!(external_window_open(&view, u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn a_leg_must_cover_its_realized_fee_and_carries_it_on_chain() {
        // the leg that funds the settlement carries it; the others of its transition do not.
        assert_eq!(realized_floor(100, Some(60), 20, 10), Some(90));
        assert_eq!(realized_floor(89, Some(60), 20, 10), None);
        assert_eq!(realized_floor(89, Some(60), 0, 10), Some(70));
        assert_eq!(realized_floor(100, None, 20, 10), None);

        let mut leg = call(Felt::ONE, "execute_external_fill", vec![Felt::ZERO; 8]);
        leg.calldata[LEG_MIN_PROFIT_INDEX] = Felt::from(50_u8);
        raise_min_profit(&mut leg, 70);
        assert_eq!(leg.calldata[LEG_MIN_PROFIT_INDEX], Felt::from(70_u8));
        // the estimated floor is never lowered.
        raise_min_profit(&mut leg, 60);
        assert_eq!(leg.calldata[LEG_MIN_PROFIT_INDEX], Felt::from(70_u8));
    }

    #[test]
    fn orders_that_can_never_join_leave_the_pending_set() {
        let mut notes = Notes::default();
        let seller = user(4);
        let note = deposit(&seller, BASE, 10, 4);
        notes.add_deposit(&note);
        let order = new_order(
            &notes,
            &seller,
            true,
            true,
            10,
            95,
            std::slice::from_ref(&note),
        );
        let request = OrderRequest {
            terms: order.terms.clone(),
            funding: vec![note.clone()],
            authorization: order.authorization,
        };
        let pending = vec![PendingOrder {
            request: request.clone(),
            received_at_ms: 0,
        }];
        let order_key = key(&from_core(request.order_id()));
        let nullifier = from_core(note.nullifier()).to_bytes_be();
        let expiry = request.terms.expiry_ms;
        let chain = |state: u8| BTreeMap::from([(nullifier, state)]);

        assert!(stale_pending(&pending, expiry - 1, &BTreeSet::new(), &chain(0)).is_empty());
        assert_eq!(
            stale_pending(&pending, expiry, &BTreeSet::new(), &chain(0)),
            std::slice::from_ref(&order_key)
        );
        assert_eq!(
            stale_pending(&pending, expiry - 1, &BTreeSet::new(), &chain(1)),
            std::slice::from_ref(&order_key)
        );
        // spent by a transition still in flight, or not read: it waits.
        assert!(
            stale_pending(
                &pending,
                expiry - 1,
                &BTreeSet::from([nullifier]),
                &chain(1)
            )
            .is_empty()
        );
        assert!(stale_pending(&pending, expiry - 1, &BTreeSet::new(), &BTreeMap::new()).is_empty());

        let mut state = OperatorState::new(0);
        state.pending_orders.insert(
            order_key.clone(),
            PendingOrder {
                request: request.clone(),
                received_at_ms: 0,
            },
        );
        state.cancellations.insert(
            order_key.clone(),
            (
                CancelRequest {
                    order_id: request.order_id(),
                    signature: sign_message(
                        &seller.cancel_key,
                        &cancel_message(Felt::from(CHAIN), request.order_id()),
                    )
                    .unwrap(),
                },
                7,
            ),
        );
        let pending_order = &state.pending_orders[&order_key];
        assert!(protected_by_closing_epoch(pending_order, 7, Some(6)));
        assert!(!protected_by_closing_epoch(pending_order, 5, Some(6)));
        assert!(!protected_by_closing_epoch(pending_order, 7, None));
        let mut at_boundary = pending_order.clone();
        at_boundary.received_at_ms = 6;
        assert!(!protected_by_closing_epoch(&at_boundary, 7, Some(6)));
        assert!(!settle_pending_cancellations(&mut state, Some(6)));
        assert!(state.pending_orders.contains_key(&order_key));
        assert!(state.cancellations.contains_key(&order_key));
        assert!(settle_pending_cancellations(&mut state, None));
        assert!(!state.pending_orders.contains_key(&order_key));
        assert!(!state.cancellations.contains_key(&order_key));
        let tombstone = &state.cancelled_orders[&order_key];
        assert_eq!(tombstone.expires_at_ms, expiry);
        assert_eq!(tombstone.cancelled_at_ms, 7);
    }

    #[test]
    fn the_transition_gas_estimate_follows_landed_fees() {
        let mut state = OperatorState::new(0);
        learn_transition_gas(&mut state, 400 * 1_000, 1_000, 200);
        assert_eq!(state.transition_gas, 200 - 50 + 100);
        for _ in 0..40 {
            learn_transition_gas(&mut state, 400 * 1_000, 1_000, 200);
        }
        assert!((395..=400).contains(&state.transition_gas));
        learn_transition_gas(&mut state, 0, 1_000, 200);
        assert!((395..=400).contains(&state.transition_gas));
    }

    #[test]
    fn closed_histories_and_finished_withdrawals_are_pruned_after_retention() {
        let mut state = OperatorState::new(0);
        let report = |removal| OrderEvent {
            seq: 1,
            close_time_ms: 1_000,
            report: zylith_core::exchange::OrderReport {
                removal,
                ..Default::default()
            },
        };
        state
            .orders
            .insert("closed".into(), vec![report(Some(Removal::Completed))]);
        state.orders.insert("live".into(), vec![report(None)]);
        state.cancelled_orders.insert(
            "cancelled".into(),
            CancellationTombstone {
                cancel_authority: Felt::ONE,
                cancelled_at_ms: 1_000,
                expires_at_ms: 1_010 + TOMBSTONE_RETENTION_MS,
                effective_after_seq: 1,
            },
        );
        assert!(!prune(&mut state, 1_000 + HISTORY_RETENTION_MS));
        assert!(prune(&mut state, 1_001 + HISTORY_RETENTION_MS));
        assert_eq!(state.orders.keys().collect::<Vec<_>>(), ["live"]);
        // the pruned history leaves a tombstone, itself dropped long after.
        assert_eq!(
            state.closed_orders["closed"],
            ClosedOrder {
                seq: 1,
                close_time_ms: 1_000,
                removal: Removal::Completed,
            }
        );
        assert!(!prune(&mut state, 1_000 + TOMBSTONE_RETENTION_MS));
        assert!(prune(&mut state, 1_001 + TOMBSTONE_RETENTION_MS));
        assert!(state.closed_orders.is_empty());
        assert!(state.cancelled_orders.contains_key("cancelled"));
        assert!(prune(&mut state, 1_011 + TOMBSTONE_RETENTION_MS));
        assert!(state.cancelled_orders.is_empty());
    }
}

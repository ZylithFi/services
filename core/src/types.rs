use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    ProtocolError,
    hash::{
        domain_felt, encode_starknet_felt, felt_from_hex_str, field_from_bool, field_from_u64,
        field_from_u128, poseidon_chain_hex, tagged_commitment_sha256,
    },
    keys::UserKeys,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nullifier(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderCommitment(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub asset_id: AssetId,
    pub amount: u128,
    pub owner_public_key: String,
    pub withdraw_authority: String,
    pub blinding: String,
    pub nonce: u64,
    pub metadata_commitment: String,
}

impl Note {
    pub fn commitment(&self) -> Result<NoteCommitment, ProtocolError> {
        let asset_id = felt_from_hex_str(&encode_starknet_felt("asset-id", &self.asset_id.0))?;
        let owner_public_key = felt_from_hex_str(&encode_starknet_felt(
            "owner-public-key",
            &self.owner_public_key,
        ))?;
        let blinding = felt_from_hex_str(&self.blinding)?;
        let nonce = field_from_u64(self.nonce);
        let metadata_commitment = felt_from_hex_str(&self.metadata_commitment)?;
        let amount = field_from_u128(self.amount);
        let withdraw_authority = felt_from_hex_str(&self.withdraw_authority)?;

        Ok(NoteCommitment(poseidon_chain_hex(
            domain_felt("zylith/note"),
            &[
                asset_id,
                amount,
                owner_public_key,
                withdraw_authority,
                blinding,
                nonce,
                metadata_commitment,
            ],
        )))
    }

    pub fn nullifier(&self, keys: &UserKeys) -> Result<Nullifier, ProtocolError> {
        let note_commitment = felt_from_hex_str(&self.commitment()?.0)?;
        let spend_auth_key = felt_from_hex_str(&encode_starknet_felt(
            "spend-auth-key",
            &hex::encode(keys.spend_auth_key),
        ))?;

        Ok(Nullifier(poseidon_chain_hex(
            domain_felt("zylith/nullifier"),
            &[note_commitment, spend_auth_key],
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositIntent {
    pub asset_id: AssetId,
    pub amount: u128,
    pub deposit_nonce: u64,
    pub recipient_owner_public_key: String,
    pub recipient_withdraw_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderIntent {
    pub pair_id: PairId,
    pub side: OrderSide,
    pub limit_price: u128,
    pub amount: u128,
    pub min_fill: u128,
    pub expiry_epoch: u64,
    pub order_nonce: u64,
    pub funding_note_ref: NoteCommitment,
    pub funding_nullifier: Nullifier,
    pub recipient_owner_public_key: String,
    pub recipient_withdraw_authority: String,
    pub auditor_view_allowed: bool,
}

impl OrderIntent {
    pub fn commitment(&self) -> Result<OrderCommitment, ProtocolError> {
        let pair_id = felt_from_hex_str(&encode_starknet_felt("pair-id", &self.pair_id.0))?;
        let side = match self.side {
            OrderSide::Buy => field_from_u64(0),
            OrderSide::Sell => field_from_u64(1),
        };
        let limit_price = field_from_u128(self.limit_price);
        let amount = field_from_u128(self.amount);
        let min_fill = field_from_u128(self.min_fill);
        let expiry_epoch = field_from_u64(self.expiry_epoch);
        let order_nonce = field_from_u64(self.order_nonce);
        let funding_note_ref = felt_from_hex_str(&self.funding_note_ref.0)?;
        let funding_nullifier = felt_from_hex_str(&self.funding_nullifier.0)?;
        let recipient_owner_public_key = felt_from_hex_str(&encode_starknet_felt(
            "owner-public-key",
            &self.recipient_owner_public_key,
        ))?;
        let recipient_withdraw_authority = felt_from_hex_str(&self.recipient_withdraw_authority)?;
        let auditor_view_allowed = field_from_bool(self.auditor_view_allowed);

        Ok(OrderCommitment(poseidon_chain_hex(
            domain_felt("zylith/order"),
            &[
                pair_id,
                side,
                limit_price,
                amount,
                min_fill,
                expiry_epoch,
                order_nonce,
                funding_note_ref,
                funding_nullifier,
                recipient_owner_public_key,
                recipient_withdraw_authority,
                auditor_view_allowed,
            ],
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOrderPayload {
    pub order: OrderIntent,
    pub funding_note: Note,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub algorithm: String,
    pub key_id: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderShare {
    pub committee_member_id: String,
    pub encrypted_share: EncryptedBlob,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderShareBundle {
    pub order_commitment: OrderCommitment,
    pub cancellation_auth_tag: String,
    pub pair_id: PairId,
    pub epoch_id: u64,
    pub transport_envelope: Option<EncryptedBlob>,
    pub shares: Vec<OrderShare>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderSubmission {
    pub order_bundle: OrderShareBundle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderSubmissionAccepted {
    pub batch_id: BatchId,
    pub order_commitment: OrderCommitment,
    pub accepted_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderCancellationRequest {
    pub batch_id: BatchId,
    pub order_commitment: OrderCommitment,
    pub cancellation_secret: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderCancellationAccepted {
    pub batch_id: BatchId,
    pub order_commitment: OrderCommitment,
    pub cancelled_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMemberPublicConfig {
    pub member_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMemberPrivateConfig {
    pub member_id: String,
    pub private_key: String,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeKeyRegistry {
    pub members: Vec<CommitteeMemberPublicConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptedOrderShare {
    pub member_id: String,
    pub order_commitment: OrderCommitment,
    pub share_index: u64,
    pub share_count: u64,
    pub plaintext_len: u64,
    pub share_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchShareContributions {
    pub batch_id: BatchId,
    pub shares: Vec<DecryptedOrderShare>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmittedOrderRecord {
    pub received_at_unix_ms: u64,
    pub order_bundle: OrderShareBundle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchStatus {
    Open,
    Closed,
    Clearing,
    Settled,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub epoch_id: u64,
    pub close_time_unix_ms: u64,
    pub status: BatchStatus,
    pub order_commitment_root: String,
    pub encrypted_order_set_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSummary {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub epoch_id: u64,
    pub close_time_unix_ms: u64,
    pub status: BatchStatus,
    pub order_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchOrderSet {
    pub batch: BatchSummary,
    pub orders: Vec<SubmittedOrderRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedOrder {
    pub order_commitment: OrderCommitment,
    pub filled_amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedOrderWitness {
    pub order_commitment: OrderCommitment,
    pub funding_note: Note,
    pub funding_note_ref: NoteCommitment,
    pub funding_nullifier: Nullifier,
    pub side: OrderSide,
    pub limit_price: u128,
    pub order_amount: u128,
    pub min_fill: u128,
    pub expiry_epoch: u64,
    pub order_nonce: u64,
    pub auditor_view_allowed: bool,
    pub recipient_owner_public_key: String,
    pub recipient_withdraw_authority: String,
    pub filled_amount: u128,
    pub output_note: Note,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumedInput {
    pub note_commitment: NoteCommitment,
    pub nullifier: Nullifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEntry {
    pub asset_id: AssetId,
    pub amount: u128,
    pub recipient: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputNoteRecord {
    pub note_commitment: NoteCommitment,
    pub asset_id: AssetId,
    pub amount: u128,
    pub withdraw_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputCiphertextBundle {
    pub batch_id: BatchId,
    pub bundle_commitment: String,
    pub data_availability_ref: String,
    pub ciphertexts: Vec<EncryptedBlob>,
}

impl OutputCiphertextBundle {
    pub fn from_ciphertexts(
        batch_id: BatchId,
        data_availability_ref: impl Into<String>,
        ciphertexts: Vec<EncryptedBlob>,
    ) -> Result<Self, ProtocolError> {
        let bundle_commitment = tagged_commitment_sha256("zylith/output-bundle", &ciphertexts)?;
        Ok(Self {
            batch_id,
            bundle_commitment,
            data_availability_ref: data_availability_ref.into(),
            ciphertexts,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementTranscript {
    pub batch_id: BatchId,
    pub clearing_price: u128,
    pub matched_orders: Vec<MatchedOrder>,
    pub consumed_inputs: Vec<ConsumedInput>,
    pub fees: Vec<FeeEntry>,
    pub output_notes: Vec<OutputNoteRecord>,
    pub output_ciphertext_bundle_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifacts {
    pub transcript: SettlementTranscript,
    pub output_bundle: OutputCiphertextBundle,
    pub settlement_witness: SettlementWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifactSummary {
    pub batch_id: BatchId,
    pub transcript_commitment: String,
    pub output_bundle_ref: String,
    pub bundle_commitment: String,
    pub data_availability_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBatchArtifactList {
    pub batches: Vec<PublishedBatchArtifactSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorStatus {
    pub service: String,
    pub current_batch_id: Option<BatchId>,
    pub tracked_batches: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPeerStatus {
    pub member_id: String,
    pub url: String,
    pub state: String,
    pub last_checked_at_unix_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcServiceStatus {
    pub service: String,
    pub coordinator_url: String,
    pub staged_batches: u64,
    pub committee_member_count: u64,
    pub local_member_ids: Vec<String>,
    pub configured_peer_count: u64,
    pub reachable_peer_count: u64,
    pub quorum_threshold: u64,
    pub quorum_mode: String,
    pub peer_request_timeout_ms: u64,
    pub peer_request_max_attempts: u64,
    pub peer_retry_backoff_ms: u64,
    pub prepare_max_attempts: u64,
    pub prepare_retry_backoff_ms: u64,
    pub peer_statuses: Vec<MpcPeerStatus>,
    pub last_prepare_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcStagedBatchStatus {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub order_count: u64,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedBatchStatus {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub order_count: u64,
    pub state: String,
    pub candidate_clearing_price: Option<u128>,
    pub matched_volume: u128,
    pub transcript_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobStatus {
    pub batch_id: BatchId,
    pub state: String,
    pub transcript_commitment: String,
    pub matched_order_count: u64,
    pub settlement_plan_available: bool,
    pub witness_available: bool,
    pub proof_artifact_available: bool,
    pub onchain_submission_available: bool,
    pub proof_artifact_id: Option<String>,
    pub onchain_submission_id: Option<String>,
    pub prover_backend: String,
    pub last_error: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub settlement_contract_address: String,
    pub settlement_entrypoint: String,
    pub settlement_calldata_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifactRecord {
    pub artifact_id: String,
    pub batch_id: BatchId,
    pub proof_system: String,
    pub proof_format: String,
    pub prover_backend: String,
    pub created_at_unix_ms: u64,
    pub proof_artifact_commitment: String,
    pub proof_path: String,
    pub public_inputs_path: String,
    pub prover_stdout_path: String,
    pub prover_stderr_path: String,
    pub proof_sha256: String,
    pub public_inputs_sha256: String,
    pub native_proof_file_path: Option<String>,
    pub native_proof_facts_file_path: Option<String>,
    pub native_execution_request_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnchainSubmissionRecord {
    pub submission_id: String,
    pub batch_id: BatchId,
    pub transaction_hash: String,
    pub submitted_at_unix_ms: u64,
    pub receipt_checked_at_unix_ms: Option<u64>,
    pub confirmed_at_unix_ms: Option<u64>,
    pub finality_status: Option<String>,
    pub execution_status: Option<String>,
    pub revert_reason: Option<String>,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub submission_mode: String,
    pub settlement_contract_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarknetCall {
    pub contract_address: String,
    pub entrypoint: String,
    pub calldata: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalCallArguments {
    pub spender: String,
    pub amount: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCallArguments {
    pub asset_id: String,
    pub amount: String,
    pub deposit_nonce: String,
    pub note_commitment: String,
    pub withdraw_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositSubmissionPlan {
    pub note: Note,
    pub note_commitment: NoteCommitment,
    pub approval_call: StarknetCall,
    pub starknet_call: StarknetCall,
    pub starknet_calls: Vec<StarknetCall>,
    pub approval_args: ApprovalCallArguments,
    pub encoded_args: DepositCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositRecord {
    pub deposit_id: u64,
    pub asset_id: AssetId,
    pub amount: u128,
    pub deposit_nonce: u64,
    pub note_commitment: NoteCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalCallArguments {
    pub note_commitment: String,
    pub recipient: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalSubmissionPlan {
    pub note_commitment: NoteCommitment,
    pub starknet_call: StarknetCall,
    pub encoded_args: WithdrawalCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRecord {
    pub withdrawal_id: u64,
    pub asset_id: AssetId,
    pub amount: u128,
    pub recipient: String,
    pub note_commitment: NoteCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositSyncStatus {
    pub service: String,
    pub rpc_url: String,
    pub shielded_asset_adapter_address: String,
    pub cached_deposits: u64,
    pub synced_deposit_count: u64,
    pub cached_withdrawals: u64,
    pub synced_withdrawal_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositConfirmationRequest {
    pub note_commitments: Vec<NoteCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositConfirmationList {
    pub confirmed: Vec<DepositRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementCallArguments {
    pub batch_id: String,
    pub transcript_commitment: String,
    pub proof_artifact_commitment: String,
    pub clearing_price: String,
    pub matched_order_count: String,
    pub output_bundle_ref: String,
    pub consumed_note_commitments: Vec<String>,
    pub consumed_nullifiers: Vec<String>,
    pub output_note_commitments: Vec<String>,
    pub output_note_asset_ids: Vec<String>,
    pub output_note_amounts: Vec<String>,
    pub output_note_withdraw_authorities: Vec<String>,
    pub fee_asset_ids: Vec<String>,
    pub fee_recipients: Vec<String>,
    pub fee_amounts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementSubmissionPlan {
    pub batch_id: BatchId,
    pub transcript_commitment: String,
    pub proof_artifact_commitment: String,
    pub settlement_call: StarknetCall,
    pub encoded_args: SettlementCallArguments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementWitness {
    pub batch_id: BatchId,
    pub pair_id: PairId,
    pub transcript_commitment: String,
    pub settlement_verifier_address: String,
    pub clearing_price: u128,
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub matched_orders: Vec<MatchedOrder>,
    pub matched_order_witnesses: Vec<MatchedOrderWitness>,
    pub consumed_inputs: Vec<ConsumedInput>,
    pub fees: Vec<FeeEntry>,
    pub output_notes: Vec<OutputNoteRecord>,
    pub output_ciphertext_bundle_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub snapshot_id: String,
    pub latest_batch_id: Option<BatchId>,
    pub notes: Vec<Note>,
    pub spent_nullifiers: Vec<Nullifier>,
    pub tracked_orders: Vec<OrderCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletEventKind {
    NoteReceived { commitment: NoteCommitment },
    NoteSpent { nullifier: Nullifier },
    OrderSubmitted { commitment: OrderCommitment },
    OrderCancelled { commitment: OrderCommitment },
    BatchSettled { batch_id: BatchId },
    SnapshotCreated { snapshot_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletEvent {
    pub event_id: String,
    pub timestamp_unix_ms: u64,
    pub kind: WalletEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryArtifactKind {
    Snapshot,
    WalletEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRecoveryPayload {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArtifact {
    pub artifact_id: String,
    pub account_id: String,
    pub kind: RecoveryArtifactKind,
    pub sequence: u64,
    pub created_at_unix_ms: u64,
    pub payload: EncryptedRecoveryPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArtifactUpload {
    pub artifact: RecoveryArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArtifactList {
    pub account_id: String,
    pub artifacts: Vec<RecoveryArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentContracts {
    pub commitment_registry: String,
    pub batch_registry: String,
    pub fee_ledger: String,
    pub shielded_asset_adapter: String,
    pub deposit_router: String,
    pub settlement_verifier: String,
    pub proof_friendly_account: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentManifest {
    pub network: String,
    pub rpc_url: String,
    pub chain_id: String,
    pub contracts: DeploymentContracts,
    pub token_addresses: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::{
        AssetId, BatchId, BatchStatus, BatchSummary, DepositIntent, Note, Nullifier, OrderIntent,
        OrderShareBundle, OrderSide, OrderSubmission, PairId,
    };
    use crate::EncryptedBlob;
    use crate::{RecoverySeed, derive_user_keys};

    #[test]
    fn note_commitments_are_deterministic() {
        let note = Note {
            asset_id: AssetId("STRK".into()),
            amount: 10,
            owner_public_key: "owner".into(),
            withdraw_authority: "0x111".into(),
            blinding: "0x111".into(),
            nonce: 1,
            metadata_commitment: "0x222".into(),
        };

        let a = note.commitment().expect("note commitment");
        let b = note.commitment().expect("note commitment");
        assert_eq!(a, b);
    }

    #[test]
    fn nullifier_derivation_uses_spend_key() {
        let note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 25,
            owner_public_key: "owner".into(),
            withdraw_authority: "0x222".into(),
            blinding: "0x333".into(),
            nonce: 2,
            metadata_commitment: "0x444".into(),
        };
        let seed = RecoverySeed([3_u8; 32]);
        let keys = derive_user_keys(&seed);

        let nullifier = note.nullifier(&keys).expect("nullifier");
        let commitment = note.commitment().expect("commitment");

        assert_ne!(nullifier.0, commitment.0);
    }

    #[test]
    fn order_commitments_are_deterministic() {
        let funding_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 200_000,
            owner_public_key: "ab".repeat(32),
            withdraw_authority: "0x333".into(),
            blinding: "0x111".into(),
            nonce: 7,
            metadata_commitment: "0x222".into(),
        };
        let order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            side: OrderSide::Buy,
            limit_price: 145,
            amount: 1_000,
            min_fill: 100,
            expiry_epoch: 42,
            order_nonce: 9,
            funding_note_ref: funding_note.commitment().expect("funding note commitment"),
            funding_nullifier: Nullifier("0x333".into()),
            recipient_owner_public_key: "ab".repeat(32),
            recipient_withdraw_authority: "0x444".into(),
            auditor_view_allowed: false,
        };

        let a = order.commitment().expect("order commitment");
        let b = order.commitment().expect("order commitment");
        assert_eq!(a, b);
    }

    #[test]
    fn deposit_intents_serialize_predictably() {
        let deposit = DepositIntent {
            asset_id: AssetId("USDC".into()),
            amount: 1_000,
            deposit_nonce: 7,
            recipient_owner_public_key: "owner-key".into(),
            recipient_withdraw_authority: "0x555".into(),
        };

        let json = serde_json::to_value(deposit).expect("serialize deposit");
        assert_eq!(json["asset_id"], "USDC");
        assert_eq!(json["deposit_nonce"], 7);
    }

    #[test]
    fn newtypes_serialize_as_plain_strings() {
        let summary = BatchSummary {
            batch_id: BatchId("batch-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            epoch_id: 1,
            close_time_unix_ms: 1234,
            status: BatchStatus::Open,
            order_count: 0,
        };

        let json = serde_json::to_value(summary).expect("serialize batch summary");
        assert_eq!(json["batch_id"], "batch-1");
        assert_eq!(json["pair_id"], "STRK/USDC");
    }

    #[test]
    fn order_submission_shape_is_client_friendly() {
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: crate::OrderCommitment("commitment-1".into()),
                cancellation_auth_tag: "cancel-tag-1".into(),
                pair_id: PairId("STRK/USDC".into()),
                epoch_id: 0,
                transport_envelope: Some(EncryptedBlob {
                    algorithm: "ecdh-p256+aes-256-gcm".into(),
                    key_id: "member-0".into(),
                    ephemeral_public_key: "04abcdef".into(),
                    nonce: "00".into(),
                    ciphertext: "11".into(),
                }),
                shares: vec![],
            },
        };

        let json = serde_json::to_value(submission).expect("serialize order submission");
        assert_eq!(json["order_bundle"]["order_commitment"], "commitment-1");
        assert_eq!(
            json["order_bundle"]["cancellation_auth_tag"],
            "cancel-tag-1"
        );
        assert_eq!(json["order_bundle"]["pair_id"], "STRK/USDC");
    }
}

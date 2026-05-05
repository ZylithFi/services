pub mod auth;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod keys;
pub mod types;

pub use auth::{
    CONTROL_PLANE_TOKEN_ENV, RECOVERY_AUTH_HEADER, constant_time_eq, derive_recovery_auth_tag,
    extract_bearer_token, format_bearer_token,
};
pub use crypto::{
    build_auction_serialized_input, build_deposit_note, build_deposit_submission_plan,
    build_order_submission, build_output_note, build_settlement_submission_plan,
    build_settlement_witness, build_stwo_serialized_input, build_withdrawal_submission_plan,
    create_order_ingress_receipt, create_recovery_artifact, decrypt_note_for_owner,
    decrypt_order_bundle, decrypt_order_share, decrypt_recovery_artifact_payload,
    derive_account_id, derive_order_cancellation_auth_tag, derive_order_cancellation_secret,
    derive_order_cancellation_tag, encrypt_note_for_owner, native_settlement_message_hash,
    private_execution_key_registry_fingerprint, private_order_payload_commitment,
    proof_artifact_commitment, reconstruct_order_from_shares,
    renewal_child_uses_from_matched_witnesses, sanitize_order_submission_for_coordinator,
    settlement_proof_message_hash, settlement_proof_message_hash_from_statement,
    settlement_transcript_commitment, sign_order_authorization,
    validate_order_ingress_receipt_for_manifest,
    validate_order_ingress_receipt_for_manifest_with_secrets,
    validate_private_execution_key_registry_pin, verify_order_ingress_receipt,
    verify_order_ingress_receipt_with_secrets,
};
pub use error::ProtocolError;
pub use keys::{RecoverySeed, UserKeys, derive_user_keys};
pub use types::{
    ApprovalCallArguments, AssetId, AuctionOrderWitness, Batch, BatchId, BatchLiquidityReport,
    BatchOrderSet, BatchShareContributions, BatchStatus, BatchSummary, ConsumedInput,
    CoordinatorStatus, DecryptedOrderShare, DeploymentContracts, DeploymentManifest,
    DepositCallArguments, DepositConfirmationList, DepositConfirmationRequest, DepositIntent,
    DepositRecord, DepositSubmissionPlan, DepositSyncStatus, EncryptedBlob,
    EncryptedRecoveryPayload, FeeEntry, FundingRailAssetConfig, FundingRailCapabilities,
    FundingRailConfig, FundingRailKind, HiddenMakerCurve, MakerCurvePoint, MatchedOrder,
    MatchedOrderWitness, Note, NoteCommitment, Nullifier, OnchainSubmissionRecord,
    OrderCancellationAccepted, OrderCancellationRequest, OrderCommitment, OrderExecutionReport,
    OrderIngressReceipt, OrderIntent, OrderShare, OrderShareBundle, OrderSide, OrderSubmission,
    OrderSubmissionAccepted, OrderType, OutputCiphertextBundle, OutputNoteRecord, PairId,
    PreparedBatchStatus, PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig,
    PrivateExecutionKeyRegistry, PrivateOrderPayload, ProductAssetConfig, ProductConfig,
    ProductPairConfig, ProofArtifactRecord, ProofJobStatus, PublishedBatchArtifactList,
    PublishedBatchArtifactSummary, PublishedBatchArtifacts, RecoveryArtifact, RecoveryArtifactKind,
    RecoveryArtifactList, RecoveryArtifactUpload, RenewalChildUse, SettlementCallArguments,
    SettlementSubmissionPlan, SettlementTranscript, SettlementWitness, SpendAuthorization,
    StarknetCall, StarknetPrivacyFundingRail,
    SubmittedOrderRecord, TimeInForce, TrustedOrderIngressRequest, TrustedOrderIngressResponse,
    WalletEvent, WalletEventKind, WalletSnapshot, WithdrawalCallArguments, WithdrawalRecord,
    WithdrawalSubmissionPlan, nullifier_from_spend_auth_key_felt, renewal_child_nullifier,
    renewal_parent_commitment, renewal_parent_secret_commitment,
    spend_auth_key_felt_from_raw_key_hex, spend_authority_from_raw_key_hex,
    spend_authority_from_spend_auth_key_felt, withdraw_auth_key_felt_from_raw_key_hex,
    withdraw_authority_from_raw_key_hex, withdraw_authority_from_withdraw_auth_key_felt,
};

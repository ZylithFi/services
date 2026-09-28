pub mod auth;
mod crypto;
pub mod error;
pub(crate) mod exact_clearing;
pub mod exchange;
pub mod hash;
pub mod keys;
pub mod reference_price;
mod types;

pub use auth::{
    CONTROL_PLANE_TOKEN_ENV, RECOVERY_AUTH_HEADER, constant_time_eq, derive_recovery_auth_tag,
    extract_bearer_token, forwarded_client_ip,
};
pub use crypto::{
    ReferencePriceBatchEntry, Strk20ExitClaimMessage, build_deposit_submission_plan,
    create_recovery_artifact, decrypt_recovery_artifact_payload, derive_account_id,
    note_recognition_public_key_from_raw_key_hex, reference_price_batch_commitment,
    reference_price_source_set_commitment, sign_reference_price_attestation,
    sign_reference_price_attestation_in_batch, sign_strk20_exit_claim_authorization,
    strk20_exit_claim_message_hash,
};
pub use error::ProtocolError;
pub use keys::{RecoverySeed, UserKeys, derive_user_keys};
pub use reference_price::{
    ReferencePriceAttestation, ReferencePriceEnvelope, ReferencePricePolicy, ReferencePriceSample,
    build_reference_price_envelope, reference_price_policy_for_pair,
};
pub use types::{
    AssetId, DeploymentContracts, DeploymentManifest, DeploymentMetadata, DeploymentProofConfig,
    DeploymentRoles, DeploymentRuntime, DepositActivationRecord, DepositActivationRecordList,
    DepositCallArguments, DepositConfirmationList, DepositIntent, DepositSubmissionPlan,
    EncryptedBlob, EncryptedRecoveryPayload, FundingRailAssetConfig, FundingRailConfig,
    FundingRailKind, Note, NoteCommitment, PairId, PrivateExecutionKeyPrivateConfig,
    PrivateExecutionKeyPublicConfig, PrivateExecutionKeyRegistry, ProductAssetConfig,
    ProductConfig, ProductPairConfig, RecoveryArtifact, RecoveryArtifactKind, RecoveryArtifactList,
    RecoveryArtifactUpload, SpendAuthorization, StarknetPrivacyFundingRail, count_bucket_label,
    spend_authority_from_raw_key_hex, validate_private_execution_keys,
    withdraw_authority_from_raw_key_hex,
};

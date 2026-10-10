//! zylith protocol primitives expose wallet operations without exposing derived child keys.
//!
//! Low-level compatibility adapters are intentionally not part of the public API:
//!
//! ```compile_fail
//! use zylith_core::{UserKeys, derive_user_keys};
//! ```
//!
//! ```compile_fail
//! use zylith_core::{
//!     derive_recovery_auth_tag,
//!     spend_authority_from_raw_key_hex,
//!     withdraw_authority_from_raw_key_hex,
//! };
//! ```
//!
//! ```compile_fail
//! use zylith_core::wallet_crypto::WalletKeyBytes;
//! ```
//!
//! ```compile_fail
//! use zylith_core::RecoverySeed;
//! let seed = RecoverySeed([0; 32]);
//! ```

pub mod auth;
mod crypto;
pub mod error;
pub(crate) mod exact_clearing;
pub mod exchange;
pub mod hash;
pub mod keys;
pub mod market_registry;
pub mod private_envelope;
pub mod reference_price;
mod types;
pub mod wallet_crypto;
mod wallet_state;

pub use auth::{
    CONTROL_PLANE_TOKEN_ENV, RECOVERY_AUTH_HEADER, constant_time_eq,
    derive_wallet_recovery_auth_tag, extract_bearer_token, forwarded_client_ip,
};
pub use crypto::{
    ReferencePriceBatchEntry, Strk20ExitClaimMessage, build_wallet_deposit_submission_plan,
    create_recovery_artifact, decrypt_recovery_artifact_payload,
    decrypt_recovery_artifact_payload_classified, derive_account_id,
    deserialize_unique_wallet_json, reference_price_batch_commitment,
    reference_price_source_set_commitment, sign_reference_price_attestation,
    sign_reference_price_attestation_in_batch, sign_strk20_exit_claim_authorization,
    strk20_exit_claim_message_hash,
};
pub use error::{ProtocolError, WalletDataError};
pub use keys::RecoverySeed;
pub use market_registry::{
    MARKET_REGISTRY_SCHEMA_VERSION, MarketCapabilities, MarketReferencePrice, MarketRegistry,
    MarketRegistryAsset, MarketRegistryMarket, OhttpPolicy, ReferenceIdentity,
    ReferencePriceMethodology, ReferenceRelationship, VenueAdapter, VenueObservation,
};
pub use reference_price::{
    ReferencePriceAttestation, ReferencePriceDerivation, ReferencePriceEnvelope,
    ReferencePricePolicy, ReferencePriceSample, build_reference_price_envelope,
    build_synthetic_cross_envelope, derive_synthetic_cross_bbo,
};
pub use types::{
    AssetId, DeploymentContracts, DeploymentManifest, DeploymentMetadata, DeploymentProofConfig,
    DeploymentRoles, DeploymentRuntime, DepositActivationRecord, DepositActivationRecordList,
    DepositCallArguments, DepositConfirmationList, DepositDerivationContext, DepositIntent,
    DepositSubmissionPlan, EncryptedRecoveryPayload, FundingRailConfig, FundingRailKind, Note,
    NoteCommitment, PairId, PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig,
    PrivateExecutionKeyRegistry, RecoveryArtifact, RecoveryArtifactKind, RecoveryArtifactList,
    RecoveryArtifactUpload, SpendAuthorization, StarknetPrivacyFundingRail, count_bucket_label,
    validate_execution_key_id, validate_private_execution_keys,
};
pub use wallet_crypto::{WALLET_KEY_SCHEDULE_ID, WALLET_KEY_SCHEDULE_VERSION, WalletKeyScheduleV2};
pub use wallet_state::{
    MAX_WALLET_STATE_CIPHERTEXT_BYTES, MAX_WALLET_STATE_REQUEST_BYTES, WalletStateRecord,
    decrypt_wallet_state, decrypt_wallet_state_classified, encrypt_wallet_state,
};

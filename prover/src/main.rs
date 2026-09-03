#![recursion_limit = "256"]

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    env, fs,
    io::{Cursor, Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header::AUTHORIZATION, request::Parts},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use ipnet::IpNet;
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use starknet_rust_accounts::{Account, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount};
use starknet_rust_core::{
    types::{
        BlockId, BlockTag, BroadcastedTransaction, Call, ExecutionResult, FeeEstimate, Felt,
        FunctionCall, MaybePreConfirmedBlockWithTxHashes, SimulationFlagForEstimateFee,
        TransactionFinalityStatus, TransactionReceiptWithBlockInfo,
    },
    utils::get_selector_from_name,
};
use starknet_rust_providers::{
    Provider,
    jsonrpc::{HttpTransport, JsonRpcClient},
};
use starknet_rust_signers::{LocalWallet, SigningKey};
use tokio::{
    sync::{RwLock, Semaphore},
    task,
    time::{Duration, sleep},
};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use url::Url;
use zeroize::Zeroize;
use zylith_core::hash::{
    encode_starknet_felt, normalize_felt_hex, ordered_felt_list_commitment, tagged_field_hex,
};
use zylith_core::{
    AssetId, AuctionOrderWitness, BatchId, BatchOrderSet, BatchStatus, BatchSummary,
    CONTROL_PLANE_TOKEN_ENV, ConsumedInput, DeploymentManifest, DepositActivationRecord,
    DepositActivationRecordList, FeeEntry, FeeOutputNoteInput, LiquidityAttributionBundle,
    LiquidityAttributionPlaintext, LiquidityBandAttribution, LiquidityBandFillAttribution,
    LiquidityCurve, LiquidityCurvePoint, LiquidityPositionCommitment,
    LiquidityPositionLifecycleSubmission, LiquidityPositionMarketContext,
    LiquidityPositionProofWitness, LiquidityPositionSettlementFill, LiquidityPositionState,
    LiquidityPositionStateUpdate, LiquidityPositionTransitionKind,
    LiquidityPositionTransitionWitness, MatchedOrder, MatchedOrderWitness, Note, NoteCommitment,
    NoteConsolidationWitness, NoteMembershipKind, NoteMembershipWitness, OnchainSubmissionRecord,
    OrderCommitment, OrderExecutionReport, OrderIngressClientTelemetry, OrderIngressReceipt,
    OrderIngressReceiptAttestation, OrderIntent, OrderShareBundle, OrderSide, OrderSubmission,
    OutputCiphertextBundle, OutputNoteRecord, OutputRecoveryRecord, PairId, PreparedBatchStatus,
    PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig, PrivateExecutionKeyRegistry,
    PrivateLiquidityPosition, ProductConfig, ProductPairConfig, ProofArtifactRecord,
    ProofJobStatus, PublishedBatchArtifacts, RelayMode, RenewalCancelMarkerList,
    SettlementOutputWithdrawalWitness, SettlementRootHistoryArchive, SettlementSubmissionPlan,
    SettlementTranscript, SettlementWitness, SpendAuthorization, StarknetCall, TimeInForce,
    TrustedLiquidityPositionIngressRequest, TrustedLiquidityPositionIngressResponse,
    TrustedOrderIngressRequest, TrustedOrderIngressResponse,
    admission_proof_message_hash_for_program, apply_liquidity_position_fill,
    auction_admission_root, auction_result_proof_message_hash_for_program,
    base_amount_affordable_for_quote, build_admission_serialized_input,
    build_auction_result_serialized_input, build_fee_output_note, build_heartbeat_cover_orders,
    build_liquidity_position_serialized_input, build_note_consolidation_serialized_input,
    build_note_consolidation_submission_plan, build_output_note,
    build_settlement_output_withdrawal_serialized_input,
    build_settlement_output_withdrawal_submission_plan_from_witness,
    build_settlement_submission_plan, create_liquidity_attribution_artifact,
    create_liquidity_position_ingress_receipt, create_order_ingress_receipt, decrypt_order_bundle,
    deposit_note_membership_witnesses_for_chain, deposit_root_from_note,
    derive_liquidity_position_curve_slice, derive_order_execution_report_auth_tag,
    encrypt_output_note_for_owner, extract_bearer_token, format_bearer_token,
    funding_input_set_commitment, funding_nullifier_set_commitment,
    liquidity_position_lifecycle_id, liquidity_position_proof_message_hash_for_program,
    liquidity_position_root_transition, liquidity_position_transition_commitment,
    liquidity_position_transition_witness_payload_commitment,
    native_note_consolidation_message_hash, native_settlement_message_hash,
    native_settlement_output_withdrawal_message_hash, note_consolidation_commitment,
    note_consolidation_proof_message_hash_for_program,
    note_recognition_public_key_from_raw_key_hex, nullifier_from_note_secret,
    nullifier_proof_message_hash_for_program,
    nullifier_sparse_update_witnesses_for_consumed_inputs, output_note_merkle_proof,
    private_execution_key_registry_fingerprint, private_order_payload_commitment,
    quote_amount_for_base_amount, renewal_proof_message_hash_for_program,
    renewal_sparse_witnesses_for_child_uses, root_only_settlement_commitments,
    sanitize_order_submission_for_coordinator,
    settlement_input_membership_proof_message_hash_for_program,
    settlement_note_root_after_deposit_roots, settlement_order_proof_message_hash_for_program,
    settlement_output_recovery_proof_message_hash_for_program,
    settlement_output_withdrawal_commitment,
    settlement_output_withdrawal_proof_message_hash_for_program,
    settlement_proof_message_hash_for_program, settlement_state_transition_root,
    settlement_transcript_commitment,
    validate_liquidity_position_ingress_receipt_for_manifest_with_secrets,
    validate_order_ingress_receipt_for_manifest_with_secrets,
    verify_liquidity_position_transition_witness, verify_output_note_membership,
    withdraw_authority_from_raw_key_hex,
};

#[derive(Clone, Copy)]
struct PeerAddress(Option<SocketAddr>);

impl<S> FromRequestParts<S> for PeerAddress
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let address = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connect_info| connect_info.0);
        async move { Ok(Self(address)) }
    }
}

const DEFAULT_COORDINATOR_URL: &str = "http://127.0.0.1:3000";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:3300";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3200";
const DEFAULT_DEPLOYMENT_MANIFEST_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../client/public/deployment.json"
);
const DEFAULT_PROVER_DATA_DIR: &str = "prover/data.dev";
const DEFAULT_NATIVE_L1_GAS_FLOOR: u64 = 1_000;
const DEFAULT_NATIVE_L1_DATA_GAS_FLOOR: u64 = 8_000;
const DEFAULT_NATIVE_L2_GAS_FLOOR: u64 = 120_000_000;
const DEFAULT_NATIVE_PROOF_ONLY_L2_GAS_FLOOR: u64 = 10_000_000_000;
const DEFAULT_STWO_MANIFEST_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../stwo_statement/Scarb.toml");
const DEFAULT_STWO_PACKAGE_NAME: &str = "zylith_settlement_statement";
const DEFAULT_SCARB_BIN: &str = "scarb";
const DEFAULT_RECEIPT_POLL_ATTEMPTS: usize = 20;
const DEFAULT_RECEIPT_POLL_INTERVAL_MS: u64 = 1_500;
const DEFAULT_NATIVE_PROVER_ATTEMPTS: usize = 8;
const DEFAULT_NATIVE_PROVER_RETRY_INTERVAL_MS: u64 = 5_000;
const DEFAULT_NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS: u64 = 3_600;
const DEFAULT_NATIVE_PROVER_BLOCKS_BACK: u64 = 20;
const DEFAULT_NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS: usize = 16;
const DEFAULT_NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS: u64 = 5_000;
const DEFAULT_AUCTION_PROVER_KEYS_PATH: &str = "prover/auction_keys.dev.json";
const NATIVE_GAS_PRICE_MULTIPLIER_NUMERATOR: u128 = 2;
const NATIVE_GAS_PRICE_MULTIPLIER_DENOMINATOR: u128 = 1;
const NATIVE_GAS_AMOUNT_MULTIPLIER_NUMERATOR: u64 = 3;
const NATIVE_GAS_AMOUNT_MULTIPLIER_DENOMINATOR: u64 = 2;
const NATIVE_L1_GAS_MAX_AMOUNT_ENV: &str = "ZYLITH_NATIVE_L1_GAS_MAX_AMOUNT";
const NATIVE_L1_DATA_GAS_MAX_AMOUNT_ENV: &str = "ZYLITH_NATIVE_L1_DATA_GAS_MAX_AMOUNT";
const NATIVE_L2_GAS_MAX_AMOUNT_ENV: &str = "ZYLITH_NATIVE_L2_GAS_MAX_AMOUNT";
const NATIVE_PROVER_ATTEMPTS_ENV: &str = "ZYLITH_NATIVE_PROVER_ATTEMPTS";
const NATIVE_PROVER_RETRY_INTERVAL_MS_ENV: &str = "ZYLITH_NATIVE_PROVER_RETRY_INTERVAL_MS";
const NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS_ENV: &str =
    "ZYLITH_NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS";
const NATIVE_PROVER_BLOCKS_BACK_ENV: &str = "ZYLITH_NATIVE_PROVER_BLOCKS_BACK";
const NATIVE_PROVER_BLOCK_TAG_ENV: &str = "ZYLITH_NATIVE_PROVER_BLOCK_TAG";
const NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS_ENV: &str =
    "ZYLITH_NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS";
const NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS_ENV: &str =
    "ZYLITH_NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS";
const NATIVE_PROOF_ACCOUNT_ADDRESS_ENV: &str = "ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS";
const NATIVE_PROOF_PRIVATE_KEY_ENV: &str = "ZYLITH_NATIVE_PROOF_PRIVATE_KEY";
const NATIVE_PROOF_PROGRAM_ADDRESS_ENV: &str = "ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS";
const NATIVE_PROOF_ENTRYPOINT_ENV: &str = "ZYLITH_NATIVE_PROOF_ENTRYPOINT";
const NATIVE_PROOF_AGGREGATE_ENTRYPOINT_ENV: &str = "ZYLITH_NATIVE_PROOF_AGGREGATE_ENTRYPOINT";
const AUCTION_PROVER_KEYS_PATH_ENV: &str = "ZYLITH_AUCTION_PROVER_KEYS_PATH";
const DEFAULT_PROTOCOL_FEE_RECIPIENT: &str = "zylith-protocol-treasury";
const DEFAULT_RELAY_FEE_RECIPIENT: &str = "zylith-renewal-relay";
const PROTOCOL_FEE_OWNER_KEY_ENV: &str = "ZYLITH_PROTOCOL_FEE_OWNER_KEY_HEX";
const PROTOCOL_FEE_WITHDRAW_KEY_ENV: &str = "ZYLITH_PROTOCOL_FEE_WITHDRAW_KEY_HEX";
const RELAY_FEE_OWNER_KEY_ENV: &str = "ZYLITH_RELAY_FEE_OWNER_KEY_HEX";
const RELAY_FEE_WITHDRAW_KEY_ENV: &str = "ZYLITH_RELAY_FEE_WITHDRAW_KEY_HEX";
const DEV_PROTOCOL_FEE_OWNER_KEY: &str =
    "7171717171717171717171717171717171717171717171717171717171717171";
const DEV_PROTOCOL_FEE_WITHDRAW_KEY: &str =
    "7373737373737373737373737373737373737373737373737373737373737373";
const DEV_RELAY_FEE_OWNER_KEY: &str =
    "8181818181818181818181818181818181818181818181818181818181818181";
const DEV_RELAY_FEE_WITHDRAW_KEY: &str =
    "8383838383838383838383838383838383838383838383838383838383838383";
const PROOF_JOBS_DIR: &str = "proof_jobs";
const MAX_PUBLIC_PROOF_JOB_BATCH_IDS: usize = 128;
const SETTLEMENT_PLANS_DIR: &str = "settlement_plans";
const SETTLEMENT_WITNESSES_DIR: &str = "settlement_witnesses";
const PREPARED_BATCH_ARTIFACTS_DIR: &str = "prepared_batch_artifacts";
const PROOF_ARTIFACTS_DIR: &str = "proof_artifacts";
const ONCHAIN_SUBMISSIONS_DIR: &str = "onchain_submissions";
const NOTE_CONSOLIDATION_HISTORY_DIR: &str = "note_consolidation_history";
const SETTLEMENT_OUTPUT_WITHDRAWAL_NULLIFIERS_DIR: &str = "settlement_output_withdrawal_nullifiers";
const PROOF_OUTPUTS_DIR: &str = "proof_outputs";
const PUBLIC_INPUTS_DIR: &str = "public_inputs";
const PROVER_LOGS_DIR: &str = "prover_logs";
const PRIVATE_ORDER_PAYLOADS_DIR: &str = "private_order_payloads";
const PRIVATE_LIQUIDITY_POSITION_PAYLOADS_DIR: &str = "private_liquidity_position_payloads";
static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);
const NOTE_ROOT_TRANSITION_DEPOSIT_KIND: u64 = 0;
const NOTE_ROOT_TRANSITION_SETTLEMENT_KIND: u64 = 1;
const NOTE_ROOT_TRANSITION_CONSOLIDATION_KIND: u64 = 2;
const ORDER_INGRESS_RECEIPT_SECRET_ENV: &str = "ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET";
const ORDER_INGRESS_RECEIPT_PREVIOUS_SECRETS_ENV: &str =
    "ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS";
const HOSTED_LIQUIDITY_RELAY_URL_ENV: &str = "ZYLITH_HOSTED_LIQUIDITY_RELAY_URL";
const HOSTED_LIQUIDITY_RELAY_TOKEN_ENV: &str = "ZYLITH_HOSTED_LIQUIDITY_RELAY_TOKEN";
const ORDER_INGRESS_ID_ENV: &str = "ZYLITH_TRUSTED_PROVER_INGRESS_ID";
const HEARTBEAT_COVER_SECRET_ENV: &str = "ZYLITH_HEARTBEAT_COVER_SECRET";
const HEARTBEAT_COVER_PRICES_ENV: &str = "ZYLITH_HEARTBEAT_COVER_PRICES";
const LIQUIDITY_POSITION_MARKET_CONTEXTS_ENV: &str = "ZYLITH_LIQUIDITY_POSITION_MARKET_CONTEXTS";
const LIQUIDITY_POSITION_MARKET_CONTEXTS_PATH_ENV: &str =
    "ZYLITH_LIQUIDITY_POSITION_MARKET_CONTEXTS_PATH";
const PROVER_MAX_BODY_BYTES_ENV: &str = "ZYLITH_PROVER_MAX_BODY_BYTES";
const PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE_ENV: &str =
    "ZYLITH_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE";
const PROVER_PUBLIC_RATE_LIMIT_PER_MINUTE_ENV: &str = "ZYLITH_PROVER_PUBLIC_RATE_LIMIT_PER_MINUTE";
const PROVER_MAX_STORED_PRIVATE_PAYLOADS_ENV: &str = "ZYLITH_PROVER_MAX_STORED_PRIVATE_PAYLOADS";
const PROVER_PRIVATE_PAYLOAD_RETENTION_MS_ENV: &str = "ZYLITH_PRIVATE_PAYLOAD_RETENTION_MS";
const PROVER_MAX_ROOT_TRANSITIONS_ENV: &str = "ZYLITH_PROVER_MAX_ROOT_TRANSITIONS";
const NOTE_ROOT_HISTORY_VERIFIER_ADDRESS_ENV: &str = "ZYLITH_NOTE_ROOT_HISTORY_VERIFIER_ADDRESS";
const INITIAL_NOTE_ROOT_ENV: &str = "ZYLITH_INITIAL_NOTE_ROOT";
const PROVER_EMERGENCY_PAUSED_ENV: &str = "ZYLITH_PROVER_EMERGENCY_PAUSED";
const PROVER_ALLOWED_ORIGINS_ENV: &str = "ZYLITH_PROVER_ALLOWED_ORIGINS";
const PROVER_WORKER_ENABLED_ENV: &str = "ZYLITH_PROVER_WORKER_ENABLED";
const PROVER_WORKER_TICK_MS_ENV: &str = "ZYLITH_PROVER_WORKER_TICK_MS";
const PROVER_WORKER_MAX_BATCHES_PER_TICK_ENV: &str = "ZYLITH_PROVER_WORKER_MAX_BATCHES_PER_TICK";
const PROVER_WORKER_SUBMIT_ONCHAIN_ENV: &str = "ZYLITH_PROVER_WORKER_SUBMIT_ONCHAIN";
const MAX_PROVABLE_BATCH_ORDERS_ENV: &str = "ZYLITH_MAX_PROVABLE_BATCH_ORDERS";
const MAX_ORDER_AMOUNT_ENV: &str = "ZYLITH_MAX_ORDER_AMOUNT";
const MAX_LIQUIDITY_CURVE_BASE_AMOUNT_ENV: &str = "ZYLITH_MAX_LIQUIDITY_CURVE_BASE_AMOUNT";
const MAX_LIQUIDITY_CURVE_QUOTE_NOTIONAL_ENV: &str = "ZYLITH_MAX_LIQUIDITY_CURVE_QUOTE_NOTIONAL";
const SETTLEMENT_SUBMISSION_JITTER_MS_ENV: &str = "ZYLITH_SETTLEMENT_SUBMISSION_JITTER_MS";
const NATIVE_TX_PROVER_URL_ENV: &str = "ZYLITH_NATIVE_TX_PROVER_URL";
const NATIVE_TX_PROVER_OHTTP_ENABLED_ENV: &str = "ZYLITH_NATIVE_TX_PROVER_OHTTP_ENABLED";
const NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX_ENV: &str =
    "ZYLITH_NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX";
const DEFAULT_PROVER_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_DEPLOYMENT_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_PERSISTED_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_PROOF_FILE_BYTES: usize = 128 * 1024 * 1024;
const MAX_NATIVE_PROOF_FACTS_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_AUCTION_KEY_FILE_BYTES: usize = 1024 * 1024;
const MAX_LIQUIDITY_POSITION_MARKET_CONTEXTS_BYTES: usize = 512 * 1024;
const MAX_PERSISTED_RECORDS_PER_DIRECTORY: usize = 100_000;
const MAX_PERSISTED_RECORD_DIRECTORY_BYTES: usize = 256 * 1024 * 1024;
const MAX_CONTROL_PLANE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_NATIVE_PROVER_RESPONSE_BYTES: usize = 128 * 1024 * 1024;
const MAX_NATIVE_PROVER_ERROR_CHARS: usize = 2_000;
const PROOF_WORKER_BATCH_SCAN_LIMIT: usize = 4_096;
const MAX_OHTTP_KEY_CONFIG_BYTES: usize = 64 * 1024;
const DEFAULT_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE: u64 = 60;
const DEFAULT_PROVER_PUBLIC_RATE_LIMIT_PER_MINUTE: u64 = 120;
const DEFAULT_PROVER_MAX_STORED_PRIVATE_PAYLOADS: usize = 10_000;
const DEFAULT_PROVER_PRIVATE_PAYLOAD_RETENTION_MS: u64 = 2 * 60 * 60 * 1_000;
const DEFAULT_PROVER_MAX_ROOT_TRANSITIONS: usize = 100_000;
const DEFAULT_SETTLEMENT_SUBMISSION_JITTER_MS: u64 = 5_000;
const DEFAULT_MAX_PROVABLE_BATCH_ORDERS: u64 = 32;
const DEFAULT_PROVER_WORKER_TICK_MS: u64 = 10_000;
const DEFAULT_PROVER_WORKER_MAX_BATCHES_PER_TICK: usize = 2;
const DEFAULT_HTTP_CLIENT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_STARKNET_RPC_TIMEOUT_SECS: u64 = 60;
const PROOF_WORKER_FAILURE_BACKOFF_BASE_MS: u64 = 120_000;
const PROOF_WORKER_FAILURE_BACKOFF_MAX_MS: u64 = 30 * 60_000;
const PROOF_WORKER_STALE_PROVING_RETRY_MS: u64 = 10 * 60_000;
const PROOF_WORKER_STALE_SUBMITTING_RETRY_MS: u64 = 10 * 60_000;
const PROOF_WORKER_FAILED_RETRY_MS: u64 = 10 * 60_000;
const INDEXER_HISTORY_PAGE_SIZE: u64 = 10_000;
const INDEXER_DEPOSIT_CACHE_REVALIDATION_WINDOW: u64 = 64;
const NOTE_ROOT_TRANSITION_CACHE_REVALIDATION_WINDOW: usize = 64;

#[derive(Clone)]
struct AppState {
    coordinator_url: String,
    indexer_url: String,
    hosted_liquidity_relay_url: Option<String>,
    hosted_liquidity_relay_token: Option<Arc<String>>,
    auction_verifier_address: String,
    note_root_history_verifier_address: String,
    shielded_asset_adapter_address: String,
    native_proof_program_address: String,
    native_proof_entrypoint: String,
    native_proof_aggregate_entrypoint: String,
    native_tx_prover_url: String,
    native_tx_prover_ohttp: Option<NativeProverOhttpConfig>,
    scarb_bin: String,
    stwo_manifest_path: Arc<PathBuf>,
    stwo_package_name: String,
    data_dir: Arc<PathBuf>,
    http_client: Client,
    proof_jobs: Arc<RwLock<BTreeMap<String, ProofJobStatus>>>,
    proof_worker_failures: Arc<RwLock<BTreeMap<String, ProofWorkerBatchFailure>>>,
    active_proof_batches: Arc<Mutex<BTreeSet<String>>>,
    settlement_plans: Arc<RwLock<BTreeMap<String, SettlementSubmissionPlan>>>,
    settlement_witnesses: Arc<RwLock<BTreeMap<String, SettlementWitness>>>,
    prepared_batch_artifacts: Arc<RwLock<BTreeMap<String, PublishedBatchArtifacts>>>,
    note_consolidation_history: Arc<RwLock<BTreeMap<String, NoteConsolidationHistoryRecord>>>,
    settlement_output_withdrawal_nullifiers: Arc<RwLock<BTreeMap<String, ConsumedInput>>>,
    proof_artifacts: Arc<RwLock<BTreeMap<String, ProofArtifactRecord>>>,
    onchain_submissions: Arc<RwLock<BTreeMap<String, OnchainSubmissionRecord>>>,
    private_order_payloads: Arc<RwLock<BTreeMap<String, PrivateOrderPayloadRecord>>>,
    private_liquidity_position_payloads:
        Arc<RwLock<BTreeMap<String, PrivateLiquidityPositionPayloadRecord>>>,
    deposit_activation_cache: Arc<RwLock<Vec<DepositActivationRecord>>>,
    note_root_transition_cache: Arc<RwLock<Vec<NoteRootTransitionRecord>>>,
    private_ingress_metrics: IngressTelemetryMetrics,
    proof_lifecycle_metrics: LifecycleTelemetryMetrics,
    product_config: Arc<ProductConfig>,
    liquidity_position_market_contexts: Arc<LiquidityPositionMarketContexts>,
    liquidity_position_market_contexts_path: Option<Arc<PathBuf>>,
    auction_key_registry: Arc<PrivateExecutionKeyRegistry>,
    auction_private_keys: Arc<Vec<PrivateExecutionKeyPrivateConfig>>,
    starknet_executor: Option<Arc<StarknetExecutorConfig>>,
    batch_registrar: Option<Arc<BatchRegistrarConfig>>,
    internal_api_token: Option<Arc<String>>,
    initial_note_root: String,
    order_ingress_id: String,
    order_ingress_receipt_secret: Option<Arc<String>>,
    order_ingress_receipt_secrets: Arc<Vec<String>>,
    heartbeat_cover_secret: Arc<String>,
    max_provable_batch_orders: u64,
    max_order_amount: u128,
    max_liquidity_curve_base_amount: u128,
    max_liquidity_curve_quote_notional: u128,
    protocol_fee_recipient: String,
    relay_fee_recipient: String,
    protocol_fee_note_recipient: FeeNoteRecipientConfig,
    relay_fee_note_recipient: FeeNoteRecipientConfig,
    settlement_submission_jitter_ms: u64,
    private_payload_retention_ms: u64,
    max_stored_private_payloads: usize,
    private_ingress_rate_limit_per_minute: u64,
    public_rate_limit_per_minute: u64,
    emergency_paused: bool,
    prover_worker_enabled: bool,
    prover_worker_tick_ms: u64,
    prover_worker_max_batches_per_tick: usize,
    prover_worker_submit_onchain: bool,
    rate_limiter: RateLimiter,
    native_prover_attempts: usize,
    native_prover_retry_interval_ms: u64,
    native_prover_request_timeout_seconds: u64,
    native_prover_permits: Arc<Semaphore>,
}

fn service_http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_CLIENT_TIMEOUT_SECS))
        .build()
        .expect("failed to build prover HTTP client")
}

fn starknet_http_transport(rpc_url: Url) -> HttpTransport {
    let client = reqwest_013::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_STARKNET_RPC_TIMEOUT_SECS))
        .build()
        .expect("failed to build prover Starknet RPC HTTP client");
    HttpTransport::new_with_client(rpc_url, client)
}

#[derive(Clone, Debug)]
struct ProofWorkerBatchFailure {
    attempts: u32,
    next_retry_unix_ms: u64,
}

#[derive(Clone)]
struct StarknetExecutorConfig {
    rpc_url: String,
    account_address: String,
    private_key: String,
    chain_id: String,
    proof_account_address: String,
    proof_private_key: Option<String>,
}

impl StarknetExecutorConfig {
    fn request_account_address(&self, mode: NativeTransactionMode) -> &str {
        match mode {
            NativeTransactionMode::ProofOnly => &self.proof_account_address,
            NativeTransactionMode::SubmitOnchain => &self.account_address,
        }
    }

    fn request_private_key(&self, mode: NativeTransactionMode) -> &str {
        match mode {
            NativeTransactionMode::ProofOnly => self
                .proof_private_key
                .as_deref()
                .unwrap_or(self.private_key.as_str()),
            NativeTransactionMode::SubmitOnchain => &self.private_key,
        }
    }
}

impl Drop for StarknetExecutorConfig {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.proof_private_key.zeroize();
    }
}

#[derive(Clone)]
struct BatchRegistrarConfig {
    rpc_url: String,
    account_address: String,
    private_key: String,
    chain_id: String,
    batch_registry_address: String,
}

impl Drop for BatchRegistrarConfig {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[derive(Clone, Debug)]
struct FeeNoteRecipientConfig {
    owner_public_key: String,
    spend_authority: String,
    withdraw_authority: String,
}

#[derive(Clone, Debug, Default)]
struct LiquidityPositionMarketContexts {
    pairs: BTreeMap<String, LiquidityPositionPairMarketContext>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LiquidityPositionPairMarketContext {
    observed_at_unix_ms: u64,
    reference_price: u128,
    confirmation_price: Option<u128>,
}

impl LiquidityPositionMarketContexts {
    fn overlay(&mut self, update: Self) {
        self.pairs.extend(update.pairs);
    }

    fn context_for_pair(
        &self,
        pair: &ProductPairConfig,
        epoch: u64,
        default_observed_at_unix_ms: u64,
        current_time_unix_ms: u64,
    ) -> LiquidityPositionMarketContext {
        let Some(context) = self.pairs.get(&pair.pair_id.0) else {
            return LiquidityPositionMarketContext {
                epoch,
                observed_at_unix_ms: default_observed_at_unix_ms,
                current_time_unix_ms,
                reference_price: 0,
                confirmation_price: None,
                price_base_scale: pair.price_base_scale,
            };
        };

        LiquidityPositionMarketContext {
            epoch,
            observed_at_unix_ms: context.observed_at_unix_ms,
            current_time_unix_ms,
            reference_price: context.reference_price,
            confirmation_price: context.confirmation_price,
            price_base_scale: pair.price_base_scale,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct SettlementRoots {
    note_root: String,
    nullifier_root: String,
    renewal_root: String,
    fee_root: String,
    liquidity_position_root: String,
}

#[cfg(test)]
impl SettlementRoots {
    fn zero() -> Self {
        Self {
            note_root: "0x0".into(),
            nullifier_root: "0x0".into(),
            renewal_root: "0x0".into(),
            fee_root: "0x0".into(),
            liquidity_position_root: "0x0".into(),
        }
    }
}

struct AppConfig {
    coordinator_url: String,
    indexer_url: String,
    hosted_liquidity_relay_url: Option<String>,
    hosted_liquidity_relay_token: Option<String>,
    chain_id: String,
    auction_verifier_address: String,
    note_root_history_verifier_address: String,
    shielded_asset_adapter_address: String,
    native_proof_program_address: String,
    native_proof_entrypoint: String,
    native_proof_aggregate_entrypoint: String,
    native_tx_prover_url: String,
    native_tx_prover_ohttp: Option<NativeProverOhttpConfig>,
    scarb_bin: String,
    stwo_manifest_path: PathBuf,
    stwo_package_name: String,
    data_dir: PathBuf,
    starknet_executor: Option<StarknetExecutorConfig>,
    batch_registrar: Option<BatchRegistrarConfig>,
    product_config: ProductConfig,
    liquidity_position_market_contexts: LiquidityPositionMarketContexts,
    liquidity_position_market_contexts_path: Option<PathBuf>,
    auction_private_keys: Vec<PrivateExecutionKeyPrivateConfig>,
    internal_api_token: Option<String>,
    initial_note_root: String,
    order_ingress_id: String,
    order_ingress_receipt_secret: Option<String>,
    order_ingress_receipt_secrets: Vec<String>,
    heartbeat_cover_secret: String,
    max_provable_batch_orders: u64,
    max_order_amount: u128,
    max_liquidity_curve_base_amount: u128,
    max_liquidity_curve_quote_notional: u128,
    protocol_fee_recipient: String,
    relay_fee_recipient: String,
    protocol_fee_note_recipient: FeeNoteRecipientConfig,
    relay_fee_note_recipient: FeeNoteRecipientConfig,
    settlement_submission_jitter_ms: u64,
    private_payload_retention_ms: u64,
    max_stored_private_payloads: usize,
    private_ingress_rate_limit_per_minute: u64,
    public_rate_limit_per_minute: u64,
    emergency_paused: bool,
    prover_worker_enabled: bool,
    prover_worker_tick_ms: u64,
    prover_worker_max_batches_per_tick: usize,
    prover_worker_submit_onchain: bool,
    max_body_bytes: usize,
    native_prover_attempts: usize,
    native_prover_retry_interval_ms: u64,
    native_prover_request_timeout_seconds: u64,
    allowed_origins: Vec<HeaderValue>,
}

#[derive(Clone, Debug, Default)]
struct RateLimiter {
    buckets: Arc<Mutex<BTreeMap<String, RateLimitBucket>>>,
}

#[derive(Clone, Debug)]
struct RateLimitBucket {
    window_started_unix_ms: u64,
    count: u64,
}

const INGRESS_LATENCY_BUCKETS_MS: &[u64] = &[
    10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000,
];
const INGRESS_REMAINING_BUCKETS_MS: &[u64] =
    &[0, 5_000, 10_000, 15_000, 30_000, 60_000, 120_000, 300_000];
const MAX_CLIENT_TELEMETRY_MS: u64 = 10 * 60 * 1_000;
const LIFECYCLE_LATENCY_BUCKETS_MS: &[u64] = &[
    100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000, 300_000, 600_000,
    1_800_000,
];
const LIFECYCLE_OPERATIONS: &[&str] = &[
    "settlement_prepare",
    "settlement_proof_job",
    "settlement_proof_generation",
    "settlement_onchain_submit",
    "settlement_total",
    "withdrawal_submit",
    "withdrawal_proof_generation",
    "withdrawal_onchain_submit",
];

#[derive(Clone, Debug, Default)]
struct IngressTelemetryMetrics {
    inner: Arc<Mutex<IngressTelemetryMetricsInner>>,
}

#[derive(Clone, Debug, Default)]
struct IngressTelemetryMetricsInner {
    outcomes: BTreeMap<&'static str, u64>,
    processing_ms: HistogramCounts,
    client_build_ms: HistogramCounts,
    private_submission_delay_ms: HistogramCounts,
    client_elapsed_before_private_ingress_ms: HistogramCounts,
    private_ingress_roundtrip_ms: HistogramCounts,
    client_elapsed_before_coordinator_ms: HistogramCounts,
    batch_time_remaining_before_private_ingress_ms: HistogramCounts,
    batch_time_remaining_before_coordinator_ms: HistogramCounts,
}

#[derive(Clone, Debug, Default)]
struct HistogramCounts {
    buckets: BTreeMap<u64, u64>,
    overflow: u64,
    count: u64,
    sum: u128,
}

impl HistogramCounts {
    fn observe(&mut self, value: u64, buckets: &[u64]) {
        if let Some(bucket) = buckets.iter().copied().find(|bucket| value <= *bucket) {
            *self.buckets.entry(bucket).or_insert(0) += 1;
        } else {
            self.overflow += 1;
        }
        self.count += 1;
        self.sum += value as u128;
    }
}

impl IngressTelemetryMetrics {
    fn record(
        &self,
        outcome: &'static str,
        processing_ms: u64,
        telemetry: Option<&OrderIngressClientTelemetry>,
    ) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner.outcomes.entry(outcome).or_insert(0) += 1;
        inner
            .processing_ms
            .observe(processing_ms, INGRESS_LATENCY_BUCKETS_MS);
        if let Some(telemetry) = telemetry {
            observe_client_ms(
                &mut inner.client_build_ms,
                telemetry.client_build_ms,
                INGRESS_LATENCY_BUCKETS_MS,
            );
            observe_client_ms(
                &mut inner.private_submission_delay_ms,
                telemetry.private_submission_delay_ms,
                INGRESS_LATENCY_BUCKETS_MS,
            );
            observe_client_ms(
                &mut inner.client_elapsed_before_private_ingress_ms,
                telemetry.client_elapsed_before_private_ingress_ms,
                INGRESS_LATENCY_BUCKETS_MS,
            );
            observe_client_ms(
                &mut inner.private_ingress_roundtrip_ms,
                telemetry.private_ingress_roundtrip_ms,
                INGRESS_LATENCY_BUCKETS_MS,
            );
            observe_client_ms(
                &mut inner.client_elapsed_before_coordinator_ms,
                telemetry.client_elapsed_before_coordinator_ms,
                INGRESS_LATENCY_BUCKETS_MS,
            );
            observe_client_ms(
                &mut inner.batch_time_remaining_before_private_ingress_ms,
                telemetry.batch_time_remaining_before_private_ingress_ms,
                INGRESS_REMAINING_BUCKETS_MS,
            );
            observe_client_ms(
                &mut inner.batch_time_remaining_before_coordinator_ms,
                telemetry.batch_time_remaining_before_coordinator_ms,
                INGRESS_REMAINING_BUCKETS_MS,
            );
        }
    }

    fn render_prometheus(&self, namespace: &str) -> String {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut output = String::new();
        output.push_str(&format!(
            "# HELP {namespace}_private_order_ingress_requests_total Private order ingress requests by outcome.\n\
             # TYPE {namespace}_private_order_ingress_requests_total counter\n"
        ));
        for (outcome, count) in &inner.outcomes {
            output.push_str(&format!(
                "{namespace}_private_order_ingress_requests_total{{outcome=\"{outcome}\"}} {count}\n"
            ));
        }
        render_histogram(
            &mut output,
            namespace,
            "private_order_ingress_processing_ms",
            "Private order ingress server processing latency.",
            &inner.processing_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "private_order_ingress_client_build_ms",
            "Client-reported private order build time before ingress.",
            &inner.client_build_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "private_order_ingress_submission_delay_ms",
            "Client-reported private submission smoothing delay.",
            &inner.private_submission_delay_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "private_order_ingress_client_elapsed_before_private_ingress_ms",
            "Client-reported elapsed time before private ingress submission.",
            &inner.client_elapsed_before_private_ingress_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "private_order_ingress_private_ingress_roundtrip_ms",
            "Client-reported private ingress roundtrip time.",
            &inner.private_ingress_roundtrip_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "private_order_ingress_client_elapsed_before_coordinator_ms",
            "Client-reported elapsed time before coordinator submission.",
            &inner.client_elapsed_before_coordinator_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "private_order_ingress_batch_time_remaining_before_private_ingress_ms",
            "Client-reported batch time remaining before private ingress submission.",
            &inner.batch_time_remaining_before_private_ingress_ms,
            INGRESS_REMAINING_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "private_order_ingress_batch_time_remaining_before_coordinator_ms",
            "Client-reported batch time remaining before coordinator submission.",
            &inner.batch_time_remaining_before_coordinator_ms,
            INGRESS_REMAINING_BUCKETS_MS,
        );
        output
    }
}

#[derive(Clone, Debug, Default)]
struct LifecycleTelemetryMetrics {
    inner: Arc<Mutex<LifecycleTelemetryMetricsInner>>,
}

#[derive(Clone, Debug, Default)]
struct LifecycleTelemetryMetricsInner {
    outcomes: BTreeMap<(&'static str, &'static str), u64>,
    latency_ms: BTreeMap<&'static str, HistogramCounts>,
}

impl LifecycleTelemetryMetrics {
    fn record(&self, operation: &'static str, outcome: &'static str, latency_ms: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner.outcomes.entry((operation, outcome)).or_insert(0) += 1;
        inner
            .latency_ms
            .entry(operation)
            .or_default()
            .observe(latency_ms, LIFECYCLE_LATENCY_BUCKETS_MS);
    }

    fn render_prometheus(&self, namespace: &str) -> String {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut output = String::new();
        output.push_str(&format!(
            "# HELP {namespace}_proof_lifecycle_operations_total Proof, settlement, and withdrawal lifecycle operations by outcome.\n\
             # TYPE {namespace}_proof_lifecycle_operations_total counter\n"
        ));
        for ((operation, outcome), count) in &inner.outcomes {
            output.push_str(&format!(
                "{namespace}_proof_lifecycle_operations_total{{operation=\"{operation}\",outcome=\"{outcome}\"}} {count}\n"
            ));
        }
        for &operation in LIFECYCLE_OPERATIONS {
            if !inner
                .outcomes
                .keys()
                .any(|(observed_operation, _)| *observed_operation == operation)
            {
                output.push_str(&format!(
                    "{namespace}_proof_lifecycle_operations_total{{operation=\"{operation}\",outcome=\"success\"}} 0\n"
                ));
            }
        }
        for &operation in LIFECYCLE_OPERATIONS {
            let empty = HistogramCounts::default();
            let histogram = inner.latency_ms.get(operation).unwrap_or(&empty);
            render_histogram(
                &mut output,
                namespace,
                &format!("proof_lifecycle_{operation}_latency_ms"),
                "Proof, settlement, and withdrawal lifecycle latency.",
                histogram,
                LIFECYCLE_LATENCY_BUCKETS_MS,
            );
        }
        for (operation, histogram) in &inner.latency_ms {
            if LIFECYCLE_OPERATIONS.contains(operation) {
                continue;
            }
            render_histogram(
                &mut output,
                namespace,
                &format!("proof_lifecycle_{operation}_latency_ms"),
                "Proof, settlement, and withdrawal lifecycle latency.",
                histogram,
                LIFECYCLE_LATENCY_BUCKETS_MS,
            );
        }
        output
    }
}

fn observe_client_ms(histogram: &mut HistogramCounts, value: Option<u64>, buckets: &[u64]) {
    if let Some(value) = value.filter(|value| *value <= MAX_CLIENT_TELEMETRY_MS) {
        histogram.observe(value, buckets);
    }
}

fn render_histogram(
    output: &mut String,
    namespace: &str,
    metric: &str,
    help: &str,
    histogram: &HistogramCounts,
    buckets: &[u64],
) {
    output.push_str(&format!(
        "# HELP {namespace}_{metric} {help}\n# TYPE {namespace}_{metric} histogram\n"
    ));
    let mut cumulative = 0_u64;
    for bucket in buckets {
        cumulative += histogram.buckets.get(bucket).copied().unwrap_or_default();
        output.push_str(&format!(
            "{namespace}_{metric}_bucket{{le=\"{bucket}\"}} {cumulative}\n"
        ));
    }
    cumulative += histogram.overflow;
    output.push_str(&format!(
        "{namespace}_{metric}_bucket{{le=\"+Inf\"}} {cumulative}\n"
    ));
    output.push_str(&format!("{namespace}_{metric}_count {}\n", histogram.count));
    output.push_str(&format!("{namespace}_{metric}_sum {}\n", histogram.sum));
}

struct JobStateUpdate {
    next_state: String,
    proof_artifact_id: Option<String>,
    last_error: Option<String>,
    proof_artifact_available: bool,
    settlement_plan_available: Option<bool>,
    settlement_calldata_len: Option<u64>,
    settlement_entrypoint: Option<String>,
}

struct ProofExecutionPaths {
    proof_path: PathBuf,
    public_inputs_path: PathBuf,
    native_execution_request_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

struct SettlementArtifacts {
    transcript: SettlementTranscript,
    output_bundle: OutputCiphertextBundle,
    liquidity_provider_attribution_bundle: Option<LiquidityAttributionBundle>,
    settlement_witness: SettlementWitness,
    order_execution_reports: Vec<OrderExecutionReport>,
}

#[derive(Clone)]
struct DecryptedOrderRecord {
    order_commitment: OrderCommitment,
    cancellation_auth_tag: String,
    order: OrderIntent,
    funding_note: Note,
    funding_notes: Vec<Note>,
    funding_authorization: zylith_core::SpendAuthorization,
}

#[derive(Clone, Serialize, Deserialize)]
struct PrivateOrderPayloadRecord {
    order_commitment: OrderCommitment,
    payload_commitment: String,
    received_at_unix_ms: u64,
    receipt: OrderIngressReceipt,
    order_bundle: OrderShareBundle,
}

#[derive(Clone, Serialize, Deserialize)]
struct PrivateLiquidityPositionPayloadRecord {
    lifecycle_id: String,
    pair_id: PairId,
    batch_id: BatchId,
    epoch_id: u64,
    transition_commitment: String,
    payload_commitment: String,
    received_at_unix_ms: u64,
    receipt: zylith_core::LiquidityPositionIngressReceipt,
    transition_witness: LiquidityPositionTransitionWitness,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiquidityPositionInsertionWitnessRequest {
    position_id: String,
    output_commitment: LiquidityPositionCommitment,
    #[serde(skip_serializing_if = "Option::is_none")]
    prior_liquidity_position_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    padding: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LiquidityPositionStateUpdateWitnessKind {
    Reconfigure,
    Close,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiquidityPositionStateUpdateWitnessRequest {
    kind: LiquidityPositionStateUpdateWitnessKind,
    position_id: String,
    prior_commitment: LiquidityPositionCommitment,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_commitment: Option<LiquidityPositionCommitment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prior_liquidity_position_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    padding: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiquidityPositionStateRequest {
    position_id: String,
    owner_authority: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prior_liquidity_position_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    padding: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LiquidityPositionStateResponse {
    prior_liquidity_position_root: String,
    position: PrivateLiquidityPosition,
    position_commitment: LiquidityPositionCommitment,
    active_position_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    padding: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LiquidityPositionInsertionWitnessResponse {
    prior_liquidity_position_root: String,
    new_liquidity_position_root: String,
    active_position_count: usize,
    state_update: LiquidityPositionStateUpdate,
    #[serde(skip_serializing_if = "Option::is_none")]
    padding: Option<String>,
}

#[derive(Clone, Debug)]
struct ActiveLiquidityPositionRecord {
    position: PrivateLiquidityPosition,
    owner_public_key: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct ActiveLiquidityPositionBook {
    positions: BTreeMap<String, ActiveLiquidityPositionRecord>,
}

impl ActiveLiquidityPositionBook {
    fn root(&self) -> Result<String, StatusCode> {
        let positions = self
            .positions
            .values()
            .map(|record| record.position.clone())
            .collect::<Vec<_>>();
        LiquidityPositionState::from_positions(&positions)
            .and_then(|state| state.root())
            .map_err(|error| {
                eprintln!("active liquidity position book root failed: {error}");
                StatusCode::CONFLICT
            })
    }

    fn state(&self) -> Result<LiquidityPositionState, StatusCode> {
        let positions = self
            .positions
            .values()
            .map(|record| record.position.clone())
            .collect::<Vec<_>>();
        LiquidityPositionState::from_positions(&positions).map_err(|error| {
            eprintln!("active liquidity position book state failed: {error}");
            StatusCode::CONFLICT
        })
    }

    fn apply_transition_witness(
        &mut self,
        prior_root: &str,
        witness: &LiquidityPositionTransitionWitness,
    ) -> Result<String, StatusCode> {
        let verified =
            verify_liquidity_position_transition_witness(prior_root, witness).map_err(|error| {
                eprintln!("active liquidity position transition rejected: {error}");
                StatusCode::CONFLICT
            })?;
        let position_id = witness
            .prior_position
            .as_ref()
            .or(witness.output_position.as_ref())
            .map(|position| normalize_felt_hex(&position.position_id))
            .transpose()
            .map_err(|_| StatusCode::CONFLICT)?
            .ok_or(StatusCode::CONFLICT)?;
        match witness.transition.kind {
            LiquidityPositionTransitionKind::Open => {
                if self.positions.contains_key(&position_id) {
                    return Err(StatusCode::CONFLICT);
                }
                let output = witness
                    .output_position
                    .clone()
                    .ok_or(StatusCode::CONFLICT)?;
                let owner_public_key =
                    liquidity_position_owner_public_key_from_open_witness(witness)?;
                self.positions.insert(
                    position_id,
                    ActiveLiquidityPositionRecord {
                        position: output,
                        owner_public_key,
                    },
                );
            }
            LiquidityPositionTransitionKind::Update
            | LiquidityPositionTransitionKind::Reconfigure => {
                let prior = witness
                    .prior_position
                    .as_ref()
                    .ok_or(StatusCode::CONFLICT)?;
                let prior_commitment = prior.commitment().map_err(|_| StatusCode::CONFLICT)?;
                let existing = self
                    .positions
                    .get(&position_id)
                    .ok_or(StatusCode::CONFLICT)?;
                if existing
                    .position
                    .commitment()
                    .map_err(|_| StatusCode::CONFLICT)?
                    != prior_commitment
                {
                    return Err(StatusCode::CONFLICT);
                }
                let owner_public_key = existing.owner_public_key.clone();
                let output = witness
                    .output_position
                    .clone()
                    .ok_or(StatusCode::CONFLICT)?;
                self.positions.insert(
                    position_id,
                    ActiveLiquidityPositionRecord {
                        position: output,
                        owner_public_key,
                    },
                );
            }
            LiquidityPositionTransitionKind::Close => {
                let prior = witness
                    .prior_position
                    .as_ref()
                    .ok_or(StatusCode::CONFLICT)?;
                let prior_commitment = prior.commitment().map_err(|_| StatusCode::CONFLICT)?;
                let existing = self
                    .positions
                    .get(&position_id)
                    .ok_or(StatusCode::CONFLICT)?;
                if existing
                    .position
                    .commitment()
                    .map_err(|_| StatusCode::CONFLICT)?
                    != prior_commitment
                {
                    return Err(StatusCode::CONFLICT);
                }
                self.positions.remove(&position_id);
            }
        }
        let recomputed = self.root()?;
        if recomputed != verified.new_root {
            eprintln!(
                "active liquidity position book root mismatch recomputed={} verified={}",
                recomputed, verified.new_root
            );
            return Err(StatusCode::CONFLICT);
        }
        Ok(verified.new_root)
    }
}

fn liquidity_position_owner_public_key_from_open_witness(
    witness: &LiquidityPositionTransitionWitness,
) -> Result<Option<String>, StatusCode> {
    if !matches!(
        witness.transition.kind,
        LiquidityPositionTransitionKind::Open
    ) {
        return Ok(None);
    }
    let Some(open_funding) = witness.open_funding.as_ref() else {
        return Err(StatusCode::CONFLICT);
    };
    let mut owner_public_key: Option<String> = None;
    for note in open_funding
        .input_notes
        .iter()
        .chain(open_funding.change_notes.iter())
        .chain(witness.output_notes.iter())
    {
        let normalized_owner =
            normalize_owner_public_key(&note.owner_public_key).ok_or(StatusCode::CONFLICT)?;
        if let Some(existing) = owner_public_key.as_ref() {
            if existing != &normalized_owner {
                return Err(StatusCode::CONFLICT);
            }
        } else {
            owner_public_key = Some(normalized_owner);
        }
    }
    Ok(owner_public_key)
}

fn normalize_owner_public_key(owner_public_key: &str) -> Option<String> {
    if owner_public_key.trim().is_empty() {
        return None;
    }
    Some(owner_public_key.trim().to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NoteConsolidationHistoryRecord {
    consolidation_id: BatchId,
    consumed_inputs: Vec<ConsumedInput>,
    output_notes: Vec<OutputNoteRecord>,
}

#[derive(Clone)]
struct OrderFillPlan {
    order_commitment: OrderCommitment,
    cancellation_auth_tag: String,
    order: OrderIntent,
    funding_note: Note,
    funding_notes: Vec<Note>,
    funding_authorization: zylith_core::SpendAuthorization,
    filled_amount: u128,
}

#[derive(Clone)]
struct LiquidityPositionFillSource {
    position: PrivateLiquidityPosition,
    liquidity_provider_public_key: Option<String>,
    side: OrderSide,
    market_context: LiquidityPositionMarketContext,
    points: Vec<LiquidityCurvePoint>,
    available_amount: u128,
}

#[derive(Clone)]
struct LiquidityPositionFillPlan {
    source: LiquidityPositionFillSource,
    filled_amount: u128,
}

struct PrivateSettlementFillPlan {
    clearing_price: u128,
    order_fills: Vec<OrderFillPlan>,
    liquidity_position_fills: Vec<LiquidityPositionFillPlan>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NativeExecutionRequestRecord {
    block_id: NativeBlockId,
    transaction: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum NativeBlockId {
    Tag(String),
    Number { block_number: u64 },
    Hash { block_hash: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NativeProverRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: (NativeBlockId, serde_json::Value),
}

#[derive(Clone, Debug, Deserialize)]
struct NativeProverRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<NativeProverResult>,
    error: Option<NativeProverError>,
}

#[derive(Clone, Debug, Deserialize)]
struct NativeProverResult {
    proof: String,
    proof_facts: Vec<String>,
    l2_to_l1_messages: Vec<NativeMessageToL1>,
}

#[derive(Clone, Debug)]
struct NativeStatementProofArtifact {
    proof_path: String,
    proof_facts_path: String,
    execution_request_path: String,
    stdout_path: String,
    stderr_path: String,
    proof_sha256: String,
    proof_facts_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSettlementStatementKind {
    Nullifier,
    Renewal,
    LiquidityPosition,
    SettlementOrder,
    SettlementInputMembership,
    SettlementOutputRecovery,
    Settlement,
}

const NATIVE_SETTLEMENT_SUBMISSION_ORDER: [NativeSettlementStatementKind; 7] = [
    NativeSettlementStatementKind::Nullifier,
    NativeSettlementStatementKind::Renewal,
    NativeSettlementStatementKind::LiquidityPosition,
    NativeSettlementStatementKind::SettlementOrder,
    NativeSettlementStatementKind::SettlementInputMembership,
    NativeSettlementStatementKind::SettlementOutputRecovery,
    NativeSettlementStatementKind::Settlement,
];

impl NativeSettlementStatementKind {
    fn label(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::Renewal => "renewal",
            Self::LiquidityPosition => "liquidity-position",
            Self::SettlementOrder => "settlement-order",
            Self::SettlementInputMembership => "settlement-input-membership",
            Self::SettlementOutputRecovery => "settlement-output-recovery",
            Self::Settlement => "settlement",
        }
    }

    fn entrypoint(self, settlement_entrypoint: &str) -> &str {
        match self {
            Self::Nullifier => "compile_nullifier_proof",
            Self::Renewal => "compile_renewal_proof",
            Self::LiquidityPosition => "compile_liquidity_position_proof",
            Self::SettlementOrder => "compile_settlement_order_proof",
            Self::SettlementInputMembership => "compile_settlement_input_membership_proof",
            Self::SettlementOutputRecovery => "compile_settlement_output_recovery_proof",
            Self::Settlement => settlement_entrypoint,
        }
    }
}

struct NativeSettlementSubmissionProofContext {
    tx_prover_url: String,
    executor: Arc<StarknetExecutorConfig>,
    batch_id: String,
    serialized_settlement_witness: Vec<String>,
    serialized_liquidity_position_witness: Vec<String>,
    settlement_message_hash: String,
    nullifier_message_hash: String,
    renewal_message_hash: String,
    liquidity_position_message_hash: String,
    settlement_order_message_hash: String,
    settlement_input_membership_message_hash: String,
    settlement_output_recovery_message_hash: String,
}

impl NativeSettlementSubmissionProofContext {
    fn expected_message_hash(&self, kind: NativeSettlementStatementKind) -> &String {
        match kind {
            NativeSettlementStatementKind::Nullifier => &self.nullifier_message_hash,
            NativeSettlementStatementKind::Renewal => &self.renewal_message_hash,
            NativeSettlementStatementKind::LiquidityPosition => {
                &self.liquidity_position_message_hash
            }
            NativeSettlementStatementKind::SettlementOrder => &self.settlement_order_message_hash,
            NativeSettlementStatementKind::SettlementInputMembership => {
                &self.settlement_input_membership_message_hash
            }
            NativeSettlementStatementKind::SettlementOutputRecovery => {
                &self.settlement_output_recovery_message_hash
            }
            NativeSettlementStatementKind::Settlement => &self.settlement_message_hash,
        }
    }

    fn serialized_witness(&self, kind: NativeSettlementStatementKind) -> &[String] {
        match kind {
            NativeSettlementStatementKind::LiquidityPosition => {
                &self.serialized_liquidity_position_witness
            }
            _ => &self.serialized_settlement_witness,
        }
    }

    fn stage_key(&self, kind: NativeSettlementStatementKind) -> String {
        format!("{}-onchain-{}", self.batch_id, kind.label())
    }
}

#[derive(Clone, Debug, Deserialize)]
struct NativeMessageToL1 {
    from_address: String,
    to_address: String,
    payload: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct NativeProverError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
struct NativeProverOhttpConfig {
    pinned_key_config: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProofAggregationManifest {
    manifest_id: String,
    mode: String,
    epoch_start: u64,
    epoch_end: u64,
    batch_count_bucket: String,
    pair_count_bucket: String,
    proof_artifact_count_bucket: String,
    aggregate_commitment: String,
    proof_artifact_commitment_root: String,
    transcript_commitment_root: String,
    native_aggregation_supported: bool,
    verifier_mode: String,
}

#[derive(Clone, Serialize)]
struct NativeProofAggregationRecord {
    manifest: ProofAggregationManifest,
    member_count_bucket: String,
    provider: String,
    verifier_mode: String,
    aggregate_proof_artifact_commitment: String,
    settlement_call: StarknetCall,
    member_batches: Vec<BatchId>,
    proof: String,
    proof_facts: Vec<String>,
    #[serde(skip_serializing)]
    prepared_members: Vec<NativeAggregationPreparedMember>,
}

#[derive(Clone)]
struct NativeAggregationPreparedMember {
    witness: SettlementWitness,
    transcript: SettlementTranscript,
    settlement_plan: SettlementSubmissionPlan,
    proof_message_hashes: Vec<String>,
}

fn redact_native_execution_request(
    request: &NativeExecutionRequestRecord,
) -> NativeExecutionRequestRecord {
    let mut redacted = request.clone();
    redact_transaction_calldata(&mut redacted.transaction);
    redacted
}

fn redact_native_prover_request(request: &NativeProverRpcRequest) -> NativeProverRpcRequest {
    let mut redacted = request.clone();
    redact_transaction_calldata(&mut redacted.params.1);
    redacted
}

fn redact_transaction_calldata(transaction: &mut serde_json::Value) {
    if let Some(object) = transaction.as_object_mut()
        && let Some(calldata) = object.get_mut("calldata")
    {
        let len = calldata
            .as_array()
            .map(|values| values.len())
            .unwrap_or_default();
        *calldata = serde_json::json!({
            "redacted": true,
            "felt_count": len,
            "reason": "private settlement witness"
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let app = build_app()?;
    let bind_addr =
        env::var("ZYLITH_PROVER_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.into());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|error| format!("failed to bind prover service on {bind_addr}: {error}"))?;

    println!("Zylith prover listening on http://{bind_addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("prover service failed: {error}"))
}

fn configured_env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
fn fee_note_key_from_value(env_name: &str, configured: Option<String>) -> Result<String, String> {
    fee_note_key_from_value_for_mode(env_name, configured, false)
}

fn fee_note_key_from_value_for_mode(
    env_name: &str,
    configured: Option<String>,
    production: bool,
) -> Result<String, String> {
    match configured {
        Some(value) if !value.trim().is_empty() => {
            if production
                && default_fee_note_key_for_env(env_name)
                    .is_some_and(|default| same_secret_hex(&value, default))
            {
                return Err(format!("{env_name} must not use the development default"));
            }
            Ok(value)
        }
        Some(_) | None => Err(format!("{env_name} is required")),
    }
}

fn fee_note_key_from_env(env_name: &str) -> Result<String, String> {
    fee_note_key_from_value_for_mode(
        env_name,
        configured_env_value(env_name),
        prover_production_mode(),
    )
}

fn default_fee_note_key_for_env(env_name: &str) -> Option<&'static str> {
    match env_name {
        PROTOCOL_FEE_OWNER_KEY_ENV => Some(DEV_PROTOCOL_FEE_OWNER_KEY),
        PROTOCOL_FEE_WITHDRAW_KEY_ENV => Some(DEV_PROTOCOL_FEE_WITHDRAW_KEY),
        RELAY_FEE_OWNER_KEY_ENV => Some(DEV_RELAY_FEE_OWNER_KEY),
        RELAY_FEE_WITHDRAW_KEY_ENV => Some(DEV_RELAY_FEE_WITHDRAW_KEY),
        _ => None,
    }
}

fn same_secret_hex(left: &str, right: &str) -> bool {
    left.trim()
        .trim_start_matches("0x")
        .eq_ignore_ascii_case(right.trim().trim_start_matches("0x"))
}

fn fee_note_recipient_from_env(
    owner_key_env: &str,
    withdraw_key_env: &str,
) -> Result<FeeNoteRecipientConfig, String> {
    let owner_key = fee_note_key_from_env(owner_key_env)?;
    let withdraw_key = fee_note_key_from_env(withdraw_key_env)?;
    let owner_public_key = note_recognition_public_key_from_raw_key_hex(&owner_key)
        .map_err(|error| format!("invalid fee note owner key: {error}"))?;
    let withdraw_authority = withdraw_authority_from_raw_key_hex(&withdraw_key)
        .map_err(|error| format!("invalid fee note withdraw key: {error}"))?;
    Ok(FeeNoteRecipientConfig {
        owner_public_key,
        spend_authority: withdraw_authority.clone(),
        withdraw_authority,
    })
}

fn protocol_fee_note_recipient_from_env() -> Result<FeeNoteRecipientConfig, String> {
    fee_note_recipient_from_env(PROTOCOL_FEE_OWNER_KEY_ENV, PROTOCOL_FEE_WITHDRAW_KEY_ENV)
}

fn relay_fee_note_recipient_from_env() -> Result<FeeNoteRecipientConfig, String> {
    fee_note_recipient_from_env(RELAY_FEE_OWNER_KEY_ENV, RELAY_FEE_WITHDRAW_KEY_ENV)
}

fn build_app() -> Result<Router, String> {
    let deployment_manifest = load_deployment_manifest()?;
    let coordinator_url = load_service_url("ZYLITH_COORDINATOR_URL", DEFAULT_COORDINATOR_URL)?;
    let indexer_url = load_service_url("ZYLITH_INDEXER_URL", DEFAULT_INDEXER_URL)?;
    let hosted_liquidity_relay_url = env::var(HOSTED_LIQUIDITY_RELAY_URL_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let hosted_liquidity_relay_token = env::var(HOSTED_LIQUIDITY_RELAY_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let chain_id = configured_env_value("ZYLITH_STARKNET_CHAIN_ID")
        .or_else(|| {
            deployment_manifest
                .as_ref()
                .map(|manifest| manifest.chain_id.clone())
        })
        .unwrap_or_default();
    let auction_verifier_address = env::var("ZYLITH_AUCTION_VERIFIER_ADDRESS")
        .ok()
        .or_else(|| {
            deployment_manifest
                .as_ref()
                .map(|manifest| manifest.contracts.auction_verifier.clone())
        })
        .unwrap_or_default();
    let note_root_history_verifier_address = env::var(NOTE_ROOT_HISTORY_VERIFIER_ADDRESS_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| auction_verifier_address.clone());
    let shielded_asset_adapter_address = env::var("ZYLITH_SHIELDED_ASSET_ADAPTER_ADDRESS")
        .ok()
        .or_else(|| {
            deployment_manifest
                .as_ref()
                .map(|manifest| manifest.contracts.shielded_asset_adapter.clone())
        })
        .unwrap_or_default();
    let native_proof_program_address = env::var(NATIVE_PROOF_PROGRAM_ADDRESS_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            deployment_manifest.as_ref().and_then(|manifest| {
                let manifest_address = manifest.proof.proof_program_address.trim();
                if manifest_address.is_empty() {
                    None
                } else {
                    Some(manifest.proof.proof_program_address.clone())
                }
            })
        })
        .unwrap_or_default();
    let native_proof_entrypoint = env::var(NATIVE_PROOF_ENTRYPOINT_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            deployment_manifest.as_ref().and_then(|manifest| {
                let manifest_entrypoint = manifest.proof.proof_entrypoint.trim();
                if manifest_entrypoint.is_empty() {
                    None
                } else {
                    Some(manifest.proof.proof_entrypoint.clone())
                }
            })
        })
        .unwrap_or_else(|| "compile_settlement_proof".into());
    let native_proof_aggregate_entrypoint = env::var(NATIVE_PROOF_AGGREGATE_ENTRYPOINT_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "compile_settlement_aggregate_proof".into());
    let native_tx_prover_url = configured_env_value(NATIVE_TX_PROVER_URL_ENV)
        .ok_or_else(|| format!("{NATIVE_TX_PROVER_URL_ENV} is required"))?;
    enforce_native_tx_prover_trust_boundary(Some(&native_tx_prover_url))?;
    validate_native_tx_prover_manifest_pin(deployment_manifest.as_ref(), &native_tx_prover_url)?;
    let native_tx_prover_ohttp = load_native_prover_ohttp_config(&native_tx_prover_url)?;
    let scarb_bin = env::var("ZYLITH_SCARB_BIN").unwrap_or_else(|_| DEFAULT_SCARB_BIN.into());
    let stwo_manifest_path = env::var("ZYLITH_STWO_MANIFEST_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STWO_MANIFEST_PATH));
    let stwo_package_name =
        env::var("ZYLITH_STWO_PACKAGE_NAME").unwrap_or_else(|_| DEFAULT_STWO_PACKAGE_NAME.into());
    let data_dir = env::var("ZYLITH_PROVER_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PROVER_DATA_DIR));
    let data_dir = scoped_prover_data_dir(
        data_dir,
        &auction_verifier_address,
        prover_production_mode(),
    )?;
    let order_ingress_id =
        env::var(ORDER_INGRESS_ID_ENV).unwrap_or_else(|_| "zylith-prover-ingress".into());
    let order_ingress_receipt_secret = env::var(ORDER_INGRESS_RECEIPT_SECRET_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let order_ingress_receipt_secrets =
        load_receipt_secret_keyring(order_ingress_receipt_secret.as_ref());
    let heartbeat_cover_secret =
        load_required_control_plane_token("zylith-prover", HEARTBEAT_COVER_SECRET_ENV)?;
    let product_config = load_product_config(deployment_manifest.as_ref())?;
    let auction_private_keys = load_auction_private_keys()?;
    let starknet_executor = load_starknet_executor_from_env(deployment_manifest.as_ref());
    let batch_registrar = load_batch_registrar_from_env(deployment_manifest.as_ref())?;
    let initial_note_root = load_initial_note_root()?;
    let native_prover_attempts =
        env_positive_config_or_default(NATIVE_PROVER_ATTEMPTS_ENV, DEFAULT_NATIVE_PROVER_ATTEMPTS)?;
    let native_prover_retry_interval_ms = env_positive_config_or_default(
        NATIVE_PROVER_RETRY_INTERVAL_MS_ENV,
        DEFAULT_NATIVE_PROVER_RETRY_INTERVAL_MS,
    )?;
    let native_prover_request_timeout_seconds = env_positive_config_or_default(
        NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS_ENV,
        DEFAULT_NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS,
    )?;
    let protocol_fee_note_recipient = protocol_fee_note_recipient_from_env()?;
    let relay_fee_note_recipient = relay_fee_note_recipient_from_env()?;
    let (liquidity_position_market_contexts, liquidity_position_market_contexts_path) =
        load_liquidity_position_market_contexts_from_env()?;

    build_app_with_config(AppConfig {
        coordinator_url,
        indexer_url,
        hosted_liquidity_relay_url,
        hosted_liquidity_relay_token,
        chain_id,
        auction_verifier_address,
        note_root_history_verifier_address,
        shielded_asset_adapter_address,
        native_proof_program_address,
        native_proof_entrypoint,
        native_proof_aggregate_entrypoint,
        native_tx_prover_url,
        native_tx_prover_ohttp,
        scarb_bin,
        stwo_manifest_path,
        stwo_package_name,
        data_dir,
        starknet_executor,
        batch_registrar,
        product_config,
        liquidity_position_market_contexts,
        liquidity_position_market_contexts_path,
        auction_private_keys,
        internal_api_token: Some(load_required_control_plane_token(
            "zylith-prover",
            CONTROL_PLANE_TOKEN_ENV,
        )?),
        initial_note_root,
        order_ingress_id,
        order_ingress_receipt_secret,
        order_ingress_receipt_secrets,
        heartbeat_cover_secret,
        max_provable_batch_orders: env_positive_config_or_default(
            MAX_PROVABLE_BATCH_ORDERS_ENV,
            DEFAULT_MAX_PROVABLE_BATCH_ORDERS,
        )?,
        max_order_amount: env_config_or_default(MAX_ORDER_AMOUNT_ENV, 0_u128)?,
        max_liquidity_curve_base_amount: env_config_or_default(
            MAX_LIQUIDITY_CURVE_BASE_AMOUNT_ENV,
            0_u128,
        )?,
        max_liquidity_curve_quote_notional: env_config_or_default(
            MAX_LIQUIDITY_CURVE_QUOTE_NOTIONAL_ENV,
            0_u128,
        )?,
        protocol_fee_recipient: protocol_fee_note_recipient.withdraw_authority.clone(),
        relay_fee_recipient: relay_fee_note_recipient.withdraw_authority.clone(),
        protocol_fee_note_recipient,
        relay_fee_note_recipient,
        settlement_submission_jitter_ms: env_config_or_default(
            SETTLEMENT_SUBMISSION_JITTER_MS_ENV,
            DEFAULT_SETTLEMENT_SUBMISSION_JITTER_MS,
        )?,
        private_payload_retention_ms: env_positive_config_or_default(
            PROVER_PRIVATE_PAYLOAD_RETENTION_MS_ENV,
            DEFAULT_PROVER_PRIVATE_PAYLOAD_RETENTION_MS,
        )?,
        max_stored_private_payloads: env_positive_config_or_default(
            PROVER_MAX_STORED_PRIVATE_PAYLOADS_ENV,
            DEFAULT_PROVER_MAX_STORED_PRIVATE_PAYLOADS,
        )?,
        private_ingress_rate_limit_per_minute: env_positive_config_or_default(
            PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE_ENV,
            DEFAULT_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE,
        )?,
        public_rate_limit_per_minute: env_positive_config_or_default(
            PROVER_PUBLIC_RATE_LIMIT_PER_MINUTE_ENV,
            DEFAULT_PROVER_PUBLIC_RATE_LIMIT_PER_MINUTE,
        )?,
        emergency_paused: env_bool_or_default(PROVER_EMERGENCY_PAUSED_ENV, false),
        prover_worker_enabled: env_bool_or_default(PROVER_WORKER_ENABLED_ENV, true),
        prover_worker_tick_ms: env_positive_config_or_default(
            PROVER_WORKER_TICK_MS_ENV,
            DEFAULT_PROVER_WORKER_TICK_MS,
        )?,
        prover_worker_max_batches_per_tick: env_positive_config_or_default(
            PROVER_WORKER_MAX_BATCHES_PER_TICK_ENV,
            DEFAULT_PROVER_WORKER_MAX_BATCHES_PER_TICK,
        )?,
        prover_worker_submit_onchain: env_bool_or_default(PROVER_WORKER_SUBMIT_ONCHAIN_ENV, true),
        max_body_bytes: env_positive_config_or_default(
            PROVER_MAX_BODY_BYTES_ENV,
            DEFAULT_PROVER_MAX_BODY_BYTES,
        )?,
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
        allowed_origins: allowed_origins_from_env(PROVER_ALLOWED_ORIGINS_ENV)
            .ok_or_else(|| format!("{PROVER_ALLOWED_ORIGINS_ENV} is required"))?,
    })
}

fn load_deployment_manifest() -> Result<Option<DeploymentManifest>, String> {
    let explicit_path = env::var("ZYLITH_DEPLOYMENT_MANIFEST").ok();
    let manifest_path = explicit_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DEPLOYMENT_MANIFEST_PATH));
    let manifest = match read_utf8_file_limited(
        &manifest_path,
        MAX_DEPLOYMENT_MANIFEST_BYTES,
        "deployment manifest",
    ) {
        Ok(manifest) => manifest,
        Err(error) if explicit_path.is_some() || prover_production_mode() => {
            return Err(format!(
                "failed to read deployment manifest {}: {error}",
                manifest_path.display()
            ));
        }
        Err(_) => return Ok(None),
    };
    let value = serde_json::from_str::<serde_json::Value>(&manifest).map_err(|error| {
        format!(
            "failed to parse deployment manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let manifest = value.get("manifest").cloned().unwrap_or(value);
    serde_json::from_value(manifest).map(Some).map_err(|error| {
        format!(
            "failed to parse deployment manifest {}: {error}",
            manifest_path.display()
        )
    })
}

fn load_product_config(
    deployment_manifest: Option<&DeploymentManifest>,
) -> Result<ProductConfig, String> {
    let product_pairs = env::var("ZYLITH_PRODUCT_PAIRS").ok();
    let mut product_config =
        product_config_from_sources(product_pairs.as_deref(), deployment_manifest)?;
    if let Ok(value) = env::var(HEARTBEAT_COVER_PRICES_ENV) {
        product_config
            .apply_heartbeat_cover_prices_csv(&value)
            .map_err(|error| format!("invalid ZYLITH_HEARTBEAT_COVER_PRICES: {error}"))?;
    }
    Ok(product_config)
}

fn load_liquidity_position_market_contexts_from_env()
-> Result<(LiquidityPositionMarketContexts, Option<PathBuf>), String> {
    let contexts = env::var(LIQUIDITY_POSITION_MARKET_CONTEXTS_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_liquidity_position_market_contexts(&value))
        .transpose()?
        .unwrap_or_default();
    let path = env::var(LIQUIDITY_POSITION_MARKET_CONTEXTS_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    Ok((contexts, path))
}

fn liquidity_position_market_contexts_for_batch(
    state: &AppState,
) -> Result<LiquidityPositionMarketContexts, StatusCode> {
    let mut contexts = state.liquidity_position_market_contexts.as_ref().clone();
    let Some(path) = state.liquidity_position_market_contexts_path.as_deref() else {
        return Ok(contexts);
    };
    let raw = read_utf8_file_limited(
        path.as_ref(),
        MAX_LIQUIDITY_POSITION_MARKET_CONTEXTS_BYTES,
        "liquidity position market contexts",
    )
    .map_err(|error| {
        eprintln!(
            "failed to read liquidity position market contexts {}: {error}",
            path.display()
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let file_contexts = parse_liquidity_position_market_contexts(&raw).map_err(|error| {
        eprintln!(
            "failed to parse liquidity position market contexts {}: {error}",
            path.display()
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    contexts.overlay(file_contexts);
    Ok(contexts)
}

fn parse_liquidity_position_market_contexts(
    raw: &str,
) -> Result<LiquidityPositionMarketContexts, String> {
    let value = serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|error| format!("invalid market context JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "liquidity position market contexts must be a JSON object".to_string())?;
    for key in object.keys() {
        if key != "pairs" {
            return Err(format!(
                "liquidity position market contexts has unknown top-level field '{key}'"
            ));
        }
    }
    let pairs_value = object
        .get("pairs")
        .ok_or_else(|| "liquidity position market contexts require a pairs object".to_string())?;
    let pairs_object = pairs_value
        .as_object()
        .ok_or_else(|| "liquidity position market context pairs must be an object".to_string())?;

    let mut pairs = BTreeMap::new();
    for (pair_id, context_value) in pairs_object {
        let pair_id = pair_id.trim();
        if pair_id.is_empty() {
            return Err("liquidity position market context pair id must not be empty".into());
        }
        let context = parse_liquidity_position_pair_market_context(pair_id, context_value)?;
        pairs.insert(pair_id.to_owned(), context);
    }
    Ok(LiquidityPositionMarketContexts { pairs })
}

fn parse_liquidity_position_pair_market_context(
    pair_id: &str,
    value: &serde_json::Value,
) -> Result<LiquidityPositionPairMarketContext, String> {
    let object = value.as_object().ok_or_else(|| {
        format!("liquidity position market context for {pair_id} must be an object")
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "observed_at_unix_ms" | "reference_price" | "confirmation_price"
        ) {
            return Err(format!(
                "liquidity position market context for {pair_id} has unknown field '{key}'"
            ));
        }
    }
    let observed_at_unix_ms = parse_json_u64_field(
        object.get("observed_at_unix_ms").ok_or_else(|| {
            format!("liquidity position market context for {pair_id} requires observed_at_unix_ms")
        })?,
        "observed_at_unix_ms",
    )?;
    let reference_price = parse_json_u128_field(
        object.get("reference_price").ok_or_else(|| {
            format!("liquidity position market context for {pair_id} requires reference_price")
        })?,
        "reference_price",
    )?;
    if reference_price == 0 {
        return Err(format!(
            "liquidity position market context for {pair_id} requires a positive reference_price"
        ));
    }
    let confirmation_price = object
        .get("confirmation_price")
        .map(|value| parse_json_u128_field(value, "confirmation_price"))
        .transpose()?;
    if matches!(confirmation_price, Some(0)) {
        return Err(format!(
            "liquidity position market context for {pair_id} requires a positive confirmation_price"
        ));
    }
    Ok(LiquidityPositionPairMarketContext {
        observed_at_unix_ms,
        reference_price,
        confirmation_price,
    })
}

fn parse_json_u64_field(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| format!("{field} must be a non-negative u64")),
        serde_json::Value::String(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{field} must be a decimal u64")),
        _ => Err(format!("{field} must be a decimal number or string")),
    }
}

fn parse_json_u128_field(value: &serde_json::Value, field: &str) -> Result<u128, String> {
    match value {
        serde_json::Value::Number(number) => number
            .to_string()
            .parse::<u128>()
            .map_err(|_| format!("{field} must be a non-negative u128")),
        serde_json::Value::String(value) => value
            .trim()
            .parse::<u128>()
            .map_err(|_| format!("{field} must be a decimal u128")),
        _ => Err(format!("{field} must be a decimal number or string")),
    }
}

fn product_config_from_sources(
    product_pairs: Option<&str>,
    deployment_manifest: Option<&DeploymentManifest>,
) -> Result<ProductConfig, String> {
    let product_config = if let Some(value) = product_pairs {
        ProductConfig::from_enabled_pair_ids_csv(value)
            .map_err(|error| format!("invalid ZYLITH_PRODUCT_PAIRS: {error}"))?
    } else if let Some(manifest) = deployment_manifest {
        manifest.product.clone()
    } else {
        return Err(
            "ZYLITH_PRODUCT_PAIRS or deployment manifest product config is required".into(),
        );
    };
    Ok(product_config)
}

fn load_auction_private_keys() -> Result<Vec<PrivateExecutionKeyPrivateConfig>, String> {
    let path = env::var(AUCTION_PROVER_KEYS_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_AUCTION_PROVER_KEYS_PATH));
    load_required_auction_keys(&path)
}

fn load_receipt_secret_keyring(current_secret: Option<&String>) -> Vec<String> {
    let mut keyring = Vec::new();
    if let Some(current_secret) = current_secret
        && !current_secret.trim().is_empty()
    {
        keyring.push(current_secret.trim().to_owned());
    }
    if let Ok(previous) = env::var(ORDER_INGRESS_RECEIPT_PREVIOUS_SECRETS_ENV) {
        for secret in previous.split(',') {
            let secret = secret.trim();
            if !secret.is_empty() && !keyring.iter().any(|known| known == secret) {
                keyring.push(secret.to_owned());
            }
        }
    }
    keyring
}

fn load_required_control_plane_token(service_name: &str, env_name: &str) -> Result<String, String> {
    env::var(env_name)
        .map(|value| value.trim().to_owned())
        .map_err(|_| {
            format!("{service_name} requires {env_name} to protect internal control-plane routes")
        })
        .and_then(|value| {
            if value.is_empty() {
                Err(format!(
                    "{service_name} requires non-empty {env_name} to protect internal control-plane routes"
                ))
            } else {
                Ok(value)
            }
        })
}

fn prover_production_mode() -> bool {
    matches!(
        env::var("ZYLITH_PROVER_STRICT")
            .or_else(|_| env::var("ZYLITH_ENV"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "production" | "prod"
    )
}

fn is_zero_felt_like(value: &str) -> bool {
    normalize_felt_hex(value)
        .map(|normalized| normalized == "0x0")
        .unwrap_or_else(|_| value.trim().is_empty())
}

fn validate_native_proof_program_config(
    proof_program_address: &str,
    auction_verifier_address: &str,
    production: bool,
) -> Result<(), String> {
    if !production {
        return Ok(());
    }
    if proof_program_address.trim().is_empty() || is_zero_felt_like(proof_program_address) {
        return Err(format!(
            "{NATIVE_PROOF_PROGRAM_ADDRESS_ENV} is required when ZYLITH_ENV=production or ZYLITH_PROVER_STRICT=true"
        ));
    }
    if !auction_verifier_address.trim().is_empty()
        && same_starknet_address(proof_program_address, auction_verifier_address)
    {
        return Err(format!(
            "{NATIVE_PROOF_PROGRAM_ADDRESS_ENV} must not equal ZYLITH_AUCTION_VERIFIER_ADDRESS"
        ));
    }
    Ok(())
}

fn validate_native_tx_prover_endpoint_config(
    native_tx_prover_url: Option<&str>,
) -> Result<(), String> {
    let Some(url) = native_tx_prover_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(
            "ZYLITH_NATIVE_TX_PROVER_URL is required; Zylith proving must use the configured Starknet prover endpoint".into(),
        );
    };
    let parsed = Url::parse(url)
        .map_err(|error| format!("ZYLITH_NATIVE_TX_PROVER_URL is invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("ZYLITH_NATIVE_TX_PROVER_URL must be an HTTP(S) URL with a host".into());
    }
    enforce_native_tx_prover_trust_boundary(Some(url))
}

fn normalize_native_tx_prover_url(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value.trim())
        .map_err(|error| format!("ZYLITH_NATIVE_TX_PROVER_URL is invalid: {error}"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err("ZYLITH_NATIVE_TX_PROVER_URL must be an HTTP(S) URL with a host".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "ZYLITH_NATIVE_TX_PROVER_URL must be an HTTP(S) URL with a host".to_owned())?
        .to_ascii_lowercase();
    let mut normalized = format!("{scheme}://{host}");
    if let Some(port) = parsed.port() {
        let default_port = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
        if !default_port {
            normalized.push(':');
            normalized.push_str(&port.to_string());
        }
    }
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() {
        normalized.push_str(path);
    }
    if let Some(query) = parsed.query() {
        normalized.push('?');
        normalized.push_str(query);
    }
    Ok(normalized)
}

fn validate_native_tx_prover_manifest_pin(
    deployment_manifest: Option<&DeploymentManifest>,
    configured_url: &str,
) -> Result<(), String> {
    let Some(manifest_url) = deployment_manifest
        .map(|manifest| manifest.proof.native_tx_prover_url.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let configured = normalize_native_tx_prover_url(configured_url)?;
    let pinned = normalize_native_tx_prover_url(manifest_url)?;
    if configured != pinned {
        return Err(format!(
            "{NATIVE_TX_PROVER_URL_ENV} must match deployment manifest proof.native_tx_prover_url"
        ));
    }
    Ok(())
}

fn load_service_url(env_name: &str, development_default: &str) -> Result<String, String> {
    let configured = env::var(env_name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    match configured {
        Some(value) => Ok(value),
        None if prover_production_mode() => Err(format!(
            "{env_name} is required when ZYLITH_ENV=production or ZYLITH_PROVER_STRICT=true"
        )),
        None => Ok(development_default.into()),
    }
}

fn allowed_origins_from_env(env_name: &str) -> Option<Vec<HeaderValue>> {
    let value = env::var(env_name).ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let origins = value
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            if origin.contains('*') {
                panic!("{env_name} must contain exact origins only");
            }
            HeaderValue::from_str(origin)
                .unwrap_or_else(|_| panic!("{env_name} contains invalid origin '{origin}'"))
        })
        .collect::<Vec<_>>();
    if origins.is_empty() {
        None
    } else {
        Some(origins)
    }
}

fn scoped_prover_data_dir(
    base_dir: PathBuf,
    auction_verifier_address: &str,
    production_scoped: bool,
) -> Result<PathBuf, String> {
    if !production_scoped {
        return Ok(base_dir);
    }
    let scope = storage_key(
        &normalize_felt_hex(auction_verifier_address)
            .map_err(|_| "auction verifier address must be a felt for prover data scoping")?,
    );
    if base_dir.file_name().and_then(|name| name.to_str()) == Some(scope.as_str()) {
        return Ok(base_dir);
    }
    Ok(base_dir.join("deployments").join(scope))
}

fn require_internal_auth(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(expected_token) = state.internal_api_token.as_deref() else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !zylith_core::constant_time_eq(provided, expected_token.as_str()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn apply_internal_auth(
    request: reqwest::RequestBuilder,
    internal_api_token: Option<&str>,
) -> reqwest::RequestBuilder {
    if let Some(token) = internal_api_token {
        request.header(AUTHORIZATION.as_str(), format_bearer_token(token))
    } else {
        request
    }
}

fn build_app_with_config(config: AppConfig) -> Result<Router, String> {
    let AppConfig {
        coordinator_url,
        indexer_url,
        hosted_liquidity_relay_url,
        hosted_liquidity_relay_token,
        chain_id,
        auction_verifier_address,
        note_root_history_verifier_address,
        shielded_asset_adapter_address,
        native_proof_program_address,
        native_proof_entrypoint,
        native_proof_aggregate_entrypoint,
        native_tx_prover_url,
        native_tx_prover_ohttp,
        scarb_bin,
        stwo_manifest_path,
        stwo_package_name,
        data_dir,
        starknet_executor,
        batch_registrar,
        product_config,
        liquidity_position_market_contexts,
        liquidity_position_market_contexts_path,
        auction_private_keys,
        internal_api_token,
        initial_note_root,
        order_ingress_id,
        order_ingress_receipt_secret,
        order_ingress_receipt_secrets,
        heartbeat_cover_secret,
        max_provable_batch_orders,
        max_order_amount,
        max_liquidity_curve_base_amount,
        max_liquidity_curve_quote_notional,
        protocol_fee_recipient,
        relay_fee_recipient,
        protocol_fee_note_recipient,
        relay_fee_note_recipient,
        settlement_submission_jitter_ms,
        private_payload_retention_ms,
        max_stored_private_payloads,
        private_ingress_rate_limit_per_minute,
        public_rate_limit_per_minute,
        emergency_paused,
        prover_worker_enabled,
        prover_worker_tick_ms,
        prover_worker_max_batches_per_tick,
        prover_worker_submit_onchain,
        max_body_bytes,
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
        allowed_origins,
    } = config;

    if protocol_fee_recipient.trim().is_empty() {
        return Err("protocol fee recipient must not be empty".into());
    }
    if relay_fee_recipient.trim().is_empty() {
        return Err("relay fee recipient must not be empty".into());
    }
    if normalize_felt_hex(&chain_id).map_err(|_| "chain id must be a Starknet felt".to_string())?
        == "0x0"
    {
        return Err("chain id must not be zero".into());
    }
    if note_root_history_verifier_address.trim().is_empty() {
        return Err("note root history verifier address must not be empty".into());
    }
    normalize_felt_hex(&note_root_history_verifier_address)
        .map_err(|_| format!("{NOTE_ROOT_HISTORY_VERIFIER_ADDRESS_ENV} must be a Starknet felt"))?;
    if native_proof_entrypoint != "compile_settlement_proof" {
        return Err("native proof entrypoint must be compile_settlement_proof".into());
    }
    if native_proof_aggregate_entrypoint != "compile_settlement_aggregate_proof" {
        return Err(
            "native aggregate proof entrypoint must be compile_settlement_aggregate_proof".into(),
        );
    }
    validate_native_proof_program_config(
        &native_proof_program_address,
        &auction_verifier_address,
        prover_production_mode(),
    )?;
    validate_native_tx_prover_endpoint_config(Some(&native_tx_prover_url))?;
    ensure_prover_dirs(&data_dir)?;
    let auction_key_registry = PrivateExecutionKeyRegistry {
        keys: auction_private_keys
            .iter()
            .map(|member| PrivateExecutionKeyPublicConfig {
                key_id: member.key_id.clone(),
                public_key: member.public_key.clone(),
            })
            .collect(),
    };

    let state = AppState {
        coordinator_url,
        indexer_url,
        hosted_liquidity_relay_url,
        hosted_liquidity_relay_token: hosted_liquidity_relay_token.map(Arc::new),
        auction_verifier_address,
        note_root_history_verifier_address,
        shielded_asset_adapter_address,
        native_proof_program_address,
        native_proof_entrypoint,
        native_proof_aggregate_entrypoint,
        native_tx_prover_url,
        native_tx_prover_ohttp,
        scarb_bin,
        stwo_manifest_path: Arc::new(stwo_manifest_path),
        stwo_package_name,
        data_dir: Arc::new(data_dir.clone()),
        http_client: service_http_client(),
        proof_jobs: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            PROOF_JOBS_DIR,
            |record: &ProofJobStatus| record.batch_id.0.clone(),
        ))),
        proof_worker_failures: Arc::new(RwLock::new(BTreeMap::new())),
        active_proof_batches: Arc::new(Mutex::new(BTreeSet::new())),
        settlement_plans: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            SETTLEMENT_PLANS_DIR,
            |record: &SettlementSubmissionPlan| record.batch_id.0.clone(),
        ))),
        settlement_witnesses: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            SETTLEMENT_WITNESSES_DIR,
            |record: &SettlementWitness| record.batch_id.0.clone(),
        ))),
        prepared_batch_artifacts: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            PREPARED_BATCH_ARTIFACTS_DIR,
            |record: &PublishedBatchArtifacts| record.transcript.batch_id.0.clone(),
        ))),
        note_consolidation_history: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            NOTE_CONSOLIDATION_HISTORY_DIR,
            |record: &NoteConsolidationHistoryRecord| record.consolidation_id.0.clone(),
        ))),
        settlement_output_withdrawal_nullifiers: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            SETTLEMENT_OUTPUT_WITHDRAWAL_NULLIFIERS_DIR,
            settlement_output_withdrawal_consumed_input_key,
        ))),
        proof_artifacts: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            PROOF_ARTIFACTS_DIR,
            |record: &ProofArtifactRecord| record.batch_id.0.clone(),
        ))),
        onchain_submissions: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            ONCHAIN_SUBMISSIONS_DIR,
            onchain_submission_storage_key,
        ))),
        private_order_payloads: Arc::new(RwLock::new(load_json_records_with_limits(
            &data_dir,
            PRIVATE_ORDER_PAYLOADS_DIR,
            max_stored_private_payloads,
            MAX_PERSISTED_RECORD_DIRECTORY_BYTES,
            |record: &PrivateOrderPayloadRecord| record.order_commitment.0.clone(),
        ))),
        private_liquidity_position_payloads: Arc::new(RwLock::new(load_json_records_with_limits(
            &data_dir,
            PRIVATE_LIQUIDITY_POSITION_PAYLOADS_DIR,
            max_stored_private_payloads,
            MAX_PERSISTED_RECORD_DIRECTORY_BYTES,
            |record: &PrivateLiquidityPositionPayloadRecord| record.lifecycle_id.clone(),
        ))),
        deposit_activation_cache: Arc::new(RwLock::new(Vec::new())),
        note_root_transition_cache: Arc::new(RwLock::new(Vec::new())),
        private_ingress_metrics: IngressTelemetryMetrics::default(),
        proof_lifecycle_metrics: LifecycleTelemetryMetrics::default(),
        product_config: Arc::new(product_config),
        liquidity_position_market_contexts: Arc::new(liquidity_position_market_contexts),
        liquidity_position_market_contexts_path: liquidity_position_market_contexts_path
            .map(Arc::new),
        auction_key_registry: Arc::new(auction_key_registry),
        auction_private_keys: Arc::new(auction_private_keys),
        starknet_executor: starknet_executor.map(Arc::new),
        batch_registrar: batch_registrar.map(Arc::new),
        internal_api_token: internal_api_token.map(Arc::new),
        initial_note_root,
        order_ingress_id,
        order_ingress_receipt_secret: order_ingress_receipt_secret.map(Arc::new),
        order_ingress_receipt_secrets: Arc::new(order_ingress_receipt_secrets),
        heartbeat_cover_secret: Arc::new(heartbeat_cover_secret),
        max_provable_batch_orders,
        max_order_amount,
        max_liquidity_curve_base_amount,
        max_liquidity_curve_quote_notional,
        protocol_fee_recipient,
        relay_fee_recipient,
        protocol_fee_note_recipient,
        relay_fee_note_recipient,
        settlement_submission_jitter_ms,
        private_payload_retention_ms,
        max_stored_private_payloads,
        private_ingress_rate_limit_per_minute,
        public_rate_limit_per_minute,
        emergency_paused,
        prover_worker_enabled,
        prover_worker_tick_ms,
        prover_worker_max_batches_per_tick,
        prover_worker_submit_onchain,
        rate_limiter: RateLimiter::default(),
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
        native_prover_permits: Arc::new(Semaphore::new(1)),
    };

    if state.prover_worker_enabled {
        task::spawn(proof_worker_loop(state.clone()));
    }

    Ok(Router::new()
        .route("/health", get(health))
        .route("/api/internal/health", get(internal_health))
        .route("/api/public/auction-keys", get(public_auction_keys))
        .route(
            "/api/public/auction-keys/fingerprint",
            get(public_auction_keys_fingerprint),
        )
        .route("/api/internal/metrics", get(internal_metrics))
        .route(
            "/api/public/proof-jobs/{batch_id}",
            get(get_public_proof_job),
        )
        .route("/api/public/proof-jobs", get(list_public_proof_jobs))
        .route("/api/private/orders", post(ingest_private_order_payload))
        .route(
            "/api/private/liquidity-positions/lifecycle",
            post(ingest_private_liquidity_position_payload),
        )
        .route(
            "/api/private/liquidity-positions/state",
            post(get_private_liquidity_position_state),
        )
        .route(
            "/api/private/liquidity-positions/insertion-witness",
            post(prepare_liquidity_position_insertion_witness),
        )
        .route(
            "/api/private/liquidity-positions/state-update-witness",
            post(prepare_liquidity_position_state_update_witness),
        )
        .route(
            "/api/private/note-consolidations/prepare",
            post(prepare_note_consolidation),
        )
        .route(
            "/api/private/note-consolidations/submit",
            post(submit_note_consolidation),
        )
        .route(
            "/api/private/withdrawals/prepare",
            post(prepare_settlement_output_withdrawal),
        )
        .route(
            "/api/private/withdrawals/submit",
            post(submit_settlement_output_withdrawal),
        )
        .route(
            "/api/internal/batches/{batch_id}/prepare",
            post(prepare_private_auction_batch),
        )
        .route(
            "/api/internal/proof-jobs/{batch_id}",
            get(get_proof_job).post(prepare_proof_job),
        )
        .route(
            "/api/internal/proof-jobs/{batch_id}/prove",
            post(run_proof_job),
        )
        .route(
            "/api/internal/proof-jobs/{batch_id}/submit",
            post(submit_onchain),
        )
        .route(
            "/api/internal/settlement-plans/{batch_id}",
            get(get_settlement_plan),
        )
        .route(
            "/api/internal/settlement-witnesses/{batch_id}",
            get(get_settlement_witness),
        )
        .route(
            "/api/internal/proof-artifacts/{batch_id}",
            get(get_proof_artifact),
        )
        .route(
            "/api/internal/proof-aggregation-manifests/epochs/{start_epoch}/{end_epoch}",
            get(get_proof_aggregation_manifest).post(run_native_proof_aggregation),
        )
        .route(
            "/api/internal/proof-aggregation-manifests/epochs/{start_epoch}/{end_epoch}/submit",
            post(submit_native_proof_aggregation),
        )
        .route(
            "/api/internal/onchain-submissions/{batch_id}",
            get(get_onchain_submission),
        )
        .route(
            "/api/internal/onchain-submissions/{batch_id}/refresh",
            post(refresh_onchain_submission),
        )
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state,
            internal_route_auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(cors_layer_for_origins(allowed_origins)))
}

fn cors_layer_for_origins(origins: Vec<HeaderValue>) -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any)
        .allow_origin(AllowOrigin::list(origins))
}

async fn internal_route_auth_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if request.uri().path().starts_with("/api/internal/") {
        require_internal_auth(&state, request.headers())?;
    }
    Ok(next.run(request).await)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "zylith-prover",
        "status": "ok",
    }))
}

async fn internal_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let proof_jobs = state.proof_jobs.read().await;
    let settlement_plans = state.settlement_plans.read().await;
    let settlement_witnesses = state.settlement_witnesses.read().await;
    let note_consolidation_history = state.note_consolidation_history.read().await;
    let settlement_output_withdrawal_nullifiers =
        state.settlement_output_withdrawal_nullifiers.read().await;
    let proof_artifacts = state.proof_artifacts.read().await;
    let onchain_submissions = state.onchain_submissions.read().await;
    let private_order_payloads = state.private_order_payloads.read().await;
    let mut proof_jobs_by_state = BTreeMap::<String, usize>::new();
    for status in proof_jobs.values() {
        *proof_jobs_by_state.entry(status.state.clone()).or_default() += 1;
    }
    let latest_failed_job = proof_jobs
        .values()
        .filter(|status| is_failed_proof_job_state(&status.state))
        .max_by_key(|status| status.updated_at_unix_ms)
        .map(|status| {
            serde_json::json!({
                "batch_id": status.batch_id.0,
                "state": status.state,
                "error_class": proof_job_error_class(status.last_error.as_deref()),
                "updated_at_unix_ms": status.updated_at_unix_ms,
            })
        });
    Ok(Json(serde_json::json!({
        "service": "zylith-prover",
        "coordinator_configured": !state.coordinator_url.trim().is_empty(),
        "indexer_configured": !state.indexer_url.trim().is_empty(),
        "prepared_jobs_bucket": count_bucket(proof_jobs.len()),
        "proof_jobs_by_state": proof_jobs_by_state,
        "latest_failed_job": latest_failed_job,
        "auction_verifier_address": state.auction_verifier_address,
        "note_root_history_verifier_address": state.note_root_history_verifier_address,
        "prepared_settlement_plans_bucket": count_bucket(settlement_plans.len()),
        "prepared_settlement_witnesses_bucket": count_bucket(settlement_witnesses.len()),
        "note_consolidation_history_bucket": count_bucket(note_consolidation_history.len()),
        "recorded_settlement_output_withdrawal_nullifiers_bucket": count_bucket(settlement_output_withdrawal_nullifiers.len()),
        "stored_proof_artifacts_bucket": count_bucket(proof_artifacts.len()),
        "stored_onchain_submissions_bucket": count_bucket(onchain_submissions.len()),
        "stored_private_order_payloads_bucket": count_bucket(private_order_payloads.len()),
        "starknet_executor_enabled": state.starknet_executor.is_some(),
        "native_tx_prover_enabled": true,
        "native_tx_prover_ohttp_enabled": state.native_tx_prover_ohttp.is_some(),
        "native_proof_aggregation_enabled": true,
        "prover_worker_enabled": state.prover_worker_enabled,
        "prover_worker_tick_ms": state.prover_worker_tick_ms,
        "prover_worker_max_batches_per_tick": state.prover_worker_max_batches_per_tick,
        "prover_worker_submit_onchain": state.prover_worker_submit_onchain,
        "trusted_order_ingress_enabled": state.order_ingress_receipt_secret.is_some(),
        "trusted_order_ingress_id": state.order_ingress_id,
        "trusted_order_ingress_receipt_key_count": state.order_ingress_receipt_secrets.len(),
        "auction_key_count": state.auction_key_registry.keys.len(),
        "auction_key_registry_fingerprint": private_execution_key_registry_fingerprint(state.auction_key_registry.as_ref()).ok(),
        "emergency_paused": state.emergency_paused,
        "private_payload_retention_ms": state.private_payload_retention_ms,
        "max_stored_private_payloads": state.max_stored_private_payloads,
        "private_ingress_rate_limit_per_minute": state.private_ingress_rate_limit_per_minute,
        "public_rate_limit_per_minute": state.public_rate_limit_per_minute,
        "max_provable_batch_orders": state.max_provable_batch_orders,
        "max_order_amount": state.max_order_amount.to_string(),
        "max_liquidity_curve_base_amount": state.max_liquidity_curve_base_amount.to_string(),
        "max_liquidity_curve_quote_notional": state.max_liquidity_curve_quote_notional.to_string(),
        "protocol_fee_recipient": &state.protocol_fee_recipient,
        "settlement_submission_jitter_ms": state.settlement_submission_jitter_ms,
        "native_prover_attempts": state.native_prover_attempts,
        "native_prover_retry_interval_ms": state.native_prover_retry_interval_ms,
        "native_prover_request_timeout_seconds": state.native_prover_request_timeout_seconds,
        "prover_backend": prover_backend_label(),
        "scarb_bin": state.scarb_bin,
        "stwo_manifest_path": state.stwo_manifest_path.display().to_string(),
        "stwo_package_name": state.stwo_package_name,
        "data_dir": state.data_dir.display().to_string(),
    })))
}

async fn internal_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let mut body = state
        .private_ingress_metrics
        .render_prometheus("zylith_prover");
    body.push_str(
        &state
            .proof_lifecycle_metrics
            .render_prometheus("zylith_prover"),
    );
    Ok(body)
}

fn enforce_public_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    scope: &str,
) -> Result<(), StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        headers,
        peer,
        scope,
        state.public_rate_limit_per_minute,
    )
}

async fn public_auction_keys(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
) -> Result<Json<PrivateExecutionKeyRegistry>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "auction-keys")?;
    Ok(Json((*state.auction_key_registry).clone()))
}

fn count_bucket(count: usize) -> &'static str {
    match count {
        0..=7 => "0-7",
        8..=31 => "8-31",
        32..=127 => "32-127",
        128..=511 => "128-511",
        _ => "512+",
    }
}

fn deterministic_settlement_submission_jitter_ms(batch_id: &str, max_jitter_ms: u64) -> u64 {
    if max_jitter_ms == 0 {
        return 0;
    }
    let mut accumulator = 0xd6e8_feb8_6659_fd93_u64;
    for byte in batch_id.as_bytes() {
        accumulator ^= u64::from(*byte);
        accumulator = accumulator
            .rotate_left(9)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    accumulator % max_jitter_ms.saturating_add(1)
}

async fn public_auction_keys_fingerprint(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "auction-keys-fingerprint")?;
    let fingerprint =
        private_execution_key_registry_fingerprint(state.auction_key_registry.as_ref())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "algorithm": "sha256(tagged-json:zylith/private-execution-key-registry-v1)",
        "fingerprint": fingerprint,
        "key_count": state.auction_key_registry.keys.len(),
    })))
}

fn reject_private_ingress(reason: &str) -> StatusCode {
    eprintln!("private order ingress rejected: {reason}");
    StatusCode::BAD_REQUEST
}

async fn verify_hosted_relay_order_attestation(
    state: &AppState,
    package_id: &str,
    package_commitment: &str,
    order: &OrderIntent,
    order_commitment: &OrderCommitment,
) -> Result<(), StatusCode> {
    let relay_url = state
        .hosted_liquidity_relay_url
        .as_deref()
        .ok_or_else(|| reject_private_ingress("hosted liquidity relay is not configured"))?;
    let url = format!(
        "{}/packages/{}/attest-order",
        relay_url.trim_end_matches('/'),
        package_id
    );
    let request = HostedRelayOrderAttestationRequest {
        package_commitment: package_commitment.into(),
        order_commitment: order_commitment.0.clone(),
        pair: order.pair_id.0.clone(),
        batch_id: order.batch_id.0.clone(),
        epoch_id: order.expiry_epoch,
    };
    let response = apply_internal_auth(
        state.http_client.post(url).json(&request),
        state
            .hosted_liquidity_relay_token
            .as_deref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| reject_private_ingress("hosted liquidity relay attestation failed"))?;
    if !response.status().is_success() {
        return Err(reject_private_ingress(
            "hosted liquidity relay attestation rejected",
        ));
    }
    let response = decode_bounded_json_response::<HostedRelayOrderAttestationResponse>(
        response,
        MAX_CONTROL_PLANE_RESPONSE_BYTES,
    )
    .await
    .map_err(|_| reject_private_ingress("hosted liquidity relay attestation was invalid"))?;
    validate_hosted_relay_order_attestation_response(
        &response,
        package_id,
        package_commitment,
        order,
        order_commitment,
    )
}

fn validate_hosted_relay_order_attestation_response(
    response: &HostedRelayOrderAttestationResponse,
    package_id: &str,
    package_commitment: &str,
    order: &OrderIntent,
    order_commitment: &OrderCommitment,
) -> Result<(), StatusCode> {
    if response.package_id != package_id
        || response.package_commitment != package_commitment
        || response.order_commitment != order_commitment.0
        || response.pair != order.pair_id.0
        || response.batch_id != order.batch_id.0
        || response.epoch_id != order.expiry_epoch
        || response.relay_mode != RelayMode::ZylithRelay
    {
        return Err(reject_private_ingress(
            "hosted liquidity relay attestation mismatch",
        ));
    }
    Ok(())
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteConsolidationPrepareRequest {
    consolidation_id: BatchId,
    input_notes: Vec<Note>,
    output_notes: Vec<OutputNoteRecord>,
    output_note_preimages: Vec<Note>,
    output_recovery_records: Vec<OutputRecoveryRecord>,
    output_recovery_dummy_commitments: Vec<String>,
    output_ciphertext_bundle_ref: String,
}

#[derive(Clone, Serialize)]
struct NoteConsolidationPrepareResponse {
    witness: NoteConsolidationWitness,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteConsolidationSubmitRequest {
    witness: NoteConsolidationWitness,
}

#[derive(Clone, Debug, Serialize)]
struct NoteConsolidationSubmitResponse {
    consolidation_id: String,
    transaction_hash: String,
    finality_status: Option<String>,
    execution_status: Option<String>,
    settled_at_unix_ms: Option<u64>,
    output_note_commitments: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementOutputWithdrawalPrepareRequest {
    batch_id: BatchId,
    output_note: OutputNoteRecord,
    output_note_preimage: Note,
    output_proof: zylith_core::OutputNoteMerkleProof,
    strk20_exit_commitment: String,
}

#[derive(Clone, Serialize)]
struct SettlementOutputWithdrawalPrepareResponse {
    witness: SettlementOutputWithdrawalWitness,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementOutputWithdrawalSubmitRequest {
    witness: SettlementOutputWithdrawalWitness,
}

#[derive(Clone, Debug, Serialize)]
struct SettlementOutputWithdrawalSubmitResponse {
    batch_id: String,
    note_commitment: String,
    strk20_exit_commitment: String,
    transaction_hash: String,
    finality_status: Option<String>,
    execution_status: Option<String>,
    settled_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct HostedRelayOrderAttestationRequest {
    package_commitment: String,
    order_commitment: String,
    pair: String,
    batch_id: String,
    epoch_id: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostedRelayOrderAttestationResponse {
    package_id: String,
    package_commitment: String,
    order_commitment: String,
    pair: String,
    batch_id: String,
    epoch_id: u64,
    relay_mode: RelayMode,
}

async fn prepare_note_consolidation(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<NoteConsolidationPrepareRequest>,
) -> Result<Json<NoteConsolidationPrepareResponse>, StatusCode> {
    require_prover_not_paused(&state)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "note-consolidation",
        state.private_ingress_rate_limit_per_minute,
    )?;
    if request.input_notes.is_empty() || request.output_notes.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let prior_roots = fetch_current_settlement_roots(&state).await?;
    let consumed_inputs = consumed_inputs_for_notes(&request.input_notes)?;
    let historical_settlement_witnesses = confirmed_settlement_witnesses(&state).await;
    let prior_note_consolidation_history = {
        let note_consolidation_history = state.note_consolidation_history.read().await;
        note_consolidation_history
            .values()
            .cloned()
            .collect::<Vec<_>>()
    };
    let prior_withdrawal_nullifiers = {
        let withdrawal_nullifiers = state.settlement_output_withdrawal_nullifiers.read().await;
        withdrawal_nullifiers.values().cloned().collect::<Vec<_>>()
    };
    let prior_note_root_nonzero =
        normalize_felt_hex(&prior_roots.note_root).map_err(|_| StatusCode::BAD_GATEWAY)? != "0x0";
    let deposit_activations = if prior_note_root_nonzero {
        fetch_indexed_deposit_activations(&state).await?
    } else {
        Vec::new()
    };
    let note_root_transitions = if prior_note_root_nonzero {
        fetch_note_root_transition_records(&state).await?
    } else {
        Vec::new()
    };
    let note_membership_witnesses = derive_note_membership_witnesses(
        &prior_roots.note_root,
        &consumed_inputs,
        NoteMembershipSources {
            initial_note_root: &state.initial_note_root,
            direct_input_notes: &request.input_notes,
            matched_order_witnesses: &[],
            deposit_activations: &deposit_activations,
            note_root_transitions: &note_root_transitions,
            prior_settlement_witnesses: &historical_settlement_witnesses,
            prior_note_consolidation_history: &prior_note_consolidation_history,
        },
    )
    .inspect_err(|status| {
        eprintln!("prepare_note_consolidation rejected stage=note_membership status={status}");
    })?;
    if note_membership_witnesses.len() != consumed_inputs.len() {
        eprintln!(
            "prepare_note_consolidation rejected stage=note_membership_count consumed={} witnesses={}",
            consumed_inputs.len(),
            note_membership_witnesses.len()
        );
        return Err(StatusCode::CONFLICT);
    }
    let prior_consumed_inputs = historical_consumed_inputs(
        &historical_settlement_witnesses,
        &prior_note_consolidation_history,
        &prior_withdrawal_nullifiers,
    )?;
    let (computed_prior_nullifier_root, new_nullifier_root, nullifier_sparse_witnesses) =
        nullifier_sparse_update_witnesses_for_consumed_inputs(
            &prior_consumed_inputs,
            &consumed_inputs,
        )
        .map_err(|error| {
            let sanitized_error = sanitize_native_prover_error_text(&error.to_string());
            eprintln!(
                "prepare_note_consolidation rejected stage=nullifier_sparse error={sanitized_error}"
            );
            StatusCode::CONFLICT
        })?;
    if computed_prior_nullifier_root
        != normalize_felt_hex(&prior_roots.nullifier_root).map_err(|_| StatusCode::BAD_GATEWAY)?
    {
        eprintln!("prepare_note_consolidation rejected stage=prior_nullifier_root");
        return Err(StatusCode::CONFLICT);
    }

    let witness = NoteConsolidationWitness {
        consolidation_id: request.consolidation_id,
        auction_verifier_address: state.auction_verifier_address.clone(),
        prior_note_root: prior_roots.note_root,
        prior_nullifier_root: prior_roots.nullifier_root,
        input_notes: request.input_notes,
        spend_authorization: SpendAuthorization {
            signature_r: "0x0".into(),
            signature_s: "0x0".into(),
        },
        note_membership_witnesses,
        nullifier_history: Vec::new(),
        nullifier_sparse_witnesses,
        output_notes: request.output_notes,
        output_note_preimages: request.output_note_preimages,
        output_recovery_records: request.output_recovery_records,
        output_recovery_dummy_commitments: request.output_recovery_dummy_commitments,
        output_ciphertext_bundle_ref: request.output_ciphertext_bundle_ref,
        new_nullifier_root,
    };
    build_note_consolidation_serialized_input(&witness).map_err(|error| {
        let sanitized_error = sanitize_native_prover_error_text(&error.to_string());
        eprintln!("prepare_note_consolidation rejected stage=serialize error={sanitized_error}");
        StatusCode::CONFLICT
    })?;
    Ok(Json(NoteConsolidationPrepareResponse { witness }))
}

async fn submit_note_consolidation(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<NoteConsolidationSubmitRequest>,
) -> Result<Json<NoteConsolidationSubmitResponse>, StatusCode> {
    require_prover_not_paused(&state)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "note-consolidation",
        state.private_ingress_rate_limit_per_minute,
    )?;
    let response = submit_note_consolidation_inner(&state, request.witness).await?;
    Ok(Json(response))
}

async fn prepare_settlement_output_withdrawal(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<SettlementOutputWithdrawalPrepareRequest>,
) -> Result<Json<SettlementOutputWithdrawalPrepareResponse>, StatusCode> {
    require_prover_not_paused(&state)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "settlement-output-withdrawal",
        state.private_ingress_rate_limit_per_minute,
    )?;
    if request.output_note.amount == 0 || request.output_note_preimage.amount == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if request
        .output_note_preimage
        .commitment()
        .map_err(|_| StatusCode::CONFLICT)?
        != request.output_note.note_commitment
    {
        return Err(StatusCode::CONFLICT);
    }
    let prior_roots = fetch_current_settlement_roots(&state).await?;
    let historical_settlement_witnesses = confirmed_settlement_witnesses(&state).await;
    let prior_note_consolidation_history = {
        let note_consolidation_history = state.note_consolidation_history.read().await;
        note_consolidation_history
            .values()
            .cloned()
            .collect::<Vec<_>>()
    };
    let prior_withdrawal_nullifiers = {
        let withdrawal_nullifiers = state.settlement_output_withdrawal_nullifiers.read().await;
        withdrawal_nullifiers.values().cloned().collect::<Vec<_>>()
    };
    let current_inputs =
        consumed_inputs_for_notes(std::slice::from_ref(&request.output_note_preimage))?;
    let prior_consumed_inputs = historical_consumed_inputs(
        &historical_settlement_witnesses,
        &prior_note_consolidation_history,
        &prior_withdrawal_nullifiers,
    )?;
    let (computed_prior_nullifier_root, new_nullifier_root, mut nullifier_sparse_witnesses) =
        nullifier_sparse_update_witnesses_for_consumed_inputs(
            &prior_consumed_inputs,
            &current_inputs,
        )
        .map_err(|_| StatusCode::CONFLICT)?;
    if computed_prior_nullifier_root
        != normalize_felt_hex(&prior_roots.nullifier_root).map_err(|_| StatusCode::BAD_GATEWAY)?
    {
        return Err(StatusCode::CONFLICT);
    }
    let sparse_witness = nullifier_sparse_witnesses
        .pop()
        .ok_or(StatusCode::CONFLICT)?;
    if !nullifier_sparse_witnesses.is_empty() {
        return Err(StatusCode::CONFLICT);
    }
    let executor = state
        .starknet_executor
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let shielded_asset_adapter_address = normalize_felt_hex(&state.shielded_asset_adapter_address)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if shielded_asset_adapter_address == "0x0" {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let strk20_exit_commitment =
        normalize_felt_hex(&request.strk20_exit_commitment).map_err(|_| StatusCode::BAD_REQUEST)?;
    if strk20_exit_commitment == "0x0" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let witness = SettlementOutputWithdrawalWitness {
        batch_id: request.batch_id,
        auction_verifier_address: state.auction_verifier_address.clone(),
        shielded_asset_adapter_address,
        chain_id: executor.chain_id.clone(),
        strk20_exit_commitment,
        prior_nullifier_root: prior_roots.nullifier_root,
        output_note: request.output_note,
        output_note_preimage: request.output_note_preimage,
        output_proof: request.output_proof,
        withdraw_authorization: SpendAuthorization {
            signature_r: "0x0".into(),
            signature_s: "0x0".into(),
        },
        nullifier_history: Vec::new(),
        nullifier_sparse_witness: Some(sparse_witness),
        new_nullifier_root,
    };
    build_settlement_output_withdrawal_serialized_input(&witness)
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(Json(SettlementOutputWithdrawalPrepareResponse { witness }))
}

async fn submit_settlement_output_withdrawal(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<SettlementOutputWithdrawalSubmitRequest>,
) -> Result<Json<SettlementOutputWithdrawalSubmitResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_prover_not_paused(&state).map_err(withdrawal_submit_error)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "settlement-output-withdrawal",
        state.private_ingress_rate_limit_per_minute,
    )
    .map_err(withdrawal_submit_error)?;
    let started_at = now_unix_ms();
    let result = submit_settlement_output_withdrawal_inner(&state, request.witness).await;
    state.proof_lifecycle_metrics.record(
        "withdrawal_submit",
        if result.is_ok() { "success" } else { "error" },
        now_unix_ms().saturating_sub(started_at),
    );
    let response = result.map_err(withdrawal_submit_error)?;
    Ok(Json(response))
}

fn withdrawal_submit_error(status: StatusCode) -> (StatusCode, Json<serde_json::Value>) {
    let error = match status {
        StatusCode::TOO_EARLY => {
            "Settlement output claim window is not open yet. Retry after the claim delay."
        }
        StatusCode::CONFLICT => {
            "Settlement output withdrawal conflicts with current on-chain state. Refresh and retry."
        }
        StatusCode::FORBIDDEN => "Withdrawal request is not authorized.",
        StatusCode::SERVICE_UNAVAILABLE => "Withdrawal proving service is not configured.",
        StatusCode::TOO_MANY_REQUESTS => "Too many withdrawal requests. Please retry later.",
        StatusCode::BAD_REQUEST => "Withdrawal request is invalid.",
        _ if status.is_server_error() => "Withdrawal service is unavailable. Please retry later.",
        _ => "Withdrawal request failed.",
    };
    (status, Json(serde_json::json!({ "error": error })))
}

fn consumed_inputs_for_notes(notes: &[Note]) -> Result<Vec<ConsumedInput>, StatusCode> {
    notes
        .iter()
        .map(|note| {
            let commitment = note
                .commitment()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let nullifier = nullifier_from_note_secret(&commitment, &note.blinding)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(ConsumedInput {
                note_commitment: commitment,
                nullifier,
            })
        })
        .collect()
}

fn historical_consumed_inputs(
    settlement_witnesses: &[SettlementWitness],
    note_consolidation_history: &[NoteConsolidationHistoryRecord],
    settlement_output_withdrawal_nullifiers: &[ConsumedInput],
) -> Result<Vec<ConsumedInput>, StatusCode> {
    let mut consumed = settlement_witnesses
        .iter()
        .flat_map(|witness| witness.consumed_inputs.iter().cloned())
        .collect::<Vec<_>>();
    for record in note_consolidation_history {
        consumed.extend(record.consumed_inputs.iter().cloned());
    }
    consumed.extend(settlement_output_withdrawal_nullifiers.iter().cloned());
    Ok(consumed)
}

fn onchain_submission_has_succeeded(submission: &OnchainSubmissionRecord) -> bool {
    submission.execution_status.as_deref() == Some("SUCCEEDED")
        && matches!(
            submission.finality_status.as_deref(),
            Some("PRE_CONFIRMED" | "ACCEPTED_ON_L2" | "ACCEPTED_ON_L1")
        )
}

fn confirmed_settlement_witnesses_from_maps(
    settlement_witnesses: &BTreeMap<String, SettlementWitness>,
    onchain_submissions: &BTreeMap<String, OnchainSubmissionRecord>,
) -> Vec<SettlementWitness> {
    settlement_witnesses
        .iter()
        .filter(|(batch_id, _)| {
            onchain_submissions
                .get(*batch_id)
                .map(onchain_submission_has_succeeded)
                .unwrap_or(false)
        })
        .map(|(_, witness)| witness.clone())
        .collect()
}

async fn confirmed_settlement_witnesses(state: &AppState) -> Vec<SettlementWitness> {
    let settlement_witnesses = state.settlement_witnesses.read().await;
    let onchain_submissions = state.onchain_submissions.read().await;
    confirmed_settlement_witnesses_from_maps(&settlement_witnesses, &onchain_submissions)
}

fn consumed_nullifier_set(
    consumed_inputs: &[ConsumedInput],
) -> Result<BTreeSet<String>, StatusCode> {
    consumed_inputs
        .iter()
        .map(|input| {
            normalize_felt_hex(&input.nullifier.0).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        })
        .collect()
}

fn record_uses_spent_funding(
    record: &DecryptedOrderRecord,
    spent_nullifiers: &BTreeSet<String>,
) -> Result<bool, StatusCode> {
    for input in consumed_inputs_for_notes(&record.funding_notes)? {
        let nullifier = normalize_felt_hex(&input.nullifier.0)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if spent_nullifiers.contains(&nullifier) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn submit_note_consolidation_inner(
    state: &AppState,
    witness: NoteConsolidationWitness,
) -> Result<NoteConsolidationSubmitResponse, StatusCode> {
    if state.starknet_executor.is_none() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    if normalize_felt_hex(&witness.auction_verifier_address).map_err(|_| StatusCode::CONFLICT)?
        != normalize_felt_hex(&state.auction_verifier_address).map_err(|_| StatusCode::CONFLICT)?
    {
        return Err(StatusCode::CONFLICT);
    }
    let consolidation_id = witness.consolidation_id.0.clone();
    {
        let note_consolidation_history = state.note_consolidation_history.read().await;
        if note_consolidation_history.contains_key(&consolidation_id) {
            return Err(StatusCode::CONFLICT);
        }
    }
    let consolidation_consumed_inputs = consumed_inputs_for_notes(&witness.input_notes)?;
    let serialized_native_witness =
        build_note_consolidation_serialized_input(&witness).map_err(|_| StatusCode::CONFLICT)?;
    let consolidation_commitment =
        note_consolidation_commitment(&witness).map_err(|_| StatusCode::CONFLICT)?;
    let statement_message = native_note_consolidation_message_hash(
        &state.auction_verifier_address,
        &consolidation_commitment,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    let expected_message_hash = note_consolidation_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &consolidation_commitment,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    let plan = build_note_consolidation_submission_plan(
        &witness,
        &state.auction_verifier_address,
        &statement_message,
    )
    .map_err(|_| StatusCode::CONFLICT)?;

    record_note_consolidation_status(state, &witness, "proving", None, false, false, None).await?;
    let tx_prover_url = state.native_tx_prover_url.clone();
    let executor = state
        .starknet_executor
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let stage_key = format!("{consolidation_id}-note-consolidation");
    let proof = match execute_native_statement_prover(NativeStatementProverRequest {
        state,
        tx_prover_url: &tx_prover_url,
        executor: &executor,
        batch_id: &consolidation_id,
        stage_key: &stage_key,
        entrypoint: "compile_note_consolidation_proof",
        serialized_native_witness: &serialized_native_witness,
        expected_message_hashes: &[expected_message_hash],
    })
    .await
    {
        Ok(proof) => proof,
        Err(error) => {
            record_note_consolidation_status(
                state,
                &witness,
                "proving-failed",
                Some(error),
                false,
                false,
                None,
            )
            .await?;
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let (proof_body, proof_facts) = read_native_proof_bundle(
        &proof.proof_path,
        &proof.proof_facts_path,
        "note-consolidation",
    )
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    record_note_consolidation_status(
        state,
        &witness,
        "proof-generated",
        None,
        true,
        false,
        Some(plan.consolidation_call.calldata.len() as u64),
    )
    .await?;

    let tx_hash = match submit_native_invoke_with_typed_sdk_retry(
        state,
        &executor,
        &plan.consolidation_call,
        proof_body,
        &proof_facts,
    )
    .await
    {
        Ok(tx_hash) => tx_hash,
        Err(error) => {
            record_note_consolidation_status(
                state,
                &witness,
                "onchain-submit-failed",
                Some(error),
                true,
                false,
                Some(plan.consolidation_call.calldata.len() as u64),
            )
            .await?;
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    let provider = JsonRpcClient::new(starknet_http_transport(
        Url::parse(&executor.rpc_url).map_err(|_| StatusCode::BAD_GATEWAY)?,
    ));
    let mut submission = OnchainSubmissionRecord {
        submission_id: format!("{consolidation_id}:{tx_hash}"),
        batch_id: witness.consolidation_id.clone(),
        transaction_hash: tx_hash.clone(),
        submitted_at_unix_ms: now_unix_ms(),
        receipt_checked_at_unix_ms: None,
        confirmed_at_unix_ms: None,
        finality_status: None,
        execution_status: None,
        revert_reason: None,
        block_number: None,
        block_hash: None,
        block_timestamp_unix_ms: None,
        submission_mode: "native-note-consolidation-proof-facts".into(),
        settlement_contract_address: plan.consolidation_call.contract_address.clone(),
    };
    populate_submission_receipt_status(
        &mut submission,
        wait_for_accepted_receipt(
            &provider,
            parse_felt(&tx_hash, "note consolidation transaction hash")
                .map_err(|_| StatusCode::BAD_GATEWAY)?,
        )
        .await,
    );
    if matches!(submission.execution_status.as_deref(), Some("REVERTED")) {
        record_note_consolidation_status(
            state,
            &witness,
            "onchain-reverted",
            submission.revert_reason.clone(),
            true,
            true,
            Some(plan.consolidation_call.calldata.len() as u64),
        )
        .await?;
        return Err(StatusCode::BAD_GATEWAY);
    }
    if let Some(block_number) = submission.block_number
        && let Ok(block_timestamp) = fetch_block_timestamp_unix_ms(&provider, block_number).await
    {
        submission.block_timestamp_unix_ms = Some(block_timestamp);
    }
    {
        let mut submissions = state.onchain_submissions.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &mut submissions,
            consolidation_id.clone(),
            submission.clone(),
        )?;
    }
    {
        let history = NoteConsolidationHistoryRecord {
            consolidation_id: witness.consolidation_id.clone(),
            consumed_inputs: consolidation_consumed_inputs,
            output_notes: witness.output_notes.clone(),
        };
        let mut note_consolidation_history = state.note_consolidation_history.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            NOTE_CONSOLIDATION_HISTORY_DIR,
            &mut note_consolidation_history,
            consolidation_id.clone(),
            history,
        )?;
    }
    record_note_consolidation_status(
        state,
        &witness,
        if matches!(
            submission.finality_status.as_deref(),
            Some("ACCEPTED_ON_L1" | "ACCEPTED_ON_L2")
        ) {
            "confirmed-onchain"
        } else {
            "submitted-onchain"
        },
        submission.revert_reason.clone(),
        true,
        true,
        Some(plan.consolidation_call.calldata.len() as u64),
    )
    .await?;

    Ok(NoteConsolidationSubmitResponse {
        consolidation_id,
        transaction_hash: tx_hash,
        finality_status: submission.finality_status,
        execution_status: submission.execution_status,
        settled_at_unix_ms: submission
            .block_timestamp_unix_ms
            .or(submission.confirmed_at_unix_ms),
        output_note_commitments: witness
            .output_notes
            .iter()
            .map(|note| note.note_commitment.0.clone())
            .collect(),
    })
}

fn settlement_output_withdrawal_key(witness: &SettlementOutputWithdrawalWitness) -> String {
    normalize_felt_hex(&witness.output_note.note_commitment.0)
        .unwrap_or_else(|_| witness.output_note.note_commitment.0.clone())
}

fn settlement_output_withdrawal_consumed_input_key(record: &ConsumedInput) -> String {
    normalize_felt_hex(&record.note_commitment.0)
        .unwrap_or_else(|_| record.note_commitment.0.clone())
}

fn onchain_submission_storage_key(record: &OnchainSubmissionRecord) -> String {
    record
        .submission_id
        .split_once(':')
        .map(|(key, _)| key)
        .filter(|key| !key.is_empty())
        .unwrap_or(&record.batch_id.0)
        .to_owned()
}

fn settlement_output_withdrawal_revert_status(revert_reason: Option<&str>) -> StatusCode {
    let Some(reason) = revert_reason else {
        return StatusCode::CONFLICT;
    };
    let normalized = reason.to_ascii_lowercase();
    if normalized.contains("claim_window_closed")
        || normalized.contains("claim window closed")
        || normalized.contains("claim window")
            && (normalized.contains("closed") || normalized.contains("not open"))
    {
        return StatusCode::TOO_EARLY;
    }
    StatusCode::CONFLICT
}

fn settlement_output_withdrawal_submit_error_status(error: &str) -> StatusCode {
    let revert_status = settlement_output_withdrawal_revert_status(Some(error));
    if revert_status == StatusCode::TOO_EARLY {
        return revert_status;
    }
    StatusCode::BAD_GATEWAY
}

async fn submit_settlement_output_withdrawal_inner(
    state: &AppState,
    witness: SettlementOutputWithdrawalWitness,
) -> Result<SettlementOutputWithdrawalSubmitResponse, StatusCode> {
    if state.starknet_executor.is_none() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    if normalize_felt_hex(&witness.auction_verifier_address).map_err(|_| StatusCode::CONFLICT)?
        != normalize_felt_hex(&state.auction_verifier_address).map_err(|_| StatusCode::CONFLICT)?
    {
        return Err(StatusCode::CONFLICT);
    }
    if normalize_felt_hex(&witness.shielded_asset_adapter_address)
        .map_err(|_| StatusCode::CONFLICT)?
        != normalize_felt_hex(&state.shielded_asset_adapter_address)
            .map_err(|_| StatusCode::CONFLICT)?
    {
        return Err(StatusCode::CONFLICT);
    }
    let withdrawal_key = settlement_output_withdrawal_key(&witness);
    let withdrawal_consumed_input =
        consumed_inputs_for_notes(std::slice::from_ref(&witness.output_note_preimage))?
            .into_iter()
            .next()
            .ok_or(StatusCode::CONFLICT)?;
    {
        let withdrawal_nullifiers = state.settlement_output_withdrawal_nullifiers.read().await;
        if withdrawal_nullifiers.contains_key(&withdrawal_key) {
            return Err(StatusCode::CONFLICT);
        }
    }
    let serialized_native_witness = build_settlement_output_withdrawal_serialized_input(&witness)
        .map_err(|_| StatusCode::CONFLICT)?;
    let withdrawal_commitment =
        settlement_output_withdrawal_commitment(&witness).map_err(|_| StatusCode::CONFLICT)?;
    let statement_message = native_settlement_output_withdrawal_message_hash(
        &state.auction_verifier_address,
        &withdrawal_commitment,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    let expected_message_hash = settlement_output_withdrawal_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &withdrawal_commitment,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    let plan = build_settlement_output_withdrawal_submission_plan_from_witness(
        &witness,
        &state.auction_verifier_address,
        &statement_message,
    )
    .map_err(|_| StatusCode::CONFLICT)?;

    let tx_prover_url = state.native_tx_prover_url.clone();
    let executor = state
        .starknet_executor
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let stage_key = format!("{withdrawal_key}-withdrawal");
    let proof_started_at = now_unix_ms();
    let proof_result = execute_native_statement_prover(NativeStatementProverRequest {
        state,
        tx_prover_url: &tx_prover_url,
        executor: &executor,
        batch_id: &witness.batch_id.0,
        stage_key: &stage_key,
        entrypoint: "compile_withdrawal_proof",
        serialized_native_witness: &serialized_native_witness,
        expected_message_hashes: &[expected_message_hash],
    })
    .await;
    state.proof_lifecycle_metrics.record(
        "withdrawal_proof_generation",
        if proof_result.is_ok() {
            "success"
        } else {
            "error"
        },
        now_unix_ms().saturating_sub(proof_started_at),
    );
    let proof = proof_result.map_err(|error| {
        let sanitized_error = sanitize_native_prover_error_text(&error);
        eprintln!(
            "settlement output withdrawal proof generation failed batch={} error={sanitized_error}",
            witness.batch_id.0,
        );
        StatusCode::BAD_GATEWAY
    })?;
    let (proof_body, proof_facts) = read_native_proof_bundle(
        &proof.proof_path,
        &proof.proof_facts_path,
        "settlement-output-withdrawal",
    )
    .map_err(|error| {
        let sanitized_error = sanitize_native_prover_error_text(&error);
        eprintln!(
            "settlement output withdrawal proof bundle read failed batch={} error={sanitized_error}",
            witness.batch_id.0,
        );
        StatusCode::BAD_GATEWAY
    })?;
    let submit_started_at = now_unix_ms();
    let submit_result = submit_native_invoke_with_typed_sdk_retry(
        state,
        &executor,
        &plan.starknet_call,
        proof_body,
        &proof_facts,
    )
    .await;
    state.proof_lifecycle_metrics.record(
        "withdrawal_onchain_submit",
        if submit_result.is_ok() {
            "success"
        } else {
            "error"
        },
        now_unix_ms().saturating_sub(submit_started_at),
    );
    let tx_hash = submit_result.map_err(|error| {
        let status = settlement_output_withdrawal_submit_error_status(&error.to_string());
        let sanitized_error = sanitize_native_prover_error_text(&error.to_string());
        eprintln!(
            "settlement output withdrawal onchain submit failed batch={} error={sanitized_error}",
            witness.batch_id.0,
        );
        status
    })?;

    let provider = JsonRpcClient::new(starknet_http_transport(
        Url::parse(&executor.rpc_url).map_err(|_| StatusCode::BAD_GATEWAY)?,
    ));
    let mut submission = OnchainSubmissionRecord {
        submission_id: format!("{withdrawal_key}:{tx_hash}"),
        batch_id: witness.batch_id.clone(),
        transaction_hash: tx_hash.clone(),
        submitted_at_unix_ms: now_unix_ms(),
        receipt_checked_at_unix_ms: None,
        confirmed_at_unix_ms: None,
        finality_status: None,
        execution_status: None,
        revert_reason: None,
        block_number: None,
        block_hash: None,
        block_timestamp_unix_ms: None,
        submission_mode: "native-settlement-output-withdrawal-proof-facts".into(),
        settlement_contract_address: plan.starknet_call.contract_address.clone(),
    };
    populate_submission_receipt_status(
        &mut submission,
        wait_for_accepted_receipt(
            &provider,
            parse_felt(&tx_hash, "withdrawal transaction hash")
                .map_err(|_| StatusCode::BAD_GATEWAY)?,
        )
        .await,
    );
    if matches!(submission.execution_status.as_deref(), Some("REVERTED")) {
        let sanitized_reason = submission
            .revert_reason
            .as_deref()
            .map(sanitize_native_prover_error_text)
            .unwrap_or_else(|| "none".into());
        eprintln!(
            "settlement output withdrawal reverted batch={} tx={} reason={}",
            witness.batch_id.0, tx_hash, sanitized_reason,
        );
        return Err(settlement_output_withdrawal_revert_status(
            submission.revert_reason.as_deref(),
        ));
    }
    if let Some(block_number) = submission.block_number
        && let Ok(block_timestamp) = fetch_block_timestamp_unix_ms(&provider, block_number).await
    {
        submission.block_timestamp_unix_ms = Some(block_timestamp);
    }
    {
        let mut submissions = state.onchain_submissions.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &mut submissions,
            withdrawal_key.clone(),
            submission.clone(),
        )?;
    }
    {
        let mut withdrawal_nullifiers = state.settlement_output_withdrawal_nullifiers.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            SETTLEMENT_OUTPUT_WITHDRAWAL_NULLIFIERS_DIR,
            &mut withdrawal_nullifiers,
            withdrawal_key.clone(),
            withdrawal_consumed_input,
        )?;
    }

    Ok(SettlementOutputWithdrawalSubmitResponse {
        batch_id: witness.batch_id.0,
        note_commitment: witness.output_note.note_commitment.0,
        strk20_exit_commitment: witness.strk20_exit_commitment,
        transaction_hash: tx_hash,
        finality_status: submission.finality_status,
        execution_status: submission.execution_status,
        settled_at_unix_ms: submission
            .block_timestamp_unix_ms
            .or(submission.confirmed_at_unix_ms),
    })
}

async fn record_note_consolidation_status(
    state: &AppState,
    witness: &NoteConsolidationWitness,
    next_state: &str,
    last_error: Option<String>,
    proof_artifact_available: bool,
    onchain_submission_available: bool,
    settlement_calldata_len: Option<u64>,
) -> Result<(), StatusCode> {
    let batch_id = witness.consolidation_id.0.clone();
    let consolidation_commitment =
        note_consolidation_commitment(witness).map_err(|_| StatusCode::CONFLICT)?;
    let now = now_unix_ms();
    let mut proof_jobs = state.proof_jobs.write().await;
    let mut status = proof_jobs
        .get(&batch_id)
        .cloned()
        .unwrap_or_else(|| ProofJobStatus {
            batch_id: witness.consolidation_id.clone(),
            state: next_state.into(),
            transcript_commitment: consolidation_commitment.clone(),
            matched_order_count: 0,
            settlement_plan_available: false,
            witness_available: true,
            proof_artifact_available,
            onchain_submission_available,
            proof_artifact_id: None,
            onchain_submission_id: None,
            prover_backend: prover_backend_label(),
            last_error: None,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            settlement_contract_address: state.auction_verifier_address.clone(),
            settlement_entrypoint: "submit_note_consolidation_with_proof_facts".into(),
            settlement_calldata_len: settlement_calldata_len.unwrap_or(0),
        });
    status.state = next_state.into();
    status.transcript_commitment = consolidation_commitment;
    status.witness_available = true;
    status.proof_artifact_available = proof_artifact_available;
    status.onchain_submission_available = onchain_submission_available;
    status.last_error = last_error;
    if let Some(len) = settlement_calldata_len {
        status.settlement_calldata_len = len;
        status.settlement_plan_available = true;
    }
    status.updated_at_unix_ms = now;
    persist_record_and_insert(
        state.data_dir.as_ref(),
        PROOF_JOBS_DIR,
        &mut proof_jobs,
        batch_id,
        status,
    )?;
    Ok(())
}

async fn ingest_private_order_payload(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<TrustedOrderIngressRequest>,
) -> Result<Json<TrustedOrderIngressResponse>, StatusCode> {
    let started_at_unix_ms = now_unix_ms();
    let ingress_telemetry = request.ingress_telemetry.clone();
    let result = async {
        require_prover_not_paused(&state)?;
        enforce_rate_limit(
            &state.rate_limiter,
            &headers,
            peer,
            "private-order-ingress",
            state.private_ingress_rate_limit_per_minute,
        )?;
        prune_private_order_payloads(&state).await?;
        let receipt_secret = state
            .order_ingress_receipt_secret
            .as_deref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let TrustedOrderIngressRequest {
            order_submission: submission,
            renewal_package_id,
            renewal_package_commitment,
            renewal_relay_mode,
            renewal_slot_order_commitment,
            renewal_slot_pair,
            renewal_slot_batch_id,
            renewal_slot_epoch_id,
            ingress_telemetry: _,
            padding: _padding,
        } = request;
        if submission.order_bundle.ingress_receipt.is_some() {
            return Err(reject_private_ingress("client supplied an ingress receipt"));
        }
        let payload_commitment = private_order_payload_commitment(&submission.order_bundle)
            .map_err(|_| reject_private_ingress("payload commitment failed"))?;
        let order_commitment = submission.order_bundle.order_commitment.clone();

        {
            let private_order_payloads = state.private_order_payloads.read().await;
            if let Some(existing) = private_order_payloads.get(&order_commitment.0) {
                if existing.payload_commitment != payload_commitment {
                    return Err(StatusCode::CONFLICT);
                }
                let coordinator_submission = sanitize_order_submission_for_coordinator(
                    &OrderSubmission {
                        order_bundle: existing.order_bundle.clone(),
                    },
                    existing.receipt.clone(),
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                return Ok(Json(TrustedOrderIngressResponse {
                    receipt: existing.receipt.clone(),
                    coordinator_submission,
                    padding: Some(private_ingress_response_padding()),
                }));
            }
        }

        let private_payload =
            decrypt_order_bundle(&submission.order_bundle, &state.auction_private_keys)
                .map_err(|_| reject_private_ingress("payload decryption failed"))?;
        let reconstructed_order_commitment = private_payload
            .order
            .commitment()
            .map_err(|_| reject_private_ingress("order commitment reconstruction failed"))?;
        if reconstructed_order_commitment != order_commitment {
            return Err(reject_private_ingress("order commitment mismatch"));
        }
        if submission.order_bundle.pair_id != private_payload.order.pair_id {
            return Err(reject_private_ingress("pair mismatch"));
        }
        if submission.order_bundle.batch_id != private_payload.order.batch_id {
            return Err(reject_private_ingress("batch mismatch"));
        }
        if submission.order_bundle.epoch_id != private_payload.order.expiry_epoch {
            return Err(reject_private_ingress("epoch mismatch"));
        }

        state
            .product_config
            .validate_order_funding_notes(
                &private_payload.order,
                &private_payload
                    .effective_funding_notes()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| reject_private_ingress("funding notes are invalid"))?;
        validate_private_order_risk_limits(&state, &private_payload.order)
            .map_err(|_| reject_private_ingress("order risk limits rejected"))?;
        if let Some(expected_relay_mode) = renewal_relay_mode.as_ref()
            && expected_relay_mode != &private_payload.order.relay_mode
        {
            return Err(reject_private_ingress("renewal relay mode mismatch"));
        }
        if renewal_package_id.is_some() != renewal_package_commitment.is_some() {
            return Err(reject_private_ingress(
                "renewal package attestation incomplete",
            ));
        }
        if renewal_package_id.is_some() && renewal_relay_mode.is_none() {
            return Err(reject_private_ingress(
                "renewal package attestation missing relay mode",
            ));
        }
        if matches!(private_payload.order.relay_mode, RelayMode::ZylithRelay)
            && (renewal_package_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
                || renewal_package_commitment
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none()
                || renewal_relay_mode.as_ref() != Some(&RelayMode::ZylithRelay))
        {
            return Err(reject_private_ingress(
                "Zylith relay orders require a renewal package attestation",
            ));
        }
        let has_renewal_slot_attestation = renewal_slot_order_commitment.is_some()
            || renewal_slot_pair.is_some()
            || renewal_slot_batch_id.is_some()
            || renewal_slot_epoch_id.is_some();
        if !matches!(private_payload.order.relay_mode, RelayMode::ZylithRelay)
            && has_renewal_slot_attestation
        {
            return Err(reject_private_ingress(
                "renewal slot attestation is only valid for Zylith relay orders",
            ));
        }
        if matches!(private_payload.order.relay_mode, RelayMode::ZylithRelay)
            && (renewal_slot_order_commitment.as_deref() != Some(order_commitment.0.as_str())
                || renewal_slot_pair.as_deref() != Some(private_payload.order.pair_id.0.as_str())
                || renewal_slot_batch_id.as_deref()
                    != Some(private_payload.order.batch_id.0.as_str())
                || renewal_slot_epoch_id != Some(private_payload.order.expiry_epoch))
        {
            return Err(reject_private_ingress(
                "Zylith relay orders require a matching renewal slot attestation",
            ));
        }
        if matches!(private_payload.order.relay_mode, RelayMode::ZylithRelay) {
            verify_hosted_relay_order_attestation(
                &state,
                renewal_package_id.as_deref().unwrap_or_default(),
                renewal_package_commitment.as_deref().unwrap_or_default(),
                &private_payload.order,
                &order_commitment,
            )
            .await?;
        }

        let receipt = create_order_ingress_receipt(
            &submission.order_bundle,
            &state.order_ingress_id,
            "zylith-prover",
            receipt_secret,
            now_unix_ms(),
            OrderIngressReceiptAttestation {
                relay_mode: Some(private_payload.order.relay_mode.clone()),
                renewal_package_id,
                renewal_package_commitment,
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let coordinator_submission =
            sanitize_order_submission_for_coordinator(&submission, receipt.clone())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let record = PrivateOrderPayloadRecord {
            order_commitment: order_commitment.clone(),
            payload_commitment,
            received_at_unix_ms: now_unix_ms(),
            receipt: receipt.clone(),
            order_bundle: submission.order_bundle,
        };

        {
            let mut private_order_payloads = state.private_order_payloads.write().await;
            if state.max_stored_private_payloads > 0
                && private_order_payloads.len() >= state.max_stored_private_payloads
            {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            persist_record_and_insert(
                state.data_dir.as_ref(),
                PRIVATE_ORDER_PAYLOADS_DIR,
                &mut private_order_payloads,
                order_commitment.0.clone(),
                record,
            )?;
        }

        Ok(Json(TrustedOrderIngressResponse {
            receipt,
            coordinator_submission,
            padding: Some(private_ingress_response_padding()),
        }))
    }
    .await;
    state.private_ingress_metrics.record(
        private_ingress_outcome_label(&result),
        now_unix_ms().saturating_sub(started_at_unix_ms),
        Some(&ingress_telemetry),
    );
    result
}

fn private_ingress_response_padding() -> String {
    "0".repeat(512)
}

fn private_ingress_outcome_label<T>(result: &Result<T, StatusCode>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(StatusCode::CONFLICT) => "duplicate_conflict",
        Err(StatusCode::TOO_MANY_REQUESTS) => "rate_limited",
        Err(StatusCode::BAD_REQUEST) => "bad_request",
        Err(StatusCode::SERVICE_UNAVAILABLE) => "unavailable",
        Err(_) => "rejected",
    }
}

async fn ingest_private_liquidity_position_payload(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<TrustedLiquidityPositionIngressRequest>,
) -> Result<Json<TrustedLiquidityPositionIngressResponse>, StatusCode> {
    let started_at_unix_ms = now_unix_ms();
    let ingress_telemetry = request.ingress_telemetry.clone();
    let result = async {
        require_prover_not_paused(&state)?;
        enforce_rate_limit(
            &state.rate_limiter,
            &headers,
            peer,
            "private-liquidity-position-ingress",
            state.private_ingress_rate_limit_per_minute,
        )?;
        prune_private_liquidity_position_payloads(&state).await?;
        let receipt_secret = state
            .order_ingress_receipt_secret
            .as_deref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let TrustedLiquidityPositionIngressRequest {
            pair_id,
            batch_id,
            epoch_id,
            transition_witness,
            ingress_telemetry: _,
            padding: _padding,
        } = request;
        validate_private_liquidity_position_ingress_request(
            &pair_id,
            &batch_id,
            epoch_id,
            &transition_witness,
        )?;
        let transition_commitment = liquidity_position_transition_commitment(&transition_witness)
            .map_err(|_| {
            reject_private_ingress("liquidity position transition commitment failed")
        })?;
        let lifecycle_id =
            liquidity_position_lifecycle_id(&pair_id, &batch_id, epoch_id, &transition_commitment)
                .map_err(|_| reject_private_ingress("liquidity position lifecycle id failed"))?;
        let payload_commitment = liquidity_position_transition_witness_payload_commitment(
            &transition_witness,
        )
        .map_err(|_| reject_private_ingress("liquidity position payload commitment failed"))?;

        {
            let private_payloads = state.private_liquidity_position_payloads.read().await;
            if let Some(existing) = private_payloads.get(&lifecycle_id) {
                if existing.payload_commitment != payload_commitment
                    || existing.transition_commitment != transition_commitment
                {
                    return Err(StatusCode::CONFLICT);
                }
                let coordinator_submission = LiquidityPositionLifecycleSubmission {
                    lifecycle_id: existing.lifecycle_id.clone(),
                    pair_id: existing.pair_id.clone(),
                    batch_id: existing.batch_id.clone(),
                    epoch_id: existing.epoch_id,
                    transition_commitment: existing.transition_commitment.clone(),
                    ingress_receipt: Some(existing.receipt.clone()),
                };
                return Ok(Json(TrustedLiquidityPositionIngressResponse {
                    receipt: existing.receipt.clone(),
                    coordinator_submission,
                    padding: Some(private_ingress_response_padding()),
                }));
            }
        }

        let manifest = LiquidityPositionLifecycleSubmission {
            lifecycle_id: lifecycle_id.clone(),
            pair_id: pair_id.clone(),
            batch_id: batch_id.clone(),
            epoch_id,
            transition_commitment: transition_commitment.clone(),
            ingress_receipt: None,
        };
        let receipt = create_liquidity_position_ingress_receipt(
            &manifest,
            &payload_commitment,
            &state.order_ingress_id,
            "zylith-prover",
            receipt_secret,
            now_unix_ms(),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let coordinator_submission = LiquidityPositionLifecycleSubmission {
            ingress_receipt: Some(receipt.clone()),
            ..manifest
        };
        let record = PrivateLiquidityPositionPayloadRecord {
            lifecycle_id: lifecycle_id.clone(),
            pair_id,
            batch_id,
            epoch_id,
            transition_commitment,
            payload_commitment,
            received_at_unix_ms: now_unix_ms(),
            receipt: receipt.clone(),
            transition_witness,
        };
        {
            let mut private_payloads = state.private_liquidity_position_payloads.write().await;
            if state.max_stored_private_payloads > 0
                && private_payloads.len() >= state.max_stored_private_payloads
            {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            persist_record_and_insert(
                state.data_dir.as_ref(),
                PRIVATE_LIQUIDITY_POSITION_PAYLOADS_DIR,
                &mut private_payloads,
                lifecycle_id,
                record,
            )?;
        }

        Ok(Json(TrustedLiquidityPositionIngressResponse {
            receipt,
            coordinator_submission,
            padding: Some(private_ingress_response_padding()),
        }))
    }
    .await;
    state.private_ingress_metrics.record(
        private_ingress_outcome_label(&result),
        now_unix_ms().saturating_sub(started_at_unix_ms),
        Some(&ingress_telemetry),
    );
    result
}

async fn prepare_liquidity_position_insertion_witness(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<LiquidityPositionInsertionWitnessRequest>,
) -> Result<Json<LiquidityPositionInsertionWitnessResponse>, StatusCode> {
    require_prover_not_paused(&state)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "private-liquidity-position-insertion-witness",
        state.private_ingress_rate_limit_per_minute,
    )?;
    let requested_prior_root = match request.prior_liquidity_position_root.clone() {
        Some(root) => root,
        None => {
            fetch_current_settlement_roots(&state)
                .await?
                .liquidity_position_root
        }
    };
    let prior_root =
        normalize_felt_hex(&requested_prior_root).map_err(|_| StatusCode::BAD_REQUEST)?;
    let position_id =
        normalize_felt_hex(&request.position_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let output_commitment = LiquidityPositionCommitment(
        normalize_felt_hex(&request.output_commitment.0).map_err(|_| StatusCode::BAD_REQUEST)?,
    );
    let confirmed = confirmed_settlement_witnesses(&state).await;
    let book = active_liquidity_position_book_for_root(&prior_root, &confirmed)?;
    let state_service = book.state()?;
    let (computed_prior_root, new_root, state_update) = state_service
        .insertion_update(&position_id, output_commitment)
        .map_err(|error| {
            eprintln!("liquidity position insertion witness rejected: {error}");
            StatusCode::CONFLICT
        })?;
    if computed_prior_root != prior_root {
        return Err(StatusCode::CONFLICT);
    }
    Ok(Json(LiquidityPositionInsertionWitnessResponse {
        prior_liquidity_position_root: prior_root,
        new_liquidity_position_root: new_root,
        active_position_count: book.positions.len(),
        state_update,
        padding: request
            .padding
            .map(|padding| "0".repeat(padding.len().min(2048))),
    }))
}

async fn get_private_liquidity_position_state(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<LiquidityPositionStateRequest>,
) -> Result<Json<LiquidityPositionStateResponse>, StatusCode> {
    require_prover_not_paused(&state)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "private-liquidity-position-state",
        state.private_ingress_rate_limit_per_minute,
    )?;
    let requested_prior_root = match request.prior_liquidity_position_root.clone() {
        Some(root) => root,
        None => {
            fetch_current_settlement_roots(&state)
                .await?
                .liquidity_position_root
        }
    };
    let prior_root =
        normalize_felt_hex(&requested_prior_root).map_err(|_| StatusCode::BAD_REQUEST)?;
    let position_id =
        normalize_felt_hex(&request.position_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let owner_authority =
        normalize_felt_hex(&request.owner_authority).map_err(|_| StatusCode::BAD_REQUEST)?;
    let confirmed = confirmed_settlement_witnesses(&state).await;
    let book = active_liquidity_position_book_for_root(&prior_root, &confirmed)?;
    let position = book
        .positions
        .get(&position_id)
        .filter(|record| {
            normalize_felt_hex(&record.position.owner_authority)
                .map(|normalized| normalized == owner_authority)
                .unwrap_or(false)
        })
        .map(|record| record.position.clone())
        .ok_or(StatusCode::NOT_FOUND)?;
    let position_commitment = position.commitment().map_err(|error| {
        eprintln!("active liquidity position commitment failed: {error}");
        StatusCode::CONFLICT
    })?;
    Ok(Json(LiquidityPositionStateResponse {
        prior_liquidity_position_root: prior_root,
        position,
        position_commitment,
        active_position_count: book.positions.len(),
        padding: request
            .padding
            .map(|padding| "0".repeat(padding.len().min(2048))),
    }))
}

async fn prepare_liquidity_position_state_update_witness(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<LiquidityPositionStateUpdateWitnessRequest>,
) -> Result<Json<LiquidityPositionInsertionWitnessResponse>, StatusCode> {
    require_prover_not_paused(&state)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "private-liquidity-position-state-update-witness",
        state.private_ingress_rate_limit_per_minute,
    )?;
    let requested_prior_root = match request.prior_liquidity_position_root.clone() {
        Some(root) => root,
        None => {
            fetch_current_settlement_roots(&state)
                .await?
                .liquidity_position_root
        }
    };
    let prior_root =
        normalize_felt_hex(&requested_prior_root).map_err(|_| StatusCode::BAD_REQUEST)?;
    let position_id =
        normalize_felt_hex(&request.position_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let prior_commitment = LiquidityPositionCommitment(
        normalize_felt_hex(&request.prior_commitment.0).map_err(|_| StatusCode::BAD_REQUEST)?,
    );
    let output_commitment = request
        .output_commitment
        .map(|commitment| {
            normalize_felt_hex(&commitment.0)
                .map(LiquidityPositionCommitment)
                .map_err(|_| StatusCode::BAD_REQUEST)
        })
        .transpose()?;
    let confirmed = confirmed_settlement_witnesses(&state).await;
    let book = active_liquidity_position_book_for_root(&prior_root, &confirmed)?;
    let state_service = book.state()?;
    let (computed_prior_root, new_root, state_update) = match request.kind {
        LiquidityPositionStateUpdateWitnessKind::Reconfigure => {
            let output_commitment = output_commitment.ok_or(StatusCode::BAD_REQUEST)?;
            state_service.replacement_update(&position_id, prior_commitment, output_commitment)
        }
        LiquidityPositionStateUpdateWitnessKind::Close => {
            if output_commitment.is_some() {
                return Err(StatusCode::BAD_REQUEST);
            }
            state_service.removal_update(&position_id, prior_commitment)
        }
    }
    .map_err(|error| {
        eprintln!("liquidity position state update witness rejected: {error}");
        StatusCode::CONFLICT
    })?;
    if computed_prior_root != prior_root {
        return Err(StatusCode::CONFLICT);
    }
    Ok(Json(LiquidityPositionInsertionWitnessResponse {
        prior_liquidity_position_root: prior_root,
        new_liquidity_position_root: new_root,
        active_position_count: book.positions.len(),
        state_update,
        padding: request
            .padding
            .map(|padding| "0".repeat(padding.len().min(2048))),
    }))
}

fn active_liquidity_position_book_for_root(
    expected_root: &str,
    historical_witnesses: &[SettlementWitness],
) -> Result<ActiveLiquidityPositionBook, StatusCode> {
    let expected_root = normalize_felt_hex(expected_root).map_err(|_| StatusCode::CONFLICT)?;
    let mut book = ActiveLiquidityPositionBook::default();
    let mut running_root = "0x0".to_string();
    let mut history = historical_witnesses.to_vec();
    history.sort_by(|left, right| {
        left.batch_epoch
            .cmp(&right.batch_epoch)
            .then_with(|| left.pair_id.0.cmp(&right.pair_id.0))
            .then_with(|| left.batch_id.0.cmp(&right.batch_id.0))
    });
    for witness in &history {
        let prior_root = normalize_felt_hex(&witness.prior_liquidity_position_root)
            .map_err(|_| StatusCode::CONFLICT)?;
        let new_root = normalize_felt_hex(&witness.new_liquidity_position_root)
            .map_err(|_| StatusCode::CONFLICT)?;
        if prior_root != running_root {
            if witness.liquidity_position_witnesses.is_empty() && prior_root == new_root {
                continue;
            }
            eprintln!(
                "active liquidity position history is not chained expected_prior={} witness_prior={} batch={}",
                running_root, prior_root, witness.batch_id.0
            );
            return Err(StatusCode::CONFLICT);
        }
        for transition_witness in &witness.liquidity_position_witnesses {
            running_root = book.apply_transition_witness(&running_root, transition_witness)?;
        }
        if running_root != new_root {
            eprintln!(
                "active liquidity position history root mismatch batch={} computed={} witness={}",
                witness.batch_id.0, running_root, new_root
            );
            return Err(StatusCode::CONFLICT);
        }
    }
    let recomputed = book.root()?;
    if recomputed != expected_root {
        eprintln!(
            "active liquidity position book does not match expected root computed={} expected={}",
            recomputed, expected_root
        );
        return Err(StatusCode::CONFLICT);
    }
    Ok(book)
}

fn apply_liquidity_position_lifecycle_witnesses(
    mut book: ActiveLiquidityPositionBook,
    prior_root: &str,
    witnesses: &[LiquidityPositionTransitionWitness],
) -> Result<(ActiveLiquidityPositionBook, String, BTreeSet<String>), StatusCode> {
    let mut running_root = normalize_felt_hex(prior_root).map_err(|_| StatusCode::CONFLICT)?;
    let mut touched_positions = BTreeSet::new();
    for witness in witnesses {
        if matches!(
            witness.transition.kind,
            LiquidityPositionTransitionKind::Update
        ) {
            return Err(StatusCode::CONFLICT);
        }
        if let Some(position) = witness
            .prior_position
            .as_ref()
            .or(witness.output_position.as_ref())
        {
            touched_positions.insert(
                normalize_felt_hex(&position.position_id).map_err(|_| StatusCode::CONFLICT)?,
            );
        }
        running_root = book.apply_transition_witness(&running_root, witness)?;
    }
    Ok((book, running_root, touched_positions))
}

fn liquidity_position_fill_sources_for_batch(
    book: &ActiveLiquidityPositionBook,
    pair: &ProductPairConfig,
    epoch: u64,
    observed_at_unix_ms: u64,
    current_time_unix_ms: u64,
    excluded_position_ids: &BTreeSet<String>,
    market_contexts: &LiquidityPositionMarketContexts,
) -> Result<Vec<LiquidityPositionFillSource>, StatusCode> {
    let mut sources = Vec::new();
    for record in book.positions.values() {
        let position = &record.position;
        let position_id =
            normalize_felt_hex(&position.position_id).map_err(|_| StatusCode::CONFLICT)?;
        if excluded_position_ids.contains(&position_id) {
            continue;
        }
        if position.pair_id != pair.pair_id
            || position.base_asset_id != pair.base_asset_id
            || position.quote_asset_id != pair.quote_asset_id
        {
            continue;
        }
        let context = market_contexts.context_for_pair(
            pair,
            epoch,
            observed_at_unix_ms,
            current_time_unix_ms,
        );
        let slice = match derive_liquidity_position_curve_slice(position, &context) {
            Ok(slice) => slice,
            Err(error) => {
                eprintln!(
                    "liquidity position slice skipped position_id={} pair={} reason={error}",
                    safe_position_id(position),
                    pair.pair_id.0
                );
                continue;
            }
        };
        if slice.skipped {
            continue;
        }
        if let Some(bid) = slice.bid {
            push_liquidity_position_fill_source(
                &mut sources,
                position,
                record.owner_public_key.clone(),
                OrderSide::Buy,
                context.clone(),
                bid.points,
            )?;
        }
        if let Some(ask) = slice.ask {
            push_liquidity_position_fill_source(
                &mut sources,
                position,
                record.owner_public_key.clone(),
                OrderSide::Sell,
                context,
                ask.points,
            )?;
        }
    }
    Ok(sources)
}

fn push_liquidity_position_fill_source(
    sources: &mut Vec<LiquidityPositionFillSource>,
    position: &PrivateLiquidityPosition,
    liquidity_provider_public_key: Option<String>,
    side: OrderSide,
    market_context: LiquidityPositionMarketContext,
    points: Vec<LiquidityCurvePoint>,
) -> Result<(), StatusCode> {
    if points.is_empty() {
        return Ok(());
    }
    let available_amount = points.iter().try_fold(0_u128, |total, point| {
        total
            .checked_add(point.base_amount)
            .ok_or(StatusCode::CONFLICT)
    })?;
    if available_amount == 0 {
        return Ok(());
    }
    sources.push(LiquidityPositionFillSource {
        position: position.clone(),
        liquidity_provider_public_key,
        side,
        market_context,
        points,
        available_amount,
    });
    Ok(())
}

fn compute_private_settlement_fill_plan(
    records: &[DecryptedOrderRecord],
    liquidity_position_sources: &[LiquidityPositionFillSource],
    price_base_scale: u128,
) -> Result<PrivateSettlementFillPlan, StatusCode> {
    let candidate_clearing_price = compute_candidate_clearing_price_with_liquidity(
        records,
        liquidity_position_sources,
        price_base_scale,
    )?;
    let clearing_price = candidate_clearing_price.unwrap_or(0);
    let order_fills = compute_fill_plan_with_liquidity(
        records,
        liquidity_position_sources,
        clearing_price,
        price_base_scale,
    )?;
    let liquidity_position_fills = compute_liquidity_position_fill_plan(
        liquidity_position_sources,
        clearing_price,
        &order_fills,
    )?;
    Ok(PrivateSettlementFillPlan {
        clearing_price,
        order_fills,
        liquidity_position_fills,
    })
}

fn compute_candidate_clearing_price_with_liquidity(
    records: &[DecryptedOrderRecord],
    liquidity_position_sources: &[LiquidityPositionFillSource],
    price_base_scale: u128,
) -> Result<Option<u128>, StatusCode> {
    let has_user_order = records.iter().any(|record| {
        !matches!(
            record.order.order_type,
            zylith_core::OrderType::HeartbeatCover
        )
    });
    if !has_user_order {
        return compute_candidate_clearing_price(records, price_base_scale);
    }

    let mut candidate_prices: Vec<u128> = records
        .iter()
        .filter(|record| {
            !matches!(
                record.order.order_type,
                zylith_core::OrderType::HeartbeatCover
            )
        })
        .flat_map(|record| candidate_prices_for_order(&record.order))
        .collect();
    candidate_prices.extend(
        liquidity_position_sources
            .iter()
            .flat_map(|source| source.points.iter().map(|point| point.price)),
    );
    candidate_prices.sort_unstable();
    candidate_prices.dedup();

    let mut best: Option<(u128, u128, u128, u128)> = None;
    for price in candidate_prices {
        let (matched, imbalance) = stable_pruned_score_at_price_with_liquidity(
            records,
            liquidity_position_sources,
            price,
            price_base_scale,
        )?;
        match best {
            None => best = Some((price, price, matched, imbalance)),
            Some((best_low, best_high, best_matched, best_imbalance)) => {
                if matched > best_matched || (matched == best_matched && imbalance < best_imbalance)
                {
                    best = Some((price, price, matched, imbalance));
                } else if matched == best_matched && imbalance == best_imbalance {
                    best = Some((
                        best_low.min(price),
                        best_high.max(price),
                        best_matched,
                        best_imbalance,
                    ));
                }
            }
        }
    }

    Ok(best.map(|(low, high, matched, _)| {
        if matched == 0 {
            low
        } else {
            midpoint_u128(low, high)
        }
    }))
}

fn stable_pruned_score_at_price_with_liquidity(
    records: &[DecryptedOrderRecord],
    liquidity_position_sources: &[LiquidityPositionFillSource],
    price: u128,
    price_base_scale: u128,
) -> Result<(u128, u128), StatusCode> {
    let active_flags = stable_active_flags_with_liquidity(
        records,
        liquidity_position_sources,
        price,
        price_base_scale,
    )?;
    let user_buy_demand = active_capacity_total_checked(
        records,
        &active_flags,
        &OrderSide::Buy,
        price,
        price_base_scale,
    )?;
    let user_sell_supply = active_capacity_total_checked(
        records,
        &active_flags,
        &OrderSide::Sell,
        price,
        price_base_scale,
    )?;
    if user_buy_demand >= user_sell_supply {
        let natural = user_sell_supply;
        let residual_buy = user_buy_demand - user_sell_supply;
        let lp_sell_capacity =
            liquidity_position_capacity_total(liquidity_position_sources, &OrderSide::Sell, price)?;
        let lp_fill = residual_buy.min(lp_sell_capacity);
        Ok((
            natural.checked_add(lp_fill).ok_or(StatusCode::CONFLICT)?,
            residual_buy - lp_fill,
        ))
    } else {
        let natural = user_buy_demand;
        let residual_sell = user_sell_supply - user_buy_demand;
        let lp_buy_capacity =
            liquidity_position_capacity_total(liquidity_position_sources, &OrderSide::Buy, price)?;
        let lp_fill = residual_sell.min(lp_buy_capacity);
        Ok((
            natural.checked_add(lp_fill).ok_or(StatusCode::CONFLICT)?,
            residual_sell - lp_fill,
        ))
    }
}

fn stable_active_flags_with_liquidity(
    records: &[DecryptedOrderRecord],
    liquidity_position_sources: &[LiquidityPositionFillSource],
    price: u128,
    price_base_scale: u128,
) -> Result<Vec<bool>, StatusCode> {
    let mut active_flags = records
        .iter()
        .map(|record| max_fill_at_price(record, price, price_base_scale) > 0)
        .collect::<Vec<_>>();

    for _ in 0..records.len() {
        let mut next_flags = Vec::with_capacity(active_flags.len());
        for (index, active) in active_flags.iter().enumerate() {
            if !*active {
                next_flags.push(false);
                continue;
            }
            let fill = expected_fill_with_active_flags_and_liquidity(
                records,
                liquidity_position_sources,
                &active_flags,
                index,
                price,
                price_base_scale,
            )?;
            if fill == 0 {
                next_flags.push(true);
                continue;
            }
            next_flags.push(
                fill >= records[index].order.min_fill
                    && (!is_fill_or_kill_order(&records[index].order)
                        || fill >= records[index].order.amount),
            );
        }
        if next_flags == active_flags {
            break;
        }
        active_flags = next_flags;
    }

    Ok(active_flags)
}

fn expected_fill_with_active_flags_and_liquidity(
    records: &[DecryptedOrderRecord],
    liquidity_position_sources: &[LiquidityPositionFillSource],
    active_flags: &[bool],
    target_index: usize,
    price: u128,
    price_base_scale: u128,
) -> Result<u128, StatusCode> {
    if !active_flags[target_index] {
        return Ok(0);
    }
    let target = &records[target_index];
    let max_fill = max_fill_at_price(target, price, price_base_scale);
    let opposite_side = match target.order.side {
        OrderSide::Buy => OrderSide::Sell,
        OrderSide::Sell => OrderSide::Buy,
    };
    let opposite_user_total = active_capacity_total_checked(
        records,
        active_flags,
        &opposite_side,
        price,
        price_base_scale,
    )?;
    let opposite_lp_total =
        liquidity_position_capacity_total(liquidity_position_sources, &opposite_side, price)?;
    let opposite_total = opposite_user_total
        .checked_add(opposite_lp_total)
        .ok_or(StatusCode::CONFLICT)?;
    let priority_capacity = active_priority_capacity_before(
        records,
        active_flags,
        target_index,
        price,
        price_base_scale,
    );
    if opposite_total <= priority_capacity {
        return Ok(0);
    }
    Ok(max_fill.min(opposite_total - priority_capacity))
}

fn active_capacity_total_checked(
    records: &[DecryptedOrderRecord],
    active_flags: &[bool],
    side: &OrderSide,
    price: u128,
    price_base_scale: u128,
) -> Result<u128, StatusCode> {
    records
        .iter()
        .zip(active_flags.iter())
        .filter(|(record, active)| **active && &record.order.side == side)
        .try_fold(0_u128, |total, (record, _)| {
            total
                .checked_add(max_fill_at_price(record, price, price_base_scale))
                .ok_or(StatusCode::CONFLICT)
        })
}

fn compute_fill_plan_with_liquidity(
    records: &[DecryptedOrderRecord],
    liquidity_position_sources: &[LiquidityPositionFillSource],
    clearing_price: u128,
    price_base_scale: u128,
) -> Result<Vec<OrderFillPlan>, StatusCode> {
    if clearing_price == 0 {
        return Ok(Vec::new());
    }
    let active_flags = stable_active_flags_with_liquidity(
        records,
        liquidity_position_sources,
        clearing_price,
        price_base_scale,
    )?;
    let mut fills = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if !active_flags[index] || !is_order_eligible(&record.order, clearing_price) {
            continue;
        }
        let filled_amount = expected_fill_with_active_flags_and_liquidity(
            records,
            liquidity_position_sources,
            &active_flags,
            index,
            clearing_price,
            price_base_scale,
        )?;
        if filled_amount == 0 {
            continue;
        }
        fills.push(OrderFillPlan {
            order_commitment: record.order_commitment.clone(),
            cancellation_auth_tag: record.cancellation_auth_tag.clone(),
            order: record.order.clone(),
            funding_note: record.funding_note.clone(),
            funding_notes: record.funding_notes.clone(),
            funding_authorization: record.funding_authorization.clone(),
            filled_amount,
        });
    }
    Ok(fills)
}

fn compute_liquidity_position_fill_plan(
    liquidity_position_sources: &[LiquidityPositionFillSource],
    clearing_price: u128,
    order_fills: &[OrderFillPlan],
) -> Result<Vec<LiquidityPositionFillPlan>, StatusCode> {
    if clearing_price == 0 || order_fills.is_empty() {
        return Ok(Vec::new());
    }
    let mut total_buy_fill = 0_u128;
    let mut total_sell_fill = 0_u128;
    for fill in order_fills {
        match fill.order.side {
            OrderSide::Buy => {
                total_buy_fill = total_buy_fill
                    .checked_add(fill.filled_amount)
                    .ok_or(StatusCode::CONFLICT)?;
            }
            OrderSide::Sell => {
                total_sell_fill = total_sell_fill
                    .checked_add(fill.filled_amount)
                    .ok_or(StatusCode::CONFLICT)?;
            }
        }
    }
    if total_buy_fill == total_sell_fill {
        return Ok(Vec::new());
    }
    let (required_side, required_amount) = if total_buy_fill > total_sell_fill {
        (OrderSide::Sell, total_buy_fill - total_sell_fill)
    } else {
        (OrderSide::Buy, total_sell_fill - total_buy_fill)
    };
    allocate_liquidity_position_fills(
        liquidity_position_sources,
        required_side,
        required_amount,
        clearing_price,
    )
}

fn allocate_liquidity_position_fills(
    liquidity_position_sources: &[LiquidityPositionFillSource],
    required_side: OrderSide,
    required_amount: u128,
    clearing_price: u128,
) -> Result<Vec<LiquidityPositionFillPlan>, StatusCode> {
    if required_amount == 0 {
        return Ok(Vec::new());
    }
    let mut candidates = liquidity_position_sources
        .iter()
        .filter(|source| source.side == required_side)
        .filter_map(|source| {
            let capacity =
                liquidity_position_source_capacity_at_price(source, clearing_price).ok()?;
            (capacity > 0).then_some((source.clone(), capacity))
        })
        .collect::<Vec<_>>();
    sort_liquidity_position_fill_sources(&mut candidates, &required_side, clearing_price);
    let mut remaining = required_amount;
    let mut fills = Vec::new();
    for (source, capacity) in candidates {
        if remaining == 0 {
            break;
        }
        let filled_amount = remaining.min(capacity);
        remaining -= filled_amount;
        fills.push(LiquidityPositionFillPlan {
            source,
            filled_amount,
        });
    }
    if remaining != 0 {
        return Err(StatusCode::CONFLICT);
    }
    Ok(fills)
}

fn sort_liquidity_position_fill_sources(
    sources: &mut [(LiquidityPositionFillSource, u128)],
    side: &OrderSide,
    clearing_price: u128,
) {
    sources.sort_by(|(left, _), (right, _)| {
        let left_price = liquidity_position_source_priority_price(left, clearing_price);
        let right_price = liquidity_position_source_priority_price(right, clearing_price);
        let price_order = match side {
            OrderSide::Buy => right_price.cmp(&left_price),
            OrderSide::Sell => left_price.cmp(&right_price),
        };
        price_order
            .then_with(|| safe_position_id(&left.position).cmp(&safe_position_id(&right.position)))
    });
}

fn liquidity_position_source_priority_price(
    source: &LiquidityPositionFillSource,
    clearing_price: u128,
) -> u128 {
    let prices = source
        .points
        .iter()
        .filter(|point| point_is_executable_for_side(point, &source.side, clearing_price))
        .map(|point| point.price);
    match source.side {
        OrderSide::Buy => prices.max().unwrap_or(clearing_price),
        OrderSide::Sell => prices.min().unwrap_or(clearing_price),
    }
}

fn liquidity_position_capacity_total(
    sources: &[LiquidityPositionFillSource],
    side: &OrderSide,
    clearing_price: u128,
) -> Result<u128, StatusCode> {
    sources
        .iter()
        .filter(|source| &source.side == side)
        .try_fold(0_u128, |total, source| {
            total
                .checked_add(liquidity_position_source_capacity_at_price(
                    source,
                    clearing_price,
                )?)
                .ok_or(StatusCode::CONFLICT)
        })
}

fn liquidity_position_source_capacity_at_price(
    source: &LiquidityPositionFillSource,
    clearing_price: u128,
) -> Result<u128, StatusCode> {
    let capacity = source
        .points
        .iter()
        .filter(|point| point_is_executable_for_side(point, &source.side, clearing_price))
        .try_fold(0_u128, |total, point| {
            total
                .checked_add(point.base_amount)
                .ok_or(StatusCode::CONFLICT)
        })?;
    Ok(capacity.min(source.available_amount))
}

fn point_is_executable_for_side(
    point: &LiquidityCurvePoint,
    side: &OrderSide,
    clearing_price: u128,
) -> bool {
    match side {
        OrderSide::Buy => point.price >= clearing_price,
        OrderSide::Sell => point.price <= clearing_price,
    }
}

fn materialize_liquidity_position_fill_witnesses(
    mut book: ActiveLiquidityPositionBook,
    prior_root: &str,
    fills: &[LiquidityPositionFillPlan],
    batch_id: &str,
    epoch: u64,
    clearing_price: u128,
    price_base_scale: u128,
) -> Result<
    (
        ActiveLiquidityPositionBook,
        String,
        Vec<LiquidityPositionTransitionWitness>,
    ),
    StatusCode,
> {
    let mut state = book.state()?;
    let mut running_root = normalize_felt_hex(prior_root).map_err(|_| StatusCode::CONFLICT)?;
    let mut witnesses = Vec::with_capacity(fills.len());
    for (fill_index, fill_plan) in fills.iter().enumerate() {
        let position_id = normalize_felt_hex(&fill_plan.source.position.position_id)
            .map_err(|_| StatusCode::CONFLICT)?;
        let prior_record = book
            .positions
            .get(&position_id)
            .cloned()
            .ok_or(StatusCode::CONFLICT)?;
        let prior_position = prior_record.position;
        let next_blinding = liquidity_position_fill_blinding(
            batch_id,
            epoch,
            fill_index,
            &running_root,
            &prior_position,
            &fill_plan.source.side,
            fill_plan.filled_amount,
            clearing_price,
        )?;
        let (output_position, _) = apply_liquidity_position_fill(
            &prior_position,
            fill_plan.source.side.clone(),
            fill_plan.filled_amount,
            clearing_price,
            price_base_scale,
            &next_blinding,
        )
        .map_err(|error| {
            eprintln!("liquidity position fill materialization failed: {error}");
            StatusCode::CONFLICT
        })?;
        let (computed_prior_root, new_root, state_update) = state
            .replace(&prior_position, &output_position)
            .map_err(|error| {
                eprintln!("liquidity position state update materialization failed: {error}");
                StatusCode::CONFLICT
            })?;
        if computed_prior_root != running_root {
            return Err(StatusCode::CONFLICT);
        }
        let transition = liquidity_position_root_transition(
            LiquidityPositionTransitionKind::Update,
            Some(&prior_position),
            Some(&output_position),
        )
        .map_err(|_| StatusCode::CONFLICT)?;
        let witness = LiquidityPositionTransitionWitness {
            transition,
            prior_position: Some(prior_position),
            output_position: Some(output_position.clone()),
            state_update,
            epoch,
            fill: Some(LiquidityPositionSettlementFill {
                market_context: fill_plan.source.market_context.clone(),
                position_side: fill_plan.source.side.clone(),
                filled_base_amount: fill_plan.filled_amount,
                clearing_price,
                price_base_scale,
            }),
            open_funding: None,
            output_notes: Vec::new(),
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        };
        verify_liquidity_position_transition_witness(&running_root, &witness).map_err(|error| {
            eprintln!("generated liquidity position fill witness rejected: {error}");
            StatusCode::CONFLICT
        })?;
        book.positions.insert(
            position_id,
            ActiveLiquidityPositionRecord {
                position: output_position,
                owner_public_key: prior_record.owner_public_key,
            },
        );
        running_root = new_root;
        witnesses.push(witness);
    }
    Ok((book, running_root, witnesses))
}

fn build_liquidity_position_attribution_bundle(
    batch_id: &str,
    pair: &ProductPairConfig,
    epoch: u64,
    fills: &[LiquidityPositionFillPlan],
    witnesses: &[LiquidityPositionTransitionWitness],
    signer_private_key: &str,
    issued_at_unix_ms: u64,
) -> Result<Option<LiquidityAttributionBundle>, StatusCode> {
    if fills.is_empty() {
        return Ok(None);
    }
    if fills.len() != witnesses.len() {
        return Err(StatusCode::CONFLICT);
    }
    let mut artifacts = Vec::with_capacity(fills.len());
    for (fill_plan, witness) in fills.iter().zip(witnesses.iter()) {
        let liquidity_provider_public_key = fill_plan
            .source
            .liquidity_provider_public_key
            .as_ref()
            .ok_or(StatusCode::CONFLICT)?;
        let transition_commitment =
            liquidity_position_transition_commitment(witness).map_err(|error| {
                eprintln!("liquidity attribution transition commitment failed: {error}");
                StatusCode::CONFLICT
            })?;
        let consumed_position_commitment = witness
            .transition
            .consumed_position_commitment
            .as_ref()
            .ok_or(StatusCode::CONFLICT)?;
        let output_position_commitment = witness
            .transition
            .output_position_commitment
            .as_ref()
            .ok_or(StatusCode::CONFLICT)?;
        let settlement_fill = witness.fill.as_ref().ok_or(StatusCode::CONFLICT)?;
        if settlement_fill.position_side != fill_plan.source.side
            || settlement_fill.filled_base_amount != fill_plan.filled_amount
            || settlement_fill.price_base_scale != pair.price_base_scale
        {
            return Err(StatusCode::CONFLICT);
        }
        let curve_commitment = LiquidityCurve {
            points: fill_plan.source.points.clone(),
        }
        .commitment()
        .map_err(|error| {
            eprintln!("liquidity attribution curve commitment failed: {error}");
            StatusCode::CONFLICT
        })?;
        let attribution = liquidity_position_band_attribution(
            pair,
            fill_plan,
            &transition_commitment,
            consumed_position_commitment,
            settlement_fill.clearing_price,
        )?;
        let plaintext = LiquidityAttributionPlaintext {
            version: 1,
            batch_id: BatchId(batch_id.into()),
            pair_id: pair.pair_id.clone(),
            epoch_id: epoch,
            liquidity_provider_public_key: liquidity_provider_public_key.clone(),
            curve_commitment,
            output_note_commitment: NoteCommitment(output_position_commitment.0.clone()),
            attribution,
        };
        let artifact = create_liquidity_attribution_artifact(
            &plaintext,
            liquidity_provider_public_key,
            signer_private_key,
            issued_at_unix_ms,
        )
        .map_err(|error| {
            eprintln!("liquidity attribution artifact encryption failed: {error}");
            StatusCode::CONFLICT
        })?;
        artifacts.push(artifact);
    }
    Ok(Some(LiquidityAttributionBundle {
        version: 1,
        batch_id: BatchId(batch_id.into()),
        artifacts,
    }))
}

fn liquidity_position_band_attribution(
    pair: &ProductPairConfig,
    fill_plan: &LiquidityPositionFillPlan,
    transition_commitment: &str,
    consumed_position_commitment: &LiquidityPositionCommitment,
    clearing_price: u128,
) -> Result<LiquidityBandAttribution, StatusCode> {
    let bands = liquidity_position_band_fill_attributions(fill_plan, clearing_price)?;
    Ok(LiquidityBandAttribution {
        version: 1,
        pair_id: pair.pair_id.clone(),
        order_commitment: OrderCommitment(transition_commitment.into()),
        funding_note_ref: NoteCommitment(consumed_position_commitment.0.clone()),
        side: fill_plan.source.side.clone(),
        clearing_price,
        filled_base_amount: fill_plan.filled_amount,
        bands,
    })
}

fn liquidity_position_band_fill_attributions(
    fill_plan: &LiquidityPositionFillPlan,
    clearing_price: u128,
) -> Result<Vec<LiquidityBandFillAttribution>, StatusCode> {
    let mut candidates = fill_plan
        .source
        .points
        .iter()
        .enumerate()
        .filter(|(_, point)| {
            point_is_executable_for_side(point, &fill_plan.source.side, clearing_price)
        })
        .map(|(index, point)| (index as u64, point.clone()))
        .collect::<Vec<_>>();
    candidates.sort_by(|(left_index, left), (right_index, right)| {
        let price_order = match fill_plan.source.side {
            OrderSide::Buy => right.price.cmp(&left.price),
            OrderSide::Sell => left.price.cmp(&right.price),
        };
        price_order.then_with(|| left_index.cmp(right_index))
    });
    let mut remaining = fill_plan.filled_amount;
    let mut bands = Vec::new();
    for (band_index, band) in candidates {
        if remaining == 0 {
            break;
        }
        let filled_base_amount = band.base_amount.min(remaining);
        if filled_base_amount == 0 {
            continue;
        }
        remaining -= filled_base_amount;
        bands.push(LiquidityBandFillAttribution {
            band_index,
            band_price: band.price,
            band_base_amount: band.base_amount,
            filled_base_amount,
        });
    }
    if remaining != 0 {
        return Err(StatusCode::CONFLICT);
    }
    bands.sort_by_key(|band| band.band_index);
    Ok(bands)
}

#[allow(clippy::too_many_arguments)]
fn liquidity_position_fill_blinding(
    batch_id: &str,
    epoch: u64,
    fill_index: usize,
    prior_root: &str,
    position: &PrivateLiquidityPosition,
    side: &OrderSide,
    filled_amount: u128,
    clearing_price: u128,
) -> Result<String, StatusCode> {
    let prior_commitment = position.commitment().map_err(|_| StatusCode::CONFLICT)?;
    let side_label = match side {
        OrderSide::Buy => "buy",
        OrderSide::Sell => "sell",
    };
    tagged_field_hex(
        "zylith/liquidity-position-fill-blinding-v1",
        &serde_json::json!({
            "batch_id": batch_id,
            "epoch": epoch,
            "fill_index": fill_index,
            "prior_root": normalize_felt_hex(prior_root).map_err(|_| StatusCode::CONFLICT)?,
            "position_id": normalize_felt_hex(&position.position_id).map_err(|_| StatusCode::CONFLICT)?,
            "prior_commitment": prior_commitment.0,
            "side": side_label,
            "filled_amount": filled_amount.to_string(),
            "clearing_price": clearing_price.to_string(),
        }),
    )
    .map_err(|_| StatusCode::CONFLICT)
}

fn safe_position_id(position: &PrivateLiquidityPosition) -> String {
    normalize_felt_hex(&position.position_id).unwrap_or_else(|_| "<invalid-position-id>".into())
}

fn validate_private_liquidity_position_ingress_request(
    pair_id: &PairId,
    batch_id: &BatchId,
    epoch_id: u64,
    witness: &LiquidityPositionTransitionWitness,
) -> Result<(), StatusCode> {
    if epoch_id == 0 || witness.epoch != epoch_id {
        return Err(reject_private_ingress("liquidity position epoch mismatch"));
    }
    let expected_batch_id = coordinator_batch_key(pair_id, epoch_id);
    if batch_id.0 != expected_batch_id {
        return Err(reject_private_ingress("liquidity position batch mismatch"));
    }
    let witness_pair = liquidity_position_witness_pair_id(witness).ok_or_else(|| {
        reject_private_ingress("liquidity position witness is missing pair metadata")
    })?;
    if &witness_pair != pair_id {
        return Err(reject_private_ingress("liquidity position pair mismatch"));
    }
    witness
        .transition
        .validate()
        .map_err(|_| reject_private_ingress("liquidity position transition summary is invalid"))?;
    match witness.transition.kind {
        LiquidityPositionTransitionKind::Open
        | LiquidityPositionTransitionKind::Reconfigure
        | LiquidityPositionTransitionKind::Close => Ok(()),
        LiquidityPositionTransitionKind::Update => Err(reject_private_ingress(
            "liquidity position fills are settlement-derived, not user lifecycle submissions",
        )),
    }
}

fn coordinator_batch_key(pair_id: &PairId, epoch_id: u64) -> String {
    format!(
        "batch-{}-{}",
        pair_id.0.to_lowercase().replace('/', "-"),
        epoch_id
    )
}

fn liquidity_position_witness_pair_id(
    witness: &LiquidityPositionTransitionWitness,
) -> Option<PairId> {
    let mut pair_id = witness
        .prior_position
        .as_ref()
        .map(|position| position.pair_id.clone())
        .or_else(|| {
            witness
                .output_position
                .as_ref()
                .map(|position| position.pair_id.clone())
        })?;
    if let Some(output) = witness.output_position.as_ref()
        && output.pair_id != pair_id
    {
        return None;
    }
    if let Some(prior) = witness.prior_position.as_ref() {
        pair_id = prior.pair_id.clone();
    }
    Some(pair_id)
}

async fn prune_private_order_payloads(state: &AppState) -> Result<(), StatusCode> {
    if state.private_payload_retention_ms == 0 {
        return Ok(());
    }
    let cutoff = now_unix_ms().saturating_sub(state.private_payload_retention_ms);
    let removed = {
        let private_order_payloads = state.private_order_payloads.read().await;
        private_order_payloads
            .iter()
            .filter(|(_, record)| record.received_at_unix_ms < cutoff)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>()
    };
    for key in removed {
        let mut private_order_payloads = state.private_order_payloads.write().await;
        if private_order_payloads
            .get(&key)
            .is_some_and(|record| record.received_at_unix_ms < cutoff)
        {
            delete_record_and_remove(
                state.data_dir.as_ref(),
                PRIVATE_ORDER_PAYLOADS_DIR,
                &mut private_order_payloads,
                &key,
            )?;
        }
    }
    Ok(())
}

async fn prune_private_liquidity_position_payloads(state: &AppState) -> Result<(), StatusCode> {
    if state.private_payload_retention_ms == 0 {
        return Ok(());
    }
    let cutoff = now_unix_ms().saturating_sub(state.private_payload_retention_ms);
    let removed = {
        let private_payloads = state.private_liquidity_position_payloads.read().await;
        private_payloads
            .iter()
            .filter(|(_, record)| record.received_at_unix_ms < cutoff)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>()
    };
    for key in removed {
        let mut private_payloads = state.private_liquidity_position_payloads.write().await;
        if private_payloads
            .get(&key)
            .is_some_and(|record| record.received_at_unix_ms < cutoff)
        {
            delete_record_and_remove(
                state.data_dir.as_ref(),
                PRIVATE_LIQUIDITY_POSITION_PAYLOADS_DIR,
                &mut private_payloads,
                &key,
            )?;
        }
    }
    Ok(())
}

async fn prepare_private_auction_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<PreparedBatchStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    require_prover_not_paused(&state)?;
    let prepared = prepare_private_auction_batch_inner(&state, &batch_id)
        .await
        .inspect_err(|status| {
            eprintln!(
                "prepare_private_auction_batch batch_id={} failed status={}",
                batch_id, status
            );
        })?;
    Ok(Json(prepared))
}

fn env_parse_or_default<T>(env_name: &str, default: T) -> T
where
    T: std::str::FromStr + Copy,
{
    env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default)
}

fn env_config_or_default<T>(env_name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr + Copy,
{
    env::var(env_name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .trim()
                .parse::<T>()
                .map_err(|_| format!("invalid {env_name}"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn env_positive_config_or_default<T>(env_name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr + Copy + PartialEq + From<u8>,
{
    let value = env_config_or_default(env_name, default)?;
    if value == T::from(0) {
        return Err(format!("{env_name} must be positive"));
    }
    Ok(value)
}

fn env_optional_config<T>(env_name: &str) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
{
    env::var(env_name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .trim()
                .parse::<T>()
                .map_err(|_| format!("invalid {env_name}"))
        })
        .transpose()
}

fn env_positive_optional_config<T>(env_name: &str) -> Result<Option<T>, String>
where
    T: std::str::FromStr + Copy + PartialEq + From<u8>,
{
    let Some(value) = env_optional_config(env_name)? else {
        return Ok(None);
    };
    if value == T::from(0) {
        return Err(format!("{env_name} must be positive"));
    }
    Ok(Some(value))
}

fn env_bool_or_default(env_name: &str, default: bool) -> bool {
    env::var(env_name)
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn load_initial_note_root() -> Result<String, String> {
    env::var(INITIAL_NOTE_ROOT_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| {
            normalize_felt_hex(&value)
                .map_err(|error| format!("invalid {INITIAL_NOTE_ROOT_ENV}: {error}"))
        })
        .transpose()
        .map(|value| value.unwrap_or_else(|| "0x0".to_string()))
}

fn ceil_fee_amount(amount: u128, fee_bps: u128) -> Option<u128> {
    if amount == 0 || fee_bps == 0 {
        return Some(0);
    }
    amount
        .checked_mul(fee_bps)?
        .checked_add(9_999)
        .map(|numerator| numerator / 10_000)
}

fn enforce_native_tx_prover_trust_boundary(
    native_tx_prover_url: Option<&str>,
) -> Result<(), String> {
    let Some(url) = native_tx_prover_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    if native_tx_prover_is_private_or_local(url) {
        return Err(
            "ZYLITH_NATIVE_TX_PROVER_URL must use the configured external Starknet prover endpoint; local, private, and self-hosted native proving endpoints are not allowed"
                .into(),
        );
    }
    Ok(())
}

fn native_tx_prover_is_private_or_local(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    if matches!(host.as_str(), "localhost") {
        return true;
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(ip) => {
                ip.is_private() || ip.is_link_local() || ip.is_broadcast() || ip.is_documentation()
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || (segments[0] == 0x2001 && segments[1] == 0x0db8)
            }
        }
}

fn load_native_prover_ohttp_config(
    native_tx_prover_url: &str,
) -> Result<Option<NativeProverOhttpConfig>, String> {
    if !env_bool_or_default(NATIVE_TX_PROVER_OHTTP_ENABLED_ENV, true) {
        let parsed = Url::parse(native_tx_prover_url)
            .map_err(|error| format!("invalid {NATIVE_TX_PROVER_URL_ENV}: {error}"))?;
        if parsed.scheme() != "https" {
            return Err(format!(
                "{NATIVE_TX_PROVER_OHTTP_ENABLED_ENV}=0 requires an HTTPS {NATIVE_TX_PROVER_URL_ENV}"
            ));
        }
        return Ok(None);
    }
    let pinned_key_config = env::var(NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX_ENV)
        .ok()
        .map(|value| parse_ohttp_key_config_hex(&value))
        .transpose()?;
    Ok(Some(NativeProverOhttpConfig { pinned_key_config }))
}

fn parse_ohttp_key_config_hex(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.is_empty() {
        return Err(format!(
            "{NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX_ENV} must not be empty"
        ));
    }
    hex::decode(stripped).map_err(|error| {
        format!("{NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX_ENV} is invalid hex: {error}")
    })
}

fn validate_private_order_risk_limits(state: &AppState, order: &OrderIntent) -> Result<(), String> {
    validate_private_order_shape_and_amount(state.max_order_amount, order)
}

fn validate_private_order_shape_and_amount(
    max_order_amount: u128,
    order: &OrderIntent,
) -> Result<(), String> {
    if matches!(order.order_type, zylith_core::OrderType::HeartbeatCover) {
        return Err("heartbeat cover orders are protocol-generated".into());
    }
    if max_order_amount > 0 && order.amount > max_order_amount {
        return Err("order amount exceeds configured maximum".into());
    }

    if matches!(order.order_type, zylith_core::OrderType::LiquidityCurve) {
        return Err(
            "legacy liquidity curve orders are disabled; open a private liquidity position lifecycle"
                .into(),
        );
    }

    Ok(())
}

fn require_prover_not_paused(state: &AppState) -> Result<(), StatusCode> {
    if state.emergency_paused {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(())
}

async fn proof_worker_loop(state: AppState) {
    eprintln!(
        "zylith prover worker enabled tick_ms={} max_batches_per_tick={} submit_onchain={}",
        state.prover_worker_tick_ms,
        state.prover_worker_max_batches_per_tick,
        state.prover_worker_submit_onchain
    );
    loop {
        if let Err(error) = run_proof_worker_tick(&state).await {
            eprintln!("zylith prover worker tick failed: {error}");
        }
        sleep(Duration::from_millis(state.prover_worker_tick_ms.max(1))).await;
    }
}

async fn run_proof_worker_tick(state: &AppState) -> Result<usize, String> {
    if state.emergency_paused {
        return Ok(0);
    }
    if let Err(error) = refresh_pending_onchain_submissions(state).await {
        eprintln!("zylith prover worker onchain refresh failed: {error}");
    }
    let mut batches = fetch_proof_worker_batch_summaries(state).await?;
    sort_proof_worker_batches_for_selection(&mut batches);

    let mut selected_pairs = BTreeSet::new();
    let mut selected_batches = Vec::new();
    for batch in batches {
        if selected_batches.len() >= state.prover_worker_max_batches_per_tick {
            break;
        }
        if !matches!(batch.status, BatchStatus::Closed | BatchStatus::Clearing) {
            continue;
        }
        if selected_pairs.contains(&batch.pair_id.0) {
            continue;
        }
        let batch_id = batch.batch_id.0.as_str();
        if !proof_worker_should_process_batch(state, batch_id).await {
            continue;
        }
        if batch.order_count == 0 {
            continue;
        }
        selected_pairs.insert(batch.pair_id.0.clone());
        eprintln!(
            "zylith prover worker queued batch_id={} pair={} epoch={} orders={}",
            batch_id, batch.pair_id.0, batch.epoch_id, batch.order_count
        );
        selected_batches.push(batch.batch_id.0.clone());
    }

    let mut join_set = task::JoinSet::new();
    for batch_id in selected_batches {
        let state = state.clone();
        join_set.spawn(async move {
            let result = process_proof_worker_batch(&state, &batch_id).await;
            (batch_id, result)
        });
    }

    let mut processed = 0usize;
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok((batch_id, Ok(()))) => {
                processed += 1;
                clear_proof_worker_batch_failure(state, &batch_id).await;
                eprintln!("zylith prover worker batch {batch_id} processed");
            }
            Ok((batch_id, Err(status))) => {
                processed += 1;
                record_proof_worker_batch_failure(state, &batch_id).await;
                eprintln!("zylith prover worker batch {batch_id} failed status={status}");
            }
            Err(error) => {
                eprintln!("zylith prover worker task failed: {error}");
            }
        }
    }
    Ok(processed)
}

async fn refresh_pending_onchain_submissions(state: &AppState) -> Result<usize, String> {
    let pending = {
        let submissions = state.onchain_submissions.read().await;
        submissions
            .iter()
            .filter(|(_, submission)| should_refresh_onchain_submission(submission))
            .map(|(batch_id, submission)| (batch_id.clone(), submission.clone()))
            .collect::<Vec<_>>()
    };
    let mut refreshed = 0usize;
    for (batch_id, submission) in pending {
        let refreshed_record = refresh_submission_status(state, submission)
            .await
            .map_err(|_| format!("failed to refresh onchain submission for {batch_id}"))?;
        {
            let mut submissions = state.onchain_submissions.write().await;
            persist_record_and_insert(
                state.data_dir.as_ref(),
                ONCHAIN_SUBMISSIONS_DIR,
                &mut submissions,
                batch_id.clone(),
                refreshed_record.clone(),
            )
            .map_err(|status| {
                format!("failed to persist refreshed onchain submission for {batch_id}: {status}")
            })?;
        }
        sync_job_with_onchain_submission(state, &batch_id, &refreshed_record)
            .await
            .map_err(|status| {
                format!("failed to sync proof job after onchain refresh for {batch_id}: {status}")
            })?;
        if let Err(error) =
            publish_settlement_timestamp_to_artifact_stores(state, &batch_id, &refreshed_record)
                .await
        {
            eprintln!("failed to publish settlement timestamp for batch {batch_id}: {error}");
        }
        refreshed += 1;
    }
    Ok(refreshed)
}

fn should_refresh_onchain_submission(submission: &OnchainSubmissionRecord) -> bool {
    if matches!(submission.execution_status.as_deref(), Some("REVERTED")) {
        return false;
    }
    !matches!(
        submission.finality_status.as_deref(),
        Some("ACCEPTED_ON_L1" | "ACCEPTED_ON_L2")
    )
}

async fn fetch_proof_worker_batch_summaries(state: &AppState) -> Result<Vec<BatchSummary>, String> {
    let url = proof_worker_batch_list_url(&state.coordinator_url);
    let response = apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|error| format!("coordinator batch list request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "coordinator batch list rejected with HTTP {}",
            response.status()
        ));
    }
    decode_bounded_json_response(response, MAX_CONTROL_PLANE_RESPONSE_BYTES)
        .await
        .map_err(|error| format!("coordinator batch list decode failed: {error}"))
}

fn proof_worker_batch_list_url(coordinator_url: &str) -> String {
    format!(
        "{}/api/internal/batches/proof-work?status=Closed,Clearing&limit={PROOF_WORKER_BATCH_SCAN_LIMIT}",
        coordinator_url.trim_end_matches('/')
    )
}

fn sort_proof_worker_batches_for_selection(batches: &mut [BatchSummary]) {
    batches.sort_by(|left, right| {
        right
            .close_time_unix_ms
            .cmp(&left.close_time_unix_ms)
            .then_with(|| right.epoch_id.cmp(&left.epoch_id))
            .then_with(|| right.batch_id.0.cmp(&left.batch_id.0))
    });
}

async fn proof_worker_should_process_batch(state: &AppState, batch_id: &str) -> bool {
    if active_proof_batch_contains(state, batch_id) {
        return false;
    }
    if proof_worker_batch_in_backoff(state, batch_id, now_unix_ms()).await {
        return false;
    }
    if state
        .onchain_submissions
        .read()
        .await
        .contains_key(batch_id)
    {
        return false;
    }
    let proof_jobs = state.proof_jobs.read().await;
    let Some(status) = proof_jobs.get(batch_id) else {
        return true;
    };
    let now = now_unix_ms();
    if proof_worker_status_is_stale_proving(status, now) {
        return true;
    }
    if proof_worker_status_is_stale_submitting(status, now, state.prover_worker_submit_onchain) {
        return true;
    }
    if proof_worker_status_is_retryable_failure(status, now, state.prover_worker_submit_onchain) {
        return true;
    }
    proof_worker_status_is_processable(status.state.as_str(), state.prover_worker_submit_onchain)
}

fn proof_worker_status_is_stale_proving(status: &ProofJobStatus, now: u64) -> bool {
    status.state == "proving"
        && now.saturating_sub(status.updated_at_unix_ms) >= PROOF_WORKER_STALE_PROVING_RETRY_MS
}

fn proof_worker_status_is_stale_submitting(
    status: &ProofJobStatus,
    now: u64,
    submit_onchain: bool,
) -> bool {
    submit_onchain
        && status.state == "submitting-onchain"
        && !status.onchain_submission_available
        && now.saturating_sub(status.updated_at_unix_ms) >= PROOF_WORKER_STALE_SUBMITTING_RETRY_MS
}

fn proof_worker_status_is_retryable_failure(
    status: &ProofJobStatus,
    now: u64,
    submit_onchain: bool,
) -> bool {
    let retryable_state = match status.state.as_str() {
        "proving-failed" => true,
        "onchain-submit-failed" => {
            submit_onchain
                && status
                    .last_error
                    .as_deref()
                    .is_some_and(proof_worker_onchain_submit_failure_is_retryable)
        }
        _ => false,
    };
    retryable_state && now.saturating_sub(status.updated_at_unix_ms) >= PROOF_WORKER_FAILED_RETRY_MS
}

fn proof_worker_onchain_submit_failure_is_retryable(error: &str) -> bool {
    native_onchain_submit_error_is_retryable(error)
        || native_proving_service_error_is_retryable(error)
}

fn active_proof_batch_contains(state: &AppState, batch_id: &str) -> bool {
    state
        .active_proof_batches
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(batch_id)
}

async fn proof_worker_batch_in_backoff(state: &AppState, batch_id: &str, now: u64) -> bool {
    state
        .proof_worker_failures
        .read()
        .await
        .get(batch_id)
        .is_some_and(|failure| proof_worker_failure_blocks_retry(failure, now))
}

async fn record_proof_worker_batch_failure(state: &AppState, batch_id: &str) {
    let now = now_unix_ms();
    let mut failures = state.proof_worker_failures.write().await;
    let attempts = failures
        .get(batch_id)
        .map(|failure| failure.attempts.saturating_add(1))
        .unwrap_or(1);
    let next_retry_unix_ms = now.saturating_add(proof_worker_failure_backoff_ms(attempts));
    failures.insert(
        batch_id.to_owned(),
        ProofWorkerBatchFailure {
            attempts,
            next_retry_unix_ms,
        },
    );
}

async fn clear_proof_worker_batch_failure(state: &AppState, batch_id: &str) {
    state.proof_worker_failures.write().await.remove(batch_id);
}

fn proof_worker_failure_blocks_retry(failure: &ProofWorkerBatchFailure, now: u64) -> bool {
    failure.next_retry_unix_ms > now
}

fn proof_worker_failure_backoff_ms(attempts: u32) -> u64 {
    let multiplier = u64::from(attempts.max(1));
    PROOF_WORKER_FAILURE_BACKOFF_BASE_MS
        .saturating_mul(multiplier)
        .min(PROOF_WORKER_FAILURE_BACKOFF_MAX_MS)
}

fn proof_worker_status_is_processable(status: &str, submit_onchain: bool) -> bool {
    match status {
        "witness-prepared" => true,
        "proof-generated" => submit_onchain,
        "no-fill" => false,
        _ => false,
    }
}

struct ActiveProofBatchGuard {
    active_batches: Arc<Mutex<BTreeSet<String>>>,
    batch_id: String,
}

impl Drop for ActiveProofBatchGuard {
    fn drop(&mut self) {
        let mut active_batches = self
            .active_batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        active_batches.remove(&self.batch_id);
    }
}

fn try_enter_active_batch(
    active_batches: &Arc<Mutex<BTreeSet<String>>>,
    batch_id: &str,
) -> Option<ActiveProofBatchGuard> {
    let mut locked = active_batches
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !locked.insert(batch_id.to_owned()) {
        return None;
    }
    Some(ActiveProofBatchGuard {
        active_batches: active_batches.clone(),
        batch_id: batch_id.to_owned(),
    })
}

fn try_enter_active_proof_batch(
    state: &AppState,
    batch_id: &str,
) -> Result<ActiveProofBatchGuard, StatusCode> {
    try_enter_active_batch(&state.active_proof_batches, batch_id).ok_or(StatusCode::CONFLICT)
}

async fn process_proof_worker_batch(state: &AppState, batch_id: &str) -> Result<(), StatusCode> {
    let Some(_guard) = try_enter_active_batch(&state.active_proof_batches, batch_id) else {
        return Ok(());
    };
    let mut current_state = {
        let proof_jobs = state.proof_jobs.read().await;
        proof_jobs.get(batch_id).map(|status| status.state.clone())
    };
    if current_state.as_deref() != Some("proof-generated") {
        match run_proof_job_inner_locked(state, batch_id).await {
            Ok(status) => current_state = Some(status.state),
            Err(status) => {
                if current_state.is_none() && status == StatusCode::CONFLICT {
                    record_prepare_job_error(
                        state,
                        batch_id,
                        "proof worker could not prepare batch artifacts".into(),
                    )
                    .await?;
                }
                return Err(status);
            }
        }
    }
    if current_state.as_deref() == Some("no-fill") {
        return Ok(());
    }
    if state.prover_worker_submit_onchain {
        submit_onchain_inner_locked(state, batch_id).await?;
    }
    Ok(())
}

fn enforce_rate_limit(
    limiter: &RateLimiter,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    scope: &str,
    limit_per_minute: u64,
) -> Result<(), StatusCode> {
    if limit_per_minute == 0 {
        return Ok(());
    }

    let now = now_unix_ms();
    let window_started_unix_ms = now - (now % 60_000);
    let key = format!("{scope}:{}", rate_limit_subject(headers, peer));
    let mut buckets = match limiter.buckets.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    buckets.retain(|_, bucket| bucket.window_started_unix_ms + 120_000 >= window_started_unix_ms);
    let bucket = buckets.entry(key).or_insert(RateLimitBucket {
        window_started_unix_ms,
        count: 0,
    });
    if bucket.window_started_unix_ms != window_started_unix_ms {
        bucket.window_started_unix_ms = window_started_unix_ms;
        bucket.count = 0;
    }
    if bucket.count >= limit_per_minute {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    bucket.count += 1;
    Ok(())
}

fn rate_limit_subject(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if trusted_proxy_headers_enabled_for_peer(peer.map(|address| address.ip())) {
        for header in ["x-forwarded-for", "x-real-ip"] {
            if let Some(value) = forwarded_client_ip(headers, header) {
                return value;
            }
        }
    }
    if let Some(address) = peer {
        return address.ip().to_string();
    }
    "anonymous".into()
}

fn forwarded_client_ip(headers: &HeaderMap, header: &str) -> Option<String> {
    headers
        .get(header)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map(|value| value.to_string())
}

fn trusted_proxy_headers_enabled_for_peer(peer_ip: Option<IpAddr>) -> bool {
    let enabled = matches!(
        env::var("ZYLITH_PROVER_TRUST_PROXY_HEADERS")
            .or_else(|_| env::var("ZYLITH_TRUST_PROXY_HEADERS"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    );
    if !enabled {
        return false;
    }
    let Some(peer_ip) = peer_ip else {
        return false;
    };
    let cidrs = env::var("ZYLITH_TRUSTED_PROXY_CIDRS")
        .or_else(|_| env::var("ZYLITH_PROVER_TRUSTED_PROXY_CIDRS"))
        .unwrap_or_default();
    cidrs
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| value.parse::<IpNet>().ok())
        .any(|network| network.contains(&peer_ip))
}

async fn get_proof_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofJobStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let proof_jobs = state.proof_jobs.read().await;
    let status = proof_jobs
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(status))
}

#[derive(Serialize)]
struct PublicProofJobStatus {
    batch_id: String,
    state: String,
    matched_order_count_bucket: String,
    reuse_state: String,
    witness_available: bool,
    proof_artifact_available: bool,
    onchain_submission_available: bool,
    failure: Option<String>,
    updated_at_unix_ms: u64,
}

fn public_proof_failure(state: &str) -> Option<String> {
    match state {
        "proving-failed" => Some("proving_failed".into()),
        "onchain-submit-failed" => Some("onchain_submit_failed".into()),
        _ => None,
    }
}

fn is_failed_proof_job_state(state: &str) -> bool {
    matches!(
        state,
        "proving-failed" | "onchain-submit-failed" | "onchain-reverted"
    )
}

fn proof_job_error_class(error: Option<&str>) -> &'static str {
    let Some(error) = error else {
        return "unknown";
    };
    if error.contains("not deployed") {
        return "contract_not_deployed";
    }
    if error.contains("Invalid Starknet version") {
        return "unsupported_starknet_version";
    }
    if error.contains("Service busy") || error.contains("-32005") {
        return "prover_busy";
    }
    if error.contains("timed out") || error.contains("timeout") {
        return "timeout";
    }
    if error.contains("reverted") || error.contains("REVERTED") {
        return "onchain_revert";
    }
    "prover_error"
}

async fn get_public_proof_job(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<PublicProofJobStatus>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "proof-job")?;
    let proof_jobs = state.proof_jobs.read().await;
    let status = proof_jobs.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(public_proof_job_status(status)))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicProofJobQuery {
    batch_ids: String,
}

async fn list_public_proof_jobs(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Query(query): Query<PublicProofJobQuery>,
) -> Result<Json<Vec<PublicProofJobStatus>>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "proof-jobs")?;
    let requested = parse_limited_batch_id_query(&query.batch_ids, MAX_PUBLIC_PROOF_JOB_BATCH_IDS)?;
    let proof_jobs = state.proof_jobs.read().await;
    let statuses = requested
        .into_iter()
        .filter_map(|batch_id| proof_jobs.get(batch_id))
        .map(public_proof_job_status)
        .collect();
    Ok(Json(statuses))
}

fn parse_limited_batch_id_query(
    batch_ids: &str,
    max_batch_ids: usize,
) -> Result<BTreeSet<&str>, StatusCode> {
    let requested = batch_ids
        .split(',')
        .map(str::trim)
        .filter(|batch_id| !batch_id.is_empty())
        .collect::<BTreeSet<_>>();
    if requested.len() > max_batch_ids {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(requested)
}

fn public_proof_job_status(status: &ProofJobStatus) -> PublicProofJobStatus {
    PublicProofJobStatus {
        batch_id: status.batch_id.0.clone(),
        state: status.state.clone(),
        matched_order_count_bucket: zylith_core::count_bucket_label(status.matched_order_count),
        reuse_state: "unknown".into(),
        witness_available: status.witness_available,
        proof_artifact_available: status.proof_artifact_available,
        onchain_submission_available: status.onchain_submission_available,
        failure: public_proof_failure(&status.state),
        updated_at_unix_ms: status.updated_at_unix_ms,
    }
}

async fn get_settlement_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<SettlementSubmissionPlan>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let settlement_plans = state.settlement_plans.read().await;
    let plan = settlement_plans
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(plan))
}

async fn get_settlement_witness(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<SettlementWitness>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let settlement_witnesses = state.settlement_witnesses.read().await;
    let witness = settlement_witnesses
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(witness))
}

async fn get_proof_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofArtifactRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let proof_artifacts = state.proof_artifacts.read().await;
    let artifact = proof_artifacts
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(artifact))
}

async fn get_proof_aggregation_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((start_epoch, end_epoch)): Path<(u64, u64)>,
) -> Result<Json<ProofAggregationManifest>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    Ok(Json(
        build_proof_aggregation_manifest(&state, start_epoch, end_epoch).await?,
    ))
}

async fn run_native_proof_aggregation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((start_epoch, end_epoch)): Path<(u64, u64)>,
) -> Result<Json<NativeProofAggregationRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    Ok(Json(
        run_true_native_proof_aggregation(&state, start_epoch, end_epoch).await?,
    ))
}

async fn submit_native_proof_aggregation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((start_epoch, end_epoch)): Path<(u64, u64)>,
) -> Result<Json<OnchainSubmissionRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    require_prover_not_paused(&state)?;
    let aggregate = run_true_native_proof_aggregation(&state, start_epoch, end_epoch).await?;
    for member in &aggregate.prepared_members {
        let _guard = try_enter_active_proof_batch(&state, &member.witness.batch_id.0)?;
        if let Err(error) = prove_and_record_auction_result_for_member(&state, member, true).await {
            set_onchain_submission_error(&state, &member.witness.batch_id.0, error).await?;
            return Err(StatusCode::BAD_GATEWAY);
        }
    }
    let tx_hash = submit_native_invoke_with_typed_sdk_retry(
        &state,
        state
            .starknet_executor
            .as_ref()
            .ok_or(StatusCode::CONFLICT)?,
        &aggregate.settlement_call,
        aggregate.proof.clone(),
        &aggregate.proof_facts,
    )
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let submission_id = format!(
        "{}:{}:{}",
        aggregate.manifest.manifest_id, aggregate.aggregate_proof_artifact_commitment, tx_hash
    );
    let mut submission = OnchainSubmissionRecord {
        submission_id,
        batch_id: BatchId(aggregate.manifest.manifest_id.clone()),
        transaction_hash: tx_hash.clone(),
        submitted_at_unix_ms: now_unix_ms(),
        receipt_checked_at_unix_ms: None,
        confirmed_at_unix_ms: None,
        finality_status: None,
        execution_status: None,
        revert_reason: None,
        block_number: None,
        block_hash: None,
        block_timestamp_unix_ms: None,
        submission_mode: "native-aggregate-proof-facts".into(),
        settlement_contract_address: aggregate.settlement_call.contract_address.clone(),
    };
    if let Some(executor) = &state.starknet_executor {
        let provider = JsonRpcClient::new(starknet_http_transport(
            Url::parse(&executor.rpc_url).map_err(|_| StatusCode::BAD_GATEWAY)?,
        ));
        populate_submission_receipt_status(
            &mut submission,
            wait_for_receipt(
                &provider,
                parse_felt(&tx_hash, "aggregate transaction hash")
                    .map_err(|_| StatusCode::BAD_GATEWAY)?,
            )
            .await,
        );
        if let Some(block_number) = submission.block_number
            && let Ok(block_timestamp) =
                fetch_block_timestamp_unix_ms(&provider, block_number).await
        {
            submission.block_timestamp_unix_ms = Some(block_timestamp);
        }
    }
    {
        let mut submissions = state.onchain_submissions.write().await;
        for member_batch_id in &aggregate.member_batches {
            let mut member_submission = submission.clone();
            member_submission.submission_id =
                format!("{}:{}", member_batch_id.0, member_submission.submission_id);
            member_submission.batch_id = member_batch_id.clone();
            persist_record_and_insert(
                state.data_dir.as_ref(),
                ONCHAIN_SUBMISSIONS_DIR,
                &mut submissions,
                member_batch_id.0.clone(),
                member_submission,
            )?;
        }
    }
    for member_batch_id in &aggregate.member_batches {
        let member_submission = {
            let submissions = state.onchain_submissions.read().await;
            submissions
                .get(&member_batch_id.0)
                .cloned()
                .ok_or(StatusCode::BAD_GATEWAY)?
        };
        sync_job_with_onchain_submission(&state, &member_batch_id.0, &member_submission).await?;
        if let Err(error) = publish_settlement_timestamp_to_artifact_stores(
            &state,
            &member_batch_id.0,
            &member_submission,
        )
        .await
        {
            eprintln!(
                "failed to publish aggregate settlement timestamp for batch {}: {error}",
                member_batch_id.0
            );
        }
    }
    Ok(Json(submission))
}

async fn run_true_native_proof_aggregation(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<NativeProofAggregationRecord, StatusCode> {
    let tx_prover_url = state.native_tx_prover_url.clone();
    let members = prepare_native_aggregation_members(state, start_epoch, end_epoch).await?;
    if members.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
    let manifest =
        build_proof_aggregation_manifest_from_prepared(state, start_epoch, end_epoch, &members)?;
    validate_aggregate_root_chain(&members).map_err(|_| StatusCode::CONFLICT)?;
    let expected_messages = members
        .iter()
        .flat_map(|member| member.proof_message_hashes.iter().cloned())
        .collect::<Vec<_>>();
    let aggregate_call = build_native_aggregate_proof_program_call(state, &members)?;
    let executor = state
        .starknet_executor
        .clone()
        .ok_or(StatusCode::CONFLICT)?;
    let execution_request = build_native_execution_request(
        &executor,
        &aggregate_call,
        NativeTransactionMode::ProofOnly,
    )
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let rpc_request = NativeProverRpcRequest {
        jsonrpc: "2.0".into(),
        id: 1,
        method: "starknet_proveTransaction".into(),
        params: (
            execution_request.block_id.clone(),
            execution_request.transaction.clone(),
        ),
    };
    let (result, response_value) = request_native_proof(state, &tx_prover_url, &rpc_request)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    validate_native_proof_facts_messages(&result.proof_facts, &expected_messages)
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let settlement_call = build_aggregate_settlement_call(&members)?;
    let aggregate_proof_artifact_commitment = zylith_core::hash::tagged_commitment_sha256(
        "zylith/native-aggregate-proof-artifact-v1",
        &serde_json::json!({
            "manifest_id": manifest.manifest_id,
            "aggregate_commitment": manifest.aggregate_commitment,
            "proof": &result.proof,
            "proof_facts": &result.proof_facts,
            "native_execution_request": redact_native_prover_request(&rpc_request),
            "native_prover_response": response_value,
        }),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(NativeProofAggregationRecord {
        manifest,
        member_count_bucket: count_bucket(members.len()).into(),
        provider: "native-transaction-prover".into(),
        verifier_mode: "submit_aggregate_settlements_with_proof_facts".into(),
        aggregate_proof_artifact_commitment,
        settlement_call,
        member_batches: members
            .iter()
            .map(|member| member.witness.batch_id.clone())
            .collect(),
        proof: result.proof,
        proof_facts: result.proof_facts,
        prepared_members: members,
    })
}

async fn prepare_native_aggregation_members(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<Vec<NativeAggregationPreparedMember>, StatusCode> {
    let witnesses = proof_aggregation_witness_members(state, start_epoch, end_epoch).await?;
    let mut members = Vec::with_capacity(witnesses.len());
    let mut expected_roots = fetch_current_settlement_roots(state).await?;
    for witness in witnesses {
        let transcript = fetch_transcript(state, &witness.batch_id.0).await?;
        let transcript_commitment =
            settlement_transcript_commitment(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
        if transcript_commitment != witness.transcript_commitment {
            return Err(StatusCode::CONFLICT);
        }
        let (transcript, witness, roots) =
            aggregate_member_for_expected_roots(transcript, witness, &expected_roots)?;
        let statement_message = native_settlement_message_hash(
            &state.auction_verifier_address,
            &witness.transcript_commitment,
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let settlement_proof_message = settlement_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &witness.transcript_commitment,
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let nullifier_proof_message = nullifier_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &witness.transcript_commitment,
            &roots.prior_nullifier_root,
            &roots.consumed_nullifier_root,
            &roots.new_nullifier_root,
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let renewal_proof_message = renewal_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &witness.transcript_commitment,
            &roots.prior_renewal_root,
            &roots.renewal_child_root,
            &roots.new_renewal_root,
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let liquidity_position_proof_message = liquidity_position_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &witness.transcript_commitment,
            &roots.prior_liquidity_position_root,
            &roots.liquidity_position_transition_root,
            &roots.new_liquidity_position_root,
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let settlement_plan = build_settlement_submission_plan(
            &transcript,
            &state.auction_verifier_address,
            &statement_message,
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
        members.push(NativeAggregationPreparedMember {
            witness,
            transcript,
            settlement_plan,
            proof_message_hashes: vec![
                settlement_proof_message,
                nullifier_proof_message,
                renewal_proof_message,
                liquidity_position_proof_message,
            ],
        });
        expected_roots = SettlementRoots {
            note_root: roots.new_note_root,
            nullifier_root: roots.new_nullifier_root,
            renewal_root: roots.new_renewal_root,
            fee_root: roots.new_fee_root,
            liquidity_position_root: roots.new_liquidity_position_root,
        };
    }
    Ok(members)
}

fn aggregate_member_for_expected_roots(
    mut transcript: SettlementTranscript,
    mut witness: SettlementWitness,
    expected_roots: &SettlementRoots,
) -> Result<
    (
        SettlementTranscript,
        SettlementWitness,
        zylith_core::RootOnlySettlementCommitments,
    ),
    StatusCode,
> {
    precheck_aggregate_member_liquidity_position_witness_shape(&transcript, &witness)?;
    let roots =
        root_only_settlement_commitments(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let expected_note =
        normalize_felt_hex(&expected_roots.note_root).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let expected_nullifier =
        normalize_felt_hex(&expected_roots.nullifier_root).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let expected_renewal =
        normalize_felt_hex(&expected_roots.renewal_root).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let expected_fee =
        normalize_felt_hex(&expected_roots.fee_root).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let expected_liquidity_position = normalize_felt_hex(&expected_roots.liquidity_position_root)
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if roots.prior_note_root == expected_note
        && roots.prior_nullifier_root == expected_nullifier
        && roots.prior_renewal_root == expected_renewal
        && roots.prior_fee_root == expected_fee
        && roots.prior_liquidity_position_root == expected_liquidity_position
    {
        validate_aggregate_member_liquidity_position_witnesses(&transcript, &witness)?;
        return Ok((transcript, witness, roots));
    }

    if !transcript.consumed_inputs.is_empty()
        || !transcript.renewal_child_uses.is_empty()
        || !transcript.liquidity_position_transitions.is_empty()
        || !witness.nullifier_sparse_witnesses.is_empty()
        || !witness.renewal_child_sparse_witnesses.is_empty()
        || !witness.note_membership_witnesses.is_empty()
        || !witness.liquidity_position_transitions.is_empty()
        || !witness.liquidity_position_witnesses.is_empty()
    {
        return Err(StatusCode::CONFLICT);
    }

    transcript.prior_note_root = expected_note;
    transcript.prior_nullifier_root = expected_nullifier.clone();
    transcript.prior_renewal_root = expected_renewal.clone();
    transcript.prior_fee_root = expected_fee;
    transcript.prior_liquidity_position_root = expected_liquidity_position.clone();
    transcript.new_nullifier_root = expected_nullifier;
    transcript.new_renewal_root = expected_renewal;
    transcript.new_liquidity_position_root = expected_liquidity_position;
    let rechained_roots =
        root_only_settlement_commitments(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let transcript_commitment =
        settlement_transcript_commitment(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
    witness.transcript_commitment = transcript_commitment;
    witness.prior_note_root = transcript.prior_note_root.clone();
    witness.prior_nullifier_root = transcript.prior_nullifier_root.clone();
    witness.prior_renewal_root = transcript.prior_renewal_root.clone();
    witness.prior_fee_root = transcript.prior_fee_root.clone();
    witness.prior_liquidity_position_root = transcript.prior_liquidity_position_root.clone();
    witness.new_nullifier_root = transcript.new_nullifier_root.clone();
    witness.new_renewal_root = transcript.new_renewal_root.clone();
    witness.new_liquidity_position_root = transcript.new_liquidity_position_root.clone();
    Ok((transcript, witness, rechained_roots))
}

fn precheck_aggregate_member_liquidity_position_witness_shape(
    transcript: &SettlementTranscript,
    witness: &SettlementWitness,
) -> Result<(), StatusCode> {
    if transcript.liquidity_position_transitions.is_empty()
        && witness.liquidity_position_transitions.is_empty()
        && witness.liquidity_position_witnesses.is_empty()
    {
        return Ok(());
    }
    if transcript.liquidity_position_transitions != witness.liquidity_position_transitions {
        return Err(StatusCode::CONFLICT);
    }
    if witness.liquidity_position_witnesses.len() != witness.liquidity_position_transitions.len() {
        return Err(StatusCode::CONFLICT);
    }
    Ok(())
}

fn validate_aggregate_member_liquidity_position_witnesses(
    transcript: &SettlementTranscript,
    witness: &SettlementWitness,
) -> Result<(), StatusCode> {
    if transcript.liquidity_position_transitions.is_empty()
        && witness.liquidity_position_transitions.is_empty()
        && witness.liquidity_position_witnesses.is_empty()
    {
        return Ok(());
    }
    if transcript.liquidity_position_transitions != witness.liquidity_position_transitions {
        return Err(StatusCode::CONFLICT);
    }
    if witness.liquidity_position_witnesses.len() != witness.liquidity_position_transitions.len() {
        return Err(StatusCode::CONFLICT);
    }
    zylith_core::build_stwo_serialized_input(witness)
        .map(|_| ())
        .map_err(|_| StatusCode::CONFLICT)
}

async fn build_proof_aggregation_manifest(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<ProofAggregationManifest, StatusCode> {
    let members = prepare_native_aggregation_members(state, start_epoch, end_epoch).await?;
    build_proof_aggregation_manifest_from_prepared(state, start_epoch, end_epoch, &members)
}

fn build_proof_aggregation_manifest_from_prepared(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
    members: &[NativeAggregationPreparedMember],
) -> Result<ProofAggregationManifest, StatusCode> {
    let pair_count = members
        .iter()
        .map(|member| member.witness.pair_id.0.clone())
        .collect::<BTreeSet<_>>()
        .len();
    let proof_artifact_commitments = members
        .iter()
        .map(|member| {
            native_settlement_message_hash(
                &state.auction_verifier_address,
                &member.witness.transcript_commitment,
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        })
        .collect::<Result<Vec<_>, StatusCode>>()?;
    let transcript_commitments = members
        .iter()
        .map(|member| member.witness.transcript_commitment.clone())
        .collect::<Vec<_>>();
    let proof_artifact_commitment_root = zylith_core::hash::tagged_commitment_sha256(
        "zylith/proof-aggregation/artifact-root-v1",
        &proof_artifact_commitments,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let transcript_commitment_root = zylith_core::hash::tagged_commitment_sha256(
        "zylith/proof-aggregation/transcript-root-v1",
        &transcript_commitments,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mode = "native_virtual_tx_aggregate_proof_facts";
    let binding_members = members
        .iter()
        .zip(proof_artifact_commitments.iter())
        .map(|(member, proof_artifact_commitment)| {
            serde_json::json!({
                "batch_id": member.witness.batch_id,
                "pair_id": member.witness.pair_id,
                "batch_epoch": member.witness.batch_epoch,
                "transcript_commitment": member.witness.transcript_commitment,
                "proof_artifact_commitment": proof_artifact_commitment,
                "proof_system": "starknet-snip36",
                "prover_backend": prover_backend_label(),
            })
        })
        .collect::<Vec<_>>();
    let aggregate_commitment = zylith_core::hash::tagged_commitment_sha256(
        "zylith/proof-aggregation-manifest-v1",
        &serde_json::json!({
            "mode": mode,
            "epoch_start": start_epoch,
            "epoch_end": end_epoch,
            "members": binding_members,
            "proof_artifact_commitment_root": proof_artifact_commitment_root,
            "transcript_commitment_root": transcript_commitment_root,
        }),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let suffix = aggregate_commitment
        .get(..16)
        .unwrap_or(aggregate_commitment.as_str());

    Ok(ProofAggregationManifest {
        manifest_id: format!("proof-aggregation-{start_epoch}-{end_epoch}-{suffix}"),
        mode: mode.into(),
        epoch_start: start_epoch,
        epoch_end: end_epoch,
        batch_count_bucket: count_bucket(members.len()).into(),
        pair_count_bucket: count_bucket(pair_count).into(),
        proof_artifact_count_bucket: count_bucket(proof_artifact_commitments.len()).into(),
        aggregate_commitment,
        proof_artifact_commitment_root,
        transcript_commitment_root,
        native_aggregation_supported: true,
        verifier_mode: "submit_aggregate_settlements_with_proof_facts".into(),
    })
}

async fn proof_aggregation_witness_members(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<Vec<SettlementWitness>, StatusCode> {
    if start_epoch > end_epoch {
        return Err(StatusCode::BAD_REQUEST);
    }
    let settlement_witnesses = state.settlement_witnesses.read().await;
    let mut members = settlement_witnesses
        .values()
        .filter(|witness| witness.batch_epoch >= start_epoch && witness.batch_epoch <= end_epoch)
        .cloned()
        .collect::<Vec<_>>();
    members.sort_by(|left, right| {
        left.batch_epoch
            .cmp(&right.batch_epoch)
            .then_with(|| left.pair_id.0.cmp(&right.pair_id.0))
            .then_with(|| left.batch_id.0.cmp(&right.batch_id.0))
    });
    Ok(members)
}

fn validate_aggregate_root_chain(
    members: &[NativeAggregationPreparedMember],
) -> Result<(), String> {
    let mut batch_ids = BTreeSet::new();
    let mut settlement_contract_address = None::<String>;
    for member in members {
        let batch_id = member.witness.batch_id.0.as_str();
        if !batch_ids.insert(batch_id.to_string()) {
            return Err("aggregate member batch id is duplicated".into());
        }
        if member.transcript.batch_id.0.as_str() != batch_id
            || member.settlement_plan.batch_id.0.as_str() != batch_id
            || member.settlement_plan.encoded_args.batch_id.as_str() != batch_id
        {
            return Err("aggregate member batch ids do not agree".into());
        }
        let member_contract = member
            .settlement_plan
            .settlement_call
            .contract_address
            .as_str();
        match settlement_contract_address.as_deref() {
            Some(expected) if expected != member_contract => {
                return Err("aggregate member settlement targets do not agree".into());
            }
            None => settlement_contract_address = Some(member_contract.to_string()),
            _ => {}
        }
        if member.settlement_plan.settlement_call.entrypoint != "submit_settlement_with_proof_facts"
        {
            return Err("aggregate member settlement entrypoint is invalid".into());
        }
    }
    for window in members.windows(2) {
        let current = &window[0].settlement_plan.encoded_args;
        let next = &window[1].settlement_plan.encoded_args;
        if current.new_note_root != next.prior_note_root {
            return Err("aggregate member note roots are not chained".into());
        }
        if current.new_nullifier_root != next.prior_nullifier_root {
            return Err("aggregate member nullifier roots are not chained".into());
        }
        if current.new_renewal_root != next.prior_renewal_root {
            return Err("aggregate member renewal roots are not chained".into());
        }
        if current.new_fee_root != next.prior_fee_root {
            return Err("aggregate member fee roots are not chained".into());
        }
        if current.new_liquidity_position_root != next.prior_liquidity_position_root {
            return Err("aggregate member liquidity position roots are not chained".into());
        }
    }
    Ok(())
}

fn build_native_aggregate_proof_program_call(
    state: &AppState,
    members: &[NativeAggregationPreparedMember],
) -> Result<StarknetCall, StatusCode> {
    let verifier = normalize_nonzero_felt(&state.auction_verifier_address, "auction_verifier")
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let mut aggregate_payload = vec![encode_usize_hex(members.len())];
    for member in members {
        let serialized = zylith_core::build_stwo_serialized_input(&member.witness)
            .map_err(|_| StatusCode::CONFLICT)?;
        aggregate_payload.extend(serialized);
    }
    let mut calldata = Vec::with_capacity(aggregate_payload.len() + 2);
    calldata.push(verifier);
    calldata.push(encode_usize_hex(aggregate_payload.len()));
    calldata.extend(aggregate_payload);
    Ok(StarknetCall {
        contract_address: normalize_nonzero_felt(
            &state.native_proof_program_address,
            "native_proof_program_address",
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?,
        entrypoint: state.native_proof_aggregate_entrypoint.clone(),
        calldata,
    })
}

fn build_aggregate_settlement_call(
    members: &[NativeAggregationPreparedMember],
) -> Result<StarknetCall, StatusCode> {
    let first = members.first().ok_or(StatusCode::NOT_FOUND)?;
    let mut payload = vec![encode_usize_hex(members.len())];
    for member in members {
        payload.extend(
            member
                .settlement_plan
                .settlement_call
                .calldata
                .iter()
                .cloned(),
        );
    }
    let mut calldata = Vec::with_capacity(payload.len() + 1);
    calldata.push(encode_usize_hex(payload.len()));
    calldata.extend(payload);
    Ok(StarknetCall {
        contract_address: first
            .settlement_plan
            .settlement_call
            .contract_address
            .clone(),
        entrypoint: "submit_aggregate_settlements_with_proof_facts".into(),
        calldata,
    })
}

fn encode_usize_hex(value: usize) -> String {
    format!("0x{value:x}")
}

async fn get_onchain_submission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<OnchainSubmissionRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let submissions = state.onchain_submissions.read().await;
    let record = submissions
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(record))
}

async fn refresh_onchain_submission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<OnchainSubmissionRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let current_record = {
        let submissions = state.onchain_submissions.read().await;
        submissions
            .get(&batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };

    let refreshed_record = refresh_submission_status(&state, current_record)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    {
        let mut submissions = state.onchain_submissions.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &mut submissions,
            batch_id.clone(),
            refreshed_record.clone(),
        )?;
    }

    sync_job_with_onchain_submission(&state, &batch_id, &refreshed_record).await?;
    if let Err(error) =
        publish_settlement_timestamp_to_artifact_stores(&state, &batch_id, &refreshed_record).await
    {
        eprintln!("failed to publish settlement timestamp for batch {batch_id}: {error}");
    }

    Ok(Json(refreshed_record))
}

async fn prepare_proof_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofJobStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    require_prover_not_paused(&state)?;
    let started_at = now_unix_ms();
    let result = prepare_or_rebuild_job(&state, &batch_id).await;
    state.proof_lifecycle_metrics.record(
        "settlement_prepare",
        if result.is_ok() { "success" } else { "error" },
        now_unix_ms().saturating_sub(started_at),
    );
    let (status, _) = result?;
    Ok(Json(status))
}

async fn run_proof_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofJobStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    require_prover_not_paused(&state)?;
    let started_at = now_unix_ms();
    let result = run_proof_job_inner(&state, &batch_id).await;
    state.proof_lifecycle_metrics.record(
        "settlement_proof_job",
        if result.is_ok() { "success" } else { "error" },
        now_unix_ms().saturating_sub(started_at),
    );
    Ok(Json(result?))
}

async fn run_proof_job_inner(
    state: &AppState,
    batch_id: &str,
) -> Result<ProofJobStatus, StatusCode> {
    let _guard = try_enter_active_proof_batch(state, batch_id)?;
    run_proof_job_inner_locked(state, batch_id).await
}

async fn run_proof_job_inner_locked(
    state: &AppState,
    batch_id: &str,
) -> Result<ProofJobStatus, StatusCode> {
    let (_, settlement_witness) = ensure_prepared_job(state, batch_id).await?;
    let transcript = fetch_transcript(state, batch_id).await?;

    if transcript.matched_orders.is_empty() && transcript.liquidity_position_transitions.is_empty()
    {
        return set_job_state(
            state,
            batch_id,
            JobStateUpdate {
                next_state: "no-fill".into(),
                proof_artifact_id: None,
                last_error: None,
                proof_artifact_available: false,
                settlement_plan_available: Some(false),
                settlement_calldata_len: Some(0),
                settlement_entrypoint: Some("submit_settlement_with_proof_facts".into()),
            },
        )
        .await;
    }

    set_job_state(
        state,
        batch_id,
        JobStateUpdate {
            next_state: "proving".into(),
            proof_artifact_id: None,
            last_error: None,
            proof_artifact_available: false,
            settlement_plan_available: None,
            settlement_calldata_len: None,
            settlement_entrypoint: None,
        },
    )
    .await?;

    let proof_started_at = now_unix_ms();
    let transcript_commitment =
        settlement_transcript_commitment(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if settlement_witness.transcript_commitment != transcript_commitment {
        set_job_error(
            state,
            batch_id,
            "settlement witness commitment does not match transcript".into(),
        )
        .await?;
        return Err(StatusCode::BAD_GATEWAY);
    }
    let artifact = build_pending_native_settlement_artifact_record(
        state,
        batch_id,
        &transcript,
        &transcript_commitment,
    )
    .map_err(|error| {
        eprintln!("failed to build pending native artifact for batch {batch_id}: {error}");
        StatusCode::BAD_GATEWAY
    })?;
    let settlement_plan = match build_settlement_submission_plan_for_artifact(
        &transcript,
        &state.auction_verifier_address,
        &artifact,
    ) {
        Ok(plan) => plan,
        Err(_) => return Err(StatusCode::BAD_GATEWAY),
    };
    let artifact_id = artifact.artifact_id.clone();
    {
        let mut proof_artifacts = state.proof_artifacts.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            PROOF_ARTIFACTS_DIR,
            &mut proof_artifacts,
            batch_id.to_owned(),
            artifact,
        )?;
    }
    {
        let mut settlement_plans = state.settlement_plans.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            SETTLEMENT_PLANS_DIR,
            &mut settlement_plans,
            batch_id.to_owned(),
            settlement_plan.clone(),
        )?;
    }
    state.proof_lifecycle_metrics.record(
        "settlement_plan_prepare",
        "success",
        now_unix_ms().saturating_sub(proof_started_at),
    );

    set_job_state(
        state,
        batch_id,
        JobStateUpdate {
            next_state: "proof-generated".into(),
            proof_artifact_id: Some(artifact_id),
            last_error: None,
            proof_artifact_available: false,
            settlement_plan_available: Some(true),
            settlement_calldata_len: Some(settlement_plan.settlement_call.calldata.len() as u64),
            settlement_entrypoint: Some(settlement_plan.settlement_call.entrypoint),
        },
    )
    .await
}

async fn submit_onchain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<OnchainSubmissionRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    require_prover_not_paused(&state)?;
    let started_at = now_unix_ms();
    let result = submit_onchain_inner(&state, &batch_id).await;
    state.proof_lifecycle_metrics.record(
        "settlement_onchain_submit",
        if result.is_ok() { "success" } else { "error" },
        now_unix_ms().saturating_sub(started_at),
    );
    Ok(Json(result?))
}

async fn submit_onchain_inner(
    state: &AppState,
    batch_id: &str,
) -> Result<OnchainSubmissionRecord, StatusCode> {
    let _guard = try_enter_active_proof_batch(state, batch_id)?;
    submit_onchain_inner_locked(state, batch_id).await
}

async fn submit_onchain_inner_locked(
    state: &AppState,
    batch_id: &str,
) -> Result<OnchainSubmissionRecord, StatusCode> {
    let settlement_plan = {
        let settlement_plans = state.settlement_plans.read().await;
        settlement_plans
            .get(batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };
    let proof_artifact = {
        let proof_artifacts = state.proof_artifacts.read().await;
        proof_artifacts.get(batch_id).cloned()
    };
    let proof_artifact = match proof_artifact {
        Some(artifact) => artifact,
        None => {
            let transcript = fetch_transcript(state, batch_id).await?;
            let transcript_commitment =
                settlement_transcript_commitment(&transcript).map_err(|_| StatusCode::CONFLICT)?;
            build_pending_native_settlement_artifact_record(
                state,
                batch_id,
                &transcript,
                &transcript_commitment,
            )
            .map_err(|_| StatusCode::CONFLICT)?
        }
    };

    set_job_submitting_onchain(state, batch_id).await?;

    if let Err(error) = ensure_batch_registered_onchain(state, batch_id).await {
        set_onchain_submission_error(
            state,
            batch_id,
            format!("failed to register batch before native proof recording: {error}"),
        )
        .await?;
        return Err(StatusCode::BAD_GATEWAY);
    }

    if let Err(error) = prove_and_record_auction_result(state, batch_id, true).await {
        set_onchain_submission_error(state, batch_id, error).await?;
        return Err(StatusCode::BAD_GATEWAY);
    }

    let jitter_ms = deterministic_settlement_submission_jitter_ms(
        &settlement_plan.batch_id.0,
        state.settlement_submission_jitter_ms,
    );
    if jitter_ms > 0 {
        sleep(Duration::from_millis(jitter_ms)).await;
    }

    let submission =
        match submit_native_plan_onchain(state, &settlement_plan, &proof_artifact).await {
            Ok(submission) => submission,
            Err(error) => {
                set_onchain_submission_error(state, batch_id, error).await?;
                return Err(StatusCode::BAD_GATEWAY);
            }
        };

    {
        let mut submissions = state.onchain_submissions.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &mut submissions,
            batch_id.to_owned(),
            submission.clone(),
        )?;
    }
    sync_job_with_onchain_submission(state, batch_id, &submission).await?;
    if let Some(created_at_unix_ms) = state
        .proof_jobs
        .read()
        .await
        .get(batch_id)
        .map(|status| status.created_at_unix_ms)
    {
        state.proof_lifecycle_metrics.record(
            "settlement_total",
            "success",
            now_unix_ms().saturating_sub(created_at_unix_ms),
        );
    }
    if let Err(error) =
        publish_settlement_timestamp_to_artifact_stores(state, batch_id, &submission).await
    {
        eprintln!("failed to publish settlement timestamp for batch {batch_id}: {error}");
    }

    Ok(submission)
}

async fn prove_and_record_auction_result(
    state: &AppState,
    batch_id: &str,
    record_onchain: bool,
) -> Result<Option<String>, String> {
    let transcript = fetch_transcript(state, batch_id)
        .await
        .map_err(|status| format!("failed to fetch transcript for auction proof: {status}"))?;
    let settlement_witness = {
        let settlement_witnesses = state.settlement_witnesses.read().await;
        settlement_witnesses
            .get(batch_id)
            .cloned()
            .ok_or_else(|| "settlement witness not prepared for auction proof".to_string())?
    };
    prove_and_record_auction_result_with_inputs(
        state,
        batch_id,
        transcript,
        settlement_witness,
        record_onchain,
    )
    .await
}

async fn prove_and_record_auction_result_for_member(
    state: &AppState,
    member: &NativeAggregationPreparedMember,
    record_onchain: bool,
) -> Result<Option<String>, String> {
    prove_and_record_auction_result_with_inputs(
        state,
        &member.witness.batch_id.0,
        member.transcript.clone(),
        member.witness.clone(),
        record_onchain,
    )
    .await
}

async fn prove_and_record_auction_result_with_inputs(
    state: &AppState,
    batch_id: &str,
    transcript: SettlementTranscript,
    settlement_witness: SettlementWitness,
    record_onchain: bool,
) -> Result<Option<String>, String> {
    let tx_prover_url = state.native_tx_prover_url.clone();
    let executor = state
        .starknet_executor
        .clone()
        .ok_or_else(|| "native auction proof requires Starknet executor config".to_string())?;
    let auction_order_witnesses = fetch_auction_order_witnesses(state, batch_id)
        .await
        .map_err(|status| format!("failed to fetch auction order witnesses: {status}"))?;
    let transcript_commitment =
        settlement_transcript_commitment(&transcript).map_err(|error| error.to_string())?;
    if settlement_witness.transcript_commitment != transcript_commitment {
        return Err("auction proof transcript commitment does not match settlement witness".into());
    }
    let batch_id_felt = encode_starknet_felt("batch-id", &transcript.batch_id.0);
    let order_commitment_root =
        normalize_felt_hex(&transcript.order_commitment_root).map_err(|error| error.to_string())?;
    let admission_root = auction_admission_root(&settlement_witness, &auction_order_witnesses)
        .map_err(|error| format!("failed to compute admission root: {error}"))?;
    let (admission_already_recorded, auction_result_already_recorded) = if record_onchain {
        let recorded_admission = fetch_verified_batch_commitment(
            &executor,
            &state.auction_verifier_address,
            "verified_admission_root",
            &batch_id_felt,
        )
        .await?;
        let recorded_auction_result = fetch_verified_batch_commitment(
            &executor,
            &state.auction_verifier_address,
            "verified_auction_transcript",
            &batch_id_felt,
        )
        .await?;
        let admission_root_felt = parse_felt(&admission_root, "admission root")?;
        let transcript_commitment_felt =
            parse_felt(&transcript_commitment, "transcript commitment")?;
        reconcile_verified_auction_records(
            recorded_admission,
            admission_root_felt,
            recorded_auction_result,
            transcript_commitment_felt,
        )?
    } else {
        (false, false)
    };
    if auction_result_already_recorded {
        return Ok(None);
    }
    let expected_admission_message_hash = admission_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &batch_id_felt,
        &order_commitment_root,
        &admission_root,
    )
    .map_err(|error| error.to_string())?;
    let serialized_admission_witness =
        build_admission_serialized_input(&settlement_witness, &auction_order_witnesses)
            .map_err(|error| format!("failed to serialize admission witness: {error}"))?;
    let admission_program_calldata = build_native_proof_program_calldata(
        &state.auction_verifier_address,
        &serialized_admission_witness,
    )?;
    let admission_compilation_call = StarknetCall {
        contract_address: normalize_nonzero_felt(
            &state.native_proof_program_address,
            "native_proof_program_address",
        )?,
        entrypoint: "compile_admission_proof".into(),
        calldata: admission_program_calldata,
    };
    let admission_execution_request = build_native_execution_request(
        &executor,
        &admission_compilation_call,
        NativeTransactionMode::ProofOnly,
    )
    .await?;
    let admission_rpc_request = NativeProverRpcRequest {
        jsonrpc: "2.0".into(),
        id: 1,
        method: "starknet_proveTransaction".into(),
        params: (
            admission_execution_request.block_id.clone(),
            admission_execution_request.transaction.clone(),
        ),
    };

    let mut final_admission_response_value = None;
    let mut final_admission_result = None;
    let mut last_admission_error = None;
    for attempt in 1..=state.native_prover_attempts {
        match request_native_proof(state, &tx_prover_url, &admission_rpc_request).await {
            Ok((result, response_value)) => {
                final_admission_result = Some(result);
                final_admission_response_value = Some(response_value);
                break;
            }
            Err(error) if attempt < state.native_prover_attempts => {
                eprintln!(
                    "native admission prover attempt {attempt}/{attempts} failed for batch {batch_id}: {error}",
                    attempts = state.native_prover_attempts
                );
                last_admission_error = Some(error);
                sleep(Duration::from_millis(state.native_prover_retry_interval_ms)).await;
            }
            Err(error) => {
                last_admission_error = Some(error);
                break;
            }
        }
    }
    let admission_response_value = final_admission_response_value.ok_or_else(|| {
        last_admission_error.unwrap_or_else(|| "native admission prover returned no result".into())
    })?;
    let admission_result = final_admission_result
        .ok_or_else(|| "native admission prover returned no result".to_string())?;
    validate_native_proof_facts(
        &admission_result.proof_facts,
        &expected_admission_message_hash,
    )?;

    let admission_stage_key = format!("{batch_id}-admission");
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), &admission_stage_key)
        .map_err(|status| format!("failed to clear admission proof outputs: {status}"))?;
    let admission_paths = proof_execution_paths(state.data_dir.as_ref(), &admission_stage_key);
    persist_json_file(
        &admission_paths.native_execution_request_path,
        &redact_native_execution_request(&admission_execution_request),
    )
    .map_err(status_to_error)?;
    fs::write(&admission_paths.proof_path, admission_result.proof.trim())
        .map_err(|error| format!("failed to persist native admission proof: {error}"))?;
    persist_json_file(
        &admission_paths.public_inputs_path,
        &admission_result.proof_facts,
    )
    .map_err(status_to_error)?;
    persist_json_file(
        &admission_paths.stdout_path,
        &serde_json::json!({
            "request": redact_native_prover_request(&admission_rpc_request),
            "response": admission_response_value,
        }),
    )
    .map_err(status_to_error)?;
    fs::write(&admission_paths.stderr_path, "")
        .map_err(|error| format!("failed to persist native admission stderr log: {error}"))?;

    let provider = if record_onchain {
        let provider = JsonRpcClient::new(starknet_http_transport(
            Url::parse(&executor.rpc_url)
                .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?,
        ));
        if admission_already_recorded {
            Some(provider)
        } else {
            let admission_record_call = StarknetCall {
                contract_address: normalize_nonzero_felt(
                    &state.auction_verifier_address,
                    "auction_verifier_address",
                )?,
                entrypoint: "record_admission_root_with_proof_facts".into(),
                calldata: vec![
                    batch_id_felt.clone(),
                    order_commitment_root.clone(),
                    admission_root.clone(),
                ],
            };
            let admission_tx_hash = submit_native_invoke_with_typed_sdk_retry(
                state,
                &executor,
                &admission_record_call,
                admission_result.proof.clone(),
                &admission_result.proof_facts,
            )
            .await
            .map_err(|error| format!("failed to record native admission proof: {error}"))?;
            let admission_receipt = wait_for_accepted_receipt(
            &provider,
            parse_felt(&admission_tx_hash, "admission transaction hash")?,
        )
        .await
        .ok_or_else(|| {
            format!(
                "admission proof transaction {admission_tx_hash} was not accepted before settlement"
            )
        })?;
            if let ExecutionResult::Reverted { reason } =
                admission_receipt.receipt.execution_result()
            {
                return Err(format!(
                    "admission proof transaction {admission_tx_hash} reverted onchain: {reason}"
                ));
            }
            Some(provider)
        }
    } else {
        None
    };

    let expected_proof_message_hash = auction_result_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &batch_id_felt,
        &order_commitment_root,
        &admission_root,
        &transcript_commitment,
    )
    .map_err(|error| error.to_string())?;
    let serialized_native_witness =
        build_auction_result_serialized_input(&settlement_witness, &auction_order_witnesses)
            .map_err(|error| format!("failed to serialize auction result witness: {error}"))?;
    let proof_program_calldata = build_native_proof_program_calldata(
        &state.auction_verifier_address,
        &serialized_native_witness,
    )?;
    let proof_compilation_call = StarknetCall {
        contract_address: normalize_nonzero_felt(
            &state.native_proof_program_address,
            "native_proof_program_address",
        )?,
        entrypoint: "compile_auction_result_proof".into(),
        calldata: proof_program_calldata,
    };
    let execution_request = build_native_execution_request(
        &executor,
        &proof_compilation_call,
        NativeTransactionMode::ProofOnly,
    )
    .await?;
    let rpc_request = NativeProverRpcRequest {
        jsonrpc: "2.0".into(),
        id: 1,
        method: "starknet_proveTransaction".into(),
        params: (
            execution_request.block_id.clone(),
            execution_request.transaction.clone(),
        ),
    };

    let mut final_response_value = None;
    let mut final_result = None;
    let mut last_error = None;
    for attempt in 1..=state.native_prover_attempts {
        match request_native_proof(state, &tx_prover_url, &rpc_request).await {
            Ok((result, response_value)) => {
                final_result = Some(result);
                final_response_value = Some(response_value);
                break;
            }
            Err(error) if attempt < state.native_prover_attempts => {
                eprintln!(
                    "native auction-result prover attempt {attempt}/{attempts} failed for batch {batch_id}: {error}",
                    attempts = state.native_prover_attempts
                );
                last_error = Some(error);
                sleep(Duration::from_millis(state.native_prover_retry_interval_ms)).await;
            }
            Err(error) => {
                last_error = Some(error);
                break;
            }
        }
    }
    let response_value = final_response_value.ok_or_else(|| {
        last_error.unwrap_or_else(|| "native auction-result prover returned no result".into())
    })?;
    let result = final_result
        .ok_or_else(|| "native auction-result prover returned no result".to_string())?;
    validate_native_proof_facts(&result.proof_facts, &expected_proof_message_hash)?;

    let stage_key = format!("{batch_id}-auction-result");
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), &stage_key)
        .map_err(|status| format!("failed to clear auction proof outputs: {status}"))?;
    let paths = proof_execution_paths(state.data_dir.as_ref(), &stage_key);
    persist_json_file(
        &paths.native_execution_request_path,
        &redact_native_execution_request(&execution_request),
    )
    .map_err(status_to_error)?;
    fs::write(&paths.proof_path, result.proof.trim())
        .map_err(|error| format!("failed to persist native auction-result proof: {error}"))?;
    persist_json_file(&paths.public_inputs_path, &result.proof_facts).map_err(status_to_error)?;
    persist_json_file(
        &paths.stdout_path,
        &serde_json::json!({
            "request": redact_native_prover_request(&rpc_request),
            "response": response_value,
        }),
    )
    .map_err(status_to_error)?;
    fs::write(&paths.stderr_path, "")
        .map_err(|error| format!("failed to persist native auction-result stderr log: {error}"))?;

    if record_onchain {
        let Some(provider) = provider else {
            return Err("native auction-result recording requires a Starknet RPC provider".into());
        };
        let record_call = StarknetCall {
            contract_address: normalize_nonzero_felt(
                &state.auction_verifier_address,
                "auction_verifier_address",
            )?,
            entrypoint: "record_auction_result_with_proof_facts".into(),
            calldata: vec![
                batch_id_felt,
                order_commitment_root,
                admission_root,
                transcript_commitment,
            ],
        };
        let tx_hash = submit_native_invoke_with_typed_sdk_retry(
            state,
            &executor,
            &record_call,
            result.proof.clone(),
            &result.proof_facts,
        )
        .await
        .map_err(|error| format!("failed to record native auction-result proof: {error}"))?;
        let receipt = wait_for_accepted_receipt(
            &provider,
            parse_felt(&tx_hash, "auction-result transaction hash")?,
        )
        .await
        .ok_or_else(|| {
            format!("auction-result proof transaction {tx_hash} was not accepted before settlement")
        })?;
        match receipt.receipt.execution_result() {
            ExecutionResult::Succeeded => Ok(Some(tx_hash)),
            ExecutionResult::Reverted { reason } => Err(format!(
                "auction-result proof transaction {tx_hash} reverted onchain: {reason}"
            )),
        }
    } else {
        Ok(None)
    }
}

async fn prepare_private_auction_batch_inner(
    state: &AppState,
    batch_id: &str,
) -> Result<PreparedBatchStatus, StatusCode> {
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=prune_payloads start");
    prune_private_order_payloads(state).await?;
    prune_private_liquidity_position_payloads(state).await?;
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=fetch_batch start");
    let batch = fetch_batch_order_set(state, batch_id).await?;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=fetch_batch ok status={:?} orders={} liquidity_lifecycle={}",
        batch_id,
        batch.batch.status,
        batch.orders.len(),
        batch.liquidity_position_lifecycle_submissions.len()
    );
    let private_activity_count =
        batch.orders.len() + batch.liquidity_position_lifecycle_submissions.len();
    if state.max_provable_batch_orders > 0
        && private_activity_count as u64 > state.max_provable_batch_orders
    {
        eprintln!(
            "prepare_private_auction_batch batch_id={} failed=max_provable_batch_orders private_activity={} limit={}",
            batch_id, private_activity_count, state.max_provable_batch_orders
        );
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let pair = state
        .product_config
        .enabled_pair(&batch.batch.pair_id)
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=decrypt_orders start");
    let records = decrypt_private_auction_orders(state, &batch, &pair).await?;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=decrypt_orders ok records={}",
        batch_id,
        records.len()
    );
    eprintln!(
        "prepare_private_auction_batch batch_id={batch_id} stage=resolve_liquidity_positions start"
    );
    let liquidity_position_witnesses =
        resolve_private_liquidity_position_witnesses(state, &batch).await?;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=resolve_liquidity_positions ok witnesses={}",
        batch_id,
        liquidity_position_witnesses.len()
    );
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=fetch_root_history start");
    let indexed_history =
        fetch_indexed_root_history_witnesses(state, batch.batch.epoch_id, batch_id).await?;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=fetch_root_history ok witnesses={}",
        batch_id,
        indexed_history.len()
    );
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=fetch_current_roots start");
    let prior_roots = fetch_current_settlement_roots(state).await?;
    let prior_note_root_nonzero =
        normalize_felt_hex(&prior_roots.note_root).map_err(|_| StatusCode::BAD_GATEWAY)? != "0x0";
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=fetch_current_roots ok prior_note_root_nonzero={}",
        batch_id, prior_note_root_nonzero
    );
    let historical_note_consolidation_history = {
        let note_consolidation_history = state.note_consolidation_history.read().await;
        note_consolidation_history
            .values()
            .cloned()
            .collect::<Vec<_>>()
    };
    let historical_withdrawal_nullifiers = {
        let withdrawal_nullifiers = state.settlement_output_withdrawal_nullifiers.read().await;
        withdrawal_nullifiers.values().cloned().collect::<Vec<_>>()
    };
    eprintln!(
        "prepare_private_auction_batch batch_id={batch_id} stage=fetch_renewal_cancel_markers start"
    );
    let renewal_cancel_markers = fetch_indexed_renewal_cancel_markers(state).await?;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=fetch_renewal_cancel_markers ok records={}",
        batch_id,
        renewal_cancel_markers.len()
    );
    let historical_witnesses = {
        let settlement_witnesses = state.settlement_witnesses.read().await;
        let onchain_submissions = state.onchain_submissions.read().await;
        let confirmed_local_witnesses =
            confirmed_settlement_witnesses_from_maps(&settlement_witnesses, &onchain_submissions);
        let mut merged = indexed_history
            .into_iter()
            .map(|witness| (witness.batch_id.0.clone(), witness))
            .collect::<BTreeMap<_, _>>();
        merged.extend(
            confirmed_local_witnesses
                .into_iter()
                .filter(|witness| witness.batch_id.0 != batch_id)
                .map(|witness| (witness.batch_id.0.clone(), witness)),
        );
        let merged_witnesses = merged.into_values().collect::<Vec<_>>();
        let confirmed_witnesses = filter_root_history_witnesses_for_current_roots(
            state,
            merged_witnesses,
            &prior_roots,
            &historical_note_consolidation_history,
            &historical_withdrawal_nullifiers,
            &renewal_cancel_markers,
        )?;
        if let Err(error) =
            validate_batch_nullifier_freshness(batch_id, &records, confirmed_witnesses.iter())
        {
            eprintln!(
                "prepare_private_auction_batch batch_id={} stage=confirmed_root_history failed=nullifier_freshness error={}",
                batch_id, error
            );
            record_prepare_job_error(state, batch_id, format!("batch witness rejected: {error}"))
                .await?;
            return Err(StatusCode::CONFLICT);
        }
        confirmed_witnesses
    };
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=confirmed_root_history ok witnesses={}",
        batch_id,
        historical_witnesses.len()
    );
    let historical_note_consolidation_history = {
        let note_consolidation_history = state.note_consolidation_history.read().await;
        note_consolidation_history
            .values()
            .cloned()
            .collect::<Vec<_>>()
    };
    let historical_withdrawal_nullifiers = {
        let withdrawal_nullifiers = state.settlement_output_withdrawal_nullifiers.read().await;
        withdrawal_nullifiers.values().cloned().collect::<Vec<_>>()
    };
    let needs_note_membership = (!records.is_empty() || !liquidity_position_witnesses.is_empty())
        && prior_note_root_nonzero;
    let deposit_activations = if needs_note_membership {
        eprintln!(
            "prepare_private_auction_batch batch_id={batch_id} stage=fetch_deposit_activations start"
        );
        fetch_indexed_deposit_activations(state).await?
    } else {
        Vec::new()
    };
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=fetch_deposit_activations ok records={}",
        batch_id,
        deposit_activations.len()
    );
    let note_root_transitions = if needs_note_membership {
        eprintln!(
            "prepare_private_auction_batch batch_id={batch_id} stage=fetch_note_root_transitions start"
        );
        fetch_note_root_transition_records(state).await?
    } else {
        Vec::new()
    };
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=fetch_note_root_transitions ok records={}",
        batch_id,
        note_root_transitions.len()
    );
    let liquidity_position_market_contexts = liquidity_position_market_contexts_for_batch(state)?;
    let liquidity_attribution_signer_private_key = state
        .auction_private_keys
        .first()
        .map(|key| key.private_key.as_str())
        .ok_or_else(|| {
            eprintln!(
                "prepare_private_auction_batch batch_id={batch_id} stage=build_artifacts failed=missing_attribution_signer"
            );
            StatusCode::SERVICE_UNAVAILABLE
        })?;
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=build_artifacts start");
    let artifacts = build_settlement_artifacts(
        batch_id,
        &batch.batch,
        &pair,
        &records,
        &liquidity_position_witnesses,
        SettlementBuildContext {
            product_config: &state.product_config,
            liquidity_position_market_contexts: &liquidity_position_market_contexts,
            prior_roots: &prior_roots,
            initial_note_root: &state.initial_note_root,
            deposit_activations: &deposit_activations,
            note_root_transitions: &note_root_transitions,
            prior_settlement_witnesses: &historical_witnesses,
            prior_renewal_cancel_markers: &renewal_cancel_markers,
            prior_note_consolidation_history: &historical_note_consolidation_history,
            prior_withdrawal_nullifiers: &historical_withdrawal_nullifiers,
            protocol_fee_recipient: &state.protocol_fee_recipient,
            relay_fee_recipient: &state.relay_fee_recipient,
            protocol_fee_note_recipient: &state.protocol_fee_note_recipient,
            relay_fee_note_recipient: &state.relay_fee_note_recipient,
            liquidity_attribution_signer_private_key,
        },
    )?;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=build_artifacts ok matched_orders={} outputs={}",
        batch_id,
        artifacts.transcript.matched_orders.len(),
        artifacts.transcript.output_notes.len()
    );
    let matched_volume =
        artifacts
            .transcript
            .matched_orders
            .iter()
            .try_fold(0_u128, |total, entry| {
                total
                    .checked_add(entry.filled_amount)
                    .ok_or(StatusCode::CONFLICT)
            })?;
    let candidate_clearing_price = if artifacts.transcript.matched_orders.is_empty() {
        compute_candidate_clearing_price(&records, pair.price_base_scale)?
    } else {
        Some(artifacts.transcript.clearing_price)
    };
    let liquidity = build_batch_liquidity_report(
        &records,
        artifacts.transcript.clearing_price,
        matched_volume,
        0,
        pair.price_base_scale,
    );
    let prepared_artifacts = artifacts;
    let status = PreparedBatchStatus {
        batch_id: prepared_artifacts.transcript.batch_id.clone(),
        pair_id: batch.batch.pair_id.clone(),
        order_count: records.len() as u64 + liquidity_position_witnesses.len() as u64,
        state: if prepared_artifacts.transcript.matched_orders.is_empty() {
            if prepared_artifacts
                .transcript
                .liquidity_position_transitions
                .is_empty()
            {
                "proof-auction-no-match".into()
            } else {
                "proof-auction-ready".into()
            }
        } else {
            "proof-auction-ready".into()
        },
        candidate_clearing_price,
        matched_volume,
        transcript_available: true,
        liquidity,
        order_execution_reports: prepared_artifacts.order_execution_reports.clone(),
    };

    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=store_artifacts start");
    store_prepared_batch_artifacts(state, &prepared_artifacts).await?;
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=store_artifacts ok");
    {
        let mut settlement_witnesses = state.settlement_witnesses.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            SETTLEMENT_WITNESSES_DIR,
            &mut settlement_witnesses,
            batch_id.into(),
            prepared_artifacts.settlement_witness.clone(),
        )?;
    }

    Ok(status)
}

async fn decrypt_private_auction_orders(
    state: &AppState,
    batch: &BatchOrderSet,
    pair: &ProductPairConfig,
) -> Result<Vec<DecryptedOrderRecord>, StatusCode> {
    let private_order_payloads = state.private_order_payloads.read().await;
    let mut records = Vec::with_capacity(batch.orders.len());
    for record in &batch.orders {
        let order_bundle =
            resolve_private_order_payload_bundle(record, &private_order_payloads, state)
                .map_err(|_| StatusCode::CONFLICT)?;
        let payload = decrypt_order_bundle(&order_bundle, &state.auction_private_keys)
            .map_err(|_| StatusCode::CONFLICT)?;

        validate_private_order_risk_limits(state, &payload.order)
            .map_err(|_| StatusCode::CONFLICT)?;
        let funding_notes = payload
            .effective_funding_notes()
            .into_iter()
            .cloned()
            .collect();
        let funding_note = payload.funding_note.clone();
        let order = payload.order;
        let funding_authorization = payload.funding_authorization;
        records.push(DecryptedOrderRecord {
            order_commitment: record.order_bundle.order_commitment.clone(),
            cancellation_auth_tag: order_bundle.cancellation_auth_tag.clone(),
            order,
            funding_note,
            funding_notes,
            funding_authorization,
        });
    }
    let cover_orders = build_heartbeat_cover_orders(
        state.heartbeat_cover_secret.as_str(),
        &batch.batch,
        &pair.base_asset_id,
        &pair.quote_asset_id,
        pair.heartbeat_cover_price,
        records.len(),
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    records.extend(cover_orders.into_iter().map(|cover| {
        let funding_notes = cover
            .payload
            .effective_funding_notes()
            .into_iter()
            .cloned()
            .collect();
        let funding_note = cover.payload.funding_note.clone();
        let order = cover.payload.order;
        let funding_authorization = cover.payload.funding_authorization;
        DecryptedOrderRecord {
            order_commitment: cover.order_commitment,
            cancellation_auth_tag: String::new(),
            order,
            funding_note,
            funding_notes,
            funding_authorization,
        }
    }));

    let root = ordered_felt_list_commitment(
        "zylith/batch-order-root",
        &records
            .iter()
            .map(|record| record.order_commitment.0.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    if root != batch.batch.order_commitment_root {
        return Err(StatusCode::CONFLICT);
    }
    Ok(records)
}

async fn resolve_private_liquidity_position_witnesses(
    state: &AppState,
    batch: &BatchOrderSet,
) -> Result<Vec<LiquidityPositionTransitionWitness>, StatusCode> {
    if batch.liquidity_position_lifecycle_submissions.is_empty() {
        return Ok(Vec::new());
    }
    if state.order_ingress_receipt_secrets.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let private_payloads = state.private_liquidity_position_payloads.read().await;
    let mut witnesses = Vec::with_capacity(batch.liquidity_position_lifecycle_submissions.len());
    for record in &batch.liquidity_position_lifecycle_submissions {
        let submission = &record.submission;
        validate_liquidity_position_ingress_receipt_for_manifest_with_secrets(
            submission,
            state.order_ingress_receipt_secrets.as_ref(),
        )
        .map_err(|_| StatusCode::CONFLICT)?;
        if submission.batch_id != batch.batch.batch_id
            || submission.pair_id != batch.batch.pair_id
            || submission.epoch_id != batch.batch.epoch_id
        {
            return Err(StatusCode::CONFLICT);
        }
        let receipt = submission
            .ingress_receipt
            .as_ref()
            .ok_or(StatusCode::CONFLICT)?;
        let payload_record = private_payloads
            .get(&submission.lifecycle_id)
            .ok_or(StatusCode::CONFLICT)?;
        if payload_record.payload_commitment != receipt.payload_commitment
            || payload_record.transition_commitment != submission.transition_commitment
            || payload_record.pair_id != submission.pair_id
            || payload_record.batch_id != submission.batch_id
            || payload_record.epoch_id != submission.epoch_id
            || payload_record.receipt != *receipt
        {
            return Err(StatusCode::CONFLICT);
        }
        let actual_payload_commitment = liquidity_position_transition_witness_payload_commitment(
            &payload_record.transition_witness,
        )
        .map_err(|_| StatusCode::CONFLICT)?;
        let actual_transition_commitment =
            liquidity_position_transition_commitment(&payload_record.transition_witness)
                .map_err(|_| StatusCode::CONFLICT)?;
        if actual_payload_commitment != receipt.payload_commitment
            || actual_transition_commitment != submission.transition_commitment
        {
            return Err(StatusCode::CONFLICT);
        }
        validate_private_liquidity_position_ingress_request(
            &submission.pair_id,
            &submission.batch_id,
            submission.epoch_id,
            &payload_record.transition_witness,
        )?;
        witnesses.push(payload_record.transition_witness.clone());
    }
    Ok(witnesses)
}

fn validate_batch_nullifier_freshness<'a>(
    _current_batch_id: &str,
    records: &[DecryptedOrderRecord],
    _historical_witnesses: impl IntoIterator<Item = &'a SettlementWitness>,
) -> Result<(), String> {
    let mut current_nullifiers = BTreeMap::new();
    for record in records {
        for note in &record.funding_notes {
            let commitment = note
                .commitment()
                .map_err(|error| format!("invalid funding note: {error}"))?;
            let commitment_hex = normalize_felt_hex(&commitment.0)
                .map_err(|error| format!("invalid funding note commitment: {error}"))?;
            let nullifier = nullifier_from_note_secret(&commitment, &note.blinding)
                .map_err(|error| format!("invalid funding nullifier: {error}"))?;
            let nullifier = normalize_felt_hex(&nullifier.0)
                .map_err(|error| format!("invalid funding nullifier: {error}"))?;
            if current_nullifiers
                .insert(nullifier, commitment_hex)
                .is_some()
            {
                return Err("duplicate funding nullifier in current batch".into());
            }
        }
    }

    Ok(())
}

fn funding_note_commitments_for_report(
    _funding_note: &Note,
    funding_notes: &[Note],
) -> Result<Vec<NoteCommitment>, StatusCode> {
    if funding_notes.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    funding_notes
        .iter()
        .map(|note| {
            note.commitment()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        })
        .collect()
}

async fn fetch_auction_order_witnesses(
    state: &AppState,
    batch_id: &str,
) -> Result<Vec<AuctionOrderWitness>, StatusCode> {
    if let Ok(batch) = fetch_coordinator_batch_order_set(state, batch_id).await {
        let pair = state
            .product_config
            .enabled_pair(&batch.batch.pair_id)
            .cloned()
            .ok_or(StatusCode::CONFLICT)?;
        let records = decrypt_private_auction_orders(state, &batch, &pair).await?;
        return Ok(records
            .into_iter()
            .map(auction_order_witness_from_record)
            .collect());
    }

    if let Some(published) = state
        .prepared_batch_artifacts
        .read()
        .await
        .get(batch_id)
        .cloned()
    {
        let witnesses = auction_order_witnesses_from_prepared_artifact(state, published)?;
        return Ok(witnesses);
    }

    let batch = fetch_batch_order_set(state, batch_id).await?;
    let pair = state
        .product_config
        .enabled_pair(&batch.batch.pair_id)
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    let records = decrypt_private_auction_orders(state, &batch, &pair).await?;
    Ok(records
        .into_iter()
        .map(auction_order_witness_from_record)
        .collect())
}

fn auction_order_witness_from_record(record: DecryptedOrderRecord) -> AuctionOrderWitness {
    AuctionOrderWitness {
        order_commitment: record.order_commitment,
        order: record.order,
        funding_note: record.funding_note,
        funding_notes: record.funding_notes,
        funding_authorization: record.funding_authorization,
    }
}

fn auction_order_witnesses_from_prepared_artifact(
    state: &AppState,
    published: PublishedBatchArtifacts,
) -> Result<Vec<AuctionOrderWitness>, StatusCode> {
    let settlement_witness = published.settlement_witness;
    let pair = state
        .product_config
        .enabled_pair(&settlement_witness.pair_id)
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    let pair_id = settlement_witness.pair_id.clone();
    let batch_id = settlement_witness.batch_id.clone();
    let mut witnesses = settlement_witness
        .matched_order_witnesses
        .into_iter()
        .map(|matched| AuctionOrderWitness {
            order_commitment: matched.order_commitment,
            order: OrderIntent {
                pair_id: pair_id.clone(),
                batch_id: batch_id.clone(),
                side: matched.side,
                order_type: matched.order_type,
                relay_mode: matched.relay_mode,
                liquidity_curve: matched.liquidity_curve,
                limit_price: matched.limit_price,
                amount: matched.order_amount,
                min_fill: matched.min_fill,
                time_in_force: matched.time_in_force,
                expiry_epoch: matched.expiry_epoch,
                order_nonce: matched.order_nonce,
                parent_order_commitment: matched.parent_order_commitment,
                parent_child_index: matched.parent_child_index,
                parent_secret_commitment: matched.parent_secret_commitment,
                parent_cancel_authority: matched.parent_cancel_authority,
                parent_authorization_secret: matched.parent_authorization_secret,
                funding_note_ref: matched.funding_note_ref,
                funding_nullifier: matched.funding_nullifier,
                recipient_owner_public_key: matched.recipient_owner_public_key,
                recipient_spend_authority: matched.recipient_spend_authority,
                recipient_withdraw_authority: matched.recipient_withdraw_authority,
                recipient_residual_withdraw_authority: matched
                    .recipient_residual_withdraw_authority,
                auditor_view_allowed: matched.auditor_view_allowed,
            },
            funding_note: matched.funding_note,
            funding_notes: matched.funding_notes,
            funding_authorization: matched.funding_authorization,
        })
        .collect::<Vec<_>>();
    if witnesses.is_empty() {
        let batch = BatchSummary {
            batch_id,
            pair_id,
            epoch_id: settlement_witness.batch_epoch,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: zylith_core::heartbeat_cover_order_count(0) as u64,
            order_commitment_root: settlement_witness.order_commitment_root.clone(),
            encrypted_order_set_commitment: settlement_witness.encrypted_order_set_commitment,
        };
        witnesses.extend(
            build_heartbeat_cover_orders(
                state.heartbeat_cover_secret.as_str(),
                &batch,
                &pair.base_asset_id,
                &pair.quote_asset_id,
                pair.heartbeat_cover_price,
                0,
            )
            .map_err(|_| StatusCode::CONFLICT)?
            .into_iter()
            .map(|cover| {
                auction_order_witness_from_record(DecryptedOrderRecord {
                    order_commitment: cover.order_commitment,
                    cancellation_auth_tag: String::new(),
                    order: cover.payload.order,
                    funding_note: cover.payload.funding_note,
                    funding_notes: cover.payload.funding_notes,
                    funding_authorization: cover.payload.funding_authorization,
                })
            }),
        );
    }
    let root = ordered_felt_list_commitment(
        "zylith/batch-order-root",
        &witnesses
            .iter()
            .map(|witness| witness.order_commitment.0.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    if root != settlement_witness.order_commitment_root {
        return Err(StatusCode::CONFLICT);
    }
    Ok(witnesses)
}

async fn fetch_current_settlement_roots(state: &AppState) -> Result<SettlementRoots, StatusCode> {
    let Some(executor) = &state.starknet_executor else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    if state.auction_verifier_address.trim().is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let rpc_url = Url::parse(&executor.rpc_url).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let provider = JsonRpcClient::new(starknet_http_transport(rpc_url));
    let verifier_address = parse_felt(
        &state.auction_verifier_address,
        "ZYLITH_AUCTION_VERIFIER_ADDRESS",
    )
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let call = FunctionCall {
        contract_address: verifier_address,
        entry_point_selector: get_selector_from_name("current_settlement_roots")
            .map_err(|_| StatusCode::BAD_GATEWAY)?,
        calldata: vec![],
    };
    let result = provider
        .call(call, BlockId::Tag(BlockTag::Latest))
        .await
        .map_err(|error| {
            eprintln!(
                "fetch_current_settlement_roots failed auction_verifier={} rpc={} error={error:?}",
                state.auction_verifier_address, executor.rpc_url
            );
            StatusCode::BAD_GATEWAY
        })?;
    if result.len() != 4 {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let liquidity_position_result = provider
        .call(
            FunctionCall {
                contract_address: verifier_address,
                entry_point_selector: get_selector_from_name("current_liquidity_position_root")
                    .map_err(|_| StatusCode::BAD_GATEWAY)?,
                calldata: vec![],
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .map_err(|error| {
            eprintln!(
                "fetch_current_liquidity_position_root failed auction_verifier={} rpc={} error={error:?}",
                state.auction_verifier_address, executor.rpc_url
            );
            StatusCode::BAD_GATEWAY
        })?;
    if liquidity_position_result.len() != 1 {
        return Err(StatusCode::BAD_GATEWAY);
    }

    Ok(SettlementRoots {
        note_root: format!("{:#x}", result[0]),
        nullifier_root: format!("{:#x}", result[1]),
        renewal_root: format!("{:#x}", result[2]),
        fee_root: format!("{:#x}", result[3]),
        liquidity_position_root: format!("{:#x}", liquidity_position_result[0]),
    })
}

async fn fetch_verified_batch_commitment(
    executor: &StarknetExecutorConfig,
    verifier_address: &str,
    entrypoint: &str,
    batch_id: &str,
) -> Result<Felt, String> {
    let provider = JsonRpcClient::new(starknet_http_transport(
        Url::parse(&executor.rpc_url)
            .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?,
    ));
    let result = provider
        .call(
            FunctionCall {
                contract_address: parse_felt(verifier_address, "auction verifier address")?,
                entry_point_selector: get_selector_from_name(entrypoint)
                    .map_err(|error| format!("failed to compute {entrypoint} selector: {error}"))?,
                calldata: vec![parse_felt(batch_id, "batch id")?],
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .map_err(|error| format!("failed to query {entrypoint}: {error}"))?;
    if result.len() != 1 {
        return Err(format!(
            "{entrypoint} returned {} values instead of one",
            result.len()
        ));
    }
    Ok(result[0])
}

fn reconcile_verified_auction_records(
    recorded_admission: Felt,
    expected_admission: Felt,
    recorded_auction_result: Felt,
    expected_transcript: Felt,
) -> Result<(bool, bool), String> {
    if recorded_admission != Felt::ZERO && recorded_admission != expected_admission {
        return Err("onchain admission root does not match the prepared auction".into());
    }
    if recorded_auction_result != Felt::ZERO && recorded_auction_result != expected_transcript {
        return Err("onchain auction result does not match the prepared transcript".into());
    }
    let admission_already_recorded = recorded_admission == expected_admission;
    let auction_result_already_recorded = recorded_auction_result == expected_transcript;
    if auction_result_already_recorded && !admission_already_recorded {
        return Err("onchain auction result exists without its admission root".into());
    }
    Ok((admission_already_recorded, auction_result_already_recorded))
}

#[derive(Clone, Debug)]
struct NoteRootTransitionRecord {
    kind: u64,
    _key: String,
    batch_root: String,
    new_root: String,
}

#[derive(Debug, Deserialize)]
struct InternalDepositSyncStatus {
    synced_deposit_count: u64,
}

async fn fetch_note_root_transition_records(
    state: &AppState,
) -> Result<Vec<NoteRootTransitionRecord>, StatusCode> {
    let Some(executor) = &state.starknet_executor else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    if state.note_root_history_verifier_address.trim().is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let rpc_url = Url::parse(&executor.rpc_url).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let provider = JsonRpcClient::new(starknet_http_transport(rpc_url));
    let contract_address = parse_felt(
        &state.note_root_history_verifier_address,
        NOTE_ROOT_HISTORY_VERIFIER_ADDRESS_ENV,
    )
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let count_call = FunctionCall {
        contract_address,
        entry_point_selector: get_selector_from_name("note_root_transition_count")
            .map_err(|_| StatusCode::BAD_GATEWAY)?,
        calldata: vec![],
    };
    let count_result = provider
        .call(count_call, BlockId::Tag(BlockTag::Latest))
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let count: usize = count_result
        .first()
        .ok_or(StatusCode::BAD_GATEWAY)?
        .to_biguint()
        .try_into()
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let max_transitions = env_parse_or_default(
        PROVER_MAX_ROOT_TRANSITIONS_ENV,
        DEFAULT_PROVER_MAX_ROOT_TRANSITIONS,
    );
    if count > max_transitions {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let refresh_start = {
        let cached = state.note_root_transition_cache.read().await;
        note_root_transition_cache_refresh_start(cached.len(), count)
    };
    let mut records = {
        let cached = state.note_root_transition_cache.read().await;
        cached
            .iter()
            .take(refresh_start)
            .cloned()
            .collect::<Vec<_>>()
    };

    let selector =
        get_selector_from_name("note_root_transition").map_err(|_| StatusCode::BAD_GATEWAY)?;
    records.reserve(count.saturating_sub(records.len()));
    for transition_id in records.len()..count {
        let call = FunctionCall {
            contract_address,
            entry_point_selector: selector,
            calldata: vec![Felt::from(transition_id as u64)],
        };
        let result = provider
            .call(call, BlockId::Tag(BlockTag::Latest))
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        if result.len() != 4 {
            return Err(StatusCode::BAD_GATEWAY);
        }
        records.push(NoteRootTransitionRecord {
            kind: result[0]
                .to_biguint()
                .try_into()
                .map_err(|_| StatusCode::BAD_GATEWAY)?,
            _key: format!("{:#x}", result[1]),
            batch_root: format!("{:#x}", result[2]),
            new_root: format!("{:#x}", result[3]),
        });
    }
    {
        let mut cached = state.note_root_transition_cache.write().await;
        *cached = records.clone();
    }
    Ok(records)
}

fn note_root_transition_cache_refresh_start(cached_len: usize, onchain_count: usize) -> usize {
    if onchain_count < cached_len.saturating_sub(NOTE_ROOT_TRANSITION_CACHE_REVALIDATION_WINDOW) {
        return 0;
    }
    cached_len
        .min(onchain_count)
        .saturating_sub(NOTE_ROOT_TRANSITION_CACHE_REVALIDATION_WINDOW)
}

async fn fetch_indexed_deposit_activations(
    state: &AppState,
) -> Result<Vec<DepositActivationRecord>, StatusCode> {
    let sync_url = format!("{}/api/internal/sync/deposits", state.indexer_url);
    let response = apply_internal_auth(
        state.http_client.post(sync_url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let sync_status = decode_control_plane_json::<InternalDepositSyncStatus>(response).await?;

    let refresh_start = {
        let cached = state.deposit_activation_cache.read().await;
        deposit_activation_cache_refresh_start(&cached, sync_status.synced_deposit_count)
    };

    let mut records = {
        let cached = state.deposit_activation_cache.read().await;
        cached
            .iter()
            .filter(|record| record.activation_id < refresh_start)
            .cloned()
            .collect::<Vec<_>>()
    };
    let mut start = refresh_start;
    while start < sync_status.synced_deposit_count {
        let end = start
            .saturating_add(INDEXER_HISTORY_PAGE_SIZE - 1)
            .min(sync_status.synced_deposit_count.saturating_sub(1));
        let list_url = format!("{}/api/deposits/range/{}/{}", state.indexer_url, start, end);
        let response = state
            .http_client
            .get(list_url)
            .send()
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let mut page = decode_control_plane_json::<DepositActivationRecordList>(response)
            .await?
            .records;
        records.append(&mut page);
        start = end.saturating_add(1);
    }
    records.sort_by_key(|record| record.activation_id);
    let mut by_activation_id = BTreeMap::new();
    for record in records {
        by_activation_id.insert(record.activation_id, record);
    }
    let records = by_activation_id.into_values().collect::<Vec<_>>();
    {
        let mut cached = state.deposit_activation_cache.write().await;
        *cached = records.clone();
    }
    Ok(records)
}

fn deposit_activation_cache_refresh_start(
    cached: &[DepositActivationRecord],
    synced_deposit_count: u64,
) -> u64 {
    let cached_next_activation_id = cached
        .last()
        .map(|record| record.activation_id.saturating_add(1))
        .unwrap_or(0);
    if synced_deposit_count
        < cached_next_activation_id.saturating_sub(INDEXER_DEPOSIT_CACHE_REVALIDATION_WINDOW)
    {
        return 0;
    }
    cached_next_activation_id
        .min(synced_deposit_count)
        .saturating_sub(INDEXER_DEPOSIT_CACHE_REVALIDATION_WINDOW)
}

async fn fetch_indexed_renewal_cancel_markers(state: &AppState) -> Result<Vec<String>, StatusCode> {
    let url = format!(
        "{}/api/internal/renewal/cancel-markers",
        state.coordinator_url
    );
    let response = apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let list = decode_control_plane_json::<RenewalCancelMarkerList>(response).await?;
    let mut markers = list
        .records
        .into_iter()
        .map(|record| record.cancel_marker)
        .collect::<Vec<_>>();
    markers.sort();
    markers.dedup();
    Ok(markers)
}

async fn fetch_indexed_root_history_witnesses(
    state: &AppState,
    batch_epoch: u64,
    current_batch_id: &str,
) -> Result<Vec<SettlementWitness>, StatusCode> {
    if batch_epoch == 0 {
        return Ok(Vec::new());
    }
    let url = format!(
        "{}/api/internal/batches/root-history/epochs/0/{}",
        state.indexer_url,
        batch_epoch.saturating_sub(1)
    );
    let response = apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let archive = decode_control_plane_json::<SettlementRootHistoryArchive>(response).await?;

    Ok(archive
        .batches
        .into_iter()
        .filter(|batch| batch.batch_id.0 != current_batch_id)
        .map(root_history_batch_to_witness)
        .collect())
}

fn root_history_batch_to_witness(
    batch: zylith_core::SettlementRootHistoryBatch,
) -> SettlementWitness {
    SettlementWitness {
        batch_id: batch.batch_id,
        pair_id: batch.pair_id,
        batch_epoch: batch.batch_epoch,
        order_commitment_root: "0x0".into(),
        encrypted_order_set_commitment: "0x0".into(),
        transcript_commitment: "0x0".into(),
        auction_verifier_address: "0x0".into(),
        prior_note_root: batch.prior_note_root,
        prior_nullifier_root: batch.prior_nullifier_root,
        prior_renewal_root: batch.prior_renewal_root,
        prior_fee_root: batch.prior_fee_root,
        prior_liquidity_position_root: batch.prior_liquidity_position_root,
        new_nullifier_root: batch.new_nullifier_root,
        new_renewal_root: batch.new_renewal_root,
        new_liquidity_position_root: batch.new_liquidity_position_root,
        clearing_price: 0,
        price_base_scale: 1,
        taker_fee_bps: 0,
        relay_fee_bps: 0,
        protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
        relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT.into(),
        base_asset_id: AssetId("ROOT_HISTORY".into()),
        quote_asset_id: AssetId("ROOT_HISTORY".into()),
        matched_orders: Vec::new(),
        matched_order_witnesses: Vec::new(),
        consumed_inputs: batch.consumed_inputs,
        note_membership_witnesses: Vec::new(),
        nullifier_history: Vec::new(),
        nullifier_sparse_witnesses: Vec::new(),
        renewal_history: Vec::new(),
        renewal_child_uses: batch
            .renewal_entries
            .into_iter()
            .map(|entry| zylith_core::RenewalChildUse {
                parent_order_commitment: "0x0".into(),
                child_nullifier: entry,
            })
            .collect(),
        renewal_child_sparse_witnesses: Vec::new(),
        renewal_cancel_sparse_witnesses: Vec::new(),
        liquidity_position_transitions: batch.liquidity_position_transitions,
        liquidity_position_witnesses: Vec::new(),
        fees: Vec::new(),
        output_notes: batch.output_notes,
        output_note_preimages: Vec::new(),
        output_recovery_records: Vec::new(),
        output_recovery_dummy_commitments: Vec::new(),
        output_ciphertext_bundle_ref: "root-history".into(),
    }
}

fn filter_root_history_witnesses_for_current_roots(
    state: &AppState,
    witnesses: Vec<SettlementWitness>,
    roots: &SettlementRoots,
    note_consolidation_history: &[NoteConsolidationHistoryRecord],
    settlement_output_withdrawal_nullifiers: &[ConsumedInput],
    renewal_cancel_markers: &[String],
) -> Result<Vec<SettlementWitness>, StatusCode> {
    if !should_filter_root_history_against_onchain(state) {
        return Ok(witnesses);
    }

    select_root_history_witnesses_for_current_roots(
        witnesses,
        roots,
        note_consolidation_history,
        settlement_output_withdrawal_nullifiers,
        renewal_cancel_markers,
    )
}

fn select_root_history_witnesses_for_current_roots(
    witnesses: Vec<SettlementWitness>,
    roots: &SettlementRoots,
    note_consolidation_history: &[NoteConsolidationHistoryRecord],
    settlement_output_withdrawal_nullifiers: &[ConsumedInput],
    renewal_cancel_markers: &[String],
) -> Result<Vec<SettlementWitness>, StatusCode> {
    let zero = normalize_felt_hex("0x0").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let target_nullifier =
        normalize_felt_hex(&roots.nullifier_root).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let target_renewal =
        normalize_felt_hex(&roots.renewal_root).map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut candidates = witnesses;
    candidates.sort_by(|left, right| {
        left.batch_epoch
            .cmp(&right.batch_epoch)
            .then_with(|| left.batch_id.0.cmp(&right.batch_id.0))
    });

    let mut maintenance_consumed_inputs = note_consolidation_history
        .iter()
        .flat_map(|record| record.consumed_inputs.iter().cloned())
        .collect::<Vec<_>>();
    maintenance_consumed_inputs.extend(settlement_output_withdrawal_nullifiers.iter().cloned());

    let mut maintenance_renewal_entries = renewal_cancel_markers
        .iter()
        .map(|marker| normalize_felt_hex(marker).map_err(|_| StatusCode::CONFLICT))
        .collect::<Result<Vec<_>, StatusCode>>()?;
    maintenance_renewal_entries.sort();
    maintenance_renewal_entries.dedup();

    let mut selected_len = None;
    let mut last_computed_nullifier_root = None;
    let mut last_computed_renewal_root = None;
    for len in 0..=candidates.len() {
        let prefix = &candidates[..len];
        let (computed_nullifier_root, computed_renewal_root) = root_history_candidate_roots(
            prefix,
            &maintenance_consumed_inputs,
            &maintenance_renewal_entries,
        )?;
        last_computed_nullifier_root = Some(computed_nullifier_root);
        last_computed_renewal_root = Some(computed_renewal_root);

        if last_computed_nullifier_root.as_deref() == Some(target_nullifier.as_str())
            && last_computed_renewal_root.as_deref() == Some(target_renewal.as_str())
        {
            selected_len = Some(len);
        }
    }

    if let Some(len) = selected_len {
        return Ok(candidates.into_iter().take(len).collect());
    }

    let lineage_candidates =
        select_root_history_witness_lineage_subset(&candidates, &target_nullifier, &target_renewal);
    if !lineage_candidates.is_empty() && lineage_candidates.len() < candidates.len() {
        let (computed_nullifier_root, computed_renewal_root) = root_history_candidate_roots(
            &lineage_candidates,
            &maintenance_consumed_inputs,
            &maintenance_renewal_entries,
        )?;
        if computed_nullifier_root == target_nullifier && computed_renewal_root == target_renewal {
            return Ok(lineage_candidates);
        }
        last_computed_nullifier_root = Some(computed_nullifier_root);
        last_computed_renewal_root = Some(computed_renewal_root);
    }

    eprintln!(
        "filter_root_history_witnesses_for_current_roots failed missing target_nullifier={} target_renewal={} computed_nullifier={:?} computed_renewal={:?} witnesses={} maintenance_inputs={} maintenance_renewals={} zero={}",
        target_nullifier,
        target_renewal,
        last_computed_nullifier_root,
        last_computed_renewal_root,
        candidates.len(),
        maintenance_consumed_inputs.len(),
        maintenance_renewal_entries.len(),
        zero
    );
    Err(StatusCode::CONFLICT)
}

fn root_history_candidate_roots(
    candidates: &[SettlementWitness],
    maintenance_consumed_inputs: &[ConsumedInput],
    maintenance_renewal_entries: &[String],
) -> Result<(String, String), StatusCode> {
    let mut consumed_inputs = candidates
        .iter()
        .flat_map(|witness| witness.consumed_inputs.iter().cloned())
        .collect::<Vec<_>>();
    consumed_inputs.extend(maintenance_consumed_inputs.iter().cloned());
    let (_prior_nullifier_root, computed_nullifier_root, _witnesses) =
        nullifier_sparse_update_witnesses_for_consumed_inputs(&[], &consumed_inputs)
            .map_err(|_| StatusCode::CONFLICT)?;
    let computed_nullifier_root =
        normalize_felt_hex(&computed_nullifier_root).map_err(|_| StatusCode::CONFLICT)?;

    let mut renewal_entries = candidates
        .iter()
        .flat_map(|witness| {
            witness
                .renewal_child_uses
                .iter()
                .map(|renewal| renewal.child_nullifier.clone())
        })
        .collect::<Vec<_>>();
    renewal_entries.extend(maintenance_renewal_entries.iter().cloned());
    renewal_entries.sort();
    renewal_entries.dedup();
    let (_prior_renewal_root, computed_renewal_root, _child_witnesses, _cancel_witnesses) =
        renewal_sparse_witnesses_for_child_uses(&renewal_entries, &[], &[])
            .map_err(|_| StatusCode::CONFLICT)?;
    let computed_renewal_root =
        normalize_felt_hex(&computed_renewal_root).map_err(|_| StatusCode::CONFLICT)?;

    Ok((computed_nullifier_root, computed_renewal_root))
}

fn select_root_history_witness_lineage_subset(
    candidates: &[SettlementWitness],
    target_nullifier_root: &str,
    target_renewal_root: &str,
) -> Vec<SettlementWitness> {
    let mut required_nullifier_root = Some(target_nullifier_root.to_owned());
    let mut required_renewal_root = Some(target_renewal_root.to_owned());
    let mut selected = Vec::new();

    for candidate in candidates.iter().rev() {
        let new_nullifier_root = normalize_felt_hex(&candidate.new_nullifier_root).ok();
        let new_renewal_root = normalize_felt_hex(&candidate.new_renewal_root).ok();
        let mut matches_lineage = false;

        if required_nullifier_root.as_deref() == new_nullifier_root.as_deref() {
            required_nullifier_root = normalize_felt_hex(&candidate.prior_nullifier_root).ok();
            matches_lineage = true;
        }
        if required_renewal_root.as_deref() == new_renewal_root.as_deref() {
            required_renewal_root = normalize_felt_hex(&candidate.prior_renewal_root).ok();
            matches_lineage = true;
        }

        if matches_lineage {
            selected.push(candidate.clone());
        }
    }

    selected.reverse();
    selected
}

fn should_filter_root_history_against_onchain(state: &AppState) -> bool {
    state.starknet_executor.is_some()
        && !state.auction_verifier_address.trim().is_empty()
        && state.auction_verifier_address.trim() != "0x123"
}

fn resolve_private_order_payload_bundle(
    record: &zylith_core::SubmittedOrderRecord,
    private_order_payloads: &BTreeMap<String, PrivateOrderPayloadRecord>,
    state: &AppState,
) -> Result<OrderShareBundle, String> {
    if !record.order_bundle.shares.is_empty() || record.order_bundle.transport_envelope.is_some() {
        return Ok(record.order_bundle.clone());
    }

    if state.order_ingress_receipt_secrets.is_empty() {
        return Err("private order ingress receipt secret keyring is not configured".to_string());
    }
    validate_order_ingress_receipt_for_manifest_with_secrets(
        &record.order_bundle,
        state.order_ingress_receipt_secrets.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    let receipt = record
        .order_bundle
        .ingress_receipt
        .as_ref()
        .ok_or_else(|| "order manifest missing ingress receipt".to_string())?;
    let payload_record = private_order_payloads
        .get(&record.order_bundle.order_commitment.0)
        .ok_or_else(|| "private prover ingress is missing private order payload".to_string())?;
    if payload_record.payload_commitment != receipt.payload_commitment {
        return Err("private prover payload commitment does not match receipt".into());
    }
    let actual_payload_commitment = private_order_payload_commitment(&payload_record.order_bundle)
        .map_err(|error| error.to_string())?;
    if actual_payload_commitment != receipt.payload_commitment {
        return Err("private prover stored payload failed payload commitment check".into());
    }
    if payload_record.receipt != *receipt {
        return Err("private prover stored receipt does not match coordinator manifest".into());
    }

    Ok(payload_record.order_bundle.clone())
}

fn published_artifacts_payload(
    artifacts: &SettlementArtifacts,
) -> Result<PublishedBatchArtifacts, StatusCode> {
    let transcript_shape = zylith_core::validate_transcript_shape_policy(
        &artifacts.transcript,
        &artifacts.output_bundle,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(PublishedBatchArtifacts {
        transcript: artifacts.transcript.clone(),
        output_bundle: artifacts.output_bundle.clone(),
        liquidity_provider_attribution_bundle: artifacts
            .liquidity_provider_attribution_bundle
            .clone(),
        settlement_witness: artifacts.settlement_witness.clone(),
        published_at_unix_ms: now_unix_ms(),
        settled_at_unix_ms: None,
        settlement_transaction_hash: None,
        settlement_contract_address: None,
        order_execution_reports: artifacts.order_execution_reports.clone(),
        transcript_shape: Some(transcript_shape),
    })
}

async fn store_prepared_batch_artifacts(
    state: &AppState,
    artifacts: &SettlementArtifacts,
) -> Result<(), StatusCode> {
    let batch_id = &artifacts.transcript.batch_id.0;
    let payload = published_artifacts_payload(artifacts)?;
    let mut prepared = state.prepared_batch_artifacts.write().await;
    persist_record_and_insert(
        state.data_dir.as_ref(),
        PREPARED_BATCH_ARTIFACTS_DIR,
        &mut prepared,
        batch_id.clone(),
        payload,
    )?;
    Ok(())
}

async fn publish_verified_batch_artifacts_to_artifact_stores(
    state: &AppState,
    batch_id: &str,
    submission: &OnchainSubmissionRecord,
    settled_at_unix_ms: u64,
    settlement_plan: &SettlementSubmissionPlan,
) -> Result<(), String> {
    let mut payload = state
        .prepared_batch_artifacts
        .read()
        .await
        .get(batch_id)
        .cloned()
        .ok_or_else(|| format!("prepared artifacts missing for confirmed batch {batch_id}"))?;
    let roots = root_only_settlement_commitments(&payload.transcript)
        .map_err(|error| format!("settlement roots failed for {batch_id}: {error}"))?;
    if roots.output_note_root != settlement_plan.encoded_args.output_note_root {
        return Err(format!(
            "prepared artifact output root does not match settlement plan for {batch_id}"
        ));
    }
    let transcript_commitment = settlement_transcript_commitment(&payload.transcript)
        .map_err(|error| format!("transcript commitment failed for {batch_id}: {error}"))?;
    if transcript_commitment != settlement_plan.transcript_commitment {
        return Err(format!(
            "prepared artifact transcript commitment does not match settlement plan for {batch_id}"
        ));
    }
    payload.settled_at_unix_ms = Some(settled_at_unix_ms);
    payload.settlement_transaction_hash = Some(submission.transaction_hash.clone());
    payload.settlement_contract_address = Some(submission.settlement_contract_address.clone());
    let coordinator_url = format!(
        "{}/api/internal/batches/{batch_id}/artifacts",
        state.coordinator_url
    );
    let indexer_url = format!(
        "{}/api/internal/batches/{batch_id}/artifacts",
        state.indexer_url
    );
    for (label, target) in [("coordinator", coordinator_url), ("indexer", indexer_url)] {
        apply_internal_auth(
            state.http_client.post(target).json(&payload),
            state
                .internal_api_token
                .as_ref()
                .map(|token| token.as_str()),
        )
        .send()
        .await
        .map_err(|error| {
            format!("publish verified artifacts batch_id={batch_id} target={label} send_failed={error}")
        })?
        .error_for_status()
        .map_err(|error| {
            format!("publish verified artifacts batch_id={batch_id} target={label} status_failed={error}")
        })?;
    }
    Ok(())
}

async fn ensure_prepared_job(
    state: &AppState,
    batch_id: &str,
) -> Result<(ProofJobStatus, SettlementWitness), StatusCode> {
    let maybe_status = {
        let proof_jobs = state.proof_jobs.read().await;
        proof_jobs.get(batch_id).cloned()
    };
    let maybe_witness = {
        let settlement_witnesses = state.settlement_witnesses.read().await;
        settlement_witnesses.get(batch_id).cloned()
    };
    let maybe_prepared_artifact = {
        let prepared = state.prepared_batch_artifacts.read().await;
        prepared.get(batch_id).cloned()
    };

    match (maybe_status, maybe_witness, maybe_prepared_artifact) {
        (Some(status), Some(witness), Some(_)) => Ok((status, witness)),
        _ => prepare_or_rebuild_job(state, batch_id).await,
    }
}

async fn prepare_or_rebuild_job(
    state: &AppState,
    batch_id: &str,
) -> Result<(ProofJobStatus, SettlementWitness), StatusCode> {
    let mut settlement_witness = match fetch_witness(state, batch_id).await {
        Ok(witness) => witness,
        Err(StatusCode::NOT_FOUND) => {
            prepare_private_auction_batch_inner(state, batch_id).await?;
            fetch_witness(state, batch_id).await?
        }
        Err(status) => return Err(status),
    };
    let transcript = fetch_transcript(state, batch_id).await?;
    let transcript_commitment =
        settlement_transcript_commitment(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if settlement_witness.batch_id != transcript.batch_id {
        return Err(StatusCode::BAD_GATEWAY);
    }
    settlement_witness.transcript_commitment = transcript_commitment.clone();
    settlement_witness.auction_verifier_address = state.auction_verifier_address.clone();
    settlement_witness.prior_note_root = transcript.prior_note_root.clone();
    settlement_witness.prior_nullifier_root = transcript.prior_nullifier_root.clone();
    settlement_witness.prior_renewal_root = transcript.prior_renewal_root.clone();
    settlement_witness.prior_fee_root = transcript.prior_fee_root.clone();
    settlement_witness.prior_liquidity_position_root =
        transcript.prior_liquidity_position_root.clone();
    settlement_witness.new_nullifier_root = transcript.new_nullifier_root.clone();
    settlement_witness.new_renewal_root = transcript.new_renewal_root.clone();
    settlement_witness.new_liquidity_position_root = transcript.new_liquidity_position_root.clone();

    let now = now_unix_ms();
    let settlement_entrypoint = "submit_settlement_with_proof_facts";
    let created_at_unix_ms = {
        let proof_jobs = state.proof_jobs.read().await;
        proof_jobs
            .get(batch_id)
            .map(|existing| existing.created_at_unix_ms)
            .unwrap_or(now)
    };

    let status = ProofJobStatus {
        batch_id: transcript.batch_id.clone(),
        state: "witness-prepared".into(),
        transcript_commitment,
        matched_order_count: transcript.matched_orders.len() as u64,
        settlement_plan_available: false,
        witness_available: true,
        proof_artifact_available: false,
        onchain_submission_available: false,
        proof_artifact_id: None,
        onchain_submission_id: None,
        prover_backend: prover_backend_label(),
        last_error: None,
        created_at_unix_ms,
        updated_at_unix_ms: now,
        settlement_contract_address: state.auction_verifier_address.clone(),
        settlement_entrypoint: settlement_entrypoint.into(),
        settlement_calldata_len: 0,
    };

    {
        let mut proof_jobs = state.proof_jobs.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            PROOF_JOBS_DIR,
            &mut proof_jobs,
            batch_id.into(),
            status.clone(),
        )?;
    }
    {
        let mut settlement_plans = state.settlement_plans.write().await;
        delete_record_and_remove(
            state.data_dir.as_ref(),
            SETTLEMENT_PLANS_DIR,
            &mut settlement_plans,
            batch_id,
        )?;
    }
    {
        let mut settlement_witnesses = state.settlement_witnesses.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            SETTLEMENT_WITNESSES_DIR,
            &mut settlement_witnesses,
            batch_id.into(),
            settlement_witness.clone(),
        )?;
    }
    {
        let mut proof_artifacts = state.proof_artifacts.write().await;
        delete_record_and_remove(
            state.data_dir.as_ref(),
            PROOF_ARTIFACTS_DIR,
            &mut proof_artifacts,
            batch_id,
        )?;
    }
    {
        let mut onchain_submissions = state.onchain_submissions.write().await;
        delete_record_and_remove(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &mut onchain_submissions,
            batch_id,
        )?;
    }
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), batch_id)?;

    Ok((status, settlement_witness))
}

async fn set_job_state(
    state: &AppState,
    batch_id: &str,
    update: JobStateUpdate,
) -> Result<ProofJobStatus, StatusCode> {
    let JobStateUpdate {
        next_state,
        proof_artifact_id,
        last_error,
        proof_artifact_available,
        settlement_plan_available,
        settlement_calldata_len,
        settlement_entrypoint,
    } = update;
    let mut proof_jobs = state.proof_jobs.write().await;
    let mut status = proof_jobs
        .get(batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    status.state = next_state;
    status.proof_artifact_id = proof_artifact_id;
    status.proof_artifact_available = proof_artifact_available;
    status.last_error = last_error;
    if let Some(value) = settlement_plan_available {
        status.settlement_plan_available = value;
    }
    if let Some(value) = settlement_calldata_len {
        status.settlement_calldata_len = value;
    }
    if let Some(value) = settlement_entrypoint {
        status.settlement_entrypoint = value;
    }
    status.updated_at_unix_ms = now_unix_ms();
    persist_record_and_insert(
        state.data_dir.as_ref(),
        PROOF_JOBS_DIR,
        &mut proof_jobs,
        batch_id.to_owned(),
        status.clone(),
    )?;
    Ok(status)
}

async fn sync_job_with_onchain_submission(
    state: &AppState,
    batch_id: &str,
    submission: &OnchainSubmissionRecord,
) -> Result<ProofJobStatus, StatusCode> {
    let mut proof_jobs = state.proof_jobs.write().await;
    let mut status = proof_jobs
        .get(batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    status.state = match (
        submission.finality_status.as_deref(),
        submission.execution_status.as_deref(),
    ) {
        (_, Some("REVERTED")) => "onchain-reverted".into(),
        (Some("ACCEPTED_ON_L1" | "ACCEPTED_ON_L2"), Some("SUCCEEDED")) => {
            "confirmed-onchain".into()
        }
        (Some("PRE_CONFIRMED"), _) => "submitted-onchain".into(),
        _ => "submitted-onchain".into(),
    };
    status.last_error = submission.revert_reason.clone();
    status.onchain_submission_available = true;
    status.onchain_submission_id = Some(submission.submission_id.clone());
    status.updated_at_unix_ms = now_unix_ms();
    persist_record_and_insert(
        state.data_dir.as_ref(),
        PROOF_JOBS_DIR,
        &mut proof_jobs,
        batch_id.to_owned(),
        status.clone(),
    )?;

    Ok(status)
}

async fn set_job_submitting_onchain(
    state: &AppState,
    batch_id: &str,
) -> Result<ProofJobStatus, StatusCode> {
    let existing = {
        let proof_jobs = state.proof_jobs.read().await;
        proof_jobs
            .get(batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };
    set_job_state(
        state,
        batch_id,
        JobStateUpdate {
            next_state: "submitting-onchain".into(),
            proof_artifact_id: existing.proof_artifact_id,
            last_error: None,
            proof_artifact_available: existing.proof_artifact_available,
            settlement_plan_available: Some(existing.settlement_plan_available),
            settlement_calldata_len: Some(existing.settlement_calldata_len),
            settlement_entrypoint: Some(existing.settlement_entrypoint),
        },
    )
    .await
}

async fn publish_settlement_timestamp_to_artifact_stores(
    state: &AppState,
    batch_id: &str,
    submission: &OnchainSubmissionRecord,
) -> Result<(), String> {
    if submission.execution_status.as_deref() != Some("SUCCEEDED")
        || !matches!(
            submission.finality_status.as_deref(),
            Some("ACCEPTED_ON_L1" | "ACCEPTED_ON_L2")
        )
    {
        return Ok(());
    }
    let Some(settled_at_unix_ms) = submission
        .block_timestamp_unix_ms
        .or(submission.confirmed_at_unix_ms)
    else {
        return Ok(());
    };
    let settlement_plan = state
        .settlement_plans
        .read()
        .await
        .get(batch_id)
        .cloned()
        .ok_or_else(|| format!("settlement plan missing for confirmed batch {batch_id}"))?;
    publish_verified_batch_artifacts_to_artifact_stores(
        state,
        batch_id,
        submission,
        settled_at_unix_ms,
        &settlement_plan,
    )
    .await?;
    Ok(())
}

async fn set_job_error(
    state: &AppState,
    batch_id: &str,
    error: String,
) -> Result<ProofJobStatus, StatusCode> {
    set_job_state(
        state,
        batch_id,
        JobStateUpdate {
            next_state: "proving-failed".into(),
            proof_artifact_id: None,
            last_error: Some(error),
            proof_artifact_available: false,
            settlement_plan_available: None,
            settlement_calldata_len: None,
            settlement_entrypoint: None,
        },
    )
    .await
}

async fn record_prepare_job_error(
    state: &AppState,
    batch_id: &str,
    error: String,
) -> Result<ProofJobStatus, StatusCode> {
    if state.proof_jobs.read().await.contains_key(batch_id) {
        return set_job_error(state, batch_id, error).await;
    }
    let now = now_unix_ms();
    let status = ProofJobStatus {
        batch_id: BatchId(batch_id.into()),
        state: "proving-failed".into(),
        transcript_commitment: String::new(),
        matched_order_count: 0,
        settlement_plan_available: false,
        witness_available: false,
        proof_artifact_available: false,
        onchain_submission_available: false,
        proof_artifact_id: None,
        onchain_submission_id: None,
        prover_backend: prover_backend_label(),
        last_error: Some(error),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        settlement_contract_address: state.auction_verifier_address.clone(),
        settlement_entrypoint: "submit_settlement_with_proof_facts".into(),
        settlement_calldata_len: 0,
    };
    {
        let mut proof_jobs = state.proof_jobs.write().await;
        persist_record_and_insert(
            state.data_dir.as_ref(),
            PROOF_JOBS_DIR,
            &mut proof_jobs,
            batch_id.into(),
            status.clone(),
        )?;
    }
    Ok(status)
}

async fn set_onchain_submission_error(
    state: &AppState,
    batch_id: &str,
    error: String,
) -> Result<ProofJobStatus, StatusCode> {
    let existing = {
        let proof_jobs = state.proof_jobs.read().await;
        proof_jobs
            .get(batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };

    set_job_state(
        state,
        batch_id,
        JobStateUpdate {
            next_state: onchain_submission_error_next_state(&error).into(),
            proof_artifact_id: existing.proof_artifact_id,
            last_error: Some(sanitize_native_prover_error_text(&error)),
            proof_artifact_available: existing.proof_artifact_available,
            settlement_plan_available: Some(existing.settlement_plan_available),
            settlement_calldata_len: Some(existing.settlement_calldata_len),
            settlement_entrypoint: Some(existing.settlement_entrypoint),
        },
    )
    .await
}

fn onchain_submission_error_next_state(error: &str) -> &'static str {
    if native_onchain_submit_error_is_retryable(error) {
        "submitting-onchain"
    } else {
        "onchain-submit-failed"
    }
}

fn build_pending_native_settlement_artifact_record(
    state: &AppState,
    batch_id: &str,
    transcript: &SettlementTranscript,
    transcript_commitment: &str,
) -> Result<ProofArtifactRecord, String> {
    let native_proof_reference =
        native_settlement_message_hash(&state.auction_verifier_address, transcript_commitment)
            .map_err(|error| error.to_string())?;
    Ok(ProofArtifactRecord {
        artifact_id: artifact_id_for(batch_id, transcript_commitment),
        batch_id: transcript.batch_id.clone(),
        proof_system: "starknet-snip36".into(),
        proof_format: "virtual-tx-proof".into(),
        prover_backend: prover_backend_label(),
        created_at_unix_ms: now_unix_ms(),
        proof_artifact_commitment: native_proof_reference,
        proof_path: String::new(),
        public_inputs_path: String::new(),
        prover_stdout_path: String::new(),
        prover_stderr_path: String::new(),
        proof_sha256: String::new(),
        public_inputs_sha256: String::new(),
        native_proof_file_path: None,
        native_proof_facts_file_path: None,
        native_execution_request_path: None,
        native_nullifier_proof_file_path: None,
        native_nullifier_proof_facts_file_path: None,
        native_nullifier_execution_request_path: None,
        native_renewal_proof_file_path: None,
        native_renewal_proof_facts_file_path: None,
        native_renewal_execution_request_path: None,
        native_liquidity_position_proof_file_path: None,
        native_liquidity_position_proof_facts_file_path: None,
        native_liquidity_position_execution_request_path: None,
        native_settlement_order_proof_file_path: None,
        native_settlement_order_proof_facts_file_path: None,
        native_settlement_order_execution_request_path: None,
        native_settlement_input_membership_proof_file_path: None,
        native_settlement_input_membership_proof_facts_file_path: None,
        native_settlement_input_membership_execution_request_path: None,
        native_settlement_output_recovery_proof_file_path: None,
        native_settlement_output_recovery_proof_facts_file_path: None,
        native_settlement_output_recovery_execution_request_path: None,
    })
}

struct NativeStatementProverRequest<'a> {
    state: &'a AppState,
    tx_prover_url: &'a str,
    executor: &'a StarknetExecutorConfig,
    batch_id: &'a str,
    stage_key: &'a str,
    entrypoint: &'a str,
    serialized_native_witness: &'a [String],
    expected_message_hashes: &'a [String],
}

async fn execute_native_statement_prover(
    request: NativeStatementProverRequest<'_>,
) -> Result<NativeStatementProofArtifact, String> {
    let NativeStatementProverRequest {
        state,
        tx_prover_url,
        executor,
        batch_id,
        stage_key,
        entrypoint,
        serialized_native_witness,
        expected_message_hashes,
    } = request;
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), stage_key)
        .map_err(status_to_error)?;
    let paths = proof_execution_paths(state.data_dir.as_ref(), stage_key);
    let proof_program_calldata = build_native_proof_program_calldata(
        &state.auction_verifier_address,
        serialized_native_witness,
    )?;
    let proof_compilation_call = StarknetCall {
        contract_address: normalize_nonzero_felt(
            &state.native_proof_program_address,
            "native_proof_program_address",
        )?,
        entrypoint: entrypoint.into(),
        calldata: proof_program_calldata,
    };
    let execution_request = build_native_execution_request(
        executor,
        &proof_compilation_call,
        NativeTransactionMode::ProofOnly,
    )
    .await?;
    persist_json_file(
        &paths.native_execution_request_path,
        &redact_native_execution_request(&execution_request),
    )
    .map_err(status_to_error)?;

    let rpc_request = NativeProverRpcRequest {
        jsonrpc: "2.0".into(),
        id: 1,
        method: "starknet_proveTransaction".into(),
        params: (
            execution_request.block_id.clone(),
            execution_request.transaction.clone(),
        ),
    };
    let mut final_response_value = None;
    let mut final_result = None;
    let mut last_error = None;
    for attempt in 1..=state.native_prover_attempts {
        match request_native_proof(state, tx_prover_url, &rpc_request).await {
            Ok((result, response_value)) => {
                final_result = Some(result);
                final_response_value = Some(response_value);
                break;
            }
            Err(error) if attempt < state.native_prover_attempts => {
                eprintln!(
                    "native {entrypoint} prover attempt {attempt}/{attempts} failed for batch {batch_id}: {error}",
                    attempts = state.native_prover_attempts
                );
                last_error = Some(error);
                sleep(Duration::from_millis(state.native_prover_retry_interval_ms)).await;
            }
            Err(error) => {
                last_error = Some(error);
                break;
            }
        }
    }
    let response_value = final_response_value.ok_or_else(|| {
        last_error.unwrap_or_else(|| format!("native {entrypoint} prover returned no result"))
    })?;
    let result =
        final_result.ok_or_else(|| format!("native {entrypoint} prover returned no result"))?;
    validate_native_proof_facts_messages(&result.proof_facts, expected_message_hashes)?;

    fs::write(&paths.proof_path, result.proof.trim())
        .map_err(|error| format!("failed to persist native {entrypoint} proof: {error}"))?;
    persist_json_file(&paths.public_inputs_path, &result.proof_facts).map_err(status_to_error)?;
    persist_json_file(
        &paths.stdout_path,
        &serde_json::json!({
            "request": redact_native_prover_request(&rpc_request),
            "response": response_value,
        }),
    )
    .map_err(status_to_error)?;
    fs::write(&paths.stderr_path, "")
        .map_err(|error| format!("failed to persist native {entrypoint} stderr log: {error}"))?;

    let proof_sha256 = sha256_file_hex(&paths.proof_path)?;
    let proof_facts_sha256 = sha256_file_hex(&paths.public_inputs_path)?;
    Ok(NativeStatementProofArtifact {
        proof_path: paths.proof_path.display().to_string(),
        proof_facts_path: paths.public_inputs_path.display().to_string(),
        execution_request_path: paths.native_execution_request_path.display().to_string(),
        stdout_path: paths.stdout_path.display().to_string(),
        stderr_path: paths.stderr_path.display().to_string(),
        proof_sha256,
        proof_facts_sha256,
    })
}

async fn request_native_proof(
    state: &AppState,
    tx_prover_url: &str,
    rpc_request: &NativeProverRpcRequest,
) -> Result<(NativeProverResult, serde_json::Value), String> {
    let _permit = state
        .native_prover_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| "native transaction prover queue is closed".to_string())?;
    if let Some(ohttp_config) = &state.native_tx_prover_ohttp {
        return request_native_proof_ohttp(state, tx_prover_url, ohttp_config, rpc_request).await;
    }
    let response_value = tokio::time::timeout(
        Duration::from_secs(state.native_prover_request_timeout_seconds),
        async {
            let response = state
                .http_client
                .post(tx_prover_url)
                .timeout(Duration::from_secs(
                    state.native_prover_request_timeout_seconds,
                ))
                .json(rpc_request)
                .send()
                .await
                .map_err(|error| format!("native transaction prover request failed: {error}"))?;
            decode_bounded_json_response(response, MAX_NATIVE_PROVER_RESPONSE_BYTES)
                .await
                .map_err(|error| {
                    format!("native transaction prover response decode failed: {error}")
                })
        },
    )
    .await
    .map_err(|_| {
        format!(
            "native transaction prover request timed out after {}s",
            state.native_prover_request_timeout_seconds
        )
    })??;
    decode_native_prover_response(response_value)
}

async fn request_native_proof_ohttp(
    state: &AppState,
    tx_prover_url: &str,
    ohttp_config: &NativeProverOhttpConfig,
    rpc_request: &NativeProverRpcRequest,
) -> Result<(NativeProverResult, serde_json::Value), String> {
    let response_value = tokio::time::timeout(
        Duration::from_secs(state.native_prover_request_timeout_seconds),
        async {
            let body = serde_json::to_vec(rpc_request).map_err(|error| {
                format!("native transaction prover OHTTP request encode failed: {error}")
            })?;
            let key_config = load_ohttp_key_config(state, tx_prover_url, ohttp_config).await?;
            let ohttp_client = ohttp::ClientRequest::from_encoded_config_list(&key_config)
                .map_err(|error| {
                    format!("native transaction prover OHTTP key config invalid: {error}")
                })?;
            let bhttp_request = encode_bhttp_json_post(&body).map_err(|error| {
                format!("native transaction prover OHTTP BHTTP encode failed: {error}")
            })?;
            let (encrypted_request, response_context) =
                ohttp_client.encapsulate(&bhttp_request).map_err(|error| {
                    format!("native transaction prover OHTTP encapsulation failed: {error}")
                })?;
            let response = state
                .http_client
                .post(tx_prover_url)
                .timeout(Duration::from_secs(
                    state.native_prover_request_timeout_seconds,
                ))
                .header("content-type", "message/ohttp-req")
                .body(encrypted_request)
                .send()
                .await
                .map_err(|error| {
                    format!("native transaction prover OHTTP request failed: {error}")
                })?;
            let status = response.status();
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let response_bytes = read_bounded_response(response, MAX_NATIVE_PROVER_RESPONSE_BYTES)
                .await
                .map_err(|error| {
                    format!("native transaction prover OHTTP response read failed: {error}")
                })?;
            if !status.is_success() && !content_type.contains("message/ohttp-res") {
                let body =
                    sanitize_native_prover_error_text(&String::from_utf8_lossy(&response_bytes));
                return Err(format!(
                    "native transaction prover OHTTP gateway returned HTTP {status}: {body}"
                ));
            }
            let bhttp_response =
                response_context
                    .decapsulate(&response_bytes)
                    .map_err(|error| {
                        format!("native transaction prover OHTTP decapsulation failed: {error}")
                    })?;
            let (inner_status, inner_body) =
                decode_bhttp_response(&bhttp_response).map_err(|error| {
                    format!("native transaction prover OHTTP BHTTP decode failed: {error}")
                })?;
            if inner_status != 200 {
                let body = sanitize_native_prover_error_text(&String::from_utf8_lossy(&inner_body));
                return Err(format!(
                    "native transaction prover OHTTP inner response HTTP {inner_status}: {body}"
                ));
            }
            serde_json::from_slice::<serde_json::Value>(&inner_body).map_err(|error| {
                format!("native transaction prover OHTTP JSON response decode failed: {error}")
            })
        },
    )
    .await
    .map_err(|_| {
        format!(
            "native transaction prover OHTTP request timed out after {}s",
            state.native_prover_request_timeout_seconds
        )
    })??;
    decode_native_prover_response(response_value)
}

async fn load_ohttp_key_config(
    state: &AppState,
    tx_prover_url: &str,
    ohttp_config: &NativeProverOhttpConfig,
) -> Result<Vec<u8>, String> {
    if let Some(pinned) = &ohttp_config.pinned_key_config {
        return Ok(pinned.clone());
    }
    let parsed_url =
        Url::parse(tx_prover_url).map_err(|error| format!("invalid native prover URL: {error}"))?;
    if parsed_url.scheme() != "https" {
        return Err(format!(
            "{NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX_ENV} is required when ZYLITH_NATIVE_TX_PROVER_URL is not HTTPS"
        ));
    }
    let key_url = format!("{}/ohttp-keys", tx_prover_url.trim_end_matches('/'));
    let response = state
        .http_client
        .get(key_url)
        .send()
        .await
        .map_err(|error| format!("native transaction prover OHTTP key fetch failed: {error}"))?;
    let status = response.status();
    let body = read_bounded_response(response, MAX_OHTTP_KEY_CONFIG_BYTES)
        .await
        .map_err(|error| {
            format!("native transaction prover OHTTP key response read failed: {error}")
        })?;
    if !status.is_success() {
        let body = sanitize_native_prover_error_text(&String::from_utf8_lossy(&body));
        return Err(format!(
            "native transaction prover OHTTP key fetch returned HTTP {status}: {body}"
        ));
    }
    Ok(body)
}

async fn read_bounded_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(format!("response exceeds {max_bytes} bytes"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("response read failed: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!("response exceeds {max_bytes} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn decode_bounded_json_response<T: DeserializeOwned>(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<T, String> {
    let body = read_bounded_response(response, max_bytes).await?;
    serde_json::from_slice(&body).map_err(|error| format!("invalid JSON: {error}"))
}

async fn decode_control_plane_json<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, StatusCode> {
    if !response.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    decode_bounded_json_response(response, MAX_CONTROL_PLANE_RESPONSE_BYTES)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

async fn decode_internal_json<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, StatusCode> {
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(StatusCode::NOT_FOUND);
    }
    decode_control_plane_json(response).await
}

fn encode_bhttp_json_post(body: &[u8]) -> Result<Vec<u8>, bhttp::Error> {
    let mut message = bhttp::Message::request(
        b"POST".to_vec(),
        b"https".to_vec(),
        b"ohttp-target.invalid".to_vec(),
        b"/".to_vec(),
    );
    message.put_header(b"content-type".to_vec(), b"application/json".to_vec());
    message.write_content(body);
    let mut encoded = Vec::new();
    message.write_bhttp(bhttp::Mode::KnownLength, &mut encoded)?;
    Ok(encoded)
}

fn decode_bhttp_response(bytes: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let mut cursor = Cursor::new(bytes);
    let message = bhttp::Message::read_bhttp(&mut cursor).map_err(|error| error.to_string())?;
    let status = message
        .control()
        .status()
        .ok_or_else(|| "OHTTP inner message was not a response".to_string())?
        .code();
    Ok((status, message.content().to_vec()))
}

fn decode_native_prover_response(
    response_value: serde_json::Value,
) -> Result<(NativeProverResult, serde_json::Value), String> {
    let response: NativeProverRpcResponse = serde_json::from_value(response_value.clone())
        .map_err(|error| format!("native transaction prover response shape error: {error}"))?;
    let result = match (response.result, response.error) {
        (Some(result), None) => result,
        (_, Some(error)) => {
            let message = sanitize_native_prover_error_text(&error.message);
            let data = error
                .data
                .map(|value| sanitize_native_prover_error_text(&value.to_string()))
                .filter(|value| !value.is_empty())
                .map(|value| format!(" ({value})"))
                .unwrap_or_default();
            return Err(format!(
                "native transaction prover error {}: {}{}",
                error.code, message, data
            ));
        }
        _ => return Err("native transaction prover returned no result".to_string()),
    };
    validate_native_prover_l2_messages(&result)?;

    Ok((result, response_value))
}

fn sanitize_native_prover_error_text(value: &str) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut index = 0;
    let mut last_was_space = false;
    while index < chars.len() {
        let current = chars[index];
        if current.is_whitespace() {
            if !last_was_space && !output.is_empty() {
                output.push(' ');
                last_was_space = true;
            }
            index += 1;
            continue;
        }
        last_was_space = false;

        if current == '0'
            && chars
                .get(index + 1)
                .is_some_and(|next| *next == 'x' || *next == 'X')
        {
            let mut end = index + 2;
            while chars
                .get(end)
                .is_some_and(|candidate| candidate.is_ascii_hexdigit())
            {
                end += 1;
            }
            if end.saturating_sub(index + 2) >= 32 {
                output.push_str("<felt>");
            } else {
                output.extend(chars[index..end].iter());
            }
            index = end;
            continue;
        }

        if current.is_ascii_digit() {
            let mut end = index + 1;
            while chars
                .get(end)
                .is_some_and(|candidate| candidate.is_ascii_digit())
            {
                end += 1;
            }
            if end.saturating_sub(index) >= 32 {
                output.push_str("<number>");
            } else {
                output.extend(chars[index..end].iter());
            }
            index = end;
            continue;
        }

        output.push(current);
        index += 1;
    }
    let sanitized = output.trim();
    sanitized
        .chars()
        .take(MAX_NATIVE_PROVER_ERROR_CHARS)
        .collect()
}

fn validate_native_prover_l2_messages(result: &NativeProverResult) -> Result<(), String> {
    if result.l2_to_l1_messages.is_empty() {
        return Err("native transaction prover returned no L2-to-L1 messages".into());
    }
    for (index, message) in result.l2_to_l1_messages.iter().enumerate() {
        normalize_nonzero_felt(
            &message.from_address,
            &format!("native l2_to_l1_messages[{index}].from_address"),
        )?;
        let to_address = message.to_address.trim();
        if !to_address.starts_with("0x") {
            return Err(format!(
                "native l2_to_l1_messages[{index}].to_address is not hex encoded"
            ));
        }
        if message.payload.is_empty() {
            return Err(format!(
                "native l2_to_l1_messages[{index}].payload must not be empty"
            ));
        }
        for (payload_index, payload) in message.payload.iter().enumerate() {
            parse_felt(
                payload,
                &format!("native l2_to_l1_messages[{index}].payload[{payload_index}]"),
            )?;
        }
    }
    Ok(())
}

fn validate_native_proof_facts(
    serialized_proof_facts: &[String],
    expected_message_hash: &str,
) -> Result<(), String> {
    validate_native_proof_facts_messages(
        serialized_proof_facts,
        &[expected_message_hash.to_owned()],
    )
}

fn validate_native_proof_facts_messages(
    serialized_proof_facts: &[String],
    expected_message_hashes: &[String],
) -> Result<(), String> {
    if serialized_proof_facts.len() < 8 {
        return Err("native prover returned malformed proof_facts".into());
    }
    let message_count = parse_felt(&serialized_proof_facts[7], "proof_facts.message_count")?;
    let message_count: usize = message_count
        .to_biguint()
        .try_into()
        .map_err(|_| "proof_facts.message_count does not fit usize".to_string())?;
    let expected_len = 8 + message_count;
    if serialized_proof_facts.len() != expected_len {
        return Err(format!(
            "native prover returned malformed proof_facts length: expected {expected_len}, got {}",
            serialized_proof_facts.len()
        ));
    }
    if message_count != expected_message_hashes.len() {
        return Err(format!(
            "native prover returned {message_count} proof messages, expected {}",
            expected_message_hashes.len()
        ));
    }
    for (index, expected_message_hash) in expected_message_hashes.iter().enumerate() {
        let actual_message_hash =
            normalize_nonzero_felt(&serialized_proof_facts[8 + index], "proof_message")?;
        let expected_message_hash =
            normalize_nonzero_felt(expected_message_hash, "expected_message")?;
        if actual_message_hash != expected_message_hash {
            return Err(format!(
                "native proof_facts message {index} mismatch: expected {expected_message_hash}, got {actual_message_hash}"
            ));
        }
    }
    Ok(())
}

fn build_native_proof_program_calldata(
    auction_verifier_address: &str,
    serialized_auction_witness: &[String],
) -> Result<Vec<String>, String> {
    let verifier = normalize_nonzero_felt(auction_verifier_address, "auction_verifier_address")?;
    let mut calldata = Vec::with_capacity(serialized_auction_witness.len() + 1);
    calldata.push(verifier);
    calldata.extend(serialized_auction_witness.iter().cloned());
    Ok(calldata)
}

fn build_settlement_submission_plan_for_artifact(
    transcript: &SettlementTranscript,
    auction_verifier_address: &str,
    _proof_artifact: &ProofArtifactRecord,
) -> Result<SettlementSubmissionPlan, zylith_core::ProtocolError> {
    let transcript_commitment = settlement_transcript_commitment(transcript)?;
    let statement_message_hash =
        native_settlement_message_hash(auction_verifier_address, &transcript_commitment)?;
    build_settlement_submission_plan(
        transcript,
        auction_verifier_address,
        &statement_message_hash,
    )
}

async fn fetch_transcript(
    state: &AppState,
    batch_id: &str,
) -> Result<SettlementTranscript, StatusCode> {
    if let Some(transcript) = state
        .prepared_batch_artifacts
        .read()
        .await
        .get(batch_id)
        .map(|published| published.transcript.clone())
    {
        return Ok(transcript);
    }
    let url = format!(
        "{}/api/internal/batches/{}/transcript",
        state.coordinator_url, batch_id
    );
    let response = apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    decode_internal_json(response).await
}

async fn fetch_batch_summary(state: &AppState, batch_id: &str) -> Result<BatchSummary, StatusCode> {
    fetch_batch_order_set(state, batch_id)
        .await
        .map(|order_set| order_set.batch)
}

async fn fetch_batch_order_set(
    state: &AppState,
    batch_id: &str,
) -> Result<BatchOrderSet, StatusCode> {
    if let Some(published) = state
        .prepared_batch_artifacts
        .read()
        .await
        .get(batch_id)
        .cloned()
    {
        let order_count = (published.settlement_witness.matched_order_witnesses.len()
            + published
                .settlement_witness
                .liquidity_position_witnesses
                .len()) as u64;
        return Ok(BatchOrderSet {
            batch: BatchSummary {
                batch_id: published.transcript.batch_id.clone(),
                pair_id: published.transcript.pair_id.clone(),
                epoch_id: published.transcript.batch_epoch,
                close_time_unix_ms: published.published_at_unix_ms,
                status: BatchStatus::Closed,
                order_count,
                order_commitment_root: published.transcript.order_commitment_root,
                encrypted_order_set_commitment: published.transcript.encrypted_order_set_commitment,
            },
            orders: vec![],
            liquidity_position_lifecycle_submissions: vec![],
        });
    }

    fetch_coordinator_batch_order_set(state, batch_id).await
}

async fn fetch_coordinator_batch_order_set(
    state: &AppState,
    batch_id: &str,
) -> Result<BatchOrderSet, StatusCode> {
    let url = format!(
        "{}/api/internal/batches/{}/orders",
        state.coordinator_url, batch_id
    );
    let response = apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    decode_internal_json(response).await
}

async fn fetch_witness(state: &AppState, batch_id: &str) -> Result<SettlementWitness, StatusCode> {
    if let Some(witness) = state
        .settlement_witnesses
        .read()
        .await
        .get(batch_id)
        .cloned()
    {
        return Ok(witness);
    }
    let url = format!(
        "{}/api/internal/batches/{}/witness",
        state.coordinator_url, batch_id
    );
    let response = apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    decode_internal_json(response).await
}

fn compute_candidate_clearing_price(
    records: &[DecryptedOrderRecord],
    price_base_scale: u128,
) -> Result<Option<u128>, StatusCode> {
    let mut candidate_prices: Vec<u128> = records
        .iter()
        .filter(|record| {
            !matches!(
                record.order.order_type,
                zylith_core::OrderType::HeartbeatCover
            )
        })
        .flat_map(|record| candidate_prices_for_order(&record.order))
        .collect();
    if candidate_prices.is_empty() {
        candidate_prices = records
            .iter()
            .filter(|record| {
                matches!(
                    record.order.order_type,
                    zylith_core::OrderType::HeartbeatCover
                )
            })
            .flat_map(|record| candidate_prices_for_order(&record.order))
            .collect();
    }
    candidate_prices.sort_unstable();
    candidate_prices.dedup();

    let mut best: Option<(u128, u128, u128, u128)> = None;

    for price in candidate_prices {
        let (matched, imbalance) = stable_pruned_score_at_price(records, price, price_base_scale)?;

        match best {
            None => best = Some((price, price, matched, imbalance)),
            Some((best_low, best_high, best_matched, best_imbalance)) => {
                if matched > best_matched || (matched == best_matched && imbalance < best_imbalance)
                {
                    best = Some((price, price, matched, imbalance));
                } else if matched == best_matched && imbalance == best_imbalance {
                    best = Some((
                        best_low.min(price),
                        best_high.max(price),
                        best_matched,
                        best_imbalance,
                    ));
                }
            }
        }
    }

    Ok(best.map(|(low, high, matched, _)| {
        if matched == 0 {
            low
        } else {
            midpoint_u128(low, high)
        }
    }))
}

fn midpoint_u128(low: u128, high: u128) -> u128 {
    (low / 2) + (high / 2) + ((low % 2 + high % 2) / 2)
}

fn stable_pruned_score_at_price(
    records: &[DecryptedOrderRecord],
    price: u128,
    price_base_scale: u128,
) -> Result<(u128, u128), StatusCode> {
    let active_flags = stable_active_flags(records, price, price_base_scale);
    let buy_demand = records
        .iter()
        .zip(active_flags.iter())
        .filter(|(record, active)| **active && matches!(record.order.side, OrderSide::Buy))
        .try_fold(0_u128, |total, (record, _)| {
            total
                .checked_add(max_fill_at_price(record, price, price_base_scale))
                .ok_or(StatusCode::CONFLICT)
        })?;
    let sell_supply = records
        .iter()
        .zip(active_flags.iter())
        .filter(|(record, active)| **active && matches!(record.order.side, OrderSide::Sell))
        .try_fold(0_u128, |total, (record, _)| {
            total
                .checked_add(max_fill_at_price(record, price, price_base_scale))
                .ok_or(StatusCode::CONFLICT)
        })?;
    Ok((
        buy_demand.min(sell_supply),
        buy_demand.abs_diff(sell_supply),
    ))
}

fn stable_active_flags(
    records: &[DecryptedOrderRecord],
    price: u128,
    price_base_scale: u128,
) -> Vec<bool> {
    let mut active_flags = records
        .iter()
        .map(|record| max_fill_at_price(record, price, price_base_scale) > 0)
        .collect::<Vec<_>>();

    for _ in 0..records.len() {
        let next_flags = active_flags
            .iter()
            .enumerate()
            .map(|(index, active)| {
                if !*active {
                    return false;
                }
                let fill = expected_fill_with_active_flags(
                    records,
                    &active_flags,
                    index,
                    price,
                    price_base_scale,
                );
                if fill == 0 {
                    return true;
                }
                fill >= records[index].order.min_fill
                    && (!is_fill_or_kill_order(&records[index].order)
                        || fill >= records[index].order.amount)
            })
            .collect::<Vec<_>>();
        if next_flags == active_flags {
            break;
        }
        active_flags = next_flags;
    }

    active_flags
}

fn expected_fill_with_active_flags(
    records: &[DecryptedOrderRecord],
    active_flags: &[bool],
    target_index: usize,
    price: u128,
    price_base_scale: u128,
) -> u128 {
    if !active_flags[target_index] {
        return 0;
    }
    let target = &records[target_index];
    let max_fill = max_fill_at_price(target, price, price_base_scale);
    let opposite_side = match target.order.side {
        OrderSide::Buy => OrderSide::Sell,
        OrderSide::Sell => OrderSide::Buy,
    };
    let opposite_total = active_capacity_total(
        records,
        active_flags,
        &opposite_side,
        price,
        price_base_scale,
    );
    let priority_capacity = active_priority_capacity_before(
        records,
        active_flags,
        target_index,
        price,
        price_base_scale,
    );
    if opposite_total <= priority_capacity {
        return 0;
    }
    max_fill.min(opposite_total - priority_capacity)
}

fn active_capacity_total(
    records: &[DecryptedOrderRecord],
    active_flags: &[bool],
    side: &OrderSide,
    price: u128,
    price_base_scale: u128,
) -> u128 {
    records
        .iter()
        .zip(active_flags.iter())
        .filter(|(record, active)| **active && &record.order.side == side)
        .map(|(record, _)| max_fill_at_price(record, price, price_base_scale))
        .sum()
}

fn active_priority_capacity_before(
    records: &[DecryptedOrderRecord],
    active_flags: &[bool],
    target_index: usize,
    price: u128,
    price_base_scale: u128,
) -> u128 {
    let target = &records[target_index].order;
    records
        .iter()
        .zip(active_flags.iter())
        .enumerate()
        .filter(|(index, (record, active))| {
            if !**active || record.order.side != target.side {
                return false;
            }
            match target.side {
                OrderSide::Buy => {
                    record.order.limit_price > target.limit_price
                        || (record.order.limit_price == target.limit_price && *index < target_index)
                }
                OrderSide::Sell => {
                    record.order.limit_price < target.limit_price
                        || (record.order.limit_price == target.limit_price && *index < target_index)
                }
            }
        })
        .map(|(_, (record, _))| max_fill_at_price(record, price, price_base_scale))
        .sum()
}

fn sum_fill_at_price<'a>(
    mut records: impl Iterator<Item = &'a DecryptedOrderRecord>,
    price: u128,
    price_base_scale: u128,
) -> Result<u128, StatusCode> {
    records.try_fold(0_u128, |total, record| {
        total
            .checked_add(max_fill_at_price(record, price, price_base_scale))
            .ok_or(StatusCode::CONFLICT)
    })
}

fn build_batch_liquidity_report(
    records: &[DecryptedOrderRecord],
    clearing_price: u128,
    matched_base_volume: u128,
    min_base_liquidity: u128,
    price_base_scale: u128,
) -> zylith_core::BatchLiquidityReport {
    let diagnostic_price = if clearing_price > 0 {
        Some(clearing_price)
    } else {
        compute_candidate_clearing_price(records, price_base_scale).unwrap_or_default()
    };

    let Some(price) = diagnostic_price else {
        return zylith_core::BatchLiquidityReport {
            status: "empty".into(),
            reason: Some("no orders were staged for this batch".into()),
            diagnostic_price: None,
            buy_base_demand: 0,
            sell_base_supply: 0,
            matched_base_volume,
            crossing_order_count: 0,
            min_base_liquidity,
        };
    };

    let eligible_orders = records
        .iter()
        .filter(|record| {
            is_order_eligible(&record.order, price)
                && max_fill_at_price(record, price, price_base_scale) > 0
        })
        .collect::<Vec<_>>();
    let buy_base_demand = sum_fill_at_price(
        eligible_orders
            .iter()
            .copied()
            .filter(|record| matches!(record.order.side, OrderSide::Buy)),
        price,
        price_base_scale,
    )
    .unwrap_or(0);
    let sell_base_supply = sum_fill_at_price(
        eligible_orders
            .iter()
            .copied()
            .filter(|record| matches!(record.order.side, OrderSide::Sell)),
        price,
        price_base_scale,
    )
    .unwrap_or(0);
    let crossing_order_count = eligible_orders.len() as u64;

    let (status, reason) = if records.is_empty() {
        ("empty", "no orders were staged for this batch")
    } else if buy_base_demand == 0 {
        (
            "no_buy_liquidity",
            "no eligible buy liquidity at the diagnostic price",
        )
    } else if sell_base_supply == 0 {
        (
            "no_sell_liquidity",
            "no eligible sell liquidity at the diagnostic price",
        )
    } else if matched_base_volume == 0 {
        (
            "no_cross",
            "eligible orders did not produce an executable cross",
        )
    } else {
        ("ready", "batch has executable liquidity")
    };

    zylith_core::BatchLiquidityReport {
        status: status.into(),
        reason: Some(reason.into()),
        diagnostic_price: Some(price),
        buy_base_demand,
        sell_base_supply,
        matched_base_volume,
        crossing_order_count,
        min_base_liquidity,
    }
}

struct OutputNettingResult {
    bundle: OutputCiphertextBundle,
    note_preimages: Vec<Note>,
    recovery_records: Vec<OutputRecoveryRecord>,
    recovery_dummy_commitments: Vec<String>,
}

fn build_canonical_output_bundle(
    batch_id: &str,
    output_notes: &[OutputNoteRecord],
    matched_order_witnesses: &[MatchedOrderWitness],
    extra_note_preimages: &[Note],
) -> Result<OutputNettingResult, StatusCode> {
    let mut note_preimages = Vec::with_capacity(output_notes.len());
    for witness in matched_order_witnesses {
        note_preimages.push(witness.output_note.clone());
        if let Some(residual_note) = witness.residual_note.as_ref() {
            note_preimages.push(residual_note.clone());
        }
    }
    note_preimages.extend(extra_note_preimages.iter().cloned());
    if note_preimages.len() != output_notes.len() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    for (note, output) in note_preimages.iter().zip(output_notes.iter()) {
        let commitment = note
            .commitment()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if commitment != output.note_commitment
            || note.asset_id != output.asset_id
            || note.amount != output.amount
            || note.withdraw_authority != output.withdraw_authority
        {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let mut ciphertexts = Vec::with_capacity(output_notes.len());
    for (output_index, (note, output_note)) in
        note_preimages.iter().zip(output_notes.iter()).enumerate()
    {
        let output_proof = output_note_merkle_proof(output_notes, &output_note.note_commitment)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        ciphertexts.push(
            encrypt_output_note_for_owner(
                batch_id,
                output_index,
                note,
                output_note,
                &output_proof,
                &note.owner_public_key,
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
    }
    let bundle = OutputCiphertextBundle::from_ciphertexts(
        BatchId(batch_id.into()),
        format!("proof-auction://{batch_id}/output-bundle"),
        ciphertexts,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let recovery_records = bundle
        .ciphertexts
        .iter()
        .take(output_notes.len())
        .map(|ciphertext| {
            ciphertext
                .recovery
                .clone()
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
        })
        .collect::<Result<Vec<_>, StatusCode>>()?;
    let recovery_dummy_commitments = bundle
        .ciphertexts
        .iter()
        .skip(output_notes.len())
        .map(|ciphertext| {
            ciphertext
                .recovery
                .as_ref()
                .map(|recovery| recovery.commitment.clone())
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
        })
        .collect::<Result<Vec<_>, StatusCode>>()?;
    Ok(OutputNettingResult {
        bundle,
        note_preimages,
        recovery_records,
        recovery_dummy_commitments,
    })
}

fn note_commitment_from_note(note: &Note) -> Result<String, StatusCode> {
    note.commitment()
        .map(|commitment| commitment.0)
        .and_then(|commitment| normalize_felt_hex(&commitment))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn try_deposit_membership_candidate(
    prior_note_root: &str,
    activation_deposit_roots: &[String],
    consumed_deposit_roots_by_commitment: &[(String, String)],
    consumed_commitments: &[String],
) -> Result<Option<Vec<NoteMembershipWitness>>, StatusCode> {
    let prior_note_root =
        normalize_felt_hex(prior_note_root).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let consumed_roots = consumed_deposit_roots_by_commitment
        .iter()
        .map(|(_commitment, deposit_root)| deposit_root.clone())
        .collect::<BTreeSet<_>>();
    for start_index in 0..activation_deposit_roots.len() {
        let suffix = &activation_deposit_roots[start_index..];
        let suffix_set = suffix.iter().cloned().collect::<BTreeSet<_>>();
        if !consumed_roots.is_subset(&suffix_set) {
            continue;
        }
        let (candidate_root, witnesses) = deposit_note_membership_witnesses_for_chain(
            "0x0",
            suffix,
            consumed_deposit_roots_by_commitment,
            consumed_commitments,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if candidate_root == prior_note_root {
            return Ok(Some(witnesses));
        }
    }
    Ok(None)
}

type MerklePathProof = (Vec<String>, Vec<String>);

fn settlement_output_membership_proof(
    note_commitment: &str,
    batch_root: &str,
    prior_settlement_witnesses: &[SettlementWitness],
    prior_note_consolidation_history: &[NoteConsolidationHistoryRecord],
) -> Result<Option<MerklePathProof>, StatusCode> {
    let note_commitment =
        normalize_felt_hex(note_commitment).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let batch_root =
        normalize_felt_hex(batch_root).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for witness in prior_settlement_witnesses {
        let Some(output_note) = witness.output_notes.iter().find(|output| {
            normalize_felt_hex(&output.note_commitment.0)
                .map(|commitment| commitment == note_commitment)
                .unwrap_or(false)
        }) else {
            continue;
        };
        let proof = output_note_merkle_proof(&witness.output_notes, &output_note.note_commitment)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if verify_output_note_membership(output_note, &proof, &batch_root).is_ok() {
            return Ok(Some((proof.merkle_path, proof.merkle_directions)));
        }
    }
    for record in prior_note_consolidation_history {
        let Some(output_note) = record.output_notes.iter().find(|output| {
            normalize_felt_hex(&output.note_commitment.0)
                .map(|commitment| commitment == note_commitment)
                .unwrap_or(false)
        }) else {
            continue;
        };
        let proof = output_note_merkle_proof(&record.output_notes, &output_note.note_commitment)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if verify_output_note_membership(output_note, &proof, &batch_root).is_ok() {
            return Ok(Some((proof.merkle_path, proof.merkle_directions)));
        }
    }
    Ok(None)
}

fn derive_note_membership_witnesses_from_note_root_transitions(
    prior_note_root: &str,
    initial_note_root: &str,
    consumed_commitments: &[String],
    deposit_roots_by_commitment: &BTreeMap<String, String>,
    transitions: &[NoteRootTransitionRecord],
    prior_settlement_witnesses: &[SettlementWitness],
    prior_note_consolidation_history: &[NoteConsolidationHistoryRecord],
) -> Result<Option<Vec<NoteMembershipWitness>>, StatusCode> {
    let target_root =
        normalize_felt_hex(prior_note_root).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if target_root == "0x0" || consumed_commitments.is_empty() || transitions.is_empty() {
        return Ok(None);
    }

    let consumed_set = consumed_commitments
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut root =
        normalize_felt_hex(initial_note_root).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut prefixes = Vec::new();
    let mut batch_roots = Vec::new();
    let mut active_transitions = Vec::new();

    for transition in transitions {
        let batch_root = normalize_felt_hex(&transition.batch_root)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let expected_new_root = settlement_state_transition_root(&root, &batch_root)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let recorded_new_root = normalize_felt_hex(&transition.new_root)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if recorded_new_root != expected_new_root {
            return Err(StatusCode::CONFLICT);
        }
        prefixes.push(root.clone());
        batch_roots.push(batch_root);
        active_transitions.push(transition.clone());
        root = expected_new_root;
        if root == target_root {
            break;
        }
    }

    if root != target_root {
        return Ok(None);
    }

    let mut witnesses_by_commitment = BTreeMap::<String, NoteMembershipWitness>::new();
    for (index, transition) in active_transitions.iter().enumerate() {
        if transition.kind == NOTE_ROOT_TRANSITION_DEPOSIT_KIND {
            for commitment in &consumed_set {
                if witnesses_by_commitment.contains_key(commitment) {
                    continue;
                }
                let Some(deposit_root) = deposit_roots_by_commitment.get(commitment) else {
                    continue;
                };
                if deposit_root != &batch_roots[index] {
                    continue;
                }
                if witnesses_by_commitment
                    .insert(
                        commitment.clone(),
                        NoteMembershipWitness {
                            kind: NoteMembershipKind::Deposit,
                            prefix_root: prefixes[index].clone(),
                            batch_root: batch_roots[index].clone(),
                            merkle_path: Vec::new(),
                            merkle_directions: Vec::new(),
                            suffix_batch_roots: batch_roots[index + 1..].to_vec(),
                        },
                    )
                    .is_some()
                {
                    return Err(StatusCode::CONFLICT);
                }
            }
            continue;
        }

        if transition.kind != NOTE_ROOT_TRANSITION_SETTLEMENT_KIND
            && transition.kind != NOTE_ROOT_TRANSITION_CONSOLIDATION_KIND
        {
            return Err(StatusCode::CONFLICT);
        }

        for commitment in &consumed_set {
            if witnesses_by_commitment.contains_key(commitment) {
                continue;
            }
            let Some((merkle_path, merkle_directions)) = settlement_output_membership_proof(
                commitment,
                &batch_roots[index],
                prior_settlement_witnesses,
                prior_note_consolidation_history,
            )?
            else {
                continue;
            };
            if witnesses_by_commitment
                .insert(
                    commitment.clone(),
                    NoteMembershipWitness {
                        kind: NoteMembershipKind::SettlementOutput,
                        prefix_root: prefixes[index].clone(),
                        batch_root: batch_roots[index].clone(),
                        merkle_path,
                        merkle_directions,
                        suffix_batch_roots: batch_roots[index + 1..].to_vec(),
                    },
                )
                .is_some()
            {
                return Err(StatusCode::CONFLICT);
            }
        }
    }

    let mut witnesses = Vec::with_capacity(consumed_commitments.len());
    for commitment in consumed_commitments {
        let Some(witness) = witnesses_by_commitment.get(commitment).cloned() else {
            return Ok(None);
        };
        witnesses.push(witness);
    }
    Ok(Some(witnesses))
}

struct NoteMembershipSources<'a> {
    initial_note_root: &'a str,
    direct_input_notes: &'a [Note],
    matched_order_witnesses: &'a [MatchedOrderWitness],
    deposit_activations: &'a [DepositActivationRecord],
    note_root_transitions: &'a [NoteRootTransitionRecord],
    prior_settlement_witnesses: &'a [SettlementWitness],
    prior_note_consolidation_history: &'a [NoteConsolidationHistoryRecord],
}

fn derive_note_membership_witnesses(
    prior_note_root: &str,
    consumed_inputs: &[ConsumedInput],
    sources: NoteMembershipSources<'_>,
) -> Result<Vec<NoteMembershipWitness>, StatusCode> {
    let NoteMembershipSources {
        initial_note_root,
        direct_input_notes,
        matched_order_witnesses,
        deposit_activations,
        note_root_transitions,
        prior_settlement_witnesses,
        prior_note_consolidation_history,
    } = sources;
    if consumed_inputs.is_empty() {
        return Ok(Vec::new());
    }
    let consumed_commitments = consumed_inputs
        .iter()
        .map(|input| normalize_felt_hex(&input.note_commitment.0))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut deposit_roots_by_commitment = BTreeMap::<String, String>::new();
    let mut funding_note_results = direct_input_notes
        .iter()
        .map(|note| {
            Ok((
                note.nonce,
                note_commitment_from_note(note)?,
                deposit_root_from_note(note).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ))
        })
        .collect::<Vec<Result<(u64, String, String), StatusCode>>>();
    funding_note_results.extend(matched_order_witnesses.iter().flat_map(|witness| {
        witness
            .effective_funding_notes()
            .into_iter()
            .map(|note| {
                Ok((
                    note.nonce,
                    note_commitment_from_note(note)?,
                    deposit_root_from_note(note).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                ))
            })
            .collect::<Vec<Result<(u64, String, String), StatusCode>>>()
    }));
    let mut funding_notes = funding_note_results
        .into_iter()
        .collect::<Result<Vec<_>, StatusCode>>()?;
    funding_notes.sort_by_key(|(nonce, commitment, _root)| (*nonce, commitment.clone()));
    for (_nonce, commitment, deposit_root) in &funding_notes {
        deposit_roots_by_commitment.insert(
            commitment.clone(),
            normalize_felt_hex(deposit_root).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
    }
    let consumed_deposit_roots_by_commitment = consumed_commitments
        .iter()
        .filter_map(|commitment| {
            deposit_roots_by_commitment
                .get(commitment)
                .map(|deposit_root| (commitment.clone(), deposit_root.clone()))
        })
        .collect::<Vec<_>>();

    if let Some(witnesses) = derive_note_membership_witnesses_from_note_root_transitions(
        prior_note_root,
        initial_note_root,
        &consumed_commitments,
        &deposit_roots_by_commitment,
        note_root_transitions,
        prior_settlement_witnesses,
        prior_note_consolidation_history,
    )? {
        return Ok(witnesses);
    }

    let mut candidates = Vec::<Vec<String>>::new();
    if !deposit_activations.is_empty() {
        candidates.push(
            deposit_activations
                .iter()
                .map(|record| normalize_felt_hex(&record.deposit_root))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
    }

    let funding_activation_roots = funding_notes
        .into_iter()
        .map(|(_nonce, _commitment, deposit_root)| deposit_root)
        .collect::<Vec<_>>();
    if !funding_activation_roots.is_empty() && !candidates.contains(&funding_activation_roots) {
        candidates.push(funding_activation_roots);
    }

    for activation_deposit_roots in candidates {
        if let Some(witnesses) = try_deposit_membership_candidate(
            prior_note_root,
            &activation_deposit_roots,
            &consumed_deposit_roots_by_commitment,
            &consumed_commitments,
        )? {
            return Ok(witnesses);
        }
    }

    Ok(Vec::new())
}

struct SettlementBuildContext<'a> {
    product_config: &'a ProductConfig,
    liquidity_position_market_contexts: &'a LiquidityPositionMarketContexts,
    prior_roots: &'a SettlementRoots,
    initial_note_root: &'a str,
    deposit_activations: &'a [DepositActivationRecord],
    note_root_transitions: &'a [NoteRootTransitionRecord],
    prior_settlement_witnesses: &'a [SettlementWitness],
    prior_renewal_cancel_markers: &'a [String],
    prior_note_consolidation_history: &'a [NoteConsolidationHistoryRecord],
    prior_withdrawal_nullifiers: &'a [ConsumedInput],
    protocol_fee_recipient: &'a str,
    relay_fee_recipient: &'a str,
    protocol_fee_note_recipient: &'a FeeNoteRecipientConfig,
    relay_fee_note_recipient: &'a FeeNoteRecipientConfig,
    liquidity_attribution_signer_private_key: &'a str,
}

fn verify_liquidity_position_proof_witness_for_settlement(
    prior_root: &str,
    witnesses: &[LiquidityPositionTransitionWitness],
) -> Result<zylith_core::VerifiedLiquidityPositionProof, StatusCode> {
    if witnesses.is_empty() {
        return Ok(zylith_core::VerifiedLiquidityPositionProof {
            prior_root: normalize_felt_hex(prior_root).map_err(|_| StatusCode::CONFLICT)?,
            transition_root: "0x0".into(),
            new_root: normalize_felt_hex(prior_root).map_err(|_| StatusCode::CONFLICT)?,
            transition_count: 0,
            buy_filled_base_amount: 0,
            sell_filled_base_amount: 0,
        });
    }
    zylith_core::verify_liquidity_position_proof_witness(&LiquidityPositionProofWitness {
        prior_root: prior_root.into(),
        transitions: witnesses.to_vec(),
    })
    .map_err(|error| {
        eprintln!("liquidity position settlement witness rejected: {error}");
        StatusCode::CONFLICT
    })
}

fn append_liquidity_position_open_consumed_inputs(
    consumed_inputs: &mut Vec<ConsumedInput>,
    witnesses: &[LiquidityPositionTransitionWitness],
) -> Result<Vec<Note>, StatusCode> {
    let mut seen_nullifiers = consumed_inputs
        .iter()
        .map(|input| normalize_felt_hex(&input.nullifier.0))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| StatusCode::CONFLICT)?;
    let mut input_notes = Vec::new();
    for witness in witnesses {
        if !matches!(
            witness.transition.kind,
            LiquidityPositionTransitionKind::Open
        ) {
            continue;
        }
        let Some(open_funding) = witness.open_funding.as_ref() else {
            return Err(StatusCode::CONFLICT);
        };
        for note in &open_funding.input_notes {
            let commitment = note.commitment().map_err(|_| StatusCode::CONFLICT)?;
            let nullifier = nullifier_from_note_secret(&commitment, &note.blinding)
                .map_err(|_| StatusCode::CONFLICT)?;
            let normalized_nullifier =
                normalize_felt_hex(&nullifier.0).map_err(|_| StatusCode::CONFLICT)?;
            if !seen_nullifiers.insert(normalized_nullifier) {
                return Err(StatusCode::CONFLICT);
            }
            consumed_inputs.push(ConsumedInput {
                note_commitment: commitment,
                nullifier,
            });
            input_notes.push(note.clone());
        }
    }
    Ok(input_notes)
}

fn liquidity_position_lifecycle_output_note_preimages(
    witnesses: &[LiquidityPositionTransitionWitness],
) -> Vec<Note> {
    witnesses
        .iter()
        .flat_map(|witness| {
            let open_change_notes = witness
                .open_funding
                .as_ref()
                .into_iter()
                .flat_map(|funding| funding.change_notes.iter().cloned());
            open_change_notes.chain(witness.output_notes.iter().cloned())
        })
        .collect()
}

fn append_output_note_preimages(
    _batch_id: &str,
    output_notes: &mut Vec<OutputNoteRecord>,
    note_preimages: &[Note],
) -> Result<(), StatusCode> {
    for note in note_preimages {
        let note_commitment = note.commitment().map_err(|_| StatusCode::CONFLICT)?;
        output_notes.push(OutputNoteRecord {
            note_commitment,
            asset_id: note.asset_id.clone(),
            amount: note.amount,
            withdraw_authority: note.withdraw_authority.clone(),
        });
    }
    Ok(())
}

fn build_settlement_artifacts(
    batch_id: &str,
    batch: &BatchSummary,
    pair: &ProductPairConfig,
    records: &[DecryptedOrderRecord],
    liquidity_position_witnesses: &[LiquidityPositionTransitionWitness],
    context: SettlementBuildContext<'_>,
) -> Result<SettlementArtifacts, StatusCode> {
    let SettlementBuildContext {
        product_config,
        liquidity_position_market_contexts,
        prior_roots,
        initial_note_root,
        deposit_activations,
        note_root_transitions,
        prior_settlement_witnesses,
        prior_renewal_cancel_markers,
        prior_note_consolidation_history,
        prior_withdrawal_nullifiers,
        protocol_fee_recipient,
        relay_fee_recipient,
        protocol_fee_note_recipient,
        relay_fee_note_recipient,
        liquidity_attribution_signer_private_key,
    } = context;
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=validate_orders start records={}",
        batch_id,
        records.len()
    );
    for record in records {
        if record.order.pair_id != pair.pair_id {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=validate_orders failed=pair_id"
            );
            return Err(StatusCode::CONFLICT);
        }
        if record.order.batch_id != batch.batch_id {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=validate_orders failed=batch_id"
            );
            return Err(StatusCode::CONFLICT);
        }
        if record.order.expiry_epoch != batch.epoch_id {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=validate_orders failed=expiry_epoch"
            );
            return Err(StatusCode::CONFLICT);
        }
        if matches!(
            record.order.order_type,
            zylith_core::OrderType::LiquidityCurve
        ) {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=validate_orders failed=legacy_liquidity_curve_order"
            );
            return Err(StatusCode::CONFLICT);
        }
        if !matches!(
            record.order.order_type,
            zylith_core::OrderType::HeartbeatCover
        ) {
            product_config
                .validate_order_funding_notes(&record.order, &record.funding_notes)
                .map_err(|_| {
                    eprintln!(
                        "build_settlement_artifacts batch_id={batch_id} stage=validate_orders failed=funding_policy"
                    );
                    StatusCode::CONFLICT
                })?;
        }
    }

    let prior_consumed_inputs = historical_consumed_inputs(
        prior_settlement_witnesses,
        prior_note_consolidation_history,
        prior_withdrawal_nullifiers,
    )?;
    let spent_nullifiers = consumed_nullifier_set(&prior_consumed_inputs)?;
    let mut fillable_records = Vec::with_capacity(records.len());
    let mut spent_funding_records = 0usize;
    for record in records {
        if !matches!(
            record.order.order_type,
            zylith_core::OrderType::HeartbeatCover
        ) && record_uses_spent_funding(record, &spent_nullifiers)?
        {
            spent_funding_records += 1;
            continue;
        }
        fillable_records.push(record.clone());
    }
    if spent_funding_records > 0 {
        eprintln!(
            "build_settlement_artifacts batch_id={} stage=filter_spent_funding excluded={}",
            batch_id, spent_funding_records
        );
    }

    eprintln!(
        "build_settlement_artifacts batch_id={batch_id} stage=resolve_liquidity_positions start"
    );
    let prior_liquidity_position_book = active_liquidity_position_book_for_root(
        &prior_roots.liquidity_position_root,
        prior_settlement_witnesses,
    )?;
    let (
        liquidity_position_book_after_lifecycle,
        lifecycle_liquidity_position_root,
        lifecycle_touched_position_ids,
    ) = apply_liquidity_position_lifecycle_witnesses(
        prior_liquidity_position_book,
        &prior_roots.liquidity_position_root,
        liquidity_position_witnesses,
    )?;
    let observed_at_unix_ms = now_unix_ms();
    let liquidity_position_sources = liquidity_position_fill_sources_for_batch(
        &liquidity_position_book_after_lifecycle,
        pair,
        batch.epoch_id,
        observed_at_unix_ms,
        observed_at_unix_ms,
        &lifecycle_touched_position_ids,
        liquidity_position_market_contexts,
    )?;
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=resolve_liquidity_positions ok active_sources={}",
        batch_id,
        liquidity_position_sources.len()
    );

    eprintln!("build_settlement_artifacts batch_id={batch_id} stage=compute_price start");
    let fill_plan = compute_private_settlement_fill_plan(
        &fillable_records,
        &liquidity_position_sources,
        pair.price_base_scale,
    )?;
    let fills = fill_plan.order_fills;
    let clearing_price = fill_plan.clearing_price;
    let (
        _liquidity_position_book_after_fills,
        materialized_liquidity_position_root,
        materialized_liquidity_position_witnesses,
    ) = materialize_liquidity_position_fill_witnesses(
        liquidity_position_book_after_lifecycle,
        &lifecycle_liquidity_position_root,
        &fill_plan.liquidity_position_fills,
        batch_id,
        batch.epoch_id,
        clearing_price,
        pair.price_base_scale,
    )?;
    let liquidity_provider_attribution_bundle = build_liquidity_position_attribution_bundle(
        batch_id,
        pair,
        batch.epoch_id,
        &fill_plan.liquidity_position_fills,
        &materialized_liquidity_position_witnesses,
        liquidity_attribution_signer_private_key,
        observed_at_unix_ms,
    )?;
    let mut resolved_liquidity_position_witnesses = liquidity_position_witnesses.to_vec();
    resolved_liquidity_position_witnesses.extend(materialized_liquidity_position_witnesses);
    let liquidity_position_proof = verify_liquidity_position_proof_witness_for_settlement(
        &prior_roots.liquidity_position_root,
        &resolved_liquidity_position_witnesses,
    )?;
    if liquidity_position_proof.new_root != materialized_liquidity_position_root {
        eprintln!(
            "build_settlement_artifacts batch_id={} stage=resolve_liquidity_positions failed=root_mismatch proof={} materialized={}",
            batch_id, liquidity_position_proof.new_root, materialized_liquidity_position_root
        );
        return Err(StatusCode::CONFLICT);
    }
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=compute_price ok price={} order_fills={} liquidity_position_fills={}",
        batch_id,
        clearing_price,
        fills.len(),
        fill_plan.liquidity_position_fills.len()
    );
    let base_asset = pair.base_asset_id.clone();
    let quote_asset = pair.quote_asset_id.clone();

    let mut matched_orders = Vec::with_capacity(fills.len());
    let mut consumed_inputs = Vec::with_capacity(fills.len() * 2);
    let mut protocol_fee_accumulator: BTreeMap<String, u128> = BTreeMap::new();
    let mut relay_fee_accumulator: BTreeMap<String, u128> = BTreeMap::new();
    let mut output_notes = Vec::with_capacity(fills.len());
    let mut matched_order_witnesses = Vec::with_capacity(fills.len());
    let mut seen_funding_notes = BTreeMap::<String, String>::new();
    let mut reported_orders = BTreeSet::<String>::new();
    let mut order_execution_reports = Vec::with_capacity(records.len());
    let liquidity_position_transitions = resolved_liquidity_position_witnesses
        .iter()
        .map(|witness| witness.transition.clone())
        .collect::<Vec<_>>();

    eprintln!("build_settlement_artifacts batch_id={batch_id} stage=build_fills start");
    for fill in fills.iter() {
        let funding_note_commitments = fill
            .funding_notes
            .iter()
            .map(|note| note.commitment())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let funding_nullifiers = fill
            .funding_notes
            .iter()
            .zip(funding_note_commitments.iter())
            .map(|(note, commitment)| nullifier_from_note_secret(commitment, &note.blinding))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if funding_input_set_commitment(&funding_note_commitments)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            != fill.order.funding_note_ref
        {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=build_fills failed=funding_note_ref"
            );
            return Err(StatusCode::CONFLICT);
        }
        if funding_nullifier_set_commitment(&funding_nullifiers)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            != fill.order.funding_nullifier
        {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=build_fills failed=funding_nullifier_ref"
            );
            return Err(StatusCode::CONFLICT);
        }
        for funding_note_commitment in &funding_note_commitments {
            if seen_funding_notes
                .insert(
                    funding_note_commitment.0.clone(),
                    fill.order_commitment.0.clone(),
                )
                .is_some()
            {
                eprintln!(
                    "build_settlement_artifacts batch_id={batch_id} stage=build_fills failed=duplicate_funding_note"
                );
                return Err(StatusCode::CONFLICT);
            }
        }

        matched_orders.push(MatchedOrder {
            order_commitment: fill.order_commitment.clone(),
            filled_amount: fill.filled_amount,
        });
        consumed_inputs.extend(
            funding_note_commitments
                .iter()
                .cloned()
                .zip(funding_nullifiers.iter().cloned())
                .map(|(note_commitment, nullifier)| ConsumedInput {
                    note_commitment,
                    nullifier,
                }),
        );

        let (asset_id, gross_amount) = match fill.order.side {
            OrderSide::Buy => (base_asset.clone(), fill.filled_amount),
            OrderSide::Sell => (
                quote_asset.clone(),
                quote_amount_for_base_amount(
                    fill.filled_amount,
                    clearing_price,
                    pair.price_base_scale,
                )
                .map_err(|_| StatusCode::CONFLICT)?,
            ),
        };
        let protocol_fee_bps = u128::from(
            pair.fee_bps_for_order(&fill.order)
                .map_err(|_| StatusCode::CONFLICT)?,
        );
        let relay_fee_bps = u128::from(
            pair.relay_fee_bps_for_order(&fill.order)
                .map_err(|_| StatusCode::CONFLICT)?,
        );
        let protocol_fee_amount =
            ceil_fee_amount(gross_amount, protocol_fee_bps).ok_or(StatusCode::CONFLICT)?;
        let relay_fee_amount =
            ceil_fee_amount(gross_amount, relay_fee_bps).ok_or(StatusCode::CONFLICT)?;
        let fee_amount = protocol_fee_amount
            .checked_add(relay_fee_amount)
            .ok_or(StatusCode::CONFLICT)?;
        let net_amount = gross_amount
            .checked_sub(fee_amount)
            .ok_or(StatusCode::CONFLICT)?;
        if gross_amount == 0 || net_amount == 0 {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=build_fills failed=dust_output"
            );
            return Err(StatusCode::CONFLICT);
        }
        if protocol_fee_amount > 0 {
            let accrued_fee = protocol_fee_accumulator
                .entry(asset_id.0.clone())
                .or_default();
            *accrued_fee = accrued_fee
                .checked_add(protocol_fee_amount)
                .ok_or(StatusCode::CONFLICT)?;
        }
        if relay_fee_amount > 0 {
            let accrued_fee = relay_fee_accumulator.entry(asset_id.0.clone()).or_default();
            *accrued_fee = accrued_fee
                .checked_add(relay_fee_amount)
                .ok_or(StatusCode::CONFLICT)?;
        }

        let note_asset_id = asset_id.clone();
        let output_index = output_notes.len();
        let note = build_output_note(
            batch_id,
            output_index,
            &fill.order_commitment,
            &fill.order,
            note_asset_id.clone(),
            net_amount,
            &fill.order.recipient_withdraw_authority,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let note_commitment = note
            .commitment()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let output_note_commitment = note_commitment.clone();
        output_notes.push(OutputNoteRecord {
            note_commitment: note_commitment.clone(),
            asset_id: note_asset_id,
            amount: net_amount,
            withdraw_authority: note.withdraw_authority.clone(),
        });

        let (residual_asset_id, residual_amount) =
            residual_for_fill(fill, clearing_price, pair.price_base_scale)?;
        let mut residual_note_commitment = None;
        let residual_note = if residual_amount > 0 {
            let residual_output_index = output_notes.len();
            let residual_note = build_output_note(
                batch_id,
                residual_output_index,
                &fill.order_commitment,
                &fill.order,
                residual_asset_id.clone(),
                residual_amount,
                &fill.order.recipient_residual_withdraw_authority,
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let residual_commitment = residual_note
                .commitment()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            residual_note_commitment = Some(residual_commitment.clone());
            output_notes.push(OutputNoteRecord {
                note_commitment: residual_commitment,
                asset_id: residual_asset_id.clone(),
                amount: residual_amount,
                withdraw_authority: residual_note.withdraw_authority.clone(),
            });
            Some(residual_note)
        } else {
            None
        };

        reported_orders.insert(fill.order_commitment.0.clone());
        let funding_note_commitments =
            funding_note_commitments_for_report(&fill.funding_note, &fill.funding_notes)?;
        order_execution_reports.push(OrderExecutionReport {
            batch_id: BatchId(batch_id.into()),
            pair_id: pair.pair_id.clone(),
            order_commitment: fill.order_commitment.clone(),
            order_report_auth_tag: Some(derive_order_execution_report_auth_tag(
                &BatchId(batch_id.into()),
                &fill.order_commitment,
                &fill.cancellation_auth_tag,
            )),
            funding_note_commitment: fill.order.funding_note_ref.clone(),
            funding_note_commitments,
            status: "clearing".into(),
            side: fill.order.side.clone(),
            order_type: fill.order.order_type.clone(),
            time_in_force: fill.order.time_in_force.clone(),
            submitted_amount: fill.order.amount,
            filled_amount: fill.filled_amount,
            unfilled_amount: fill.order.amount.saturating_sub(fill.filled_amount),
            limit_price: fill.order.limit_price,
            execution_price: Some(clearing_price),
            fee_asset_id: Some(asset_id.clone()),
            fee_amount,
            output_note_commitment: Some(output_note_commitment),
            output_asset_id: Some(asset_id),
            output_amount: net_amount,
            residual_note_commitment,
            residual_asset_id: (residual_amount > 0).then_some(residual_asset_id),
            residual_amount,
        });

        matched_order_witnesses.push(MatchedOrderWitness {
            order_commitment: fill.order_commitment.clone(),
            funding_note: fill.funding_note.clone(),
            funding_notes: fill.funding_notes.clone(),
            funding_note_ref: fill.order.funding_note_ref.clone(),
            funding_nullifier: fill.order.funding_nullifier.clone(),
            funding_nullifiers,
            funding_authorization: fill.funding_authorization.clone(),
            side: fill.order.side.clone(),
            order_type: fill.order.order_type.clone(),
            relay_mode: fill.order.relay_mode.clone(),
            liquidity_curve: fill.order.liquidity_curve.clone(),
            liquidity_provider_band_attribution: None,
            limit_price: fill.order.limit_price,
            order_amount: fill.order.amount,
            min_fill: fill.order.min_fill,
            time_in_force: fill.order.time_in_force.clone(),
            expiry_epoch: fill.order.expiry_epoch,
            order_nonce: fill.order.order_nonce,
            parent_order_commitment: fill.order.parent_order_commitment.clone(),
            parent_child_index: fill.order.parent_child_index,
            parent_secret_commitment: fill.order.parent_secret_commitment.clone(),
            parent_cancel_authority: fill.order.parent_cancel_authority.clone(),
            parent_authorization_secret: fill.order.parent_authorization_secret.clone(),
            auditor_view_allowed: fill.order.auditor_view_allowed,
            recipient_owner_public_key: fill.order.recipient_owner_public_key.clone(),
            recipient_spend_authority: fill.order.recipient_spend_authority.clone(),
            recipient_withdraw_authority: fill.order.recipient_withdraw_authority.clone(),
            recipient_residual_withdraw_authority: fill
                .order
                .recipient_residual_withdraw_authority
                .clone(),
            filled_amount: fill.filled_amount,
            output_note: note,
            residual_note,
        });
    }

    eprintln!(
        "build_settlement_artifacts batch_id={} stage=build_fills ok consumed={} outputs={}",
        batch_id,
        consumed_inputs.len(),
        output_notes.len()
    );
    let liquidity_position_open_input_notes = append_liquidity_position_open_consumed_inputs(
        &mut consumed_inputs,
        &resolved_liquidity_position_witnesses,
    )?;
    let liquidity_position_output_note_preimages =
        liquidity_position_lifecycle_output_note_preimages(&resolved_liquidity_position_witnesses);
    append_output_note_preimages(
        batch_id,
        &mut output_notes,
        &liquidity_position_output_note_preimages,
    )?;
    for record in records {
        if reported_orders.contains(&record.order_commitment.0) {
            continue;
        }
        if matches!(
            record.order.order_type,
            zylith_core::OrderType::HeartbeatCover
        ) {
            continue;
        }
        let funding_note_commitments =
            funding_note_commitments_for_report(&record.funding_note, &record.funding_notes)?;
        order_execution_reports.push(OrderExecutionReport {
            batch_id: BatchId(batch_id.into()),
            pair_id: pair.pair_id.clone(),
            order_commitment: record.order_commitment.clone(),
            order_report_auth_tag: Some(derive_order_execution_report_auth_tag(
                &BatchId(batch_id.into()),
                &record.order_commitment,
                &record.cancellation_auth_tag,
            )),
            funding_note_commitment: record.order.funding_note_ref.clone(),
            funding_note_commitments,
            status: "clearing".into(),
            side: record.order.side.clone(),
            order_type: record.order.order_type.clone(),
            time_in_force: record.order.time_in_force.clone(),
            submitted_amount: record.order.amount,
            filled_amount: 0,
            unfilled_amount: record.order.amount,
            limit_price: record.order.limit_price,
            execution_price: None,
            fee_asset_id: None,
            fee_amount: 0,
            output_note_commitment: None,
            output_asset_id: None,
            output_amount: 0,
            residual_note_commitment: None,
            residual_asset_id: None,
            residual_amount: 0,
        });
    }

    let fees = deterministic_fee_entries(
        &protocol_fee_accumulator,
        &relay_fee_accumulator,
        &base_asset,
        &quote_asset,
        protocol_fee_recipient,
        relay_fee_recipient,
    );
    let fee_note_preimages = append_fee_output_notes(
        batch_id,
        &mut output_notes,
        &fees,
        protocol_fee_recipient,
        relay_fee_recipient,
        protocol_fee_note_recipient,
        relay_fee_note_recipient,
    )?;

    eprintln!("build_settlement_artifacts batch_id={batch_id} stage=output_bundle start");
    let mut extra_note_preimages = liquidity_position_output_note_preimages;
    extra_note_preimages.extend(fee_note_preimages);
    let output_netting = build_canonical_output_bundle(
        batch_id,
        &output_notes,
        &matched_order_witnesses,
        &extra_note_preimages,
    )?;
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=output_bundle ok outputs={} recovery_records={}",
        batch_id,
        output_notes.len(),
        output_netting.recovery_records.len()
    );
    let renewal_child_uses = zylith_core::renewal_child_uses_from_matched_witnesses(
        &matched_order_witnesses,
    )
    .map_err(|_| {
        eprintln!("build_settlement_artifacts batch_id={batch_id} stage=renewal_child_uses failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=nullifier_witnesses start prior_consumed={} consumed={}",
        batch_id,
        prior_consumed_inputs.len(),
        consumed_inputs.len()
    );
    let (computed_prior_nullifier_root, new_nullifier_root, nullifier_sparse_witnesses) =
        nullifier_sparse_update_witnesses_for_consumed_inputs(
            &prior_consumed_inputs,
            &consumed_inputs,
        )
        .map_err(|_| {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=nullifier_witnesses failed=derive"
            );
            StatusCode::CONFLICT
        })?;
    if computed_prior_nullifier_root
        != normalize_felt_hex(&prior_roots.nullifier_root)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        eprintln!(
            "build_settlement_artifacts batch_id={} stage=nullifier_witnesses failed=root_mismatch computed={} expected={}",
            batch_id, computed_prior_nullifier_root, prior_roots.nullifier_root
        );
        return Err(StatusCode::CONFLICT);
    }
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=nullifier_witnesses ok new_root={}",
        batch_id, new_nullifier_root
    );
    let mut prior_renewal_entries = prior_settlement_witnesses
        .iter()
        .flat_map(|witness| {
            witness
                .renewal_child_uses
                .iter()
                .map(|renewal| renewal.child_nullifier.clone())
        })
        .collect::<Vec<_>>();
    prior_renewal_entries.extend(prior_renewal_cancel_markers.iter().cloned());
    prior_renewal_entries.sort();
    prior_renewal_entries.dedup();
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=renewal_witnesses start prior_entries={} child_uses={}",
        batch_id,
        prior_renewal_entries.len(),
        renewal_child_uses.len()
    );
    let (
        computed_prior_renewal_root,
        new_renewal_root,
        renewal_child_sparse_witnesses,
        renewal_cancel_sparse_witnesses,
    ) = renewal_sparse_witnesses_for_child_uses(
        &prior_renewal_entries,
        &renewal_child_uses,
        &matched_order_witnesses,
    )
    .map_err(|_| {
        eprintln!(
            "build_settlement_artifacts batch_id={batch_id} stage=renewal_witnesses failed=derive"
        );
        StatusCode::CONFLICT
    })?;
    if computed_prior_renewal_root
        != normalize_felt_hex(&prior_roots.renewal_root)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        eprintln!(
            "build_settlement_artifacts batch_id={} stage=renewal_witnesses failed=root_mismatch computed={} expected={}",
            batch_id, computed_prior_renewal_root, prior_roots.renewal_root
        );
        return Err(StatusCode::CONFLICT);
    }
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=renewal_witnesses ok new_root={}",
        batch_id, new_renewal_root
    );

    let prior_note_root = if normalize_felt_hex(&prior_roots.note_root)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        == "0x0"
        && !consumed_inputs.is_empty()
    {
        let deposit_roots = matched_order_witnesses
            .iter()
            .flat_map(|witness| witness.effective_funding_notes())
            .chain(liquidity_position_open_input_notes.iter())
            .map(|note| deposit_root_from_note(note).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR))
            .collect::<Result<Vec<_>, StatusCode>>()?;
        settlement_note_root_after_deposit_roots(&deposit_roots)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        prior_roots.note_root.clone()
    };
    let prior_nullifier_root = prior_roots.nullifier_root.clone();
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=note_membership start consumed={} deposits={} transitions={}",
        batch_id,
        consumed_inputs.len(),
        deposit_activations.len(),
        note_root_transitions.len()
    );
    let note_membership_witnesses = derive_note_membership_witnesses(
        &prior_note_root,
        &consumed_inputs,
        NoteMembershipSources {
            initial_note_root,
            direct_input_notes: &liquidity_position_open_input_notes,
            matched_order_witnesses: &matched_order_witnesses,
            deposit_activations,
            note_root_transitions,
            prior_settlement_witnesses,
            prior_note_consolidation_history,
        },
    )
    .inspect_err(|status| {
        eprintln!(
            "build_settlement_artifacts batch_id={} stage=note_membership failed status={}",
            batch_id, status
        );
    })?;
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=note_membership ok witnesses={}",
        batch_id,
        note_membership_witnesses.len()
    );

    let transcript = SettlementTranscript {
        batch_id: BatchId(batch_id.into()),
        pair_id: pair.pair_id.clone(),
        batch_epoch: batch.epoch_id,
        order_commitment_root: batch.order_commitment_root.clone(),
        encrypted_order_set_commitment: batch.encrypted_order_set_commitment.clone(),
        prior_note_root: prior_note_root.clone(),
        prior_nullifier_root: prior_nullifier_root.clone(),
        prior_renewal_root: prior_roots.renewal_root.clone(),
        prior_fee_root: prior_roots.fee_root.clone(),
        prior_liquidity_position_root: prior_roots.liquidity_position_root.clone(),
        new_nullifier_root: new_nullifier_root.clone(),
        new_renewal_root: new_renewal_root.clone(),
        new_liquidity_position_root: liquidity_position_proof.new_root.clone(),
        clearing_price,
        price_base_scale: pair.price_base_scale,
        taker_fee_bps: pair.taker_fee_bps,
        relay_fee_bps: pair.relay_fee_bps,
        protocol_fee_recipient: protocol_fee_recipient.into(),
        relay_fee_recipient: relay_fee_recipient.into(),
        matched_orders,
        consumed_inputs,
        renewal_child_uses: renewal_child_uses.clone(),
        liquidity_position_transitions,
        fees,
        output_notes,
        output_note_preimages: output_netting.note_preimages.clone(),
        output_recovery_records: output_netting.recovery_records.clone(),
        output_recovery_dummy_commitments: output_netting.recovery_dummy_commitments.clone(),
        output_ciphertext_bundle_ref: output_netting.bundle.bundle_commitment.clone(),
    };
    let settlement_witness = SettlementWitness {
        batch_id: BatchId(batch_id.into()),
        pair_id: pair.pair_id.clone(),
        batch_epoch: batch.epoch_id,
        order_commitment_root: transcript.order_commitment_root.clone(),
        encrypted_order_set_commitment: transcript.encrypted_order_set_commitment.clone(),
        transcript_commitment: settlement_transcript_commitment(&transcript)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        auction_verifier_address: "unbound".into(),
        prior_note_root,
        prior_nullifier_root: transcript.prior_nullifier_root.clone(),
        prior_renewal_root: transcript.prior_renewal_root.clone(),
        prior_fee_root: transcript.prior_fee_root.clone(),
        prior_liquidity_position_root: transcript.prior_liquidity_position_root.clone(),
        new_nullifier_root: transcript.new_nullifier_root.clone(),
        new_renewal_root: transcript.new_renewal_root.clone(),
        new_liquidity_position_root: transcript.new_liquidity_position_root.clone(),
        clearing_price,
        price_base_scale: pair.price_base_scale,
        taker_fee_bps: pair.taker_fee_bps,
        relay_fee_bps: pair.relay_fee_bps,
        protocol_fee_recipient: protocol_fee_recipient.into(),
        relay_fee_recipient: relay_fee_recipient.into(),
        base_asset_id: base_asset,
        quote_asset_id: quote_asset,
        matched_orders: transcript.matched_orders.clone(),
        matched_order_witnesses,
        consumed_inputs: transcript.consumed_inputs.clone(),
        note_membership_witnesses,
        nullifier_history: Vec::new(),
        nullifier_sparse_witnesses,
        renewal_history: Vec::new(),
        renewal_child_sparse_witnesses,
        renewal_cancel_sparse_witnesses,
        renewal_child_uses,
        liquidity_position_transitions: transcript.liquidity_position_transitions.clone(),
        liquidity_position_witnesses: resolved_liquidity_position_witnesses,
        fees: transcript.fees.clone(),
        output_notes: transcript.output_notes.clone(),
        output_note_preimages: transcript.output_note_preimages.clone(),
        output_recovery_records: transcript.output_recovery_records.clone(),
        output_recovery_dummy_commitments: transcript.output_recovery_dummy_commitments.clone(),
        output_ciphertext_bundle_ref: transcript.output_ciphertext_bundle_ref.clone(),
    };

    Ok(SettlementArtifacts {
        transcript,
        output_bundle: output_netting.bundle,
        liquidity_provider_attribution_bundle,
        settlement_witness,
        order_execution_reports,
    })
}

fn residual_for_fill(
    fill: &OrderFillPlan,
    clearing_price: u128,
    price_base_scale: u128,
) -> Result<(AssetId, u128), StatusCode> {
    let funding_total = funding_note_total(&fill.funding_notes).ok_or(StatusCode::CONFLICT)?;
    match fill.order.side {
        OrderSide::Buy => {
            let spent =
                quote_amount_for_base_amount(fill.filled_amount, clearing_price, price_base_scale)
                    .map_err(|_| StatusCode::CONFLICT)?;
            Ok((
                fill.funding_note.asset_id.clone(),
                funding_total
                    .checked_sub(spent)
                    .ok_or(StatusCode::CONFLICT)?,
            ))
        }
        OrderSide::Sell => Ok((
            fill.funding_note.asset_id.clone(),
            funding_total
                .checked_sub(fill.filled_amount)
                .ok_or(StatusCode::CONFLICT)?,
        )),
    }
}

fn funding_note_total(notes: &[Note]) -> Option<u128> {
    notes
        .iter()
        .try_fold(0u128, |total, note| total.checked_add(note.amount))
}

fn deterministic_fee_entries(
    protocol_fee_accumulator: &BTreeMap<String, u128>,
    relay_fee_accumulator: &BTreeMap<String, u128>,
    base_asset: &AssetId,
    quote_asset: &AssetId,
    protocol_fee_recipient: &str,
    relay_fee_recipient: &str,
) -> Vec<FeeEntry> {
    let mut fees = Vec::with_capacity(4);
    push_fee_entry_if_present(
        &mut fees,
        protocol_fee_accumulator,
        base_asset,
        protocol_fee_recipient,
    );
    push_fee_entry_if_present(
        &mut fees,
        protocol_fee_accumulator,
        quote_asset,
        protocol_fee_recipient,
    );
    push_fee_entry_if_present(
        &mut fees,
        relay_fee_accumulator,
        base_asset,
        relay_fee_recipient,
    );
    push_fee_entry_if_present(
        &mut fees,
        relay_fee_accumulator,
        quote_asset,
        relay_fee_recipient,
    );
    fees
}

fn append_fee_output_notes(
    batch_id: &str,
    output_notes: &mut Vec<OutputNoteRecord>,
    fees: &[FeeEntry],
    protocol_fee_recipient: &str,
    relay_fee_recipient: &str,
    protocol_fee_note_recipient: &FeeNoteRecipientConfig,
    relay_fee_note_recipient: &FeeNoteRecipientConfig,
) -> Result<Vec<Note>, StatusCode> {
    let mut note_preimages = Vec::with_capacity(fees.len());
    for fee in fees {
        let (slot_prefix, recipient_config) = if fee.recipient == protocol_fee_recipient {
            ("protocol", protocol_fee_note_recipient)
        } else if fee.recipient == relay_fee_recipient {
            ("relay", relay_fee_note_recipient)
        } else {
            return Err(StatusCode::CONFLICT);
        };
        if normalize_felt_hex(&recipient_config.withdraw_authority)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            != normalize_felt_hex(&fee.recipient).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            return Err(StatusCode::CONFLICT);
        }
        let output_index = output_notes.len();
        let fee_slot = format!("{slot_prefix}:{}", fee.asset_id.0);
        let note = build_fee_output_note(FeeOutputNoteInput {
            batch_id,
            output_index,
            fee_slot: &fee_slot,
            asset_id: fee.asset_id.clone(),
            amount: fee.amount,
            owner_public_key: &recipient_config.owner_public_key,
            spend_authority: &recipient_config.spend_authority,
            withdraw_authority: &recipient_config.withdraw_authority,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let note_commitment = note
            .commitment()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        output_notes.push(OutputNoteRecord {
            note_commitment,
            asset_id: note.asset_id.clone(),
            amount: note.amount,
            withdraw_authority: note.withdraw_authority.clone(),
        });
        note_preimages.push(note);
    }
    Ok(note_preimages)
}

fn push_fee_entry_if_present(
    fees: &mut Vec<FeeEntry>,
    fee_accumulator: &BTreeMap<String, u128>,
    asset: &AssetId,
    recipient: &str,
) {
    if let Some(amount) = fee_accumulator
        .get(&asset.0)
        .copied()
        .filter(|amount| *amount > 0)
    {
        fees.push(FeeEntry {
            asset_id: asset.clone(),
            amount,
            recipient: recipient.into(),
        });
    }
}

fn is_order_eligible(order: &OrderIntent, clearing_price: u128) -> bool {
    if matches!(order.order_type, zylith_core::OrderType::HeartbeatCover) {
        return false;
    }
    if matches!(order.order_type, zylith_core::OrderType::LiquidityCurve) {
        return false;
    }

    match order.side {
        OrderSide::Buy => order.limit_price >= clearing_price,
        OrderSide::Sell => order.limit_price <= clearing_price,
    }
}

fn max_fill_at_price(
    record: &DecryptedOrderRecord,
    clearing_price: u128,
    price_base_scale: u128,
) -> u128 {
    if matches!(
        record.order.order_type,
        zylith_core::OrderType::HeartbeatCover
    ) {
        return 0;
    }
    if matches!(
        record.order.order_type,
        zylith_core::OrderType::LiquidityCurve
    ) {
        return 0;
    }
    if !is_order_eligible(&record.order, clearing_price) {
        return 0;
    }
    let requested_amount = record.order.amount;

    let available_amount = match record.order.side {
        OrderSide::Buy => {
            if clearing_price == 0 {
                return 0;
            }
            let Some(funding_total) = funding_note_total(&record.funding_notes) else {
                return 0;
            };
            let affordable_amount =
                base_amount_affordable_for_quote(funding_total, clearing_price, price_base_scale)
                    .unwrap_or(u128::MAX);
            requested_amount.min(affordable_amount)
        }
        OrderSide::Sell => {
            let Some(funding_total) = funding_note_total(&record.funding_notes) else {
                return 0;
            };
            requested_amount.min(funding_total)
        }
    };

    if available_amount < record.order.min_fill {
        return 0;
    }
    if is_fill_or_kill_order(&record.order) && available_amount < record.order.amount {
        return 0;
    }
    available_amount
}

fn candidate_prices_for_order(order: &OrderIntent) -> Vec<u128> {
    vec![order.limit_price]
}

fn is_fill_or_kill_order(order: &OrderIntent) -> bool {
    matches!(order.time_in_force, TimeInForce::FillOrKill)
}

async fn ensure_batch_registered_onchain(state: &AppState, batch_id: &str) -> Result<(), String> {
    let registrar = match &state.batch_registrar {
        Some(registrar) => registrar.clone(),
        None => return Ok(()),
    };
    let batch = fetch_batch_summary(state, batch_id)
        .await
        .map_err(|status| {
            format!("failed to fetch batch summary for onchain registration: {status}")
        })?;

    let rpc_url = Url::parse(&registrar.rpc_url)
        .map_err(|error| format!("invalid batch registrar rpc url: {error}"))?;
    let provider = JsonRpcClient::new(starknet_http_transport(rpc_url));
    let batch_registry_address = parse_felt(
        &registrar.batch_registry_address,
        "ZYLITH_BATCH_REGISTRY_ADDRESS",
    )?;
    let batch_id_felt = parse_felt(
        &encode_starknet_felt("batch-id", &batch.batch_id.0),
        "encoded batch id",
    )?;
    let order_count_felt = Felt::from(batch.order_count);
    let order_commitment_root =
        parse_felt(&batch.order_commitment_root, "batch order commitment root")?;
    let encrypted_order_set_commitment = parse_felt(
        &batch.encrypted_order_set_commitment,
        "batch encrypted order set commitment",
    )?;

    let exists_call = FunctionCall {
        contract_address: batch_registry_address,
        entry_point_selector: get_selector_from_name("batch_exists")
            .map_err(|error| format!("failed to compute batch_exists selector: {error}"))?,
        calldata: vec![batch_id_felt],
    };
    let exists = provider
        .call(exists_call, BlockId::Tag(BlockTag::Latest))
        .await
        .map_err(|error| format!("failed to query onchain batch existence: {error}"))?;
    let exists = exists.first().copied().unwrap_or(Felt::ZERO) != Felt::ZERO;

    let batch_registry_call = if exists {
        let view_call = FunctionCall {
            contract_address: batch_registry_address,
            entry_point_selector: get_selector_from_name("get_batch")
                .map_err(|error| format!("failed to compute get_batch selector: {error}"))?,
            calldata: vec![batch_id_felt],
        };
        let view = provider
            .call(view_call, BlockId::Tag(BlockTag::Latest))
            .await
            .map_err(|error| format!("failed to query onchain batch view: {error}"))?;
        let onchain_order_count = view.get(5).copied().unwrap_or(Felt::ZERO);
        let onchain_order_root = view.get(6).copied().unwrap_or(Felt::ZERO);
        let onchain_encrypted_set = view.get(7).copied().unwrap_or(Felt::ZERO);
        if onchain_order_count == order_count_felt
            && onchain_order_root == order_commitment_root
            && onchain_encrypted_set == encrypted_order_set_commitment
        {
            return Ok(());
        }
        return Err(format!(
            "onchain batch {} is already registered with different order roots",
            batch.batch_id.0
        ));
    } else {
        Call {
            to: batch_registry_address,
            selector: get_selector_from_name("register_batch")
                .map_err(|error| format!("failed to compute register_batch selector: {error}"))?,
            calldata: vec![
                batch_id_felt,
                parse_felt(
                    &encode_starknet_felt("pair-id", &batch.pair_id.0),
                    "encoded pair id",
                )?,
                Felt::from(batch.epoch_id),
                Felt::from(batch.close_time_unix_ms),
                order_count_felt,
                order_commitment_root,
                encrypted_order_set_commitment,
            ],
        }
    };

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(parse_felt(
        &registrar.private_key,
        "ZYLITH_BATCH_REGISTRAR_PRIVATE_KEY",
    )?));
    let account = SingleOwnerAccount::new(
        provider,
        signer,
        parse_felt(
            &registrar.account_address,
            "ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS",
        )?,
        parse_felt(&registrar.chain_id, "ZYLITH_BATCH_REGISTRAR_CHAIN_ID")?,
        ExecutionEncoding::New,
    );

    let result = account
        .execute_v3(vec![batch_registry_call])
        .send()
        .await
        .map_err(|error| format!("failed to submit onchain batch root registration: {error}"))?;

    let receipt = wait_for_accepted_receipt(account.provider(), result.transaction_hash).await;
    let Some(receipt) = receipt else {
        return Err("batch registration receipt unavailable".into());
    };
    match receipt.receipt.execution_result() {
        ExecutionResult::Succeeded => Ok(()),
        ExecutionResult::Reverted { reason } => Err(format!(
            "batch root registration reverted onchain: {reason}"
        )),
    }
}

fn load_starknet_executor_from_env(
    deployment_manifest: Option<&DeploymentManifest>,
) -> Option<StarknetExecutorConfig> {
    let rpc_url = env::var("ZYLITH_STARKNET_RPC_URL")
        .ok()
        .or_else(|| deployment_manifest.map(|manifest| manifest.rpc_url.clone()))?;
    let account_address = env::var("ZYLITH_STARKNET_ACCOUNT_ADDRESS").ok()?;
    let private_key = env::var("ZYLITH_STARKNET_PRIVATE_KEY").ok()?;
    let chain_id = env::var("ZYLITH_STARKNET_CHAIN_ID")
        .ok()
        .or_else(|| deployment_manifest.map(|manifest| manifest.chain_id.clone()))?;
    let proof_account_address = env::var(NATIVE_PROOF_ACCOUNT_ADDRESS_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            deployment_manifest.and_then(|manifest| {
                let manifest_address = manifest.proof.proof_account_address.trim();
                if !manifest_address.is_empty() {
                    Some(manifest.proof.proof_account_address.clone())
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| account_address.clone());
    let proof_private_key = env::var(NATIVE_PROOF_PRIVATE_KEY_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty());

    Some(StarknetExecutorConfig {
        rpc_url,
        account_address,
        private_key,
        chain_id,
        proof_account_address,
        proof_private_key,
    })
}

fn load_batch_registrar_from_env(
    deployment_manifest: Option<&DeploymentManifest>,
) -> Result<Option<BatchRegistrarConfig>, String> {
    let Some(account_address) = env::var("ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS").ok() else {
        return Ok(None);
    };
    let private_key = resolve_batch_registrar_private_key(
        &account_address,
        env::var("ZYLITH_BATCH_REGISTRAR_PRIVATE_KEY").ok(),
        env::var("ZYLITH_STARKNET_ACCOUNT_ADDRESS").ok(),
        env::var("ZYLITH_STARKNET_PRIVATE_KEY").ok(),
    )?;
    let rpc_url = env::var("ZYLITH_BATCH_REGISTRAR_RPC_URL")
        .ok()
        .or_else(|| env::var("ZYLITH_STARKNET_RPC_URL").ok())
        .or_else(|| deployment_manifest.map(|manifest| manifest.rpc_url.clone()))
        .ok_or_else(|| "ZYLITH_BATCH_REGISTRAR_RPC_URL or deployment manifest rpc_url is required when ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS is set".to_string())?;
    let chain_id = env::var("ZYLITH_BATCH_REGISTRAR_CHAIN_ID")
        .ok()
        .or_else(|| env::var("ZYLITH_STARKNET_CHAIN_ID").ok())
        .or_else(|| deployment_manifest.map(|manifest| manifest.chain_id.clone()))
        .ok_or_else(|| "ZYLITH_BATCH_REGISTRAR_CHAIN_ID or deployment manifest chain_id is required when ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS is set".to_string())?;
    let batch_registry_address = env::var("ZYLITH_BATCH_REGISTRY_ADDRESS").ok().or_else(|| {
        deployment_manifest.map(|manifest| manifest.contracts.batch_registry.clone())
    }).ok_or_else(|| "ZYLITH_BATCH_REGISTRY_ADDRESS or deployment manifest batch_registry is required when ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS is set".to_string())?;

    Ok(Some(BatchRegistrarConfig {
        rpc_url,
        account_address,
        private_key,
        chain_id,
        batch_registry_address,
    }))
}

fn resolve_batch_registrar_private_key(
    registrar_account_address: &str,
    explicit_registrar_private_key: Option<String>,
    settlement_account_address: Option<String>,
    settlement_private_key: Option<String>,
) -> Result<String, String> {
    if let Some(private_key) = explicit_registrar_private_key
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    {
        return Ok(private_key);
    }

    if let (Some(settlement_account_address), Some(settlement_private_key)) =
        (settlement_account_address, settlement_private_key)
        && same_starknet_address(registrar_account_address, &settlement_account_address)
    {
        let private_key = settlement_private_key.trim().to_owned();
        if !private_key.is_empty() {
            return Ok(private_key);
        }
    }

    Err("ZYLITH_BATCH_REGISTRAR_PRIVATE_KEY is required when ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS is set and differs from ZYLITH_STARKNET_ACCOUNT_ADDRESS".into())
}

fn same_starknet_address(left: &str, right: &str) -> bool {
    match (Felt::from_hex(left.trim()), Felt::from_hex(right.trim())) {
        (Ok(left), Ok(right)) => left == right,
        _ => left.trim() == right.trim(),
    }
}

async fn build_native_execution_request(
    executor: &StarknetExecutorConfig,
    settlement_call: &StarknetCall,
    mode: NativeTransactionMode,
) -> Result<NativeExecutionRequestRecord, String> {
    let (execution_context, nonce, resource_bounds, settlement_call_contract) =
        prepare_native_execution_fields(executor, settlement_call, mode).await?;

    let rpc_url = Url::parse(&executor.rpc_url)
        .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?;
    let provider = JsonRpcClient::new(starknet_http_transport(rpc_url));
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(parse_felt(
        executor.request_private_key(mode),
        "native proof transaction private key",
    )?));
    let request_account_address = executor.request_account_address(mode);
    let account = SingleOwnerAccount::new(
        provider,
        signer,
        parse_felt(
            request_account_address,
            "native proof transaction account address",
        )?,
        parse_felt(&executor.chain_id, "ZYLITH_STARKNET_CHAIN_ID")?,
        ExecutionEncoding::New,
    );
    let invoke_request = account
        .execute_v3(vec![settlement_call_contract])
        .nonce(nonce)
        .l1_gas(resource_bounds.l1_gas)
        .l1_gas_price(execution_context.l1_gas_price)
        .l2_gas(resource_bounds.l2_gas)
        .l2_gas_price(execution_context.l2_gas_price)
        .l1_data_gas(resource_bounds.l1_data_gas)
        .l1_data_gas_price(execution_context.l1_data_gas_price)
        .tip(0)
        .prepared()
        .map_err(|_| "failed to prepare native execution request".to_string())?
        .get_invoke_request(false, false)
        .await
        .map_err(|error| format!("failed to build native execution request: {error}"))?;
    let transaction = serde_json::to_value(&invoke_request)
        .map_err(|error| format!("failed to serialize native invoke request: {error}"))?;

    Ok(NativeExecutionRequestRecord {
        block_id: execution_context.block_id,
        transaction,
    })
}

async fn prepare_native_execution_fields(
    executor: &StarknetExecutorConfig,
    settlement_call: &StarknetCall,
    mode: NativeTransactionMode,
) -> Result<(NativeExecutionContext, Felt, NativeResourceBounds, Call), String> {
    let rpc_url = Url::parse(&executor.rpc_url)
        .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?;
    let provider = JsonRpcClient::new(starknet_http_transport(rpc_url));
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(parse_felt(
        executor.request_private_key(mode),
        "native proof transaction private key",
    )?));
    let mut account = SingleOwnerAccount::new(
        provider,
        signer,
        parse_felt(
            executor.request_account_address(mode),
            "native proof transaction account address",
        )?,
        parse_felt(&executor.chain_id, "ZYLITH_STARKNET_CHAIN_ID")?,
        ExecutionEncoding::New,
    );
    let settlement_call_contract = starknet_call_to_call(settlement_call)?;
    let mut execution_context = fetch_native_execution_context(account.provider(), mode).await?;
    if mode == NativeTransactionMode::ProofOnly {
        execution_context.l1_gas_price = 0;
        execution_context.l2_gas_price = 0;
        execution_context.l1_data_gas_price = 0;
    }
    account.set_block_id(native_block_id_to_starknet_block_id(
        &execution_context.block_id,
    )?);
    let nonce = account
        .get_nonce()
        .await
        .map_err(|error| format!("failed to fetch account nonce: {error}"))?;
    let resource_bounds = build_native_resource_bounds(
        &account,
        &settlement_call_contract,
        nonce,
        &execution_context,
        mode,
        starknet_call_requires_native_proof_facts(settlement_call),
    )
    .await?;

    Ok((
        execution_context,
        nonce,
        resource_bounds,
        settlement_call_contract,
    ))
}

#[derive(Clone, Copy, Debug)]
struct NativeResourceBounds {
    l1_gas: u64,
    l2_gas: u64,
    l1_data_gas: u64,
}

struct NativeExecutionContext {
    block_id: NativeBlockId,
    l1_gas_price: u128,
    l2_gas_price: u128,
    l1_data_gas_price: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTransactionMode {
    ProofOnly,
    SubmitOnchain,
}

async fn build_native_resource_bounds(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    settlement_call: &Call,
    nonce: Felt,
    execution_context: &NativeExecutionContext,
    mode: NativeTransactionMode,
    skip_fee_estimate: bool,
) -> Result<NativeResourceBounds, String> {
    let configured_l1_gas = env_positive_optional_config::<u64>(NATIVE_L1_GAS_MAX_AMOUNT_ENV)?;
    let configured_l2_gas = env_positive_optional_config::<u64>(NATIVE_L2_GAS_MAX_AMOUNT_ENV)?;
    let configured_l1_data_gas =
        env_positive_optional_config::<u64>(NATIVE_L1_DATA_GAS_MAX_AMOUNT_ENV)?;
    let estimate = if mode == NativeTransactionMode::SubmitOnchain
        && !skip_fee_estimate
        && native_resource_bounds_require_estimate(
            configured_l1_gas,
            configured_l2_gas,
            configured_l1_data_gas,
        ) {
        match estimate_native_fee(account, settlement_call, nonce, execution_context).await {
            Ok(estimate) => Some(estimate),
            Err(error) if native_fee_estimate_should_use_configured_bounds(&error) => {
                eprintln!(
                    "native settlement fee estimation requires proof_facts; using configured/default native resource bounds"
                );
                None
            }
            Err(error) => {
                return Err(format!("failed to estimate native settlement fee: {error}"));
            }
        }
    } else {
        None
    };

    let l2_gas_floor = if mode == NativeTransactionMode::ProofOnly {
        DEFAULT_NATIVE_PROOF_ONLY_L2_GAS_FLOOR
    } else {
        DEFAULT_NATIVE_L2_GAS_FLOOR
    };

    Ok(NativeResourceBounds {
        l1_gas: configured_l1_gas.unwrap_or_else(|| {
            native_gas_amount_bound(
                estimate
                    .as_ref()
                    .map(|estimate| estimate.l1_gas_consumed)
                    .unwrap_or_default(),
                DEFAULT_NATIVE_L1_GAS_FLOOR,
            )
        }),
        l2_gas: configured_l2_gas.unwrap_or_else(|| {
            native_gas_amount_bound(
                estimate
                    .as_ref()
                    .map(|estimate| estimate.l2_gas_consumed)
                    .unwrap_or_default(),
                l2_gas_floor,
            )
        }),
        l1_data_gas: configured_l1_data_gas.unwrap_or_else(|| {
            native_gas_amount_bound(
                estimate
                    .as_ref()
                    .map(|estimate| estimate.l1_data_gas_consumed)
                    .unwrap_or_default(),
                DEFAULT_NATIVE_L1_DATA_GAS_FLOOR,
            )
        }),
    })
}

fn starknet_call_requires_native_proof_facts(call: &StarknetCall) -> bool {
    call.entrypoint.ends_with("_with_proof_facts")
}

fn native_resource_bounds_require_estimate(
    l1_gas: Option<u64>,
    l2_gas: Option<u64>,
    l1_data_gas: Option<u64>,
) -> bool {
    l1_gas.is_none() || l1_data_gas.is_none() || l2_gas.is_none()
}

fn native_fee_estimate_should_use_configured_bounds(error: &str) -> bool {
    error.contains("PROOF_FACTS_MISSING")
        || error.contains("EMPTY_PROOF_FACTS")
        || error.contains("TransactionExecutionError")
}

async fn estimate_native_fee(
    account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
    settlement_call: &Call,
    nonce: Felt,
    execution_context: &NativeExecutionContext,
) -> Result<FeeEstimate, String> {
    let estimate_request = account
        .execute_v3(vec![settlement_call.clone()])
        .nonce(nonce)
        .l1_gas(0)
        .l1_gas_price(execution_context.l1_gas_price)
        .l2_gas(0)
        .l2_gas_price(execution_context.l2_gas_price)
        .l1_data_gas(0)
        .l1_data_gas_price(execution_context.l1_data_gas_price)
        .tip(0)
        .prepared()
        .map_err(|_| "failed to prepare native fee estimate request".to_string())?
        .get_invoke_request(false, true)
        .await
        .map_err(|error| format!("failed to build native fee estimate request: {error}"))?;

    account
        .provider()
        .estimate_fee_single(
            BroadcastedTransaction::Invoke(estimate_request),
            [SimulationFlagForEstimateFee::SkipValidate],
            native_block_id_to_starknet_block_id(&execution_context.block_id)?,
        )
        .await
        .map_err(|error| error.to_string())
}

fn native_block_id_to_starknet_block_id(block_id: &NativeBlockId) -> Result<BlockId, String> {
    match block_id {
        NativeBlockId::Tag(tag) if tag == "latest" => Ok(BlockId::Tag(BlockTag::Latest)),
        NativeBlockId::Tag(tag) if tag == "pre_confirmed" => {
            Ok(BlockId::Tag(BlockTag::PreConfirmed))
        }
        NativeBlockId::Number { block_number } => Ok(BlockId::Number(*block_number)),
        NativeBlockId::Hash { block_hash } => {
            Ok(BlockId::Hash(parse_felt(block_hash, "block hash")?))
        }
        NativeBlockId::Tag(tag) => Err(format!("unsupported native block tag {tag}")),
    }
}

async fn fetch_native_execution_context(
    provider: &JsonRpcClient<HttpTransport>,
    mode: NativeTransactionMode,
) -> Result<NativeExecutionContext, String> {
    let block = provider
        .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
        .await
        .map_err(|error| format!("failed to fetch latest block gas prices: {error}"))?;
    let proving_blocks_back = env_positive_config_or_default(
        NATIVE_PROVER_BLOCKS_BACK_ENV,
        DEFAULT_NATIVE_PROVER_BLOCKS_BACK,
    )?;
    let proof_block_tag_override = native_proof_block_tag_override();
    match block {
        MaybePreConfirmedBlockWithTxHashes::Block(block) => Ok(NativeExecutionContext {
            block_id: native_execution_context_block_id(
                mode,
                block.block_number,
                proving_blocks_back,
                proof_block_tag_override.as_deref(),
            ),
            l1_gas_price: native_gas_price_bound(block.l1_gas_price.price_in_fri)?,
            l2_gas_price: native_gas_price_bound(block.l2_gas_price.price_in_fri)?,
            l1_data_gas_price: native_gas_price_bound(block.l1_data_gas_price.price_in_fri)?,
        }),
        MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(block) => {
            // Starknet RPC `latest` is accepted state. Some providers omit newer confirmed-block
            // header counters that starknet-rust 0.19 requires, which makes the untagged response
            // deserialize as the pre-confirmed shape even when the raw block has ACCEPTED_ON_L2.
            Ok(NativeExecutionContext {
                block_id: native_execution_context_block_id(
                    mode,
                    block.block_number,
                    proving_blocks_back,
                    proof_block_tag_override.as_deref(),
                ),
                l1_gas_price: native_gas_price_bound(block.l1_gas_price.price_in_fri)?,
                l2_gas_price: native_gas_price_bound(block.l2_gas_price.price_in_fri)?,
                l1_data_gas_price: native_gas_price_bound(block.l1_data_gas_price.price_in_fri)?,
            })
        }
    }
}

fn native_execution_context_block_id(
    mode: NativeTransactionMode,
    latest_block_number: u64,
    proving_blocks_back: u64,
    proof_block_tag_override: Option<&str>,
) -> NativeBlockId {
    match mode {
        NativeTransactionMode::ProofOnly if proof_block_tag_override == Some("latest") => {
            NativeBlockId::Tag("latest".into())
        }
        NativeTransactionMode::ProofOnly => NativeBlockId::Number {
            block_number: latest_block_number.saturating_sub(proving_blocks_back),
        },
        NativeTransactionMode::SubmitOnchain if proof_block_tag_override == Some("latest") => {
            NativeBlockId::Tag("latest".into())
        }
        NativeTransactionMode::SubmitOnchain => NativeBlockId::Number {
            block_number: latest_block_number.saturating_sub(proving_blocks_back),
        },
    }
}

fn native_proof_block_tag_override() -> Option<String> {
    let value = env::var(NATIVE_PROVER_BLOCK_TAG_ENV).ok()?;
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" => None,
        "latest" => Some("latest".to_string()),
        unsupported => {
            eprintln!(
                "unsupported {NATIVE_PROVER_BLOCK_TAG_ENV}={unsupported}; using numbered proof block"
            );
            None
        }
    }
}

fn native_gas_price_bound(price: Felt) -> Result<u128, String> {
    let hex = format!("{price:#x}");
    let base = u128::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|error| format!("gas price {hex} does not fit in u128: {error}"))?;
    Ok(base.saturating_mul(NATIVE_GAS_PRICE_MULTIPLIER_NUMERATOR)
        / NATIVE_GAS_PRICE_MULTIPLIER_DENOMINATOR)
}

fn native_gas_amount_bound(consumed: u64, floor: u64) -> u64 {
    let adjusted = consumed
        .saturating_mul(NATIVE_GAS_AMOUNT_MULTIPLIER_NUMERATOR)
        .div_ceil(NATIVE_GAS_AMOUNT_MULTIPLIER_DENOMINATOR);
    adjusted.max(floor)
}

async fn submit_native_plan_onchain(
    state: &AppState,
    settlement_plan: &SettlementSubmissionPlan,
    proof_artifact: &ProofArtifactRecord,
) -> Result<OnchainSubmissionRecord, String> {
    let proof_context =
        build_native_settlement_submission_proof_context(state, settlement_plan).await?;
    let executor = &proof_context.executor;
    let [
        nullifier_kind,
        renewal_kind,
        liquidity_position_kind,
        settlement_order_kind,
        settlement_input_membership_kind,
        settlement_output_recovery_kind,
        settlement_kind,
    ] = NATIVE_SETTLEMENT_SUBMISSION_ORDER;

    let provider = JsonRpcClient::new(starknet_http_transport(
        Url::parse(&executor.rpc_url)
            .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?,
    ));
    let verifier_address = settlement_plan.settlement_call.contract_address.clone();
    let args = &settlement_plan.encoded_args;
    let nullifier_record_call = StarknetCall {
        contract_address: verifier_address.clone(),
        entrypoint: "record_nullifier_roots_with_proof_facts".into(),
        calldata: vec![
            args.batch_id.clone(),
            args.transcript_commitment.clone(),
            args.prior_nullifier_root.clone(),
            args.consumed_nullifier_root.clone(),
            args.new_nullifier_root.clone(),
        ],
    };
    let nullifier_statement =
        prove_fresh_native_settlement_statement(state, &proof_context, nullifier_kind).await?;
    let (nullifier_proof, nullifier_proof_facts) = read_native_proof_bundle(
        &nullifier_statement.proof_path,
        &nullifier_statement.proof_facts_path,
        "nullifier",
    )?;
    let nullifier_tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        executor,
        &nullifier_record_call,
        nullifier_proof,
        &nullifier_proof_facts,
    )
    .await
    .map_err(|error| format!("failed to record native nullifier proof: {error}"))?;
    ensure_native_statement_record_accepted(&provider, &nullifier_tx_hash, "nullifier").await?;

    let renewal_record_call = StarknetCall {
        contract_address: verifier_address.clone(),
        entrypoint: "record_renewal_roots_with_proof_facts".into(),
        calldata: vec![
            args.batch_id.clone(),
            args.transcript_commitment.clone(),
            args.prior_renewal_root.clone(),
            args.renewal_child_root.clone(),
            args.new_renewal_root.clone(),
        ],
    };
    let renewal_statement =
        prove_fresh_native_settlement_statement(state, &proof_context, renewal_kind).await?;
    let (renewal_proof, renewal_proof_facts) = read_native_proof_bundle(
        &renewal_statement.proof_path,
        &renewal_statement.proof_facts_path,
        "renewal",
    )?;
    let renewal_tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        executor,
        &renewal_record_call,
        renewal_proof,
        &renewal_proof_facts,
    )
    .await
    .map_err(|error| format!("failed to record native renewal proof: {error}"))?;
    ensure_native_statement_record_accepted(&provider, &renewal_tx_hash, "renewal").await?;

    let liquidity_position_record_call = StarknetCall {
        contract_address: verifier_address.clone(),
        entrypoint: "record_liquidity_position_roots_with_proof_facts".into(),
        calldata: vec![
            args.batch_id.clone(),
            args.transcript_commitment.clone(),
            args.prior_liquidity_position_root.clone(),
            args.liquidity_position_transition_root.clone(),
            args.new_liquidity_position_root.clone(),
        ],
    };
    let liquidity_position_statement =
        prove_fresh_native_settlement_statement(state, &proof_context, liquidity_position_kind)
            .await?;
    let (liquidity_position_proof, liquidity_position_proof_facts) = read_native_proof_bundle(
        &liquidity_position_statement.proof_path,
        &liquidity_position_statement.proof_facts_path,
        "liquidity-position",
    )?;
    let liquidity_position_tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        executor,
        &liquidity_position_record_call,
        liquidity_position_proof,
        &liquidity_position_proof_facts,
    )
    .await
    .map_err(|error| format!("failed to record native liquidity-position proof: {error}"))?;
    ensure_native_statement_record_accepted(
        &provider,
        &liquidity_position_tx_hash,
        "liquidity-position",
    )
    .await?;

    let settlement_order_record_call = StarknetCall {
        contract_address: verifier_address.clone(),
        entrypoint: "record_settlement_order_with_proof_facts".into(),
        calldata: vec![args.batch_id.clone(), args.transcript_commitment.clone()],
    };
    let settlement_order_statement =
        prove_fresh_native_settlement_statement(state, &proof_context, settlement_order_kind)
            .await?;
    let (settlement_order_proof, settlement_order_proof_facts) = read_native_proof_bundle(
        &settlement_order_statement.proof_path,
        &settlement_order_statement.proof_facts_path,
        "settlement-order",
    )?;
    let settlement_order_tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        executor,
        &settlement_order_record_call,
        settlement_order_proof,
        &settlement_order_proof_facts,
    )
    .await
    .map_err(|error| format!("failed to record native settlement-order proof: {error}"))?;
    ensure_native_statement_record_accepted(
        &provider,
        &settlement_order_tx_hash,
        "settlement-order",
    )
    .await?;

    let settlement_input_membership_record_call = StarknetCall {
        contract_address: verifier_address.clone(),
        entrypoint: "record_settlement_input_membership_with_proof_facts".into(),
        calldata: vec![args.batch_id.clone(), args.transcript_commitment.clone()],
    };
    let settlement_input_membership_statement = prove_fresh_native_settlement_statement(
        state,
        &proof_context,
        settlement_input_membership_kind,
    )
    .await?;
    let (settlement_input_membership_proof, settlement_input_membership_proof_facts) =
        read_native_proof_bundle(
            &settlement_input_membership_statement.proof_path,
            &settlement_input_membership_statement.proof_facts_path,
            "settlement-input-membership",
        )?;
    let settlement_input_membership_tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        executor,
        &settlement_input_membership_record_call,
        settlement_input_membership_proof,
        &settlement_input_membership_proof_facts,
    )
    .await
    .map_err(|error| {
        format!("failed to record native settlement-input-membership proof: {error}")
    })?;
    ensure_native_statement_record_accepted(
        &provider,
        &settlement_input_membership_tx_hash,
        "settlement-input-membership",
    )
    .await?;

    let settlement_output_recovery_record_call = StarknetCall {
        contract_address: verifier_address.clone(),
        entrypoint: "record_settlement_output_recovery_with_proof_facts".into(),
        calldata: vec![args.batch_id.clone(), args.transcript_commitment.clone()],
    };
    let settlement_output_recovery_statement = prove_fresh_native_settlement_statement(
        state,
        &proof_context,
        settlement_output_recovery_kind,
    )
    .await?;
    let (settlement_output_recovery_proof, settlement_output_recovery_proof_facts) =
        read_native_proof_bundle(
            &settlement_output_recovery_statement.proof_path,
            &settlement_output_recovery_statement.proof_facts_path,
            "settlement-output-recovery",
        )?;
    let settlement_output_recovery_tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        executor,
        &settlement_output_recovery_record_call,
        settlement_output_recovery_proof,
        &settlement_output_recovery_proof_facts,
    )
    .await
    .map_err(|error| {
        format!("failed to record native settlement-output-recovery proof: {error}")
    })?;
    ensure_native_statement_record_accepted(
        &provider,
        &settlement_output_recovery_tx_hash,
        "settlement-output-recovery",
    )
    .await?;

    let settlement_statement =
        prove_fresh_native_settlement_statement(state, &proof_context, settlement_kind).await?;
    persist_refreshed_native_settlement_artifact(
        state,
        proof_artifact,
        RefreshedNativeSettlementArtifacts {
            settlement: &settlement_statement,
            nullifier: &nullifier_statement,
            renewal: &renewal_statement,
            liquidity_position: &liquidity_position_statement,
            settlement_order: &settlement_order_statement,
            settlement_input_membership: &settlement_input_membership_statement,
            settlement_output_recovery: &settlement_output_recovery_statement,
        },
    )
    .await?;
    let (proof, proof_facts) = read_native_proof_bundle(
        &settlement_statement.proof_path,
        &settlement_statement.proof_facts_path,
        "settlement",
    )?;
    let tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        executor,
        &settlement_plan.settlement_call,
        proof,
        &proof_facts,
    )
    .await?;
    let settlement_contract_address = settlement_plan.settlement_call.contract_address.clone();
    let batch_id = settlement_plan.batch_id.clone();
    let submission_id = format!("{}:{}", batch_id.0, tx_hash);

    let mut submission = OnchainSubmissionRecord {
        submission_id,
        batch_id,
        transaction_hash: tx_hash.clone(),
        submitted_at_unix_ms: now_unix_ms(),
        receipt_checked_at_unix_ms: None,
        confirmed_at_unix_ms: None,
        finality_status: None,
        execution_status: None,
        revert_reason: None,
        block_number: None,
        block_hash: None,
        block_timestamp_unix_ms: None,
        submission_mode: "native-proof-facts".into(),
        settlement_contract_address,
    };

    populate_submission_receipt_status(
        &mut submission,
        wait_for_receipt(&provider, parse_felt(&tx_hash, "transaction hash")?).await,
    );
    if let Some(block_number) = submission.block_number
        && let Ok(block_timestamp) = fetch_block_timestamp_unix_ms(&provider, block_number).await
    {
        submission.block_timestamp_unix_ms = Some(block_timestamp);
    }

    Ok(submission)
}

async fn build_native_settlement_submission_proof_context(
    state: &AppState,
    settlement_plan: &SettlementSubmissionPlan,
) -> Result<NativeSettlementSubmissionProofContext, String> {
    let tx_prover_url = state.native_tx_prover_url.clone();
    let executor = state
        .starknet_executor
        .clone()
        .ok_or_else(|| "starknet executor is not configured".to_string())?;
    let batch_id = &settlement_plan.batch_id.0;
    let transcript = fetch_transcript(state, batch_id)
        .await
        .map_err(|status| format!("failed to fetch settlement transcript: {status}"))?;
    let settlement_witness = state
        .settlement_witnesses
        .read()
        .await
        .get(batch_id)
        .cloned()
        .ok_or_else(|| "settlement witness is not prepared".to_string())?;
    let transcript_commitment =
        settlement_transcript_commitment(&transcript).map_err(|error| error.to_string())?;
    if settlement_witness.transcript_commitment != transcript_commitment {
        return Err("settlement witness commitment does not match transcript".into());
    }
    let native_proof_reference =
        native_settlement_message_hash(&state.auction_verifier_address, &transcript_commitment)
            .map_err(|error| error.to_string())?;
    let rebuilt_plan = build_settlement_submission_plan(
        &transcript,
        &state.auction_verifier_address,
        &native_proof_reference,
    )
    .map_err(|error| error.to_string())?;
    if rebuilt_plan != *settlement_plan {
        return Err("stored settlement plan does not match the current transcript".into());
    }
    ensure_batch_registered_onchain(state, batch_id).await?;
    let roots = root_only_settlement_commitments(&transcript).map_err(|error| error.to_string())?;
    let settlement_message_hash = settlement_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &transcript_commitment,
    )
    .map_err(|error| error.to_string())?;
    let nullifier_message_hash = nullifier_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &transcript_commitment,
        &roots.prior_nullifier_root,
        &roots.consumed_nullifier_root,
        &roots.new_nullifier_root,
    )
    .map_err(|error| error.to_string())?;
    let renewal_message_hash = renewal_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &transcript_commitment,
        &roots.prior_renewal_root,
        &roots.renewal_child_root,
        &roots.new_renewal_root,
    )
    .map_err(|error| error.to_string())?;
    let liquidity_position_message_hash = liquidity_position_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &transcript_commitment,
        &roots.prior_liquidity_position_root,
        &roots.liquidity_position_transition_root,
        &roots.new_liquidity_position_root,
    )
    .map_err(|error| error.to_string())?;
    let settlement_order_message_hash = settlement_order_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &transcript_commitment,
    )
    .map_err(|error| error.to_string())?;
    let settlement_input_membership_message_hash =
        settlement_input_membership_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &transcript_commitment,
        )
        .map_err(|error| error.to_string())?;
    let settlement_output_recovery_message_hash =
        settlement_output_recovery_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &transcript_commitment,
        )
        .map_err(|error| error.to_string())?;
    let serialized_settlement_witness =
        zylith_core::build_stwo_serialized_input(&settlement_witness)
            .map_err(|error| format!("failed to serialize settlement witness: {error}"))?;
    let serialized_liquidity_position_witness =
        build_liquidity_position_serialized_input(&settlement_witness)
            .map_err(|error| format!("failed to serialize liquidity position witness: {error}"))?;

    Ok(NativeSettlementSubmissionProofContext {
        tx_prover_url,
        executor,
        batch_id: batch_id.clone(),
        serialized_settlement_witness,
        serialized_liquidity_position_witness,
        settlement_message_hash,
        nullifier_message_hash,
        renewal_message_hash,
        liquidity_position_message_hash,
        settlement_order_message_hash,
        settlement_input_membership_message_hash,
        settlement_output_recovery_message_hash,
    })
}

async fn prove_fresh_native_settlement_statement(
    state: &AppState,
    context: &NativeSettlementSubmissionProofContext,
    kind: NativeSettlementStatementKind,
) -> Result<NativeStatementProofArtifact, String> {
    let stage_key = context.stage_key(kind);
    execute_native_statement_prover(NativeStatementProverRequest {
        state,
        tx_prover_url: &context.tx_prover_url,
        executor: &context.executor,
        batch_id: &context.batch_id,
        stage_key: &stage_key,
        entrypoint: kind.entrypoint(&state.native_proof_entrypoint),
        serialized_native_witness: context.serialized_witness(kind),
        expected_message_hashes: std::slice::from_ref(context.expected_message_hash(kind)),
    })
    .await
}

struct RefreshedNativeSettlementArtifacts<'a> {
    settlement: &'a NativeStatementProofArtifact,
    nullifier: &'a NativeStatementProofArtifact,
    renewal: &'a NativeStatementProofArtifact,
    liquidity_position: &'a NativeStatementProofArtifact,
    settlement_order: &'a NativeStatementProofArtifact,
    settlement_input_membership: &'a NativeStatementProofArtifact,
    settlement_output_recovery: &'a NativeStatementProofArtifact,
}

async fn persist_refreshed_native_settlement_artifact(
    state: &AppState,
    existing: &ProofArtifactRecord,
    artifacts: RefreshedNativeSettlementArtifacts<'_>,
) -> Result<(), String> {
    let mut refreshed = existing.clone();
    refreshed.created_at_unix_ms = now_unix_ms();
    refreshed.proof_path = artifacts.settlement.proof_path.clone();
    refreshed.public_inputs_path = artifacts.settlement.proof_facts_path.clone();
    refreshed.prover_stdout_path = artifacts.settlement.stdout_path.clone();
    refreshed.prover_stderr_path = artifacts.settlement.stderr_path.clone();
    refreshed.proof_sha256 = artifacts.settlement.proof_sha256.clone();
    refreshed.public_inputs_sha256 = artifacts.settlement.proof_facts_sha256.clone();
    refreshed.native_proof_file_path = Some(artifacts.settlement.proof_path.clone());
    refreshed.native_proof_facts_file_path = Some(artifacts.settlement.proof_facts_path.clone());
    refreshed.native_execution_request_path =
        Some(artifacts.settlement.execution_request_path.clone());
    refreshed.native_nullifier_proof_file_path = Some(artifacts.nullifier.proof_path.clone());
    refreshed.native_nullifier_proof_facts_file_path =
        Some(artifacts.nullifier.proof_facts_path.clone());
    refreshed.native_nullifier_execution_request_path =
        Some(artifacts.nullifier.execution_request_path.clone());
    refreshed.native_renewal_proof_file_path = Some(artifacts.renewal.proof_path.clone());
    refreshed.native_renewal_proof_facts_file_path =
        Some(artifacts.renewal.proof_facts_path.clone());
    refreshed.native_renewal_execution_request_path =
        Some(artifacts.renewal.execution_request_path.clone());
    refreshed.native_liquidity_position_proof_file_path =
        Some(artifacts.liquidity_position.proof_path.clone());
    refreshed.native_liquidity_position_proof_facts_file_path =
        Some(artifacts.liquidity_position.proof_facts_path.clone());
    refreshed.native_liquidity_position_execution_request_path =
        Some(artifacts.liquidity_position.execution_request_path.clone());
    refreshed.native_settlement_order_proof_file_path =
        Some(artifacts.settlement_order.proof_path.clone());
    refreshed.native_settlement_order_proof_facts_file_path =
        Some(artifacts.settlement_order.proof_facts_path.clone());
    refreshed.native_settlement_order_execution_request_path =
        Some(artifacts.settlement_order.execution_request_path.clone());
    refreshed.native_settlement_input_membership_proof_file_path =
        Some(artifacts.settlement_input_membership.proof_path.clone());
    refreshed.native_settlement_input_membership_proof_facts_file_path = Some(
        artifacts
            .settlement_input_membership
            .proof_facts_path
            .clone(),
    );
    refreshed.native_settlement_input_membership_execution_request_path = Some(
        artifacts
            .settlement_input_membership
            .execution_request_path
            .clone(),
    );
    refreshed.native_settlement_output_recovery_proof_file_path =
        Some(artifacts.settlement_output_recovery.proof_path.clone());
    refreshed.native_settlement_output_recovery_proof_facts_file_path = Some(
        artifacts
            .settlement_output_recovery
            .proof_facts_path
            .clone(),
    );
    refreshed.native_settlement_output_recovery_execution_request_path = Some(
        artifacts
            .settlement_output_recovery
            .execution_request_path
            .clone(),
    );
    let batch_id = refreshed.batch_id.0.clone();
    let artifact_id = refreshed.artifact_id.clone();
    let mut proof_artifacts = state.proof_artifacts.write().await;
    persist_record_and_insert(
        state.data_dir.as_ref(),
        PROOF_ARTIFACTS_DIR,
        &mut proof_artifacts,
        batch_id.clone(),
        refreshed,
    )
    .map_err(status_to_error)?;
    let mut proof_jobs = state.proof_jobs.write().await;
    let updated_status = if let Some(status) = proof_jobs.get_mut(&batch_id) {
        status.proof_artifact_id = Some(artifact_id);
        status.proof_artifact_available = true;
        status.updated_at_unix_ms = now_unix_ms();
        Some(status.clone())
    } else {
        None
    };
    if let Some(updated_status) = updated_status {
        persist_record_and_insert(
            state.data_dir.as_ref(),
            PROOF_JOBS_DIR,
            &mut proof_jobs,
            batch_id,
            updated_status,
        )
        .map_err(status_to_error)?;
    }
    Ok(())
}

fn read_native_proof_bundle(
    proof_path: &str,
    proof_facts_path: &str,
    label: &str,
) -> Result<(String, Vec<String>), String> {
    let proof = read_utf8_file_limited(
        FsPath::new(proof_path),
        MAX_NATIVE_PROOF_FILE_BYTES,
        &format!("native {label} proof"),
    )?;
    let proof_facts_body = read_utf8_file_limited(
        FsPath::new(proof_facts_path),
        MAX_NATIVE_PROOF_FACTS_FILE_BYTES,
        &format!("native {label} proof facts"),
    )?;
    let proof_facts: Vec<String> = serde_json::from_str(&proof_facts_body)
        .map_err(|error| format!("failed to parse native {label} proof facts: {error}"))?;
    Ok((proof, proof_facts))
}

async fn ensure_native_statement_record_accepted(
    provider: &JsonRpcClient<HttpTransport>,
    tx_hash: &str,
    label: &str,
) -> Result<(), String> {
    let receipt = wait_for_accepted_receipt(
        provider,
        parse_felt(tx_hash, &format!("{label} proof transaction hash"))?,
    )
    .await
    .ok_or_else(|| {
        format!("{label} proof transaction {tx_hash} was not accepted before settlement")
    })?;
    match receipt.receipt.execution_result() {
        ExecutionResult::Succeeded => Ok(()),
        ExecutionResult::Reverted { reason } => Err(format!(
            "{label} proof transaction {tx_hash} reverted onchain: {reason}"
        )),
    }
}

async fn submit_native_invoke_with_typed_sdk_retry(
    _state: &AppState,
    executor: &StarknetExecutorConfig,
    settlement_call: &StarknetCall,
    proof: String,
    proof_facts: &[String],
) -> Result<String, String> {
    let proof = proof.trim();
    if proof.is_empty() {
        return Err("native proof cannot be empty".into());
    }
    let typed_proof_facts = proof_facts
        .iter()
        .map(|value| parse_felt(value, "proof_facts felt"))
        .collect::<Result<Vec<_>, _>>()?;
    let attempts = env_positive_config_or_default(
        NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS_ENV,
        DEFAULT_NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS,
    )?;
    let retry_interval_ms = env_positive_config_or_default(
        NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS_ENV,
        DEFAULT_NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS,
    )?;

    let mut last_error = None;
    for attempt in 1..=attempts {
        let (execution_context, nonce, resource_bounds, _) = match prepare_native_execution_fields(
            executor,
            settlement_call,
            NativeTransactionMode::SubmitOnchain,
        )
        .await
        {
            Ok(fields) => fields,
            Err(error)
                if native_onchain_submit_error_is_retryable(&error) && attempt < attempts =>
            {
                let sanitized_error = sanitize_native_prover_error_text(&error);
                eprintln!(
                    "native invoke preparation hit a transient provider error; retrying in {retry_interval_ms}ms ({attempt}/{attempts}): {sanitized_error}"
                );
                last_error = Some(sanitized_error);
                sleep(Duration::from_millis(retry_interval_ms)).await;
                continue;
            }
            Err(error) => return Err(sanitize_native_prover_error_text(&error)),
        };

        let rpc_url = Url::parse(&executor.rpc_url)
            .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?;
        let provider = JsonRpcClient::new(starknet_http_transport(rpc_url));
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(parse_felt(
            &executor.private_key,
            "ZYLITH_STARKNET_PRIVATE_KEY",
        )?));
        let account = SingleOwnerAccount::new(
            provider,
            signer,
            parse_felt(&executor.account_address, "ZYLITH_STARKNET_ACCOUNT_ADDRESS")?,
            parse_felt(&executor.chain_id, "ZYLITH_STARKNET_CHAIN_ID")?,
            ExecutionEncoding::New,
        );
        let execution = account
            .execute_v3(vec![starknet_call_to_call(settlement_call)?])
            .nonce(nonce)
            .l1_gas(resource_bounds.l1_gas)
            .l1_gas_price(execution_context.l1_gas_price)
            .l2_gas(resource_bounds.l2_gas)
            .l2_gas_price(execution_context.l2_gas_price)
            .l1_data_gas(resource_bounds.l1_data_gas)
            .l1_data_gas_price(execution_context.l1_data_gas_price)
            .tip(0)
            .proof(proof.to_owned())
            .proof_facts(typed_proof_facts.clone());
        let prepared_invoke = execution
            .prepared()
            .map_err(|_| "failed to prepare typed native proof-bearing invoke".to_string())?;
        let expected_tx_hash = prepared_invoke.transaction_hash(false);
        let invoke_request = match prepared_invoke.get_invoke_request(false, false).await {
            Ok(request) => request,
            Err(error) => {
                let formatted_error =
                    format!("failed to build typed native proof-bearing invoke: {error}");
                let sanitized_error = sanitize_native_prover_error_text(&formatted_error);
                if native_onchain_submit_error_is_retryable(&formatted_error) && attempt < attempts
                {
                    eprintln!(
                        "native invoke construction hit a transient provider error; retrying in {retry_interval_ms}ms ({attempt}/{attempts}): {sanitized_error}"
                    );
                    last_error = Some(sanitized_error);
                    sleep(Duration::from_millis(retry_interval_ms)).await;
                    continue;
                }
                return Err(sanitized_error);
            }
        };

        match account
            .provider()
            .add_invoke_transaction(&invoke_request)
            .await
        {
            Ok(result) => return Ok(format!("{:#x}", result.transaction_hash)),
            Err(error) => {
                let formatted_error = format!("native invoke rejected: {error}");
                let sanitized_error = sanitize_native_prover_error_text(&formatted_error);
                if native_invoke_error_is_retryable_after_submission(&formatted_error)
                    && let Some(_receipt) =
                        wait_for_receipt(account.provider(), expected_tx_hash).await
                {
                    return Ok(format!("{expected_tx_hash:#x}"));
                }

                if native_invoke_error_is_retryable_proof_facts_delay(&formatted_error)
                    && attempt < attempts
                {
                    let wait_ms =
                        proof_fact_age_wait_ms(&formatted_error, retry_interval_ms, attempt);
                    eprintln!(
                        "native proof facts are not old enough for onchain acceptance; retrying submission in {wait_ms}ms ({attempt}/{attempts})"
                    );
                    last_error = Some(sanitized_error);
                    sleep(Duration::from_millis(wait_ms)).await;
                    continue;
                }

                if native_invoke_error_is_retryable_nonce(&formatted_error) && attempt < attempts {
                    eprintln!(
                        "native invoke submission hit a stale nonce; rebuilding with a fresh nonce in {retry_interval_ms}ms ({attempt}/{attempts})"
                    );
                    last_error = Some(sanitized_error);
                    sleep(Duration::from_millis(retry_interval_ms)).await;
                    continue;
                }

                if native_invoke_error_is_retryable_after_submission(&formatted_error)
                    && attempt < attempts
                {
                    eprintln!(
                        "native invoke submission hit a transient provider error; retrying submission in {retry_interval_ms}ms ({attempt}/{attempts})"
                    );
                    last_error = Some(sanitized_error);
                    sleep(Duration::from_millis(retry_interval_ms)).await;
                    continue;
                }

                return Err(sanitized_error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "native invoke submission failed without response".into()))
}

fn native_invoke_error_is_retryable_nonce(error: &str) -> bool {
    let formatted = error.to_lowercase();
    formatted.contains("invalidtransactionnonce")
        || formatted.contains("invalid transaction nonce")
        || formatted.contains("invalid nonce")
        || formatted.contains("nonce")
            && formatted.contains("expected")
            && formatted.contains("got")
}

fn native_onchain_submit_error_is_retryable(error: &str) -> bool {
    native_invoke_error_is_retryable_after_submission(error)
}

fn native_proving_service_error_is_retryable(error: &str) -> bool {
    let formatted = error.to_lowercase();
    formatted.contains("service is busy")
        || formatted.contains("proving service is at capacity")
        || formatted.contains("at capacity")
}

fn native_invoke_error_is_retryable_proof_facts_delay(error: &str) -> bool {
    let formatted = error.to_lowercase();
    if !formatted.contains("invalid proof facts") {
        return false;
    }
    formatted.contains("proof block number") && formatted.contains("too recent")
        || formatted.contains("block hash mismatch") && formatted.contains("stored block hash: 0")
}

fn proof_fact_age_wait_ms(error: &str, base_interval_ms: u64, attempt: usize) -> u64 {
    if let Some(delta_blocks) = proof_fact_too_recent_delta_blocks(error) {
        return base_interval_ms
            .saturating_mul(delta_blocks.max(1))
            .clamp(1_000, 30_000);
    }
    adaptive_proof_fact_age_wait_ms(base_interval_ms, attempt)
}

fn proof_fact_too_recent_delta_blocks(error: &str) -> Option<u64> {
    let lower = error.to_lowercase();
    if !lower.contains("proof block number") || !lower.contains("maximum allowed block number") {
        return None;
    }
    let numbers = lower
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if numbers.len() < 2 {
        return None;
    }
    let proof_block = numbers[numbers.len() - 2];
    let max_allowed = numbers[numbers.len() - 1];
    proof_block
        .checked_sub(max_allowed)
        .map(|delta| delta.saturating_add(1))
}

fn adaptive_proof_fact_age_wait_ms(base_interval_ms: u64, attempt: usize) -> u64 {
    base_interval_ms
        .saturating_mul(attempt.max(1) as u64)
        .clamp(1_000, 30_000)
}

fn native_invoke_error_is_retryable_after_submission(error: &str) -> bool {
    let formatted = error.to_lowercase();
    formatted.contains("502 bad gateway")
        || formatted.contains("503 service unavailable")
        || formatted.contains("504 gateway timeout")
        || formatted.contains("http status server error")
        || formatted.contains("429 too many requests")
        || formatted.contains("timed out")
        || formatted.contains("connection reset")
        || formatted.contains("connection closed")
        || formatted.contains("receipt unavailable")
}

async fn refresh_submission_status(
    state: &AppState,
    mut submission: OnchainSubmissionRecord,
) -> Result<OnchainSubmissionRecord, String> {
    let executor = state
        .starknet_executor
        .clone()
        .ok_or_else(|| "starknet executor is not configured".to_string())?;
    let rpc_url = Url::parse(&executor.rpc_url)
        .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?;
    let provider = JsonRpcClient::new(starknet_http_transport(rpc_url));
    let tx_hash = parse_felt(&submission.transaction_hash, "transaction hash")?;

    populate_submission_receipt_status(&mut submission, wait_for_receipt(&provider, tx_hash).await);

    Ok(submission)
}

async fn wait_for_receipt(
    provider: &JsonRpcClient<HttpTransport>,
    tx_hash: Felt,
) -> Option<TransactionReceiptWithBlockInfo> {
    for attempt in 0..DEFAULT_RECEIPT_POLL_ATTEMPTS {
        match provider.get_transaction_receipt(tx_hash).await {
            Ok(receipt) => return Some(receipt),
            Err(_) if attempt + 1 < DEFAULT_RECEIPT_POLL_ATTEMPTS => {
                sleep(Duration::from_millis(DEFAULT_RECEIPT_POLL_INTERVAL_MS)).await;
            }
            Err(_) => return None,
        }
    }

    None
}

async fn wait_for_accepted_receipt(
    provider: &JsonRpcClient<HttpTransport>,
    tx_hash: Felt,
) -> Option<TransactionReceiptWithBlockInfo> {
    for attempt in 0..DEFAULT_RECEIPT_POLL_ATTEMPTS {
        match provider.get_transaction_receipt(tx_hash).await {
            Ok(receipt) => {
                if matches!(
                    receipt.receipt.finality_status(),
                    TransactionFinalityStatus::AcceptedOnL1
                        | TransactionFinalityStatus::AcceptedOnL2
                ) {
                    return Some(receipt);
                }
                if matches!(
                    receipt.receipt.execution_result(),
                    ExecutionResult::Reverted { .. }
                ) {
                    return Some(receipt);
                }
            }
            Err(_) if attempt + 1 == DEFAULT_RECEIPT_POLL_ATTEMPTS => return None,
            Err(_) => {}
        }
        sleep(Duration::from_millis(DEFAULT_RECEIPT_POLL_INTERVAL_MS)).await;
    }

    None
}

async fn fetch_block_timestamp_unix_ms(
    provider: &JsonRpcClient<HttpTransport>,
    block_number: u64,
) -> Result<u64, String> {
    let block = provider
        .get_block_with_tx_hashes(BlockId::Number(block_number))
        .await
        .map_err(|error| format!("failed to fetch settlement block timestamp: {error}"))?;
    let timestamp = match block {
        MaybePreConfirmedBlockWithTxHashes::Block(block) => block.timestamp,
        MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(block) => block.timestamp,
    };
    timestamp
        .checked_mul(1_000)
        .ok_or_else(|| "settlement block timestamp overflow".to_string())
}

fn populate_submission_receipt_status(
    submission: &mut OnchainSubmissionRecord,
    receipt: Option<TransactionReceiptWithBlockInfo>,
) {
    submission.receipt_checked_at_unix_ms = Some(now_unix_ms());

    let Some(receipt) = receipt else {
        return;
    };

    submission.finality_status = Some(format_finality_status(receipt.receipt.finality_status()));
    submission.execution_status = Some(format_execution_result(receipt.receipt.execution_result()));
    submission.revert_reason = receipt
        .receipt
        .execution_result()
        .revert_reason()
        .map(str::to_owned);
    submission.block_number = Some(receipt.block.block_number());
    submission.block_hash = receipt
        .block
        .block_hash()
        .map(|value| format!("{value:#x}"));

    if matches!(
        receipt.receipt.finality_status(),
        TransactionFinalityStatus::AcceptedOnL1 | TransactionFinalityStatus::AcceptedOnL2
    ) {
        submission.confirmed_at_unix_ms = Some(now_unix_ms());
    }
}

fn format_finality_status(status: &TransactionFinalityStatus) -> String {
    match status {
        TransactionFinalityStatus::PreConfirmed => "PRE_CONFIRMED".into(),
        TransactionFinalityStatus::AcceptedOnL2 => "ACCEPTED_ON_L2".into(),
        TransactionFinalityStatus::AcceptedOnL1 => "ACCEPTED_ON_L1".into(),
    }
}

fn format_execution_result(result: &ExecutionResult) -> String {
    match result {
        ExecutionResult::Succeeded => "SUCCEEDED".into(),
        ExecutionResult::Reverted { .. } => "REVERTED".into(),
    }
}

fn starknet_call_to_call(call: &StarknetCall) -> Result<Call, String> {
    Ok(Call {
        to: parse_felt(&call.contract_address, "contract address")?,
        selector: get_selector_from_name(&call.entrypoint)
            .map_err(|error| format!("missing selector for {}: {error}", call.entrypoint))?,
        calldata: call
            .calldata
            .iter()
            .map(|value| parse_felt(value, "calldata felt"))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_felt(value: &str, label: &str) -> Result<Felt, String> {
    Felt::from_hex(value).map_err(|error| format!("invalid {label} {value}: {error}"))
}

fn normalize_nonzero_felt(value: &str, label: &str) -> Result<String, String> {
    let felt = parse_felt(value.trim(), label)?;
    if felt == Felt::ZERO {
        return Err(format!("{label} cannot be zero"));
    }
    Ok(format!("{felt:#x}"))
}

fn ensure_prover_dirs(data_dir: &FsPath) -> Result<(), String> {
    for subdir in [
        PROOF_JOBS_DIR,
        SETTLEMENT_PLANS_DIR,
        SETTLEMENT_WITNESSES_DIR,
        NOTE_CONSOLIDATION_HISTORY_DIR,
        SETTLEMENT_OUTPUT_WITHDRAWAL_NULLIFIERS_DIR,
        PROOF_ARTIFACTS_DIR,
        ONCHAIN_SUBMISSIONS_DIR,
        PROOF_OUTPUTS_DIR,
        PUBLIC_INPUTS_DIR,
        PROVER_LOGS_DIR,
        PRIVATE_ORDER_PAYLOADS_DIR,
        PRIVATE_LIQUIDITY_POSITION_PAYLOADS_DIR,
    ] {
        let path = data_dir.join(subdir);
        fs::create_dir_all(&path).map_err(|error| {
            format!(
                "failed to create prover directory {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn load_json_records<T, F>(data_dir: &FsPath, subdir: &str, key_fn: F) -> BTreeMap<String, T>
where
    T: DeserializeOwned,
    F: Fn(&T) -> String,
{
    load_json_records_with_limits(
        data_dir,
        subdir,
        MAX_PERSISTED_RECORDS_PER_DIRECTORY,
        MAX_PERSISTED_RECORD_DIRECTORY_BYTES,
        key_fn,
    )
}

fn load_json_records_with_limits<T, F>(
    data_dir: &FsPath,
    subdir: &str,
    max_records: usize,
    max_total_bytes: usize,
    key_fn: F,
) -> BTreeMap<String, T>
where
    T: DeserializeOwned,
    F: Fn(&T) -> String,
{
    let directory = data_dir.join(subdir);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return BTreeMap::new(),
        Err(error) => {
            panic!(
                "failed to read prover record directory {}: {error}",
                directory.display()
            )
        }
    };

    let mut paths = Vec::new();
    let mut declared_total_bytes = 0_u64;

    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "failed to enumerate prover record directory {}: {error}",
                directory.display()
            )
        });
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if paths.len() >= max_records {
            panic!(
                "prover record directory {} exceeds {max_records} records",
                directory.display()
            );
        }
        let file_bytes = entry
            .metadata()
            .unwrap_or_else(|error| {
                panic!(
                    "failed to inspect prover record {}: {error}",
                    path.display()
                )
            })
            .len();
        declared_total_bytes = declared_total_bytes
            .checked_add(file_bytes)
            .unwrap_or_else(|| {
                panic!(
                    "prover record directory {} byte count overflowed",
                    directory.display()
                )
            });
        if declared_total_bytes > max_total_bytes as u64 {
            panic!(
                "prover record directory {} exceeds {max_total_bytes} bytes",
                directory.display()
            );
        }
        paths.push(path);
    }

    paths.sort();
    let mut records = BTreeMap::new();
    let mut actual_total_bytes = 0_usize;

    for path in paths {
        let body = read_utf8_file_limited(&path, MAX_PERSISTED_RECORD_BYTES, "prover record")
            .unwrap_or_else(|error| {
                panic!("failed to read prover record {}: {error}", path.display())
            });
        actual_total_bytes = actual_total_bytes
            .checked_add(body.len())
            .unwrap_or_else(|| {
                panic!(
                    "prover record directory {} byte count overflowed",
                    directory.display()
                )
            });
        if actual_total_bytes > max_total_bytes {
            panic!(
                "prover record directory {} exceeds {max_total_bytes} bytes",
                directory.display()
            );
        }
        let record = serde_json::from_str::<T>(&body).unwrap_or_else(|error| {
            panic!("failed to parse prover record {}: {error}", path.display())
        });
        let key = key_fn(&record);
        if records.insert(key.clone(), record).is_some() {
            panic!(
                "duplicate prover record key {key} in {}",
                directory.display()
            );
        }
    }

    records
}

fn persist_record<T: Serialize>(
    data_dir: &FsPath,
    subdir: &str,
    batch_id: &str,
    value: &T,
) -> Result<(), StatusCode> {
    let path = record_path(data_dir, subdir, batch_id);
    persist_json_file(&path, value)
}

fn persist_record_and_insert<T: Serialize>(
    data_dir: &FsPath,
    subdir: &str,
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
) -> Result<(), StatusCode> {
    persist_record(data_dir, subdir, &key, &value)?;
    records.insert(key, value);
    Ok(())
}

fn delete_record_if_exists(
    data_dir: &FsPath,
    subdir: &str,
    batch_id: &str,
) -> Result<(), StatusCode> {
    let path = record_path(data_dir, subdir, batch_id);
    if path.exists() {
        fs::remove_file(&path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(())
}

fn delete_record_and_remove<T>(
    data_dir: &FsPath,
    subdir: &str,
    records: &mut BTreeMap<String, T>,
    key: &str,
) -> Result<(), StatusCode> {
    delete_record_if_exists(data_dir, subdir, key)?;
    records.remove(key);
    Ok(())
}

fn persist_json_file<T: Serialize>(path: &FsPath, value: &T) -> Result<(), StatusCode> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let body = serde_json::to_vec_pretty(value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    atomic_write(path, &body)
}

fn atomic_write(path: &FsPath, contents: &[u8]) -> Result<(), StatusCode> {
    let file_name = path.file_name().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let temp_path = path.with_file_name(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    let mut temp_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if temp_file
        .write_all(contents)
        .and_then(|_| temp_file.sync_all())
        .is_err()
    {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    drop(temp_file);
    fs::rename(&temp_path, path).map_err(|_| {
        let _ = fs::remove_file(&temp_path);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(())
}

fn delete_execution_outputs_if_exist(data_dir: &FsPath, batch_id: &str) -> Result<(), StatusCode> {
    let paths = proof_execution_paths(data_dir, batch_id);
    for path in [
        paths.proof_path,
        paths.public_inputs_path,
        paths.native_execution_request_path,
        paths.stdout_path,
        paths.stderr_path,
    ] {
        if path.exists() {
            fs::remove_file(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }
    Ok(())
}

fn proof_execution_paths(data_dir: &FsPath, batch_id: &str) -> ProofExecutionPaths {
    ProofExecutionPaths {
        proof_path: record_path(data_dir, PROOF_OUTPUTS_DIR, batch_id),
        public_inputs_path: record_path(data_dir, PUBLIC_INPUTS_DIR, batch_id),
        native_execution_request_path: data_dir
            .join(PROOF_OUTPUTS_DIR)
            .join(format!("{}.native-request.json", storage_key(batch_id))),
        stdout_path: log_path(data_dir, batch_id, "stdout"),
        stderr_path: log_path(data_dir, batch_id, "stderr"),
    }
}

fn record_path(data_dir: &FsPath, subdir: &str, batch_id: &str) -> PathBuf {
    data_dir
        .join(subdir)
        .join(format!("{}.json", storage_key(batch_id)))
}

fn log_path(data_dir: &FsPath, batch_id: &str, suffix: &str) -> PathBuf {
    data_dir
        .join(PROVER_LOGS_DIR)
        .join(format!("{}.{}.log", storage_key(batch_id), suffix))
}

fn storage_key(batch_id: &str) -> String {
    batch_id
        .chars()
        .flat_map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                vec![character]
            } else {
                let encoded = format!("_{:x}_", character as u32);
                encoded.chars().collect::<Vec<_>>()
            }
        })
        .collect()
}

fn artifact_id_for(batch_id: &str, transcript_commitment: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zylith/proof-artifact");
    hasher.update(batch_id.as_bytes());
    hasher.update(transcript_commitment.as_bytes());
    hex::encode(hasher.finalize())
}

fn prover_backend_label() -> String {
    "starknet-transaction-prover".into()
}

fn status_to_error(status: StatusCode) -> String {
    format!("internal prover storage error: {status}")
}

fn load_required_auction_keys(
    path: &FsPath,
) -> Result<Vec<PrivateExecutionKeyPrivateConfig>, String> {
    if let Some(existing) = load_auction_keys(path)? {
        if existing.is_empty() {
            return Err(format!(
                "auction prover key file {} contains no keys",
                path.display()
            ));
        }
        return Ok(existing);
    }
    Err(format!(
        "auction prover key file {} is missing; provision auction prover keys before startup",
        path.display()
    ))
}

fn load_auction_keys(
    path: &FsPath,
) -> Result<Option<Vec<PrivateExecutionKeyPrivateConfig>>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = read_utf8_file_limited(path, MAX_AUCTION_KEY_FILE_BYTES, "auction key file")?;
    serde_json::from_str::<Vec<PrivateExecutionKeyPrivateConfig>>(&contents)
        .map(Some)
        .map_err(|error| {
            format!(
                "failed to parse auction key file {}: {error}",
                path.display()
            )
        })
}

fn sha256_file_hex(path: &FsPath) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn read_utf8_file_limited(path: &FsPath, max_bytes: usize, label: &str) -> Result<String, String> {
    let file = fs::File::open(path)
        .map_err(|error| format!("failed to read {label} {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {label} {}: {error}", path.display()))?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "{label} {} exceeds {max_bytes} bytes",
            path.display()
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| format!("{label} {} is not valid UTF-8: {error}", path.display()))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::{
        AppConfig, DEFAULT_PROTOCOL_FEE_RECIPIENT, DEFAULT_RELAY_FEE_RECIPIENT,
        DEV_PROTOCOL_FEE_OWNER_KEY, DEV_RELAY_FEE_WITHDRAW_KEY, DecryptedOrderRecord,
        FeeNoteRecipientConfig, HostedRelayOrderAttestationResponse,
        LiquidityPositionInsertionWitnessResponse, LiquidityPositionMarketContexts,
        MAX_PUBLIC_PROOF_JOB_BATCH_IDS, NATIVE_TX_PROVER_OHTTP_ENABLED_ENV,
        NOTE_ROOT_TRANSITION_CONSOLIDATION_KIND, NOTE_ROOT_TRANSITION_DEPOSIT_KIND,
        NativeAggregationPreparedMember, NativeBlockId, NativeExecutionRequestRecord,
        NativeProverRpcRequest, NativeTransactionMode, NoteConsolidationHistoryRecord,
        NoteConsolidationPrepareRequest, NoteMembershipSources, NoteRootTransitionRecord,
        OnchainSubmissionRecord, PROTOCOL_FEE_OWNER_KEY_ENV, RELAY_FEE_WITHDRAW_KEY_ENV,
        SettlementBuildContext, SettlementRoots, StarknetExecutorConfig,
        active_liquidity_position_book_for_root, aggregate_member_for_expected_roots,
        allowed_origins_from_env, artifact_id_for, build_app_with_config,
        build_batch_liquidity_report, build_native_proof_program_calldata,
        build_settlement_artifacts, compute_candidate_clearing_price,
        confirmed_settlement_witnesses_from_maps, cors_layer_for_origins, decode_bhttp_response,
        decode_bounded_json_response, delete_record_and_remove,
        deposit_activation_cache_refresh_start, derive_note_membership_witnesses,
        deterministic_settlement_submission_jitter_ms, encode_bhttp_json_post,
        fee_note_key_from_value, fee_note_key_from_value_for_mode, health,
        liquidity_position_fill_sources_for_batch, load_native_prover_ohttp_config,
        native_execution_context_block_id, native_fee_estimate_should_use_configured_bounds,
        native_invoke_error_is_retryable_after_submission, native_invoke_error_is_retryable_nonce,
        native_invoke_error_is_retryable_proof_facts_delay,
        note_root_transition_cache_refresh_start, onchain_submission_storage_key,
        parse_limited_batch_id_query, parse_liquidity_position_market_contexts,
        parse_ohttp_key_config_hex, persist_record_and_insert, proof_fact_age_wait_ms,
        public_proof_job_status, redact_native_execution_request, redact_native_prover_request,
        resolve_batch_registrar_private_key, same_starknet_address,
        sanitize_native_prover_error_text, select_root_history_witnesses_for_current_roots,
        service_http_client, settlement_output_withdrawal_consumed_input_key,
        settlement_output_withdrawal_revert_status,
        settlement_output_withdrawal_submit_error_status, should_refresh_onchain_submission,
        storage_key, try_enter_active_batch, validate_aggregate_root_chain,
        validate_batch_nullifier_freshness, validate_hosted_relay_order_attestation_response,
        validate_native_proof_program_config, validate_native_tx_prover_endpoint_config,
        validate_native_tx_prover_manifest_pin, withdrawal_submit_error,
    };
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::PathBuf,
        sync::{Arc, Mutex},
    };
    use tower::ServiceExt;
    use zylith_core::{
        AssetId, BatchId, BatchStatus, BatchSummary, ConsumedInput, DepositActivationRecord,
        LiquidityCurve, LiquidityCurvePoint, LiquidityPositionCommitment,
        LiquidityPositionRootTransition, LiquidityPositionTransitionKind, MatchedOrderWitness,
        Note, NoteCommitment, NoteMembershipKind, Nullifier, NullifierHistoryBatch,
        OrderCommitment, OrderIngressClientTelemetry, OrderIntent, OrderSide, OrderType,
        OutputNoteRecord, PairId, ProductConfig, ProofJobStatus, RelayMode, RenewalChildUse,
        SettlementCallArguments, SettlementSubmissionPlan, SettlementTranscript, SettlementWitness,
        SpendAuthorization, StarknetCall, TimeInForce, deposit_root_from_note,
        hash::{normalize_felt_hex, ordered_felt_list_commitment},
        note_recognition_public_key_from_raw_key_hex, nullifier_from_note_secret,
        nullifier_sparse_update_witnesses_for_consumed_inputs,
        renewal_sparse_witnesses_for_child_uses, root_only_settlement_commitments,
        settlement_nullifier_root_after_history, settlement_state_transition_root,
        withdraw_authority_from_raw_key_hex,
    };

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                unsafe {
                    std::env::set_var(self.key, previous);
                }
            } else {
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[tokio::test]
    async fn bounded_response_decoder_rejects_oversized_upstream_bodies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let address = listener.local_addr().expect("mock upstream address");
        let app = axum::Router::new().route("/", axum::routing::get(|| async { vec![b'x'; 65] }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock upstream");
        });
        let response = service_http_client()
            .get(format!("http://{address}/"))
            .send()
            .await
            .expect("mock upstream response");

        let error = decode_bounded_json_response::<serde_json::Value>(response, 64)
            .await
            .expect_err("oversized upstream response rejected");
        assert!(error.contains("response exceeds 64 bytes"));
        server.abort();
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn failed_record_persistence_does_not_publish_live_state() {
        let data_dir = std::env::temp_dir().join(format!(
            "zylith-prover-persist-failure-{}-{}",
            std::process::id(),
            super::now_unix_ms()
        ));
        fs::create_dir_all(&data_dir).expect("create test data dir");
        fs::write(data_dir.join("records"), b"blocks directory creation")
            .expect("create blocking file");
        let mut records = BTreeMap::<String, String>::new();

        let result = persist_record_and_insert(
            &data_dir,
            "records",
            &mut records,
            "record-1".into(),
            "private-value".into(),
        );

        assert_eq!(result, Err(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(!records.contains_key("record-1"));
        fs::remove_dir_all(data_dir).expect("remove test data dir");
    }

    #[test]
    fn failed_record_deletion_does_not_remove_live_state() {
        let data_dir = std::env::temp_dir().join(format!(
            "zylith-prover-delete-failure-{}-{}",
            std::process::id(),
            super::now_unix_ms()
        ));
        let record_path = data_dir.join("records").join("record-1.json");
        fs::create_dir_all(&record_path).expect("create blocking record directory");
        let mut records = BTreeMap::from([("record-1".into(), "private-value".to_string())]);

        let result = delete_record_and_remove(&data_dir, "records", &mut records, "record-1");

        assert_eq!(result, Err(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(
            records.get("record-1").map(String::as_str),
            Some("private-value")
        );
        fs::remove_dir_all(data_dir).expect("remove test data dir");
    }

    fn test_deposit_activation_record(activation_id: u64) -> DepositActivationRecord {
        DepositActivationRecord {
            activation_id,
            funding_commitment: format!("0x{:x}", activation_id + 1),
            deposit_root: format!("0x{:x}", activation_id + 2),
            encrypted_note_activation: format!("0x{:x}", activation_id + 3),
        }
    }

    #[test]
    fn deposit_activation_cache_revalidates_recent_tail() {
        let cached = (0..100)
            .map(test_deposit_activation_record)
            .collect::<Vec<_>>();
        assert_eq!(deposit_activation_cache_refresh_start(&cached, 120), 36);
    }

    #[test]
    fn deposit_activation_cache_refetches_all_after_large_rollback() {
        let cached = (0..200)
            .map(test_deposit_activation_record)
            .collect::<Vec<_>>();
        assert_eq!(deposit_activation_cache_refresh_start(&cached, 10), 0);
    }

    #[test]
    fn note_root_transition_cache_revalidates_recent_tail() {
        assert_eq!(note_root_transition_cache_refresh_start(100, 100), 36);
        assert_eq!(note_root_transition_cache_refresh_start(100, 120), 36);
    }

    #[test]
    fn note_root_transition_cache_refetches_all_after_large_rollback() {
        assert_eq!(note_root_transition_cache_refresh_start(200, 10), 0);
    }

    #[test]
    fn prover_product_config_requires_env_or_manifest_source() {
        let error = super::product_config_from_sources(None, None).expect_err("missing source");
        assert!(error.contains("ZYLITH_PRODUCT_PAIRS"));
    }

    #[test]
    fn prover_product_config_accepts_explicit_pair_source() {
        let config = super::product_config_from_sources(Some("STRK/USDC,ETH/USDC"), None)
            .expect("explicit product pairs");
        assert!(config.enabled_pair(&PairId("STRK/USDC".into())).is_some());
        assert!(config.enabled_pair(&PairId("ETH/USDC".into())).is_some());
        assert!(config.enabled_pair(&PairId("USDC/USDT".into())).is_none());
    }

    #[test]
    fn prover_startup_config_env_rejects_invalid_or_zero_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let invalid_env = "ZYLITH_TEST_PROVER_INVALID_CONFIG";
        let zero_env = "ZYLITH_TEST_PROVER_ZERO_CONFIG";
        unsafe {
            std::env::set_var(invalid_env, "not-a-number");
            std::env::set_var(zero_env, "0");
        }

        assert_eq!(
            super::env_config_or_default::<u64>(invalid_env, 10).unwrap_err(),
            format!("invalid {invalid_env}")
        );
        assert_eq!(
            super::env_positive_config_or_default::<u64>(zero_env, 10).unwrap_err(),
            format!("{zero_env} must be positive")
        );
        assert_eq!(
            super::env_optional_config::<u64>(invalid_env).unwrap_err(),
            format!("invalid {invalid_env}")
        );
        assert_eq!(
            super::env_positive_optional_config::<u64>(zero_env).unwrap_err(),
            format!("{zero_env} must be positive")
        );
        assert_eq!(
            super::env_optional_config::<u64>("ZYLITH_TEST_PROVER_MISSING_CONFIG")
                .expect("missing optional env"),
            None
        );
        unsafe {
            std::env::remove_var(invalid_env);
            std::env::remove_var(zero_env);
        }
    }

    #[test]
    fn default_private_payload_retention_is_short_operational_window() {
        assert_eq!(
            super::DEFAULT_PROVER_PRIVATE_PAYLOAD_RETENTION_MS,
            2 * 60 * 60 * 1_000
        );
    }

    #[test]
    fn rejects_private_or_loopback_native_transaction_prover() {
        let _guard = ENV_LOCK.lock().expect("env lock");

        let loopback =
            super::enforce_native_tx_prover_trust_boundary(Some("http://127.0.0.1:18090"));
        let private = super::enforce_native_tx_prover_trust_boundary(Some("http://10.1.2.3:18090"));

        assert!(
            loopback
                .expect_err("loopback proving must be rejected")
                .contains("self-hosted native proving endpoints are not allowed")
        );
        assert!(
            private
                .expect_err("private proving must be rejected")
                .contains("self-hosted native proving endpoints are not allowed")
        );
    }

    #[test]
    fn rate_limit_subject_uses_peer_ip_without_trusted_proxy_cidr() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var("ZYLITH_PROVER_TRUST_PROXY_HEADERS", "true");
            std::env::remove_var("ZYLITH_PROVER_TRUSTED_PROXY_CIDRS");
            std::env::remove_var("ZYLITH_TRUSTED_PROXY_CIDRS");
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
        let peer: std::net::SocketAddr = "198.51.100.7:9443".parse().expect("peer");

        assert_eq!(
            super::rate_limit_subject(&headers, Some(peer)),
            "198.51.100.7"
        );

        unsafe {
            std::env::remove_var("ZYLITH_PROVER_TRUST_PROXY_HEADERS");
        }
    }

    #[test]
    fn rate_limit_subject_uses_forwarded_ip_only_from_trusted_cidr() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var("ZYLITH_PROVER_TRUST_PROXY_HEADERS", "true");
            std::env::set_var("ZYLITH_PROVER_TRUSTED_PROXY_CIDRS", "198.51.100.0/24");
            std::env::remove_var("ZYLITH_TRUSTED_PROXY_CIDRS");
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
        let peer: std::net::SocketAddr = "198.51.100.7:9443".parse().expect("peer");

        assert_eq!(
            super::rate_limit_subject(&headers, Some(peer)),
            "203.0.113.9"
        );

        headers.insert("x-forwarded-for", "not-an-ip".parse().expect("header"));
        headers.insert("x-real-ip", "203.0.113.10".parse().expect("header"));
        assert_eq!(
            super::rate_limit_subject(&headers, Some(peer)),
            "203.0.113.10"
        );

        headers.insert("x-real-ip", "also-not-an-ip".parse().expect("header"));
        assert_eq!(
            super::rate_limit_subject(&headers, Some(peer)),
            "198.51.100.7"
        );

        unsafe {
            std::env::remove_var("ZYLITH_PROVER_TRUST_PROXY_HEADERS");
            std::env::remove_var("ZYLITH_PROVER_TRUSTED_PROXY_CIDRS");
        }
    }

    #[test]
    fn rate_limiter_recovers_from_poisoned_bucket_lock() {
        let limiter = super::RateLimiter::default();
        let poisoned = limiter.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.buckets.lock().expect("lock buckets");
            panic!("poison rate limiter lock");
        })
        .join();

        assert_eq!(
            super::enforce_rate_limit(
                &limiter,
                &axum::http::HeaderMap::new(),
                None,
                "poisoned-test",
                1,
            ),
            Ok(())
        );
        assert_eq!(
            super::enforce_rate_limit(
                &limiter,
                &axum::http::HeaderMap::new(),
                None,
                "poisoned-test",
                1,
            ),
            Err(StatusCode::TOO_MANY_REQUESTS)
        );
    }

    #[tokio::test]
    async fn cors_preflight_does_not_allow_disallowed_origin() {
        let router = {
            let _guard = ENV_LOCK.lock().expect("env lock");
            unsafe {
                std::env::set_var(
                    "ZYLITH_TEST_PROVER_ALLOWED_ORIGINS",
                    "https://app.zylith.fi",
                );
            }
            let router = axum::Router::new()
                .route("/probe", axum::routing::get(|| async { "ok" }))
                .layer(cors_layer_for_origins(
                    allowed_origins_from_env("ZYLITH_TEST_PROVER_ALLOWED_ORIGINS")
                        .expect("test CORS origins"),
                ));
            unsafe {
                std::env::remove_var("ZYLITH_TEST_PROVER_ALLOWED_ORIGINS");
            }
            router
        };

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/probe")
                    .header("origin", "https://evil.example")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
    }

    #[test]
    fn prover_cors_origins_reject_wildcards() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var("ZYLITH_TEST_PROVER_ALLOWED_ORIGINS", "https://*.zylith.fi");
        }
        let result = std::panic::catch_unwind(|| {
            allowed_origins_from_env("ZYLITH_TEST_PROVER_ALLOWED_ORIGINS")
        });
        unsafe {
            std::env::remove_var("ZYLITH_TEST_PROVER_ALLOWED_ORIGINS");
        }
        assert!(result.is_err());
    }

    fn test_fee_note_recipient(
        owner_key_byte: &str,
        withdraw_authority: &str,
    ) -> FeeNoteRecipientConfig {
        FeeNoteRecipientConfig {
            owner_public_key: note_recognition_public_key_from_raw_key_hex(
                &owner_key_byte.repeat(32),
            )
            .expect("test fee owner key"),
            spend_authority: "0x789".into(),
            withdraw_authority: withdraw_authority.into(),
        }
    }

    fn test_app_config(internal_api_token: Option<&str>) -> AppConfig {
        AppConfig {
            coordinator_url: "http://127.0.0.1:1".into(),
            indexer_url: "http://127.0.0.1:2".into(),
            hosted_liquidity_relay_url: None,
            hosted_liquidity_relay_token: None,
            chain_id: "0x534e5f5345504f4c4941".into(),
            auction_verifier_address: "0x123".into(),
            note_root_history_verifier_address: "0x123".into(),
            shielded_asset_adapter_address: "0x456".into(),
            native_proof_program_address: "0x789".into(),
            native_proof_entrypoint: "compile_settlement_proof".into(),
            native_proof_aggregate_entrypoint: "compile_settlement_aggregate_proof".into(),
            native_tx_prover_url: "https://starknet-prover.example".into(),
            native_tx_prover_ohttp: None,
            scarb_bin: "scarb".into(),
            stwo_manifest_path: PathBuf::from("Scarb.toml"),
            stwo_package_name: "stwo_statement".into(),
            data_dir: std::env::temp_dir()
                .join(format!("zylith-prover-test-{}", std::process::id())),
            starknet_executor: None,
            batch_registrar: None,
            product_config: ProductConfig::from_enabled_pair_ids_csv("STRK/USDC")
                .expect("product config"),
            liquidity_position_market_contexts: LiquidityPositionMarketContexts::default(),
            liquidity_position_market_contexts_path: None,
            auction_private_keys: Vec::new(),
            internal_api_token: internal_api_token.map(str::to_owned),
            initial_note_root: "0x0".into(),
            order_ingress_id: "test-ingress".into(),
            order_ingress_receipt_secret: Some("test-receipt-secret".into()),
            order_ingress_receipt_secrets: vec!["test-receipt-secret".into()],
            heartbeat_cover_secret: "test-heartbeat-cover".into(),
            max_provable_batch_orders: 64,
            max_order_amount: 1_000_000,
            max_liquidity_curve_base_amount: 1_000_000,
            max_liquidity_curve_quote_notional: 1_000_000,
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT.into(),
            protocol_fee_note_recipient: test_fee_note_recipient("ab", "0xaaa"),
            relay_fee_note_recipient: test_fee_note_recipient("cd", "0xbbb"),
            settlement_submission_jitter_ms: 0,
            private_payload_retention_ms: 0,
            max_stored_private_payloads: 32,
            private_ingress_rate_limit_per_minute: 60,
            public_rate_limit_per_minute: 60,
            emergency_paused: false,
            prover_worker_enabled: false,
            prover_worker_tick_ms: 1_000,
            prover_worker_max_batches_per_tick: 1,
            prover_worker_submit_onchain: false,
            max_body_bytes: 1024 * 1024,
            native_prover_attempts: 1,
            native_prover_retry_interval_ms: 1,
            native_prover_request_timeout_seconds: 1,
            allowed_origins: vec![super::HeaderValue::from_static("https://app.zylith.test")],
        }
    }

    fn matching_relay_attestation_response(
        order: &OrderIntent,
        order_commitment: &OrderCommitment,
    ) -> HostedRelayOrderAttestationResponse {
        HostedRelayOrderAttestationResponse {
            package_id: "pkg-1".into(),
            package_commitment: "pkg-commitment-1".into(),
            order_commitment: order_commitment.0.clone(),
            pair: order.pair_id.0.clone(),
            batch_id: order.batch_id.0.clone(),
            epoch_id: order.expiry_epoch,
            relay_mode: RelayMode::ZylithRelay,
        }
    }

    #[test]
    fn hosted_relay_attestation_response_accepts_matching_order() {
        let record = test_record(
            701,
            OrderSide::Buy,
            10,
            100,
            1,
            TimeInForce::CurrentBatchOnly,
            1_000,
        );
        let mut order = record.order.clone();
        order.relay_mode = RelayMode::ZylithRelay;
        let response = matching_relay_attestation_response(&order, &record.order_commitment);

        validate_hosted_relay_order_attestation_response(
            &response,
            "pkg-1",
            "pkg-commitment-1",
            &order,
            &record.order_commitment,
        )
        .expect("matching relay attestation accepted");
    }

    #[test]
    fn hosted_relay_attestation_response_rejects_mismatched_fields() {
        let record = test_record(
            702,
            OrderSide::Buy,
            10,
            100,
            1,
            TimeInForce::CurrentBatchOnly,
            1_000,
        );
        let mut order = record.order.clone();
        order.relay_mode = RelayMode::ZylithRelay;
        let base = matching_relay_attestation_response(&order, &record.order_commitment);

        let mut wrong_package_id = base.clone();
        wrong_package_id.package_id = "pkg-2".into();
        assert_eq!(
            validate_hosted_relay_order_attestation_response(
                &wrong_package_id,
                "pkg-1",
                "pkg-commitment-1",
                &order,
                &record.order_commitment,
            )
            .expect_err("wrong package id rejected"),
            StatusCode::BAD_REQUEST
        );

        let mut wrong_package_commitment = base.clone();
        wrong_package_commitment.package_commitment = "pkg-commitment-2".into();
        assert_eq!(
            validate_hosted_relay_order_attestation_response(
                &wrong_package_commitment,
                "pkg-1",
                "pkg-commitment-1",
                &order,
                &record.order_commitment,
            )
            .expect_err("wrong package commitment rejected"),
            StatusCode::BAD_REQUEST
        );

        let mut wrong_order_commitment = base.clone();
        wrong_order_commitment.order_commitment = "0xdead".into();
        assert_eq!(
            validate_hosted_relay_order_attestation_response(
                &wrong_order_commitment,
                "pkg-1",
                "pkg-commitment-1",
                &order,
                &record.order_commitment,
            )
            .expect_err("wrong order commitment rejected"),
            StatusCode::BAD_REQUEST
        );

        let mut wrong_pair = base.clone();
        wrong_pair.pair = "ETH/USDC".into();
        assert_eq!(
            validate_hosted_relay_order_attestation_response(
                &wrong_pair,
                "pkg-1",
                "pkg-commitment-1",
                &order,
                &record.order_commitment,
            )
            .expect_err("wrong pair rejected"),
            StatusCode::BAD_REQUEST
        );

        let mut wrong_batch = base.clone();
        wrong_batch.batch_id = "batch-strk-usdc-2".into();
        assert_eq!(
            validate_hosted_relay_order_attestation_response(
                &wrong_batch,
                "pkg-1",
                "pkg-commitment-1",
                &order,
                &record.order_commitment,
            )
            .expect_err("wrong batch rejected"),
            StatusCode::BAD_REQUEST
        );

        let mut wrong_epoch = base.clone();
        wrong_epoch.epoch_id += 1;
        assert_eq!(
            validate_hosted_relay_order_attestation_response(
                &wrong_epoch,
                "pkg-1",
                "pkg-commitment-1",
                &order,
                &record.order_commitment,
            )
            .expect_err("wrong epoch rejected"),
            StatusCode::BAD_REQUEST
        );

        let mut wrong_relay_mode = base;
        wrong_relay_mode.relay_mode = RelayMode::SelfRelay;
        assert_eq!(
            validate_hosted_relay_order_attestation_response(
                &wrong_relay_mode,
                "pkg-1",
                "pkg-commitment-1",
                &order,
                &record.order_commitment,
            )
            .expect_err("wrong relay mode rejected"),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn proof_worker_does_not_starve_new_batches_when_onchain_submit_is_disabled() {
        assert!(super::proof_worker_status_is_processable(
            "witness-prepared",
            false
        ));
        assert!(!super::proof_worker_status_is_processable(
            "proof-generated",
            false
        ));
        assert!(super::proof_worker_status_is_processable(
            "proof-generated",
            true
        ));
        assert!(!super::proof_worker_status_is_processable(
            "confirmed-onchain",
            false
        ));
        assert!(!super::proof_worker_status_is_processable("no-fill", true));
    }

    #[test]
    fn proof_worker_retries_stale_proving_jobs_after_restart() {
        let now = 1_000_000;
        let mut status = ProofJobStatus {
            batch_id: BatchId("batch-strk-eth-stale".into()),
            state: "proving".into(),
            transcript_commitment: "0x1".into(),
            matched_order_count: 2,
            settlement_plan_available: false,
            witness_available: true,
            proof_artifact_available: false,
            onchain_submission_available: false,
            proof_artifact_id: None,
            onchain_submission_id: None,
            prover_backend: "native".into(),
            last_error: None,
            created_at_unix_ms: now - super::PROOF_WORKER_STALE_PROVING_RETRY_MS,
            updated_at_unix_ms: now - super::PROOF_WORKER_STALE_PROVING_RETRY_MS,
            settlement_contract_address: "0x2".into(),
            settlement_entrypoint: "submit_settlement_with_proof_facts".into(),
            settlement_calldata_len: 0,
        };

        assert!(super::proof_worker_status_is_stale_proving(&status, now));
        status.updated_at_unix_ms = now - super::PROOF_WORKER_STALE_PROVING_RETRY_MS + 1;
        assert!(!super::proof_worker_status_is_stale_proving(&status, now));
        status.state = "proof-generated".into();
        status.updated_at_unix_ms = now - super::PROOF_WORKER_STALE_PROVING_RETRY_MS;
        assert!(!super::proof_worker_status_is_stale_proving(&status, now));
    }

    #[test]
    fn proof_worker_retries_stale_submitting_jobs_without_submission_record() {
        let now = 1_000_000;
        let mut status = ProofJobStatus {
            batch_id: BatchId("batch-strk-eth-stale-submit".into()),
            state: "submitting-onchain".into(),
            transcript_commitment: "0x1".into(),
            matched_order_count: 2,
            settlement_plan_available: true,
            witness_available: true,
            proof_artifact_available: true,
            onchain_submission_available: false,
            proof_artifact_id: Some("artifact-1".into()),
            onchain_submission_id: None,
            prover_backend: "native".into(),
            last_error: None,
            created_at_unix_ms: now - super::PROOF_WORKER_STALE_SUBMITTING_RETRY_MS,
            updated_at_unix_ms: now - super::PROOF_WORKER_STALE_SUBMITTING_RETRY_MS,
            settlement_contract_address: "0x2".into(),
            settlement_entrypoint: "submit_settlement_with_proof_facts".into(),
            settlement_calldata_len: 25,
        };

        assert!(super::proof_worker_status_is_stale_submitting(
            &status, now, true
        ));
        status.updated_at_unix_ms = now - super::PROOF_WORKER_STALE_SUBMITTING_RETRY_MS + 1;
        assert!(!super::proof_worker_status_is_stale_submitting(
            &status, now, true
        ));
        status.updated_at_unix_ms = now - super::PROOF_WORKER_STALE_SUBMITTING_RETRY_MS;
        status.onchain_submission_available = true;
        assert!(!super::proof_worker_status_is_stale_submitting(
            &status, now, true
        ));
        status.onchain_submission_available = false;
        assert!(!super::proof_worker_status_is_stale_submitting(
            &status, now, false
        ));
        status.state = "submitted-onchain".into();
        assert!(!super::proof_worker_status_is_stale_submitting(
            &status, now, true
        ));
    }

    #[test]
    fn proof_worker_retries_persisted_failed_jobs_after_cooldown() {
        let now = 1_000_000;
        let mut status = ProofJobStatus {
            batch_id: BatchId("batch-strk-eth-failed".into()),
            state: "proving-failed".into(),
            transcript_commitment: "0x1".into(),
            matched_order_count: 2,
            settlement_plan_available: false,
            witness_available: true,
            proof_artifact_available: false,
            onchain_submission_available: false,
            proof_artifact_id: None,
            onchain_submission_id: None,
            prover_backend: "native".into(),
            last_error: Some("transient native prover failure".into()),
            created_at_unix_ms: now - super::PROOF_WORKER_FAILED_RETRY_MS,
            updated_at_unix_ms: now - super::PROOF_WORKER_FAILED_RETRY_MS,
            settlement_contract_address: "0x2".into(),
            settlement_entrypoint: "submit_settlement_with_proof_facts".into(),
            settlement_calldata_len: 0,
        };

        assert!(super::proof_worker_status_is_retryable_failure(
            &status, now, true
        ));
        status.updated_at_unix_ms = now - super::PROOF_WORKER_FAILED_RETRY_MS + 1;
        assert!(!super::proof_worker_status_is_retryable_failure(
            &status, now, true
        ));
        status.state = "onchain-submit-failed".into();
        status.last_error = Some("native transaction prover error -32005: Service is busy".into());
        status.updated_at_unix_ms = now - super::PROOF_WORKER_FAILED_RETRY_MS;
        assert!(super::proof_worker_status_is_retryable_failure(
            &status, now, true
        ));
        assert!(!super::proof_worker_status_is_retryable_failure(
            &status, now, false
        ));
        status.last_error = Some(
            "nullifier proof transaction <felt> reverted onchain: NULLIFIER_ROOT_STALE".into(),
        );
        assert!(!super::proof_worker_status_is_retryable_failure(
            &status, now, true
        ));
        status.state = "onchain-reverted".into();
        assert!(!super::proof_worker_status_is_retryable_failure(
            &status, now, true
        ));
    }

    #[test]
    fn proof_worker_failure_backoff_skips_stale_failed_batches_temporarily() {
        assert_eq!(
            super::proof_worker_failure_backoff_ms(1),
            super::PROOF_WORKER_FAILURE_BACKOFF_BASE_MS
        );
        assert_eq!(
            super::proof_worker_failure_backoff_ms(u32::MAX),
            super::PROOF_WORKER_FAILURE_BACKOFF_MAX_MS
        );
        let failure = super::ProofWorkerBatchFailure {
            attempts: 2,
            next_retry_unix_ms: 10_000,
        };

        assert!(super::proof_worker_failure_blocks_retry(&failure, 9_999));
        assert!(!super::proof_worker_failure_blocks_retry(&failure, 10_000));
    }

    #[test]
    fn proof_worker_prioritizes_recent_batches_before_historical_failures() {
        let mut batches = vec![
            BatchSummary {
                batch_id: BatchId("batch-strk-eth-10".into()),
                pair_id: PairId("STRK/ETH".into()),
                epoch_id: 10,
                close_time_unix_ms: 1_000,
                status: BatchStatus::Closed,
                order_count: 1,
                order_commitment_root: "0x1".into(),
                encrypted_order_set_commitment: "0x2".into(),
            },
            BatchSummary {
                batch_id: BatchId("batch-strk-eth-12".into()),
                pair_id: PairId("STRK/ETH".into()),
                epoch_id: 12,
                close_time_unix_ms: 1_200,
                status: BatchStatus::Closed,
                order_count: 1,
                order_commitment_root: "0x1".into(),
                encrypted_order_set_commitment: "0x2".into(),
            },
            BatchSummary {
                batch_id: BatchId("batch-strk-eth-11".into()),
                pair_id: PairId("STRK/ETH".into()),
                epoch_id: 11,
                close_time_unix_ms: 1_200,
                status: BatchStatus::Closed,
                order_count: 1,
                order_commitment_root: "0x1".into(),
                encrypted_order_set_commitment: "0x2".into(),
            },
        ];

        super::sort_proof_worker_batches_for_selection(&mut batches);

        assert_eq!(
            batches
                .into_iter()
                .map(|batch| batch.batch_id.0)
                .collect::<Vec<_>>(),
            vec![
                "batch-strk-eth-12",
                "batch-strk-eth-11",
                "batch-strk-eth-10"
            ]
        );
    }

    #[test]
    fn proof_worker_uses_internal_nonempty_batch_queue() {
        assert_eq!(
            super::proof_worker_batch_list_url("https://api.zylith.fi/coordinator/"),
            "https://api.zylith.fi/coordinator/api/internal/batches/proof-work?status=Closed,Clearing&limit=4096"
        );
    }

    #[test]
    fn storage_key_sanitizes_non_alphanumeric_batch_ids() {
        assert_eq!(
            storage_key("batch/strk usdc:1"),
            "batch_2f_strk_20_usdc_3a_1"
        );
        assert_eq!(storage_key("batch-strk-usdc-1"), "batch-strk-usdc-1");
        assert_eq!(storage_key("_2f_"), "_5f_2f_5f_");
        assert_ne!(storage_key("/"), storage_key("_2f_"));
    }

    #[test]
    fn production_prover_data_dir_is_scoped_by_verifier() {
        let scoped = super::scoped_prover_data_dir(
            PathBuf::from("/opt/zylith/state/prover"),
            "0x043187860068c987357c912682cbea15f6d299a8633c238bc79c110b17480522",
            true,
        )
        .expect("scoped data dir");
        assert_eq!(
            scoped,
            PathBuf::from(
                "/opt/zylith/state/prover/deployments/0x43187860068c987357c912682cbea15f6d299a8633c238bc79c110b17480522"
            )
        );
        let already_scoped = super::scoped_prover_data_dir(
            scoped.clone(),
            "0x43187860068c987357c912682cbea15f6d299a8633c238bc79c110b17480522",
            true,
        )
        .expect("already scoped data dir");
        assert_eq!(already_scoped, scoped);
        let dev = super::scoped_prover_data_dir(PathBuf::from("prover/data.dev"), "0x123", false)
            .expect("dev data dir");
        assert_eq!(dev, PathBuf::from("prover/data.dev"));
    }

    #[tokio::test]
    async fn public_health_exposes_only_minimal_status() {
        let body = health().await.0;

        assert_eq!(body["service"], "zylith-prover");
        assert_eq!(body["status"], "ok");
        assert!(body.get("auction_verifier_address").is_none());
        assert!(body.get("native_tx_prover_enabled").is_none());
        assert!(body.get("stored_private_order_payloads_bucket").is_none());
        assert!(body.get("proof_jobs_by_state").is_none());
        assert!(body.get("protocol_fee_recipient").is_none());
    }

    #[tokio::test]
    async fn internal_routes_require_control_plane_bearer_token() {
        let token = "prover-test-internal-token";
        let app = build_app_with_config(test_app_config(Some(token))).expect("app");
        let routes = [
            (Method::GET, "/api/internal/health"),
            (Method::GET, "/api/internal/metrics"),
            (
                Method::POST,
                "/api/internal/batches/batch-strk-usdc-1/prepare",
            ),
            (Method::GET, "/api/internal/proof-jobs/batch-strk-usdc-1"),
            (Method::POST, "/api/internal/proof-jobs/batch-strk-usdc-1"),
            (
                Method::POST,
                "/api/internal/proof-jobs/batch-strk-usdc-1/prove",
            ),
            (
                Method::POST,
                "/api/internal/proof-jobs/batch-strk-usdc-1/submit",
            ),
            (
                Method::GET,
                "/api/internal/settlement-plans/batch-strk-usdc-1",
            ),
            (
                Method::GET,
                "/api/internal/settlement-witnesses/batch-strk-usdc-1",
            ),
            (
                Method::GET,
                "/api/internal/proof-artifacts/batch-strk-usdc-1",
            ),
            (
                Method::GET,
                "/api/internal/proof-aggregation-manifests/epochs/0/8",
            ),
            (
                Method::POST,
                "/api/internal/proof-aggregation-manifests/epochs/0/8",
            ),
            (
                Method::POST,
                "/api/internal/proof-aggregation-manifests/epochs/0/8/submit",
            ),
            (
                Method::GET,
                "/api/internal/onchain-submissions/batch-strk-usdc-1",
            ),
            (
                Method::POST,
                "/api/internal/onchain-submissions/batch-strk-usdc-1/refresh",
            ),
        ];

        for (method, uri) in routes {
            let missing = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .method(method.clone())
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(missing.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");

            let wrong = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .method(method)
                        .header("authorization", "Bearer wrong-token")
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[test]
    fn private_ingress_metrics_render_only_aggregate_buckets() {
        let metrics = super::IngressTelemetryMetrics::default();
        metrics.record(
            "accepted",
            42,
            Some(&OrderIngressClientTelemetry {
                version: 1,
                client_build_ms: Some(25),
                private_submission_delay_ms: Some(7_000),
                client_elapsed_before_private_ingress_ms: Some(7_025),
                private_ingress_roundtrip_ms: Some(120),
                client_elapsed_before_coordinator_ms: Some(7_145),
                batch_time_remaining_before_private_ingress_ms: Some(25_000),
                batch_time_remaining_before_coordinator_ms: Some(24_850),
                submission_safety_buffer_ms: Some(15_000),
            }),
        );
        let text = metrics.render_prometheus("zylith_prover");

        assert!(text.contains(
            "zylith_prover_private_order_ingress_requests_total{outcome=\"accepted\"} 1"
        ));
        assert!(text.contains("zylith_prover_private_order_ingress_processing_ms_count 1"));
        assert!(text.contains(
            "zylith_prover_private_order_ingress_submission_delay_ms_bucket{le=\"10000\"} 1"
        ));
        assert!(text.contains(
            "zylith_prover_private_order_ingress_batch_time_remaining_before_private_ingress_ms_bucket{le=\"30000\"} 1"
        ));
        assert!(!text.contains("order_commitment"));
        assert!(!text.contains("note"));
    }

    #[test]
    fn note_consolidation_prepare_requires_dummy_recovery_commitments_field() {
        let request = serde_json::json!({
            "consolidation_id": "consolidation-1",
            "input_notes": [],
            "output_notes": [],
            "output_note_preimages": [],
            "output_recovery_records": [],
            "output_ciphertext_bundle_ref": "0xbundle"
        });

        assert!(serde_json::from_value::<NoteConsolidationPrepareRequest>(request).is_err());
    }

    #[test]
    fn proof_lifecycle_metrics_render_only_aggregate_buckets() {
        let metrics = super::LifecycleTelemetryMetrics::default();
        metrics.record("settlement_proof_generation", "success", 42_000);
        metrics.record("withdrawal_onchain_submit", "error", 1_500);

        let text = metrics.render_prometheus("zylith_prover");

        assert!(text.contains(
            "zylith_prover_proof_lifecycle_operations_total{operation=\"settlement_proof_generation\",outcome=\"success\"} 1"
        ));
        assert!(text.contains(
            "zylith_prover_proof_lifecycle_operations_total{operation=\"withdrawal_onchain_submit\",outcome=\"error\"} 1"
        ));
        assert!(text.contains(
            "zylith_prover_proof_lifecycle_settlement_proof_generation_latency_ms_count 1"
        ));
        assert!(
            text.contains(
                "zylith_prover_proof_lifecycle_withdrawal_onchain_submit_latency_ms_bucket{le=\"2500\"} 1"
            )
        );
        assert!(!text.contains("order_commitment"));
        assert!(!text.contains("note_preimage"));
    }

    #[tokio::test]
    async fn private_order_ingress_records_rejected_route_telemetry() {
        let token = "prover-test-internal-token";
        let app = build_app_with_config(test_app_config(Some(token))).expect("app");
        let request = serde_json::json!({
            "order_submission": {
                "order_bundle": {
                    "order_commitment": "0x1234",
                    "cancellation_auth_tag": "cancel-tag",
                    "pair_id": "STRK/USDC",
                    "batch_id": "batch-strk-usdc-1",
                    "epoch_id": 1,
                    "transport_envelope": null,
                    "ingress_receipt": null,
                    "shares": []
                }
            },
            "ingress_telemetry": {
                "version": 1,
                "client_build_ms": 20,
                "private_submission_delay_ms": 7000,
                "client_elapsed_before_private_ingress_ms": 7020,
                "batch_time_remaining_before_private_ingress_ms": 25000,
                "submission_safety_buffer_ms": 15000
            }
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/private/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("serialize ingress request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut stale_request = request.clone();
        stale_request["order_submission"]["order_bundle"]["unsupported_payload_ref"] =
            serde_json::json!("unexpected-private-payload");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/private/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&stale_request)
                            .expect("serialize stale ingress request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/internal/metrics")
                    .method(Method::GET)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(text.contains(
            "zylith_prover_private_order_ingress_requests_total{outcome=\"bad_request\"} 1"
        ));
        assert!(text.contains(
            "zylith_prover_private_order_ingress_submission_delay_ms_bucket{le=\"10000\"} 1"
        ));
        assert!(text.contains(
            "zylith_prover_private_order_ingress_batch_time_remaining_before_private_ingress_ms_bucket{le=\"30000\"} 1"
        ));
        assert!(!text.contains("0x1234"));
    }

    #[test]
    fn fee_note_keys_must_be_explicit() {
        assert!(fee_note_key_from_value("ZYLITH_TEST_FEE_KEY", None).is_err());
        assert!(fee_note_key_from_value("ZYLITH_TEST_FEE_KEY", Some("".into())).is_err());
        assert_eq!(
            fee_note_key_from_value("ZYLITH_TEST_FEE_KEY", Some("cdcd".into())).unwrap(),
            "cdcd"
        );
    }

    #[test]
    fn production_fee_note_keys_reject_development_defaults() {
        assert!(
            fee_note_key_from_value_for_mode(
                PROTOCOL_FEE_OWNER_KEY_ENV,
                Some(DEV_PROTOCOL_FEE_OWNER_KEY.into()),
                true,
            )
            .is_err()
        );
        assert!(
            fee_note_key_from_value_for_mode(
                RELAY_FEE_WITHDRAW_KEY_ENV,
                Some(format!("0x{DEV_RELAY_FEE_WITHDRAW_KEY}")),
                true,
            )
            .is_err()
        );
        assert_eq!(
            fee_note_key_from_value_for_mode(
                PROTOCOL_FEE_OWNER_KEY_ENV,
                Some("cdcd".into()),
                true,
            )
            .unwrap(),
            "cdcd"
        );
    }

    #[test]
    fn production_native_proof_program_must_be_pinned_separately() {
        assert!(validate_native_proof_program_config("", "0x123", true).is_err());
        assert!(validate_native_proof_program_config("0x0", "0x123", true).is_err());
        assert!(validate_native_proof_program_config("0x123", "0x0123", true).is_err());
        assert!(validate_native_proof_program_config("0x456", "0x123", true).is_ok());
        assert!(validate_native_proof_program_config("", "0x123", false).is_ok());
    }

    #[test]
    fn requires_native_tx_prover_endpoint() {
        assert!(validate_native_tx_prover_endpoint_config(None).is_err());
        assert!(validate_native_tx_prover_endpoint_config(Some("")).is_err());
        assert!(validate_native_tx_prover_endpoint_config(Some("not a url")).is_err());
        assert!(validate_native_tx_prover_endpoint_config(Some("file:///tmp/prover")).is_err());
        assert!(validate_native_tx_prover_endpoint_config(Some("http://127.0.0.1:18090")).is_err());
        assert!(
            validate_native_tx_prover_endpoint_config(Some("https://starknet-prover.example"))
                .is_ok()
        );
    }

    #[test]
    fn native_tx_prover_ohttp_can_be_disabled_only_for_https() {
        let _guard = EnvVarGuard::set(NATIVE_TX_PROVER_OHTTP_ENABLED_ENV, "0");

        assert!(load_native_prover_ohttp_config("https://starknet-prover.example").is_ok());
        assert!(
            load_native_prover_ohttp_config("https://starknet-prover.example")
                .expect("https direct prover is allowed")
                .is_none()
        );
        assert!(load_native_prover_ohttp_config("http://starknet-prover.example").is_err());
        assert!(load_native_prover_ohttp_config("not a url").is_err());
    }

    #[test]
    fn native_tx_prover_must_match_deployment_manifest_pin() {
        let mut manifest: zylith_core::DeploymentManifest =
            serde_json::from_str(include_str!("../../core/fixtures/deployment.example.json"))
                .expect("checked-in deployment manifest parses");
        manifest.proof.native_tx_prover_url =
            "https://api.zylith.fi/starknet-privacy-prover-sepolia".into();

        assert!(
            validate_native_tx_prover_manifest_pin(
                Some(&manifest),
                "https://api.zylith.fi:443/starknet-privacy-prover-sepolia/",
            )
            .is_ok()
        );
        assert!(
            validate_native_tx_prover_manifest_pin(
                Some(&manifest),
                "https://different-prover.example/starknet-privacy-prover-sepolia",
            )
            .expect_err("manifest drift must fail closed")
            .contains("proof.native_tx_prover_url")
        );
    }

    #[test]
    fn explicit_deployment_manifest_must_parse() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let path = std::env::temp_dir().join(format!(
            "zylith-prover-invalid-manifest-{}.json",
            super::now_unix_ms()
        ));
        fs::write(&path, "{ not-json").expect("write invalid manifest");
        unsafe {
            std::env::set_var("ZYLITH_DEPLOYMENT_MANIFEST", &path);
        }

        let error = super::load_deployment_manifest().expect_err("invalid explicit manifest");
        assert!(error.contains("failed to parse deployment manifest"));

        unsafe {
            std::env::remove_var("ZYLITH_DEPLOYMENT_MANIFEST");
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn deployment_manifest_size_is_bounded_before_parsing() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let path = std::env::temp_dir().join(format!(
            "zylith-prover-oversized-manifest-{}-{}.json",
            std::process::id(),
            super::now_unix_ms()
        ));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("create oversized manifest");
        file.set_len((super::MAX_DEPLOYMENT_MANIFEST_BYTES + 1) as u64)
            .expect("size oversized manifest");
        unsafe {
            std::env::set_var("ZYLITH_DEPLOYMENT_MANIFEST", &path);
        }

        let error = super::load_deployment_manifest().expect_err("oversized manifest must fail");
        assert!(error.contains("exceeds"));

        unsafe {
            std::env::remove_var("ZYLITH_DEPLOYMENT_MANIFEST");
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn production_requires_explicit_internal_service_urls() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var("ZYLITH_PROVER_STRICT", "true");
            std::env::remove_var("ZYLITH_COORDINATOR_URL");
            std::env::remove_var("ZYLITH_INDEXER_URL");
        }

        assert!(
            super::load_service_url("ZYLITH_COORDINATOR_URL", "http://127.0.0.1:3000").is_err()
        );
        assert!(super::load_service_url("ZYLITH_INDEXER_URL", "http://127.0.0.1:3300").is_err());

        unsafe {
            std::env::remove_var("ZYLITH_PROVER_STRICT");
        }
    }

    #[test]
    fn public_proof_job_status_never_exposes_exact_reuse_state_or_count() {
        let status = ProofJobStatus {
            batch_id: BatchId("batch-strk-usdc-privacy".into()),
            state: "confirmed-onchain".into(),
            transcript_commitment: "0xabc".into(),
            matched_order_count: 1,
            settlement_plan_available: true,
            witness_available: true,
            proof_artifact_available: true,
            onchain_submission_available: true,
            proof_artifact_id: Some("artifact-1".into()),
            onchain_submission_id: Some("submission-1".into()),
            prover_backend: "native".into(),
            last_error: Some("exact internal error should not leak".into()),
            created_at_unix_ms: 10,
            updated_at_unix_ms: 20,
            settlement_contract_address: "0xverifier".into(),
            settlement_entrypoint: "submit_settlement_with_proof_facts".into(),
            settlement_calldata_len: 42,
        };

        let public = public_proof_job_status(&status);
        assert_eq!(public.reuse_state, "unknown");
        assert_eq!(public.matched_order_count_bucket, "0-7");
        assert!(public.failure.is_none());
        let public_json = serde_json::to_value(&public).expect("public status json");
        assert!(public_json.get("matched_order_count").is_none());
        assert!(public_json.get("last_error").is_none());
        assert!(public_json.get("transcript_commitment").is_none());
    }

    #[test]
    fn public_proof_job_batch_query_is_bounded() {
        let allowed = (0..MAX_PUBLIC_PROOF_JOB_BATCH_IDS)
            .map(|index| format!("batch-strk-usdc-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_limited_batch_id_query(&allowed, MAX_PUBLIC_PROOF_JOB_BATCH_IDS)
                .expect("allowed query")
                .len(),
            MAX_PUBLIC_PROOF_JOB_BATCH_IDS
        );

        let oversized = format!("{allowed},batch-strk-usdc-extra");
        assert_eq!(
            parse_limited_batch_id_query(&oversized, MAX_PUBLIC_PROOF_JOB_BATCH_IDS).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn public_proof_job_reads_are_rate_limited() {
        let mut config = test_app_config(Some("test-internal-token"));
        config.public_rate_limit_per_minute = 1;
        let app = build_app_with_config(config).expect("test app should build");

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/public/proof-jobs?batch_ids=batch-strk-usdc-1")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/api/public/proof-jobs?batch_ids=batch-strk-usdc-1")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn pending_onchain_submissions_are_refreshed_until_accepted_or_reverted() {
        let mut submission = sample_onchain_submission();
        submission.finality_status = Some("PRE_CONFIRMED".into());
        submission.execution_status = Some("SUCCEEDED".into());
        assert!(should_refresh_onchain_submission(&submission));

        submission.finality_status = Some("ACCEPTED_ON_L2".into());
        assert!(!should_refresh_onchain_submission(&submission));

        submission.finality_status = Some("PRE_CONFIRMED".into());
        submission.execution_status = Some("REVERTED".into());
        assert!(!should_refresh_onchain_submission(&submission));
    }

    #[test]
    fn artifact_ids_are_deterministic_and_transcript_bound() {
        let a = artifact_id_for("batch-strk-usdc-1", "0xabc");
        let b = artifact_id_for("batch-strk-usdc-1", "0xabc");
        let c = artifact_id_for("batch-strk-usdc-1", "0xdef");

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    fn sample_onchain_submission() -> OnchainSubmissionRecord {
        OnchainSubmissionRecord {
            submission_id: "batch-strk-usdc-1:0xabc".into(),
            batch_id: BatchId("batch-strk-usdc-1".into()),
            transaction_hash: "0xabc".into(),
            submitted_at_unix_ms: 1,
            receipt_checked_at_unix_ms: Some(2),
            confirmed_at_unix_ms: None,
            finality_status: None,
            execution_status: None,
            revert_reason: None,
            block_number: None,
            block_hash: None,
            block_timestamp_unix_ms: None,
            submission_mode: "native-proof-facts".into(),
            settlement_contract_address: "0x123".into(),
        }
    }

    #[test]
    fn restart_keys_withdrawal_records_by_output_note_not_batch() {
        let data_dir = std::env::temp_dir().join(format!(
            "zylith-prover-restart-keys-{}-{}",
            std::process::id(),
            super::now_unix_ms()
        ));
        let settlement_submission = sample_onchain_submission();
        let mut withdrawal_submission = sample_onchain_submission();
        withdrawal_submission.submission_id = "0xabc:0xdef".into();
        withdrawal_submission.submission_mode =
            "native-settlement-output-withdrawal-proof-facts".into();
        super::persist_record(
            &data_dir,
            super::ONCHAIN_SUBMISSIONS_DIR,
            "batch-strk-usdc-1",
            &settlement_submission,
        )
        .expect("persist settlement submission");
        super::persist_record(
            &data_dir,
            super::ONCHAIN_SUBMISSIONS_DIR,
            "0xabc",
            &withdrawal_submission,
        )
        .expect("persist withdrawal submission");
        let submissions = super::load_json_records(
            &data_dir,
            super::ONCHAIN_SUBMISSIONS_DIR,
            onchain_submission_storage_key,
        );
        assert_eq!(submissions.len(), 2);
        assert!(submissions.contains_key("batch-strk-usdc-1"));
        assert!(submissions.contains_key("0xabc"));

        let consumed = ConsumedInput {
            note_commitment: NoteCommitment("0x00abc".into()),
            nullifier: Nullifier("0x123".into()),
        };
        assert_eq!(
            settlement_output_withdrawal_consumed_input_key(&consumed),
            "0xabc"
        );
        fs::remove_dir_all(data_dir).expect("remove restart key data");
    }

    #[test]
    fn restart_rejects_duplicate_logical_record_keys() {
        let data_dir = std::env::temp_dir().join(format!(
            "zylith-prover-duplicate-keys-{}-{}",
            std::process::id(),
            super::now_unix_ms()
        ));
        let records_dir = data_dir.join(super::ONCHAIN_SUBMISSIONS_DIR);
        let record = sample_onchain_submission();
        super::persist_json_file(&records_dir.join("first.json"), &record)
            .expect("persist first record");
        super::persist_json_file(&records_dir.join("second.json"), &record)
            .expect("persist duplicate record");

        let result = std::panic::catch_unwind(|| {
            super::load_json_records::<OnchainSubmissionRecord, _>(
                &data_dir,
                super::ONCHAIN_SUBMISSIONS_DIR,
                onchain_submission_storage_key,
            )
        });

        fs::remove_dir_all(data_dir).expect("remove duplicate key data");
        assert!(result.is_err());
    }

    #[test]
    fn restart_rejects_record_directories_above_configured_limits() {
        let data_dir = std::env::temp_dir().join(format!(
            "zylith-prover-record-limits-{}-{}",
            std::process::id(),
            super::now_unix_ms()
        ));
        let records_dir = data_dir.join(super::ONCHAIN_SUBMISSIONS_DIR);
        let first = sample_onchain_submission();
        let mut second = sample_onchain_submission();
        second.submission_id = "submission-2".into();
        second.batch_id = BatchId("batch-strk-usdc-2".into());
        super::persist_json_file(&records_dir.join("first.json"), &first)
            .expect("persist first record");
        super::persist_json_file(&records_dir.join("second.json"), &second)
            .expect("persist second record");

        let too_many = std::panic::catch_unwind(|| {
            super::load_json_records_with_limits::<OnchainSubmissionRecord, _>(
                &data_dir,
                super::ONCHAIN_SUBMISSIONS_DIR,
                1,
                usize::MAX,
                onchain_submission_storage_key,
            )
        });
        let too_large = std::panic::catch_unwind(|| {
            super::load_json_records_with_limits::<OnchainSubmissionRecord, _>(
                &data_dir,
                super::ONCHAIN_SUBMISSIONS_DIR,
                2,
                1,
                onchain_submission_storage_key,
            )
        });

        fs::remove_dir_all(data_dir).expect("remove limited record data");
        assert!(too_many.is_err());
        assert!(too_large.is_err());
    }

    #[test]
    fn maintenance_root_history_uses_only_confirmed_onchain_settlements() {
        let confirmed_witness =
            historical_witness_with_nullifier("batch-confirmed", Nullifier("0x11".into()));
        let stale_witness =
            historical_witness_with_nullifier("batch-proving-failed", Nullifier("0x22".into()));
        let mut confirmed_submission = sample_onchain_submission();
        confirmed_submission.batch_id = BatchId("batch-confirmed".into());
        confirmed_submission.execution_status = Some("SUCCEEDED".into());
        confirmed_submission.finality_status = Some("ACCEPTED_ON_L2".into());
        let mut failed_submission = sample_onchain_submission();
        failed_submission.batch_id = BatchId("batch-proving-failed".into());
        failed_submission.execution_status = Some("REVERTED".into());
        failed_submission.finality_status = Some("ACCEPTED_ON_L2".into());

        let witnesses = BTreeMap::from([
            (
                confirmed_witness.batch_id.0.clone(),
                confirmed_witness.clone(),
            ),
            (stale_witness.batch_id.0.clone(), stale_witness),
        ]);
        let submissions = BTreeMap::from([
            (
                confirmed_submission.batch_id.0.clone(),
                confirmed_submission,
            ),
            (failed_submission.batch_id.0.clone(), failed_submission),
        ]);

        let filtered = confirmed_settlement_witnesses_from_maps(&witnesses, &submissions);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].batch_id, confirmed_witness.batch_id);
    }

    #[allow(clippy::too_many_arguments)]
    fn aggregate_test_member(
        batch_id: &str,
        prior_note_root: &str,
        new_note_root: &str,
        prior_nullifier_root: &str,
        new_nullifier_root: &str,
        prior_renewal_root: &str,
        new_renewal_root: &str,
        prior_fee_root: &str,
        new_fee_root: &str,
        prior_liquidity_position_root: &str,
        new_liquidity_position_root: &str,
    ) -> NativeAggregationPreparedMember {
        let witness = historical_witness_with_nullifier(batch_id, Nullifier("0x1".into()));
        let transcript = SettlementTranscript {
            batch_id: BatchId(batch_id.into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: prior_note_root.into(),
            prior_nullifier_root: prior_nullifier_root.into(),
            prior_renewal_root: prior_renewal_root.into(),
            prior_fee_root: prior_fee_root.into(),
            prior_liquidity_position_root: prior_liquidity_position_root.into(),
            new_nullifier_root: new_nullifier_root.into(),
            new_renewal_root: new_renewal_root.into(),
            new_liquidity_position_root: new_liquidity_position_root.into(),
            clearing_price: 1,
            price_base_scale: 1,
            taker_fee_bps: 4,
            relay_fee_bps: 0,
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT.into(),
            matched_orders: vec![],
            consumed_inputs: vec![],
            renewal_child_uses: vec![],
            liquidity_position_transitions: vec![],
            fees: vec![],
            output_notes: vec![],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "0x777".into(),
        };
        let encoded_args = SettlementCallArguments {
            batch_id: batch_id.into(),
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            transcript_commitment: "0x333".into(),
            proof_artifact_commitment: "0x444".into(),
            clearing_price: "0x1".into(),
            price_base_scale: "0x1".into(),
            taker_fee_bps: "0x4".into(),
            relay_fee_bps: "0x0".into(),
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT.into(),
            output_bundle_ref: "0x777".into(),
            prior_note_root: prior_note_root.into(),
            prior_nullifier_root: prior_nullifier_root.into(),
            prior_renewal_root: prior_renewal_root.into(),
            prior_fee_root: prior_fee_root.into(),
            prior_liquidity_position_root: prior_liquidity_position_root.into(),
            consumed_note_root: "0x500".into(),
            consumed_nullifier_root: "0x501".into(),
            renewal_child_root: "0x502".into(),
            liquidity_position_transition_root: "0x0".into(),
            output_note_root: "0x503".into(),
            fee_root: "0x504".into(),
            new_note_root: new_note_root.into(),
            new_nullifier_root: new_nullifier_root.into(),
            new_renewal_root: new_renewal_root.into(),
            new_fee_root: new_fee_root.into(),
            new_liquidity_position_root: new_liquidity_position_root.into(),
        };

        NativeAggregationPreparedMember {
            witness,
            transcript,
            settlement_plan: SettlementSubmissionPlan {
                batch_id: BatchId(batch_id.into()),
                transcript_commitment: "0x333".into(),
                proof_artifact_commitment: "0x444".into(),
                settlement_call: StarknetCall {
                    contract_address: "0x123".into(),
                    entrypoint: "submit_settlement_with_proof_facts".into(),
                    calldata: vec![],
                },
                encoded_args,
            },
            proof_message_hashes: vec![],
        }
    }

    #[test]
    fn aggregate_root_chain_validation_rejects_any_broken_root_link() {
        let first = aggregate_test_member(
            "batch-a", "0x0", "0x10", "0x0", "0x20", "0x0", "0x30", "0x0", "0x40", "0x0", "0x50",
        );
        let second = aggregate_test_member(
            "batch-b", "0x10", "0x11", "0x20", "0x21", "0x30", "0x31", "0x40", "0x41", "0x50",
            "0x51",
        );

        assert!(validate_aggregate_root_chain(&[first.clone(), second.clone()]).is_ok());

        let mut broken = second.clone();
        broken.settlement_plan.encoded_args.prior_note_root = "0xdead".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first.clone(), broken]).expect_err("note mismatch"),
            "aggregate member note roots are not chained"
        );

        let mut broken = second.clone();
        broken.settlement_plan.encoded_args.prior_nullifier_root = "0xdead".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first.clone(), broken])
                .expect_err("nullifier mismatch"),
            "aggregate member nullifier roots are not chained"
        );

        let mut broken = second.clone();
        broken.settlement_plan.encoded_args.prior_renewal_root = "0xdead".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first.clone(), broken]).expect_err("renewal mismatch"),
            "aggregate member renewal roots are not chained"
        );

        let mut broken = second.clone();
        broken.settlement_plan.encoded_args.prior_fee_root = "0xdead".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first.clone(), broken]).expect_err("fee mismatch"),
            "aggregate member fee roots are not chained"
        );

        let mut broken = second;
        broken
            .settlement_plan
            .encoded_args
            .prior_liquidity_position_root = "0xdead".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first, broken])
                .expect_err("liquidity position mismatch"),
            "aggregate member liquidity position roots are not chained"
        );
    }

    #[test]
    fn aggregate_root_chain_validation_rejects_member_identity_mismatch() {
        let first = aggregate_test_member(
            "batch-a", "0x0", "0x10", "0x0", "0x20", "0x0", "0x30", "0x0", "0x40", "0x0", "0x50",
        );
        let second = aggregate_test_member(
            "batch-b", "0x10", "0x11", "0x20", "0x21", "0x30", "0x31", "0x40", "0x41", "0x50",
            "0x51",
        );

        let mut duplicate = second.clone();
        duplicate.witness.batch_id = BatchId("batch-a".into());
        duplicate.transcript.batch_id = BatchId("batch-a".into());
        duplicate.settlement_plan.batch_id = BatchId("batch-a".into());
        duplicate.settlement_plan.encoded_args.batch_id = "batch-a".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first.clone(), duplicate])
                .expect_err("duplicate batch rejected"),
            "aggregate member batch id is duplicated"
        );

        let mut mismatched = second.clone();
        mismatched.settlement_plan.encoded_args.batch_id = "batch-c".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first.clone(), mismatched])
                .expect_err("batch mismatch rejected"),
            "aggregate member batch ids do not agree"
        );

        let mut mismatched = second.clone();
        mismatched.settlement_plan.settlement_call.contract_address = "0x456".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first.clone(), mismatched])
                .expect_err("target mismatch rejected"),
            "aggregate member settlement targets do not agree"
        );

        let mut mismatched = second;
        mismatched.settlement_plan.settlement_call.entrypoint = "submit_other".into();
        assert_eq!(
            validate_aggregate_root_chain(&[first, mismatched])
                .expect_err("entrypoint mismatch rejected"),
            "aggregate member settlement entrypoint is invalid"
        );
    }

    #[test]
    fn aggregate_member_rejects_nonempty_liquidity_position_transitions_when_roots_match() {
        let mut member = aggregate_test_member(
            "batch-lp", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0",
        );
        let transition = LiquidityPositionRootTransition {
            kind: LiquidityPositionTransitionKind::Open,
            consumed_position_commitment: None,
            position_nullifier: None,
            output_position_commitment: Some(LiquidityPositionCommitment("0x123".into())),
        };
        member.transcript.liquidity_position_transitions = vec![transition.clone()];
        member.witness.liquidity_position_transitions = vec![transition];

        let result = aggregate_member_for_expected_roots(
            member.transcript,
            member.witness,
            &SettlementRoots::zero(),
        );
        assert!(
            matches!(result, Err(StatusCode::CONFLICT)),
            "unproved liquidity-position transition must fail closed",
        );
    }

    fn test_note(asset_id: &str, amount: u128, nonce: u64) -> Note {
        Note {
            asset_id: AssetId(asset_id.into()),
            amount,
            owner_public_key: format!("0x{:x}", 0x1000 + nonce),
            spend_authority: format!("0x{:x}", 0x2000 + nonce),
            withdraw_authority: format!("0x{:x}", 0x3000 + nonce),
            blinding: format!("0x{:x}", 0x4000 + nonce),
            nonce,
            metadata_commitment: "0x0".into(),
        }
    }

    fn test_matched_order_witness(funding_note: Note) -> MatchedOrderWitness {
        let funding_note_ref = funding_note.commitment().expect("funding note commitment");
        let funding_nullifier = Nullifier(format!("0x{:x}", 0x8000 + 1));
        MatchedOrderWitness {
            order_commitment: OrderCommitment(format!("0x{:x}", 0x7000 + funding_note.nonce)),
            funding_note: funding_note.clone(),
            funding_notes: vec![funding_note],
            funding_note_ref,
            funding_nullifier: funding_nullifier.clone(),
            funding_nullifiers: vec![funding_nullifier],
            funding_authorization: SpendAuthorization {
                signature_r: "0x1".into(),
                signature_s: "0x2".into(),
            },
            side: OrderSide::Buy,
            order_type: OrderType::LimitBatch,
            relay_mode: RelayMode::SelfRelay,
            liquidity_curve: None,
            liquidity_provider_band_attribution: None,
            limit_price: 1,
            order_amount: 1,
            min_fill: 1,
            time_in_force: TimeInForce::CurrentBatchOnly,
            expiry_epoch: 1,
            order_nonce: 1,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            auditor_view_allowed: false,
            recipient_owner_public_key: "0x0".into(),
            recipient_spend_authority: "0x0".into(),
            recipient_withdraw_authority: "0x0".into(),
            recipient_residual_withdraw_authority: "0x0".into(),
            filled_amount: 1,
            output_note: test_note("STRK", 1, 9000 + 1),
            residual_note: None,
        }
    }

    #[test]
    fn note_membership_derivation_supports_prior_settlement_outputs() {
        let initial_deposit_note = test_note("STRK", 10, 101);
        let later_deposit_note = test_note("ETH", 2, 202);
        let initial_deposit_commitment = initial_deposit_note
            .commitment()
            .expect("initial deposit commitment")
            .0;
        let later_deposit_commitment = later_deposit_note
            .commitment()
            .expect("later deposit commitment")
            .0;
        let initial_deposit_root =
            deposit_root_from_note(&initial_deposit_note).expect("initial deposit root");
        let root_after_initial_deposit =
            settlement_state_transition_root("0x0", &initial_deposit_root)
                .expect("initial note root");

        let output_a = OutputNoteRecord {
            note_commitment: NoteCommitment("0x303".into()),
            asset_id: AssetId("STRK".into()),
            amount: 10,
            withdraw_authority: "0x404".into(),
        };
        let output_b = OutputNoteRecord {
            note_commitment: NoteCommitment("0x505".into()),
            asset_id: AssetId("ETH".into()),
            amount: 2,
            withdraw_authority: "0x606".into(),
        };
        let prior_transcript = SettlementTranscript {
            batch_id: BatchId("batch-strk-eth-7".into()),
            pair_id: PairId("STRK/ETH".into()),
            batch_epoch: 7,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            prior_note_root: root_after_initial_deposit.clone(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            prior_liquidity_position_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            new_liquidity_position_root: "0x0".into(),
            clearing_price: 1,
            price_base_scale: 1,
            taker_fee_bps: 4,
            relay_fee_bps: 0,
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: Vec::new(),
            consumed_inputs: Vec::new(),
            renewal_child_uses: Vec::new(),
            liquidity_position_transitions: Vec::new(),
            fees: Vec::new(),
            output_notes: vec![output_a.clone(), output_b.clone()],
            output_note_preimages: Vec::new(),
            output_recovery_records: Vec::new(),
            output_recovery_dummy_commitments: Vec::new(),
            output_ciphertext_bundle_ref: "0x777".into(),
        };
        let prior_roots =
            root_only_settlement_commitments(&prior_transcript).expect("prior settlement roots");
        let later_deposit_root =
            deposit_root_from_note(&later_deposit_note).expect("later deposit root");
        let target_note_root =
            settlement_state_transition_root(&prior_roots.new_note_root, &later_deposit_root)
                .expect("target note root");
        let transitions = vec![
            NoteRootTransitionRecord {
                kind: 0,
                _key: initial_deposit_commitment,
                batch_root: initial_deposit_root,
                new_root: root_after_initial_deposit.clone(),
            },
            NoteRootTransitionRecord {
                kind: 1,
                _key: "0x7".into(),
                batch_root: prior_roots.output_note_root.clone(),
                new_root: prior_roots.new_note_root.clone(),
            },
            NoteRootTransitionRecord {
                kind: 0,
                _key: later_deposit_commitment.clone(),
                batch_root: later_deposit_root,
                new_root: target_note_root.clone(),
            },
        ];
        let prior_witness = SettlementWitness {
            batch_id: BatchId("batch-strk-eth-7".into()),
            pair_id: PairId("STRK/ETH".into()),
            batch_epoch: 7,
            order_commitment_root: "0x0".into(),
            encrypted_order_set_commitment: "0x0".into(),
            transcript_commitment: "0x0".into(),
            auction_verifier_address: "0x0".into(),
            prior_note_root: root_after_initial_deposit,
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            prior_liquidity_position_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            new_liquidity_position_root: "0x0".into(),
            clearing_price: 0,
            price_base_scale: 1,
            taker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT.into(),
            base_asset_id: AssetId("STRK".into()),
            quote_asset_id: AssetId("ETH".into()),
            matched_orders: Vec::new(),
            matched_order_witnesses: Vec::new(),
            consumed_inputs: Vec::new(),
            note_membership_witnesses: Vec::new(),
            nullifier_history: Vec::new(),
            nullifier_sparse_witnesses: Vec::new(),
            renewal_history: Vec::new(),
            renewal_child_sparse_witnesses: Vec::new(),
            renewal_cancel_sparse_witnesses: Vec::new(),
            renewal_child_uses: Vec::new(),
            liquidity_position_transitions: Vec::new(),
            liquidity_position_witnesses: Vec::new(),
            fees: Vec::new(),
            output_notes: vec![output_a, output_b.clone()],
            output_note_preimages: Vec::new(),
            output_recovery_records: Vec::new(),
            output_recovery_dummy_commitments: Vec::new(),
            output_ciphertext_bundle_ref: "root-history".into(),
        };
        let consumed_inputs = vec![
            ConsumedInput {
                note_commitment: output_b.note_commitment,
                nullifier: Nullifier("0x900".into()),
            },
            ConsumedInput {
                note_commitment: NoteCommitment(later_deposit_commitment),
                nullifier: Nullifier("0x901".into()),
            },
        ];
        let matched_order_witnesses = vec![
            test_matched_order_witness(initial_deposit_note),
            test_matched_order_witness(later_deposit_note),
        ];

        let witnesses = derive_note_membership_witnesses(
            &target_note_root,
            &consumed_inputs,
            NoteMembershipSources {
                initial_note_root: "0x0",
                direct_input_notes: &[],
                matched_order_witnesses: &matched_order_witnesses,
                deposit_activations: &[],
                note_root_transitions: &transitions,
                prior_settlement_witnesses: &[prior_witness],
                prior_note_consolidation_history: &[],
            },
        )
        .expect("note membership witnesses");

        assert_eq!(witnesses.len(), 2);
        assert_eq!(witnesses[0].kind, NoteMembershipKind::SettlementOutput);
        assert_eq!(witnesses[0].batch_root, prior_roots.output_note_root);
        assert_eq!(witnesses[0].merkle_path.len(), 1);
        assert_eq!(witnesses[0].suffix_batch_roots.len(), 1);
        assert_eq!(witnesses[1].kind, NoteMembershipKind::Deposit);
        assert!(witnesses[1].merkle_path.is_empty());
        assert!(witnesses[1].suffix_batch_roots.is_empty());
    }

    #[test]
    fn note_membership_derivation_supports_prior_consolidation_outputs() {
        let deposit_note = test_note("STRK", 10, 101);
        let deposit_commitment = deposit_note.commitment().expect("deposit commitment").0;
        let deposit_root = deposit_root_from_note(&deposit_note).expect("deposit root");
        let root_after_deposit =
            settlement_state_transition_root("0x0", &deposit_root).expect("deposit note root");
        let consolidated_output = OutputNoteRecord {
            note_commitment: NoteCommitment("0x303".into()),
            asset_id: AssetId("STRK".into()),
            amount: 10,
            withdraw_authority: "0x404".into(),
        };
        let fake_transcript = SettlementTranscript {
            batch_id: BatchId("consolidation-1".into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x0".into(),
            encrypted_order_set_commitment: "0x0".into(),
            prior_note_root: root_after_deposit.clone(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            prior_liquidity_position_root: "0x0".into(),
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            new_liquidity_position_root: "0x0".into(),
            clearing_price: 0,
            price_base_scale: 1,
            taker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: Vec::new(),
            consumed_inputs: Vec::new(),
            renewal_child_uses: Vec::new(),
            liquidity_position_transitions: Vec::new(),
            fees: Vec::new(),
            output_notes: vec![consolidated_output.clone()],
            output_note_preimages: Vec::new(),
            output_recovery_records: Vec::new(),
            output_recovery_dummy_commitments: Vec::new(),
            output_ciphertext_bundle_ref: "0x777".into(),
        };
        let consolidation_roots =
            root_only_settlement_commitments(&fake_transcript).expect("consolidation roots");
        let target_note_root = consolidation_roots.new_note_root.clone();
        let transitions = vec![
            NoteRootTransitionRecord {
                kind: 0,
                _key: deposit_commitment,
                batch_root: deposit_root,
                new_root: root_after_deposit.clone(),
            },
            NoteRootTransitionRecord {
                kind: NOTE_ROOT_TRANSITION_CONSOLIDATION_KIND,
                _key: "0x1".into(),
                batch_root: consolidation_roots.output_note_root.clone(),
                new_root: target_note_root.clone(),
            },
        ];
        let consolidation_history = NoteConsolidationHistoryRecord {
            consolidation_id: BatchId("consolidation-1".into()),
            consumed_inputs: Vec::new(),
            output_notes: vec![consolidated_output.clone()],
        };
        let consumed_inputs = vec![ConsumedInput {
            note_commitment: consolidated_output.note_commitment,
            nullifier: Nullifier("0x900".into()),
        }];
        let matched_order_witnesses = vec![test_matched_order_witness(deposit_note)];

        let witnesses = derive_note_membership_witnesses(
            &target_note_root,
            &consumed_inputs,
            NoteMembershipSources {
                initial_note_root: "0x0",
                direct_input_notes: &[],
                matched_order_witnesses: &matched_order_witnesses,
                deposit_activations: &[],
                note_root_transitions: &transitions,
                prior_settlement_witnesses: &[],
                prior_note_consolidation_history: &[consolidation_history],
            },
        )
        .expect("note membership witnesses");

        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].kind, NoteMembershipKind::SettlementOutput);
        assert_eq!(
            witnesses[0].batch_root,
            consolidation_roots.output_note_root
        );
        assert!(witnesses[0].suffix_batch_roots.is_empty());
    }

    #[test]
    fn note_membership_derivation_supports_direct_deposit_consolidation_input() {
        let deposit_note = test_note("STRK", 10, 101);
        let deposit_commitment = deposit_note.commitment().expect("deposit commitment").0;
        let deposit_root = deposit_root_from_note(&deposit_note).expect("deposit root");
        let root_after_deposit =
            settlement_state_transition_root("0x0", &deposit_root).expect("deposit note root");
        let transitions = vec![NoteRootTransitionRecord {
            kind: NOTE_ROOT_TRANSITION_DEPOSIT_KIND,
            _key: deposit_commitment.clone(),
            batch_root: deposit_root.clone(),
            new_root: root_after_deposit.clone(),
        }];
        let consumed_inputs = vec![ConsumedInput {
            note_commitment: NoteCommitment(deposit_commitment),
            nullifier: Nullifier("0x900".into()),
        }];

        let witnesses = derive_note_membership_witnesses(
            &root_after_deposit,
            &consumed_inputs,
            NoteMembershipSources {
                initial_note_root: "0x0",
                direct_input_notes: std::slice::from_ref(&deposit_note),
                matched_order_witnesses: &[],
                deposit_activations: &[],
                note_root_transitions: &transitions,
                prior_settlement_witnesses: &[],
                prior_note_consolidation_history: &[],
            },
        )
        .expect("note membership witnesses");

        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].kind, NoteMembershipKind::Deposit);
        assert_eq!(witnesses[0].batch_root, deposit_root);
        assert!(witnesses[0].merkle_path.is_empty());
        assert!(witnesses[0].suffix_batch_roots.is_empty());
    }

    #[test]
    fn note_membership_derivation_supports_nonzero_initial_note_root() {
        let initial_note_root = "0x12345";
        let deposit_note = test_note("STRK", 10, 101);
        let deposit_commitment = deposit_note.commitment().expect("deposit commitment").0;
        let deposit_root = deposit_root_from_note(&deposit_note).expect("deposit root");
        let root_after_deposit = settlement_state_transition_root(initial_note_root, &deposit_root)
            .expect("deposit note root");
        let transitions = vec![NoteRootTransitionRecord {
            kind: NOTE_ROOT_TRANSITION_DEPOSIT_KIND,
            _key: deposit_commitment.clone(),
            batch_root: deposit_root.clone(),
            new_root: root_after_deposit.clone(),
        }];
        let consumed_inputs = vec![ConsumedInput {
            note_commitment: NoteCommitment(deposit_commitment),
            nullifier: Nullifier("0x900".into()),
        }];

        let witnesses = derive_note_membership_witnesses(
            &root_after_deposit,
            &consumed_inputs,
            NoteMembershipSources {
                initial_note_root,
                direct_input_notes: std::slice::from_ref(&deposit_note),
                matched_order_witnesses: &[],
                deposit_activations: &[],
                note_root_transitions: &transitions,
                prior_settlement_witnesses: &[],
                prior_note_consolidation_history: &[],
            },
        )
        .expect("note membership witnesses");

        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].kind, NoteMembershipKind::Deposit);
        assert_eq!(witnesses[0].prefix_root, initial_note_root);
        assert_eq!(witnesses[0].batch_root, deposit_root);
        assert!(witnesses[0].merkle_path.is_empty());
        assert!(witnesses[0].suffix_batch_roots.is_empty());
    }

    #[test]
    fn native_request_redaction_removes_private_witness_calldata() {
        let request = NativeExecutionRequestRecord {
            block_id: NativeBlockId::Number { block_number: 7 },
            transaction: serde_json::json!({
                "sender_address": "0x123",
                "calldata": ["0x1", "0x2", "0x3"],
                "signature": ["0xa", "0xb"]
            }),
        };

        let redacted = redact_native_execution_request(&request);

        assert_eq!(
            request.transaction["calldata"],
            serde_json::json!(["0x1", "0x2", "0x3"])
        );
        assert_eq!(redacted.transaction["calldata"]["redacted"], true);
        assert_eq!(redacted.transaction["calldata"]["felt_count"], 3);
        assert_eq!(
            redacted.transaction["signature"],
            serde_json::json!(["0xa", "0xb"])
        );
    }

    #[test]
    fn ohttp_key_config_hex_accepts_prefixed_and_plain_values() {
        assert_eq!(
            parse_ohttp_key_config_hex("0x000102ff").expect("prefixed key config"),
            vec![0x00, 0x01, 0x02, 0xff]
        );
        assert_eq!(
            parse_ohttp_key_config_hex("000102ff").expect("plain key config"),
            vec![0x00, 0x01, 0x02, 0xff]
        );

        assert!(parse_ohttp_key_config_hex("0x").is_err());
        assert!(parse_ohttp_key_config_hex("not-hex").is_err());
    }

    #[test]
    fn ohttp_bhttp_helpers_round_trip_json_request_response() {
        let server_config = ohttp::KeyConfig::new(
            1,
            ohttp::hpke::Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(
                ohttp::hpke::Kdf::HkdfSha256,
                ohttp::hpke::Aead::Aes128Gcm,
            )],
        )
        .expect("server key config");
        let encoded_config =
            ohttp::KeyConfig::encode_list(&[&server_config]).expect("encoded key config list");
        let client =
            ohttp::ClientRequest::from_encoded_config_list(&encoded_config).expect("ohttp client");
        let request_body = br#"{"jsonrpc":"2.0","method":"starknet_proveTransaction"}"#;
        let bhttp_request = encode_bhttp_json_post(request_body).expect("bhttp request");
        let (encrypted_request, client_response) = client
            .encapsulate(&bhttp_request)
            .expect("encrypted request");
        assert_ne!(encrypted_request, bhttp_request);

        let server = ohttp::Server::new(server_config).expect("ohttp server");
        let (inner_request, server_response) = server
            .decapsulate(&encrypted_request)
            .expect("decrypted request");
        let mut request_cursor = std::io::Cursor::new(inner_request);
        let decoded_request =
            bhttp::Message::read_bhttp(&mut request_cursor).expect("decoded bhttp request");
        assert_eq!(decoded_request.control().method(), Some(&b"POST"[..]));
        assert_eq!(decoded_request.control().path(), Some(&b"/"[..]));
        assert_eq!(decoded_request.content(), request_body);

        let response_body = br#"{"jsonrpc":"2.0","id":1,"result":{"proof":[]}}"#;
        let mut response = bhttp::Message::response(bhttp::StatusCode::OK);
        response.put_header(b"content-type".to_vec(), b"application/json".to_vec());
        response.write_content(response_body);
        let mut encoded_response = Vec::new();
        response
            .write_bhttp(bhttp::Mode::KnownLength, &mut encoded_response)
            .expect("encoded bhttp response");
        let encrypted_response = server_response
            .encapsulate(&encoded_response)
            .expect("encrypted response");
        let decrypted_response = client_response
            .decapsulate(&encrypted_response)
            .expect("decrypted response");
        let (status, body) =
            decode_bhttp_response(&decrypted_response).expect("decoded bhttp response");

        assert_eq!(status, 200);
        assert_eq!(body, response_body);
    }

    #[test]
    fn native_proof_program_calldata_prefixes_verifier_address() {
        let calldata =
            build_native_proof_program_calldata("0x123", &["0x2".into(), "0xabc".into()])
                .expect("proof calldata");

        assert_eq!(calldata, vec!["0x123", "0x2", "0xabc"]);
    }

    #[test]
    fn native_proof_program_calldata_rejects_zero_verifier_address() {
        let error = build_native_proof_program_calldata("0x0", &["0x1".into()])
            .expect_err("zero verifier must fail");

        assert!(error.contains("auction_verifier_address"));
    }

    #[test]
    fn native_prover_request_redaction_removes_nested_private_calldata() {
        let request = NativeProverRpcRequest {
            jsonrpc: "2.0".into(),
            id: 1,
            method: "starknet_proveTransaction".into(),
            params: (
                NativeBlockId::Tag("latest".into()),
                serde_json::json!({
                    "calldata": ["0xabc"]
                }),
            ),
        };

        let redacted = redact_native_prover_request(&request);
        let serialized = serde_json::to_value(&request).expect("serialize native prover request");

        assert_eq!(request.params.1["calldata"], serde_json::json!(["0xabc"]));
        assert!(serialized["params"].is_array());
        assert_eq!(serialized["params"].as_array().map(Vec::len), Some(2));
        assert_eq!(serialized["params"][0], serde_json::json!("latest"));
        assert_eq!(
            serialized["params"][1]["calldata"],
            serde_json::json!(["0xabc"])
        );
        assert_eq!(redacted.params.1["calldata"]["redacted"], true);
        assert_eq!(redacted.params.1["calldata"]["felt_count"], 1);
    }

    #[test]
    fn native_prover_error_sanitizer_redacts_private_like_payloads() {
        let sensitive = concat!(
            "Execution failed calldata=[0x1234567890abcdef1234567890abcdef1234567890abcdef]",
            " amount=1234567890123456789012345678901234567890\n",
            "signature=0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        );

        let sanitized = sanitize_native_prover_error_text(sensitive);

        assert!(sanitized.contains("<felt>"));
        assert!(sanitized.contains("<number>"));
        assert!(!sanitized.contains("1234567890abcdef1234567890abcdef"));
        assert!(!sanitized.contains("1234567890123456789012345678901234567890"));
        assert!(!sanitized.contains('\n'));
    }

    #[test]
    fn native_fee_estimation_falls_back_for_proof_fact_simulation_reverts() {
        assert!(native_fee_estimate_should_use_configured_bounds(
            "Execution failed: PROOF_FACTS_MISSING"
        ));
        assert!(native_fee_estimate_should_use_configured_bounds(
            "Execution failed: EMPTY_PROOF_FACTS"
        ));
        assert!(native_fee_estimate_should_use_configured_bounds(
            "TransactionExecutionError: TransactionExecutionErrorData { execution_error: Nested(InnerContractExecutionError { error: Nested(...) }) }"
        ));
        assert!(!native_fee_estimate_should_use_configured_bounds(
            "Execution failed: UNKNOWN_BATCH"
        ));
    }

    #[test]
    fn native_execution_context_ages_proof_and_submit_by_default() {
        match native_execution_context_block_id(NativeTransactionMode::ProofOnly, 100, 7, None) {
            NativeBlockId::Number { block_number } => assert_eq!(block_number, 93),
            other => panic!("proof context must use numbered block, got {other:?}"),
        }

        match native_execution_context_block_id(NativeTransactionMode::SubmitOnchain, 100, 7, None)
        {
            NativeBlockId::Number { block_number } => assert_eq!(block_number, 93),
            other => panic!("submit context must use numbered block, got {other:?}"),
        }
    }

    #[test]
    fn native_execution_context_can_use_latest_tag_for_official_prover() {
        match native_execution_context_block_id(
            NativeTransactionMode::ProofOnly,
            100,
            7,
            Some("latest"),
        ) {
            NativeBlockId::Tag(tag) => assert_eq!(tag, "latest"),
            other => panic!("proof context must use latest tag, got {other:?}"),
        }

        match native_execution_context_block_id(
            NativeTransactionMode::SubmitOnchain,
            100,
            7,
            Some("latest"),
        ) {
            NativeBlockId::Tag(tag) => assert_eq!(tag, "latest"),
            other => panic!(
                "submit context must use latest tag when explicitly requested, got {other:?}"
            ),
        }
    }

    #[test]
    fn native_settlement_submission_proves_each_transition_in_onchain_order() {
        let [
            nullifier,
            renewal,
            liquidity_position,
            settlement_order,
            settlement_input_membership,
            settlement_output_recovery,
            settlement,
        ] = super::NATIVE_SETTLEMENT_SUBMISSION_ORDER;

        assert_eq!(nullifier.label(), "nullifier");
        assert_eq!(
            nullifier.entrypoint("compile_settlement"),
            "compile_nullifier_proof"
        );
        assert_eq!(renewal.label(), "renewal");
        assert_eq!(
            renewal.entrypoint("compile_settlement"),
            "compile_renewal_proof"
        );
        assert_eq!(liquidity_position.label(), "liquidity-position");
        assert_eq!(
            liquidity_position.entrypoint("compile_settlement"),
            "compile_liquidity_position_proof"
        );
        assert_eq!(settlement_order.label(), "settlement-order");
        assert_eq!(
            settlement_order.entrypoint("compile_settlement"),
            "compile_settlement_order_proof"
        );
        assert_eq!(
            settlement_input_membership.label(),
            "settlement-input-membership"
        );
        assert_eq!(
            settlement_input_membership.entrypoint("compile_settlement"),
            "compile_settlement_input_membership_proof"
        );
        assert_eq!(
            settlement_output_recovery.label(),
            "settlement-output-recovery"
        );
        assert_eq!(
            settlement_output_recovery.entrypoint("compile_settlement"),
            "compile_settlement_output_recovery_proof"
        );
        assert_eq!(settlement.label(), "settlement");
        assert_eq!(
            settlement.entrypoint("compile_settlement"),
            "compile_settlement"
        );
    }

    #[test]
    fn native_auction_record_retries_reuse_only_matching_onchain_values() {
        let admission = super::Felt::from_hex_unchecked("0x11");
        let transcript = super::Felt::from_hex_unchecked("0x22");

        assert_eq!(
            super::reconcile_verified_auction_records(
                super::Felt::ZERO,
                admission,
                super::Felt::ZERO,
                transcript,
            )
            .expect("empty records are valid"),
            (false, false)
        );
        assert_eq!(
            super::reconcile_verified_auction_records(
                admission,
                admission,
                transcript,
                transcript,
            )
            .expect("matching records are reusable"),
            (true, true)
        );
        assert!(
            super::reconcile_verified_auction_records(
                super::Felt::from_hex_unchecked("0x33"),
                admission,
                super::Felt::ZERO,
                transcript,
            )
            .is_err()
        );
        assert!(
            super::reconcile_verified_auction_records(
                super::Felt::ZERO,
                admission,
                transcript,
                transcript,
            )
            .is_err()
        );
    }

    #[test]
    fn native_proof_request_uses_separate_proof_private_key_when_configured() {
        let executor = StarknetExecutorConfig {
            rpc_url: "http://127.0.0.1:5050".into(),
            account_address: "0x111".into(),
            private_key: "0xaaa".into(),
            chain_id: "0x534e5f5345504f4c4941".into(),
            proof_account_address: "0x222".into(),
            proof_private_key: Some("0xbbb".into()),
        };

        assert_eq!(
            executor.request_account_address(NativeTransactionMode::ProofOnly),
            "0x222"
        );
        assert_eq!(
            executor.request_private_key(NativeTransactionMode::ProofOnly),
            "0xbbb"
        );
        assert_eq!(
            executor.request_account_address(NativeTransactionMode::SubmitOnchain),
            "0x111"
        );
        assert_eq!(
            executor.request_private_key(NativeTransactionMode::SubmitOnchain),
            "0xaaa"
        );
    }

    #[test]
    fn native_submit_retries_only_for_proof_facts_delay() {
        let too_recent = serde_json::json!({
            "code": 55,
            "message": "Account validation failed",
            "data": "Invalid proof facts: The proof block number 9245965 is too recent. The maximum allowed block number is 9245961."
        });
        assert!(native_invoke_error_is_retryable_proof_facts_delay(
            &too_recent.to_string()
        ));
        assert_eq!(
            proof_fact_age_wait_ms(&too_recent.to_string(), 5_000, 1),
            25_000
        );

        let missing_block_hash = serde_json::json!({
            "code": 55,
            "message": "Account validation failed",
            "data": "Invalid proof facts: Block hash mismatch for block 9246031. Proof block hash: 811206585724913684484793365759388883086436621802564158104548057456911368569, stored block hash: 0."
        });
        assert!(native_invoke_error_is_retryable_proof_facts_delay(
            &missing_block_hash.to_string()
        ));
        assert_eq!(
            proof_fact_age_wait_ms(&missing_block_hash.to_string(), 5_000, 2),
            10_000
        );

        let missing = serde_json::json!({
            "code": 55,
            "message": "Account validation failed",
            "data": "Invalid proof facts: EMPTY_PROOF_FACTS"
        });
        assert!(!native_invoke_error_is_retryable_proof_facts_delay(
            &missing.to_string()
        ));

        let duplicate = serde_json::json!({
            "code": 51,
            "message": "Invalid transaction nonce"
        });
        assert!(!native_invoke_error_is_retryable_proof_facts_delay(
            &duplicate.to_string()
        ));
    }

    #[test]
    fn native_submit_retries_provider_transport_failures() {
        assert!(native_invoke_error_is_retryable_after_submission(
            "UnexpectedError: \"HTTP status server error (502 Bad Gateway) for url\""
        ));
        assert!(native_invoke_error_is_retryable_after_submission(
            "provider request timed out"
        ));
        assert!(native_invoke_error_is_retryable_after_submission(
            "HTTP status client error (429 Too Many Requests)"
        ));
        assert!(!native_invoke_error_is_retryable_after_submission(
            "Invalid transaction nonce"
        ));
        assert!(!native_invoke_error_is_retryable_after_submission(
            "Account validation failed: Invalid proof facts: EMPTY_PROOF_FACTS"
        ));
    }

    #[test]
    fn retryable_onchain_submission_errors_stay_submitting() {
        assert_eq!(
            super::onchain_submission_error_next_state(
                "failed to record native nullifier proof: failed to fetch latest block gas prices: HTTP status server error (502 Bad Gateway)"
            ),
            "submitting-onchain"
        );
        assert_eq!(
            super::onchain_submission_error_next_state(
                "failed to record native renewal proof: failed to fetch account nonce: provider request timed out"
            ),
            "submitting-onchain"
        );
        assert_eq!(
            super::onchain_submission_error_next_state(
                "failed to register batch before native proof recording: batch registration receipt unavailable"
            ),
            "submitting-onchain"
        );
        assert_eq!(
            super::onchain_submission_error_next_state(
                "settlement proof transaction 0x123 reverted onchain: INVALID_ROOT_TRANSITION"
            ),
            "onchain-submit-failed"
        );
    }

    #[test]
    fn active_proof_batch_guard_blocks_concurrent_reentry_until_drop() {
        let active_batches = Arc::new(Mutex::new(BTreeSet::new()));
        let first = try_enter_active_batch(&active_batches, "batch-1")
            .expect("first entry must acquire guard");

        assert!(try_enter_active_batch(&active_batches, "batch-1").is_none());
        assert!(try_enter_active_batch(&active_batches, "batch-2").is_some());

        drop(first);

        assert!(try_enter_active_batch(&active_batches, "batch-1").is_some());
    }

    #[test]
    fn withdrawal_revert_status_maps_claim_window_to_too_early() {
        assert_eq!(
            settlement_output_withdrawal_revert_status(Some(
                "Execution failed: CLAIM_WINDOW_CLOSED"
            )),
            StatusCode::TOO_EARLY
        );
        assert_eq!(
            settlement_output_withdrawal_revert_status(Some(
                "Execution failed: claim window not open yet"
            )),
            StatusCode::TOO_EARLY
        );
        assert_eq!(
            settlement_output_withdrawal_revert_status(Some(
                "Execution failed: NULLIFIER_ALREADY_USED"
            )),
            StatusCode::CONFLICT
        );
        assert_eq!(
            settlement_output_withdrawal_revert_status(None),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn withdrawal_submit_error_status_maps_preflight_claim_window_to_too_early() {
        assert_eq!(
            settlement_output_withdrawal_submit_error_status(
                "failed to estimate native settlement fee: TransactionExecutionError: \
                 Message(\"0x434c41494d5f57494e444f575f434c4f534544 ('CLAIM_WINDOW_CLOSED')\")"
            ),
            StatusCode::TOO_EARLY
        );
        assert_eq!(
            settlement_output_withdrawal_submit_error_status("provider timeout"),
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn withdrawal_submit_error_returns_actionable_json_body() {
        let (status, body) = withdrawal_submit_error(StatusCode::TOO_EARLY);
        assert_eq!(status, StatusCode::TOO_EARLY);
        assert_eq!(
            body.0.get("error").and_then(serde_json::Value::as_str),
            Some("Settlement output claim window is not open yet. Retry after the claim delay.")
        );

        let (status, body) = withdrawal_submit_error(StatusCode::BAD_GATEWAY);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            body.0.get("error").and_then(serde_json::Value::as_str),
            Some("Withdrawal service is unavailable. Please retry later.")
        );
    }

    #[test]
    fn native_submit_rebuilds_for_stale_nonce_errors() {
        assert!(native_invoke_error_is_retryable_nonce(
            "InvalidTransactionNonce: \"Invalid transaction nonce. Expected: 2822, got: 2821.\""
        ));
        assert!(native_invoke_error_is_retryable_nonce(
            "RPC error: nonce expected 3022 got 3021"
        ));
        assert!(!native_invoke_error_is_retryable_nonce(
            "Invalid proof facts: EMPTY_PROOF_FACTS"
        ));
    }

    #[test]
    fn batch_registrar_private_key_requires_matching_account_when_reusing_settlement_key() {
        assert_eq!(
            resolve_batch_registrar_private_key(
                "0x123",
                Some("0xregistrar".into()),
                Some("0x456".into()),
                Some("0xsettlement".into()),
            )
            .expect("explicit registrar key"),
            "0xregistrar"
        );

        assert_eq!(
            resolve_batch_registrar_private_key(
                "0x0123",
                None,
                Some("0x123".into()),
                Some("0xshared".into()),
            )
            .expect("shared same-account key"),
            "0xshared"
        );

        assert!(
            resolve_batch_registrar_private_key(
                "0x123",
                None,
                Some("0x456".into()),
                Some("0xsettlement".into()),
            )
            .is_err()
        );
    }

    #[test]
    fn starknet_address_comparison_normalizes_felts() {
        assert!(same_starknet_address("0x0123", "0x123"));
        assert!(!same_starknet_address("0x123", "0x124"));
    }

    #[test]
    fn clearing_price_scoring_uses_stable_pruned_liquidity() {
        let records = vec![
            test_record(
                0,
                OrderSide::Buy,
                10,
                2,
                2,
                TimeInForce::CurrentBatchOnly,
                20,
            ),
            test_record(
                1,
                OrderSide::Sell,
                5,
                8,
                4,
                TimeInForce::CurrentBatchOnly,
                8,
            ),
            test_record(
                2,
                OrderSide::Sell,
                6,
                1,
                1,
                TimeInForce::CurrentBatchOnly,
                1,
            ),
        ];

        assert_eq!(
            compute_candidate_clearing_price(&records, 1).unwrap(),
            Some(6)
        );
    }

    #[test]
    fn clearing_price_uses_midpoint_of_best_crossing_interval() {
        let records = vec![
            test_record(
                0,
                OrderSide::Buy,
                55,
                20,
                1,
                TimeInForce::CurrentBatchOnly,
                1_100,
            ),
            test_record(
                1,
                OrderSide::Sell,
                45,
                20,
                1,
                TimeInForce::CurrentBatchOnly,
                20,
            ),
        ];

        assert_eq!(
            compute_candidate_clearing_price(&records, 1).unwrap(),
            Some(50)
        );
    }

    #[test]
    fn liquidity_report_does_not_block_below_disabled_threshold() {
        let records = vec![
            test_record(
                0,
                OrderSide::Buy,
                10,
                2,
                2,
                TimeInForce::CurrentBatchOnly,
                20,
            ),
            test_record(
                1,
                OrderSide::Sell,
                5,
                2,
                2,
                TimeInForce::CurrentBatchOnly,
                2,
            ),
        ];

        let report = build_batch_liquidity_report(&records, 5, 2, 3, 1);

        assert_eq!(report.status, "ready");
        assert_eq!(report.matched_base_volume, 2);
        assert_eq!(report.min_base_liquidity, 3);
    }

    #[test]
    fn no_cross_artifacts_use_candidate_clearing_price_for_noop_proof() {
        let mut product_config = ProductConfig::default_v1();
        let pair_id = PairId("STRK/USDC".into());
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .min_order_amount = 1;
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let records = vec![
            valid_test_record(
                0,
                OrderSide::Buy,
                1,
                2,
                1,
                TimeInForce::CurrentBatchOnly,
                20,
            ),
            valid_test_record(
                1,
                OrderSide::Sell,
                5,
                2,
                1,
                TimeInForce::CurrentBatchOnly,
                2,
            ),
        ];
        let order_commitments = records
            .iter()
            .map(|record| record.order_commitment.0.clone())
            .collect::<Vec<_>>();
        let batch = BatchSummary {
            batch_id: BatchId("batch-strk-usdc-1".into()),
            pair_id,
            epoch_id: 1,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: records.len() as u64,
            order_commitment_root: ordered_felt_list_commitment(
                "zylith/batch-order-root",
                &order_commitments,
            )
            .expect("order root"),
            encrypted_order_set_commitment: "0x222".into(),
        };

        let protocol_fee_note_recipient = test_fee_note_recipient("91", "0xf01");
        let relay_fee_note_recipient = test_fee_note_recipient("92", "0xf02");
        let artifacts = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            &[],
            SettlementBuildContext {
                product_config: &product_config,
                liquidity_position_market_contexts: &LiquidityPositionMarketContexts::default(),
                prior_roots: &SettlementRoots::zero(),
                initial_note_root: "0x0",
                deposit_activations: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_renewal_cancel_markers: &[],
                prior_note_consolidation_history: &[],
                prior_withdrawal_nullifiers: &[],
                protocol_fee_recipient: &protocol_fee_note_recipient.withdraw_authority,
                relay_fee_recipient: &relay_fee_note_recipient.withdraw_authority,
                protocol_fee_note_recipient: &protocol_fee_note_recipient,
                relay_fee_note_recipient: &relay_fee_note_recipient,
                liquidity_attribution_signer_private_key: "0x12345",
            },
        )
        .expect("no-cross artifacts");

        assert_eq!(
            compute_candidate_clearing_price(&records, 1).unwrap(),
            Some(1)
        );
        assert_eq!(artifacts.transcript.clearing_price, 1);
        assert!(artifacts.transcript.matched_orders.is_empty());
        assert!(artifacts.transcript.consumed_inputs.is_empty());
        assert!(artifacts.transcript.output_notes.is_empty());
        assert!(artifacts.transcript.fees.is_empty());
        assert!(artifacts.liquidity_provider_attribution_bundle.is_none());
        assert_eq!(artifacts.output_bundle.padded_ciphertext_count, 4);
        assert_eq!(artifacts.output_bundle.ciphertext_count_bucket, "0-4");
    }

    #[test]
    fn settlement_artifacts_reject_legacy_liquidity_curve_order_records() {
        let mut product_config = ProductConfig::default_v1();
        let pair_id = PairId("STRK/USDC".into());
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .price_base_scale = 1;
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .min_order_amount = 1;
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let mut record = valid_test_record(
            1,
            OrderSide::Sell,
            100,
            1_000,
            100,
            TimeInForce::CurrentBatchOnly,
            1_000,
        );
        record.order.order_type = OrderType::LiquidityCurve;
        record.order.liquidity_curve = Some(LiquidityCurve {
            points: vec![LiquidityCurvePoint {
                price: 100,
                base_amount: 1_000,
            }],
        });
        record.order_commitment = record.order.commitment().expect("legacy curve commitment");
        let batch = BatchSummary {
            batch_id: BatchId("batch-strk-usdc-1".into()),
            pair_id,
            epoch_id: 1,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: 1,
            order_commitment_root: record.order_commitment.0.clone(),
            encrypted_order_set_commitment: "0x222".into(),
        };

        let protocol_fee_note_recipient = test_fee_note_recipient("91", "0xf01");
        let relay_fee_note_recipient = test_fee_note_recipient("92", "0xf02");
        let result = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &[record],
            &[],
            SettlementBuildContext {
                product_config: &product_config,
                liquidity_position_market_contexts: &LiquidityPositionMarketContexts::default(),
                prior_roots: &SettlementRoots::zero(),
                initial_note_root: "0x0",
                deposit_activations: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_renewal_cancel_markers: &[],
                prior_note_consolidation_history: &[],
                prior_withdrawal_nullifiers: &[],
                protocol_fee_recipient: &protocol_fee_note_recipient.withdraw_authority,
                relay_fee_recipient: &relay_fee_note_recipient.withdraw_authority,
                protocol_fee_note_recipient: &protocol_fee_note_recipient,
                relay_fee_note_recipient: &relay_fee_note_recipient,
                liquidity_attribution_signer_private_key: "0x12345",
            },
        );

        assert!(matches!(result, Err(StatusCode::CONFLICT)));
    }

    #[test]
    fn settlement_artifacts_preserve_per_order_output_metadata_for_same_recipient() {
        let mut product_config = ProductConfig::default_v1();
        let pair_id = PairId("STRK/USDC".into());
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .price_base_scale = 1;
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .min_order_amount = 1;
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let mut records = vec![
            valid_test_record(
                0,
                OrderSide::Buy,
                10,
                10,
                1,
                TimeInForce::CurrentBatchOnly,
                100,
            ),
            valid_test_record(
                1,
                OrderSide::Buy,
                10,
                10,
                1,
                TimeInForce::CurrentBatchOnly,
                100,
            ),
            valid_test_record(
                2,
                OrderSide::Sell,
                10,
                10,
                1,
                TimeInForce::CurrentBatchOnly,
                10,
            ),
            valid_test_record(
                3,
                OrderSide::Sell,
                10,
                10,
                1,
                TimeInForce::CurrentBatchOnly,
                10,
            ),
        ];
        let buyer_owner_public_key = note_recognition_public_key_from_raw_key_hex(&"11".repeat(32))
            .expect("buyer owner public key");
        let seller_owner_public_key =
            note_recognition_public_key_from_raw_key_hex(&"22".repeat(32))
                .expect("seller owner public key");
        for index in [0_usize, 1] {
            records[index].order.recipient_owner_public_key = buyer_owner_public_key.clone();
            records[index].order_commitment = records[index]
                .order
                .commitment()
                .expect("buy order commitment");
        }
        for index in [2_usize, 3] {
            records[index].order.recipient_owner_public_key = seller_owner_public_key.clone();
            records[index].order_commitment = records[index]
                .order
                .commitment()
                .expect("sell order commitment");
        }
        let order_commitments = records
            .iter()
            .map(|record| record.order_commitment.0.clone())
            .collect::<Vec<_>>();
        let batch = BatchSummary {
            batch_id: BatchId("batch-strk-usdc-1".into()),
            pair_id,
            epoch_id: 1,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: records.len() as u64,
            order_commitment_root: ordered_felt_list_commitment(
                "zylith/batch-order-root",
                &order_commitments,
            )
            .expect("order root"),
            encrypted_order_set_commitment: "0x222".into(),
        };

        let protocol_fee_note_recipient = test_fee_note_recipient("91", "0xf01");
        let relay_fee_note_recipient = test_fee_note_recipient("92", "0xf02");
        let artifacts = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            &[],
            SettlementBuildContext {
                product_config: &product_config,
                liquidity_position_market_contexts: &LiquidityPositionMarketContexts::default(),
                prior_roots: &SettlementRoots::zero(),
                initial_note_root: "0x0",
                deposit_activations: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_renewal_cancel_markers: &[],
                prior_note_consolidation_history: &[],
                prior_withdrawal_nullifiers: &[],
                protocol_fee_recipient: &protocol_fee_note_recipient.withdraw_authority,
                relay_fee_recipient: &relay_fee_note_recipient.withdraw_authority,
                protocol_fee_note_recipient: &protocol_fee_note_recipient,
                relay_fee_note_recipient: &relay_fee_note_recipient,
                liquidity_attribution_signer_private_key: "0x12345",
            },
        )
        .expect("netted artifacts");

        assert_eq!(artifacts.transcript.matched_orders.len(), 4);
        assert_eq!(artifacts.transcript.output_notes.len(), 6);
        assert_eq!(artifacts.output_bundle.ciphertext_count_bucket, "5-8");
        let user_output_commitments = artifacts
            .settlement_witness
            .matched_order_witnesses
            .iter()
            .map(|witness| witness.output_note.commitment().expect("output commitment"))
            .collect::<Vec<_>>();
        let user_outputs = artifacts
            .transcript
            .output_notes
            .iter()
            .filter(|note| user_output_commitments.contains(&note.note_commitment))
            .collect::<Vec<_>>();
        assert_eq!(user_outputs.len(), 4);
        let buy_outputs = user_outputs
            .iter()
            .filter(|note| note.asset_id.0 == "STRK")
            .collect::<Vec<_>>();
        let sell_outputs = user_outputs
            .iter()
            .filter(|note| note.asset_id.0 == "USDC")
            .collect::<Vec<_>>();
        assert_eq!(buy_outputs.len(), 2);
        assert_eq!(sell_outputs.len(), 2);
        assert!(buy_outputs.iter().all(|note| note.amount == 9));
        assert!(sell_outputs.iter().all(|note| note.amount == 99));
        assert!(
            artifacts
                .settlement_witness
                .output_note_preimages
                .iter()
                .all(|note| note.nonce > 0),
            "netted output notes must keep proof-valid non-zero nonces",
        );
        let first_buy_commitment = artifacts.settlement_witness.matched_order_witnesses[0]
            .output_note
            .commitment()
            .expect("buy output commitment");
        assert!(
            artifacts
                .transcript
                .output_notes
                .iter()
                .any(|note| note.note_commitment == first_buy_commitment)
        );
        assert_ne!(
            first_buy_commitment,
            artifacts.settlement_witness.matched_order_witnesses[1]
                .output_note
                .commitment()
                .expect("second buy output commitment"),
        );
    }

    #[test]
    fn nullifier_freshness_rejects_current_batch_duplicates() {
        let mut records = vec![
            test_record(
                0,
                OrderSide::Buy,
                10,
                2,
                1,
                TimeInForce::CurrentBatchOnly,
                20,
            ),
            test_record(
                1,
                OrderSide::Sell,
                5,
                1,
                1,
                TimeInForce::CurrentBatchOnly,
                1,
            ),
        ];
        records[1].order.funding_nullifier = records[0].order.funding_nullifier.clone();
        records[1].funding_note = records[0].funding_note.clone();
        records[1].funding_notes = vec![records[0].funding_note.clone()];
        let historical = Vec::<SettlementWitness>::new();

        let error =
            validate_batch_nullifier_freshness("batch-strk-usdc-1", &records, historical.iter())
                .expect_err("duplicate current nullifier rejected");

        assert!(error.contains("duplicate funding nullifier"));
    }

    #[test]
    fn nullifier_freshness_allows_historical_replay_for_no_fill_filtering() {
        let records = vec![test_record(
            0,
            OrderSide::Buy,
            10,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        )];
        let historical = [historical_witness_with_nullifier(
            "batch-strk-usdc-0",
            records[0].order.funding_nullifier.clone(),
        )];

        validate_batch_nullifier_freshness("batch-strk-usdc-1", &records, historical.iter())
            .expect("historically spent notes are filtered as no-fill during settlement");
    }

    #[test]
    fn root_history_selection_accepts_consolidation_nullifier_transition() {
        let settlement_input = consumed_input("0x101", "0x201");
        let consolidation_input = consumed_input("0x102", "0x202");
        let witness = historical_witness_with_consumed_inputs(
            "batch-strk-usdc-0",
            0,
            vec![settlement_input.clone()],
        );
        let roots = SettlementRoots {
            nullifier_root: nullifier_root_for_consumed_inputs(&[
                settlement_input,
                consolidation_input.clone(),
            ]),
            renewal_root: "0x0".into(),
            note_root: "0x0".into(),
            fee_root: "0x0".into(),
            liquidity_position_root: "0x0".into(),
        };
        let consolidation_history = NoteConsolidationHistoryRecord {
            consolidation_id: BatchId("consolidation-1".into()),
            consumed_inputs: vec![consolidation_input],
            output_notes: Vec::new(),
        };

        let selected = select_root_history_witnesses_for_current_roots(
            vec![witness.clone()],
            &roots,
            &[consolidation_history],
            &[],
            &[],
        )
        .expect("consolidation nullifier transition is part of current root");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].batch_id, witness.batch_id);
    }

    #[test]
    fn root_history_selection_accepts_withdrawal_nullifier_transition() {
        let settlement_input = consumed_input("0x111", "0x211");
        let withdrawal_input = consumed_input("0x112", "0x212");
        let witness = historical_witness_with_consumed_inputs(
            "batch-strk-usdc-0",
            0,
            vec![settlement_input.clone()],
        );
        let roots = SettlementRoots {
            nullifier_root: nullifier_root_for_consumed_inputs(&[
                settlement_input,
                withdrawal_input.clone(),
            ]),
            renewal_root: "0x0".into(),
            note_root: "0x0".into(),
            fee_root: "0x0".into(),
            liquidity_position_root: "0x0".into(),
        };

        let selected = select_root_history_witnesses_for_current_roots(
            vec![witness.clone()],
            &roots,
            &[],
            &[withdrawal_input],
            &[],
        )
        .expect("withdrawal nullifier transition is part of current root");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].batch_id, witness.batch_id);
    }

    #[test]
    fn root_history_selection_excludes_unconfirmed_future_witness() {
        let confirmed_input = consumed_input("0x121", "0x221");
        let future_input = consumed_input("0x122", "0x222");
        let consolidation_input = consumed_input("0x123", "0x223");
        let confirmed = historical_witness_with_consumed_inputs(
            "batch-strk-usdc-0",
            0,
            vec![confirmed_input.clone()],
        );
        let future =
            historical_witness_with_consumed_inputs("batch-strk-usdc-1", 1, vec![future_input]);
        let roots = SettlementRoots {
            nullifier_root: nullifier_root_for_consumed_inputs(&[
                confirmed_input,
                consolidation_input.clone(),
            ]),
            renewal_root: "0x0".into(),
            note_root: "0x0".into(),
            fee_root: "0x0".into(),
            liquidity_position_root: "0x0".into(),
        };
        let consolidation_history = NoteConsolidationHistoryRecord {
            consolidation_id: BatchId("consolidation-1".into()),
            consumed_inputs: vec![consolidation_input],
            output_notes: Vec::new(),
        };

        let selected = select_root_history_witnesses_for_current_roots(
            vec![confirmed.clone(), future],
            &roots,
            &[consolidation_history],
            &[],
            &[],
        )
        .expect("only the settled prefix matches current roots");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].batch_id, confirmed.batch_id);
    }

    #[test]
    fn root_history_selection_skips_stale_disconnected_lineage() {
        let first_input = consumed_input("0x131", "0x231");
        let stale_input = consumed_input("0x132", "0x232");
        let current_input = consumed_input("0x133", "0x233");
        let maintenance_input = consumed_input("0x134", "0x234");

        let mut first = historical_witness_with_consumed_inputs(
            "batch-strk-eth-45",
            45,
            vec![first_input.clone()],
        );
        first.renewal_child_uses = vec![RenewalChildUse {
            parent_order_commitment: "0xabc".into(),
            child_nullifier: "0x301".into(),
        }];
        first.new_renewal_root = renewal_root_for_entries(&["0x301"]);

        let mut stale =
            historical_witness_with_consumed_inputs("batch-strk-eth-1311", 1311, vec![stale_input]);
        stale.renewal_child_uses = vec![RenewalChildUse {
            parent_order_commitment: "0xdef".into(),
            child_nullifier: "0x302".into(),
        }];
        stale.new_renewal_root = renewal_root_for_entries(&["0x302"]);

        let mut current = historical_witness_with_consumed_inputs(
            "batch-strk-eth-35825",
            35825,
            vec![current_input.clone()],
        );
        current.prior_nullifier_root =
            nullifier_root_for_consumed_inputs(&[first_input.clone(), maintenance_input.clone()]);
        current.new_nullifier_root = nullifier_root_for_consumed_inputs(&[
            first_input.clone(),
            maintenance_input.clone(),
            current_input,
        ]);
        current.prior_renewal_root = first.new_renewal_root.clone();
        current.renewal_child_uses = vec![RenewalChildUse {
            parent_order_commitment: "0x456".into(),
            child_nullifier: "0x303".into(),
        }];
        current.new_renewal_root = renewal_root_for_entries(&["0x301", "0x303"]);

        let roots = SettlementRoots {
            nullifier_root: current.new_nullifier_root.clone(),
            renewal_root: current.new_renewal_root.clone(),
            note_root: "0x0".into(),
            fee_root: "0x0".into(),
            liquidity_position_root: "0x0".into(),
        };
        let consolidation_history = NoteConsolidationHistoryRecord {
            consolidation_id: BatchId("consolidation-1".into()),
            consumed_inputs: vec![maintenance_input],
            output_notes: Vec::new(),
        };

        let selected = select_root_history_witnesses_for_current_roots(
            vec![first.clone(), stale, current.clone()],
            &roots,
            &[consolidation_history],
            &[],
            &[],
        )
        .expect("stale disconnected root-history branches must be ignored");

        let selected_ids = selected
            .iter()
            .map(|witness| witness.batch_id.0.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            selected_ids,
            vec![first.batch_id.0.as_str(), current.batch_id.0.as_str()]
        );
    }

    #[test]
    fn root_history_selection_accepts_renewal_cancel_marker_transition() {
        let mut witness =
            historical_witness_with_consumed_inputs("batch-strk-usdc-0", 0, Vec::new());
        witness.renewal_child_uses = vec![RenewalChildUse {
            parent_order_commitment: "0xabc".into(),
            child_nullifier: "0x301".into(),
        }];
        witness.new_renewal_root = renewal_root_for_entries(&["0x301"]);
        let roots = SettlementRoots {
            nullifier_root: "0x0".into(),
            renewal_root: renewal_root_for_entries(&["0x301", "0x302"]),
            note_root: "0x0".into(),
            fee_root: "0x0".into(),
            liquidity_position_root: "0x0".into(),
        };

        let selected = select_root_history_witnesses_for_current_roots(
            vec![witness.clone()],
            &roots,
            &[],
            &[],
            &["0x302".into()],
        )
        .expect("renewal cancel marker is part of current root");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].batch_id, witness.batch_id);
    }

    #[test]
    fn settlement_submission_jitter_is_batch_bound_and_capped() {
        let same = deterministic_settlement_submission_jitter_ms("batch-strk-usdc-1", 1_000);
        assert_eq!(
            same,
            deterministic_settlement_submission_jitter_ms("batch-strk-usdc-1", 1_000)
        );
        assert!(same <= 1_000);
        assert_eq!(
            deterministic_settlement_submission_jitter_ms("batch-strk-usdc-1", 0),
            0
        );
    }

    fn consumed_input(note_commitment: &str, nullifier: &str) -> ConsumedInput {
        ConsumedInput {
            note_commitment: NoteCommitment(note_commitment.into()),
            nullifier: Nullifier(nullifier.into()),
        }
    }

    fn nullifier_root_for_consumed_inputs(consumed_inputs: &[ConsumedInput]) -> String {
        let (_prior_root, root, _witnesses) =
            nullifier_sparse_update_witnesses_for_consumed_inputs(&[], consumed_inputs)
                .expect("nullifier root");
        root
    }

    fn renewal_root_for_entries(entries: &[&str]) -> String {
        let entries = entries
            .iter()
            .map(|entry| (*entry).to_string())
            .collect::<Vec<_>>();
        let (_prior_root, root, _child_witnesses, _cancel_witnesses) =
            renewal_sparse_witnesses_for_child_uses(&entries, &[], &[]).expect("renewal root");
        root
    }

    fn historical_witness_with_consumed_inputs(
        batch_id: &str,
        batch_epoch: u64,
        consumed_inputs: Vec<ConsumedInput>,
    ) -> SettlementWitness {
        let mut witness = historical_witness_with_nullifier(
            batch_id,
            consumed_inputs
                .first()
                .map(|input| input.nullifier.clone())
                .unwrap_or_else(|| Nullifier("0x1".into())),
        );
        witness.batch_epoch = batch_epoch;
        witness.consumed_inputs = consumed_inputs;
        witness.new_nullifier_root = nullifier_root_for_consumed_inputs(&witness.consumed_inputs);
        witness
    }

    fn historical_witness_with_nullifier(
        batch_id: &str,
        nullifier: Nullifier,
    ) -> SettlementWitness {
        SettlementWitness {
            batch_id: BatchId(batch_id.into()),
            pair_id: PairId("STRK/USDC".into()),
            batch_epoch: 1,
            order_commitment_root: "0x111".into(),
            encrypted_order_set_commitment: "0x222".into(),
            transcript_commitment: "0x333".into(),
            auction_verifier_address: "0x444".into(),
            prior_note_root: "0x0".into(),
            prior_nullifier_root: "0x0".into(),
            prior_renewal_root: "0x0".into(),
            prior_fee_root: "0x0".into(),
            prior_liquidity_position_root: "0x0".into(),
            new_nullifier_root: settlement_nullifier_root_after_history(&[NullifierHistoryBatch {
                repeat_count: 1,
                nullifiers: vec![nullifier.clone()],
            }])
            .expect("sparse nullifier root"),
            new_renewal_root: "0x0".into(),
            new_liquidity_position_root: "0x0".into(),
            clearing_price: 1,
            price_base_scale: 1,
            taker_fee_bps: 4,
            relay_fee_bps: 0,
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT.into(),
            base_asset_id: AssetId("STRK".into()),
            quote_asset_id: AssetId("USDC".into()),
            matched_orders: vec![],
            matched_order_witnesses: vec![],
            consumed_inputs: vec![ConsumedInput {
                note_commitment: NoteCommitment("0xabc".into()),
                nullifier,
            }],
            note_membership_witnesses: vec![],
            nullifier_history: vec![],
            nullifier_sparse_witnesses: vec![],
            renewal_history: vec![],
            renewal_child_sparse_witnesses: vec![],
            renewal_cancel_sparse_witnesses: vec![],
            renewal_child_uses: vec![],
            liquidity_position_transitions: vec![],
            liquidity_position_witnesses: vec![],
            fees: vec![],
            output_notes: vec![],
            output_note_preimages: vec![],
            output_recovery_records: vec![],
            output_recovery_dummy_commitments: vec![],
            output_ciphertext_bundle_ref: "bundle".into(),
        }
    }

    fn test_record(
        index: u64,
        side: OrderSide,
        limit_price: u128,
        amount: u128,
        min_fill: u128,
        time_in_force: TimeInForce,
        funding_amount: u128,
    ) -> DecryptedOrderRecord {
        let funding_note = Note {
            asset_id: AssetId(if matches!(side, OrderSide::Buy) {
                "USDC".into()
            } else {
                "STRK".into()
            }),
            amount: funding_amount,
            owner_public_key: "ab".repeat(32),
            spend_authority: "0x123".into(),
            withdraw_authority: "0x456".into(),
            blinding: format!("0x{:x}", 0x100 + index),
            nonce: index,
            metadata_commitment: format!("0x{:x}", 0x200 + index),
        };
        let recipient_owner_public_key =
            note_recognition_public_key_from_raw_key_hex(&format!("{:064x}", 0xcd_u64 + index))
                .expect("test recipient owner public key");
        let funding_note_ref = funding_note
            .commitment()
            .expect("test funding note commitment");
        let funding_nullifier =
            nullifier_from_note_secret(&funding_note_ref, &funding_note.blinding)
                .expect("test funding nullifier");
        let order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-1".into()),
            side,
            order_type: OrderType::LimitBatch,
            relay_mode: RelayMode::SelfRelay,
            liquidity_curve: None,
            limit_price,
            amount,
            min_fill,
            time_in_force,
            expiry_epoch: 1,
            order_nonce: index + 1,
            parent_order_commitment: "0x0".into(),
            parent_child_index: 0,
            parent_secret_commitment: "0x0".into(),
            parent_cancel_authority: "0x0".into(),
            parent_authorization_secret: "0x0".into(),
            funding_note_ref,
            funding_nullifier,
            recipient_owner_public_key,
            recipient_spend_authority: "0x789".into(),
            recipient_withdraw_authority: "0xabc".into(),
            recipient_residual_withdraw_authority: "0xabd".into(),
            auditor_view_allowed: false,
        };
        DecryptedOrderRecord {
            order_commitment: zylith_core::OrderCommitment(format!("0x{:x}", 0x500 + index)),
            cancellation_auth_tag: format!("test-cancel-auth-{index}"),
            order,
            funding_notes: vec![funding_note.clone()],
            funding_note,
            funding_authorization: SpendAuthorization {
                signature_r: "0x1".into(),
                signature_s: "0x2".into(),
            },
        }
    }

    #[test]
    fn private_order_shape_rejects_legacy_liquidity_curve_orders() {
        let record = test_record(
            801,
            OrderSide::Sell,
            100,
            10,
            1,
            TimeInForce::CurrentBatchOnly,
            10,
        );
        let mut order = record.order;
        order.order_type = OrderType::LiquidityCurve;
        order.liquidity_curve = Some(LiquidityCurve {
            points: vec![
                LiquidityCurvePoint {
                    price: 90,
                    base_amount: 3,
                },
                LiquidityCurvePoint {
                    price: 100,
                    base_amount: 3,
                },
                LiquidityCurvePoint {
                    price: 110,
                    base_amount: 4,
                },
            ],
        });

        let error = super::validate_private_order_shape_and_amount(1_000_000, &order)
            .expect_err("legacy liquidity curve orders are no longer accepted");

        assert_eq!(
            error,
            "legacy liquidity curve orders are disabled; open a private liquidity position lifecycle"
        );
    }

    #[test]
    fn settlement_artifacts_reject_dust_matched_outputs_before_proving() {
        let product_config = ProductConfig::default_v1();
        let pair_id = PairId("STRK/USDC".into());
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let records = vec![
            valid_test_record(
                0,
                OrderSide::Buy,
                300,
                10,
                1,
                TimeInForce::CurrentBatchOnly,
                1,
            ),
            valid_test_record(
                1,
                OrderSide::Sell,
                300,
                10,
                1,
                TimeInForce::CurrentBatchOnly,
                10,
            ),
        ];
        let order_commitments = records
            .iter()
            .map(|record| record.order_commitment.0.clone())
            .collect::<Vec<_>>();
        let batch = BatchSummary {
            batch_id: BatchId("batch-strk-usdc-1".into()),
            pair_id,
            epoch_id: 1,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: records.len() as u64,
            order_commitment_root: ordered_felt_list_commitment(
                "zylith/batch-order-root",
                &order_commitments,
            )
            .expect("order root"),
            encrypted_order_set_commitment: "0x222".into(),
        };

        let protocol_fee_note_recipient = test_fee_note_recipient("91", "0xf01");
        let relay_fee_note_recipient = test_fee_note_recipient("92", "0xf02");
        let result = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            &[],
            SettlementBuildContext {
                product_config: &product_config,
                liquidity_position_market_contexts: &LiquidityPositionMarketContexts::default(),
                prior_roots: &SettlementRoots::zero(),
                initial_note_root: "0x0",
                deposit_activations: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_renewal_cancel_markers: &[],
                prior_note_consolidation_history: &[],
                prior_withdrawal_nullifiers: &[],
                protocol_fee_recipient: &protocol_fee_note_recipient.withdraw_authority,
                relay_fee_recipient: &relay_fee_note_recipient.withdraw_authority,
                protocol_fee_note_recipient: &protocol_fee_note_recipient,
                relay_fee_note_recipient: &relay_fee_note_recipient,
                liquidity_attribution_signer_private_key: "0x12345",
            },
        );

        assert!(
            result.is_err(),
            "dust-sized matched outputs must not reach the Cairo statement",
        );
    }

    fn valid_test_record(
        index: u64,
        side: OrderSide,
        limit_price: u128,
        amount: u128,
        min_fill: u128,
        time_in_force: TimeInForce,
        funding_amount: u128,
    ) -> DecryptedOrderRecord {
        let mut record = test_record(
            index,
            side,
            limit_price,
            amount,
            min_fill,
            time_in_force,
            funding_amount,
        );
        record.order.funding_note_ref = record
            .funding_note
            .commitment()
            .expect("funding note commitment");
        record.order.funding_nullifier = nullifier_from_note_secret(
            &record.order.funding_note_ref,
            &record.funding_note.blinding,
        )
        .expect("funding nullifier");
        record.order_commitment = record.order.commitment().expect("order commitment");
        record
    }

    fn test_liquidity_position_open_lifecycle_witness(
        epoch: u64,
    ) -> zylith_core::LiquidityPositionTransitionWitness {
        const LP_AUTHORITY_SECRET: &str = "0x123456";

        let pair_id = PairId("STRK/USDC".into());
        let owner_authority =
            zylith_core::liquidity_position_private_authority(LP_AUTHORITY_SECRET)
                .expect("position owner authority");
        let owner_public_key = note_recognition_public_key_from_raw_key_hex(&"ab".repeat(32))
            .expect("position owner note key");
        let position = zylith_core::PrivateLiquidityPosition {
            version: zylith_core::LIQUIDITY_POSITION_VERSION,
            position_id: "0x7001".into(),
            backing: zylith_core::LiquidityPositionBacking::PrivateReserve,
            status: zylith_core::LiquidityPositionStatus::Active,
            pair_id,
            base_asset_id: AssetId("STRK".into()),
            quote_asset_id: AssetId("USDC".into()),
            owner_authority: owner_authority.clone(),
            base_reserve: 10_000,
            quote_reserve: 1_000_000,
            price_lower_bound: 90,
            price_upper_bound: 120,
            max_fill_base_per_batch: 1_000,
            curve_policy: zylith_core::LiquidityPositionCurvePolicy {
                kind: zylith_core::LiquidityPositionCurveKind::StaticRange,
                band_count: 3,
                spread_bps: 40,
                target_base_ratio_bps: 5_000,
                inventory_skew_bps: 0,
                max_price_deviation_bps: 0,
            },
            oracle_guard: None,
            rotation_policy: zylith_core::LiquidityPositionRotationPolicy {
                max_price_rotation_bps: 0,
                max_depth_rotation_bps: 0,
                skip_epoch_bps: 0,
            },
            opened_epoch: epoch,
            expiry_epoch: epoch + 20,
            blinding: format!("0x{:x}", 0x900 + epoch),
            metadata_commitment: "0x0".into(),
        };
        let base_input_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: position.base_reserve,
            owner_public_key: owner_public_key.clone(),
            spend_authority: owner_authority.clone(),
            withdraw_authority: withdraw_authority_from_raw_key_hex(&"cd".repeat(32))
                .expect("base withdraw authority"),
            blinding: format!("0x{:x}", 0x8100 + epoch),
            nonce: epoch * 10 + 1,
            metadata_commitment: "0x0".into(),
        };
        let quote_input_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: position.quote_reserve + 100,
            owner_public_key: owner_public_key.clone(),
            spend_authority: owner_authority.clone(),
            withdraw_authority: withdraw_authority_from_raw_key_hex(&"ef".repeat(32))
                .expect("quote withdraw authority"),
            blinding: format!("0x{:x}", 0x8200 + epoch),
            nonce: epoch * 10 + 2,
            metadata_commitment: "0x0".into(),
        };
        let quote_change_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 100,
            owner_public_key,
            spend_authority: owner_authority,
            withdraw_authority: withdraw_authority_from_raw_key_hex(&"12".repeat(32))
                .expect("change withdraw authority"),
            blinding: format!("0x{:x}", 0x8300 + epoch),
            nonce: epoch * 10 + 3,
            metadata_commitment: "0x0".into(),
        };
        let transition = zylith_core::liquidity_position_root_transition(
            LiquidityPositionTransitionKind::Open,
            None,
            Some(&position),
        )
        .expect("open transition");
        let open_authorization = zylith_core::sign_liquidity_position_transition(
            LP_AUTHORITY_SECRET,
            LiquidityPositionTransitionKind::Open,
            &position.position_id,
            None,
            transition.output_position_commitment.as_ref(),
            position.opened_epoch,
            0,
            0,
        )
        .expect("open authorization");
        let mut position_state = zylith_core::LiquidityPositionState::new();
        let (_prior_position_root, _new_position_root, state_update) = position_state
            .open(&position)
            .expect("position open state update");
        zylith_core::LiquidityPositionTransitionWitness {
            transition,
            prior_position: None,
            output_position: Some(position),
            state_update,
            epoch,
            fill: None,
            open_funding: Some(zylith_core::LiquidityPositionOpenFunding {
                input_notes: vec![base_input_note, quote_input_note],
                change_notes: vec![quote_change_note],
                authorization: open_authorization,
            }),
            output_notes: Vec::new(),
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        }
    }

    #[tokio::test]
    async fn private_liquidity_position_ingress_returns_receipt_bound_submission() {
        let app = build_app_with_config(test_app_config(Some("test-internal-token")))
            .expect("test app should build");
        let request = zylith_core::TrustedLiquidityPositionIngressRequest {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-1".into()),
            epoch_id: 1,
            transition_witness: test_liquidity_position_open_lifecycle_witness(1),
            ingress_telemetry: OrderIngressClientTelemetry {
                version: 1,
                client_build_ms: Some(20),
                private_submission_delay_ms: Some(100),
                client_elapsed_before_private_ingress_ms: Some(120),
                private_ingress_roundtrip_ms: None,
                client_elapsed_before_coordinator_ms: None,
                batch_time_remaining_before_private_ingress_ms: Some(25_000),
                batch_time_remaining_before_coordinator_ms: None,
                submission_safety_buffer_ms: Some(15_000),
            },
            padding: Some("0".repeat(128)),
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/private/liquidity-positions/lifecycle")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("serialize LP ingress request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read LP ingress response");
        let trusted_response: zylith_core::TrustedLiquidityPositionIngressResponse =
            serde_json::from_slice(&body).expect("decode LP ingress response");
        let receipt = trusted_response
            .coordinator_submission
            .ingress_receipt
            .as_ref()
            .expect("coordinator submission receipt");
        assert_eq!(receipt.lifecycle_id, trusted_response.receipt.lifecycle_id);
        assert_eq!(
            trusted_response.coordinator_submission.lifecycle_id,
            trusted_response.receipt.lifecycle_id
        );
        assert_eq!(
            trusted_response
                .coordinator_submission
                .transition_commitment,
            trusted_response.receipt.transition_commitment
        );
        zylith_core::validate_liquidity_position_ingress_receipt_for_manifest_with_secrets(
            &trusted_response.coordinator_submission,
            &["test-receipt-secret".into()],
        )
        .expect("receipt verifies against coordinator manifest");

        let duplicate_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/private/liquidity-positions/lifecycle")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("serialize duplicate request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("duplicate response");
        assert_eq!(duplicate_response.status(), StatusCode::OK);
        let duplicate_body = axum::body::to_bytes(duplicate_response.into_body(), usize::MAX)
            .await
            .expect("read duplicate response");
        let duplicate_trusted_response: zylith_core::TrustedLiquidityPositionIngressResponse =
            serde_json::from_slice(&duplicate_body).expect("decode duplicate response");
        assert_eq!(
            duplicate_trusted_response.receipt.lifecycle_id,
            trusted_response.receipt.lifecycle_id
        );
        assert_eq!(
            duplicate_trusted_response.receipt.payload_commitment,
            trusted_response.receipt.payload_commitment
        );
    }

    #[test]
    fn settlement_artifacts_include_liquidity_position_open_lifecycle() {
        const LP_AUTHORITY_SECRET: &str = "0x123456";

        let product_config =
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product config");
        let pair_id = PairId("STRK/USDC".into());
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let batch = BatchSummary {
            batch_id: BatchId("batch-strk-usdc-1".into()),
            pair_id: pair_id.clone(),
            epoch_id: 1,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: 1,
            order_commitment_root: ordered_felt_list_commitment("zylith/batch-order-root", &[])
                .expect("empty order root"),
            encrypted_order_set_commitment: "0x222".into(),
        };

        let owner_authority =
            zylith_core::liquidity_position_private_authority(LP_AUTHORITY_SECRET)
                .expect("position owner authority");
        let owner_public_key = note_recognition_public_key_from_raw_key_hex(&"ab".repeat(32))
            .expect("position owner note key");
        let position = zylith_core::PrivateLiquidityPosition {
            version: zylith_core::LIQUIDITY_POSITION_VERSION,
            position_id: "0x7001".into(),
            backing: zylith_core::LiquidityPositionBacking::PrivateReserve,
            status: zylith_core::LiquidityPositionStatus::Active,
            pair_id: pair_id.clone(),
            base_asset_id: AssetId("STRK".into()),
            quote_asset_id: AssetId("USDC".into()),
            owner_authority: owner_authority.clone(),
            base_reserve: 10_000,
            quote_reserve: 1_000_000,
            price_lower_bound: 90,
            price_upper_bound: 120,
            max_fill_base_per_batch: 1_000,
            curve_policy: zylith_core::LiquidityPositionCurvePolicy {
                kind: zylith_core::LiquidityPositionCurveKind::StaticRange,
                band_count: 3,
                spread_bps: 40,
                target_base_ratio_bps: 5_000,
                inventory_skew_bps: 0,
                max_price_deviation_bps: 0,
            },
            oracle_guard: None,
            rotation_policy: zylith_core::LiquidityPositionRotationPolicy {
                max_price_rotation_bps: 0,
                max_depth_rotation_bps: 0,
                skip_epoch_bps: 0,
            },
            opened_epoch: 1,
            expiry_epoch: 20,
            blinding: "0x902".into(),
            metadata_commitment: "0x0".into(),
        };

        let base_input_note = Note {
            asset_id: AssetId("STRK".into()),
            amount: position.base_reserve,
            owner_public_key: owner_public_key.clone(),
            spend_authority: owner_authority.clone(),
            withdraw_authority: withdraw_authority_from_raw_key_hex(&"cd".repeat(32))
                .expect("base withdraw authority"),
            blinding: "0x8101".into(),
            nonce: 1,
            metadata_commitment: "0x0".into(),
        };
        let quote_input_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: position.quote_reserve + 100,
            owner_public_key: owner_public_key.clone(),
            spend_authority: owner_authority.clone(),
            withdraw_authority: withdraw_authority_from_raw_key_hex(&"ef".repeat(32))
                .expect("quote withdraw authority"),
            blinding: "0x8102".into(),
            nonce: 2,
            metadata_commitment: "0x0".into(),
        };
        let quote_change_note = Note {
            asset_id: AssetId("USDC".into()),
            amount: 100,
            owner_public_key,
            spend_authority: owner_authority.clone(),
            withdraw_authority: withdraw_authority_from_raw_key_hex(&"12".repeat(32))
                .expect("change withdraw authority"),
            blinding: "0x8201".into(),
            nonce: 3,
            metadata_commitment: "0x0".into(),
        };

        let transition = zylith_core::liquidity_position_root_transition(
            LiquidityPositionTransitionKind::Open,
            None,
            Some(&position),
        )
        .expect("open transition");
        let open_authorization = zylith_core::sign_liquidity_position_transition(
            LP_AUTHORITY_SECRET,
            LiquidityPositionTransitionKind::Open,
            &position.position_id,
            None,
            transition.output_position_commitment.as_ref(),
            position.opened_epoch,
            0,
            0,
        )
        .expect("open authorization");
        let mut position_state = zylith_core::LiquidityPositionState::new();
        let (_prior_position_root, expected_position_root, state_update) = position_state
            .open(&position)
            .expect("position open state update");
        let lp_witness = zylith_core::LiquidityPositionTransitionWitness {
            transition,
            prior_position: None,
            output_position: Some(position),
            state_update,
            epoch: batch.epoch_id,
            fill: None,
            open_funding: Some(zylith_core::LiquidityPositionOpenFunding {
                input_notes: vec![base_input_note, quote_input_note],
                change_notes: vec![quote_change_note.clone()],
                authorization: open_authorization,
            }),
            output_notes: Vec::new(),
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        };

        let protocol_fee_note_recipient = test_fee_note_recipient("91", "0xf01");
        let relay_fee_note_recipient = test_fee_note_recipient("92", "0xf02");
        let artifacts = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &[],
            &[lp_witness],
            SettlementBuildContext {
                product_config: &product_config,
                liquidity_position_market_contexts: &LiquidityPositionMarketContexts::default(),
                prior_roots: &SettlementRoots::zero(),
                initial_note_root: "0x0",
                deposit_activations: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_renewal_cancel_markers: &[],
                prior_note_consolidation_history: &[],
                prior_withdrawal_nullifiers: &[],
                protocol_fee_recipient: &protocol_fee_note_recipient.withdraw_authority,
                relay_fee_recipient: &relay_fee_note_recipient.withdraw_authority,
                protocol_fee_note_recipient: &protocol_fee_note_recipient,
                relay_fee_note_recipient: &relay_fee_note_recipient,
                liquidity_attribution_signer_private_key: "0x12345",
            },
        )
        .expect("settlement artifacts");

        assert!(artifacts.transcript.matched_orders.is_empty());
        assert_eq!(artifacts.transcript.liquidity_position_transitions.len(), 1);
        assert_eq!(
            artifacts.transcript.new_liquidity_position_root,
            expected_position_root
        );
        assert_eq!(artifacts.settlement_witness.consumed_inputs.len(), 2);
        assert_eq!(
            artifacts
                .settlement_witness
                .liquidity_position_witnesses
                .len(),
            1
        );
        assert_eq!(
            artifacts.settlement_witness.output_note_preimages,
            vec![quote_change_note]
        );
        zylith_core::build_stwo_serialized_input(&artifacts.settlement_witness)
            .expect("serialize Stwo witness with LP lifecycle");
    }

    #[test]
    fn settlement_artifacts_do_not_fill_liquidity_positions_opened_in_same_batch() {
        let mut product_config =
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product config");
        let pair_id = PairId("STRK/USDC".into());
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .price_base_scale = 1;
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .min_order_amount = 1;
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let lp_witness = test_liquidity_position_open_lifecycle_witness(1);
        let opened_position = lp_witness
            .output_position
            .clone()
            .expect("open fixture has output position");
        let market_context = zylith_core::LiquidityPositionMarketContext {
            epoch: 1,
            observed_at_unix_ms: 1,
            current_time_unix_ms: 1,
            reference_price: 0,
            confirmation_price: None,
            price_base_scale: 1,
        };
        let curve_slice =
            zylith_core::derive_liquidity_position_curve_slice(&opened_position, &market_context)
                .expect("canonical position slice");
        let ask_point = curve_slice
            .ask
            .as_ref()
            .and_then(|curve| curve.points.first())
            .expect("ask liquidity");
        let requested_base = ask_point.base_amount.min(250);
        let mut buy_record = valid_test_record(
            902,
            OrderSide::Buy,
            ask_point.price,
            requested_base,
            1,
            TimeInForce::CurrentBatchOnly,
            requested_base * ask_point.price,
        );
        buy_record.order.pair_id = pair_id.clone();
        buy_record.order.batch_id = BatchId("batch-strk-usdc-1".into());
        buy_record.order.expiry_epoch = 1;
        buy_record.order_commitment = buy_record.order.commitment().expect("order commitment");
        let records = vec![buy_record];
        let batch = BatchSummary {
            batch_id: BatchId("batch-strk-usdc-1".into()),
            pair_id,
            epoch_id: 1,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: 1,
            order_commitment_root: ordered_felt_list_commitment(
                "zylith/batch-order-root",
                &records
                    .iter()
                    .map(|record| record.order_commitment.0.clone())
                    .collect::<Vec<_>>(),
            )
            .expect("order root"),
            encrypted_order_set_commitment: "0x222".into(),
        };

        let protocol_fee_note_recipient = test_fee_note_recipient("91", "0xf01");
        let relay_fee_note_recipient = test_fee_note_recipient("92", "0xf02");
        let artifacts = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            &[lp_witness],
            SettlementBuildContext {
                product_config: &product_config,
                liquidity_position_market_contexts: &LiquidityPositionMarketContexts::default(),
                prior_roots: &SettlementRoots::zero(),
                initial_note_root: "0x0",
                deposit_activations: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_renewal_cancel_markers: &[],
                prior_note_consolidation_history: &[],
                prior_withdrawal_nullifiers: &[],
                protocol_fee_recipient: &protocol_fee_note_recipient.withdraw_authority,
                relay_fee_recipient: &relay_fee_note_recipient.withdraw_authority,
                protocol_fee_note_recipient: &protocol_fee_note_recipient,
                relay_fee_note_recipient: &relay_fee_note_recipient,
                liquidity_attribution_signer_private_key: "0x12345",
            },
        )
        .expect("settlement artifacts");

        assert!(artifacts.transcript.matched_orders.is_empty());
        assert_eq!(
            artifacts
                .settlement_witness
                .liquidity_position_witnesses
                .len(),
            1,
            "same-batch LP opens should not materialize fill transitions"
        );
        assert_eq!(
            artifacts.settlement_witness.liquidity_position_witnesses[0]
                .transition
                .kind,
            LiquidityPositionTransitionKind::Open
        );
    }

    #[test]
    fn settlement_artifacts_reject_user_submitted_liquidity_position_fill_updates() {
        let product_config =
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product config");
        let pair_id = PairId("STRK/USDC".into());
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let batch = BatchSummary {
            batch_id: BatchId("batch-strk-usdc-2".into()),
            pair_id,
            epoch_id: 2,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: 0,
            order_commitment_root: ordered_felt_list_commitment("zylith/batch-order-root", &[])
                .expect("empty order root"),
            encrypted_order_set_commitment: "0x222".into(),
        };
        let open_witness = test_liquidity_position_open_lifecycle_witness(1);
        let prior_position = open_witness
            .output_position
            .expect("open fixture has output position");
        let mut position_state = zylith_core::LiquidityPositionState::from_positions(
            std::slice::from_ref(&prior_position),
        )
        .expect("position state");
        let prior_position_root = position_state.root().expect("prior position root");
        let market_context = zylith_core::LiquidityPositionMarketContext {
            epoch: batch.epoch_id,
            observed_at_unix_ms: 1,
            current_time_unix_ms: 1,
            reference_price: 0,
            confirmation_price: None,
            price_base_scale: 1,
        };
        let curve_slice =
            zylith_core::derive_liquidity_position_curve_slice(&prior_position, &market_context)
                .expect("canonical position slice");
        let ask_point = curve_slice
            .ask
            .as_ref()
            .and_then(|curve| curve.points.first())
            .expect("ask liquidity")
            .clone();
        let (output_position, _) = zylith_core::apply_liquidity_position_fill(
            &prior_position,
            OrderSide::Sell,
            ask_point.base_amount,
            ask_point.price,
            1,
            "0xdead02",
        )
        .expect("position fill");
        let (_, _, state_update) = position_state
            .replace(&prior_position, &output_position)
            .expect("position update");
        let transition = zylith_core::liquidity_position_root_transition(
            LiquidityPositionTransitionKind::Update,
            Some(&prior_position),
            Some(&output_position),
        )
        .expect("transition");
        let fill_witness = zylith_core::LiquidityPositionTransitionWitness {
            transition,
            prior_position: Some(prior_position),
            output_position: Some(output_position),
            state_update,
            epoch: batch.epoch_id,
            fill: Some(zylith_core::LiquidityPositionSettlementFill {
                market_context,
                position_side: OrderSide::Sell,
                filled_base_amount: ask_point.base_amount,
                clearing_price: ask_point.price,
                price_base_scale: 1,
            }),
            open_funding: None,
            output_notes: Vec::new(),
            base_amount: 0,
            quote_amount: 0,
            lifecycle_authorization: None,
        };
        let prior_roots = SettlementRoots {
            liquidity_position_root: prior_position_root,
            ..SettlementRoots::zero()
        };
        let protocol_fee_note_recipient = test_fee_note_recipient("91", "0xf01");
        let relay_fee_note_recipient = test_fee_note_recipient("92", "0xf02");

        let result = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &[],
            &[fill_witness],
            SettlementBuildContext {
                product_config: &product_config,
                liquidity_position_market_contexts: &LiquidityPositionMarketContexts::default(),
                prior_roots: &prior_roots,
                initial_note_root: "0x0",
                deposit_activations: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_renewal_cancel_markers: &[],
                prior_note_consolidation_history: &[],
                prior_withdrawal_nullifiers: &[],
                protocol_fee_recipient: &protocol_fee_note_recipient.withdraw_authority,
                relay_fee_recipient: &relay_fee_note_recipient.withdraw_authority,
                protocol_fee_note_recipient: &protocol_fee_note_recipient,
                relay_fee_note_recipient: &relay_fee_note_recipient,
                liquidity_attribution_signer_private_key: "0x12345",
            },
        );

        match result {
            Ok(_) => panic!("LP fills must be materialized by settlement"),
            Err(status) => assert_eq!(status, StatusCode::CONFLICT),
        }
    }

    #[test]
    fn liquidity_position_fill_sources_use_configured_oracle_context() {
        let mut product_config =
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product config");
        let pair_id = PairId("STRK/USDC".into());
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .price_base_scale = 1;
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let mut position = test_liquidity_position_open_lifecycle_witness(1)
            .output_position
            .expect("open fixture has output position");
        position.curve_policy.kind = zylith_core::LiquidityPositionCurveKind::OraclePegged;
        position.curve_policy.max_price_deviation_bps = 50;
        position.oracle_guard = Some(zylith_core::LiquidityPositionOracleGuard {
            oracle_id: "pragma-strk-usdc".into(),
            max_staleness_ms: 60_000,
            max_divergence_bps: 50,
        });

        let mut positions = BTreeMap::new();
        positions.insert(
            normalize_felt_hex(&position.position_id).expect("normalized position id"),
            super::ActiveLiquidityPositionRecord {
                position,
                owner_public_key: None,
            },
        );
        let book = super::ActiveLiquidityPositionBook { positions };
        let excluded = BTreeSet::new();
        let now = 10_000;
        let missing_context_sources = liquidity_position_fill_sources_for_batch(
            &book,
            &pair,
            2,
            now,
            now,
            &excluded,
            &LiquidityPositionMarketContexts::default(),
        )
        .expect("missing oracle context fails closed");
        assert!(
            missing_context_sources.is_empty(),
            "oracle-guarded LP positions must not quote without configured market context"
        );

        let market_contexts = parse_liquidity_position_market_contexts(
            r#"{"pairs":{"STRK/USDC":{"observed_at_unix_ms":"10000","reference_price":"100","confirmation_price":"100"}}}"#,
        )
        .expect("market context parses");
        let sources = liquidity_position_fill_sources_for_batch(
            &book,
            &pair,
            2,
            now,
            now,
            &excluded,
            &market_contexts,
        )
        .expect("oracle-guarded LP sources materialize");

        assert!(!sources.is_empty());
        assert!(sources.iter().any(|source| source.side == OrderSide::Buy));
        assert!(sources.iter().any(|source| source.side == OrderSide::Sell));
        assert!(sources.iter().all(|source| {
            source.market_context.reference_price == 100
                && source.market_context.confirmation_price == Some(100)
        }));
    }

    #[test]
    fn active_liquidity_position_book_reconstructs_nonempty_root_for_insertion_witnesses() {
        let open_witness = test_liquidity_position_open_lifecycle_witness(1);
        let opened_position = open_witness
            .output_position
            .clone()
            .expect("open fixture has output position");
        let expected_root = zylith_core::LiquidityPositionState::from_positions(
            std::slice::from_ref(&opened_position),
        )
        .expect("position state")
        .root()
        .expect("position root");
        let mut historical =
            historical_witness_with_consumed_inputs("batch-strk-usdc-1", 1, Vec::new());
        historical.prior_liquidity_position_root = "0x0".into();
        historical.new_liquidity_position_root = expected_root.clone();
        historical.liquidity_position_transitions = vec![open_witness.transition.clone()];
        historical.liquidity_position_witnesses = vec![open_witness];

        let book = active_liquidity_position_book_for_root(&expected_root, &[historical])
            .expect("active book");
        let new_commitment = LiquidityPositionCommitment("0x700200".into());
        let (prior_root, new_root, update) = book
            .state()
            .expect("state")
            .insertion_update("0x7002", new_commitment.clone())
            .expect("insertion witness");

        assert_eq!(prior_root, expected_root);
        assert_ne!(new_root, expected_root);
        assert_eq!(update.prior_commitment, None);
        assert_eq!(update.output_commitment, Some(new_commitment));
    }

    #[tokio::test]
    async fn private_liquidity_position_state_returns_latest_active_position() {
        let data_dir = std::env::temp_dir().join(format!(
            "zylith-prover-lp-state-{}-{}",
            std::process::id(),
            super::now_unix_ms()
        ));
        let _ = fs::remove_dir_all(&data_dir);

        let open_witness = test_liquidity_position_open_lifecycle_witness(1);
        let opened_position = open_witness
            .output_position
            .clone()
            .expect("open fixture has output position");
        let opened_root = zylith_core::LiquidityPositionState::from_positions(
            std::slice::from_ref(&opened_position),
        )
        .expect("position state")
        .root()
        .expect("position root");
        let mut historical =
            historical_witness_with_consumed_inputs("batch-strk-usdc-1", 1, Vec::new());
        historical.prior_liquidity_position_root = "0x0".into();
        historical.new_liquidity_position_root = opened_root.clone();
        historical.liquidity_position_transitions = vec![open_witness.transition.clone()];
        historical.liquidity_position_witnesses = vec![open_witness];
        super::persist_record(
            &data_dir,
            super::SETTLEMENT_WITNESSES_DIR,
            &historical.batch_id.0,
            &historical,
        )
        .expect("persist historical settlement witness");

        let mut confirmed = sample_onchain_submission();
        confirmed.batch_id = historical.batch_id.clone();
        confirmed.submission_id = format!("{}:0xabc", confirmed.batch_id.0);
        confirmed.execution_status = Some("SUCCEEDED".into());
        confirmed.finality_status = Some("ACCEPTED_ON_L2".into());
        super::persist_record(
            &data_dir,
            super::ONCHAIN_SUBMISSIONS_DIR,
            &onchain_submission_storage_key(&confirmed),
            &confirmed,
        )
        .expect("persist confirmed onchain submission");

        let mut config = test_app_config(Some("test-internal-token"));
        config.data_dir = data_dir.clone();
        let app = build_app_with_config(config).expect("test app should build");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/private/liquidity-positions/state")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "position_id": opened_position.position_id.clone(),
                            "owner_authority": opened_position.owner_authority.clone(),
                            "prior_liquidity_position_root": opened_root.clone(),
                            "padding": "x".repeat(64),
                        }))
                        .expect("serialize state request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("state response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read state response");
        let state: super::LiquidityPositionStateResponse =
            serde_json::from_slice(&body).expect("decode state response");
        assert_eq!(state.prior_liquidity_position_root, opened_root);
        assert_eq!(state.position.position_id, "0x7001");
        assert_eq!(
            state.position_commitment,
            state.position.commitment().expect("position commitment")
        );

        let forbidden = app
            .oneshot(
                Request::builder()
                    .uri("/api/private/liquidity-positions/state")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "position_id": "0x7001",
                            "owner_authority": "0x9999",
                            "prior_liquidity_position_root": state.prior_liquidity_position_root,
                        }))
                        .expect("serialize wrong owner state request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("forbidden state response");
        assert_eq!(forbidden.status(), StatusCode::NOT_FOUND);

        fs::remove_dir_all(data_dir).expect("remove test data dir");
    }

    #[tokio::test]
    async fn private_liquidity_position_state_update_witness_supports_lifecycle_updates() {
        let data_dir = std::env::temp_dir().join(format!(
            "zylith-prover-lp-state-update-witness-{}-{}",
            std::process::id(),
            super::now_unix_ms()
        ));
        let _ = fs::remove_dir_all(&data_dir);

        let open_witness = test_liquidity_position_open_lifecycle_witness(1);
        let opened_position = open_witness
            .output_position
            .clone()
            .expect("open fixture has output position");
        let opened_root = zylith_core::LiquidityPositionState::from_positions(
            std::slice::from_ref(&opened_position),
        )
        .expect("position state")
        .root()
        .expect("position root");
        let mut historical =
            historical_witness_with_consumed_inputs("batch-strk-usdc-1", 1, Vec::new());
        historical.prior_liquidity_position_root = "0x0".into();
        historical.new_liquidity_position_root = opened_root.clone();
        historical.liquidity_position_transitions = vec![open_witness.transition.clone()];
        historical.liquidity_position_witnesses = vec![open_witness];
        super::persist_record(
            &data_dir,
            super::SETTLEMENT_WITNESSES_DIR,
            &historical.batch_id.0,
            &historical,
        )
        .expect("persist historical settlement witness");

        let mut confirmed = sample_onchain_submission();
        confirmed.batch_id = historical.batch_id.clone();
        confirmed.submission_id = format!("{}:0xabc", confirmed.batch_id.0);
        confirmed.execution_status = Some("SUCCEEDED".into());
        confirmed.finality_status = Some("ACCEPTED_ON_L2".into());
        super::persist_record(
            &data_dir,
            super::ONCHAIN_SUBMISSIONS_DIR,
            &onchain_submission_storage_key(&confirmed),
            &confirmed,
        )
        .expect("persist confirmed onchain submission");

        let mut config = test_app_config(Some("test-internal-token"));
        config.data_dir = data_dir.clone();
        let app = build_app_with_config(config).expect("test app should build");

        let prior_commitment = opened_position.commitment().expect("prior commitment");
        let mut reconfigured = opened_position.clone();
        reconfigured.expiry_epoch += 1;
        reconfigured.max_fill_base_per_batch /= 2;
        reconfigured.blinding = "0x777777".into();
        reconfigured.metadata_commitment = "0x888888".into();
        let output_commitment = reconfigured.commitment().expect("output commitment");
        let replacement_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/private/liquidity-positions/state-update-witness")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "kind": "reconfigure",
                            "position_id": opened_position.position_id.clone(),
                            "prior_commitment": prior_commitment,
                            "output_commitment": output_commitment,
                            "prior_liquidity_position_root": opened_root.clone(),
                            "padding": "x".repeat(128),
                        }))
                        .expect("serialize replacement witness request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("replacement response");
        assert_eq!(replacement_response.status(), StatusCode::OK);
        let replacement_body = axum::body::to_bytes(replacement_response.into_body(), usize::MAX)
            .await
            .expect("read replacement response");
        let replacement: LiquidityPositionInsertionWitnessResponse =
            serde_json::from_slice(&replacement_body).expect("decode replacement response");
        assert_eq!(replacement.prior_liquidity_position_root, opened_root);
        assert_eq!(
            zylith_core::verify_liquidity_position_state_update(
                &replacement.prior_liquidity_position_root,
                &replacement.state_update,
            )
            .expect("replacement update verifies"),
            replacement.new_liquidity_position_root
        );
        assert_ne!(
            replacement.new_liquidity_position_root,
            replacement.prior_liquidity_position_root
        );

        let close_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/private/liquidity-positions/state-update-witness")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "kind": "close",
                            "position_id": opened_position.position_id.clone(),
                            "prior_commitment": opened_position.commitment().expect("close prior commitment"),
                            "prior_liquidity_position_root": opened_root.clone(),
                        }))
                        .expect("serialize removal witness request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("close response");
        assert_eq!(close_response.status(), StatusCode::OK);
        let close_body = axum::body::to_bytes(close_response.into_body(), usize::MAX)
            .await
            .expect("read close response");
        let close: LiquidityPositionInsertionWitnessResponse =
            serde_json::from_slice(&close_body).expect("decode close response");
        assert_eq!(close.prior_liquidity_position_root, opened_root);
        assert_eq!(close.new_liquidity_position_root, "0x0");
        assert_eq!(
            zylith_core::verify_liquidity_position_state_update(
                &close.prior_liquidity_position_root,
                &close.state_update,
            )
            .expect("close update verifies"),
            "0x0"
        );

        fs::remove_dir_all(data_dir).expect("remove test data dir");
    }

    #[test]
    fn settlement_artifacts_materialize_liquidity_position_fill_updates() {
        let mut product_config =
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product config");
        let pair_id = PairId("STRK/USDC".into());
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .price_base_scale = 1;
        product_config
            .pairs
            .get_mut(&pair_id.0)
            .expect("test pair")
            .min_order_amount = 1;
        let pair = product_config
            .enabled_pair(&pair_id)
            .expect("enabled pair")
            .clone();
        let open_witness = test_liquidity_position_open_lifecycle_witness(1);
        let prior_position = open_witness
            .output_position
            .clone()
            .expect("open fixture has output position");
        let prior_position_root = zylith_core::LiquidityPositionState::from_positions(
            std::slice::from_ref(&prior_position),
        )
        .expect("position state")
        .root()
        .expect("prior position root");
        let mut prior_witness =
            historical_witness_with_consumed_inputs("batch-strk-usdc-1", 1, Vec::new());
        prior_witness.prior_liquidity_position_root = "0x0".into();
        prior_witness.new_liquidity_position_root = prior_position_root.clone();
        prior_witness.liquidity_position_transitions = vec![open_witness.transition.clone()];
        prior_witness.liquidity_position_witnesses = vec![open_witness];

        let batch = BatchSummary {
            batch_id: BatchId("batch-strk-usdc-2".into()),
            pair_id: pair_id.clone(),
            epoch_id: 2,
            close_time_unix_ms: 0,
            status: BatchStatus::Closed,
            order_count: 1,
            order_commitment_root: "0x0".into(),
            encrypted_order_set_commitment: "0x222".into(),
        };
        let market_context = zylith_core::LiquidityPositionMarketContext {
            epoch: batch.epoch_id,
            observed_at_unix_ms: 1,
            current_time_unix_ms: 1,
            reference_price: 0,
            confirmation_price: None,
            price_base_scale: 1,
        };
        let curve_slice =
            zylith_core::derive_liquidity_position_curve_slice(&prior_position, &market_context)
                .expect("canonical position slice");
        let ask_point = curve_slice
            .ask
            .as_ref()
            .and_then(|curve| curve.points.first())
            .expect("ask liquidity");
        let requested_base = ask_point.base_amount.min(250);
        let mut buy_record = valid_test_record(
            901,
            OrderSide::Buy,
            ask_point.price,
            requested_base,
            1,
            TimeInForce::CurrentBatchOnly,
            requested_base * ask_point.price,
        );
        buy_record.order.pair_id = pair_id;
        buy_record.order.batch_id = batch.batch_id.clone();
        buy_record.order.expiry_epoch = batch.epoch_id;
        buy_record.order_commitment = buy_record.order.commitment().expect("order commitment");
        let records = vec![buy_record];
        let mut batch = batch;
        batch.order_commitment_root = ordered_felt_list_commitment(
            "zylith/batch-order-root",
            &records
                .iter()
                .map(|record| record.order_commitment.0.clone())
                .collect::<Vec<_>>(),
        )
        .expect("order root");

        let protocol_fee_note_recipient = test_fee_note_recipient("91", "0xf01");
        let relay_fee_note_recipient = test_fee_note_recipient("92", "0xf02");
        let artifacts = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            &[],
            SettlementBuildContext {
                product_config: &product_config,
                liquidity_position_market_contexts: &LiquidityPositionMarketContexts::default(),
                prior_roots: &SettlementRoots {
                    liquidity_position_root: prior_position_root.clone(),
                    ..SettlementRoots::zero()
                },
                initial_note_root: "0x0",
                deposit_activations: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[prior_witness],
                prior_renewal_cancel_markers: &[],
                prior_note_consolidation_history: &[],
                prior_withdrawal_nullifiers: &[],
                protocol_fee_recipient: &protocol_fee_note_recipient.withdraw_authority,
                relay_fee_recipient: &relay_fee_note_recipient.withdraw_authority,
                protocol_fee_note_recipient: &protocol_fee_note_recipient,
                relay_fee_note_recipient: &relay_fee_note_recipient,
                liquidity_attribution_signer_private_key: "0x12345",
            },
        )
        .expect("settlement artifacts");

        assert_eq!(artifacts.transcript.matched_orders.len(), 1);
        assert_eq!(
            artifacts.transcript.matched_orders[0].filled_amount,
            requested_base
        );
        assert_eq!(artifacts.transcript.liquidity_position_transitions.len(), 1);
        assert_eq!(
            artifacts.transcript.liquidity_position_transitions[0].kind,
            LiquidityPositionTransitionKind::Update
        );
        let fill_witness = artifacts
            .settlement_witness
            .liquidity_position_witnesses
            .first()
            .expect("materialized fill witness");
        assert_eq!(
            fill_witness
                .fill
                .as_ref()
                .map(|fill| fill.position_side.clone()),
            Some(OrderSide::Sell)
        );
        assert_ne!(
            artifacts.transcript.new_liquidity_position_root,
            prior_position_root
        );
        let attribution_bundle = artifacts
            .liquidity_provider_attribution_bundle
            .as_ref()
            .expect("LP fill emits attribution bundle");
        assert_eq!(attribution_bundle.version, 1);
        assert_eq!(attribution_bundle.batch_id, batch.batch_id);
        assert_eq!(attribution_bundle.artifacts.len(), 1);
        zylith_core::validate_liquidity_attribution_receipt(
            &attribution_bundle.artifacts[0].receipt,
        )
        .expect("attribution receipt verifies");
        let decrypted = zylith_core::decrypt_liquidity_attribution_artifact(
            &"ab".repeat(32),
            &attribution_bundle.artifacts[0],
        )
        .expect("decrypt attribution artifact")
        .expect("artifact is addressed to LP");
        let settlement_fill = fill_witness.fill.as_ref().expect("LP settlement fill");
        assert_eq!(decrypted.batch_id, batch.batch_id);
        assert_eq!(decrypted.pair_id, pair.pair_id);
        assert_eq!(decrypted.epoch_id, batch.epoch_id);
        assert_eq!(decrypted.attribution.side, OrderSide::Sell);
        assert_eq!(
            decrypted.attribution.clearing_price,
            settlement_fill.clearing_price
        );
        assert_eq!(decrypted.attribution.filled_base_amount, requested_base);
        assert_eq!(
            decrypted
                .attribution
                .bands
                .iter()
                .map(|band| band.filled_base_amount)
                .sum::<u128>(),
            requested_base
        );
        assert_eq!(
            Some(decrypted.output_note_commitment.0.as_str()),
            fill_witness
                .transition
                .output_position_commitment
                .as_ref()
                .map(|commitment| commitment.0.as_str())
        );
        zylith_core::build_stwo_serialized_input(&artifacts.settlement_witness)
            .expect("serialize settlement witness with generated LP fill");
    }
}

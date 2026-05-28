#![recursion_limit = "256"]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Cursor,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::OsRng;
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
    sync::RwLock,
    task,
    time::{Duration, sleep},
};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use url::Url;
use zylith_core::hash::{encode_starknet_felt, normalize_felt_hex, ordered_felt_list_commitment};
use zylith_core::{
    AssetId, AuctionOrderWitness, AuctionPrivacyGateWitness, BatchId, BatchOrderSet, BatchStatus,
    BatchSummary, CONTROL_PLANE_TOKEN_ENV, ConsumedInput, DeploymentManifest, DepositRecord,
    DepositRecordList, FeeEntry, MakerAttributionBundle, MakerAttributionPlaintext,
    MakerBandAttribution, MakerBandFillAttribution, MatchedOrder, MatchedOrderWitness, Note,
    NoteCommitment, NoteConsolidationWitness, NoteMembershipKind, NoteMembershipWitness,
    OnchainSubmissionRecord, OrderCommitment, OrderExecutionReport, OrderIngressReceipt,
    OrderIntent, OrderShareBundle, OrderSide, OrderSubmission, OrderType, OutputCiphertextBundle,
    OutputNoteRecord, OutputRecoveryRecord, PairId, PreparedBatchStatus,
    PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig, PrivateExecutionKeyRegistry,
    ProductConfig, ProductPairConfig, ProofArtifactRecord, ProofJobStatus, PublicBatchSummary,
    PublishedBatchArtifacts, SettlementRootHistoryArchive, SettlementSubmissionPlan,
    SettlementTimestampUpdate, SettlementTranscript, SettlementWitness, StarknetCall, TimeInForce,
    TrustedOrderIngressRequest, TrustedOrderIngressResponse,
    admission_proof_message_hash_for_program, auction_admission_root,
    auction_result_proof_message_hash_for_program, base_amount_affordable_for_quote,
    build_admission_serialized_input, build_auction_result_serialized_input,
    build_heartbeat_cover_orders, build_output_note, build_settlement_submission_plan,
    create_maker_attribution_artifact, create_order_ingress_receipt, decrypt_order_bundle,
    deposit_note_membership_witnesses_for_chain, encrypt_output_note_for_owner,
    extract_bearer_token, format_bearer_token, funding_input_set_commitment,
    funding_nullifier_set_commitment, native_settlement_message_hash, nullifier_from_note_secret,
    nullifier_proof_message_hash_for_program,
    nullifier_sparse_update_witnesses_for_consumed_inputs, output_note_merkle_proof,
    private_execution_key_registry_fingerprint, private_order_payload_commitment,
    proof_artifact_commitment, quote_amount_for_base_amount,
    renewal_proof_message_hash_for_program, renewal_sparse_witnesses_for_child_uses,
    root_only_settlement_commitments, sanitize_order_submission_for_coordinator,
    settlement_note_root_after_deposit_chain, settlement_proof_message_hash_for_program,
    settlement_state_transition_root, settlement_transcript_commitment,
    validate_order_ingress_receipt_for_manifest_with_secrets, verify_output_note_membership,
};

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
const DEFAULT_NATIVE_PROVER_BLOCKS_BACK: u64 = 0;
const DEFAULT_NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS: usize = 120;
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
const NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS_ENV: &str =
    "ZYLITH_NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS";
const NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS_ENV: &str =
    "ZYLITH_NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS";
const NATIVE_SIGNATURE_BINDS_PROOF_FACTS_ENV: &str = "ZYLITH_NATIVE_SIGNATURE_BINDS_PROOF_FACTS";
const NATIVE_PROOF_ACCOUNT_ADDRESS_ENV: &str = "ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS";
const NATIVE_PROOF_PROGRAM_ADDRESS_ENV: &str = "ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS";
const NATIVE_PROOF_ENTRYPOINT_ENV: &str = "ZYLITH_NATIVE_PROOF_ENTRYPOINT";
const NATIVE_PROOF_AGGREGATE_ENTRYPOINT_ENV: &str = "ZYLITH_NATIVE_PROOF_AGGREGATE_ENTRYPOINT";
const NATIVE_PROOF_AGGREGATOR_URL_ENV: &str = "ZYLITH_NATIVE_PROOF_AGGREGATOR_URL";
const NATIVE_PROOF_SMOKE_ZERO_ROOTS_ENV: &str = "ZYLITH_NATIVE_PROOF_SMOKE_ZERO_ROOTS";
const AUCTION_PROVER_KEYS_PATH_ENV: &str = "ZYLITH_AUCTION_PROVER_KEYS_PATH";
const AUCTION_PROVER_ALLOW_KEYGEN_ENV: &str = "ZYLITH_AUCTION_PROVER_ALLOW_KEYGEN";
const DEFAULT_PRODUCT_PAIR_IDS: &str =
    "STRK/USDC,ETH/USDC,strkBTC/USDC,STRK/ETH,STRK/strkBTC,WBTC/strkBTC,USDC/USDT";
const DEFAULT_PROTOCOL_FEE_RECIPIENT: &str = "zylith-protocol-treasury";
const DEFAULT_RELAY_FEE_RECIPIENT: &str = "zylith-renewal-relay";
const PROTOCOL_FEE_RECIPIENT_ENV: &str = "ZYLITH_PROTOCOL_FEE_RECIPIENT";
const LEGACY_PROTOCOL_FEE_RECIPIENT_ENV: &str = "ZYLITH_PROTOCOL_TREASURY_RECIPIENT";
const RELAY_FEE_RECIPIENT_ENV: &str = "ZYLITH_RELAY_FEE_RECIPIENT";
const PROOF_JOBS_DIR: &str = "proof_jobs";
const SETTLEMENT_PLANS_DIR: &str = "settlement_plans";
const SETTLEMENT_WITNESSES_DIR: &str = "settlement_witnesses";
const PROOF_ARTIFACTS_DIR: &str = "proof_artifacts";
const ONCHAIN_SUBMISSIONS_DIR: &str = "onchain_submissions";
const PROOF_OUTPUTS_DIR: &str = "proof_outputs";
const PUBLIC_INPUTS_DIR: &str = "public_inputs";
const PROVER_LOGS_DIR: &str = "prover_logs";
const PRIVATE_ORDER_PAYLOADS_DIR: &str = "private_order_payloads";
const NOTE_ROOT_TRANSITION_DEPOSIT_KIND: u64 = 0;
const NOTE_ROOT_TRANSITION_SETTLEMENT_KIND: u64 = 1;
const NOTE_ROOT_TRANSITION_CONSOLIDATION_KIND: u64 = 2;
const ORDER_INGRESS_RECEIPT_SECRET_ENV: &str = "ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET";
const ORDER_INGRESS_RECEIPT_PREVIOUS_SECRETS_ENV: &str =
    "ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS";
const ORDER_INGRESS_ID_ENV: &str = "ZYLITH_TRUSTED_PROVER_INGRESS_ID";
const ATTRIBUTION_SIGNING_PRIVATE_KEY_ENV: &str = "ZYLITH_ATTRIBUTION_SIGNING_PRIVATE_KEY";
const HEARTBEAT_COVER_SECRET_ENV: &str = "ZYLITH_HEARTBEAT_COVER_SECRET";
const HEARTBEAT_COVER_PRICES_ENV: &str = "ZYLITH_HEARTBEAT_COVER_PRICES";
const MIN_BATCH_BASE_LIQUIDITY_ENV: &str = "ZYLITH_MIN_BATCH_BASE_LIQUIDITY";
const PROVER_MAX_BODY_BYTES_ENV: &str = "ZYLITH_PROVER_MAX_BODY_BYTES";
const PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE_ENV: &str =
    "ZYLITH_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE";
const PROVER_MAX_STORED_PRIVATE_PAYLOADS_ENV: &str = "ZYLITH_PROVER_MAX_STORED_PRIVATE_PAYLOADS";
const PROVER_PRIVATE_PAYLOAD_RETENTION_MS_ENV: &str = "ZYLITH_PRIVATE_PAYLOAD_RETENTION_MS";
const PROVER_EMERGENCY_PAUSED_ENV: &str = "ZYLITH_PROVER_EMERGENCY_PAUSED";
const PROVER_ALLOWED_ORIGINS_ENV: &str = "ZYLITH_PROVER_ALLOWED_ORIGINS";
const PROVER_WORKER_ENABLED_ENV: &str = "ZYLITH_PROVER_WORKER_ENABLED";
const PROVER_WORKER_TICK_MS_ENV: &str = "ZYLITH_PROVER_WORKER_TICK_MS";
const PROVER_WORKER_MAX_BATCHES_PER_TICK_ENV: &str = "ZYLITH_PROVER_WORKER_MAX_BATCHES_PER_TICK";
const PROVER_WORKER_SUBMIT_ONCHAIN_ENV: &str = "ZYLITH_PROVER_WORKER_SUBMIT_ONCHAIN";
const MIN_BATCH_PARTICIPANTS_ENV: &str = "ZYLITH_MIN_BATCH_PARTICIPANTS";
const MIN_ELIGIBLE_ORDERS_ENV: &str = "ZYLITH_MIN_ELIGIBLE_ORDERS";
const MIN_MAKER_PARTICIPANTS_ENV: &str = "ZYLITH_MIN_MAKER_PARTICIPANTS";
const MAX_SINGLE_ORDER_FILL_BPS_ENV: &str = "ZYLITH_MAX_SINGLE_ORDER_FILL_BPS";
const MAX_SINGLE_OWNER_FILL_BPS_ENV: &str = "ZYLITH_MAX_SINGLE_OWNER_FILL_BPS";
const MAX_MAKER_FILL_BPS_ENV: &str = "ZYLITH_MAX_MAKER_FILL_BPS";
const MAX_PROVABLE_BATCH_ORDERS_ENV: &str = "ZYLITH_MAX_PROVABLE_BATCH_ORDERS";
const MAX_ORDER_AMOUNT_ENV: &str = "ZYLITH_MAX_ORDER_AMOUNT";
const MAX_MAKER_CURVE_BASE_AMOUNT_ENV: &str = "ZYLITH_MAX_MAKER_CURVE_BASE_AMOUNT";
const MAX_MAKER_CURVE_QUOTE_NOTIONAL_ENV: &str = "ZYLITH_MAX_MAKER_CURVE_QUOTE_NOTIONAL";
const SETTLEMENT_SUBMISSION_JITTER_MS_ENV: &str = "ZYLITH_SETTLEMENT_SUBMISSION_JITTER_MS";
const NATIVE_TX_PROVER_OHTTP_ENABLED_ENV: &str = "ZYLITH_NATIVE_TX_PROVER_OHTTP_ENABLED";
const NATIVE_TX_PROVER_OHTTP_RELAY_URL_ENV: &str = "ZYLITH_NATIVE_TX_PROVER_OHTTP_RELAY_URL";
const NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX_ENV: &str =
    "ZYLITH_NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX";
const DEFAULT_PROVER_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE: u64 = 60;
const DEFAULT_PROVER_MAX_STORED_PRIVATE_PAYLOADS: usize = 10_000;
const DEFAULT_PROVER_PRIVATE_PAYLOAD_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
const DEFAULT_SETTLEMENT_SUBMISSION_JITTER_MS: u64 = 5_000;
const DEFAULT_MAX_PROVABLE_BATCH_ORDERS: u64 = 32;
const DEFAULT_PROVER_WORKER_TICK_MS: u64 = 10_000;
const DEFAULT_PROVER_WORKER_MAX_BATCHES_PER_TICK: usize = 2;

#[derive(Clone)]
struct AppState {
    coordinator_url: String,
    indexer_url: String,
    auction_verifier_address: String,
    native_proof_program_address: String,
    native_proof_entrypoint: String,
    native_proof_aggregate_entrypoint: String,
    native_tx_prover_url: Option<String>,
    native_tx_prover_ohttp: Option<NativeProverOhttpConfig>,
    native_proof_aggregator_url: Option<String>,
    scarb_bin: String,
    stwo_manifest_path: Arc<PathBuf>,
    stwo_package_name: String,
    data_dir: Arc<PathBuf>,
    http_client: Client,
    proof_jobs: Arc<RwLock<BTreeMap<String, ProofJobStatus>>>,
    settlement_plans: Arc<RwLock<BTreeMap<String, SettlementSubmissionPlan>>>,
    settlement_witnesses: Arc<RwLock<BTreeMap<String, SettlementWitness>>>,
    proof_artifacts: Arc<RwLock<BTreeMap<String, ProofArtifactRecord>>>,
    onchain_submissions: Arc<RwLock<BTreeMap<String, OnchainSubmissionRecord>>>,
    private_order_payloads: Arc<RwLock<BTreeMap<String, PrivateOrderPayloadRecord>>>,
    product_config: Arc<ProductConfig>,
    auction_key_registry: Arc<PrivateExecutionKeyRegistry>,
    auction_private_keys: Arc<Vec<PrivateExecutionKeyPrivateConfig>>,
    starknet_executor: Option<StarknetExecutorConfig>,
    batch_registrar: Option<BatchRegistrarConfig>,
    internal_api_token: Option<Arc<String>>,
    order_ingress_id: String,
    order_ingress_receipt_secret: Option<Arc<String>>,
    order_ingress_receipt_secrets: Arc<Vec<String>>,
    attribution_signing_private_key: Arc<String>,
    heartbeat_cover_secret: Arc<String>,
    min_batch_base_liquidity: u128,
    min_batch_participants: u64,
    min_eligible_orders: u64,
    min_maker_participants: u64,
    max_single_order_fill_bps: u64,
    max_single_owner_fill_bps: u64,
    max_maker_fill_bps: u64,
    max_provable_batch_orders: u64,
    max_order_amount: u128,
    max_maker_curve_base_amount: u128,
    max_maker_curve_quote_notional: u128,
    protocol_fee_recipient: String,
    relay_fee_recipient: String,
    settlement_submission_jitter_ms: u64,
    private_payload_retention_ms: u64,
    max_stored_private_payloads: usize,
    private_ingress_rate_limit_per_minute: u64,
    emergency_paused: bool,
    prover_worker_enabled: bool,
    prover_worker_tick_ms: u64,
    prover_worker_max_batches_per_tick: usize,
    prover_worker_submit_onchain: bool,
    rate_limiter: RateLimiter,
    native_prover_attempts: usize,
    native_prover_retry_interval_ms: u64,
    native_prover_request_timeout_seconds: u64,
}

#[derive(Clone)]
struct StarknetExecutorConfig {
    rpc_url: String,
    account_address: String,
    private_key: String,
    chain_id: String,
    proof_account_address: String,
}

impl StarknetExecutorConfig {
    fn request_account_address(&self, mode: NativeTransactionMode) -> &str {
        match mode {
            NativeTransactionMode::ProofOnly => &self.proof_account_address,
            NativeTransactionMode::SubmitOnchain => &self.account_address,
        }
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

#[derive(Clone, Debug, Default)]
struct SettlementRoots {
    note_root: String,
    nullifier_root: String,
    renewal_root: String,
    fee_root: String,
}

impl SettlementRoots {
    fn zero() -> Self {
        Self {
            note_root: "0x0".into(),
            nullifier_root: "0x0".into(),
            renewal_root: "0x0".into(),
            fee_root: "0x0".into(),
        }
    }
}

struct AppConfig {
    coordinator_url: String,
    indexer_url: String,
    auction_verifier_address: String,
    native_proof_program_address: String,
    native_proof_entrypoint: String,
    native_proof_aggregate_entrypoint: String,
    native_tx_prover_url: Option<String>,
    native_tx_prover_ohttp: Option<NativeProverOhttpConfig>,
    native_proof_aggregator_url: Option<String>,
    scarb_bin: String,
    stwo_manifest_path: PathBuf,
    stwo_package_name: String,
    data_dir: PathBuf,
    starknet_executor: Option<StarknetExecutorConfig>,
    batch_registrar: Option<BatchRegistrarConfig>,
    product_config: ProductConfig,
    auction_private_keys: Vec<PrivateExecutionKeyPrivateConfig>,
    internal_api_token: Option<String>,
    order_ingress_id: String,
    order_ingress_receipt_secret: Option<String>,
    order_ingress_receipt_secrets: Vec<String>,
    attribution_signing_private_key: String,
    heartbeat_cover_secret: String,
    min_batch_base_liquidity: u128,
    min_batch_participants: u64,
    min_eligible_orders: u64,
    min_maker_participants: u64,
    max_single_order_fill_bps: u64,
    max_single_owner_fill_bps: u64,
    max_maker_fill_bps: u64,
    max_provable_batch_orders: u64,
    max_order_amount: u128,
    max_maker_curve_base_amount: u128,
    max_maker_curve_quote_notional: u128,
    protocol_fee_recipient: String,
    relay_fee_recipient: String,
    settlement_submission_jitter_ms: u64,
    private_payload_retention_ms: u64,
    max_stored_private_payloads: usize,
    private_ingress_rate_limit_per_minute: u64,
    emergency_paused: bool,
    prover_worker_enabled: bool,
    prover_worker_tick_ms: u64,
    prover_worker_max_batches_per_tick: usize,
    prover_worker_submit_onchain: bool,
    max_body_bytes: usize,
    native_prover_attempts: usize,
    native_prover_retry_interval_ms: u64,
    native_prover_request_timeout_seconds: u64,
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
    witness_path: PathBuf,
    proof_path: PathBuf,
    public_inputs_path: PathBuf,
    native_execution_request_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

#[derive(Debug)]
struct SettlementArtifacts {
    transcript: SettlementTranscript,
    output_bundle: OutputCiphertextBundle,
    maker_attribution_bundle: Option<MakerAttributionBundle>,
    settlement_witness: SettlementWitness,
    order_execution_reports: Vec<OrderExecutionReport>,
}

#[derive(Clone, Debug)]
struct DecryptedOrderRecord {
    order_commitment: OrderCommitment,
    order: OrderIntent,
    funding_note: Note,
    funding_notes: Vec<Note>,
    funding_authorization: zylith_core::SpendAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PrivateOrderPayloadRecord {
    order_commitment: OrderCommitment,
    payload_commitment: String,
    received_at_unix_ms: u64,
    receipt: OrderIngressReceipt,
    order_bundle: OrderShareBundle,
}

#[derive(Clone)]
struct OrderFillPlan {
    order_commitment: OrderCommitment,
    order: OrderIntent,
    funding_note: Note,
    funding_notes: Vec<Note>,
    funding_authorization: zylith_core::SpendAuthorization,
    available_amount: u128,
    filled_amount: u128,
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
    params: NativeProverParams,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NativeProverParams {
    block_id: NativeBlockId,
    transaction: serde_json::Value,
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
    #[serde(default)]
    data: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
struct NativeProverOhttpConfig {
    relay_url: Option<String>,
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

#[derive(Clone, Debug, Serialize)]
struct NativeProofAggregationMember {
    batch_id: BatchId,
    pair_id: PairId,
    batch_epoch: u64,
    transcript_commitment: String,
    proof_artifact_commitment: String,
    proof_system: String,
    prover_backend: String,
    proof: String,
    proof_facts: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct NativeProofAggregationProviderRequest {
    manifest: ProofAggregationManifest,
    members: Vec<NativeProofAggregationMember>,
}

#[derive(Clone, Debug, Deserialize)]
struct NativeProofAggregationProviderResponse {
    proof: String,
    proof_facts: Vec<String>,
    #[serde(default)]
    aggregate_proof_artifact_commitment: Option<String>,
    #[serde(default)]
    verifier_mode: Option<String>,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
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
}

#[derive(Clone, Debug)]
struct NativeAggregationPreparedMember {
    witness: SettlementWitness,
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
    redact_transaction_calldata(&mut redacted.params.transaction);
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
    axum::serve(listener, app)
        .await
        .map_err(|error| format!("prover service failed: {error}"))
}

fn protocol_fee_recipient_from_values(canonical: Option<String>, legacy: Option<String>) -> String {
    canonical
        .or(legacy)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_PROTOCOL_FEE_RECIPIENT.into())
}

fn protocol_fee_recipient_from_env() -> String {
    protocol_fee_recipient_from_values(
        env::var(PROTOCOL_FEE_RECIPIENT_ENV).ok(),
        env::var(LEGACY_PROTOCOL_FEE_RECIPIENT_ENV).ok(),
    )
}

fn relay_fee_recipient_from_env() -> String {
    env::var(RELAY_FEE_RECIPIENT_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_RELAY_FEE_RECIPIENT.into())
}

fn build_app() -> Result<Router, String> {
    let deployment_manifest = load_deployment_manifest();
    let coordinator_url =
        env::var("ZYLITH_COORDINATOR_URL").unwrap_or_else(|_| DEFAULT_COORDINATOR_URL.into());
    let indexer_url = env::var("ZYLITH_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
    let auction_verifier_address = env::var("ZYLITH_AUCTION_VERIFIER_ADDRESS")
        .ok()
        .or_else(|| {
            deployment_manifest
                .as_ref()
                .map(|manifest| manifest.contracts.auction_verifier.clone())
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
        .unwrap_or_else(|| auction_verifier_address.clone());
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
    let native_tx_prover_url = env::var("ZYLITH_NATIVE_TX_PROVER_URL").ok();
    let native_tx_prover_ohttp = load_native_prover_ohttp_config()?;
    let native_proof_aggregator_url = env::var(NATIVE_PROOF_AGGREGATOR_URL_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let scarb_bin = env::var("ZYLITH_SCARB_BIN").unwrap_or_else(|_| DEFAULT_SCARB_BIN.into());
    let stwo_manifest_path = env::var("ZYLITH_STWO_MANIFEST_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STWO_MANIFEST_PATH));
    let stwo_package_name =
        env::var("ZYLITH_STWO_PACKAGE_NAME").unwrap_or_else(|_| DEFAULT_STWO_PACKAGE_NAME.into());
    let data_dir = env::var("ZYLITH_PROVER_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PROVER_DATA_DIR));
    let order_ingress_id =
        env::var(ORDER_INGRESS_ID_ENV).unwrap_or_else(|_| "zylith-prover-ingress".into());
    let order_ingress_receipt_secret = env::var(ORDER_INGRESS_RECEIPT_SECRET_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let order_ingress_receipt_secrets =
        load_receipt_secret_keyring(order_ingress_receipt_secret.as_ref());
    let attribution_signing_private_key =
        load_attribution_signing_private_key(order_ingress_receipt_secret.as_ref())?;
    let heartbeat_cover_secret =
        load_required_control_plane_token("zylith-prover", HEARTBEAT_COVER_SECRET_ENV)?;
    let product_config = load_product_config(deployment_manifest.as_ref())?;
    let auction_private_keys = load_auction_private_keys()?;
    let starknet_executor = load_starknet_executor_from_env(deployment_manifest.as_ref());
    let batch_registrar = load_batch_registrar_from_env(deployment_manifest.as_ref())?;
    let native_prover_attempts =
        env_parse_or_default(NATIVE_PROVER_ATTEMPTS_ENV, DEFAULT_NATIVE_PROVER_ATTEMPTS);
    let native_prover_retry_interval_ms = env_parse_or_default(
        NATIVE_PROVER_RETRY_INTERVAL_MS_ENV,
        DEFAULT_NATIVE_PROVER_RETRY_INTERVAL_MS,
    );
    let native_prover_request_timeout_seconds = env_parse_or_default(
        NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS_ENV,
        DEFAULT_NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS,
    );

    build_app_with_config(AppConfig {
        coordinator_url,
        indexer_url,
        auction_verifier_address,
        native_proof_program_address,
        native_proof_entrypoint,
        native_proof_aggregate_entrypoint,
        native_tx_prover_url,
        native_tx_prover_ohttp,
        native_proof_aggregator_url,
        scarb_bin,
        stwo_manifest_path,
        stwo_package_name,
        data_dir,
        starknet_executor,
        batch_registrar,
        product_config,
        auction_private_keys,
        internal_api_token: Some(load_required_control_plane_token(
            "zylith-prover",
            CONTROL_PLANE_TOKEN_ENV,
        )?),
        order_ingress_id,
        order_ingress_receipt_secret,
        order_ingress_receipt_secrets,
        attribution_signing_private_key,
        heartbeat_cover_secret,
        min_batch_base_liquidity: env_parse_or_default(MIN_BATCH_BASE_LIQUIDITY_ENV, 0_u128),
        min_batch_participants: env_parse_or_default(MIN_BATCH_PARTICIPANTS_ENV, 0_u64),
        min_eligible_orders: env_parse_or_default(MIN_ELIGIBLE_ORDERS_ENV, 0_u64),
        min_maker_participants: env_parse_or_default(MIN_MAKER_PARTICIPANTS_ENV, 0_u64),
        max_single_order_fill_bps: env_parse_or_default(MAX_SINGLE_ORDER_FILL_BPS_ENV, 0_u64),
        max_single_owner_fill_bps: env_parse_or_default(MAX_SINGLE_OWNER_FILL_BPS_ENV, 0_u64),
        max_maker_fill_bps: env_parse_or_default(MAX_MAKER_FILL_BPS_ENV, 0_u64),
        max_provable_batch_orders: env_parse_or_default(
            MAX_PROVABLE_BATCH_ORDERS_ENV,
            DEFAULT_MAX_PROVABLE_BATCH_ORDERS,
        ),
        max_order_amount: env_parse_or_default(MAX_ORDER_AMOUNT_ENV, 0_u128),
        max_maker_curve_base_amount: env_parse_or_default(MAX_MAKER_CURVE_BASE_AMOUNT_ENV, 0_u128),
        max_maker_curve_quote_notional: env_parse_or_default(
            MAX_MAKER_CURVE_QUOTE_NOTIONAL_ENV,
            0_u128,
        ),
        protocol_fee_recipient: protocol_fee_recipient_from_env(),
        relay_fee_recipient: relay_fee_recipient_from_env(),
        settlement_submission_jitter_ms: env_parse_or_default(
            SETTLEMENT_SUBMISSION_JITTER_MS_ENV,
            DEFAULT_SETTLEMENT_SUBMISSION_JITTER_MS,
        ),
        private_payload_retention_ms: env_parse_or_default(
            PROVER_PRIVATE_PAYLOAD_RETENTION_MS_ENV,
            DEFAULT_PROVER_PRIVATE_PAYLOAD_RETENTION_MS,
        ),
        max_stored_private_payloads: env_parse_or_default(
            PROVER_MAX_STORED_PRIVATE_PAYLOADS_ENV,
            DEFAULT_PROVER_MAX_STORED_PRIVATE_PAYLOADS,
        ),
        private_ingress_rate_limit_per_minute: env_parse_or_default(
            PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE_ENV,
            DEFAULT_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE,
        ),
        emergency_paused: env_bool_or_default(PROVER_EMERGENCY_PAUSED_ENV, false),
        prover_worker_enabled: env_bool_or_default(PROVER_WORKER_ENABLED_ENV, false),
        prover_worker_tick_ms: env_parse_or_default(
            PROVER_WORKER_TICK_MS_ENV,
            DEFAULT_PROVER_WORKER_TICK_MS,
        ),
        prover_worker_max_batches_per_tick: env_parse_or_default(
            PROVER_WORKER_MAX_BATCHES_PER_TICK_ENV,
            DEFAULT_PROVER_WORKER_MAX_BATCHES_PER_TICK,
        ),
        prover_worker_submit_onchain: env_bool_or_default(PROVER_WORKER_SUBMIT_ONCHAIN_ENV, true),
        max_body_bytes: env_parse_or_default(
            PROVER_MAX_BODY_BYTES_ENV,
            DEFAULT_PROVER_MAX_BODY_BYTES,
        ),
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
    })
}

fn load_deployment_manifest() -> Option<DeploymentManifest> {
    let manifest_path = env::var("ZYLITH_DEPLOYMENT_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DEPLOYMENT_MANIFEST_PATH));
    let manifest = fs::read_to_string(manifest_path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&manifest).ok()?;
    let manifest = value.get("manifest").cloned().unwrap_or(value);
    serde_json::from_value(manifest).ok()
}

fn load_product_config(
    deployment_manifest: Option<&DeploymentManifest>,
) -> Result<ProductConfig, String> {
    let mut product_config = if let Ok(value) = env::var("ZYLITH_PRODUCT_PAIRS") {
        ProductConfig::from_enabled_pair_ids_csv(&value)
            .map_err(|error| format!("invalid ZYLITH_PRODUCT_PAIRS: {error}"))?
    } else if let Some(manifest) = deployment_manifest {
        manifest.product.clone()
    } else {
        ProductConfig::from_enabled_pair_ids_csv(DEFAULT_PRODUCT_PAIR_IDS)
            .map_err(|error| format!("default prover product pairs are invalid: {error}"))?
    };
    if let Ok(value) = env::var(HEARTBEAT_COVER_PRICES_ENV) {
        product_config
            .apply_heartbeat_cover_prices_csv(&value)
            .map_err(|error| format!("invalid ZYLITH_HEARTBEAT_COVER_PRICES: {error}"))?;
    }
    Ok(product_config)
}

fn load_auction_private_keys() -> Result<Vec<PrivateExecutionKeyPrivateConfig>, String> {
    let path = env::var(AUCTION_PROVER_KEYS_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_AUCTION_PROVER_KEYS_PATH));
    let allow_keygen = env::var(AUCTION_PROVER_ALLOW_KEYGEN_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    load_or_create_auction_keys(&path, allow_keygen)
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

fn load_attribution_signing_private_key(
    current_receipt_secret: Option<&String>,
) -> Result<String, String> {
    if let Ok(value) = env::var(ATTRIBUTION_SIGNING_PRIVATE_KEY_ENV) {
        let value = value.trim().to_owned();
        if !value.is_empty() {
            return Ok(value);
        }
    }
    if let Ok(value) = env::var("ZYLITH_STARKNET_PRIVATE_KEY") {
        let value = value.trim().to_owned();
        if !value.is_empty() {
            return Ok(value);
        }
    }
    if let Some(secret) = current_receipt_secret
        && !secret.trim().is_empty()
    {
        return Ok(encode_starknet_felt(
            "maker-attribution-signing-key",
            secret.trim(),
        ));
    }
    Err(format!(
        "zylith-prover requires {ATTRIBUTION_SIGNING_PRIVATE_KEY_ENV}, ZYLITH_STARKNET_PRIVATE_KEY, or {ORDER_INGRESS_RECEIPT_SECRET_ENV} for maker attribution receipts"
    ))
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

fn service_cors_layer(env_name: &str) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);
    match allowed_origins_from_env(env_name) {
        Some(origins) => base.allow_origin(AllowOrigin::list(origins)),
        None => base.allow_origin(Any),
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

fn require_internal_auth(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(expected_token) = state.internal_api_token.as_deref() else {
        return Ok(());
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
        auction_verifier_address,
        native_proof_program_address,
        native_proof_entrypoint,
        native_proof_aggregate_entrypoint,
        native_tx_prover_url,
        native_tx_prover_ohttp,
        native_proof_aggregator_url,
        scarb_bin,
        stwo_manifest_path,
        stwo_package_name,
        data_dir,
        starknet_executor,
        batch_registrar,
        product_config,
        auction_private_keys,
        internal_api_token,
        order_ingress_id,
        order_ingress_receipt_secret,
        order_ingress_receipt_secrets,
        attribution_signing_private_key,
        heartbeat_cover_secret,
        min_batch_base_liquidity,
        min_batch_participants,
        min_eligible_orders,
        min_maker_participants,
        max_single_order_fill_bps,
        max_single_owner_fill_bps,
        max_maker_fill_bps,
        max_provable_batch_orders,
        max_order_amount,
        max_maker_curve_base_amount,
        max_maker_curve_quote_notional,
        protocol_fee_recipient,
        relay_fee_recipient,
        settlement_submission_jitter_ms,
        private_payload_retention_ms,
        max_stored_private_payloads,
        private_ingress_rate_limit_per_minute,
        emergency_paused,
        prover_worker_enabled,
        prover_worker_tick_ms,
        prover_worker_max_batches_per_tick,
        prover_worker_submit_onchain,
        max_body_bytes,
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
    } = config;

    if protocol_fee_recipient.trim().is_empty() {
        return Err("protocol fee recipient must not be empty".into());
    }
    if relay_fee_recipient.trim().is_empty() {
        return Err("relay fee recipient must not be empty".into());
    }
    if native_proof_entrypoint != "compile_settlement_proof" {
        return Err("native proof entrypoint must be compile_settlement_proof".into());
    }
    if native_proof_aggregate_entrypoint != "compile_settlement_aggregate_proof" {
        return Err(
            "native aggregate proof entrypoint must be compile_settlement_aggregate_proof".into(),
        );
    }

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
        auction_verifier_address,
        native_proof_program_address,
        native_proof_entrypoint,
        native_proof_aggregate_entrypoint,
        native_tx_prover_url,
        native_tx_prover_ohttp,
        native_proof_aggregator_url,
        scarb_bin,
        stwo_manifest_path: Arc::new(stwo_manifest_path),
        stwo_package_name,
        data_dir: Arc::new(data_dir.clone()),
        http_client: Client::new(),
        proof_jobs: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            PROOF_JOBS_DIR,
            |record: &ProofJobStatus| record.batch_id.0.clone(),
        ))),
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
        proof_artifacts: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            PROOF_ARTIFACTS_DIR,
            |record: &ProofArtifactRecord| record.batch_id.0.clone(),
        ))),
        onchain_submissions: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            ONCHAIN_SUBMISSIONS_DIR,
            |record: &OnchainSubmissionRecord| record.batch_id.0.clone(),
        ))),
        private_order_payloads: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            PRIVATE_ORDER_PAYLOADS_DIR,
            |record: &PrivateOrderPayloadRecord| record.order_commitment.0.clone(),
        ))),
        product_config: Arc::new(product_config),
        auction_key_registry: Arc::new(auction_key_registry),
        auction_private_keys: Arc::new(auction_private_keys),
        starknet_executor,
        batch_registrar,
        internal_api_token: internal_api_token.map(Arc::new),
        order_ingress_id,
        order_ingress_receipt_secret: order_ingress_receipt_secret.map(Arc::new),
        order_ingress_receipt_secrets: Arc::new(order_ingress_receipt_secrets),
        attribution_signing_private_key: Arc::new(attribution_signing_private_key),
        heartbeat_cover_secret: Arc::new(heartbeat_cover_secret),
        min_batch_base_liquidity,
        min_batch_participants,
        min_eligible_orders,
        min_maker_participants,
        max_single_order_fill_bps,
        max_single_owner_fill_bps,
        max_maker_fill_bps,
        max_provable_batch_orders,
        max_order_amount,
        max_maker_curve_base_amount,
        max_maker_curve_quote_notional,
        protocol_fee_recipient,
        relay_fee_recipient,
        settlement_submission_jitter_ms,
        private_payload_retention_ms,
        max_stored_private_payloads,
        private_ingress_rate_limit_per_minute,
        emergency_paused,
        prover_worker_enabled,
        prover_worker_tick_ms,
        prover_worker_max_batches_per_tick,
        prover_worker_submit_onchain,
        rate_limiter: RateLimiter::default(),
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
    };

    if state.prover_worker_enabled {
        task::spawn(proof_worker_loop(state.clone()));
    }

    Ok(Router::new()
        .route("/health", get(health))
        .route("/api/public/auction-keys", get(public_auction_keys))
        .route(
            "/api/public/auction-keys/fingerprint",
            get(public_auction_keys_fingerprint),
        )
        .route(
            "/api/public/proof-jobs/{batch_id}",
            get(get_public_proof_job),
        )
        .route("/api/private/orders", post(ingest_private_order_payload))
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
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(service_cors_layer(PROVER_ALLOWED_ORIGINS_ENV)))
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let proof_jobs = state.proof_jobs.read().await;
    let settlement_plans = state.settlement_plans.read().await;
    let settlement_witnesses = state.settlement_witnesses.read().await;
    let proof_artifacts = state.proof_artifacts.read().await;
    let onchain_submissions = state.onchain_submissions.read().await;
    let private_order_payloads = state.private_order_payloads.read().await;
    Json(serde_json::json!({
        "service": "zylith-prover",
        "coordinator_configured": !state.coordinator_url.trim().is_empty(),
        "indexer_configured": !state.indexer_url.trim().is_empty(),
        "prepared_jobs_bucket": count_bucket(proof_jobs.len()),
        "auction_verifier_address": state.auction_verifier_address,
        "prepared_settlement_plans_bucket": count_bucket(settlement_plans.len()),
        "prepared_settlement_witnesses_bucket": count_bucket(settlement_witnesses.len()),
        "stored_proof_artifacts_bucket": count_bucket(proof_artifacts.len()),
        "stored_onchain_submissions_bucket": count_bucket(onchain_submissions.len()),
        "stored_private_order_payloads_bucket": count_bucket(private_order_payloads.len()),
        "starknet_executor_enabled": state.starknet_executor.is_some(),
        "native_tx_prover_enabled": state.native_tx_prover_url.is_some(),
        "native_tx_prover_ohttp_enabled": state.native_tx_prover_ohttp.is_some(),
        "native_proof_aggregation_enabled": state.native_tx_prover_url.is_some() || state.native_proof_aggregator_url.is_some(),
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
        "min_batch_base_liquidity": state.min_batch_base_liquidity.to_string(),
        "min_batch_participants": state.min_batch_participants,
        "min_eligible_orders": state.min_eligible_orders,
        "min_maker_participants": state.min_maker_participants,
        "max_single_order_fill_bps": state.max_single_order_fill_bps,
        "max_single_owner_fill_bps": state.max_single_owner_fill_bps,
        "max_maker_fill_bps": state.max_maker_fill_bps,
        "max_provable_batch_orders": state.max_provable_batch_orders,
        "max_order_amount": state.max_order_amount.to_string(),
        "max_maker_curve_base_amount": state.max_maker_curve_base_amount.to_string(),
        "max_maker_curve_quote_notional": state.max_maker_curve_quote_notional.to_string(),
        "protocol_fee_recipient": &state.protocol_fee_recipient,
        "settlement_submission_jitter_ms": state.settlement_submission_jitter_ms,
        "native_prover_attempts": state.native_prover_attempts,
        "native_prover_retry_interval_ms": state.native_prover_retry_interval_ms,
        "native_prover_request_timeout_seconds": state.native_prover_request_timeout_seconds,
        "prover_backend": prover_backend_label(state.native_tx_prover_url.is_some()),
        "scarb_bin": state.scarb_bin,
        "stwo_manifest_path": state.stwo_manifest_path.display().to_string(),
        "stwo_package_name": state.stwo_package_name,
        "data_dir": state.data_dir.display().to_string(),
    }))
}

async fn public_auction_keys(State(state): State<AppState>) -> Json<PrivateExecutionKeyRegistry> {
    Json((*state.auction_key_registry).clone())
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
) -> Result<Json<serde_json::Value>, StatusCode> {
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

async fn ingest_private_order_payload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TrustedOrderIngressRequest>,
) -> Result<Json<TrustedOrderIngressResponse>, StatusCode> {
    require_prover_not_paused(&state)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        "private-order-ingress",
        state.private_ingress_rate_limit_per_minute,
    )?;
    prune_private_order_payloads(&state).await?;
    let receipt_secret = state
        .order_ingress_receipt_secret
        .as_deref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let submission = request.order_submission;
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
        .map_err(|error| reject_private_ingress(&format!("funding notes are invalid: {error}")))?;
    validate_private_order_risk_limits(&state, &private_payload.order)
        .map_err(|_| reject_private_ingress("order risk limits rejected"))?;

    let receipt = create_order_ingress_receipt(
        &submission.order_bundle,
        &state.order_ingress_id,
        "zylith-prover",
        receipt_secret,
        now_unix_ms(),
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
        private_order_payloads.insert(order_commitment.0.clone(), record.clone());
        persist_record(
            state.data_dir.as_ref(),
            PRIVATE_ORDER_PAYLOADS_DIR,
            &order_commitment.0,
            &record,
        )?;
    }

    Ok(Json(TrustedOrderIngressResponse {
        receipt,
        coordinator_submission,
        padding: Some(private_ingress_response_padding()),
    }))
}

fn private_ingress_response_padding() -> String {
    "0".repeat(512)
}

async fn prune_private_order_payloads(state: &AppState) -> Result<(), StatusCode> {
    if state.private_payload_retention_ms == 0 {
        return Ok(());
    }
    let cutoff = now_unix_ms().saturating_sub(state.private_payload_retention_ms);
    let mut removed = Vec::new();
    {
        let mut private_order_payloads = state.private_order_payloads.write().await;
        private_order_payloads.retain(|key, record| {
            let keep = record.received_at_unix_ms >= cutoff;
            if !keep {
                removed.push(key.clone());
            }
            keep
        });
    }
    for key in removed {
        delete_record_if_exists(state.data_dir.as_ref(), PRIVATE_ORDER_PAYLOADS_DIR, &key)?;
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

fn env_parse_optional<T>(env_name: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
}

fn env_bool_or_default(env_name: &str, default: bool) -> bool {
    env::var(env_name)
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn load_native_prover_ohttp_config() -> Result<Option<NativeProverOhttpConfig>, String> {
    if !env_bool_or_default(NATIVE_TX_PROVER_OHTTP_ENABLED_ENV, true) {
        return Ok(None);
    }
    let relay_url = env::var(NATIVE_TX_PROVER_OHTTP_RELAY_URL_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let pinned_key_config = env::var(NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX_ENV)
        .ok()
        .map(|value| parse_ohttp_key_config_hex(&value))
        .transpose()?;
    Ok(Some(NativeProverOhttpConfig {
        relay_url,
        pinned_key_config,
    }))
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
    if matches!(order.order_type, zylith_core::OrderType::HeartbeatCover) {
        return Err("heartbeat cover orders are protocol-generated".into());
    }
    if state.max_order_amount > 0 && order.amount > state.max_order_amount {
        return Err("order amount exceeds configured maximum".into());
    }

    if matches!(order.order_type, zylith_core::OrderType::MakerCurve) {
        let base_amount = maker_curve_total_base_amount(order)?;
        if state.max_maker_curve_base_amount > 0 && base_amount > state.max_maker_curve_base_amount
        {
            return Err("maker curve base exposure exceeds configured maximum".into());
        }
        let quote_notional = maker_curve_quote_notional(order)?;
        if state.max_maker_curve_quote_notional > 0
            && quote_notional > state.max_maker_curve_quote_notional
        {
            return Err("maker curve quote notional exceeds configured maximum".into());
        }
    }

    Ok(())
}

fn maker_curve_total_base_amount(order: &OrderIntent) -> Result<u128, String> {
    let Some(curve) = order.maker_curve.as_ref() else {
        return Ok(0);
    };
    curve.points.iter().try_fold(0_u128, |total, point| {
        total
            .checked_add(point.base_amount)
            .ok_or_else(|| "maker curve base amount overflow".to_string())
    })
}

fn maker_curve_quote_notional(order: &OrderIntent) -> Result<u128, String> {
    let Some(curve) = order.maker_curve.as_ref() else {
        return Ok(0);
    };
    curve.points.iter().try_fold(0_u128, |total, point| {
        let notional = point
            .price
            .checked_mul(point.base_amount)
            .ok_or_else(|| "maker curve quote notional overflow".to_string())?;
        total
            .checked_add(notional)
            .ok_or_else(|| "maker curve quote notional overflow".to_string())
    })
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
    let mut batches = fetch_public_batch_summaries(state).await?;
    batches.sort_by(|left, right| {
        left.close_time_unix_ms
            .cmp(&right.close_time_unix_ms)
            .then_with(|| left.epoch_id.cmp(&right.epoch_id))
            .then_with(|| left.batch_id.0.cmp(&right.batch_id.0))
    });

    let mut processed = 0usize;
    for batch in batches {
        if processed >= state.prover_worker_max_batches_per_tick {
            break;
        }
        if !matches!(batch.status, BatchStatus::Closed | BatchStatus::Clearing) {
            continue;
        }
        let batch_id = batch.batch_id.0.as_str();
        if !proof_worker_should_process_batch(state, batch_id).await {
            continue;
        }
        let order_set = match fetch_batch_order_set(state, batch_id).await {
            Ok(order_set) => order_set,
            Err(StatusCode::NOT_FOUND) => continue,
            Err(status) => {
                return Err(format!(
                    "failed to fetch closed batch {batch_id} orders: {status}"
                ));
            }
        };
        if order_set.orders.is_empty() {
            continue;
        }
        eprintln!(
            "zylith prover worker processing batch_id={} pair={} epoch={} orders={}",
            batch_id,
            batch.pair_id.0,
            batch.epoch_id,
            order_set.orders.len()
        );
        if let Err(status) = process_proof_worker_batch(state, batch_id).await {
            eprintln!("zylith prover worker batch {batch_id} failed status={status}");
        }
        processed += 1;
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
            submissions.insert(batch_id.clone(), refreshed_record.clone());
            persist_record(
                state.data_dir.as_ref(),
                ONCHAIN_SUBMISSIONS_DIR,
                &batch_id,
                &refreshed_record,
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

async fn fetch_public_batch_summaries(state: &AppState) -> Result<Vec<PublicBatchSummary>, String> {
    let url = format!("{}/api/batches", state.coordinator_url);
    state
        .http_client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("coordinator batch list request failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("coordinator batch list rejected: {error}"))?
        .json()
        .await
        .map_err(|error| format!("coordinator batch list decode failed: {error}"))
}

async fn proof_worker_should_process_batch(state: &AppState, batch_id: &str) -> bool {
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
    matches!(
        status.state.as_str(),
        "witness-prepared" | "proof-generated"
    )
}

async fn process_proof_worker_batch(state: &AppState, batch_id: &str) -> Result<(), StatusCode> {
    let existing_state = {
        let proof_jobs = state.proof_jobs.read().await;
        proof_jobs.get(batch_id).map(|status| status.state.clone())
    };
    if existing_state.as_deref() != Some("proof-generated") {
        run_proof_job_inner(state, batch_id).await?;
    }
    if state.prover_worker_submit_onchain {
        submit_onchain_inner(state, batch_id).await?;
    }
    Ok(())
}

fn enforce_rate_limit(
    limiter: &RateLimiter,
    headers: &HeaderMap,
    scope: &str,
    limit_per_minute: u64,
) -> Result<(), StatusCode> {
    if limit_per_minute == 0 {
        return Ok(());
    }

    let now = now_unix_ms();
    let window_started_unix_ms = now - (now % 60_000);
    let key = format!("{scope}:{}", rate_limit_subject(headers));
    let mut buckets = limiter
        .buckets
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
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

fn rate_limit_subject(headers: &HeaderMap) -> String {
    for header in ["x-forwarded-for", "x-real-ip"] {
        if let Some(value) = headers
            .get(header)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return value.chars().take(96).collect();
        }
    }
    "anonymous".into()
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
    matched_order_count: u64,
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

async fn get_public_proof_job(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> Result<Json<PublicProofJobStatus>, StatusCode> {
    let proof_jobs = state.proof_jobs.read().await;
    let status = proof_jobs.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(PublicProofJobStatus {
        batch_id: status.batch_id.0.clone(),
        state: status.state.clone(),
        matched_order_count: status.matched_order_count,
        witness_available: status.witness_available,
        proof_artifact_available: status.proof_artifact_available,
        onchain_submission_available: status.onchain_submission_available,
        failure: public_proof_failure(&status.state),
        updated_at_unix_ms: status.updated_at_unix_ms,
    }))
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
    if state.native_tx_prover_url.is_some() {
        return Ok(Json(
            run_true_native_proof_aggregation(&state, start_epoch, end_epoch).await?,
        ));
    }
    let Some(aggregator_url) = state.native_proof_aggregator_url.clone() else {
        return Err(StatusCode::NOT_IMPLEMENTED);
    };
    Ok(Json(
        run_provider_proof_aggregation(&state, &aggregator_url, start_epoch, end_epoch).await?,
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
    for batch_id in &aggregate.member_batches {
        if let Err(error) = prove_and_record_auction_result(&state, &batch_id.0, true).await {
            set_onchain_submission_error(&state, &batch_id.0, error).await?;
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
        let provider = JsonRpcClient::new(HttpTransport::new(
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
    Ok(Json(submission))
}

async fn run_provider_proof_aggregation(
    state: &AppState,
    aggregator_url: &str,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<NativeProofAggregationRecord, StatusCode> {
    let manifest = build_proof_aggregation_manifest(state, start_epoch, end_epoch).await?;
    let members = build_native_proof_aggregation_members(state, start_epoch, end_epoch).await?;
    if members.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
    let request = NativeProofAggregationProviderRequest {
        manifest: manifest.clone(),
        members,
    };
    let response = tokio::time::timeout(
        Duration::from_secs(state.native_prover_request_timeout_seconds),
        state.http_client.post(aggregator_url).json(&request).send(),
    )
    .await
    .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !response.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let provider_response = response
        .json::<NativeProofAggregationProviderResponse>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if provider_response.proof.trim().is_empty() || provider_response.proof_facts.is_empty() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let aggregate_proof_artifact_commitment = match provider_response
        .aggregate_proof_artifact_commitment
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => value,
        None => zylith_core::hash::tagged_commitment_sha256(
            "zylith/native-proof-aggregation-result-v1",
            &serde_json::json!({
                "manifest_id": manifest.manifest_id,
                "aggregate_commitment": manifest.aggregate_commitment,
                "proof": &provider_response.proof,
                "proof_facts": &provider_response.proof_facts,
            }),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    };
    let prepared_members =
        prepare_native_aggregation_members(state, start_epoch, end_epoch).await?;
    validate_aggregate_root_chain(&prepared_members).map_err(|_| StatusCode::CONFLICT)?;
    let expected_messages = prepared_members
        .iter()
        .flat_map(|member| member.proof_message_hashes.iter().cloned())
        .collect::<Vec<_>>();
    validate_native_proof_facts_messages(&provider_response.proof_facts, &expected_messages)
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let settlement_call = build_aggregate_settlement_call(&prepared_members)?;
    Ok(NativeProofAggregationRecord {
        manifest,
        member_count_bucket: count_bucket(request.members.len()).into(),
        provider: provider_response
            .provider
            .unwrap_or_else(|| "configured-native-proof-aggregator".into()),
        verifier_mode: provider_response
            .verifier_mode
            .unwrap_or_else(|| "aggregate_submit_settlement_with_proof_facts".into()),
        aggregate_proof_artifact_commitment,
        settlement_call,
        member_batches: prepared_members
            .iter()
            .map(|member| member.witness.batch_id.clone())
            .collect(),
        proof: provider_response.proof,
        proof_facts: provider_response.proof_facts,
    })
}

async fn run_true_native_proof_aggregation(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<NativeProofAggregationRecord, StatusCode> {
    let Some(tx_prover_url) = state.native_tx_prover_url.clone() else {
        return Err(StatusCode::NOT_IMPLEMENTED);
    };
    let manifest = build_proof_aggregation_manifest(state, start_epoch, end_epoch).await?;
    let members = prepare_native_aggregation_members(state, start_epoch, end_epoch).await?;
    if members.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
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
        params: NativeProverParams {
            block_id: execution_request.block_id.clone(),
            transaction: execution_request.transaction.clone(),
        },
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
    })
}

async fn prepare_native_aggregation_members(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<Vec<NativeAggregationPreparedMember>, StatusCode> {
    let witnesses = proof_aggregation_witness_members(state, start_epoch, end_epoch).await?;
    let mut members = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        let transcript = fetch_transcript(state, &witness.batch_id.0).await?;
        let transcript_commitment =
            settlement_transcript_commitment(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
        if transcript_commitment != witness.transcript_commitment {
            return Err(StatusCode::CONFLICT);
        }
        let statement_message =
            native_settlement_message_hash(&state.auction_verifier_address, &transcript_commitment)
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let roots =
            root_only_settlement_commitments(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
        let settlement_proof_message = settlement_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &transcript_commitment,
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let nullifier_proof_message = nullifier_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &transcript_commitment,
            &roots.prior_nullifier_root,
            &roots.consumed_nullifier_root,
            &roots.new_nullifier_root,
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let renewal_proof_message = renewal_proof_message_hash_for_program(
            &state.native_proof_program_address,
            &state.auction_verifier_address,
            &transcript_commitment,
            &roots.prior_renewal_root,
            &roots.renewal_child_root,
            &roots.new_renewal_root,
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
            settlement_plan,
            proof_message_hashes: vec![
                settlement_proof_message,
                nullifier_proof_message,
                renewal_proof_message,
            ],
        });
    }
    Ok(members)
}

async fn build_proof_aggregation_manifest(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<ProofAggregationManifest, StatusCode> {
    let members = proof_aggregation_witness_members(state, start_epoch, end_epoch).await?;
    let pair_count = members
        .iter()
        .map(|witness| witness.pair_id.0.clone())
        .collect::<BTreeSet<_>>()
        .len();
    let proof_artifact_commitments = members
        .iter()
        .map(|witness| {
            native_settlement_message_hash(
                &state.auction_verifier_address,
                &witness.transcript_commitment,
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        })
        .collect::<Result<Vec<_>, StatusCode>>()?;
    let transcript_commitments = members
        .iter()
        .map(|witness| witness.transcript_commitment.clone())
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
    let native_aggregation_supported =
        state.native_tx_prover_url.is_some() || state.native_proof_aggregator_url.is_some();
    let mode = if native_aggregation_supported {
        if state.native_tx_prover_url.is_some() {
            "native_virtual_tx_aggregate_proof_facts"
        } else {
            "native_provider_aggregate_proof_facts"
        }
    } else {
        "manifest_only_per_batch_proof_facts"
    };
    let binding_members = members
        .iter()
        .zip(proof_artifact_commitments.iter())
        .map(|(witness, proof_artifact_commitment)| {
            serde_json::json!({
                "batch_id": witness.batch_id,
                "pair_id": witness.pair_id,
                "batch_epoch": witness.batch_epoch,
                "transcript_commitment": witness.transcript_commitment,
                "proof_artifact_commitment": proof_artifact_commitment,
                "proof_system": "starknet-snip36",
                "prover_backend": prover_backend_label(state.native_tx_prover_url.is_some()),
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
        native_aggregation_supported,
        verifier_mode: if native_aggregation_supported {
            "submit_aggregate_settlements_with_proof_facts".into()
        } else {
            "per_batch_submit_settlement_with_proof_facts".into()
        },
    })
}

async fn build_native_proof_aggregation_members(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<Vec<NativeProofAggregationMember>, StatusCode> {
    proof_aggregation_members(state, start_epoch, end_epoch)
        .await?
        .into_iter()
        .map(|(witness, artifact)| {
            let proof_path = artifact
                .native_proof_file_path
                .as_deref()
                .ok_or(StatusCode::CONFLICT)?;
            let proof_facts_path = artifact
                .native_proof_facts_file_path
                .as_deref()
                .ok_or(StatusCode::CONFLICT)?;
            let proof = fs::read_to_string(proof_path).map_err(|_| StatusCode::CONFLICT)?;
            let proof_facts = serde_json::from_str::<Vec<String>>(
                &fs::read_to_string(proof_facts_path).map_err(|_| StatusCode::CONFLICT)?,
            )
            .map_err(|_| StatusCode::CONFLICT)?;
            if proof.trim().is_empty() || proof_facts.is_empty() {
                return Err(StatusCode::CONFLICT);
            }
            Ok(NativeProofAggregationMember {
                batch_id: witness.batch_id,
                pair_id: witness.pair_id,
                batch_epoch: witness.batch_epoch,
                transcript_commitment: witness.transcript_commitment,
                proof_artifact_commitment: artifact.proof_artifact_commitment,
                proof_system: artifact.proof_system,
                prover_backend: artifact.prover_backend,
                proof,
                proof_facts,
            })
        })
        .collect()
}

async fn proof_aggregation_members(
    state: &AppState,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<Vec<(SettlementWitness, ProofArtifactRecord)>, StatusCode> {
    if start_epoch > end_epoch {
        return Err(StatusCode::BAD_REQUEST);
    }

    let settlement_witnesses = state.settlement_witnesses.read().await;
    let proof_artifacts = state.proof_artifacts.read().await;
    let mut members = settlement_witnesses
        .values()
        .filter(|witness| witness.batch_epoch >= start_epoch && witness.batch_epoch <= end_epoch)
        .filter_map(|witness| {
            proof_artifacts
                .get(&witness.batch_id.0)
                .map(|artifact| (witness.clone(), artifact.clone()))
        })
        .collect::<Vec<_>>();
    members.sort_by(|(left_witness, _), (right_witness, _)| {
        left_witness
            .batch_epoch
            .cmp(&right_witness.batch_epoch)
            .then_with(|| left_witness.pair_id.0.cmp(&right_witness.pair_id.0))
            .then_with(|| left_witness.batch_id.0.cmp(&right_witness.batch_id.0))
    });
    Ok(members)
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
        submissions.insert(batch_id.clone(), refreshed_record.clone());
        persist_record(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &batch_id,
            &refreshed_record,
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
    let (status, _) = prepare_or_rebuild_job(&state, &batch_id).await?;
    Ok(Json(status))
}

async fn run_proof_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofJobStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    require_prover_not_paused(&state)?;
    Ok(Json(run_proof_job_inner(&state, &batch_id).await?))
}

async fn run_proof_job_inner(
    state: &AppState,
    batch_id: &str,
) -> Result<ProofJobStatus, StatusCode> {
    let (_, settlement_witness) = ensure_prepared_job(state, batch_id).await?;
    let transcript = fetch_transcript(state, batch_id).await?;

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

    let proof_result = match fetch_auction_order_witnesses(state, batch_id).await {
        Ok(auction_order_witnesses) => {
            if state.native_tx_prover_url.is_some() {
                execute_native_transaction_prover(
                    state,
                    batch_id,
                    &transcript,
                    &settlement_witness,
                    &auction_order_witnesses,
                )
                .await
            } else {
                execute_stwo_prover(
                    state,
                    batch_id,
                    &settlement_witness,
                    &auction_order_witnesses,
                )
                .await
            }
        }
        Err(status) => Err(format!(
            "failed to load private auction order witness set for proof: {status}"
        )),
    };

    match proof_result {
        Ok(artifact) => {
            if state.native_tx_prover_url.is_some()
                && let Err(error) = prove_and_record_auction_result(state, batch_id, false).await
            {
                set_job_error(state, batch_id, error).await?;
                return Err(StatusCode::BAD_GATEWAY);
            }

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
                proof_artifacts.insert(batch_id.to_owned(), artifact.clone());
                persist_record(
                    state.data_dir.as_ref(),
                    PROOF_ARTIFACTS_DIR,
                    batch_id,
                    &artifact,
                )?;
            }
            {
                let mut settlement_plans = state.settlement_plans.write().await;
                settlement_plans.insert(batch_id.to_owned(), settlement_plan.clone());
                persist_record(
                    state.data_dir.as_ref(),
                    SETTLEMENT_PLANS_DIR,
                    batch_id,
                    &settlement_plan,
                )?;
            }

            let updated_status = set_job_state(
                state,
                batch_id,
                JobStateUpdate {
                    next_state: "proof-generated".into(),
                    proof_artifact_id: Some(artifact_id),
                    last_error: None,
                    proof_artifact_available: true,
                    settlement_plan_available: Some(true),
                    settlement_calldata_len: Some(
                        settlement_plan.settlement_call.calldata.len() as u64
                    ),
                    settlement_entrypoint: Some(settlement_plan.settlement_call.entrypoint),
                },
            )
            .await?;

            Ok(updated_status)
        }
        Err(error) => {
            set_job_error(state, batch_id, error).await?;
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

async fn submit_onchain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<OnchainSubmissionRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    require_prover_not_paused(&state)?;
    Ok(Json(submit_onchain_inner(&state, &batch_id).await?))
}

async fn submit_onchain_inner(
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
        proof_artifacts
            .get(batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };

    if proof_artifact.native_proof_file_path.is_none()
        || proof_artifact.native_proof_facts_file_path.is_none()
        || proof_artifact.native_execution_request_path.is_none()
    {
        return Err(StatusCode::CONFLICT);
    }

    set_job_submitting_onchain(state, batch_id).await?;

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
        submissions.insert(batch_id.to_owned(), submission.clone());
        persist_record(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            batch_id,
            &submission,
        )?;
    }
    sync_job_with_onchain_submission(state, batch_id, &submission).await?;
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
    let tx_prover_url = state.native_tx_prover_url.clone().ok_or_else(|| {
        "native split auction proof requires ZYLITH_NATIVE_TX_PROVER_URL".to_string()
    })?;
    let executor = state.starknet_executor.clone().ok_or_else(|| {
        "native split auction proof requires Starknet executor config".to_string()
    })?;
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
        params: NativeProverParams {
            block_id: admission_execution_request.block_id.clone(),
            transaction: admission_execution_request.transaction.clone(),
        },
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
        let provider = JsonRpcClient::new(HttpTransport::new(
            Url::parse(&executor.rpc_url)
                .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?,
        ));
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
        if let ExecutionResult::Reverted { reason } = admission_receipt.receipt.execution_result() {
            return Err(format!(
                "admission proof transaction {admission_tx_hash} reverted onchain: {reason}"
            ));
        }
        Some(provider)
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
        params: NativeProverParams {
            block_id: execution_request.block_id.clone(),
            transaction: execution_request.transaction.clone(),
        },
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
        let provider = provider.expect("provider exists when record_onchain is true");
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
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=fetch_batch start");
    let batch = fetch_batch_order_set(state, batch_id).await?;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=fetch_batch ok status={:?} orders={}",
        batch_id,
        batch.batch.status,
        batch.orders.len()
    );
    if state.max_provable_batch_orders > 0
        && batch.orders.len() as u64 > state.max_provable_batch_orders
    {
        eprintln!(
            "prepare_private_auction_batch batch_id={} failed=max_provable_batch_orders orders={} limit={}",
            batch_id,
            batch.orders.len(),
            state.max_provable_batch_orders
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
    let historical_witnesses = {
        let settlement_witnesses = state.settlement_witnesses.read().await;
        let mut merged = indexed_history
            .into_iter()
            .map(|witness| (witness.batch_id.0.clone(), witness))
            .collect::<BTreeMap<_, _>>();
        merged.extend(
            settlement_witnesses
                .values()
                .filter(|witness| witness.batch_id.0 != batch_id)
                .cloned()
                .map(|witness| (witness.batch_id.0.clone(), witness)),
        );
        let merged_witnesses = merged.into_values().collect::<Vec<_>>();
        let confirmed_witnesses =
            filter_root_history_witnesses_for_current_roots(state, merged_witnesses, &prior_roots)?;
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
    let deposit_records = if !records.is_empty() && prior_note_root_nonzero {
        eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=fetch_deposits start");
        fetch_indexed_deposit_records(state).await?
    } else {
        Vec::new()
    };
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=fetch_deposits ok records={}",
        batch_id,
        deposit_records.len()
    );
    let note_root_transitions = if !records.is_empty() && prior_note_root_nonzero {
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
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=build_artifacts start");
    let artifacts = build_settlement_artifacts(
        batch_id,
        &batch.batch,
        &pair,
        &records,
        SettlementBuildContext {
            product_config: &state.product_config,
            prior_roots: &prior_roots,
            deposit_records: &deposit_records,
            note_root_transitions: &note_root_transitions,
            prior_settlement_witnesses: &historical_witnesses,
            prior_note_consolidation_witnesses: &[],
            privacy_gate: Default::default(),
            protocol_fee_recipient: &state.protocol_fee_recipient,
            relay_fee_recipient: &state.relay_fee_recipient,
            attribution_signing_private_key: &state.attribution_signing_private_key,
        },
    )?;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=build_artifacts ok matched_orders={} outputs={}",
        batch_id,
        artifacts.transcript.matched_orders.len(),
        artifacts.transcript.output_notes.len()
    );
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=privacy_metrics start");
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
        state.min_batch_base_liquidity,
        pair.price_base_scale,
    );
    let below_minimum_liquidity = state.min_batch_base_liquidity > 0
        && matched_volume > 0
        && matched_volume < state.min_batch_base_liquidity;
    let matched_participant_count =
        matched_participant_count(&records, &artifacts.transcript.matched_orders);
    let below_minimum_participants = state.min_batch_participants > 0
        && matched_participant_count > 0
        && matched_participant_count < state.min_batch_participants;
    let eligible_order_count = candidate_clearing_price
        .map(|price| eligible_order_count(&records, price, pair.price_base_scale))
        .unwrap_or(0);
    let below_minimum_eligible_orders = state.min_eligible_orders > 0
        && eligible_order_count > 0
        && eligible_order_count < state.min_eligible_orders;
    let single_order_fill_bps =
        max_single_order_fill_share_bps(&artifacts.transcript.matched_orders, matched_volume)?;
    let single_order_dominance_blocked = state.max_single_order_fill_bps > 0
        && single_order_fill_bps > state.max_single_order_fill_bps;
    let single_owner_fill_bps = max_single_owner_fill_share_bps(
        &records,
        &artifacts.transcript.matched_orders,
        matched_volume,
    )?;
    let single_owner_dominance_blocked = state.max_single_owner_fill_bps > 0
        && single_owner_fill_bps > state.max_single_owner_fill_bps;
    let maker_participant_count =
        matched_maker_participant_count(&records, &artifacts.transcript.matched_orders);
    let below_minimum_maker_participants = state.min_maker_participants > 0
        && maker_participant_count > 0
        && maker_participant_count < state.min_maker_participants;
    let maker_fill_bps = max_maker_fill_share_bps(
        &records,
        &artifacts.transcript.matched_orders,
        matched_volume,
    )?;
    let maker_dominance_blocked =
        state.max_maker_fill_bps > 0 && maker_fill_bps > state.max_maker_fill_bps;
    let privacy_blocked = below_minimum_liquidity
        || below_minimum_participants
        || below_minimum_eligible_orders
        || single_order_dominance_blocked
        || single_owner_dominance_blocked
        || below_minimum_maker_participants
        || maker_dominance_blocked;
    eprintln!(
        "prepare_private_auction_batch batch_id={} stage=privacy_metrics ok blocked={} matched_volume={} participants={} eligible={}",
        batch_id, privacy_blocked, matched_volume, matched_participant_count, eligible_order_count
    );
    let privacy_gate_witness = AuctionPrivacyGateWitness {
        enforced: true,
        min_batch_base_liquidity: state.min_batch_base_liquidity,
        min_batch_participants: state.min_batch_participants,
        min_eligible_orders: state.min_eligible_orders,
        max_single_order_fill_bps: state.max_single_order_fill_bps,
        max_single_owner_fill_bps: state.max_single_owner_fill_bps,
        min_maker_participants: state.min_maker_participants,
        max_maker_fill_bps: state.max_maker_fill_bps,
    };
    let prepared_artifacts = if privacy_blocked {
        eprintln!(
            "prepare_private_auction_batch batch_id={batch_id} stage=build_privacy_blocked_artifacts start"
        );
        build_settlement_artifacts(
            batch_id,
            &batch.batch,
            &pair,
            &records,
            SettlementBuildContext {
                product_config: &state.product_config,
                prior_roots: &prior_roots,
                deposit_records: &deposit_records,
                note_root_transitions: &note_root_transitions,
                prior_settlement_witnesses: &historical_witnesses,
                prior_note_consolidation_witnesses: &[],
                privacy_gate: privacy_gate_witness.clone(),
                protocol_fee_recipient: &state.protocol_fee_recipient,
                relay_fee_recipient: &state.relay_fee_recipient,
                attribution_signing_private_key: &state.attribution_signing_private_key,
            },
        )?
    } else if !artifacts.transcript.matched_orders.is_empty() {
        let mut artifacts = artifacts;
        artifacts.settlement_witness.privacy_gate = privacy_gate_witness;
        artifacts
    } else {
        artifacts
    };
    let status = PreparedBatchStatus {
        batch_id: prepared_artifacts.transcript.batch_id.clone(),
        pair_id: batch.batch.pair_id.clone(),
        order_count: records.len() as u64,
        state: if below_minimum_liquidity {
            "proof-auction-below-minimum".into()
        } else if below_minimum_participants {
            "proof-auction-below-participants".into()
        } else if below_minimum_eligible_orders {
            "proof-auction-below-eligible-orders".into()
        } else if single_order_dominance_blocked {
            "proof-auction-dominance-risk".into()
        } else if single_owner_dominance_blocked {
            "proof-auction-owner-dominance-risk".into()
        } else if below_minimum_maker_participants {
            "proof-auction-below-maker-diversity".into()
        } else if maker_dominance_blocked {
            "proof-auction-maker-dominance-risk".into()
        } else if prepared_artifacts.transcript.matched_orders.is_empty() {
            "proof-auction-no-match".into()
        } else {
            "proof-auction-ready".into()
        },
        candidate_clearing_price,
        matched_volume,
        transcript_available: true,
        liquidity,
        order_execution_reports: prepared_artifacts.order_execution_reports.clone(),
    };

    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=publish_artifacts start");
    publish_batch_artifacts_to_coordinator(state, &prepared_artifacts).await?;
    eprintln!("prepare_private_auction_batch batch_id={batch_id} stage=publish_artifacts ok");
    {
        let mut settlement_witnesses = state.settlement_witnesses.write().await;
        settlement_witnesses.insert(
            batch_id.into(),
            prepared_artifacts.settlement_witness.clone(),
        );
        persist_record(
            state.data_dir.as_ref(),
            SETTLEMENT_WITNESSES_DIR,
            batch_id,
            &prepared_artifacts.settlement_witness,
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

fn validate_batch_nullifier_freshness<'a>(
    current_batch_id: &str,
    records: &[DecryptedOrderRecord],
    historical_witnesses: impl IntoIterator<Item = &'a SettlementWitness>,
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

    for witness in historical_witnesses {
        if witness.batch_id.0 == current_batch_id {
            continue;
        }
        for input in &witness.consumed_inputs {
            let historical_nullifier = normalize_felt_hex(&input.nullifier.0)
                .map_err(|error| format!("invalid historical nullifier: {error}"))?;
            if let Some(current_commitment) = current_nullifiers.get(&historical_nullifier) {
                return Err(format!(
                    "funding nullifier for note {} was already reserved by batch {}",
                    current_commitment, witness.batch_id.0
                ));
            }
        }
    }

    Ok(())
}

fn funding_note_commitments_for_report(
    funding_note: &Note,
    funding_notes: &[Note],
) -> Result<Vec<NoteCommitment>, StatusCode> {
    let source_notes = if funding_notes.is_empty() {
        std::slice::from_ref(funding_note)
    } else {
        funding_notes
    };
    source_notes
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
    let batch = fetch_batch_order_set(state, batch_id).await?;
    let pair = state
        .product_config
        .enabled_pair(&batch.batch.pair_id)
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    let records = decrypt_private_auction_orders(state, &batch, &pair).await?;
    Ok(records
        .into_iter()
        .map(|record| AuctionOrderWitness {
            order_commitment: record.order_commitment,
            order: record.order,
            funding_note: record.funding_note,
            funding_notes: record.funding_notes,
            funding_authorization: record.funding_authorization,
        })
        .collect())
}

async fn fetch_current_settlement_roots(state: &AppState) -> Result<SettlementRoots, StatusCode> {
    if env_bool_or_default(NATIVE_PROOF_SMOKE_ZERO_ROOTS_ENV, false) {
        return Ok(SettlementRoots::zero());
    }
    let Some(executor) = &state.starknet_executor else {
        return Ok(SettlementRoots::zero());
    };
    if state.auction_verifier_address.trim().is_empty() {
        return Ok(SettlementRoots::zero());
    }

    let rpc_url = Url::parse(&executor.rpc_url).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
    let call = FunctionCall {
        contract_address: parse_felt(
            &state.auction_verifier_address,
            "ZYLITH_AUCTION_VERIFIER_ADDRESS",
        )
        .map_err(|_| StatusCode::BAD_GATEWAY)?,
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

    Ok(SettlementRoots {
        note_root: format!("{:#x}", result[0]),
        nullifier_root: format!("{:#x}", result[1]),
        renewal_root: format!("{:#x}", result[2]),
        fee_root: format!("{:#x}", result[3]),
    })
}

#[derive(Clone, Debug)]
struct NoteRootTransitionRecord {
    kind: u64,
    key: String,
    batch_root: String,
    new_root: String,
}

async fn fetch_note_root_transition_records(
    state: &AppState,
) -> Result<Vec<NoteRootTransitionRecord>, StatusCode> {
    let Some(executor) = &state.starknet_executor else {
        return Ok(Vec::new());
    };
    if state.auction_verifier_address.trim().is_empty() {
        return Ok(Vec::new());
    }

    let rpc_url = Url::parse(&executor.rpc_url).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
    let contract_address = parse_felt(
        &state.auction_verifier_address,
        "ZYLITH_AUCTION_VERIFIER_ADDRESS",
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

    let selector =
        get_selector_from_name("note_root_transition").map_err(|_| StatusCode::BAD_GATEWAY)?;
    let mut records = Vec::with_capacity(count);
    for transition_id in 0..count {
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
            key: format!("{:#x}", result[1]),
            batch_root: format!("{:#x}", result[2]),
            new_root: format!("{:#x}", result[3]),
        });
    }
    Ok(records)
}

async fn fetch_indexed_deposit_records(state: &AppState) -> Result<Vec<DepositRecord>, StatusCode> {
    let sync_url = format!("{}/api/internal/sync/deposits", state.indexer_url);
    apply_internal_auth(
        state.http_client.post(sync_url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?
    .error_for_status()
    .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let list_url = format!("{}/api/deposits/range/0/{}", state.indexer_url, u64::MAX);
    let response = state
        .http_client
        .get(list_url)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .error_for_status()
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let mut records = response
        .json::<DepositRecordList>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .records;
    records.sort_by_key(|record| record.deposit_id);
    Ok(records)
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
    .map_err(|_| StatusCode::BAD_GATEWAY)?
    .error_for_status()
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let archive = response
        .json::<SettlementRootHistoryArchive>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

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
        new_nullifier_root: batch.new_nullifier_root,
        new_renewal_root: batch.new_renewal_root,
        clearing_price: 0,
        price_base_scale: 1,
        taker_fee_bps: 0,
        maker_fee_bps: 0,
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
        renewal_child_sparse_witnesses: Vec::new(),
        renewal_cancel_sparse_witnesses: Vec::new(),
        privacy_gate: Default::default(),
        renewal_child_uses: Vec::new(),
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
) -> Result<Vec<SettlementWitness>, StatusCode> {
    if !should_filter_root_history_against_onchain(state) {
        return Ok(witnesses);
    }

    let zero = normalize_felt_hex("0x0").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut cursor_nullifier =
        normalize_felt_hex(&roots.nullifier_root).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let mut cursor_renewal =
        normalize_felt_hex(&roots.renewal_root).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if cursor_nullifier == zero && cursor_renewal == zero {
        return Ok(Vec::new());
    }

    let mut candidates = witnesses;
    candidates.sort_by(|left, right| {
        left.batch_epoch
            .cmp(&right.batch_epoch)
            .then_with(|| left.batch_id.0.cmp(&right.batch_id.0))
    });
    let mut selected = Vec::new();
    while cursor_nullifier != zero || cursor_renewal != zero {
        let Some(position) = candidates.iter().rposition(|witness| {
            normalize_felt_hex(&witness.new_nullifier_root)
                .map(|root| root == cursor_nullifier)
                .unwrap_or(false)
                && normalize_felt_hex(&witness.new_renewal_root)
                    .map(|root| root == cursor_renewal)
                    .unwrap_or(false)
        }) else {
            eprintln!(
                "filter_root_history_witnesses_for_current_roots failed missing cursor_nullifier={} cursor_renewal={}",
                cursor_nullifier, cursor_renewal
            );
            return Err(StatusCode::CONFLICT);
        };
        let witness = candidates.remove(position);
        cursor_nullifier =
            normalize_felt_hex(&witness.prior_nullifier_root).map_err(|_| StatusCode::CONFLICT)?;
        cursor_renewal =
            normalize_felt_hex(&witness.prior_renewal_root).map_err(|_| StatusCode::CONFLICT)?;
        selected.push(witness);
    }
    selected.reverse();
    Ok(selected)
}

fn should_filter_root_history_against_onchain(state: &AppState) -> bool {
    state.starknet_executor.is_some()
        && !state.auction_verifier_address.trim().is_empty()
        && state.auction_verifier_address.trim() != "0x123"
}

fn max_single_order_fill_share_bps(
    matched_orders: &[MatchedOrder],
    matched_volume: u128,
) -> Result<u64, StatusCode> {
    if matched_volume == 0 {
        return Ok(0);
    }
    let max_fill = matched_orders
        .iter()
        .map(|order| order.filled_amount)
        .max()
        .unwrap_or(0);
    let bps = max_fill.checked_mul(10_000).ok_or(StatusCode::CONFLICT)? / matched_volume;
    Ok(bps.min(u64::MAX as u128) as u64)
}

fn max_maker_fill_share_bps(
    records: &[DecryptedOrderRecord],
    matched_orders: &[MatchedOrder],
    matched_volume: u128,
) -> Result<u64, StatusCode> {
    if matched_volume == 0 {
        return Ok(0);
    }
    let order_types = records
        .iter()
        .map(|record| (record.order_commitment.0.as_str(), &record.order.order_type))
        .collect::<BTreeMap<_, _>>();
    let max_maker_fill = matched_orders
        .iter()
        .filter(|order| {
            order_types
                .get(order.order_commitment.0.as_str())
                .is_some_and(|order_type| matches!(order_type, OrderType::MakerCurve))
        })
        .map(|order| order.filled_amount)
        .max()
        .unwrap_or(0);
    let bps = max_maker_fill
        .checked_mul(10_000)
        .ok_or(StatusCode::CONFLICT)?
        / matched_volume;
    Ok(bps.min(u64::MAX as u128) as u64)
}

fn eligible_order_count(
    records: &[DecryptedOrderRecord],
    price: u128,
    price_base_scale: u128,
) -> u64 {
    records
        .iter()
        .filter(|record| {
            is_order_eligible(&record.order, price)
                && max_fill_at_price(record, price, price_base_scale) > 0
        })
        .count() as u64
}

fn max_single_owner_fill_share_bps(
    records: &[DecryptedOrderRecord],
    matched_orders: &[MatchedOrder],
    matched_volume: u128,
) -> Result<u64, StatusCode> {
    if matched_volume == 0 {
        return Ok(0);
    }
    let owners = records
        .iter()
        .map(|record| {
            (
                record.order_commitment.0.as_str(),
                record.funding_note.owner_public_key.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut fill_by_owner = BTreeMap::<&str, u128>::new();
    for order in matched_orders
        .iter()
        .filter(|order| order.filled_amount > 0)
    {
        let Some(owner) = owners.get(order.order_commitment.0.as_str()) else {
            continue;
        };
        let total = fill_by_owner.entry(owner).or_default();
        *total = total
            .checked_add(order.filled_amount)
            .ok_or(StatusCode::CONFLICT)?;
    }
    let max_owner_fill = fill_by_owner.values().copied().max().unwrap_or(0);
    let bps = max_owner_fill
        .checked_mul(10_000)
        .ok_or(StatusCode::CONFLICT)?
        / matched_volume;
    Ok(bps.min(u64::MAX as u128) as u64)
}

fn matched_maker_participant_count(
    records: &[DecryptedOrderRecord],
    matched_orders: &[MatchedOrder],
) -> u64 {
    let matched_commitments = matched_orders
        .iter()
        .filter(|order| order.filled_amount > 0)
        .map(|order| order.order_commitment.0.as_str())
        .collect::<BTreeSet<_>>();
    records
        .iter()
        .filter(|record| matched_commitments.contains(record.order_commitment.0.as_str()))
        .filter(|record| matches!(record.order.order_type, OrderType::MakerCurve))
        .map(|record| record.funding_note.owner_public_key.as_str())
        .collect::<BTreeSet<_>>()
        .len() as u64
}

fn matched_participant_count(
    records: &[DecryptedOrderRecord],
    matched_orders: &[MatchedOrder],
) -> u64 {
    let matched_commitments = matched_orders
        .iter()
        .filter(|order| order.filled_amount > 0)
        .map(|order| order.order_commitment.0.as_str())
        .collect::<BTreeSet<_>>();
    records
        .iter()
        .filter(|record| matched_commitments.contains(record.order_commitment.0.as_str()))
        .map(|record| record.funding_note.owner_public_key.as_str())
        .collect::<BTreeSet<_>>()
        .len() as u64
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

async fn publish_batch_artifacts_to_coordinator(
    state: &AppState,
    artifacts: &SettlementArtifacts,
) -> Result<(), StatusCode> {
    let batch_id = &artifacts.transcript.batch_id.0;
    let transcript_shape = zylith_core::validate_transcript_shape_policy(
        &artifacts.transcript,
        &artifacts.output_bundle,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let payload = PublishedBatchArtifacts {
        transcript: artifacts.transcript.clone(),
        output_bundle: artifacts.output_bundle.clone(),
        maker_attribution_bundle: artifacts.maker_attribution_bundle.clone(),
        settlement_witness: artifacts.settlement_witness.clone(),
        published_at_unix_ms: now_unix_ms(),
        settled_at_unix_ms: None,
        order_execution_reports: artifacts.order_execution_reports.clone(),
        transcript_shape: Some(transcript_shape),
    };
    let coordinator_url = format!(
        "{}/api/internal/batches/{batch_id}/artifacts",
        state.coordinator_url
    );
    let indexer_url = format!(
        "{}/api/internal/batches/{batch_id}/artifacts",
        state.indexer_url
    );
    apply_internal_auth(
        state.http_client.post(coordinator_url).json(&payload),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|error| {
        eprintln!(
            "publish_batch_artifacts batch_id={} target=coordinator send_failed={}",
            batch_id, error
        );
        StatusCode::BAD_GATEWAY
    })?
    .error_for_status()
    .map_err(|error| {
        eprintln!(
            "publish_batch_artifacts batch_id={} target=coordinator status_failed={}",
            batch_id, error
        );
        StatusCode::BAD_GATEWAY
    })?;
    apply_internal_auth(
        state.http_client.post(indexer_url).json(&payload),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|error| {
        eprintln!(
            "publish_batch_artifacts batch_id={} target=indexer send_failed={}",
            batch_id, error
        );
        StatusCode::BAD_GATEWAY
    })?
    .error_for_status()
    .map_err(|error| {
        eprintln!(
            "publish_batch_artifacts batch_id={} target=indexer status_failed={}",
            batch_id, error
        );
        StatusCode::BAD_GATEWAY
    })?;

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

    match (maybe_status, maybe_witness) {
        (Some(status), Some(witness)) => Ok((status, witness)),
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
        prover_backend: prover_backend_label(state.native_tx_prover_url.is_some()),
        last_error: None,
        created_at_unix_ms,
        updated_at_unix_ms: now,
        settlement_contract_address: state.auction_verifier_address.clone(),
        settlement_entrypoint: settlement_entrypoint.into(),
        settlement_calldata_len: 0,
    };

    {
        let mut proof_jobs = state.proof_jobs.write().await;
        proof_jobs.insert(batch_id.into(), status.clone());
        persist_record(state.data_dir.as_ref(), PROOF_JOBS_DIR, batch_id, &status)?;
    }
    {
        let mut settlement_plans = state.settlement_plans.write().await;
        settlement_plans.remove(batch_id);
        delete_record_if_exists(state.data_dir.as_ref(), SETTLEMENT_PLANS_DIR, batch_id)?;
    }
    {
        let mut settlement_witnesses = state.settlement_witnesses.write().await;
        settlement_witnesses.insert(batch_id.into(), settlement_witness.clone());
        persist_record(
            state.data_dir.as_ref(),
            SETTLEMENT_WITNESSES_DIR,
            batch_id,
            &settlement_witness,
        )?;
    }
    {
        let mut proof_artifacts = state.proof_artifacts.write().await;
        proof_artifacts.remove(batch_id);
        delete_record_if_exists(state.data_dir.as_ref(), PROOF_ARTIFACTS_DIR, batch_id)?;
    }
    {
        let mut onchain_submissions = state.onchain_submissions.write().await;
        onchain_submissions.remove(batch_id);
        delete_record_if_exists(state.data_dir.as_ref(), ONCHAIN_SUBMISSIONS_DIR, batch_id)?;
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
    let status = proof_jobs.get_mut(batch_id).ok_or(StatusCode::NOT_FOUND)?;
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
    persist_record(state.data_dir.as_ref(), PROOF_JOBS_DIR, batch_id, status)?;
    Ok(status.clone())
}

async fn sync_job_with_onchain_submission(
    state: &AppState,
    batch_id: &str,
    submission: &OnchainSubmissionRecord,
) -> Result<ProofJobStatus, StatusCode> {
    let mut proof_jobs = state.proof_jobs.write().await;
    let status = proof_jobs.get_mut(batch_id).ok_or(StatusCode::NOT_FOUND)?;

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
    persist_record(state.data_dir.as_ref(), PROOF_JOBS_DIR, batch_id, status)?;

    Ok(status.clone())
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
    let payload = SettlementTimestampUpdate { settled_at_unix_ms };
    let targets = [
        format!(
            "{}/api/internal/batches/{batch_id}/settled-at",
            state.coordinator_url
        ),
        format!(
            "{}/api/internal/batches/{batch_id}/settled-at",
            state.indexer_url
        ),
    ];
    for target in targets {
        apply_internal_auth(
            state.http_client.post(&target).json(&payload),
            state
                .internal_api_token
                .as_ref()
                .map(|token| token.as_str()),
        )
        .send()
        .await
        .map_err(|error| format!("settlement timestamp publish failed for {target}: {error}"))?
        .error_for_status()
        .map_err(|error| format!("settlement timestamp publish rejected by {target}: {error}"))?;
    }
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
        prover_backend: prover_backend_label(state.native_tx_prover_url.is_some()),
        last_error: Some(error),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        settlement_contract_address: state.auction_verifier_address.clone(),
        settlement_entrypoint: "submit_settlement_with_proof_facts".into(),
        settlement_calldata_len: 0,
    };
    {
        let mut proof_jobs = state.proof_jobs.write().await;
        proof_jobs.insert(batch_id.into(), status.clone());
        persist_record(state.data_dir.as_ref(), PROOF_JOBS_DIR, batch_id, &status)?;
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
            next_state: "onchain-submit-failed".into(),
            proof_artifact_id: existing.proof_artifact_id,
            last_error: Some(error),
            proof_artifact_available: existing.proof_artifact_available,
            settlement_plan_available: Some(existing.settlement_plan_available),
            settlement_calldata_len: Some(existing.settlement_calldata_len),
            settlement_entrypoint: Some(existing.settlement_entrypoint),
        },
    )
    .await
}

async fn execute_stwo_prover(
    state: &AppState,
    batch_id: &str,
    settlement_witness: &SettlementWitness,
    _auction_order_witnesses: &[AuctionOrderWitness],
) -> Result<ProofArtifactRecord, String> {
    let manifest_workdir = state
        .stwo_manifest_path
        .parent()
        .ok_or_else(|| "invalid stwo manifest path".to_string())?;
    let paths = proof_execution_paths(state.data_dir.as_ref(), batch_id);
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), batch_id)
        .map_err(status_to_error)?;

    persist_json_file(&paths.witness_path, settlement_witness).map_err(status_to_error)?;
    let serialized_input = zylith_core::build_stwo_serialized_input(settlement_witness)
        .map_err(|error| format!("failed to serialize settlement witness for S-two: {error}"))?;
    persist_json_file(&paths.public_inputs_path, &serialized_input).map_err(status_to_error)?;

    let mut prove_command = build_stwo_prove_command(
        &state.scarb_bin,
        state.stwo_manifest_path.as_ref(),
        &state.stwo_package_name,
        &paths.public_inputs_path,
    );
    let prove_output = task::spawn_blocking(move || prove_command.output())
        .await
        .map_err(|join_error| format!("stwo prove join error: {join_error}"))?
        .map_err(|io_error| format!("stwo prove spawn error: {io_error}"))?;

    let prove_stdout = String::from_utf8_lossy(&prove_output.stdout).into_owned();
    let prove_stderr = String::from_utf8_lossy(&prove_output.stderr).into_owned();

    if !prove_output.status.success() {
        fs::write(&paths.stdout_path, &prove_stdout)
            .map_err(|error| format!("failed to persist prover stdout: {error}"))?;
        fs::write(&paths.stderr_path, &prove_stderr)
            .map_err(|error| format!("failed to persist prover stderr: {error}"))?;
        return Err(format!(
            "stwo prove exited with status {}{}",
            prove_output.status,
            if prove_stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", prove_stderr.trim())
            }
        ));
    }

    let prove_status_lines = parse_scarb_status_lines(&prove_stdout);
    let raw_proof_path = extract_proof_path(&prove_status_lines).ok_or_else(|| {
        format!("could not locate proof path in scarb prove output: {prove_stdout}")
    })?;
    let source_proof_path = resolve_proof_path(manifest_workdir, &raw_proof_path);
    if !source_proof_path.exists() {
        return Err(format!(
            "stwo prove reported proof path {}, but the file does not exist",
            source_proof_path.display()
        ));
    }

    fs::copy(&source_proof_path, &paths.proof_path)
        .map_err(|error| format!("failed to copy proof artifact: {error}"))?;

    let mut verify_command = build_stwo_verify_command(
        &state.scarb_bin,
        state.stwo_manifest_path.as_ref(),
        &paths.proof_path,
    );
    let verify_output = task::spawn_blocking(move || verify_command.output())
        .await
        .map_err(|join_error| format!("stwo verify join error: {join_error}"))?
        .map_err(|io_error| format!("stwo verify spawn error: {io_error}"))?;

    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout).into_owned();
    let verify_stderr = String::from_utf8_lossy(&verify_output.stderr).into_owned();

    fs::write(
        &paths.stdout_path,
        format!(
            "=== scarb prove stdout ===\n{prove_stdout}\n=== scarb verify stdout ===\n{verify_stdout}\n"
        ),
    )
    .map_err(|error| format!("failed to persist prover stdout: {error}"))?;
    fs::write(
        &paths.stderr_path,
        format!(
            "=== scarb prove stderr ===\n{prove_stderr}\n=== scarb verify stderr ===\n{verify_stderr}\n"
        ),
    )
    .map_err(|error| format!("failed to persist prover stderr: {error}"))?;

    if !verify_output.status.success() {
        return Err(format!(
            "stwo verify exited with status {}{}",
            verify_output.status,
            if verify_stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", verify_stderr.trim())
            }
        ));
    }

    let verify_status_lines = parse_scarb_status_lines(&verify_stdout);
    if !verify_status_lines
        .iter()
        .any(|line| line.status == "verified")
    {
        return Err(format!(
            "stwo verify completed without a verified status line: {verify_stdout}"
        ));
    }

    let proof_sha256 = sha256_file_hex(&paths.proof_path)?;
    let public_inputs_sha256 = sha256_file_hex(&paths.public_inputs_path)?;
    let proof_artifact_commitment = proof_artifact_commitment(&proof_sha256, &public_inputs_sha256)
        .map_err(|error| format!("failed to derive proof artifact commitment: {error}"))?;
    let artifact_id = artifact_id_for(batch_id, &settlement_witness.transcript_commitment);

    Ok(ProofArtifactRecord {
        artifact_id,
        batch_id: settlement_witness.batch_id.clone(),
        proof_system: "s-two".into(),
        proof_format: "scarb-proof-json".into(),
        prover_backend: prover_backend_label(state.native_tx_prover_url.is_some()),
        created_at_unix_ms: now_unix_ms(),
        proof_artifact_commitment,
        proof_path: paths.proof_path.display().to_string(),
        public_inputs_path: paths.public_inputs_path.display().to_string(),
        prover_stdout_path: paths.stdout_path.display().to_string(),
        prover_stderr_path: paths.stderr_path.display().to_string(),
        proof_sha256,
        public_inputs_sha256,
        native_proof_file_path: None,
        native_proof_facts_file_path: None,
        native_execution_request_path: None,
        native_nullifier_proof_file_path: None,
        native_nullifier_proof_facts_file_path: None,
        native_nullifier_execution_request_path: None,
        native_renewal_proof_file_path: None,
        native_renewal_proof_facts_file_path: None,
        native_renewal_execution_request_path: None,
    })
}

async fn execute_native_transaction_prover(
    state: &AppState,
    batch_id: &str,
    transcript: &SettlementTranscript,
    settlement_witness: &SettlementWitness,
    _auction_order_witnesses: &[AuctionOrderWitness],
) -> Result<ProofArtifactRecord, String> {
    let tx_prover_url = state
        .native_tx_prover_url
        .clone()
        .ok_or_else(|| "native transaction prover is not configured".to_string())?;
    let executor = state
        .starknet_executor
        .clone()
        .ok_or_else(|| "starknet executor is not configured".to_string())?;
    let transcript_commitment =
        settlement_transcript_commitment(transcript).map_err(|error| error.to_string())?;
    ensure_batch_registered_onchain(state, batch_id).await?;
    let native_proof_reference =
        native_settlement_message_hash(&state.auction_verifier_address, &transcript_commitment)
            .map_err(|error| error.to_string())?;
    let roots = root_only_settlement_commitments(transcript).map_err(|error| error.to_string())?;
    let expected_settlement_proof_message_hash = settlement_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &transcript_commitment,
    )
    .map_err(|error| error.to_string())?;
    let expected_nullifier_proof_message_hash = nullifier_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &transcript_commitment,
        &roots.prior_nullifier_root,
        &roots.consumed_nullifier_root,
        &roots.new_nullifier_root,
    )
    .map_err(|error| error.to_string())?;
    let expected_renewal_proof_message_hash = renewal_proof_message_hash_for_program(
        &state.native_proof_program_address,
        &state.auction_verifier_address,
        &transcript_commitment,
        &roots.prior_renewal_root,
        &roots.renewal_child_root,
        &roots.new_renewal_root,
    )
    .map_err(|error| error.to_string())?;

    let _settlement_plan = build_settlement_submission_plan(
        transcript,
        &state.auction_verifier_address,
        &native_proof_reference,
    )
    .map_err(|error| error.to_string())?;
    if settlement_witness.transcript_commitment != transcript_commitment {
        return Err("settlement witness commitment does not match transcript".into());
    }
    let serialized_native_witness = zylith_core::build_stwo_serialized_input(settlement_witness)
        .map_err(|error| {
            format!("failed to serialize settlement witness for native proof: {error}")
        })?;
    let settlement_statement = execute_native_statement_prover(NativeStatementProverRequest {
        state,
        tx_prover_url: &tx_prover_url,
        executor: &executor,
        batch_id,
        stage_key: batch_id,
        entrypoint: &state.native_proof_entrypoint,
        serialized_native_witness: &serialized_native_witness,
        expected_message_hashes: &[expected_settlement_proof_message_hash],
    })
    .await?;
    let nullifier_stage_key = format!("{batch_id}-nullifier");
    let nullifier_statement = execute_native_statement_prover(NativeStatementProverRequest {
        state,
        tx_prover_url: &tx_prover_url,
        executor: &executor,
        batch_id,
        stage_key: &nullifier_stage_key,
        entrypoint: "compile_nullifier_proof",
        serialized_native_witness: &serialized_native_witness,
        expected_message_hashes: &[expected_nullifier_proof_message_hash],
    })
    .await?;
    let renewal_stage_key = format!("{batch_id}-renewal");
    let renewal_statement = execute_native_statement_prover(NativeStatementProverRequest {
        state,
        tx_prover_url: &tx_prover_url,
        executor: &executor,
        batch_id,
        stage_key: &renewal_stage_key,
        entrypoint: "compile_renewal_proof",
        serialized_native_witness: &serialized_native_witness,
        expected_message_hashes: &[expected_renewal_proof_message_hash],
    })
    .await?;

    let artifact_id = artifact_id_for(batch_id, &transcript_commitment);

    Ok(ProofArtifactRecord {
        artifact_id,
        batch_id: transcript.batch_id.clone(),
        proof_system: "starknet-snip36".into(),
        proof_format: "virtual-tx-proof".into(),
        prover_backend: prover_backend_label(true),
        created_at_unix_ms: now_unix_ms(),
        proof_artifact_commitment: native_proof_reference,
        proof_path: settlement_statement.proof_path.clone(),
        public_inputs_path: settlement_statement.proof_facts_path.clone(),
        prover_stdout_path: settlement_statement.stdout_path.clone(),
        prover_stderr_path: settlement_statement.stderr_path.clone(),
        proof_sha256: settlement_statement.proof_sha256.clone(),
        public_inputs_sha256: settlement_statement.proof_facts_sha256.clone(),
        native_proof_file_path: Some(settlement_statement.proof_path),
        native_proof_facts_file_path: Some(settlement_statement.proof_facts_path),
        native_execution_request_path: Some(settlement_statement.execution_request_path),
        native_nullifier_proof_file_path: Some(nullifier_statement.proof_path),
        native_nullifier_proof_facts_file_path: Some(nullifier_statement.proof_facts_path),
        native_nullifier_execution_request_path: Some(nullifier_statement.execution_request_path),
        native_renewal_proof_file_path: Some(renewal_statement.proof_path),
        native_renewal_proof_facts_file_path: Some(renewal_statement.proof_facts_path),
        native_renewal_execution_request_path: Some(renewal_statement.execution_request_path),
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
        params: NativeProverParams {
            block_id: execution_request.block_id.clone(),
            transaction: execution_request.transaction.clone(),
        },
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
    if let Some(ohttp_config) = &state.native_tx_prover_ohttp {
        return request_native_proof_ohttp(state, tx_prover_url, ohttp_config, rpc_request).await;
    }
    let response_value = tokio::time::timeout(
        Duration::from_secs(state.native_prover_request_timeout_seconds),
        async {
            let response = state
                .http_client
                .post(tx_prover_url)
                .json(rpc_request)
                .send()
                .await
                .map_err(|error| format!("native transaction prover request failed: {error}"))?;
            response.json::<serde_json::Value>().await.map_err(|error| {
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
            let target_url = ohttp_config.relay_url.as_deref().unwrap_or(tx_prover_url);
            let response = state
                .http_client
                .post(target_url)
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
            let response_bytes = response.bytes().await.map_err(|error| {
                format!("native transaction prover OHTTP response read failed: {error}")
            })?;
            if !status.is_success() && !content_type.contains("message/ohttp-res") {
                let body = String::from_utf8_lossy(&response_bytes);
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
                return Err(format!(
                    "native transaction prover OHTTP inner response HTTP {inner_status}: {}",
                    String::from_utf8_lossy(&inner_body)
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
            "{NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX_ENV} is required when {NATIVE_TX_PROVER_OHTTP_ENABLED_ENV}=true and ZYLITH_NATIVE_TX_PROVER_URL is not HTTPS"
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
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "native transaction prover OHTTP key fetch returned HTTP {status}: {body}"
        ));
    }
    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|error| {
            format!("native transaction prover OHTTP key response read failed: {error}")
        })
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
            return Err(format!(
                "native transaction prover error {}: {}{}",
                error.code,
                error.message,
                error
                    .data
                    .map(|value| format!(" ({value})"))
                    .unwrap_or_default()
            ));
        }
        _ => return Err("native transaction prover returned no result".to_string()),
    };
    validate_native_prover_l2_messages(&result)?;

    Ok((result, response_value))
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
    proof_artifact: &ProofArtifactRecord,
) -> Result<SettlementSubmissionPlan, zylith_core::ProtocolError> {
    build_settlement_submission_plan(
        transcript,
        auction_verifier_address,
        &proof_artifact.proof_artifact_commitment,
    )
}

async fn fetch_transcript(
    state: &AppState,
    batch_id: &str,
) -> Result<SettlementTranscript, StatusCode> {
    let url = format!(
        "{}/api/internal/batches/{}/transcript",
        state.coordinator_url, batch_id
    );
    apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?
    .error_for_status()
    .map_err(|status| {
        if status.status() == Some(reqwest::StatusCode::NOT_FOUND) {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_GATEWAY
        }
    })?
    .json()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)
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
    let url = format!(
        "{}/api/internal/batches/{}/orders",
        state.coordinator_url, batch_id
    );
    apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?
    .error_for_status()
    .map_err(|status| {
        if status.status() == Some(reqwest::StatusCode::NOT_FOUND) {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_GATEWAY
        }
    })?
    .json()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)
}

async fn fetch_witness(state: &AppState, batch_id: &str) -> Result<SettlementWitness, StatusCode> {
    let url = format!(
        "{}/api/internal/batches/{}/witness",
        state.coordinator_url, batch_id
    );
    apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?
    .error_for_status()
    .map_err(|status| {
        if status.status() == Some(reqwest::StatusCode::NOT_FOUND) {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_GATEWAY
        }
    })?
    .json()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)
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
    } else if min_base_liquidity > 0 && matched_base_volume < min_base_liquidity {
        (
            "below_minimum",
            "matched volume is below the configured launch-liquidity threshold",
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct OutputNettingKey {
    asset_id: String,
    owner_public_key: String,
    spend_authority: String,
    withdraw_authority: String,
    metadata_commitment: String,
}

struct OutputNettingGroup {
    template: Note,
    amount: u128,
    old_commitments: Vec<String>,
}

struct OutputNettingResult {
    bundle: OutputCiphertextBundle,
    note_preimages: Vec<Note>,
    recovery_records: Vec<OutputRecoveryRecord>,
    recovery_dummy_commitments: Vec<String>,
}

fn add_output_to_netting_group(
    groups: &mut BTreeMap<OutputNettingKey, OutputNettingGroup>,
    note: &Note,
) -> Result<(), StatusCode> {
    let old_commitment = note
        .commitment()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .0;
    let key = OutputNettingKey {
        asset_id: note.asset_id.0.clone(),
        owner_public_key: note.owner_public_key.clone(),
        spend_authority: normalize_felt_hex(&note.spend_authority)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        withdraw_authority: normalize_felt_hex(&note.withdraw_authority)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        metadata_commitment: normalize_felt_hex(&note.metadata_commitment)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    };
    let entry = groups.entry(key).or_insert_with(|| OutputNettingGroup {
        template: note.clone(),
        amount: 0,
        old_commitments: Vec::new(),
    });
    entry.amount = entry
        .amount
        .checked_add(note.amount)
        .ok_or(StatusCode::CONFLICT)?;
    entry.old_commitments.push(old_commitment);
    Ok(())
}

fn apply_cross_order_output_netting(
    batch_id: &str,
    output_notes: &mut Vec<OutputNoteRecord>,
    matched_order_witnesses: &mut [MatchedOrderWitness],
    order_execution_reports: &mut [OrderExecutionReport],
) -> Result<OutputNettingResult, StatusCode> {
    let mut groups = BTreeMap::<OutputNettingKey, OutputNettingGroup>::new();
    for witness in matched_order_witnesses.iter() {
        add_output_to_netting_group(&mut groups, &witness.output_note)?;
        if let Some(residual_note) = witness.residual_note.as_ref() {
            add_output_to_netting_group(&mut groups, residual_note)?;
        }
    }

    let mut replacements = BTreeMap::<String, Note>::new();
    let mut netted_records = Vec::with_capacity(groups.len());
    let mut netted_notes = Vec::with_capacity(groups.len());
    for (_key, group) in groups.into_iter() {
        let output_index = netted_records.len();
        let mut note = group.template.clone();
        note.amount = group.amount;
        note.nonce = (output_index as u64).saturating_add(1);
        let note_commitment = note
            .commitment()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        for old_commitment in group.old_commitments {
            replacements.insert(old_commitment, note.clone());
        }
        netted_notes.push(note.clone());
        netted_records.push(OutputNoteRecord {
            note_commitment,
            asset_id: note.asset_id.clone(),
            amount: note.amount,
            withdraw_authority: note.withdraw_authority.clone(),
        });
    }

    for witness in matched_order_witnesses.iter_mut() {
        let old_output_commitment = witness
            .output_note
            .commitment()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .0;
        witness.output_note = replacements
            .get(&old_output_commitment)
            .cloned()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Some(residual_note) = witness.residual_note.as_mut() {
            let old_residual_commitment = residual_note
                .commitment()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .0;
            *residual_note = replacements
                .get(&old_residual_commitment)
                .cloned()
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }

    for report in order_execution_reports.iter_mut() {
        if let Some(old_commitment) = report
            .output_note_commitment
            .as_ref()
            .map(|commitment| commitment.0.clone())
            && let Some(note) = replacements.get(&old_commitment)
        {
            report.output_note_commitment = Some(
                note.commitment()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            );
        }
        if let Some(old_commitment) = report
            .residual_note_commitment
            .as_ref()
            .map(|commitment| commitment.0.clone())
            && let Some(note) = replacements.get(&old_commitment)
        {
            report.residual_note_commitment = Some(
                note.commitment()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            );
        }
    }

    *output_notes = netted_records;
    let mut ciphertexts = Vec::with_capacity(output_notes.len());
    for (output_index, (note, output_note)) in
        netted_notes.iter().zip(output_notes.iter()).enumerate()
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
        note_preimages: netted_notes,
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
    activation_commitments: &[String],
    consumed_commitments: &[String],
) -> Result<Option<Vec<NoteMembershipWitness>>, StatusCode> {
    let prior_note_root =
        normalize_felt_hex(prior_note_root).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let consumed_set = consumed_commitments
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for start_index in 0..activation_commitments.len() {
        let suffix = &activation_commitments[start_index..];
        let suffix_set = suffix.iter().cloned().collect::<BTreeSet<_>>();
        if !consumed_set.is_subset(&suffix_set) {
            continue;
        }
        let (candidate_root, witnesses) =
            deposit_note_membership_witnesses_for_chain("0x0", suffix, consumed_commitments)
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
    prior_note_consolidation_witnesses: &[NoteConsolidationWitness],
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
    for witness in prior_note_consolidation_witnesses {
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
    Ok(None)
}

fn derive_note_membership_witnesses_from_note_root_transitions(
    prior_note_root: &str,
    consumed_commitments: &[String],
    transitions: &[NoteRootTransitionRecord],
    prior_settlement_witnesses: &[SettlementWitness],
    prior_note_consolidation_witnesses: &[NoteConsolidationWitness],
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
    let mut root = "0x0".to_string();
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
            let key = normalize_felt_hex(&transition.key)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if !consumed_set.contains(&key) {
                continue;
            }
            if witnesses_by_commitment
                .insert(
                    key,
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
                prior_note_consolidation_witnesses,
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

fn derive_note_membership_witnesses(
    prior_note_root: &str,
    consumed_inputs: &[ConsumedInput],
    matched_order_witnesses: &[MatchedOrderWitness],
    deposit_records: &[DepositRecord],
    note_root_transitions: &[NoteRootTransitionRecord],
    prior_settlement_witnesses: &[SettlementWitness],
    prior_note_consolidation_witnesses: &[NoteConsolidationWitness],
) -> Result<Vec<NoteMembershipWitness>, StatusCode> {
    if consumed_inputs.is_empty() {
        return Ok(Vec::new());
    }
    let consumed_commitments = consumed_inputs
        .iter()
        .map(|input| normalize_felt_hex(&input.note_commitment.0))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(witnesses) = derive_note_membership_witnesses_from_note_root_transitions(
        prior_note_root,
        &consumed_commitments,
        note_root_transitions,
        prior_settlement_witnesses,
        prior_note_consolidation_witnesses,
    )? {
        return Ok(witnesses);
    }

    let mut candidates = Vec::<Vec<String>>::new();
    if !deposit_records.is_empty() {
        candidates.push(
            deposit_records
                .iter()
                .map(|record| normalize_felt_hex(&record.note_commitment.0))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
    }

    let mut funding_notes = matched_order_witnesses
        .iter()
        .flat_map(|witness| {
            witness
                .effective_funding_notes()
                .into_iter()
                .map(|note| Ok((note.nonce, note_commitment_from_note(note)?)))
                .collect::<Vec<Result<(u64, String), StatusCode>>>()
        })
        .collect::<Result<Vec<_>, StatusCode>>()?;
    funding_notes.sort_by_key(|(nonce, commitment)| (*nonce, commitment.clone()));
    let funding_activation_commitments = funding_notes
        .into_iter()
        .map(|(_nonce, commitment)| commitment)
        .collect::<Vec<_>>();
    if !funding_activation_commitments.is_empty()
        && !candidates.contains(&funding_activation_commitments)
    {
        candidates.push(funding_activation_commitments);
    }

    for activation_commitments in candidates {
        if let Some(witnesses) = try_deposit_membership_candidate(
            prior_note_root,
            &activation_commitments,
            &consumed_commitments,
        )? {
            return Ok(witnesses);
        }
    }

    Ok(Vec::new())
}

struct SettlementBuildContext<'a> {
    product_config: &'a ProductConfig,
    prior_roots: &'a SettlementRoots,
    deposit_records: &'a [DepositRecord],
    note_root_transitions: &'a [NoteRootTransitionRecord],
    prior_settlement_witnesses: &'a [SettlementWitness],
    prior_note_consolidation_witnesses: &'a [NoteConsolidationWitness],
    privacy_gate: AuctionPrivacyGateWitness,
    protocol_fee_recipient: &'a str,
    relay_fee_recipient: &'a str,
    attribution_signing_private_key: &'a str,
}

fn build_settlement_artifacts(
    batch_id: &str,
    batch: &BatchSummary,
    pair: &ProductPairConfig,
    records: &[DecryptedOrderRecord],
    context: SettlementBuildContext<'_>,
) -> Result<SettlementArtifacts, StatusCode> {
    let SettlementBuildContext {
        product_config,
        prior_roots,
        deposit_records,
        note_root_transitions,
        prior_settlement_witnesses,
        prior_note_consolidation_witnesses,
        privacy_gate,
        protocol_fee_recipient,
        relay_fee_recipient,
        attribution_signing_private_key,
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

    eprintln!("build_settlement_artifacts batch_id={batch_id} stage=compute_price start");
    let candidate_clearing_price =
        compute_candidate_clearing_price(records, pair.price_base_scale)?;
    let candidate_price = candidate_clearing_price.unwrap_or(0);
    let fills = if privacy_gate.enforced {
        Vec::new()
    } else {
        compute_fill_plan(records, candidate_price, pair.price_base_scale)
    };
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=compute_price ok price={} fills={}",
        batch_id,
        candidate_price,
        fills.len()
    );
    let clearing_price = candidate_price;
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
        let protocol_fee_amount = gross_amount
            .checked_mul(protocol_fee_bps)
            .ok_or(StatusCode::CONFLICT)?
            / 10_000;
        let relay_fee_amount = gross_amount
            .checked_mul(relay_fee_bps)
            .ok_or(StatusCode::CONFLICT)?
            / 10_000;
        let fee_amount = protocol_fee_amount
            .checked_add(relay_fee_amount)
            .ok_or(StatusCode::CONFLICT)?;
        let net_amount = gross_amount
            .checked_sub(fee_amount)
            .ok_or(StatusCode::CONFLICT)?;
        if gross_amount == 0 || net_amount == 0 {
            eprintln!(
                "build_settlement_artifacts batch_id={batch_id} stage=build_fills failed=dust_output order={} asset={} gross={} net={}",
                fill.order_commitment.0, asset_id.0, gross_amount, net_amount
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
        let maker_band_attribution = maker_band_attribution_for_fill(fill, clearing_price)
            .map_err(|_| StatusCode::CONFLICT)?;
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
            maker_curve: fill.order.maker_curve.clone(),
            maker_band_attribution,
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

    eprintln!("build_settlement_artifacts batch_id={batch_id} stage=output_netting start");
    let output_netting = apply_cross_order_output_netting(
        batch_id,
        &mut output_notes,
        &mut matched_order_witnesses,
        &mut order_execution_reports,
    )?;
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=output_netting ok outputs={} recovery_records={}",
        batch_id,
        output_notes.len(),
        output_netting.recovery_records.len()
    );
    let maker_attribution_bundle = build_maker_attribution_bundle(
        batch_id,
        &pair.pair_id,
        batch.epoch_id,
        &matched_order_witnesses,
        attribution_signing_private_key,
    )?;
    let renewal_child_uses = zylith_core::renewal_child_uses_from_matched_witnesses(
        &matched_order_witnesses,
    )
    .map_err(|_| {
        eprintln!("build_settlement_artifacts batch_id={batch_id} stage=renewal_child_uses failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let prior_consumed_inputs = prior_settlement_witnesses
        .iter()
        .flat_map(|witness| witness.consumed_inputs.iter().cloned())
        .collect::<Vec<_>>();
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
    let prior_renewal_entries = prior_settlement_witnesses
        .iter()
        .flat_map(|witness| {
            witness
                .renewal_child_uses
                .iter()
                .map(|renewal| renewal.child_nullifier.clone())
        })
        .collect::<Vec<_>>();
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
        let note_commitments = consumed_inputs
            .iter()
            .map(|input| normalize_felt_hex(&input.note_commitment.0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        settlement_note_root_after_deposit_chain(&note_commitments)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        prior_roots.note_root.clone()
    };
    let prior_nullifier_root = prior_roots.nullifier_root.clone();
    eprintln!(
        "build_settlement_artifacts batch_id={} stage=note_membership start consumed={} deposits={} transitions={}",
        batch_id,
        consumed_inputs.len(),
        deposit_records.len(),
        note_root_transitions.len()
    );
    let note_membership_witnesses = derive_note_membership_witnesses(
        &prior_note_root,
        &consumed_inputs,
        &matched_order_witnesses,
        deposit_records,
        note_root_transitions,
        prior_settlement_witnesses,
        prior_note_consolidation_witnesses,
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

    let fees = deterministic_fee_entries(
        &protocol_fee_accumulator,
        &relay_fee_accumulator,
        &base_asset,
        &quote_asset,
        protocol_fee_recipient,
        relay_fee_recipient,
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
        new_nullifier_root: new_nullifier_root.clone(),
        new_renewal_root: new_renewal_root.clone(),
        clearing_price,
        price_base_scale: pair.price_base_scale,
        taker_fee_bps: pair.taker_fee_bps,
        maker_fee_bps: pair.maker_fee_bps,
        relay_fee_bps: pair.relay_fee_bps,
        protocol_fee_recipient: protocol_fee_recipient.into(),
        relay_fee_recipient: relay_fee_recipient.into(),
        matched_orders,
        consumed_inputs,
        renewal_child_uses: renewal_child_uses.clone(),
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
        new_nullifier_root: transcript.new_nullifier_root.clone(),
        new_renewal_root: transcript.new_renewal_root.clone(),
        clearing_price,
        price_base_scale: pair.price_base_scale,
        taker_fee_bps: pair.taker_fee_bps,
        maker_fee_bps: pair.maker_fee_bps,
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
        privacy_gate,
        renewal_child_uses,
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
        maker_attribution_bundle,
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

fn maker_band_attribution_for_fill(
    fill: &OrderFillPlan,
    clearing_price: u128,
) -> Result<Option<MakerBandAttribution>, String> {
    if !matches!(fill.order.order_type, OrderType::MakerCurve) {
        return Ok(None);
    }
    let curve = fill
        .order
        .maker_curve
        .as_ref()
        .ok_or_else(|| "maker curve order missing curve points".to_string())?;
    let mut remaining = fill.filled_amount;
    let mut bands = Vec::new();
    for (index, point) in curve.points.iter().enumerate() {
        if remaining == 0 {
            break;
        }
        let eligible = match fill.order.side {
            OrderSide::Buy => point.price >= clearing_price,
            OrderSide::Sell => point.price <= clearing_price,
        };
        if !eligible {
            continue;
        }
        let consumed = remaining.min(point.base_amount);
        if consumed == 0 {
            continue;
        }
        bands.push(MakerBandFillAttribution {
            band_index: index as u64,
            band_price: point.price,
            band_base_amount: point.base_amount,
            filled_base_amount: consumed,
        });
        remaining = remaining.saturating_sub(consumed);
    }
    if remaining != 0 || bands.is_empty() {
        return Err("maker curve fill exceeds eligible attributed bands".into());
    }
    Ok(Some(MakerBandAttribution {
        version: 1,
        pair_id: fill.order.pair_id.clone(),
        order_commitment: fill.order_commitment.clone(),
        funding_note_ref: fill.order.funding_note_ref.clone(),
        side: fill.order.side.clone(),
        clearing_price,
        filled_base_amount: fill.filled_amount,
        bands,
    }))
}

fn build_maker_attribution_bundle(
    batch_id: &str,
    pair_id: &PairId,
    epoch_id: u64,
    witnesses: &[MatchedOrderWitness],
    attribution_signing_private_key: &str,
) -> Result<Option<MakerAttributionBundle>, StatusCode> {
    let mut artifacts = Vec::new();
    for witness in witnesses {
        let Some(attribution) = witness.maker_band_attribution.as_ref() else {
            continue;
        };
        let curve = witness
            .maker_curve
            .as_ref()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let output_note_commitment = witness
            .output_note
            .commitment()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let plaintext = MakerAttributionPlaintext {
            version: 1,
            batch_id: BatchId(batch_id.into()),
            pair_id: pair_id.clone(),
            epoch_id,
            maker_public_key: witness.recipient_owner_public_key.clone(),
            curve_commitment: curve
                .commitment()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            output_note_commitment,
            attribution: attribution.clone(),
        };
        artifacts.push(
            create_maker_attribution_artifact(
                &plaintext,
                &witness.recipient_owner_public_key,
                attribution_signing_private_key,
                now_unix_ms(),
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
    }
    if artifacts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(MakerAttributionBundle {
            version: 1,
            batch_id: BatchId(batch_id.into()),
            artifacts,
        }))
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

fn compute_fill_plan(
    records: &[DecryptedOrderRecord],
    clearing_price: u128,
    price_base_scale: u128,
) -> Vec<OrderFillPlan> {
    if clearing_price == 0 {
        return Vec::new();
    }

    let mut current: Vec<OrderFillPlan> = records
        .iter()
        .filter(|record| is_order_eligible(&record.order, clearing_price))
        .map(|record| OrderFillPlan {
            order_commitment: record.order_commitment.clone(),
            order: record.order.clone(),
            funding_note: record.funding_note.clone(),
            funding_notes: record.funding_notes.clone(),
            funding_authorization: record.funding_authorization.clone(),
            available_amount: max_fill_at_price(record, clearing_price, price_base_scale),
            filled_amount: 0,
        })
        .filter(|fill| fill.available_amount > 0)
        .collect();

    loop {
        let mut next = greedy_fill_round(&current);
        let original_len = next.len();
        next.retain(|fill| {
            fill.filled_amount == 0
                || (fill.filled_amount >= fill.order.min_fill
                    && (!is_fill_or_kill_order(&fill.order)
                        || fill.filled_amount >= fill.order.amount))
        });
        if next.len() == original_len {
            return next
                .into_iter()
                .filter(|fill| fill.filled_amount > 0)
                .collect();
        }
        current = next;
    }
}

fn greedy_fill_round(orders: &[OrderFillPlan]) -> Vec<OrderFillPlan> {
    let mut buys: Vec<(usize, u128)> = orders
        .iter()
        .enumerate()
        .filter(|(_, order)| matches!(order.order.side, OrderSide::Buy))
        .map(|(index, order)| (index, order.available_amount))
        .collect();
    let mut sells: Vec<(usize, u128)> = orders
        .iter()
        .enumerate()
        .filter(|(_, order)| matches!(order.order.side, OrderSide::Sell))
        .map(|(index, order)| (index, order.available_amount))
        .collect();

    buys.sort_by(|(left_index, _), (right_index, _)| {
        let left = &orders[*left_index];
        let right = &orders[*right_index];
        right
            .order
            .limit_price
            .cmp(&left.order.limit_price)
            .then(left_index.cmp(right_index))
    });
    sells.sort_by(|(left_index, _), (right_index, _)| {
        let left = &orders[*left_index];
        let right = &orders[*right_index];
        left.order
            .limit_price
            .cmp(&right.order.limit_price)
            .then(left_index.cmp(right_index))
    });

    let mut results: Vec<OrderFillPlan> = orders
        .iter()
        .cloned()
        .map(|mut order| {
            order.filled_amount = 0;
            order
        })
        .collect();
    let mut buy_cursor = 0;
    let mut sell_cursor = 0;

    while buy_cursor < buys.len() && sell_cursor < sells.len() {
        let (buy_index, buy_remaining) = buys[buy_cursor];
        let (sell_index, sell_remaining) = sells[sell_cursor];
        let fill_amount = buy_remaining.min(sell_remaining);
        if fill_amount == 0 {
            if buy_remaining == 0 {
                buy_cursor += 1;
            }
            if sell_remaining == 0 {
                sell_cursor += 1;
            }
            continue;
        }

        results[buy_index].filled_amount =
            results[buy_index].filled_amount.saturating_add(fill_amount);
        results[sell_index].filled_amount = results[sell_index]
            .filled_amount
            .saturating_add(fill_amount);
        buys[buy_cursor].1 = buys[buy_cursor].1.saturating_sub(fill_amount);
        sells[sell_cursor].1 = sells[sell_cursor].1.saturating_sub(fill_amount);

        if buys[buy_cursor].1 == 0 {
            buy_cursor += 1;
        }
        if sells[sell_cursor].1 == 0 {
            sell_cursor += 1;
        }
    }

    results
}

fn is_order_eligible(order: &OrderIntent, clearing_price: u128) -> bool {
    if matches!(order.order_type, zylith_core::OrderType::HeartbeatCover) {
        return false;
    }
    if matches!(order.order_type, zylith_core::OrderType::MakerCurve) {
        return maker_curve_capacity_at_price(order, clearing_price) > 0;
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
    let is_maker_curve = matches!(record.order.order_type, zylith_core::OrderType::MakerCurve);
    let requested_amount = if is_maker_curve {
        maker_curve_capacity_at_price(&record.order, clearing_price)
    } else {
        if !is_order_eligible(&record.order, clearing_price) {
            return 0;
        }
        record.order.amount
    };

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
    if let (zylith_core::OrderType::MakerCurve, Some(curve)) =
        (&order.order_type, order.maker_curve.as_ref())
    {
        return curve.points.iter().map(|point| point.price).collect();
    }

    vec![order.limit_price]
}

fn maker_curve_capacity_at_price(order: &OrderIntent, clearing_price: u128) -> u128 {
    let Some(curve) = order.maker_curve.as_ref() else {
        return 0;
    };

    curve
        .points
        .iter()
        .filter(|point| match order.side {
            OrderSide::Buy => point.price >= clearing_price,
            OrderSide::Sell => point.price <= clearing_price,
        })
        .map(|point| point.base_amount)
        .sum()
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
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
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
        Call {
            to: batch_registry_address,
            selector: get_selector_from_name("record_order_set_commitments").map_err(|error| {
                format!("failed to compute record_order_set_commitments selector: {error}")
            })?,
            calldata: vec![
                batch_id_felt,
                order_count_felt,
                order_commitment_root,
                encrypted_order_set_commitment,
            ],
        }
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

    Some(StarknetExecutorConfig {
        rpc_url,
        account_address,
        private_key,
        chain_id,
        proof_account_address,
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
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(parse_felt(
        &executor.private_key,
        "ZYLITH_STARKNET_PRIVATE_KEY",
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
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(parse_felt(
        &executor.private_key,
        "ZYLITH_STARKNET_PRIVATE_KEY",
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
) -> Result<NativeResourceBounds, String> {
    let estimate = if mode == NativeTransactionMode::SubmitOnchain
        && native_resource_bounds_require_estimate()
    {
        match estimate_native_fee(account, settlement_call, nonce, execution_context).await {
            Ok(estimate) => Some(estimate),
            Err(error) if native_fee_estimate_requires_proof_facts(&error) => {
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
        l1_gas: env_parse_optional(NATIVE_L1_GAS_MAX_AMOUNT_ENV).unwrap_or_else(|| {
            native_gas_amount_bound(
                estimate
                    .as_ref()
                    .map(|estimate| estimate.l1_gas_consumed)
                    .unwrap_or_default(),
                DEFAULT_NATIVE_L1_GAS_FLOOR,
            )
        }),
        l2_gas: env_parse_optional(NATIVE_L2_GAS_MAX_AMOUNT_ENV).unwrap_or_else(|| {
            native_gas_amount_bound(
                estimate
                    .as_ref()
                    .map(|estimate| estimate.l2_gas_consumed)
                    .unwrap_or_default(),
                l2_gas_floor,
            )
        }),
        l1_data_gas: env_parse_optional(NATIVE_L1_DATA_GAS_MAX_AMOUNT_ENV).unwrap_or_else(|| {
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

fn native_resource_bounds_require_estimate() -> bool {
    env_parse_optional::<u64>(NATIVE_L1_GAS_MAX_AMOUNT_ENV).is_none()
        || env_parse_optional::<u64>(NATIVE_L1_DATA_GAS_MAX_AMOUNT_ENV).is_none()
        || env_parse_optional::<u64>(NATIVE_L2_GAS_MAX_AMOUNT_ENV).is_none()
}

fn native_fee_estimate_requires_proof_facts(error: &str) -> bool {
    error.contains("PROOF_FACTS_MISSING") || error.contains("EMPTY_PROOF_FACTS")
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
    let proving_blocks_back = env_parse_or_default(
        NATIVE_PROVER_BLOCKS_BACK_ENV,
        DEFAULT_NATIVE_PROVER_BLOCKS_BACK,
    );
    match block {
        MaybePreConfirmedBlockWithTxHashes::Block(block) => Ok(NativeExecutionContext {
            block_id: native_execution_context_block_id(
                mode,
                block.block_number,
                proving_blocks_back,
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
) -> NativeBlockId {
    match mode {
        NativeTransactionMode::ProofOnly => NativeBlockId::Number {
            block_number: latest_block_number.saturating_sub(proving_blocks_back),
        },
        NativeTransactionMode::SubmitOnchain => NativeBlockId::Tag("latest".into()),
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
    let executor = state
        .starknet_executor
        .clone()
        .ok_or_else(|| "starknet executor is not configured".to_string())?;
    let _proof_request_path = proof_artifact
        .native_execution_request_path
        .as_ref()
        .ok_or_else(|| "native execution request path missing".to_string())?;
    let proof_path = proof_artifact
        .native_proof_file_path
        .as_ref()
        .ok_or_else(|| "native proof path missing".to_string())?;
    let proof_facts_path = proof_artifact
        .native_proof_facts_file_path
        .as_ref()
        .ok_or_else(|| "native proof facts path missing".to_string())?;
    let nullifier_proof_path = proof_artifact
        .native_nullifier_proof_file_path
        .as_ref()
        .ok_or_else(|| "native nullifier proof path missing".to_string())?;
    let nullifier_proof_facts_path = proof_artifact
        .native_nullifier_proof_facts_file_path
        .as_ref()
        .ok_or_else(|| "native nullifier proof facts path missing".to_string())?;
    let renewal_proof_path = proof_artifact
        .native_renewal_proof_file_path
        .as_ref()
        .ok_or_else(|| "native renewal proof path missing".to_string())?;
    let renewal_proof_facts_path = proof_artifact
        .native_renewal_proof_facts_file_path
        .as_ref()
        .ok_or_else(|| "native renewal proof facts path missing".to_string())?;

    let (nullifier_proof, nullifier_proof_facts) = read_native_proof_bundle(
        nullifier_proof_path,
        nullifier_proof_facts_path,
        "nullifier",
    )?;
    let (renewal_proof, renewal_proof_facts) =
        read_native_proof_bundle(renewal_proof_path, renewal_proof_facts_path, "renewal")?;
    let (proof, proof_facts) =
        read_native_proof_bundle(proof_path, proof_facts_path, "settlement")?;

    let provider = JsonRpcClient::new(HttpTransport::new(
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
    let nullifier_tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        &executor,
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
    let renewal_tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        &executor,
        &renewal_record_call,
        renewal_proof,
        &renewal_proof_facts,
    )
    .await
    .map_err(|error| format!("failed to record native renewal proof: {error}"))?;
    ensure_native_statement_record_accepted(&provider, &renewal_tx_hash, "renewal").await?;

    let tx_hash = submit_native_invoke_with_typed_sdk_retry(
        state,
        &executor,
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

fn read_native_proof_bundle(
    proof_path: &str,
    proof_facts_path: &str,
    label: &str,
) -> Result<(String, Vec<String>), String> {
    let proof = fs::read_to_string(proof_path)
        .map_err(|error| format!("failed to read native {label} proof {proof_path}: {error}"))?;
    let proof_facts: Vec<String> =
        serde_json::from_str(&fs::read_to_string(proof_facts_path).map_err(|error| {
            format!("failed to read native {label} proof facts {proof_facts_path}: {error}")
        })?)
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
    let (execution_context, nonce, resource_bounds, _) = prepare_native_execution_fields(
        executor,
        settlement_call,
        NativeTransactionMode::SubmitOnchain,
    )
    .await?;

    let rpc_url = Url::parse(&executor.rpc_url)
        .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?;
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
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
    let typed_proof_facts = proof_facts
        .iter()
        .map(|value| parse_felt(value, "proof_facts felt"))
        .collect::<Result<Vec<_>, _>>()?;
    let signature_binds_proof_facts =
        env_bool_or_default(NATIVE_SIGNATURE_BINDS_PROOF_FACTS_ENV, true);
    let mut execution = account
        .execute_v3(vec![starknet_call_to_call(settlement_call)?])
        .nonce(nonce)
        .l1_gas(resource_bounds.l1_gas)
        .l1_gas_price(execution_context.l1_gas_price)
        .l2_gas(resource_bounds.l2_gas)
        .l2_gas_price(execution_context.l2_gas_price)
        .l1_data_gas(resource_bounds.l1_data_gas)
        .l1_data_gas_price(execution_context.l1_data_gas_price)
        .tip(0)
        .proof(proof.to_owned());
    if signature_binds_proof_facts {
        execution = execution.proof_facts(typed_proof_facts.clone());
    }
    let prepared_invoke = execution
        .prepared()
        .map_err(|_| "failed to prepare typed native proof-bearing invoke".to_string())?;
    let expected_tx_hash = prepared_invoke.transaction_hash(false);
    let mut invoke_request = prepared_invoke
        .get_invoke_request(false, false)
        .await
        .map_err(|error| format!("failed to build typed native proof-bearing invoke: {error}"))?;
    if !signature_binds_proof_facts {
        // Non-proof-aware RPC debugging path: some providers accept the extra JSON field but do
        // not propagate it into `tx_info.proof_facts`. Keep this opt-in only; production proof
        // submission must bind facts in the signed transaction hash.
        invoke_request.broadcasted_invoke_txn_v3.proof_facts = Some(typed_proof_facts);
    }

    let attempts = env_parse_or_default(
        NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS_ENV,
        DEFAULT_NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS,
    )
    .max(1);
    let retry_interval_ms = env_parse_or_default(
        NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS_ENV,
        DEFAULT_NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS,
    );

    let mut last_error = None;
    for attempt in 1..=attempts {
        match account
            .provider()
            .add_invoke_transaction(&invoke_request)
            .await
        {
            Ok(result) => return Ok(format!("{:#x}", result.transaction_hash)),
            Err(error) => {
                let formatted_error = format!("native invoke rejected: {error}");
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
                    last_error = Some(formatted_error);
                    sleep(Duration::from_millis(wait_ms)).await;
                    continue;
                }

                if native_invoke_error_is_retryable_after_submission(&formatted_error)
                    && attempt < attempts
                {
                    eprintln!(
                        "native invoke submission hit a transient provider error; retrying submission in {retry_interval_ms}ms ({attempt}/{attempts})"
                    );
                    last_error = Some(formatted_error);
                    sleep(Duration::from_millis(retry_interval_ms)).await;
                    continue;
                }

                return Err(formatted_error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "native invoke submission failed without response".into()))
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
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
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
        PROOF_ARTIFACTS_DIR,
        ONCHAIN_SUBMISSIONS_DIR,
        PROOF_OUTPUTS_DIR,
        PUBLIC_INPUTS_DIR,
        PROVER_LOGS_DIR,
        PRIVATE_ORDER_PAYLOADS_DIR,
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
    let directory = data_dir.join(subdir);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(_) => return BTreeMap::new(),
    };

    let mut records = BTreeMap::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }

        match fs::read_to_string(&path)
            .ok()
            .and_then(|body| serde_json::from_str::<T>(&body).ok())
        {
            Some(record) => {
                records.insert(key_fn(&record), record);
            }
            None => {
                eprintln!("Skipping invalid prover record at {}", path.display());
            }
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
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    fs::write(&temp_path, contents).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    fs::rename(&temp_path, path).map_err(|_| {
        let _ = fs::remove_file(&temp_path);
        StatusCode::INTERNAL_SERVER_ERROR
    })
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
        witness_path: record_path(data_dir, SETTLEMENT_WITNESSES_DIR, batch_id),
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
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
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

#[derive(Clone, Debug, Deserialize)]
struct ScarbStatusLine {
    status: String,
    message: String,
}

fn prover_backend_label(native_tx_prover_enabled: bool) -> String {
    if native_tx_prover_enabled {
        "starknet-transaction-prover".into()
    } else {
        "stwo-scarb".into()
    }
}

fn build_stwo_prove_command(
    scarb_bin: &str,
    manifest_path: &FsPath,
    package_name: &str,
    arguments_file: &FsPath,
) -> Command {
    let mut command = Command::new(scarb_bin);
    command
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("prove")
        .arg("-p")
        .arg(package_name)
        .arg("--execute")
        .arg("--arguments-file")
        .arg(arguments_file)
        .arg("--json");
    if let Some(workdir) = manifest_path.parent() {
        command.current_dir(workdir);
    }
    command
}

fn build_stwo_verify_command(
    scarb_bin: &str,
    manifest_path: &FsPath,
    proof_file: &FsPath,
) -> Command {
    let mut command = Command::new(scarb_bin);
    command
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("verify")
        .arg("--proof-file")
        .arg(proof_file)
        .arg("--json");
    if let Some(workdir) = manifest_path.parent() {
        command.current_dir(workdir);
    }
    command
}

fn parse_scarb_status_lines(stdout: &str) -> Vec<ScarbStatusLine> {
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<ScarbStatusLine>(line).ok())
        .collect()
}

fn extract_proof_path(lines: &[ScarbStatusLine]) -> Option<String> {
    lines.iter().find_map(|line| {
        if line.status == "saving proof to:" {
            Some(line.message.clone())
        } else {
            None
        }
    })
}

fn resolve_proof_path(workdir: &FsPath, proof_path: &str) -> PathBuf {
    let candidate = PathBuf::from(proof_path);
    if candidate.is_absolute() {
        candidate
    } else {
        workdir.join(candidate)
    }
}

fn status_to_error(status: StatusCode) -> String {
    format!("internal prover storage error: {status}")
}

fn load_or_create_auction_keys(
    path: &FsPath,
    allow_keygen: bool,
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
    if !allow_keygen {
        return Err(format!(
            "auction prover key file {} is missing; provision keys or set {AUCTION_PROVER_ALLOW_KEYGEN_ENV}=1 for local development",
            path.display()
        ));
    }

    let generated = vec![generate_auction_key("auction-prover-0")?];
    persist_auction_keys(path, &generated)?;
    Ok(generated)
}

fn load_auction_keys(
    path: &FsPath,
) -> Result<Option<Vec<PrivateExecutionKeyPrivateConfig>>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read auction key file {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_str::<Vec<PrivateExecutionKeyPrivateConfig>>(&contents)
        .map(Some)
        .map_err(|error| {
            format!(
                "failed to parse auction key file {}: {error}",
                path.display()
            )
        })
}

fn persist_auction_keys(
    path: &FsPath,
    keys: &[PrivateExecutionKeyPrivateConfig],
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create auction key directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let encoded = serde_json::to_string_pretty(keys)
        .map_err(|error| format!("failed to serialize auction keys: {error}"))?;
    fs::write(path, encoded).map_err(|error| {
        format!(
            "failed to persist auction keys to {}: {error}",
            path.display()
        )
    })
}

fn generate_auction_key(key_id: &str) -> Result<PrivateExecutionKeyPrivateConfig, String> {
    let private_key = SecretKey::random(&mut OsRng);
    let public_key = private_key.public_key();
    Ok(PrivateExecutionKeyPrivateConfig {
        key_id: key_id.into(),
        private_key: hex::encode(private_key.to_bytes()),
        public_key: hex::encode(public_key.to_encoded_point(false).as_bytes()),
    })
}

fn sha256_file_hex(path: &FsPath) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
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
        DEFAULT_PROTOCOL_FEE_RECIPIENT, DEFAULT_RELAY_FEE_RECIPIENT, DecryptedOrderRecord,
        NOTE_ROOT_TRANSITION_CONSOLIDATION_KIND, NativeBlockId, NativeExecutionRequestRecord,
        NativeProverParams, NativeProverRpcRequest, NativeTransactionMode,
        NoteRootTransitionRecord, OnchainSubmissionRecord, SettlementBuildContext, SettlementRoots,
        artifact_id_for, build_batch_liquidity_report, build_native_proof_program_calldata,
        build_settlement_artifacts, compute_candidate_clearing_price, decode_bhttp_response,
        derive_note_membership_witnesses, deterministic_settlement_submission_jitter_ms,
        eligible_order_count, encode_bhttp_json_post, matched_maker_participant_count,
        matched_participant_count, max_maker_fill_share_bps, max_single_order_fill_share_bps,
        max_single_owner_fill_share_bps, native_execution_context_block_id,
        native_fee_estimate_requires_proof_facts,
        native_invoke_error_is_retryable_after_submission,
        native_invoke_error_is_retryable_proof_facts_delay, parse_ohttp_key_config_hex,
        proof_fact_age_wait_ms, protocol_fee_recipient_from_values,
        redact_native_execution_request, redact_native_prover_request,
        resolve_batch_registrar_private_key, same_starknet_address,
        should_refresh_onchain_submission, storage_key, validate_batch_nullifier_freshness,
    };
    use zylith_core::{
        AssetId, BatchId, BatchStatus, BatchSummary, ConsumedInput, HiddenMakerCurve,
        MakerCurvePoint, MatchedOrder, Note, NoteCommitment, NoteConsolidationWitness,
        NoteMembershipKind, Nullifier, NullifierHistoryBatch, OrderIntent, OrderSide, OrderType,
        OutputNoteRecord, PairId, ProductConfig, RelayMode, SettlementTranscript,
        SettlementWitness, SpendAuthorization, TimeInForce, deposit_note_root,
        hash::ordered_felt_list_commitment, note_recognition_public_key_from_raw_key_hex,
        nullifier_from_note_secret, root_only_settlement_commitments,
        settlement_nullifier_root_after_history, settlement_state_transition_root,
    };

    #[test]
    fn storage_key_sanitizes_non_alphanumeric_batch_ids() {
        assert_eq!(
            storage_key("batch/strk usdc:1"),
            "batch_2f_strk_20_usdc_3a_1"
        );
        assert_eq!(storage_key("batch-strk-usdc-1"), "batch-strk-usdc-1");
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
    fn protocol_fee_recipient_prefers_canonical_env_value() {
        assert_eq!(
            protocol_fee_recipient_from_values(
                Some("0xabc".into()),
                Some("legacy-recipient".into())
            ),
            "0xabc"
        );
    }

    #[test]
    fn protocol_fee_recipient_keeps_legacy_env_fallback() {
        assert_eq!(
            protocol_fee_recipient_from_values(None, Some("legacy-recipient".into())),
            "legacy-recipient"
        );
        assert_eq!(
            protocol_fee_recipient_from_values(Some("   ".into()), None),
            DEFAULT_PROTOCOL_FEE_RECIPIENT
        );
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
    fn note_membership_derivation_supports_prior_settlement_outputs() {
        let initial_deposit_commitment = "0x101".to_string();
        let later_deposit_commitment = "0x202".to_string();
        let initial_deposit_root =
            deposit_note_root(&initial_deposit_commitment).expect("initial deposit root");
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
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 1,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: Vec::new(),
            consumed_inputs: Vec::new(),
            renewal_child_uses: Vec::new(),
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
            deposit_note_root(&later_deposit_commitment).expect("later deposit root");
        let target_note_root =
            settlement_state_transition_root(&prior_roots.new_note_root, &later_deposit_root)
                .expect("target note root");
        let transitions = vec![
            NoteRootTransitionRecord {
                kind: 0,
                key: initial_deposit_commitment,
                batch_root: initial_deposit_root,
                new_root: root_after_initial_deposit.clone(),
            },
            NoteRootTransitionRecord {
                kind: 1,
                key: "0x7".into(),
                batch_root: prior_roots.output_note_root.clone(),
                new_root: prior_roots.new_note_root.clone(),
            },
            NoteRootTransitionRecord {
                kind: 0,
                key: later_deposit_commitment.clone(),
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
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 0,
            price_base_scale: 1,
            taker_fee_bps: 0,
            maker_fee_bps: 0,
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
            privacy_gate: Default::default(),
            renewal_child_uses: Vec::new(),
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

        let witnesses = derive_note_membership_witnesses(
            &target_note_root,
            &consumed_inputs,
            &[],
            &[],
            &transitions,
            &[prior_witness],
            &[],
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
        let deposit_commitment = "0x101".to_string();
        let deposit_root = deposit_note_root(&deposit_commitment).expect("deposit root");
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
            new_nullifier_root: "0x0".into(),
            new_renewal_root: "0x0".into(),
            clearing_price: 0,
            price_base_scale: 1,
            taker_fee_bps: 0,
            maker_fee_bps: 0,
            relay_fee_bps: 0,
            protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT.into(),
            relay_fee_recipient: "zylith-renewal-relay".into(),
            matched_orders: Vec::new(),
            consumed_inputs: Vec::new(),
            renewal_child_uses: Vec::new(),
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
                key: deposit_commitment,
                batch_root: deposit_root,
                new_root: root_after_deposit.clone(),
            },
            NoteRootTransitionRecord {
                kind: NOTE_ROOT_TRANSITION_CONSOLIDATION_KIND,
                key: "0x1".into(),
                batch_root: consolidation_roots.output_note_root.clone(),
                new_root: target_note_root.clone(),
            },
        ];
        let consolidation_witness = NoteConsolidationWitness {
            consolidation_id: BatchId("consolidation-1".into()),
            auction_verifier_address: "0x0".into(),
            prior_note_root: root_after_deposit,
            prior_nullifier_root: "0x0".into(),
            input_notes: Vec::new(),
            spend_authorization: SpendAuthorization {
                signature_r: "0x0".into(),
                signature_s: "0x0".into(),
            },
            note_membership_witnesses: Vec::new(),
            nullifier_history: Vec::new(),
            nullifier_sparse_witnesses: Vec::new(),
            output_notes: vec![consolidated_output.clone()],
            output_note_preimages: Vec::new(),
            output_recovery_records: Vec::new(),
            output_recovery_dummy_commitments: Vec::new(),
            output_ciphertext_bundle_ref: "0x777".into(),
            new_nullifier_root: "0x0".into(),
        };
        let consumed_inputs = vec![ConsumedInput {
            note_commitment: consolidated_output.note_commitment,
            nullifier: Nullifier("0x900".into()),
        }];

        let witnesses = derive_note_membership_witnesses(
            &target_note_root,
            &consumed_inputs,
            &[],
            &[],
            &transitions,
            &[],
            &[consolidation_witness],
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
            params: NativeProverParams {
                block_id: NativeBlockId::Tag("latest".into()),
                transaction: serde_json::json!({
                    "calldata": ["0xabc"]
                }),
            },
        };

        let redacted = redact_native_prover_request(&request);

        assert_eq!(
            request.params.transaction["calldata"],
            serde_json::json!(["0xabc"])
        );
        assert_eq!(redacted.params.transaction["calldata"]["redacted"], true);
        assert_eq!(redacted.params.transaction["calldata"]["felt_count"], 1);
    }

    #[test]
    fn native_fee_estimation_falls_back_only_when_proof_facts_are_missing() {
        assert!(native_fee_estimate_requires_proof_facts(
            "Execution failed: PROOF_FACTS_MISSING"
        ));
        assert!(native_fee_estimate_requires_proof_facts(
            "Execution failed: EMPTY_PROOF_FACTS"
        ));
        assert!(!native_fee_estimate_requires_proof_facts(
            "Execution failed: UNKNOWN_BATCH"
        ));
    }

    #[test]
    fn native_execution_context_pins_proof_but_uses_latest_for_submit() {
        match native_execution_context_block_id(NativeTransactionMode::ProofOnly, 100, 7) {
            NativeBlockId::Number { block_number } => assert_eq!(block_number, 93),
            other => panic!("proof context must use numbered block, got {other:?}"),
        }

        match native_execution_context_block_id(NativeTransactionMode::SubmitOnchain, 100, 7) {
            NativeBlockId::Tag(tag) => assert_eq!(tag, "latest"),
            other => panic!("submit context must use latest block, got {other:?}"),
        }
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
    fn liquidity_report_flags_batches_below_minimum_threshold() {
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

        assert_eq!(report.status, "below_minimum");
        assert_eq!(report.matched_base_volume, 2);
        assert_eq!(report.min_base_liquidity, 3);
    }

    #[test]
    fn no_cross_artifacts_use_candidate_clearing_price_for_noop_proof() {
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

        let artifacts = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            SettlementBuildContext {
                product_config: &product_config,
                prior_roots: &SettlementRoots::zero(),
                deposit_records: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_note_consolidation_witnesses: &[],
                privacy_gate: Default::default(),
                protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT,
                relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT,
                attribution_signing_private_key: "0x12345",
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
        assert!(artifacts.maker_attribution_bundle.is_none());
        assert_eq!(artifacts.output_bundle.padded_ciphertext_count, 4);
        assert_eq!(artifacts.output_bundle.ciphertext_count_bucket, "0-4");
    }

    #[test]
    fn settlement_artifacts_separate_zylith_relay_fees_from_protocol_fees() {
        let mut product_config = ProductConfig::default_v1();
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
        let base_unit = 1_000_000_000_000_000_000_u128;
        let mut records = vec![
            valid_test_record(
                0,
                OrderSide::Buy,
                100,
                2 * base_unit,
                base_unit,
                TimeInForce::CurrentBatchOnly,
                300 * base_unit,
            ),
            valid_test_record(
                1,
                OrderSide::Sell,
                100,
                3 * base_unit,
                base_unit,
                TimeInForce::CurrentBatchOnly,
                3 * base_unit,
            ),
        ];
        let parent_secret = "0x12345";
        let parent_secret_commitment = zylith_core::renewal_parent_secret_commitment(parent_secret)
            .expect("parent secret commitment");
        let parent_cancel_authority = "0x777";
        let parent_order_commitment = zylith_core::renewal_parent_commitment(
            &parent_secret_commitment,
            parent_cancel_authority,
        )
        .expect("parent commitment");
        records[1].order.order_type = OrderType::MakerCurve;
        records[1].order.relay_mode = RelayMode::ZylithRelay;
        records[1].order.limit_price = 99;
        records[1].order.maker_curve = Some(HiddenMakerCurve {
            points: vec![
                MakerCurvePoint {
                    price: 99,
                    base_amount: base_unit,
                },
                MakerCurvePoint {
                    price: 100,
                    base_amount: base_unit,
                },
                MakerCurvePoint {
                    price: 101,
                    base_amount: base_unit,
                },
            ],
        });
        records[1].order.parent_order_commitment = parent_order_commitment;
        records[1].order.parent_child_index = 1;
        records[1].order.parent_secret_commitment = parent_secret_commitment;
        records[1].order.parent_cancel_authority = parent_cancel_authority.into();
        records[1].order.parent_authorization_secret = parent_secret.into();
        records[1].order_commitment = records[1].order.commitment().expect("maker commitment");
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

        let artifacts = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            SettlementBuildContext {
                product_config: &product_config,
                prior_roots: &SettlementRoots::zero(),
                deposit_records: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_note_consolidation_witnesses: &[],
                privacy_gate: Default::default(),
                protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT,
                relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT,
                attribution_signing_private_key: "0x12345",
            },
        )
        .expect("relay fee artifacts");

        assert_eq!(artifacts.transcript.clearing_price, 100);
        assert_eq!(artifacts.transcript.relay_fee_bps, 2);
        assert_eq!(artifacts.transcript.matched_orders.len(), 2);
        assert_eq!(
            artifacts.settlement_witness.matched_order_witnesses[1].relay_mode,
            RelayMode::ZylithRelay
        );
        let attribution = artifacts.settlement_witness.matched_order_witnesses[1]
            .maker_band_attribution
            .as_ref()
            .expect("maker band attribution");
        assert_eq!(attribution.clearing_price, 100);
        assert_eq!(attribution.filled_base_amount, 2 * base_unit);
        assert_eq!(
            attribution
                .bands
                .iter()
                .map(|band| (band.band_index, band.filled_base_amount))
                .collect::<Vec<_>>(),
            vec![(0, base_unit), (1, base_unit)]
        );
        let attribution_bundle = artifacts
            .maker_attribution_bundle
            .as_ref()
            .expect("maker attribution bundle");
        assert_eq!(attribution_bundle.artifacts.len(), 1);
        let attribution_artifact = &attribution_bundle.artifacts[0];
        assert_eq!(
            attribution_artifact.order_commitment,
            records[1].order_commitment
        );
        assert_eq!(
            attribution_artifact.output_note_commitment,
            artifacts.settlement_witness.matched_order_witnesses[1]
                .output_note
                .commitment()
                .expect("output note commitment")
        );
        zylith_core::validate_maker_attribution_receipt(&attribution_artifact.receipt)
            .expect("maker attribution receipt verifies");
        assert_eq!(artifacts.transcript.fees.len(), 2);
        assert_eq!(artifacts.transcript.fees[0].asset_id.0, "STRK");
        assert_eq!(
            artifacts.transcript.fees[0].recipient,
            DEFAULT_PROTOCOL_FEE_RECIPIENT
        );
        assert_eq!(artifacts.transcript.fees[0].amount, 800_000_000_000_000);
        assert_eq!(artifacts.transcript.fees[1].asset_id.0, "USDC");
        assert_eq!(
            artifacts.transcript.fees[1].recipient,
            DEFAULT_RELAY_FEE_RECIPIENT
        );
        assert_eq!(artifacts.transcript.fees[1].amount, 40_000_000_000_000_000);
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

        let artifacts = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            SettlementBuildContext {
                product_config: &product_config,
                prior_roots: &SettlementRoots::zero(),
                deposit_records: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_note_consolidation_witnesses: &[],
                privacy_gate: Default::default(),
                protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT,
                relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT,
                attribution_signing_private_key: "0x12345",
            },
        )
        .expect("netted artifacts");

        assert_eq!(artifacts.transcript.matched_orders.len(), 4);
        assert_eq!(artifacts.transcript.output_notes.len(), 4);
        assert_eq!(artifacts.output_bundle.ciphertext_count_bucket, "0-4");
        let buy_outputs = artifacts
            .transcript
            .output_notes
            .iter()
            .filter(|note| note.asset_id.0 == "STRK")
            .collect::<Vec<_>>();
        let sell_outputs = artifacts
            .transcript
            .output_notes
            .iter()
            .filter(|note| note.asset_id.0 == "USDC")
            .collect::<Vec<_>>();
        assert_eq!(buy_outputs.len(), 2);
        assert_eq!(sell_outputs.len(), 2);
        assert!(buy_outputs.iter().all(|note| note.amount == 10));
        assert!(sell_outputs.iter().all(|note| note.amount == 100));
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
    fn participant_threshold_counts_distinct_matched_owners() {
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
            test_record(
                2,
                OrderSide::Sell,
                5,
                1,
                1,
                TimeInForce::CurrentBatchOnly,
                1,
            ),
        ];
        records[1].funding_note.owner_public_key = "bb".repeat(32);
        records[2].funding_note.owner_public_key = records[1].funding_note.owner_public_key.clone();
        let matched_orders = records
            .iter()
            .map(|record| MatchedOrder {
                order_commitment: record.order_commitment.clone(),
                filled_amount: 1,
            })
            .collect::<Vec<_>>();

        assert_eq!(matched_participant_count(&records, &matched_orders), 2);
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
    fn nullifier_freshness_rejects_historical_replay() {
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

        let error =
            validate_batch_nullifier_freshness("batch-strk-usdc-1", &records, historical.iter())
                .expect_err("historical nullifier rejected");

        assert!(error.contains("already reserved"));
    }

    #[test]
    fn dominance_gate_measures_largest_single_order_fill_share() {
        let matched_orders = vec![
            MatchedOrder {
                order_commitment: zylith_core::OrderCommitment("0x1".into()),
                filled_amount: 80,
            },
            MatchedOrder {
                order_commitment: zylith_core::OrderCommitment("0x2".into()),
                filled_amount: 20,
            },
        ];

        assert_eq!(
            max_single_order_fill_share_bps(&matched_orders, 100).expect("dominance bps"),
            8000
        );
    }

    #[test]
    fn maker_dominance_gate_only_counts_maker_curve_fills() {
        let mut maker = test_record(
            0,
            OrderSide::Sell,
            5,
            80,
            1,
            TimeInForce::CurrentBatchOnly,
            80,
        );
        maker.order.order_type = OrderType::MakerCurve;
        let taker = test_record(
            1,
            OrderSide::Buy,
            5,
            20,
            1,
            TimeInForce::CurrentBatchOnly,
            100,
        );
        let matched_orders = vec![
            MatchedOrder {
                order_commitment: maker.order_commitment.clone(),
                filled_amount: 80,
            },
            MatchedOrder {
                order_commitment: taker.order_commitment.clone(),
                filled_amount: 20,
            },
        ];

        assert_eq!(
            max_maker_fill_share_bps(&[maker, taker], &matched_orders, 100)
                .expect("maker dominance bps"),
            8000
        );
    }

    #[test]
    fn eligible_order_gate_counts_orders_executable_at_price() {
        let buy = test_record(
            0,
            OrderSide::Buy,
            10,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );
        let sell = test_record(
            1,
            OrderSide::Sell,
            5,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );
        let out_of_band = test_record(
            2,
            OrderSide::Buy,
            1,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );

        assert_eq!(eligible_order_count(&[buy, sell, out_of_band], 5, 1), 2);
    }

    #[test]
    fn owner_dominance_gate_aggregates_split_orders() {
        let first = test_record(
            0,
            OrderSide::Buy,
            10,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );
        let mut second = test_record(
            1,
            OrderSide::Buy,
            10,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );
        second.funding_note.owner_public_key = first.funding_note.owner_public_key.clone();
        let mut third = test_record(
            2,
            OrderSide::Sell,
            5,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );
        third.funding_note.owner_public_key = "cd".repeat(32);
        let matched_orders = vec![
            MatchedOrder {
                order_commitment: first.order_commitment.clone(),
                filled_amount: 40,
            },
            MatchedOrder {
                order_commitment: second.order_commitment.clone(),
                filled_amount: 35,
            },
            MatchedOrder {
                order_commitment: third.order_commitment.clone(),
                filled_amount: 25,
            },
        ];

        assert_eq!(
            max_single_owner_fill_share_bps(&[first, second, third], &matched_orders, 100)
                .expect("owner dominance bps"),
            7500
        );
    }

    #[test]
    fn maker_participant_count_uses_distinct_matched_maker_owners() {
        let mut first = test_record(
            0,
            OrderSide::Sell,
            5,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );
        first.order.order_type = OrderType::MakerCurve;
        let mut second = test_record(
            1,
            OrderSide::Sell,
            5,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );
        second.order.order_type = OrderType::MakerCurve;
        second.funding_note.owner_public_key = "cd".repeat(32);
        let taker = test_record(
            2,
            OrderSide::Buy,
            10,
            2,
            1,
            TimeInForce::CurrentBatchOnly,
            20,
        );
        let matched_orders = vec![
            MatchedOrder {
                order_commitment: first.order_commitment.clone(),
                filled_amount: 25,
            },
            MatchedOrder {
                order_commitment: second.order_commitment.clone(),
                filled_amount: 25,
            },
            MatchedOrder {
                order_commitment: taker.order_commitment.clone(),
                filled_amount: 50,
            },
        ];

        assert_eq!(
            matched_maker_participant_count(&[first, second, taker], &matched_orders),
            2
        );
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
            new_nullifier_root: settlement_nullifier_root_after_history(&[NullifierHistoryBatch {
                repeat_count: 1,
                nullifiers: vec![nullifier.clone()],
            }])
            .expect("sparse nullifier root"),
            new_renewal_root: "0x0".into(),
            clearing_price: 1,
            price_base_scale: 1,
            taker_fee_bps: 4,
            maker_fee_bps: 0,
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
            privacy_gate: Default::default(),
            renewal_child_uses: vec![],
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
            maker_curve: None,
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

        let result = build_settlement_artifacts(
            &batch.batch_id.0,
            &batch,
            &pair,
            &records,
            SettlementBuildContext {
                product_config: &product_config,
                prior_roots: &SettlementRoots::zero(),
                deposit_records: &[],
                note_root_transitions: &[],
                prior_settlement_witnesses: &[],
                prior_note_consolidation_witnesses: &[],
                privacy_gate: Default::default(),
                protocol_fee_recipient: DEFAULT_PROTOCOL_FEE_RECIPIENT,
                relay_fee_recipient: DEFAULT_RELAY_FEE_RECIPIENT,
                attribution_signing_private_key: "0x12345",
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
}

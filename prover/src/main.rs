use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, Method, StatusCode, header::AUTHORIZATION},
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
use tower_http::cors::{Any, CorsLayer};
use url::Url;
use zylith_core::hash::{encode_starknet_felt, ordered_felt_list_commitment};
use zylith_core::{
    AssetId, AuctionOrderWitness, BatchId, BatchOrderSet, BatchSummary, CONTROL_PLANE_TOKEN_ENV,
    ConsumedInput, DeploymentManifest, FeeEntry, MatchedOrder, MatchedOrderWitness, Note,
    OnchainSubmissionRecord, OrderCommitment, OrderExecutionReport, OrderIngressReceipt,
    OrderIntent, OrderShareBundle, OrderSide, OrderSubmission, OutputCiphertextBundle,
    OutputNoteRecord, PreparedBatchStatus, PrivateExecutionKeyPrivateConfig,
    PrivateExecutionKeyPublicConfig, PrivateExecutionKeyRegistry, ProductConfig, ProductPairConfig,
    ProofArtifactRecord, ProofJobStatus, PublishedBatchArtifacts, SettlementSubmissionPlan,
    SettlementTranscript, SettlementWitness, StarknetCall, TimeInForce, TrustedOrderIngressRequest,
    TrustedOrderIngressResponse, build_auction_serialized_input, build_output_note,
    build_settlement_submission_plan, create_order_ingress_receipt, decrypt_order_bundle,
    encrypt_note_for_owner, extract_bearer_token, format_bearer_token,
    native_settlement_message_hash, private_execution_key_registry_fingerprint,
    private_order_payload_commitment, proof_artifact_commitment,
    sanitize_order_submission_for_coordinator, settlement_proof_message_hash,
    settlement_transcript_commitment, validate_order_ingress_receipt_for_manifest_with_secrets,
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
const DEFAULT_STWO_MANIFEST_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../stwo_statement/Scarb.toml");
const DEFAULT_STWO_PACKAGE_NAME: &str = "zylith_settlement_statement";
const DEFAULT_SCARB_BIN: &str = "scarb";
const DEFAULT_RECEIPT_POLL_ATTEMPTS: usize = 20;
const DEFAULT_RECEIPT_POLL_INTERVAL_MS: u64 = 1_500;
const DEFAULT_NATIVE_PROVER_ATTEMPTS: usize = 8;
const DEFAULT_NATIVE_PROVER_RETRY_INTERVAL_MS: u64 = 5_000;
const DEFAULT_NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS: u64 = 3_600;
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
const NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS_ENV: &str =
    "ZYLITH_NATIVE_PROOF_FACTS_SUBMIT_RETRY_ATTEMPTS";
const NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS_ENV: &str =
    "ZYLITH_NATIVE_PROOF_FACTS_SUBMIT_RETRY_INTERVAL_MS";
const NATIVE_PROOF_ACCOUNT_ADDRESS_ENV: &str = "ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS";
const AUCTION_PROVER_KEYS_PATH_ENV: &str = "ZYLITH_AUCTION_PROVER_KEYS_PATH";
const AUCTION_PROVER_ALLOW_KEYGEN_ENV: &str = "ZYLITH_AUCTION_PROVER_ALLOW_KEYGEN";
const DEFAULT_PRODUCT_PAIR_IDS: &str = "STRK/ETH,STRK/USDC,STRK/strkBTC";
const PROTOCOL_FEE_BPS: u128 = 30;
const PROTOCOL_FEE_RECIPIENT: &str = "zylith-protocol-fees";
const PROOF_JOBS_DIR: &str = "proof_jobs";
const SETTLEMENT_PLANS_DIR: &str = "settlement_plans";
const SETTLEMENT_WITNESSES_DIR: &str = "settlement_witnesses";
const PROOF_ARTIFACTS_DIR: &str = "proof_artifacts";
const ONCHAIN_SUBMISSIONS_DIR: &str = "onchain_submissions";
const PROOF_OUTPUTS_DIR: &str = "proof_outputs";
const PUBLIC_INPUTS_DIR: &str = "public_inputs";
const PROVER_LOGS_DIR: &str = "prover_logs";
const PRIVATE_ORDER_PAYLOADS_DIR: &str = "private_order_payloads";
const ORDER_INGRESS_RECEIPT_SECRET_ENV: &str = "ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET";
const ORDER_INGRESS_RECEIPT_PREVIOUS_SECRETS_ENV: &str =
    "ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS";
const ORDER_INGRESS_ID_ENV: &str = "ZYLITH_TRUSTED_PROVER_INGRESS_ID";
const MIN_BATCH_BASE_LIQUIDITY_ENV: &str = "ZYLITH_MIN_BATCH_BASE_LIQUIDITY";
const PROVER_MAX_BODY_BYTES_ENV: &str = "ZYLITH_PROVER_MAX_BODY_BYTES";
const PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE_ENV: &str =
    "ZYLITH_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE";
const PROVER_MAX_STORED_PRIVATE_PAYLOADS_ENV: &str = "ZYLITH_PROVER_MAX_STORED_PRIVATE_PAYLOADS";
const PROVER_PRIVATE_PAYLOAD_RETENTION_MS_ENV: &str = "ZYLITH_PRIVATE_PAYLOAD_RETENTION_MS";
const PROVER_EMERGENCY_PAUSED_ENV: &str = "ZYLITH_PROVER_EMERGENCY_PAUSED";
const MIN_BATCH_PARTICIPANTS_ENV: &str = "ZYLITH_MIN_BATCH_PARTICIPANTS";
const MAX_SINGLE_ORDER_FILL_BPS_ENV: &str = "ZYLITH_MAX_SINGLE_ORDER_FILL_BPS";
const MAX_ORDER_AMOUNT_ENV: &str = "ZYLITH_MAX_ORDER_AMOUNT";
const MAX_MAKER_CURVE_BASE_AMOUNT_ENV: &str = "ZYLITH_MAX_MAKER_CURVE_BASE_AMOUNT";
const MAX_MAKER_CURVE_QUOTE_NOTIONAL_ENV: &str = "ZYLITH_MAX_MAKER_CURVE_QUOTE_NOTIONAL";
const DEFAULT_PROVER_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE: u64 = 60;
const DEFAULT_PROVER_MAX_STORED_PRIVATE_PAYLOADS: usize = 10_000;
const DEFAULT_PROVER_PRIVATE_PAYLOAD_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone)]
struct AppState {
    coordinator_url: String,
    indexer_url: String,
    auction_verifier_address: String,
    native_tx_prover_url: Option<String>,
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
    min_batch_base_liquidity: u128,
    min_batch_participants: u64,
    max_single_order_fill_bps: u64,
    max_order_amount: u128,
    max_maker_curve_base_amount: u128,
    max_maker_curve_quote_notional: u128,
    private_payload_retention_ms: u64,
    max_stored_private_payloads: usize,
    private_ingress_rate_limit_per_minute: u64,
    emergency_paused: bool,
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

struct AppConfig {
    coordinator_url: String,
    indexer_url: String,
    auction_verifier_address: String,
    native_tx_prover_url: Option<String>,
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
    min_batch_base_liquidity: u128,
    min_batch_participants: u64,
    max_single_order_fill_bps: u64,
    max_order_amount: u128,
    max_maker_curve_base_amount: u128,
    max_maker_curve_quote_notional: u128,
    private_payload_retention_ms: u64,
    max_stored_private_payloads: usize,
    private_ingress_rate_limit_per_minute: u64,
    emergency_paused: bool,
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
    settlement_witness: SettlementWitness,
    order_execution_reports: Vec<OrderExecutionReport>,
}

#[derive(Clone, Debug)]
struct DecryptedOrderRecord {
    order_commitment: OrderCommitment,
    order: OrderIntent,
    funding_note: Note,
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
}

#[derive(Clone, Debug, Deserialize)]
struct NativeProverError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
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

fn build_app() -> Result<Router, String> {
    let deployment_manifest = load_deployment_manifest();
    let coordinator_url =
        env::var("ZYLITH_COORDINATOR_URL").unwrap_or_else(|_| DEFAULT_COORDINATOR_URL.into());
    let indexer_url = env::var("ZYLITH_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
    let auction_verifier_address = env::var("ZYLITH_AUCTION_VERIFIER_ADDRESS")
        .or_else(|_| env::var("ZYLITH_SETTLEMENT_VERIFIER_ADDRESS"))
        .ok()
        .or_else(|| {
            deployment_manifest
                .as_ref()
                .map(|manifest| manifest.contracts.auction_verifier.clone())
        })
        .unwrap_or_default();
    let native_tx_prover_url = env::var("ZYLITH_NATIVE_TX_PROVER_URL").ok();
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
        native_tx_prover_url,
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
        min_batch_base_liquidity: env_parse_or_default(MIN_BATCH_BASE_LIQUIDITY_ENV, 0_u128),
        min_batch_participants: env_parse_or_default(MIN_BATCH_PARTICIPANTS_ENV, 0_u64),
        max_single_order_fill_bps: env_parse_or_default(MAX_SINGLE_ORDER_FILL_BPS_ENV, 0_u64),
        max_order_amount: env_parse_or_default(MAX_ORDER_AMOUNT_ENV, 0_u128),
        max_maker_curve_base_amount: env_parse_or_default(MAX_MAKER_CURVE_BASE_AMOUNT_ENV, 0_u128),
        max_maker_curve_quote_notional: env_parse_or_default(
            MAX_MAKER_CURVE_QUOTE_NOTIONAL_ENV,
            0_u128,
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
    if let Ok(value) = env::var("ZYLITH_PRODUCT_PAIRS") {
        return ProductConfig::from_enabled_pair_ids_csv(&value)
            .map_err(|error| format!("invalid ZYLITH_PRODUCT_PAIRS: {error}"));
    }
    if let Some(manifest) = deployment_manifest {
        return Ok(manifest.product.clone());
    }
    ProductConfig::from_enabled_pair_ids_csv(DEFAULT_PRODUCT_PAIR_IDS)
        .map_err(|error| format!("default prover product pairs are invalid: {error}"))
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
        native_tx_prover_url,
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
        min_batch_base_liquidity,
        min_batch_participants,
        max_single_order_fill_bps,
        max_order_amount,
        max_maker_curve_base_amount,
        max_maker_curve_quote_notional,
        private_payload_retention_ms,
        max_stored_private_payloads,
        private_ingress_rate_limit_per_minute,
        emergency_paused,
        max_body_bytes,
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
    } = config;

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
        native_tx_prover_url,
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
        min_batch_base_liquidity,
        min_batch_participants,
        max_single_order_fill_bps,
        max_order_amount,
        max_maker_curve_base_amount,
        max_maker_curve_quote_notional,
        private_payload_retention_ms,
        max_stored_private_payloads,
        private_ingress_rate_limit_per_minute,
        emergency_paused,
        rate_limiter: RateLimiter::default(),
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
    };

    Ok(Router::new()
        .route("/health", get(health))
        .route("/api/public/auction-keys", get(public_auction_keys))
        .route(
            "/api/public/auction-keys/fingerprint",
            get(public_auction_keys_fingerprint),
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
            "/api/internal/onchain-submissions/{batch_id}",
            get(get_onchain_submission),
        )
        .route(
            "/api/internal/onchain-submissions/{batch_id}/refresh",
            post(refresh_onchain_submission),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        ))
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
        "coordinator_url": state.coordinator_url,
        "indexer_url": state.indexer_url,
        "prepared_jobs": proof_jobs.len(),
        "auction_verifier_address": state.auction_verifier_address,
        "native_tx_prover_url": state.native_tx_prover_url,
        "prepared_settlement_plans": settlement_plans.len(),
        "prepared_settlement_witnesses": settlement_witnesses.len(),
        "stored_proof_artifacts": proof_artifacts.len(),
        "stored_onchain_submissions": onchain_submissions.len(),
        "stored_private_order_payloads": private_order_payloads.len(),
        "starknet_executor_enabled": state.starknet_executor.is_some(),
        "native_tx_prover_enabled": state.native_tx_prover_url.is_some(),
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
        "max_single_order_fill_bps": state.max_single_order_fill_bps,
        "max_order_amount": state.max_order_amount.to_string(),
        "max_maker_curve_base_amount": state.max_maker_curve_base_amount.to_string(),
        "max_maker_curve_quote_notional": state.max_maker_curve_quote_notional.to_string(),
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
        return Err(StatusCode::BAD_REQUEST);
    }
    let payload_commitment = private_order_payload_commitment(&submission.order_bundle)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
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
            }));
        }
    }

    let private_payload =
        decrypt_order_bundle(&submission.order_bundle, &state.auction_private_keys)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let reconstructed_order_commitment = private_payload
        .order
        .commitment()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if reconstructed_order_commitment != order_commitment {
        return Err(StatusCode::BAD_REQUEST);
    }
    if submission.order_bundle.pair_id != private_payload.order.pair_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    if submission.order_bundle.batch_id != private_payload.order.batch_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    if submission.order_bundle.epoch_id != private_payload.order.expiry_epoch {
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .product_config
        .validate_order_funding(&private_payload.order, &private_payload.funding_note)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_private_order_risk_limits(&state, &private_payload.order)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

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
    }))
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
    prepare_private_auction_batch_inner(&state, &batch_id)
        .await
        .map(Json)
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

fn validate_private_order_risk_limits(state: &AppState, order: &OrderIntent) -> Result<(), String> {
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
    for header in ["x-zylith-client-id", "x-forwarded-for", "x-real-ip"] {
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
    let (_, settlement_witness) = ensure_prepared_job(&state, &batch_id).await?;
    let transcript = fetch_transcript(&state, &batch_id).await?;

    set_job_state(
        &state,
        &batch_id,
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

    let proof_result = match fetch_auction_order_witnesses(&state, &batch_id).await {
        Ok(auction_order_witnesses) => {
            if state.native_tx_prover_url.is_some() {
                execute_native_transaction_prover(
                    &state,
                    &batch_id,
                    &transcript,
                    &settlement_witness,
                    &auction_order_witnesses,
                )
                .await
            } else {
                execute_stwo_prover(
                    &state,
                    &batch_id,
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
                proof_artifacts.insert(batch_id.clone(), artifact.clone());
                persist_record(
                    state.data_dir.as_ref(),
                    PROOF_ARTIFACTS_DIR,
                    &batch_id,
                    &artifact,
                )?;
            }
            {
                let mut settlement_plans = state.settlement_plans.write().await;
                settlement_plans.insert(batch_id.clone(), settlement_plan.clone());
                persist_record(
                    state.data_dir.as_ref(),
                    SETTLEMENT_PLANS_DIR,
                    &batch_id,
                    &settlement_plan,
                )?;
            }

            let updated_status = set_job_state(
                &state,
                &batch_id,
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

            Ok(Json(updated_status))
        }
        Err(error) => {
            set_job_error(&state, &batch_id, error).await?;
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
    let settlement_plan = {
        let settlement_plans = state.settlement_plans.read().await;
        settlement_plans
            .get(&batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };
    let proof_artifact = {
        let proof_artifacts = state.proof_artifacts.read().await;
        proof_artifacts
            .get(&batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };

    if proof_artifact.native_proof_file_path.is_none()
        || proof_artifact.native_proof_facts_file_path.is_none()
        || proof_artifact.native_execution_request_path.is_none()
    {
        return Err(StatusCode::CONFLICT);
    }

    let submission =
        match submit_native_plan_onchain(&state, &settlement_plan, &proof_artifact).await {
            Ok(submission) => submission,
            Err(error) => {
                set_onchain_submission_error(&state, &batch_id, error).await?;
                return Err(StatusCode::BAD_GATEWAY);
            }
        };

    {
        let mut submissions = state.onchain_submissions.write().await;
        submissions.insert(batch_id.clone(), submission.clone());
        persist_record(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &batch_id,
            &submission,
        )?;
    }
    sync_job_with_onchain_submission(&state, &batch_id, &submission).await?;

    Ok(Json(submission))
}

async fn prepare_private_auction_batch_inner(
    state: &AppState,
    batch_id: &str,
) -> Result<PreparedBatchStatus, StatusCode> {
    prune_private_order_payloads(state).await?;
    let batch = fetch_batch_order_set(state, batch_id).await?;
    let pair = state
        .product_config
        .enabled_pair(&batch.batch.pair_id)
        .cloned()
        .ok_or(StatusCode::CONFLICT)?;
    let records = decrypt_private_auction_orders(state, &batch).await?;
    let artifacts = build_settlement_artifacts(
        batch_id,
        &batch.batch,
        &pair,
        &records,
        &state.product_config,
    )?;
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
        compute_candidate_clearing_price(&records)?
    } else {
        Some(artifacts.transcript.clearing_price)
    };
    let liquidity = build_batch_liquidity_report(
        &records,
        artifacts.transcript.clearing_price,
        matched_volume,
        state.min_batch_base_liquidity,
    );
    let below_minimum_liquidity = state.min_batch_base_liquidity > 0
        && matched_volume > 0
        && matched_volume < state.min_batch_base_liquidity;
    let matched_participant_count =
        matched_participant_count(&records, &artifacts.transcript.matched_orders);
    let below_minimum_participants = state.min_batch_participants > 0
        && matched_participant_count > 0
        && matched_participant_count < state.min_batch_participants;
    let single_order_fill_bps =
        max_single_order_fill_share_bps(&artifacts.transcript.matched_orders, matched_volume)?;
    let single_order_dominance_blocked = state.max_single_order_fill_bps > 0
        && single_order_fill_bps > state.max_single_order_fill_bps;
    let privacy_blocked =
        below_minimum_liquidity || below_minimum_participants || single_order_dominance_blocked;
    let status = PreparedBatchStatus {
        batch_id: artifacts.transcript.batch_id.clone(),
        pair_id: batch.batch.pair_id.clone(),
        order_count: records.len() as u64,
        state: if below_minimum_liquidity {
            "proof-auction-below-minimum".into()
        } else if below_minimum_participants {
            "proof-auction-below-participants".into()
        } else if single_order_dominance_blocked {
            "proof-auction-dominance-risk".into()
        } else if artifacts.transcript.matched_orders.is_empty() {
            "proof-auction-no-match".into()
        } else {
            "proof-auction-ready".into()
        },
        candidate_clearing_price,
        matched_volume,
        transcript_available: !privacy_blocked,
        liquidity,
        order_execution_reports: if privacy_blocked {
            Vec::new()
        } else {
            artifacts.order_execution_reports.clone()
        },
    };

    if privacy_blocked {
        return Ok(status);
    }

    publish_batch_artifacts_to_coordinator(state, &artifacts).await?;
    {
        let mut settlement_witnesses = state.settlement_witnesses.write().await;
        settlement_witnesses.insert(batch_id.into(), artifacts.settlement_witness.clone());
        persist_record(
            state.data_dir.as_ref(),
            SETTLEMENT_WITNESSES_DIR,
            batch_id,
            &artifacts.settlement_witness,
        )?;
    }

    Ok(status)
}

async fn decrypt_private_auction_orders(
    state: &AppState,
    batch: &BatchOrderSet,
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
        records.push(DecryptedOrderRecord {
            order_commitment: record.order_bundle.order_commitment.clone(),
            order: payload.order,
            funding_note: payload.funding_note,
            funding_authorization: payload.funding_authorization,
        });
    }

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

async fn fetch_auction_order_witnesses(
    state: &AppState,
    batch_id: &str,
) -> Result<Vec<AuctionOrderWitness>, StatusCode> {
    let batch = fetch_batch_order_set(state, batch_id).await?;
    let records = decrypt_private_auction_orders(state, &batch).await?;
    Ok(records
        .into_iter()
        .map(|record| AuctionOrderWitness {
            order_commitment: record.order_commitment,
            order: record.order,
            funding_note: record.funding_note,
            funding_authorization: record.funding_authorization,
        })
        .collect())
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
    let payload = PublishedBatchArtifacts {
        transcript: artifacts.transcript.clone(),
        output_bundle: artifacts.output_bundle.clone(),
        settlement_witness: artifacts.settlement_witness.clone(),
        order_execution_reports: artifacts.order_execution_reports.clone(),
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
    .map_err(|_| StatusCode::BAD_GATEWAY)?
    .error_for_status()
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    apply_internal_auth(
        state.http_client.post(indexer_url).json(&payload),
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
    auction_order_witnesses: &[AuctionOrderWitness],
) -> Result<ProofArtifactRecord, String> {
    let manifest_workdir = state
        .stwo_manifest_path
        .parent()
        .ok_or_else(|| "invalid stwo manifest path".to_string())?;
    let paths = proof_execution_paths(state.data_dir.as_ref(), batch_id);
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), batch_id)
        .map_err(status_to_error)?;

    persist_json_file(&paths.witness_path, settlement_witness).map_err(status_to_error)?;
    let serialized_input =
        build_auction_serialized_input(settlement_witness, auction_order_witnesses)
            .map_err(|error| format!("failed to serialize auction witness for S-two: {error}"))?;
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
    })
}

async fn execute_native_transaction_prover(
    state: &AppState,
    batch_id: &str,
    transcript: &SettlementTranscript,
    settlement_witness: &SettlementWitness,
    auction_order_witnesses: &[AuctionOrderWitness],
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
    let expected_proof_message_hash =
        settlement_proof_message_hash(&state.auction_verifier_address, &transcript_commitment)
            .map_err(|error| error.to_string())?;
    let paths = proof_execution_paths(state.data_dir.as_ref(), batch_id);
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), batch_id)
        .map_err(status_to_error)?;

    let _settlement_plan = build_settlement_submission_plan(
        transcript,
        &state.auction_verifier_address,
        &native_proof_reference,
    )
    .map_err(|error| error.to_string())?;
    if settlement_witness.transcript_commitment != transcript_commitment {
        return Err("settlement witness commitment does not match transcript".into());
    }
    let serialized_auction_witness =
        build_auction_serialized_input(settlement_witness, auction_order_witnesses).map_err(
            |error| format!("failed to serialize auction witness for native proof: {error}"),
        )?;
    let proof_compilation_call = StarknetCall {
        contract_address: normalize_nonzero_felt(
            &state.auction_verifier_address,
            "auction_verifier_address",
        )?,
        entrypoint: "compile_auction_proof".into(),
        calldata: serialized_auction_witness,
    };
    let execution_request = build_native_execution_request(
        &executor,
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
        match request_native_proof(state, &tx_prover_url, &rpc_request).await {
            Ok((result, response_value)) => {
                final_result = Some(result);
                final_response_value = Some(response_value);
                break;
            }
            Err(error) if attempt < state.native_prover_attempts => {
                eprintln!(
                    "native transaction prover attempt {attempt}/{attempts} failed for batch {batch_id}: {error}",
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
        last_error.unwrap_or_else(|| "native transaction prover returned no result".into())
    })?;
    let result =
        final_result.ok_or_else(|| "native transaction prover returned no result".to_string())?;
    validate_native_proof_facts(&result.proof_facts, &expected_proof_message_hash)?;

    fs::write(&paths.proof_path, result.proof.trim())
        .map_err(|error| format!("failed to persist native proof: {error}"))?;
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
        .map_err(|error| format!("failed to persist native prover stderr log: {error}"))?;

    let proof_sha256 = sha256_file_hex(&paths.proof_path)?;
    let proof_facts_sha256 = sha256_file_hex(&paths.public_inputs_path)?;
    let artifact_id = artifact_id_for(batch_id, &transcript_commitment);

    Ok(ProofArtifactRecord {
        artifact_id,
        batch_id: transcript.batch_id.clone(),
        proof_system: "starknet-snip36".into(),
        proof_format: "virtual-tx-proof".into(),
        prover_backend: prover_backend_label(true),
        created_at_unix_ms: now_unix_ms(),
        proof_artifact_commitment: native_proof_reference,
        proof_path: paths.proof_path.display().to_string(),
        public_inputs_path: paths.public_inputs_path.display().to_string(),
        prover_stdout_path: paths.stdout_path.display().to_string(),
        prover_stderr_path: paths.stderr_path.display().to_string(),
        proof_sha256,
        public_inputs_sha256: proof_facts_sha256,
        native_proof_file_path: Some(paths.proof_path.display().to_string()),
        native_proof_facts_file_path: Some(paths.public_inputs_path.display().to_string()),
        native_execution_request_path: Some(
            paths.native_execution_request_path.display().to_string(),
        ),
    })
}

async fn request_native_proof(
    state: &AppState,
    tx_prover_url: &str,
    rpc_request: &NativeProverRpcRequest,
) -> Result<(NativeProverResult, serde_json::Value), String> {
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

    Ok((result, response_value))
}

fn validate_native_proof_facts(
    serialized_proof_facts: &[String],
    expected_message_hash: &str,
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
    if message_count != 1 {
        return Err(format!(
            "native prover returned {message_count} proof messages, expected exactly 1"
        ));
    }
    let actual_message_hash = normalize_nonzero_felt(&serialized_proof_facts[8], "proof_message")?;
    let expected_message_hash = normalize_nonzero_felt(expected_message_hash, "expected_message")?;
    if actual_message_hash != expected_message_hash {
        return Err(format!(
            "native proof_facts message mismatch: expected {expected_message_hash}, got {actual_message_hash}"
        ));
    }
    Ok(())
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
        "{}/api/batches/{}/transcript",
        state.coordinator_url, batch_id
    );
    state
        .http_client
        .get(url)
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
    let url = format!("{}/api/batches/{batch_id}", state.coordinator_url);
    state
        .http_client
        .get(url)
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
) -> Result<Option<u128>, StatusCode> {
    let mut candidate_prices: Vec<u128> = records
        .iter()
        .flat_map(|record| candidate_prices_for_order(&record.order))
        .collect();
    candidate_prices.sort_unstable();
    candidate_prices.dedup();

    let mut best: Option<(u128, u128, u128)> = None;

    for price in candidate_prices {
        let (matched, imbalance) = stable_pruned_score_at_price(records, price)?;

        match best {
            None => best = Some((price, matched, imbalance)),
            Some((best_price, best_matched, best_imbalance)) => {
                if matched > best_matched
                    || (matched == best_matched
                        && (imbalance < best_imbalance
                            || (imbalance == best_imbalance && price < best_price)))
                {
                    best = Some((price, matched, imbalance));
                }
            }
        }
    }

    Ok(best.map(|(price, _, _)| price))
}

fn stable_pruned_score_at_price(
    records: &[DecryptedOrderRecord],
    price: u128,
) -> Result<(u128, u128), StatusCode> {
    let active_flags = stable_active_flags(records, price);
    let buy_demand = records
        .iter()
        .zip(active_flags.iter())
        .filter(|(record, active)| **active && matches!(record.order.side, OrderSide::Buy))
        .try_fold(0_u128, |total, (record, _)| {
            total
                .checked_add(max_fill_at_price(record, price))
                .ok_or(StatusCode::CONFLICT)
        })?;
    let sell_supply = records
        .iter()
        .zip(active_flags.iter())
        .filter(|(record, active)| **active && matches!(record.order.side, OrderSide::Sell))
        .try_fold(0_u128, |total, (record, _)| {
            total
                .checked_add(max_fill_at_price(record, price))
                .ok_or(StatusCode::CONFLICT)
        })?;
    Ok((
        buy_demand.min(sell_supply),
        buy_demand.abs_diff(sell_supply),
    ))
}

fn stable_active_flags(records: &[DecryptedOrderRecord], price: u128) -> Vec<bool> {
    let mut active_flags = records
        .iter()
        .map(|record| max_fill_at_price(record, price) > 0)
        .collect::<Vec<_>>();

    for _ in 0..records.len() {
        let next_flags = active_flags
            .iter()
            .enumerate()
            .map(|(index, active)| {
                if !*active {
                    return false;
                }
                let fill = expected_fill_with_active_flags(records, &active_flags, index, price);
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
) -> u128 {
    if !active_flags[target_index] {
        return 0;
    }
    let target = &records[target_index];
    let max_fill = max_fill_at_price(target, price);
    let opposite_side = match target.order.side {
        OrderSide::Buy => OrderSide::Sell,
        OrderSide::Sell => OrderSide::Buy,
    };
    let opposite_total = active_capacity_total(records, active_flags, &opposite_side, price);
    let priority_capacity =
        active_priority_capacity_before(records, active_flags, target_index, price);
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
) -> u128 {
    records
        .iter()
        .zip(active_flags.iter())
        .filter(|(record, active)| **active && &record.order.side == side)
        .map(|(record, _)| max_fill_at_price(record, price))
        .sum()
}

fn active_priority_capacity_before(
    records: &[DecryptedOrderRecord],
    active_flags: &[bool],
    target_index: usize,
    price: u128,
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
        .map(|(_, (record, _))| max_fill_at_price(record, price))
        .sum()
}

fn sum_fill_at_price<'a>(
    mut records: impl Iterator<Item = &'a DecryptedOrderRecord>,
    price: u128,
) -> Result<u128, StatusCode> {
    records.try_fold(0_u128, |total, record| {
        total
            .checked_add(max_fill_at_price(record, price))
            .ok_or(StatusCode::CONFLICT)
    })
}

fn build_batch_liquidity_report(
    records: &[DecryptedOrderRecord],
    clearing_price: u128,
    matched_base_volume: u128,
    min_base_liquidity: u128,
) -> zylith_core::BatchLiquidityReport {
    let diagnostic_price = if clearing_price > 0 {
        Some(clearing_price)
    } else {
        compute_candidate_clearing_price(records).unwrap_or_default()
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
            is_order_eligible(&record.order, price) && max_fill_at_price(record, price) > 0
        })
        .collect::<Vec<_>>();
    let buy_base_demand = sum_fill_at_price(
        eligible_orders
            .iter()
            .copied()
            .filter(|record| matches!(record.order.side, OrderSide::Buy)),
        price,
    )
    .unwrap_or(0);
    let sell_base_supply = sum_fill_at_price(
        eligible_orders
            .iter()
            .copied()
            .filter(|record| matches!(record.order.side, OrderSide::Sell)),
        price,
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

fn build_settlement_artifacts(
    batch_id: &str,
    batch: &BatchSummary,
    pair: &ProductPairConfig,
    records: &[DecryptedOrderRecord],
    product_config: &ProductConfig,
) -> Result<SettlementArtifacts, StatusCode> {
    for record in records {
        if record.order.pair_id != pair.pair_id {
            return Err(StatusCode::CONFLICT);
        }
        if record.order.batch_id != batch.batch_id {
            return Err(StatusCode::CONFLICT);
        }
        if record.order.expiry_epoch != batch.epoch_id {
            return Err(StatusCode::CONFLICT);
        }
        product_config
            .validate_order_funding(&record.order, &record.funding_note)
            .map_err(|_| StatusCode::CONFLICT)?;
    }

    let clearing_price = compute_candidate_clearing_price(records)?.unwrap_or(0);
    let fills = compute_fill_plan(records, clearing_price);
    let base_asset = pair.base_asset_id.clone();
    let quote_asset = pair.quote_asset_id.clone();

    let mut matched_orders = Vec::with_capacity(fills.len());
    let mut consumed_inputs = Vec::with_capacity(fills.len());
    let mut fee_accumulator: BTreeMap<String, u128> = BTreeMap::new();
    let mut output_notes = Vec::with_capacity(fills.len());
    let mut ciphertexts = Vec::with_capacity(fills.len());
    let mut matched_order_witnesses = Vec::with_capacity(fills.len());
    let mut seen_funding_notes = BTreeMap::<String, String>::new();
    let mut reported_orders = BTreeSet::<String>::new();
    let mut order_execution_reports = Vec::with_capacity(records.len());

    for fill in fills.iter() {
        let funding_note_commitment = fill
            .funding_note
            .commitment()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if funding_note_commitment != fill.order.funding_note_ref {
            return Err(StatusCode::CONFLICT);
        }
        if seen_funding_notes
            .insert(
                funding_note_commitment.0.clone(),
                fill.order_commitment.0.clone(),
            )
            .is_some()
        {
            return Err(StatusCode::CONFLICT);
        }

        matched_orders.push(MatchedOrder {
            order_commitment: fill.order_commitment.clone(),
            filled_amount: fill.filled_amount,
        });
        consumed_inputs.push(ConsumedInput {
            note_commitment: funding_note_commitment,
            nullifier: fill.order.funding_nullifier.clone(),
        });

        let (asset_id, gross_amount) = match fill.order.side {
            OrderSide::Buy => (base_asset.clone(), fill.filled_amount),
            OrderSide::Sell => (
                quote_asset.clone(),
                fill.filled_amount
                    .checked_mul(clearing_price)
                    .ok_or(StatusCode::CONFLICT)?,
            ),
        };
        let fee_amount = gross_amount
            .checked_mul(PROTOCOL_FEE_BPS)
            .ok_or(StatusCode::CONFLICT)?
            / 10_000;
        let net_amount = gross_amount
            .checked_sub(fee_amount)
            .ok_or(StatusCode::CONFLICT)?;
        if fee_amount > 0 {
            let accrued_fee = fee_accumulator.entry(asset_id.0.clone()).or_default();
            *accrued_fee = accrued_fee
                .checked_add(fee_amount)
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
        ciphertexts.push(
            encrypt_note_for_owner(
                batch_id,
                output_index,
                &note,
                &fill.order.recipient_owner_public_key,
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
        output_notes.push(OutputNoteRecord {
            note_commitment: note_commitment.clone(),
            asset_id: note_asset_id,
            amount: net_amount,
            withdraw_authority: note.withdraw_authority.clone(),
        });

        let (residual_asset_id, residual_amount) = residual_for_fill(fill, clearing_price)?;
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
            ciphertexts.push(
                encrypt_note_for_owner(
                    batch_id,
                    residual_output_index,
                    &residual_note,
                    &fill.order.recipient_owner_public_key,
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            );
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
        order_execution_reports.push(OrderExecutionReport {
            batch_id: BatchId(batch_id.into()),
            pair_id: pair.pair_id.clone(),
            order_commitment: fill.order_commitment.clone(),
            funding_note_commitment: fill.order.funding_note_ref.clone(),
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
            funding_note_ref: fill.order.funding_note_ref.clone(),
            funding_nullifier: fill.order.funding_nullifier.clone(),
            funding_authorization: fill.funding_authorization.clone(),
            side: fill.order.side.clone(),
            order_type: fill.order.order_type.clone(),
            maker_curve: fill.order.maker_curve.clone(),
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

    for record in records {
        if reported_orders.contains(&record.order_commitment.0) {
            continue;
        }
        order_execution_reports.push(OrderExecutionReport {
            batch_id: BatchId(batch_id.into()),
            pair_id: pair.pair_id.clone(),
            order_commitment: record.order_commitment.clone(),
            funding_note_commitment: record.order.funding_note_ref.clone(),
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

    let output_bundle = OutputCiphertextBundle::from_ciphertexts(
        BatchId(batch_id.into()),
        format!("proof-auction://{batch_id}/output-bundle"),
        ciphertexts,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let renewal_child_uses =
        zylith_core::renewal_child_uses_from_matched_witnesses(&matched_order_witnesses)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let transcript = SettlementTranscript {
        batch_id: BatchId(batch_id.into()),
        pair_id: pair.pair_id.clone(),
        batch_epoch: batch.epoch_id,
        order_commitment_root: batch.order_commitment_root.clone(),
        encrypted_order_set_commitment: batch.encrypted_order_set_commitment.clone(),
        clearing_price,
        matched_orders,
        consumed_inputs,
        renewal_child_uses: renewal_child_uses.clone(),
        fees: fee_accumulator
            .into_iter()
            .map(|(asset_id, amount)| FeeEntry {
                asset_id: AssetId(asset_id),
                amount,
                recipient: PROTOCOL_FEE_RECIPIENT.into(),
            })
            .collect(),
        output_notes,
        output_ciphertext_bundle_ref: output_bundle.bundle_commitment.clone(),
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
        clearing_price,
        base_asset_id: base_asset,
        quote_asset_id: quote_asset,
        matched_orders: transcript.matched_orders.clone(),
        matched_order_witnesses,
        consumed_inputs: transcript.consumed_inputs.clone(),
        renewal_child_uses,
        fees: transcript.fees.clone(),
        output_notes: transcript.output_notes.clone(),
        output_ciphertext_bundle_ref: transcript.output_ciphertext_bundle_ref.clone(),
    };

    Ok(SettlementArtifacts {
        transcript,
        output_bundle,
        settlement_witness,
        order_execution_reports,
    })
}

fn residual_for_fill(
    fill: &OrderFillPlan,
    clearing_price: u128,
) -> Result<(AssetId, u128), StatusCode> {
    match fill.order.side {
        OrderSide::Buy => {
            let spent = fill
                .filled_amount
                .checked_mul(clearing_price)
                .ok_or(StatusCode::CONFLICT)?;
            Ok((
                fill.funding_note.asset_id.clone(),
                fill.funding_note
                    .amount
                    .checked_sub(spent)
                    .ok_or(StatusCode::CONFLICT)?,
            ))
        }
        OrderSide::Sell => Ok((
            fill.funding_note.asset_id.clone(),
            fill.funding_note
                .amount
                .checked_sub(fill.filled_amount)
                .ok_or(StatusCode::CONFLICT)?,
        )),
    }
}

fn compute_fill_plan(records: &[DecryptedOrderRecord], clearing_price: u128) -> Vec<OrderFillPlan> {
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
            funding_authorization: record.funding_authorization.clone(),
            available_amount: max_fill_at_price(record, clearing_price),
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
    if matches!(order.order_type, zylith_core::OrderType::MakerCurve) {
        return maker_curve_capacity_at_price(order, clearing_price) > 0;
    }

    match order.side {
        OrderSide::Buy => order.limit_price >= clearing_price,
        OrderSide::Sell => order.limit_price <= clearing_price,
    }
}

fn max_fill_at_price(record: &DecryptedOrderRecord, clearing_price: u128) -> u128 {
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
            let affordable_amount = record.funding_note.amount / clearing_price;
            requested_amount.min(affordable_amount)
        }
        OrderSide::Sell => requested_amount.min(record.funding_note.amount),
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
        .or_else(|| deployment_manifest.map(|manifest| manifest.contracts.auction_verifier.clone()))
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
        .get_invoke_request(false, mode == NativeTransactionMode::ProofOnly)
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
    let account = SingleOwnerAccount::new(
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
    let mut execution_context = fetch_native_gas_prices(account.provider()).await?;
    if mode == NativeTransactionMode::ProofOnly {
        execution_context.l1_gas_price = 0;
        execution_context.l2_gas_price = 0;
        execution_context.l1_data_gas_price = 0;
    }
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
                DEFAULT_NATIVE_L2_GAS_FLOOR,
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

async fn fetch_native_gas_prices(
    provider: &JsonRpcClient<HttpTransport>,
) -> Result<NativeExecutionContext, String> {
    let block = provider
        .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
        .await
        .map_err(|error| format!("failed to fetch latest block gas prices: {error}"))?;
    let block = match block {
        MaybePreConfirmedBlockWithTxHashes::Block(block) => block,
        MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(pre_confirmed) => {
            let Some(confirmed_block_number) = pre_confirmed.block_number.checked_sub(1) else {
                return Err("pre-confirmed genesis block cannot be used for native proving".into());
            };
            match provider
                .get_block_with_tx_hashes(BlockId::Number(confirmed_block_number))
                .await
                .map_err(|error| {
                    format!(
                        "failed to fetch confirmed block {confirmed_block_number} after pre-confirmed latest: {error}"
                    )
                })?
            {
                MaybePreConfirmedBlockWithTxHashes::Block(block) => block,
                MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(_) => {
                    return Err(format!(
                        "block {confirmed_block_number} is still pre-confirmed; confirmed block required for native proving"
                    ));
                }
            }
        }
    };
    Ok(NativeExecutionContext {
        block_id: NativeBlockId::Number {
            block_number: block.block_number,
        },
        l1_gas_price: native_gas_price_bound(block.l1_gas_price.price_in_fri)?,
        l2_gas_price: native_gas_price_bound(block.l2_gas_price.price_in_fri)?,
        l1_data_gas_price: native_gas_price_bound(block.l1_data_gas_price.price_in_fri)?,
    })
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

    let proof = fs::read_to_string(proof_path)
        .map_err(|error| format!("failed to read native proof {proof_path}: {error}"))?;
    let proof_facts: Vec<String> =
        serde_json::from_str(&fs::read_to_string(proof_facts_path).map_err(|error| {
            format!("failed to read native proof facts {proof_facts_path}: {error}")
        })?)
        .map_err(|error| format!("failed to parse native proof facts: {error}"))?;

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

    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(&executor.rpc_url)
            .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?,
    ));
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
        submission_mode: "native-proof-facts".into(),
        settlement_contract_address,
    };

    populate_submission_receipt_status(
        &mut submission,
        wait_for_receipt(&provider, parse_felt(&tx_hash, "transaction hash")?).await,
    );

    Ok(submission)
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
    let prepared_invoke = account
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
        .proof_facts(typed_proof_facts)
        .prepared()
        .map_err(|_| "failed to prepare typed native proof-bearing invoke".to_string())?;
    let expected_tx_hash = prepared_invoke.transaction_hash(false);
    let invoke_request = prepared_invoke
        .get_invoke_request(false, false)
        .await
        .map_err(|error| format!("failed to build typed native proof-bearing invoke: {error}"))?;

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
                    eprintln!(
                        "native proof facts are not old enough for onchain acceptance; retrying submission in {retry_interval_ms}ms ({attempt}/{attempts})"
                    );
                    last_error = Some(formatted_error);
                    sleep(Duration::from_millis(retry_interval_ms)).await;
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
        DecryptedOrderRecord, NativeBlockId, NativeExecutionRequestRecord, NativeProverParams,
        NativeProverRpcRequest, artifact_id_for, build_batch_liquidity_report,
        compute_candidate_clearing_price, matched_participant_count,
        max_single_order_fill_share_bps, native_fee_estimate_requires_proof_facts,
        native_invoke_error_is_retryable_after_submission,
        native_invoke_error_is_retryable_proof_facts_delay, redact_native_execution_request,
        redact_native_prover_request, resolve_batch_registrar_private_key, same_starknet_address,
        storage_key,
    };
    use zylith_core::{
        AssetId, BatchId, MatchedOrder, Note, NoteCommitment, Nullifier, OrderIntent, OrderSide,
        OrderType, PairId, SpendAuthorization, TimeInForce,
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
    fn artifact_ids_are_deterministic_and_transcript_bound() {
        let a = artifact_id_for("batch-strk-usdc-1", "0xabc");
        let b = artifact_id_for("batch-strk-usdc-1", "0xabc");
        let c = artifact_id_for("batch-strk-usdc-1", "0xdef");

        assert_eq!(a, b);
        assert_ne!(a, c);
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
    fn native_submit_retries_only_for_proof_facts_delay() {
        let too_recent = serde_json::json!({
            "code": 55,
            "message": "Account validation failed",
            "data": "Invalid proof facts: The proof block number 9245965 is too recent. The maximum allowed block number is 9245961."
        });
        assert!(native_invoke_error_is_retryable_proof_facts_delay(
            &too_recent.to_string()
        ));

        let missing_block_hash = serde_json::json!({
            "code": 55,
            "message": "Account validation failed",
            "data": "Invalid proof facts: Block hash mismatch for block 9246031. Proof block hash: 811206585724913684484793365759388883086436621802564158104548057456911368569, stored block hash: 0."
        });
        assert!(native_invoke_error_is_retryable_proof_facts_delay(
            &missing_block_hash.to_string()
        ));

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

        assert_eq!(compute_candidate_clearing_price(&records).unwrap(), Some(6));
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

        let report = build_batch_liquidity_report(&records, 5, 2, 3);

        assert_eq!(report.status, "below_minimum");
        assert_eq!(report.matched_base_volume, 2);
        assert_eq!(report.min_base_liquidity, 3);
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
        let order = OrderIntent {
            pair_id: PairId("STRK/USDC".into()),
            batch_id: BatchId("batch-strk-usdc-1".into()),
            side,
            order_type: OrderType::LimitBatch,
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
            funding_note_ref: NoteCommitment(format!("0x{:x}", 0x300 + index)),
            funding_nullifier: Nullifier(format!("0x{:x}", 0x400 + index)),
            recipient_owner_public_key: "cd".repeat(32),
            recipient_spend_authority: "0x789".into(),
            recipient_withdraw_authority: "0xabc".into(),
            recipient_residual_withdraw_authority: "0xabd".into(),
            auditor_view_allowed: false,
        };
        DecryptedOrderRecord {
            order_commitment: zylith_core::OrderCommitment(format!("0x{:x}", 0x500 + index)),
            order,
            funding_note,
            funding_authorization: SpendAuthorization {
                signature_r: "0x1".into(),
                signature_s: "0x2".into(),
            },
        }
    }
}

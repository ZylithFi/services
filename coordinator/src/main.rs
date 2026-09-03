use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    env, fmt, fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
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
use reqwest::Client;
use rusqlite::Connection;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use starknet_rust_core::utils::get_selector_from_name;
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use zylith_core::{
    Batch, BatchId, BatchOrderSet, BatchStatus, BatchSummary, CONTROL_PLANE_TOKEN_ENV,
    CoordinatorStatus, LiquidityPositionLifecycleAccepted, LiquidityPositionLifecycleReport,
    LiquidityPositionLifecycleSubmission, OrderCancellationAccepted, OrderCancellationRequest,
    OrderIngressClientTelemetry, OrderShareBundle, OrderSubmission, OrderSubmissionAccepted,
    PairId, PrivateSettlementOutputRecoveryRecord, PrivateSettlementReport,
    PrivateSettlementReportQuery, ProductConfig, PublicBatchSummary, PublicSettlementTranscript,
    PublishedBatchArtifacts, RecoveryArtifact, RecoveryArtifactList, RecoveryArtifactUpload,
    RenewalCancelMarkerList, RenewalCancelMarkerRecord, SettlementTimestampUpdate,
    SubmittedLiquidityPositionLifecycleRecord, SubmittedOrderRecord, artifact_epoch_bucket_end,
    artifact_epoch_bucket_start, count_bucket_label, derive_order_cancellation_tag,
    extract_bearer_token,
    hash::{
        encode_starknet_felt, normalize_felt_hex, ordered_felt_list_commitment,
        tagged_commitment_sha256, tagged_field_hex, tagged_sha256_hex,
    },
    heartbeat_cover_order_commitments, heartbeat_cover_order_count,
    renewal_sparse_witness_for_parent_cancel_marker, root_only_settlement_commitments,
    settlement_liquidity_position_transition_root, settlement_transcript_commitment,
    validate_liquidity_position_ingress_receipt_for_manifest_with_secrets,
    validate_order_ingress_receipt_for_manifest_with_secrets,
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

const DEFAULT_BATCH_WINDOW_MS: u64 = 20 * 1_000;
// The hosted liquidity relay may submit child slots ahead of the currently
// submittable epoch. Keep that lookahead materialized so exact batch lookups
// and coordinator submissions never 404 for authorized relay slots.
const HOSTED_LIQUIDITY_RELAY_SLOT_LOOKAHEAD_EPOCHS: usize = 12;
const OPEN_ACCEPTING_BATCHES_PER_PAIR: usize = HOSTED_LIQUIDITY_RELAY_SLOT_LOOKAHEAD_EPOCHS + 2;
const DEFAULT_PUBLIC_BATCH_LIST_LIMIT: usize = 512;
const MAX_PUBLIC_BATCH_LIST_LIMIT: usize = 4_096;
const BATCH_STORE_RETAIN_RECENT_PER_PAIR: usize = MAX_PUBLIC_BATCH_LIST_LIMIT;
const MIN_BATCH_SUBMISSION_SAFETY_BUFFER_MS: u64 = 5_000;
const MAX_BATCH_SUBMISSION_SAFETY_BUFFER_MS: u64 = 15_000;
const BATCH_SUBMISSION_SAFETY_BUFFER_BPS: u64 = 2_000;
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_BATCH_STORE_PATH: &str = "coordinator/batches.dev.json";
const DEFAULT_RECOVERY_STORE_PATH: &str = "coordinator/recovery_artifacts.dev.json";
const DEFAULT_ARTIFACT_STORE_PATH: &str = "coordinator/published_batch_artifacts.dev.json";
static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
const DEFAULT_PAIR_IDS: &str =
    "STRK/USDC,ETH/USDC,strkBTC/USDC,STRK/ETH,STRK/strkBTC,WBTC/strkBTC,USDC/USDT";
const PRODUCT_PAIRS_ENV: &str = "ZYLITH_PRODUCT_PAIRS";
const COORDINATOR_PAIR_IDS_ENV: &str = "ZYLITH_COORDINATOR_PAIRS";
const BATCH_WINDOW_MS_ENV: &str = "ZYLITH_BATCH_WINDOW_MS";
const COORDINATOR_EPOCH_OFFSET_ENV: &str = "ZYLITH_COORDINATOR_EPOCH_OFFSET";
const ORDER_INGRESS_RECEIPT_SECRET_ENV: &str = "ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET";
const ORDER_INGRESS_RECEIPT_PREVIOUS_SECRETS_ENV: &str =
    "ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS";
const BATCH_CLOSE_JITTER_MS_ENV: &str = "ZYLITH_BATCH_CLOSE_JITTER_MS";
const COORDINATOR_MAX_BODY_BYTES_ENV: &str = "ZYLITH_COORDINATOR_MAX_BODY_BYTES";
const COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE_ENV: &str =
    "ZYLITH_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE";
const COORDINATOR_MAX_ORDERS_PER_BATCH_ENV: &str = "ZYLITH_COORDINATOR_MAX_ORDERS_PER_BATCH";
const COORDINATOR_EMERGENCY_PAUSED_ENV: &str = "ZYLITH_COORDINATOR_EMERGENCY_PAUSED";
const COORDINATOR_ALLOWED_ORIGINS_ENV: &str = "ZYLITH_COORDINATOR_ALLOWED_ORIGINS";
const HEARTBEAT_COVER_SECRET_ENV: &str = "ZYLITH_HEARTBEAT_COVER_SECRET";
const HEARTBEAT_COVER_PRICES_ENV: &str = "ZYLITH_HEARTBEAT_COVER_PRICES";
const DEFAULT_COORDINATOR_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE: u64 = 120;
const DEFAULT_COORDINATOR_MAX_ORDERS_PER_BATCH: u64 = 32;
const DEFAULT_HTTP_CLIENT_TIMEOUT_SECS: u64 = 30;
const MAX_STARKNET_RPC_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_JSON_STORE_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS: u64 = 14;
const DEFAULT_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS: u64 = 36;
const DEFAULT_ARTIFACT_EPOCH_BUCKET_SIZE: u64 = 8;
const MAX_PUBLIC_TRANSCRIPT_BATCH_IDS: usize = 128;
const ARTIFACT_DELAY_MIN_EPOCHS_ENV: &str = "ZYLITH_ARTIFACT_DELAY_MIN_EPOCHS";
const ARTIFACT_DELAY_MAX_EPOCHS_ENV: &str = "ZYLITH_ARTIFACT_DELAY_MAX_EPOCHS";
const ARTIFACT_EPOCH_BUCKET_SIZE_ENV: &str = "ZYLITH_ARTIFACT_EPOCH_BUCKET_SIZE";
const STARKNET_RPC_URL_ENV: &str = "ZYLITH_STARKNET_RPC_URL";
const AUCTION_VERIFIER_ADDRESS_ENV: &str = "ZYLITH_AUCTION_VERIFIER_ADDRESS";

#[derive(Clone)]
struct AppState {
    batches: Arc<RwLock<BTreeMap<String, BatchRecord>>>,
    batch_store_path: Option<Arc<PathBuf>>,
    product_config: Arc<ProductConfig>,
    recovery_artifacts: Arc<RwLock<BTreeMap<String, RecoveryAccountRecord>>>,
    wallet_vaults: Arc<RwLock<BTreeMap<String, WalletVaultBundleRecord>>>,
    recovery_store_path: Option<Arc<PathBuf>>,
    published_batch_artifacts: Arc<RwLock<BTreeMap<String, PublishedBatchArtifacts>>>,
    renewal_cancel_markers: Arc<RwLock<BTreeMap<String, RenewalCancelMarkerRecord>>>,
    published_batch_artifacts_store_path: Option<Arc<PathBuf>>,
    internal_api_token: Option<Arc<String>>,
    batch_window_ms: u64,
    batch_epoch_offset: u64,
    batch_close_jitter_ms: u64,
    order_ingress_receipt_secrets: Arc<Vec<String>>,
    emergency_paused: bool,
    max_orders_per_batch: u64,
    heartbeat_cover_secret: Arc<String>,
    public_rate_limit_per_minute: u64,
    public_artifact_delay_min_epochs: u64,
    public_artifact_delay_max_epochs: u64,
    artifact_epoch_bucket_size: u64,
    require_artifact_onchain_verification: bool,
    starknet_rpc_url: Option<Arc<String>>,
    auction_verifier_address: Option<Arc<String>>,
    http_client: Client,
    output_note_root_selector: String,
    verified_auction_transcript_selector: String,
    renewal_cancel_marker_recorded_selector: String,
    rate_limiter: RateLimiter,
    order_submission_metrics: IngressTelemetryMetrics,
}

fn service_http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_CLIENT_TIMEOUT_SECS))
        .build()
        .expect("failed to build coordinator HTTP client")
}

#[derive(Serialize)]
struct StarknetRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: serde_json::Value,
}

#[derive(Serialize)]
struct StarknetCallRequest<'a> {
    contract_address: &'a str,
    entry_point_selector: &'a str,
    calldata: &'a [String],
}

#[derive(Deserialize)]
struct StarknetRpcResponse {
    result: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct StarknetTransactionReceiptResponse {
    result: Option<StarknetTransactionReceipt>,
}

#[derive(Deserialize)]
struct StarknetTransactionReceipt {
    block_hash: Option<String>,
}

struct StarknetTransactionBlockRef {
    block_id: serde_json::Value,
    timestamp_unix_ms: u64,
}

#[derive(Deserialize)]
struct StarknetBlockResponse {
    result: Option<StarknetBlock>,
}

#[derive(Deserialize)]
struct StarknetBlock {
    timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BatchRecord {
    batch: Batch,
    order_count: u64,
    orders: Vec<SubmittedOrderRecord>,
    #[serde(default)]
    liquidity_lifecycle_count: u64,
    #[serde(default)]
    liquidity_lifecycle_submissions: Vec<SubmittedLiquidityPositionLifecycleRecord>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct BatchStoreFile {
    batches_by_id: BTreeMap<String, BatchRecord>,
}

#[derive(Clone, Debug)]
struct CoordinatorStoreConfig {
    batch_store_path: Option<PathBuf>,
    recovery_store_path: Option<PathBuf>,
    published_batch_artifacts_store_path: Option<PathBuf>,
}

#[derive(Clone)]
struct OrderIngressConfig {
    receipt_secrets: Vec<String>,
}

impl fmt::Debug for OrderIngressConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let receipt_secrets = format!("<{} redacted>", self.receipt_secrets.len());
        formatter
            .debug_struct("OrderIngressConfig")
            .field("receipt_secrets", &receipt_secrets)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct BatchTimingConfig {
    window_ms: u64,
    epoch_offset: u64,
    close_jitter_ms: u64,
}

#[derive(Clone)]
struct CoordinatorHardeningConfig {
    emergency_paused: bool,
    max_body_bytes: usize,
    public_rate_limit_per_minute: u64,
    max_orders_per_batch: u64,
    heartbeat_cover_secret: String,
    public_artifact_delay_min_epochs: u64,
    public_artifact_delay_max_epochs: u64,
    artifact_epoch_bucket_size: u64,
    require_artifact_onchain_verification: bool,
    starknet_rpc_url: Option<String>,
    auction_verifier_address: Option<String>,
    allowed_origins: Vec<HeaderValue>,
}

impl fmt::Debug for CoordinatorHardeningConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorHardeningConfig")
            .field("emergency_paused", &self.emergency_paused)
            .field("max_body_bytes", &self.max_body_bytes)
            .field(
                "public_rate_limit_per_minute",
                &self.public_rate_limit_per_minute,
            )
            .field("max_orders_per_batch", &self.max_orders_per_batch)
            .field("heartbeat_cover_secret", &"<redacted>")
            .field(
                "public_artifact_delay_min_epochs",
                &self.public_artifact_delay_min_epochs,
            )
            .field(
                "public_artifact_delay_max_epochs",
                &self.public_artifact_delay_max_epochs,
            )
            .field(
                "artifact_epoch_bucket_size",
                &self.artifact_epoch_bucket_size,
            )
            .field(
                "require_artifact_onchain_verification",
                &self.require_artifact_onchain_verification,
            )
            .field("starknet_rpc_url", &self.starknet_rpc_url)
            .field("auction_verifier_address", &self.auction_verifier_address)
            .field("allowed_origins", &self.allowed_origins)
            .finish()
    }
}

impl Default for CoordinatorHardeningConfig {
    fn default() -> Self {
        Self {
            emergency_paused: false,
            max_body_bytes: DEFAULT_COORDINATOR_MAX_BODY_BYTES,
            public_rate_limit_per_minute: DEFAULT_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE,
            max_orders_per_batch: DEFAULT_COORDINATOR_MAX_ORDERS_PER_BATCH,
            heartbeat_cover_secret: "test-heartbeat-cover-secret".into(),
            public_artifact_delay_min_epochs: 0,
            public_artifact_delay_max_epochs: 0,
            artifact_epoch_bucket_size: DEFAULT_ARTIFACT_EPOCH_BUCKET_SIZE,
            require_artifact_onchain_verification: false,
            starknet_rpc_url: None,
            auction_verifier_address: None,
            allowed_origins: vec![HeaderValue::from_static("https://app.zylith.test")],
        }
    }
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderSubmissionTelemetryEnvelope {
    order_bundle: OrderShareBundle,
    ingress_telemetry: OrderIngressClientTelemetry,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiquidityPositionLifecycleSubmissionTelemetryEnvelope {
    lifecycle_id: String,
    pair_id: PairId,
    batch_id: BatchId,
    epoch_id: u64,
    transition_commitment: String,
    ingress_receipt: Option<zylith_core::LiquidityPositionIngressReceipt>,
    #[serde(default = "default_order_ingress_client_telemetry")]
    ingress_telemetry: OrderIngressClientTelemetry,
}

impl From<LiquidityPositionLifecycleSubmissionTelemetryEnvelope>
    for LiquidityPositionLifecycleSubmission
{
    fn from(value: LiquidityPositionLifecycleSubmissionTelemetryEnvelope) -> Self {
        Self {
            lifecycle_id: value.lifecycle_id,
            pair_id: value.pair_id,
            batch_id: value.batch_id,
            epoch_id: value.epoch_id,
            transition_commitment: value.transition_commitment,
            ingress_receipt: value.ingress_receipt,
        }
    }
}

fn default_order_ingress_client_telemetry() -> OrderIngressClientTelemetry {
    OrderIngressClientTelemetry {
        version: 1,
        client_build_ms: None,
        private_submission_delay_ms: None,
        client_elapsed_before_private_ingress_ms: None,
        private_ingress_roundtrip_ms: None,
        client_elapsed_before_coordinator_ms: None,
        batch_time_remaining_before_private_ingress_ms: None,
        batch_time_remaining_before_coordinator_ms: None,
        submission_safety_buffer_ms: None,
    }
}

const INGRESS_LATENCY_BUCKETS_MS: &[u64] = &[
    10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000,
];
const INGRESS_REMAINING_BUCKETS_MS: &[u64] =
    &[0, 5_000, 10_000, 15_000, 30_000, 60_000, 120_000, 300_000];
const MAX_CLIENT_TELEMETRY_MS: u64 = 10 * 60 * 1_000;

#[derive(Clone, Debug, Default)]
struct IngressTelemetryMetrics {
    inner: Arc<Mutex<IngressTelemetryMetricsInner>>,
}

#[derive(Clone, Debug, Default)]
struct IngressTelemetryMetricsInner {
    outcomes: BTreeMap<&'static str, u64>,
    processing_ms: HistogramCounts,
    private_ingress_roundtrip_ms: HistogramCounts,
    client_elapsed_before_coordinator_ms: HistogramCounts,
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
            "# HELP {namespace}_order_submission_requests_total Coordinator order submissions by outcome.\n\
             # TYPE {namespace}_order_submission_requests_total counter\n"
        ));
        for (outcome, count) in &inner.outcomes {
            output.push_str(&format!(
                "{namespace}_order_submission_requests_total{{outcome=\"{outcome}\"}} {count}\n"
            ));
        }
        render_histogram(
            &mut output,
            namespace,
            "order_submission_processing_ms",
            "Coordinator order submission server processing latency.",
            &inner.processing_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "order_submission_private_ingress_roundtrip_ms",
            "Client-reported private ingress roundtrip time for coordinator submissions.",
            &inner.private_ingress_roundtrip_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "order_submission_client_elapsed_before_coordinator_ms",
            "Client-reported elapsed time before coordinator submission.",
            &inner.client_elapsed_before_coordinator_ms,
            INGRESS_LATENCY_BUCKETS_MS,
        );
        render_histogram(
            &mut output,
            namespace,
            "order_submission_batch_time_remaining_before_coordinator_ms",
            "Client-reported batch time remaining before coordinator submission.",
            &inner.batch_time_remaining_before_coordinator_ms,
            INGRESS_REMAINING_BUCKETS_MS,
        );
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

#[derive(Clone, Default, Serialize, Deserialize)]
struct RecoveryStoreFile {
    #[serde(default)]
    accounts_by_id: BTreeMap<String, RecoveryAccountRecord>,
    #[serde(default)]
    wallet_vaults_by_auth_id: BTreeMap<String, WalletVaultBundleRecord>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct RecoveryAccountRecord {
    recovery_auth_tag: Option<String>,
    artifacts: Vec<RecoveryArtifact>,
}

const MAX_RECOVERY_ARTIFACTS_PER_ACCOUNT: usize = 512;
const MAX_RECOVERY_ARTIFACT_PAYLOAD_CHARS: usize = 1_048_576;
const MAX_WALLET_VAULT_PAYLOAD_CHARS: usize = 65_536;
const WALLET_VAULT_AUTH_HEADER: &str = "x-zylith-wallet-vault-auth";
const WALLET_VAULT_ID_DOMAIN: &str = "zylith/wallet-signature-vault/id/v2:";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletVaultBundleRecord {
    wallet_auth_id: String,
    vault: serde_json::Value,
    updated_at_unix_ms: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishedBatchArtifactsStoreFile {
    artifacts_by_batch: BTreeMap<String, PublishedBatchArtifacts>,
    renewal_cancel_markers: BTreeMap<String, RenewalCancelMarkerRecord>,
}

#[derive(Clone, Debug, Serialize)]
struct RenewalCancelWitnessResponse {
    cancel_marker: String,
    renewal_cancel_sparse_witness: zylith_core::NullifierSparseUpdateWitness,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewalCancelMarkerRequest {
    cancel_marker: String,
    transaction_hash: Option<String>,
    auction_verifier_address: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct RenewalCancelMarkerStatus {
    cancel_marker: String,
    recorded: bool,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let app = build_app()?;
    let bind_addr =
        env::var("ZYLITH_COORDINATOR_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.into());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|error| format!("failed to bind coordinator on {bind_addr}: {error}"))?;

    println!("Zylith coordinator listening on http://{bind_addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("coordinator service failed: {error}"))
}

fn build_app() -> Result<Router, String> {
    let batch_store_path = env::var("ZYLITH_COORDINATOR_BATCH_PATH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(DEFAULT_BATCH_STORE_PATH)));
    let recovery_store_path = env::var("ZYLITH_COORDINATOR_RECOVERY_PATH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(DEFAULT_RECOVERY_STORE_PATH)));
    let published_batch_artifacts_store_path = env::var("ZYLITH_COORDINATOR_ARTIFACT_PATH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(DEFAULT_ARTIFACT_STORE_PATH)));
    if coordinator_strict_mode() {
        ensure_non_default_store_path(
            "ZYLITH_COORDINATOR_BATCH_PATH",
            batch_store_path.as_deref(),
            DEFAULT_BATCH_STORE_PATH,
        )?;
        ensure_non_default_store_path(
            "ZYLITH_COORDINATOR_RECOVERY_PATH",
            recovery_store_path.as_deref(),
            DEFAULT_RECOVERY_STORE_PATH,
        )?;
        ensure_non_default_store_path(
            "ZYLITH_COORDINATOR_ARTIFACT_PATH",
            published_batch_artifacts_store_path.as_deref(),
            DEFAULT_ARTIFACT_STORE_PATH,
        )?;
        ensure_sqlite_store_path("ZYLITH_COORDINATOR_BATCH_PATH", batch_store_path.as_deref())?;
        ensure_sqlite_store_path(
            "ZYLITH_COORDINATOR_RECOVERY_PATH",
            recovery_store_path.as_deref(),
        )?;
        ensure_sqlite_store_path(
            "ZYLITH_COORDINATOR_ARTIFACT_PATH",
            published_batch_artifacts_store_path.as_deref(),
        )?;
    }

    let internal_api_token = Some(load_required_control_plane_token(
        "zylith-coordinator",
        CONTROL_PLANE_TOKEN_ENV,
    )?);
    let product_config = load_product_config()?;
    let order_ingress_receipt_secrets = load_receipt_secret_keyring();
    if order_ingress_receipt_secrets.is_empty() {
        return Err(format!(
            "zylith-coordinator requires {ORDER_INGRESS_RECEIPT_SECRET_ENV} to verify trusted private order ingress receipts"
        ));
    }
    let batch_window_ms = env::var(BATCH_WINDOW_MS_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("invalid {BATCH_WINDOW_MS_ENV}"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_BATCH_WINDOW_MS);
    if batch_window_ms == 0 {
        return Err(format!("{BATCH_WINDOW_MS_ENV} must be positive"));
    }
    let batch_epoch_offset = env::var(COORDINATOR_EPOCH_OFFSET_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("invalid {COORDINATOR_EPOCH_OFFSET_ENV}"))
        })
        .transpose()?
        .unwrap_or(0);
    let batch_close_jitter_ms = env::var(BATCH_CLOSE_JITTER_MS_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("invalid {BATCH_CLOSE_JITTER_MS_ENV}"))
        })
        .transpose()?
        .unwrap_or(0);
    let public_artifact_delay_min_epochs = env_u64_or_default(
        ARTIFACT_DELAY_MIN_EPOCHS_ENV,
        DEFAULT_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS,
    )?;
    let public_artifact_delay_max_epochs = env_u64_or_default(
        ARTIFACT_DELAY_MAX_EPOCHS_ENV,
        DEFAULT_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS,
    )?
    .max(public_artifact_delay_min_epochs);
    let artifact_epoch_bucket_size = env::var(ARTIFACT_EPOCH_BUCKET_SIZE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("invalid {ARTIFACT_EPOCH_BUCKET_SIZE_ENV}"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_ARTIFACT_EPOCH_BUCKET_SIZE);
    if artifact_epoch_bucket_size == 0 {
        return Err(format!("{ARTIFACT_EPOCH_BUCKET_SIZE_ENV} must be positive"));
    }
    let require_artifact_onchain_verification = true;
    let starknet_rpc_url = env::var(STARKNET_RPC_URL_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if require_artifact_onchain_verification && starknet_rpc_url.is_none() {
        return Err(format!(
            "{STARKNET_RPC_URL_ENV} is required for artifact on-chain verification"
        ));
    }
    let auction_verifier_address = env::var(AUCTION_VERIFIER_ADDRESS_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if require_artifact_onchain_verification
        && !auction_verifier_address
            .as_deref()
            .is_some_and(is_configured_felt)
    {
        return Err(format!(
            "{AUCTION_VERIFIER_ADDRESS_ENV} is required for artifact on-chain verification"
        ));
    }
    let hardening = CoordinatorHardeningConfig {
        emergency_paused: env_bool_or_default(COORDINATOR_EMERGENCY_PAUSED_ENV, false),
        max_body_bytes: env_positive_usize_or_default(
            COORDINATOR_MAX_BODY_BYTES_ENV,
            DEFAULT_COORDINATOR_MAX_BODY_BYTES,
        )?,
        public_rate_limit_per_minute: env_positive_u64_or_default(
            COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE_ENV,
            DEFAULT_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE,
        )?,
        max_orders_per_batch: env_positive_u64_or_default(
            COORDINATOR_MAX_ORDERS_PER_BATCH_ENV,
            DEFAULT_COORDINATOR_MAX_ORDERS_PER_BATCH,
        )?,
        heartbeat_cover_secret: load_required_control_plane_token(
            "zylith-coordinator",
            HEARTBEAT_COVER_SECRET_ENV,
        )?,
        public_artifact_delay_min_epochs,
        public_artifact_delay_max_epochs,
        artifact_epoch_bucket_size,
        require_artifact_onchain_verification,
        starknet_rpc_url,
        auction_verifier_address,
        allowed_origins: allowed_origins_from_env(COORDINATOR_ALLOWED_ORIGINS_ENV)
            .ok_or_else(|| format!("{COORDINATOR_ALLOWED_ORIGINS_ENV} is required"))?,
    };

    build_app_with_config(
        CoordinatorStoreConfig {
            batch_store_path,
            recovery_store_path,
            published_batch_artifacts_store_path,
        },
        internal_api_token,
        product_config,
        BatchTimingConfig {
            window_ms: batch_window_ms,
            epoch_offset: batch_epoch_offset,
            close_jitter_ms: batch_close_jitter_ms,
        },
        OrderIngressConfig {
            receipt_secrets: order_ingress_receipt_secrets,
        },
        hardening,
    )
}

#[cfg(test)]
fn build_app_with_paths(
    batch_store_path: Option<PathBuf>,
    recovery_store_path: Option<PathBuf>,
    published_batch_artifacts_store_path: Option<PathBuf>,
    internal_api_token: Option<String>,
) -> Router {
    build_app_with_config(
        CoordinatorStoreConfig {
            batch_store_path,
            recovery_store_path,
            published_batch_artifacts_store_path,
        },
        internal_api_token,
        ProductConfig::from_enabled_pair_ids_csv(DEFAULT_PAIR_IDS)
            .expect("default coordinator pairs"),
        BatchTimingConfig {
            window_ms: DEFAULT_BATCH_WINDOW_MS,
            epoch_offset: 0,
            close_jitter_ms: 0,
        },
        OrderIngressConfig {
            receipt_secrets: vec!["test-receipt-secret".into()],
        },
        CoordinatorHardeningConfig::default(),
    )
    .expect("test coordinator app should build")
}

fn build_app_with_config(
    store_config: CoordinatorStoreConfig,
    internal_api_token: Option<String>,
    product_config: ProductConfig,
    batch_timing: BatchTimingConfig,
    order_ingress: OrderIngressConfig,
    hardening: CoordinatorHardeningConfig,
) -> Result<Router, String> {
    let CoordinatorStoreConfig {
        batch_store_path,
        recovery_store_path,
        published_batch_artifacts_store_path,
    } = store_config;
    let mut loaded_batches = batch_store_path
        .as_deref()
        .map(load_batch_store)
        .unwrap_or_default();
    let enabled_pairs = product_config.enabled_pairs();
    let initialized_batches = ensure_open_batches(
        &mut loaded_batches,
        &product_config,
        &enabled_pairs,
        batch_timing.window_ms,
        batch_timing.epoch_offset,
        batch_timing.close_jitter_ms,
        &hardening.heartbeat_cover_secret,
    )
    .map_err(|status| format!("failed to initialize coordinator batches: {status}"))?;
    let pruned_batches = prune_batch_store_for_retention(&mut loaded_batches);
    if (initialized_batches || pruned_batches)
        && let Some(path) = batch_store_path.as_deref()
    {
        persist_batch_store(path, &loaded_batches)
            .map_err(|status| format!("failed to persist initial coordinator batches: {status}"))?;
    }
    let published_artifact_store = published_batch_artifacts_store_path
        .as_deref()
        .map(load_published_batch_artifacts_store_file)
        .unwrap_or_default();
    let recovery_store = recovery_store_path
        .as_deref()
        .map(load_recovery_store_file)
        .unwrap_or_default();
    let app_state = AppState {
        batches: Arc::new(RwLock::new(loaded_batches)),
        batch_store_path: batch_store_path.map(Arc::new),
        product_config: Arc::new(product_config),
        recovery_artifacts: Arc::new(RwLock::new(recovery_store.accounts_by_id)),
        wallet_vaults: Arc::new(RwLock::new(recovery_store.wallet_vaults_by_auth_id)),
        recovery_store_path: recovery_store_path.map(Arc::new),
        published_batch_artifacts: Arc::new(RwLock::new(
            published_artifact_store.artifacts_by_batch,
        )),
        renewal_cancel_markers: Arc::new(RwLock::new(
            published_artifact_store.renewal_cancel_markers,
        )),
        published_batch_artifacts_store_path: published_batch_artifacts_store_path.map(Arc::new),
        internal_api_token: internal_api_token.map(Arc::new),
        batch_window_ms: batch_timing.window_ms,
        batch_epoch_offset: batch_timing.epoch_offset,
        batch_close_jitter_ms: batch_timing.close_jitter_ms,
        order_ingress_receipt_secrets: Arc::new(order_ingress.receipt_secrets),
        emergency_paused: hardening.emergency_paused,
        max_orders_per_batch: hardening.max_orders_per_batch,
        heartbeat_cover_secret: Arc::new(hardening.heartbeat_cover_secret),
        public_rate_limit_per_minute: hardening.public_rate_limit_per_minute,
        public_artifact_delay_min_epochs: hardening.public_artifact_delay_min_epochs,
        public_artifact_delay_max_epochs: hardening.public_artifact_delay_max_epochs,
        artifact_epoch_bucket_size: hardening.artifact_epoch_bucket_size,
        require_artifact_onchain_verification: hardening.require_artifact_onchain_verification,
        starknet_rpc_url: hardening.starknet_rpc_url.map(Arc::new),
        auction_verifier_address: hardening.auction_verifier_address.map(Arc::new),
        http_client: service_http_client(),
        output_note_root_selector: selector_hex("output_note_root"),
        verified_auction_transcript_selector: selector_hex("verified_auction_transcript"),
        renewal_cancel_marker_recorded_selector: selector_hex("renewal_cancel_marker_recorded"),
        rate_limiter: RateLimiter::default(),
        order_submission_metrics: IngressTelemetryMetrics::default(),
    };

    Ok(Router::new()
        .route("/health", get(health))
        .route("/api/batches", get(list_batches))
        .route("/api/batches/current", get(current_batch))
        .route("/api/batches/submittable", get(submittable_batch))
        .route("/api/batches/transcripts", get(list_published_transcripts))
        .route(
            "/api/pairs/{base}/{quote}/batches/current",
            get(current_pair_batch),
        )
        .route(
            "/api/pairs/{base}/{quote}/batches/submittable",
            get(submittable_pair_batch),
        )
        .route("/api/batches/{batch_id}", get(get_batch))
        .route(
            "/api/batches/{batch_id}/transcript",
            get(get_published_transcript),
        )
        .route(
            "/api/batches/{batch_id}/output-bundle",
            get(get_published_output_bundle),
        )
        .route(
            "/api/internal/batches/proof-work",
            get(list_internal_proof_work_batches),
        )
        .route(
            "/api/internal/batches/{batch_id}/orders",
            get(get_batch_orders),
        )
        .route(
            "/api/internal/batches/{batch_id}/transcript",
            get(get_internal_published_transcript),
        )
        .route(
            "/api/internal/batches/{batch_id}/artifacts",
            post(publish_batch_artifacts),
        )
        .route(
            "/api/internal/batches/{batch_id}/settled-at",
            post(mark_published_batch_settled),
        )
        .route(
            "/api/internal/batches/{batch_id}/witness",
            get(get_published_witness),
        )
        .route(
            "/api/recovery/{account_id}/artifacts",
            get(list_recovery_artifacts).post(upload_recovery_artifact),
        )
        .route(
            "/api/recovery/{account_id}/artifacts/range/{start_sequence}/{end_sequence}",
            get(list_recovery_artifacts_range),
        )
        .route(
            "/api/wallet-vaults/{wallet_auth_id}",
            get(get_wallet_vault_bundle).post(upload_wallet_vault_bundle),
        )
        .route(
            "/api/settlement-reports/{batch_id}",
            post(query_private_settlement_report_by_batch),
        )
        .route(
            "/api/renewal/cancel-witness/{cancel_marker}",
            get(get_renewal_cancel_witness),
        )
        .route(
            "/api/renewal/cancel-markers",
            post(record_renewal_cancel_marker),
        )
        .route(
            "/api/renewal/cancel-markers/{cancel_marker}",
            get(get_renewal_cancel_marker_status),
        )
        .route(
            "/api/liquidity-positions/lifecycle",
            post(submit_liquidity_position_lifecycle),
        )
        .route(
            "/api/internal/renewal/cancel-markers",
            get(list_internal_renewal_cancel_markers),
        )
        .route("/api/internal/metrics", get(internal_metrics))
        .route("/api/orders", post(submit_order))
        .route("/api/orders/cancel", post(cancel_order))
        .with_state(app_state.clone())
        .layer(middleware::from_fn_with_state(
            app_state,
            internal_route_auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(hardening.max_body_bytes))
        .layer(cors_layer_for_origins(hardening.allowed_origins)))
}

async fn internal_route_auth_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();
    if path.starts_with("/api/internal/") {
        require_internal_auth(&state, request.headers())?;
    }
    Ok(next.run(request).await)
}

async fn health(State(state): State<AppState>) -> Json<CoordinatorStatus> {
    let mut batches = state.batches.write().await;
    if let Err(status) = advance_batch_lifecycle_durably(&state, &mut batches) {
        eprintln!("coordinator health failed to persist batch lifecycle: {status}");
    }
    let current_batch_id =
        current_open_batch_for_default_pair(&state.product_config, batches.values())
            .map(|record| record.batch.batch_id.clone());

    Json(CoordinatorStatus {
        service: "zylith-coordinator".into(),
        current_batch_id,
        batch_window_ms: state.batch_window_ms,
    })
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

async fn internal_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, StatusCode> {
    require_internal_auth(&state, &headers)?;
    Ok(state
        .order_submission_metrics
        .render_prometheus("zylith_coordinator"))
}

async fn list_batches(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Query(query): Query<ListBatchesQuery>,
) -> Result<Json<Vec<PublicBatchSummary>>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "batches-list")?;
    let mut batches = state.batches.write().await;
    advance_batch_lifecycle_durably(&state, &mut batches)?;
    let limit = public_batch_list_limit(query.limit);
    let status_filter = query.status.as_deref().map(public_batch_status_filter);
    Ok(Json(public_batch_summaries_limited(
        batches.values(),
        limit,
        status_filter.as_deref(),
    )))
}

#[derive(Debug, Deserialize)]
struct ListBatchesQuery {
    limit: Option<usize>,
    status: Option<String>,
}

async fn current_batch(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
) -> Result<Json<PublicBatchSummary>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "batch-current")?;
    let mut batches = state.batches.write().await;
    advance_batch_lifecycle_durably(&state, &mut batches)?;
    current_open_batch_for_default_pair(&state.product_config, batches.values())
        .map(public_summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn submittable_batch(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
) -> Result<Json<PublicBatchSummary>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "batch-submittable")?;
    let mut batches = state.batches.write().await;
    advance_batch_lifecycle_durably(&state, &mut batches)?;
    let default_pair = state
        .product_config
        .enabled_pairs()
        .into_iter()
        .next()
        .ok_or(StatusCode::NOT_FOUND)?;
    submittable_open_batch_for_pair(batches.values(), &default_pair, state.batch_window_ms)
        .map(public_summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn current_pair_batch(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path((base, quote)): Path<(String, String)>,
) -> Result<Json<PublicBatchSummary>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "pair-batch-current")?;
    let pair_id = PairId(format!("{base}/{quote}"));
    if state.product_config.enabled_pair(&pair_id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut batches = state.batches.write().await;
    advance_batch_lifecycle_durably(&state, &mut batches)?;

    current_open_batch_for_pair(batches.values(), &pair_id)
        .map(public_summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn submittable_pair_batch(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path((base, quote)): Path<(String, String)>,
) -> Result<Json<PublicBatchSummary>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "pair-batch-submittable")?;
    let pair_id = PairId(format!("{base}/{quote}"));
    if state.product_config.enabled_pair(&pair_id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut batches = state.batches.write().await;
    advance_batch_lifecycle_durably(&state, &mut batches)?;

    submittable_open_batch_for_pair(batches.values(), &pair_id, state.batch_window_ms)
        .map(public_summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_batch(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<PublicBatchSummary>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "batch-get")?;
    let mut batches = state.batches.write().await;
    advance_batch_lifecycle_durably(&state, &mut batches)?;
    batches
        .get(&batch_id)
        .map(public_summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_batch_orders(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<BatchOrderSet>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let mut batches = state.batches.write().await;
    advance_batch_lifecycle_durably(&state, &mut batches)?;
    let record = batches.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(BatchOrderSet {
        batch: summary_from_record(record),
        orders: record.orders.clone(),
        liquidity_position_lifecycle_submissions: record.liquidity_lifecycle_submissions.clone(),
    }))
}

async fn list_internal_proof_work_batches(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListBatchesQuery>,
) -> Result<Json<Vec<BatchSummary>>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let mut batches = state.batches.write().await;
    advance_batch_lifecycle_durably(&state, &mut batches)?;
    let limit = public_batch_list_limit(query.limit);
    let status_filter = query
        .status
        .as_deref()
        .map(public_batch_status_filter)
        .unwrap_or_else(|| vec![BatchStatus::Closed, BatchStatus::Clearing]);
    Ok(Json(internal_proof_work_batch_summaries_limited(
        batches.values(),
        limit,
        &status_filter,
    )))
}

async fn get_published_transcript(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<PublicSettlementTranscript>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "batch-transcript")?;
    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    if !is_public_artifact_visible(
        &artifacts,
        published,
        published.transcript.batch_epoch,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        state.batch_window_ms,
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    public_settlement_transcript(published).map(Json)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptBatchQuery {
    batch_ids: String,
}

async fn list_published_transcripts(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Query(query): Query<TranscriptBatchQuery>,
) -> Result<Json<Vec<PublicSettlementTranscript>>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "batch-transcripts")?;
    let requested = query
        .batch_ids
        .split(',')
        .map(str::trim)
        .filter(|batch_id| !batch_id.is_empty())
        .collect::<BTreeSet<_>>();
    if requested.len() > MAX_PUBLIC_TRANSCRIPT_BATCH_IDS {
        return Err(StatusCode::BAD_REQUEST);
    }
    let artifacts = state.published_batch_artifacts.read().await;
    let transcripts = requested
        .into_iter()
        .filter_map(|batch_id| {
            let published = artifacts.get(batch_id)?;
            is_public_artifact_visible(
                &artifacts,
                published,
                published.transcript.batch_epoch,
                state.public_artifact_delay_min_epochs,
                state.public_artifact_delay_max_epochs,
                state.artifact_epoch_bucket_size,
                state.batch_window_ms,
            )
            .then(|| public_settlement_transcript(published).ok())
            .flatten()
        })
        .collect();
    Ok(Json(transcripts))
}

async fn get_internal_published_transcript(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<zylith_core::SettlementTranscript>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(published.transcript.clone()))
}

async fn get_published_output_bundle(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<zylith_core::OutputCiphertextBundle>, StatusCode> {
    enforce_public_rate_limit(&state, &headers, peer, "output-bundle")?;
    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    if !is_public_artifact_visible(
        &artifacts,
        published,
        published.transcript.batch_epoch,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        state.batch_window_ms,
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(published.output_bundle.clone()))
}

fn is_public_artifact_visible(
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
    published: &PublishedBatchArtifacts,
    batch_epoch: u64,
    min_delay_epochs: u64,
    max_delay_epochs: u64,
    artifact_epoch_bucket_size: u64,
    batch_window_ms: u64,
) -> bool {
    let Ok(bucket_start) = artifact_epoch_bucket_start(batch_epoch, artifact_epoch_bucket_size)
    else {
        return false;
    };
    let Ok(bucket_end) = artifact_epoch_bucket_end(bucket_start, artifact_epoch_bucket_size) else {
        return false;
    };
    let delay_subject = format!("{bucket_start}:{bucket_end}");
    let delay_epochs =
        effective_public_artifact_delay_epochs(&delay_subject, min_delay_epochs, max_delay_epochs);
    if published.settled_at_unix_ms.is_none() {
        return false;
    }
    if delay_epochs == 0 {
        return published.published_at_unix_ms != 0;
    }
    let Some(max_epoch) = artifacts
        .values()
        .map(|published| published.transcript.batch_epoch)
        .max()
    else {
        return false;
    };
    let release_epoch = bucket_end.saturating_add(delay_epochs);
    if max_epoch >= release_epoch {
        return true;
    }
    let release_delay_epochs = release_epoch.saturating_sub(batch_epoch);
    let delay_ms = release_delay_epochs.saturating_mul(batch_window_ms);
    published.published_at_unix_ms != 0
        && now_unix_ms() >= published.published_at_unix_ms.saturating_add(delay_ms)
}

fn effective_public_artifact_delay_epochs(
    delay_subject: &str,
    min_delay_epochs: u64,
    max_delay_epochs: u64,
) -> u64 {
    if max_delay_epochs <= min_delay_epochs {
        return min_delay_epochs;
    }
    let Ok(digest) = tagged_commitment_sha256("zylith/artifact-delay-jitter-v1", &delay_subject)
    else {
        return min_delay_epochs;
    };
    let hex = digest.trim_start_matches("0x");
    let prefix = hex.get(..16).unwrap_or(hex);
    let entropy = u64::from_str_radix(prefix, 16).unwrap_or(0);
    min_delay_epochs + (entropy % (max_delay_epochs - min_delay_epochs + 1))
}

fn public_settlement_transcript(
    published: &PublishedBatchArtifacts,
) -> Result<PublicSettlementTranscript, StatusCode> {
    let roots = root_only_settlement_commitments(&published.transcript)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let transcript_commitment = settlement_transcript_commitment(&published.transcript)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let transcript_shape = published.transcript_shape.clone().unwrap_or_else(|| {
        zylith_core::transcript_shape_metadata(&published.transcript, &published.output_bundle)
    });
    Ok(PublicSettlementTranscript {
        batch_id: published.transcript.batch_id.clone(),
        pair_id: published.transcript.pair_id.clone(),
        batch_epoch: published.transcript.batch_epoch,
        published_at_unix_ms: published.published_at_unix_ms,
        settled_at_unix_ms: published.settled_at_unix_ms,
        order_commitment_root: published.transcript.order_commitment_root.clone(),
        encrypted_order_set_commitment: published.transcript.encrypted_order_set_commitment.clone(),
        transcript_commitment,
        clearing_price: published.transcript.clearing_price,
        price_base_scale: published.transcript.price_base_scale,
        taker_fee_bps: published.transcript.taker_fee_bps,
        relay_fee_bps: published.transcript.relay_fee_bps,
        protocol_fee_recipient: published.transcript.protocol_fee_recipient.clone(),
        relay_fee_recipient: published.transcript.relay_fee_recipient.clone(),
        output_bundle_ref: published.transcript.output_ciphertext_bundle_ref.clone(),
        prior_note_root: roots.prior_note_root,
        prior_nullifier_root: roots.prior_nullifier_root,
        prior_renewal_root: roots.prior_renewal_root,
        prior_fee_root: roots.prior_fee_root,
        prior_liquidity_position_root: roots.prior_liquidity_position_root,
        consumed_note_root: roots.consumed_note_root,
        consumed_nullifier_root: roots.consumed_nullifier_root,
        renewal_child_root: roots.renewal_child_root,
        liquidity_position_transition_root: roots.liquidity_position_transition_root,
        output_note_root: roots.output_note_root,
        fee_root: roots.fee_root,
        new_note_root: roots.new_note_root,
        new_nullifier_root: roots.new_nullifier_root,
        new_renewal_root: roots.new_renewal_root,
        new_fee_root: roots.new_fee_root,
        new_liquidity_position_root: roots.new_liquidity_position_root,
        transcript_shape,
    })
}

fn published_artifact_fingerprint(
    published: &PublishedBatchArtifacts,
) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(published)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("published_at_unix_ms");
        object.remove("settled_at_unix_ms");
        object.remove("settlement_transaction_hash");
        object.remove("settlement_contract_address");
    }
    serde_json::to_string(&value)
}

fn settlement_timestamp_update_from_published(
    published: &PublishedBatchArtifacts,
) -> Result<SettlementTimestampUpdate, StatusCode> {
    let roots = root_only_settlement_commitments(&published.transcript)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let transcript_commitment = settlement_transcript_commitment(&published.transcript)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let transaction_hash = published
        .settlement_transaction_hash
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Ok(SettlementTimestampUpdate {
        settled_at_unix_ms: published.settled_at_unix_ms.unwrap_or(1),
        transaction_hash,
        settlement_contract_address: published.settlement_contract_address.clone(),
        output_note_root: Some(roots.output_note_root),
        transcript_commitment: Some(transcript_commitment),
    })
}

async fn verify_published_batch_artifact(
    state: &AppState,
    published: &PublishedBatchArtifacts,
) -> Result<u64, StatusCode> {
    let update = settlement_timestamp_update_from_published(published)?;
    if state.require_artifact_onchain_verification {
        verify_settlement_timestamp_update(state, published, &update).await
    } else {
        // Explicit dev/test bypass: even unverified stores must not accept pre-settlement artifacts.
        published.settled_at_unix_ms.ok_or(StatusCode::BAD_REQUEST)
    }
}

async fn get_published_witness(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<zylith_core::SettlementWitness>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(published.settlement_witness.clone()))
}

async fn get_renewal_cancel_witness(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(cancel_marker): Path<String>,
) -> Result<Json<RenewalCancelWitnessResponse>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "renewal-cancel-witness",
        state.public_rate_limit_per_minute,
    )?;
    let artifacts = state.published_batch_artifacts.read().await;
    let markers = state.renewal_cancel_markers.read().await;
    let entries = settled_renewal_entries(&artifacts, &markers);
    let witness = renewal_sparse_witness_for_parent_cancel_marker(&entries, &cancel_marker)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(RenewalCancelWitnessResponse {
        cancel_marker,
        renewal_cancel_sparse_witness: witness,
    }))
}

async fn record_renewal_cancel_marker(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<RenewalCancelMarkerRequest>,
) -> Result<Json<RenewalCancelMarkerRecord>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "renewal-cancel-marker",
        state.public_rate_limit_per_minute,
    )?;
    let cancel_marker = normalize_required_felt(&request.cancel_marker)?;
    let has_internal_auth = require_internal_auth(&state, &headers).is_ok();
    {
        let markers = state.renewal_cancel_markers.read().await;
        if let Some(existing) = markers.get(&cancel_marker) {
            return Ok(Json(existing.clone()));
        }
    }
    if !has_internal_auth || state.require_artifact_onchain_verification {
        let transaction_hash = request
            .transaction_hash
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(StatusCode::BAD_REQUEST)?;
        let contract_address = configured_auction_verifier_address(&state)?;
        if let Some(request_address) = request
            .auction_verifier_address
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            let request_address = normalize_required_felt(request_address)?;
            if request_address != contract_address {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        let block_ref = fetch_transaction_block_ref(&state, transaction_hash).await?;
        let recorded = fetch_onchain_renewal_cancel_marker_recorded_at_block(
            &state,
            &contract_address,
            &cancel_marker,
            block_ref.block_id,
        )
        .await?;
        if !recorded {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let record = RenewalCancelMarkerRecord {
        cancel_marker: cancel_marker.clone(),
        transaction_hash: request
            .transaction_hash
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        recorded_at_unix_ms: now_unix_ms(),
    };
    let artifacts = state.published_batch_artifacts.read().await;
    let mut markers = state.renewal_cancel_markers.write().await;
    if let Some(existing) = markers.get(&cancel_marker) {
        return Ok(Json(existing.clone()));
    }
    let mut candidate = markers.clone();
    candidate.insert(cancel_marker, record.clone());
    persist_published_artifact_snapshots_if_configured(&state, &artifacts, &candidate)?;
    *markers = candidate;
    Ok(Json(record))
}

async fn get_renewal_cancel_marker_status(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(cancel_marker): Path<String>,
) -> Result<Json<RenewalCancelMarkerStatus>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "renewal-cancel-marker-status",
        state.public_rate_limit_per_minute,
    )?;
    let cancel_marker = normalize_required_felt(&cancel_marker)?;
    let markers = state.renewal_cancel_markers.read().await;
    Ok(Json(RenewalCancelMarkerStatus {
        recorded: markers.contains_key(&cancel_marker),
        cancel_marker,
    }))
}

async fn list_internal_renewal_cancel_markers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RenewalCancelMarkerList>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let markers = state.renewal_cancel_markers.read().await;
    Ok(Json(RenewalCancelMarkerList {
        records: markers.values().cloned().collect(),
    }))
}

fn settled_renewal_entries(
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
    cancel_markers: &BTreeMap<String, RenewalCancelMarkerRecord>,
) -> Vec<String> {
    let mut entries = BTreeSet::new();
    for published in artifacts.values() {
        if published.settled_at_unix_ms.is_none() {
            continue;
        }
        for renewal in &published.transcript.renewal_child_uses {
            entries.insert(renewal.child_nullifier.clone());
        }
    }
    entries.extend(cancel_markers.keys().cloned());
    entries.into_iter().collect()
}

fn recovery_artifact_payload_len(artifact: &RecoveryArtifact) -> usize {
    artifact.payload.algorithm.len()
        + artifact.payload.nonce.len()
        + artifact.payload.ciphertext.len()
}

async fn publish_batch_artifacts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
    Json(mut request): Json<PublishedBatchArtifacts>,
) -> Result<Json<PublishedBatchArtifacts>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    if request.transcript.batch_id.0 != batch_id || request.output_bundle.batch_id.0 != batch_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(bundle) = request.liquidity_provider_attribution_bundle.as_ref()
        && (bundle.batch_id.0 != batch_id
            || bundle
                .artifacts
                .iter()
                .any(|artifact| artifact.batch_id.0 != batch_id))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let expected_shape =
        zylith_core::validate_transcript_shape_policy(&request.transcript, &request.output_bundle)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(provided_shape) = request.transcript_shape.as_ref()
        && provided_shape != &expected_shape
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    request.transcript_shape = Some(expected_shape);
    if request.published_at_unix_ms == 0 {
        request.published_at_unix_ms = now_unix_ms();
    }
    let settled_at_unix_ms = verify_published_batch_artifact(&state, &request).await?;
    request.settled_at_unix_ms = Some(settled_at_unix_ms);

    let mut artifacts = state.published_batch_artifacts.write().await;
    let markers = state.renewal_cancel_markers.read().await;
    let mut candidate = artifacts.clone();
    let response = if let Some(existing) = candidate.get(&batch_id) {
        if published_artifact_fingerprint(existing).map_err(|_| StatusCode::BAD_REQUEST)?
            != published_artifact_fingerprint(&request).map_err(|_| StatusCode::BAD_REQUEST)?
        {
            return Err(StatusCode::CONFLICT);
        }
        if let Some(existing_settled_at) = existing.settled_at_unix_ms
            && existing_settled_at != settled_at_unix_ms
        {
            return Err(StatusCode::CONFLICT);
        }
        let existing = candidate.get_mut(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
        if existing.settled_at_unix_ms.is_none() {
            existing.settled_at_unix_ms = Some(settled_at_unix_ms);
            existing.settlement_transaction_hash = request.settlement_transaction_hash.clone();
            existing.settlement_contract_address = request.settlement_contract_address.clone();
        }
        existing.clone()
    } else {
        candidate.insert(batch_id, request.clone());
        request
    };
    persist_published_artifact_snapshots_if_configured(&state, &candidate, &markers)?;
    *artifacts = candidate;

    Ok(Json(response))
}

async fn mark_published_batch_settled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
    Json(request): Json<SettlementTimestampUpdate>,
) -> Result<Json<PublishedBatchArtifacts>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    if request.settled_at_unix_ms == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let published_snapshot = {
        let artifacts = state.published_batch_artifacts.read().await;
        artifacts
            .get(&batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };
    if let Some(existing_settled_at) = published_snapshot.settled_at_unix_ms {
        let settled_at_unix_ms =
            verify_settlement_timestamp_update(&state, &published_snapshot, &request).await?;
        if existing_settled_at != settled_at_unix_ms {
            return Err(StatusCode::CONFLICT);
        }
        let mut batches = state.batches.write().await;
        mark_batch_settled_durably(&state, &mut batches, &batch_id)?;
        return Ok(Json(published_snapshot));
    }
    let settled_at_unix_ms =
        verify_settlement_timestamp_update(&state, &published_snapshot, &request).await?;

    {
        let mut batches = state.batches.write().await;
        mark_batch_settled_durably(&state, &mut batches, &batch_id)?;
    }

    let mut artifacts = state.published_batch_artifacts.write().await;
    let markers = state.renewal_cancel_markers.read().await;
    let mut candidate = artifacts.clone();
    let published = candidate.get_mut(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    published.settled_at_unix_ms = Some(settled_at_unix_ms);
    published.settlement_transaction_hash = request
        .transaction_hash
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    published.settlement_contract_address = request
        .settlement_contract_address
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let response = published.clone();
    persist_published_artifact_snapshots_if_configured(&state, &candidate, &markers)?;
    *artifacts = candidate;

    Ok(Json(response))
}

async fn verify_settlement_timestamp_update(
    state: &AppState,
    published: &PublishedBatchArtifacts,
    request: &SettlementTimestampUpdate,
) -> Result<u64, StatusCode> {
    let roots = root_only_settlement_commitments(&published.transcript)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let output_note_root = request
        .output_note_root
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let provided = normalize_required_felt(output_note_root)?;
    let expected = normalize_required_felt(&roots.output_note_root)?;
    if provided != expected {
        return Err(StatusCode::BAD_REQUEST);
    }
    let transcript_commitment = request
        .transcript_commitment
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let provided = normalize_required_felt(transcript_commitment)?;
    let expected = normalize_required_felt(
        &settlement_transcript_commitment(&published.transcript)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
    )?;
    if provided != expected {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !state.require_artifact_onchain_verification {
        return Ok(request.settled_at_unix_ms);
    }
    if request
        .transaction_hash
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let contract_address = configured_auction_verifier_address(state)?;
    if let Some(request_address) = request
        .settlement_contract_address
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let request_address = normalize_required_felt(request_address)?;
        if request_address != contract_address {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let transaction_hash = request
        .transaction_hash
        .as_deref()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let block_ref = fetch_transaction_block_ref(state, transaction_hash).await?;
    let chain_root = fetch_onchain_output_note_root(
        state,
        &contract_address,
        &published.transcript.batch_id.0,
        block_ref.block_id.clone(),
    )
    .await?;
    let expected = normalize_required_felt(&roots.output_note_root)?;
    if chain_root != expected {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let chain_transcript = fetch_onchain_verified_auction_transcript(
        state,
        &contract_address,
        &published.transcript.batch_id.0,
        block_ref.block_id,
    )
    .await?;
    let expected_transcript = normalize_required_felt(
        &settlement_transcript_commitment(&published.transcript)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
    )?;
    if chain_transcript != expected_transcript {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(block_ref.timestamp_unix_ms)
}

async fn fetch_onchain_output_note_root(
    state: &AppState,
    contract_address: &str,
    batch_id: &str,
    block_id: serde_json::Value,
) -> Result<String, StatusCode> {
    let contract_address = normalize_required_felt(contract_address)?;
    if contract_address == "0x0" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let batch_id_felt = encode_starknet_felt("batch-id", batch_id);
    let root = starknet_call_contract_at_block(
        state,
        &contract_address,
        &state.output_note_root_selector,
        &[batch_id_felt],
        block_id,
    )
    .await?
    .into_iter()
    .next()
    .ok_or(StatusCode::BAD_GATEWAY)?;
    normalize_required_felt(&root)
}

async fn fetch_onchain_verified_auction_transcript(
    state: &AppState,
    contract_address: &str,
    batch_id: &str,
    block_id: serde_json::Value,
) -> Result<String, StatusCode> {
    let contract_address = normalize_required_felt(contract_address)?;
    if contract_address == "0x0" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let batch_id_felt = encode_starknet_felt("batch-id", batch_id);
    let transcript = starknet_call_contract_at_block(
        state,
        &contract_address,
        &state.verified_auction_transcript_selector,
        &[batch_id_felt],
        block_id,
    )
    .await?
    .into_iter()
    .next()
    .ok_or(StatusCode::BAD_GATEWAY)?;
    normalize_required_felt(&transcript)
}

fn configured_auction_verifier_address(state: &AppState) -> Result<String, StatusCode> {
    let address = state
        .auction_verifier_address
        .as_deref()
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let normalized = normalize_required_felt(address)?;
    if normalized == "0x0" {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(normalized)
}

async fn fetch_transaction_block_ref(
    state: &AppState,
    transaction_hash: &str,
) -> Result<StarknetTransactionBlockRef, StatusCode> {
    let rpc_url = state
        .starknet_rpc_url
        .as_deref()
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let transaction_hash = normalize_required_felt(transaction_hash)?;
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "starknet_getTransactionReceipt",
        "params": [transaction_hash],
    });
    let response = state
        .http_client
        .post(rpc_url.as_str())
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let body = decode_bounded_json::<StarknetTransactionReceiptResponse>(response).await?;
    let block_hash = body
        .result
        .and_then(|receipt| receipt.block_hash)
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let block_id = serde_json::json!({ "block_hash": normalize_required_felt(&block_hash)? });
    let timestamp_unix_ms = fetch_block_timestamp_unix_ms(state, block_id.clone()).await?;
    Ok(StarknetTransactionBlockRef {
        block_id,
        timestamp_unix_ms,
    })
}

async fn fetch_block_timestamp_unix_ms(
    state: &AppState,
    block_id: serde_json::Value,
) -> Result<u64, StatusCode> {
    let rpc_url = state
        .starknet_rpc_url
        .as_deref()
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "starknet_getBlockWithTxHashes",
        "params": [block_id],
    });
    let response = state
        .http_client
        .post(rpc_url.as_str())
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let body = decode_bounded_json::<StarknetBlockResponse>(response).await?;
    let timestamp = body.result.ok_or(StatusCode::BAD_GATEWAY)?.timestamp;
    timestamp.checked_mul(1000).ok_or(StatusCode::BAD_GATEWAY)
}

async fn fetch_onchain_renewal_cancel_marker_recorded_at_block(
    state: &AppState,
    contract_address: &str,
    cancel_marker: &str,
    block_id: serde_json::Value,
) -> Result<bool, StatusCode> {
    let contract_address = normalize_required_felt(contract_address)?;
    let cancel_marker = normalize_required_felt(cancel_marker)?;
    let result = starknet_call_contract_at_block(
        state,
        &contract_address,
        &state.renewal_cancel_marker_recorded_selector,
        &[cancel_marker],
        block_id,
    )
    .await?;
    let value = result.into_iter().next().ok_or(StatusCode::BAD_GATEWAY)?;
    Ok(normalize_required_felt(&value)? != "0x0")
}

async fn starknet_call_contract_at_block(
    state: &AppState,
    contract_address: &str,
    selector: &str,
    calldata: &[String],
    block_id: serde_json::Value,
) -> Result<Vec<String>, StatusCode> {
    let rpc_url = state
        .starknet_rpc_url
        .as_deref()
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let call = StarknetCallRequest {
        contract_address,
        entry_point_selector: selector,
        calldata,
    };
    let payload = StarknetRpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "starknet_call",
        params: serde_json::json!([call, block_id]),
    };
    let response = state
        .http_client
        .post(rpc_url.as_str())
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let body = decode_bounded_json::<StarknetRpcResponse>(response).await?;
    body.result.ok_or(StatusCode::BAD_GATEWAY)
}

async fn decode_bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, StatusCode> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_STARKNET_RPC_RESPONSE_BYTES as u64)
    {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_STARKNET_RPC_RESPONSE_BYTES {
            return Err(StatusCode::BAD_GATEWAY);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_GATEWAY)
}

async fn list_recovery_artifacts(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Result<Json<RecoveryArtifactList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "recovery-list",
        state.public_rate_limit_per_minute,
    )?;
    let provided_auth_tag = require_recovery_auth_header(&headers)?;
    let recovery_artifacts = state.recovery_artifacts.read().await;
    let artifacts = if let Some(account) = recovery_artifacts.get(&account_id) {
        if let Some(expected) = &account.recovery_auth_tag {
            if !zylith_core::constant_time_eq(expected, &provided_auth_tag) {
                return Err(StatusCode::UNAUTHORIZED);
            }
        } else {
            if !account.artifacts.is_empty() {
                return Err(StatusCode::NOT_FOUND);
            }
        }
        account.artifacts.clone()
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    Ok(Json(RecoveryArtifactList {
        account_id,
        sequence_start: artifacts
            .first()
            .map(|artifact| artifact.sequence)
            .unwrap_or(0),
        sequence_end: artifacts
            .last()
            .map(|artifact| artifact.sequence)
            .unwrap_or(0),
        artifact_count_bucket: count_bucket_label(artifacts.len() as u64),
        artifacts,
    }))
}

async fn get_wallet_vault_bundle(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(wallet_auth_id): Path<String>,
) -> Result<Json<WalletVaultBundleRecord>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "wallet-vault-get",
        state.public_rate_limit_per_minute,
    )?;
    if !is_wallet_auth_id(&wallet_auth_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    require_wallet_vault_auth(&headers, &wallet_auth_id)?;
    let wallet_vaults = state.wallet_vaults.read().await;
    let bundle = wallet_vaults
        .get(&wallet_auth_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(bundle))
}

async fn upload_wallet_vault_bundle(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(wallet_auth_id): Path<String>,
    Json(mut request): Json<WalletVaultBundleRecord>,
) -> Result<Json<WalletVaultBundleRecord>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "wallet-vault-upload",
        state.public_rate_limit_per_minute,
    )?;
    if !is_wallet_auth_id(&wallet_auth_id) || request.wallet_auth_id != wallet_auth_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    require_wallet_vault_auth(&headers, &wallet_auth_id)?;
    let payload_len = serde_json::to_string(&request)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .len();
    if payload_len > MAX_WALLET_VAULT_PAYLOAD_CHARS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    validate_wallet_vault_bundle(&request)?;
    if request.updated_at_unix_ms == 0 {
        request.updated_at_unix_ms = now_unix_ms();
    }
    let recovery_artifacts = state.recovery_artifacts.read().await;
    let mut wallet_vaults = state.wallet_vaults.write().await;
    if wallet_vaults
        .get(&wallet_auth_id)
        .is_some_and(|existing| request.updated_at_unix_ms <= existing.updated_at_unix_ms)
    {
        return Err(StatusCode::CONFLICT);
    }
    let mut candidate = wallet_vaults.clone();
    candidate.insert(wallet_auth_id, request.clone());
    if let Some(path) = state.recovery_store_path.as_deref() {
        persist_recovery_store_file(path, &recovery_artifacts, &candidate)?;
    }
    *wallet_vaults = candidate;
    Ok(Json(request))
}

async fn list_recovery_artifacts_range(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path((account_id, start_sequence, end_sequence)): Path<(String, u64, u64)>,
) -> Result<Json<RecoveryArtifactList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "recovery-list-range",
        state.public_rate_limit_per_minute,
    )?;
    if start_sequence > end_sequence {
        return Err(StatusCode::BAD_REQUEST);
    }
    let provided_auth_tag = require_recovery_auth_header(&headers)?;
    let recovery_artifacts = state.recovery_artifacts.read().await;
    let artifacts = if let Some(account) = recovery_artifacts.get(&account_id) {
        if let Some(expected) = &account.recovery_auth_tag {
            if !zylith_core::constant_time_eq(expected, &provided_auth_tag) {
                return Err(StatusCode::UNAUTHORIZED);
            }
        } else {
            return Err(StatusCode::NOT_FOUND);
        }
        account
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.sequence >= start_sequence && artifact.sequence <= end_sequence
            })
            .cloned()
            .collect::<Vec<_>>()
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    Ok(Json(RecoveryArtifactList {
        account_id,
        sequence_start: start_sequence,
        sequence_end: end_sequence,
        artifact_count_bucket: count_bucket_label(artifacts.len() as u64),
        artifacts,
    }))
}

async fn query_private_settlement_report_by_batch(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
    Json(request): Json<PrivateSettlementReportQuery>,
) -> Result<Json<PrivateSettlementReport>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "private-settlement-report",
        state.public_rate_limit_per_minute,
    )?;
    private_settlement_report_for_batch(&state, batch_id, request).await
}

async fn private_settlement_report_for_batch(
    state: &AppState,
    batch_id: String,
    request: PrivateSettlementReportQuery,
) -> Result<Json<PrivateSettlementReport>, StatusCode> {
    let requested_key_tags = request
        .output_recovery_key_tags
        .iter()
        .filter_map(|value| zylith_core::hash::normalize_felt_hex(value).ok())
        .collect::<BTreeSet<_>>();
    let mut requested_order_auths = BTreeMap::<String, BTreeSet<String>>::new();
    for auth in &request.order_report_auths {
        let Ok(commitment) = zylith_core::hash::normalize_felt_hex(&auth.order_commitment.0) else {
            continue;
        };
        let auth_tag = auth.order_report_auth_tag.trim().to_ascii_lowercase();
        if auth_tag.is_empty() {
            continue;
        }
        requested_order_auths
            .entry(commitment)
            .or_default()
            .insert(auth_tag);
    }
    let requested_liquidity_position_transition_commitments = request
        .liquidity_position_transition_commitments
        .iter()
        .filter_map(|value| zylith_core::hash::normalize_felt_hex(value).ok())
        .collect::<BTreeSet<_>>();
    let requested_liquidity_provider_public_keys = request
        .liquidity_provider_public_keys
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    if requested_key_tags.is_empty()
        && requested_order_auths.is_empty()
        && requested_liquidity_position_transition_commitments.is_empty()
        && requested_liquidity_provider_public_keys.is_empty()
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    let settled_at_unix_ms = published.settled_at_unix_ms.ok_or(StatusCode::NOT_FOUND)?;
    let order_execution_reports = if requested_order_auths.is_empty() {
        Vec::new()
    } else {
        published
            .order_execution_reports
            .iter()
            .filter(|report| {
                let Some(report_auth_tag) = report.order_report_auth_tag.as_deref() else {
                    return false;
                };
                let Ok(commitment) =
                    zylith_core::hash::normalize_felt_hex(&report.order_commitment.0)
                else {
                    return false;
                };
                requested_order_auths
                    .get(&commitment)
                    .map(|tags| {
                        tags.iter().any(|tag| {
                            zylith_core::constant_time_eq(
                                tag,
                                &report_auth_tag.trim().to_ascii_lowercase(),
                            )
                        })
                    })
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    let liquidity_position_lifecycle_reports =
        if requested_liquidity_position_transition_commitments.is_empty() {
            Vec::new()
        } else {
            published
                .transcript
                .liquidity_position_transitions
                .iter()
                .filter_map(|transition| {
                    let transition_commitment = settlement_liquidity_position_transition_root(
                        std::slice::from_ref(transition),
                    )
                    .ok()?;
                    let normalized =
                        zylith_core::hash::normalize_felt_hex(&transition_commitment).ok()?;
                    requested_liquidity_position_transition_commitments
                        .contains(&normalized)
                        .then(|| LiquidityPositionLifecycleReport {
                            transition_commitment: normalized,
                            kind: transition.kind.clone(),
                            consumed_position_commitment: transition
                                .consumed_position_commitment
                                .clone(),
                            output_position_commitment: transition
                                .output_position_commitment
                                .clone(),
                        })
                })
                .collect::<Vec<_>>()
        };
    let liquidity_provider_attribution_artifacts = published
        .liquidity_provider_attribution_bundle
        .as_ref()
        .map(|bundle| {
            bundle
                .artifacts
                .iter()
                .filter(|artifact| {
                    let owner_match = requested_liquidity_provider_public_keys.contains(
                        &artifact
                            .liquidity_provider_public_key
                            .trim()
                            .to_ascii_lowercase(),
                    );
                    let transition_match =
                        zylith_core::hash::normalize_felt_hex(&artifact.order_commitment.0)
                            .ok()
                            .map(|commitment| {
                                requested_liquidity_position_transition_commitments
                                    .contains(&commitment)
                            })
                            .unwrap_or(false);
                    owner_match || transition_match
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let authenticated_output_commitments = order_execution_reports
        .iter()
        .flat_map(|report| {
            [
                report.output_note_commitment.as_ref(),
                report.residual_note_commitment.as_ref(),
            ]
        })
        .flatten()
        .filter_map(|commitment| zylith_core::hash::normalize_felt_hex(&commitment.0).ok())
        .collect::<BTreeSet<_>>();
    let authenticated_output_indices = published
        .transcript
        .output_notes
        .iter()
        .enumerate()
        .filter_map(|(output_index, output)| {
            let normalized =
                zylith_core::hash::normalize_felt_hex(&output.note_commitment.0).ok()?;
            authenticated_output_commitments
                .contains(&normalized)
                .then_some(output_index)
        })
        .collect::<BTreeSet<_>>();
    let output_recovery_records = published
        .transcript
        .output_recovery_records
        .iter()
        .enumerate()
        .filter_map(|(output_index, recovery)| {
            let key_tag_match = zylith_core::hash::normalize_felt_hex(&recovery.key_tag)
                .ok()
                .map(|normalized| requested_key_tags.contains(&normalized))
                .unwrap_or(false);
            (key_tag_match || authenticated_output_indices.contains(&output_index)).then(|| {
                PrivateSettlementOutputRecoveryRecord {
                    output_index: output_index as u64,
                    recovery: recovery.clone(),
                }
            })
        })
        .collect::<Vec<_>>();
    if output_recovery_records.is_empty()
        && order_execution_reports.is_empty()
        && liquidity_position_lifecycle_reports.is_empty()
        && liquidity_provider_attribution_artifacts.is_empty()
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let roots = root_only_settlement_commitments(&published.transcript)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(PrivateSettlementReport {
        batch_id: published.transcript.batch_id.clone(),
        pair_id: published.transcript.pair_id.clone(),
        batch_epoch: published.transcript.batch_epoch,
        settled_at_unix_ms,
        output_note_root: roots.output_note_root,
        clearing_price: published.transcript.clearing_price,
        price_base_scale: published.transcript.price_base_scale,
        matched_order_count_bucket: count_bucket_label(
            published.transcript.matched_orders.len() as u64
        ),
        output_recovery_records,
        order_execution_reports,
        liquidity_position_lifecycle_reports,
        liquidity_provider_attribution_artifacts,
    }))
}

async fn upload_recovery_artifact(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<RecoveryArtifactUpload>,
) -> Result<Json<RecoveryArtifact>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "recovery-upload",
        state.public_rate_limit_per_minute,
    )?;
    if request.artifact.account_id != account_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    if recovery_artifact_payload_len(&request.artifact) > MAX_RECOVERY_ARTIFACT_PAYLOAD_CHARS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let provided_auth_tag = require_recovery_auth_header(&headers)?;
    let artifact = request.artifact;
    let mut recovery_artifacts = state.recovery_artifacts.write().await;
    let mut candidate = recovery_artifacts.clone();
    let account = candidate.entry(account_id).or_default();
    if let Some(expected) = &account.recovery_auth_tag {
        if !zylith_core::constant_time_eq(expected, &provided_auth_tag) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        if !account.artifacts.is_empty() {
            return Err(StatusCode::NOT_FOUND);
        }
        account.recovery_auth_tag = Some(provided_auth_tag);
    }
    if account
        .artifacts
        .iter()
        .any(|existing| existing.artifact_id == artifact.artifact_id)
    {
        return Err(StatusCode::CONFLICT);
    }
    if let Some(latest) = account.artifacts.iter().map(|entry| entry.sequence).max()
        && artifact.sequence <= latest
    {
        return Err(StatusCode::CONFLICT);
    }
    if account.artifacts.len() >= MAX_RECOVERY_ARTIFACTS_PER_ACCOUNT {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    account.artifacts.push(artifact.clone());
    account
        .artifacts
        .sort_by_key(|entry| (entry.sequence, entry.created_at_unix_ms));

    if let Some(path) = state.recovery_store_path.as_deref() {
        let wallet_vaults = state.wallet_vaults.read().await;
        persist_recovery_store_file(path, &candidate, &wallet_vaults)?;
    }
    *recovery_artifacts = candidate;

    Ok(Json(artifact))
}

async fn submit_order(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<OrderSubmissionTelemetryEnvelope>,
) -> Result<Json<OrderSubmissionAccepted>, StatusCode> {
    let started_at_unix_ms = now_unix_ms();
    let ingress_telemetry = request.ingress_telemetry.clone();
    let result = async {
        require_order_intake_enabled(&state)?;
        enforce_rate_limit(
            &state.rate_limiter,
            &headers,
            peer,
            "submit-order",
            state.public_rate_limit_per_minute,
        )?;
        submit_order_inner(
            state.clone(),
            OrderSubmission {
                order_bundle: request.order_bundle,
            },
        )
        .await
    }
    .await;
    state.order_submission_metrics.record(
        coordinator_order_submission_outcome_label(&result),
        now_unix_ms().saturating_sub(started_at_unix_ms),
        Some(&ingress_telemetry),
    );
    result
}

async fn submit_liquidity_position_lifecycle(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<LiquidityPositionLifecycleSubmissionTelemetryEnvelope>,
) -> Result<Json<LiquidityPositionLifecycleAccepted>, StatusCode> {
    let started_at_unix_ms = now_unix_ms();
    let ingress_telemetry = request.ingress_telemetry.clone();
    let result = async {
        require_order_intake_enabled(&state)?;
        enforce_rate_limit(
            &state.rate_limiter,
            &headers,
            peer,
            "submit-liquidity-position-lifecycle",
            state.public_rate_limit_per_minute,
        )?;
        submit_liquidity_position_lifecycle_inner(state.clone(), request.into()).await
    }
    .await;
    state.order_submission_metrics.record(
        coordinator_order_submission_outcome_label(&result),
        now_unix_ms().saturating_sub(started_at_unix_ms),
        Some(&ingress_telemetry),
    );
    result
}

fn coordinator_order_submission_outcome_label<T>(result: &Result<T, StatusCode>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(StatusCode::CONFLICT) => "conflict",
        Err(StatusCode::TOO_MANY_REQUESTS) => "rate_limited",
        Err(StatusCode::BAD_REQUEST) => "bad_request",
        Err(StatusCode::SERVICE_UNAVAILABLE) => "unavailable",
        Err(_) => "rejected",
    }
}

async fn submit_liquidity_position_lifecycle_inner(
    state: AppState,
    request: LiquidityPositionLifecycleSubmission,
) -> Result<Json<LiquidityPositionLifecycleAccepted>, StatusCode> {
    let accepted_at_unix_ms = now_unix_ms();
    let submission = coordinator_liquidity_position_lifecycle_for_storage(&state, request)?;

    let mut batches = state.batches.write().await;
    let mut candidate = batches.clone();
    let enabled_pairs = state.product_config.enabled_pairs();
    advance_batch_lifecycle(
        &mut candidate,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    )?;
    if state
        .product_config
        .enabled_pair(&submission.pair_id)
        .is_none()
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let batch_key = batch_key(&submission.pair_id, submission.epoch_id);
    if submission.batch_id.0 != batch_key {
        return Err(StatusCode::CONFLICT);
    }
    let record = candidate.get_mut(&batch_key).ok_or(StatusCode::CONFLICT)?;
    if record.batch.status != BatchStatus::Open {
        return Err(StatusCode::CONFLICT);
    }
    if record
        .batch
        .close_time_unix_ms
        .saturating_sub(accepted_at_unix_ms)
        <= batch_submission_safety_buffer_ms(state.batch_window_ms)
    {
        return Err(StatusCode::CONFLICT);
    }
    let private_activity_count =
        record.orders.len() as u64 + record.liquidity_lifecycle_submissions.len() as u64;
    if state.max_orders_per_batch > 0 && private_activity_count >= state.max_orders_per_batch {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let accepted = if let Some(existing) = record
        .liquidity_lifecycle_submissions
        .iter()
        .find(|entry| entry.submission.lifecycle_id == submission.lifecycle_id)
    {
        LiquidityPositionLifecycleAccepted {
            batch_id: record.batch.batch_id.clone(),
            lifecycle_id: existing.submission.lifecycle_id.clone(),
            transition_commitment: existing.submission.transition_commitment.clone(),
            accepted_at_unix_ms: existing.received_at_unix_ms,
        }
    } else {
        record.liquidity_lifecycle_count += 1;
        record
            .liquidity_lifecycle_submissions
            .push(SubmittedLiquidityPositionLifecycleRecord {
                received_at_unix_ms: accepted_at_unix_ms,
                submission: submission.clone(),
            });
        LiquidityPositionLifecycleAccepted {
            batch_id: record.batch.batch_id.clone(),
            lifecycle_id: submission.lifecycle_id,
            transition_commitment: submission.transition_commitment,
            accepted_at_unix_ms,
        }
    };
    persist_batch_store_if_configured(&state, &candidate)?;
    *batches = candidate;

    Ok(Json(accepted))
}

async fn submit_order_inner(
    state: AppState,
    request: OrderSubmission,
) -> Result<Json<OrderSubmissionAccepted>, StatusCode> {
    let accepted_at_unix_ms = now_unix_ms();
    let order_bundle = coordinator_order_bundle_for_storage(&state, request.order_bundle)?;

    let mut batches = state.batches.write().await;
    let mut candidate = batches.clone();
    let enabled_pairs = state.product_config.enabled_pairs();
    advance_batch_lifecycle(
        &mut candidate,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    )?;
    if state
        .product_config
        .enabled_pair(&order_bundle.pair_id)
        .is_none()
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let batch_key = batch_key(&order_bundle.pair_id, order_bundle.epoch_id);
    if order_bundle.batch_id.0 != batch_key {
        return Err(StatusCode::CONFLICT);
    }
    let record = candidate.get_mut(&batch_key).ok_or(StatusCode::CONFLICT)?;

    if record.batch.status != BatchStatus::Open {
        return Err(StatusCode::CONFLICT);
    }
    if record
        .batch
        .close_time_unix_ms
        .saturating_sub(accepted_at_unix_ms)
        <= batch_submission_safety_buffer_ms(state.batch_window_ms)
    {
        return Err(StatusCode::CONFLICT);
    }
    if state.max_orders_per_batch > 0 && record.orders.len() as u64 >= state.max_orders_per_batch {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let accepted = if let Some(existing) = record
        .orders
        .iter()
        .find(|order| order.order_bundle.order_commitment == order_bundle.order_commitment)
    {
        OrderSubmissionAccepted {
            batch_id: record.batch.batch_id.clone(),
            order_commitment: existing.order_bundle.order_commitment.clone(),
            accepted_at_unix_ms: existing.received_at_unix_ms,
        }
    } else {
        record.order_count += 1;
        record.orders.push(SubmittedOrderRecord {
            received_at_unix_ms: accepted_at_unix_ms,
            order_bundle: order_bundle.clone(),
        });
        refresh_batch_commitments(
            record,
            &state.product_config,
            state.heartbeat_cover_secret.as_str(),
        )?;
        OrderSubmissionAccepted {
            batch_id: record.batch.batch_id.clone(),
            order_commitment: order_bundle.order_commitment,
            accepted_at_unix_ms,
        }
    };
    persist_batch_store_if_configured(&state, &candidate)?;
    *batches = candidate;

    Ok(Json(accepted))
}

fn coordinator_liquidity_position_lifecycle_for_storage(
    state: &AppState,
    submission: LiquidityPositionLifecycleSubmission,
) -> Result<LiquidityPositionLifecycleSubmission, StatusCode> {
    if state.order_ingress_receipt_secrets.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    validate_liquidity_position_ingress_receipt_for_manifest_with_secrets(
        &submission,
        state.order_ingress_receipt_secrets.as_ref(),
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(submission)
}

fn coordinator_order_bundle_for_storage(
    state: &AppState,
    mut order_bundle: OrderShareBundle,
) -> Result<OrderShareBundle, StatusCode> {
    if order_bundle.ingress_receipt.is_some() {
        if state.order_ingress_receipt_secrets.is_empty() {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        validate_order_ingress_receipt_for_manifest_with_secrets(
            &order_bundle,
            state.order_ingress_receipt_secrets.as_ref(),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        order_bundle.transport_envelope = None;
        order_bundle.shares.clear();
        return Ok(order_bundle);
    }

    Err(StatusCode::BAD_REQUEST)
}

async fn cancel_order(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<OrderCancellationRequest>,
) -> Result<Json<OrderCancellationAccepted>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "cancel-order",
        state.public_rate_limit_per_minute,
    )?;
    cancel_order_inner(state, request).await
}

async fn cancel_order_inner(
    state: AppState,
    request: OrderCancellationRequest,
) -> Result<Json<OrderCancellationAccepted>, StatusCode> {
    let mut batches = state.batches.write().await;
    let mut candidate = batches.clone();
    let enabled_pairs = state.product_config.enabled_pairs();
    advance_batch_lifecycle(
        &mut candidate,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    )?;
    let record = candidate
        .get_mut(&request.batch_id.0)
        .ok_or(StatusCode::NOT_FOUND)?;

    if record.batch.status != BatchStatus::Open {
        return Err(StatusCode::CONFLICT);
    }
    if record
        .batch
        .close_time_unix_ms
        .saturating_sub(now_unix_ms())
        <= batch_submission_safety_buffer_ms(state.batch_window_ms)
    {
        return Err(StatusCode::CONFLICT);
    }

    let expected_tag = derive_order_cancellation_tag(&request.cancellation_secret);
    let order_index = record
        .orders
        .iter()
        .position(|order| {
            order.order_bundle.order_commitment == request.order_commitment
                && order.order_bundle.cancellation_auth_tag == expected_tag
        })
        .ok_or(StatusCode::NOT_FOUND)?;

    record.orders.remove(order_index);
    record.order_count = record.orders.len() as u64;
    refresh_batch_commitments(
        record,
        &state.product_config,
        state.heartbeat_cover_secret.as_str(),
    )?;
    let accepted = OrderCancellationAccepted {
        batch_id: request.batch_id,
        order_commitment: request.order_commitment,
        cancelled_at_unix_ms: now_unix_ms(),
    };
    persist_batch_store_if_configured(&state, &candidate)?;
    *batches = candidate;

    Ok(Json(accepted))
}

fn summary_from_record(record: &BatchRecord) -> BatchSummary {
    BatchSummary {
        batch_id: record.batch.batch_id.clone(),
        pair_id: record.batch.pair_id.clone(),
        epoch_id: record.batch.epoch_id,
        close_time_unix_ms: record.batch.close_time_unix_ms,
        status: record.batch.status.clone(),
        order_count: heartbeat_cover_order_count(record.orders.len()) as u64
            + record.liquidity_lifecycle_submissions.len() as u64,
        order_commitment_root: record.batch.order_commitment_root.clone(),
        encrypted_order_set_commitment: record.batch.encrypted_order_set_commitment.clone(),
    }
}

fn public_summary_from_record(record: &BatchRecord) -> PublicBatchSummary {
    PublicBatchSummary {
        batch_id: record.batch.batch_id.clone(),
        pair_id: record.batch.pair_id.clone(),
        epoch_id: record.batch.epoch_id,
        close_time_unix_ms: record.batch.close_time_unix_ms,
        status: record.batch.status.clone(),
        order_count_bucket: count_bucket_label(
            heartbeat_cover_order_count(record.orders.len()) as u64
                + record.liquidity_lifecycle_submissions.len() as u64,
        ),
    }
}

fn public_batch_list_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_PUBLIC_BATCH_LIST_LIMIT)
        .clamp(1, MAX_PUBLIC_BATCH_LIST_LIMIT)
}

fn public_batch_status_filter(value: &str) -> Vec<BatchStatus> {
    value
        .split(',')
        .filter_map(|status| match status.trim().to_ascii_lowercase().as_str() {
            "open" => Some(BatchStatus::Open),
            "closed" => Some(BatchStatus::Closed),
            "clearing" => Some(BatchStatus::Clearing),
            "settled" => Some(BatchStatus::Settled),
            _ => None,
        })
        .collect()
}

fn public_batch_summaries_limited<'a>(
    records: impl Iterator<Item = &'a BatchRecord>,
    limit: usize,
    status_filter: Option<&[BatchStatus]>,
) -> Vec<PublicBatchSummary> {
    let mut summaries = records
        .filter(|record| {
            status_filter
                .map(|statuses| statuses.contains(&record.batch.status))
                .unwrap_or(true)
        })
        .map(public_summary_from_record)
        .collect::<Vec<PublicBatchSummary>>();
    summaries.sort_by(|left, right| {
        right
            .close_time_unix_ms
            .cmp(&left.close_time_unix_ms)
            .then_with(|| right.epoch_id.cmp(&left.epoch_id))
            .then_with(|| right.batch_id.0.cmp(&left.batch_id.0))
    });
    summaries.truncate(limit);
    summaries
}

fn internal_proof_work_batch_summaries_limited<'a>(
    records: impl Iterator<Item = &'a BatchRecord>,
    limit: usize,
    status_filter: &[BatchStatus],
) -> Vec<BatchSummary> {
    let mut summaries = records
        .filter(|record| {
            !record.orders.is_empty() || !record.liquidity_lifecycle_submissions.is_empty()
        })
        .filter(|record| status_filter.contains(&record.batch.status))
        .map(summary_from_record)
        .collect::<Vec<BatchSummary>>();
    summaries.sort_by(|left, right| {
        right
            .close_time_unix_ms
            .cmp(&left.close_time_unix_ms)
            .then_with(|| right.epoch_id.cmp(&left.epoch_id))
            .then_with(|| right.batch_id.0.cmp(&left.batch_id.0))
    });
    summaries.truncate(limit);
    summaries
}

fn load_product_config() -> Result<ProductConfig, String> {
    let primary = env::var(PRODUCT_PAIRS_ENV).ok();
    let coordinator = env::var(COORDINATOR_PAIR_IDS_ENV).ok();
    let mut product_config =
        product_config_from_pair_sources(primary.as_deref(), coordinator.as_deref())?;
    if let Ok(value) = env::var(HEARTBEAT_COVER_PRICES_ENV) {
        product_config
            .apply_heartbeat_cover_prices_csv(&value)
            .map_err(|error| format!("configured heartbeat cover prices are invalid: {error}"))?;
    }
    Ok(product_config)
}

fn product_config_from_pair_sources(
    primary: Option<&str>,
    coordinator: Option<&str>,
) -> Result<ProductConfig, String> {
    let product_config = if let Some(value) = primary.or(coordinator) {
        ProductConfig::from_enabled_pair_ids_csv(value)
            .map_err(|error| format!("configured product pairs are invalid: {error}"))?
    } else {
        return Err(format!(
            "{PRODUCT_PAIRS_ENV} or {COORDINATOR_PAIR_IDS_ENV} is required"
        ));
    };
    Ok(product_config)
}

fn env_bool_or_default(env_name: &str, default: bool) -> bool {
    env::var(env_name)
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn env_u64_or_default(env_name: &str, default: u64) -> Result<u64, String> {
    env::var(env_name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("invalid {env_name}"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn env_positive_u64_or_default(env_name: &str, default: u64) -> Result<u64, String> {
    let value = env_u64_or_default(env_name, default)?;
    if value == 0 {
        return Err(format!("{env_name} must be positive"));
    }
    Ok(value)
}

fn env_positive_usize_or_default(env_name: &str, default: usize) -> Result<usize, String> {
    let value = env::var(env_name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("invalid {env_name}"))
        })
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{env_name} must be positive"));
    }
    Ok(value)
}

fn selector_hex(name: &str) -> String {
    format!(
        "{:#x}",
        get_selector_from_name(name).expect("known Starknet selector name")
    )
}

fn normalize_required_felt(value: &str) -> Result<String, StatusCode> {
    normalize_felt_hex(value).map_err(|_| StatusCode::BAD_REQUEST)
}

fn is_wallet_auth_id(value: &str) -> bool {
    let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn require_wallet_vault_auth(headers: &HeaderMap, wallet_auth_id: &str) -> Result<(), StatusCode> {
    let auth_token = headers
        .get(WALLET_VAULT_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit()))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let expected_id = format!(
        "0x{}",
        tagged_sha256_hex(WALLET_VAULT_ID_DOMAIN, auth_token.as_bytes())
    );
    if !zylith_core::constant_time_eq(&expected_id, &wallet_auth_id.to_ascii_lowercase()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn validate_wallet_vault_bundle(bundle: &WalletVaultBundleRecord) -> Result<(), StatusCode> {
    let Some(vault) = bundle.vault.as_object() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    const WALLET_VAULT_FIELDS: &[&str] = &[
        "version",
        "kdf",
        "algorithm",
        "wallet_address",
        "chain_id",
        "deployment_id",
        "origin",
        "message_version",
        "nonce",
        "ciphertext",
    ];
    if vault
        .keys()
        .any(|field| !WALLET_VAULT_FIELDS.contains(&field.as_str()))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if vault.get("version").and_then(|value| value.as_u64()) != Some(4)
        || vault.get("kdf").and_then(|value| value.as_str()) != Some("wallet-signature-sha256-v2")
        || vault.get("algorithm").and_then(|value| value.as_str()) != Some("AES-GCM")
        || vault
            .get("message_version")
            .and_then(|value| value.as_u64())
            != Some(2)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    for field in [
        "wallet_address",
        "chain_id",
        "deployment_id",
        "origin",
        "nonce",
        "ciphertext",
    ] {
        if vault
            .get(field)
            .and_then(|value| value.as_str())
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Ok(())
}

fn is_configured_felt(value: &str) -> bool {
    normalize_felt_hex(value)
        .ok()
        .is_some_and(|felt| felt != "0x0")
}

fn load_receipt_secret_keyring() -> Vec<String> {
    let mut keyring = Vec::new();
    if let Ok(current) = env::var(ORDER_INGRESS_RECEIPT_SECRET_ENV) {
        let current = current.trim();
        if !current.is_empty() {
            keyring.push(current.to_owned());
        }
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

fn cors_layer_for_origins(origins: Vec<HeaderValue>) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);
    base.allow_origin(AllowOrigin::list(origins))
}

fn coordinator_strict_mode() -> bool {
    env::var("ZYLITH_COORDINATOR_STRICT")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        || env::var("ZYLITH_ENV")
            .ok()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("production"))
}

fn ensure_non_default_store_path(
    env_name: &str,
    path: Option<&FsPath>,
    default_path: &str,
) -> Result<(), String> {
    let Some(path) = path else {
        return Err(format!("{env_name} is required in production"));
    };
    if path == FsPath::new(default_path) {
        return Err(format!("{env_name} must point at a production volume"));
    }
    Ok(())
}

fn ensure_sqlite_store_path(env_name: &str, path: Option<&FsPath>) -> Result<(), String> {
    let Some(path) = path else {
        return Err(format!("{env_name} is required in production"));
    };
    if !is_sqlite_store(path) {
        return Err(format!(
            "{env_name} must point to a .db, .sqlite, or .sqlite3 durable store in production"
        ));
    }
    Ok(())
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

fn require_order_intake_enabled(state: &AppState) -> Result<(), StatusCode> {
    if state.emergency_paused {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
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
    rate_limit_subject_with_trusted_proxy_cidrs(
        headers,
        peer,
        trusted_proxy_headers_enabled(),
        &trusted_proxy_cidrs(),
    )
}

fn rate_limit_subject_with_trusted_proxy_cidrs(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trust_proxy_headers: bool,
    trusted_proxy_cidrs: &[String],
) -> String {
    if trust_proxy_headers
        && peer
            .map(|address| ip_matches_trusted_proxy(address.ip(), trusted_proxy_cidrs))
            .unwrap_or(false)
    {
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
        .map(|value| normalize_ip(value).to_string())
}

fn trusted_proxy_cidrs() -> Vec<String> {
    env::var("ZYLITH_COORDINATOR_TRUSTED_PROXY_CIDRS")
        .or_else(|_| env::var("ZYLITH_TRUSTED_PROXY_CIDRS"))
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn ip_matches_trusted_proxy(peer: IpAddr, trusted_proxy_cidrs: &[String]) -> bool {
    let peer = normalize_ip(peer);
    trusted_proxy_cidrs.iter().any(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return false;
        }
        if let Ok(exact) = entry.parse::<IpAddr>() {
            return normalize_ip(exact) == peer;
        }
        let Some((base, prefix_len)) = entry.split_once('/') else {
            return false;
        };
        let Ok(prefix_len) = prefix_len.parse::<u32>() else {
            return false;
        };
        let Ok(base_ip) = base.parse::<IpAddr>() else {
            return false;
        };
        match (normalize_ip(base_ip), peer) {
            (IpAddr::V4(base), IpAddr::V4(peer)) if prefix_len <= 32 => {
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                u32::from(base) & mask == u32::from(peer) & mask
            }
            (IpAddr::V6(base), IpAddr::V6(peer)) if prefix_len <= 128 => {
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                u128::from(base) & mask == u128::from(peer) & mask
            }
            _ => false,
        }
    })
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        value => value,
    }
}

fn trusted_proxy_headers_enabled() -> bool {
    matches!(
        env::var("ZYLITH_TRUST_PROXY_HEADERS")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

fn require_recovery_auth_header(headers: &HeaderMap) -> Result<String, StatusCode> {
    headers
        .get(zylith_core::RECOVERY_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or(StatusCode::UNAUTHORIZED)
}

fn current_open_batch_for_default_pair<'a>(
    product_config: &ProductConfig,
    batches: impl Iterator<Item = &'a BatchRecord>,
) -> Option<&'a BatchRecord> {
    let default_pair = product_config.enabled_pairs().into_iter().next()?;
    current_open_batch_for_pair(batches, &default_pair)
}

fn current_open_batch_for_pair<'a>(
    batches: impl Iterator<Item = &'a BatchRecord>,
    pair_id: &PairId,
) -> Option<&'a BatchRecord> {
    batches
        .filter(|record| {
            record.batch.pair_id == *pair_id && record.batch.status == BatchStatus::Open
        })
        .min_by_key(|record| {
            (
                record.batch.epoch_id,
                record.batch.close_time_unix_ms,
                record.order_count,
            )
        })
}

fn submittable_open_batch_for_pair<'a>(
    batches: impl Iterator<Item = &'a BatchRecord>,
    pair_id: &PairId,
    batch_window_ms: u64,
) -> Option<&'a BatchRecord> {
    let now = now_unix_ms();
    let safety_buffer_ms = batch_submission_safety_buffer_ms(batch_window_ms);
    let mut open_batches = batches
        .filter(|record| {
            record.batch.pair_id == *pair_id && record.batch.status == BatchStatus::Open
        })
        .collect::<Vec<_>>();
    open_batches.sort_by_key(|record| {
        (
            record.batch.epoch_id,
            record.batch.close_time_unix_ms,
            record.order_count,
        )
    });
    open_batches
        .iter()
        .copied()
        .find(|record| record.batch.close_time_unix_ms.saturating_sub(now) > safety_buffer_ms)
}

fn advance_batch_lifecycle(
    batches: &mut BTreeMap<String, BatchRecord>,
    product_config: &ProductConfig,
    enabled_pairs: &[PairId],
    batch_window_ms: u64,
    batch_epoch_offset: u64,
    batch_close_jitter_ms: u64,
    heartbeat_cover_secret: &str,
) -> Result<bool, StatusCode> {
    let mut changed = close_expired_open_batches(batches);
    if ensure_open_batches(
        batches,
        product_config,
        enabled_pairs,
        batch_window_ms,
        batch_epoch_offset,
        batch_close_jitter_ms,
        heartbeat_cover_secret,
    )? {
        changed = true;
    }
    if prune_batch_store_for_retention(batches) {
        changed = true;
    }
    Ok(changed)
}

fn advance_batch_lifecycle_durably(
    state: &AppState,
    batches: &mut BTreeMap<String, BatchRecord>,
) -> Result<bool, StatusCode> {
    let mut candidate = batches.clone();
    let enabled_pairs = state.product_config.enabled_pairs();
    let changed = advance_batch_lifecycle(
        &mut candidate,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    )?;
    if changed {
        persist_batch_store_if_configured(state, &candidate)?;
        *batches = candidate;
    }
    Ok(changed)
}

fn mark_batch_settled_durably(
    state: &AppState,
    batches: &mut BTreeMap<String, BatchRecord>,
    batch_id: &str,
) -> Result<(), StatusCode> {
    let Some(record) = batches.get(batch_id) else {
        return Ok(());
    };
    if record.batch.status == BatchStatus::Settled {
        return Ok(());
    }
    let mut candidate = batches.clone();
    let record = candidate
        .get_mut(batch_id)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    record.batch.status = BatchStatus::Settled;
    prune_batch_store_for_retention(&mut candidate);
    persist_batch_store_if_configured(state, &candidate)?;
    *batches = candidate;
    Ok(())
}

fn prune_batch_store_for_retention(batches: &mut BTreeMap<String, BatchRecord>) -> bool {
    prune_batch_store_for_retention_with_limit(batches, BATCH_STORE_RETAIN_RECENT_PER_PAIR)
}

fn prune_batch_store_for_retention_with_limit(
    batches: &mut BTreeMap<String, BatchRecord>,
    retain_recent_per_pair: usize,
) -> bool {
    let initial_len = batches.len();
    if initial_len <= retain_recent_per_pair {
        return false;
    }

    let mut retained_ids = std::collections::BTreeSet::new();
    let mut recent_by_pair: BTreeMap<String, Vec<(u64, u64, String)>> = BTreeMap::new();

    for (batch_id, record) in batches.iter() {
        match record.batch.status {
            BatchStatus::Open | BatchStatus::Clearing => {
                retained_ids.insert(batch_id.clone());
            }
            BatchStatus::Closed if record.order_count > 0 || !record.orders.is_empty() => {
                retained_ids.insert(batch_id.clone());
            }
            BatchStatus::Closed | BatchStatus::Settled | BatchStatus::Cancelled => {}
        }

        recent_by_pair
            .entry(record.batch.pair_id.0.clone())
            .or_default()
            .push((
                record.batch.epoch_id,
                record.batch.close_time_unix_ms,
                batch_id.clone(),
            ));
    }

    for records in recent_by_pair.values_mut() {
        records.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| right.2.cmp(&left.2))
        });
        for (_, _, batch_id) in records.iter().take(retain_recent_per_pair) {
            retained_ids.insert(batch_id.clone());
        }
    }

    batches.retain(|batch_id, _| retained_ids.contains(batch_id));
    batches.len() != initial_len
}

fn close_expired_open_batches(batches: &mut BTreeMap<String, BatchRecord>) -> bool {
    let now = now_unix_ms();
    let mut changed = false;
    for record in batches.values_mut() {
        if record.batch.status == BatchStatus::Open && record.batch.close_time_unix_ms <= now {
            record.batch.status = BatchStatus::Closed;
            changed = true;
        }
    }
    changed
}

fn ensure_open_batches(
    batches: &mut BTreeMap<String, BatchRecord>,
    product_config: &ProductConfig,
    enabled_pairs: &[PairId],
    batch_window_ms: u64,
    batch_epoch_offset: u64,
    batch_close_jitter_ms: u64,
    heartbeat_cover_secret: &str,
) -> Result<bool, StatusCode> {
    let mut changed = false;
    for pair_id in enabled_pairs {
        while open_batch_count_for_pair(batches.values(), pair_id) < OPEN_ACCEPTING_BATCHES_PER_PAIR
        {
            let epoch_id = next_epoch_for_pair(batches, pair_id, batch_epoch_offset);
            let opened_at_unix_ms = next_open_batch_anchor_ms(batches.values(), pair_id);
            let batch = empty_batch(
                product_config,
                pair_id,
                epoch_id,
                opened_at_unix_ms,
                batch_window_ms,
                batch_close_jitter_ms,
                heartbeat_cover_secret,
            )?;
            batches.insert(
                batch_key(pair_id, epoch_id),
                BatchRecord {
                    batch,
                    order_count: 0,
                    orders: vec![],
                    liquidity_lifecycle_count: 0,
                    liquidity_lifecycle_submissions: vec![],
                },
            );
            changed = true;
        }
    }
    Ok(changed)
}

fn open_batch_count_for_pair<'a>(
    batches: impl Iterator<Item = &'a BatchRecord>,
    pair_id: &PairId,
) -> usize {
    batches
        .filter(|record| {
            record.batch.pair_id == *pair_id && record.batch.status == BatchStatus::Open
        })
        .count()
}

fn next_open_batch_anchor_ms<'a>(
    batches: impl Iterator<Item = &'a BatchRecord>,
    pair_id: &PairId,
) -> u64 {
    let now = now_unix_ms();
    batches
        .filter(|record| {
            record.batch.pair_id == *pair_id && record.batch.status == BatchStatus::Open
        })
        .map(|record| record.batch.close_time_unix_ms)
        .max()
        .unwrap_or(now)
        .max(now)
}

fn next_epoch_for_pair(
    batches: &BTreeMap<String, BatchRecord>,
    pair_id: &PairId,
    batch_epoch_offset: u64,
) -> u64 {
    batches
        .values()
        .filter(|record| record.batch.pair_id == *pair_id)
        .map(|record| record.batch.epoch_id)
        .max()
        .map(|epoch| {
            epoch
                .saturating_add(1)
                .max(batch_epoch_offset.saturating_add(1))
        })
        .unwrap_or_else(|| batch_epoch_offset.saturating_add(1))
}

fn batch_submission_safety_buffer_ms(batch_window_ms: u64) -> u64 {
    if batch_window_ms == 0 {
        return MAX_BATCH_SUBMISSION_SAFETY_BUFFER_MS;
    }
    MIN_BATCH_SUBMISSION_SAFETY_BUFFER_MS.max(
        MAX_BATCH_SUBMISSION_SAFETY_BUFFER_MS
            .min(batch_window_ms.saturating_mul(BATCH_SUBMISSION_SAFETY_BUFFER_BPS) / 10_000),
    )
}

fn batch_key(pair_id: &PairId, epoch_id: u64) -> String {
    format!(
        "batch-{}-{}",
        pair_id.0.to_lowercase().replace('/', "-"),
        epoch_id
    )
}

fn empty_batch(
    product_config: &ProductConfig,
    pair_id: &PairId,
    epoch_id: u64,
    opened_at_unix_ms: u64,
    batch_window_ms: u64,
    batch_close_jitter_ms: u64,
    heartbeat_cover_secret: &str,
) -> Result<Batch, StatusCode> {
    let batch_id = BatchId(batch_key(pair_id, epoch_id));
    let (order_commitment_root, encrypted_order_set_commitment) = compute_batch_commitments_for(
        product_config,
        heartbeat_cover_secret,
        pair_id,
        &batch_id,
        epoch_id,
        &[],
    )?;
    let close_jitter_ms =
        deterministic_batch_close_jitter_ms(pair_id, epoch_id, batch_close_jitter_ms);
    Ok(Batch {
        batch_id,
        pair_id: pair_id.clone(),
        epoch_id,
        close_time_unix_ms: opened_at_unix_ms + batch_window_ms + close_jitter_ms,
        status: BatchStatus::Open,
        order_commitment_root,
        encrypted_order_set_commitment,
    })
}

fn deterministic_batch_close_jitter_ms(pair_id: &PairId, epoch_id: u64, max_jitter_ms: u64) -> u64 {
    if max_jitter_ms == 0 {
        return 0;
    }
    let mut accumulator = epoch_id ^ 0x9e37_79b9_7f4a_7c15;
    for byte in pair_id.0.as_bytes() {
        accumulator ^= u64::from(*byte);
        accumulator = accumulator
            .rotate_left(7)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    accumulator % max_jitter_ms.saturating_add(1)
}

fn refresh_batch_commitments(
    record: &mut BatchRecord,
    product_config: &ProductConfig,
    heartbeat_cover_secret: &str,
) -> Result<(), StatusCode> {
    let (order_commitment_root, encrypted_order_set_commitment) = compute_batch_commitments_for(
        product_config,
        heartbeat_cover_secret,
        &record.batch.pair_id,
        &record.batch.batch_id,
        record.batch.epoch_id,
        &record.orders,
    )?;
    record.batch.order_commitment_root = order_commitment_root;
    record.batch.encrypted_order_set_commitment = encrypted_order_set_commitment;
    Ok(())
}

fn compute_batch_commitments_for(
    product_config: &ProductConfig,
    heartbeat_cover_secret: &str,
    pair_id: &PairId,
    batch_id: &BatchId,
    epoch_id: u64,
    orders: &[SubmittedOrderRecord],
) -> Result<(String, String), StatusCode> {
    let pair = product_config
        .enabled_pair(pair_id)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let batch = BatchSummary {
        batch_id: batch_id.clone(),
        pair_id: pair_id.clone(),
        epoch_id,
        close_time_unix_ms: 0,
        status: BatchStatus::Closed,
        order_count: heartbeat_cover_order_count(orders.len()) as u64,
        order_commitment_root: "0x0".into(),
        encrypted_order_set_commitment: "0x0".into(),
    };
    let cover_commitments = heartbeat_cover_order_commitments(
        heartbeat_cover_secret,
        &batch,
        &pair.base_asset_id,
        &pair.quote_asset_id,
        pair.heartbeat_cover_price,
        orders.len(),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let order_commitments = orders
        .iter()
        .map(|record| record.order_bundle.order_commitment.0.clone())
        .chain(
            cover_commitments
                .iter()
                .map(|commitment| commitment.0.clone()),
        )
        .collect::<Vec<_>>();
    let mut encrypted_order_set = orders
        .iter()
        .map(|record| record.order_bundle.clone())
        .collect::<Vec<_>>();
    for commitment in cover_commitments.iter() {
        let cancellation_auth_tag = tagged_field_hex(
            "zylith/heartbeat-cover/cancel-tag-v1",
            &serde_json::json!({
                "batch_id": batch_id.0,
                "pair_id": pair_id.0,
                "epoch_id": epoch_id,
                "order_commitment": commitment.0,
            }),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        encrypted_order_set.push(OrderShareBundle {
            order_commitment: commitment.clone(),
            cancellation_auth_tag,
            pair_id: pair_id.clone(),
            batch_id: batch_id.clone(),
            epoch_id,
            transport_envelope: None,
            ingress_receipt: None,
            shares: Vec::new(),
        });
    }

    let order_root = ordered_felt_list_commitment("zylith/batch-order-root", &order_commitments)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let encrypted_set_commitment =
        tagged_field_hex("zylith/batch-encrypted-order-set", &encrypted_order_set)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((order_root, encrypted_set_commitment))
}

fn load_batch_store(path: &FsPath) -> BTreeMap<String, BatchRecord> {
    if is_sqlite_store(path) {
        return load_sqlite_records(path, "batches").unwrap_or_else(|error| {
            panic!("failed to load batch store {}: {error}", path.display())
        });
    }
    let contents = read_json_store(path, "batch").unwrap_or_else(|error| panic!("{error}"));
    let Some(contents) = contents else {
        return BTreeMap::default();
    };

    serde_json::from_str::<BatchStoreFile>(&contents)
        .map(|store| store.batches_by_id)
        .unwrap_or_else(|error| panic!("failed to parse batch store {}: {error}", path.display()))
}

fn persist_batch_store_if_configured(
    state: &AppState,
    batches: &BTreeMap<String, BatchRecord>,
) -> Result<(), StatusCode> {
    if let Some(path) = state.batch_store_path.as_deref() {
        persist_batch_store(path, batches)?;
    }
    Ok(())
}

fn persist_batch_store(
    path: &FsPath,
    batches: &BTreeMap<String, BatchRecord>,
) -> Result<(), StatusCode> {
    if is_sqlite_store(path) {
        return persist_sqlite_records(path, "batches", batches);
    }
    let encoded = serde_json::to_string_pretty(&BatchStoreFile {
        batches_by_id: batches.clone(),
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    atomic_write(path, &encoded)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
fn load_recovery_store(path: &FsPath) -> BTreeMap<String, RecoveryAccountRecord> {
    load_recovery_store_file(path).accounts_by_id
}

fn load_recovery_store_file(path: &FsPath) -> RecoveryStoreFile {
    if is_sqlite_store(path) {
        return RecoveryStoreFile {
            accounts_by_id: load_sqlite_records(path, "recovery_accounts").unwrap_or_else(
                |error| panic!("failed to load recovery store {}: {error}", path.display()),
            ),
            wallet_vaults_by_auth_id: load_sqlite_records(path, "wallet_vault_bundles")
                .unwrap_or_default(),
        };
    }
    let contents = read_json_store(path, "recovery").unwrap_or_else(|error| panic!("{error}"));
    let Some(contents) = contents else {
        return RecoveryStoreFile::default();
    };

    serde_json::from_str::<RecoveryStoreFile>(&contents).unwrap_or_else(|error| {
        panic!("failed to parse recovery store {}: {error}", path.display())
    })
}

fn load_published_batch_artifacts_store_file(path: &FsPath) -> PublishedBatchArtifactsStoreFile {
    if is_sqlite_store(path) {
        return PublishedBatchArtifactsStoreFile {
            artifacts_by_batch: load_sqlite_records(path, "published_batch_artifacts")
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to load published batch artifacts store {}: {error}",
                        path.display()
                    )
                }),
            renewal_cancel_markers: load_sqlite_records(path, "renewal_cancel_markers")
                .unwrap_or_default(),
        };
    }
    let contents = read_json_store(path, "published batch artifacts")
        .unwrap_or_else(|error| panic!("{error}"));
    let Some(contents) = contents else {
        return PublishedBatchArtifactsStoreFile::default();
    };

    serde_json::from_str::<PublishedBatchArtifactsStoreFile>(&contents).unwrap_or_else(|error| {
        panic!(
            "failed to parse published batch artifacts store {}: {error}",
            path.display()
        )
    })
}

#[cfg(test)]
fn persist_recovery_store(
    path: &FsPath,
    accounts: &BTreeMap<String, RecoveryAccountRecord>,
) -> Result<(), StatusCode> {
    persist_recovery_store_file(path, accounts, &BTreeMap::new())
}

fn persist_recovery_store_file(
    path: &FsPath,
    accounts: &BTreeMap<String, RecoveryAccountRecord>,
    wallet_vaults: &BTreeMap<String, WalletVaultBundleRecord>,
) -> Result<(), StatusCode> {
    if is_sqlite_store(path) {
        let mut connection =
            open_sqlite_store(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let transaction = connection
            .transaction()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        persist_sqlite_records_in_transaction(&transaction, "recovery_accounts", accounts)?;
        persist_sqlite_records_in_transaction(&transaction, "wallet_vault_bundles", wallet_vaults)?;
        return transaction
            .commit()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }
    let encoded = serde_json::to_string_pretty(&RecoveryStoreFile {
        accounts_by_id: accounts.clone(),
        wallet_vaults_by_auth_id: wallet_vaults.clone(),
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    atomic_write(path, &encoded)
}

fn read_json_store(path: &FsPath, label: &str) -> Result<Option<String>, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to inspect {label} store {}: {error}",
                path.display()
            ));
        }
    };
    if metadata.len() > MAX_JSON_STORE_BYTES {
        return Err(format!(
            "{label} store {} exceeds {} bytes",
            path.display(),
            MAX_JSON_STORE_BYTES
        ));
    }
    fs::read_to_string(path)
        .map(Some)
        .map_err(|error| format!("failed to read {label} store {}: {error}", path.display()))
}

fn persist_published_batch_artifacts_store(
    path: &FsPath,
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
    renewal_cancel_markers: &BTreeMap<String, RenewalCancelMarkerRecord>,
) -> Result<(), StatusCode> {
    if is_sqlite_store(path) {
        let mut connection =
            open_sqlite_store(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let transaction = connection
            .transaction()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        persist_sqlite_records_in_transaction(
            &transaction,
            "published_batch_artifacts",
            artifacts,
        )?;
        persist_sqlite_records_in_transaction(
            &transaction,
            "renewal_cancel_markers",
            renewal_cancel_markers,
        )?;
        return transaction
            .commit()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }
    let encoded = serde_json::to_string_pretty(&PublishedBatchArtifactsStoreFile {
        artifacts_by_batch: artifacts.clone(),
        renewal_cancel_markers: renewal_cancel_markers.clone(),
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    atomic_write(path, &encoded)
}

fn persist_published_artifact_snapshots_if_configured(
    state: &AppState,
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
    markers: &BTreeMap<String, RenewalCancelMarkerRecord>,
) -> Result<(), StatusCode> {
    let Some(path) = state.published_batch_artifacts_store_path.as_deref() else {
        return Ok(());
    };
    persist_published_batch_artifacts_store(path, artifacts, markers)
}

fn is_sqlite_store(path: &FsPath) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "db" | "sqlite" | "sqlite3"
            )
        })
}

fn open_sqlite_store(path: &FsPath) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    }
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS coordinator_records (
            namespace TEXT NOT NULL,
            record_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            PRIMARY KEY(namespace, record_key)
        );
        CREATE INDEX IF NOT EXISTS idx_coordinator_records_namespace
            ON coordinator_records(namespace);",
    )?;
    Ok(connection)
}

fn load_sqlite_records<T: DeserializeOwned>(
    path: &FsPath,
    namespace: &str,
) -> Result<BTreeMap<String, T>, StatusCode> {
    let connection = open_sqlite_store(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut statement = connection
        .prepare(
            "SELECT record_key, value_json
             FROM coordinator_records
             WHERE namespace = ?1
             ORDER BY record_key",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = statement
        .query_map([namespace], |row| {
            let key: String = row.get(0)?;
            let value_json: String = row.get(1)?;
            Ok((key, value_json))
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut records = BTreeMap::new();
    for row in rows {
        let (key, value_json) = row.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let value =
            serde_json::from_str(&value_json).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        records.insert(key, value);
    }
    Ok(records)
}

fn persist_sqlite_records<T: Serialize>(
    path: &FsPath,
    namespace: &str,
    records: &BTreeMap<String, T>,
) -> Result<(), StatusCode> {
    let mut connection = open_sqlite_store(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let transaction = connection
        .transaction()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    persist_sqlite_records_in_transaction(&transaction, namespace, records)?;
    transaction
        .commit()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn persist_sqlite_records_in_transaction<T: Serialize>(
    transaction: &rusqlite::Transaction<'_>,
    namespace: &str,
    records: &BTreeMap<String, T>,
) -> Result<(), StatusCode> {
    let mut existing_keys = {
        let mut statement = transaction
            .prepare("SELECT record_key FROM coordinator_records WHERE namespace = ?1")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let rows = statement
            .query_map([namespace], |row| row.get::<_, String>(0))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let mut keys = BTreeSet::new();
        for row in rows {
            keys.insert(row.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
        }
        keys
    };
    let updated_at_unix_ms = now_unix_ms() as i64;
    for (key, value) in records {
        let value_json =
            serde_json::to_string(value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        transaction
            .execute(
                "INSERT INTO coordinator_records
                    (namespace, record_key, value_json, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, record_key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at_unix_ms = excluded.updated_at_unix_ms",
                rusqlite::params![namespace, key, value_json, updated_at_unix_ms],
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        existing_keys.remove(key);
    }
    for key in existing_keys {
        transaction
            .execute(
                "DELETE FROM coordinator_records WHERE namespace = ?1 AND record_key = ?2",
                rusqlite::params![namespace, key],
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(())
}

fn atomic_write(path: &FsPath, contents: &str) -> Result<(), StatusCode> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
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
        .write_all(contents.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::{
        BatchRecord, BatchTimingConfig, DEFAULT_BATCH_WINDOW_MS, MAX_JSON_STORE_BYTES,
        MAX_PUBLIC_TRANSCRIPT_BATCH_IDS, MAX_STARKNET_RPC_RESPONSE_BYTES, OrderIngressConfig,
        RenewalCancelWitnessResponse, SubmittedOrderRecord, WALLET_VAULT_AUTH_HEADER,
        WALLET_VAULT_ID_DOMAIN, WalletVaultBundleRecord, build_app_with_config,
        build_app_with_paths, close_expired_open_batches, decode_bounded_json,
        deterministic_batch_close_jitter_ms, effective_public_artifact_delay_epochs, empty_batch,
        load_batch_store, load_published_batch_artifacts_store_file, load_recovery_store,
        load_recovery_store_file, now_unix_ms, persist_batch_store, persist_recovery_store,
        product_config_from_pair_sources, service_http_client, submittable_open_batch_for_pair,
    };
    use axum::http::StatusCode;
    use axum::{
        body::Body,
        http::{HeaderMap, Method, Request},
    };
    use http_body_util::BodyExt;
    use std::{collections::BTreeMap, fs, net::SocketAddr, path::PathBuf};
    use tower::ServiceExt;
    use zylith_core::hash::tagged_sha256_hex;
    use zylith_core::types::{
        NOTE_RECOGNITION_ALGORITHM, OUTPUT_NOTE_CIPHERTEXT_LEN, OUTPUT_RECOVERY_FIELD_COUNT,
        output_recovery_record_commitment,
    };
    use zylith_core::{
        BatchId, BatchStatus, EncryptedRecoveryPayload, LiquidityPositionLifecycleSubmission,
        OrderCancellationRequest, OrderIngressClientTelemetry, OrderShareBundle, OrderSubmission,
        PairId, ProductConfig, PublishedBatchArtifacts, RecoveryArtifact, RecoveryArtifactKind,
        RecoveryArtifactUpload, SubmittedLiquidityPositionLifecycleRecord,
        create_order_ingress_receipt, derive_order_cancellation_tag,
    };

    #[tokio::test]
    async fn starknet_rpc_decode_rejects_oversized_response_bodies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock RPC");
        let address = listener.local_addr().expect("mock RPC address");
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                vec![b'x'; MAX_STARKNET_RPC_RESPONSE_BYTES.saturating_add(1)]
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock RPC");
        });
        let response = service_http_client()
            .get(format!("http://{address}/"))
            .send()
            .await
            .expect("mock RPC response");

        assert_eq!(
            decode_bounded_json::<serde_json::Value>(response).await,
            Err(StatusCode::BAD_GATEWAY)
        );
        server.abort();
    }

    #[test]
    fn coordinator_product_config_requires_explicit_pair_source() {
        let error = product_config_from_pair_sources(None, None).expect_err("missing pair source");
        assert!(error.contains("ZYLITH_PRODUCT_PAIRS"));
    }

    #[test]
    fn coordinator_product_config_accepts_explicit_pair_source() {
        let config = product_config_from_pair_sources(Some("STRK/USDC,ETH/USDC"), None)
            .expect("explicit pair source");
        assert!(config.enabled_pair(&PairId("STRK/USDC".into())).is_some());
        assert!(config.enabled_pair(&PairId("ETH/USDC".into())).is_some());
        assert!(config.enabled_pair(&PairId("USDC/USDT".into())).is_none());
    }

    #[test]
    fn coordinator_cors_origins_reject_wildcards() {
        let env_name = "ZYLITH_TEST_COORDINATOR_ALLOWED_ORIGINS";
        unsafe {
            std::env::set_var(env_name, "https://*.zylith.fi");
        }
        let result = std::panic::catch_unwind(|| super::allowed_origins_from_env(env_name));
        unsafe {
            std::env::remove_var(env_name);
        }
        assert!(result.is_err());
    }

    #[test]
    fn coordinator_positive_env_helpers_reject_zero_values() {
        let u64_env_name = "ZYLITH_TEST_COORDINATOR_POSITIVE_U64";
        let usize_env_name = "ZYLITH_TEST_COORDINATOR_POSITIVE_USIZE";
        unsafe {
            std::env::set_var(u64_env_name, "0");
            std::env::set_var(usize_env_name, "0");
        }

        assert_eq!(
            super::env_positive_u64_or_default(u64_env_name, 1).unwrap_err(),
            format!("{u64_env_name} must be positive")
        );
        assert_eq!(
            super::env_positive_usize_or_default(usize_env_name, 1).unwrap_err(),
            format!("{usize_env_name} must be positive")
        );

        unsafe {
            std::env::remove_var(u64_env_name);
            std::env::remove_var(usize_env_name);
        }
    }

    const TEST_INTERNAL_TOKEN: &str = "test-control-plane-token";
    const TEST_RECEIPT_SECRET: &str = "test-receipt-secret";
    const TEST_RECOVERY_AUTH: &str = "test-recovery-auth";

    fn test_order_ingress_telemetry() -> OrderIngressClientTelemetry {
        OrderIngressClientTelemetry {
            version: 1,
            client_build_ms: Some(25),
            private_submission_delay_ms: Some(0),
            client_elapsed_before_private_ingress_ms: Some(25),
            private_ingress_roundtrip_ms: Some(10),
            client_elapsed_before_coordinator_ms: Some(35),
            batch_time_remaining_before_private_ingress_ms: Some(25_000),
            batch_time_remaining_before_coordinator_ms: Some(24_990),
            submission_safety_buffer_ms: Some(15_000),
        }
    }

    fn test_order_submission_body(submission: &OrderSubmission) -> Vec<u8> {
        let mut value = serde_json::to_value(submission).expect("serialize submission");
        value["ingress_telemetry"] =
            serde_json::to_value(test_order_ingress_telemetry()).expect("serialize telemetry");
        serde_json::to_vec(&value).expect("serialize telemetry envelope")
    }

    fn trusted_order_submission(mut submission: OrderSubmission) -> OrderSubmission {
        if submission.order_bundle.transport_envelope.is_none() {
            submission.order_bundle.transport_envelope = Some(zylith_core::EncryptedBlob {
                algorithm: "test-encrypted-payload".into(),
                key_id: "test-key".into(),
                ephemeral_public_key: "04abcdef".into(),
                nonce: "00".into(),
                ciphertext: "11".into(),
                recovery: None,
            });
        }
        let receipt = create_order_ingress_receipt(
            &submission.order_bundle,
            "test-ingress",
            "zylith-prover",
            TEST_RECEIPT_SECRET,
            123,
            Default::default(),
        )
        .expect("trusted test ingress receipt");
        submission.order_bundle.ingress_receipt = Some(receipt);
        submission
    }

    fn trusted_order_submission_body(submission: OrderSubmission) -> Vec<u8> {
        test_order_submission_body(&trusted_order_submission(submission))
    }

    fn auth_request(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
    }

    async fn submittable_test_batch(app: &axum::Router, pair_path: &str) -> (String, u64) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/pairs/{pair_path}/batches/submittable"))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        (
            json["batch_id"].as_str().expect("batch id").to_owned(),
            json["epoch_id"].as_u64().expect("epoch id"),
        )
    }

    fn bind_submission_to_batch(submission: &mut OrderSubmission, batch: &(String, u64)) {
        submission.order_bundle.batch_id = zylith_core::BatchId(batch.0.clone());
        submission.order_bundle.epoch_id = batch.1;
    }

    #[test]
    fn debug_redacts_coordinator_secret_config() {
        let ingress = OrderIngressConfig {
            receipt_secrets: vec![
                "first-receipt-secret".into(),
                "second-receipt-secret".into(),
            ],
        };
        let hardening = super::CoordinatorHardeningConfig {
            heartbeat_cover_secret: "do-not-log-heartbeat-secret".into(),
            ..Default::default()
        };

        let ingress_debug = format!("{ingress:?}");
        let hardening_debug = format!("{hardening:?}");

        assert!(ingress_debug.contains("<2 redacted>"));
        assert!(!ingress_debug.contains("first-receipt-secret"));
        assert!(!ingress_debug.contains("second-receipt-secret"));
        assert!(hardening_debug.contains("heartbeat_cover_secret"));
        assert!(hardening_debug.contains("<redacted>"));
        assert!(!hardening_debug.contains("do-not-log-heartbeat-secret"));
    }

    #[test]
    fn batch_close_jitter_is_pair_epoch_bound_and_capped() {
        let pair = PairId("STRK/USDC".into());
        let same = deterministic_batch_close_jitter_ms(&pair, 7, 1_000);
        assert_eq!(same, deterministic_batch_close_jitter_ms(&pair, 7, 1_000));
        assert!(same <= 1_000);
        assert_eq!(deterministic_batch_close_jitter_ms(&pair, 7, 0), 0);
    }

    #[test]
    fn empty_batch_rejects_unconfigured_pair() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let result = empty_batch(
            &product,
            &PairId("ETH/USDC".into()),
            1,
            now_unix_ms(),
            DEFAULT_BATCH_WINDOW_MS,
            0,
            "test-heartbeat-cover-secret",
        );
        assert!(matches!(result, Err(StatusCode::INTERNAL_SERVER_ERROR)));
    }

    #[test]
    fn coordinator_startup_persists_initial_open_batches() {
        let path = std::env::temp_dir().join(format!(
            "zylith-coordinator-initial-batches-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&path);

        let _app = build_app_with_paths(Some(path.clone()), None, None, None);
        let batches = load_batch_store(&path);
        assert!(!batches.is_empty());
        assert!(batches.values().all(|record| {
            !record.batch.order_commitment_root.is_empty()
                && !record.batch.encrypted_order_set_commitment.is_empty()
        }));

        fs::remove_file(path).expect("remove initial batch store");
    }

    #[test]
    fn batch_store_retention_prunes_old_empty_history_but_keeps_active_and_proof_work() {
        const TEST_RETAIN_RECENT_PER_PAIR: usize = 8;
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let pair = PairId("STRK/USDC".into());
        let now = now_unix_ms();
        let mut batches = BTreeMap::new();
        let total_epochs = TEST_RETAIN_RECENT_PER_PAIR as u64 + 8;

        for epoch in 1..=total_epochs {
            let mut batch = empty_batch(
                &product,
                &pair,
                epoch,
                now.saturating_sub(total_epochs.saturating_sub(epoch) * DEFAULT_BATCH_WINDOW_MS),
                DEFAULT_BATCH_WINDOW_MS,
                0,
                "test-heartbeat-cover-secret",
            )
            .expect("construct batch");
            batch.close_time_unix_ms = epoch * 1_000;
            batch.status = BatchStatus::Settled;
            batches.insert(
                batch.batch_id.0.clone(),
                BatchRecord {
                    batch,
                    order_count: 0,
                    orders: Vec::new(),
                    liquidity_lifecycle_count: 0,
                    liquidity_lifecycle_submissions: Vec::new(),
                },
            );
        }

        batches
            .get_mut("batch-strk-usdc-1")
            .expect("old open batch")
            .batch
            .status = BatchStatus::Open;
        let old_closed = batches
            .get_mut("batch-strk-usdc-2")
            .expect("old nonempty closed batch");
        old_closed.batch.status = BatchStatus::Closed;
        old_closed.order_count = 1;
        old_closed.orders.push(SubmittedOrderRecord {
            received_at_unix_ms: now,
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0xabc".into()),
                cancellation_auth_tag: "cancel-retained".into(),
                pair_id: pair.clone(),
                batch_id: zylith_core::BatchId("batch-strk-usdc-2".into()),
                epoch_id: 2,
                transport_envelope: None,
                ingress_receipt: None,
                shares: Vec::new(),
            },
        });
        batches
            .get_mut("batch-strk-usdc-3")
            .expect("old clearing batch")
            .batch
            .status = BatchStatus::Clearing;
        assert!(super::prune_batch_store_for_retention_with_limit(
            &mut batches,
            TEST_RETAIN_RECENT_PER_PAIR
        ));

        assert!(batches.contains_key("batch-strk-usdc-1"));
        assert!(batches.contains_key("batch-strk-usdc-2"));
        assert!(batches.contains_key("batch-strk-usdc-3"));
        assert!(!batches.contains_key("batch-strk-usdc-4"));
        assert!(batches.contains_key(&format!("batch-strk-usdc-{total_epochs}")));
        assert_eq!(batches.len(), TEST_RETAIN_RECENT_PER_PAIR + 3);
    }

    #[test]
    fn sqlite_stores_round_trip_namespaced_records() {
        let path = std::env::temp_dir().join(format!(
            "zylith-coordinator-store-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let product_config =
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product config");
        let pair = PairId("STRK/USDC".into());
        let mut batches = BTreeMap::new();
        batches.insert(
            "strk-usdc-7".into(),
            BatchRecord {
                batch: empty_batch(
                    &product_config,
                    &pair,
                    7,
                    now_unix_ms(),
                    DEFAULT_BATCH_WINDOW_MS,
                    0,
                    "test-heartbeat-cover-secret",
                )
                .expect("construct test batch"),
                order_count: 2,
                orders: Vec::new(),
                liquidity_lifecycle_count: 0,
                liquidity_lifecycle_submissions: Vec::new(),
            },
        );
        persist_batch_store(&path, &batches).expect("persist batch sqlite store");
        assert_eq!(
            load_batch_store(&path)
                .get("strk-usdc-7")
                .expect("batch record")
                .order_count,
            2
        );

        let mut recovery = BTreeMap::new();
        recovery.insert(
            "account-1".into(),
            super::RecoveryAccountRecord {
                recovery_auth_tag: Some("auth-tag".into()),
                artifacts: Vec::new(),
            },
        );
        persist_recovery_store(&path, &recovery).expect("persist recovery sqlite store");
        assert_eq!(
            load_recovery_store(&path)
                .get("account-1")
                .expect("recovery record")
                .recovery_auth_tag
                .as_deref(),
            Some("auth-tag")
        );
        assert_eq!(load_batch_store(&path).len(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn recovery_store_ignores_legacy_artifacts_by_account_field() {
        let path = std::env::temp_dir().join(format!(
            "zylith-coordinator-legacy-recovery-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        fs::write(&path, r#"{"artifacts_by_account":{}}"#).expect("write legacy recovery store");

        let store = load_recovery_store_file(&path);
        assert!(store.accounts_by_id.is_empty());
        assert!(store.wallet_vaults_by_auth_id.is_empty());
        fs::remove_file(path).expect("remove legacy recovery store");
    }

    #[test]
    fn recovery_store_defaults_missing_wallet_vault_section() {
        let path = std::env::temp_dir().join(format!(
            "zylith-coordinator-partial-recovery-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        fs::write(&path, r#"{"accounts_by_id":{}}"#).expect("write partial recovery store");

        let store = load_recovery_store_file(&path);
        assert!(store.accounts_by_id.is_empty());
        assert!(store.wallet_vaults_by_auth_id.is_empty());
        fs::remove_file(path).expect("remove partial recovery store");
    }

    #[test]
    fn wallet_vault_record_requires_timestamp() {
        let result = serde_json::from_str::<WalletVaultBundleRecord>(
            r#"{"wallet_auth_id":"0x1","vault":{"version":3}}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn published_artifacts_store_requires_current_cancel_marker_section() {
        let path = std::env::temp_dir().join(format!(
            "zylith-coordinator-partial-artifacts-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        fs::write(&path, r#"{"artifacts_by_batch":{}}"#).expect("write partial artifact store");

        let result = std::panic::catch_unwind(|| load_published_batch_artifacts_store_file(&path));
        assert!(result.is_err());
        fs::remove_file(path).expect("remove partial artifact store");
    }

    #[test]
    fn json_store_rejects_oversized_files_before_deserialization() {
        let path = std::env::temp_dir().join(format!(
            "zylith-coordinator-oversized-store-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let file = fs::File::create(&path).expect("create oversized store");
        file.set_len(MAX_JSON_STORE_BYTES + 1)
            .expect("size oversized store");

        let result = std::panic::catch_unwind(|| load_batch_store(&path));
        assert!(result.is_err());
        fs::remove_file(path).expect("remove oversized store");
    }

    #[test]
    fn empty_expired_batches_close_as_pair_heartbeat_not_cancelled() {
        let pair = PairId("STRK/USDC".into());
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let mut batch = empty_batch(
            &product,
            &pair,
            1,
            1,
            DEFAULT_BATCH_WINDOW_MS,
            0,
            "test-heartbeat-cover-secret",
        )
        .expect("construct test batch");
        batch.close_time_unix_ms = 1;
        let mut batches = BTreeMap::from([(
            batch.batch_id.0.clone(),
            BatchRecord {
                batch,
                order_count: 0,
                orders: Vec::new(),
                liquidity_lifecycle_count: 0,
                liquidity_lifecycle_submissions: Vec::new(),
            },
        )]);

        assert!(close_expired_open_batches(&mut batches));
        let record = batches.values().next().expect("closed batch");
        assert_eq!(record.batch.status, zylith_core::BatchStatus::Closed);
    }

    #[test]
    fn rate_limit_subject_uses_forwarded_headers_only_from_trusted_proxy_cidrs() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
        let trusted_peer: SocketAddr = "10.1.2.3:443".parse().expect("trusted peer");
        let untrusted_peer: SocketAddr = "198.51.100.7:443".parse().expect("untrusted peer");
        let cidrs = vec!["10.0.0.0/8".to_string()];

        assert_eq!(
            super::rate_limit_subject_with_trusted_proxy_cidrs(
                &headers,
                Some(trusted_peer),
                true,
                &cidrs,
            ),
            "203.0.113.9"
        );
        assert_eq!(
            super::rate_limit_subject_with_trusted_proxy_cidrs(
                &headers,
                Some(untrusted_peer),
                true,
                &cidrs,
            ),
            "198.51.100.7"
        );
        assert_eq!(
            super::rate_limit_subject_with_trusted_proxy_cidrs(
                &headers,
                Some(trusted_peer),
                false,
                &cidrs,
            ),
            "10.1.2.3"
        );

        headers.insert("x-forwarded-for", "not-an-ip".parse().expect("header"));
        headers.insert("x-real-ip", "203.0.113.10".parse().expect("header"));
        assert_eq!(
            super::rate_limit_subject_with_trusted_proxy_cidrs(
                &headers,
                Some(trusted_peer),
                true,
                &cidrs,
            ),
            "203.0.113.10"
        );

        headers.insert("x-real-ip", "also-not-an-ip".parse().expect("header"));
        assert_eq!(
            super::rate_limit_subject_with_trusted_proxy_cidrs(
                &headers,
                Some(trusted_peer),
                true,
                &cidrs,
            ),
            "10.1.2.3"
        );
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
            super::enforce_rate_limit(&limiter, &HeaderMap::new(), None, "poisoned-test", 1),
            Ok(())
        );
        assert_eq!(
            super::enforce_rate_limit(&limiter, &HeaderMap::new(), None, "poisoned-test", 1),
            Err(StatusCode::TOO_MANY_REQUESTS)
        );
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn renewal_cancel_marker_rejects_unknown_request_fields() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));

        let response = app
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri("/api/renewal/cancel-markers")
                        .method(Method::POST)
                        .header("content-type", "application/json"),
                )
                .body(Body::from(
                    serde_json::json!({
                        "cancel_marker": "0xabc",
                        "unsupported_signature": "0x123"
                    })
                    .to_string(),
                ))
                .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn renewal_cancel_witness_response_omits_exact_entry_count() {
        let cancel_marker = "0xabc";
        let witness = zylith_core::renewal_sparse_witness_for_parent_cancel_marker(
            &["0xdef".into()],
            cancel_marker,
        )
        .expect("cancel witness");
        let response = RenewalCancelWitnessResponse {
            cancel_marker: cancel_marker.into(),
            renewal_cancel_sparse_witness: witness,
        };
        let json = serde_json::to_value(&response).expect("serialize cancel witness response");

        assert_eq!(json["cancel_marker"], cancel_marker);
        assert!(json.get("renewal_cancel_sparse_witness").is_some());
        assert!(json.get("entry_count").is_none());
        assert!(json.get("prior_renewal_entries").is_none());
    }

    #[tokio::test]
    async fn renewal_cancel_public_reads_are_rate_limited() {
        let hardening = super::CoordinatorHardeningConfig {
            public_rate_limit_per_minute: 1,
            ..Default::default()
        };
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: None,
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            None,
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product"),
            BatchTimingConfig {
                window_ms: 60 * 60 * 1_000,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            hardening,
        )
        .expect("test app should build");

        let status_first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/renewal/cancel-markers/0xabc")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(status_first.status(), StatusCode::OK);

        let status_second = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/renewal/cancel-markers/0xabc")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(status_second.status(), StatusCode::TOO_MANY_REQUESTS);

        let witness_first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/renewal/cancel-witness/0xabc")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_ne!(witness_first.status(), StatusCode::TOO_MANY_REQUESTS);

        let witness_second = app
            .oneshot(
                Request::builder()
                    .uri("/api/renewal/cancel-witness/0xabc")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(witness_second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn public_batch_reads_are_rate_limited() {
        let hardening = super::CoordinatorHardeningConfig {
            public_rate_limit_per_minute: 1,
            ..Default::default()
        };
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: None,
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            None,
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product"),
            BatchTimingConfig {
                window_ms: DEFAULT_BATCH_WINDOW_MS,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            hardening,
        )
        .expect("test app should build");

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/batches/current")
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
                    .uri("/api/batches/current")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn internal_metrics_requires_auth_and_exposes_order_submission_telemetry() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));
        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/internal/metrics")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x1234".into()),
                cancellation_auth_tag: "cancel-tag-metrics".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);
        let submission = trusted_order_submission(submission);
        let mut submission_json = serde_json::to_value(&submission).expect("serialize submission");
        submission_json["ingress_telemetry"] = serde_json::json!({
            "version": 1,
            "private_ingress_roundtrip_ms": 120,
            "client_elapsed_before_coordinator_ms": 7120,
            "batch_time_remaining_before_coordinator_ms": 24000,
            "submission_safety_buffer_ms": 15000
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&submission_json).expect("serialize submission"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri("/api/internal/metrics")
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let text = String::from_utf8(body.to_vec()).expect("utf8");

        assert!(text.contains(
            "zylith_coordinator_order_submission_requests_total{outcome=\"accepted\"} 1"
        ));
        assert!(text.contains("zylith_coordinator_order_submission_processing_ms_count 1"));
        assert!(
            text.contains(
                "zylith_coordinator_order_submission_private_ingress_roundtrip_ms_count 1"
            )
        );
        assert!(text.contains(
            "zylith_coordinator_order_submission_batch_time_remaining_before_coordinator_ms_bucket{le=\"30000\"} 1"
        ));
        assert!(!text.contains("0x1234"));
    }

    #[tokio::test]
    async fn current_batch_endpoint_returns_open_batch() {
        let app = build_app_with_paths(None, None, None, None);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/batches/current")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        let pair_id = json["pair_id"].as_str().expect("pair id");
        assert!(
            ProductConfig::default_v1()
                .enabled_pair(&PairId(pair_id.to_owned()))
                .is_some(),
            "current batch pair must be enabled by default product config"
        );
    }

    #[tokio::test]
    async fn configured_pair_endpoint_returns_pair_specific_open_batch() {
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: None,
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            None,
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC,STRK/ETH").expect("product"),
            BatchTimingConfig {
                window_ms: DEFAULT_BATCH_WINDOW_MS,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/pairs/STRK/ETH/batches/current")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["pair_id"], "STRK/ETH");
        let batch_id = json["batch_id"].as_str().expect("batch id");
        assert!(
            batch_id.starts_with("batch-strk-eth-"),
            "current batch id should be scoped to the requested pair"
        );
    }

    #[tokio::test]
    async fn lifecycle_preopens_next_accepting_batch_per_pair() {
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: None,
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            None,
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product"),
            BatchTimingConfig {
                window_ms: DEFAULT_BATCH_WINDOW_MS,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/batches")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<Vec<serde_json::Value>>(&body).expect("json");
        let mut open_epochs = json
            .iter()
            .filter(|record| record["pair_id"] == "STRK/USDC" && record["status"] == "Open")
            .map(|record| record["epoch_id"].as_u64().expect("epoch"))
            .collect::<Vec<_>>();
        open_epochs.sort_unstable();
        assert_eq!(
            open_epochs,
            (1..=super::OPEN_ACCEPTING_BATCHES_PER_PAIR as u64).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn direct_batch_lookup_advances_lifecycle_for_future_relay_slots() {
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: None,
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            None,
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product"),
            BatchTimingConfig {
                window_ms: 1_000,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/batches/batch-strk-usdc-13")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["batch_id"], "batch-strk-usdc-13");
        assert_eq!(json["status"], "Open");
    }

    #[test]
    fn public_batch_list_is_bounded_and_recent_first() {
        assert_eq!(super::public_batch_list_limit(None), 512);
        assert_eq!(super::public_batch_list_limit(Some(0)), 1);
        assert_eq!(super::public_batch_list_limit(Some(usize::MAX)), 4_096);

        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let pair = PairId("STRK/USDC".into());
        let mut records = Vec::new();
        for epoch in [1_u64, 3, 2] {
            let mut batch = empty_batch(
                &product,
                &pair,
                epoch,
                now_unix_ms(),
                DEFAULT_BATCH_WINDOW_MS,
                0,
                "test-heartbeat-cover-secret",
            )
            .expect("construct batch");
            batch.close_time_unix_ms = epoch * 1_000;
            batch.status = match epoch {
                2 => BatchStatus::Closed,
                3 => BatchStatus::Clearing,
                _ => BatchStatus::Open,
            };
            records.push(BatchRecord {
                batch,
                order_count: 0,
                orders: Vec::new(),
                liquidity_lifecycle_count: 0,
                liquidity_lifecycle_submissions: Vec::new(),
            });
        }

        let summaries = super::public_batch_summaries_limited(records.iter(), 2, None);
        assert_eq!(
            summaries
                .into_iter()
                .map(|batch| batch.epoch_id)
                .collect::<Vec<_>>(),
            vec![3, 2]
        );
        let status_filter = super::public_batch_status_filter("closed");
        let summaries =
            super::public_batch_summaries_limited(records.iter(), 10, Some(&status_filter));
        assert_eq!(
            summaries
                .into_iter()
                .map(|batch| batch.epoch_id)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn internal_proof_work_batches_are_recent_nonempty_and_exact() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let pair = PairId("STRK/USDC".into());
        let mut records = Vec::new();
        for epoch in [1_u64, 3, 2] {
            let mut batch = empty_batch(
                &product,
                &pair,
                epoch,
                now_unix_ms(),
                DEFAULT_BATCH_WINDOW_MS,
                0,
                "test-heartbeat-cover-secret",
            )
            .expect("construct batch");
            batch.close_time_unix_ms = epoch * 1_000;
            batch.status = match epoch {
                1 => BatchStatus::Open,
                _ => BatchStatus::Closed,
            };
            let order_bundle = OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment(format!("0x{epoch:x}")),
                cancellation_auth_tag: format!("cancel-{epoch}"),
                pair_id: pair.clone(),
                batch_id: batch.batch_id.clone(),
                epoch_id: batch.epoch_id,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            };
            records.push(BatchRecord {
                batch,
                order_count: if epoch == 2 { 0 } else { 1 },
                orders: if epoch == 2 {
                    Vec::new()
                } else {
                    vec![SubmittedOrderRecord {
                        received_at_unix_ms: now_unix_ms(),
                        order_bundle,
                    }]
                },
                liquidity_lifecycle_count: u64::from(epoch == 2),
                liquidity_lifecycle_submissions: if epoch == 2 {
                    vec![SubmittedLiquidityPositionLifecycleRecord {
                        received_at_unix_ms: now_unix_ms(),
                        submission: LiquidityPositionLifecycleSubmission {
                            lifecycle_id: "lp-lifecycle-epoch-2".into(),
                            pair_id: pair.clone(),
                            batch_id: BatchId("batch-strk-usdc-2".into()),
                            epoch_id: 2,
                            transition_commitment: "0x2222".into(),
                            ingress_receipt: None,
                        },
                    }]
                } else {
                    Vec::new()
                },
            });
        }

        let summaries = super::internal_proof_work_batch_summaries_limited(
            records.iter(),
            10,
            &[BatchStatus::Closed, BatchStatus::Clearing],
        );

        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].epoch_id, 3);
        assert_eq!(summaries[0].order_count, 1);
        assert_eq!(summaries[1].epoch_id, 2);
        assert_eq!(summaries[1].order_count, 5);
        assert_ne!(summaries[0].order_commitment_root, "");
    }

    #[tokio::test]
    async fn submittable_endpoint_skips_current_batch_inside_safety_buffer() {
        let temp_path = PathBuf::from(format!(
            "/tmp/zylith-coordinator-submittable-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&temp_path);
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let pair = PairId("STRK/USDC".into());
        let now = now_unix_ms();
        let mut batch_one = empty_batch(
            &product,
            &pair,
            1,
            now,
            DEFAULT_BATCH_WINDOW_MS,
            0,
            "test-heartbeat-cover-secret",
        )
        .expect("construct test batch");
        batch_one.close_time_unix_ms = now + 4_000;
        let mut batch_two = empty_batch(
            &product,
            &pair,
            2,
            now + 1_000,
            DEFAULT_BATCH_WINDOW_MS,
            0,
            "test-heartbeat-cover-secret",
        )
        .expect("construct test batch");
        batch_two.close_time_unix_ms = now + DEFAULT_BATCH_WINDOW_MS + 1_000;
        let mut batches = BTreeMap::new();
        batches.insert(
            batch_one.batch_id.0.clone(),
            BatchRecord {
                batch: batch_one,
                order_count: 0,
                orders: Vec::new(),
                liquidity_lifecycle_count: 0,
                liquidity_lifecycle_submissions: Vec::new(),
            },
        );
        batches.insert(
            batch_two.batch_id.0.clone(),
            BatchRecord {
                batch: batch_two,
                order_count: 0,
                orders: Vec::new(),
                liquidity_lifecycle_count: 0,
                liquidity_lifecycle_submissions: Vec::new(),
            },
        );
        persist_batch_store(&temp_path, &batches).expect("persist batches");

        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: Some(temp_path.clone()),
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            None,
            product,
            BatchTimingConfig {
                window_ms: DEFAULT_BATCH_WINDOW_MS,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");

        let submittable = app
            .oneshot(
                Request::builder()
                    .uri("/api/pairs/STRK/USDC/batches/submittable")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(submittable.status(), StatusCode::OK);
        let body = submittable
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["batch_id"], "batch-strk-usdc-2");
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn submittable_helper_never_returns_unsafe_open_batch() {
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let pair = PairId("STRK/USDC".into());
        let now = now_unix_ms();
        let mut unsafe_batch = empty_batch(
            &product,
            &pair,
            1,
            now,
            DEFAULT_BATCH_WINDOW_MS,
            0,
            "test-heartbeat-cover-secret",
        )
        .expect("construct test batch");
        unsafe_batch.close_time_unix_ms = now + 1_000;
        let batches = [BatchRecord {
            batch: unsafe_batch,
            order_count: 0,
            orders: Vec::new(),
            liquidity_lifecycle_count: 0,
            liquidity_lifecycle_submissions: Vec::new(),
        }];

        assert!(
            submittable_open_batch_for_pair(batches.iter(), &pair, DEFAULT_BATCH_WINDOW_MS)
                .is_none()
        );
    }

    #[tokio::test]
    async fn order_submission_rejects_open_batch_inside_safety_buffer() {
        let temp_path = PathBuf::from(format!(
            "/tmp/zylith-coordinator-unsafe-submit-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&temp_path);
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let pair = PairId("STRK/USDC".into());
        let now = now_unix_ms();
        let mut unsafe_batch = empty_batch(
            &product,
            &pair,
            1,
            now,
            DEFAULT_BATCH_WINDOW_MS,
            0,
            "test-heartbeat-cover-secret",
        )
        .expect("construct test batch");
        unsafe_batch.close_time_unix_ms = now + 1_000;
        let mut next_batch = empty_batch(
            &product,
            &pair,
            2,
            now + 1_000,
            DEFAULT_BATCH_WINDOW_MS,
            0,
            "test-heartbeat-cover-secret",
        )
        .expect("construct test batch");
        next_batch.close_time_unix_ms = now + DEFAULT_BATCH_WINDOW_MS + 1_000;
        let mut batches = BTreeMap::new();
        batches.insert(
            unsafe_batch.batch_id.0.clone(),
            BatchRecord {
                batch: unsafe_batch,
                order_count: 0,
                orders: Vec::new(),
                liquidity_lifecycle_count: 0,
                liquidity_lifecycle_submissions: Vec::new(),
            },
        );
        batches.insert(
            next_batch.batch_id.0.clone(),
            BatchRecord {
                batch: next_batch,
                order_count: 0,
                orders: Vec::new(),
                liquidity_lifecycle_count: 0,
                liquidity_lifecycle_submissions: Vec::new(),
            },
        );
        persist_batch_store(&temp_path, &batches).expect("persist batches");

        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: Some(temp_path.clone()),
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            None,
            product,
            BatchTimingConfig {
                window_ms: DEFAULT_BATCH_WINDOW_MS,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");

        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x7788".into()),
                cancellation_auth_tag: "cancel-tag-unsafe".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
                epoch_id: 1,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let _ = fs::remove_file(temp_path);
    }

    #[tokio::test]
    async fn order_submission_rejects_unknown_wire_fields() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));
        let submission = trusted_order_submission(OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x7789".into()),
                cancellation_auth_tag: "cancel-tag-strict".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
                epoch_id: 1,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        });
        let mut top_level = serde_json::to_value(&submission).expect("submission json");
        top_level["ingress_telemetry"] =
            serde_json::to_value(test_order_ingress_telemetry()).expect("telemetry json");
        top_level["unsupported_batch_hint"] = serde_json::json!("batch-strk-usdc-1");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&top_level).expect("serialize top-level strict test"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let mut nested = serde_json::to_value(&submission).expect("submission json");
        nested["ingress_telemetry"] =
            serde_json::to_value(test_order_ingress_telemetry()).expect("telemetry json");
        nested["order_bundle"]["unsupported_order_commitment"] = serde_json::json!("0x7789");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&nested).expect("serialize nested strict test"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn order_submission_accepts_preopened_next_batch() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x8888".into()),
                cancellation_auth_tag: "cancel-tag-next".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let selected_batch_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/batches/{}", batch.0))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = selected_batch_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["batch_id"], batch.0);
        assert_eq!(json["order_count_bucket"], "0-7");

        let next_batch_response = app
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{}/orders", batch.0))
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(next_batch_response.status(), StatusCode::OK);
        let body = next_batch_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["batch"]["batch_id"], batch.0);
        assert_eq!(
            json["orders"][0]["order_bundle"]["order_commitment"],
            "0x8888"
        );
    }

    #[tokio::test]
    async fn liquidity_position_lifecycle_submission_accepts_receipt_bound_manifest() {
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: None,
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            Some(TEST_INTERNAL_TOKEN.into()),
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product"),
            BatchTimingConfig {
                window_ms: 600_000,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = zylith_core::LiquidityPositionLifecycleSubmission {
            lifecycle_id: "lp-lifecycle-open-1".into(),
            pair_id: PairId("STRK/USDC".into()),
            batch_id: zylith_core::BatchId(batch.0.clone()),
            epoch_id: batch.1,
            transition_commitment: "0xabc123".into(),
            ingress_receipt: None,
        };
        submission.ingress_receipt = Some(
            zylith_core::create_liquidity_position_ingress_receipt(
                &submission,
                "0xfeed",
                "test-ingress",
                "zylith-prover",
                TEST_RECEIPT_SECRET,
                123,
            )
            .expect("trusted LP lifecycle receipt"),
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/liquidity-positions/lifecycle")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize lifecycle submission"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let accepted =
            serde_json::from_slice::<zylith_core::LiquidityPositionLifecycleAccepted>(&body)
                .expect("accepted response");
        assert_eq!(accepted.batch_id.0, batch.0);
        assert_eq!(accepted.lifecycle_id, "lp-lifecycle-open-1");

        let order_set_response = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{}/orders", batch.0))
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("internal order set response");
        assert_eq!(order_set_response.status(), StatusCode::OK);
        let body = order_set_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["orders"].as_array().expect("orders").len(), 0);
        assert_eq!(
            json["liquidity_position_lifecycle_submissions"]
                .as_array()
                .expect("lifecycle submissions")
                .len(),
            1
        );

        let duplicate_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/liquidity-positions/lifecycle")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize duplicate submission"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("duplicate response");
        assert_eq!(duplicate_response.status(), StatusCode::OK);

        let mut telemetry_submission =
            serde_json::to_value(&submission).expect("serialize telemetry submission");
        telemetry_submission["ingress_telemetry"] =
            serde_json::to_value(test_order_ingress_telemetry()).expect("telemetry json");
        let telemetry_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/liquidity-positions/lifecycle")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&telemetry_submission)
                            .expect("serialize lifecycle telemetry submission"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("telemetry response");
        assert_eq!(telemetry_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn order_submission_persistence_failure_does_not_activate_order() {
        let path = std::env::temp_dir().join(format!(
            "zylith-coordinator-submit-persist-failure-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&path);
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: Some(path.clone()),
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            Some(TEST_INTERNAL_TOKEN.into()),
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product"),
            BatchTimingConfig {
                window_ms: 120_000,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        fs::remove_file(&path).expect("remove initialized batch store");
        fs::create_dir_all(&path).expect("blocking batch store path");
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x8899".into()),
                cancellation_auth_tag: "cancel-tag-persist-failure".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        fs::remove_dir_all(&path).expect("unblock batch store path");
        let response = app
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{}/orders", batch.0))
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["orders"].as_array().map(Vec::len), Some(0));
        let _ = fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn order_submission_increments_batch_order_count() {
        let app = build_app_with_paths(None, None, None, None);
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x111".into()),
                cancellation_auth_tag: "cancel-tag-1".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let current_batch_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/batches/{}", batch.0))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let body = current_batch_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["order_count_bucket"], "0-7");
        assert!(json.get("order_count").is_none());
        assert!(json.get("order_commitment_root").is_none());
    }

    #[tokio::test]
    async fn receipt_backed_order_submission_stores_public_manifest_only() {
        let receipt_secret = "coordinator-receipt-test-secret";
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: None,
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            Some(TEST_INTERNAL_TOKEN.into()),
            ProductConfig::from_enabled_pair_ids_csv(super::DEFAULT_PAIR_IDS)
                .expect("default coordinator pairs"),
            BatchTimingConfig {
                window_ms: DEFAULT_BATCH_WINDOW_MS,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec![receipt_secret.into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut full_bundle = OrderShareBundle {
            order_commitment: zylith_core::OrderCommitment("0xabc".into()),
            cancellation_auth_tag: "cancel-tag-receipt".into(),
            pair_id: PairId("STRK/USDC".into()),
            batch_id: zylith_core::BatchId(batch.0.clone()),
            epoch_id: batch.1,
            transport_envelope: Some(zylith_core::EncryptedBlob {
                algorithm: "test-encrypted-payload".into(),
                key_id: "test-key".into(),
                ephemeral_public_key: "04abcdef".into(),
                nonce: "00".into(),
                ciphertext: "11".into(),
                recovery: None,
            }),
            ingress_receipt: None,
            shares: vec![],
        };
        let receipt = create_order_ingress_receipt(
            &full_bundle,
            "test-ingress",
            "zylith-prover",
            receipt_secret,
            123,
            Default::default(),
        )
        .expect("receipt");
        full_bundle.ingress_receipt = Some(receipt);
        let submission = OrderSubmission {
            order_bundle: full_bundle,
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(test_order_submission_body(&submission)))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{}/orders", batch.0))
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert!(
            json["orders"][0]["order_bundle"]["shares"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(json["orders"][0]["order_bundle"]["transport_envelope"].is_null());
        assert!(json["orders"][0]["order_bundle"]["ingress_receipt"].is_object());
    }

    #[tokio::test]
    async fn direct_order_share_submission_is_rejected() {
        let app = build_app_with_paths(None, None, None, None);
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x9999".into()),
                cancellation_auth_tag: "cancel-tag-direct".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
                epoch_id: 1,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(test_order_submission_body(&submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn duplicate_order_commitments_return_original_acceptance_in_open_batch() {
        let app = build_app_with_paths(None, None, None, None);
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x222".into()),
                cancellation_auth_tag: "cancel-tag-duplicate".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(
                        submission.clone(),
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(first.status(), StatusCode::OK);

        let duplicate = app
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(duplicate.status(), StatusCode::OK);
        let body = duplicate
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["order_commitment"], "0x222");
        assert_eq!(json["batch_id"], batch.0);
    }

    #[tokio::test]
    async fn coordinator_rejects_orders_for_disabled_pairs() {
        let app = build_app_with_paths(None, None, None, None);
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x444".into()),
                cancellation_auth_tag: "cancel-tag-disabled".into(),
                pair_id: PairId("USDC/STRK".into()),
                batch_id: zylith_core::BatchId("batch-usdc-strk-1".into()),
                epoch_id: 1,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn coordinator_rejects_unexpected_client_epoch() {
        let app = build_app_with_paths(None, None, None, None);
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x555".into()),
                cancellation_auth_tag: "cancel-tag-latest".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-42".into()),
                epoch_id: 42,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let current_batch_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/pairs/STRK/USDC/batches/current")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let body = current_batch_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert!(json["batch_id"].as_str().is_some());
        assert_eq!(json["order_count_bucket"], "0-7");
    }

    #[tokio::test]
    async fn internal_batch_orders_endpoint_returns_stored_orders() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x666".into()),
                cancellation_auth_tag: "cancel-tag-2".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        let response = app
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{}/orders", batch.0))
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(
            json["orders"][0]["order_bundle"]["order_commitment"],
            "0x666"
        );
    }

    #[tokio::test]
    async fn cancel_endpoint_removes_matching_open_order() {
        let app = build_app_with_paths(None, None, None, None);
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x777".into()),
                cancellation_auth_tag: derive_order_cancellation_tag("cancel-secret-3"),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        let cancellation = OrderCancellationRequest {
            batch_id: zylith_core::BatchId(batch.0.clone()),
            order_commitment: zylith_core::OrderCommitment("0x777".into()),
            cancellation_secret: "cancel-secret-3".into(),
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders/cancel")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&cancellation).expect("serialize cancellation"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let current_batch_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/pairs/STRK/USDC/batches/current")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let body = current_batch_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["order_count_bucket"], "0-7");
    }

    #[tokio::test]
    async fn cancellation_persistence_failure_keeps_order_active() {
        let path = std::env::temp_dir().join(format!(
            "zylith-coordinator-cancel-persist-failure-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&path);
        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: Some(path.clone()),
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            Some(TEST_INTERNAL_TOKEN.into()),
            ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product"),
            BatchTimingConfig {
                window_ms: 120_000,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x7799".into()),
                cancellation_auth_tag: derive_order_cancellation_tag("cancel-persist-failure"),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        fs::remove_file(&path).expect("remove batch store file");
        fs::create_dir_all(&path).expect("blocking batch store path");
        let cancellation = OrderCancellationRequest {
            batch_id: zylith_core::BatchId(batch.0.clone()),
            order_commitment: zylith_core::OrderCommitment("0x7799".into()),
            cancellation_secret: "cancel-persist-failure".into(),
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders/cancel")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&cancellation).expect("serialize cancellation"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let response = app
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{}/orders", batch.0))
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["orders"].as_array().map(Vec::len), Some(1));
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn cancel_endpoint_rejects_open_batch_inside_safety_buffer() {
        let temp_path = PathBuf::from(format!(
            "/tmp/zylith-coordinator-unsafe-cancel-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&temp_path);
        let product = ProductConfig::from_enabled_pair_ids_csv("STRK/USDC").expect("product");
        let pair = PairId("STRK/USDC".into());
        let now = now_unix_ms();
        let cancellation_secret = "cancel-secret-unsafe";
        let mut unsafe_batch = empty_batch(
            &product,
            &pair,
            1,
            now,
            DEFAULT_BATCH_WINDOW_MS,
            0,
            "test-heartbeat-cover-secret",
        )
        .expect("construct test batch");
        unsafe_batch.close_time_unix_ms = now + 1_000;
        let order_bundle = OrderShareBundle {
            order_commitment: zylith_core::OrderCommitment("0x7780".into()),
            cancellation_auth_tag: derive_order_cancellation_tag(cancellation_secret),
            pair_id: pair.clone(),
            batch_id: unsafe_batch.batch_id.clone(),
            epoch_id: unsafe_batch.epoch_id,
            transport_envelope: None,
            ingress_receipt: None,
            shares: vec![],
        };
        let mut batches = BTreeMap::new();
        batches.insert(
            unsafe_batch.batch_id.0.clone(),
            BatchRecord {
                batch: unsafe_batch,
                order_count: 1,
                orders: vec![SubmittedOrderRecord {
                    received_at_unix_ms: now,
                    order_bundle: order_bundle.clone(),
                }],
                liquidity_lifecycle_count: 0,
                liquidity_lifecycle_submissions: Vec::new(),
            },
        );
        persist_batch_store(&temp_path, &batches).expect("persist batches");

        let app = build_app_with_config(
            super::CoordinatorStoreConfig {
                batch_store_path: Some(temp_path.clone()),
                recovery_store_path: None,
                published_batch_artifacts_store_path: None,
            },
            None,
            product,
            BatchTimingConfig {
                window_ms: DEFAULT_BATCH_WINDOW_MS,
                epoch_offset: 0,
                close_jitter_ms: 0,
            },
            OrderIngressConfig {
                receipt_secrets: vec!["test-receipt-secret".into()],
            },
            super::CoordinatorHardeningConfig::default(),
        )
        .expect("test app should build");

        let cancellation = OrderCancellationRequest {
            batch_id: order_bundle.batch_id,
            order_commitment: order_bundle.order_commitment,
            cancellation_secret: cancellation_secret.into(),
        };

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/orders/cancel")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&cancellation).expect("serialize cancellation"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let _ = fs::remove_file(temp_path);
    }

    #[tokio::test]
    async fn recovery_artifacts_can_be_uploaded_and_listed() {
        let temp_path = PathBuf::from(format!(
            "/tmp/zylith-recovery-test-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&temp_path);
        let app = build_app_with_paths(None, Some(temp_path.clone()), None, None);

        let artifact = RecoveryArtifact {
            artifact_id: "artifact-1".into(),
            account_id: "account-1".into(),
            kind: RecoveryArtifactKind::Snapshot,
            sequence: 1,
            created_at_unix_ms: 123,
            payload: EncryptedRecoveryPayload {
                algorithm: "aes-256-gcm/recovery".into(),
                nonce: "00".into(),
                ciphertext: "11".into(),
            },
        };

        let upload = RecoveryArtifactUpload {
            artifact: artifact.clone(),
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-1/artifacts")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::from(
                        serde_json::to_vec(&upload).expect("serialize upload"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-1/artifacts")
                    .method(Method::GET)
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["account_id"], "account-1");
        assert_eq!(json["artifacts"][0]["artifact_id"], "artifact-1");
        assert_eq!(json["artifact_count_bucket"], "0-7");

        let range_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-1/artifacts/range/0/128")
                    .method(Method::GET)
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(range_response.status(), StatusCode::OK);
        let body = range_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["sequence_start"], 0);
        assert_eq!(json["sequence_end"], 128);
        assert_eq!(json["artifact_count_bucket"], "0-7");

        let persisted = std::fs::read_to_string(&temp_path).expect("persisted file");
        assert!(persisted.contains("artifact-1"));
        let _ = std::fs::remove_file(temp_path);
    }

    #[tokio::test]
    async fn published_batch_artifacts_can_be_uploaded_and_fetched() {
        let temp_path = PathBuf::from(format!(
            "/tmp/zylith-artifacts-test-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&temp_path);
        let app = build_app_with_paths(
            None,
            None,
            Some(temp_path.clone()),
            Some(TEST_INTERNAL_TOKEN.into()),
        );

        let batch_id = "batch-strk-usdc-9";
        let liquidity_provider_public_key = "LP-PUBLIC-KEY-01";
        let liquidity_provider_fill_transition_commitment =
            zylith_core::OrderCommitment("0x000f00".into());
        let mut output_recovery_record = zylith_core::OutputRecoveryRecord {
            key_tag: "0x1234".into(),
            ciphertext_fields: (0..OUTPUT_RECOVERY_FIELD_COUNT)
                .map(|_| "0x1".to_string())
                .collect(),
            auth_tag: "0x2".into(),
            commitment: "0x0".into(),
        };
        output_recovery_record.commitment =
            output_recovery_record_commitment(&output_recovery_record)
                .expect("recovery commitment");
        let output_bundle = zylith_core::OutputCiphertextBundle::from_ciphertexts(
            zylith_core::BatchId(batch_id.into()),
            "da-ref",
            vec![zylith_core::EncryptedBlob {
                algorithm: NOTE_RECOGNITION_ALGORITHM.into(),
                key_id: "01".repeat(32),
                ephemeral_public_key: "04".to_string() + &"11".repeat(64),
                nonce: "02".repeat(12),
                ciphertext: "11".repeat(OUTPUT_NOTE_CIPHERTEXT_LEN),
                recovery: Some(output_recovery_record.clone()),
            }],
        )
        .expect("output bundle");
        let output_bundle_ref = output_bundle.bundle_commitment.clone();
        let output_recovery_dummy_commitments = output_bundle
            .ciphertexts
            .iter()
            .skip(1)
            .filter_map(|ciphertext| {
                ciphertext
                    .recovery
                    .as_ref()
                    .map(|recovery| recovery.commitment.clone())
            })
            .collect::<Vec<_>>();
        let liquidity_position_transition = zylith_core::LiquidityPositionRootTransition {
            kind: zylith_core::LiquidityPositionTransitionKind::Reconfigure,
            consumed_position_commitment: Some(zylith_core::LiquidityPositionCommitment(
                "0x7001".into(),
            )),
            position_nullifier: Some("0x7002".into()),
            output_position_commitment: Some(zylith_core::LiquidityPositionCommitment(
                "0x7003".into(),
            )),
        };
        let liquidity_position_transition_commitment =
            zylith_core::settlement_liquidity_position_transition_root(std::slice::from_ref(
                &liquidity_position_transition,
            ))
            .expect("liquidity position transition commitment");
        let liquidity_provider_attribution_artifact =
            zylith_core::EncryptedLiquidityAttributionArtifact {
                version: 1,
                batch_id: zylith_core::BatchId(batch_id.into()),
                pair_id: zylith_core::PairId("STRK/USDC".into()),
                epoch_id: 9,
                liquidity_provider_public_key: liquidity_provider_public_key.into(),
                curve_commitment: "0xabc123".into(),
                output_note_commitment: zylith_core::NoteCommitment("0x7003".into()),
                order_commitment: liquidity_provider_fill_transition_commitment.clone(),
                algorithm: "zylith-liquidity-attribution-v1".into(),
                key_id: "01".repeat(32),
                ephemeral_public_key: "04".to_string() + &"22".repeat(64),
                nonce: "02".repeat(12),
                ciphertext: "33".repeat(512),
                receipt: zylith_core::LiquidityAttributionReceipt {
                    version: 1,
                    signer_public_key: "0x123".into(),
                    issued_at_unix_ms: 1_778_661_520_000_u64,
                    payload_commitment: "0x456".into(),
                    signature_r: "0x789".into(),
                    signature_s: "0xabc".into(),
                },
            };
        let published = PublishedBatchArtifacts {
            transcript: zylith_core::SettlementTranscript {
                batch_id: zylith_core::BatchId(batch_id.into()),
                pair_id: zylith_core::PairId("STRK/USDC".into()),
                batch_epoch: 9,
                order_commitment_root: "0x111".into(),
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                prior_liquidity_position_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                new_liquidity_position_root: "0x9999".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                relay_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-treasury".into(),
                relay_fee_recipient: "zylith-renewal-relay".into(),
                matched_orders: vec![],
                consumed_inputs: vec![],
                renewal_child_uses: vec![],
                liquidity_position_transitions: vec![liquidity_position_transition.clone()],
                fees: vec![],
                output_notes: vec![zylith_core::OutputNoteRecord {
                    note_commitment: zylith_core::NoteCommitment("0x4567".into()),
                    asset_id: zylith_core::AssetId("STRK".into()),
                    amount: 999,
                    withdraw_authority: "0x123".into(),
                }],
                output_note_preimages: vec![],
                output_recovery_records: vec![output_recovery_record.clone()],
                output_recovery_dummy_commitments: output_recovery_dummy_commitments.clone(),
                output_ciphertext_bundle_ref: output_bundle_ref.clone(),
            },
            output_bundle,
            liquidity_provider_attribution_bundle: Some(zylith_core::LiquidityAttributionBundle {
                version: 1,
                batch_id: zylith_core::BatchId(batch_id.into()),
                artifacts: vec![liquidity_provider_attribution_artifact.clone()],
            }),
            settlement_witness: zylith_core::SettlementWitness {
                batch_id: zylith_core::BatchId(batch_id.into()),
                pair_id: zylith_core::PairId("STRK/USDC".into()),
                batch_epoch: 9,
                order_commitment_root: "0x111".into(),
                encrypted_order_set_commitment: "0x222".into(),
                transcript_commitment: "transcript-commitment".into(),
                auction_verifier_address: "0x0".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                prior_liquidity_position_root: "0x0".into(),
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                new_liquidity_position_root: "0x9999".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                relay_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-treasury".into(),
                relay_fee_recipient: "zylith-renewal-relay".into(),
                base_asset_id: zylith_core::AssetId("STRK".into()),
                quote_asset_id: zylith_core::AssetId("USDC".into()),
                matched_orders: vec![],
                matched_order_witnesses: vec![],
                consumed_inputs: vec![],
                note_membership_witnesses: vec![],
                nullifier_history: vec![],
                nullifier_sparse_witnesses: vec![],
                renewal_history: vec![],
                renewal_child_sparse_witnesses: vec![],
                renewal_cancel_sparse_witnesses: vec![],
                renewal_child_uses: vec![],
                liquidity_position_transitions: vec![liquidity_position_transition.clone()],
                liquidity_position_witnesses: vec![],
                fees: vec![],
                output_notes: vec![zylith_core::OutputNoteRecord {
                    note_commitment: zylith_core::NoteCommitment("0x4567".into()),
                    asset_id: zylith_core::AssetId("STRK".into()),
                    amount: 999,
                    withdraw_authority: "0x123".into(),
                }],
                output_note_preimages: vec![],
                output_recovery_records: vec![output_recovery_record.clone()],
                output_recovery_dummy_commitments,
                output_ciphertext_bundle_ref: output_bundle_ref.clone(),
            },
            published_at_unix_ms: now_unix_ms(),
            settled_at_unix_ms: Some(1_778_661_520_000_u64),
            settlement_transaction_hash: None,
            settlement_contract_address: None,
            order_execution_reports: vec![zylith_core::OrderExecutionReport {
                batch_id: zylith_core::BatchId(batch_id.into()),
                pair_id: zylith_core::PairId("STRK/USDC".into()),
                order_commitment: zylith_core::OrderCommitment("0x000abc".into()),
                order_report_auth_tag: Some("test-order-report-auth".into()),
                funding_note_commitment: zylith_core::NoteCommitment("0xdef".into()),
                funding_note_commitments: vec![zylith_core::NoteCommitment("0xdef".into())],
                status: "Filled".into(),
                side: zylith_core::OrderSide::Buy,
                order_type: zylith_core::OrderType::LimitBatch,
                time_in_force: zylith_core::TimeInForce::CurrentBatchOnly,
                submitted_amount: 1_000,
                filled_amount: 1_000,
                unfilled_amount: 0,
                limit_price: 150,
                execution_price: Some(145),
                fee_asset_id: Some(zylith_core::AssetId("USDC".into())),
                fee_amount: 1,
                output_note_commitment: Some(zylith_core::NoteCommitment("0x4567".into())),
                output_asset_id: Some(zylith_core::AssetId("STRK".into())),
                output_amount: 999,
                residual_note_commitment: None,
                residual_asset_id: None,
                residual_amount: 0,
            }],
            transcript_shape: None,
        };

        let response = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/artifacts"))
                        .method(Method::POST),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&published).expect("serialize published artifacts"),
                ))
                .expect("request"),
            )
            .await
            .expect("response");

        let publish_status = response.status();
        let publish_body = response
            .into_body()
            .collect()
            .await
            .expect("publish body")
            .to_bytes();
        assert_eq!(
            publish_status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&publish_body)
        );

        let duplicate_publish = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/artifacts"))
                        .method(Method::POST),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&published).expect("serialize duplicate artifacts"),
                ))
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(duplicate_publish.status(), StatusCode::OK);

        let mut conflicting_publish = published.clone();
        conflicting_publish.transcript.clearing_price += 1;
        let conflicting_response = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/artifacts"))
                        .method(Method::POST),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&conflicting_publish)
                        .expect("serialize conflicting artifacts"),
                ))
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(conflicting_response.status(), StatusCode::CONFLICT);

        let roots = zylith_core::root_only_settlement_commitments(&published.transcript)
            .expect("settlement roots");
        let transcript_commitment =
            zylith_core::settlement_transcript_commitment(&published.transcript)
                .expect("transcript commitment");
        let settlement_payload = serde_json::json!({
            "settled_at_unix_ms": 1_778_661_520_000_u64,
            "output_note_root": roots.output_note_root,
            "transcript_commitment": transcript_commitment,
        })
        .to_string();

        let settled_response = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/settled-at"))
                        .method(Method::POST),
                )
                .header("content-type", "application/json")
                .body(Body::from(settlement_payload.clone()))
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(settled_response.status(), StatusCode::OK);

        let duplicate_settled_response = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/settled-at"))
                        .method(Method::POST),
                )
                .header("content-type", "application/json")
                .body(Body::from(settlement_payload))
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(duplicate_settled_response.status(), StatusCode::OK);

        let conflicting_settlement_payload = serde_json::json!({
            "settled_at_unix_ms": 1_778_661_520_001_u64,
            "output_note_root": roots.output_note_root,
            "transcript_commitment": transcript_commitment,
        })
        .to_string();
        let conflicting_settled_response = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/settled-at"))
                        .method(Method::POST),
                )
                .header("content-type", "application/json")
                .body(Body::from(conflicting_settlement_payload))
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(conflicting_settled_response.status(), StatusCode::CONFLICT);

        let unknown_report_field_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"output_recovery_key_tags":[],"unexpected_report_filter":["0xabc"]}"#
                            .to_vec(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            unknown_report_field_response.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let unknown_order_report_auth_field_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"output_recovery_key_tags":[],"order_report_auths":[{"order_commitment":"0xabc","order_report_auth_tag":"test-order-report-auth","order_commitments":["0xabc"]}]}"#
                            .to_vec(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            unknown_order_report_auth_field_response.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let missing_report_capability_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"output_recovery_key_tags":[],"order_report_auths":[],"liquidity_position_transition_commitments":[]}"#.to_vec(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            missing_report_capability_response.status(),
            StatusCode::BAD_REQUEST
        );
        let wrong_liquidity_provider_key_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "output_recovery_key_tags": [],
                            "order_report_auths": [],
                            "liquidity_position_transition_commitments": [],
                            "liquidity_provider_public_keys": ["wrong-lp-public-key"]
                        }))
                        .expect("wrong liquidity provider report request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            wrong_liquidity_provider_key_response.status(),
            StatusCode::NOT_FOUND
        );
        let wrong_order_report_auth_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"output_recovery_key_tags":[],"order_report_auths":[{"order_commitment":"0xabc","order_report_auth_tag":"wrong-order-report-auth"}],"liquidity_position_transition_commitments":[]}"#
                            .to_vec(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            wrong_order_report_auth_response.status(),
            StatusCode::NOT_FOUND
        );
        let batch_scoped_report_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"output_recovery_key_tags":[],"order_report_auths":[{"order_commitment":"0xabc","order_report_auth_tag":"test-order-report-auth"}],"liquidity_position_transition_commitments":[]}"#
                            .to_vec(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(batch_scoped_report_response.status(), StatusCode::OK);
        let batch_scoped_body = batch_scoped_report_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let batch_scoped_json = serde_json::from_slice::<serde_json::Value>(&batch_scoped_body)
            .expect("batch scoped private report json");
        assert!(batch_scoped_json.get("matched_order_count").is_none());
        assert_eq!(batch_scoped_json["matched_order_count_bucket"], "0-7");
        assert_eq!(
            batch_scoped_json["order_execution_reports"][0]["order_commitment"],
            "0x000abc"
        );
        assert_eq!(
            batch_scoped_json["output_recovery_records"]
                .as_array()
                .expect("recovery records array")
                .len(),
            1
        );
        assert_eq!(
            batch_scoped_json["output_recovery_records"][0]["recovery"]["key_tag"],
            "0x1234"
        );
        assert_eq!(
            batch_scoped_json["liquidity_position_lifecycle_reports"]
                .as_array()
                .expect("lifecycle reports")
                .len(),
            0
        );

        let lifecycle_scoped_report_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "output_recovery_key_tags": [],
                            "order_report_auths": [],
                            "liquidity_position_transition_commitments": [
                                liquidity_position_transition_commitment
                            ]
                        }))
                        .expect("lifecycle report request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(lifecycle_scoped_report_response.status(), StatusCode::OK);
        let lifecycle_scoped_body = lifecycle_scoped_report_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let lifecycle_scoped_json =
            serde_json::from_slice::<serde_json::Value>(&lifecycle_scoped_body)
                .expect("lifecycle scoped private report json");
        assert_eq!(
            lifecycle_scoped_json["liquidity_position_lifecycle_reports"][0]["transition_commitment"],
            liquidity_position_transition_commitment
        );
        assert_eq!(
            lifecycle_scoped_json["liquidity_position_lifecycle_reports"][0]["kind"],
            "Reconfigure"
        );
        assert_eq!(
            lifecycle_scoped_json["liquidity_position_lifecycle_reports"][0]["output_position_commitment"],
            "0x7003"
        );

        let liquidity_provider_scoped_report_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "output_recovery_key_tags": [],
                            "order_report_auths": [],
                            "liquidity_position_transition_commitments": [],
                            "liquidity_provider_public_keys": [
                                liquidity_provider_public_key.to_ascii_lowercase()
                            ]
                        }))
                        .expect("liquidity provider report request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            liquidity_provider_scoped_report_response.status(),
            StatusCode::OK
        );
        let liquidity_provider_scoped_body = liquidity_provider_scoped_report_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let liquidity_provider_scoped_json =
            serde_json::from_slice::<serde_json::Value>(&liquidity_provider_scoped_body)
                .expect("liquidity provider scoped private report json");
        assert_eq!(
            liquidity_provider_scoped_json["liquidity_provider_attribution_artifacts"][0]["liquidity_provider_public_key"],
            liquidity_provider_public_key
        );
        assert_eq!(
            liquidity_provider_scoped_json["liquidity_provider_attribution_artifacts"][0]["order_commitment"],
            liquidity_provider_fill_transition_commitment.0.as_str()
        );
        assert_eq!(
            liquidity_provider_scoped_json["liquidity_position_lifecycle_reports"]
                .as_array()
                .expect("lifecycle reports")
                .len(),
            0
        );

        let fill_transition_scoped_report_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "output_recovery_key_tags": [],
                            "order_report_auths": [],
                            "liquidity_position_transition_commitments": [
                                liquidity_provider_fill_transition_commitment.0.clone()
                            ],
                            "liquidity_provider_public_keys": []
                        }))
                        .expect("liquidity provider fill transition report request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            fill_transition_scoped_report_response.status(),
            StatusCode::OK
        );
        let fill_transition_scoped_body = fill_transition_scoped_report_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let fill_transition_scoped_json =
            serde_json::from_slice::<serde_json::Value>(&fill_transition_scoped_body)
                .expect("liquidity provider fill transition scoped private report json");
        assert_eq!(
            fill_transition_scoped_json["liquidity_provider_attribution_artifacts"][0]["output_note_commitment"],
            "0x7003"
        );

        let wrong_recovery_tag_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"output_recovery_key_tags":["0x9999"],"order_report_auths":[],"liquidity_position_transition_commitments":[]}"#
                            .to_vec(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(wrong_recovery_tag_response.status(), StatusCode::NOT_FOUND);

        let recovery_scoped_report_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/settlement-reports/{batch_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"output_recovery_key_tags":["0x1234"],"order_report_auths":[],"liquidity_position_transition_commitments":[]}"#
                            .to_vec(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(recovery_scoped_report_response.status(), StatusCode::OK);
        let recovery_scoped_body = recovery_scoped_report_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let recovery_scoped_json =
            serde_json::from_slice::<serde_json::Value>(&recovery_scoped_body)
                .expect("recovery scoped private report json");
        assert!(recovery_scoped_json.get("matched_order_count").is_none());
        assert_eq!(recovery_scoped_json["matched_order_count_bucket"], "0-7");
        assert_eq!(
            recovery_scoped_json["order_execution_reports"]
                .as_array()
                .expect("order reports")
                .len(),
            0
        );
        assert_eq!(
            recovery_scoped_json["output_recovery_records"]
                .as_array()
                .expect("recovery records")
                .len(),
            1
        );

        let transcript_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/batches/{batch_id}/transcript"))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(transcript_response.status(), StatusCode::OK);
        let public_body = transcript_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let public_json = serde_json::from_slice::<serde_json::Value>(&public_body).expect("json");
        assert_eq!(public_json["batch_id"], batch_id);
        assert_eq!(public_json["settled_at_unix_ms"], 1_778_661_520_000_u64);
        assert_eq!(public_json["output_bundle_ref"], output_bundle_ref);
        assert!(public_json["transcript_shape"].is_object());
        assert!(public_json.get("matched_orders").is_none());
        assert!(public_json.get("consumed_inputs").is_none());
        assert!(public_json.get("output_notes").is_none());
        assert!(public_json.get("fees").is_none());

        let public_list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/batches/transcripts?batch_ids={batch_id}"))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(public_list_response.status(), StatusCode::OK);
        let public_list_body = public_list_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let public_list_json =
            serde_json::from_slice::<serde_json::Value>(&public_list_body).expect("json");
        let listed_transcript = &public_list_json.as_array().expect("public transcript list")[0];
        assert_eq!(listed_transcript["batch_id"], batch_id);
        assert!(listed_transcript.get("matched_orders").is_none());
        assert!(listed_transcript.get("consumed_inputs").is_none());
        assert!(listed_transcript.get("output_notes").is_none());
        assert!(listed_transcript.get("fees").is_none());

        let oversized_batch_query = (0..=MAX_PUBLIC_TRANSCRIPT_BATCH_IDS)
            .map(|index| format!("batch-strk-usdc-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let oversized_public_list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/batches/transcripts?batch_ids={oversized_batch_query}"
                    ))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            oversized_public_list_response.status(),
            StatusCode::BAD_REQUEST
        );

        let internal_transcript_response = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/transcript"))
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(internal_transcript_response.status(), StatusCode::OK);
        let internal_body = internal_transcript_response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let internal_json =
            serde_json::from_slice::<serde_json::Value>(&internal_body).expect("json");
        assert!(internal_json.get("matched_orders").is_some());
        assert!(internal_json.get("consumed_inputs").is_some());
        assert!(internal_json.get("output_notes").is_some());
        assert!(internal_json.get("fees").is_some());

        let output_bundle_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/batches/{batch_id}/output-bundle"))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(output_bundle_response.status(), StatusCode::OK);

        let persisted = std::fs::read_to_string(&temp_path).expect("persisted file");
        assert!(persisted.contains(&output_bundle_ref));
        let _ = std::fs::remove_file(temp_path);
    }

    #[tokio::test]
    async fn order_submission_persists_live_batches_and_real_commitments() {
        let temp_path = PathBuf::from(format!(
            "/tmp/zylith-batches-test-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&temp_path);
        let app = build_app_with_paths(Some(temp_path.clone()), None, None, None);
        let batch = submittable_test_batch(&app, "STRK/USDC").await;
        let mut submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x333".into()),
                cancellation_auth_tag: "cancel-tag-persisted".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId(String::new()),
                epoch_id: 0,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };
        bind_submission_to_batch(&mut submission, &batch);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(trusted_order_submission_body(submission)))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let persisted = std::fs::read_to_string(&temp_path).expect("persisted file");
        let json = serde_json::from_str::<serde_json::Value>(&persisted).expect("persisted json");
        let batch_json = &json["batches_by_id"][&batch.0];
        assert_eq!(batch_json["order_count"], 1);
        assert_ne!(
            batch_json["batch"]["order_commitment_root"],
            "invalid-order-root"
        );
        assert_ne!(
            batch_json["batch"]["encrypted_order_set_commitment"],
            "invalid-ciphertext-root"
        );
        let _ = std::fs::remove_file(temp_path);
    }

    #[tokio::test]
    async fn internal_routes_require_control_plane_bearer_token() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));

        let routes = [
            (Method::GET, "/api/internal/batches/proof-work"),
            (
                Method::GET,
                "/api/internal/batches/batch-strk-usdc-1/orders",
            ),
            (
                Method::GET,
                "/api/internal/batches/batch-strk-usdc-1/transcript",
            ),
            (
                Method::POST,
                "/api/internal/batches/batch-strk-usdc-1/artifacts",
            ),
            (
                Method::POST,
                "/api/internal/batches/batch-strk-usdc-1/settled-at",
            ),
            (
                Method::GET,
                "/api/internal/batches/batch-strk-usdc-1/witness",
            ),
            (Method::GET, "/api/internal/renewal/cancel-markers"),
        ];

        for (method, uri) in routes {
            let unauthorized = app
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
            assert_eq!(
                unauthorized.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri}"
            );

            let wrong_auth = app
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
            assert_eq!(wrong_auth.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }

        let authorized = app
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri("/api/internal/batches/batch-strk-usdc-1/orders")
                        .method(Method::GET),
                )
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(authorized.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn recovery_routes_require_matching_recovery_auth_tag() {
        let app = build_app_with_paths(None, None, None, None);
        let artifact = RecoveryArtifact {
            artifact_id: "artifact-auth".into(),
            account_id: "account-auth".into(),
            kind: RecoveryArtifactKind::Snapshot,
            sequence: 1,
            created_at_unix_ms: 1,
            payload: EncryptedRecoveryPayload {
                algorithm: "aes-256-gcm/recovery".into(),
                nonce: "00".into(),
                ciphertext: "11".into(),
            },
        };
        let upload = RecoveryArtifactUpload {
            artifact: artifact.clone(),
        };

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-auth/artifacts")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&upload).expect("serialize upload"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-auth/artifacts")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::from(
                        serde_json::to_vec(&upload).expect("serialize upload"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(authorized.status(), StatusCode::OK);

        let wrong_auth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-auth/artifacts")
                    .method(Method::GET)
                    .header(zylith_core::RECOVERY_AUTH_HEADER, "wrong-auth")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(wrong_auth.status(), StatusCode::UNAUTHORIZED);

        let missing_list_auth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-auth/artifacts")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(missing_list_auth.status(), StatusCode::UNAUTHORIZED);

        let unknown_recovery_field = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-auth/artifacts")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::from(
                        br#"{"artifact":{"artifact_id":"artifact-extra","account_id":"account-auth","kind":"Snapshot","sequence":2,"created_at_unix_ms":2,"payload":{"algorithm":"aes-256-gcm/recovery","nonce":"00","ciphertext":"11","unsupported_plaintext":"unexpected"}}}"#
                            .to_vec(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            unknown_recovery_field.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let wrong_range_auth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-auth/artifacts/range/0/10")
                    .method(Method::GET)
                    .header(zylith_core::RECOVERY_AUTH_HEADER, "wrong-auth")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(wrong_range_auth.status(), StatusCode::UNAUTHORIZED);

        let missing_account_list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-missing/artifacts")
                    .method(Method::GET)
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(missing_account_list.status(), StatusCode::UNAUTHORIZED);

        let missing_account_range = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-missing/artifacts/range/0/10")
                    .method(Method::GET)
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(missing_account_range.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn recovery_artifact_persistence_failure_does_not_publish_artifact() {
        let path = std::env::temp_dir().join(format!(
            "zylith-recovery-artifact-persist-failure-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&path);
        let app = build_app_with_paths(None, Some(path.clone()), None, None);
        fs::create_dir_all(&path).expect("blocking recovery store path");
        let upload = RecoveryArtifactUpload {
            artifact: RecoveryArtifact {
                artifact_id: "artifact-persist-failure".into(),
                account_id: "account-persist-failure".into(),
                kind: RecoveryArtifactKind::Snapshot,
                sequence: 1,
                created_at_unix_ms: 1,
                payload: EncryptedRecoveryPayload {
                    algorithm: "aes-256-gcm/recovery".into(),
                    nonce: "00".into(),
                    ciphertext: "11".into(),
                },
            },
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-persist-failure/artifacts")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::from(
                        serde_json::to_vec(&upload).expect("serialize recovery artifact"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/recovery/account-persist-failure/artifacts")
                    .method(Method::GET)
                    .header(zylith_core::RECOVERY_AUTH_HEADER, TEST_RECOVERY_AUTH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        fs::remove_dir_all(path).expect("remove blocking recovery store path");
    }

    #[tokio::test]
    async fn wallet_vault_persistence_failure_does_not_publish_bundle() {
        let path = std::env::temp_dir().join(format!(
            "zylith-wallet-vault-persist-failure-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&path);
        let app = build_app_with_paths(None, Some(path.clone()), None, None);
        fs::create_dir_all(&path).expect("blocking recovery store path");
        let wallet_auth_token = "cd".repeat(32);
        let wallet_auth_id = format!(
            "0x{}",
            tagged_sha256_hex(WALLET_VAULT_ID_DOMAIN, wallet_auth_token.as_bytes())
        );
        let bundle = WalletVaultBundleRecord {
            wallet_auth_id: wallet_auth_id.clone(),
            vault: serde_json::json!({
                "version": 4,
                "kdf": "wallet-signature-sha256-v2",
                "algorithm": "AES-GCM",
                "wallet_address": "0xabc",
                "chain_id": "0x534e5f5345504f4c4941",
                "deployment_id": "0xdeployment",
                "origin": "http://localhost:5173",
                "message_version": 2,
                "nonce": "AA==",
                "ciphertext": "EQ=="
            }),
            updated_at_unix_ms: 1,
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(WALLET_VAULT_AUTH_HEADER, &wallet_auth_token)
                    .body(Body::from(
                        serde_json::to_vec(&bundle).expect("serialize bundle"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::GET)
                    .header(WALLET_VAULT_AUTH_HEADER, &wallet_auth_token)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        fs::remove_dir_all(path).expect("remove blocking recovery store path");
    }

    #[tokio::test]
    async fn wallet_vault_bundles_round_trip_by_auth_id() {
        let app = build_app_with_paths(None, None, None, None);
        let wallet_auth_token = "ab".repeat(32);
        let wallet_auth_id = format!(
            "0x{}",
            tagged_sha256_hex(WALLET_VAULT_ID_DOMAIN, wallet_auth_token.as_bytes())
        );
        let bundle = WalletVaultBundleRecord {
            wallet_auth_id: wallet_auth_id.clone(),
            vault: serde_json::json!({
                "version": 4,
                "kdf": "wallet-signature-sha256-v2",
                "algorithm": "AES-GCM",
                "wallet_address": "0xabc",
                "chain_id": "0x534e5f5345504f4c4941",
                "deployment_id": "0xdeployment",
                "origin": "http://localhost:5173",
                "message_version": 2,
                "nonce": "AA==",
                "ciphertext": "EQ=="
            }),
            updated_at_unix_ms: 1,
        };

        let uploaded = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(WALLET_VAULT_AUTH_HEADER, &wallet_auth_token)
                    .body(Body::from(
                        serde_json::to_vec(&bundle).expect("serialize bundle"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(uploaded.status(), StatusCode::OK);

        let fetched = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::GET)
                    .header(WALLET_VAULT_AUTH_HEADER, &wallet_auth_token)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(fetched.status(), StatusCode::OK);
        let body = fetched.into_body().collect().await.unwrap().to_bytes();
        let decoded: WalletVaultBundleRecord =
            serde_json::from_slice(&body).expect("decode bundle");
        assert_eq!(decoded.wallet_auth_id, wallet_auth_id);
        assert_eq!(decoded.vault["kdf"], "wallet-signature-sha256-v2");

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let stale = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(WALLET_VAULT_AUTH_HEADER, &wallet_auth_token)
                    .body(Body::from(
                        serde_json::to_vec(&bundle).expect("serialize bundle"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(stale.status(), StatusCode::CONFLICT);

        let unknown_bundle = serde_json::json!({
            "wallet_auth_id": wallet_auth_id.clone(),
            "vault": {
                "version": 4,
                "kdf": "wallet-signature-sha256-v2",
                "algorithm": "AES-GCM",
                "wallet_address": "0xabc",
                "chain_id": "0x534e5f5345504f4c4941",
                "deployment_id": "0xdeployment",
                "origin": "http://localhost:5173",
                "message_version": 2,
                "nonce": "AA==",
                "ciphertext": "EQ=="
            },
            "updated_at_unix_ms": 2,
            "unsupported_wallet_hint": "unexpected",
        });
        let unknown_bundle_field = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(WALLET_VAULT_AUTH_HEADER, &wallet_auth_token)
                    .body(Body::from(
                        serde_json::to_vec(&unknown_bundle).expect("serialize unknown bundle"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            unknown_bundle_field.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let unknown_vault_field = WalletVaultBundleRecord {
            wallet_auth_id: wallet_auth_id.clone(),
            vault: serde_json::json!({
                "version": 4,
                "kdf": "wallet-signature-sha256-v2",
                "algorithm": "AES-GCM",
                "wallet_address": "0xabc",
                "chain_id": "0x534e5f5345504f4c4941",
                "deployment_id": "0xdeployment",
                "origin": "http://localhost:5173",
                "message_version": 2,
                "nonce": "AA==",
                "ciphertext": "EQ==",
                "unsupported_passphrase_hint": "unexpected"
            }),
            updated_at_unix_ms: 2,
        };
        let unknown_vault_field_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(WALLET_VAULT_AUTH_HEADER, &wallet_auth_token)
                    .body(Body::from(
                        serde_json::to_vec(&unknown_vault_field)
                            .expect("serialize unknown vault field"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            unknown_vault_field_response.status(),
            StatusCode::BAD_REQUEST
        );

        let stale_vault_shape = WalletVaultBundleRecord {
            wallet_auth_id: wallet_auth_id.clone(),
            vault: serde_json::json!({
                "version": 3,
                "kdf": "wallet-signature-sha256-v2",
                "algorithm": "AES-GCM",
                "wallet_address": "0xabc",
                "chain_id": "0x534e5f5345504f4c4941",
                "deployment_id": "0xdeployment",
                "origin": "http://localhost:5173",
                "message_version": 1,
                "nonce": "AA==",
                "ciphertext": "EQ=="
            }),
            updated_at_unix_ms: 2,
        };
        let stale_shape_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/wallet-vaults/{wallet_auth_id}"))
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .header(WALLET_VAULT_AUTH_HEADER, &wallet_auth_token)
                    .body(Body::from(
                        serde_json::to_vec(&stale_vault_shape).expect("serialize stale shape"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(stale_shape_response.status(), StatusCode::BAD_REQUEST);

        let malformed = app
            .oneshot(
                Request::builder()
                    .uri("/api/wallet-vaults/not-a-wallet-auth-id")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn artifact_delay_jitter_is_epoch_bucket_bound_and_capped() {
        let first = effective_public_artifact_delay_epochs("88:95", 3, 8);
        let second = effective_public_artifact_delay_epochs("88:95", 3, 8);
        assert_eq!(first, second);
        assert!((3..=8).contains(&first));
        assert_eq!(effective_public_artifact_delay_epochs("88:95", 4, 4), 4);
    }
}

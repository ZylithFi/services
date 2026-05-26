use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use zylith_core::{
    Batch, BatchId, BatchOrderSet, BatchStatus, BatchSummary, CONTROL_PLANE_TOKEN_ENV,
    CoordinatorStatus, MakerAttributionArtifactList, OrderCancellationAccepted,
    OrderCancellationRequest, OrderShareBundle, OrderSubmission, OrderSubmissionAccepted, PairId,
    ProductConfig, PublicBatchSummary, PublicSettlementTranscript, PublishedBatchArtifacts,
    RecoveryArtifact, RecoveryArtifactList, RecoveryArtifactUpload, SettlementTimestampUpdate,
    SubmittedOrderRecord, count_bucket_label, derive_order_cancellation_tag, extract_bearer_token,
    hash::{ordered_felt_list_commitment, tagged_field_hex},
    heartbeat_cover_order_commitments, heartbeat_cover_order_count,
    root_only_settlement_commitments, settlement_transcript_commitment,
    validate_order_ingress_receipt_for_manifest_with_secrets,
};

const DEFAULT_BATCH_WINDOW_MS: u64 = 90 * 1_000;
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_BATCH_STORE_PATH: &str = "coordinator/batches.dev.json";
const DEFAULT_RECOVERY_STORE_PATH: &str = "coordinator/recovery_artifacts.dev.json";
const DEFAULT_ARTIFACT_STORE_PATH: &str = "coordinator/published_batch_artifacts.dev.json";
const DEFAULT_PAIR_IDS: &str =
    "STRK/USDC,ETH/USDC,strkBTC/USDC,STRK/ETH,STRK/strkBTC,WBTC/strkBTC,USDC/USDT";
const PRODUCT_PAIRS_ENV: &str = "ZYLITH_PRODUCT_PAIRS";
const COORDINATOR_PAIR_IDS_ENV: &str = "ZYLITH_COORDINATOR_PAIRS";
const BATCH_WINDOW_MS_ENV: &str = "ZYLITH_BATCH_WINDOW_MS";
const COORDINATOR_EPOCH_OFFSET_ENV: &str = "ZYLITH_COORDINATOR_EPOCH_OFFSET";
const ORDER_INGRESS_RECEIPT_SECRET_ENV: &str = "ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET";
const ORDER_INGRESS_RECEIPT_PREVIOUS_SECRETS_ENV: &str =
    "ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS";
const REQUIRE_TRUSTED_ORDER_INGRESS_ENV: &str = "ZYLITH_REQUIRE_TRUSTED_ORDER_INGRESS";
const ALLOW_DIRECT_PRIVATE_ORDER_PAYLOADS_ENV: &str = "ZYLITH_ALLOW_DIRECT_PRIVATE_ORDER_PAYLOADS";
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
const DEFAULT_PUBLIC_ARTIFACT_DELAY_EPOCHS: u64 = 1;
const ARTIFACT_DELAY_EPOCHS_ENV: &str = "ZYLITH_ARTIFACT_DELAY_EPOCHS";
const PUBLIC_ARTIFACT_DELAY_EPOCHS_ENV: &str = "ZYLITH_PUBLIC_ARTIFACT_DELAY_EPOCHS";

#[derive(Clone)]
struct AppState {
    batches: Arc<RwLock<BTreeMap<String, BatchRecord>>>,
    batch_store_path: Option<Arc<PathBuf>>,
    product_config: Arc<ProductConfig>,
    recovery_artifacts: Arc<RwLock<BTreeMap<String, RecoveryAccountRecord>>>,
    recovery_store_path: Option<Arc<PathBuf>>,
    published_batch_artifacts: Arc<RwLock<BTreeMap<String, PublishedBatchArtifacts>>>,
    published_batch_artifacts_store_path: Option<Arc<PathBuf>>,
    internal_api_token: Option<Arc<String>>,
    batch_window_ms: u64,
    batch_epoch_offset: u64,
    batch_close_jitter_ms: u64,
    order_ingress_receipt_secrets: Arc<Vec<String>>,
    require_trusted_order_ingress: bool,
    allow_direct_private_order_payloads: bool,
    emergency_paused: bool,
    max_orders_per_batch: u64,
    heartbeat_cover_secret: Arc<String>,
    public_rate_limit_per_minute: u64,
    public_artifact_delay_epochs: u64,
    rate_limiter: RateLimiter,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BatchRecord {
    batch: Batch,
    order_count: u64,
    orders: Vec<SubmittedOrderRecord>,
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

#[derive(Clone, Debug)]
struct OrderIngressConfig {
    receipt_secrets: Vec<String>,
    require_trusted_ingress: bool,
    allow_direct_private_payloads: bool,
}

#[derive(Clone, Debug)]
struct BatchTimingConfig {
    window_ms: u64,
    epoch_offset: u64,
    close_jitter_ms: u64,
}

#[derive(Clone, Debug)]
struct CoordinatorHardeningConfig {
    emergency_paused: bool,
    max_body_bytes: usize,
    public_rate_limit_per_minute: u64,
    max_orders_per_batch: u64,
    heartbeat_cover_secret: String,
    public_artifact_delay_epochs: u64,
}

impl Default for CoordinatorHardeningConfig {
    fn default() -> Self {
        Self {
            emergency_paused: false,
            max_body_bytes: DEFAULT_COORDINATOR_MAX_BODY_BYTES,
            public_rate_limit_per_minute: DEFAULT_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE,
            max_orders_per_batch: DEFAULT_COORDINATOR_MAX_ORDERS_PER_BATCH,
            heartbeat_cover_secret: "test-heartbeat-cover-secret".into(),
            public_artifact_delay_epochs: 0,
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

#[derive(Clone, Debug, Serialize)]
struct MakerOrderStatus {
    batch_id: BatchId,
    order_commitment: zylith_core::OrderCommitment,
    status: String,
    received_at_unix_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RecoveryStoreFile {
    #[serde(default)]
    accounts_by_id: BTreeMap<String, RecoveryAccountRecord>,
    #[serde(default)]
    artifacts_by_account: BTreeMap<String, Vec<RecoveryArtifact>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RecoveryAccountRecord {
    recovery_auth_tag: Option<String>,
    artifacts: Vec<RecoveryArtifact>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PublishedBatchArtifactsStoreFile {
    artifacts_by_batch: BTreeMap<String, PublishedBatchArtifacts>,
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
    axum::serve(listener, app)
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

    let internal_api_token = Some(load_required_control_plane_token(
        "zylith-coordinator",
        CONTROL_PLANE_TOKEN_ENV,
    )?);
    let product_config = load_product_config()?;
    let order_ingress_receipt_secrets = load_receipt_secret_keyring();
    let require_trusted_order_ingress =
        env_bool_or_default(REQUIRE_TRUSTED_ORDER_INGRESS_ENV, true);
    let allow_direct_private_order_payloads =
        env_bool_or_default(ALLOW_DIRECT_PRIVATE_ORDER_PAYLOADS_ENV, false);
    if require_trusted_order_ingress && order_ingress_receipt_secrets.is_empty() {
        return Err(format!(
            "zylith-coordinator requires {ORDER_INGRESS_RECEIPT_SECRET_ENV} when {REQUIRE_TRUSTED_ORDER_INGRESS_ENV} is enabled"
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
    let hardening = CoordinatorHardeningConfig {
        emergency_paused: env_bool_or_default(COORDINATOR_EMERGENCY_PAUSED_ENV, false),
        max_body_bytes: env::var(COORDINATOR_MAX_BODY_BYTES_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid {COORDINATOR_MAX_BODY_BYTES_ENV}"))
            })
            .transpose()?
            .unwrap_or(DEFAULT_COORDINATOR_MAX_BODY_BYTES),
        public_rate_limit_per_minute: env::var(COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid {COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE_ENV}"))
            })
            .transpose()?
            .unwrap_or(DEFAULT_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE),
        max_orders_per_batch: env::var(COORDINATOR_MAX_ORDERS_PER_BATCH_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid {COORDINATOR_MAX_ORDERS_PER_BATCH_ENV}"))
            })
            .transpose()?
            .unwrap_or(DEFAULT_COORDINATOR_MAX_ORDERS_PER_BATCH),
        heartbeat_cover_secret: load_required_control_plane_token(
            "zylith-coordinator",
            HEARTBEAT_COVER_SECRET_ENV,
        )?,
        public_artifact_delay_epochs: env_u64_alias_or_default(
            ARTIFACT_DELAY_EPOCHS_ENV,
            PUBLIC_ARTIFACT_DELAY_EPOCHS_ENV,
            DEFAULT_PUBLIC_ARTIFACT_DELAY_EPOCHS,
        )?,
    };

    Ok(build_app_with_config(
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
            require_trusted_ingress: require_trusted_order_ingress,
            allow_direct_private_payloads: allow_direct_private_order_payloads,
        },
        hardening,
    ))
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
            receipt_secrets: Vec::new(),
            require_trusted_ingress: false,
            allow_direct_private_payloads: true,
        },
        CoordinatorHardeningConfig::default(),
    )
}

fn build_app_with_config(
    store_config: CoordinatorStoreConfig,
    internal_api_token: Option<String>,
    product_config: ProductConfig,
    batch_timing: BatchTimingConfig,
    order_ingress: OrderIngressConfig,
    hardening: CoordinatorHardeningConfig,
) -> Router {
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
    ensure_open_batches(
        &mut loaded_batches,
        &product_config,
        &enabled_pairs,
        batch_timing.window_ms,
        batch_timing.epoch_offset,
        batch_timing.close_jitter_ms,
        &hardening.heartbeat_cover_secret,
    );
    let app_state = AppState {
        batches: Arc::new(RwLock::new(loaded_batches)),
        batch_store_path: batch_store_path.map(Arc::new),
        product_config: Arc::new(product_config),
        recovery_artifacts: Arc::new(RwLock::new(
            recovery_store_path
                .as_deref()
                .map(load_recovery_store)
                .unwrap_or_default(),
        )),
        recovery_store_path: recovery_store_path.map(Arc::new),
        published_batch_artifacts: Arc::new(RwLock::new(
            published_batch_artifacts_store_path
                .as_deref()
                .map(load_published_batch_artifacts_store)
                .unwrap_or_default(),
        )),
        published_batch_artifacts_store_path: published_batch_artifacts_store_path.map(Arc::new),
        internal_api_token: internal_api_token.map(Arc::new),
        batch_window_ms: batch_timing.window_ms,
        batch_epoch_offset: batch_timing.epoch_offset,
        batch_close_jitter_ms: batch_timing.close_jitter_ms,
        order_ingress_receipt_secrets: Arc::new(order_ingress.receipt_secrets),
        require_trusted_order_ingress: order_ingress.require_trusted_ingress,
        allow_direct_private_order_payloads: order_ingress.allow_direct_private_payloads,
        emergency_paused: hardening.emergency_paused,
        max_orders_per_batch: hardening.max_orders_per_batch,
        heartbeat_cover_secret: Arc::new(hardening.heartbeat_cover_secret),
        public_rate_limit_per_minute: hardening.public_rate_limit_per_minute,
        public_artifact_delay_epochs: hardening.public_artifact_delay_epochs,
        rate_limiter: RateLimiter::default(),
    };

    Router::new()
        .route("/health", get(health))
        .route("/api/batches", get(list_batches))
        .route("/api/batches/current", get(current_batch))
        .route(
            "/api/pairs/{base}/{quote}/batches/current",
            get(current_pair_batch),
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
            "/api/attribution/{batch_id}/{maker_public_key}",
            get(get_published_maker_attribution),
        )
        .route(
            "/attribution/{batch_id}/{maker_public_key}",
            get(get_published_maker_attribution),
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
        .route("/api/orders", post(submit_order))
        .route("/api/orders/cancel", post(cancel_order))
        .route("/api/maker/orders", post(submit_maker_order))
        .route("/api/maker/orders/cancel", post(cancel_maker_order))
        .route(
            "/api/maker/orders/{order_commitment}",
            get(get_maker_order_status),
        )
        .route("/api/maker/batches/{batch_id}", get(get_maker_batch))
        .with_state(app_state)
        .layer(DefaultBodyLimit::max(hardening.max_body_bytes))
        .layer(service_cors_layer(COORDINATOR_ALLOWED_ORIGINS_ENV))
}

async fn health(State(state): State<AppState>) -> Json<CoordinatorStatus> {
    let mut batches = state.batches.write().await;
    let enabled_pairs = state.product_config.enabled_pairs();
    let changed = advance_batch_lifecycle(
        &mut batches,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    );
    if changed {
        let _ = persist_batch_store_if_configured(&state, &batches);
    }
    let current_batch_id =
        current_open_batch_for_default_pair(&state.product_config, batches.values())
            .map(|record| record.batch.batch_id.clone());

    Json(CoordinatorStatus {
        service: "zylith-coordinator".into(),
        current_batch_id,
        tracked_batches_bucket: count_bucket_label(batches.len() as u64),
        batch_window_ms: state.batch_window_ms,
        batch_close_jitter_ms: state.batch_close_jitter_ms,
    })
}

async fn list_batches(State(state): State<AppState>) -> Json<Vec<PublicBatchSummary>> {
    let mut batches = state.batches.write().await;
    let enabled_pairs = state.product_config.enabled_pairs();
    let changed = advance_batch_lifecycle(
        &mut batches,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    );
    if changed {
        let _ = persist_batch_store_if_configured(&state, &batches);
    }
    Json(batches.values().map(public_summary_from_record).collect())
}

async fn current_batch(
    State(state): State<AppState>,
) -> Result<Json<PublicBatchSummary>, StatusCode> {
    let mut batches = state.batches.write().await;
    let enabled_pairs = state.product_config.enabled_pairs();
    let changed = advance_batch_lifecycle(
        &mut batches,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    );
    if changed {
        persist_batch_store_if_configured(&state, &batches)?;
    }
    current_open_batch_for_default_pair(&state.product_config, batches.values())
        .map(public_summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn current_pair_batch(
    State(state): State<AppState>,
    Path((base, quote)): Path<(String, String)>,
) -> Result<Json<PublicBatchSummary>, StatusCode> {
    let pair_id = PairId(format!("{base}/{quote}"));
    if state.product_config.enabled_pair(&pair_id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut batches = state.batches.write().await;
    let enabled_pairs = state.product_config.enabled_pairs();
    let changed = advance_batch_lifecycle(
        &mut batches,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    );
    if changed {
        persist_batch_store_if_configured(&state, &batches)?;
    }

    current_open_batch_for_pair(batches.values(), &pair_id)
        .map(public_summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_batch(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> Result<Json<PublicBatchSummary>, StatusCode> {
    let batches = state.batches.read().await;
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
    let enabled_pairs = state.product_config.enabled_pairs();
    let changed = advance_batch_lifecycle(
        &mut batches,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    );
    if changed {
        persist_batch_store_if_configured(&state, &batches)?;
    }
    let record = batches.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(BatchOrderSet {
        batch: summary_from_record(record),
        orders: record.orders.clone(),
    }))
}

async fn get_published_transcript(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> Result<Json<PublicSettlementTranscript>, StatusCode> {
    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    if !is_public_artifact_visible(
        &artifacts,
        published,
        published.transcript.batch_epoch,
        state.public_artifact_delay_epochs,
        state.batch_window_ms,
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    public_settlement_transcript(published).map(Json)
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
    Path(batch_id): Path<String>,
) -> Result<Json<zylith_core::OutputCiphertextBundle>, StatusCode> {
    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    if !is_public_artifact_visible(
        &artifacts,
        published,
        published.transcript.batch_epoch,
        state.public_artifact_delay_epochs,
        state.batch_window_ms,
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(published.output_bundle.clone()))
}

async fn get_published_maker_attribution(
    State(state): State<AppState>,
    Path((batch_id, maker_public_key)): Path<(String, String)>,
) -> Result<Json<MakerAttributionArtifactList>, StatusCode> {
    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    if !is_public_artifact_visible(
        &artifacts,
        published,
        published.transcript.batch_epoch,
        state.public_artifact_delay_epochs,
        state.batch_window_ms,
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    let matching = published
        .maker_attribution_bundle
        .as_ref()
        .map(|bundle| {
            bundle
                .artifacts
                .iter()
                .filter(|artifact| artifact.maker_public_key == maker_public_key)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if matching.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(MakerAttributionArtifactList {
        batch_id: zylith_core::BatchId(batch_id),
        maker_public_key,
        artifacts: matching,
    }))
}

fn is_public_artifact_visible(
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
    published: &PublishedBatchArtifacts,
    batch_epoch: u64,
    delay_epochs: u64,
    batch_window_ms: u64,
) -> bool {
    if delay_epochs == 0 {
        return published.published_at_unix_ms != 0;
    }
    if published.settled_at_unix_ms.is_none() {
        return false;
    }
    let Some(max_epoch) = artifacts
        .values()
        .map(|published| published.transcript.batch_epoch)
        .max()
    else {
        return false;
    };
    let Some(cutoff) = max_epoch.checked_sub(delay_epochs) else {
        return false;
    };
    if batch_epoch <= cutoff {
        return true;
    }
    let delay_ms = delay_epochs.saturating_mul(batch_window_ms);
    published.published_at_unix_ms != 0
        && now_unix_ms() >= published.published_at_unix_ms.saturating_add(delay_ms)
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
        maker_fee_bps: published.transcript.maker_fee_bps,
        relay_fee_bps: published.transcript.relay_fee_bps,
        protocol_fee_recipient: published.transcript.protocol_fee_recipient.clone(),
        relay_fee_recipient: published.transcript.relay_fee_recipient.clone(),
        output_bundle_ref: published.transcript.output_ciphertext_bundle_ref.clone(),
        prior_note_root: roots.prior_note_root,
        prior_nullifier_root: roots.prior_nullifier_root,
        prior_renewal_root: roots.prior_renewal_root,
        prior_fee_root: roots.prior_fee_root,
        consumed_note_root: roots.consumed_note_root,
        consumed_nullifier_root: roots.consumed_nullifier_root,
        renewal_child_root: roots.renewal_child_root,
        output_note_root: roots.output_note_root,
        fee_root: roots.fee_root,
        new_note_root: roots.new_note_root,
        new_nullifier_root: roots.new_nullifier_root,
        new_renewal_root: roots.new_renewal_root,
        new_fee_root: roots.new_fee_root,
        transcript_shape,
    })
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
    if let Some(bundle) = request.maker_attribution_bundle.as_ref()
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

    let mut artifacts = state.published_batch_artifacts.write().await;
    artifacts.insert(batch_id, request.clone());

    if let Some(path) = state.published_batch_artifacts_store_path.as_deref() {
        persist_published_batch_artifacts_store(path, &artifacts)?;
    }

    Ok(Json(request))
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

    let mut artifacts = state.published_batch_artifacts.write().await;
    let published = artifacts.get_mut(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    published.settled_at_unix_ms = Some(request.settled_at_unix_ms);
    let response = published.clone();

    if let Some(path) = state.published_batch_artifacts_store_path.as_deref() {
        persist_published_batch_artifacts_store(path, &artifacts)?;
    }

    {
        let mut batches = state.batches.write().await;
        if let Some(record) = batches.get_mut(&batch_id) {
            record.batch.status = BatchStatus::Settled;
            if let Some(path) = state.batch_store_path.as_deref() {
                persist_batch_store(path, &batches)?;
            }
        }
    }

    Ok(Json(response))
}

async fn list_recovery_artifacts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Result<Json<RecoveryArtifactList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        "recovery-list",
        state.public_rate_limit_per_minute,
    )?;
    let provided_auth_tag = require_recovery_auth_header(&headers)?;
    let mut recovery_artifacts = state.recovery_artifacts.write().await;
    let mut changed = false;
    let artifacts = if let Some(account) = recovery_artifacts.get_mut(&account_id) {
        if let Some(expected) = &account.recovery_auth_tag {
            if !zylith_core::constant_time_eq(expected, &provided_auth_tag) {
                return Err(StatusCode::UNAUTHORIZED);
            }
        } else {
            account.recovery_auth_tag = Some(provided_auth_tag);
            changed = true;
        }
        account.artifacts.clone()
    } else {
        Vec::new()
    };

    if changed && let Some(path) = state.recovery_store_path.as_deref() {
        persist_recovery_store(path, &recovery_artifacts)?;
    }

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

async fn list_recovery_artifacts_range(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((account_id, start_sequence, end_sequence)): Path<(String, u64, u64)>,
) -> Result<Json<RecoveryArtifactList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
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
        Vec::new()
    };

    Ok(Json(RecoveryArtifactList {
        account_id,
        sequence_start: start_sequence,
        sequence_end: end_sequence,
        artifact_count_bucket: count_bucket_label(artifacts.len() as u64),
        artifacts,
    }))
}

async fn upload_recovery_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<RecoveryArtifactUpload>,
) -> Result<Json<RecoveryArtifact>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        "recovery-upload",
        state.public_rate_limit_per_minute,
    )?;
    if request.artifact.account_id != account_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    let provided_auth_tag = require_recovery_auth_header(&headers)?;
    let artifact = request.artifact;
    let mut recovery_artifacts = state.recovery_artifacts.write().await;
    let account = recovery_artifacts.entry(account_id).or_default();
    if let Some(expected) = &account.recovery_auth_tag {
        if !zylith_core::constant_time_eq(expected, &provided_auth_tag) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        account.recovery_auth_tag = Some(provided_auth_tag);
    }
    account.artifacts.push(artifact.clone());
    account
        .artifacts
        .sort_by_key(|entry| (entry.sequence, entry.created_at_unix_ms));

    if let Some(path) = state.recovery_store_path.as_deref() {
        persist_recovery_store(path, &recovery_artifacts)?;
    }

    Ok(Json(artifact))
}

async fn submit_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OrderSubmission>,
) -> Result<Json<OrderSubmissionAccepted>, StatusCode> {
    require_order_intake_enabled(&state)?;
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        "submit-order",
        state.public_rate_limit_per_minute,
    )?;
    submit_order_inner(state, request).await
}

async fn submit_maker_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OrderSubmission>,
) -> Result<Json<OrderSubmissionAccepted>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    require_order_intake_enabled(&state)?;
    submit_order_inner(state, request).await
}

async fn submit_order_inner(
    state: AppState,
    request: OrderSubmission,
) -> Result<Json<OrderSubmissionAccepted>, StatusCode> {
    let accepted_at_unix_ms = now_unix_ms();
    let order_bundle = coordinator_order_bundle_for_storage(&state, request.order_bundle)?;

    let mut batches = state.batches.write().await;
    let enabled_pairs = state.product_config.enabled_pairs();
    advance_batch_lifecycle(
        &mut batches,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    );
    if state
        .product_config
        .enabled_pair(&order_bundle.pair_id)
        .is_none()
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let expected_epoch =
        expected_epoch_for_pair(&batches, &order_bundle.pair_id, state.batch_epoch_offset);
    if order_bundle.epoch_id != expected_epoch {
        return Err(StatusCode::CONFLICT);
    }
    let batch_key = batch_key(&order_bundle.pair_id, expected_epoch);
    if order_bundle.batch_id.0 != batch_key {
        return Err(StatusCode::CONFLICT);
    }
    let record = batches
        .entry(batch_key.clone())
        .or_insert_with(|| BatchRecord {
            batch: empty_batch(
                &state.product_config,
                &order_bundle.pair_id,
                expected_epoch,
                accepted_at_unix_ms,
                state.batch_window_ms,
                state.batch_close_jitter_ms,
                state.heartbeat_cover_secret.as_str(),
            ),
            order_count: 0,
            orders: vec![],
        });

    if record.batch.status != BatchStatus::Open {
        return Err(StatusCode::CONFLICT);
    }
    if state.max_orders_per_batch > 0 && record.orders.len() as u64 >= state.max_orders_per_batch {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if record
        .orders
        .iter()
        .any(|order| order.order_bundle.order_commitment == order_bundle.order_commitment)
    {
        return Err(StatusCode::CONFLICT);
    }

    let accepted_batch_id = {
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
        record.batch.batch_id.clone()
    };
    persist_batch_store_if_configured(&state, &batches)?;

    Ok(Json(OrderSubmissionAccepted {
        batch_id: accepted_batch_id,
        order_commitment: order_bundle.order_commitment,
        accepted_at_unix_ms,
    }))
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

    if state.require_trusted_order_ingress {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !state.allow_direct_private_order_payloads
        && (order_bundle.transport_envelope.is_some() || !order_bundle.shares.is_empty())
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(order_bundle)
}

async fn cancel_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OrderCancellationRequest>,
) -> Result<Json<OrderCancellationAccepted>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        "cancel-order",
        state.public_rate_limit_per_minute,
    )?;
    cancel_order_inner(state, request).await
}

async fn cancel_maker_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OrderCancellationRequest>,
) -> Result<Json<OrderCancellationAccepted>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    cancel_order_inner(state, request).await
}

async fn cancel_order_inner(
    state: AppState,
    request: OrderCancellationRequest,
) -> Result<Json<OrderCancellationAccepted>, StatusCode> {
    let mut batches = state.batches.write().await;
    let enabled_pairs = state.product_config.enabled_pairs();
    advance_batch_lifecycle(
        &mut batches,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    );
    let record = batches
        .get_mut(&request.batch_id.0)
        .ok_or(StatusCode::NOT_FOUND)?;

    if record.batch.status != BatchStatus::Open {
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
    persist_batch_store_if_configured(&state, &batches)?;

    Ok(Json(OrderCancellationAccepted {
        batch_id: request.batch_id,
        order_commitment: request.order_commitment,
        cancelled_at_unix_ms: now_unix_ms(),
    }))
}

async fn get_maker_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<BatchOrderSet>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let mut batches = state.batches.write().await;
    let enabled_pairs = state.product_config.enabled_pairs();
    let changed = advance_batch_lifecycle(
        &mut batches,
        &state.product_config,
        &enabled_pairs,
        state.batch_window_ms,
        state.batch_epoch_offset,
        state.batch_close_jitter_ms,
        state.heartbeat_cover_secret.as_str(),
    );
    if changed {
        persist_batch_store_if_configured(&state, &batches)?;
    }
    let record = batches.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(BatchOrderSet {
        batch: summary_from_record(record),
        orders: record.orders.clone(),
    }))
}

async fn get_maker_order_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(order_commitment): Path<String>,
) -> Result<Json<MakerOrderStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let batches = state.batches.read().await;
    for (batch_id, record) in batches.iter() {
        if let Some(order) = record
            .orders
            .iter()
            .find(|entry| entry.order_bundle.order_commitment.0 == order_commitment)
        {
            return Ok(Json(MakerOrderStatus {
                batch_id: BatchId(batch_id.clone()),
                order_commitment: order.order_bundle.order_commitment.clone(),
                status: match record.batch.status {
                    BatchStatus::Open => "open",
                    BatchStatus::Closed => "closed",
                    BatchStatus::Clearing => "clearing",
                    BatchStatus::Settled => "settled",
                    BatchStatus::Cancelled => "cancelled",
                }
                .into(),
                received_at_unix_ms: order.received_at_unix_ms,
            }));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

fn summary_from_record(record: &BatchRecord) -> BatchSummary {
    BatchSummary {
        batch_id: record.batch.batch_id.clone(),
        pair_id: record.batch.pair_id.clone(),
        epoch_id: record.batch.epoch_id,
        close_time_unix_ms: record.batch.close_time_unix_ms,
        status: record.batch.status.clone(),
        order_count: heartbeat_cover_order_count(record.orders.len()) as u64,
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
        ),
    }
}

fn load_product_config() -> Result<ProductConfig, String> {
    let mut product_config = if let Ok(value) =
        env::var(PRODUCT_PAIRS_ENV).or_else(|_| env::var(COORDINATOR_PAIR_IDS_ENV))
    {
        ProductConfig::from_enabled_pair_ids_csv(&value)
            .map_err(|error| format!("configured product pairs are invalid: {error}"))?
    } else {
        ProductConfig::from_enabled_pair_ids_csv(DEFAULT_PAIR_IDS)
            .map_err(|error| format!("default coordinator pairs are invalid: {error}"))?
    };
    if let Ok(value) = env::var(HEARTBEAT_COVER_PRICES_ENV) {
        product_config
            .apply_heartbeat_cover_prices_csv(&value)
            .map_err(|error| format!("configured heartbeat cover prices are invalid: {error}"))?;
    }
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

fn env_u64_alias_or_default(primary: &str, fallback: &str, default: u64) -> Result<u64, String> {
    if env::var(primary)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_some()
    {
        return env_u64_or_default(primary, default);
    }
    env_u64_or_default(fallback, default)
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

fn require_order_intake_enabled(state: &AppState) -> Result<(), StatusCode> {
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
        .max_by_key(|record| {
            (
                record.batch.epoch_id,
                record.batch.close_time_unix_ms,
                record.order_count,
            )
        })
}

fn advance_batch_lifecycle(
    batches: &mut BTreeMap<String, BatchRecord>,
    product_config: &ProductConfig,
    enabled_pairs: &[PairId],
    batch_window_ms: u64,
    batch_epoch_offset: u64,
    batch_close_jitter_ms: u64,
    heartbeat_cover_secret: &str,
) -> bool {
    let mut changed = close_expired_open_batches(batches);
    if ensure_open_batches(
        batches,
        product_config,
        enabled_pairs,
        batch_window_ms,
        batch_epoch_offset,
        batch_close_jitter_ms,
        heartbeat_cover_secret,
    ) {
        changed = true;
    }
    changed
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
) -> bool {
    let mut changed = false;
    for pair_id in enabled_pairs {
        if pair_has_open_batch(batches.values(), pair_id) {
            continue;
        }

        let epoch_id = expected_epoch_for_pair(batches, pair_id, batch_epoch_offset);
        let close_time_unix_ms = now_unix_ms();
        batches.insert(
            batch_key(pair_id, epoch_id),
            BatchRecord {
                batch: empty_batch(
                    product_config,
                    pair_id,
                    epoch_id,
                    close_time_unix_ms,
                    batch_window_ms,
                    batch_close_jitter_ms,
                    heartbeat_cover_secret,
                ),
                order_count: 0,
                orders: vec![],
            },
        );
        changed = true;
    }
    changed
}

fn pair_has_open_batch<'a>(
    mut batches: impl Iterator<Item = &'a BatchRecord>,
    pair_id: &PairId,
) -> bool {
    batches
        .any(|record| record.batch.pair_id == *pair_id && record.batch.status == BatchStatus::Open)
}

fn expected_epoch_for_pair(
    batches: &BTreeMap<String, BatchRecord>,
    pair_id: &PairId,
    batch_epoch_offset: u64,
) -> u64 {
    if let Some(open_batch) = batches
        .values()
        .filter(|record| {
            record.batch.pair_id == *pair_id && record.batch.status == BatchStatus::Open
        })
        .max_by_key(|record| record.batch.epoch_id)
    {
        return open_batch.batch.epoch_id;
    }

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
) -> Batch {
    let batch_id = BatchId(batch_key(pair_id, epoch_id));
    let (order_commitment_root, encrypted_order_set_commitment) = compute_batch_commitments_for(
        product_config,
        heartbeat_cover_secret,
        pair_id,
        &batch_id,
        epoch_id,
        &[],
    )
    .unwrap_or_else(|_| ("".into(), "".into()));
    let close_jitter_ms =
        deterministic_batch_close_jitter_ms(pair_id, epoch_id, batch_close_jitter_ms);
    Batch {
        batch_id,
        pair_id: pair_id.clone(),
        epoch_id,
        close_time_unix_ms: opened_at_unix_ms + batch_window_ms + close_jitter_ms,
        status: BatchStatus::Open,
        order_commitment_root,
        encrypted_order_set_commitment,
    }
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
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::default();
    };

    serde_json::from_str::<BatchStoreFile>(&contents)
        .map(|store| store.batches_by_id)
        .unwrap_or_default()
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

fn load_recovery_store(path: &FsPath) -> BTreeMap<String, RecoveryAccountRecord> {
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::default();
    };

    serde_json::from_str::<RecoveryStoreFile>(&contents)
        .map(|store| {
            if !store.accounts_by_id.is_empty() {
                store.accounts_by_id
            } else {
                store
                    .artifacts_by_account
                    .into_iter()
                    .map(|(account_id, artifacts)| {
                        (
                            account_id,
                            RecoveryAccountRecord {
                                recovery_auth_tag: None,
                                artifacts,
                            },
                        )
                    })
                    .collect()
            }
        })
        .unwrap_or_default()
}

fn load_published_batch_artifacts_store(
    path: &FsPath,
) -> BTreeMap<String, PublishedBatchArtifacts> {
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::default();
    };

    serde_json::from_str::<PublishedBatchArtifactsStoreFile>(&contents)
        .map(|store| store.artifacts_by_batch)
        .unwrap_or_default()
}

fn persist_recovery_store(
    path: &FsPath,
    accounts: &BTreeMap<String, RecoveryAccountRecord>,
) -> Result<(), StatusCode> {
    let encoded = serde_json::to_string_pretty(&RecoveryStoreFile {
        accounts_by_id: accounts.clone(),
        artifacts_by_account: BTreeMap::new(),
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    atomic_write(path, &encoded)
}

fn persist_published_batch_artifacts_store(
    path: &FsPath,
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
) -> Result<(), StatusCode> {
    let encoded = serde_json::to_string_pretty(&PublishedBatchArtifactsStoreFile {
        artifacts_by_batch: artifacts.clone(),
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    atomic_write(path, &encoded)
}

fn atomic_write(path: &FsPath, contents: &str) -> Result<(), StatusCode> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
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

#[cfg(test)]
mod tests {
    use super::{
        BatchRecord, BatchTimingConfig, DEFAULT_BATCH_WINDOW_MS, OrderIngressConfig,
        build_app_with_config, build_app_with_paths, close_expired_open_batches,
        deterministic_batch_close_jitter_ms, empty_batch, now_unix_ms,
    };
    use axum::http::StatusCode;
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use http_body_util::BodyExt;
    use std::{collections::BTreeMap, path::PathBuf};
    use tower::ServiceExt;
    use zylith_core::{
        EncryptedRecoveryPayload, OrderCancellationRequest, OrderShareBundle, OrderSubmission,
        PairId, ProductConfig, PublishedBatchArtifacts, RecoveryArtifact, RecoveryArtifactKind,
        RecoveryArtifactUpload, create_order_ingress_receipt, derive_order_cancellation_tag,
    };

    const TEST_INTERNAL_TOKEN: &str = "test-control-plane-token";
    const TEST_RECOVERY_AUTH: &str = "test-recovery-auth";

    fn auth_request(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
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
        );
        batch.close_time_unix_ms = 1;
        let mut batches = BTreeMap::from([(
            batch.batch_id.0.clone(),
            BatchRecord {
                batch,
                order_count: 0,
                orders: Vec::new(),
            },
        )]);

        assert!(close_expired_open_batches(&mut batches));
        let record = batches.values().next().expect("closed batch");
        assert_eq!(record.batch.status, zylith_core::BatchStatus::Closed);
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = build_app_with_paths(None, None, None, None);

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
            ProductConfig::default()
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
                receipt_secrets: Vec::new(),
                require_trusted_ingress: false,
                allow_direct_private_payloads: true,
            },
            super::CoordinatorHardeningConfig::default(),
        );

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
        assert_eq!(json["batch_id"], "batch-strk-eth-1");
    }

    #[tokio::test]
    async fn order_submission_increments_batch_order_count() {
        let app = build_app_with_paths(None, None, None, None);
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x111".into()),
                cancellation_auth_tag: "cancel-tag-1".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
                epoch_id: 1,
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
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
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
                require_trusted_ingress: true,
                allow_direct_private_payloads: false,
            },
            super::CoordinatorHardeningConfig::default(),
        );
        let mut full_bundle = OrderShareBundle {
            order_commitment: zylith_core::OrderCommitment("0xabc".into()),
            cancellation_auth_tag: "cancel-tag-receipt".into(),
            pair_id: PairId("STRK/USDC".into()),
            batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
            epoch_id: 1,
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
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
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
                        .uri("/api/internal/batches/batch-strk-usdc-1/orders")
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
    async fn duplicate_order_commitments_are_rejected_in_open_batch() {
        let app = build_app_with_paths(None, None, None, None);
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x222".into()),
                cancellation_auth_tag: "cancel-tag-duplicate".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
                epoch_id: 1,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
                    ))
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
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
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
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
                    ))
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
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
                    ))
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
        assert_eq!(json["batch_id"], "batch-strk-usdc-1");
        assert_eq!(json["order_count_bucket"], "0-7");
    }

    #[tokio::test]
    async fn internal_batch_orders_endpoint_returns_stored_orders() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x666".into()),
                cancellation_auth_tag: "cancel-tag-2".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
                epoch_id: 1,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        let response = app
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
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x777".into()),
                cancellation_auth_tag: derive_order_cancellation_tag("cancel-secret-3"),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
                epoch_id: 1,
                transport_envelope: None,
                ingress_receipt: None,
                shares: vec![],
            },
        };

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/orders")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        let cancellation = OrderCancellationRequest {
            batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
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
        let output_bundle = zylith_core::OutputCiphertextBundle::from_ciphertexts(
            zylith_core::BatchId(batch_id.into()),
            "da-ref",
            vec![],
        )
        .expect("output bundle");
        let output_bundle_ref = output_bundle.bundle_commitment.clone();
        let output_recovery_dummy_commitments = output_bundle
            .ciphertexts
            .iter()
            .filter_map(|ciphertext| {
                ciphertext
                    .recovery
                    .as_ref()
                    .map(|recovery| recovery.commitment.clone())
            })
            .collect::<Vec<_>>();
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
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                relay_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-treasury".into(),
                relay_fee_recipient: "zylith-renewal-relay".into(),
                matched_orders: vec![],
                consumed_inputs: vec![],
                renewal_child_uses: vec![],
                fees: vec![],
                output_notes: vec![],
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: output_recovery_dummy_commitments.clone(),
                output_ciphertext_bundle_ref: output_bundle_ref.clone(),
            },
            output_bundle,
            maker_attribution_bundle: None,
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
                new_nullifier_root: "0x0".into(),
                new_renewal_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
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
                privacy_gate: Default::default(),
                renewal_child_uses: vec![],
                fees: vec![],
                output_notes: vec![],
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments,
                output_ciphertext_bundle_ref: output_bundle_ref.clone(),
            },
            published_at_unix_ms: now_unix_ms(),
            settled_at_unix_ms: None,
            order_execution_reports: vec![],
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

        assert_eq!(response.status(), StatusCode::OK);

        let settled_response = app
            .clone()
            .oneshot(
                auth_request(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/settled-at"))
                        .method(Method::POST),
                )
                .header("content-type", "application/json")
                .body(Body::from(r#"{"settled_at_unix_ms":1778661520000}"#))
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(settled_response.status(), StatusCode::OK);

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
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("0x333".into()),
                cancellation_auth_tag: "cancel-tag-persisted".into(),
                pair_id: PairId("STRK/USDC".into()),
                batch_id: zylith_core::BatchId("batch-strk-usdc-1".into()),
                epoch_id: 1,
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
                    .body(Body::from(
                        serde_json::to_vec(&submission).expect("serialize submission"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let persisted = std::fs::read_to_string(&temp_path).expect("persisted file");
        let json = serde_json::from_str::<serde_json::Value>(&persisted).expect("persisted json");
        let batch = &json["batches_by_id"]["batch-strk-usdc-1"];
        assert_eq!(batch["order_count"], 1);
        assert_ne!(batch["batch"]["order_commitment_root"], "todo-order-root");
        assert_ne!(
            batch["batch"]["encrypted_order_set_commitment"],
            "todo-ciphertext-root"
        );
        let _ = std::fs::remove_file(temp_path);
    }

    #[tokio::test]
    async fn internal_routes_require_control_plane_bearer_token() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/internal/batches/batch-strk-usdc-1/orders")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

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
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    env, fs,
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
use ipnet::IpNet;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use starknet_rust_core::utils::get_selector_from_name;
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use zylith_core::{
    ARTIFACT_AGGREGATION_POLICY_VERSION, ArtifactAggregationPolicy, CONTROL_PLANE_TOKEN_ENV,
    ClaimWindowPolicy, DeploymentManifest, DepositActivationRecord, DepositActivationRecordList,
    DepositConfirmationList, DepositConfirmationRequest, DepositSyncStatus,
    MultiPairArtifactBundleList, MultiPairArtifactBundleSummary, OutputCiphertextBundle,
    PublicSettlementTranscript, PublishedBatchArtifactList, PublishedBatchArtifactSummary,
    PublishedBatchArtifacts, SettlementRootHistoryArchive, SettlementRootHistoryBatch,
    SettlementTimestampUpdate, SettlementTranscript, WithdrawalAmountBucketPolicy,
    artifact_bundle_padded_count, artifact_epoch_bucket_end, artifact_epoch_bucket_start,
    count_bucket_label, extract_bearer_token,
    hash::{encode_starknet_felt, normalize_felt_hex},
    root_only_settlement_commitments, settlement_transcript_commitment, transcript_shape_metadata,
};

static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

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

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:5050/rpc/v0_8";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3300";
const DEFAULT_DEPLOYMENT_MANIFEST_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../client/public/deployment.json"
);
const DEFAULT_COMMITMENT_REGISTRY_ADDRESS: &str = "";
const DEFAULT_ARTIFACT_ARCHIVE_PATH: &str = "indexer/published_batch_artifacts.dev.json";
const DEFAULT_BATCH_WINDOW_MS: u64 = 20_000;
const DEFAULT_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS: u64 = 14;
const DEFAULT_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS: u64 = 36;
const DEFAULT_ARTIFACT_EPOCH_BUCKET_SIZE: u64 = 8;
const ARTIFACT_DELAY_MIN_EPOCHS_ENV: &str = "ZYLITH_ARTIFACT_DELAY_MIN_EPOCHS";
const ARTIFACT_DELAY_MAX_EPOCHS_ENV: &str = "ZYLITH_ARTIFACT_DELAY_MAX_EPOCHS";
const INDEXER_ALLOWED_ORIGINS_ENV: &str = "ZYLITH_INDEXER_ALLOWED_ORIGINS";
const INDEXER_SYNC_INTERVAL_MS_ENV: &str = "ZYLITH_INDEXER_SYNC_INTERVAL_MS";
const AUCTION_VERIFIER_ADDRESS_ENV: &str = "ZYLITH_AUCTION_VERIFIER_ADDRESS";
const INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE_ENV: &str =
    "ZYLITH_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE";
const INDEXER_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS_ENV: &str =
    "ZYLITH_INDEXER_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS";
const DEFAULT_INDEXER_SYNC_INTERVAL_MS: u64 = 15_000;
const MAX_PUBLIC_HISTORY_RANGE_SPAN: u64 = 10_000;
const MAX_PUBLIC_TRANSCRIPT_BATCH_IDS: usize = 128;
const DEFAULT_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE: u64 = 120;
const DEFAULT_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS: u64 = 128;
const DEFAULT_INDEXER_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const DEPOSIT_SYNC_ROLLBACK_WINDOW: u64 = 64;
const DEFAULT_HTTP_CLIENT_TIMEOUT_SECS: u64 = 30;
const MAX_STARKNET_RPC_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_DEPLOYMENT_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ARTIFACT_STORE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    rpc_url: String,
    commitment_registry_address: String,
    funding_activation_count_selector: String,
    funding_activation_record_selector: String,
    http_client: reqwest::Client,
    confirmed_deposits: Arc<RwLock<BTreeMap<String, DepositActivationRecord>>>,
    synced_deposit_count: Arc<RwLock<u64>>,
    last_successful_sync_unix_ms: Arc<RwLock<u64>>,
    published_batch_artifacts: Arc<RwLock<BTreeMap<String, PublishedBatchArtifacts>>>,
    artifact_archive_path: Option<Arc<PathBuf>>,
    internal_api_token: Option<Arc<String>>,
    batch_window_ms: u64,
    public_artifact_delay_min_epochs: u64,
    public_artifact_delay_max_epochs: u64,
    artifact_epoch_bucket_size: u64,
    require_artifact_onchain_verification: bool,
    output_note_root_selector: String,
    verified_auction_transcript_selector: String,
    auction_verifier_address: Option<Arc<String>>,
    rate_limiter: RateLimiter,
    public_rate_limit_per_minute: u64,
    max_deposit_confirmation_commitments: usize,
}

fn service_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_CLIENT_TIMEOUT_SECS))
        .build()
        .expect("failed to build indexer HTTP client")
}

#[derive(Clone, Default)]
struct RateLimiter {
    buckets: Arc<Mutex<BTreeMap<String, RateLimitBucket>>>,
}

struct RateLimitBucket {
    window_started_unix_ms: u64,
    count: u64,
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

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishedBatchArtifactsStoreFile {
    artifacts_by_batch: BTreeMap<String, PublishedBatchArtifacts>,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let artifact_archive_path = env::var("ZYLITH_INDEXER_ARTIFACT_PATH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(DEFAULT_ARTIFACT_ARCHIVE_PATH)));
    let public_artifact_delay_min_epochs = load_u64_env(
        ARTIFACT_DELAY_MIN_EPOCHS_ENV,
        DEFAULT_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS,
        0,
    )?;
    let public_artifact_delay_max_epochs = load_u64_env(
        ARTIFACT_DELAY_MAX_EPOCHS_ENV,
        DEFAULT_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS,
        public_artifact_delay_min_epochs,
    )?
    .max(public_artifact_delay_min_epochs);
    let require_artifact_onchain_verification = true;
    if allowed_origins_from_env(INDEXER_ALLOWED_ORIGINS_ENV).is_none() {
        return Err(format!("{INDEXER_ALLOWED_ORIGINS_ENV} is required"));
    }
    let auction_verifier_address = load_auction_verifier_address()?;
    if require_artifact_onchain_verification {
        let configured = auction_verifier_address
            .as_deref()
            .and_then(|address| normalize_felt_hex(address).ok())
            .filter(|address| address != "0x0");
        if configured.is_none() {
            return Err(
                "artifact on-chain verification requires a nonzero ZYLITH_AUCTION_VERIFIER_ADDRESS"
                    .to_string(),
            );
        }
    }
    let state = AppState {
        rpc_url: load_rpc_url()?,
        commitment_registry_address: load_commitment_registry_address()?,
        funding_activation_count_selector: selector_hex("funding_activation_count"),
        funding_activation_record_selector: selector_hex("funding_activation_record"),
        http_client: service_http_client(),
        confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
        synced_deposit_count: Arc::new(RwLock::new(0)),
        last_successful_sync_unix_ms: Arc::new(RwLock::new(0)),
        published_batch_artifacts: Arc::new(RwLock::new(
            artifact_archive_path
                .as_deref()
                .map(load_published_batch_artifacts_store)
                .unwrap_or_default(),
        )),
        artifact_archive_path: artifact_archive_path.map(Arc::new),
        internal_api_token: Some(Arc::new(load_required_control_plane_token(
            "zylith-indexer",
            CONTROL_PLANE_TOKEN_ENV,
        )?)),
        batch_window_ms: load_u64_env("ZYLITH_BATCH_WINDOW_MS", DEFAULT_BATCH_WINDOW_MS, 1_000)?,
        public_artifact_delay_min_epochs,
        public_artifact_delay_max_epochs,
        artifact_epoch_bucket_size: load_u64_env(
            "ZYLITH_ARTIFACT_EPOCH_BUCKET_SIZE",
            DEFAULT_ARTIFACT_EPOCH_BUCKET_SIZE,
            1,
        )?,
        require_artifact_onchain_verification,
        output_note_root_selector: selector_hex("output_note_root"),
        verified_auction_transcript_selector: selector_hex("verified_auction_transcript"),
        auction_verifier_address: auction_verifier_address.map(Arc::new),
        rate_limiter: RateLimiter::default(),
        public_rate_limit_per_minute: load_u64_env(
            INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE_ENV,
            DEFAULT_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE,
            1,
        )?,
        max_deposit_confirmation_commitments: load_u64_env(
            INDEXER_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS_ENV,
            DEFAULT_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS,
            1,
        )? as usize,
    };

    if let Err(status) = sync_deposits(&state).await {
        eprintln!("indexer startup deposit sync skipped: {status}");
    }

    let sync_interval_ms = load_u64_env(
        INDEXER_SYNC_INTERVAL_MS_ENV,
        DEFAULT_INDEXER_SYNC_INTERVAL_MS,
        1_000,
    )?;
    spawn_background_sync(state.clone(), sync_interval_ms);

    let app = build_app_with_state(state);

    let bind_addr =
        env::var("ZYLITH_INDEXER_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.into());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|error| format!("failed to bind indexer on {bind_addr}: {error}"))?;

    println!("Zylith indexer listening on http://{bind_addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("indexer service failed: {error}"))
}

fn build_app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/internal/sync/deposits", post(sync_deposits_endpoint))
        .route(
            "/api/deposits/range/{start}/{end}",
            get(list_confirmed_deposits_range),
        )
        .route("/api/batches/artifacts", get(list_archived_batch_artifacts))
        .route(
            "/api/batches/artifacts/epochs/{start_epoch}/{end_epoch}",
            get(list_archived_batch_artifacts_by_epoch_range),
        )
        .route(
            "/api/batches/artifact-bundles",
            get(list_multi_pair_artifact_bundles),
        )
        .route(
            "/api/batches/artifact-bundles/epochs/{start_epoch}/{end_epoch}",
            get(list_multi_pair_artifact_bundles_by_epoch_range),
        )
        .route("/api/batches/transcripts", get(list_archived_transcripts))
        .route(
            "/api/internal/batches/root-history/epochs/{start_epoch}/{end_epoch}",
            get(list_internal_root_history_by_epoch_range),
        )
        .route(
            "/api/privacy/claim-window-policy",
            get(get_claim_window_policy),
        )
        .route(
            "/api/privacy/withdrawal-amount-bucket-policy",
            get(get_withdrawal_amount_bucket_policy),
        )
        .route(
            "/api/privacy/artifact-aggregation-policy",
            get(get_artifact_aggregation_policy),
        )
        .route(
            "/api/batches/{batch_id}/transcript",
            get(get_archived_transcript),
        )
        .route(
            "/api/internal/batches/{batch_id}/transcript",
            get(get_internal_archived_transcript),
        )
        .route(
            "/api/batches/{batch_id}/output-bundle",
            get(get_archived_output_bundle),
        )
        .route(
            "/api/internal/batches/{batch_id}/artifacts",
            post(publish_batch_artifacts),
        )
        .route(
            "/api/internal/batches/{batch_id}/settled-at",
            post(mark_published_batch_settled),
        )
        .route("/api/deposits/confirmations", post(confirm_deposits))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state,
            internal_route_auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(DEFAULT_INDEXER_MAX_BODY_BYTES))
        .layer(service_cors_layer(INDEXER_ALLOWED_ORIGINS_ENV))
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

fn spawn_background_sync(state: AppState, interval_ms: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        loop {
            interval.tick().await;
            if let Err(status) = sync_deposits(&state).await {
                eprintln!("indexer background deposit sync skipped: {status}");
            }
        }
    });
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
        None => {
            #[cfg(test)]
            {
                base.allow_origin(AllowOrigin::list(vec![HeaderValue::from_static(
                    "https://app.zylith.test",
                )]))
            }
            #[cfg(not(test))]
            {
                panic!("{env_name} is required");
            }
        }
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

fn load_rpc_url() -> Result<String, String> {
    let deployment_manifest = load_deployment_manifest()?;
    if let Ok(rpc_url) = env::var("ZYLITH_STARKNET_RPC_URL")
        && let Some(rpc_url) = nonempty_string(Some(&rpc_url))
    {
        return Ok(rpc_url);
    }

    if let Some(rpc_url) = deployment_manifest
        .as_ref()
        .and_then(|manifest| nonempty_string(Some(&manifest.rpc_url)))
    {
        return Ok(rpc_url);
    }

    if indexer_production_mode() {
        return Err(
            "ZYLITH_STARKNET_RPC_URL or deployment manifest rpc_url is required in production"
                .into(),
        );
    }
    Ok(DEFAULT_RPC_URL.into())
}

fn load_commitment_registry_address() -> Result<String, String> {
    let manifest_address =
        load_deployment_manifest()?.map(|manifest| manifest.contracts.commitment_registry);
    let selected = nonempty_string(
        env::var("ZYLITH_COMMITMENT_REGISTRY_ADDRESS")
            .ok()
            .as_deref(),
    )
    .or_else(|| manifest_address.and_then(|address| nonempty_string(Some(&address))));
    match selected {
        Some(address) if !indexer_production_mode() || is_configured_felt(&address) => Ok(address),
        Some(_) => Err(
            "ZYLITH_COMMITMENT_REGISTRY_ADDRESS or manifest commitment_registry must be nonzero in production".into()
        ),
        None if indexer_production_mode() => Err(
            "ZYLITH_COMMITMENT_REGISTRY_ADDRESS or manifest commitment_registry is required in production".into()
        ),
        None => Ok(DEFAULT_COMMITMENT_REGISTRY_ADDRESS.into()),
    }
}

fn load_auction_verifier_address() -> Result<Option<String>, String> {
    let manifest_address = load_deployment_manifest()?
        .and_then(|manifest| nonempty_string(Some(&manifest.contracts.auction_verifier)));
    Ok(
        nonempty_string(env::var(AUCTION_VERIFIER_ADDRESS_ENV).ok().as_deref())
            .or(manifest_address)
            .filter(|address| is_configured_felt(address)),
    )
}

fn nonempty_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn load_u64_env(name: &str, default_value: u64, minimum_value: u64) -> Result<u64, String> {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(_) => return Ok(default_value),
    };
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an integer >= {minimum_value}"))?;
    if parsed < minimum_value {
        return Err(format!("{name} must be an integer >= {minimum_value}"));
    }
    Ok(parsed)
}

fn indexer_production_mode() -> bool {
    env::var("ZYLITH_INDEXER_STRICT")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        || env::var("ZYLITH_ENV")
            .ok()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("production"))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn load_deployment_manifest() -> Result<Option<DeploymentManifest>, String> {
    let explicit_path = env::var("ZYLITH_DEPLOYMENT_MANIFEST").ok();
    let manifest_path = explicit_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DEPLOYMENT_MANIFEST_PATH));
    let manifest = match read_utf8_file_limited(&manifest_path, MAX_DEPLOYMENT_MANIFEST_BYTES) {
        Ok(manifest) => manifest,
        Err(error) if explicit_path.is_some() || indexer_production_mode() => {
            return Err(format!(
                "failed to read deployment manifest {}: {error}",
                manifest_path.display()
            ));
        }
        Err(_) => return Ok(None),
    };
    parse_deployment_manifest(&manifest)
        .map(Some)
        .map_err(|error| {
            format!(
                "failed to parse deployment manifest {}: {error}",
                manifest_path.display()
            )
        })
}

fn parse_deployment_manifest(contents: &str) -> Result<DeploymentManifest, serde_json::Error> {
    let value = serde_json::from_str::<serde_json::Value>(contents)?;
    let manifest = value.get("manifest").cloned().unwrap_or(value);
    serde_json::from_value(manifest)
}

fn selector_hex(name: &str) -> String {
    get_selector_from_name(name)
        .map(|selector| format!("{selector:#x}"))
        .unwrap_or_else(|_| panic!("invalid Starknet selector name '{name}'"))
}

fn is_configured_felt(value: &str) -> bool {
    normalize_felt_hex(value).is_ok_and(|normalized| normalized != "0x0")
}

fn load_published_batch_artifacts_store(
    path: &FsPath,
) -> BTreeMap<String, PublishedBatchArtifacts> {
    let contents = match read_utf8_file_limited(path, MAX_ARTIFACT_STORE_BYTES) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return BTreeMap::default(),
        Err(error) => {
            panic!(
                "failed to read published batch artifacts store {}: {error}",
                path.display()
            )
        }
    };

    serde_json::from_str::<PublishedBatchArtifactsStoreFile>(&contents)
        .map(|store| store.artifacts_by_batch)
        .unwrap_or_else(|error| {
            panic!(
                "failed to parse published batch artifacts store {}: {error}",
                path.display()
            )
        })
}

fn read_utf8_file_limited(path: &FsPath, max_bytes: u64) -> std::io::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} bytes"),
        ));
    }
    fs::read_to_string(path)
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

fn published_batch_artifact_summary(
    published: &PublishedBatchArtifacts,
) -> Option<PublishedBatchArtifactSummary> {
    let roots = root_only_settlement_commitments(&published.transcript).ok()?;
    let shape = published.transcript_shape.clone().unwrap_or_else(|| {
        transcript_shape_metadata(&published.transcript, &published.output_bundle)
    });

    Some(PublishedBatchArtifactSummary {
        batch_id: published.transcript.batch_id.clone(),
        pair_id: published.transcript.pair_id.clone(),
        batch_epoch: published.transcript.batch_epoch,
        published_at_unix_ms: published.published_at_unix_ms,
        settled_at_unix_ms: published.settled_at_unix_ms,
        transcript_commitment: published.settlement_witness.transcript_commitment.clone(),
        output_bundle_ref: published.transcript.output_ciphertext_bundle_ref.clone(),
        output_note_root: roots.output_note_root,
        bundle_commitment: published.output_bundle.bundle_commitment.clone(),
        data_availability_ref: published.output_bundle.data_availability_ref.clone(),
        ciphertext_count_bucket: published.output_bundle.ciphertext_count_bucket.clone(),
        padded_ciphertext_count: published.output_bundle.padded_ciphertext_count,
        matched_order_count_bucket: shape.matched_order_count_bucket,
        consumed_input_count_bucket: shape.consumed_input_count_bucket,
        renewal_child_count_bucket: shape.renewal_child_count_bucket,
        fee_count_bucket: shape.fee_count_bucket,
        output_note_count_bucket: shape.output_note_count_bucket,
        transcript_shape_policy_version: shape.policy_version,
    })
}

fn artifact_aggregation_policy(state: &AppState) -> ArtifactAggregationPolicy {
    ArtifactAggregationPolicy {
        policy_version: ARTIFACT_AGGREGATION_POLICY_VERSION,
        public_artifact_delay_epochs: state.public_artifact_delay_max_epochs,
        public_artifact_delay_min_epochs: state.public_artifact_delay_min_epochs,
        public_artifact_delay_max_epochs: state.public_artifact_delay_max_epochs,
        epoch_bucket_size: state.artifact_epoch_bucket_size,
        aggregation_scope: "multi_pair_epoch_bucket".into(),
        proof_aggregation_mode: "native_aggregate_proof_facts_when_prover_configured".into(),
    }
}

fn public_visible_epoch_cutoff(
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
) -> Option<u64> {
    let max_epoch = artifacts
        .values()
        .map(|published| published.transcript.batch_epoch)
        .max()?;
    Some(max_epoch)
}

fn validate_public_history_range(start: u64, end: u64) -> Result<(), StatusCode> {
    if start > end || end.saturating_sub(start) >= MAX_PUBLIC_HISTORY_RANGE_SPAN {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

fn latest_public_history_window(
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
) -> (u64, u64) {
    let end_epoch = public_visible_epoch_cutoff(artifacts).unwrap_or(0);
    let start_epoch = end_epoch.saturating_sub(MAX_PUBLIC_HISTORY_RANGE_SPAN.saturating_sub(1));
    (start_epoch, end_epoch)
}

fn effective_public_artifact_delay_epochs(
    delay_subject: &str,
    min_delay_epochs: u64,
    max_delay_epochs: u64,
) -> u64 {
    if max_delay_epochs <= min_delay_epochs {
        return min_delay_epochs;
    }
    let Ok(digest) = zylith_core::hash::tagged_commitment_sha256(
        "zylith/artifact-delay-jitter-v1",
        &delay_subject,
    ) else {
        return min_delay_epochs;
    };
    let hex = digest.trim_start_matches("0x");
    let prefix = hex.get(..16).unwrap_or(hex);
    let entropy = u64::from_str_radix(prefix, 16).unwrap_or(0);
    min_delay_epochs + (entropy % (max_delay_epochs - min_delay_epochs + 1))
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
    let release_epoch = bucket_end.saturating_add(delay_epochs);
    if public_visible_epoch_cutoff(artifacts)
        .map(|max_epoch| max_epoch >= release_epoch)
        .unwrap_or(false)
    {
        return true;
    }
    let release_delay_epochs = release_epoch.saturating_sub(batch_epoch);
    let delay_ms = release_delay_epochs.saturating_mul(batch_window_ms);
    published.published_at_unix_ms != 0
        && now_unix_ms() >= published.published_at_unix_ms.saturating_add(delay_ms)
}

fn public_artifact_summaries_for_epoch_range(
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
    min_delay_epochs: u64,
    max_delay_epochs: u64,
    artifact_epoch_bucket_size: u64,
    batch_window_ms: u64,
    start_epoch: u64,
    end_epoch: u64,
) -> Vec<PublishedBatchArtifactSummary> {
    let mut summaries = artifacts
        .values()
        .filter(|published| {
            let epoch = published.transcript.batch_epoch;
            epoch >= start_epoch
                && epoch <= end_epoch
                && is_public_artifact_visible(
                    artifacts,
                    published,
                    epoch,
                    min_delay_epochs,
                    max_delay_epochs,
                    artifact_epoch_bucket_size,
                    batch_window_ms,
                )
        })
        .filter_map(published_batch_artifact_summary)
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        left.batch_epoch
            .cmp(&right.batch_epoch)
            .then_with(|| left.pair_id.0.cmp(&right.pair_id.0))
            .then_with(|| left.batch_id.0.cmp(&right.batch_id.0))
    });
    summaries
}

fn public_artifact_complete_through_epoch(
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
    min_delay_epochs: u64,
    max_delay_epochs: u64,
    artifact_epoch_bucket_size: u64,
    start_epoch: u64,
    end_epoch: u64,
) -> Option<u64> {
    if start_epoch > end_epoch {
        return None;
    }
    let visible_cutoff = public_visible_epoch_cutoff(artifacts)?;
    let mut epoch = start_epoch;
    let mut complete_through = None;
    loop {
        let bucket_start = artifact_epoch_bucket_start(epoch, artifact_epoch_bucket_size).ok()?;
        let bucket_end =
            artifact_epoch_bucket_end(bucket_start, artifact_epoch_bucket_size).ok()?;
        let bucket_has_artifact = artifacts.values().any(|published| {
            let artifact_epoch = published.transcript.batch_epoch;
            artifact_epoch >= bucket_start && artifact_epoch <= bucket_end
        });
        if !bucket_has_artifact {
            break;
        }
        let delay_subject = format!("{bucket_start}:{bucket_end}");
        let delay_epochs = effective_public_artifact_delay_epochs(
            &delay_subject,
            min_delay_epochs,
            max_delay_epochs,
        );
        let release_epoch = bucket_end.saturating_add(delay_epochs);
        if visible_cutoff < release_epoch {
            break;
        }
        complete_through = Some(bucket_end.min(end_epoch));
        if bucket_end >= end_epoch {
            break;
        }
        epoch = bucket_end.saturating_add(1);
    }
    complete_through
}

fn multi_pair_artifact_bundles_for_epoch_range(
    policy: &ArtifactAggregationPolicy,
    summaries: Vec<PublishedBatchArtifactSummary>,
) -> Result<Vec<MultiPairArtifactBundleSummary>, StatusCode> {
    let mut buckets = BTreeMap::<u64, Vec<PublishedBatchArtifactSummary>>::new();
    for summary in summaries {
        let bucket_start =
            artifact_epoch_bucket_start(summary.batch_epoch, policy.epoch_bucket_size)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        buckets.entry(bucket_start).or_default().push(summary);
    }

    let mut bundles = Vec::with_capacity(buckets.len());
    for (epoch_start, mut members) in buckets {
        members.sort_by(|left, right| {
            left.batch_epoch
                .cmp(&right.batch_epoch)
                .then_with(|| left.pair_id.0.cmp(&right.pair_id.0))
                .then_with(|| left.batch_id.0.cmp(&right.batch_id.0))
        });
        let epoch_end = artifact_epoch_bucket_end(epoch_start, policy.epoch_bucket_size)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let delay_subject = format!("{epoch_start}:{epoch_end}");
        let release_delay_epochs = effective_public_artifact_delay_epochs(
            &delay_subject,
            policy.public_artifact_delay_min_epochs,
            policy.public_artifact_delay_max_epochs,
        );
        let pair_count = members
            .iter()
            .map(|member| member.pair_id.0.clone())
            .collect::<BTreeSet<_>>()
            .len();
        let transcript_commitments = members
            .iter()
            .map(|member| member.transcript_commitment.clone())
            .collect::<Vec<_>>();
        let output_bundle_refs = members
            .iter()
            .map(|member| member.output_bundle_ref.clone())
            .collect::<Vec<_>>();
        let data_availability_refs = members
            .iter()
            .map(|member| member.data_availability_ref.clone())
            .collect::<Vec<_>>();
        let transcript_commitment_root = zylith_core::hash::tagged_commitment_sha256(
            "zylith/multi-pair-artifacts/transcript-root-v1",
            &transcript_commitments,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let output_bundle_root = zylith_core::hash::tagged_commitment_sha256(
            "zylith/multi-pair-artifacts/output-bundle-root-v1",
            &output_bundle_refs,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let data_availability_root = zylith_core::hash::tagged_commitment_sha256(
            "zylith/multi-pair-artifacts/data-availability-root-v1",
            &data_availability_refs,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let binding_members = members
            .iter()
            .map(|member| {
                serde_json::json!({
                    "batch_id": member.batch_id,
                    "pair_id": member.pair_id,
                    "batch_epoch": member.batch_epoch,
                    "transcript_commitment": member.transcript_commitment,
                    "output_bundle_ref": member.output_bundle_ref,
                    "bundle_commitment": member.bundle_commitment,
                    "data_availability_ref": member.data_availability_ref,
                    "transcript_shape_policy_version": member.transcript_shape_policy_version,
                })
            })
            .collect::<Vec<_>>();
        let aggregate_commitment = zylith_core::hash::tagged_commitment_sha256(
            "zylith/multi-pair-artifact-bundle-v1",
            &serde_json::json!({
                "policy": policy,
                "epoch_start": epoch_start,
                "epoch_end": epoch_end,
                "members": binding_members,
                "transcript_commitment_root": transcript_commitment_root,
                "output_bundle_root": output_bundle_root,
                "data_availability_root": data_availability_root,
            }),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let suffix = aggregate_commitment
            .get(..16)
            .unwrap_or(aggregate_commitment.as_str());
        bundles.push(MultiPairArtifactBundleSummary {
            bundle_id: format!("artifact-bundle-{epoch_start}-{epoch_end}-{suffix}"),
            epoch_start,
            epoch_end,
            delayed_until_epoch: epoch_end.saturating_add(release_delay_epochs),
            artifact_count_bucket: count_bucket_label(members.len() as u64),
            pair_count_bucket: count_bucket_label(pair_count as u64),
            padded_artifact_count: artifact_bundle_padded_count(members.len()) as u64,
            aggregate_commitment,
            transcript_commitment_root,
            output_bundle_root,
            data_availability_root,
            transcript_shape_policy_version: members
                .iter()
                .map(|member| member.transcript_shape_policy_version)
                .max()
                .unwrap_or_default(),
        });
    }

    Ok(bundles)
}

async fn health(State(state): State<AppState>) -> Json<DepositSyncStatus> {
    Json(current_status(&state).await)
}

async fn get_claim_window_policy() -> Json<ClaimWindowPolicy> {
    Json(ClaimWindowPolicy::default())
}

async fn get_withdrawal_amount_bucket_policy() -> Json<WithdrawalAmountBucketPolicy> {
    Json(WithdrawalAmountBucketPolicy::default())
}

async fn get_artifact_aggregation_policy(
    State(state): State<AppState>,
) -> Json<ArtifactAggregationPolicy> {
    Json(artifact_aggregation_policy(&state))
}

#[derive(Clone, Debug, Serialize)]
struct InternalDepositSyncStatus {
    #[serde(flatten)]
    status: DepositSyncStatus,
    synced_deposit_count: u64,
}

async fn sync_deposits_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<InternalDepositSyncStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    sync_deposits(&state).await?;
    Ok(Json(internal_current_status(&state).await))
}

async fn list_confirmed_deposits_range(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path((start, end)): Path<(u64, u64)>,
) -> Result<Json<DepositActivationRecordList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "deposits-range",
        state.public_rate_limit_per_minute,
    )?;
    validate_public_history_range(start, end)?;
    let deposits = state.confirmed_deposits.read().await;
    let mut records = deposits
        .values()
        .filter(|record| record.activation_id >= start && record.activation_id <= end)
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.activation_id);
    Ok(Json(DepositActivationRecordList {
        start,
        end,
        count_bucket: count_bucket_label(records.len() as u64),
        records,
    }))
}

async fn list_archived_batch_artifacts(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
) -> Result<Json<PublishedBatchArtifactList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "batch-artifacts",
        state.public_rate_limit_per_minute,
    )?;
    let artifacts = state.published_batch_artifacts.read().await;
    let (start_epoch, end_epoch) = latest_public_history_window(&artifacts);
    let batches = public_artifact_summaries_for_epoch_range(
        &artifacts,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        state.batch_window_ms,
        start_epoch,
        end_epoch,
    );
    let complete_through_epoch = public_visible_epoch_cutoff(&artifacts).and_then(|end_epoch| {
        public_artifact_complete_through_epoch(
            &artifacts,
            state.public_artifact_delay_min_epochs,
            state.public_artifact_delay_max_epochs,
            state.artifact_epoch_bucket_size,
            start_epoch,
            end_epoch,
        )
    });
    Ok(Json(PublishedBatchArtifactList {
        batches,
        complete_through_epoch,
    }))
}

async fn list_archived_batch_artifacts_by_epoch_range(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path((start_epoch, end_epoch)): Path<(u64, u64)>,
) -> Result<Json<PublishedBatchArtifactList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "batch-artifacts-range",
        state.public_rate_limit_per_minute,
    )?;
    validate_public_history_range(start_epoch, end_epoch)?;
    let artifacts = state.published_batch_artifacts.read().await;
    let batches = public_artifact_summaries_for_epoch_range(
        &artifacts,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        state.batch_window_ms,
        start_epoch,
        end_epoch,
    );
    let complete_through_epoch = public_artifact_complete_through_epoch(
        &artifacts,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        start_epoch,
        end_epoch,
    );
    Ok(Json(PublishedBatchArtifactList {
        batches,
        complete_through_epoch,
    }))
}

async fn list_multi_pair_artifact_bundles(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
) -> Result<Json<MultiPairArtifactBundleList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "artifact-bundles",
        state.public_rate_limit_per_minute,
    )?;
    let artifacts = state.published_batch_artifacts.read().await;
    let policy = artifact_aggregation_policy(&state);
    let (start_epoch, end_epoch) = latest_public_history_window(&artifacts);
    let summaries = public_artifact_summaries_for_epoch_range(
        &artifacts,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        state.batch_window_ms,
        start_epoch,
        end_epoch,
    );
    let bundles = multi_pair_artifact_bundles_for_epoch_range(&policy, summaries)?;
    Ok(Json(MultiPairArtifactBundleList { policy, bundles }))
}

async fn list_multi_pair_artifact_bundles_by_epoch_range(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path((start_epoch, end_epoch)): Path<(u64, u64)>,
) -> Result<Json<MultiPairArtifactBundleList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "artifact-bundles-range",
        state.public_rate_limit_per_minute,
    )?;
    validate_public_history_range(start_epoch, end_epoch)?;
    let artifacts = state.published_batch_artifacts.read().await;
    let policy = artifact_aggregation_policy(&state);
    let summaries = public_artifact_summaries_for_epoch_range(
        &artifacts,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        state.batch_window_ms,
        start_epoch,
        end_epoch,
    );
    let bundles = multi_pair_artifact_bundles_for_epoch_range(&policy, summaries)?;
    Ok(Json(MultiPairArtifactBundleList { policy, bundles }))
}

async fn list_internal_root_history_by_epoch_range(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((start_epoch, end_epoch)): Path<(u64, u64)>,
) -> Result<Json<SettlementRootHistoryArchive>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    if start_epoch > end_epoch {
        return Err(StatusCode::BAD_REQUEST);
    }
    let artifacts = state.published_batch_artifacts.read().await;
    let mut batches = artifacts
        .values()
        .filter(|published| {
            published.transcript.batch_epoch >= start_epoch
                && published.transcript.batch_epoch <= end_epoch
        })
        .filter_map(|published| match root_history_batch(published) {
            Ok(batch) => Some(batch),
            Err(status) => {
                eprintln!(
                    "skipping invalid root-history artifact batch_id={} status={status}",
                    published.transcript.batch_id.0
                );
                None
            }
        })
        .collect::<Vec<_>>();
    batches.sort_by(|left, right| {
        left.batch_epoch
            .cmp(&right.batch_epoch)
            .then_with(|| left.batch_id.0.cmp(&right.batch_id.0))
    });
    Ok(Json(SettlementRootHistoryArchive { batches }))
}

async fn get_archived_transcript(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<PublicSettlementTranscript>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "batch-transcript",
        state.public_rate_limit_per_minute,
    )?;
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

async fn list_archived_transcripts(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Query(query): Query<TranscriptBatchQuery>,
) -> Result<Json<Vec<PublicSettlementTranscript>>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "batch-transcripts",
        state.public_rate_limit_per_minute,
    )?;
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

async fn get_internal_archived_transcript(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<SettlementTranscript>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let artifacts = state.published_batch_artifacts.read().await;
    let published = artifacts.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(published.transcript.clone()))
}

async fn get_archived_output_bundle(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<OutputCiphertextBundle>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "output-bundle",
        state.public_rate_limit_per_minute,
    )?;
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

fn root_history_batch(
    published: &PublishedBatchArtifacts,
) -> Result<SettlementRootHistoryBatch, StatusCode> {
    let roots = root_only_settlement_commitments(&published.transcript)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(SettlementRootHistoryBatch {
        batch_id: published.transcript.batch_id.clone(),
        pair_id: published.transcript.pair_id.clone(),
        batch_epoch: published.transcript.batch_epoch,
        prior_note_root: roots.prior_note_root,
        prior_nullifier_root: roots.prior_nullifier_root,
        prior_renewal_root: roots.prior_renewal_root,
        prior_fee_root: roots.prior_fee_root,
        prior_liquidity_position_root: roots.prior_liquidity_position_root,
        output_note_root: roots.output_note_root,
        consumed_nullifier_root: roots.consumed_nullifier_root,
        liquidity_position_transition_root: roots.liquidity_position_transition_root,
        new_note_root: roots.new_note_root,
        new_nullifier_root: roots.new_nullifier_root,
        new_renewal_root: roots.new_renewal_root,
        new_liquidity_position_root: roots.new_liquidity_position_root,
        consumed_inputs: published.transcript.consumed_inputs.clone(),
        renewal_entries: published
            .transcript
            .renewal_child_uses
            .iter()
            .map(|renewal| renewal.child_nullifier.clone())
            .collect(),
        liquidity_position_transitions: published.transcript.liquidity_position_transitions.clone(),
        output_notes: published.transcript.output_notes.clone(),
    })
}

fn public_settlement_transcript(
    published: &PublishedBatchArtifacts,
) -> Result<PublicSettlementTranscript, StatusCode> {
    let roots = root_only_settlement_commitments(&published.transcript)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let transcript_commitment = settlement_transcript_commitment(&published.transcript)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let transcript_shape = published.transcript_shape.clone().unwrap_or_else(|| {
        transcript_shape_metadata(&published.transcript, &published.output_bundle)
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

    if let Some(path) = state.artifact_archive_path.as_deref() {
        persist_published_batch_artifacts_store(path, &candidate)?;
    }
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
        return Ok(Json(published_snapshot));
    }
    let settled_at_unix_ms =
        verify_settlement_timestamp_update(&state, &published_snapshot, &request).await?;

    let mut artifacts = state.published_batch_artifacts.write().await;
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

    if let Some(path) = state.artifact_archive_path.as_deref() {
        persist_published_batch_artifacts_store(path, &candidate)?;
    }
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

async fn confirm_deposits(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Json(request): Json<DepositConfirmationRequest>,
) -> Result<Json<DepositConfirmationList>, StatusCode> {
    enforce_rate_limit(
        &state.rate_limiter,
        &headers,
        peer,
        "deposit-confirmations",
        state.public_rate_limit_per_minute,
    )?;
    if request.funding_commitments.len() > state.max_deposit_confirmation_commitments {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let deposits = state.confirmed_deposits.read().await;
    let confirmed = request
        .funding_commitments
        .iter()
        .filter_map(|commitment| deposits.get(&normalize_hex(commitment)).cloned())
        .collect();
    let status = current_status(&state).await;
    Ok(Json(DepositConfirmationList {
        confirmed,
        last_successful_sync_unix_ms: status.last_successful_sync_unix_ms,
        sync_lag_ms: status.sync_lag_ms,
    }))
}

async fn current_status(state: &AppState) -> DepositSyncStatus {
    let deposits = state.confirmed_deposits.read().await;
    let synced_count = state.synced_deposit_count.read().await;
    let last_successful_sync_unix_ms = *state.last_successful_sync_unix_ms.read().await;
    DepositSyncStatus {
        service: "zylith-indexer".into(),
        cached_deposits_bucket: count_bucket_label(deposits.len() as u64),
        synced_deposit_count_bucket: count_bucket_label(*synced_count),
        last_successful_sync_unix_ms,
        sync_lag_ms: if last_successful_sync_unix_ms == 0 {
            0
        } else {
            now_unix_ms().saturating_sub(last_successful_sync_unix_ms)
        },
    }
}

async fn internal_current_status(state: &AppState) -> InternalDepositSyncStatus {
    let synced_deposit_count = *state.synced_deposit_count.read().await;
    InternalDepositSyncStatus {
        status: current_status(state).await,
        synced_deposit_count,
    }
}

async fn sync_deposits(state: &AppState) -> Result<(), StatusCode> {
    if !is_configured_felt(&state.commitment_registry_address)
        || !is_configured_felt(&state.funding_activation_count_selector)
        || !is_configured_felt(&state.funding_activation_record_selector)
    {
        return Err(StatusCode::FAILED_DEPENDENCY);
    }

    let remote_count = fetch_deposit_count(state).await?;
    let local_count = *state.synced_deposit_count.read().await;
    let start_index = deposit_sync_start_index(local_count, remote_count);

    let mut candidate = state.confirmed_deposits.read().await.clone();
    candidate.retain(|_, record| record.activation_id < start_index);

    for activation_id in start_index..remote_count {
        let record = fetch_deposit_activation_record(state, activation_id).await?;
        candidate.insert(normalize_hex(&record.funding_commitment), record);
    }

    *state.confirmed_deposits.write().await = candidate;
    *state.synced_deposit_count.write().await = remote_count;
    *state.last_successful_sync_unix_ms.write().await = now_unix_ms();
    Ok(())
}

fn deposit_sync_start_index(local_count: u64, remote_count: u64) -> u64 {
    if remote_count < local_count.saturating_sub(DEPOSIT_SYNC_ROLLBACK_WINDOW) {
        return 0;
    }
    local_count
        .min(remote_count)
        .saturating_sub(DEPOSIT_SYNC_ROLLBACK_WINDOW)
}

async fn fetch_deposit_count(state: &AppState) -> Result<u64, StatusCode> {
    let result = starknet_call_contract(
        state,
        &state.commitment_registry_address,
        &state.funding_activation_count_selector,
        &[],
    )
    .await?;
    let value = result.first().ok_or(StatusCode::BAD_GATEWAY)?;
    parse_hex_u64(value).ok_or(StatusCode::BAD_GATEWAY)
}

async fn fetch_deposit_activation_record(
    state: &AppState,
    activation_id: u64,
) -> Result<DepositActivationRecord, StatusCode> {
    let calldata = [format!("0x{activation_id:x}")];
    let result = starknet_call_contract(
        state,
        &state.commitment_registry_address,
        &state.funding_activation_record_selector,
        &calldata,
    )
    .await?;
    if result.len() < 4 {
        return Err(StatusCode::BAD_GATEWAY);
    }

    Ok(DepositActivationRecord {
        activation_id: parse_hex_u64(&result[0]).ok_or(StatusCode::BAD_GATEWAY)?,
        funding_commitment: normalize_hex(&result[1]),
        deposit_root: normalize_hex(&result[2]),
        encrypted_note_activation: normalize_hex(&result[3]),
    })
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
    let result = starknet_call_contract_at_block(
        state,
        &contract_address,
        &state.output_note_root_selector,
        &[batch_id_felt],
        block_id,
    )
    .await?;
    let root = result.into_iter().next().ok_or(StatusCode::BAD_GATEWAY)?;
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
    let result = starknet_call_contract_at_block(
        state,
        &contract_address,
        &state.verified_auction_transcript_selector,
        &[batch_id_felt],
        block_id,
    )
    .await?;
    let transcript = result.into_iter().next().ok_or(StatusCode::BAD_GATEWAY)?;
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
    let transaction_hash = normalize_required_felt(transaction_hash)?;
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "starknet_getTransactionReceipt",
        "params": [transaction_hash],
    });
    let response = state
        .http_client
        .post(state.rpc_url.as_str())
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
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "starknet_getBlockWithTxHashes",
        "params": [block_id],
    });
    let response = state
        .http_client
        .post(state.rpc_url.as_str())
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let body = decode_bounded_json::<StarknetBlockResponse>(response).await?;
    let timestamp = body.result.ok_or(StatusCode::BAD_GATEWAY)?.timestamp;
    timestamp.checked_mul(1000).ok_or(StatusCode::BAD_GATEWAY)
}

async fn starknet_call_contract(
    state: &AppState,
    contract_address: &str,
    entry_point_selector: &str,
    calldata: &[String],
) -> Result<Vec<String>, StatusCode> {
    starknet_call_contract_at_block(
        state,
        contract_address,
        entry_point_selector,
        calldata,
        serde_json::json!("latest"),
    )
    .await
}

async fn starknet_call_contract_at_block(
    state: &AppState,
    contract_address: &str,
    entry_point_selector: &str,
    calldata: &[String],
    block_id: serde_json::Value,
) -> Result<Vec<String>, StatusCode> {
    let call = StarknetCallRequest {
        contract_address,
        entry_point_selector,
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
        .post(&state.rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let body = decode_bounded_json::<StarknetRpcResponse>(response).await?;
    Ok(body
        .result
        .ok_or(StatusCode::BAD_GATEWAY)?
        .into_iter()
        .map(|felt| normalize_hex(&felt))
        .collect())
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
        env::var("ZYLITH_INDEXER_TRUST_PROXY_HEADERS")
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
    let cidrs = env::var("ZYLITH_INDEXER_TRUSTED_PROXY_CIDRS")
        .or_else(|_| env::var("ZYLITH_TRUSTED_PROXY_CIDRS"))
        .unwrap_or_default();
    cidrs
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| value.parse::<IpNet>().ok())
        .any(|network| network.contains(&peer_ip))
}

fn parse_hex_u64(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

fn normalize_hex(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with("0x") {
        trimmed.to_lowercase()
    } else {
        format!("0x{}", trimmed.to_lowercase())
    }
}

fn normalize_required_felt(value: &str) -> Result<String, StatusCode> {
    normalize_felt_hex(value).map_err(|_| StatusCode::BAD_REQUEST)
}

#[cfg(test)]
mod tests {
    use super::{
        AppState, DEFAULT_BATCH_WINDOW_MS, DEFAULT_INDEXER_MAX_BODY_BYTES,
        DEFAULT_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE, DEFAULT_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS,
        DEPOSIT_SYNC_ROLLBACK_WINDOW, MAX_ARTIFACT_STORE_BYTES, MAX_PUBLIC_HISTORY_RANGE_SPAN,
        MAX_PUBLIC_TRANSCRIPT_BATCH_IDS, MAX_STARKNET_RPC_RESPONSE_BYTES, RateLimiter,
        build_app_with_state, decode_bounded_json, deposit_sync_start_index,
        effective_public_artifact_delay_epochs, is_configured_felt, latest_public_history_window,
        load_commitment_registry_address, load_published_batch_artifacts_store, load_rpc_url,
        normalize_hex, now_unix_ms, parse_deployment_manifest, parse_hex_u64, rate_limit_subject,
        selector_hex, service_http_client, validate_public_history_range,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderMap, Method, Request, StatusCode},
    };
    use std::{
        collections::BTreeMap,
        env, fs,
        net::SocketAddr,
        sync::{Arc, Mutex},
    };
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;
    use zylith_core::{
        AssetId, BatchId, ConsumedInput, DepositActivationRecord, DepositSyncStatus,
        NoteCommitment, Nullifier, NullifierHistoryBatch, OutputCiphertextBundle, OutputNoteRecord,
        PairId, PublishedBatchArtifacts, SettlementTranscript, SettlementWitness,
        settlement_nullifier_root_after_history,
    };

    const TEST_INTERNAL_TOKEN: &str = "indexer-test-token";
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    fn artifact_store_rejects_oversized_unknown_and_missing_current_shapes() {
        let oversized_path = std::env::temp_dir().join(format!(
            "zylith-indexer-oversized-artifacts-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let file = fs::File::create(&oversized_path).expect("create oversized artifact store");
        file.set_len(MAX_ARTIFACT_STORE_BYTES + 1)
            .expect("size oversized artifact store");
        assert!(
            std::panic::catch_unwind(|| load_published_batch_artifacts_store(&oversized_path))
                .is_err()
        );
        fs::remove_file(&oversized_path).expect("remove oversized artifact store");

        let unknown_path = std::env::temp_dir().join(format!(
            "zylith-indexer-unknown-artifacts-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        fs::write(
            &unknown_path,
            r#"{"artifacts_by_batch":{},"unsupported_extra":[]}"#,
        )
        .expect("write unknown artifact store");
        assert!(
            std::panic::catch_unwind(|| load_published_batch_artifacts_store(&unknown_path))
                .is_err()
        );
        fs::remove_file(unknown_path).expect("remove unknown artifact store");

        let missing_path = std::env::temp_dir().join(format!(
            "zylith-indexer-missing-artifacts-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        fs::write(&missing_path, r#"{}"#).expect("write missing artifact store");
        assert!(
            std::panic::catch_unwind(|| load_published_batch_artifacts_store(&missing_path))
                .is_err()
        );
        fs::remove_file(missing_path).expect("remove missing artifact store");
    }

    fn sample_published_artifact(batch_id: &str, batch_epoch: u64) -> PublishedBatchArtifacts {
        sample_published_artifact_for_pair(batch_id, batch_epoch, "STRK/USDC")
    }

    #[test]
    fn rate_limit_subject_uses_peer_ip_without_trusted_proxy_cidr() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            env::set_var("ZYLITH_INDEXER_TRUST_PROXY_HEADERS", "true");
            env::remove_var("ZYLITH_INDEXER_TRUSTED_PROXY_CIDRS");
            env::remove_var("ZYLITH_TRUSTED_PROXY_CIDRS");
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
        let peer: SocketAddr = "198.51.100.7:9443".parse().expect("peer");

        assert_eq!(rate_limit_subject(&headers, Some(peer)), "198.51.100.7");

        unsafe {
            env::remove_var("ZYLITH_INDEXER_TRUST_PROXY_HEADERS");
        }
    }

    #[test]
    fn rate_limit_subject_uses_forwarded_ip_only_from_trusted_cidr() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            env::set_var("ZYLITH_INDEXER_TRUST_PROXY_HEADERS", "true");
            env::set_var("ZYLITH_INDEXER_TRUSTED_PROXY_CIDRS", "198.51.100.0/24");
            env::remove_var("ZYLITH_TRUSTED_PROXY_CIDRS");
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
        let peer: SocketAddr = "198.51.100.7:9443".parse().expect("peer");

        assert_eq!(rate_limit_subject(&headers, Some(peer)), "203.0.113.9");

        headers.insert("x-forwarded-for", "not-an-ip".parse().expect("header"));
        headers.insert("x-real-ip", "203.0.113.10".parse().expect("header"));
        assert_eq!(rate_limit_subject(&headers, Some(peer)), "203.0.113.10");

        headers.insert("x-real-ip", "also-not-an-ip".parse().expect("header"));
        assert_eq!(rate_limit_subject(&headers, Some(peer)), "198.51.100.7");

        unsafe {
            env::remove_var("ZYLITH_INDEXER_TRUST_PROXY_HEADERS");
            env::remove_var("ZYLITH_INDEXER_TRUSTED_PROXY_CIDRS");
        }
    }

    #[test]
    fn rate_limiter_recovers_from_poisoned_bucket_lock() {
        let limiter = RateLimiter::default();
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
    async fn cors_preflight_does_not_allow_disallowed_origin() {
        let router = {
            let _guard = ENV_LOCK.lock().expect("env lock");
            unsafe {
                env::set_var(
                    "ZYLITH_TEST_INDEXER_ALLOWED_ORIGINS",
                    "https://app.zylith.fi",
                );
            }
            let router = axum::Router::new()
                .route("/probe", axum::routing::get(|| async { "ok" }))
                .layer(super::service_cors_layer(
                    "ZYLITH_TEST_INDEXER_ALLOWED_ORIGINS",
                ));
            unsafe {
                env::remove_var("ZYLITH_TEST_INDEXER_ALLOWED_ORIGINS");
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
    fn indexer_cors_origins_reject_wildcards() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            env::set_var("ZYLITH_TEST_INDEXER_ALLOWED_ORIGINS", "https://*.zylith.fi");
        }
        let result = std::panic::catch_unwind(|| {
            super::allowed_origins_from_env("ZYLITH_TEST_INDEXER_ALLOWED_ORIGINS")
        });
        unsafe {
            env::remove_var("ZYLITH_TEST_INDEXER_ALLOWED_ORIGINS");
        }
        assert!(result.is_err());
    }

    fn sample_published_artifact_for_pair(
        batch_id: &str,
        batch_epoch: u64,
        pair: &str,
    ) -> PublishedBatchArtifacts {
        let pair_id = PairId(pair.into());
        let output_bundle =
            OutputCiphertextBundle::from_ciphertexts(BatchId(batch_id.into()), "da-ref", vec![])
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
        let consumed_inputs = vec![ConsumedInput {
            note_commitment: NoteCommitment("0x101".into()),
            nullifier: Nullifier("0x202".into()),
        }];
        let new_nullifier_root =
            settlement_nullifier_root_after_history(&[NullifierHistoryBatch {
                repeat_count: 1,
                nullifiers: consumed_inputs
                    .iter()
                    .map(|input| input.nullifier.clone())
                    .collect(),
            }])
            .expect("sparse nullifier root");
        let output_notes = vec![OutputNoteRecord {
            note_commitment: NoteCommitment("0x303".into()),
            asset_id: AssetId("USDC".into()),
            amount: 90,
            withdraw_authority: "0x404".into(),
        }];
        PublishedBatchArtifacts {
            transcript: SettlementTranscript {
                batch_id: BatchId(batch_id.into()),
                pair_id: pair_id.clone(),
                batch_epoch,
                order_commitment_root: "0x111".into(),
                encrypted_order_set_commitment: "0x222".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                prior_liquidity_position_root: "0x0".into(),
                new_nullifier_root: new_nullifier_root.clone(),
                new_renewal_root: "0x0".into(),
                new_liquidity_position_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                relay_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-fees".into(),
                relay_fee_recipient: "zylith-renewal-relay".into(),
                matched_orders: vec![],
                consumed_inputs: consumed_inputs.clone(),
                renewal_child_uses: vec![],
                liquidity_position_transitions: vec![],
                fees: vec![],
                output_notes: output_notes.clone(),
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: output_recovery_dummy_commitments.clone(),
                output_ciphertext_bundle_ref: output_bundle_ref.clone(),
            },
            output_bundle,
            liquidity_provider_attribution_bundle: None,
            settlement_witness: SettlementWitness {
                batch_id: BatchId(batch_id.into()),
                pair_id,
                batch_epoch,
                order_commitment_root: "0x111".into(),
                encrypted_order_set_commitment: "0x222".into(),
                transcript_commitment: "transcript-commitment".into(),
                auction_verifier_address: "0x0".into(),
                prior_note_root: "0x0".into(),
                prior_nullifier_root: "0x0".into(),
                prior_renewal_root: "0x0".into(),
                prior_fee_root: "0x0".into(),
                prior_liquidity_position_root: "0x0".into(),
                new_nullifier_root,
                new_renewal_root: "0x0".into(),
                new_liquidity_position_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                relay_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-fees".into(),
                relay_fee_recipient: "zylith-renewal-relay".into(),
                base_asset_id: AssetId("STRK".into()),
                quote_asset_id: AssetId("USDC".into()),
                matched_orders: vec![],
                matched_order_witnesses: vec![],
                consumed_inputs,
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
                output_notes,
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments,
                output_ciphertext_bundle_ref: output_bundle_ref,
            },
            published_at_unix_ms: now_unix_ms(),
            settled_at_unix_ms: None,
            settlement_transaction_hash: None,
            settlement_contract_address: None,
            order_execution_reports: vec![],
            transcript_shape: None,
        }
    }

    fn settlement_update_json(
        published: &PublishedBatchArtifacts,
        settled_at_unix_ms: u64,
    ) -> String {
        let roots = zylith_core::root_only_settlement_commitments(&published.transcript)
            .expect("settlement roots");
        let transcript_commitment =
            zylith_core::settlement_transcript_commitment(&published.transcript)
                .expect("transcript commitment");
        serde_json::json!({
            "settled_at_unix_ms": settled_at_unix_ms,
            "output_note_root": roots.output_note_root,
            "transcript_commitment": transcript_commitment,
        })
        .to_string()
    }

    #[test]
    fn hex_parsers_accept_prefixed_values() {
        assert_eq!(parse_hex_u64("0x2a"), Some(42));
    }

    #[test]
    fn normalize_hex_adds_prefix_and_lowercases() {
        assert_eq!(normalize_hex("ABC"), "0xabc");
        assert_eq!(normalize_hex("0xDEF"), "0xdef");
    }

    #[test]
    fn configured_felt_requires_valid_nonzero_felt() {
        assert!(!is_configured_felt(""));
        assert!(!is_configured_felt("0x0"));
        assert!(!is_configured_felt("not-a-felt"));
        assert!(is_configured_felt("0x1"));
    }

    #[test]
    fn load_u64_env_rejects_invalid_or_below_minimum_values() {
        let invalid_env = "ZYLITH_TEST_INDEXER_INVALID_U64";
        let below_min_env = "ZYLITH_TEST_INDEXER_BELOW_MIN_U64";
        unsafe {
            env::set_var(invalid_env, "not-a-number");
            env::set_var(below_min_env, "0");
        }

        assert_eq!(
            super::load_u64_env(invalid_env, 10, 1).unwrap_err(),
            format!("{invalid_env} must be an integer >= 1")
        );
        assert_eq!(
            super::load_u64_env(below_min_env, 10, 1).unwrap_err(),
            format!("{below_min_env} must be an integer >= 1")
        );

        unsafe {
            env::remove_var(invalid_env);
            env::remove_var(below_min_env);
        }
    }

    #[test]
    fn deployment_manifest_parser_accepts_public_and_live_wrapped_shapes() {
        let public_manifest = include_str!("../../core/fixtures/deployment.example.json");

        let live_manifest = format!(
            r#"{{
                "manifest": {public_manifest},
                "deployment": {{
                    "timestamp": "2026-04-29T00:00:00Z"
                }}
            }}"#
        );

        let public = parse_deployment_manifest(public_manifest).expect("public manifest");
        let live = parse_deployment_manifest(&live_manifest).expect("live manifest");
        assert_eq!(public, live);
        assert_eq!(live.contracts.shielded_asset_adapter, "0x0");
    }

    #[test]
    fn production_indexer_requires_rpc_and_registry_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            env::set_var("ZYLITH_INDEXER_STRICT", "true");
            env::set_var(
                "ZYLITH_DEPLOYMENT_MANIFEST",
                "/tmp/zylith-indexer-missing-manifest.json",
            );
            env::remove_var("ZYLITH_STARKNET_RPC_URL");
            env::remove_var("ZYLITH_COMMITMENT_REGISTRY_ADDRESS");
        }

        assert!(load_rpc_url().is_err());
        assert!(load_commitment_registry_address().is_err());

        unsafe {
            env::set_var("ZYLITH_COMMITMENT_REGISTRY_ADDRESS", "0x0");
        }
        assert!(load_commitment_registry_address().is_err());

        unsafe {
            env::remove_var("ZYLITH_INDEXER_STRICT");
            env::remove_var("ZYLITH_DEPLOYMENT_MANIFEST");
            env::remove_var("ZYLITH_COMMITMENT_REGISTRY_ADDRESS");
        }
    }

    #[tokio::test]
    async fn archived_transcript_is_root_only_public_and_root_history_is_internal() {
        let batch_id = "batch-strk-usdc-11";
        let mut artifacts = BTreeMap::new();
        let published = sample_published_artifact(batch_id, 11);
        artifacts.insert(batch_id.into(), published.clone());

        let app = build_app_with_state(AppState {
            rpc_url: "http://127.0.0.1:5050/rpc/v0_8".into(),
            commitment_registry_address: "0x5".into(),
            funding_activation_count_selector: "0x1".into(),
            funding_activation_record_selector: "0x2".into(),
            http_client: service_http_client(),
            confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
            synced_deposit_count: Arc::new(RwLock::new(0)),
            last_successful_sync_unix_ms: Arc::new(RwLock::new(0)),
            published_batch_artifacts: Arc::new(RwLock::new(artifacts)),
            artifact_archive_path: None,
            internal_api_token: Some(Arc::new(TEST_INTERNAL_TOKEN.into())),
            batch_window_ms: DEFAULT_BATCH_WINDOW_MS,
            public_artifact_delay_min_epochs: 0,
            public_artifact_delay_max_epochs: 0,
            artifact_epoch_bucket_size: 8,
            require_artifact_onchain_verification: false,
            output_note_root_selector: selector_hex("output_note_root"),
            verified_auction_transcript_selector: selector_hex("verified_auction_transcript"),
            auction_verifier_address: None,
            rate_limiter: RateLimiter::default(),
            public_rate_limit_per_minute: DEFAULT_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE,
            max_deposit_confirmation_commitments: DEFAULT_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS
                as usize,
        });

        let settled_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/internal/batches/{batch_id}/settled-at"))
                    .method(Method::POST)
                    .header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(settlement_update_json(
                        &published,
                        1_778_661_520_000,
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(settled_response.status(), StatusCode::OK);

        let public_response = app
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
        assert_eq!(public_response.status(), StatusCode::OK);
        let public_body = to_bytes(public_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let public_json = serde_json::from_slice::<serde_json::Value>(&public_body).expect("json");
        assert_eq!(public_json["batch_id"], batch_id);
        assert_eq!(public_json["settled_at_unix_ms"], 1_778_661_520_000_u64);
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
        let public_list_body = to_bytes(public_list_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let public_list_json =
            serde_json::from_slice::<serde_json::Value>(&public_list_body).expect("json");
        let listed_transcript = &public_list_json.as_array().expect("public transcript list")[0];
        assert_eq!(listed_transcript["batch_id"], batch_id);
        assert!(listed_transcript.get("matched_orders").is_none());
        assert!(listed_transcript.get("consumed_inputs").is_none());
        assert!(listed_transcript.get("output_notes").is_none());
        assert!(listed_transcript.get("fees").is_none());

        let oversized_query = (0..=MAX_PUBLIC_TRANSCRIPT_BATCH_IDS)
            .map(|index| format!("batch-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let oversized_list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/batches/transcripts?batch_ids={oversized_query}"
                    ))
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(oversized_list_response.status(), StatusCode::BAD_REQUEST);

        let internal_transcript = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/internal/batches/{batch_id}/transcript"))
                    .method(Method::GET)
                    .header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(internal_transcript.status(), StatusCode::OK);
        let internal_body = to_bytes(internal_transcript.into_body(), usize::MAX)
            .await
            .expect("body");
        let internal_json =
            serde_json::from_slice::<serde_json::Value>(&internal_body).expect("json");
        assert_eq!(
            internal_json["consumed_inputs"].as_array().unwrap().len(),
            1
        );
        assert_eq!(internal_json["output_notes"].as_array().unwrap().len(), 1);

        let unauth_history = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/internal/batches/root-history/epochs/0/12")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauth_history.status(), StatusCode::UNAUTHORIZED);

        let history_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/internal/batches/root-history/epochs/0/12")
                    .method(Method::GET)
                    .header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(history_response.status(), StatusCode::OK);
        let history_body = to_bytes(history_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let history_json =
            serde_json::from_slice::<serde_json::Value>(&history_body).expect("json");
        assert_eq!(history_json["batches"].as_array().unwrap().len(), 1);
        assert_eq!(history_json["batches"][0]["batch_id"], batch_id);
        assert_eq!(
            history_json["batches"][0]["consumed_inputs"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            history_json["batches"][0]["output_notes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn public_artifact_bundles_delay_and_aggregate_pair_membership() {
        let mut artifacts = BTreeMap::new();
        let usdc_10 = sample_published_artifact_for_pair("batch-strk-usdc-10", 10, "STRK/USDC");
        let eth_10 = sample_published_artifact_for_pair("batch-strk-eth-10", 10, "STRK/ETH");
        artifacts.insert("batch-strk-usdc-10".into(), usdc_10.clone());
        artifacts.insert("batch-strk-eth-10".into(), eth_10.clone());
        artifacts.insert(
            "batch-strk-usdc-11".into(),
            sample_published_artifact_for_pair("batch-strk-usdc-11", 11, "STRK/USDC"),
        );
        artifacts.insert(
            "batch-strk-usdc-16".into(),
            sample_published_artifact_for_pair("batch-strk-usdc-16", 16, "STRK/USDC"),
        );

        let app = build_app_with_state(AppState {
            rpc_url: "http://127.0.0.1:5050/rpc/v0_8".into(),
            commitment_registry_address: "0x5".into(),
            funding_activation_count_selector: "0x1".into(),
            funding_activation_record_selector: "0x2".into(),
            http_client: service_http_client(),
            confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
            synced_deposit_count: Arc::new(RwLock::new(0)),
            last_successful_sync_unix_ms: Arc::new(RwLock::new(0)),
            published_batch_artifacts: Arc::new(RwLock::new(artifacts)),
            artifact_archive_path: None,
            internal_api_token: Some(Arc::new(TEST_INTERNAL_TOKEN.into())),
            batch_window_ms: DEFAULT_BATCH_WINDOW_MS,
            public_artifact_delay_min_epochs: 1,
            public_artifact_delay_max_epochs: 1,
            artifact_epoch_bucket_size: 8,
            require_artifact_onchain_verification: false,
            output_note_root_selector: selector_hex("output_note_root"),
            verified_auction_transcript_selector: selector_hex("verified_auction_transcript"),
            auction_verifier_address: None,
            rate_limiter: RateLimiter::default(),
            public_rate_limit_per_minute: DEFAULT_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE,
            max_deposit_confirmation_commitments: DEFAULT_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS
                as usize,
        });

        for (batch_id, published) in [
            ("batch-strk-usdc-10", &usdc_10),
            ("batch-strk-eth-10", &eth_10),
        ] {
            let settled_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/settled-at"))
                        .method(Method::POST)
                        .header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
                        .header("content-type", "application/json")
                        .body(Body::from(settlement_update_json(
                            published,
                            1_778_661_520_000,
                        )))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(settled_response.status(), StatusCode::OK);
        }

        let exact_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/batches/artifacts")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(exact_response.status(), StatusCode::OK);
        let exact_body = to_bytes(exact_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let exact_json = serde_json::from_slice::<serde_json::Value>(&exact_body).expect("json");
        let exact_batches = exact_json["batches"].as_array().expect("batches");
        assert_eq!(exact_batches.len(), 2);
        assert!(
            exact_batches
                .iter()
                .all(|batch| batch["batch_epoch"].as_u64() == Some(10))
        );

        let delayed_exact_transcript = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/batches/batch-strk-usdc-11/transcript")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(delayed_exact_transcript.status(), StatusCode::NOT_FOUND);

        let visible_output_bundle = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/batches/batch-strk-usdc-10/output-bundle")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(visible_output_bundle.status(), StatusCode::OK);

        let bundle_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/batches/artifact-bundles/epochs/8/15")
                    .method(Method::GET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(bundle_response.status(), StatusCode::OK);
        let bundle_body = to_bytes(bundle_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let bundle_json = serde_json::from_slice::<serde_json::Value>(&bundle_body).expect("json");
        assert_eq!(
            bundle_json["policy"]["proof_aggregation_mode"],
            "native_aggregate_proof_facts_when_prover_configured"
        );
        let bundles = bundle_json["bundles"].as_array().expect("bundles");
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0]["epoch_start"], 8);
        assert_eq!(bundles[0]["epoch_end"], 15);
        assert_eq!(bundles[0]["delayed_until_epoch"], 16);
        assert_eq!(bundles[0]["artifact_count_bucket"], "0-7");
        assert_eq!(bundles[0]["pair_count_bucket"], "0-7");
        assert_eq!(bundles[0]["padded_artifact_count"], 8);
        assert!(bundles[0].get("batch_id").is_none());
        assert!(bundles[0].get("pair_id").is_none());
        assert!(bundles[0]["aggregate_commitment"].as_str().unwrap().len() >= 32);
    }

    #[test]
    fn artifact_delay_jitter_is_epoch_bucket_bound_and_capped() {
        let first = effective_public_artifact_delay_epochs("88:95", 3, 8);
        let second = effective_public_artifact_delay_epochs("88:95", 3, 8);
        assert_eq!(first, second);
        assert!((3..=8).contains(&first));
        assert_eq!(effective_public_artifact_delay_epochs("88:95", 4, 4), 4);
    }

    #[test]
    fn public_history_ranges_are_bounded() {
        assert!(validate_public_history_range(0, MAX_PUBLIC_HISTORY_RANGE_SPAN - 1).is_ok());
        assert_eq!(
            validate_public_history_range(0, MAX_PUBLIC_HISTORY_RANGE_SPAN).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            validate_public_history_range(10, 9).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn deposit_sync_revalidates_recent_activation_window() {
        assert_eq!(
            deposit_sync_start_index(
                DEPOSIT_SYNC_ROLLBACK_WINDOW + 20,
                DEPOSIT_SYNC_ROLLBACK_WINDOW + 40
            ),
            20
        );
    }

    #[test]
    fn deposit_sync_handles_count_decrease_inside_rollback_window() {
        assert_eq!(
            deposit_sync_start_index(
                DEPOSIT_SYNC_ROLLBACK_WINDOW + 20,
                DEPOSIT_SYNC_ROLLBACK_WINDOW + 10
            ),
            10
        );
    }

    #[test]
    fn deposit_sync_refetches_all_on_large_count_rollback() {
        assert_eq!(
            deposit_sync_start_index(DEPOSIT_SYNC_ROLLBACK_WINDOW * 4, 8),
            0
        );
    }

    #[test]
    fn exact_deposit_sync_count_is_internal_only() {
        let public = DepositSyncStatus {
            service: "zylith-indexer".into(),
            cached_deposits_bucket: "64-127".into(),
            synced_deposit_count_bucket: "64-127".into(),
            last_successful_sync_unix_ms: 123,
            sync_lag_ms: 456,
        };
        let public_json = serde_json::to_value(&public).expect("public status json");
        assert!(public_json.get("synced_deposit_count").is_none());

        let internal = super::InternalDepositSyncStatus {
            status: public,
            synced_deposit_count: 99,
        };
        let internal_json = serde_json::to_value(&internal).expect("internal status json");
        assert_eq!(internal_json["synced_deposit_count"], 99);
    }

    #[test]
    fn latest_public_history_window_uses_recent_epoch_cap() {
        let mut artifacts = BTreeMap::new();
        artifacts.insert("early".into(), sample_published_artifact("early", 1));
        artifacts.insert(
            "late".into(),
            sample_published_artifact("late", MAX_PUBLIC_HISTORY_RANGE_SPAN + 50),
        );

        let (start, end) = latest_public_history_window(&artifacts);
        assert_eq!(end, MAX_PUBLIC_HISTORY_RANGE_SPAN + 50);
        assert_eq!(start, 51);
    }

    #[tokio::test]
    async fn internal_routes_require_control_plane_bearer_token() {
        let app = build_app_with_state(AppState {
            rpc_url: "http://127.0.0.1:5050/rpc/v0_8".into(),
            commitment_registry_address: "0x5".into(),
            funding_activation_count_selector: "0x1".into(),
            funding_activation_record_selector: "0x2".into(),
            http_client: service_http_client(),
            confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
            synced_deposit_count: Arc::new(RwLock::new(0)),
            last_successful_sync_unix_ms: Arc::new(RwLock::new(0)),
            published_batch_artifacts: Arc::new(RwLock::new(BTreeMap::new())),
            artifact_archive_path: None,
            internal_api_token: Some(Arc::new(TEST_INTERNAL_TOKEN.into())),
            batch_window_ms: DEFAULT_BATCH_WINDOW_MS,
            public_artifact_delay_min_epochs: 1,
            public_artifact_delay_max_epochs: 1,
            artifact_epoch_bucket_size: 8,
            require_artifact_onchain_verification: false,
            output_note_root_selector: selector_hex("output_note_root"),
            verified_auction_transcript_selector: selector_hex("verified_auction_transcript"),
            auction_verifier_address: None,
            rate_limiter: RateLimiter::default(),
            public_rate_limit_per_minute: DEFAULT_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE,
            max_deposit_confirmation_commitments: DEFAULT_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS
                as usize,
        });

        let routes = [
            (Method::POST, "/api/internal/sync/deposits"),
            (
                Method::GET,
                "/api/internal/batches/root-history/epochs/0/12",
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

        let oversized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/deposits/confirmations")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(vec![b'x'; DEFAULT_INDEXER_MAX_BODY_BYTES + 1]))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let authorized = app
            .oneshot(
                Request::builder()
                    .uri("/api/internal/sync/deposits")
                    .method(Method::POST)
                    .header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_ne!(authorized.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn artifact_persistence_failure_does_not_publish_live_state() {
        let path = std::env::temp_dir().join(format!(
            "zylith-indexer-artifact-persist-failure-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create blocking archive path");
        let artifacts = Arc::new(RwLock::new(BTreeMap::new()));
        let state = AppState {
            rpc_url: "http://127.0.0.1:5050/rpc/v0_8".into(),
            commitment_registry_address: "0x5".into(),
            funding_activation_count_selector: "0x1".into(),
            funding_activation_record_selector: "0x2".into(),
            http_client: service_http_client(),
            confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
            synced_deposit_count: Arc::new(RwLock::new(0)),
            last_successful_sync_unix_ms: Arc::new(RwLock::new(0)),
            published_batch_artifacts: artifacts.clone(),
            artifact_archive_path: Some(Arc::new(path.clone())),
            internal_api_token: Some(Arc::new(TEST_INTERNAL_TOKEN.into())),
            batch_window_ms: DEFAULT_BATCH_WINDOW_MS,
            public_artifact_delay_min_epochs: 1,
            public_artifact_delay_max_epochs: 1,
            artifact_epoch_bucket_size: 8,
            require_artifact_onchain_verification: false,
            output_note_root_selector: selector_hex("output_note_root"),
            verified_auction_transcript_selector: selector_hex("verified_auction_transcript"),
            auction_verifier_address: None,
            rate_limiter: RateLimiter::default(),
            public_rate_limit_per_minute: DEFAULT_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE,
            max_deposit_confirmation_commitments: DEFAULT_MAX_DEPOSIT_CONFIRMATION_COMMITMENTS
                as usize,
        };
        let mut artifact = sample_published_artifact("batch-persist-failure", 1);
        artifact.settled_at_unix_ms = Some(1);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {TEST_INTERNAL_TOKEN}")
                .parse()
                .expect("authorization header"),
        );

        let result = super::publish_batch_artifacts(
            axum::extract::State(state),
            headers,
            axum::extract::Path("batch-persist-failure".into()),
            axum::Json(artifact),
        )
        .await;

        assert!(matches!(result, Err(StatusCode::INTERNAL_SERVER_ERROR)));
        assert!(artifacts.read().await.is_empty());
        fs::remove_dir_all(path).expect("remove blocking archive path");
    }

    #[tokio::test]
    async fn deposit_confirmations_are_cache_only_and_request_capped() {
        let mut cached_deposits = BTreeMap::new();
        cached_deposits.insert(
            "0xabc".into(),
            DepositActivationRecord {
                activation_id: 7,
                funding_commitment: "0xabc".into(),
                deposit_root: "0xdef".into(),
                encrypted_note_activation: "0x123".into(),
            },
        );
        let app = build_app_with_state(AppState {
            rpc_url: "http://127.0.0.1:1/rpc/v0_8".into(),
            commitment_registry_address: "0x5".into(),
            funding_activation_count_selector: "0x1".into(),
            funding_activation_record_selector: "0x2".into(),
            http_client: service_http_client(),
            confirmed_deposits: Arc::new(RwLock::new(cached_deposits)),
            synced_deposit_count: Arc::new(RwLock::new(0)),
            last_successful_sync_unix_ms: Arc::new(RwLock::new(0)),
            published_batch_artifacts: Arc::new(RwLock::new(BTreeMap::new())),
            artifact_archive_path: None,
            internal_api_token: Some(Arc::new(TEST_INTERNAL_TOKEN.into())),
            batch_window_ms: DEFAULT_BATCH_WINDOW_MS,
            public_artifact_delay_min_epochs: 1,
            public_artifact_delay_max_epochs: 1,
            artifact_epoch_bucket_size: 8,
            require_artifact_onchain_verification: false,
            output_note_root_selector: selector_hex("output_note_root"),
            verified_auction_transcript_selector: selector_hex("verified_auction_transcript"),
            auction_verifier_address: None,
            rate_limiter: RateLimiter::default(),
            public_rate_limit_per_minute: DEFAULT_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE,
            max_deposit_confirmation_commitments: 1,
        });

        let cached_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/deposits/confirmations")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"funding_commitments":["0xabc"]}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(cached_response.status(), StatusCode::OK);
        let body = to_bytes(cached_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["confirmed"].as_array().unwrap().len(), 1);
        let serialized = serde_json::to_string(&json).expect("serialized response");
        assert!(!serialized.contains("asset_id"));
        assert!(!serialized.contains("amount"));
        assert!(!serialized.contains("deposit_nonce"));
        assert!(!serialized.contains("note_commitment"));

        let capped_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/deposits/confirmations")
                    .method(Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"funding_commitments":["0xabc","0xdef"]}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(capped_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use starknet_rust_core::utils::get_selector_from_name;
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use zylith_core::{
    ARTIFACT_AGGREGATION_POLICY_VERSION, ArtifactAggregationPolicy, AssetId,
    CONTROL_PLANE_TOKEN_ENV, ClaimWindowPolicy, DeploymentManifest, DepositConfirmationList,
    DepositConfirmationRequest, DepositRecord, DepositRecordList, DepositSyncStatus,
    MakerAttributionArtifactList, MultiPairArtifactBundleList, MultiPairArtifactBundleSummary,
    NoteCommitment, OutputCiphertextBundle, PublicSettlementTranscript, PublishedBatchArtifactList,
    PublishedBatchArtifactSummary, PublishedBatchArtifacts, SettlementRootHistoryArchive,
    SettlementRootHistoryBatch, SettlementTimestampUpdate, SettlementTranscript,
    WithdrawalAmountBucketPolicy, WithdrawalRecord, WithdrawalRecordList,
    artifact_bundle_padded_count, artifact_epoch_bucket_end, artifact_epoch_bucket_start,
    count_bucket_label, extract_bearer_token,
    hash::{encode_starknet_felt, normalize_felt_hex},
    root_only_settlement_commitments, settlement_transcript_commitment, transcript_shape_metadata,
};

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:5050/rpc/v0_8";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3300";
const DEFAULT_DEPLOYMENT_MANIFEST_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../client/public/deployment.json"
);
const DEFAULT_SHIELDED_ASSET_ADAPTER_ADDRESS: &str = "";
const DEFAULT_ARTIFACT_ARCHIVE_PATH: &str = "indexer/published_batch_artifacts.dev.json";
const DEFAULT_BATCH_WINDOW_MS: u64 = 90_000;
const DEFAULT_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS: u64 = 3;
const DEFAULT_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS: u64 = 8;
const DEFAULT_ARTIFACT_EPOCH_BUCKET_SIZE: u64 = 8;
const ARTIFACT_DELAY_MIN_EPOCHS_ENV: &str = "ZYLITH_ARTIFACT_DELAY_MIN_EPOCHS";
const ARTIFACT_DELAY_MAX_EPOCHS_ENV: &str = "ZYLITH_ARTIFACT_DELAY_MAX_EPOCHS";
const INDEXER_ALLOWED_ORIGINS_ENV: &str = "ZYLITH_INDEXER_ALLOWED_ORIGINS";
const INDEXER_SYNC_INTERVAL_MS_ENV: &str = "ZYLITH_INDEXER_SYNC_INTERVAL_MS";
const REQUIRE_ARTIFACT_ONCHAIN_VERIFICATION_ENV: &str =
    "ZYLITH_REQUIRE_ARTIFACT_ONCHAIN_VERIFICATION";
const DEFAULT_INDEXER_SYNC_INTERVAL_MS: u64 = 15_000;

#[derive(Clone)]
struct AppState {
    rpc_url: String,
    shielded_asset_adapter_address: String,
    deposit_count_selector: String,
    deposit_record_selector: String,
    withdrawal_count_selector: String,
    withdrawal_record_selector: String,
    http_client: reqwest::Client,
    confirmed_deposits: Arc<RwLock<BTreeMap<String, DepositRecord>>>,
    confirmed_withdrawals: Arc<RwLock<BTreeMap<String, WithdrawalRecord>>>,
    synced_deposit_count: Arc<RwLock<u64>>,
    synced_withdrawal_count: Arc<RwLock<u64>>,
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
}

#[derive(Serialize)]
struct StarknetRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: (&'a StarknetCallRequest<'a>, &'static str),
}

#[derive(Serialize)]
struct StarknetCallRequest<'a> {
    contract_address: &'a str,
    entry_point_selector: &'a str,
    calldata: &'a [String],
}

#[derive(Deserialize)]
struct StarknetRpcResponse {
    result: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    );
    let public_artifact_delay_max_epochs = load_u64_env(
        ARTIFACT_DELAY_MAX_EPOCHS_ENV,
        DEFAULT_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS,
        public_artifact_delay_min_epochs,
    )
    .max(public_artifact_delay_min_epochs);
    let state = AppState {
        rpc_url: load_rpc_url(),
        shielded_asset_adapter_address: load_shielded_asset_adapter_address(),
        deposit_count_selector: selector_hex("deposit_count"),
        deposit_record_selector: selector_hex("deposit_record"),
        withdrawal_count_selector: selector_hex("withdrawal_count"),
        withdrawal_record_selector: selector_hex("withdrawal_record"),
        http_client: reqwest::Client::new(),
        confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
        confirmed_withdrawals: Arc::new(RwLock::new(BTreeMap::new())),
        synced_deposit_count: Arc::new(RwLock::new(0)),
        synced_withdrawal_count: Arc::new(RwLock::new(0)),
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
        batch_window_ms: load_u64_env("ZYLITH_BATCH_WINDOW_MS", DEFAULT_BATCH_WINDOW_MS, 1_000),
        public_artifact_delay_min_epochs,
        public_artifact_delay_max_epochs,
        artifact_epoch_bucket_size: load_u64_env(
            "ZYLITH_ARTIFACT_EPOCH_BUCKET_SIZE",
            DEFAULT_ARTIFACT_EPOCH_BUCKET_SIZE,
            1,
        ),
        require_artifact_onchain_verification: env_bool_or_default(
            REQUIRE_ARTIFACT_ONCHAIN_VERIFICATION_ENV,
            true,
        ),
        output_note_root_selector: selector_hex("output_note_root"),
    };

    if let Err(status) = sync_deposits(&state).await {
        eprintln!("indexer startup deposit sync skipped: {status}");
    }
    if let Err(status) = sync_withdrawals(&state).await {
        eprintln!("indexer startup withdrawal sync skipped: {status}");
    }

    let sync_interval_ms = load_u64_env(
        INDEXER_SYNC_INTERVAL_MS_ENV,
        DEFAULT_INDEXER_SYNC_INTERVAL_MS,
        1_000,
    );
    spawn_background_sync(state.clone(), sync_interval_ms);

    let app = build_app_with_state(state);

    let bind_addr =
        env::var("ZYLITH_INDEXER_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.into());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|error| format!("failed to bind indexer on {bind_addr}: {error}"))?;

    println!("Zylith indexer listening on http://{bind_addr}");
    axum::serve(listener, app)
        .await
        .map_err(|error| format!("indexer service failed: {error}"))
}

fn build_app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/internal/sync/deposits", post(sync_deposits_endpoint))
        .route(
            "/api/internal/sync/withdrawals",
            post(sync_withdrawals_endpoint),
        )
        .route(
            "/api/deposits/range/{start}/{end}",
            get(list_confirmed_deposits_range),
        )
        .route(
            "/api/deposits/{note_commitment}",
            get(get_confirmed_deposit),
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
            "/api/attribution/{batch_id}/{maker_public_key}",
            get(get_archived_maker_attribution),
        )
        .route(
            "/attribution/{batch_id}/{maker_public_key}",
            get(get_archived_maker_attribution),
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
            "/api/withdrawals/range/{start}/{end}",
            get(list_confirmed_withdrawals_range),
        )
        .route(
            "/api/withdrawals/{note_commitment}",
            get(get_confirmed_withdrawal),
        )
        .route("/api/deposits/confirmations", post(confirm_deposits))
        .with_state(state)
        .layer(service_cors_layer(INDEXER_ALLOWED_ORIGINS_ENV))
}

fn spawn_background_sync(state: AppState, interval_ms: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        loop {
            interval.tick().await;
            let deposits = sync_deposits(&state).await;
            let withdrawals = sync_withdrawals(&state).await;
            if deposits.is_ok() || withdrawals.is_ok() {
                *state.last_successful_sync_unix_ms.write().await = now_unix_ms();
            }
            if let Err(status) = deposits {
                eprintln!("indexer background deposit sync skipped: {status}");
            }
            if let Err(status) = withdrawals {
                eprintln!("indexer background withdrawal sync skipped: {status}");
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

fn load_rpc_url() -> String {
    if let Ok(rpc_url) = env::var("ZYLITH_STARKNET_RPC_URL") {
        return rpc_url;
    }

    load_deployment_manifest()
        .map(|manifest| manifest.rpc_url)
        .unwrap_or_else(|| DEFAULT_RPC_URL.into())
}

fn load_shielded_asset_adapter_address() -> String {
    let manifest_address = load_deployment_manifest()
        .map(|manifest| selected_shielded_asset_adapter_address(&manifest));
    select_shielded_asset_adapter_address(
        manifest_address.as_deref(),
        env::var("ZYLITH_SHIELDED_ASSET_ADAPTER_ADDRESS")
            .ok()
            .as_deref(),
    )
}

fn selected_shielded_asset_adapter_address(manifest: &DeploymentManifest) -> String {
    manifest
        .funding
        .starknet_privacy
        .as_ref()
        .and_then(|config| nonempty_string(config.shielded_asset_adapter.as_deref()))
        .unwrap_or_else(|| manifest.contracts.shielded_asset_adapter.clone())
}

fn select_shielded_asset_adapter_address(
    manifest_address: Option<&str>,
    env_address: Option<&str>,
) -> String {
    nonempty_string(manifest_address)
        .or_else(|| nonempty_string(env_address))
        .unwrap_or_else(|| DEFAULT_SHIELDED_ASSET_ADAPTER_ADDRESS.into())
}

fn nonempty_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn load_u64_env(name: &str, default_value: u64, minimum_value: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= minimum_value)
        .unwrap_or(default_value)
}

fn env_bool_or_default(name: &str, default_value: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default_value)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn load_deployment_manifest() -> Option<DeploymentManifest> {
    let manifest_path = env::var("ZYLITH_DEPLOYMENT_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DEPLOYMENT_MANIFEST_PATH));
    let manifest = fs::read_to_string(manifest_path).ok()?;
    parse_deployment_manifest(&manifest).ok()
}

fn parse_deployment_manifest(contents: &str) -> Result<DeploymentManifest, serde_json::Error> {
    let value = serde_json::from_str::<serde_json::Value>(contents)?;
    let manifest = value.get("manifest").cloned().unwrap_or(value);
    serde_json::from_value(manifest)
}

fn selector_hex(name: &str) -> String {
    get_selector_from_name(name)
        .map(|selector| format!("{selector:#x}"))
        .unwrap_or_default()
}

fn is_configured_felt(value: &str) -> bool {
    !value.trim().is_empty()
}

fn load_published_batch_artifacts_store(
    path: &FsPath,
) -> BTreeMap<String, PublishedBatchArtifacts> {
    let Ok(contents) = fs::read_to_string(path) else {
        if path.exists() {
            panic!(
                "failed to read published batch artifacts store {}",
                path.display()
            );
        }
        return BTreeMap::default();
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

async fn sync_deposits_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<DepositSyncStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    sync_deposits(&state).await?;
    Ok(Json(current_status(&state).await))
}

async fn sync_withdrawals_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<DepositSyncStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    sync_withdrawals(&state).await?;
    Ok(Json(current_status(&state).await))
}

async fn get_confirmed_deposit(
    State(state): State<AppState>,
    Path(note_commitment): Path<String>,
) -> Result<Json<DepositRecord>, StatusCode> {
    let deposits = state.confirmed_deposits.read().await;
    deposits
        .get(&normalize_hex(&note_commitment))
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn list_confirmed_deposits_range(
    State(state): State<AppState>,
    Path((start, end)): Path<(u64, u64)>,
) -> Result<Json<DepositRecordList>, StatusCode> {
    if start > end {
        return Err(StatusCode::BAD_REQUEST);
    }
    let deposits = state.confirmed_deposits.read().await;
    let mut records = deposits
        .values()
        .filter(|record| record.deposit_id >= start && record.deposit_id <= end)
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.deposit_id);
    Ok(Json(DepositRecordList {
        start,
        end,
        count_bucket: count_bucket_label(records.len() as u64),
        records,
    }))
}

async fn list_archived_batch_artifacts(
    State(state): State<AppState>,
) -> Json<PublishedBatchArtifactList> {
    let artifacts = state.published_batch_artifacts.read().await;
    let batches = public_artifact_summaries_for_epoch_range(
        &artifacts,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        state.batch_window_ms,
        0,
        u64::MAX,
    );
    Json(PublishedBatchArtifactList { batches })
}

async fn list_archived_batch_artifacts_by_epoch_range(
    State(state): State<AppState>,
    Path((start_epoch, end_epoch)): Path<(u64, u64)>,
) -> Result<Json<PublishedBatchArtifactList>, StatusCode> {
    if start_epoch > end_epoch {
        return Err(StatusCode::BAD_REQUEST);
    }
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
    Ok(Json(PublishedBatchArtifactList { batches }))
}

async fn list_multi_pair_artifact_bundles(
    State(state): State<AppState>,
) -> Result<Json<MultiPairArtifactBundleList>, StatusCode> {
    let artifacts = state.published_batch_artifacts.read().await;
    let policy = artifact_aggregation_policy(&state);
    let summaries = public_artifact_summaries_for_epoch_range(
        &artifacts,
        state.public_artifact_delay_min_epochs,
        state.public_artifact_delay_max_epochs,
        state.artifact_epoch_bucket_size,
        state.batch_window_ms,
        0,
        u64::MAX,
    );
    let bundles = multi_pair_artifact_bundles_for_epoch_range(&policy, summaries)?;
    Ok(Json(MultiPairArtifactBundleList { policy, bundles }))
}

async fn list_multi_pair_artifact_bundles_by_epoch_range(
    State(state): State<AppState>,
    Path((start_epoch, end_epoch)): Path<(u64, u64)>,
) -> Result<Json<MultiPairArtifactBundleList>, StatusCode> {
    if start_epoch > end_epoch {
        return Err(StatusCode::BAD_REQUEST);
    }
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
    Path(batch_id): Path<String>,
) -> Result<Json<PublicSettlementTranscript>, StatusCode> {
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
struct TranscriptBatchQuery {
    batch_ids: String,
}

async fn list_archived_transcripts(
    State(state): State<AppState>,
    Query(query): Query<TranscriptBatchQuery>,
) -> Json<Vec<PublicSettlementTranscript>> {
    let requested = query
        .batch_ids
        .split(',')
        .map(str::trim)
        .filter(|batch_id| !batch_id.is_empty())
        .collect::<BTreeSet<_>>();
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
    Json(transcripts)
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
    Path(batch_id): Path<String>,
) -> Result<Json<OutputCiphertextBundle>, StatusCode> {
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

async fn get_archived_maker_attribution(
    State(state): State<AppState>,
    Path((batch_id, maker_public_key)): Path<(String, String)>,
) -> Result<Json<MakerAttributionArtifactList>, StatusCode> {
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
        output_note_root: roots.output_note_root,
        consumed_nullifier_root: roots.consumed_nullifier_root,
        new_note_root: roots.new_note_root,
        new_nullifier_root: roots.new_nullifier_root,
        new_renewal_root: roots.new_renewal_root,
        consumed_inputs: published.transcript.consumed_inputs.clone(),
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

    if let Some(path) = state.artifact_archive_path.as_deref() {
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

    let published_snapshot = {
        let artifacts = state.published_batch_artifacts.read().await;
        artifacts
            .get(&batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };
    verify_settlement_timestamp_update(&state, &published_snapshot, &request).await?;

    let mut artifacts = state.published_batch_artifacts.write().await;
    let published = artifacts.get_mut(&batch_id).ok_or(StatusCode::NOT_FOUND)?;
    published.settled_at_unix_ms = Some(request.settled_at_unix_ms);
    let response = published.clone();

    if let Some(path) = state.artifact_archive_path.as_deref() {
        persist_published_batch_artifacts_store(path, &artifacts)?;
    }

    Ok(Json(response))
}

async fn verify_settlement_timestamp_update(
    state: &AppState,
    published: &PublishedBatchArtifacts,
    request: &SettlementTimestampUpdate,
) -> Result<(), StatusCode> {
    let roots = root_only_settlement_commitments(&published.transcript)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(output_note_root) = request.output_note_root.as_deref() {
        let provided = normalize_required_felt(output_note_root)?;
        let expected = normalize_required_felt(&roots.output_note_root)?;
        if provided != expected {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if let Some(transcript_commitment) = request.transcript_commitment.as_deref() {
        let provided = normalize_required_felt(transcript_commitment)?;
        let expected = normalize_required_felt(
            &settlement_transcript_commitment(&published.transcript)
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        )?;
        if provided != expected {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if !state.require_artifact_onchain_verification {
        return Ok(());
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
    let contract_address = request
        .settlement_contract_address
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&published.settlement_witness.auction_verifier_address);
    let chain_root =
        fetch_onchain_output_note_root(state, contract_address, &published.transcript.batch_id.0)
            .await?;
    let expected = normalize_required_felt(&roots.output_note_root)?;
    if chain_root != expected {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(())
}

async fn get_confirmed_withdrawal(
    State(state): State<AppState>,
    Path(note_commitment): Path<String>,
) -> Result<Json<WithdrawalRecord>, StatusCode> {
    let withdrawals = state.confirmed_withdrawals.read().await;
    withdrawals
        .get(&normalize_hex(&note_commitment))
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn list_confirmed_withdrawals_range(
    State(state): State<AppState>,
    Path((start, end)): Path<(u64, u64)>,
) -> Result<Json<WithdrawalRecordList>, StatusCode> {
    if start > end {
        return Err(StatusCode::BAD_REQUEST);
    }
    let withdrawals = state.confirmed_withdrawals.read().await;
    let mut records = withdrawals
        .values()
        .filter(|record| record.withdrawal_id >= start && record.withdrawal_id <= end)
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.withdrawal_id);
    Ok(Json(WithdrawalRecordList {
        start,
        end,
        count_bucket: count_bucket_label(records.len() as u64),
        records,
    }))
}

async fn confirm_deposits(
    State(state): State<AppState>,
    Json(request): Json<DepositConfirmationRequest>,
) -> Result<Json<DepositConfirmationList>, StatusCode> {
    sync_deposits(&state).await?;
    let deposits = state.confirmed_deposits.read().await;
    let confirmed = request
        .note_commitments
        .iter()
        .filter_map(|commitment| deposits.get(&normalize_hex(&commitment.0)).cloned())
        .collect();
    Ok(Json(DepositConfirmationList { confirmed }))
}

async fn current_status(state: &AppState) -> DepositSyncStatus {
    let deposits = state.confirmed_deposits.read().await;
    let withdrawals = state.confirmed_withdrawals.read().await;
    let synced_count = state.synced_deposit_count.read().await;
    let synced_withdrawal_count = state.synced_withdrawal_count.read().await;
    let last_successful_sync_unix_ms = *state.last_successful_sync_unix_ms.read().await;
    DepositSyncStatus {
        service: "zylith-indexer".into(),
        rpc_configured: !state.rpc_url.trim().is_empty(),
        shielded_asset_adapter_configured: is_configured_felt(
            &state.shielded_asset_adapter_address,
        ),
        cached_deposits_bucket: count_bucket_label(deposits.len() as u64),
        synced_deposit_count_bucket: count_bucket_label(*synced_count),
        cached_withdrawals_bucket: count_bucket_label(withdrawals.len() as u64),
        synced_withdrawal_count_bucket: count_bucket_label(*synced_withdrawal_count),
        last_successful_sync_unix_ms,
        sync_lag_ms: if last_successful_sync_unix_ms == 0 {
            0
        } else {
            now_unix_ms().saturating_sub(last_successful_sync_unix_ms)
        },
    }
}

async fn sync_deposits(state: &AppState) -> Result<(), StatusCode> {
    if !is_configured_felt(&state.shielded_asset_adapter_address)
        || !is_configured_felt(&state.deposit_count_selector)
        || !is_configured_felt(&state.deposit_record_selector)
    {
        return Err(StatusCode::FAILED_DEPENDENCY);
    }

    let remote_count = fetch_deposit_count(state).await?;
    let start_index = *state.synced_deposit_count.read().await;

    for deposit_id in start_index..remote_count {
        let record = fetch_deposit_record(state, deposit_id).await?;
        state
            .confirmed_deposits
            .write()
            .await
            .insert(normalize_hex(&record.note_commitment.0), record);
    }

    *state.synced_deposit_count.write().await = remote_count;
    *state.last_successful_sync_unix_ms.write().await = now_unix_ms();
    Ok(())
}

async fn sync_withdrawals(state: &AppState) -> Result<(), StatusCode> {
    if !is_configured_felt(&state.shielded_asset_adapter_address)
        || !is_configured_felt(&state.withdrawal_count_selector)
        || !is_configured_felt(&state.withdrawal_record_selector)
    {
        return Err(StatusCode::FAILED_DEPENDENCY);
    }

    let remote_count = fetch_withdrawal_count(state).await?;
    let start_index = *state.synced_withdrawal_count.read().await;

    for withdrawal_id in start_index..remote_count {
        let record = fetch_withdrawal_record(state, withdrawal_id).await?;
        state
            .confirmed_withdrawals
            .write()
            .await
            .insert(normalize_hex(&record.note_commitment.0), record);
    }

    *state.synced_withdrawal_count.write().await = remote_count;
    *state.last_successful_sync_unix_ms.write().await = now_unix_ms();
    Ok(())
}

async fn fetch_deposit_count(state: &AppState) -> Result<u64, StatusCode> {
    let result = starknet_call(state, &state.deposit_count_selector, &[]).await?;
    let value = result.first().ok_or(StatusCode::BAD_GATEWAY)?;
    parse_hex_u64(value).ok_or(StatusCode::BAD_GATEWAY)
}

async fn fetch_deposit_record(
    state: &AppState,
    deposit_id: u64,
) -> Result<DepositRecord, StatusCode> {
    let calldata = [format!("0x{deposit_id:x}")];
    let result = starknet_call(state, &state.deposit_record_selector, &calldata).await?;
    if result.len() < 5 {
        return Err(StatusCode::BAD_GATEWAY);
    }

    Ok(DepositRecord {
        deposit_id: parse_hex_u64(&result[0]).ok_or(StatusCode::BAD_GATEWAY)?,
        asset_id: AssetId(normalize_hex(&result[1])),
        amount: parse_hex_u128(&result[2]).ok_or(StatusCode::BAD_GATEWAY)?,
        deposit_nonce: parse_hex_u64(&result[3]).ok_or(StatusCode::BAD_GATEWAY)?,
        note_commitment: NoteCommitment(normalize_hex(&result[4])),
    })
}

async fn fetch_withdrawal_count(state: &AppState) -> Result<u64, StatusCode> {
    let result = starknet_call(state, &state.withdrawal_count_selector, &[]).await?;
    let value = result.first().ok_or(StatusCode::BAD_GATEWAY)?;
    parse_hex_u64(value).ok_or(StatusCode::BAD_GATEWAY)
}

async fn fetch_withdrawal_record(
    state: &AppState,
    withdrawal_id: u64,
) -> Result<WithdrawalRecord, StatusCode> {
    let calldata = [format!("0x{withdrawal_id:x}")];
    let result = starknet_call(state, &state.withdrawal_record_selector, &calldata).await?;
    if result.len() < 5 {
        return Err(StatusCode::BAD_GATEWAY);
    }

    Ok(WithdrawalRecord {
        withdrawal_id: parse_hex_u64(&result[0]).ok_or(StatusCode::BAD_GATEWAY)?,
        asset_id: AssetId(normalize_hex(&result[1])),
        amount: parse_hex_u128(&result[2]).ok_or(StatusCode::BAD_GATEWAY)?,
        recipient: normalize_hex(&result[3]),
        note_commitment: NoteCommitment(normalize_hex(&result[4])),
    })
}

async fn starknet_call(
    state: &AppState,
    entry_point_selector: &str,
    calldata: &[String],
) -> Result<Vec<String>, StatusCode> {
    starknet_call_contract(
        state,
        &state.shielded_asset_adapter_address,
        entry_point_selector,
        calldata,
    )
    .await
}

async fn fetch_onchain_output_note_root(
    state: &AppState,
    contract_address: &str,
    batch_id: &str,
) -> Result<String, StatusCode> {
    let contract_address = normalize_required_felt(contract_address)?;
    if contract_address == "0x0" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let batch_id_felt = encode_starknet_felt("batch-id", batch_id);
    let result = starknet_call_contract(
        state,
        &contract_address,
        &state.output_note_root_selector,
        &[batch_id_felt],
    )
    .await?;
    let root = result.into_iter().next().ok_or(StatusCode::BAD_GATEWAY)?;
    normalize_required_felt(&root)
}

async fn starknet_call_contract(
    state: &AppState,
    contract_address: &str,
    entry_point_selector: &str,
    calldata: &[String],
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
        params: (&call, "latest"),
    };

    let response = state
        .http_client
        .post(&state.rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .error_for_status()
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let body = response
        .json::<StarknetRpcResponse>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(body
        .result
        .into_iter()
        .map(|felt| normalize_hex(&felt))
        .collect())
}

fn parse_hex_u64(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

fn parse_hex_u128(value: &str) -> Option<u128> {
    u128::from_str_radix(value.trim_start_matches("0x"), 16).ok()
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
        AppState, DEFAULT_BATCH_WINDOW_MS, build_app_with_state,
        effective_public_artifact_delay_epochs, normalize_hex, now_unix_ms,
        parse_deployment_manifest, parse_hex_u64, parse_hex_u128,
        select_shielded_asset_adapter_address, selector_hex,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode},
    };
    use std::{collections::BTreeMap, sync::Arc};
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;
    use zylith_core::{
        AssetId, BatchId, ConsumedInput, NoteCommitment, Nullifier, NullifierHistoryBatch,
        OutputCiphertextBundle, OutputNoteRecord, PairId, PublishedBatchArtifacts,
        SettlementTranscript, SettlementWitness, settlement_nullifier_root_after_history,
    };

    const TEST_INTERNAL_TOKEN: &str = "indexer-test-token";

    fn sample_published_artifact(batch_id: &str, batch_epoch: u64) -> PublishedBatchArtifacts {
        sample_published_artifact_for_pair(batch_id, batch_epoch, "STRK/USDC")
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
                new_nullifier_root: new_nullifier_root.clone(),
                new_renewal_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
                relay_fee_bps: 0,
                protocol_fee_recipient: "zylith-protocol-fees".into(),
                relay_fee_recipient: "zylith-renewal-relay".into(),
                matched_orders: vec![],
                consumed_inputs: consumed_inputs.clone(),
                renewal_child_uses: vec![],
                fees: vec![],
                output_notes: output_notes.clone(),
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments: output_recovery_dummy_commitments.clone(),
                output_ciphertext_bundle_ref: output_bundle_ref.clone(),
            },
            output_bundle,
            maker_attribution_bundle: None,
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
                new_nullifier_root,
                new_renewal_root: "0x0".into(),
                clearing_price: 145,
                price_base_scale: 1,
                taker_fee_bps: 4,
                maker_fee_bps: 0,
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
                privacy_gate: Default::default(),
                renewal_child_uses: vec![],
                fees: vec![],
                output_notes,
                output_note_preimages: vec![],
                output_recovery_records: vec![],
                output_recovery_dummy_commitments,
                output_ciphertext_bundle_ref: output_bundle_ref,
            },
            published_at_unix_ms: now_unix_ms(),
            settled_at_unix_ms: None,
            order_execution_reports: vec![],
            transcript_shape: None,
        }
    }

    #[test]
    fn hex_parsers_accept_prefixed_values() {
        assert_eq!(parse_hex_u64("0x2a"), Some(42));
        assert_eq!(parse_hex_u128("0xff"), Some(255));
    }

    #[test]
    fn normalize_hex_adds_prefix_and_lowercases() {
        assert_eq!(normalize_hex("ABC"), "0xabc");
        assert_eq!(normalize_hex("0xDEF"), "0xdef");
    }

    #[test]
    fn deployment_manifest_parser_accepts_public_and_live_wrapped_shapes() {
        let public_manifest = r#"{
            "network": "sepolia",
            "rpc_url": "https://rpc.example",
            "chain_id": "SN_SEPOLIA",
            "contracts": {
                "commitment_registry": "0x1",
                "batch_registry": "0x2",
                "fee_ledger": "0x3",
                "shielded_asset_adapter": "0x4",
                "privacy_deposit_bridge": "0x6",
                "auction_verifier": "0x7"
            },
            "token_addresses": {
                "STRK": "0x9"
            }
        }"#;

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
        assert_eq!(live.contracts.shielded_asset_adapter, "0x4");
    }

    #[test]
    fn deployment_manifest_adapter_wins_over_stale_env_adapter() {
        assert_eq!(
            select_shielded_asset_adapter_address(Some("0xcurrent"), Some("0xstale")),
            "0xcurrent"
        );
        assert_eq!(
            select_shielded_asset_adapter_address(None, Some("0xenv")),
            "0xenv"
        );
        assert_eq!(
            select_shielded_asset_adapter_address(Some("  "), Some("0xenv")),
            "0xenv"
        );
    }

    #[tokio::test]
    async fn archived_transcript_is_root_only_public_and_root_history_is_internal() {
        let batch_id = "batch-strk-usdc-11";
        let mut artifacts = BTreeMap::new();
        artifacts.insert(batch_id.into(), sample_published_artifact(batch_id, 11));

        let app = build_app_with_state(AppState {
            rpc_url: "http://127.0.0.1:5050/rpc/v0_8".into(),
            shielded_asset_adapter_address: "0x1".into(),
            deposit_count_selector: "0x1".into(),
            deposit_record_selector: "0x2".into(),
            withdrawal_count_selector: "0x3".into(),
            withdrawal_record_selector: "0x4".into(),
            http_client: reqwest::Client::new(),
            confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
            confirmed_withdrawals: Arc::new(RwLock::new(BTreeMap::new())),
            synced_deposit_count: Arc::new(RwLock::new(0)),
            synced_withdrawal_count: Arc::new(RwLock::new(0)),
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
        });

        let settled_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/internal/batches/{batch_id}/settled-at"))
                    .method(Method::POST)
                    .header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"settled_at_unix_ms":1778661520000}"#))
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
        artifacts.insert(
            "batch-strk-usdc-10".into(),
            sample_published_artifact_for_pair("batch-strk-usdc-10", 10, "STRK/USDC"),
        );
        artifacts.insert(
            "batch-strk-eth-10".into(),
            sample_published_artifact_for_pair("batch-strk-eth-10", 10, "STRK/ETH"),
        );
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
            shielded_asset_adapter_address: "0x1".into(),
            deposit_count_selector: "0x1".into(),
            deposit_record_selector: "0x2".into(),
            withdrawal_count_selector: "0x3".into(),
            withdrawal_record_selector: "0x4".into(),
            http_client: reqwest::Client::new(),
            confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
            confirmed_withdrawals: Arc::new(RwLock::new(BTreeMap::new())),
            synced_deposit_count: Arc::new(RwLock::new(0)),
            synced_withdrawal_count: Arc::new(RwLock::new(0)),
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
        });

        for batch_id in ["batch-strk-usdc-10", "batch-strk-eth-10"] {
            let settled_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/internal/batches/{batch_id}/settled-at"))
                        .method(Method::POST)
                        .header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"settled_at_unix_ms":1778661520000}"#))
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

    #[tokio::test]
    async fn internal_routes_require_control_plane_bearer_token() {
        let app = build_app_with_state(AppState {
            rpc_url: "http://127.0.0.1:5050/rpc/v0_8".into(),
            shielded_asset_adapter_address: "0x1".into(),
            deposit_count_selector: "0x1".into(),
            deposit_record_selector: "0x2".into(),
            withdrawal_count_selector: "0x3".into(),
            withdrawal_record_selector: "0x4".into(),
            http_client: reqwest::Client::new(),
            confirmed_deposits: Arc::new(RwLock::new(BTreeMap::new())),
            confirmed_withdrawals: Arc::new(RwLock::new(BTreeMap::new())),
            synced_deposit_count: Arc::new(RwLock::new(0)),
            synced_withdrawal_count: Arc::new(RwLock::new(0)),
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
        });

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/internal/sync/deposits")
                    .method(Method::POST)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

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
}

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use zylith_core::{
    Batch, BatchId, BatchOrderSet, BatchStatus, BatchSummary, CONTROL_PLANE_TOKEN_ENV,
    CoordinatorStatus, OrderCancellationAccepted, OrderCancellationRequest, OrderSubmission,
    OrderSubmissionAccepted, PairId, PublishedBatchArtifacts, RecoveryArtifact,
    RecoveryArtifactList, RecoveryArtifactUpload, SubmittedOrderRecord,
    derive_order_cancellation_tag, extract_bearer_token, hash::tagged_commitment_sha256,
};

const DEFAULT_BATCH_WINDOW_MS: u64 = 2 * 60 * 1_000;
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_BATCH_STORE_PATH: &str = "coordinator/batches.dev.json";
const DEFAULT_RECOVERY_STORE_PATH: &str = "coordinator/recovery_artifacts.dev.json";
const DEFAULT_ARTIFACT_STORE_PATH: &str = "coordinator/published_batch_artifacts.dev.json";
const DEFAULT_PAIR_ID: &str = "STRK/USDC";

#[derive(Clone)]
struct AppState {
    batches: Arc<RwLock<BTreeMap<String, BatchRecord>>>,
    batch_store_path: Option<Arc<PathBuf>>,
    recovery_artifacts: Arc<RwLock<BTreeMap<String, RecoveryAccountRecord>>>,
    recovery_store_path: Option<Arc<PathBuf>>,
    published_batch_artifacts: Arc<RwLock<BTreeMap<String, PublishedBatchArtifacts>>>,
    published_batch_artifacts_store_path: Option<Arc<PathBuf>>,
    internal_api_token: Option<Arc<String>>,
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
async fn main() {
    let app = build_app();
    let bind_addr =
        env::var("ZYLITH_COORDINATOR_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.into());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("bind coordinator");

    println!("Zylith coordinator listening on http://{bind_addr}");
    axum::serve(listener, app).await.expect("serve coordinator");
}

fn build_app() -> Router {
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
    ));

    build_app_with_paths(
        batch_store_path,
        recovery_store_path,
        published_batch_artifacts_store_path,
        internal_api_token,
    )
}

fn build_app_with_paths(
    batch_store_path: Option<PathBuf>,
    recovery_store_path: Option<PathBuf>,
    published_batch_artifacts_store_path: Option<PathBuf>,
    internal_api_token: Option<String>,
) -> Router {
    let mut loaded_batches = batch_store_path
        .as_deref()
        .map(load_batch_store)
        .unwrap_or_default();
    ensure_default_open_batch(&mut loaded_batches);
    let app_state = AppState {
        batches: Arc::new(RwLock::new(loaded_batches)),
        batch_store_path: batch_store_path.map(Arc::new),
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
    };

    Router::new()
        .route("/health", get(health))
        .route("/api/batches", get(list_batches))
        .route("/api/batches/current", get(current_batch))
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
            "/api/internal/batches/{batch_id}/orders",
            get(get_batch_orders),
        )
        .route(
            "/api/internal/batches/{batch_id}/artifacts",
            post(publish_batch_artifacts),
        )
        .route(
            "/api/internal/batches/{batch_id}/witness",
            get(get_published_witness),
        )
        .route(
            "/api/recovery/{account_id}/artifacts",
            get(list_recovery_artifacts).post(upload_recovery_artifact),
        )
        .route("/api/orders", post(submit_order))
        .route("/api/orders/cancel", post(cancel_order))
        .with_state(app_state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        )
}

async fn health(State(state): State<AppState>) -> Json<CoordinatorStatus> {
    let mut batches = state.batches.write().await;
    let changed = advance_batch_lifecycle(&mut batches);
    if changed {
        let _ = persist_batch_store_if_configured(&state, &batches);
    }
    let current_batch_id =
        current_open_batch(batches.values()).map(|record| record.batch.batch_id.clone());

    Json(CoordinatorStatus {
        service: "zylith-coordinator".into(),
        current_batch_id,
        tracked_batches: batches.len() as u64,
    })
}

async fn list_batches(State(state): State<AppState>) -> Json<Vec<BatchSummary>> {
    let mut batches = state.batches.write().await;
    let changed = advance_batch_lifecycle(&mut batches);
    if changed {
        let _ = persist_batch_store_if_configured(&state, &batches);
    }
    Json(batches.values().map(summary_from_record).collect())
}

async fn current_batch(State(state): State<AppState>) -> Result<Json<BatchSummary>, StatusCode> {
    let mut batches = state.batches.write().await;
    let changed = advance_batch_lifecycle(&mut batches);
    if changed {
        persist_batch_store_if_configured(&state, &batches)?;
    }
    current_open_batch(batches.values())
        .map(summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_batch(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> Result<Json<BatchSummary>, StatusCode> {
    let batches = state.batches.read().await;
    batches
        .get(&batch_id)
        .map(summary_from_record)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_batch_orders(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<BatchOrderSet>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let batches = state.batches.read().await;
    let record = batches.get(&batch_id).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(BatchOrderSet {
        batch: summary_from_record(record),
        orders: record.orders.clone(),
    }))
}

async fn get_published_transcript(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> Result<Json<zylith_core::SettlementTranscript>, StatusCode> {
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
    Ok(Json(published.output_bundle.clone()))
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
    Json(request): Json<PublishedBatchArtifacts>,
) -> Result<Json<PublishedBatchArtifacts>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    if request.transcript.batch_id.0 != batch_id || request.output_bundle.batch_id.0 != batch_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut artifacts = state.published_batch_artifacts.write().await;
    artifacts.insert(batch_id, request.clone());

    if let Some(path) = state.published_batch_artifacts_store_path.as_deref() {
        persist_published_batch_artifacts_store(path, &artifacts)?;
    }

    Ok(Json(request))
}

async fn list_recovery_artifacts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Result<Json<RecoveryArtifactList>, StatusCode> {
    let provided_auth_tag = require_recovery_auth_header(&headers)?;
    let mut recovery_artifacts = state.recovery_artifacts.write().await;
    let mut changed = false;
    let artifacts = if let Some(account) = recovery_artifacts.get_mut(&account_id) {
        if let Some(expected) = &account.recovery_auth_tag {
            if expected != &provided_auth_tag {
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
        artifacts,
    }))
}

async fn upload_recovery_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<RecoveryArtifactUpload>,
) -> Result<Json<RecoveryArtifact>, StatusCode> {
    if request.artifact.account_id != account_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    let provided_auth_tag = require_recovery_auth_header(&headers)?;
    let artifact = request.artifact;
    let mut recovery_artifacts = state.recovery_artifacts.write().await;
    let account = recovery_artifacts.entry(account_id).or_default();
    if let Some(expected) = &account.recovery_auth_tag {
        if expected != &provided_auth_tag {
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
    Json(request): Json<OrderSubmission>,
) -> Result<Json<OrderSubmissionAccepted>, StatusCode> {
    let accepted_at_unix_ms = now_unix_ms();

    let mut batches = state.batches.write().await;
    advance_batch_lifecycle(&mut batches);
    let expected_epoch = expected_epoch_for_pair(&batches, &request.order_bundle.pair_id);
    if request.order_bundle.epoch_id != expected_epoch {
        return Err(StatusCode::CONFLICT);
    }
    let batch_key = batch_key(&request.order_bundle.pair_id, expected_epoch);
    let record = batches
        .entry(batch_key.clone())
        .or_insert_with(|| BatchRecord {
            batch: empty_batch(
                &request.order_bundle.pair_id,
                expected_epoch,
                accepted_at_unix_ms,
            ),
            order_count: 0,
            orders: vec![],
        });

    if record.batch.status != BatchStatus::Open {
        return Err(StatusCode::CONFLICT);
    }

    let accepted_batch_id = {
        record.order_count += 1;
        record.orders.push(SubmittedOrderRecord {
            received_at_unix_ms: accepted_at_unix_ms,
            order_bundle: request.order_bundle.clone(),
        });
        refresh_batch_commitments(record)?;
        record.batch.batch_id.clone()
    };
    persist_batch_store_if_configured(&state, &batches)?;

    Ok(Json(OrderSubmissionAccepted {
        batch_id: accepted_batch_id,
        order_commitment: request.order_bundle.order_commitment,
        accepted_at_unix_ms,
    }))
}

async fn cancel_order(
    State(state): State<AppState>,
    Json(request): Json<OrderCancellationRequest>,
) -> Result<Json<OrderCancellationAccepted>, StatusCode> {
    let mut batches = state.batches.write().await;
    advance_batch_lifecycle(&mut batches);
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
    refresh_batch_commitments(record)?;
    persist_batch_store_if_configured(&state, &batches)?;

    Ok(Json(OrderCancellationAccepted {
        batch_id: request.batch_id,
        order_commitment: request.order_commitment,
        cancelled_at_unix_ms: now_unix_ms(),
    }))
}

fn summary_from_record(record: &BatchRecord) -> BatchSummary {
    BatchSummary {
        batch_id: record.batch.batch_id.clone(),
        pair_id: record.batch.pair_id.clone(),
        epoch_id: record.batch.epoch_id,
        close_time_unix_ms: record.batch.close_time_unix_ms,
        status: record.batch.status.clone(),
        order_count: record.order_count,
    }
}

fn load_required_control_plane_token(service_name: &str, env_name: &str) -> String {
    env::var(env_name).unwrap_or_else(|_| {
        panic!("{service_name} requires {env_name} to protect internal control-plane routes")
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
    if provided != expected_token.as_str() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
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

fn current_open_batch<'a>(
    batches: impl Iterator<Item = &'a BatchRecord>,
) -> Option<&'a BatchRecord> {
    batches
        .filter(|record| record.batch.status == BatchStatus::Open)
        .max_by_key(|record| {
            (
                record.batch.epoch_id,
                record.batch.close_time_unix_ms,
                record.order_count,
            )
        })
}

fn advance_batch_lifecycle(batches: &mut BTreeMap<String, BatchRecord>) -> bool {
    let mut changed = close_expired_open_batches(batches);
    if ensure_default_open_batch(batches) {
        changed = true;
    }
    changed
}

fn close_expired_open_batches(batches: &mut BTreeMap<String, BatchRecord>) -> bool {
    let now = now_unix_ms();
    let mut changed = false;
    for record in batches.values_mut() {
        if record.batch.status == BatchStatus::Open && record.batch.close_time_unix_ms <= now {
            record.batch.status = if record.order_count == 0 {
                BatchStatus::Cancelled
            } else {
                BatchStatus::Closed
            };
            changed = true;
        }
    }
    changed
}

fn ensure_default_open_batch(batches: &mut BTreeMap<String, BatchRecord>) -> bool {
    let pair_id = PairId(DEFAULT_PAIR_ID.into());
    if pair_has_open_batch(batches.values(), &pair_id) {
        return false;
    }

    let epoch_id = expected_epoch_for_pair(batches, &pair_id);
    let close_time_unix_ms = now_unix_ms();
    batches.insert(
        batch_key(&pair_id, epoch_id),
        BatchRecord {
            batch: empty_batch(&pair_id, epoch_id, close_time_unix_ms),
            order_count: 0,
            orders: vec![],
        },
    );
    true
}

fn pair_has_open_batch<'a>(
    mut batches: impl Iterator<Item = &'a BatchRecord>,
    pair_id: &PairId,
) -> bool {
    batches
        .any(|record| record.batch.pair_id == *pair_id && record.batch.status == BatchStatus::Open)
}

fn expected_epoch_for_pair(batches: &BTreeMap<String, BatchRecord>, pair_id: &PairId) -> u64 {
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
        .map(|epoch| epoch + 1)
        .unwrap_or(1)
}

fn batch_key(pair_id: &PairId, epoch_id: u64) -> String {
    format!(
        "batch-{}-{}",
        pair_id.0.to_lowercase().replace('/', "-"),
        epoch_id
    )
}

fn empty_batch(pair_id: &PairId, epoch_id: u64, opened_at_unix_ms: u64) -> Batch {
    let (order_commitment_root, encrypted_order_set_commitment) =
        compute_batch_commitments(&[]).unwrap_or_else(|_| ("".into(), "".into()));
    Batch {
        batch_id: BatchId(batch_key(pair_id, epoch_id)),
        pair_id: pair_id.clone(),
        epoch_id,
        close_time_unix_ms: opened_at_unix_ms + DEFAULT_BATCH_WINDOW_MS,
        status: BatchStatus::Open,
        order_commitment_root,
        encrypted_order_set_commitment,
    }
}

fn refresh_batch_commitments(record: &mut BatchRecord) -> Result<(), StatusCode> {
    let (order_commitment_root, encrypted_order_set_commitment) =
        compute_batch_commitments(&record.orders)?;
    record.batch.order_commitment_root = order_commitment_root;
    record.batch.encrypted_order_set_commitment = encrypted_order_set_commitment;
    Ok(())
}

fn compute_batch_commitments(
    orders: &[SubmittedOrderRecord],
) -> Result<(String, String), StatusCode> {
    let order_commitments = orders
        .iter()
        .map(|record| record.order_bundle.order_commitment.0.clone())
        .collect::<Vec<_>>();
    let encrypted_order_set = orders
        .iter()
        .map(|record| record.order_bundle.clone())
        .collect::<Vec<_>>();

    let order_root = tagged_commitment_sha256("zylith/batch-order-root", &order_commitments)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let encrypted_set_commitment =
        tagged_commitment_sha256("zylith/batch-encrypted-order-set", &encrypted_order_set)
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let encoded = serde_json::to_string_pretty(&BatchStoreFile {
        batches_by_id: batches.clone(),
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    fs::write(path, encoded).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let encoded = serde_json::to_string_pretty(&RecoveryStoreFile {
        accounts_by_id: accounts.clone(),
        artifacts_by_account: BTreeMap::new(),
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    fs::write(path, encoded).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn persist_published_batch_artifacts_store(
    path: &FsPath,
    artifacts: &BTreeMap<String, PublishedBatchArtifacts>,
) -> Result<(), StatusCode> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let encoded = serde_json::to_string_pretty(&PublishedBatchArtifactsStoreFile {
        artifacts_by_batch: artifacts.clone(),
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    fs::write(path, encoded).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use super::build_app_with_paths;
    use axum::http::StatusCode;
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use http_body_util::BodyExt;
    use std::path::PathBuf;
    use tower::ServiceExt;
    use zylith_core::{
        EncryptedRecoveryPayload, OrderCancellationRequest, OrderShareBundle, OrderSubmission,
        PairId, PublishedBatchArtifacts, RecoveryArtifact, RecoveryArtifactKind,
        RecoveryArtifactUpload, derive_order_cancellation_tag,
    };

    const TEST_INTERNAL_TOKEN: &str = "test-control-plane-token";
    const TEST_RECOVERY_AUTH: &str = "test-recovery-auth";

    fn auth_request(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.header("authorization", format!("Bearer {TEST_INTERNAL_TOKEN}"))
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = build_app_with_paths(None, None, None, None);

        let response = app
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
        assert_eq!(json["pair_id"], "STRK/USDC");
    }

    #[tokio::test]
    async fn order_submission_increments_batch_order_count() {
        let app = build_app_with_paths(None, None, None, None);
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("commitment-1".into()),
                cancellation_auth_tag: "cancel-tag-1".into(),
                pair_id: PairId("STRK/USDC".into()),
                epoch_id: 1,
                transport_envelope: None,
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
                    .uri("/api/batches/current")
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
        assert_eq!(json["order_count"], 1);
    }

    #[tokio::test]
    async fn coordinator_rejects_unexpected_client_epoch() {
        let app = build_app_with_paths(None, None, None, None);
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("commitment-latest".into()),
                cancellation_auth_tag: "cancel-tag-latest".into(),
                pair_id: PairId("STRK/USDC".into()),
                epoch_id: 42,
                transport_envelope: None,
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
                    .uri("/api/batches/current")
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
        assert_eq!(json["order_count"], 0);
    }

    #[tokio::test]
    async fn internal_batch_orders_endpoint_returns_stored_orders() {
        let app = build_app_with_paths(None, None, None, Some(TEST_INTERNAL_TOKEN.into()));
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("commitment-2".into()),
                cancellation_auth_tag: "cancel-tag-2".into(),
                pair_id: PairId("STRK/USDC".into()),
                epoch_id: 1,
                transport_envelope: None,
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
            "commitment-2"
        );
    }

    #[tokio::test]
    async fn cancel_endpoint_removes_matching_open_order() {
        let app = build_app_with_paths(None, None, None, None);
        let submission = OrderSubmission {
            order_bundle: OrderShareBundle {
                order_commitment: zylith_core::OrderCommitment("commitment-3".into()),
                cancellation_auth_tag: derive_order_cancellation_tag("cancel-secret-3"),
                pair_id: PairId("STRK/USDC".into()),
                epoch_id: 1,
                transport_envelope: None,
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
            order_commitment: zylith_core::OrderCommitment("commitment-3".into()),
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
                    .uri("/api/batches/current")
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
        assert_eq!(json["order_count"], 0);
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
        let published = PublishedBatchArtifacts {
            transcript: zylith_core::SettlementTranscript {
                batch_id: zylith_core::BatchId(batch_id.into()),
                clearing_price: 145,
                matched_orders: vec![],
                consumed_inputs: vec![],
                fees: vec![],
                output_notes: vec![],
                output_ciphertext_bundle_ref: "bundle-ref".into(),
            },
            output_bundle: zylith_core::OutputCiphertextBundle {
                batch_id: zylith_core::BatchId(batch_id.into()),
                bundle_commitment: "bundle-commitment".into(),
                data_availability_ref: "da-ref".into(),
                ciphertexts: vec![],
            },
            settlement_witness: zylith_core::SettlementWitness {
                batch_id: zylith_core::BatchId(batch_id.into()),
                pair_id: zylith_core::PairId("STRK/USDC".into()),
                transcript_commitment: "transcript-commitment".into(),
                settlement_verifier_address: "0x0".into(),
                clearing_price: 145,
                base_asset_id: zylith_core::AssetId("STRK".into()),
                quote_asset_id: zylith_core::AssetId("USDC".into()),
                matched_orders: vec![],
                matched_order_witnesses: vec![],
                consumed_inputs: vec![],
                fees: vec![],
                output_notes: vec![],
                output_ciphertext_bundle_ref: "bundle-ref".into(),
            },
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
        assert!(persisted.contains("bundle-commitment"));
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
                order_commitment: zylith_core::OrderCommitment("commitment-persisted".into()),
                cancellation_auth_tag: "cancel-tag-persisted".into(),
                pair_id: PairId("STRK/USDC".into()),
                epoch_id: 1,
                transport_envelope: None,
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

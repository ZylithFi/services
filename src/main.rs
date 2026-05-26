use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
    routing::{get, post},
};
use reqwest::Client;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs,
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use zylith_core::{constant_time_eq, extract_bearer_token, format_bearer_token};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3400";
const DEFAULT_STORE_PATH: &str = "renewal_relayer/relay_store.dev.json";
const DEFAULT_TICK_MS: u64 = 5_000;
const DEFAULT_MAX_PACKAGE_SLOTS: usize = 100_000;
const DEFAULT_RETRY_BACKOFF_MS: u64 = 8_000;
const DEFAULT_MAX_ATTEMPTS: u32 = 16;
const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_PACKAGE_RETENTION_MS: u64 = 120 * 24 * 60 * 60 * 1000;
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;
const BIND_ADDR_ENV: &str = "ZYLITH_RENEWAL_RELAY_BIND_ADDR";
const STORE_PATH_ENV: &str = "ZYLITH_RENEWAL_RELAY_STORE_PATH";
const PACKAGE_TOKEN_ENV: &str = "ZYLITH_RENEWAL_RELAY_PACKAGE_TOKEN";
const COORDINATOR_URL_ENV: &str = "ZYLITH_RENEWAL_RELAY_COORDINATOR_URL";
const PROVER_URL_ENV: &str = "ZYLITH_RENEWAL_RELAY_PROVER_URL";
const COORDINATOR_CONTROL_TOKEN_ENV: &str = "ZYLITH_RENEWAL_RELAY_COORDINATOR_CONTROL_TOKEN";
const TICK_MS_ENV: &str = "ZYLITH_RENEWAL_RELAY_TICK_MS";
const ENABLE_WORKER_ENV: &str = "ZYLITH_RENEWAL_RELAY_ENABLE_WORKER";
const MAX_PACKAGE_SLOTS_ENV: &str = "ZYLITH_RENEWAL_RELAY_MAX_PACKAGE_SLOTS";
const RETRY_BACKOFF_MS_ENV: &str = "ZYLITH_RENEWAL_RELAY_RETRY_BACKOFF_MS";
const MAX_ATTEMPTS_ENV: &str = "ZYLITH_RENEWAL_RELAY_MAX_ATTEMPTS";
const STRICT_MODE_ENV: &str = "ZYLITH_RENEWAL_RELAY_STRICT";
const ALLOWED_ORIGINS_ENV: &str = "ZYLITH_RENEWAL_RELAY_ALLOWED_ORIGINS";
const MAX_BODY_BYTES_ENV: &str = "ZYLITH_RENEWAL_RELAY_MAX_BODY_BYTES";
const PACKAGE_RETENTION_MS_ENV: &str = "ZYLITH_RENEWAL_RELAY_PACKAGE_RETENTION_MS";
const RATE_LIMIT_PER_MINUTE_ENV: &str = "ZYLITH_RENEWAL_RELAY_RATE_LIMIT_PER_MINUTE";

#[derive(Clone)]
struct RelayConfig {
    bind_addr: SocketAddr,
    store_path: PathBuf,
    package_registration_token: Option<Arc<String>>,
    default_coordinator_url: Option<String>,
    default_prover_url: Option<String>,
    coordinator_control_token: Option<Arc<String>>,
    tick_interval_ms: u64,
    enable_worker: bool,
    max_package_slots: usize,
    retry_backoff_ms: u64,
    max_attempts: u32,
    strict_mode: bool,
    allowed_origins: Vec<HeaderValue>,
    max_body_bytes: usize,
    package_retention_ms: u64,
    rate_limit_per_minute: u32,
}

impl RelayConfig {
    fn from_env() -> Result<Self, String> {
        let strict_mode = env_bool(STRICT_MODE_ENV, false);
        let package_registration_token = env::var(PACKAGE_TOKEN_ENV).ok().map(Arc::new);
        let coordinator_control_token = env::var(COORDINATOR_CONTROL_TOKEN_ENV)
            .or_else(|_| env::var(zylith_core::CONTROL_PLANE_TOKEN_ENV))
            .ok()
            .map(Arc::new);
        let allowed_origins = parse_allowed_origins(ALLOWED_ORIGINS_ENV)?;
        let store_path =
            PathBuf::from(env::var(STORE_PATH_ENV).unwrap_or_else(|_| DEFAULT_STORE_PATH.into()));
        if strict_mode {
            if package_registration_token.is_none() {
                return Err(format!(
                    "{PACKAGE_TOKEN_ENV} is required when {STRICT_MODE_ENV}=true"
                ));
            }
            if coordinator_control_token.is_none() {
                return Err(format!(
                    "{COORDINATOR_CONTROL_TOKEN_ENV} or {} is required when {STRICT_MODE_ENV}=true",
                    zylith_core::CONTROL_PLANE_TOKEN_ENV,
                ));
            }
            if env::var(COORDINATOR_URL_ENV)
                .ok()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(format!(
                    "{COORDINATOR_URL_ENV} is required when {STRICT_MODE_ENV}=true"
                ));
            }
            if env::var(PROVER_URL_ENV)
                .ok()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(format!(
                    "{PROVER_URL_ENV} is required when {STRICT_MODE_ENV}=true"
                ));
            }
            if allowed_origins.is_empty() {
                return Err(format!(
                    "{ALLOWED_ORIGINS_ENV} is required when {STRICT_MODE_ENV}=true"
                ));
            }
            if store_path == FsPath::new(DEFAULT_STORE_PATH) {
                return Err(format!(
                    "{STORE_PATH_ENV} must point at a production volume when {STRICT_MODE_ENV}=true"
                ));
            }
            if !is_sqlite_store(&store_path) {
                return Err(format!(
                    "{STORE_PATH_ENV} must use a .sqlite or .db durable store when {STRICT_MODE_ENV}=true"
                ));
            }
        }
        Ok(Self {
            bind_addr: env::var(BIND_ADDR_ENV)
                .unwrap_or_else(|_| DEFAULT_BIND_ADDR.into())
                .parse()
                .map_err(|error| format!("invalid {BIND_ADDR_ENV}: {error}"))?,
            store_path,
            package_registration_token,
            default_coordinator_url: env::var(COORDINATOR_URL_ENV).ok().map(normalize_url),
            default_prover_url: env::var(PROVER_URL_ENV).ok().map(normalize_url),
            coordinator_control_token,
            tick_interval_ms: env_u64(TICK_MS_ENV, DEFAULT_TICK_MS),
            enable_worker: env_bool(ENABLE_WORKER_ENV, true),
            max_package_slots: env_usize(MAX_PACKAGE_SLOTS_ENV, DEFAULT_MAX_PACKAGE_SLOTS),
            retry_backoff_ms: env_u64(RETRY_BACKOFF_MS_ENV, DEFAULT_RETRY_BACKOFF_MS),
            max_attempts: env_u32(MAX_ATTEMPTS_ENV, DEFAULT_MAX_ATTEMPTS),
            strict_mode,
            allowed_origins,
            max_body_bytes: env_usize(MAX_BODY_BYTES_ENV, DEFAULT_MAX_BODY_BYTES),
            package_retention_ms: env_u64(PACKAGE_RETENTION_MS_ENV, DEFAULT_PACKAGE_RETENTION_MS),
            rate_limit_per_minute: env_u32(
                RATE_LIMIT_PER_MINUTE_ENV,
                DEFAULT_RATE_LIMIT_PER_MINUTE,
            ),
        })
    }
}

#[derive(Clone)]
struct AppState {
    config: RelayConfig,
    store: Arc<RwLock<RelayStore>>,
    http: Client,
    tick_lock: Arc<Mutex<()>>,
    rate_limits: Arc<RwLock<BTreeMap<String, RateLimitBucket>>>,
}

#[derive(Clone, Debug, Default)]
struct RateLimitBucket {
    window_start_unix_ms: u64,
    count: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RelayStore {
    #[serde(default)]
    packages: BTreeMap<String, StoredPackage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredPackage {
    package: OfflineRenewalPackage,
    registered_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    #[serde(default)]
    results: BTreeMap<String, StoredSlotResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSlotResult {
    result: OfflineRenewalRelayResult,
    attempts: u32,
    last_attempt_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OfflineRenewalPackage {
    version: u8,
    package_id: String,
    package_commitment: String,
    created_at_unix_ms: u64,
    pair: String,
    start_epoch: u64,
    end_epoch: u64,
    slot_count: usize,
    #[serde(default)]
    relay_mode: Option<RelayMode>,
    #[serde(default)]
    ingress_key_registry_fingerprint: Option<String>,
    relay_policy: RelayPolicy,
    slots: Vec<OfflineRenewalSlot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RelayPolicy {
    prover_url: String,
    coordinator_url: String,
    submission_safety_buffer_ms: u64,
    max_submission_delay_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OfflineRenewalSlot {
    slot_id: String,
    pair: String,
    batch_id: String,
    epoch_id: u64,
    parent_child_index: u64,
    order_commitment: String,
    ingress_request: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RelayMode {
    SelfRelay,
    ZylithRelay,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelaySlotStatus {
    Submitted,
    AlreadySubmitted,
    NotDue,
    BatchNotOpen,
    SafetyBuffer,
    Missed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OfflineRenewalRelayResult {
    slot_id: String,
    pair: String,
    parent_child_index: u64,
    order_commitment: String,
    batch_id: String,
    epoch_id: u64,
    status: RelaySlotStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted: Option<CoordinatorAccepted>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CoordinatorAccepted {
    order_commitment: String,
    batch_id: String,
    accepted_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct PublicBatchSummary {
    batch_id: String,
    epoch_id: u64,
    close_time_unix_ms: u64,
    status: String,
}

#[derive(Debug, Deserialize)]
struct IngressResponse {
    coordinator_submission: Value,
}

#[derive(Debug, Serialize)]
struct PackageStatus {
    package_id: String,
    package_commitment: String,
    pair: String,
    start_epoch: u64,
    end_epoch: u64,
    slot_count: usize,
    relay_mode: RelayMode,
    pending_slots: usize,
    submitted_slots: usize,
    failed_slots: usize,
    updated_at_unix_ms: u64,
}

#[derive(Debug, Serialize)]
struct PackageResults {
    package_id: String,
    package_commitment: String,
    results: Vec<OfflineRenewalRelayResult>,
}

#[tokio::main]
async fn main() {
    let config = match RelayConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    let store = load_store(&config.store_path)
        .await
        .unwrap_or_else(|error| {
            eprintln!(
                "failed to load renewal relay store {}: {error}",
                config.store_path.display()
            );
            RelayStore::default()
        });
    let state = AppState {
        config,
        store: Arc::new(RwLock::new(store)),
        http: Client::new(),
        tick_lock: Arc::new(Mutex::new(())),
        rate_limits: Arc::new(RwLock::new(BTreeMap::new())),
    };
    if state.config.enable_worker {
        spawn_worker(state.clone());
    }
    let bind_addr = state.config.bind_addr;
    let listener = TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind renewal relayer on {bind_addr}: {error}"));
    println!("zylith renewal relayer listening on {bind_addr}");
    axum::serve(listener, app(state))
        .await
        .expect("renewal relayer server failed");
}

fn app(state: AppState) -> Router {
    let cors = service_cors_layer(&state.config);
    let max_body_bytes = state.config.max_body_bytes;
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(readiness))
        .route("/metrics", get(metrics))
        .route("/api/relay/packages", post(register_package))
        .route("/api/relay/packages/{package_id}", get(get_package_status))
        .route(
            "/api/relay/packages/{package_id}/results",
            get(get_package_results),
        )
        .route("/api/internal/relay/tick", post(trigger_tick))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(cors)
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    let store = state.store.read().await;
    Json(json!({
        "status": "ok",
        "packages": store.packages.len(),
        "worker_enabled": state.config.enable_worker,
        "strict_mode": state.config.strict_mode,
        "max_package_slots": state.config.max_package_slots,
    }))
}

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    let store_ok = if is_sqlite_store(&state.config.store_path) {
        open_sqlite_store(&state.config.store_path).is_ok()
    } else {
        !state.config.strict_mode
    };
    let ready = store_ok
        && (!state.config.strict_mode
            || (state.config.package_registration_token.is_some()
                && state.config.coordinator_control_token.is_some()
                && state.config.default_coordinator_url.is_some()
                && state.config.default_prover_url.is_some()
                && !state.config.allowed_origins.is_empty()
                && is_sqlite_store(&state.config.store_path)));
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "store_ok": store_ok,
            "strict_mode": state.config.strict_mode,
            "worker_enabled": state.config.enable_worker,
            "coordinator_pinned": state.config.default_coordinator_url.is_some(),
            "prover_pinned": state.config.default_prover_url.is_some(),
        })),
    )
}

async fn metrics(State(state): State<AppState>) -> String {
    let store = state.store.read().await;
    let mut total_slots = 0usize;
    let mut submitted = 0usize;
    let mut failed = 0usize;
    for package in store.packages.values() {
        total_slots += package.package.slot_count;
        submitted += package
            .results
            .values()
            .filter(|entry| {
                matches!(
                    entry.result.status,
                    RelaySlotStatus::Submitted | RelaySlotStatus::AlreadySubmitted
                )
            })
            .count();
        failed += package
            .results
            .values()
            .filter(|entry| matches!(entry.result.status, RelaySlotStatus::Failed))
            .count();
    }
    format!(
        "# HELP zylith_renewal_relay_packages Registered renewal packages.\n\
         # TYPE zylith_renewal_relay_packages gauge\n\
         zylith_renewal_relay_packages {}\n\
         # HELP zylith_renewal_relay_slots Registered renewal slots.\n\
         # TYPE zylith_renewal_relay_slots gauge\n\
         zylith_renewal_relay_slots {}\n\
         # HELP zylith_renewal_relay_submitted_slots Submitted renewal slots.\n\
         # TYPE zylith_renewal_relay_submitted_slots gauge\n\
         zylith_renewal_relay_submitted_slots {}\n\
         # HELP zylith_renewal_relay_failed_slots Failed renewal slots.\n\
         # TYPE zylith_renewal_relay_failed_slots gauge\n\
         zylith_renewal_relay_failed_slots {}\n",
        store.packages.len(),
        total_slots,
        submitted,
        failed,
    )
}

async fn register_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(package): Json<OfflineRenewalPackage>,
) -> Result<Json<PackageStatus>, RelayApiError> {
    require_package_auth(&state, &headers)?;
    enforce_rate_limit(&state, &headers).await?;
    validate_package(&package, &state.config)?;
    let now = now_unix_ms();
    let package_id = package.package_id.clone();
    let status = {
        let mut store = state.store.write().await;
        prune_store_locked(&mut store, &state.config, now);
        if let Some(existing) = store.packages.get(&package_id)
            && existing.package.package_commitment != package.package_commitment
        {
            return Err(RelayApiError {
                status: StatusCode::CONFLICT,
                detail: "Renewal package ID is already registered with a different commitment"
                    .into(),
            });
        }
        let entry = store
            .packages
            .entry(package_id.clone())
            .or_insert_with(|| StoredPackage {
                package: package.clone(),
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
                results: BTreeMap::new(),
            });
        entry.package = package;
        entry.updated_at_unix_ms = now;
        package_status(entry)
    };
    persist_store(&state.config.store_path, &state.store).await?;
    Ok(Json(status))
}

async fn get_package_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(package_id): Path<String>,
) -> Result<Json<PackageStatus>, RelayApiError> {
    require_package_auth(&state, &headers)?;
    enforce_rate_limit(&state, &headers).await?;
    let store = state.store.read().await;
    let package = store
        .packages
        .get(&package_id)
        .ok_or(RelayApiError::status(StatusCode::NOT_FOUND))?;
    Ok(Json(package_status(package)))
}

async fn get_package_results(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(package_id): Path<String>,
) -> Result<Json<PackageResults>, RelayApiError> {
    require_package_auth(&state, &headers)?;
    enforce_rate_limit(&state, &headers).await?;
    let store = state.store.read().await;
    let package = store
        .packages
        .get(&package_id)
        .ok_or(RelayApiError::status(StatusCode::NOT_FOUND))?;
    Ok(Json(PackageResults {
        package_id: package.package.package_id.clone(),
        package_commitment: package.package.package_commitment.clone(),
        results: package
            .results
            .values()
            .map(|entry| entry.result.clone())
            .collect(),
    }))
}

async fn trigger_tick(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OfflineRenewalRelayResult>>, RelayApiError> {
    require_internal_auth(&state, &headers)?;
    let results = process_due_slots_once(&state).await;
    Ok(Json(results))
}

fn spawn_worker(state: AppState) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_millis(state.config.tick_interval_ms));
        loop {
            interval.tick().await;
            let results = process_due_slots_once(&state).await;
            for result in results {
                if matches!(
                    result.status,
                    RelaySlotStatus::Submitted | RelaySlotStatus::Failed
                ) {
                    println!(
                        "renewal relay slot {} epoch {} {:?}",
                        result.slot_id, result.epoch_id, result.status
                    );
                }
            }
        }
    });
}

async fn process_due_slots_once(state: &AppState) -> Vec<OfflineRenewalRelayResult> {
    let _guard = state.tick_lock.lock().await;
    let persistent_lease = acquire_persistent_tick_lease(&state.config).await;
    if matches!(persistent_lease, PersistentTickLease::Busy) {
        return Vec::new();
    }
    let snapshots = {
        let mut store = state.store.write().await;
        prune_store_locked(&mut store, &state.config, now_unix_ms());
        store
            .packages
            .values()
            .map(|stored| stored.package.clone())
            .collect::<Vec<_>>()
    };
    let mut emitted = Vec::new();
    let mut batch_cache: BTreeMap<String, Option<PublicBatchSummary>> = BTreeMap::new();
    for package in snapshots {
        for slot in package.slots.iter() {
            if !should_attempt_slot(state, &package.package_id, slot).await {
                continue;
            }
            let cache_key = batch_cache_key(state, &package, &slot.pair);
            let batch = if let Some(cached) = batch_cache.get(&cache_key) {
                cached.clone()
            } else {
                let fetched = fetch_current_batch(state, &package, &slot.pair).await.ok();
                batch_cache.insert(cache_key, fetched.clone());
                fetched
            };
            let result = match batch.as_ref() {
                Some(batch) => process_slot_against_batch(state, &package, slot, batch).await,
                None => slot_result(
                    slot,
                    RelaySlotStatus::Failed,
                    Some("Current batch unavailable".into()),
                ),
            };
            record_slot_result(state, &package.package_id, result.clone()).await;
            emitted.push(result);
        }
    }
    if !emitted.is_empty() {
        let _ = persist_store(&state.config.store_path, &state.store).await;
    }
    if let PersistentTickLease::Acquired(owner) = persistent_lease {
        release_persistent_tick_lease(&state.config.store_path, &owner).await;
    }
    emitted
}

fn batch_cache_key(state: &AppState, package: &OfflineRenewalPackage, pair: &str) -> String {
    let coordinator_url = package_coordinator_url(&state.config, package).unwrap_or_default();
    format!("{coordinator_url}|{pair}")
}

async fn should_attempt_slot(
    state: &AppState,
    package_id: &str,
    slot: &OfflineRenewalSlot,
) -> bool {
    let store = state.store.read().await;
    let Some(stored) = store.packages.get(package_id) else {
        return false;
    };
    let Some(result) = stored.results.get(&slot.slot_id) else {
        return true;
    };
    if matches!(
        result.result.status,
        RelaySlotStatus::Submitted | RelaySlotStatus::AlreadySubmitted | RelaySlotStatus::Missed
    ) {
        return false;
    }
    if result.attempts >= state.config.max_attempts {
        return false;
    }
    now_unix_ms().saturating_sub(result.last_attempt_unix_ms) >= state.config.retry_backoff_ms
}

async fn process_slot_against_batch(
    state: &AppState,
    package: &OfflineRenewalPackage,
    slot: &OfflineRenewalSlot,
    batch: &PublicBatchSummary,
) -> OfflineRenewalRelayResult {
    if batch.epoch_id > slot.epoch_id
        || (batch.epoch_id == slot.epoch_id && batch.batch_id != slot.batch_id)
    {
        return slot_result(
            slot,
            RelaySlotStatus::Missed,
            Some("Authorized batch window passed".into()),
        );
    }
    if batch.batch_id != slot.batch_id || batch.epoch_id != slot.epoch_id {
        return slot_result(slot, RelaySlotStatus::NotDue, None);
    }
    if batch.status != "Open" {
        return slot_result(
            slot,
            RelaySlotStatus::BatchNotOpen,
            Some(batch.status.clone()),
        );
    }
    let now = now_unix_ms();
    if batch.close_time_unix_ms.saturating_sub(now)
        <= package.relay_policy.submission_safety_buffer_ms
    {
        return slot_result(slot, RelaySlotStatus::SafetyBuffer, None);
    }
    let scheduled_at = scheduled_submission_time(batch, package, slot);
    if now < scheduled_at {
        return slot_result(
            slot,
            RelaySlotStatus::NotDue,
            Some(format!("scheduled at {scheduled_at}")),
        );
    }
    match submit_slot(state, package, slot).await {
        Ok(accepted) => {
            let mut result = slot_result(slot, RelaySlotStatus::Submitted, None);
            result.accepted = Some(accepted);
            result
        }
        Err(error) => slot_result(slot, RelaySlotStatus::Failed, Some(error)),
    }
}

async fn submit_slot(
    state: &AppState,
    package: &OfflineRenewalPackage,
    slot: &OfflineRenewalSlot,
) -> Result<CoordinatorAccepted, String> {
    let prover_url = package_prover_url(&state.config, package)?;
    let coordinator_url = package_coordinator_url(&state.config, package)?;
    let ingress: IngressResponse = post_json(
        &state.http,
        &prover_url,
        "/api/private/orders",
        &slot.ingress_request,
        None,
    )
    .await?;
    let order_path = if state.config.coordinator_control_token.is_some() {
        "/api/maker/orders"
    } else {
        "/api/orders"
    };
    post_json(
        &state.http,
        &coordinator_url,
        order_path,
        &ingress.coordinator_submission,
        state
            .config
            .coordinator_control_token
            .as_deref()
            .map(String::as_str),
    )
    .await
}

async fn fetch_current_batch(
    state: &AppState,
    package: &OfflineRenewalPackage,
    pair: &str,
) -> Result<PublicBatchSummary, String> {
    let coordinator_url = package_coordinator_url(&state.config, package)?;
    let (base, quote) = pair
        .split_once('/')
        .ok_or_else(|| format!("invalid pair {pair}"))?;
    get_json(
        &state.http,
        &coordinator_url,
        &format!("/api/pairs/{base}/{quote}/batches/current"),
    )
    .await
}

async fn record_slot_result(state: &AppState, package_id: &str, result: OfflineRenewalRelayResult) {
    let now = now_unix_ms();
    let mut store = state.store.write().await;
    let Some(package) = store.packages.get_mut(package_id) else {
        return;
    };
    let previous_attempts = package
        .results
        .get(&result.slot_id)
        .map(|entry| entry.attempts)
        .unwrap_or_default();
    let attempts = if matches!(result.status, RelaySlotStatus::NotDue) {
        previous_attempts
    } else {
        previous_attempts.saturating_add(1)
    };
    package.results.insert(
        result.slot_id.clone(),
        StoredSlotResult {
            result,
            attempts,
            last_attempt_unix_ms: now,
        },
    );
    package.updated_at_unix_ms = now;
}

async fn post_json<T: for<'de> Deserialize<'de>>(
    http: &Client,
    base_url: &str,
    path: &str,
    body: &Value,
    bearer_token: Option<&str>,
) -> Result<T, String> {
    let mut request = http
        .post(format!("{base_url}{path}"))
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .json(body);
    if let Some(token) = bearer_token {
        request = request.header(AUTHORIZATION.as_str(), format_bearer_token(token));
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response.text().await.unwrap_or_default();
        return Err(format!("HTTP {status}: {detail}"));
    }
    response
        .json::<T>()
        .await
        .map_err(|error| format!("invalid JSON response: {error}"))
}

async fn get_json<T: for<'de> Deserialize<'de>>(
    http: &Client,
    base_url: &str,
    path: &str,
) -> Result<T, String> {
    let response = http
        .get(format!("{base_url}{path}"))
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response.text().await.unwrap_or_default();
        return Err(format!("HTTP {status}: {detail}"));
    }
    response
        .json::<T>()
        .await
        .map_err(|error| format!("invalid JSON response: {error}"))
}

fn validate_package(
    package: &OfflineRenewalPackage,
    config: &RelayConfig,
) -> Result<(), RelayApiError> {
    if package.version != 1 {
        return Err(RelayApiError::bad_request(
            "Unsupported renewal package version",
        ));
    }
    if package.relay_mode != Some(RelayMode::ZylithRelay) {
        return Err(RelayApiError::bad_request(
            "Managed relay only accepts ZylithRelay packages",
        ));
    }
    if package.package_id.trim().is_empty() || package.package_commitment.trim().is_empty() {
        return Err(RelayApiError::bad_request(
            "Renewal package identity is missing",
        ));
    }
    if package.slot_count == 0 || package.slots.is_empty() {
        return Err(RelayApiError::bad_request("Renewal package has no slots"));
    }
    if package.slot_count != package.slots.len() {
        return Err(RelayApiError::bad_request(
            "Renewal package slot_count does not match slots length",
        ));
    }
    if package.slots.len() > config.max_package_slots {
        return Err(RelayApiError::bad_request(
            "Renewal package exceeds slot limit",
        ));
    }
    if package.start_epoch > package.end_epoch {
        return Err(RelayApiError::bad_request(
            "Renewal package epoch range is invalid",
        ));
    }
    if package_prover_url(config, package).is_err()
        || package_coordinator_url(config, package).is_err()
    {
        return Err(RelayApiError::bad_request(
            "Renewal package requires coordinator and prover URLs",
        ));
    }
    if config.strict_mode {
        if let (Some(default), Some(policy)) = (
            config.default_prover_url.as_ref(),
            package_prover_url_from_policy(package),
        ) && &policy != default
        {
            return Err(RelayApiError::bad_request(
                "Renewal package prover URL does not match the managed relay configuration",
            ));
        }
        if let (Some(default), Some(policy)) = (
            config.default_coordinator_url.as_ref(),
            package_coordinator_url_from_policy(package),
        ) && &policy != default
        {
            return Err(RelayApiError::bad_request(
                "Renewal package coordinator URL does not match the managed relay configuration",
            ));
        }
    }
    let mut slot_ids = BTreeSet::new();
    let mut commitments = BTreeSet::new();
    for slot in &package.slots {
        if slot.pair != package.pair {
            return Err(RelayApiError::bad_request("Renewal slot pair mismatch"));
        }
        if slot.epoch_id < package.start_epoch || slot.epoch_id > package.end_epoch {
            return Err(RelayApiError::bad_request(
                "Renewal slot epoch outside package range",
            ));
        }
        if !slot.order_commitment.starts_with("0x") {
            return Err(RelayApiError::bad_request(
                "Renewal slot commitment must be felt-like",
            ));
        }
        if !slot.ingress_request.is_object() {
            return Err(RelayApiError::bad_request(
                "Renewal slot ingress request must be an object",
            ));
        }
        if !slot_ids.insert(slot.slot_id.clone())
            || !commitments.insert(slot.order_commitment.clone())
        {
            return Err(RelayApiError::bad_request("Duplicate renewal slot"));
        }
    }
    Ok(())
}

fn package_status(stored: &StoredPackage) -> PackageStatus {
    let submitted_slots = stored
        .results
        .values()
        .filter(|entry| {
            matches!(
                entry.result.status,
                RelaySlotStatus::Submitted | RelaySlotStatus::AlreadySubmitted
            )
        })
        .count();
    let failed_slots = stored
        .results
        .values()
        .filter(|entry| matches!(entry.result.status, RelaySlotStatus::Failed))
        .count();
    PackageStatus {
        package_id: stored.package.package_id.clone(),
        package_commitment: stored.package.package_commitment.clone(),
        pair: stored.package.pair.clone(),
        start_epoch: stored.package.start_epoch,
        end_epoch: stored.package.end_epoch,
        slot_count: stored.package.slot_count,
        relay_mode: RelayMode::ZylithRelay,
        pending_slots: stored.package.slot_count.saturating_sub(submitted_slots),
        submitted_slots,
        failed_slots,
        updated_at_unix_ms: stored.updated_at_unix_ms,
    }
}

fn slot_result(
    slot: &OfflineRenewalSlot,
    status: RelaySlotStatus,
    detail: Option<String>,
) -> OfflineRenewalRelayResult {
    OfflineRenewalRelayResult {
        slot_id: slot.slot_id.clone(),
        pair: slot.pair.clone(),
        parent_child_index: slot.parent_child_index,
        order_commitment: slot.order_commitment.clone(),
        batch_id: slot.batch_id.clone(),
        epoch_id: slot.epoch_id,
        status,
        detail,
        accepted: None,
    }
}

fn scheduled_submission_time(
    batch: &PublicBatchSummary,
    package: &OfflineRenewalPackage,
    slot: &OfflineRenewalSlot,
) -> u64 {
    let close_minus_safety = batch
        .close_time_unix_ms
        .saturating_sub(package.relay_policy.submission_safety_buffer_ms);
    let max_delay = package.relay_policy.max_submission_delay_ms;
    if max_delay == 0 {
        return 0;
    }
    let window_start = close_minus_safety.saturating_sub(max_delay);
    window_start.saturating_add(stable_jitter_ms(slot, package).min(max_delay))
}

fn stable_jitter_ms(slot: &OfflineRenewalSlot, package: &OfflineRenewalPackage) -> u64 {
    let max_delay = package.relay_policy.max_submission_delay_ms;
    if max_delay == 0 {
        return 0;
    }
    let mut hasher = Sha256::new();
    hasher.update(package.package_commitment.as_bytes());
    hasher.update(slot.slot_id.as_bytes());
    let digest = hasher.finalize();
    let value = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    value % (max_delay + 1)
}

fn package_prover_url(
    config: &RelayConfig,
    package: &OfflineRenewalPackage,
) -> Result<String, String> {
    config
        .default_prover_url
        .clone()
        .or_else(|| package_prover_url_from_policy(package))
        .ok_or_else(|| "private ingress URL missing".into())
}

fn package_coordinator_url(
    config: &RelayConfig,
    package: &OfflineRenewalPackage,
) -> Result<String, String> {
    config
        .default_coordinator_url
        .clone()
        .or_else(|| package_coordinator_url_from_policy(package))
        .ok_or_else(|| "coordinator URL missing".into())
}

fn package_prover_url_from_policy(package: &OfflineRenewalPackage) -> Option<String> {
    non_empty(&package.relay_policy.prover_url).map(normalize_url)
}

fn package_coordinator_url_from_policy(package: &OfflineRenewalPackage) -> Option<String> {
    non_empty(&package.relay_policy.coordinator_url).map(normalize_url)
}

fn require_package_auth(state: &AppState, headers: &HeaderMap) -> Result<(), RelayApiError> {
    require_optional_bearer(
        state
            .config
            .package_registration_token
            .as_deref()
            .map(String::as_str),
        headers,
    )
    .map_err(RelayApiError::status)
}

fn require_internal_auth(state: &AppState, headers: &HeaderMap) -> Result<(), RelayApiError> {
    require_optional_bearer(
        state
            .config
            .coordinator_control_token
            .as_deref()
            .map(String::as_str),
        headers,
    )
    .map_err(RelayApiError::status)
}

fn require_optional_bearer(expected: Option<&str>, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !constant_time_eq(token, expected) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

async fn enforce_rate_limit(state: &AppState, headers: &HeaderMap) -> Result<(), RelayApiError> {
    let limit = state.config.rate_limit_per_minute;
    if limit == 0 {
        return Ok(());
    }
    let key = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer_token)
        .map(|token| {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            format!("{:x}", hasher.finalize())
        })
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "anonymous".into());
    let now = now_unix_ms();
    let mut limits = state.rate_limits.write().await;
    let bucket = limits.entry(key).or_default();
    if now.saturating_sub(bucket.window_start_unix_ms) >= 60_000 {
        bucket.window_start_unix_ms = now;
        bucket.count = 0;
    }
    bucket.count = bucket.count.saturating_add(1);
    if bucket.count > limit {
        return Err(RelayApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            detail: "Renewal relay rate limit exceeded".into(),
        });
    }
    limits.retain(|_, bucket| now.saturating_sub(bucket.window_start_unix_ms) < 120_000);
    Ok(())
}

fn prune_store_locked(store: &mut RelayStore, config: &RelayConfig, now: u64) {
    if config.package_retention_ms == 0 {
        return;
    }
    store.packages.retain(|_, package| {
        now.saturating_sub(package.updated_at_unix_ms) <= config.package_retention_ms
    });
}

async fn load_store(path: &FsPath) -> Result<RelayStore, String> {
    if is_sqlite_store(path) {
        return load_sqlite_store(path).await;
    }
    let bytes = match fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RelayStore::default());
        }
        Err(error) => return Err(error.to_string()),
    };
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

async fn persist_store(
    path: &FsPath,
    store: &Arc<RwLock<RelayStore>>,
) -> Result<(), RelayApiError> {
    let snapshot = store.read().await.clone();
    if is_sqlite_store(path) {
        return persist_sqlite_store(path, snapshot)
            .await
            .map_err(RelayApiError::internal);
    }
    let bytes = serde_json::to_vec_pretty(&snapshot).map_err(RelayApiError::internal)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(RelayApiError::internal)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes)
        .await
        .map_err(RelayApiError::internal)?;
    fs::rename(tmp, path)
        .await
        .map_err(RelayApiError::internal)?;
    Ok(())
}

fn is_sqlite_store(path: &FsPath) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "sqlite" | "sqlite3" | "db"
            )
        })
        .unwrap_or(false)
}

async fn load_sqlite_store(path: &FsPath) -> Result<RelayStore, String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || load_sqlite_store_sync(&path))
        .await
        .map_err(|error| error.to_string())?
}

fn load_sqlite_store_sync(path: &FsPath) -> Result<RelayStore, String> {
    let connection = open_sqlite_store(path)?;
    let mut store = RelayStore::default();
    {
        let mut statement = connection
            .prepare(
                "SELECT package_id, package_json, registered_at_unix_ms, updated_at_unix_ms \
                 FROM relay_packages",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = statement.query([]).map_err(|error| error.to_string())?;
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let package_id: String = row.get(0).map_err(|error| error.to_string())?;
            let package_json: String = row.get(1).map_err(|error| error.to_string())?;
            let package = serde_json::from_str::<OfflineRenewalPackage>(&package_json)
                .map_err(|error| format!("invalid package JSON for {package_id}: {error}"))?;
            let registered_at_unix_ms = row.get::<_, i64>(2).map_err(|error| error.to_string())?;
            let updated_at_unix_ms = row.get::<_, i64>(3).map_err(|error| error.to_string())?;
            store.packages.insert(
                package_id,
                StoredPackage {
                    package,
                    registered_at_unix_ms: registered_at_unix_ms.max(0) as u64,
                    updated_at_unix_ms: updated_at_unix_ms.max(0) as u64,
                    results: BTreeMap::new(),
                },
            );
        }
    }
    {
        let mut statement = connection
            .prepare(
                "SELECT package_id, slot_id, result_json, attempts, last_attempt_unix_ms \
                 FROM relay_slot_results",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = statement.query([]).map_err(|error| error.to_string())?;
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let package_id: String = row.get(0).map_err(|error| error.to_string())?;
            let slot_id: String = row.get(1).map_err(|error| error.to_string())?;
            let result_json: String = row.get(2).map_err(|error| error.to_string())?;
            let result = serde_json::from_str::<OfflineRenewalRelayResult>(&result_json)
                .map_err(|error| format!("invalid slot result JSON for {slot_id}: {error}"))?;
            let attempts = row.get::<_, i64>(3).map_err(|error| error.to_string())?;
            let last_attempt_unix_ms = row.get::<_, i64>(4).map_err(|error| error.to_string())?;
            if let Some(package) = store.packages.get_mut(&package_id) {
                package.results.insert(
                    slot_id,
                    StoredSlotResult {
                        result,
                        attempts: attempts.max(0) as u32,
                        last_attempt_unix_ms: last_attempt_unix_ms.max(0) as u64,
                    },
                );
            }
        }
    }
    Ok(store)
}

async fn persist_sqlite_store(path: &FsPath, snapshot: RelayStore) -> Result<(), String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || persist_sqlite_store_sync(&path, snapshot))
        .await
        .map_err(|error| error.to_string())?
}

fn persist_sqlite_store_sync(path: &FsPath, snapshot: RelayStore) -> Result<(), String> {
    let mut connection = open_sqlite_store(path)?;
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    transaction
        .execute("DELETE FROM relay_slot_results", [])
        .map_err(|error| error.to_string())?;
    transaction
        .execute("DELETE FROM relay_packages", [])
        .map_err(|error| error.to_string())?;
    for (package_id, stored) in snapshot.packages {
        let package_json =
            serde_json::to_string(&stored.package).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO relay_packages \
                 (package_id, package_commitment, pair, start_epoch, end_epoch, slot_count, \
                  package_json, registered_at_unix_ms, updated_at_unix_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    package_id.as_str(),
                    stored.package.package_commitment.as_str(),
                    stored.package.pair.as_str(),
                    stored.package.start_epoch as i64,
                    stored.package.end_epoch as i64,
                    stored.package.slot_count as i64,
                    package_json.as_str(),
                    stored.registered_at_unix_ms as i64,
                    stored.updated_at_unix_ms as i64,
                ],
            )
            .map_err(|error| error.to_string())?;
        for (slot_id, result) in stored.results {
            let result_json =
                serde_json::to_string(&result.result).map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO relay_slot_results \
                     (package_id, slot_id, result_json, attempts, last_attempt_unix_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        package_id.as_str(),
                        slot_id.as_str(),
                        result_json.as_str(),
                        result.attempts as i64,
                        result.last_attempt_unix_ms as i64,
                    ],
                )
                .map_err(|error| error.to_string())?;
        }
    }
    transaction.commit().map_err(|error| error.to_string())
}

fn open_sqlite_store(path: &FsPath) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    configure_sqlite_store(&connection)?;
    Ok(connection)
}

fn configure_sqlite_store(connection: &Connection) -> Result<(), String> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS relay_packages (
                package_id TEXT PRIMARY KEY,
                package_commitment TEXT NOT NULL,
                pair TEXT NOT NULL,
                start_epoch INTEGER NOT NULL,
                end_epoch INTEGER NOT NULL,
                slot_count INTEGER NOT NULL,
                package_json TEXT NOT NULL,
                registered_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS relay_packages_pair_idx ON relay_packages(pair);
            CREATE INDEX IF NOT EXISTS relay_packages_updated_idx ON relay_packages(updated_at_unix_ms);
            CREATE TABLE IF NOT EXISTS relay_slot_results (
                package_id TEXT NOT NULL,
                slot_id TEXT NOT NULL,
                result_json TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_attempt_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (package_id, slot_id),
                FOREIGN KEY(package_id) REFERENCES relay_packages(package_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS relay_slot_results_last_attempt_idx
                ON relay_slot_results(last_attempt_unix_ms);
            CREATE TABLE IF NOT EXISTS relay_locks (
                name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL
            );",
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

enum PersistentTickLease {
    Disabled,
    Busy,
    Acquired(String),
}

async fn acquire_persistent_tick_lease(config: &RelayConfig) -> PersistentTickLease {
    if !is_sqlite_store(&config.store_path) {
        return PersistentTickLease::Disabled;
    }
    let path = config.store_path.clone();
    let lease_ms = config
        .tick_interval_ms
        .saturating_mul(4)
        .max(config.retry_backoff_ms)
        .max(10_000);
    tokio::task::spawn_blocking(move || acquire_persistent_tick_lease_sync(&path, lease_ms))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(PersistentTickLease::Busy)
}

fn acquire_persistent_tick_lease_sync(
    path: &FsPath,
    lease_ms: u64,
) -> Result<PersistentTickLease, String> {
    let owner = format!("pid:{}:{}", std::process::id(), now_unix_ms());
    let now = now_unix_ms();
    let expires_at = now.saturating_add(lease_ms) as i64;
    let mut connection = open_sqlite_store(path)?;
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    let existing = transaction
        .query_row(
            "SELECT owner, expires_at_unix_ms FROM relay_locks WHERE name = 'worker_tick'",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .ok();
    if let Some((existing_owner, existing_expires_at)) = existing
        && existing_expires_at > now as i64
        && existing_owner != owner
    {
        return Ok(PersistentTickLease::Busy);
    }
    transaction
        .execute(
            "INSERT INTO relay_locks (name, owner, expires_at_unix_ms)
             VALUES ('worker_tick', ?1, ?2)
             ON CONFLICT(name) DO UPDATE SET
                owner = excluded.owner,
                expires_at_unix_ms = excluded.expires_at_unix_ms",
            params![owner, expires_at],
        )
        .map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(PersistentTickLease::Acquired(owner))
}

async fn release_persistent_tick_lease(path: &FsPath, owner: &str) {
    if !is_sqlite_store(path) {
        return;
    }
    let path = path.to_path_buf();
    let owner = owner.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        let connection = open_sqlite_store(&path)?;
        connection
            .execute(
                "DELETE FROM relay_locks WHERE name = 'worker_tick' AND owner = ?1",
                params![owner],
            )
            .map_err(|error| error.to_string())?;
        Ok::<(), String>(())
    })
    .await;
}

fn service_cors_layer(config: &RelayConfig) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);
    if config.allowed_origins.is_empty() {
        return layer.allow_origin(Any);
    }
    layer.allow_origin(AllowOrigin::list(config.allowed_origins.clone()))
}

fn parse_allowed_origins(env_name: &str) -> Result<Vec<HeaderValue>, String> {
    let Some(value) = env::var(env_name).ok() else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            HeaderValue::from_str(origin)
                .map_err(|error| format!("invalid {env_name} origin {origin}: {error}"))
        })
        .collect()
}

fn normalize_url(value: String) -> String {
    value.trim_end_matches('/').to_string()
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn env_u64(name: &str, fallback: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

fn env_u32(name: &str, fallback: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

fn env_usize(name: &str, fallback: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

fn env_bool(name: &str, fallback: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(fallback)
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug)]
struct RelayApiError {
    status: StatusCode,
    detail: String,
}

impl RelayApiError {
    fn status(status: StatusCode) -> Self {
        Self {
            status,
            detail: status
                .canonical_reason()
                .unwrap_or("Relay request failed")
                .into(),
        }
    }

    fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            detail: detail.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            detail: error.to_string(),
        }
    }
}

impl IntoResponse for RelayApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(json!({
                "error": self.detail,
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    fn test_package(coordinator_url: String, prover_url: String) -> OfflineRenewalPackage {
        OfflineRenewalPackage {
            version: 1,
            package_id: "pkg-1".into(),
            package_commitment: "0xabc".into(),
            created_at_unix_ms: 1,
            pair: "STRK/USDC".into(),
            start_epoch: 42,
            end_epoch: 42,
            slot_count: 1,
            relay_mode: Some(RelayMode::ZylithRelay),
            ingress_key_registry_fingerprint: None,
            relay_policy: RelayPolicy {
                prover_url,
                coordinator_url,
                submission_safety_buffer_ms: 1_000,
                max_submission_delay_ms: 0,
            },
            slots: vec![OfflineRenewalSlot {
                slot_id: "pkg-1:1".into(),
                pair: "STRK/USDC".into(),
                batch_id: "STRK-USDC-42".into(),
                epoch_id: 42,
                parent_child_index: 1,
                order_commitment: "0x123".into(),
                ingress_request: json!({ "order_submission": { "opaque": true } }),
            }],
        }
    }

    fn test_state(path: PathBuf) -> AppState {
        AppState {
            config: RelayConfig {
                bind_addr: DEFAULT_BIND_ADDR.parse().unwrap(),
                store_path: path,
                package_registration_token: None,
                default_coordinator_url: None,
                default_prover_url: None,
                coordinator_control_token: None,
                tick_interval_ms: DEFAULT_TICK_MS,
                enable_worker: false,
                max_package_slots: DEFAULT_MAX_PACKAGE_SLOTS,
                retry_backoff_ms: 0,
                max_attempts: DEFAULT_MAX_ATTEMPTS,
                strict_mode: false,
                allowed_origins: Vec::new(),
                max_body_bytes: DEFAULT_MAX_BODY_BYTES,
                package_retention_ms: DEFAULT_PACKAGE_RETENTION_MS,
                rate_limit_per_minute: 0,
            },
            store: Arc::new(RwLock::new(RelayStore::default())),
            http: Client::new(),
            tick_lock: Arc::new(Mutex::new(())),
            rate_limits: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    #[test]
    fn validation_rejects_self_relay_packages() {
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        package.relay_mode = Some(RelayMode::SelfRelay);
        let state = test_state(temp_store_path("validate-self-relay"));
        assert!(validate_package(&package, &state.config).is_err());
    }

    #[test]
    fn validation_rejects_duplicate_slots() {
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        package.slots.push(package.slots[0].clone());
        package.slot_count = package.slots.len();
        let state = test_state(temp_store_path("validate-duplicate"));
        assert!(validate_package(&package, &state.config).is_err());
    }

    #[test]
    fn strict_validation_rejects_unpinned_package_urls() {
        let mut package = test_package(
            "http://other-coordinator".into(),
            "http://other-prover".into(),
        );
        let mut state = test_state(temp_sqlite_store_path("strict-url-pin"));
        state.config.strict_mode = true;
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.package_registration_token = Some(Arc::new("package-token".into()));
        state.config.coordinator_control_token = Some(Arc::new("control-token".into()));
        state.config.allowed_origins = vec![HeaderValue::from_static("https://app.zylith.fi")];
        assert!(validate_package(&package, &state.config).is_err());

        package.relay_policy.coordinator_url = "http://coordinator".into();
        package.relay_policy.prover_url = "http://prover".into();
        assert!(validate_package(&package, &state.config).is_ok());
        cleanup_sqlite_store(&state.config.store_path);
    }

    #[tokio::test]
    async fn register_package_persists_sanitized_status() {
        let path = temp_store_path("register");
        let state = test_state(path.clone());
        let package = test_package("http://coordinator".into(), "http://prover".into());
        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/relay/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(path.exists());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_due_slot_posts_through_prover_and_coordinator() {
        let (coordinator_url, coordinator_shutdown) = spawn_mock_coordinator().await;
        let (prover_url, prover_shutdown) = spawn_mock_prover().await;
        let path = temp_store_path("process");
        let state = test_state(path.clone());
        let package = test_package(coordinator_url, prover_url);
        {
            let mut store = state.store.write().await;
            let now = now_unix_ms();
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package,
                    registered_at_unix_ms: now,
                    updated_at_unix_ms: now,
                    results: BTreeMap::new(),
                },
            );
        }
        let results = process_due_slots_once(&state).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, RelaySlotStatus::Submitted);
        assert_eq!(
            results[0]
                .accepted
                .as_ref()
                .map(|accepted| accepted.batch_id.as_str()),
            Some("STRK-USDC-42")
        );
        let _ = coordinator_shutdown.send(());
        let _ = prover_shutdown.send(());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn sqlite_store_persists_packages_results_and_tick_lease() {
        let path = temp_sqlite_store_path("sqlite");
        let package = test_package("http://coordinator".into(), "http://prover".into());
        let result = slot_result(&package.slots[0], RelaySlotStatus::Submitted, None);
        let mut store = RelayStore::default();
        store.packages.insert(
            package.package_id.clone(),
            StoredPackage {
                package: package.clone(),
                registered_at_unix_ms: 10,
                updated_at_unix_ms: 20,
                results: BTreeMap::from([(
                    package.slots[0].slot_id.clone(),
                    StoredSlotResult {
                        result,
                        attempts: 2,
                        last_attempt_unix_ms: 30,
                    },
                )]),
            },
        );
        persist_sqlite_store(&path, store).await.unwrap();
        let loaded = load_sqlite_store(&path).await.unwrap();
        let loaded_package = loaded.packages.get(&package.package_id).unwrap();
        assert_eq!(loaded_package.package.package_commitment, "0xabc");
        assert_eq!(
            loaded_package
                .results
                .get(&package.slots[0].slot_id)
                .unwrap()
                .attempts,
            2,
        );

        let lease = acquire_persistent_tick_lease_sync(&path, 60_000).unwrap();
        let owner = match lease {
            PersistentTickLease::Acquired(owner) => owner,
            PersistentTickLease::Busy | PersistentTickLease::Disabled => {
                panic!("expected persistent tick lease")
            }
        };
        assert!(matches!(
            acquire_persistent_tick_lease_sync(&path, 60_000).unwrap(),
            PersistentTickLease::Busy,
        ));
        release_persistent_tick_lease(&path, &owner).await;
        assert!(matches!(
            acquire_persistent_tick_lease_sync(&path, 60_000).unwrap(),
            PersistentTickLease::Acquired(_),
        ));
        cleanup_sqlite_store(&path);
    }

    async fn spawn_mock_coordinator() -> (String, oneshot::Sender<()>) {
        let app = Router::new()
            .route(
                "/api/pairs/STRK/USDC/batches/current",
                get(|| async {
                    Json(json!({
                        "batch_id": "STRK-USDC-42",
                        "pair_id": "STRK/USDC",
                        "epoch_id": 42,
                        "close_time_unix_ms": now_unix_ms() + 60_000,
                        "status": "Open",
                        "order_count_bucket": "0"
                    }))
                }),
            )
            .route(
                "/api/orders",
                post(|Json(_body): Json<Value>| async {
                    Json(json!({
                        "batch_id": "STRK-USDC-42",
                        "order_commitment": "0x123",
                        "accepted_at_unix_ms": now_unix_ms()
                    }))
                }),
            );
        spawn_mock(app).await
    }

    async fn spawn_mock_prover() -> (String, oneshot::Sender<()>) {
        let app = Router::new().route(
            "/api/private/orders",
            post(|Json(_body): Json<Value>| async {
                Json(json!({
                    "receipt": { "payload_commitment": "0xabc" },
                    "coordinator_submission": { "order_bundle": { "opaque": true } }
                }))
            }),
        );
        spawn_mock(app).await
    }

    async fn spawn_mock(app: Router) -> (String, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        (format!("http://{addr}"), tx)
    }

    fn temp_store_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "zylith-renewal-relayer-{name}-{}.json",
            now_unix_ms()
        ));
        path
    }

    fn temp_sqlite_store_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "zylith-renewal-relayer-{name}-{}.sqlite",
            now_unix_ms()
        ));
        path
    }

    fn cleanup_sqlite_store(path: &FsPath) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}

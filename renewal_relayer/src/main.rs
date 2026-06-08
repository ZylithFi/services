use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    extract::{ConnectInfo, FromRequestParts, Path, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE},
        request::Parts,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ipnet::IpNet;
use reqwest::Client;
use rusqlite::{Connection, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    fs,
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use zylith_core::{constant_time_eq, extract_bearer_token, format_bearer_token};

#[derive(Clone, Copy)]
struct PeerAddress(Option<SocketAddr>);

impl<S> FromRequestParts<S> for PeerAddress
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

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

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3400";
const DEFAULT_STORE_PATH: &str = "renewal_relayer/relay_store.dev.json";
const DEFAULT_TICK_MS: u64 = 5_000;
const DEFAULT_MAX_PACKAGE_SLOTS: usize = 86_400;
const DEFAULT_RETRY_BACKOFF_MS: u64 = 8_000;
const DEFAULT_MAX_ATTEMPTS: u32 = 16;
const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_PACKAGE_RETENTION_MS: u64 = 120 * 24 * 60 * 60 * 1000;
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;
const DEFAULT_PACKAGE_EXPIRY_WARNING_EPOCHS: u64 = 960;
const DEFAULT_ALERT_REPEAT_MS: u64 = 15 * 60 * 1000;
const MIN_MANAGED_SUBMISSION_SAFETY_BUFFER_MS: u64 = 5_000;
const MAX_MANAGED_SUBMISSION_SAFETY_BUFFER_MS: u64 = 60_000;
const MIN_MANAGED_SUBMISSION_DELAY_MS: u64 = 10_000;
const MAX_MANAGED_SUBMISSION_DELAY_MS: u64 = 60_000;
const BIND_ADDR_ENV: &str = "ZYLITH_RENEWAL_RELAY_BIND_ADDR";
const STORE_PATH_ENV: &str = "ZYLITH_RENEWAL_RELAY_STORE_PATH";
const PACKAGE_TOKEN_ENV: &str = "ZYLITH_RENEWAL_RELAY_PACKAGE_TOKEN";
const COORDINATOR_URL_ENV: &str = "ZYLITH_RENEWAL_RELAY_COORDINATOR_URL";
const PROVER_URL_ENV: &str = "ZYLITH_RENEWAL_RELAY_PROVER_URL";
const COORDINATOR_URLS_ENV: &str = "ZYLITH_RENEWAL_RELAY_COORDINATOR_URLS";
const PROVER_URLS_ENV: &str = "ZYLITH_RENEWAL_RELAY_PROVER_URLS";
const COORDINATOR_CONTROL_TOKEN_ENV: &str = "ZYLITH_RENEWAL_RELAY_COORDINATOR_CONTROL_TOKEN";
const INTERNAL_TOKEN_ENV: &str = "ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN";
const PROVER_CONTROL_TOKEN_ENV: &str = "ZYLITH_RENEWAL_RELAY_PROVER_CONTROL_TOKEN";
const ALERT_WEBHOOK_URLS_ENV: &str = "ZYLITH_RENEWAL_RELAY_ALERT_WEBHOOK_URLS";
const ALERT_WEBHOOK_TOKEN_ENV: &str = "ZYLITH_RENEWAL_RELAY_ALERT_WEBHOOK_TOKEN";
const ALERT_REPEAT_MS_ENV: &str = "ZYLITH_RENEWAL_RELAY_ALERT_REPEAT_MS";
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
const ACCEPT_RELAY_MODE_ENV: &str = "ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE";
const PACKAGE_EXPIRY_WARNING_EPOCHS_ENV: &str =
    "ZYLITH_RENEWAL_RELAY_PACKAGE_EXPIRY_WARNING_EPOCHS";
const RELAY_PACKAGE_COMMITMENT_HEADER: &str = "x-zylith-relay-package-commitment";
const RELAY_PARENT_CANCEL_AUTHORITY_HEADER: &str = "x-zylith-relay-parent-cancel-authority";
const RELAY_SIGNER_HEADER: &str = "x-zylith-relay-signer";
const RELAY_SIGNATURE_R_HEADER: &str = "x-zylith-relay-signature-r";
const RELAY_SIGNATURE_S_HEADER: &str = "x-zylith-relay-signature-s";
static TICK_LEASE_OWNER_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct RelayConfig {
    bind_addr: SocketAddr,
    store_path: PathBuf,
    package_registration_token: Option<Arc<String>>,
    default_coordinator_url: Option<String>,
    default_prover_url: Option<String>,
    default_coordinator_failover_urls: Vec<String>,
    default_prover_failover_urls: Vec<String>,
    coordinator_control_token: Option<Arc<String>>,
    internal_control_token: Option<Arc<String>>,
    prover_control_token: Option<Arc<String>>,
    alert_webhook_urls: Vec<String>,
    alert_webhook_token: Option<Arc<String>>,
    alert_repeat_ms: u64,
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
    accepted_relay_mode: AcceptedRelayMode,
    package_expiry_warning_epochs: u64,
}

impl RelayConfig {
    fn from_env() -> Result<Self, String> {
        let bind_addr: SocketAddr = env::var(BIND_ADDR_ENV)
            .unwrap_or_else(|_| DEFAULT_BIND_ADDR.into())
            .parse()
            .map_err(|error| format!("invalid {BIND_ADDR_ENV}: {error}"))?;
        let strict_mode = env_bool(STRICT_MODE_ENV, !bind_addr.ip().is_loopback());
        let package_registration_token = env::var(PACKAGE_TOKEN_ENV).ok().map(Arc::new);
        let coordinator_control_token = env::var(COORDINATOR_CONTROL_TOKEN_ENV).ok().map(Arc::new);
        let internal_control_token = env::var(INTERNAL_TOKEN_ENV)
            .or_else(|_| env::var(zylith_core::CONTROL_PLANE_TOKEN_ENV))
            .ok()
            .map(Arc::new);
        let prover_control_token = env::var(PROVER_CONTROL_TOKEN_ENV).ok().map(Arc::new);
        let allowed_origins = parse_allowed_origins(ALLOWED_ORIGINS_ENV)?;
        let store_path =
            PathBuf::from(env::var(STORE_PATH_ENV).unwrap_or_else(|_| DEFAULT_STORE_PATH.into()));
        let accepted_relay_mode_env = env::var(ACCEPT_RELAY_MODE_ENV)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let accepted_relay_mode = AcceptedRelayMode::from_configured_value(
            accepted_relay_mode_env.as_deref().unwrap_or("SelfRelay"),
        )?;
        let enable_worker = env_bool(ENABLE_WORKER_ENV, true);
        let coordinator_urls = configured_urls_from_env(COORDINATOR_URLS_ENV, COORDINATOR_URL_ENV);
        let prover_urls = configured_urls_from_env(PROVER_URLS_ENV, PROVER_URL_ENV);
        if (enable_worker || !bind_addr.ip().is_loopback()) && coordinator_urls.is_empty() {
            return Err(format!(
                "{COORDINATOR_URL_ENV} or {COORDINATOR_URLS_ENV} is required when the renewal relay worker is enabled or the service is exposed"
            ));
        }
        if (enable_worker || !bind_addr.ip().is_loopback()) && prover_urls.is_empty() {
            return Err(format!(
                "{PROVER_URL_ENV} or {PROVER_URLS_ENV} is required when the renewal relay worker is enabled or the service is exposed"
            ));
        }
        if strict_mode {
            if accepted_relay_mode_env.is_none() {
                return Err(format!(
                    "{ACCEPT_RELAY_MODE_ENV} is required when {STRICT_MODE_ENV}=true"
                ));
            }
            if internal_control_token.is_none() {
                return Err(format!(
                    "{INTERNAL_TOKEN_ENV} or {} is required when {STRICT_MODE_ENV}=true",
                    zylith_core::CONTROL_PLANE_TOKEN_ENV,
                ));
            }
            if accepted_relay_mode == AcceptedRelayMode::ZylithRelay
                && coordinator_control_token.is_none()
            {
                return Err(format!(
                    "{COORDINATOR_CONTROL_TOKEN_ENV} is required for managed ZylithRelay mode when {STRICT_MODE_ENV}=true"
                ));
            }
            if coordinator_urls.is_empty() {
                return Err(format!(
                    "{COORDINATOR_URL_ENV} or {COORDINATOR_URLS_ENV} is required when {STRICT_MODE_ENV}=true"
                ));
            }
            if prover_urls.is_empty() {
                return Err(format!(
                    "{PROVER_URL_ENV} or {PROVER_URLS_ENV} is required when {STRICT_MODE_ENV}=true"
                ));
            }
            if prover_control_token.is_none() {
                return Err(format!(
                    "{PROVER_CONTROL_TOKEN_ENV} is required when {STRICT_MODE_ENV}=true"
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
        if !bind_addr.ip().is_loopback() && accepted_relay_mode_env.is_none() {
            return Err(format!(
                "{ACCEPT_RELAY_MODE_ENV} is required when the renewal relay is exposed"
            ));
        }
        Ok(Self {
            bind_addr,
            store_path,
            package_registration_token,
            default_coordinator_url: coordinator_urls.first().cloned(),
            default_prover_url: prover_urls.first().cloned(),
            default_coordinator_failover_urls: coordinator_urls.into_iter().skip(1).collect(),
            default_prover_failover_urls: prover_urls.into_iter().skip(1).collect(),
            coordinator_control_token,
            internal_control_token,
            prover_control_token,
            alert_webhook_urls: configured_urls_from_env(ALERT_WEBHOOK_URLS_ENV, ""),
            alert_webhook_token: env::var(ALERT_WEBHOOK_TOKEN_ENV).ok().map(Arc::new),
            alert_repeat_ms: env_u64(ALERT_REPEAT_MS_ENV, DEFAULT_ALERT_REPEAT_MS),
            tick_interval_ms: env_u64(TICK_MS_ENV, DEFAULT_TICK_MS),
            enable_worker,
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
            accepted_relay_mode,
            package_expiry_warning_epochs: env_u64(
                PACKAGE_EXPIRY_WARNING_EPOCHS_ENV,
                DEFAULT_PACKAGE_EXPIRY_WARNING_EPOCHS,
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptedRelayMode {
    ZylithRelay,
    SelfRelay,
    Any,
}

impl AcceptedRelayMode {
    fn from_configured_value(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "zylith" | "zylithrelay" | "managed" => Ok(Self::ZylithRelay),
            "self" | "selfrelay" | "self-hosted" | "selfhosted" => Ok(Self::SelfRelay),
            "any" | "both" => Ok(Self::Any),
            _ => Err(format!(
                "{ACCEPT_RELAY_MODE_ENV} must be ZylithRelay, SelfRelay, or Any"
            )),
        }
    }

    fn allows(self, mode: &RelayMode) -> bool {
        matches!(
            (self, mode),
            (Self::Any, _)
                | (Self::ZylithRelay, RelayMode::ZylithRelay)
                | (Self::SelfRelay, RelayMode::SelfRelay)
        )
    }

    fn label(self) -> &'static str {
        match self {
            Self::ZylithRelay => "ZylithRelay",
            Self::SelfRelay => "SelfRelay",
            Self::Any => "Any",
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: RelayConfig,
    store: Arc<RwLock<RelayStore>>,
    http: Client,
    tick_lock: Arc<Mutex<()>>,
    rate_limits: Arc<RwLock<BTreeMap<String, RateLimitBucket>>>,
    alert_dispatch_cache: Arc<RwLock<BTreeMap<String, u64>>>,
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
    #[serde(default)]
    cancelled_packages: BTreeMap<String, u64>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay_mode: Option<RelayMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_cancel_authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_cancel_marker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay_authorization: Option<RelayPackageAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    funding_note_commitments: Vec<String>,
    ingress_request: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RelayPackageAuthorization {
    signer_public_key: String,
    signature_r: String,
    signature_s: String,
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
    AwaitingSettlement,
    AwaitingWalletRefresh,
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

#[derive(Clone, Debug, Deserialize)]
struct PublicProofJobStatus {
    state: String,
    #[serde(default)]
    reuse_state: Option<String>,
    #[serde(default)]
    failure: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IngressResponse {
    receipt: IngressReceipt,
    coordinator_submission: Value,
}

#[derive(Debug, Deserialize)]
struct IngressReceipt {
    order_commitment: String,
    pair_id: String,
    batch_id: String,
    epoch_id: u64,
    #[serde(default)]
    relay_mode: Option<RelayMode>,
    #[serde(default)]
    renewal_package_id: Option<String>,
    #[serde(default)]
    renewal_package_commitment: Option<String>,
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

#[derive(Debug, Deserialize)]
struct PackageOrderAttestationRequest {
    package_commitment: String,
    order_commitment: String,
    pair: String,
    batch_id: String,
    epoch_id: u64,
}

#[derive(Debug, Serialize)]
struct PackageOrderAttestation {
    package_id: String,
    package_commitment: String,
    order_commitment: String,
    pair: String,
    batch_id: String,
    epoch_id: u64,
    relay_mode: RelayMode,
}

#[derive(Debug, Serialize)]
struct RelayOpsSummary {
    generated_at_unix_ms: u64,
    status: String,
    strict_mode: bool,
    worker_enabled: bool,
    accepted_relay_mode: String,
    store_kind: String,
    store_ok: bool,
    ready: bool,
    package_count: usize,
    cancelled_package_count: usize,
    last_observed_epoch: Option<u64>,
    counts: RelayOpsSlotCounts,
    alerts: Vec<RelayOpsAlert>,
    packages: Vec<RelayOpsPackageSummary>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct RelayOpsSlotCounts {
    total_slots: usize,
    submitted_slots: usize,
    already_submitted_slots: usize,
    unobserved_slots: usize,
    not_due_slots: usize,
    batch_not_open_slots: usize,
    safety_buffer_slots: usize,
    awaiting_settlement_slots: usize,
    awaiting_wallet_refresh_slots: usize,
    missed_slots: usize,
    failed_slots: usize,
    retryable_failed_slots: usize,
}

#[derive(Debug, Serialize)]
struct RelayOpsPackageSummary {
    package_id: String,
    package_commitment: String,
    pair: String,
    relay_mode: String,
    start_epoch: u64,
    end_epoch: u64,
    slot_count: usize,
    result_count: usize,
    unobserved_slots: usize,
    submitted_slots: usize,
    failed_slots: usize,
    retryable_failed_slots: usize,
    missed_slots: usize,
    awaiting_settlement_slots: usize,
    awaiting_wallet_refresh_slots: usize,
    oldest_unobserved_epoch: Option<u64>,
    newest_unobserved_epoch: Option<u64>,
    last_attempt_unix_ms: Option<u64>,
    updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
struct RelayOpsAlert {
    severity: String,
    code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package_id: Option<String>,
    detail: String,
}

#[derive(Clone, Debug)]
struct ReadinessSnapshot {
    ready: bool,
    store_ok: bool,
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
            if config.strict_mode {
                std::process::exit(1);
            }
            RelayStore::default()
        });
    let state = AppState {
        config,
        store: Arc::new(RwLock::new(store)),
        http: Client::new(),
        tick_lock: Arc::new(Mutex::new(())),
        rate_limits: Arc::new(RwLock::new(BTreeMap::new())),
        alert_dispatch_cache: Arc::new(RwLock::new(BTreeMap::new())),
    };
    if state.config.enable_worker {
        spawn_worker(state.clone());
    }
    let bind_addr = state.config.bind_addr;
    let listener = TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind renewal relayer on {bind_addr}: {error}"));
    println!("zylith renewal relayer listening on {bind_addr}");
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("renewal relayer server failed");
}

fn app(state: AppState) -> Router {
    let cors = service_cors_layer(&state.config);
    let max_body_bytes = state.config.max_body_bytes;
    let register_package_route = post(register_package).route_layer(
        middleware::from_fn_with_state(state.clone(), relay_rate_limit_middleware),
    );
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(readiness))
        .route("/metrics", get(metrics))
        .route("/ops/summary", get(ops_summary))
        .route("/ops/alerts", get(ops_alerts))
        .route("/packages", register_package_route)
        .route(
            "/packages/{package_id}",
            get(get_package_status).delete(delete_package),
        )
        .route("/packages/{package_id}/results", get(get_package_results))
        .route(
            "/packages/{package_id}/results.csv",
            get(get_package_results_csv),
        )
        .route(
            "/packages/{package_id}/attest-order",
            post(attest_package_order),
        )
        .route("/api/internal/relay/tick", post(trigger_tick))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(cors)
        .with_state(state)
}

async fn relay_rate_limit_middleware(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, RelayApiError> {
    enforce_rate_limit(&state, &headers, peer).await?;
    Ok(next.run(request).await)
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "zylith-renewal-relayer",
    }))
}

fn readiness_snapshot(config: &RelayConfig) -> ReadinessSnapshot {
    let store_ok = if is_sqlite_store(&config.store_path) {
        open_sqlite_store(&config.store_path).is_ok()
    } else {
        !config.strict_mode
    };
    let coordinator_auth_ok = config.accepted_relay_mode != AcceptedRelayMode::ZylithRelay
        || config.coordinator_control_token.is_some();
    let ready = store_ok
        && (!config.strict_mode
            || (coordinator_auth_ok
                && config.internal_control_token.is_some()
                && config.prover_control_token.is_some()
                && !configured_coordinator_urls(config).is_empty()
                && !configured_prover_urls(config).is_empty()
                && !config.allowed_origins.is_empty()
                && is_sqlite_store(&config.store_path)));
    ReadinessSnapshot { ready, store_ok }
}

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    let readiness = readiness_snapshot(&state.config);
    let status = if readiness.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if readiness.ready { "ready" } else { "not_ready" },
        })),
    )
}

async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, RelayApiError> {
    require_internal_auth(&state, &headers)?;
    let store = state.store.read().await;
    let summary = build_ops_summary(&state, &store, now_unix_ms());
    let critical_alerts = summary
        .alerts
        .iter()
        .filter(|alert| alert.severity == "critical")
        .count();
    let warning_alerts = summary
        .alerts
        .iter()
        .filter(|alert| alert.severity == "warning")
        .count();
    let expiring_packages = summary
        .alerts
        .iter()
        .filter(|alert| alert.code == "package_expires_soon")
        .count();
    Ok(format!(
        "# HELP zylith_renewal_relay_packages Registered renewal packages.\n\
         # TYPE zylith_renewal_relay_packages gauge\n\
         zylith_renewal_relay_packages {}\n\
         # HELP zylith_renewal_relay_slots Registered renewal slots.\n\
         # TYPE zylith_renewal_relay_slots gauge\n\
         zylith_renewal_relay_slots {}\n\
         # HELP zylith_renewal_relay_submitted_slots Submitted renewal slots.\n\
         # TYPE zylith_renewal_relay_submitted_slots gauge\n\
         zylith_renewal_relay_submitted_slots {}\n\
         # HELP zylith_renewal_relay_pending_slots Renewal slots without a recorded terminal or in-progress result.\n\
         # TYPE zylith_renewal_relay_pending_slots gauge\n\
         zylith_renewal_relay_pending_slots {}\n\
         # HELP zylith_renewal_relay_missed_slots Renewal slots whose authorized epoch window passed before submission.\n\
         # TYPE zylith_renewal_relay_missed_slots gauge\n\
         zylith_renewal_relay_missed_slots {}\n\
         # HELP zylith_renewal_relay_failed_slots Failed renewal slots.\n\
         # TYPE zylith_renewal_relay_failed_slots gauge\n\
         zylith_renewal_relay_failed_slots {}\n\
         # HELP zylith_renewal_relay_awaiting_wallet_refresh_slots Slots blocked because reused maker capital already settled.\n\
         # TYPE zylith_renewal_relay_awaiting_wallet_refresh_slots gauge\n\
         zylith_renewal_relay_awaiting_wallet_refresh_slots {}\n\
         # HELP zylith_renewal_relay_retryable_failed_slots Failed renewal slots still under the retry-attempt cap.\n\
         # TYPE zylith_renewal_relay_retryable_failed_slots gauge\n\
         zylith_renewal_relay_retryable_failed_slots {}\n\
         # HELP zylith_renewal_relay_package_expiring_soon Packages near the configured expiry-warning horizon.\n\
         # TYPE zylith_renewal_relay_package_expiring_soon gauge\n\
         zylith_renewal_relay_package_expiring_soon {}\n\
         # HELP zylith_renewal_relay_warning_alerts Active warning-level relay alerts.\n\
         # TYPE zylith_renewal_relay_warning_alerts gauge\n\
         zylith_renewal_relay_warning_alerts {}\n\
         # HELP zylith_renewal_relay_critical_alerts Active critical relay alerts.\n\
         # TYPE zylith_renewal_relay_critical_alerts gauge\n\
         zylith_renewal_relay_critical_alerts {}\n",
        summary.package_count,
        summary.counts.total_slots,
        summary.counts.submitted_slots + summary.counts.already_submitted_slots,
        summary.counts.unobserved_slots
            + summary.counts.not_due_slots
            + summary.counts.batch_not_open_slots
            + summary.counts.safety_buffer_slots
            + summary.counts.awaiting_settlement_slots
            + summary.counts.retryable_failed_slots,
        summary.counts.missed_slots,
        summary.counts.failed_slots,
        summary.counts.awaiting_wallet_refresh_slots,
        summary.counts.retryable_failed_slots,
        expiring_packages,
        warning_alerts,
        critical_alerts,
    ))
}

async fn ops_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RelayOpsSummary>, RelayApiError> {
    require_internal_auth(&state, &headers)?;
    let store = state.store.read().await;
    Ok(Json(build_ops_summary(&state, &store, now_unix_ms())))
}

async fn ops_alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RelayOpsAlert>>, RelayApiError> {
    require_internal_auth(&state, &headers)?;
    let store = state.store.read().await;
    Ok(Json(
        build_ops_summary(&state, &store, now_unix_ms()).alerts,
    ))
}

async fn dispatch_ops_alerts(state: &AppState) {
    if state.config.alert_webhook_urls.is_empty() {
        return;
    }
    let now = now_unix_ms();
    let summary = {
        let store = state.store.read().await;
        build_ops_summary(state, &store, now)
    };
    let alerts = due_alerts_for_dispatch(state, &summary.alerts, now).await;
    if alerts.is_empty() {
        return;
    }
    let payload = json!({
        "service": "zylith-renewal-relayer",
        "generated_at_unix_ms": now,
        "status": summary.status,
        "strict_mode": summary.strict_mode,
        "accepted_relay_mode": summary.accepted_relay_mode,
        "package_count": summary.package_count,
        "counts": summary.counts,
        "alerts": alerts,
    });
    for webhook_url in &state.config.alert_webhook_urls {
        if let Err(error) = post_alert_webhook(
            &state.http,
            webhook_url,
            &payload,
            state
                .config
                .alert_webhook_token
                .as_deref()
                .map(String::as_str),
        )
        .await
        {
            eprintln!(
                "renewal relay alert webhook failed target={} error={}",
                short_log_id(webhook_url),
                sanitize_log_field(&error)
            );
        }
    }
}

async fn due_alerts_for_dispatch(
    state: &AppState,
    alerts: &[RelayOpsAlert],
    now: u64,
) -> Vec<RelayOpsAlert> {
    let mut cache = state.alert_dispatch_cache.write().await;
    cache.retain(|_, sent_at| {
        now.saturating_sub(*sent_at) <= state.config.alert_repeat_ms.saturating_mul(2)
    });
    let mut due = Vec::new();
    for alert in alerts {
        let key = alert_dispatch_key(alert);
        let last_sent = cache.get(&key).copied().unwrap_or_default();
        if last_sent == 0 || now.saturating_sub(last_sent) >= state.config.alert_repeat_ms {
            cache.insert(key, now);
            due.push(alert.clone());
        }
    }
    due
}

fn alert_dispatch_key(alert: &RelayOpsAlert) -> String {
    format!(
        "{}:{}:{}",
        alert.severity,
        alert.code,
        alert.package_id.as_deref().unwrap_or("*")
    )
}

fn build_ops_summary(state: &AppState, store: &RelayStore, now: u64) -> RelayOpsSummary {
    let readiness = readiness_snapshot(&state.config);
    let last_observed_epoch = store
        .packages
        .values()
        .flat_map(|package| package.results.values())
        .map(|entry| entry.result.epoch_id)
        .max();
    let mut counts = RelayOpsSlotCounts::default();
    let mut packages = Vec::with_capacity(store.packages.len());
    let mut alerts = Vec::new();
    if !readiness.ready {
        alerts.push(RelayOpsAlert {
            severity: "critical".into(),
            code: "relay_not_ready".into(),
            package_id: None,
            detail:
                "Readiness checks are failing; inspect /ready for the exact failed prerequisite."
                    .into(),
        });
    }
    if store.packages.is_empty() {
        alerts.push(RelayOpsAlert {
            severity: "warning".into(),
            code: "no_packages_registered".into(),
            package_id: None,
            detail: "No renewal packages are registered.".into(),
        });
    }
    for stored in store.packages.values() {
        let package_summary =
            ops_package_summary(stored, state.config.max_attempts, last_observed_epoch);
        counts.total_slots += package_summary.slot_count;
        counts.unobserved_slots += package_summary.unobserved_slots;
        counts.submitted_slots += stored
            .results
            .values()
            .filter(|entry| matches!(entry.result.status, RelaySlotStatus::Submitted))
            .count();
        counts.already_submitted_slots += stored
            .results
            .values()
            .filter(|entry| matches!(entry.result.status, RelaySlotStatus::AlreadySubmitted))
            .count();
        counts.not_due_slots += count_status(stored, RelaySlotStatus::NotDue);
        counts.batch_not_open_slots += count_status(stored, RelaySlotStatus::BatchNotOpen);
        counts.safety_buffer_slots += count_status(stored, RelaySlotStatus::SafetyBuffer);
        counts.awaiting_settlement_slots += package_summary.awaiting_settlement_slots;
        counts.awaiting_wallet_refresh_slots += package_summary.awaiting_wallet_refresh_slots;
        counts.missed_slots += package_summary.missed_slots;
        counts.failed_slots += package_summary.failed_slots;
        counts.retryable_failed_slots += package_summary.retryable_failed_slots;

        extend_ops_alerts_for_package(
            &mut alerts,
            &package_summary,
            state.config.package_expiry_warning_epochs,
            last_observed_epoch,
        );
        packages.push(package_summary);
    }
    packages.sort_by(|left, right| {
        left.pair
            .cmp(&right.pair)
            .then(left.end_epoch.cmp(&right.end_epoch))
            .then(left.package_id.cmp(&right.package_id))
    });
    let status = if alerts.iter().any(|alert| alert.severity == "critical") {
        "critical"
    } else if alerts.iter().any(|alert| alert.severity == "warning") {
        "degraded"
    } else {
        "ok"
    };
    RelayOpsSummary {
        generated_at_unix_ms: now,
        status: status.into(),
        strict_mode: state.config.strict_mode,
        worker_enabled: state.config.enable_worker,
        accepted_relay_mode: state.config.accepted_relay_mode.label().into(),
        store_kind: if is_sqlite_store(&state.config.store_path) {
            "sqlite".into()
        } else {
            "json".into()
        },
        store_ok: readiness.store_ok,
        ready: readiness.ready,
        package_count: store.packages.len(),
        cancelled_package_count: store.cancelled_packages.len(),
        last_observed_epoch,
        counts,
        alerts,
        packages,
    }
}

fn ops_package_summary(
    stored: &StoredPackage,
    max_attempts: u32,
    last_observed_epoch: Option<u64>,
) -> RelayOpsPackageSummary {
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
    let failed_slots = count_status(stored, RelaySlotStatus::Failed);
    let retryable_failed_slots = stored
        .results
        .values()
        .filter(|entry| {
            matches!(entry.result.status, RelaySlotStatus::Failed) && entry.attempts < max_attempts
        })
        .count();
    let missed_slots = count_status(stored, RelaySlotStatus::Missed);
    let awaiting_settlement_slots = count_status(stored, RelaySlotStatus::AwaitingSettlement);
    let awaiting_wallet_refresh_slots =
        count_status(stored, RelaySlotStatus::AwaitingWalletRefresh);
    let unobserved_epochs = stored
        .package
        .slots
        .iter()
        .filter(|slot| !stored.results.contains_key(&slot.slot_id))
        .map(|slot| slot.epoch_id)
        .collect::<Vec<_>>();
    let unobserved_slots = stored
        .package
        .slot_count
        .saturating_sub(stored.results.len());
    let fallback_unobserved_epoch = if unobserved_slots > 0 && unobserved_epochs.is_empty() {
        last_observed_epoch.map(|epoch| epoch.saturating_add(1))
    } else {
        None
    };
    RelayOpsPackageSummary {
        package_id: stored.package.package_id.clone(),
        package_commitment: stored.package.package_commitment.clone(),
        pair: stored.package.pair.clone(),
        relay_mode: relay_mode_log_label(stored.package.relay_mode.as_ref()).into(),
        start_epoch: stored.package.start_epoch,
        end_epoch: stored.package.end_epoch,
        slot_count: stored.package.slot_count,
        result_count: stored.results.len(),
        unobserved_slots,
        submitted_slots,
        failed_slots,
        retryable_failed_slots,
        missed_slots,
        awaiting_settlement_slots,
        awaiting_wallet_refresh_slots,
        oldest_unobserved_epoch: unobserved_epochs
            .iter()
            .copied()
            .min()
            .or(fallback_unobserved_epoch),
        newest_unobserved_epoch: unobserved_epochs
            .iter()
            .copied()
            .max()
            .or(fallback_unobserved_epoch),
        last_attempt_unix_ms: stored
            .results
            .values()
            .map(|entry| entry.last_attempt_unix_ms)
            .max(),
        updated_at_unix_ms: stored.updated_at_unix_ms,
    }
}

fn count_status(stored: &StoredPackage, status: RelaySlotStatus) -> usize {
    stored
        .results
        .values()
        .filter(|entry| entry.result.status == status)
        .count()
}

fn extend_ops_alerts_for_package(
    alerts: &mut Vec<RelayOpsAlert>,
    package: &RelayOpsPackageSummary,
    expiry_warning_epochs: u64,
    last_observed_epoch: Option<u64>,
) {
    let package_id = Some(package.package_id.clone());
    if package.missed_slots > 0 {
        alerts.push(RelayOpsAlert {
            severity: "critical".into(),
            code: "missed_slots".into(),
            package_id: package_id.clone(),
            detail: format!(
                "{} renewal slots missed their authorized epoch window.",
                package.missed_slots
            ),
        });
    }
    if package.failed_slots > 0 {
        alerts.push(RelayOpsAlert {
            severity: "warning".into(),
            code: "failed_slots".into(),
            package_id: package_id.clone(),
            detail: format!("{} renewal slots failed submission.", package.failed_slots),
        });
    }
    if package.awaiting_wallet_refresh_slots > 0 {
        alerts.push(RelayOpsAlert {
            severity: "warning".into(),
            code: "wallet_refresh_required".into(),
            package_id: package_id.clone(),
            detail: "A prior child used reusable maker capital; refresh the package from the wallet before continuing.".into(),
        });
    }
    if let Some(observed_epoch) = last_observed_epoch {
        if package.unobserved_slots > 0 && package.end_epoch <= observed_epoch {
            alerts.push(RelayOpsAlert {
                severity: "critical".into(),
                code: "package_window_passed".into(),
                package_id: package_id.clone(),
                detail: format!(
                    "Package ended at epoch {}, but {} slots remain without results.",
                    package.end_epoch, package.unobserved_slots
                ),
            });
        } else if package.unobserved_slots > 0
            && package.end_epoch <= observed_epoch.saturating_add(expiry_warning_epochs)
        {
            alerts.push(RelayOpsAlert {
                severity: "warning".into(),
                code: "package_expires_soon".into(),
                package_id,
                detail: format!(
                    "Package ends at epoch {}; refresh before expiry to avoid missed maker slots.",
                    package.end_epoch
                ),
            });
        }
    }
}

async fn register_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(package): Json<OfflineRenewalPackage>,
) -> Result<Json<PackageStatus>, RelayApiError> {
    if let Err(error) = validate_package(&package, &state.config) {
        log_package_api_error("validate", &package, &error);
        return Err(error);
    }
    if let Err(error) = require_package_registration_auth(&state, &headers, &package) {
        log_package_api_error("auth", &package, &error);
        return Err(error);
    }
    let now = now_unix_ms();
    let package_id = package.package_id.clone();
    let package_for_storage = package_for_storage(&package);
    refresh_sqlite_store_if_needed(&state).await?;
    let status = {
        let mut store = state.store.write().await;
        prune_store_locked(&mut store, &state.config, now);
        if store.cancelled_packages.contains_key(&package_id) {
            let error = RelayApiError {
                status: StatusCode::GONE,
                detail: "Renewal package has been cancelled".into(),
            };
            log_package_api_error("cancelled", &package, &error);
            return Err(error);
        }
        if let Some(existing) = store.packages.get_mut(&package_id)
            && existing.package.package_commitment != package.package_commitment
        {
            if existing.package.parent_cancel_authority != package.parent_cancel_authority {
                let error = RelayApiError {
                    status: StatusCode::CONFLICT,
                    detail: "Renewal package ID is already registered for a different parent"
                        .into(),
                };
                log_package_api_error("conflict", &package, &error);
                return Err(error);
            }
            validate_package_refresh(existing, &package)?;
            let retained_slot_ids = package
                .slots
                .iter()
                .map(|slot| slot.slot_id.clone())
                .collect::<BTreeSet<_>>();
            existing
                .results
                .retain(|slot_id, _| retained_slot_ids.contains(slot_id));
        }
        let entry = store
            .packages
            .entry(package_id.clone())
            .or_insert_with(|| StoredPackage {
                package: package_for_storage.clone(),
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
                results: BTreeMap::new(),
            });
        entry.package = package_for_storage;
        entry.updated_at_unix_ms = now;
        package_status(entry)
    };
    persist_store(&state.config.store_path, &state.store).await?;
    log_package_registered(&status);
    Ok(Json(status))
}

fn package_for_storage(package: &OfflineRenewalPackage) -> OfflineRenewalPackage {
    let mut stored = package.clone();
    stored.relay_authorization = None;
    stored
}

fn validate_package_refresh(
    existing: &StoredPackage,
    package: &OfflineRenewalPackage,
) -> Result<(), RelayApiError> {
    let current = &existing.package;
    if package.created_at_unix_ms < current.created_at_unix_ms {
        return Err(RelayApiError {
            status: StatusCode::CONFLICT,
            detail: "Renewal package refresh is older than the registered package".into(),
        });
    }
    if package.end_epoch < current.end_epoch {
        return Err(RelayApiError {
            status: StatusCode::CONFLICT,
            detail: "Renewal package refresh cannot shrink the active renewal window".into(),
        });
    }
    if package.created_at_unix_ms <= current.created_at_unix_ms
        && package.end_epoch <= current.end_epoch
    {
        return Err(RelayApiError {
            status: StatusCode::CONFLICT,
            detail: "Renewal package refresh must advance creation time or renewal window".into(),
        });
    }
    Ok(())
}

async fn get_package_status(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(package_id): Path<String>,
) -> Result<Json<PackageStatus>, RelayApiError> {
    refresh_sqlite_store_if_needed(&state).await?;
    let store = state.store.read().await;
    let package = store
        .packages
        .get(&package_id)
        .ok_or(RelayApiError::status(StatusCode::UNAUTHORIZED))?;
    require_package_access_auth(&state, &headers, &package.package)?;
    enforce_rate_limit(&state, &headers, peer).await?;
    Ok(Json(package_status(package)))
}

async fn get_package_results(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(package_id): Path<String>,
) -> Result<Json<PackageResults>, RelayApiError> {
    refresh_sqlite_store_if_needed(&state).await?;
    let store = state.store.read().await;
    let package = store
        .packages
        .get(&package_id)
        .ok_or(RelayApiError::status(StatusCode::UNAUTHORIZED))?;
    require_package_access_auth(&state, &headers, &package.package)?;
    enforce_rate_limit(&state, &headers, peer).await?;
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

async fn attest_package_order(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(package_id): Path<String>,
    Json(request): Json<PackageOrderAttestationRequest>,
) -> Result<Json<PackageOrderAttestation>, RelayApiError> {
    refresh_sqlite_store_if_needed(&state).await?;
    let store = state.store.read().await;
    let package = store
        .packages
        .get(&package_id)
        .ok_or(RelayApiError::status(StatusCode::UNAUTHORIZED))?;
    require_package_access_auth(&state, &headers, &package.package)?;
    enforce_rate_limit(&state, &headers, peer).await?;
    if package.package.package_commitment != request.package_commitment {
        return Err(RelayApiError::status(StatusCode::CONFLICT));
    }
    let slot = package
        .package
        .slots
        .iter()
        .find(|slot| {
            slot.order_commitment == request.order_commitment
                && slot.pair == request.pair
                && slot.batch_id == request.batch_id
                && slot.epoch_id == request.epoch_id
        })
        .ok_or(RelayApiError::status(StatusCode::NOT_FOUND))?;
    Ok(Json(PackageOrderAttestation {
        package_id: package.package.package_id.clone(),
        package_commitment: package.package.package_commitment.clone(),
        order_commitment: slot.order_commitment.clone(),
        pair: slot.pair.clone(),
        batch_id: slot.batch_id.clone(),
        epoch_id: slot.epoch_id,
        relay_mode: package
            .package
            .relay_mode
            .clone()
            .unwrap_or(RelayMode::ZylithRelay),
    }))
}

async fn get_package_results_csv(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(package_id): Path<String>,
) -> Result<impl IntoResponse, RelayApiError> {
    refresh_sqlite_store_if_needed(&state).await?;
    let store = state.store.read().await;
    let package = store
        .packages
        .get(&package_id)
        .ok_or(RelayApiError::status(StatusCode::UNAUTHORIZED))?;
    require_package_access_auth(&state, &headers, &package.package)?;
    enforce_rate_limit(&state, &headers, peer).await?;

    let mut csv = String::from(
        "package_id,pair,slot_id,parent_child_index,batch_id,epoch_id,order_commitment,status,detail,accepted_order_commitment,accepted_batch_id,accepted_at_unix_ms\n",
    );
    for entry in package.results.values() {
        let result = &entry.result;
        let accepted = result.accepted.as_ref();
        csv.push_str(&csv_row(&[
            &package.package.package_id,
            &result.pair,
            &result.slot_id,
            &result.parent_child_index.to_string(),
            &result.batch_id,
            &result.epoch_id.to_string(),
            &result.order_commitment,
            slot_status_label(&result.status),
            result.detail.as_deref().unwrap_or_default(),
            accepted
                .map(|value| value.order_commitment.as_str())
                .unwrap_or_default(),
            accepted
                .map(|value| value.batch_id.as_str())
                .unwrap_or_default(),
            &accepted
                .map(|value| value.accepted_at_unix_ms.to_string())
                .unwrap_or_default(),
        ]));
    }

    Ok((
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("text/csv; charset=utf-8"),
            ),
            (
                CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"zylith-renewal-results.csv\""),
            ),
        ],
        csv,
    ))
}

fn log_package_api_error(stage: &str, package: &OfflineRenewalPackage, error: &RelayApiError) {
    eprintln!(
        "renewal package rejected stage={} status={} detail={} package_id={} commitment={} pair={} relay_mode={} slots={} epochs={}..{}",
        stage,
        error.status.as_u16(),
        sanitize_log_field(&error.detail),
        short_log_id(&package.package_id),
        short_log_id(&package.package_commitment),
        sanitize_log_field(&package.pair),
        relay_mode_log_label(package.relay_mode.as_ref()),
        package.slots.len(),
        package.start_epoch,
        package.end_epoch,
    );
}

fn log_package_registered(status: &PackageStatus) {
    println!(
        "renewal package registered package_id={} commitment={} pair={} slots={} submitted={} failed={} epochs={}..{}",
        short_log_id(&status.package_id),
        short_log_id(&status.package_commitment),
        sanitize_log_field(&status.pair),
        status.slot_count,
        status.submitted_slots,
        status.failed_slots,
        status.start_epoch,
        status.end_epoch,
    );
}

fn short_log_id(value: &str) -> String {
    let trimmed = value.trim();
    let chars = trimmed.chars().collect::<Vec<_>>();
    if chars.len() <= 18 {
        return sanitize_log_field(trimmed);
    }
    let prefix = chars.iter().take(10).collect::<String>();
    let suffix = chars
        .iter()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    sanitize_log_field(&format!("{prefix}…{suffix}"))
}

fn sanitize_log_field(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '.' | '/' | ':' | '…')
            {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn relay_mode_log_label(mode: Option<&RelayMode>) -> &'static str {
    match mode {
        Some(RelayMode::ZylithRelay) => "ZylithRelay",
        Some(RelayMode::SelfRelay) => "SelfRelay",
        None => "None",
    }
}

async fn delete_package(
    State(state): State<AppState>,
    PeerAddress(peer): PeerAddress,
    headers: HeaderMap,
    Path(package_id): Path<String>,
) -> Result<StatusCode, RelayApiError> {
    refresh_sqlite_store_if_needed(&state).await?;
    let package = {
        let store = state.store.read().await;
        store
            .packages
            .get(&package_id)
            .cloned()
            .ok_or(RelayApiError::status(StatusCode::UNAUTHORIZED))?
    };
    require_package_access_auth(&state, &headers, &package.package)?;
    enforce_rate_limit(&state, &headers, peer).await?;
    let removed = {
        let mut store = state.store.write().await;
        let Some(current) = store.packages.get(&package_id) else {
            return Ok(StatusCode::NO_CONTENT);
        };
        if current.package.package_commitment != package.package.package_commitment {
            return Err(RelayApiError {
                status: StatusCode::CONFLICT,
                detail: "Renewal package changed before deletion".into(),
            });
        }
        let removed = store.packages.remove(&package_id).is_some();
        if removed {
            store
                .cancelled_packages
                .insert(package_id.clone(), now_unix_ms());
        }
        removed
    };
    if removed && is_sqlite_store(&state.config.store_path) {
        persist_sqlite_package_tombstone(&state.config.store_path, &package_id, now_unix_ms())
            .await
            .map_err(RelayApiError::internal)?;
    } else if removed {
        persist_store(&state.config.store_path, &state.store).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn trigger_tick(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OfflineRenewalRelayResult>>, RelayApiError> {
    require_internal_auth(&state, &headers)?;
    let results = process_due_slots_once(&state).await;
    dispatch_ops_alerts(&state).await;
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
                    RelaySlotStatus::Submitted
                        | RelaySlotStatus::Failed
                        | RelaySlotStatus::AwaitingWalletRefresh
                ) {
                    println!(
                        "renewal relay slot {} epoch {} {:?}",
                        result.slot_id, result.epoch_id, result.status
                    );
                }
            }
            dispatch_ops_alerts(&state).await;
        }
    });
}

async fn process_due_slots_once(state: &AppState) -> Vec<OfflineRenewalRelayResult> {
    let _guard = state.tick_lock.lock().await;
    let persistent_lease = acquire_persistent_tick_lease(&state.config).await;
    if matches!(persistent_lease, PersistentTickLease::Busy) {
        return Vec::new();
    }
    let sqlite_store = is_sqlite_store(&state.config.store_path);
    if sqlite_store && let Err(error) = refresh_sqlite_store_if_needed(state).await {
        eprintln!("renewal relay failed to refresh sqlite store before tick: {error:?}");
        if let PersistentTickLease::Acquired(owner) = persistent_lease {
            release_persistent_tick_lease(&state.config.store_path, &owner).await;
        }
        return Vec::new();
    }
    let snapshots = {
        let mut store = state.store.write().await;
        prune_store_locked(&mut store, &state.config, now_unix_ms());
        store
            .packages
            .values()
            .map(|stored| {
                let mut package = stored.package.clone();
                if sqlite_store {
                    package.slots.clear();
                }
                package
            })
            .collect::<Vec<_>>()
    };
    let mut emitted = Vec::new();
    for package in snapshots {
        let batch = fetch_current_batch(state, &package, &package.pair)
            .await
            .ok();
        let Some(batch) = batch else {
            eprintln!(
                "renewal relay skipped package {} because current batch is unavailable",
                package.package_id
            );
            continue;
        };
        let slots = due_slots_for_package_tick(state, &package, batch.epoch_id).await;
        for slot in slots.iter() {
            if !should_attempt_slot(state, &package.package_id, slot).await {
                continue;
            }
            let result = process_slot_against_batch(state, &package, slot, &batch).await;
            let stored_result =
                record_slot_result(state, &package.package_id, result.clone()).await;
            if let Some(stored_result) = stored_result
                && is_sqlite_store(&state.config.store_path)
                && let Err(error) = persist_sqlite_slot_result(
                    &state.config.store_path,
                    &package.package_id,
                    stored_result,
                )
                .await
            {
                eprintln!(
                    "renewal relay failed to persist slot result package={} slot={}: {error}",
                    package.package_id, result.slot_id
                );
            }
            emitted.push(result);
        }
    }
    if !emitted.is_empty() && !is_sqlite_store(&state.config.store_path) {
        let _ = persist_store(&state.config.store_path, &state.store).await;
    }
    if let PersistentTickLease::Acquired(owner) = persistent_lease {
        release_persistent_tick_lease(&state.config.store_path, &owner).await;
    }
    emitted
}

async fn refresh_sqlite_store_if_needed(state: &AppState) -> Result<(), RelayApiError> {
    if !is_sqlite_store(&state.config.store_path) {
        return Ok(());
    }
    let loaded = load_sqlite_store(&state.config.store_path)
        .await
        .map_err(RelayApiError::internal)?;
    let mut store = state.store.write().await;
    *store = loaded;
    Ok(())
}

async fn due_slots_for_package_tick(
    state: &AppState,
    package: &OfflineRenewalPackage,
    current_epoch: u64,
) -> Vec<OfflineRenewalSlot> {
    if is_sqlite_store(&state.config.store_path) {
        match load_sqlite_due_slots_for_package(&state.config, &package.package_id, current_epoch)
            .await
        {
            Ok(slots) => return slots,
            Err(error) => eprintln!(
                "renewal relay due-slot index unavailable for package {}: {error}; skipping tick",
                package.package_id
            ),
        }
        return Vec::new();
    }
    package
        .slots
        .iter()
        .take_while(|slot| slot.epoch_id <= current_epoch)
        .cloned()
        .collect()
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
        RelaySlotStatus::Submitted
            | RelaySlotStatus::AlreadySubmitted
            | RelaySlotStatus::AwaitingWalletRefresh
            | RelaySlotStatus::Missed
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
    let safety_buffer_ms = effective_submission_safety_buffer_ms(package);
    if batch.close_time_unix_ms.saturating_sub(now) <= safety_buffer_ms {
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
    match parent_cancel_marker_recorded(state, package).await {
        Ok(true) => {
            tombstone_package(state, &package.package_id).await;
            return slot_result(
                slot,
                RelaySlotStatus::Missed,
                Some("Renewal parent cancellation marker is recorded on-chain".into()),
            );
        }
        Ok(false) => {}
        Err(error) => {
            return slot_result(
                slot,
                RelaySlotStatus::AwaitingSettlement,
                Some(format!(
                    "Unable to verify parent cancellation status: {error}"
                )),
            );
        }
    }
    if let Some(guarded) = prior_slot_reuse_guard(state, package, slot).await {
        return guarded;
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

async fn prior_slot_reuse_guard(
    state: &AppState,
    package: &OfflineRenewalPackage,
    slot: &OfflineRenewalSlot,
) -> Option<OfflineRenewalRelayResult> {
    let prior_submitted = if is_sqlite_store(&state.config.store_path) {
        match load_sqlite_prior_submitted_reused_funding_slots(
            &state.config,
            &package.package_id,
            slot,
        )
        .await
        {
            Ok(slots) => slots,
            Err(error) => {
                return Some(slot_result(
                    slot,
                    RelaySlotStatus::AwaitingSettlement,
                    Some(format!(
                        "Prior child index unavailable; retrying later: {error}"
                    )),
                ));
            }
        }
    } else {
        prior_submitted_reused_funding_slots(state, package, slot).await
    };
    if prior_submitted.is_empty() {
        return None;
    }
    for prior in prior_submitted {
        match fetch_proof_job_status(state, package, &prior.batch_id).await {
            Ok(Some(status)) => {
                if proof_job_failed(&status) {
                    return Some(slot_result(
                        slot,
                        RelaySlotStatus::AwaitingSettlement,
                        Some(format!(
                            "Prior child batch {} proof failed; waiting for wallet refresh before reusing maker capital",
                            prior.batch_id
                        )),
                    ));
                }
                if proof_job_confirmed(&status) {
                    if status.reuse_state.as_deref() == Some("no_fill") {
                        continue;
                    }
                    if status.reuse_state.as_deref() == Some("matched") {
                        return Some(slot_result(
                            slot,
                            RelaySlotStatus::AwaitingWalletRefresh,
                            Some(format!(
                                "Prior child batch {} settled with matched orders; refresh the package from the wallet before reusing maker capital",
                                prior.batch_id
                            )),
                        ));
                    }
                    return Some(slot_result(
                        slot,
                        RelaySlotStatus::AwaitingSettlement,
                        Some(format!(
                            "Prior child batch {} is confirmed but no no-fill reuse attestation is available; waiting before reusing maker capital",
                            prior.batch_id
                        )),
                    ));
                }
                return Some(slot_result(
                    slot,
                    RelaySlotStatus::AwaitingSettlement,
                    Some(format!(
                        "Prior child batch {} is not confirmed no-fill yet; waiting before reusing maker capital",
                        prior.batch_id
                    )),
                ));
            }
            Ok(None) | Err(_) => {
                return Some(slot_result(
                    slot,
                    RelaySlotStatus::AwaitingSettlement,
                    Some(format!(
                        "Prior child batch {} status is unavailable; waiting before reusing maker capital",
                        prior.batch_id
                    )),
                ));
            }
        }
    }
    None
}

#[derive(Clone, Debug, Deserialize)]
struct RenewalCancelMarkerStatus {
    recorded: bool,
}

async fn parent_cancel_marker_recorded(
    state: &AppState,
    package: &OfflineRenewalPackage,
) -> Result<bool, String> {
    let Some(marker) = package
        .parent_cancel_marker
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err("renewal package cancellation marker is missing".into());
    };
    let coordinator_urls = package_coordinator_urls(&state.config, package)?;
    let path = format!("/api/renewal/cancel-markers/{marker}");
    let status: RenewalCancelMarkerStatus =
        get_json_with_auth_failover(&state.http, &coordinator_urls, &path, None).await?;
    Ok(status.recorded)
}

async fn tombstone_package(state: &AppState, package_id: &str) {
    let cancelled_at_unix_ms = now_unix_ms();
    {
        let mut store = state.store.write().await;
        store.packages.remove(package_id);
        store
            .cancelled_packages
            .insert(package_id.to_owned(), cancelled_at_unix_ms);
    }
    if is_sqlite_store(&state.config.store_path) {
        let _ = persist_sqlite_package_tombstone(
            &state.config.store_path,
            package_id,
            cancelled_at_unix_ms,
        )
        .await;
    } else {
        let _ = persist_store(&state.config.store_path, &state.store).await;
    }
}

async fn prior_submitted_reused_funding_slots(
    state: &AppState,
    package: &OfflineRenewalPackage,
    slot: &OfflineRenewalSlot,
) -> Vec<OfflineRenewalSlot> {
    let submitted_slot_ids = {
        let store = state.store.read().await;
        let Some(stored) = store.packages.get(&package.package_id) else {
            return Vec::new();
        };
        stored
            .results
            .iter()
            .filter_map(|(slot_id, result)| {
                if matches!(
                    result.result.status,
                    RelaySlotStatus::Submitted | RelaySlotStatus::AlreadySubmitted
                ) {
                    Some(slot_id.clone())
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>()
    };
    package
        .slots
        .iter()
        .filter(|candidate| {
            candidate.parent_child_index < slot.parent_child_index
                && submitted_slot_ids.contains(&candidate.slot_id)
                && slots_reuse_funding_notes(candidate, slot)
        })
        .cloned()
        .collect()
}

fn slots_reuse_funding_notes(candidate: &OfflineRenewalSlot, slot: &OfflineRenewalSlot) -> bool {
    if candidate.funding_note_commitments.is_empty() || slot.funding_note_commitments.is_empty() {
        return true;
    }
    let current = slot
        .funding_note_commitments
        .iter()
        .collect::<BTreeSet<_>>();
    candidate
        .funding_note_commitments
        .iter()
        .any(|commitment| current.contains(commitment))
}

async fn fetch_proof_job_status(
    state: &AppState,
    package: &OfflineRenewalPackage,
    batch_id: &str,
) -> Result<Option<PublicProofJobStatus>, String> {
    let prover_urls = package_prover_urls(&state.config, package)?;
    let internal_token = state
        .config
        .prover_control_token
        .as_ref()
        .map(|token| token.as_str());
    let path = if internal_token.is_some() {
        format!("/api/internal/proof-jobs/{batch_id}")
    } else {
        format!("/api/public/proof-jobs/{batch_id}")
    };
    match get_json_with_auth_failover::<PublicProofJobStatus>(
        &state.http,
        &prover_urls,
        &path,
        internal_token,
    )
    .await
    {
        Ok(status) => Ok(Some(status)),
        Err(error) if error.starts_with("HTTP 404") => Ok(None),
        Err(error) => Err(error),
    }
}

fn proof_job_confirmed(status: &PublicProofJobStatus) -> bool {
    status.state.eq_ignore_ascii_case("confirmed-onchain")
}

fn proof_job_failed(status: &PublicProofJobStatus) -> bool {
    status.failure.is_some() || status.state.to_ascii_lowercase().contains("failed")
}

async fn submit_slot(
    state: &AppState,
    package: &OfflineRenewalPackage,
    slot: &OfflineRenewalSlot,
) -> Result<CoordinatorAccepted, String> {
    let prover_urls = package_prover_urls(&state.config, package)?;
    let coordinator_urls = package_coordinator_urls(&state.config, package)?;
    let mut ingress_request = slot.ingress_request.clone();
    let Some(object) = ingress_request.as_object_mut() else {
        return Err("slot ingress request must be a JSON object".into());
    };
    object.insert(
        "renewal_package_id".into(),
        Value::String(package.package_id.clone()),
    );
    object.insert(
        "renewal_package_commitment".into(),
        Value::String(package.package_commitment.clone()),
    );
    object.insert(
        "renewal_relay_mode".into(),
        serde_json::to_value(package.relay_mode.as_ref())
            .map_err(|error| format!("serialize relay mode: {error}"))?,
    );
    object.insert(
        "renewal_slot_order_commitment".into(),
        Value::String(slot.order_commitment.clone()),
    );
    object.insert("renewal_slot_pair".into(), Value::String(slot.pair.clone()));
    object.insert(
        "renewal_slot_batch_id".into(),
        Value::String(slot.batch_id.clone()),
    );
    object.insert(
        "renewal_slot_epoch_id".into(),
        Value::Number(serde_json::Number::from(slot.epoch_id)),
    );
    let ingress: IngressResponse = post_json_failover(
        &state.http,
        &prover_urls,
        "/api/private/orders",
        &ingress_request,
        None,
    )
    .await?;
    validate_ingress_receipt_for_slot(package, slot, &ingress.receipt)?;
    let order_path = if state.config.coordinator_control_token.is_some() {
        "/api/maker/orders"
    } else {
        "/api/orders"
    };
    let accepted: CoordinatorAccepted = post_json_failover(
        &state.http,
        &coordinator_urls,
        order_path,
        &ingress.coordinator_submission,
        state
            .config
            .coordinator_control_token
            .as_deref()
            .map(String::as_str),
    )
    .await?;
    validate_coordinator_accepted_for_slot(slot, &accepted)?;
    Ok(accepted)
}

fn validate_ingress_receipt_for_slot(
    package: &OfflineRenewalPackage,
    slot: &OfflineRenewalSlot,
    receipt: &IngressReceipt,
) -> Result<(), String> {
    if receipt.order_commitment != slot.order_commitment {
        return Err("private ingress receipt order commitment mismatch".into());
    }
    if receipt.pair_id != slot.pair {
        return Err("private ingress receipt pair mismatch".into());
    }
    if receipt.batch_id != slot.batch_id {
        return Err("private ingress receipt batch mismatch".into());
    }
    if receipt.epoch_id != slot.epoch_id {
        return Err("private ingress receipt epoch mismatch".into());
    }
    let Some(expected_relay_mode) = package.relay_mode.as_ref() else {
        return Err("package relay mode missing".into());
    };
    if receipt.relay_mode.as_ref() != Some(expected_relay_mode) {
        return Err("private ingress receipt relay mode mismatch".into());
    }
    if receipt.renewal_package_id.as_deref() != Some(package.package_id.as_str()) {
        return Err("private ingress receipt package id mismatch".into());
    }
    if receipt.renewal_package_commitment.as_deref() != Some(package.package_commitment.as_str()) {
        return Err("private ingress receipt package commitment mismatch".into());
    }
    Ok(())
}

fn validate_coordinator_accepted_for_slot(
    slot: &OfflineRenewalSlot,
    accepted: &CoordinatorAccepted,
) -> Result<(), String> {
    if accepted.order_commitment != slot.order_commitment {
        return Err("coordinator accepted order commitment mismatch".into());
    }
    if accepted.batch_id != slot.batch_id {
        return Err("coordinator accepted batch mismatch".into());
    }
    Ok(())
}

async fn fetch_current_batch(
    state: &AppState,
    package: &OfflineRenewalPackage,
    pair: &str,
) -> Result<PublicBatchSummary, String> {
    let coordinator_urls = package_coordinator_urls(&state.config, package)?;
    let (base, quote) = pair
        .split_once('/')
        .ok_or_else(|| format!("invalid pair {pair}"))?;
    get_json_failover(
        &state.http,
        &coordinator_urls,
        &format!("/api/pairs/{base}/{quote}/batches/current"),
    )
    .await
}

async fn record_slot_result(
    state: &AppState,
    package_id: &str,
    result: OfflineRenewalRelayResult,
) -> Option<StoredSlotResult> {
    let now = now_unix_ms();
    let mut store = state.store.write().await;
    let package = store.packages.get_mut(package_id)?;
    let previous_attempts = package
        .results
        .get(&result.slot_id)
        .map(|entry| entry.attempts)
        .unwrap_or_default();
    let attempts = if matches!(
        result.status,
        RelaySlotStatus::NotDue | RelaySlotStatus::AwaitingSettlement
    ) {
        previous_attempts
    } else {
        previous_attempts.saturating_add(1)
    };
    let stored = StoredSlotResult {
        result: result.clone(),
        attempts,
        last_attempt_unix_ms: now,
    };
    package
        .results
        .insert(result.slot_id.clone(), stored.clone());
    package.updated_at_unix_ms = now;
    Some(stored)
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

async fn post_json_failover<T: for<'de> Deserialize<'de>>(
    http: &Client,
    base_urls: &[String],
    path: &str,
    body: &Value,
    bearer_token: Option<&str>,
) -> Result<T, String> {
    let mut last_error = None;
    for (index, base_url) in base_urls.iter().enumerate() {
        match post_json(http, base_url, path, body, bearer_token).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                let retryable = is_failover_retryable_error(&error);
                last_error = Some(format!("{}{}: {error}", base_url, path));
                if !retryable || index + 1 == base_urls.len() {
                    break;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| format!("no endpoints configured for {path}")))
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

async fn get_json_failover<T: for<'de> Deserialize<'de>>(
    http: &Client,
    base_urls: &[String],
    path: &str,
) -> Result<T, String> {
    let mut last_error = None;
    for (index, base_url) in base_urls.iter().enumerate() {
        match get_json(http, base_url, path).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                let retryable = is_failover_retryable_error(&error);
                last_error = Some(format!("{}{}: {error}", base_url, path));
                if !retryable || index + 1 == base_urls.len() {
                    break;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| format!("no endpoints configured for {path}")))
}

async fn get_json_with_auth<T: for<'de> Deserialize<'de>>(
    http: &Client,
    base_url: &str,
    path: &str,
    bearer_token: Option<&str>,
) -> Result<T, String> {
    let mut request = http
        .get(format!("{base_url}{path}"))
        .header("accept", "application/json");
    if let Some(token) = bearer_token {
        request = request.header("authorization", format_bearer_token(token));
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

async fn get_json_with_auth_failover<T: for<'de> Deserialize<'de>>(
    http: &Client,
    base_urls: &[String],
    path: &str,
    bearer_token: Option<&str>,
) -> Result<T, String> {
    let mut last_error = None;
    for (index, base_url) in base_urls.iter().enumerate() {
        match get_json_with_auth(http, base_url, path, bearer_token).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                let retryable = is_failover_retryable_error(&error);
                last_error = Some(format!("{}{}: {error}", base_url, path));
                if !retryable || index + 1 == base_urls.len() {
                    break;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| format!("no endpoints configured for {path}")))
}

async fn post_alert_webhook(
    http: &Client,
    webhook_url: &str,
    body: &Value,
    bearer_token: Option<&str>,
) -> Result<(), String> {
    let mut request = http
        .post(webhook_url)
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
    Ok(())
}

fn is_failover_retryable_error(error: &str) -> bool {
    error.starts_with("request failed")
        || error.starts_with("invalid JSON response")
        || error.starts_with("HTTP 5")
        || error.starts_with("HTTP 408")
        || error.starts_with("HTTP 429")
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
    let Some(relay_mode) = package.relay_mode.as_ref() else {
        return Err(RelayApiError::bad_request(
            "Renewal package relay mode is missing",
        ));
    };
    if !config.accepted_relay_mode.allows(relay_mode) {
        return Err(RelayApiError::bad_request(format!(
            "Relay accepts {} packages, got {}",
            config.accepted_relay_mode.label(),
            relay_mode_log_label(Some(relay_mode)),
        )));
    }
    if package.package_id.trim().is_empty() || package.package_commitment.trim().is_empty() {
        return Err(RelayApiError::bad_request(
            "Renewal package identity is missing",
        ));
    }
    if package
        .parent_cancel_authority
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
        || package
            .parent_cancel_marker
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(RelayApiError::bad_request(
            "Renewal package cancellation marker is missing",
        ));
    }
    let expected_commitment = renewal_package_commitment(package)
        .map_err(|error| RelayApiError::bad_request(format!("Invalid renewal package: {error}")))?;
    if !package
        .package_commitment
        .trim()
        .eq_ignore_ascii_case(&expected_commitment)
    {
        return Err(RelayApiError::bad_request(
            "Renewal package commitment does not match package body",
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
    if !package
        .slots
        .windows(2)
        .all(|window| window[0].epoch_id <= window[1].epoch_id)
    {
        return Err(RelayApiError::bad_request(
            "Renewal package slots must be sorted by epoch",
        ));
    }
    if package_prover_urls(config, package).is_err()
        || package_coordinator_urls(config, package).is_err()
    {
        return Err(RelayApiError::bad_request(
            "Renewal package requires coordinator and prover URLs",
        ));
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

fn renewal_package_commitment(package: &OfflineRenewalPackage) -> Result<String, String> {
    let mut value =
        serde_json::to_value(package).map_err(|error| format!("serialize package: {error}"))?;
    let Some(object) = value.as_object_mut() else {
        return Err("package is not an object".into());
    };
    object.remove("package_commitment");
    object.remove("relay_authorization");
    let canonical = stable_json_string(&value)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(format!("0x{}", hex_lower(&digest)))
}

fn stable_json_string(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(value) => Ok(if *value { "true" } else { "false" }.into()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => {
            serde_json::to_string(value).map_err(|error| format!("serialize string: {error}"))
        }
        Value::Array(values) => {
            let mut out = String::from("[");
            for (index, entry) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&stable_json_string(entry)?);
            }
            out.push(']');
            Ok(out)
        }
        Value::Object(values) => {
            let mut sorted = values.iter().collect::<Vec<_>>();
            sorted.sort_by_key(|(key, _)| *key);
            let mut out = String::from("{");
            for (index, (key, entry)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key)
                        .map_err(|error| format!("serialize object key: {error}"))?,
                );
                out.push(':');
                out.push_str(&stable_json_string(entry)?);
            }
            out.push('}');
            Ok(out)
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
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
        relay_mode: stored
            .package
            .relay_mode
            .clone()
            .unwrap_or(RelayMode::ZylithRelay),
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
        .saturating_sub(effective_submission_safety_buffer_ms(package));
    let max_delay = effective_max_submission_delay_ms(package);
    if max_delay == 0 {
        return 0;
    }
    let window_start = close_minus_safety.saturating_sub(max_delay);
    window_start.saturating_add(stable_jitter_ms(slot, package, max_delay).min(max_delay))
}

fn stable_jitter_ms(
    slot: &OfflineRenewalSlot,
    package: &OfflineRenewalPackage,
    max_delay: u64,
) -> u64 {
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

fn effective_submission_safety_buffer_ms(package: &OfflineRenewalPackage) -> u64 {
    if package.relay_mode == Some(RelayMode::ZylithRelay) {
        package.relay_policy.submission_safety_buffer_ms.clamp(
            MIN_MANAGED_SUBMISSION_SAFETY_BUFFER_MS,
            MAX_MANAGED_SUBMISSION_SAFETY_BUFFER_MS,
        )
    } else {
        package.relay_policy.submission_safety_buffer_ms
    }
}

fn effective_max_submission_delay_ms(package: &OfflineRenewalPackage) -> u64 {
    if package.relay_mode == Some(RelayMode::ZylithRelay) {
        if package.relay_policy.max_submission_delay_ms == 0 {
            return 0;
        }
        package.relay_policy.max_submission_delay_ms.clamp(
            MIN_MANAGED_SUBMISSION_DELAY_MS,
            MAX_MANAGED_SUBMISSION_DELAY_MS,
        )
    } else {
        package.relay_policy.max_submission_delay_ms
    }
}

fn configured_coordinator_urls(config: &RelayConfig) -> Vec<String> {
    let mut urls = Vec::new();
    if let Some(url) = config.default_coordinator_url.as_ref() {
        urls.push(url.clone());
    }
    urls.extend(config.default_coordinator_failover_urls.clone());
    dedup_urls(urls)
}

fn configured_prover_urls(config: &RelayConfig) -> Vec<String> {
    let mut urls = Vec::new();
    if let Some(url) = config.default_prover_url.as_ref() {
        urls.push(url.clone());
    }
    urls.extend(config.default_prover_failover_urls.clone());
    dedup_urls(urls)
}

fn package_prover_urls(
    config: &RelayConfig,
    package: &OfflineRenewalPackage,
) -> Result<Vec<String>, String> {
    let urls = configured_prover_urls(config);
    if !urls.is_empty() {
        return validate_service_urls(urls, false);
    }
    if package_policy_urls_disabled(config) {
        return Err("pinned prover URL is required for exposed or worker-enabled relays".into());
    }
    package_prover_url_from_policy(package)
        .map(|url| validate_service_urls(vec![url], package_policy_urls_disabled(config)))
        .transpose()?
        .ok_or_else(|| "private ingress URL missing".into())
}

fn package_coordinator_urls(
    config: &RelayConfig,
    package: &OfflineRenewalPackage,
) -> Result<Vec<String>, String> {
    let urls = configured_coordinator_urls(config);
    if !urls.is_empty() {
        return validate_service_urls(urls, false);
    }
    if package_policy_urls_disabled(config) {
        return Err(
            "pinned coordinator URL is required for exposed or worker-enabled relays".into(),
        );
    }
    package_coordinator_url_from_policy(package)
        .map(|url| validate_service_urls(vec![url], package_policy_urls_disabled(config)))
        .transpose()?
        .ok_or_else(|| "coordinator URL missing".into())
}

fn package_policy_urls_disabled(config: &RelayConfig) -> bool {
    config.strict_mode || config.enable_worker || !config.bind_addr.ip().is_loopback()
}

fn validate_service_urls(
    urls: Vec<String>,
    reject_restricted_hosts: bool,
) -> Result<Vec<String>, String> {
    urls.into_iter()
        .map(|url| validate_service_url(url, reject_restricted_hosts))
        .collect()
}

fn validate_service_url(url: String, reject_restricted_hosts: bool) -> Result<String, String> {
    let parsed =
        url::Url::parse(&url).map_err(|error| format!("invalid relay service URL: {error}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("relay service URL must use http or https".into()),
    }
    if reject_restricted_hosts {
        let Some(host) = parsed.host_str() else {
            return Err("relay service URL host is missing".into());
        };
        if let Ok(ip) = host.parse::<IpAddr>()
            && is_restricted_outbound_ip(ip)
        {
            return Err("relay service URL points at a private or link-local address".into());
        }
    }
    Ok(url)
}

fn is_restricted_outbound_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 224
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.segments()[0] & 0xffc0 == 0xffc0
        }
    }
}

fn package_prover_url_from_policy(package: &OfflineRenewalPackage) -> Option<String> {
    non_empty(&package.relay_policy.prover_url).map(normalize_url)
}

fn package_coordinator_url_from_policy(package: &OfflineRenewalPackage) -> Option<String> {
    non_empty(&package.relay_policy.coordinator_url).map(normalize_url)
}

fn require_package_registration_auth(
    state: &AppState,
    headers: &HeaderMap,
    package: &OfflineRenewalPackage,
) -> Result<(), RelayApiError> {
    let expected_bearer = state
        .config
        .package_registration_token
        .as_deref()
        .map(String::as_str);
    if let Some(expected) = expected_bearer {
        match bearer_auth_status(expected, headers) {
            BearerAuthStatus::Valid => return Ok(()),
            BearerAuthStatus::Invalid => {
                return Err(RelayApiError::status(StatusCode::UNAUTHORIZED));
            }
            BearerAuthStatus::Missing => {}
        }
    }
    if verify_package_authorization_from_body(package).unwrap_or(false) {
        return Ok(());
    }
    if verify_package_authorization_from_headers(package, headers).unwrap_or(false) {
        return Ok(());
    }
    if state.config.strict_mode || expected_bearer.is_some() {
        return Err(RelayApiError::status(StatusCode::UNAUTHORIZED));
    }
    Ok(())
}

fn require_package_access_auth(
    state: &AppState,
    headers: &HeaderMap,
    package: &OfflineRenewalPackage,
) -> Result<(), RelayApiError> {
    if verify_package_authorization_from_headers(package, headers).unwrap_or(false) {
        return Ok(());
    }
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer_token)
    else {
        return Err(RelayApiError::status(StatusCode::UNAUTHORIZED));
    };
    let mut has_configured_token = false;
    for expected in [
        state
            .config
            .package_registration_token
            .as_deref()
            .map(String::as_str),
        state
            .config
            .internal_control_token
            .as_deref()
            .map(String::as_str),
    ]
    .into_iter()
    .flatten()
    {
        has_configured_token = true;
        if constant_time_eq(token, expected) {
            return Ok(());
        }
    }
    if !has_configured_token {
        return Err(RelayApiError::status(StatusCode::UNAUTHORIZED));
    }
    Err(RelayApiError::status(StatusCode::UNAUTHORIZED))
}

fn require_internal_auth(state: &AppState, headers: &HeaderMap) -> Result<(), RelayApiError> {
    let Some(expected) = state
        .config
        .internal_control_token
        .as_deref()
        .map(String::as_str)
    else {
        return Err(RelayApiError::status(StatusCode::UNAUTHORIZED));
    };
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| RelayApiError::status(StatusCode::UNAUTHORIZED))?;
    if !constant_time_eq(token, expected) {
        return Err(RelayApiError::status(StatusCode::UNAUTHORIZED));
    }
    Ok(())
}

enum BearerAuthStatus {
    Valid,
    Missing,
    Invalid,
}

fn bearer_auth_status(expected: &str, headers: &HeaderMap) -> BearerAuthStatus {
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer_token)
    else {
        return BearerAuthStatus::Missing;
    };
    if constant_time_eq(token, expected) {
        BearerAuthStatus::Valid
    } else {
        BearerAuthStatus::Invalid
    }
}

fn verify_package_authorization_from_body(package: &OfflineRenewalPackage) -> Result<bool, String> {
    let Some(authority) = package.parent_cancel_authority.as_deref() else {
        return Ok(false);
    };
    let Some(auth) = package.relay_authorization.as_ref() else {
        return Ok(false);
    };
    verify_package_authorization(authority, &package.package_commitment, auth)
}

fn verify_package_authorization_from_headers(
    package: &OfflineRenewalPackage,
    headers: &HeaderMap,
) -> Result<bool, String> {
    let package_commitment = header_str(headers, RELAY_PACKAGE_COMMITMENT_HEADER)?;
    if package_commitment != package.package_commitment {
        return Ok(false);
    }
    let parent_cancel_authority = header_str(headers, RELAY_PARENT_CANCEL_AUTHORITY_HEADER)?;
    let body_authority = package.parent_cancel_authority.as_deref().unwrap_or("");
    if !body_authority.is_empty() && parent_cancel_authority != body_authority {
        return Ok(false);
    }
    let auth = RelayPackageAuthorization {
        signer_public_key: header_str(headers, RELAY_SIGNER_HEADER)?.to_string(),
        signature_r: header_str(headers, RELAY_SIGNATURE_R_HEADER)?.to_string(),
        signature_s: header_str(headers, RELAY_SIGNATURE_S_HEADER)?.to_string(),
    };
    verify_package_authorization(parent_cancel_authority, package_commitment, &auth)
}

fn verify_package_authorization(
    parent_cancel_authority: &str,
    package_commitment: &str,
    auth: &RelayPackageAuthorization,
) -> Result<bool, String> {
    if auth.signer_public_key != parent_cancel_authority {
        return Ok(false);
    }
    zylith_core::verify_renewal_relay_package_authorization(
        parent_cancel_authority,
        package_commitment,
        &zylith_core::SpendAuthorization {
            signature_r: auth.signature_r.clone(),
            signature_s: auth.signature_s.clone(),
        },
    )
    .map_err(|error| error.to_string())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} missing"))
}

async fn enforce_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Result<(), RelayApiError> {
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
        .or_else(|| trusted_proxy_rate_limit_subject(headers, peer.map(|address| address.ip())))
        .or_else(|| peer.map(|address| address.ip().to_string()))
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

fn trusted_proxy_rate_limit_subject(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
) -> Option<String> {
    if !trusted_proxy_headers_enabled_for_peer(peer_ip) {
        return None;
    }
    for header in ["x-forwarded-for", "x-real-ip"] {
        if let Some(value) = headers
            .get(header)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(value.chars().take(96).collect());
        }
    }
    None
}

fn trusted_proxy_headers_enabled_for_peer(peer_ip: Option<IpAddr>) -> bool {
    let enabled = matches!(
        env::var("ZYLITH_RENEWAL_RELAY_TRUST_PROXY_HEADERS")
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
    let cidrs = env::var("ZYLITH_RENEWAL_RELAY_TRUSTED_PROXY_CIDRS")
        .or_else(|_| env::var("ZYLITH_TRUSTED_PROXY_CIDRS"))
        .unwrap_or_default();
    cidrs
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| value.parse::<IpNet>().ok())
        .any(|network| network.contains(&peer_ip))
}

fn prune_store_locked(store: &mut RelayStore, config: &RelayConfig, now: u64) {
    if config.package_retention_ms == 0 {
        return;
    }
    let newest_observed_epoch = store
        .packages
        .values()
        .flat_map(|package| package.results.values())
        .map(|entry| entry.result.epoch_id)
        .max();
    store.packages.retain(|_, package| {
        if now.saturating_sub(package.updated_at_unix_ms) > config.package_retention_ms {
            return false;
        }
        if let Some(epoch) = newest_observed_epoch
            && epoch
                > package
                    .package
                    .end_epoch
                    .saturating_add(config.package_expiry_warning_epochs)
        {
            return false;
        }
        true
    });
    store
        .cancelled_packages
        .retain(|_, cancelled_at| now.saturating_sub(*cancelled_at) <= config.package_retention_ms);
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
    let mut snapshot = store.read().await.clone();
    sanitize_store_for_persistence(&mut snapshot);
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

fn sanitize_store_for_persistence(store: &mut RelayStore) {
    for stored in store.packages.values_mut() {
        stored.package.relay_authorization = None;
    }
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
            let mut package = serde_json::from_str::<OfflineRenewalPackage>(&package_json)
                .map_err(|error| format!("invalid package JSON for {package_id}: {error}"))?;
            package.relay_authorization = None;
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
    {
        let mut statement = connection
            .prepare("SELECT package_id, cancelled_at_unix_ms FROM relay_cancelled_packages")
            .map_err(|error| error.to_string())?;
        let mut rows = statement.query([]).map_err(|error| error.to_string())?;
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let package_id: String = row.get(0).map_err(|error| error.to_string())?;
            let cancelled_at_unix_ms = row.get::<_, i64>(1).map_err(|error| error.to_string())?;
            store
                .cancelled_packages
                .insert(package_id, cancelled_at_unix_ms.max(0) as u64);
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
    let mut snapshot = snapshot;
    sanitize_store_for_persistence(&mut snapshot);
    for (package_id, stored) in snapshot.packages {
        let package_json =
            serde_json::to_string(&stored.package).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO relay_packages \
                 (package_id, package_commitment, pair, start_epoch, end_epoch, slot_count, \
                  package_json, registered_at_unix_ms, updated_at_unix_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(package_id) DO UPDATE SET \
                    package_commitment=excluded.package_commitment, \
                    pair=excluded.pair, \
                    start_epoch=excluded.start_epoch, \
                    end_epoch=excluded.end_epoch, \
                    slot_count=excluded.slot_count, \
                    package_json=excluded.package_json, \
                    updated_at_unix_ms=excluded.updated_at_unix_ms",
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
        transaction
            .execute(
                "DELETE FROM relay_due_slots WHERE package_id = ?1",
                params![package_id.as_str()],
            )
            .map_err(|error| error.to_string())?;
        for slot in &stored.package.slots {
            let slot_json = serde_json::to_string(slot).map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO relay_due_slots \
                     (package_id, slot_id, pair, epoch_id, slot_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5) \
                     ON CONFLICT(package_id, slot_id) DO UPDATE SET \
                        pair=excluded.pair, \
                        epoch_id=excluded.epoch_id, \
                        slot_json=excluded.slot_json",
                    params![
                        package_id.as_str(),
                        slot.slot_id.as_str(),
                        slot.pair.as_str(),
                        slot.epoch_id as i64,
                        slot_json.as_str(),
                    ],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction
            .execute(
                "DELETE FROM relay_slot_results WHERE package_id = ?1",
                params![package_id.as_str()],
            )
            .map_err(|error| error.to_string())?;
        for (slot_id, result) in stored.results {
            let result_json =
                serde_json::to_string(&result.result).map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO relay_slot_results \
                     (package_id, slot_id, result_json, status, attempts, last_attempt_unix_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                     ON CONFLICT(package_id, slot_id) DO UPDATE SET \
                        result_json=excluded.result_json, \
                        status=excluded.status, \
                        attempts=excluded.attempts, \
                        last_attempt_unix_ms=excluded.last_attempt_unix_ms",
                    params![
                        package_id.as_str(),
                        slot_id.as_str(),
                        result_json.as_str(),
                        slot_status_label(&result.result.status),
                        result.attempts as i64,
                        result.last_attempt_unix_ms as i64,
                    ],
                )
                .map_err(|error| error.to_string())?;
        }
    }
    for (package_id, cancelled_at_unix_ms) in snapshot.cancelled_packages {
        transaction
            .execute(
                "INSERT INTO relay_cancelled_packages (package_id, cancelled_at_unix_ms) \
                 VALUES (?1, ?2) \
                 ON CONFLICT(package_id) DO UPDATE SET \
                    cancelled_at_unix_ms=excluded.cancelled_at_unix_ms",
                params![package_id.as_str(), cancelled_at_unix_ms as i64],
            )
            .map_err(|error| error.to_string())?;
    }
    transaction.commit().map_err(|error| error.to_string())
}

async fn persist_sqlite_package_tombstone(
    path: &FsPath,
    package_id: &str,
    cancelled_at_unix_ms: u64,
) -> Result<(), String> {
    let path = path.to_path_buf();
    let package_id = package_id.to_string();
    tokio::task::spawn_blocking(move || {
        let mut connection = open_sqlite_store(&path)?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "DELETE FROM relay_packages WHERE package_id = ?1",
                params![package_id.as_str()],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO relay_cancelled_packages (package_id, cancelled_at_unix_ms) \
                 VALUES (?1, ?2) \
                 ON CONFLICT(package_id) DO UPDATE SET \
                    cancelled_at_unix_ms=excluded.cancelled_at_unix_ms",
                params![package_id.as_str(), cancelled_at_unix_ms as i64],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

async fn load_sqlite_due_slots_for_package(
    config: &RelayConfig,
    package_id: &str,
    current_epoch: u64,
) -> Result<Vec<OfflineRenewalSlot>, String> {
    let path = config.store_path.clone();
    let package_id = package_id.to_string();
    let max_attempts = config.max_attempts;
    let retry_cutoff_unix_ms = now_unix_ms().saturating_sub(config.retry_backoff_ms);
    tokio::task::spawn_blocking(move || {
        let connection = open_sqlite_store(&path)?;
        let mut statement = connection
            .prepare(
                "SELECT d.slot_json \
                 FROM relay_due_slots d \
                 LEFT JOIN relay_slot_results r \
                    ON r.package_id = d.package_id AND r.slot_id = d.slot_id \
                 WHERE d.package_id = ?1 \
                   AND d.epoch_id <= ?2 \
                   AND ( \
                        r.slot_id IS NULL \
                        OR ( \
                            r.status NOT IN ('submitted', 'already_submitted', 'awaiting_wallet_refresh', 'missed') \
                            AND r.attempts < ?3 \
                            AND r.last_attempt_unix_ms <= ?4 \
                        ) \
                   ) \
                 ORDER BY d.epoch_id ASC, d.slot_id ASC \
                 LIMIT 512",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = statement
            .query(params![
                package_id.as_str(),
                current_epoch as i64,
                max_attempts as i64,
                retry_cutoff_unix_ms as i64,
            ])
            .map_err(|error| error.to_string())?;
        let mut slots = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let slot_json: String = row.get(0).map_err(|error| error.to_string())?;
            slots.push(
                serde_json::from_str::<OfflineRenewalSlot>(&slot_json)
                    .map_err(|error| format!("invalid indexed renewal slot JSON: {error}"))?,
            );
        }
        Ok(slots)
    })
    .await
    .map_err(|error| error.to_string())?
}

async fn load_sqlite_prior_submitted_reused_funding_slots(
    config: &RelayConfig,
    package_id: &str,
    slot: &OfflineRenewalSlot,
) -> Result<Vec<OfflineRenewalSlot>, String> {
    let path = config.store_path.clone();
    let package_id = package_id.to_string();
    let slot = slot.clone();
    tokio::task::spawn_blocking(move || {
        let connection = open_sqlite_store(&path)?;
        let mut statement = connection
            .prepare(
                "SELECT d.slot_json \
                 FROM relay_due_slots d \
                 INNER JOIN relay_slot_results r \
                    ON r.package_id = d.package_id AND r.slot_id = d.slot_id \
                 WHERE d.package_id = ?1 \
                   AND d.epoch_id <= ?2 \
                   AND r.status IN ('submitted', 'already_submitted') \
                 ORDER BY d.epoch_id DESC, d.slot_id DESC \
                 LIMIT 1024",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = statement
            .query(params![package_id.as_str(), slot.epoch_id as i64])
            .map_err(|error| error.to_string())?;
        let mut slots = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            let slot_json: String = row.get(0).map_err(|error| error.to_string())?;
            let candidate = serde_json::from_str::<OfflineRenewalSlot>(&slot_json)
                .map_err(|error| format!("invalid indexed renewal slot JSON: {error}"))?;
            if candidate.parent_child_index < slot.parent_child_index
                && slots_reuse_funding_notes(&candidate, &slot)
            {
                slots.push(candidate);
            }
        }
        Ok(slots)
    })
    .await
    .map_err(|error| error.to_string())?
}

async fn persist_sqlite_slot_result(
    path: &FsPath,
    package_id: &str,
    result: StoredSlotResult,
) -> Result<(), String> {
    let path = path.to_path_buf();
    let package_id = package_id.to_string();
    tokio::task::spawn_blocking(move || {
        let connection = open_sqlite_store(&path)?;
        let result_json =
            serde_json::to_string(&result.result).map_err(|error| error.to_string())?;
        let now = now_unix_ms();
        connection
            .execute(
                "INSERT INTO relay_slot_results \
                 (package_id, slot_id, result_json, status, attempts, last_attempt_unix_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(package_id, slot_id) DO UPDATE SET \
                    result_json=excluded.result_json, \
                    status=excluded.status, \
                    attempts=excluded.attempts, \
                    last_attempt_unix_ms=excluded.last_attempt_unix_ms",
                params![
                    package_id.as_str(),
                    result.result.slot_id.as_str(),
                    result_json.as_str(),
                    slot_status_label(&result.result.status),
                    result.attempts as i64,
                    result.last_attempt_unix_ms as i64,
                ],
            )
            .map_err(|error| error.to_string())?;
        connection
            .execute(
                "UPDATE relay_packages SET updated_at_unix_ms = ?2 WHERE package_id = ?1",
                params![package_id.as_str(), now as i64],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

fn slot_status_label(status: &RelaySlotStatus) -> &'static str {
    match status {
        RelaySlotStatus::Submitted => "submitted",
        RelaySlotStatus::AlreadySubmitted => "already_submitted",
        RelaySlotStatus::NotDue => "not_due",
        RelaySlotStatus::BatchNotOpen => "batch_not_open",
        RelaySlotStatus::SafetyBuffer => "safety_buffer",
        RelaySlotStatus::AwaitingSettlement => "awaiting_settlement",
        RelaySlotStatus::AwaitingWalletRefresh => "awaiting_wallet_refresh",
        RelaySlotStatus::Missed => "missed",
        RelaySlotStatus::Failed => "failed",
    }
}

fn csv_row(values: &[&str]) -> String {
    let mut row = values
        .iter()
        .map(|value| csv_cell(value))
        .collect::<Vec<_>>()
        .join(",");
    row.push('\n');
    row
}

fn csv_cell(value: &str) -> String {
    let mut sanitized = value
        .chars()
        .take(512)
        .map(|character| match character {
            '\r' | '\n' => ' ',
            _ => character,
        })
        .collect::<String>();
    if matches!(sanitized.chars().next(), Some('=' | '+' | '-' | '@')) {
        sanitized.insert(0, '\'');
    }
    if sanitized.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
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
                status TEXT NOT NULL DEFAULT '',
                attempts INTEGER NOT NULL,
                last_attempt_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (package_id, slot_id),
                FOREIGN KEY(package_id) REFERENCES relay_packages(package_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS relay_slot_results_last_attempt_idx
                ON relay_slot_results(last_attempt_unix_ms);
            CREATE TABLE IF NOT EXISTS relay_due_slots (
                package_id TEXT NOT NULL,
                slot_id TEXT NOT NULL,
                pair TEXT NOT NULL,
                epoch_id INTEGER NOT NULL,
                slot_json TEXT NOT NULL,
                PRIMARY KEY (package_id, slot_id),
                FOREIGN KEY(package_id) REFERENCES relay_packages(package_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS relay_due_slots_package_epoch_idx
                ON relay_due_slots(package_id, epoch_id);
            CREATE INDEX IF NOT EXISTS relay_due_slots_pair_epoch_idx
                ON relay_due_slots(pair, epoch_id);
            CREATE TABLE IF NOT EXISTS relay_cancelled_packages (
                package_id TEXT PRIMARY KEY,
                cancelled_at_unix_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS relay_cancelled_packages_cancelled_at_idx
                ON relay_cancelled_packages(cancelled_at_unix_ms);
            CREATE TABLE IF NOT EXISTS relay_locks (
                name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL
            );",
        )
        .map_err(|error| error.to_string())?;
    ensure_sqlite_column(
        connection,
        "relay_slot_results",
        "status",
        "ALTER TABLE relay_slot_results ADD COLUMN status TEXT NOT NULL DEFAULT ''",
    )?;
    connection
        .execute(
            "CREATE INDEX IF NOT EXISTS relay_slot_results_status_idx ON relay_slot_results(status)",
            [],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn ensure_sqlite_column(
    connection: &Connection,
    table: &str,
    column: &str,
    alter_sql: &str,
) -> Result<(), String> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|error| error.to_string())?;
    let mut rows = statement.query([]).map_err(|error| error.to_string())?;
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let name: String = row.get(1).map_err(|error| error.to_string())?;
        if name == column {
            return Ok(());
        }
    }
    connection
        .execute(alter_sql, [])
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
    let owner = format!(
        "pid:{}:{}:{}",
        std::process::id(),
        now_unix_ms(),
        TICK_LEASE_OWNER_COUNTER.fetch_add(1, Ordering::Relaxed),
    );
    let now = now_unix_ms();
    let expires_at = now.saturating_add(lease_ms) as i64;
    let mut connection = open_sqlite_store(path)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let changed = transaction
        .execute(
            "INSERT INTO relay_locks (name, owner, expires_at_unix_ms)
             VALUES ('worker_tick', ?1, ?2)
             ON CONFLICT(name) DO UPDATE SET
                owner = excluded.owner,
                expires_at_unix_ms = excluded.expires_at_unix_ms
             WHERE relay_locks.expires_at_unix_ms <= ?3 OR relay_locks.owner = ?1",
            params![owner, expires_at, now as i64],
        )
        .map_err(|error| error.to_string())?;
    if changed == 0 {
        return Ok(PersistentTickLease::Busy);
    }
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
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);
    if config.allowed_origins.is_empty() {
        return if config.bind_addr.ip().is_loopback() {
            layer.allow_origin(Any)
        } else {
            layer
        };
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

fn configured_urls_from_env(list_env: &str, single_env: &str) -> Vec<String> {
    let mut urls = env::var(list_env)
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(non_empty)
                .map(normalize_url)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if urls.is_empty()
        && !single_env.is_empty()
        && let Ok(value) = env::var(single_env)
        && let Some(url) = non_empty(&value)
    {
        urls.push(normalize_url(url));
    }
    dedup_urls(urls)
}

fn dedup_urls(urls: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    urls.into_iter()
        .filter(|url| seen.insert(url.to_ascii_lowercase()))
        .collect()
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

    static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn trusted_proxy_rate_limit_subject_ignores_untrusted_forwarded_headers() {
        let _guard = TEST_ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var("ZYLITH_RENEWAL_RELAY_TRUST_PROXY_HEADERS", "true");
            std::env::remove_var("ZYLITH_RENEWAL_RELAY_TRUSTED_PROXY_CIDRS");
            std::env::remove_var("ZYLITH_TRUSTED_PROXY_CIDRS");
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
        let peer: SocketAddr = "198.51.100.7:9443".parse().expect("peer");

        assert_eq!(
            trusted_proxy_rate_limit_subject(&headers, Some(peer.ip())),
            None
        );

        unsafe {
            std::env::remove_var("ZYLITH_RENEWAL_RELAY_TRUST_PROXY_HEADERS");
        }
    }

    #[test]
    fn trusted_proxy_rate_limit_subject_accepts_forwarded_headers_from_trusted_cidr() {
        let _guard = TEST_ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var("ZYLITH_RENEWAL_RELAY_TRUST_PROXY_HEADERS", "true");
            std::env::set_var(
                "ZYLITH_RENEWAL_RELAY_TRUSTED_PROXY_CIDRS",
                "198.51.100.0/24",
            );
            std::env::remove_var("ZYLITH_TRUSTED_PROXY_CIDRS");
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
        let peer: SocketAddr = "198.51.100.7:9443".parse().expect("peer");

        assert_eq!(
            trusted_proxy_rate_limit_subject(&headers, Some(peer.ip())),
            Some("203.0.113.9".into())
        );

        unsafe {
            std::env::remove_var("ZYLITH_RENEWAL_RELAY_TRUST_PROXY_HEADERS");
            std::env::remove_var("ZYLITH_RENEWAL_RELAY_TRUSTED_PROXY_CIDRS");
        }
    }

    fn test_package(coordinator_url: String, prover_url: String) -> OfflineRenewalPackage {
        let mut package = OfflineRenewalPackage {
            version: 1,
            package_id: "pkg-1".into(),
            package_commitment: String::new(),
            created_at_unix_ms: 1,
            pair: "STRK/USDC".into(),
            start_epoch: 42,
            end_epoch: 42,
            slot_count: 1,
            relay_mode: Some(RelayMode::ZylithRelay),
            parent_cancel_authority: Some("0xparent".into()),
            parent_cancel_marker: Some("0xcancel".into()),
            relay_authorization: None,
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
                funding_note_commitments: vec!["0xfunding".into()],
                ingress_request: json!({ "order_submission": { "opaque": true } }),
            }],
        };
        refresh_test_package_commitment(&mut package);
        package
    }

    #[test]
    fn managed_fast_submission_remains_immediate() {
        let mut package = test_package(
            "https://coordinator.example".into(),
            "https://prover.example".into(),
        );
        package.relay_mode = Some(RelayMode::ZylithRelay);
        package.relay_policy.submission_safety_buffer_ms = 15_000;
        package.relay_policy.max_submission_delay_ms = 0;
        let batch = PublicBatchSummary {
            batch_id: package.slots[0].batch_id.clone(),
            epoch_id: package.slots[0].epoch_id,
            close_time_unix_ms: now_unix_ms().saturating_add(120_000),
            status: "Open".into(),
        };

        assert_eq!(effective_max_submission_delay_ms(&package), 0);
        assert_eq!(
            scheduled_submission_time(&batch, &package, &package.slots[0]),
            0
        );
    }

    fn two_slot_test_package(
        coordinator_url: String,
        prover_url: String,
        reuse_funding_notes: bool,
    ) -> OfflineRenewalPackage {
        let mut package = test_package(coordinator_url, prover_url);
        package.end_epoch = 43;
        package.slot_count = 2;
        let mut second = package.slots[0].clone();
        second.slot_id = "pkg-1:2".into();
        second.batch_id = "STRK-USDC-43".into();
        second.epoch_id = 43;
        second.parent_child_index = 2;
        second.order_commitment = "0x456".into();
        if !reuse_funding_notes {
            second.funding_note_commitments = vec!["0xotherfunding".into()];
        }
        package.slots.push(second);
        refresh_test_package_commitment(&mut package);
        package
    }

    fn long_window_test_package(
        coordinator_url: String,
        prover_url: String,
        start_epoch: u64,
        slot_count: usize,
    ) -> OfflineRenewalPackage {
        let slots = (0..slot_count)
            .map(|index| {
                let epoch = start_epoch + index as u64;
                OfflineRenewalSlot {
                    slot_id: format!("pkg-long:{}", index + 1),
                    pair: "STRK/USDC".into(),
                    batch_id: format!("STRK-USDC-{epoch}"),
                    epoch_id: epoch,
                    parent_child_index: index as u64 + 1,
                    order_commitment: format!("0x{:x}", 0x1000u128 + index as u128),
                    funding_note_commitments: vec![format!("0xfunding{:x}", index + 1)],
                    ingress_request: json!({ "order_submission": { "opaque": true } }),
                }
            })
            .collect::<Vec<_>>();
        let mut package = OfflineRenewalPackage {
            version: 1,
            package_id: "pkg-long".into(),
            package_commitment: String::new(),
            created_at_unix_ms: 1,
            pair: "STRK/USDC".into(),
            start_epoch,
            end_epoch: start_epoch + slot_count as u64 - 1,
            slot_count,
            relay_mode: Some(RelayMode::ZylithRelay),
            parent_cancel_authority: Some("0xparent".into()),
            parent_cancel_marker: Some("0xcancel".into()),
            relay_authorization: None,
            ingress_key_registry_fingerprint: None,
            relay_policy: RelayPolicy {
                prover_url,
                coordinator_url,
                submission_safety_buffer_ms: 1_000,
                max_submission_delay_ms: 0,
            },
            slots,
        };
        refresh_test_package_commitment(&mut package);
        package
    }

    fn refresh_test_package_commitment(package: &mut OfflineRenewalPackage) {
        package.package_commitment = renewal_package_commitment(package).expect("package hash");
    }

    fn authorize_package(package: &mut OfflineRenewalPackage) {
        let private_key = "0x12345";
        let parent_cancel_authority =
            zylith_core::renewal_cancel_authority_from_renewal_cancel_auth_key_felt(private_key)
                .expect("relay auth authority");
        package.parent_cancel_authority = Some(parent_cancel_authority.clone());
        package.parent_cancel_marker = Some("0xcancel".into());
        refresh_test_package_commitment(package);
        let authorization = zylith_core::sign_renewal_relay_package_authorization(
            private_key,
            &package.package_commitment,
            &parent_cancel_authority,
        )
        .expect("relay auth signature");
        package.relay_authorization = Some(RelayPackageAuthorization {
            signer_public_key: parent_cancel_authority,
            signature_r: authorization.signature_r,
            signature_s: authorization.signature_s,
        });
    }

    fn test_state(path: PathBuf) -> AppState {
        AppState {
            config: RelayConfig {
                bind_addr: DEFAULT_BIND_ADDR.parse().unwrap(),
                store_path: path,
                package_registration_token: None,
                default_coordinator_url: None,
                default_prover_url: None,
                default_coordinator_failover_urls: Vec::new(),
                default_prover_failover_urls: Vec::new(),
                coordinator_control_token: None,
                internal_control_token: None,
                prover_control_token: None,
                alert_webhook_urls: Vec::new(),
                alert_webhook_token: None,
                alert_repeat_ms: DEFAULT_ALERT_REPEAT_MS,
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
                accepted_relay_mode: AcceptedRelayMode::ZylithRelay,
                package_expiry_warning_epochs: DEFAULT_PACKAGE_EXPIRY_WARNING_EPOCHS,
            },
            store: Arc::new(RwLock::new(RelayStore::default())),
            http: Client::new(),
            tick_lock: Arc::new(Mutex::new(())),
            rate_limits: Arc::new(RwLock::new(BTreeMap::new())),
            alert_dispatch_cache: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    #[test]
    fn prune_store_removes_expired_packages_and_cancel_tombstones() {
        let mut state = test_state(temp_store_path("prune-retention"));
        state.config.package_retention_ms = 100;
        state.config.package_expiry_warning_epochs = 2;
        let now = 1_000;

        let mut aged_out = test_package("http://coordinator".into(), "http://prover".into());
        aged_out.package_id = "pkg-aged-out".into();
        aged_out.slots[0].slot_id = "pkg-aged-out:1".into();
        refresh_test_package_commitment(&mut aged_out);

        let mut epoch_expired = test_package("http://coordinator".into(), "http://prover".into());
        epoch_expired.package_id = "pkg-epoch-expired".into();
        epoch_expired.slots[0].slot_id = "pkg-epoch-expired:1".into();
        epoch_expired.start_epoch = 40;
        epoch_expired.end_epoch = 40;
        epoch_expired.slots[0].epoch_id = 40;
        epoch_expired.slots[0].batch_id = "STRK-USDC-40".into();
        refresh_test_package_commitment(&mut epoch_expired);

        let mut live = test_package("http://coordinator".into(), "http://prover".into());
        live.package_id = "pkg-live".into();
        live.slots[0].slot_id = "pkg-live:1".into();
        live.start_epoch = 100;
        live.end_epoch = 100;
        live.slots[0].epoch_id = 100;
        live.slots[0].batch_id = "STRK-USDC-100".into();
        refresh_test_package_commitment(&mut live);
        let mut live_result = slot_result(&live.slots[0], RelaySlotStatus::Submitted, None);
        live_result.epoch_id = 101;

        let mut store = RelayStore::default();
        store.packages.insert(
            aged_out.package_id.clone(),
            StoredPackage {
                package: aged_out,
                registered_at_unix_ms: now - 500,
                updated_at_unix_ms: now - 101,
                results: BTreeMap::new(),
            },
        );
        store.packages.insert(
            epoch_expired.package_id.clone(),
            StoredPackage {
                package: epoch_expired.clone(),
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
                results: BTreeMap::from([(
                    epoch_expired.slots[0].slot_id.clone(),
                    StoredSlotResult {
                        result: slot_result(
                            &epoch_expired.slots[0],
                            RelaySlotStatus::Submitted,
                            None,
                        ),
                        attempts: 1,
                        last_attempt_unix_ms: now,
                    },
                )]),
            },
        );
        store.packages.insert(
            live.package_id.clone(),
            StoredPackage {
                package: live.clone(),
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
                results: BTreeMap::from([(
                    live.slots[0].slot_id.clone(),
                    StoredSlotResult {
                        result: live_result,
                        attempts: 1,
                        last_attempt_unix_ms: now,
                    },
                )]),
            },
        );
        store
            .cancelled_packages
            .insert("pkg-cancel-aged-out".into(), now - 101);
        store
            .cancelled_packages
            .insert("pkg-cancel-live".into(), now - 100);

        prune_store_locked(&mut store, &state.config, now);

        assert!(!store.packages.contains_key("pkg-aged-out"));
        assert!(!store.packages.contains_key("pkg-epoch-expired"));
        assert!(store.packages.contains_key("pkg-live"));
        assert!(!store.cancelled_packages.contains_key("pkg-cancel-aged-out"));
        assert!(store.cancelled_packages.contains_key("pkg-cancel-live"));
    }

    #[test]
    fn managed_validation_rejects_self_relay_packages() {
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        package.relay_mode = Some(RelayMode::SelfRelay);
        let state = test_state(temp_store_path("validate-self-relay"));
        assert!(validate_package(&package, &state.config).is_err());
    }

    #[test]
    fn self_hosted_validation_accepts_self_relay_and_rejects_managed_packages() {
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        let mut state = test_state(temp_store_path("validate-self-hosted-relay"));
        state.config.accepted_relay_mode = AcceptedRelayMode::SelfRelay;
        assert!(validate_package(&package, &state.config).is_err());

        package.relay_mode = Some(RelayMode::SelfRelay);
        refresh_test_package_commitment(&mut package);
        assert!(validate_package(&package, &state.config).is_ok());
    }

    #[tokio::test]
    async fn strict_self_hosted_readiness_does_not_require_coordinator_control_token() {
        let path = temp_sqlite_store_path("self-ready");
        let mut state = test_state(path.clone());
        state.config.strict_mode = true;
        state.config.accepted_relay_mode = AcceptedRelayMode::SelfRelay;
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.internal_control_token = Some(Arc::new("internal-token".into()));
        state.config.prover_control_token = Some(Arc::new("prover-token".into()));
        state.config.allowed_origins = vec![HeaderValue::from_static("https://app.zylith.fi")];

        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/ready")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn strict_managed_readiness_requires_coordinator_control_token() {
        let path = temp_sqlite_store_path("managed-ready");
        let mut state = test_state(path.clone());
        state.config.strict_mode = true;
        state.config.accepted_relay_mode = AcceptedRelayMode::ZylithRelay;
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.internal_control_token = Some(Arc::new("internal-token".into()));
        state.config.prover_control_token = Some(Arc::new("prover-token".into()));
        state.config.allowed_origins = vec![HeaderValue::from_static("https://app.zylith.fi")];

        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/ready")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn metrics_exposes_alertable_operational_counters() {
        let mut state = test_state(temp_store_path("metrics"));
        state.config.internal_control_token = Some(Arc::new("internal-token".into()));
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        let mut missed_slot = package.slots[0].clone();
        missed_slot.slot_id = "pkg-1:2".into();
        missed_slot.order_commitment = "0xmissed".into();
        missed_slot.epoch_id = 43;
        let mut failed_slot = package.slots[0].clone();
        failed_slot.slot_id = "pkg-1:3".into();
        failed_slot.order_commitment = "0xfailed".into();
        failed_slot.epoch_id = 44;
        package.end_epoch = 44;
        package.slot_count = 3;
        package.slots.push(missed_slot.clone());
        package.slots.push(failed_slot.clone());

        {
            let mut store = state.store.write().await;
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package: package.clone(),
                    registered_at_unix_ms: 1,
                    updated_at_unix_ms: 1,
                    results: BTreeMap::from([
                        (
                            package.slots[0].slot_id.clone(),
                            StoredSlotResult {
                                result: slot_result(
                                    &package.slots[0],
                                    RelaySlotStatus::Submitted,
                                    None,
                                ),
                                attempts: 1,
                                last_attempt_unix_ms: 1,
                            },
                        ),
                        (
                            missed_slot.slot_id.clone(),
                            StoredSlotResult {
                                result: slot_result(&missed_slot, RelaySlotStatus::Missed, None),
                                attempts: 1,
                                last_attempt_unix_ms: 1,
                            },
                        ),
                        (
                            failed_slot.slot_id.clone(),
                            StoredSlotResult {
                                result: slot_result(&failed_slot, RelaySlotStatus::Failed, None),
                                attempts: 1,
                                last_attempt_unix_ms: 1,
                            },
                        ),
                    ]),
                },
            );
        }

        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(AUTHORIZATION, "Bearer internal-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(text.contains("zylith_renewal_relay_packages 1"));
        assert!(text.contains("zylith_renewal_relay_slots 3"));
        assert!(text.contains("zylith_renewal_relay_submitted_slots 1"));
        assert!(text.contains("zylith_renewal_relay_pending_slots 1"));
        assert!(text.contains("zylith_renewal_relay_missed_slots 1"));
        assert!(text.contains("zylith_renewal_relay_failed_slots 1"));
        assert!(text.contains("zylith_renewal_relay_awaiting_wallet_refresh_slots 0"));
        assert!(text.contains("zylith_renewal_relay_retryable_failed_slots 1"));
        assert!(text.contains("zylith_renewal_relay_package_expiring_soon 0"));
        assert!(text.contains("zylith_renewal_relay_warning_alerts 1"));
        assert!(text.contains("zylith_renewal_relay_critical_alerts 1"));
    }

    #[tokio::test]
    async fn strict_metrics_requires_internal_token() {
        let path = temp_sqlite_store_path("strict-metrics");
        let mut state = test_state(path.clone());
        state.config.strict_mode = true;
        state.config.internal_control_token = Some(Arc::new("internal-token".into()));
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.coordinator_control_token = Some(Arc::new("control-token".into()));
        state.config.allowed_origins = vec![HeaderValue::from_static("https://app.zylith.fi")];
        let router = app(state);

        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(AUTHORIZATION, "Bearer internal-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn ops_summary_exposes_alertable_package_state() {
        let mut state = test_state(temp_store_path("ops-summary"));
        state.config.internal_control_token = Some(Arc::new("internal-token".into()));
        state.config.package_expiry_warning_epochs = 10;
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        let submitted_slot = package.slots[0].clone();
        let mut failed_slot = package.slots[0].clone();
        failed_slot.slot_id = "pkg-1:2".into();
        failed_slot.order_commitment = "0xfailed".into();
        failed_slot.epoch_id = 43;
        let mut pending_slot = package.slots[0].clone();
        pending_slot.slot_id = "pkg-1:3".into();
        pending_slot.order_commitment = "0xpending".into();
        pending_slot.epoch_id = 44;
        package.end_epoch = 44;
        package.slot_count = 3;
        package.slots.push(failed_slot.clone());
        package.slots.push(pending_slot);

        {
            let mut store = state.store.write().await;
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package,
                    registered_at_unix_ms: 1,
                    updated_at_unix_ms: 1,
                    results: BTreeMap::from([
                        (
                            "pkg-1:1".into(),
                            StoredSlotResult {
                                result: slot_result(
                                    &submitted_slot,
                                    RelaySlotStatus::Submitted,
                                    None,
                                ),
                                attempts: 1,
                                last_attempt_unix_ms: 1,
                            },
                        ),
                        (
                            failed_slot.slot_id.clone(),
                            StoredSlotResult {
                                result: slot_result(&failed_slot, RelaySlotStatus::Failed, None),
                                attempts: 2,
                                last_attempt_unix_ms: 2,
                            },
                        ),
                    ]),
                },
            );
        }

        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/ops/summary")
                    .header(AUTHORIZATION, "Bearer internal-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let summary: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(summary["package_count"], 1);
        assert_eq!(summary["counts"]["total_slots"], 3);
        assert_eq!(summary["counts"]["submitted_slots"], 1);
        assert_eq!(summary["counts"]["failed_slots"], 1);
        assert_eq!(summary["counts"]["unobserved_slots"], 1);
        assert_eq!(summary["last_observed_epoch"], 43);
        let alert_codes = summary["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|alert| alert["code"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert!(alert_codes.contains("failed_slots"));
        assert!(alert_codes.contains("package_expires_soon"));
    }

    #[tokio::test]
    async fn alert_webhook_dispatches_active_alerts_once_per_repeat_window() {
        let delivery_count = Arc::new(AtomicU64::new(0));
        let app = Router::new().route(
            "/alerts",
            post({
                let delivery_count = delivery_count.clone();
                move |Json(_body): Json<Value>| {
                    let delivery_count = delivery_count.clone();
                    async move {
                        delivery_count.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }
            }),
        );
        let (webhook_url, webhook_shutdown) = spawn_mock(app).await;
        let mut state = test_state(temp_store_path("alert-webhook"));
        state.config.alert_webhook_urls = vec![format!("{webhook_url}/alerts")];
        state.config.alert_repeat_ms = 60_000;
        let package = test_package("http://coordinator".into(), "http://prover".into());
        let failed_slot = package.slots[0].clone();
        {
            let mut store = state.store.write().await;
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package,
                    registered_at_unix_ms: 1,
                    updated_at_unix_ms: 1,
                    results: BTreeMap::from([(
                        failed_slot.slot_id.clone(),
                        StoredSlotResult {
                            result: slot_result(
                                &failed_slot,
                                RelaySlotStatus::Failed,
                                Some("coordinator unavailable".into()),
                            ),
                            attempts: 1,
                            last_attempt_unix_ms: 1,
                        },
                    )]),
                },
            );
        }

        dispatch_ops_alerts(&state).await;
        dispatch_ops_alerts(&state).await;

        assert_eq!(delivery_count.load(Ordering::SeqCst), 1);
        let _ = webhook_shutdown.send(());
    }

    #[tokio::test]
    async fn strict_ops_endpoints_require_internal_token() {
        let path = temp_sqlite_store_path("strict-ops");
        let mut state = test_state(path.clone());
        state.config.strict_mode = true;
        state.config.internal_control_token = Some(Arc::new("internal-token".into()));
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.coordinator_control_token = Some(Arc::new("control-token".into()));
        state.config.allowed_origins = vec![HeaderValue::from_static("https://app.zylith.fi")];
        let router = app(state);

        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/ops/alerts")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/ops/alerts")
                    .header(AUTHORIZATION, "Bearer internal-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn package_results_csv_exports_basic_local_relay_history() {
        let mut state = test_state(temp_store_path("results-csv"));
        state.config.package_registration_token = Some(Arc::new("package-token".into()));
        let package = test_package("http://coordinator".into(), "http://prover".into());
        let result = slot_result(
            &package.slots[0],
            RelaySlotStatus::Failed,
            Some("coordinator rejected, retry later".into()),
        );
        {
            let mut store = state.store.write().await;
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package,
                    registered_at_unix_ms: 1,
                    updated_at_unix_ms: 1,
                    results: BTreeMap::from([(
                        "pkg-1:1".into(),
                        StoredSlotResult {
                            result,
                            attempts: 2,
                            last_attempt_unix_ms: 1,
                        },
                    )]),
                },
            );
        }

        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/packages/pkg-1/results.csv")
                    .header(AUTHORIZATION, "Bearer package-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(text.starts_with("package_id,pair,slot_id,parent_child_index"));
        assert!(text.contains("pkg-1,STRK/USDC,pkg-1:1,1,STRK-USDC-42,42,0x123,failed"));
        assert!(text.contains("\"coordinator rejected, retry later\""));
    }

    #[test]
    fn csv_cell_neutralizes_spreadsheet_formulas() {
        assert_eq!(
            csv_cell("=IMPORTXML(\"https://attacker\")"),
            "\"'=IMPORTXML(\"\"https://attacker\"\")\""
        );
        assert_eq!(csv_cell("+1"), "'+1");
        assert_eq!(csv_cell("@cmd"), "'@cmd");
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
    fn strict_validation_uses_pinned_urls_over_package_policy() {
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
        assert!(validate_package(&package, &state.config).is_ok());

        state.config.default_coordinator_url = Some("http://127.0.0.1:3000".into());
        state.config.default_prover_url = Some("http://127.0.0.1:3200".into());
        assert!(validate_package(&package, &state.config).is_ok());

        state.config.default_coordinator_url = None;
        state.config.default_prover_url = None;
        assert!(validate_package(&package, &state.config).is_err());
        package.relay_policy.coordinator_url = String::new();
        package.relay_policy.prover_url = String::new();
        assert!(validate_package(&package, &state.config).is_err());
        package.relay_policy.coordinator_url = "http://coordinator".into();
        package.relay_policy.prover_url = "http://prover".into();
        refresh_test_package_commitment(&mut package);
        assert!(validate_package(&package, &state.config).is_err());
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
                    .uri("/packages")
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
    async fn package_order_attestation_binds_exact_slot() {
        let path = temp_store_path("attest-order");
        let mut state = test_state(path.clone());
        state.config.package_registration_token = Some(Arc::new("package-token".into()));
        let router = app(state);
        let package = test_package("http://coordinator".into(), "http://prover".into());

        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .header(AUTHORIZATION, "Bearer package-token")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let slot = &package.slots[0];
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages/pkg-1/attest-order")
                    .header("content-type", "application/json")
                    .header(AUTHORIZATION, "Bearer package-token")
                    .body(axum::body::Body::from(
                        serde_json::json!({
                            "package_commitment": package.package_commitment.clone(),
                            "order_commitment": slot.order_commitment.clone(),
                            "pair": slot.pair.clone(),
                            "batch_id": slot.batch_id.clone(),
                            "epoch_id": slot.epoch_id,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
        assert_eq!(json["package_id"], "pkg-1");
        assert_eq!(json["order_commitment"], slot.order_commitment);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages/pkg-1/attest-order")
                    .header("content-type", "application/json")
                    .header(AUTHORIZATION, "Bearer package-token")
                    .body(axum::body::Body::from(
                        serde_json::json!({
                            "package_commitment": package.package_commitment.clone(),
                            "order_commitment": "0xbad",
                            "pair": slot.pair.clone(),
                            "batch_id": slot.batch_id.clone(),
                            "epoch_id": slot.epoch_id,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn strict_register_accepts_signed_package_without_bearer_token() {
        let path = temp_sqlite_store_path("strict-signed-register");
        let mut state = test_state(path.clone());
        state.config.strict_mode = true;
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.coordinator_control_token = Some(Arc::new("control-token".into()));
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        authorize_package(&mut package);

        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn strict_register_rejects_unsigned_package_without_bearer_token() {
        let path = temp_sqlite_store_path("strict-unsigned-register");
        let mut state = test_state(path.clone());
        state.config.strict_mode = true;
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.coordinator_control_token = Some(Arc::new("control-token".into()));
        let package = test_package("http://coordinator".into(), "http://prover".into());

        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn deleted_package_cannot_be_reregistered_after_cancel_tombstone() {
        let path = temp_sqlite_store_path("cancel-tombstone");
        let mut state = test_state(path.clone());
        state.config.package_registration_token = Some(Arc::new("package-token".into()));
        let router = app(state);
        let package = test_package("http://coordinator".into(), "http://prover".into());

        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .header(AUTHORIZATION, "Bearer package-token")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/packages/pkg-1")
                    .header(AUTHORIZATION, "Bearer package-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let loaded = load_store(&path).await.unwrap();
        assert!(loaded.cancelled_packages.contains_key("pkg-1"));

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .header(AUTHORIZATION, "Bearer package-token")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE);
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn register_package_replaces_refreshed_window_for_same_parent() {
        let path = temp_sqlite_store_path("refresh-register");
        let state = test_state(path.clone());
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        package.parent_cancel_authority = Some("0xparent".into());
        refresh_test_package_commitment(&mut package);
        let router = app(state.clone());

        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        package.start_epoch = 43;
        package.end_epoch = 43;
        package.slots[0].slot_id = "pkg-1:2".into();
        package.slots[0].batch_id = "STRK-USDC-43".into();
        package.slots[0].epoch_id = 43;
        package.slots[0].parent_child_index = 2;
        package.slots[0].order_commitment = "0x456".into();
        refresh_test_package_commitment(&mut package);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let loaded = load_sqlite_store(&path).await.unwrap();
        let stored = loaded.packages.get("pkg-1").unwrap();
        assert_eq!(
            stored.package.package_commitment,
            package.package_commitment
        );
        assert_eq!(stored.package.slots[0].slot_id, "pkg-1:2");
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn register_package_rejects_stale_refresh_rollback() {
        let path = temp_sqlite_store_path("refresh-rollback");
        let state = test_state(path.clone());
        let mut original = test_package("http://coordinator".into(), "http://prover".into());
        original.parent_cancel_authority = Some("0xparent".into());
        refresh_test_package_commitment(&mut original);
        let mut refreshed = original.clone();
        refreshed.created_at_unix_ms = original.created_at_unix_ms + 1;
        refreshed.end_epoch = 43;
        refreshed.slot_count = 2;
        let mut second_slot = refreshed.slots[0].clone();
        second_slot.slot_id = "pkg-1:2".into();
        second_slot.batch_id = "STRK-USDC-43".into();
        second_slot.epoch_id = 43;
        second_slot.parent_child_index = 2;
        second_slot.order_commitment = "0x456".into();
        refreshed.slots.push(second_slot);
        refresh_test_package_commitment(&mut refreshed);
        let router = app(state);

        for package in [&original, &refreshed] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/packages")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(serde_json::to_vec(package).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&original).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let loaded = load_sqlite_store(&path).await.unwrap();
        let stored = loaded.packages.get("pkg-1").unwrap();
        assert_eq!(
            stored.package.package_commitment,
            refreshed.package_commitment
        );
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn package_registration_signature_is_not_persisted() {
        let path = temp_sqlite_store_path("strip-package-auth");
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        authorize_package(&mut package);
        let state = test_state(path.clone());

        let response = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let loaded = load_sqlite_store(&path).await.unwrap();
        assert!(
            loaded
                .packages
                .get("pkg-1")
                .unwrap()
                .package
                .relay_authorization
                .is_none()
        );
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn strict_delete_accepts_package_signature_without_bearer_token() {
        let path = temp_sqlite_store_path("strict-signed-delete");
        let mut state = test_state(path.clone());
        state.config.strict_mode = true;
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.coordinator_control_token = Some(Arc::new("control-token".into()));
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        authorize_package(&mut package);
        let auth = package.relay_authorization.as_ref().unwrap().clone();
        let router = app(state.clone());

        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/packages/pkg-1")
                    .header(RELAY_PACKAGE_COMMITMENT_HEADER, &package.package_commitment)
                    .header(
                        RELAY_PARENT_CANCEL_AUTHORITY_HEADER,
                        package.parent_cancel_authority.as_deref().unwrap(),
                    )
                    .header(RELAY_SIGNER_HEADER, &auth.signer_public_key)
                    .header(RELAY_SIGNATURE_R_HEADER, &auth.signature_r)
                    .header(RELAY_SIGNATURE_S_HEADER, &auth.signature_s)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let loaded = load_sqlite_store(&path).await.unwrap();
        assert!(!loaded.packages.contains_key("pkg-1"));
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn package_delete_rejects_stored_authorization_without_request_signature() {
        let path = temp_sqlite_store_path("delete-stored-auth-rejected");
        let mut state = test_state(path.clone());
        state.config.strict_mode = true;
        state.config.default_coordinator_url = Some("http://coordinator".into());
        state.config.default_prover_url = Some("http://prover".into());
        state.config.coordinator_control_token = Some(Arc::new("control-token".into()));
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        authorize_package(&mut package);
        let router = app(state.clone());

        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/packages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&package).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/packages/pkg-1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let loaded = load_sqlite_store(&path).await.unwrap();
        assert!(loaded.packages.contains_key("pkg-1"));
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn cors_preflight_allows_browser_package_delete() {
        let path = temp_sqlite_store_path("cors-delete");
        let state = test_state(path.clone());
        let router = app(state);
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/packages/pkg-1")
                    .header("origin", "https://app.example")
                    .header("access-control-request-method", "DELETE")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let methods = response
            .headers()
            .get("access-control-allow-methods")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(methods.contains("DELETE"));
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn cors_preflight_does_not_allow_disallowed_origin() {
        let path = temp_sqlite_store_path("cors-deny");
        let mut state = test_state(path.clone());
        state.config.allowed_origins = vec![HeaderValue::from_static("https://app.zylith.fi")];
        let router = app(state);
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/packages/pkg-1")
                    .header("origin", "https://evil.example")
                    .header("access-control-request-method", "DELETE")
                    .body(axum::body::Body::empty())
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
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn missing_package_status_and_results_do_not_reveal_existence() {
        let path = temp_sqlite_store_path("missing-oracle");
        let state = test_state(path.clone());
        let router = app(state);
        for uri in ["/packages/missing", "/packages/missing/results"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("GET")
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        cleanup_sqlite_store(&path);
    }

    #[tokio::test]
    async fn process_due_slot_posts_through_prover_and_coordinator() {
        let (coordinator_url, coordinator_shutdown) = spawn_mock_coordinator().await;
        let (prover_url, prover_shutdown) = spawn_mock_prover().await;
        let path = temp_store_path("process");
        let state = test_state(path.clone());
        let mut package = test_package(coordinator_url, prover_url);
        package.relay_mode = Some(RelayMode::SelfRelay);
        refresh_test_package_commitment(&mut package);
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
    async fn submit_slot_uses_configured_endpoint_failover() {
        let (bad_coordinator_url, bad_coordinator_shutdown) = spawn_failing_mock().await;
        let (good_coordinator_url, good_coordinator_shutdown) = spawn_mock_coordinator().await;
        let (bad_prover_url, bad_prover_shutdown) = spawn_failing_mock().await;
        let (good_prover_url, good_prover_shutdown) = spawn_mock_prover().await;
        let path = temp_store_path("submit-failover");
        let mut state = test_state(path.clone());
        state.config.default_coordinator_url = Some(bad_coordinator_url);
        state
            .config
            .default_coordinator_failover_urls
            .push(good_coordinator_url);
        state.config.default_prover_url = Some(bad_prover_url);
        state
            .config
            .default_prover_failover_urls
            .push(good_prover_url);
        let package = test_package(
            "http://ignored-coordinator".into(),
            "http://ignored-prover".into(),
        );

        let accepted = submit_slot(&state, &package, &package.slots[0])
            .await
            .expect("failover submission");

        assert_eq!(accepted.batch_id, "STRK-USDC-42");
        let _ = bad_coordinator_shutdown.send(());
        let _ = good_coordinator_shutdown.send(());
        let _ = bad_prover_shutdown.send(());
        let _ = good_prover_shutdown.send(());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_due_slot_waits_on_reused_funding_while_prior_batch_is_pending() {
        let (coordinator_url, coordinator_shutdown) =
            spawn_mock_coordinator_for_batch("STRK-USDC-43", 43).await;
        let mut statuses = BTreeMap::new();
        statuses.insert(
            "STRK-USDC-42".into(),
            json!({ "state": "proving", "matched_order_count": null }),
        );
        let (prover_url, prover_shutdown) = spawn_mock_prover_with_statuses(statuses).await;
        let path = temp_store_path("reuse-wait");
        let state = test_state(path.clone());
        let mut package = two_slot_test_package(coordinator_url, prover_url, true);
        package.relay_mode = Some(RelayMode::SelfRelay);
        refresh_test_package_commitment(&mut package);
        {
            let mut store = state.store.write().await;
            let now = now_unix_ms();
            let first_result = slot_result(&package.slots[0], RelaySlotStatus::Submitted, None);
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package: package.clone(),
                    registered_at_unix_ms: now,
                    updated_at_unix_ms: now,
                    results: BTreeMap::from([(
                        package.slots[0].slot_id.clone(),
                        StoredSlotResult {
                            result: first_result,
                            attempts: 1,
                            last_attempt_unix_ms: now,
                        },
                    )]),
                },
            );
        }
        let results = process_due_slots_once(&state).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, RelaySlotStatus::AwaitingSettlement);
        assert_eq!(results[0].slot_id, "pkg-1:2");
        let _ = coordinator_shutdown.send(());
        let _ = prover_shutdown.send(());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn runtime_cancel_marker_guard_fails_closed_when_marker_is_missing() {
        let path = temp_store_path("missing-cancel-marker-runtime");
        let state = test_state(path.clone());
        let mut package = test_package("http://coordinator".into(), "http://prover".into());
        package.parent_cancel_marker = None;
        let error = parent_cancel_marker_recorded(&state, &package)
            .await
            .expect_err("missing marker fails closed");
        assert!(error.contains("cancellation marker is missing"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_due_slot_pauses_after_matched_reused_funding_settles() {
        let (coordinator_url, coordinator_shutdown) =
            spawn_mock_coordinator_for_batch("STRK-USDC-43", 43).await;
        let mut statuses = BTreeMap::new();
        statuses.insert(
            "STRK-USDC-42".into(),
            json!({ "state": "confirmed-onchain", "reuse_state": "matched" }),
        );
        let (prover_url, prover_shutdown) = spawn_mock_prover_with_statuses(statuses).await;
        let path = temp_store_path("reuse-refresh");
        let state = test_state(path.clone());
        let mut package = two_slot_test_package(coordinator_url, prover_url, true);
        package.relay_mode = Some(RelayMode::SelfRelay);
        refresh_test_package_commitment(&mut package);
        {
            let mut store = state.store.write().await;
            let now = now_unix_ms();
            let first_result = slot_result(&package.slots[0], RelaySlotStatus::Submitted, None);
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package: package.clone(),
                    registered_at_unix_ms: now,
                    updated_at_unix_ms: now,
                    results: BTreeMap::from([(
                        package.slots[0].slot_id.clone(),
                        StoredSlotResult {
                            result: first_result,
                            attempts: 1,
                            last_attempt_unix_ms: now,
                        },
                    )]),
                },
            );
        }
        let results = process_due_slots_once(&state).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, RelaySlotStatus::AwaitingWalletRefresh);
        let _ = coordinator_shutdown.send(());
        let _ = prover_shutdown.send(());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_due_slot_blocks_reused_funding_after_prior_proof_failure() {
        let (coordinator_url, coordinator_shutdown) =
            spawn_mock_coordinator_for_batch("STRK-USDC-43", 43).await;
        let mut statuses = BTreeMap::new();
        statuses.insert(
            "STRK-USDC-42".into(),
            json!({ "state": "proof-failed", "failure": "temporary prover failure" }),
        );
        let (prover_url, prover_shutdown) = spawn_mock_prover_with_statuses(statuses).await;
        let path = temp_store_path("reuse-proof-failed");
        let state = test_state(path.clone());
        let mut package = two_slot_test_package(coordinator_url, prover_url, true);
        package.relay_mode = Some(RelayMode::SelfRelay);
        refresh_test_package_commitment(&mut package);
        {
            let mut store = state.store.write().await;
            let now = now_unix_ms();
            let first_result = slot_result(&package.slots[0], RelaySlotStatus::Submitted, None);
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package: package.clone(),
                    registered_at_unix_ms: now,
                    updated_at_unix_ms: now,
                    results: BTreeMap::from([(
                        package.slots[0].slot_id.clone(),
                        StoredSlotResult {
                            result: first_result,
                            attempts: 1,
                            last_attempt_unix_ms: now,
                        },
                    )]),
                },
            );
        }
        let results = process_due_slots_once(&state).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, RelaySlotStatus::AwaitingSettlement);
        let _ = coordinator_shutdown.send(());
        let _ = prover_shutdown.send(());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_due_slot_allows_distinct_funding_notes() {
        let (coordinator_url, coordinator_shutdown) =
            spawn_mock_coordinator_for_batch("STRK-USDC-43", 43).await;
        let (prover_url, prover_shutdown) = spawn_mock_prover().await;
        let path = temp_store_path("distinct-funding");
        let state = test_state(path.clone());
        let mut package = two_slot_test_package(coordinator_url, prover_url, false);
        package.relay_mode = Some(RelayMode::SelfRelay);
        refresh_test_package_commitment(&mut package);
        {
            let mut store = state.store.write().await;
            let now = now_unix_ms();
            let first_result = slot_result(&package.slots[0], RelaySlotStatus::Submitted, None);
            store.packages.insert(
                package.package_id.clone(),
                StoredPackage {
                    package: package.clone(),
                    registered_at_unix_ms: now,
                    updated_at_unix_ms: now,
                    results: BTreeMap::from([(
                        package.slots[0].slot_id.clone(),
                        StoredSlotResult {
                            result: first_result,
                            attempts: 1,
                            last_attempt_unix_ms: now,
                        },
                    )]),
                },
            );
        }
        let results = process_due_slots_once(&state).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, RelaySlotStatus::Submitted);
        let _ = coordinator_shutdown.send(());
        let _ = prover_shutdown.send(());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn sqlite_long_window_tick_uses_due_slot_index_after_restart() {
        let start_epoch = 10_000;
        let ninety_day_slots_at_90s_epochs = 90 * 24 * 60 * 60 / 90;
        let (coordinator_url, coordinator_shutdown) =
            spawn_mock_coordinator_for_batch("STRK-USDC-10000", start_epoch).await;
        let (prover_url, prover_shutdown) = spawn_mock_prover().await;
        let path = temp_sqlite_store_path("long-window");
        let mut package = long_window_test_package(
            coordinator_url,
            prover_url,
            start_epoch,
            ninety_day_slots_at_90s_epochs,
        );
        package.relay_mode = Some(RelayMode::SelfRelay);
        refresh_test_package_commitment(&mut package);
        let mut store = RelayStore::default();
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
        persist_sqlite_store(&path, store).await.unwrap();

        let state = test_state(path.clone());
        let loaded = load_sqlite_store(&path).await.unwrap();
        assert_eq!(
            loaded.packages.get("pkg-long").unwrap().package.slot_count,
            86_400
        );
        {
            let mut live_store = state.store.write().await;
            *live_store = loaded;
            live_store
                .packages
                .get_mut("pkg-long")
                .unwrap()
                .package
                .slots
                .clear();
        }

        let results = process_due_slots_once(&state).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, RelaySlotStatus::Submitted);
        assert_eq!(results[0].slot_id, "pkg-long:1");
        assert_eq!(results[0].parent_child_index, 1);

        let loaded = load_sqlite_store(&path).await.unwrap();
        let stored = loaded.packages.get("pkg-long").unwrap();
        assert_eq!(stored.results.len(), 1);
        assert_eq!(
            stored.results.get("pkg-long:1").unwrap().result.status,
            RelaySlotStatus::Submitted
        );
        let due_slots =
            load_sqlite_due_slots_for_package(&state.config, "pkg-long", start_epoch + 10)
                .await
                .unwrap();
        assert_eq!(due_slots.len(), 10);

        let _ = coordinator_shutdown.send(());
        let _ = prover_shutdown.send(());
        cleanup_sqlite_store(&path);
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
        assert_eq!(
            loaded_package.package.package_commitment,
            package.package_commitment
        );
        assert_eq!(
            loaded_package
                .results
                .get(&package.slots[0].slot_id)
                .unwrap()
                .attempts,
            2,
        );
        let indexed_due_slots = load_sqlite_due_slots_for_package(
            &test_state(path.clone()).config,
            &package.package_id,
            package.slots[0].epoch_id,
        )
        .await
        .unwrap();
        assert!(indexed_due_slots.is_empty());

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

    #[tokio::test]
    async fn sqlite_store_upsert_does_not_delete_packages_absent_from_snapshot() {
        let path = temp_sqlite_store_path("sqlite-no-snapshot-delete");
        let mut first = test_package("http://coordinator".into(), "http://prover".into());
        first.package_id = "pkg-a".into();
        first.slots[0].slot_id = "pkg-a:1".into();
        refresh_test_package_commitment(&mut first);
        let mut second = test_package("http://coordinator".into(), "http://prover".into());
        second.package_id = "pkg-b".into();
        second.slots[0].slot_id = "pkg-b:1".into();
        refresh_test_package_commitment(&mut second);

        let now = now_unix_ms();
        let mut first_store = RelayStore::default();
        first_store.packages.insert(
            first.package_id.clone(),
            StoredPackage {
                package: first.clone(),
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
                results: BTreeMap::new(),
            },
        );
        persist_sqlite_store(&path, first_store).await.unwrap();

        let mut second_store = RelayStore::default();
        second_store.packages.insert(
            second.package_id.clone(),
            StoredPackage {
                package: second.clone(),
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
                results: BTreeMap::new(),
            },
        );
        persist_sqlite_store(&path, second_store).await.unwrap();

        let loaded = load_sqlite_store(&path).await.unwrap();
        assert!(loaded.packages.contains_key("pkg-a"));
        assert!(loaded.packages.contains_key("pkg-b"));
        cleanup_sqlite_store(&path);
    }

    async fn spawn_mock_coordinator() -> (String, oneshot::Sender<()>) {
        spawn_mock_coordinator_for_batch("STRK-USDC-42", 42).await
    }

    async fn spawn_mock_coordinator_for_batch(
        batch_id: &'static str,
        epoch_id: u64,
    ) -> (String, oneshot::Sender<()>) {
        let app = Router::new()
            .route(
                "/api/pairs/STRK/USDC/batches/current",
                get(move || async move {
                    Json(json!({
                        "batch_id": batch_id,
                        "pair_id": "STRK/USDC",
                        "epoch_id": epoch_id,
                        "close_time_unix_ms": now_unix_ms() + 60_000,
                        "status": "Open",
                        "order_count_bucket": "0"
                    }))
                }),
            )
            .route(
                "/api/orders",
                post(move |Json(body): Json<Value>| async move {
                    Json(json!({
                        "batch_id": body.get("batch_id").cloned().unwrap_or_else(|| json!(batch_id)),
                        "order_commitment": body.get("order_commitment").cloned().unwrap_or_else(|| json!("0x123")),
                        "accepted_at_unix_ms": now_unix_ms()
                    }))
                }),
            )
            .route(
                "/api/renewal/cancel-markers/{_marker}",
                get(|| async move { Json(json!({ "recorded": false })) }),
            );
        spawn_mock(app).await
    }

    async fn spawn_mock_prover() -> (String, oneshot::Sender<()>) {
        spawn_mock_prover_with_statuses(BTreeMap::new()).await
    }

    async fn spawn_mock_prover_with_statuses(
        statuses: BTreeMap<String, Value>,
    ) -> (String, oneshot::Sender<()>) {
        let statuses = Arc::new(statuses);
        let app = Router::new()
            .route(
                "/api/private/orders",
                post(|Json(body): Json<Value>| async move {
                    Json(json!({
                        "receipt": {
                            "order_commitment": body.get("renewal_slot_order_commitment").cloned().unwrap_or(Value::Null),
                            "pair_id": body.get("renewal_slot_pair").cloned().unwrap_or(Value::Null),
                            "batch_id": body.get("renewal_slot_batch_id").cloned().unwrap_or(Value::Null),
                            "epoch_id": body.get("renewal_slot_epoch_id").cloned().unwrap_or(Value::Null),
                            "payload_commitment": "0xabc",
                            "relay_mode": body.get("renewal_relay_mode").cloned().unwrap_or(Value::Null),
                            "renewal_package_id": body.get("renewal_package_id").cloned().unwrap_or(Value::Null),
                            "renewal_package_commitment": body.get("renewal_package_commitment").cloned().unwrap_or(Value::Null)
                        },
                        "coordinator_submission": {
                            "batch_id": body.get("renewal_slot_batch_id").cloned().unwrap_or(Value::Null),
                            "order_commitment": body.get("renewal_slot_order_commitment").cloned().unwrap_or(Value::Null),
                            "order_bundle": { "opaque": true }
                        }
                    }))
                }),
            )
            .route(
                "/api/public/proof-jobs/{batch_id}",
                get({
                    let statuses = statuses.clone();
                    move |Path(batch_id): Path<String>| {
                        let statuses = statuses.clone();
                        async move {
                            statuses
                                .get(&batch_id)
                                .map(|status| Json(status.clone()).into_response())
                                .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
                        }
                    }
                }),
            );
        spawn_mock(app).await
    }

    async fn spawn_failing_mock() -> (String, oneshot::Sender<()>) {
        spawn_mock(Router::new().fallback(|| async { StatusCode::SERVICE_UNAVAILABLE })).await
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

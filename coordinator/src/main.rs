//! the zylith wallet backup service: encrypted wallet-signature vaults and recovery snapshots.
//!
//! the service stores only ciphertext it cannot read. a vault is the single backup of a wallet's
//! seed, so it is written once; a recovery account keeps only its latest snapshot and is bound
//! to the auth tag of its first upload, stored only as a verifier. records live in sqlite, one row per record, in the
//! `coordinator_records` table earlier releases already use.

mod proof_queue;

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::Connection;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use zylith_core::hash::tagged_sha256_hex;
use zylith_core::{
    RecoveryArtifact, RecoveryArtifactKind, RecoveryArtifactList, RecoveryArtifactUpload,
};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_STORE_PATH: &str = "data/coordinator/recovery.sqlite3";
const RECOVERY_NAMESPACE: &str = "recovery_accounts";
const VAULT_NAMESPACE: &str = "wallet_vault_bundles";
const MAX_RECOVERY_PAYLOAD_CHARS: usize = 1_048_576;
const MAX_VAULT_PAYLOAD_CHARS: usize = 65_536;
const WALLET_VAULT_AUTH_HEADER: &str = "x-zylith-wallet-vault-auth";
const WALLET_VAULT_ID_DOMAIN: &str = "zylith/wallet-signature-vault/id/v2:";
const RECOVERY_AUTH_DOMAIN: &str = "zylith/recovery-auth/verifier/v1:";
const VAULT_FIELDS: &[&str] = &[
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

#[derive(Clone, Default, Serialize, Deserialize)]
struct RecoveryAccountRecord {
    /// a hash of the account's auth tag salted with its account id, so a copy of the store cannot
    /// present the tag.
    #[serde(default)]
    recovery_auth_verifier: Option<String>,
    /// the plaintext tag earlier releases stored; it becomes a verifier when the store loads.
    #[serde(default, skip_serializing)]
    recovery_auth_tag: Option<String>,
    artifacts: Vec<RecoveryArtifact>,
}

fn recovery_verifier(account_id: &str, tag: &str) -> String {
    tagged_sha256_hex(
        RECOVERY_AUTH_DOMAIN,
        format!("{account_id}\n{tag}").as_bytes(),
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletVaultBundleRecord {
    wallet_auth_id: String,
    vault: serde_json::Value,
    updated_at_unix_ms: u64,
}

#[derive(Clone)]
struct AppState {
    store_path: Arc<PathBuf>,
    accounts: Arc<RwLock<BTreeMap<String, RecoveryAccountRecord>>>,
    vaults: Arc<RwLock<BTreeMap<String, WalletVaultBundleRecord>>>,
    write_lock: Arc<Mutex<()>>,
    limiter: Arc<Mutex<HashMap<IpAddr, (u64, u64)>>>,
    rate_limit_per_minute: u64,
    trusted_proxies: Arc<Vec<ipnet::IpNet>>,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as u64
}

fn open_store(path: &FsPath) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    }
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    // replaced snapshots must not linger in free pages.
    connection.pragma_update(None, "secure_delete", "ON")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS coordinator_records (
            namespace TEXT NOT NULL,
            record_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            PRIMARY KEY(namespace, record_key)
        );
        CREATE INDEX IF NOT EXISTS idx_coordinator_records_namespace ON coordinator_records(namespace);",
    )?;
    Ok(connection)
}

fn load_records<T: DeserializeOwned>(
    path: &FsPath,
    namespace: &str,
) -> Result<BTreeMap<String, T>, String> {
    let connection =
        open_store(path).map_err(|error| format!("store {}: {error}", path.display()))?;
    let mut statement = connection
        .prepare("SELECT record_key, value_json FROM coordinator_records WHERE namespace = ?1")
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([namespace], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| error.to_string())?;
    let mut records = BTreeMap::new();
    for row in rows {
        let (key, value) = row.map_err(|error| error.to_string())?;
        records.insert(
            key,
            serde_json::from_str(&value).map_err(|error| format!("{namespace} record: {error}"))?,
        );
    }
    Ok(records)
}

fn upsert_record<T: Serialize>(
    path: &FsPath,
    namespace: &str,
    key: &str,
    value: &T,
) -> Result<(), StatusCode> {
    let connection = open_store(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let value = serde_json::to_string(value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    connection
        .execute(
            "INSERT INTO coordinator_records (namespace, record_key, value_json, updated_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace, record_key) DO UPDATE SET
                 value_json = excluded.value_json,
                 updated_at_unix_ms = excluded.updated_at_unix_ms",
            rusqlite::params![namespace, key, value, now_unix_ms() as i64],
        )
        .map(|_| ())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// the client's address, resolved right-to-left through only configured proxy hops.
fn client_ip(state: &AppState, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = peer.ip();
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    zylith_core::forwarded_client_ip(peer_ip, forwarded, |address| {
        state
            .trusted_proxies
            .iter()
            .any(|network| network.contains(&address))
    })
}

async fn enforce_rate_limit(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    let client = client_ip(state, peer, headers);
    let minute = now_unix_ms() / 60_000;
    let mut limiter = state.limiter.lock().await;
    if limiter.len() > 100_000 {
        limiter.retain(|_, (window, _)| *window == minute);
    }
    let entry = limiter.entry(client).or_insert((minute, 0));
    if entry.0 != minute {
        *entry = (minute, 0);
    }
    entry.1 += 1;
    if entry.1 > state.rate_limit_per_minute {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(())
}

fn recovery_auth(headers: &HeaderMap) -> Result<String, StatusCode> {
    headers
        .get(zylith_core::RECOVERY_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn list_recovery_artifacts(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Result<Json<RecoveryArtifactList>, StatusCode> {
    enforce_rate_limit(&state, peer, &headers).await?;
    let provided = recovery_verifier(&account_id, &recovery_auth(&headers)?);
    let accounts = state.accounts.read().await;
    let account = accounts.get(&account_id).ok_or(StatusCode::UNAUTHORIZED)?;
    match &account.recovery_auth_verifier {
        Some(expected) if zylith_core::constant_time_eq(expected, &provided) => {}
        Some(_) => return Err(StatusCode::UNAUTHORIZED),
        None => return Err(StatusCode::NOT_FOUND),
    }
    // only the latest snapshot is ever served.
    let artifacts = account
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == RecoveryArtifactKind::Snapshot)
        .max_by_key(|artifact| (artifact.sequence, artifact.created_at_unix_ms))
        .cloned()
        .into_iter()
        .collect::<Vec<_>>();
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
        artifacts,
    }))
}

async fn upload_recovery_artifact(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<RecoveryArtifactUpload>,
) -> Result<Json<RecoveryArtifact>, StatusCode> {
    enforce_rate_limit(&state, peer, &headers).await?;
    let artifact = request.artifact;
    if artifact.account_id != account_id || artifact.kind != RecoveryArtifactKind::Snapshot {
        return Err(StatusCode::BAD_REQUEST);
    }
    let payload_chars = serde_json::to_string(&artifact.payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .len();
    if payload_chars > MAX_RECOVERY_PAYLOAD_CHARS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let provided = recovery_verifier(&account_id, &recovery_auth(&headers)?);
    let _guard = state.write_lock.lock().await;
    let mut account = state
        .accounts
        .read()
        .await
        .get(&account_id)
        .cloned()
        .unwrap_or_default();
    match &account.recovery_auth_verifier {
        Some(expected) if !zylith_core::constant_time_eq(expected, &provided) => {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Some(_) => {}
        None => account.recovery_auth_verifier = Some(provided),
    }
    if let Some(existing) = account
        .artifacts
        .iter()
        .find(|existing| existing.artifact_id == artifact.artifact_id)
    {
        return if existing == &artifact {
            Ok(Json(existing.clone()))
        } else {
            Err(StatusCode::CONFLICT)
        };
    }
    let current = account
        .artifacts
        .iter()
        .filter(|existing| existing.kind == RecoveryArtifactKind::Snapshot)
        .max_by_key(|existing| (existing.sequence, existing.created_at_unix_ms));
    if current.map(|existing| existing.artifact_id.as_str())
        != request.previous_artifact_id.as_deref()
        || current.is_some_and(|existing| existing.sequence >= artifact.sequence)
    {
        return Err(StatusCode::CONFLICT);
    }
    // single-snapshot retention: no history of upload times or sizes is kept.
    account.artifacts = vec![artifact.clone()];
    let path = state.store_path.as_ref().clone();
    let (key, record) = (account_id.clone(), account.clone());
    tokio::task::spawn_blocking(move || upsert_record(&path, RECOVERY_NAMESPACE, &key, &record))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;
    state.accounts.write().await.insert(account_id, account);
    Ok(Json(artifact))
}

fn is_wallet_auth_id(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|hex| {
        hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
    })
}

/// the vault id is the hash of a token only the wallet can derive from its signature.
fn require_vault_auth(headers: &HeaderMap, wallet_auth_id: &str) -> Result<(), StatusCode> {
    let token = headers
        .get(WALLET_VAULT_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| {
            value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let expected = format!(
        "0x{}",
        tagged_sha256_hex(WALLET_VAULT_ID_DOMAIN, token.as_bytes())
    );
    if !zylith_core::constant_time_eq(&expected, &wallet_auth_id.to_ascii_lowercase()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn validate_vault(bundle: &WalletVaultBundleRecord) -> Result<(), StatusCode> {
    let vault = bundle.vault.as_object().ok_or(StatusCode::BAD_REQUEST)?;
    if vault
        .keys()
        .any(|field| !VAULT_FIELDS.contains(&field.as_str()))
        || vault.get("version").and_then(|value| value.as_u64()) != Some(2)
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

async fn get_wallet_vault(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(wallet_auth_id): Path<String>,
) -> Result<Json<WalletVaultBundleRecord>, StatusCode> {
    enforce_rate_limit(&state, peer, &headers).await?;
    if !is_wallet_auth_id(&wallet_auth_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    require_vault_auth(&headers, &wallet_auth_id)?;
    state
        .vaults
        .read()
        .await
        .get(&wallet_auth_id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn upload_wallet_vault(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(wallet_auth_id): Path<String>,
    Json(mut request): Json<WalletVaultBundleRecord>,
) -> Result<Json<WalletVaultBundleRecord>, StatusCode> {
    enforce_rate_limit(&state, peer, &headers).await?;
    if !is_wallet_auth_id(&wallet_auth_id) || request.wallet_auth_id != wallet_auth_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    require_vault_auth(&headers, &wallet_auth_id)?;
    if serde_json::to_string(&request)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .len()
        > MAX_VAULT_PAYLOAD_CHARS
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    validate_vault(&request)?;
    if request.updated_at_unix_ms == 0 {
        request.updated_at_unix_ms = now_unix_ms();
    }
    let _guard = state.write_lock.lock().await;
    // write once: a retry of the same vault succeeds, a different vault (another device creating
    // a new wallet) is refused so it restores the existing wallet instead of replacing it.
    if let Some(existing) = state.vaults.read().await.get(&wallet_auth_id) {
        if existing.vault == request.vault {
            return Ok(Json(existing.clone()));
        }
        return Err(StatusCode::CONFLICT);
    }
    let path = state.store_path.as_ref().clone();
    let (key, record) = (wallet_auth_id.clone(), request.clone());
    tokio::task::spawn_blocking(move || upsert_record(&path, VAULT_NAMESPACE, &key, &record))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;
    state
        .vaults
        .write()
        .await
        .insert(wallet_auth_id, request.clone());
    Ok(Json(request))
}

fn app(state: AppState, allowed_origins: Vec<HeaderValue>, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/api/recovery/{account_id}/artifacts",
            get(list_recovery_artifacts).post(upload_recovery_artifact),
        )
        .route(
            "/api/wallet-vaults/{wallet_auth_id}",
            get(get_wallet_vault).post(upload_wallet_vault),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        // encrypted vaults and recovery artifacts are per wallet: no cache may keep them.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        ))
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any)
                .allow_origin(AllowOrigin::list(allowed_origins)),
        )
}

fn build_state(
    store_path: PathBuf,
    rate_limit_per_minute: u64,
    trusted_proxies: Vec<ipnet::IpNet>,
) -> Result<AppState, String> {
    let mut accounts: BTreeMap<String, RecoveryAccountRecord> =
        load_records(&store_path, RECOVERY_NAMESPACE)?;
    for (account_id, account) in &mut accounts {
        if let Some(tag) = account.recovery_auth_tag.take() {
            account.recovery_auth_verifier = Some(recovery_verifier(account_id, &tag));
            upsert_record(&store_path, RECOVERY_NAMESPACE, account_id, account)
                .map_err(|status| format!("migrating recovery account {account_id}: {status}"))?;
        }
    }
    Ok(AppState {
        accounts: Arc::new(RwLock::new(accounts)),
        vaults: Arc::new(RwLock::new(load_records(&store_path, VAULT_NAMESPACE)?)),
        store_path: Arc::new(store_path),
        write_lock: Arc::new(Mutex::new(())),
        limiter: Arc::new(Mutex::new(HashMap::new())),
        rate_limit_per_minute,
        trusted_proxies: Arc::new(trusted_proxies),
    })
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let variable = |name: &str| env::var(name).ok().filter(|value| !value.trim().is_empty());
    let required = |name: &str| variable(name).ok_or_else(|| format!("{name} is required"));
    let number = |name: &str, default: u64| -> Result<u64, String> {
        variable(name)
            .map(|value| value.parse().map_err(|_| format!("{name} is invalid")))
            .transpose()
            .map(|value| value.unwrap_or(default))
    };
    let store_path = PathBuf::from(
        variable("ZYLITH_COORDINATOR_RECOVERY_PATH").unwrap_or_else(|| DEFAULT_STORE_PATH.into()),
    );
    let proof_database_path = PathBuf::from(
        variable("ZYLITH_PROOF_QUEUE_DATABASE_PATH")
            .unwrap_or_else(|| store_path.to_string_lossy().into_owned()),
    );
    let proof_artifact_directory = PathBuf::from(
        variable("ZYLITH_PROOF_ARTIFACT_DIRECTORY")
            .unwrap_or_else(|| "data/coordinator/proof-artifacts".into()),
    );
    let proof_key = hex::decode(required("ZYLITH_PROOF_ARTIFACT_KEY_HEX")?.trim())
        .map_err(|_| "ZYLITH_PROOF_ARTIFACT_KEY_HEX is not hex".to_string())?;
    let proof_key: [u8; 32] = proof_key
        .try_into()
        .map_err(|_| "ZYLITH_PROOF_ARTIFACT_KEY_HEX must be 32 bytes".to_string())?;
    let grant_ttl_ms = number("ZYLITH_PROOF_WORKER_GRANT_TTL_MS", 5 * 60_000)?;
    let session_ttl_ms = number("ZYLITH_PROOF_WORKER_SESSION_TTL_MS", 30 * 60_000)?;
    let worker_max_lifetime_ms = number("ZYLITH_PROOF_WORKER_MAX_LIFETIME_MS", 4 * 60 * 60_000)?;
    let lease_duration_ms = number("ZYLITH_PROOF_JOB_LEASE_MS", 60_000)?;
    let proof_cleanup_interval_ms = number("ZYLITH_PROOF_JOB_CLEANUP_INTERVAL_MS", 60_000)?;
    if proof_cleanup_interval_ms == 0 {
        return Err("ZYLITH_PROOF_JOB_CLEANUP_INTERVAL_MS must be positive".into());
    }
    let proof_queue = proof_queue::ProofQueue::open(proof_queue::ProofQueueConfig {
        database_path: proof_database_path,
        artifact_directory: proof_artifact_directory,
        data_key: proof_key,
        control_token: required("ZYLITH_PROOF_QUEUE_CONTROL_TOKEN")?,
        monitor_token: required("ZYLITH_PROOF_QUEUE_MONITOR_TOKEN")?,
        registration_grant_ttl_ms: grant_ttl_ms,
        session_ttl_ms,
        worker_max_lifetime_ms,
        lease_duration_ms,
        max_request_bytes: number("ZYLITH_PROOF_JOB_MAX_REQUEST_BYTES", 64 * 1024 * 1024)?,
        completed_retention_ms: number("ZYLITH_PROOF_JOB_COMPLETED_RETENTION_MS", 60 * 60_000)?,
        abandoned_retention_ms: number(
            "ZYLITH_PROOF_JOB_ABANDONED_RETENTION_MS",
            7 * 24 * 60 * 60_000,
        )?,
    })?;
    let rate_limit = variable("ZYLITH_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE")
        .map(|value| {
            value
                .parse()
                .map_err(|_| "rate limit is not a number".to_string())
        })
        .transpose()?
        .unwrap_or(120);
    let max_body_bytes = variable("ZYLITH_COORDINATOR_MAX_BODY_BYTES")
        .map(|value| {
            value
                .parse()
                .map_err(|_| "max body is not a number".to_string())
        })
        .transpose()?
        .unwrap_or(2 * 1024 * 1024);
    let trusted_proxies = variable("ZYLITH_TRUSTED_PROXY_CIDRS")
        .unwrap_or_else(|| "127.0.0.1/32,::1/128".into())
        .split(',')
        .map(|cidr| {
            cidr.trim()
                .parse()
                .map_err(|_| format!("invalid proxy cidr {cidr}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let origins = variable("ZYLITH_COORDINATOR_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|origin| HeaderValue::from_str(origin.trim()).ok())
        .collect();
    let bind: SocketAddr = variable("ZYLITH_COORDINATOR_BIND_ADDR")
        .unwrap_or_else(|| DEFAULT_BIND_ADDR.into())
        .parse()
        .map_err(|error| format!("bind address: {error}"))?;
    let state = build_state(store_path, rate_limit, trusted_proxies)?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind: {error}"))?;
    eprintln!("zylith persistent control plane listening on http://{bind}");
    let retention_queue = proof_queue.clone();
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_millis(proof_cleanup_interval_ms));
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = retention_queue.prune().await {
                eprintln!("proof retention cleanup failed: {error}");
            }
        }
    });
    axum::serve(
        listener,
        app(state, origins, max_body_bytes)
            .merge(proof_queue::router(proof_queue))
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("server: {error}"))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    /// a fresh store per test: tests run in parallel, so the path takes a counter.
    fn temporary_store() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "zylith-coordinator-{}-{}-{}.sqlite3",
            std::process::id(),
            now_unix_ms(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn vault_request(wallet_auth_id: &str, ciphertext: &str) -> serde_json::Value {
        serde_json::json!({
            "wallet_auth_id": wallet_auth_id,
            "updated_at_unix_ms": 1,
            "vault": {
                "version": 2, "kdf": "wallet-signature-sha256-v2", "algorithm": "AES-GCM",
                "wallet_address": "0x1", "chain_id": "SN_SEPOLIA", "deployment_id": "d", "origin": "o",
                "message_version": 2, "nonce": "n", "ciphertext": ciphertext,
            },
        })
    }

    async fn post_vault(state: &AppState, token: &str, body: serde_json::Value) -> StatusCode {
        let wallet_auth_id = body["wallet_auth_id"].as_str().unwrap().to_owned();
        let mut request = Request::post(format!("/api/wallet-vaults/{wallet_auth_id}"))
            .header("content-type", "application/json")
            .header(WALLET_VAULT_AUTH_HEADER, token)
            .body(Body::from(body.to_string()))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 1))));
        let response = app(state.clone(), vec![], 1 << 20)
            .oneshot(request)
            .await
            .unwrap();
        // every answer, refusals included, is kept out of caches.
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        response.status()
    }

    #[tokio::test]
    async fn a_vault_is_written_once_and_survives_a_restart() {
        let path = temporary_store();
        let state = build_state(path.clone(), 100, vec![]).unwrap();
        let token = "ab".repeat(32);
        let wallet_auth_id = format!(
            "0x{}",
            tagged_sha256_hex(WALLET_VAULT_ID_DOMAIN, token.as_bytes())
        );
        assert_eq!(
            post_vault(&state, &token, vault_request(&wallet_auth_id, "c1")).await,
            StatusCode::OK
        );
        assert_eq!(
            post_vault(&state, &token, vault_request(&wallet_auth_id, "c1")).await,
            StatusCode::OK
        );
        assert_eq!(
            post_vault(&state, &token, vault_request(&wallet_auth_id, "c2")).await,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post_vault(
                &state,
                &"cd".repeat(32),
                vault_request(&wallet_auth_id, "c1")
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        let reloaded = build_state(path.clone(), 100, vec![]).unwrap();
        assert_eq!(
            reloaded.vaults.read().await[&wallet_auth_id].vault["ciphertext"],
            "c1"
        );
        let _ = std::fs::remove_file(path);
    }

    async fn list_recovery(state: &AppState, account_id: &str, tag: &str) -> StatusCode {
        let mut request = Request::get(format!("/api/recovery/{account_id}/artifacts"))
            .header(zylith_core::RECOVERY_AUTH_HEADER, tag)
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 1))));
        app(state.clone(), vec![], 1 << 20)
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    async fn post_recovery(
        state: &AppState,
        account_id: &str,
        tag: &str,
        artifact_id: &str,
        sequence: u64,
        previous_artifact_id: Option<&str>,
    ) -> StatusCode {
        let body = serde_json::json!({
            "artifact": {
                "artifact_id": artifact_id,
                "account_id": account_id,
                "kind": "Snapshot",
                "sequence": sequence,
                "created_at_unix_ms": sequence,
                "payload": { "algorithm": "AES-GCM", "nonce": "n", "ciphertext": "c" },
            },
            "previous_artifact_id": previous_artifact_id,
        });
        let mut request = Request::post(format!("/api/recovery/{account_id}/artifacts"))
            .header("content-type", "application/json")
            .header(zylith_core::RECOVERY_AUTH_HEADER, tag)
            .body(Body::from(body.to_string()))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 1))));
        app(state.clone(), vec![], 1 << 20)
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn recovery_snapshot_updates_compare_and_swap_the_remote_head() {
        let path = temporary_store();
        let state = build_state(path.clone(), 100, vec![]).unwrap();
        assert_eq!(
            post_recovery(&state, "account", "secret", "0xa1", 1, None).await,
            StatusCode::OK
        );
        assert_eq!(
            post_recovery(&state, "account", "secret", "0xa2", 2, None).await,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post_recovery(&state, "account", "secret", "0xa2", 2, Some("0xa1")).await,
            StatusCode::OK
        );
        assert_eq!(
            post_recovery(&state, "account", "secret", "0xa2", 2, Some("0xa1")).await,
            StatusCode::OK
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn the_store_keeps_only_a_verifier_of_the_recovery_tag() {
        let path = temporary_store();
        // a record written by an earlier release, with the tag in plaintext.
        upsert_record(
            &path,
            RECOVERY_NAMESPACE,
            "account",
            &serde_json::json!({ "recovery_auth_tag": "secret-tag", "artifacts": [] }),
        )
        .unwrap();
        let state = build_state(path.clone(), 100, vec![]).unwrap();
        let stored = load_records::<serde_json::Value>(&path, RECOVERY_NAMESPACE).unwrap();
        assert!(!stored["account"].to_string().contains("secret-tag"));
        assert_eq!(
            stored["account"]["recovery_auth_verifier"],
            recovery_verifier("account", "secret-tag")
        );
        assert_eq!(
            list_recovery(&state, "account", "secret-tag").await,
            StatusCode::OK
        );
        assert_eq!(
            list_recovery(&state, "account", "other-tag").await,
            StatusCode::UNAUTHORIZED
        );
        // the verifier is bound to its account.
        assert_ne!(
            recovery_verifier("account", "secret-tag"),
            recovery_verifier("another", "secret-tag")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_trusted_proxy_forwards_the_client_address() {
        let state =
            build_state(temporary_store(), 1, vec!["127.0.0.1/32".parse().unwrap()]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 198.51.100.7"),
        );
        assert_eq!(
            client_ip(&state, SocketAddr::from(([127, 0, 0, 1], 5)), &headers),
            IpAddr::from([198, 51, 100, 7])
        );
        assert_eq!(
            client_ip(&state, SocketAddr::from(([10, 0, 0, 2], 5)), &headers),
            IpAddr::from([10, 0, 0, 2])
        );
    }
}

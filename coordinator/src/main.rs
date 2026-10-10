//! the zylith wallet backup service: encrypted wallet-signature vaults and recovery snapshots.
//!
//! the service stores only ciphertext it cannot read. a vault is the single backup of a wallet's
//! seed, so it is written once; a recovery account keeps only its latest snapshot and is keyed by
//! a verifier derived from the wallet's secret auth tag. records live in sqlite, one row per
//! record, in the `coordinator_records` table earlier releases already use.

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
use base64::{Engine, engine::general_purpose::STANDARD};
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
const PROOF_MONITOR_HEADER: &str = "x-zylith-proof-monitor-token";
const WALLET_VAULT_ID_DOMAIN: &str = "zylith/wallet-signature-vault/id/v3:";
const RECOVERY_AUTH_DOMAIN: &str = "zylith/recovery-auth/verifier/v1:";
const VAULT_FIELDS: &[&str] = &[
    "version",
    "key_schedule_version",
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

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryAccountRecord {
    /// a hash of the account's auth tag salted with its account id. this is also the opaque storage
    /// key, so knowledge of the public account id alone cannot claim the wallet's namespace.
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
    #[serde(deserialize_with = "zylith_core::deserialize_unique_wallet_json")]
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
    internal_monitor_token: Arc<String>,
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
            key.clone(),
            serde_json::from_str(&value)
                .map_err(|error| format!("{namespace} record {key}: {error}"))?,
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

fn replace_namespace_records<T: Serialize>(
    path: &FsPath,
    namespace: &str,
    records: &BTreeMap<String, T>,
) -> Result<(), String> {
    let mut connection =
        open_store(path).map_err(|error| format!("store {}: {error}", path.display()))?;
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "DELETE FROM coordinator_records WHERE namespace = ?1",
            [namespace],
        )
        .map_err(|error| error.to_string())?;
    for (key, value) in records {
        let value = serde_json::to_string(value).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO coordinator_records
                 (namespace, record_key, value_json, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![namespace, key, value, now_unix_ms() as i64],
            )
            .map_err(|error| error.to_string())?;
    }
    transaction.commit().map_err(|error| error.to_string())
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
    let account = accounts.get(&provided).ok_or(StatusCode::UNAUTHORIZED)?;
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
        .get(&provided)
        .cloned()
        .unwrap_or_default();
    match &account.recovery_auth_verifier {
        Some(expected) if !zylith_core::constant_time_eq(expected, &provided) => {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Some(_) => {}
        None => account.recovery_auth_verifier = Some(provided.clone()),
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
    let (key, record) = (provided.clone(), account.clone());
    tokio::task::spawn_blocking(move || upsert_record(&path, RECOVERY_NAMESPACE, &key, &record))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;
    state.accounts.write().await.insert(provided, account);
    Ok(Json(artifact))
}

fn is_wallet_auth_id(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// the vault id is the hash of a token only the wallet can derive from its signature.
fn require_vault_auth(headers: &HeaderMap, wallet_auth_id: &str) -> Result<(), StatusCode> {
    let token = headers
        .get(WALLET_VAULT_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let expected = format!(
        "0x{}",
        tagged_sha256_hex(WALLET_VAULT_ID_DOMAIN, token.as_bytes())
    );
    if !zylith_core::constant_time_eq(&expected, wallet_auth_id) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn validate_vault(bundle: &WalletVaultBundleRecord) -> Result<(), StatusCode> {
    let vault = bundle.vault.as_object().ok_or(StatusCode::BAD_REQUEST)?;
    if vault.len() != VAULT_FIELDS.len()
        || vault
            .keys()
            .any(|field| !VAULT_FIELDS.contains(&field.as_str()))
        || vault.get("version").and_then(|value| value.as_u64()) != Some(3)
        || vault
            .get("key_schedule_version")
            .and_then(|value| value.as_u64())
            != Some(2)
        || vault.get("kdf").and_then(|value| value.as_str()) != Some("HKDF-SHA-256")
        || vault.get("algorithm").and_then(|value| value.as_str()) != Some("AES-256-GCM")
        || vault
            .get("message_version")
            .and_then(|value| value.as_u64())
            != Some(2)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let text = |field: &str| {
        vault
            .get(field)
            .and_then(|value| value.as_str())
            .ok_or(StatusCode::BAD_REQUEST)
    };
    for field in ["wallet_address", "chain_id", "deployment_id"] {
        let value = text(field)?;
        if value.len() > 66
            || !starknet_crypto::Felt::from_hex(value).is_ok_and(|felt| {
                felt != starknet_crypto::Felt::ZERO && zylith_core::hash::felt_hex(&felt) == value
            })
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let origin = text("origin")?;
    let url = url::Url::parse(origin).map_err(|_| StatusCode::BAD_REQUEST)?;
    let local = url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if origin.len() > 256
        || origin != url.origin().ascii_serialization().to_ascii_lowercase()
        || (url.scheme() != "https" && !local)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    for (field, expected) in [("nonce", 12_usize), ("ciphertext", 80)] {
        let value = text(field)?;
        if value.len() != expected.div_ceil(3) * 4 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let decoded = STANDARD
            .decode(value)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        if decoded.len() != expected || STANDARD.encode(decoded) != value {
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
        .route("/internal/migration-inventory", get(migration_inventory))
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

async fn migration_inventory(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let provided = headers
        .get(PROOF_MONITOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if state.internal_monitor_token.is_empty()
        || !zylith_core::constant_time_eq(provided, &state.internal_monitor_token)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let accounts = state.accounts.read().await;
    let vaults = state.vaults.read().await;
    let recovery_artifacts = accounts
        .iter()
        .flat_map(|(_, account)| {
            account.artifacts.iter().map(move |artifact| {
                serde_json::json!({
                    "account_id": artifact.account_id,
                    "artifact_id": artifact.artifact_id,
                    "key_schedule_version": artifact.key_schedule_version,
                    "sequence": artifact.sequence,
                })
            })
        })
        .collect::<Vec<_>>();
    let account_ids = recovery_artifacts
        .iter()
        .filter_map(|artifact| artifact["account_id"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    Ok(Json(serde_json::json!({
        "schema_version": 1,
        "recovery_accounts": {
            "count": account_ids.len(),
            "account_ids": account_ids,
        },
        "recovery_artifacts": {
            "count": recovery_artifacts.len(),
            "records": recovery_artifacts,
        },
        "wallet_vaults": {
            "count": vaults.len(),
            "wallet_auth_ids": vaults.keys().collect::<Vec<_>>(),
            "versions": vaults.values().map(|record| record.vault["version"].as_u64().unwrap_or(0)).collect::<Vec<_>>(),
        },
    })))
}

fn build_state(
    store_path: PathBuf,
    rate_limit_per_minute: u64,
    trusted_proxies: Vec<ipnet::IpNet>,
) -> Result<AppState, String> {
    let loaded_accounts: BTreeMap<String, RecoveryAccountRecord> =
        load_records(&store_path, RECOVERY_NAMESPACE)?;
    let vaults: BTreeMap<String, WalletVaultBundleRecord> =
        load_records(&store_path, VAULT_NAMESPACE)?;
    for (key, record) in &vaults {
        if !is_wallet_auth_id(key)
            || record.wallet_auth_id != *key
            || validate_vault(record).is_err()
        {
            return Err(format!(
                "{VAULT_NAMESPACE} record {key}: wallet migration required"
            ));
        }
    }
    let mut accounts = BTreeMap::new();
    let mut recovery_records_changed = false;
    for (stored_key, mut account) in loaded_accounts {
        if let Some(tag) = account.recovery_auth_tag.take() {
            let account_id = account
                .artifacts
                .first()
                .map(|artifact| artifact.account_id.as_str())
                .unwrap_or(stored_key.as_str());
            if account
                .artifacts
                .iter()
                .any(|artifact| artifact.account_id != account_id)
            {
                return Err(format!(
                    "{RECOVERY_NAMESPACE} record {stored_key}: mixed account ids"
                ));
            }
            account.recovery_auth_verifier = Some(recovery_verifier(account_id, &tag));
            recovery_records_changed = true;
        }
        let verifier = account.recovery_auth_verifier.clone().ok_or_else(|| {
            format!("{RECOVERY_NAMESPACE} record {stored_key}: missing authentication verifier")
        })?;
        if stored_key != verifier {
            recovery_records_changed = true;
        }
        if let Some(existing) = accounts.insert(verifier.clone(), account.clone())
            && existing != account
        {
            return Err(format!(
                "{RECOVERY_NAMESPACE} record {stored_key}: authentication verifier collision"
            ));
        }
    }
    if recovery_records_changed {
        replace_namespace_records(&store_path, RECOVERY_NAMESPACE, &accounts)
            .map_err(|error| format!("migrating recovery accounts: {error}"))?;
    }
    Ok(AppState {
        accounts: Arc::new(RwLock::new(accounts)),
        vaults: Arc::new(RwLock::new(vaults)),
        store_path: Arc::new(store_path),
        write_lock: Arc::new(Mutex::new(())),
        limiter: Arc::new(Mutex::new(HashMap::new())),
        rate_limit_per_minute,
        trusted_proxies: Arc::new(trusted_proxies),
        internal_monitor_token: Arc::new(String::new()),
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
    let proof_job_max_attempts = u32::try_from(number("ZYLITH_PROOF_JOB_MAX_ATTEMPTS", 3)?)
        .map_err(|_| "ZYLITH_PROOF_JOB_MAX_ATTEMPTS exceeds u32".to_string())?;
    let proof_cleanup_interval_ms = number("ZYLITH_PROOF_JOB_CLEANUP_INTERVAL_MS", 60_000)?;
    if proof_cleanup_interval_ms == 0 {
        return Err("ZYLITH_PROOF_JOB_CLEANUP_INTERVAL_MS must be positive".into());
    }
    let proof_monitor_token = required("ZYLITH_PROOF_QUEUE_MONITOR_TOKEN")?;
    let proof_queue = proof_queue::ProofQueue::open(proof_queue::ProofQueueConfig {
        database_path: proof_database_path,
        artifact_directory: proof_artifact_directory,
        data_key: proof_key,
        control_token: required("ZYLITH_PROOF_QUEUE_CONTROL_TOKEN")?,
        monitor_token: proof_monitor_token.clone(),
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
        max_attempts: proof_job_max_attempts,
        retry_backoff_ms: number("ZYLITH_PROOF_JOB_RETRY_BACKOFF_MS", 5_000)?,
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
    let mut state = build_state(store_path, rate_limit, trusted_proxies)?;
    state.internal_monitor_token = Arc::new(proof_monitor_token);
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

    fn vault_v2_request(wallet_auth_id: &str, ciphertext: &str) -> serde_json::Value {
        serde_json::json!({
            "wallet_auth_id": wallet_auth_id,
            "updated_at_unix_ms": 1,
            "vault": {
                "version": 2, "key_schedule_version": 2, "kdf": "wallet-signature-sha256-v2", "algorithm": "AES-GCM",
                "wallet_address": "0x1", "chain_id": "SN_SEPOLIA", "deployment_id": "d", "origin": "o",
                "message_version": 2, "nonce": "n", "ciphertext": ciphertext,
            },
        })
    }

    fn vault_v3_request(wallet_auth_id: &str) -> serde_json::Value {
        serde_json::json!({
            "wallet_auth_id": wallet_auth_id,
            "updated_at_unix_ms": 1,
            "vault": {
                "version": 3, "key_schedule_version": 2, "kdf": "HKDF-SHA-256", "algorithm": "AES-256-GCM",
                "wallet_address": "0xabc", "chain_id": "0x534e5f5345504f4c4941", "deployment_id": "0x123", "origin": "https://app.zylith.fi",
                "message_version": 2, "nonce": "AAECAwQFBgcICQoL",
                "ciphertext": "LsHn4kqB/KDZThd5hEoSCRZFb8ffMajvhZgWtIL3/EZ1ayK8FEw7mWy0wFxaJucgA2NWiHAs5imy9YQAYfb+jD58XkG2twdfmeoA6Ve45Tg=",
            },
        })
    }

    fn vault_request(wallet_auth_id: &str, ciphertext: &str) -> serde_json::Value {
        let mut record = vault_v3_request(wallet_auth_id);
        let marker = ciphertext.bytes().fold(0_u8, u8::wrapping_add);
        record["vault"]["ciphertext"] = serde_json::json!(STANDARD.encode([marker; 80]));
        record
    }

    #[tokio::test]
    async fn vault_v3_auth_matches_the_independent_client_vector() {
        let state = build_state(temporary_store(), 100, vec![]).unwrap();
        let token = "0f6af4e0101267ab33fcd61065bfe2c951d189e8741e1b73c5df0c3709e69f6e";
        let id = "0x8b8ff2601b68bbf0f3566b5c28d1487eb864e0d70416b60f7bb683dda95d5639";
        assert_eq!(
            post_vault(&state, token, vault_v3_request(id)).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn migration_inventory_requires_the_monitor_credential_and_exposes_no_payloads() {
        let mut state = build_state(temporary_store(), 100, vec![]).unwrap();
        state.internal_monitor_token = Arc::new("monitor".into());
        let app = app(state, vec![], 1 << 20);
        let unauthorized = app
            .clone()
            .oneshot(
                Request::get("/internal/migration-inventory")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(
                Request::get("/internal/migration-inventory")
                    .header(PROOF_MONITOR_HEADER, "monitor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let inventory: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(inventory["schema_version"], 1);
        assert_eq!(inventory["recovery_artifacts"]["count"], 0);
        assert!(
            !String::from_utf8(body.to_vec())
                .unwrap()
                .contains("ciphertext")
        );
    }

    fn malformed_v3_vaults(key: &str) -> Vec<serde_json::Value> {
        let valid = vault_v3_request(key);
        let mut invalid = Vec::new();
        for field in VAULT_FIELDS {
            let mut row = valid.clone();
            row["vault"].as_object_mut().unwrap().remove(*field);
            invalid.push(row);
        }
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("version", serde_json::json!(4)),
            ("version", serde_json::json!(3.0)),
            ("kdf", serde_json::json!("wallet-signature-sha256-v2")),
            ("algorithm", serde_json::json!("AES-GCM")),
            ("message_version", serde_json::json!(1)),
            ("message_version", serde_json::json!(2.0)),
            ("wallet_address", serde_json::json!("0x0")),
            ("wallet_address", serde_json::json!("0x0abc")),
            ("chain_id", serde_json::json!("SN_SEPOLIA")),
            (
                "deployment_id",
                serde_json::json!(
                    "0x800000000000011000000000000000000000000000000000000000000000001"
                ),
            ),
            ("origin", serde_json::json!("https://APP.ZYLITH.FI")),
            ("origin", serde_json::json!("https://app.zylith.fi/")),
            ("origin", serde_json::json!("https://app.zylith.fi?x")),
            ("origin", serde_json::json!("https://user@app.zylith.fi")),
            ("origin", serde_json::json!("http://app.zylith.fi")),
            ("origin", serde_json::json!("zylith://local")),
            ("nonce", serde_json::json!("AA==")),
            ("nonce", serde_json::json!(" AAECAwQFBgcICQoL")),
            ("ciphertext", serde_json::json!("AA==")),
            ("ciphertext", serde_json::json!("A".repeat(108))),
            (
                "ciphertext",
                serde_json::json!(
                    "LsHn4kqB/KDZThd5hEoSCRZFb8ffMajvhZgWtIL3/EZ1ayK8FEw7mWy0wFxaJucgA2NWiHAs5imy9YQAYfb+jD58XkG2twdfmeoA6Ve45Th="
                ),
            ),
            ("extra", serde_json::json!(1)),
        ] {
            let mut row = valid.clone();
            row["vault"][field] = value;
            invalid.push(row);
        }
        invalid
    }

    #[tokio::test]
    async fn vault_v3_malformed_requests_never_persist() {
        let state = build_state(temporary_store(), 100, vec![]).unwrap();
        let token = "0f6af4e0101267ab33fcd61065bfe2c951d189e8741e1b73c5df0c3709e69f6e";
        let id = "0x8b8ff2601b68bbf0f3566b5c28d1487eb864e0d70416b60f7bb683dda95d5639";
        for row in malformed_v3_vaults(id) {
            assert_eq!(
                post_vault(&state, token, row).await,
                StatusCode::BAD_REQUEST
            );
        }
        assert!(state.vaults.read().await.is_empty());
        assert!(
            load_records::<serde_json::Value>(&state.store_path, VAULT_NAMESPACE)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn vault_v3_malformed_rows_stop_startup_before_other_rows_are_mutated() {
        let key = "0x".to_owned() + &"a".repeat(64);
        for row in malformed_v3_vaults(&key) {
            let path = temporary_store();
            let recovery =
                serde_json::json!({ "recovery_auth_tag": "secret-tag", "artifacts": [] });
            upsert_record(&path, RECOVERY_NAMESPACE, "account", &recovery).unwrap();
            upsert_record(&path, VAULT_NAMESPACE, &key, &row).unwrap();
            assert!(build_state(path.clone(), 100, vec![]).is_err());
            assert_eq!(
                load_records::<serde_json::Value>(&path, VAULT_NAMESPACE).unwrap()[&key],
                row
            );
            assert_eq!(
                load_records::<serde_json::Value>(&path, RECOVERY_NAMESPACE).unwrap()["account"],
                recovery
            );
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn vault_v3_local_origins_and_canonical_header_authentication() {
        let token = "0f6af4e0101267ab33fcd61065bfe2c951d189e8741e1b73c5df0c3709e69f6e";
        let id = "0x8b8ff2601b68bbf0f3566b5c28d1487eb864e0d70416b60f7bb683dda95d5639";
        for origin in [
            "http://localhost",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://[::1]:5173",
        ] {
            let mut record = vault_v3_request(id);
            record["vault"]["origin"] = serde_json::json!(origin);
            assert!(validate_vault(&serde_json::from_value(record).unwrap()).is_ok());
        }
        for invalid in [
            token.to_uppercase(),
            format!(" {token}"),
            format!("{token} "),
            "ab".repeat(32),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                WALLET_VAULT_AUTH_HEADER,
                HeaderValue::from_str(&invalid).unwrap(),
            );
            assert_eq!(
                require_vault_auth(&headers, id),
                Err(StatusCode::UNAUTHORIZED)
            );
        }
    }

    #[test]
    fn vault_v3_startup_refuses_v2_before_any_other_row_mutation() {
        let key = "0x".to_owned() + &"a".repeat(64);
        let path = temporary_store();
        let original = vault_v2_request(&key, "c");
        let recovery = serde_json::json!({ "recovery_auth_tag": "secret-tag", "artifacts": [] });
        upsert_record(&path, RECOVERY_NAMESPACE, "account", &recovery).unwrap();
        upsert_record(&path, VAULT_NAMESPACE, &key, &original).unwrap();
        assert!(build_state(path.clone(), 100, vec![]).is_err());
        assert_eq!(
            load_records::<serde_json::Value>(&path, VAULT_NAMESPACE).unwrap()[&key],
            original
        );
        assert_eq!(
            load_records::<serde_json::Value>(&path, RECOVERY_NAMESPACE).unwrap()["account"],
            recovery
        );
        let _ = std::fs::remove_file(path);
    }

    async fn post_vault(state: &AppState, token: &str, body: serde_json::Value) -> StatusCode {
        let wallet_auth_id = body["wallet_auth_id"].as_str().unwrap().to_owned();
        post_vault_raw(state, token, &wallet_auth_id, body.to_string()).await
    }

    async fn post_vault_raw(
        state: &AppState,
        token: &str,
        wallet_auth_id: &str,
        body: String,
    ) -> StatusCode {
        let mut request = Request::post(format!("/api/wallet-vaults/{wallet_auth_id}"))
            .header("content-type", "application/json")
            .header(WALLET_VAULT_AUTH_HEADER, token)
            .body(Body::from(body))
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
    async fn a_vault_refuses_duplicate_versions_before_persisting() {
        let state = build_state(temporary_store(), 100, vec![]).unwrap();
        let token = "ab".repeat(32);
        let id = format!(
            "0x{}",
            tagged_sha256_hex(WALLET_VAULT_ID_DOMAIN, token.as_bytes())
        );
        let body = vault_request(&id, "c").to_string().replace(
            "\"key_schedule_version\":2",
            "\"key_schedule_version\":1,\"key_schedule_\\u0076ersion\":2",
        );
        assert_eq!(
            post_vault_raw(&state, &token, &id, body).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(state.vaults.read().await.is_empty());
    }

    #[tokio::test]
    async fn a_vault_refuses_missing_or_wrong_wallet_key_schedule_versions() {
        let state = build_state(temporary_store(), 100, vec![]).unwrap();
        let token = "ab".repeat(32);
        let id = format!(
            "0x{}",
            tagged_sha256_hex(WALLET_VAULT_ID_DOMAIN, token.as_bytes())
        );
        for version in [
            serde_json::Value::Null,
            serde_json::json!(1),
            serde_json::json!(3),
            serde_json::json!("2"),
            serde_json::json!(2.5),
        ] {
            let mut body = vault_request(&id, "c");
            body["vault"]["key_schedule_version"] = version;
            assert_eq!(
                post_vault(&state, &token, body).await,
                StatusCode::BAD_REQUEST
            );
        }
        let mut missing = vault_request(&id, "c");
        missing["vault"]
            .as_object_mut()
            .unwrap()
            .remove("key_schedule_version");
        assert_eq!(
            post_vault(&state, &token, missing).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_vault(&state, &token, vault_request(&id, "c")).await,
            StatusCode::OK
        );
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
            vault_request(&wallet_auth_id, "c1")["vault"]["ciphertext"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn startup_refuses_incompatible_stored_vaults_without_rewriting_them() {
        let key = "0x".to_owned() + &"a".repeat(64);
        let original = vault_request(&key, "ciphertext");
        let mut invalid = Vec::new();
        let mut missing = original.clone();
        missing["vault"]
            .as_object_mut()
            .unwrap()
            .remove("key_schedule_version");
        invalid.push(missing);
        for version in [
            serde_json::json!(1),
            serde_json::json!(3),
            serde_json::json!("2"),
            serde_json::json!(2.5),
            serde_json::Value::Null,
        ] {
            let mut row = original.clone();
            row["vault"]["key_schedule_version"] = version;
            invalid.push(row);
        }
        let mut alias = original.clone();
        alias["vault"]["keyScheduleVersion"] = serde_json::json!(1);
        invalid.push(alias);
        let mut mismatched_key = original.clone();
        mismatched_key["wallet_auth_id"] = serde_json::json!("0xdead");
        invalid.push(mismatched_key);

        for row in invalid {
            let path = temporary_store();
            upsert_record(&path, VAULT_NAMESPACE, &key, &row).unwrap();
            let error = build_state(path.clone(), 100, vec![])
                .err()
                .expect("startup must fail");
            assert!(error.contains(VAULT_NAMESPACE), "{error}");
            assert!(error.contains(&key), "{error}");
            assert!(error.contains("migration"), "{error}");
            let stored = load_records::<serde_json::Value>(&path, VAULT_NAMESPACE).unwrap();
            assert_eq!(stored[&key], row);
            let _ = std::fs::remove_file(path);
        }

        let path = temporary_store();
        upsert_record(&path, VAULT_NAMESPACE, &key, &original).unwrap();
        let state = build_state(path.clone(), 100, vec![]).expect("v3 vault must load");
        assert_eq!(state.vaults.blocking_read()[&key].vault, original["vault"]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn startup_refuses_escaped_duplicate_vault_keys_without_rewriting_the_row() {
        let key = "0x".to_owned() + &"a".repeat(64);
        let path = temporary_store();
        let raw = vault_request(&key, "ciphertext").to_string().replace(
            "\"key_schedule_version\":2",
            "\"key_schedule_version\":1,\"key_schedule_\\u0076ersion\":2",
        );
        let connection = open_store(&path).unwrap();
        connection.execute(
            "INSERT INTO coordinator_records (namespace, record_key, value_json, updated_at_unix_ms) VALUES (?1, ?2, ?3, 1)",
            rusqlite::params![VAULT_NAMESPACE, key, raw],
        ).unwrap();
        let error = build_state(path.clone(), 100, vec![])
            .err()
            .expect("startup must fail");
        assert!(error.contains(VAULT_NAMESPACE), "{error}");
        assert!(error.contains(&key), "{error}");
        assert!(error.contains("migration"), "{error}");
        let stored: String = connection.query_row(
            "SELECT value_json FROM coordinator_records WHERE namespace = ?1 AND record_key = ?2",
            rusqlite::params![VAULT_NAMESPACE, key],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(stored, raw);
        drop(connection);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn startup_rejects_a_legacy_vault_before_rewriting_other_rows() {
        let key = "0x".to_owned() + &"a".repeat(64);
        let path = temporary_store();
        let recovery = serde_json::json!({ "recovery_auth_tag": "secret-tag", "artifacts": [] });
        let mut vault = vault_request(&key, "ciphertext");
        vault["vault"]
            .as_object_mut()
            .unwrap()
            .remove("key_schedule_version");
        upsert_record(&path, RECOVERY_NAMESPACE, "account", &recovery).unwrap();
        upsert_record(&path, VAULT_NAMESPACE, &key, &vault).unwrap();

        assert!(build_state(path.clone(), 100, vec![]).is_err());
        let stored_recovery = load_records::<serde_json::Value>(&path, RECOVERY_NAMESPACE).unwrap();
        let stored_vault = load_records::<serde_json::Value>(&path, VAULT_NAMESPACE).unwrap();
        assert_eq!(stored_recovery["account"], recovery);
        assert_eq!(stored_vault[&key], vault);
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
                "key_schedule_version": 2,
                "artifact_id": artifact_id,
                "account_id": account_id,
                "kind": "Snapshot",
                "sequence": sequence,
                "created_at_unix_ms": sequence,
                "payload": { "key_schedule_version": 2, "algorithm": "AES-GCM", "nonce": "n", "ciphertext": "c" },
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
    async fn an_arbitrary_first_tag_cannot_claim_another_wallets_recovery_namespace() {
        let path = temporary_store();
        let state = build_state(path.clone(), 100, vec![]).unwrap();
        assert_eq!(
            post_recovery(&state, "known-account", "attacker-tag", "0xbad", 1, None).await,
            StatusCode::OK
        );
        assert_eq!(
            post_recovery(&state, "known-account", "wallet-tag", "0xgood", 1, None).await,
            StatusCode::OK
        );
        assert_eq!(
            list_recovery(&state, "known-account", "wallet-tag").await,
            StatusCode::OK
        );
        assert_eq!(
            list_recovery(&state, "known-account", "unknown-tag").await,
            StatusCode::UNAUTHORIZED
        );
        let accounts = state.accounts.read().await;
        assert_eq!(accounts.len(), 2);
        assert!(accounts.contains_key(&recovery_verifier("known-account", "wallet-tag")));
        assert!(accounts.contains_key(&recovery_verifier("known-account", "attacker-tag")));
        drop(accounts);
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
        let verifier = recovery_verifier("account", "secret-tag");
        assert!(!stored.contains_key("account"));
        assert!(!stored[&verifier].to_string().contains("secret-tag"));
        assert_eq!(stored[&verifier]["recovery_auth_verifier"], verifier);
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

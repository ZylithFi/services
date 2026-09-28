//! zylith's public chain index.
//!
//! it serves two things every wallet reads identically, so a request reveals nothing about its
//! owner: the commitment registry's deposit activations, which wallets match against their
//! pending deposits, and every transition's output records, decoded from the calldata the
//! exchange verified. the output records are the data-availability fallback: with them a wallet
//! recovers its fills, refunds and fees from the chain alone when the operator is unreachable.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header::AUTHORIZATION};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipnet::IpNet;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starknet_crypto::Felt;
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use zylith_core::exchange::{
    OutputRecord, multicall_arguments, output_tree_root, transition_output_records,
};
use zylith_core::{
    CONTROL_PLANE_TOKEN_ENV, DeploymentManifest, DepositActivationRecord,
    DepositActivationRecordList, DepositConfirmationList, constant_time_eq, count_bucket_label,
    extract_bearer_token,
};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3300";
const DEFAULT_DATA_PATH: &str = "indexer/zylith-index.sqlite";
const DEFAULT_SYNC_INTERVAL_MS: u64 = 3_000;
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;
const MAX_DEPOSIT_RANGE: u64 = 10_000;
const MAX_TRANSITION_RANGE: u32 = 256;
const RECENT_DEPOSIT_WINDOW: usize = 512;
const EVENT_PAGE: u64 = 512;
/// how far a detected reorganization rewinds: blocks of transitions and recent deposits.
const REORG_REWIND_BLOCKS: u64 = 64;
const REORG_REWIND_DEPOSITS: u64 = 256;
const MAX_RPC_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;

/// one settled transition's public outputs, as the chain holds them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionOutputs {
    pub seq: u32,
    pub block_number: u64,
    pub transaction_hash: String,
    pub new_book_root: String,
    pub note_root: String,
    pub output_root: String,
    pub outputs: Vec<OutputRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransitionOutputsList {
    pub start: u32,
    pub end: u32,
    pub latest_seq: u32,
    pub transitions: Vec<TransitionOutputs>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexerStatus {
    pub service: String,
    pub ready: bool,
    pub deposits_bucket: String,
    pub latest_seq: u32,
    pub last_successful_sync_unix_ms: u64,
    pub sync_lag_ms: u64,
}

struct Config {
    rpc_url: String,
    commitment_registry: Felt,
    exchange: Felt,
    sync_from_block: u64,
    data_path: PathBuf,
    control_token: String,
    allowed_origins: Vec<HeaderValue>,
    trusted_proxies: Vec<IpNet>,
    rate_limit_per_minute: u32,
    /// how deep a block must be before the index folds it in.
    confirmation_blocks: u64,
}

#[derive(Default)]
struct Index {
    deposits: BTreeMap<u64, DepositActivationRecord>,
    transitions: BTreeMap<u32, TransitionOutputs>,
    next_block: u64,
    /// the hash of block `next_block - 1` when it was scanned; zero before the first scan.
    cursor_hash: Felt,
    last_sync_ms: u64,
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    http: reqwest::Client,
    index: Arc<RwLock<Index>>,
    /// serializes syncs, and owns the store they write.
    store: Arc<Mutex<Store>>,
    limiter: Arc<std::sync::Mutex<HashMap<IpAddr, (u64, u32)>>>,
}

type ApiResult<T> = Result<Json<T>, StatusCode>;

#[tokio::main]
async fn main() -> Result<(), String> {
    let config = Config::from_env()?;
    let bind = env::var("ZYLITH_INDEXER_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.into());
    let interval = Duration::from_millis(
        parsed_env("ZYLITH_INDEXER_SYNC_INTERVAL_MS", DEFAULT_SYNC_INTERVAL_MS)?.max(500),
    );
    let state = AppState::open(config)?;
    if let Err(error) = state.sync().await {
        eprintln!("indexer startup sync skipped: {error}");
    }
    let background = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(error) = background.sync().await {
                eprintln!("indexer sync skipped: {error}");
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|error| format!("bind {bind}: {error}"))?;
    println!("zylith indexer listening on http://{bind}");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("indexer service failed: {error}"))
}

fn router(state: AppState) -> Router {
    let origins = state.config.allowed_origins.clone();
    Router::new()
        .route("/health", get(health))
        .route("/api/internal/sync", post(sync_now))
        .route("/api/deposits/range/{start}/{end}", get(deposits_range))
        .route("/api/deposits/recent", get(recent_deposits))
        .route(
            "/api/transitions/range/{start}/{end}",
            get(transitions_range),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any)
                .allow_origin(AllowOrigin::list(origins)),
        )
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let manifest = load_manifest()?;
        let setting = |name: &str, manifest_value: Option<&str>| -> Option<String> {
            env::var(name)
                .ok()
                .or_else(|| manifest_value.map(str::to_owned))
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let address = |name: &str, manifest_value: Option<&str>| -> Result<Felt, String> {
            setting(name, manifest_value)
                .and_then(|value| Felt::from_hex(&value).ok())
                .filter(|felt| *felt != Felt::ZERO)
                .ok_or_else(|| format!("{name} (or the manifest) must name a nonzero address"))
        };
        let contracts = manifest.as_ref().map(|manifest| &manifest.contracts);
        let control_token = env::var(CONTROL_PLANE_TOKEN_ENV)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if control_token.is_empty() {
            return Err(format!("{CONTROL_PLANE_TOKEN_ENV} is required"));
        }
        let allowed_origins = env::var("ZYLITH_INDEXER_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(|origin| {
                if origin.contains('*') {
                    return Err("ZYLITH_INDEXER_ALLOWED_ORIGINS takes exact origins".to_string());
                }
                HeaderValue::from_str(origin).map_err(|_| format!("invalid origin {origin}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if allowed_origins.is_empty() {
            return Err("ZYLITH_INDEXER_ALLOWED_ORIGINS is required".into());
        }
        let trusted_proxies = env::var("ZYLITH_TRUSTED_PROXY_CIDRS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|cidr| !cidr.is_empty())
            .map(|cidr| {
                cidr.parse::<IpNet>()
                    .map_err(|_| format!("invalid trusted proxy cidr {cidr}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            rpc_url: setting(
                "ZYLITH_STARKNET_RPC_URL",
                manifest.as_ref().map(|manifest| manifest.rpc_url.as_str()),
            )
            .ok_or("ZYLITH_STARKNET_RPC_URL (or the manifest's rpc_url) is required")?,
            commitment_registry: address(
                "ZYLITH_COMMITMENT_REGISTRY_ADDRESS",
                contracts.map(|contracts| contracts.commitment_registry.as_str()),
            )?,
            exchange: address(
                "ZYLITH_EXCHANGE_ADDRESS",
                contracts.map(|contracts| contracts.exchange.as_str()),
            )?,
            sync_from_block: parsed_env("ZYLITH_SYNC_FROM_BLOCK", 0)?,
            data_path: env::var("ZYLITH_INDEXER_DATA_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| DEFAULT_DATA_PATH.into()),
            control_token,
            allowed_origins,
            trusted_proxies,
            rate_limit_per_minute: parsed_env(
                "ZYLITH_INDEXER_PUBLIC_RATE_LIMIT_PER_MINUTE",
                DEFAULT_RATE_LIMIT_PER_MINUTE,
            )?,
            confirmation_blocks: parsed_env("ZYLITH_CONFIRMATION_BLOCKS", 2)?,
        })
    }
}

fn parsed_env<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match env::var(name) {
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|_| format!("{name} is not a valid number")),
        Err(_) => Ok(default),
    }
}

fn load_manifest() -> Result<Option<DeploymentManifest>, String> {
    let Ok(path) = env::var("ZYLITH_DEPLOYMENT_MANIFEST") else {
        return Ok(None);
    };
    let metadata = std::fs::metadata(&path).map_err(|error| format!("manifest {path}: {error}"))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(format!("manifest {path} is too large"));
    }
    let contents =
        std::fs::read_to_string(&path).map_err(|error| format!("manifest {path}: {error}"))?;
    let value = serde_json::from_str::<Value>(&contents)
        .map_err(|error| format!("manifest {path}: {error}"))?;
    serde_json::from_value(value.get("manifest").cloned().unwrap_or(value))
        .map(Some)
        .map_err(|error| format!("manifest {path}: {error}"))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn hex(felt: Felt) -> String {
    format!("{felt:#x}")
}

fn selector(name: &str) -> Felt {
    starknet_crypto::Felt::from_bytes_be(
        &starknet_rust_core::utils::get_selector_from_name(name)
            .expect("entrypoint name")
            .to_bytes_be(),
    )
}

fn felt_u64(felt: &Felt) -> Result<u64, String> {
    u64::try_from(*felt).map_err(|_| "a count does not fit in 64 bits".to_string())
}

/// what a reorganization removes: deposits from this activation id and transitions from this block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rewind {
    deposits_from: u64,
    block: u64,
}

/// the indexed state on disk: deposits, transitions and the event cursor, one row each.
struct Store {
    connection: Connection,
}

impl Store {
    fn open(path: &FsPath) -> Result<Self, String> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("data dir {}: {error}", parent.display()))?;
        }
        let connection =
            Connection::open(path).map_err(|error| format!("store {}: {error}", path.display()))?;
        connection
            .execute_batch(
                "pragma journal_mode=wal;
                 pragma synchronous=full;
                 create table if not exists deposits (id integer primary key, body text not null);
                 create table if not exists transitions (seq integer primary key, block integer not null, body text not null);
                 create table if not exists cursor (id integer primary key check (id = 0), next_block integer not null, block_hash text not null);",
            )
            .map_err(|error| format!("store schema: {error}"))?;
        Ok(Self { connection })
    }

    fn load(&self, sync_from_block: u64) -> Result<Index, String> {
        let fail = |error: rusqlite::Error| format!("store read: {error}");
        let mut index = Index {
            next_block: sync_from_block,
            ..Index::default()
        };
        let mut statement = self
            .connection
            .prepare("select body from deposits order by id")
            .map_err(fail)?;
        for body in statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(fail)?
        {
            let record: DepositActivationRecord = serde_json::from_str(&body.map_err(fail)?)
                .map_err(|error| format!("store deposit: {error}"))?;
            index.deposits.insert(record.activation_id, record);
        }
        let mut statement = self
            .connection
            .prepare("select body from transitions order by seq")
            .map_err(fail)?;
        for body in statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(fail)?
        {
            let transition: TransitionOutputs = serde_json::from_str(&body.map_err(fail)?)
                .map_err(|error| format!("store transition: {error}"))?;
            index.transitions.insert(transition.seq, transition);
        }
        if let Some((next_block, block_hash)) = self
            .connection
            .query_row(
                "select next_block, block_hash from cursor where id = 0",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .map(Some)
            .or_else(|error| {
                if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(fail(error))
                }
            })?
        {
            index.next_block = index.next_block.max(next_block as u64);
            index.cursor_hash = Felt::from_hex(&block_hash).map_err(|_| "store cursor hash")?;
        }
        Ok(index)
    }

    fn commit(
        &mut self,
        deposits: &[DepositActivationRecord],
        transitions: &[TransitionOutputs],
        cursor: (u64, Felt),
        rewind: Option<Rewind>,
    ) -> Result<(), String> {
        let fail = |error: rusqlite::Error| format!("store write: {error}");
        let batch = self.connection.transaction().map_err(fail)?;
        if let Some(rewind) = rewind {
            batch
                .execute(
                    "delete from deposits where id >= ?1",
                    params![rewind.deposits_from as i64],
                )
                .map_err(fail)?;
            batch
                .execute(
                    "delete from transitions where block >= ?1",
                    params![rewind.block as i64],
                )
                .map_err(fail)?;
        }
        for record in deposits {
            let body = serde_json::to_string(record).expect("deposit serializes");
            batch
                .execute(
                    "insert or replace into deposits (id, body) values (?1, ?2)",
                    params![record.activation_id as i64, body],
                )
                .map_err(fail)?;
        }
        for transition in transitions {
            let body = serde_json::to_string(transition).expect("transition serializes");
            batch
                .execute(
                    "insert or replace into transitions (seq, block, body) values (?1, ?2, ?3)",
                    params![transition.seq, transition.block_number as i64, body],
                )
                .map_err(fail)?;
        }
        batch
            .execute(
                "insert into cursor (id, next_block, block_hash) values (0, ?1, ?2) on conflict(id) do update set next_block = excluded.next_block, block_hash = excluded.block_hash",
                params![cursor.0 as i64, hex(cursor.1)],
            )
            .map_err(fail)?;
        batch.commit().map_err(fail)
    }
}

impl AppState {
    fn open(config: Config) -> Result<Self, String> {
        let store = Store::open(&config.data_path)?;
        let index = store.load(config.sync_from_block)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| format!("http client: {error}"))?;
        Ok(Self {
            config: Arc::new(config),
            http,
            index: Arc::new(RwLock::new(index)),
            store: Arc::new(Mutex::new(store)),
            limiter: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let mut response = self
            .http
            .post(&self.config.rpc_url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .map_err(|error| format!("{method}: {}", error.without_url()))?;
        if !response.status().is_success() {
            return Err(format!("{method}: http {}", response.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("{method}: {}", error.without_url()))?
        {
            if body.len() + chunk.len() > MAX_RPC_RESPONSE_BYTES {
                return Err(format!("{method}: the response is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let mut reply: Value =
            serde_json::from_slice(&body).map_err(|error| format!("{method}: {error}"))?;
        if let Some(error) = reply.get("error") {
            return Err(format!("{method}: {error}"));
        }
        reply
            .get_mut("result")
            .map(Value::take)
            .ok_or_else(|| format!("{method}: no result"))
    }

    async fn call(
        &self,
        contract: Felt,
        entrypoint: &str,
        calldata: &[Felt],
        block: u64,
    ) -> Result<Vec<Felt>, String> {
        let request = json!({
            "contract_address": hex(contract),
            "entry_point_selector": hex(selector(entrypoint)),
            "calldata": calldata.iter().copied().map(hex).collect::<Vec<_>>(),
        });
        felts(
            &self
                .rpc("starknet_call", json!([request, { "block_number": block }]))
                .await?,
        )
    }

    async fn block_hash(&self, number: u64) -> Result<Felt, String> {
        let block = self
            .rpc(
                "starknet_getBlockWithTxHashes",
                json!([{ "block_number": number }]),
            )
            .await?;
        block
            .get("block_hash")
            .and_then(Value::as_str)
            .and_then(|hash| Felt::from_hex(hash).ok())
            .ok_or_else(|| format!("block {number} has no hash"))
    }

    /// brings deposits and transitions up to the block `confirmations` below the tip, then
    /// publishes both at once. a scanned block whose hash changed means the chain reorganized:
    /// the recent transitions and deposits are dropped and rescanned.
    async fn sync(&self) -> Result<(), String> {
        let mut store = self.store.lock().await;
        let (mut known_deposits, mut next_block, cursor_hash, mut latest_seq) = {
            let index = self.index.read().await;
            (
                index.deposits.len() as u64,
                index.next_block,
                index.cursor_hash,
                index.transitions.keys().next_back().copied(),
            )
        };
        let mut rewind = None;
        if cursor_hash != Felt::ZERO && self.block_hash(next_block - 1).await? != cursor_hash {
            let target = Rewind {
                deposits_from: known_deposits.saturating_sub(REORG_REWIND_DEPOSITS),
                block: (next_block - 1).saturating_sub(REORG_REWIND_BLOCKS),
            };
            eprintln!(
                "block {} was reorganized; rescanning from block {}",
                next_block - 1,
                target.block
            );
            known_deposits = target.deposits_from;
            next_block = next_block.min(target.block);
            latest_seq = self
                .index
                .read()
                .await
                .transitions
                .values()
                .filter(|transition| transition.block_number < target.block)
                .map(|transition| transition.seq)
                .max();
            rewind = Some(target);
        }
        let tip = self
            .rpc("starknet_blockNumber", json!([]))
            .await?
            .as_u64()
            .ok_or("starknet_blockNumber: not a number")?;
        let Some(confirmed) = tip.checked_sub(self.config.confirmation_blocks) else {
            return Ok(());
        };

        let registry = self.config.commitment_registry;
        let remote_deposits = felt_u64(
            self.call(registry, "funding_activation_count", &[], confirmed)
                .await?
                .first()
                .ok_or("funding_activation_count: empty")?,
        )?;
        // the registry only appends, so a shorter log means a redeployment: start over.
        if remote_deposits < known_deposits {
            known_deposits = 0;
            rewind = Some(Rewind {
                deposits_from: 0,
                block: rewind.map_or(next_block, |rewind: Rewind| rewind.block),
            });
        }
        let mut deposits = Vec::new();
        for activation_id in known_deposits..remote_deposits {
            let fields = self
                .call(
                    registry,
                    "funding_activation_record",
                    &[Felt::from(activation_id)],
                    confirmed,
                )
                .await?;
            let [
                id,
                funding_commitment,
                deposit_root,
                encrypted_note_activation,
            ] = fields[..]
            else {
                return Err("funding_activation_record: unexpected layout".into());
            };
            if felt_u64(&id)? != activation_id {
                return Err("funding_activation_record: the record is out of order".into());
            }
            deposits.push(DepositActivationRecord {
                activation_id,
                funding_commitment: hex(funding_commitment),
                deposit_root: hex(deposit_root),
                encrypted_note_activation: hex(encrypted_note_activation),
            });
        }

        let mut transitions = Vec::new();
        if next_block <= confirmed {
            for (block_number, transaction_hash, seq, fields) in
                self.transition_events(next_block, confirmed).await?
            {
                let transaction = self
                    .rpc(
                        "starknet_getTransactionByHash",
                        json!([hex(transaction_hash)]),
                    )
                    .await?;
                let calldata = felts(
                    transaction
                        .get("calldata")
                        .ok_or("the transition transaction has no calldata")?,
                )?;
                let transition = transition_outputs(
                    self.config.exchange,
                    seq,
                    block_number,
                    transaction_hash,
                    fields,
                    &calldata,
                )?;
                let expected = transitions
                    .last()
                    .map(|previous: &TransitionOutputs| previous.seq)
                    .or(latest_seq)
                    .map_or(1, |seq| seq + 1);
                if transition.seq != expected {
                    return Err(format!(
                        "transition {} arrived while {expected} was expected",
                        transition.seq
                    ));
                }
                transitions.push(transition);
            }
        }

        let cursor = if next_block <= confirmed {
            (confirmed + 1, self.block_hash(confirmed).await?)
        } else {
            (next_block, cursor_hash)
        };
        store.commit(&deposits, &transitions, cursor, rewind)?;
        let mut index = self.index.write().await;
        if let Some(rewind) = rewind {
            index.deposits.retain(|id, _| *id < rewind.deposits_from);
            index
                .transitions
                .retain(|_, transition| transition.block_number < rewind.block);
        }
        index.deposits.extend(
            deposits
                .into_iter()
                .map(|record| (record.activation_id, record)),
        );
        index.transitions.extend(
            transitions
                .into_iter()
                .map(|transition| (transition.seq, transition)),
        );
        (index.next_block, index.cursor_hash) = cursor;
        index.last_sync_ms = now_ms();
        Ok(())
    }

    /// every transition-settled event in the block range: (block, transaction, seq, fields).
    async fn transition_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<(u64, Felt, u32, [Felt; 4])>, String> {
        let key = hex(selector("TransitionSettled"));
        let mut events = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut filter = json!({
                "from_block": { "block_number": from_block },
                "to_block": { "block_number": to_block },
                "address": hex(self.config.exchange),
                "keys": [[key]],
                "chunk_size": EVENT_PAGE,
            });
            if let Some(token) = &continuation {
                filter["continuation_token"] = json!(token);
            }
            let page = self.rpc("starknet_getEvents", json!([filter])).await?;
            for event in page
                .get("events")
                .and_then(Value::as_array)
                .ok_or("starknet_getEvents: no events")?
            {
                let field = |name: &str| {
                    event
                        .get(name)
                        .ok_or_else(|| format!("an event has no {name}"))
                };
                let keys = felts(field("keys")?)?;
                let data = felts(field("data")?)?;
                let seq = u32::try_from(felt_u64(
                    keys.get(1).ok_or("a transition event has no seq")?,
                )?)
                .map_err(|_| "a transition seq is too large")?;
                let fields: [Felt; 4] = data
                    .try_into()
                    .map_err(|_| "a transition event has an unexpected layout")?;
                let block_number = field("block_number")?
                    .as_u64()
                    .ok_or("an event has no block number")?;
                let transaction_hash = Felt::from_hex(
                    field("transaction_hash")?
                        .as_str()
                        .ok_or("an event has no transaction")?,
                )
                .map_err(|_| "bad transaction hash")?;
                events.push((block_number, transaction_hash, seq, fields));
            }
            continuation = page
                .get("continuation_token")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if continuation.is_none() {
                return Ok(events);
            }
        }
    }

    fn allow(&self, peer: SocketAddr, headers: &HeaderMap) -> Result<(), StatusCode> {
        let peer_ip = peer.ip();
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .map(str::trim);
        let client = zylith_core::forwarded_client_ip(peer_ip, forwarded, |address| {
            self.config
                .trusted_proxies
                .iter()
                .any(|network| network.contains(&address))
        });
        let minute = now_ms() / 60_000;
        let mut limiter = self
            .limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if limiter.len() > 100_000 {
            limiter.retain(|_, (window, _)| *window == minute);
        }
        let entry = limiter.entry(client).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 += 1;
        if entry.1 > self.config.rate_limit_per_minute {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        Ok(())
    }

    async fn status(&self) -> IndexerStatus {
        let index = self.index.read().await;
        IndexerStatus {
            service: "zylith-indexer".into(),
            ready: index.last_sync_ms != 0,
            deposits_bucket: count_bucket_label(index.deposits.len() as u64),
            latest_seq: index.transitions.keys().next_back().copied().unwrap_or(0),
            last_successful_sync_unix_ms: index.last_sync_ms,
            sync_lag_ms: if index.last_sync_ms == 0 {
                u64::MAX
            } else {
                now_ms().saturating_sub(index.last_sync_ms)
            },
        }
    }
}

fn felts(value: &Value) -> Result<Vec<Felt>, String> {
    value
        .as_array()
        .ok_or("expected a felt array")?
        .iter()
        .map(|felt| {
            felt.as_str()
                .and_then(|felt| Felt::from_hex(felt).ok())
                .ok_or_else(|| "expected a hex felt".to_string())
        })
        .collect()
}

/// a transition's output records from its transaction's calldata, checked against the root and
/// count the exchange emitted after verifying them.
fn transition_outputs(
    exchange: Felt,
    seq: u32,
    block_number: u64,
    transaction_hash: Felt,
    fields: [Felt; 4],
    calldata: &[Felt],
) -> Result<TransitionOutputs, String> {
    let [new_book_root, output_root, note_root, output_count] = fields;
    let arguments = multicall_arguments(calldata, exchange, selector("submit_transition"))
        .map_err(|error| format!("transition {seq}: {error}"))?;
    let outputs = transition_output_records(&arguments)
        .map_err(|error| format!("transition {seq}: {error}"))?;
    let leaves = outputs.iter().map(|record| record.leaf).collect::<Vec<_>>();
    if Felt::from(outputs.len() as u64) != output_count || output_tree_root(&leaves) != output_root
    {
        return Err(format!(
            "transition {seq}'s calldata does not match its settled outputs"
        ));
    }
    Ok(TransitionOutputs {
        seq,
        block_number,
        transaction_hash: hex(transaction_hash),
        new_book_root: hex(new_book_root),
        note_root: hex(note_root),
        output_root: hex(output_root),
        outputs,
    })
}

async fn health(State(state): State<AppState>) -> (StatusCode, Json<IndexerStatus>) {
    let status = state.status().await;
    let code = if status.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(status))
}

async fn sync_now(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<IndexerStatus> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(extract_bearer_token)
        .unwrap_or("");
    if !constant_time_eq(token, &state.config.control_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    state.sync().await.map_err(|error| {
        eprintln!("indexer sync failed: {error}");
        StatusCode::BAD_GATEWAY
    })?;
    Ok(Json(state.status().await))
}

async fn deposits_range(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((start, end)): Path<(u64, u64)>,
) -> ApiResult<DepositActivationRecordList> {
    state.allow(peer, &headers)?;
    if start > end || end - start >= MAX_DEPOSIT_RANGE {
        return Err(StatusCode::BAD_REQUEST);
    }
    let index = state.index.read().await;
    let records = index
        .deposits
        .range(start..=end)
        .map(|(_, record)| record.clone())
        .collect::<Vec<_>>();
    Ok(Json(DepositActivationRecordList {
        start,
        end,
        count_bucket: count_bucket_label(records.len() as u64),
        records,
    }))
}

async fn recent_deposits(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<DepositConfirmationList> {
    state.allow(peer, &headers)?;
    let recent_funding_commitments = state
        .index
        .read()
        .await
        .deposits
        .values()
        .rev()
        .take(RECENT_DEPOSIT_WINDOW)
        .map(|record| record.funding_commitment.clone())
        .collect();
    let status = state.status().await;
    Ok(Json(DepositConfirmationList {
        recent_funding_commitments,
        last_successful_sync_unix_ms: status.last_successful_sync_unix_ms,
        sync_lag_ms: status.sync_lag_ms,
    }))
}

async fn transitions_range(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((start, end)): Path<(u32, u32)>,
) -> ApiResult<TransitionOutputsList> {
    state.allow(peer, &headers)?;
    if start > end || end - start >= MAX_TRANSITION_RANGE {
        return Err(StatusCode::BAD_REQUEST);
    }
    let index = state.index.read().await;
    Ok(Json(TransitionOutputsList {
        start,
        end,
        latest_seq: index.transitions.keys().next_back().copied().unwrap_or(0),
        transitions: index
            .transitions
            .range(start..=end)
            .map(|(_, transition)| transition.clone())
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::util::ServiceExt;
    use zylith_core::exchange::fixtures::{attestations, crossed};
    use zylith_core::exchange::{sign_price_batch, transition_calldata};

    use super::*;

    const EXCHANGE: u64 = 0xe;

    fn state(path: PathBuf, rate_limit_per_minute: u32) -> AppState {
        AppState::open(Config {
            rpc_url: "http://127.0.0.1:9".into(),
            commitment_registry: Felt::from(0xc_u8),
            exchange: Felt::from(EXCHANGE),
            sync_from_block: 7,
            data_path: path,
            control_token: "token".into(),
            allowed_origins: vec![HeaderValue::from_static("https://app.zylith.test")],
            trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
            rate_limit_per_minute,
            confirmation_blocks: 2,
        })
        .unwrap()
    }

    fn temporary(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "zylith-indexer-{name}-{}.sqlite",
            std::process::id()
        ))
    }

    /// the settlement account's multicall: an unrelated call, then the transition.
    fn settled() -> (TransitionOutputs, Vec<Felt>, [Felt; 4]) {
        let result = crossed();
        let mut prices = attestations(&result.public);
        sign_price_batch(result.public.chain_context, &mut prices, &Felt::ONE).unwrap();
        let arguments = transition_calldata(&result.public, &prices).unwrap();
        let mut calldata = vec![
            Felt::TWO,
            Felt::from(0xabc_u16),
            Felt::ONE,
            Felt::ONE,
            Felt::from(9_u8),
        ];
        calldata.extend([
            Felt::from(EXCHANGE),
            selector("submit_transition"),
            Felt::from(arguments.len() as u64),
        ]);
        calldata.extend(arguments);
        let fields = [
            Felt::from(0xb00c_u16),
            result.public.output_root,
            result.public.note_root,
            Felt::from(result.public.output_records.len() as u64),
        ];
        let transition = transition_outputs(
            Felt::from(EXCHANGE),
            1,
            10,
            Felt::from(0x7a_u8),
            fields,
            &calldata,
        )
        .unwrap();
        assert_eq!(transition.outputs, result.public.output_records);
        (transition, calldata, fields)
    }

    #[test]
    fn output_records_decode_from_the_settlement_calldata() {
        let (_, calldata, fields) = settled();
        let mut forged = fields;
        forged[1] += Felt::ONE;
        assert!(
            transition_outputs(Felt::from(EXCHANGE), 1, 10, Felt::ONE, forged, &calldata).is_err()
        );
        let mut short = fields;
        short[3] -= Felt::ONE;
        assert!(
            transition_outputs(Felt::from(EXCHANGE), 1, 10, Felt::ONE, short, &calldata).is_err()
        );
        assert!(
            transition_outputs(Felt::from(0xf_u8), 1, 10, Felt::ONE, fields, &calldata).is_err()
        );
    }

    #[test]
    fn the_store_restores_what_it_committed() {
        let path = temporary("store");
        let _ = std::fs::remove_file(&path);
        let (transition, _, _) = settled();
        let deposit = DepositActivationRecord {
            activation_id: 0,
            funding_commitment: "0x1".into(),
            deposit_root: "0x2".into(),
            encrypted_note_activation: "0x3".into(),
        };
        Store::open(&path)
            .unwrap()
            .commit(
                std::slice::from_ref(&deposit),
                std::slice::from_ref(&transition),
                (42, Felt::from(0xb10c_u16)),
                None,
            )
            .unwrap();
        let index = Store::open(&path).unwrap().load(7).unwrap();
        assert_eq!(index.deposits.get(&0), Some(&deposit));
        assert_eq!(index.transitions.get(&1), Some(&transition));
        assert_eq!(
            (index.next_block, index.cursor_hash),
            (42, Felt::from(0xb10c_u16))
        );
        // a reorganization drops the deposits and the transitions it reaches.
        let mut store = Store::open(&path).unwrap();
        let rewind = Rewind {
            deposits_from: 0,
            block: transition.block_number,
        };
        store
            .commit(&[], &[], (43, Felt::ZERO), Some(rewind))
            .unwrap();
        let index = store.load(7).unwrap();
        assert!(index.deposits.is_empty() && index.transitions.is_empty());
        let rewind = Rewind {
            deposits_from: 1,
            block: transition.block_number + 1,
        };
        store
            .commit(
                std::slice::from_ref(&deposit),
                std::slice::from_ref(&transition),
                (44, Felt::ZERO),
                None,
            )
            .unwrap();
        store
            .commit(&[], &[], (45, Felt::ZERO), Some(rewind))
            .unwrap();
        let index = store.load(7).unwrap();
        assert_eq!(index.deposits.len(), 1);
        assert_eq!(index.transitions.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    async fn get(
        app: &Router,
        uri: &str,
        peer: &str,
        forwarded: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = Request::get(uri).body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        if let Some(forwarded) = forwarded {
            request
                .headers_mut()
                .insert("x-forwarded-for", HeaderValue::from_str(forwarded).unwrap());
        }
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn ranges_are_bounded_and_served_from_the_index() {
        let path = temporary("ranges");
        let _ = std::fs::remove_file(&path);
        let state = state(path.clone(), 100);
        let (transition, _, _) = settled();
        state
            .index
            .write()
            .await
            .transitions
            .insert(1, transition.clone());
        let app = router(state);
        let (status, body) = get(&app, "/api/transitions/range/1/4", "1.2.3.4:5", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["latest_seq"], 1);
        assert_eq!(
            serde_json::from_value::<Vec<TransitionOutputs>>(body["transitions"].clone()).unwrap(),
            vec![transition]
        );
        assert_eq!(
            get(&app, "/api/transitions/range/4/1", "1.2.3.4:5", None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get(&app, "/api/transitions/range/0/256", "1.2.3.4:5", None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get(&app, "/api/deposits/range/0/9999", "1.2.3.4:5", None)
                .await
                .0,
            StatusCode::OK
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn health_is_unavailable_until_one_sync_completes() {
        let path = temporary("health");
        let _ = std::fs::remove_file(&path);
        let state = state(path.clone(), 100);
        let app = router(state.clone());
        let (status, body) = get(&app, "/health", "1.2.3.4:5", None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["ready"], false);
        assert_eq!(body["last_successful_sync_unix_ms"], 0);

        state.index.write().await.last_sync_ms = now_ms();
        let (status, body) = get(&app, "/health", "1.2.3.4:5", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ready"], true);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn rate_limits_apply_per_client_behind_trusted_proxies_only() {
        let path = temporary("limits");
        let _ = std::fs::remove_file(&path);
        let app = router(state(path.clone(), 1));
        assert_eq!(
            get(&app, "/api/deposits/recent", "10.0.0.1:5", Some("7.7.7.7"))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            get(&app, "/api/deposits/recent", "10.0.0.1:5", Some("8.8.8.8"))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            get(&app, "/api/deposits/recent", "10.0.0.1:5", Some("8.8.8.8"))
                .await
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // an untrusted peer cannot choose its identity.
        assert_eq!(
            get(&app, "/api/deposits/recent", "9.9.9.9:5", Some("1.1.1.1"))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            get(&app, "/api/deposits/recent", "9.9.9.9:5", Some("2.2.2.2"))
                .await
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn manual_sync_requires_the_control_token() {
        let path = temporary("auth");
        let _ = std::fs::remove_file(&path);
        let app = router(state(path.clone(), 10));
        let request = Request::post("/api/internal/sync")
            .header(AUTHORIZATION, "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let _ = std::fs::remove_file(&path);
    }
}

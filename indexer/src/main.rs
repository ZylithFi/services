use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use starknet_rust_core::utils::get_selector_from_name;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use zylith_core::{
    AssetId, CONTROL_PLANE_TOKEN_ENV, DeploymentManifest, DepositConfirmationList,
    DepositConfirmationRequest, DepositRecord, DepositSyncStatus, NoteCommitment,
    OutputCiphertextBundle, PublishedBatchArtifactList, PublishedBatchArtifactSummary,
    PublishedBatchArtifacts, SettlementTranscript, WithdrawalRecord, extract_bearer_token,
};

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:5050/rpc/v0_8";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3300";
const DEFAULT_DEPLOYMENT_MANIFEST_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../client/public/deployment.json"
);
const DEFAULT_SHIELDED_ASSET_ADAPTER_ADDRESS: &str = "";
const DEFAULT_ARTIFACT_ARCHIVE_PATH: &str = "indexer/published_batch_artifacts.dev.json";

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
    published_batch_artifacts: Arc<RwLock<BTreeMap<String, PublishedBatchArtifacts>>>,
    artifact_archive_path: Option<Arc<PathBuf>>,
    internal_api_token: Option<Arc<String>>,
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
    };

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
            "/api/deposits/{note_commitment}",
            get(get_confirmed_deposit),
        )
        .route("/api/batches/artifacts", get(list_archived_batch_artifacts))
        .route(
            "/api/batches/{batch_id}/transcript",
            get(get_archived_transcript),
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
            "/api/withdrawals/{note_commitment}",
            get(get_confirmed_withdrawal),
        )
        .route("/api/deposits/confirmations", post(confirm_deposits))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers(Any),
        )
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
    if let Ok(address) = env::var("ZYLITH_SHIELDED_ASSET_ADAPTER_ADDRESS") {
        return address;
    }

    load_deployment_manifest()
        .map(|manifest| manifest.contracts.shielded_asset_adapter)
        .unwrap_or_else(|| DEFAULT_SHIELDED_ASSET_ADAPTER_ADDRESS.into())
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
        return BTreeMap::default();
    };

    serde_json::from_str::<PublishedBatchArtifactsStoreFile>(&contents)
        .map(|store| store.artifacts_by_batch)
        .unwrap_or_default()
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
) -> PublishedBatchArtifactSummary {
    PublishedBatchArtifactSummary {
        batch_id: published.transcript.batch_id.clone(),
        transcript_commitment: published.settlement_witness.transcript_commitment.clone(),
        output_bundle_ref: published.transcript.output_ciphertext_bundle_ref.clone(),
        bundle_commitment: published.output_bundle.bundle_commitment.clone(),
        data_availability_ref: published.output_bundle.data_availability_ref.clone(),
    }
}

async fn health(State(state): State<AppState>) -> Json<DepositSyncStatus> {
    Json(current_status(&state).await)
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

async fn list_archived_batch_artifacts(
    State(state): State<AppState>,
) -> Json<PublishedBatchArtifactList> {
    let artifacts = state.published_batch_artifacts.read().await;
    let batches = artifacts
        .values()
        .map(published_batch_artifact_summary)
        .collect();
    Json(PublishedBatchArtifactList { batches })
}

async fn get_archived_transcript(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> Result<Json<SettlementTranscript>, StatusCode> {
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
    Ok(Json(published.output_bundle.clone()))
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

    if let Some(path) = state.artifact_archive_path.as_deref() {
        persist_published_batch_artifacts_store(path, &artifacts)?;
    }

    Ok(Json(request))
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
    DepositSyncStatus {
        service: "zylith-indexer".into(),
        rpc_url: state.rpc_url.clone(),
        shielded_asset_adapter_address: state.shielded_asset_adapter_address.clone(),
        cached_deposits: deposits.len() as u64,
        synced_deposit_count: *synced_count,
        cached_withdrawals: withdrawals.len() as u64,
        synced_withdrawal_count: *synced_withdrawal_count,
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
    let call = StarknetCallRequest {
        contract_address: &state.shielded_asset_adapter_address,
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

#[cfg(test)]
mod tests {
    use super::{
        AppState, build_app_with_state, normalize_hex, parse_deployment_manifest, parse_hex_u64,
        parse_hex_u128,
    };
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use std::{collections::BTreeMap, sync::Arc};
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;

    const TEST_INTERNAL_TOKEN: &str = "indexer-test-token";

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
            published_batch_artifacts: Arc::new(RwLock::new(BTreeMap::new())),
            artifact_archive_path: None,
            internal_api_token: Some(Arc::new(TEST_INTERNAL_TOKEN.into())),
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

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use starknet::{
    accounts::{Account, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount},
    core::{
        types::{
            BlockId, BlockTag, BroadcastedInvokeTransactionV3, Call,
            ExecutionResult, Felt, FunctionCall,
            TransactionFinalityStatus, TransactionReceiptWithBlockInfo,
        },
        utils::get_selector_from_name,
    },
    providers::{
        Provider,
        jsonrpc::{HttpTransport, JsonRpcClient},
    },
    signers::{LocalWallet, SigningKey},
};
use tokio::{
    sync::RwLock,
    task,
    time::{Duration, sleep},
};
use url::Url;
use zylith_core::{
    BatchSummary, CONTROL_PLANE_TOKEN_ENV, DeploymentManifest, OnchainSubmissionRecord,
    ProofArtifactRecord,
    ProofJobStatus, SettlementSubmissionPlan, SettlementTranscript, SettlementWitness,
    StarknetCall, build_settlement_submission_plan, build_stwo_serialized_input,
    extract_bearer_token, format_bearer_token, native_settlement_message_hash,
    proof_artifact_commitment, proof_friendly_account_message_hash,
    settlement_transcript_commitment,
};
use zylith_core::hash::encode_starknet_felt;

const DEFAULT_COORDINATOR_URL: &str = "http://127.0.0.1:3000";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3200";
const DEFAULT_DEPLOYMENT_MANIFEST_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../client/public/deployment.json"
);
const DEFAULT_PROVER_DATA_DIR: &str = "prover/data.dev";
const DEFAULT_NATIVE_L1_GAS: u64 = 1_000_000;
const DEFAULT_NATIVE_L1_DATA_GAS: u64 = 1_000_000;
const DEFAULT_NATIVE_L2_GAS: u64 = 100_000_000;
const DEFAULT_STWO_MANIFEST_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../stwo_statement/Scarb.toml");
const DEFAULT_STWO_PACKAGE_NAME: &str = "zylith_settlement_statement";
const DEFAULT_SCARB_BIN: &str = "scarb";
const DEFAULT_RECEIPT_POLL_ATTEMPTS: usize = 20;
const DEFAULT_RECEIPT_POLL_INTERVAL_MS: u64 = 1_500;
const DEFAULT_NATIVE_PROVER_ATTEMPTS: usize = 8;
const DEFAULT_NATIVE_PROVER_RETRY_INTERVAL_MS: u64 = 5_000;
const DEFAULT_NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS: u64 = 120;
const NATIVE_GAS_PRICE_MULTIPLIER_NUMERATOR: u128 = 2;
const NATIVE_GAS_PRICE_MULTIPLIER_DENOMINATOR: u128 = 1;
const NATIVE_PROVER_ATTEMPTS_ENV: &str = "ZYLITH_NATIVE_PROVER_ATTEMPTS";
const NATIVE_PROVER_RETRY_INTERVAL_MS_ENV: &str = "ZYLITH_NATIVE_PROVER_RETRY_INTERVAL_MS";
const NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS_ENV: &str =
    "ZYLITH_NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS";

const PROOF_JOBS_DIR: &str = "proof_jobs";
const SETTLEMENT_PLANS_DIR: &str = "settlement_plans";
const SETTLEMENT_WITNESSES_DIR: &str = "settlement_witnesses";
const PROOF_ARTIFACTS_DIR: &str = "proof_artifacts";
const ONCHAIN_SUBMISSIONS_DIR: &str = "onchain_submissions";
const PROOF_OUTPUTS_DIR: &str = "proof_outputs";
const PUBLIC_INPUTS_DIR: &str = "public_inputs";
const PROVER_LOGS_DIR: &str = "prover_logs";

#[derive(Clone)]
struct AppState {
    coordinator_url: String,
    settlement_verifier_address: String,
    native_tx_prover_url: Option<String>,
    scarb_bin: String,
    stwo_manifest_path: Arc<PathBuf>,
    stwo_package_name: String,
    data_dir: Arc<PathBuf>,
    http_client: Client,
    proof_jobs: Arc<RwLock<BTreeMap<String, ProofJobStatus>>>,
    settlement_plans: Arc<RwLock<BTreeMap<String, SettlementSubmissionPlan>>>,
    settlement_witnesses: Arc<RwLock<BTreeMap<String, SettlementWitness>>>,
    proof_artifacts: Arc<RwLock<BTreeMap<String, ProofArtifactRecord>>>,
    onchain_submissions: Arc<RwLock<BTreeMap<String, OnchainSubmissionRecord>>>,
    starknet_executor: Option<StarknetExecutorConfig>,
    batch_registrar: Option<BatchRegistrarConfig>,
    internal_api_token: Option<Arc<String>>,
    native_prover_attempts: usize,
    native_prover_retry_interval_ms: u64,
    native_prover_request_timeout_seconds: u64,
}

#[derive(Clone)]
struct StarknetExecutorConfig {
    rpc_url: String,
    account_address: String,
    private_key: String,
    chain_id: String,
}

#[derive(Clone)]
struct BatchRegistrarConfig {
    rpc_url: String,
    account_address: String,
    private_key: String,
    chain_id: String,
    batch_registry_address: String,
}

struct AppConfig {
    coordinator_url: String,
    settlement_verifier_address: String,
    native_tx_prover_url: Option<String>,
    scarb_bin: String,
    stwo_manifest_path: PathBuf,
    stwo_package_name: String,
    data_dir: PathBuf,
    starknet_executor: Option<StarknetExecutorConfig>,
    batch_registrar: Option<BatchRegistrarConfig>,
    internal_api_token: Option<String>,
    native_prover_attempts: usize,
    native_prover_retry_interval_ms: u64,
    native_prover_request_timeout_seconds: u64,
}

struct JobStateUpdate {
    next_state: String,
    proof_artifact_id: Option<String>,
    last_error: Option<String>,
    proof_artifact_available: bool,
    settlement_plan_available: Option<bool>,
    settlement_calldata_len: Option<u64>,
}

struct ProofExecutionPaths {
    witness_path: PathBuf,
    proof_path: PathBuf,
    public_inputs_path: PathBuf,
    native_execution_request_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NativeExecutionRequestRecord {
    block_id: NativeBlockId,
    transaction: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum NativeBlockId {
    Tag(String),
    Number { block_number: u64 },
    Hash { block_hash: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NativeProverRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: NativeProverParams,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NativeProverParams {
    block_id: NativeBlockId,
    transaction: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
struct NativeProverRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<NativeProverResult>,
    error: Option<NativeProverError>,
}

#[derive(Clone, Debug, Deserialize)]
struct NativeProverResult {
    proof: String,
    proof_facts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct NativeProverError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

#[tokio::main]
async fn main() {
    let app = build_app();
    let bind_addr =
        env::var("ZYLITH_PROVER_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.into());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("bind prover service");

    println!("Zylith prover listening on http://{bind_addr}");
    axum::serve(listener, app).await.expect("serve prover");
}

fn build_app() -> Router {
    let deployment_manifest = load_deployment_manifest();
    let coordinator_url =
        env::var("ZYLITH_COORDINATOR_URL").unwrap_or_else(|_| DEFAULT_COORDINATOR_URL.into());
    let settlement_verifier_address = env::var("ZYLITH_SETTLEMENT_VERIFIER_ADDRESS")
        .ok()
        .or_else(|| {
            deployment_manifest
                .as_ref()
                .map(|manifest| manifest.contracts.settlement_verifier.clone())
        })
        .unwrap_or_default();
    let native_tx_prover_url = env::var("ZYLITH_NATIVE_TX_PROVER_URL").ok();
    let scarb_bin = env::var("ZYLITH_SCARB_BIN").unwrap_or_else(|_| DEFAULT_SCARB_BIN.into());
    let stwo_manifest_path = env::var("ZYLITH_STWO_MANIFEST_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STWO_MANIFEST_PATH));
    let stwo_package_name =
        env::var("ZYLITH_STWO_PACKAGE_NAME").unwrap_or_else(|_| DEFAULT_STWO_PACKAGE_NAME.into());
    let data_dir = env::var("ZYLITH_PROVER_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PROVER_DATA_DIR));
    let starknet_executor = load_starknet_executor_from_env(deployment_manifest.as_ref());
    let batch_registrar = load_batch_registrar_from_env(deployment_manifest.as_ref());
    let native_prover_attempts = env_parse_or_default(
        NATIVE_PROVER_ATTEMPTS_ENV,
        DEFAULT_NATIVE_PROVER_ATTEMPTS,
    );
    let native_prover_retry_interval_ms = env_parse_or_default(
        NATIVE_PROVER_RETRY_INTERVAL_MS_ENV,
        DEFAULT_NATIVE_PROVER_RETRY_INTERVAL_MS,
    );
    let native_prover_request_timeout_seconds = env_parse_or_default(
        NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS_ENV,
        DEFAULT_NATIVE_PROVER_REQUEST_TIMEOUT_SECONDS,
    );

    build_app_with_config(AppConfig {
        coordinator_url,
        settlement_verifier_address,
        native_tx_prover_url,
        scarb_bin,
        stwo_manifest_path,
        stwo_package_name,
        data_dir,
        starknet_executor,
        batch_registrar,
        internal_api_token: Some(load_required_control_plane_token(
            "zylith-prover",
            CONTROL_PLANE_TOKEN_ENV,
        )),
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
    })
}

fn load_deployment_manifest() -> Option<DeploymentManifest> {
    let manifest_path = env::var("ZYLITH_DEPLOYMENT_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DEPLOYMENT_MANIFEST_PATH));
    let manifest = fs::read_to_string(manifest_path).ok()?;
    serde_json::from_str(&manifest).ok()
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

fn apply_internal_auth(
    request: reqwest::RequestBuilder,
    internal_api_token: Option<&str>,
) -> reqwest::RequestBuilder {
    if let Some(token) = internal_api_token {
        request.header(AUTHORIZATION.as_str(), format_bearer_token(token))
    } else {
        request
    }
}

fn build_app_with_config(config: AppConfig) -> Router {
    let AppConfig {
        coordinator_url,
        settlement_verifier_address,
        native_tx_prover_url,
        scarb_bin,
        stwo_manifest_path,
        stwo_package_name,
        data_dir,
        starknet_executor,
        batch_registrar,
        internal_api_token,
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
    } = config;

    ensure_prover_dirs(&data_dir);

    let state = AppState {
        coordinator_url,
        settlement_verifier_address,
        native_tx_prover_url,
        scarb_bin,
        stwo_manifest_path: Arc::new(stwo_manifest_path),
        stwo_package_name,
        data_dir: Arc::new(data_dir.clone()),
        http_client: Client::new(),
        proof_jobs: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            PROOF_JOBS_DIR,
            |record: &ProofJobStatus| record.batch_id.0.clone(),
        ))),
        settlement_plans: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            SETTLEMENT_PLANS_DIR,
            |record: &SettlementSubmissionPlan| record.batch_id.0.clone(),
        ))),
        settlement_witnesses: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            SETTLEMENT_WITNESSES_DIR,
            |record: &SettlementWitness| record.batch_id.0.clone(),
        ))),
        proof_artifacts: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            PROOF_ARTIFACTS_DIR,
            |record: &ProofArtifactRecord| record.batch_id.0.clone(),
        ))),
        onchain_submissions: Arc::new(RwLock::new(load_json_records(
            &data_dir,
            ONCHAIN_SUBMISSIONS_DIR,
            |record: &OnchainSubmissionRecord| record.batch_id.0.clone(),
        ))),
        starknet_executor,
        batch_registrar,
        internal_api_token: internal_api_token.map(Arc::new),
        native_prover_attempts,
        native_prover_retry_interval_ms,
        native_prover_request_timeout_seconds,
    };

    Router::new()
        .route("/health", get(health))
        .route(
            "/api/internal/proof-jobs/{batch_id}",
            get(get_proof_job).post(prepare_proof_job),
        )
        .route(
            "/api/internal/proof-jobs/{batch_id}/prove",
            post(run_proof_job),
        )
        .route(
            "/api/internal/proof-jobs/{batch_id}/submit",
            post(submit_onchain),
        )
        .route(
            "/api/internal/settlement-plans/{batch_id}",
            get(get_settlement_plan),
        )
        .route(
            "/api/internal/settlement-witnesses/{batch_id}",
            get(get_settlement_witness),
        )
        .route(
            "/api/internal/proof-artifacts/{batch_id}",
            get(get_proof_artifact),
        )
        .route(
            "/api/internal/onchain-submissions/{batch_id}",
            get(get_onchain_submission),
        )
        .route(
            "/api/internal/onchain-submissions/{batch_id}/refresh",
            post(refresh_onchain_submission),
        )
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let proof_jobs = state.proof_jobs.read().await;
    let settlement_plans = state.settlement_plans.read().await;
    let settlement_witnesses = state.settlement_witnesses.read().await;
    let proof_artifacts = state.proof_artifacts.read().await;
    let onchain_submissions = state.onchain_submissions.read().await;
    Json(serde_json::json!({
        "service": "zylith-prover",
        "coordinator_url": state.coordinator_url,
        "prepared_jobs": proof_jobs.len(),
        "settlement_verifier_address": state.settlement_verifier_address,
        "native_tx_prover_url": state.native_tx_prover_url,
        "prepared_settlement_plans": settlement_plans.len(),
        "prepared_settlement_witnesses": settlement_witnesses.len(),
        "stored_proof_artifacts": proof_artifacts.len(),
        "stored_onchain_submissions": onchain_submissions.len(),
        "starknet_executor_enabled": state.starknet_executor.is_some(),
        "native_tx_prover_enabled": state.native_tx_prover_url.is_some(),
        "native_prover_attempts": state.native_prover_attempts,
        "native_prover_retry_interval_ms": state.native_prover_retry_interval_ms,
        "native_prover_request_timeout_seconds": state.native_prover_request_timeout_seconds,
        "prover_backend": prover_backend_label(state.native_tx_prover_url.is_some()),
        "scarb_bin": state.scarb_bin,
        "stwo_manifest_path": state.stwo_manifest_path.display().to_string(),
        "stwo_package_name": state.stwo_package_name,
        "data_dir": state.data_dir.display().to_string(),
    }))
}

fn env_parse_or_default<T>(env_name: &str, default: T) -> T
where
    T: std::str::FromStr + Copy,
{
    env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default)
}

async fn get_proof_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofJobStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let proof_jobs = state.proof_jobs.read().await;
    let status = proof_jobs
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(status))
}

async fn get_settlement_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<SettlementSubmissionPlan>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let settlement_plans = state.settlement_plans.read().await;
    let plan = settlement_plans
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(plan))
}

async fn get_settlement_witness(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<SettlementWitness>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let settlement_witnesses = state.settlement_witnesses.read().await;
    let witness = settlement_witnesses
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(witness))
}

async fn get_proof_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofArtifactRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let proof_artifacts = state.proof_artifacts.read().await;
    let artifact = proof_artifacts
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(artifact))
}

async fn get_onchain_submission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<OnchainSubmissionRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let submissions = state.onchain_submissions.read().await;
    let record = submissions
        .get(&batch_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(record))
}

async fn refresh_onchain_submission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<OnchainSubmissionRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let current_record = {
        let submissions = state.onchain_submissions.read().await;
        submissions
            .get(&batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };

    let refreshed_record = refresh_submission_status(&state, current_record)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    {
        let mut submissions = state.onchain_submissions.write().await;
        submissions.insert(batch_id.clone(), refreshed_record.clone());
        persist_record(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &batch_id,
            &refreshed_record,
        )?;
    }

    sync_job_with_onchain_submission(&state, &batch_id, &refreshed_record).await?;

    Ok(Json(refreshed_record))
}

async fn prepare_proof_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofJobStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let (status, _) = prepare_or_rebuild_job(&state, &batch_id).await?;
    Ok(Json(status))
}

async fn run_proof_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<ProofJobStatus>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let (_, settlement_witness) = ensure_prepared_job(&state, &batch_id).await?;
    let transcript = fetch_transcript(&state, &batch_id).await?;

    set_job_state(
        &state,
        &batch_id,
        JobStateUpdate {
            next_state: "proving".into(),
            proof_artifact_id: None,
            last_error: None,
            proof_artifact_available: false,
            settlement_plan_available: None,
            settlement_calldata_len: None,
        },
    )
    .await?;

    let proof_result = if state.native_tx_prover_url.is_some() {
        execute_native_transaction_prover(&state, &batch_id, &transcript).await
    } else {
        execute_stwo_prover(&state, &batch_id, &settlement_witness).await
    };

    match proof_result {
        Ok(artifact) => {
            let settlement_plan = build_settlement_submission_plan(
                &transcript,
                &state.settlement_verifier_address,
                &artifact.proof_artifact_commitment,
            )
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
            let artifact_id = artifact.artifact_id.clone();
            {
                let mut proof_artifacts = state.proof_artifacts.write().await;
                proof_artifacts.insert(batch_id.clone(), artifact.clone());
                persist_record(
                    state.data_dir.as_ref(),
                    PROOF_ARTIFACTS_DIR,
                    &batch_id,
                    &artifact,
                )?;
            }
            {
                let mut settlement_plans = state.settlement_plans.write().await;
                settlement_plans.insert(batch_id.clone(), settlement_plan.clone());
                persist_record(
                    state.data_dir.as_ref(),
                    SETTLEMENT_PLANS_DIR,
                    &batch_id,
                    &settlement_plan,
                )?;
            }

            let updated_status = set_job_state(
                &state,
                &batch_id,
                JobStateUpdate {
                    next_state: "proof-generated".into(),
                    proof_artifact_id: Some(artifact_id),
                    last_error: None,
                    proof_artifact_available: true,
                    settlement_plan_available: Some(true),
                    settlement_calldata_len: Some(
                        settlement_plan.settlement_call.calldata.len() as u64
                    ),
                },
            )
            .await?;

            Ok(Json(updated_status))
        }
        Err(error) => {
            set_job_error(&state, &batch_id, error).await?;
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

async fn submit_onchain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(batch_id): Path<String>,
) -> Result<Json<OnchainSubmissionRecord>, StatusCode> {
    require_internal_auth(&state, &headers)?;
    let settlement_plan = {
        let settlement_plans = state.settlement_plans.read().await;
        settlement_plans
            .get(&batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };
    let proof_artifact = {
        let proof_artifacts = state.proof_artifacts.read().await;
        proof_artifacts
            .get(&batch_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?
    };

    if proof_artifact.native_proof_file_path.is_none()
        || proof_artifact.native_proof_facts_file_path.is_none()
        || proof_artifact.native_execution_request_path.is_none()
    {
        return Err(StatusCode::CONFLICT);
    }

    let submission = submit_native_plan_onchain(&state, &settlement_plan, &proof_artifact)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    {
        let mut submissions = state.onchain_submissions.write().await;
        submissions.insert(batch_id.clone(), submission.clone());
        persist_record(
            state.data_dir.as_ref(),
            ONCHAIN_SUBMISSIONS_DIR,
            &batch_id,
            &submission,
        )?;
    }
    sync_job_with_onchain_submission(&state, &batch_id, &submission).await?;

    Ok(Json(submission))
}

async fn ensure_prepared_job(
    state: &AppState,
    batch_id: &str,
) -> Result<(ProofJobStatus, SettlementWitness), StatusCode> {
    let maybe_status = {
        let proof_jobs = state.proof_jobs.read().await;
        proof_jobs.get(batch_id).cloned()
    };
    let maybe_witness = {
        let settlement_witnesses = state.settlement_witnesses.read().await;
        settlement_witnesses.get(batch_id).cloned()
    };

    match (maybe_status, maybe_witness) {
        (Some(status), Some(witness)) => Ok((status, witness)),
        _ => prepare_or_rebuild_job(state, batch_id).await,
    }
}

async fn prepare_or_rebuild_job(
    state: &AppState,
    batch_id: &str,
) -> Result<(ProofJobStatus, SettlementWitness), StatusCode> {
    let transcript = fetch_transcript(state, batch_id).await?;
    let mut settlement_witness = fetch_witness(state, batch_id).await?;
    let transcript_commitment =
        settlement_transcript_commitment(&transcript).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if settlement_witness.batch_id != transcript.batch_id {
        return Err(StatusCode::BAD_GATEWAY);
    }
    settlement_witness.transcript_commitment = transcript_commitment.clone();
    settlement_witness.settlement_verifier_address = state.settlement_verifier_address.clone();

    let now = now_unix_ms();
    let created_at_unix_ms = {
        let proof_jobs = state.proof_jobs.read().await;
        proof_jobs
            .get(batch_id)
            .map(|existing| existing.created_at_unix_ms)
            .unwrap_or(now)
    };

    let status = ProofJobStatus {
        batch_id: transcript.batch_id.clone(),
        state: "witness-prepared".into(),
        transcript_commitment,
        matched_order_count: transcript.matched_orders.len() as u64,
        settlement_plan_available: false,
        witness_available: true,
        proof_artifact_available: false,
        onchain_submission_available: false,
        proof_artifact_id: None,
        onchain_submission_id: None,
        prover_backend: prover_backend_label(state.native_tx_prover_url.is_some()),
        last_error: None,
        created_at_unix_ms,
        updated_at_unix_ms: now,
        settlement_contract_address: state.settlement_verifier_address.clone(),
        settlement_entrypoint: "submit_settlement_native".into(),
        settlement_calldata_len: 0,
    };

    {
        let mut proof_jobs = state.proof_jobs.write().await;
        proof_jobs.insert(batch_id.into(), status.clone());
        persist_record(state.data_dir.as_ref(), PROOF_JOBS_DIR, batch_id, &status)?;
    }
    {
        let mut settlement_plans = state.settlement_plans.write().await;
        settlement_plans.remove(batch_id);
        delete_record_if_exists(state.data_dir.as_ref(), SETTLEMENT_PLANS_DIR, batch_id)?;
    }
    {
        let mut settlement_witnesses = state.settlement_witnesses.write().await;
        settlement_witnesses.insert(batch_id.into(), settlement_witness.clone());
        persist_record(
            state.data_dir.as_ref(),
            SETTLEMENT_WITNESSES_DIR,
            batch_id,
            &settlement_witness,
        )?;
    }
    {
        let mut proof_artifacts = state.proof_artifacts.write().await;
        proof_artifacts.remove(batch_id);
        delete_record_if_exists(state.data_dir.as_ref(), PROOF_ARTIFACTS_DIR, batch_id)?;
    }
    {
        let mut onchain_submissions = state.onchain_submissions.write().await;
        onchain_submissions.remove(batch_id);
        delete_record_if_exists(state.data_dir.as_ref(), ONCHAIN_SUBMISSIONS_DIR, batch_id)?;
    }
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), batch_id)?;

    Ok((status, settlement_witness))
}

async fn set_job_state(
    state: &AppState,
    batch_id: &str,
    update: JobStateUpdate,
) -> Result<ProofJobStatus, StatusCode> {
    let JobStateUpdate {
        next_state,
        proof_artifact_id,
        last_error,
        proof_artifact_available,
        settlement_plan_available,
        settlement_calldata_len,
    } = update;
    let mut proof_jobs = state.proof_jobs.write().await;
    let status = proof_jobs.get_mut(batch_id).ok_or(StatusCode::NOT_FOUND)?;
    status.state = next_state;
    status.proof_artifact_id = proof_artifact_id;
    status.proof_artifact_available = proof_artifact_available;
    status.last_error = last_error;
    if let Some(value) = settlement_plan_available {
        status.settlement_plan_available = value;
    }
    if let Some(value) = settlement_calldata_len {
        status.settlement_calldata_len = value;
    }
    status.updated_at_unix_ms = now_unix_ms();
    persist_record(state.data_dir.as_ref(), PROOF_JOBS_DIR, batch_id, status)?;
    Ok(status.clone())
}

async fn sync_job_with_onchain_submission(
    state: &AppState,
    batch_id: &str,
    submission: &OnchainSubmissionRecord,
) -> Result<ProofJobStatus, StatusCode> {
    let mut proof_jobs = state.proof_jobs.write().await;
    let status = proof_jobs.get_mut(batch_id).ok_or(StatusCode::NOT_FOUND)?;

    status.state = match (
        submission.finality_status.as_deref(),
        submission.execution_status.as_deref(),
    ) {
        (_, Some("REVERTED")) => "onchain-reverted".into(),
        (Some("ACCEPTED_ON_L1" | "ACCEPTED_ON_L2"), Some("SUCCEEDED")) => {
            "confirmed-onchain".into()
        }
        (Some("PRE_CONFIRMED"), _) => "submitted-onchain".into(),
        _ => "submitted-onchain".into(),
    };
    status.last_error = submission.revert_reason.clone();
    status.onchain_submission_available = true;
    status.onchain_submission_id = Some(submission.submission_id.clone());
    status.updated_at_unix_ms = now_unix_ms();
    persist_record(state.data_dir.as_ref(), PROOF_JOBS_DIR, batch_id, status)?;

    Ok(status.clone())
}

async fn set_job_error(
    state: &AppState,
    batch_id: &str,
    error: String,
) -> Result<ProofJobStatus, StatusCode> {
    set_job_state(
        state,
        batch_id,
        JobStateUpdate {
            next_state: "proving-failed".into(),
            proof_artifact_id: None,
            last_error: Some(error),
            proof_artifact_available: false,
            settlement_plan_available: None,
            settlement_calldata_len: None,
        },
    )
    .await
}

async fn execute_stwo_prover(
    state: &AppState,
    batch_id: &str,
    settlement_witness: &SettlementWitness,
) -> Result<ProofArtifactRecord, String> {
    let manifest_workdir = state
        .stwo_manifest_path
        .parent()
        .ok_or_else(|| "invalid stwo manifest path".to_string())?;
    let paths = proof_execution_paths(state.data_dir.as_ref(), batch_id);
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), batch_id)
        .map_err(status_to_error)?;

    persist_json_file(&paths.witness_path, settlement_witness).map_err(status_to_error)?;
    let serialized_input = build_stwo_serialized_input(settlement_witness);
    persist_json_file(&paths.public_inputs_path, &serialized_input).map_err(status_to_error)?;

    let mut prove_command = build_stwo_prove_command(
        &state.scarb_bin,
        state.stwo_manifest_path.as_ref(),
        &state.stwo_package_name,
        &paths.public_inputs_path,
    );
    let prove_output = task::spawn_blocking(move || prove_command.output())
        .await
        .map_err(|join_error| format!("stwo prove join error: {join_error}"))?
        .map_err(|io_error| format!("stwo prove spawn error: {io_error}"))?;

    let prove_stdout = String::from_utf8_lossy(&prove_output.stdout).into_owned();
    let prove_stderr = String::from_utf8_lossy(&prove_output.stderr).into_owned();

    if !prove_output.status.success() {
        fs::write(&paths.stdout_path, &prove_stdout)
            .map_err(|error| format!("failed to persist prover stdout: {error}"))?;
        fs::write(&paths.stderr_path, &prove_stderr)
            .map_err(|error| format!("failed to persist prover stderr: {error}"))?;
        return Err(format!(
            "stwo prove exited with status {}{}",
            prove_output.status,
            if prove_stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", prove_stderr.trim())
            }
        ));
    }

    let prove_status_lines = parse_scarb_status_lines(&prove_stdout);
    let raw_proof_path = extract_proof_path(&prove_status_lines).ok_or_else(|| {
        format!("could not locate proof path in scarb prove output: {prove_stdout}")
    })?;
    let source_proof_path = resolve_proof_path(manifest_workdir, &raw_proof_path);
    if !source_proof_path.exists() {
        return Err(format!(
            "stwo prove reported proof path {}, but the file does not exist",
            source_proof_path.display()
        ));
    }

    fs::copy(&source_proof_path, &paths.proof_path)
        .map_err(|error| format!("failed to copy proof artifact: {error}"))?;

    let mut verify_command = build_stwo_verify_command(
        &state.scarb_bin,
        state.stwo_manifest_path.as_ref(),
        &paths.proof_path,
    );
    let verify_output = task::spawn_blocking(move || verify_command.output())
        .await
        .map_err(|join_error| format!("stwo verify join error: {join_error}"))?
        .map_err(|io_error| format!("stwo verify spawn error: {io_error}"))?;

    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout).into_owned();
    let verify_stderr = String::from_utf8_lossy(&verify_output.stderr).into_owned();

    fs::write(
        &paths.stdout_path,
        format!(
            "=== scarb prove stdout ===\n{prove_stdout}\n=== scarb verify stdout ===\n{verify_stdout}\n"
        ),
    )
    .map_err(|error| format!("failed to persist prover stdout: {error}"))?;
    fs::write(
        &paths.stderr_path,
        format!(
            "=== scarb prove stderr ===\n{prove_stderr}\n=== scarb verify stderr ===\n{verify_stderr}\n"
        ),
    )
    .map_err(|error| format!("failed to persist prover stderr: {error}"))?;

    if !verify_output.status.success() {
        return Err(format!(
            "stwo verify exited with status {}{}",
            verify_output.status,
            if verify_stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", verify_stderr.trim())
            }
        ));
    }

    let verify_status_lines = parse_scarb_status_lines(&verify_stdout);
    if !verify_status_lines
        .iter()
        .any(|line| line.status == "verified")
    {
        return Err(format!(
            "stwo verify completed without a verified status line: {verify_stdout}"
        ));
    }

    let proof_sha256 = sha256_file_hex(&paths.proof_path)?;
    let public_inputs_sha256 = sha256_file_hex(&paths.public_inputs_path)?;
    let proof_artifact_commitment = proof_artifact_commitment(&proof_sha256, &public_inputs_sha256)
        .map_err(|error| format!("failed to derive proof artifact commitment: {error}"))?;
    let artifact_id = artifact_id_for(batch_id, &settlement_witness.transcript_commitment);

    Ok(ProofArtifactRecord {
        artifact_id,
        batch_id: settlement_witness.batch_id.clone(),
        proof_system: "s-two".into(),
        proof_format: "scarb-proof-json".into(),
        prover_backend: prover_backend_label(state.native_tx_prover_url.is_some()),
        created_at_unix_ms: now_unix_ms(),
        proof_artifact_commitment,
        proof_path: paths.proof_path.display().to_string(),
        public_inputs_path: paths.public_inputs_path.display().to_string(),
        prover_stdout_path: paths.stdout_path.display().to_string(),
        prover_stderr_path: paths.stderr_path.display().to_string(),
        proof_sha256,
        public_inputs_sha256,
        native_proof_file_path: None,
        native_proof_facts_file_path: None,
        native_execution_request_path: None,
    })
}

async fn execute_native_transaction_prover(
    state: &AppState,
    batch_id: &str,
    transcript: &SettlementTranscript,
) -> Result<ProofArtifactRecord, String> {
    let tx_prover_url = state
        .native_tx_prover_url
        .clone()
        .ok_or_else(|| "native transaction prover is not configured".to_string())?;
    let executor = state
        .starknet_executor
        .clone()
        .ok_or_else(|| "starknet executor is not configured".to_string())?;
    let transcript_commitment =
        settlement_transcript_commitment(transcript).map_err(|error| error.to_string())?;
    ensure_batch_registered_onchain(state, batch_id).await?;
    let native_proof_reference =
        native_settlement_message_hash(&state.settlement_verifier_address, &transcript_commitment)
            .map_err(|error| error.to_string())?;
    let paths = proof_execution_paths(state.data_dir.as_ref(), batch_id);
    delete_execution_outputs_if_exist(state.data_dir.as_ref(), batch_id)
        .map_err(status_to_error)?;

    let settlement_plan = build_settlement_submission_plan(
        transcript,
        &state.settlement_verifier_address,
        &native_proof_reference,
    )
    .map_err(|error| error.to_string())?;
    let execution_request =
        build_native_execution_request(&executor, &settlement_plan.settlement_call).await?;
    persist_json_file(&paths.native_execution_request_path, &execution_request)
        .map_err(status_to_error)?;

    let rpc_request = NativeProverRpcRequest {
        jsonrpc: "2.0".into(),
        id: 1,
        method: "starknet_proveTransaction".into(),
        params: NativeProverParams {
            block_id: execution_request.block_id.clone(),
            transaction: execution_request.transaction.clone(),
        },
    };
    let mut final_response_value = None;
    let mut final_result = None;
    let mut last_error = None;
    for attempt in 1..=state.native_prover_attempts {
        match request_native_proof(state, &tx_prover_url, &rpc_request).await {
            Ok((result, response_value)) => {
                final_result = Some(result);
                final_response_value = Some(response_value);
                break;
            }
            Err(error) if attempt < state.native_prover_attempts => {
                eprintln!(
                    "native transaction prover attempt {attempt}/{attempts} failed for batch {batch_id}: {error}",
                    attempts = state.native_prover_attempts
                );
                last_error = Some(error);
                sleep(Duration::from_millis(state.native_prover_retry_interval_ms)).await;
            }
            Err(error) => {
                last_error = Some(error);
                break;
            }
        }
    }
    let response_value = final_response_value
        .ok_or_else(|| last_error.unwrap_or_else(|| "native transaction prover returned no result".into()))?;
    let result = final_result
        .ok_or_else(|| "native transaction prover returned no result".to_string())?;

    fs::write(&paths.proof_path, result.proof.trim())
        .map_err(|error| format!("failed to persist native proof: {error}"))?;
    persist_json_file(&paths.public_inputs_path, &result.proof_facts).map_err(status_to_error)?;
    persist_json_file(
        &paths.stdout_path,
        &serde_json::json!({
            "request": rpc_request,
            "response": response_value,
        }),
    )
    .map_err(status_to_error)?;
    fs::write(&paths.stderr_path, "")
        .map_err(|error| format!("failed to persist native prover stderr log: {error}"))?;

    let proof_sha256 = sha256_file_hex(&paths.proof_path)?;
    let proof_facts_sha256 = sha256_file_hex(&paths.public_inputs_path)?;
    let artifact_id = artifact_id_for(batch_id, &transcript_commitment);

    Ok(ProofArtifactRecord {
        artifact_id,
        batch_id: transcript.batch_id.clone(),
        proof_system: "starknet-snip36".into(),
        proof_format: "virtual-tx-proof".into(),
        prover_backend: prover_backend_label(true),
        created_at_unix_ms: now_unix_ms(),
        proof_artifact_commitment: native_proof_reference,
        proof_path: paths.proof_path.display().to_string(),
        public_inputs_path: paths.public_inputs_path.display().to_string(),
        prover_stdout_path: paths.stdout_path.display().to_string(),
        prover_stderr_path: paths.stderr_path.display().to_string(),
        proof_sha256,
        public_inputs_sha256: proof_facts_sha256,
        native_proof_file_path: Some(paths.proof_path.display().to_string()),
        native_proof_facts_file_path: Some(paths.public_inputs_path.display().to_string()),
        native_execution_request_path: Some(
            paths.native_execution_request_path.display().to_string(),
        ),
    })
}

async fn request_native_proof(
    state: &AppState,
    tx_prover_url: &str,
    rpc_request: &NativeProverRpcRequest,
) -> Result<(NativeProverResult, serde_json::Value), String> {
    let response_value = tokio::time::timeout(
        Duration::from_secs(state.native_prover_request_timeout_seconds),
        async {
            let response = state
                .http_client
                .post(tx_prover_url)
                .json(rpc_request)
                .send()
                .await
                .map_err(|error| {
                    format!("native transaction prover request failed: {error}")
                })?;
            response
                .json::<serde_json::Value>()
                .await
                .map_err(|error| {
                    format!("native transaction prover response decode failed: {error}")
                })
        },
    )
    .await
    .map_err(|_| {
        format!(
            "native transaction prover request timed out after {}s",
            state.native_prover_request_timeout_seconds
        )
    })??;
    let response: NativeProverRpcResponse = serde_json::from_value(response_value.clone())
        .map_err(|error| format!("native transaction prover response shape error: {error}"))?;
    let result = match (response.result, response.error) {
        (Some(result), None) => result,
        (_, Some(error)) => {
            return Err(format!(
                "native transaction prover error {}: {}{}",
                error.code,
                error.message,
                error
                    .data
                    .map(|value| format!(" ({value})"))
                    .unwrap_or_default()
            ));
        }
        _ => return Err("native transaction prover returned no result".to_string()),
    };

    Ok((result, response_value))
}

async fn fetch_transcript(
    state: &AppState,
    batch_id: &str,
) -> Result<SettlementTranscript, StatusCode> {
    let url = format!(
        "{}/api/batches/{}/transcript",
        state.coordinator_url, batch_id
    );
    state
        .http_client
        .get(url)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .error_for_status()
        .map_err(|status| {
            if status.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_GATEWAY
            }
        })?
        .json()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

async fn fetch_batch_summary(
    state: &AppState,
    batch_id: &str,
) -> Result<BatchSummary, StatusCode> {
    let url = format!("{}/api/batches/{batch_id}", state.coordinator_url);
    state
        .http_client
        .get(url)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .error_for_status()
        .map_err(|status| {
            if status.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_GATEWAY
            }
        })?
        .json()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

async fn fetch_witness(state: &AppState, batch_id: &str) -> Result<SettlementWitness, StatusCode> {
    let url = format!(
        "{}/api/internal/batches/{}/witness",
        state.coordinator_url, batch_id
    );
    apply_internal_auth(
        state.http_client.get(url),
        state
            .internal_api_token
            .as_ref()
            .map(|token| token.as_str()),
    )
    .send()
    .await
    .map_err(|_| StatusCode::BAD_GATEWAY)?
    .error_for_status()
    .map_err(|status| {
        if status.status() == Some(reqwest::StatusCode::NOT_FOUND) {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_GATEWAY
        }
    })?
        .json()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

async fn ensure_batch_registered_onchain(
    state: &AppState,
    batch_id: &str,
) -> Result<(), String> {
    let registrar = match &state.batch_registrar {
        Some(registrar) => registrar.clone(),
        None => return Ok(()),
    };
    let batch = fetch_batch_summary(state, batch_id)
        .await
        .map_err(|status| format!("failed to fetch batch summary for onchain registration: {status}"))?;

    let rpc_url = Url::parse(&registrar.rpc_url)
        .map_err(|error| format!("invalid batch registrar rpc url: {error}"))?;
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
    let batch_registry_address =
        parse_felt(&registrar.batch_registry_address, "ZYLITH_BATCH_REGISTRY_ADDRESS")?;
    let batch_id_felt = parse_felt(
        &encode_starknet_felt("batch-id", &batch.batch_id.0),
        "encoded batch id",
    )?;

    let exists_call = FunctionCall {
        contract_address: batch_registry_address,
        entry_point_selector: get_selector_from_name("batch_exists")
            .map_err(|error| format!("failed to compute batch_exists selector: {error}"))?,
        calldata: vec![batch_id_felt],
    };
    let exists = provider
        .call(exists_call, BlockId::Tag(BlockTag::Latest))
        .await
        .map_err(|error| format!("failed to query onchain batch existence: {error}"))?;
    if exists.first().copied().unwrap_or(Felt::ZERO) != Felt::ZERO {
        return Ok(());
    }

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(parse_felt(
        &registrar.private_key,
        "ZYLITH_BATCH_REGISTRAR_PRIVATE_KEY",
    )?));
    let account = SingleOwnerAccount::new(
        provider,
        signer,
        parse_felt(
            &registrar.account_address,
            "ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS",
        )?,
        parse_felt(&registrar.chain_id, "ZYLITH_BATCH_REGISTRAR_CHAIN_ID")?,
        ExecutionEncoding::New,
    );

    let register_batch_call = Call {
        to: batch_registry_address,
        selector: get_selector_from_name("register_batch")
            .map_err(|error| format!("failed to compute register_batch selector: {error}"))?,
        calldata: vec![
            batch_id_felt,
            parse_felt(
                &encode_starknet_felt("pair-id", &batch.pair_id.0),
                "encoded pair id",
            )?,
            Felt::from(batch.epoch_id),
            Felt::from(batch.close_time_unix_ms),
        ],
    };

    let result = account
        .execute_v3(vec![register_batch_call])
        .send()
        .await
        .map_err(|error| format!("failed to submit onchain batch registration: {error}"))?;

    let receipt = wait_for_accepted_receipt(account.provider(), result.transaction_hash).await;
    let Some(receipt) = receipt else {
        return Err("batch registration receipt unavailable".into());
    };
    match receipt.receipt.execution_result() {
        ExecutionResult::Succeeded => Ok(()),
        ExecutionResult::Reverted { reason } => {
            Err(format!("batch registration reverted onchain: {reason}"))
        }
    }
}

fn load_starknet_executor_from_env(
    deployment_manifest: Option<&DeploymentManifest>,
) -> Option<StarknetExecutorConfig> {
    let rpc_url = env::var("ZYLITH_STARKNET_RPC_URL")
        .ok()
        .or_else(|| deployment_manifest.map(|manifest| manifest.rpc_url.clone()))?;
    let account_address = env::var("ZYLITH_STARKNET_ACCOUNT_ADDRESS").ok()?;
    let private_key = env::var("ZYLITH_STARKNET_PRIVATE_KEY").ok()?;
    let chain_id = env::var("ZYLITH_STARKNET_CHAIN_ID")
        .ok()
        .or_else(|| deployment_manifest.map(|manifest| manifest.chain_id.clone()))?;

    Some(StarknetExecutorConfig {
        rpc_url,
        account_address,
        private_key,
        chain_id,
    })
}

fn load_batch_registrar_from_env(
    deployment_manifest: Option<&DeploymentManifest>,
) -> Option<BatchRegistrarConfig> {
    let account_address = env::var("ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS").ok()?;
    let private_key = env::var("ZYLITH_BATCH_REGISTRAR_PRIVATE_KEY")
        .ok()
        .or_else(|| env::var("ZYLITH_STARKNET_PRIVATE_KEY").ok())?;
    let rpc_url = env::var("ZYLITH_BATCH_REGISTRAR_RPC_URL")
        .ok()
        .or_else(|| env::var("ZYLITH_STARKNET_RPC_URL").ok())
        .or_else(|| deployment_manifest.map(|manifest| manifest.rpc_url.clone()))?;
    let chain_id = env::var("ZYLITH_BATCH_REGISTRAR_CHAIN_ID")
        .ok()
        .or_else(|| env::var("ZYLITH_STARKNET_CHAIN_ID").ok())
        .or_else(|| deployment_manifest.map(|manifest| manifest.chain_id.clone()))?;
    let batch_registry_address = env::var("ZYLITH_BATCH_REGISTRY_ADDRESS")
        .ok()
        .or_else(|| {
            deployment_manifest
                .map(|manifest| manifest.contracts.batch_registry.clone())
        })?;

    Some(BatchRegistrarConfig {
        rpc_url,
        account_address,
        private_key,
        chain_id,
        batch_registry_address,
    })
}

async fn build_native_execution_request(
    executor: &StarknetExecutorConfig,
    settlement_call: &StarknetCall,
) -> Result<NativeExecutionRequestRecord, String> {
    let rpc_url = Url::parse(&executor.rpc_url)
        .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?;
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(parse_felt(
        &executor.private_key,
        "ZYLITH_STARKNET_PRIVATE_KEY",
    )?));
    let account = SingleOwnerAccount::new(
        provider,
        signer,
        parse_felt(&executor.account_address, "ZYLITH_STARKNET_ACCOUNT_ADDRESS")?,
        parse_felt(&executor.chain_id, "ZYLITH_STARKNET_CHAIN_ID")?,
        ExecutionEncoding::New,
    );
    let execution_context = fetch_native_gas_prices(account.provider()).await?;
    let nonce = account
        .get_nonce()
        .await
        .map_err(|error| format!("failed to fetch account nonce: {error}"))?;
    let invoke_request = account
        .execute_v3(vec![starknet_call_to_call(settlement_call)?])
        .nonce(nonce)
        .l1_gas(DEFAULT_NATIVE_L1_GAS)
        .l1_gas_price(execution_context.l1_gas_price)
        .l2_gas(DEFAULT_NATIVE_L2_GAS)
        .l2_gas_price(execution_context.l2_gas_price)
        .l1_data_gas(DEFAULT_NATIVE_L1_DATA_GAS)
        .l1_data_gas_price(execution_context.l1_data_gas_price)
        .tip(0)
        .prepared()
        .map_err(|_| "failed to prepare native execution request".to_string())?
        .get_invoke_request(false, true)
        .await
        .map_err(|error| format!("failed to build unsigned native execution request: {error}"))?;
    let signature = build_proof_friendly_signature(executor, settlement_call, &invoke_request)?;
    let mut transaction = serde_json::to_value(&invoke_request)
        .map_err(|error| format!("failed to serialize native invoke request: {error}"))?;
    insert_signature_into_invoke_request(&mut transaction, &signature);

    Ok(NativeExecutionRequestRecord {
        block_id: execution_context.block_id,
        transaction,
    })
}

struct NativeExecutionContext {
    block_id: NativeBlockId,
    l1_gas_price: u128,
    l2_gas_price: u128,
    l1_data_gas_price: u128,
}

async fn fetch_native_gas_prices(
    provider: &JsonRpcClient<HttpTransport>,
) -> Result<NativeExecutionContext, String> {
    let block = provider
        .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
        .await
        .map_err(|error| format!("failed to fetch latest block gas prices: {error}"))?;
    let starknet::core::types::MaybePreConfirmedBlockWithTxHashes::Block(block) = block else {
        return Err("latest block is pre-confirmed; confirmed block required for native proving".into());
    };
    Ok(NativeExecutionContext {
        block_id: NativeBlockId::Number {
            block_number: block.block_number,
        },
        l1_gas_price: native_gas_price_bound(block.l1_gas_price.price_in_fri)?,
        l2_gas_price: native_gas_price_bound(block.l2_gas_price.price_in_fri)?,
        l1_data_gas_price: native_gas_price_bound(block.l1_data_gas_price.price_in_fri)?,
    })
}

fn native_gas_price_bound(price: Felt) -> Result<u128, String> {
    let hex = format!("{price:#x}");
    let base = u128::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|error| format!("gas price {hex} does not fit in u128: {error}"))?;
    Ok(base
        .saturating_mul(NATIVE_GAS_PRICE_MULTIPLIER_NUMERATOR)
        / NATIVE_GAS_PRICE_MULTIPLIER_DENOMINATOR)
}

async fn submit_native_plan_onchain(
    state: &AppState,
    settlement_plan: &SettlementSubmissionPlan,
    proof_artifact: &ProofArtifactRecord,
) -> Result<OnchainSubmissionRecord, String> {
    let executor = state
        .starknet_executor
        .clone()
        .ok_or_else(|| "starknet executor is not configured".to_string())?;
    let request_path = proof_artifact
        .native_execution_request_path
        .as_ref()
        .ok_or_else(|| "native execution request path missing".to_string())?;
    let proof_path = proof_artifact
        .native_proof_file_path
        .as_ref()
        .ok_or_else(|| "native proof path missing".to_string())?;
    let proof_facts_path = proof_artifact
        .native_proof_facts_file_path
        .as_ref()
        .ok_or_else(|| "native proof facts path missing".to_string())?;

    let mut native_request: NativeExecutionRequestRecord =
        serde_json::from_str(&fs::read_to_string(request_path).map_err(|error| {
            format!("failed to read native execution request {request_path}: {error}")
        })?)
        .map_err(|error| format!("failed to parse native execution request: {error}"))?;
    let proof = fs::read_to_string(proof_path)
        .map_err(|error| format!("failed to read native proof {proof_path}: {error}"))?;
    let proof_facts: Vec<String> =
        serde_json::from_str(&fs::read_to_string(proof_facts_path).map_err(|error| {
            format!("failed to read native proof facts {proof_facts_path}: {error}")
        })?)
        .map_err(|error| format!("failed to parse native proof facts: {error}"))?;

    let transaction = native_request
        .transaction
        .as_object_mut()
        .ok_or_else(|| "native execution request is not a JSON object".to_string())?;
    transaction.insert(
        "proof".into(),
        serde_json::Value::String(proof.trim().to_string()),
    );
    transaction.insert(
        "proof_facts".into(),
        serde_json::to_value(&proof_facts)
            .map_err(|error| format!("failed to serialize proof facts: {error}"))?,
    );

    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "starknet_addInvokeTransaction",
        "params": {
            "invoke_transaction": native_request.transaction,
        },
    });
    let rpc_url = Url::parse(&executor.rpc_url)
        .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?;
    let response_value: serde_json::Value = state
        .http_client
        .post(rpc_url)
        .json(&rpc_request)
        .send()
        .await
        .map_err(|error| format!("native invoke submission failed: {error}"))?
        .json()
        .await
        .map_err(|error| format!("native invoke response decode failed: {error}"))?;
    if let Some(error) = response_value.get("error") {
        return Err(format!("native invoke rejected: {error}"));
    }
    let tx_hash = response_value
        .get("result")
        .and_then(|result| result.get("transaction_hash"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!("native invoke response missing transaction hash: {response_value}")
        })?
        .to_string();
    let settlement_contract_address = settlement_plan.settlement_call.contract_address.clone();
    let batch_id = settlement_plan.batch_id.clone();
    let submission_id = format!("{}:{}", batch_id.0, tx_hash);

    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(&executor.rpc_url)
            .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?,
    ));
    let mut submission = OnchainSubmissionRecord {
        submission_id,
        batch_id,
        transaction_hash: tx_hash.clone(),
        submitted_at_unix_ms: now_unix_ms(),
        receipt_checked_at_unix_ms: None,
        confirmed_at_unix_ms: None,
        finality_status: None,
        execution_status: None,
        revert_reason: None,
        block_number: None,
        block_hash: None,
        submission_mode: "native-proof-facts".into(),
        settlement_contract_address,
    };

    populate_submission_receipt_status(
        &mut submission,
        wait_for_receipt(&provider, parse_felt(&tx_hash, "transaction hash")?).await,
    );

    Ok(submission)
}

async fn refresh_submission_status(
    state: &AppState,
    mut submission: OnchainSubmissionRecord,
) -> Result<OnchainSubmissionRecord, String> {
    let executor = state
        .starknet_executor
        .clone()
        .ok_or_else(|| "starknet executor is not configured".to_string())?;
    let rpc_url = Url::parse(&executor.rpc_url)
        .map_err(|error| format!("invalid ZYLITH_STARKNET_RPC_URL: {error}"))?;
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
    let tx_hash = parse_felt(&submission.transaction_hash, "transaction hash")?;

    populate_submission_receipt_status(&mut submission, wait_for_receipt(&provider, tx_hash).await);

    Ok(submission)
}

async fn wait_for_receipt(
    provider: &JsonRpcClient<HttpTransport>,
    tx_hash: Felt,
) -> Option<TransactionReceiptWithBlockInfo> {
    for attempt in 0..DEFAULT_RECEIPT_POLL_ATTEMPTS {
        match provider.get_transaction_receipt(tx_hash).await {
            Ok(receipt) => return Some(receipt),
            Err(_) if attempt + 1 < DEFAULT_RECEIPT_POLL_ATTEMPTS => {
                sleep(Duration::from_millis(DEFAULT_RECEIPT_POLL_INTERVAL_MS)).await;
            }
            Err(_) => return None,
        }
    }

    None
}

async fn wait_for_accepted_receipt(
    provider: &JsonRpcClient<HttpTransport>,
    tx_hash: Felt,
) -> Option<TransactionReceiptWithBlockInfo> {
    for attempt in 0..DEFAULT_RECEIPT_POLL_ATTEMPTS {
        match provider.get_transaction_receipt(tx_hash).await {
            Ok(receipt) => {
                if matches!(
                    receipt.receipt.finality_status(),
                    TransactionFinalityStatus::AcceptedOnL1
                        | TransactionFinalityStatus::AcceptedOnL2
                ) {
                    return Some(receipt);
                }
                if matches!(receipt.receipt.execution_result(), ExecutionResult::Reverted { .. }) {
                    return Some(receipt);
                }
            }
            Err(_) if attempt + 1 == DEFAULT_RECEIPT_POLL_ATTEMPTS => return None,
            Err(_) => {}
        }
        sleep(Duration::from_millis(DEFAULT_RECEIPT_POLL_INTERVAL_MS)).await;
    }

    None
}

fn populate_submission_receipt_status(
    submission: &mut OnchainSubmissionRecord,
    receipt: Option<TransactionReceiptWithBlockInfo>,
) {
    submission.receipt_checked_at_unix_ms = Some(now_unix_ms());

    let Some(receipt) = receipt else {
        return;
    };

    submission.finality_status = Some(format_finality_status(receipt.receipt.finality_status()));
    submission.execution_status = Some(format_execution_result(receipt.receipt.execution_result()));
    submission.revert_reason = receipt
        .receipt
        .execution_result()
        .revert_reason()
        .map(str::to_owned);
    submission.block_number = Some(receipt.block.block_number());
    submission.block_hash = receipt
        .block
        .block_hash()
        .map(|value| format!("{value:#x}"));

    if matches!(
        receipt.receipt.finality_status(),
        TransactionFinalityStatus::AcceptedOnL1 | TransactionFinalityStatus::AcceptedOnL2
    ) {
        submission.confirmed_at_unix_ms = Some(now_unix_ms());
    }
}

fn format_finality_status(status: &TransactionFinalityStatus) -> String {
    match status {
        TransactionFinalityStatus::PreConfirmed => "PRE_CONFIRMED".into(),
        TransactionFinalityStatus::AcceptedOnL2 => "ACCEPTED_ON_L2".into(),
        TransactionFinalityStatus::AcceptedOnL1 => "ACCEPTED_ON_L1".into(),
    }
}

fn format_execution_result(result: &ExecutionResult) -> String {
    match result {
        ExecutionResult::Succeeded => "SUCCEEDED".into(),
        ExecutionResult::Reverted { .. } => "REVERTED".into(),
    }
}

fn starknet_call_to_call(call: &StarknetCall) -> Result<Call, String> {
    Ok(Call {
        to: parse_felt(&call.contract_address, "contract address")?,
        selector: get_selector_from_name(&call.entrypoint)
            .map_err(|error| format!("missing selector for {}: {error}", call.entrypoint))?,
        calldata: call
            .calldata
            .iter()
            .map(|value| parse_felt(value, "calldata felt"))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn build_proof_friendly_signature(
    executor: &StarknetExecutorConfig,
    settlement_call: &StarknetCall,
    invoke_request: &BroadcastedInvokeTransactionV3,
) -> Result<[String; 2], String> {
    let selector = get_selector_from_name(&settlement_call.entrypoint).map_err(|error| {
        format!(
            "missing selector for {}: {error}",
            settlement_call.entrypoint
        )
    })?;
    let message_hash = proof_friendly_account_message_hash(
        &executor.account_address,
        &executor.chain_id,
        &format!("{:#x}", invoke_request.nonce),
        &settlement_call.contract_address,
        &format!("{selector:#x}"),
        &settlement_call.calldata,
    )
    .map_err(|error| format!("failed to compute proof-friendly account hash: {error}"))?;
    let signing_key = SigningKey::from_secret_scalar(parse_felt(
        &executor.private_key,
        "ZYLITH_STARKNET_PRIVATE_KEY",
    )?);
    let signature = signing_key
        .sign(&parse_felt(&message_hash, "proof-friendly account hash")?)
        .map_err(|error| format!("failed to sign proof-friendly account hash: {error}"))?;

    Ok([format!("{:#x}", signature.r), format!("{:#x}", signature.s)])
}

fn insert_signature_into_invoke_request(
    transaction: &mut serde_json::Value,
    signature: &[String; 2],
) {
    if let Some(transaction) = transaction.as_object_mut() {
        transaction.insert(
            "signature".into(),
            serde_json::json!([signature[0], signature[1]]),
        );
    }
}

fn parse_felt(value: &str, label: &str) -> Result<Felt, String> {
    Felt::from_hex(value).map_err(|error| format!("invalid {label} {value}: {error}"))
}

fn ensure_prover_dirs(data_dir: &FsPath) {
    for subdir in [
        PROOF_JOBS_DIR,
        SETTLEMENT_PLANS_DIR,
        SETTLEMENT_WITNESSES_DIR,
        PROOF_ARTIFACTS_DIR,
        ONCHAIN_SUBMISSIONS_DIR,
        PROOF_OUTPUTS_DIR,
        PUBLIC_INPUTS_DIR,
        PROVER_LOGS_DIR,
    ] {
        let path = data_dir.join(subdir);
        if let Err(error) = fs::create_dir_all(&path) {
            panic!(
                "failed to create prover directory {}: {error}",
                path.display()
            );
        }
    }
}

fn load_json_records<T, F>(data_dir: &FsPath, subdir: &str, key_fn: F) -> BTreeMap<String, T>
where
    T: DeserializeOwned,
    F: Fn(&T) -> String,
{
    let directory = data_dir.join(subdir);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(_) => return BTreeMap::new(),
    };

    let mut records = BTreeMap::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }

        match fs::read_to_string(&path)
            .ok()
            .and_then(|body| serde_json::from_str::<T>(&body).ok())
        {
            Some(record) => {
                records.insert(key_fn(&record), record);
            }
            None => {
                eprintln!("Skipping invalid prover record at {}", path.display());
            }
        }
    }

    records
}

fn persist_record<T: Serialize>(
    data_dir: &FsPath,
    subdir: &str,
    batch_id: &str,
    value: &T,
) -> Result<(), StatusCode> {
    let path = record_path(data_dir, subdir, batch_id);
    persist_json_file(&path, value)
}

fn delete_record_if_exists(
    data_dir: &FsPath,
    subdir: &str,
    batch_id: &str,
) -> Result<(), StatusCode> {
    let path = record_path(data_dir, subdir, batch_id);
    if path.exists() {
        fs::remove_file(&path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(())
}

fn persist_json_file<T: Serialize>(path: &FsPath, value: &T) -> Result<(), StatusCode> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let body = serde_json::to_vec_pretty(value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    fs::write(path, body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn delete_execution_outputs_if_exist(data_dir: &FsPath, batch_id: &str) -> Result<(), StatusCode> {
    let paths = proof_execution_paths(data_dir, batch_id);
    for path in [
        paths.proof_path,
        paths.public_inputs_path,
        paths.native_execution_request_path,
        paths.stdout_path,
        paths.stderr_path,
    ] {
        if path.exists() {
            fs::remove_file(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }
    Ok(())
}

fn proof_execution_paths(data_dir: &FsPath, batch_id: &str) -> ProofExecutionPaths {
    ProofExecutionPaths {
        witness_path: record_path(data_dir, SETTLEMENT_WITNESSES_DIR, batch_id),
        proof_path: record_path(data_dir, PROOF_OUTPUTS_DIR, batch_id),
        public_inputs_path: record_path(data_dir, PUBLIC_INPUTS_DIR, batch_id),
        native_execution_request_path: data_dir
            .join(PROOF_OUTPUTS_DIR)
            .join(format!("{}.native-request.json", storage_key(batch_id))),
        stdout_path: log_path(data_dir, batch_id, "stdout"),
        stderr_path: log_path(data_dir, batch_id, "stderr"),
    }
}

fn record_path(data_dir: &FsPath, subdir: &str, batch_id: &str) -> PathBuf {
    data_dir
        .join(subdir)
        .join(format!("{}.json", storage_key(batch_id)))
}

fn log_path(data_dir: &FsPath, batch_id: &str, suffix: &str) -> PathBuf {
    data_dir
        .join(PROVER_LOGS_DIR)
        .join(format!("{}.{}.log", storage_key(batch_id), suffix))
}

fn storage_key(batch_id: &str) -> String {
    batch_id
        .chars()
        .flat_map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                vec![character]
            } else {
                let encoded = format!("_{:x}_", character as u32);
                encoded.chars().collect::<Vec<_>>()
            }
        })
        .collect()
}

fn artifact_id_for(batch_id: &str, transcript_commitment: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zylith/proof-artifact");
    hasher.update(batch_id.as_bytes());
    hasher.update(transcript_commitment.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Clone, Debug, Deserialize)]
struct ScarbStatusLine {
    status: String,
    message: String,
}

fn prover_backend_label(native_tx_prover_enabled: bool) -> String {
    if native_tx_prover_enabled {
        "starknet-transaction-prover".into()
    } else {
        "stwo-scarb".into()
    }
}

fn build_stwo_prove_command(
    scarb_bin: &str,
    manifest_path: &FsPath,
    package_name: &str,
    arguments_file: &FsPath,
) -> Command {
    let mut command = Command::new(scarb_bin);
    command
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("prove")
        .arg("-p")
        .arg(package_name)
        .arg("--execute")
        .arg("--arguments-file")
        .arg(arguments_file)
        .arg("--json");
    if let Some(workdir) = manifest_path.parent() {
        command.current_dir(workdir);
    }
    command
}

fn build_stwo_verify_command(
    scarb_bin: &str,
    manifest_path: &FsPath,
    proof_file: &FsPath,
) -> Command {
    let mut command = Command::new(scarb_bin);
    command
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("verify")
        .arg("--proof-file")
        .arg(proof_file)
        .arg("--json");
    if let Some(workdir) = manifest_path.parent() {
        command.current_dir(workdir);
    }
    command
}

fn parse_scarb_status_lines(stdout: &str) -> Vec<ScarbStatusLine> {
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<ScarbStatusLine>(line).ok())
        .collect()
}

fn extract_proof_path(lines: &[ScarbStatusLine]) -> Option<String> {
    lines.iter().find_map(|line| {
        if line.status == "saving proof to:" {
            Some(line.message.clone())
        } else {
            None
        }
    })
}

fn resolve_proof_path(workdir: &FsPath, proof_path: &str) -> PathBuf {
    let candidate = PathBuf::from(proof_path);
    if candidate.is_absolute() {
        candidate
    } else {
        workdir.join(candidate)
    }
}

fn status_to_error(status: StatusCode) -> String {
    format!("internal prover storage error: {status}")
}

fn sha256_file_hex(path: &FsPath) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift before unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::{artifact_id_for, insert_signature_into_invoke_request, storage_key};

    #[test]
    fn storage_key_sanitizes_non_alphanumeric_batch_ids() {
        assert_eq!(
            storage_key("batch/strk usdc:1"),
            "batch_2f_strk_20_usdc_3a_1"
        );
        assert_eq!(storage_key("batch-strk-usdc-1"), "batch-strk-usdc-1");
    }

    #[test]
    fn artifact_ids_are_deterministic_and_transcript_bound() {
        let a = artifact_id_for("batch-strk-usdc-1", "0xabc");
        let b = artifact_id_for("batch-strk-usdc-1", "0xabc");
        let c = artifact_id_for("batch-strk-usdc-1", "0xdef");

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn insert_signature_overwrites_transaction_signature_field() {
        let mut transaction = serde_json::json!({
            "sender_address": "0x123",
            "signature": ["0x0", "0x0"]
        });

        insert_signature_into_invoke_request(&mut transaction, &["0x111".into(), "0x222".into()]);

        assert_eq!(
            transaction["signature"],
            serde_json::json!(["0x111", "0x222"])
        );
    }
}

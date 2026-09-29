//! snip-36 control plane: freeze a complete proving request into the durable queue, validate the
//! returned proof against its pinned job, then submit the exchange call carrying that proof.
//!
//! the proof-only request is an invoke from the proof account against a block
//! `proving_blocks_back` behind the tip (starknet exposes a block's hash only after a delay); the
//! statements read no chain state, so the base block's age costs nothing.
//!
//! privacy boundary: stwo proofs are not zero knowledge. the proof travels on the broadcast
//! invoke only (stored transactions keep the proof facts, not the proof), so it reaches the
//! disposable workers and the gateway and sequencer that verify the proof see the witness, and a
//! holder may learn linear information from its trace openings. those workers are trusted for
//! confidentiality but hold no state or authority; sequencer privacy remains an assumption until
//! a zero-knowledge proving mode exists.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use starknet_rust_accounts::{
    Account as _, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount,
};
use starknet_rust_core::types::{
    BlockId, BlockTag, BroadcastedInvokeTransaction, Call, ExecuteInvocation, ExecutionResult,
    Felt, FunctionCall, MaybePreConfirmedBlockWithTxHashes, TransactionFinalityStatus,
    TransactionReceipt, TransactionReceiptWithBlockInfo, TransactionTrace,
};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::Provider;
use starknet_rust_providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust_signers::{LocalWallet, SigningKey};
use tokio::sync::Mutex;
use tokio::time::sleep;
use zylith_proof_job::{
    EnqueueProofJob, PROOF_JOB_SCHEMA_VERSION, PROOF_VALIDITY_HEADROOM_BLOCKS, ProofJobDescriptor,
    ProofJobState, ProofJobStatus, ProofStatementKind, proof_artifact_hash,
};

use crate::config::{Account, Config};

const PROOF_ONLY_L2_GAS: u64 = 10_000_000_000;
const PROOF_ONLY_L1_GAS: u64 = 1_000;
const PROOF_ONLY_L1_DATA_GAS: u64 = 8_000;
const SUBMIT_L1_GAS_FLOOR: u64 = 1_000;
const SUBMIT_L1_DATA_GAS_FLOOR: u64 = 8_000;
const SUBMIT_L2_GAS_FLOOR: u64 = 150_000_000;
const MAX_PROVER_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const PROOF_JOB_POLL_MS: u64 = 200;
const RECEIPT_POLL_ATTEMPTS: usize = 60;
const RECEIPT_POLL_INTERVAL_MS: u64 = 500;
const SUBMIT_ATTEMPTS: usize = 8;
const SUBMIT_RETRY_MS: u64 = 1_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum BlockRef {
    Number { block_number: u64 },
}

#[derive(Serialize)]
struct ProveRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: (BlockRef, serde_json::Value),
}

/// a proof and the facts the proof-bearing invoke carries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub proof: String,
    pub facts: Vec<Felt>,
}

/// one exact signed transaction, persisted before its first broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedSubmission {
    pub expected_hash: Felt,
    pub request: BroadcastedInvokeTransaction,
}

/// the canonical statement identity the control plane binds to one durable proof job.
#[derive(Clone, Debug)]
pub struct ProofJobContext {
    pub statement_kind: ProofStatementKind,
    pub transition_id: String,
    pub epoch_id: Option<u64>,
    pub exchange_address: String,
    pub input_state_root: Option<String>,
    pub expected_output_state_root: Option<String>,
    pub statement_commitment: String,
    pub witness_hash: String,
    pub program_entrypoint: String,
}

/// what a simulated transaction would do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Simulation {
    pub reverted: Option<String>,
    pub l2_gas: u64,
    /// fri.
    pub fee: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Outcome {
    /// `fee` is the actual fee paid, in fri.
    Accepted {
        block_number: u64,
        fee: u128,
    },
    Reverted {
        reason: String,
    },
}

pub struct Snip36 {
    pub provider: Arc<JsonRpcClient<HttpTransport>>,
    http: Client,
    chain_id: Felt,
    settlement: Account,
    proof_account: Account,
    proof_queue_url: String,
    proof_queue_control_token: String,
    prover_build_id: String,
    protocol_version: String,
    config_version: String,
    proof_version: String,
    virtual_program_hash: String,
    starknet_os_config_hash: String,
    proof_validity_blocks: u64,
    timeout: Duration,
    blocks_back: u64,
    /// one submission at a time from the settlement account, so nonces never collide.
    submit_lock: Mutex<()>,
}

pub fn call(to: Felt, entrypoint: &str, calldata: Vec<Felt>) -> Call {
    Call {
        to,
        selector: get_selector_from_name(entrypoint).expect("entrypoint names are ascii"),
        calldata,
    }
}

/// what proving and submission need, apart from the rest of the operator's configuration.
pub struct Snip36Config {
    pub rpc_url: url::Url,
    pub chain_id: Felt,
    pub settlement: Account,
    pub proof_account: Account,
    pub proof_queue_url: String,
    pub proof_queue_control_token: String,
    pub prover_build_id: String,
    pub protocol_version: String,
    pub config_version: String,
    pub proof_version: String,
    pub virtual_program_hash: String,
    pub starknet_os_config_hash: String,
    pub proof_validity_blocks: u64,
    pub timeout_seconds: u64,
    pub blocks_back: u64,
}

impl Snip36 {
    pub fn new(config: &Config) -> Self {
        Self::from_parts(Snip36Config {
            rpc_url: config.rpc_url.clone(),
            chain_id: config.chain_id,
            settlement: config.settlement.clone(),
            proof_account: config.proof_account.clone(),
            proof_queue_url: config.proof_queue_url.clone(),
            proof_queue_control_token: config.proof_queue_control_token.clone(),
            prover_build_id: config.prover_build_id.clone(),
            protocol_version: "zylith-v1".into(),
            config_version: config.manifest.deployment.release_commit.clone(),
            proof_version: config.manifest.proof.proof_version.clone(),
            virtual_program_hash: config.manifest.proof.virtual_program_hash.clone(),
            starknet_os_config_hash: config.manifest.proof.starknet_os_config_hash.clone(),
            proof_validity_blocks: config.manifest.proof.proof_validity_blocks,
            timeout_seconds: config.proof_job_timeout_seconds,
            blocks_back: config.proving_blocks_back,
        })
    }

    pub fn from_parts(config: Snip36Config) -> Self {
        Self {
            provider: Arc::new(JsonRpcClient::new(HttpTransport::new(config.rpc_url))),
            http: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .expect("http client"),
            chain_id: config.chain_id,
            settlement: config.settlement,
            proof_account: config.proof_account,
            proof_queue_url: config.proof_queue_url.trim_end_matches('/').to_owned(),
            proof_queue_control_token: config.proof_queue_control_token,
            prover_build_id: config.prover_build_id,
            protocol_version: config.protocol_version,
            config_version: config.config_version,
            proof_version: config.proof_version,
            virtual_program_hash: config.virtual_program_hash,
            starknet_os_config_hash: config.starknet_os_config_hash,
            proof_validity_blocks: config.proof_validity_blocks,
            timeout: Duration::from_secs(config.timeout_seconds),
            blocks_back: config.blocks_back,
            submit_lock: Mutex::new(()),
        }
    }

    fn account(
        &self,
        account: &Account,
    ) -> SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet> {
        SingleOwnerAccount::new(
            self.provider.clone(),
            LocalWallet::from(SigningKey::from_secret_scalar(account.private_key)),
            account.address,
            self.chain_id,
            ExecutionEncoding::New,
        )
    }

    pub async fn latest_block(&self) -> Result<(u64, [u128; 3]), String> {
        let block = self
            .provider
            .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
            .await
            .map_err(|error| format!("latest block: {error}"))?;
        let (number, prices) = match block {
            MaybePreConfirmedBlockWithTxHashes::Block(block) => (
                block.block_number,
                [
                    block.l1_gas_price.price_in_fri,
                    block.l2_gas_price.price_in_fri,
                    block.l1_data_gas_price.price_in_fri,
                ],
            ),
            MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(block) => (
                block.block_number,
                [
                    block.l1_gas_price.price_in_fri,
                    block.l2_gas_price.price_in_fri,
                    block.l1_data_gas_price.price_in_fri,
                ],
            ),
        };
        let bound = |price: Felt| -> Result<u128, String> {
            let price: u128 = price
                .try_into()
                .map_err(|_| "gas price exceeds u128".to_string())?;
            Ok(price.saturating_mul(3) / 2)
        };
        Ok((
            number,
            [bound(prices[0])?, bound(prices[1])?, bound(prices[2])?],
        ))
    }

    /// enqueues one immutable proving request and returns only a result bound to that job.
    pub async fn prove(
        &self,
        calls: Vec<Call>,
        expected_message: Felt,
        context: ProofJobContext,
    ) -> Result<Proof, String> {
        self.prove_checked(calls, Some(expected_message), context)
            .await
    }

    /// proves through the durable queue; a timeout leaves the job recoverable and retryable.
    pub async fn prove_checked(
        &self,
        calls: Vec<Call>,
        expected_message: Option<Felt>,
        context: ProofJobContext,
    ) -> Result<Proof, String> {
        let [program_call] = calls.as_slice() else {
            return Err("a proof job must contain exactly one proof-program call".into());
        };
        let expected_selector = get_selector_from_name(&context.program_entrypoint)
            .map_err(|error| format!("proof entrypoint: {error}"))?;
        if program_call.selector != expected_selector {
            return Err("the proof job entrypoint does not match its program call".into());
        }
        let mut descriptor = ProofJobDescriptor {
            schema_version: PROOF_JOB_SCHEMA_VERSION,
            job_id: String::new(),
            statement_kind: context.statement_kind,
            transition_id: context.transition_id,
            epoch_id: context.epoch_id,
            protocol_version: self.protocol_version.clone(),
            config_version: self.config_version.clone(),
            prover_build_id: self.prover_build_id.clone(),
            chain_id: format!("{:#x}", self.chain_id),
            exchange_address: context.exchange_address,
            proof_program_address: format!("{:#x}", program_call.to),
            program_entrypoint: context.program_entrypoint,
            proof_version: self.proof_version.clone(),
            program_variant: "VIRTUAL_SNOS".into(),
            virtual_program_hash: self.virtual_program_hash.clone(),
            starknet_os_output_version: "VIRTUAL_SNOS0".into(),
            starknet_os_config_hash: self.starknet_os_config_hash.clone(),
            base_block_number: 0,
            base_block_hash: "0x0".into(),
            input_state_root: context.input_state_root,
            expected_output_state_root: context.expected_output_state_root,
            statement_commitment: context.statement_commitment,
            expected_message: expected_message.map(|value| format!("{value:#x}")),
            witness_hash: context.witness_hash,
            request_hash: "0".repeat(64),
            request_bytes: 1,
            created_at_unix_ms: now_ms(),
        };
        descriptor.job_id = descriptor.expected_job_id()?;
        let (latest, _) = self.latest_block().await?;
        if let Some(status) = self.queue_status(&descriptor.job_id).await?
            && latest.saturating_add(PROOF_VALIDITY_HEADROOM_BLOCKS)
                <= status
                    .descriptor
                    .base_block_number
                    .saturating_add(self.proof_validity_blocks)
        {
            return self.await_job(descriptor, status, expected_message).await;
        }
        let base = latest.saturating_sub(self.blocks_back);
        let base_hash = self.block_hash(base).await?;
        let mut account = self.account(&self.proof_account);
        account.set_block_id(BlockId::Number(base));
        let nonce = account
            .get_nonce()
            .await
            .map_err(|error| format!("proof account nonce: {error}"))?;
        let request = account
            .execute_v3(calls)
            .nonce(nonce)
            .l1_gas(PROOF_ONLY_L1_GAS)
            .l1_gas_price(0)
            .l2_gas(PROOF_ONLY_L2_GAS)
            .l2_gas_price(0)
            .l1_data_gas(PROOF_ONLY_L1_DATA_GAS)
            .l1_data_gas_price(0)
            .tip(0)
            .prepared()
            .map_err(|_| "failed to prepare the proving request".to_string())?
            .get_invoke_request(false, false)
            .await
            .map_err(|error| format!("proving request: {error}"))?;
        let request = ProveRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "starknet_proveTransaction",
            params: (
                BlockRef::Number { block_number: base },
                serde_json::to_value(&request)
                    .map_err(|error| format!("proving request encode: {error}"))?,
            ),
        };
        let request = serde_json::to_value(request)
            .map_err(|error| format!("proving request encode: {error}"))?;
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|error| format!("proving request encode: {error}"))?;
        descriptor.base_block_number = base;
        descriptor.base_block_hash = format!("{base_hash:#x}");
        descriptor.request_hash = proof_artifact_hash(&request_bytes);
        descriptor.request_bytes = request_bytes.len() as u64;
        descriptor.validate()?;
        let response = self
            .http
            .post(format!("{}/internal/proof-jobs", self.proof_queue_url))
            .header(
                "x-zylith-proof-control-token",
                &self.proof_queue_control_token,
            )
            .json(&EnqueueProofJob {
                descriptor: descriptor.clone(),
                request,
            })
            .send()
            .await
            .map_err(|error| retryable(format!("enqueue failed: {error}")))?;
        let status_code = response.status();
        if status_code == reqwest::StatusCode::CONFLICT {
            let status = self
                .queue_status(&descriptor.job_id)
                .await?
                .ok_or_else(|| {
                    "proof queue reported a conflict without the existing job".to_string()
                })?;
            return self.await_job(descriptor, status, expected_message).await;
        }
        if !status_code.is_success() {
            let body = read_bounded(response, 4096).await.unwrap_or_default();
            return Err(format!(
                "proof queue rejected job with {status_code}: {}",
                sanitize(&String::from_utf8_lossy(&body))
            ));
        }
        let bytes = read_bounded(response, MAX_PROVER_RESPONSE_BYTES).await?;
        let status: ProofJobStatus = serde_json::from_slice(&bytes)
            .map_err(|error| format!("proof queue response: {error}"))?;
        self.await_job(descriptor, status, expected_message).await
    }

    async fn await_job(
        &self,
        expected: ProofJobDescriptor,
        mut status: ProofJobStatus,
        expected_message: Option<Felt>,
    ) -> Result<Proof, String> {
        let wait = async {
            loop {
                verify_job_identity(&expected, &status.descriptor)?;
                if status.state == ProofJobState::Complete {
                    let proof = proof_from_status(status, expected_message)?;
                    // the proof is self-contained after validation; consume the private witness
                    // artifact immediately instead of waiting for retention cleanup.
                    let _ = self.delete_job(&expected.job_id).await;
                    return Ok(proof);
                }
                sleep(Duration::from_millis(PROOF_JOB_POLL_MS)).await;
                status = self
                    .queue_status(&expected.job_id)
                    .await?
                    .ok_or_else(|| "proof queue lost an enqueued job".to_string())?;
            }
        };
        tokio::time::timeout(self.timeout, wait)
            .await
            .map_err(|_| {
                retryable(format!(
                    "job {} is still pending after {}s",
                    expected.job_id,
                    self.timeout.as_secs()
                ))
            })?
    }

    async fn queue_status(&self, job_id: &str) -> Result<Option<ProofJobStatus>, String> {
        let response = self
            .http
            .get(format!(
                "{}/internal/proof-jobs/{job_id}",
                self.proof_queue_url
            ))
            .header(
                "x-zylith-proof-control-token",
                &self.proof_queue_control_token,
            )
            .send()
            .await
            .map_err(|error| retryable(format!("status failed: {error}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(retryable(format!(
                "status returned http {}",
                response.status()
            )));
        }
        let bytes = read_bounded(response, MAX_PROVER_RESPONSE_BYTES)
            .await
            .map_err(retryable)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("proof queue status: {error}"))
    }

    async fn delete_job(&self, job_id: &str) -> Result<(), String> {
        let response = self
            .http
            .delete(format!(
                "{}/internal/proof-jobs/{job_id}",
                self.proof_queue_url
            ))
            .header(
                "x-zylith-proof-control-token",
                &self.proof_queue_control_token,
            )
            .send()
            .await
            .map_err(|error| format!("proof job delete: {error}"))?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(format!(
                "proof job delete returned http {}",
                response.status()
            ))
        }
    }

    /// submits calls from the settlement account, optionally carrying a proof, and returns the
    /// transaction hash.
    pub async fn submit(&self, calls: Vec<Call>, proof: Option<&Proof>) -> Result<Felt, String> {
        self.submit_with_gas(calls, proof, None).await
    }

    /// submits with an l2 gas bound from a simulation, or a conservative one when there is none.
    pub async fn submit_with_gas(
        &self,
        calls: Vec<Call>,
        proof: Option<&Proof>,
        simulated_l2_gas: Option<u64>,
    ) -> Result<Felt, String> {
        self.submit_with_gas_durable(calls, proof, simulated_l2_gas, None, |_| async { Ok(()) })
            .await
    }

    /// persists the exact signed transaction before its first broadcast. an existing journaled
    /// transaction is rebroadcast byte-for-byte and ignores the reconstruction arguments.
    pub async fn submit_with_gas_durable<F, Fut>(
        &self,
        calls: Vec<Call>,
        proof: Option<&Proof>,
        simulated_l2_gas: Option<u64>,
        existing: Option<PreparedSubmission>,
        persist: F,
    ) -> Result<Felt, String>
    where
        F: FnOnce(PreparedSubmission) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let _guard = self.submit_lock.lock().await;
        if let Some(prepared) = existing {
            return self.broadcast_prepared(&prepared).await;
        }
        // the proof's fixed charge plus room for execution, storage and every calldata felt.
        let calldata_felts: u64 = calls
            .iter()
            .map(|call| call.calldata.len() as u64 + 3)
            .sum();
        let l2_gas = simulated_l2_gas
            .map(|gas| gas + gas / 4)
            .unwrap_or(SUBMIT_L2_GAS_FLOOR + calldata_felts * 20_000);
        // prepare and sign exactly once. retrying a freshly prepared transaction could change
        // its nonce or resource prices after an ambiguous gateway response, creating two valid
        // transactions for one logical transition.
        let (_, [l1_price, l2_price, l1_data_price]) = self.latest_block().await?;
        let mut account = self.account(&self.settlement);
        account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
        let nonce = account
            .get_nonce()
            .await
            .map_err(|error| format!("settlement nonce: {error}"))?;
        let mut execution = account
            .execute_v3(calls)
            .nonce(nonce)
            .l1_gas(SUBMIT_L1_GAS_FLOOR)
            .l1_gas_price(l1_price)
            .l2_gas(l2_gas)
            .l2_gas_price(l2_price)
            .l1_data_gas(SUBMIT_L1_DATA_GAS_FLOOR)
            .l1_data_gas_price(l1_data_price)
            .tip(0);
        if let Some(proof) = proof {
            execution = execution
                .proof(proof.proof.clone())
                .proof_facts(proof.facts.clone());
        }
        let prepared = execution
            .prepared()
            .map_err(|_| "failed to prepare the submission".to_string())?;
        let expected_hash = prepared.transaction_hash(false);
        let request = prepared
            .get_invoke_request(false, false)
            .await
            .map_err(|error| format!("submission: {error}"))?;
        let prepared = PreparedSubmission {
            expected_hash,
            request,
        };
        persist(prepared.clone()).await?;
        self.broadcast_prepared(&prepared).await
    }

    async fn broadcast_prepared(&self, prepared: &PreparedSubmission) -> Result<Felt, String> {
        if self.receipt(prepared.expected_hash).await.is_some() {
            return Ok(prepared.expected_hash);
        }
        let mut last_error = String::new();
        for attempt in 1..=SUBMIT_ATTEMPTS {
            match self
                .provider
                .add_invoke_transaction(&prepared.request)
                .await
            {
                Ok(result) if result.transaction_hash == prepared.expected_hash => {
                    return Ok(result.transaction_hash);
                }
                Ok(_) => {
                    return Err("gateway returned the wrong settlement transaction hash".into());
                }
                Err(error) => {
                    let message = error.to_string();
                    let lower = message.to_lowercase();
                    if lower.contains("already") && lower.contains("exist") {
                        return Ok(prepared.expected_hash);
                    }
                    let retryable = lower.contains("nonce")
                        || lower.contains("too recent")
                        || lower.contains("timed out")
                        || lower.contains("503")
                        || lower.contains("502")
                        || lower.contains("429");
                    last_error = sanitize(&message);
                    if !retryable || attempt == SUBMIT_ATTEMPTS {
                        break;
                    }
                    sleep(Duration::from_millis(SUBMIT_RETRY_MS * attempt as u64)).await;
                }
            }
        }
        Err(format!("submission rejected: {last_error}"))
    }

    /// executes the calls from the settlement account against the pre-confirmed state without
    /// sending them: whether they would revert, and the l2 gas and fee they would use.
    pub async fn simulate(
        &self,
        calls: Vec<Call>,
        proof: Option<&Proof>,
    ) -> Result<Simulation, String> {
        let (_, [l1_price, l2_price, l1_data_price]) = self.latest_block().await?;
        let mut account = self.account(&self.settlement);
        account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
        let mut execution = account
            .execute_v3(calls)
            .l1_gas(SUBMIT_L1_GAS_FLOOR)
            .l1_gas_price(l1_price)
            .l2_gas(PROOF_ONLY_L2_GAS)
            .l2_gas_price(l2_price)
            .l1_data_gas(SUBMIT_L1_DATA_GAS_FLOOR)
            .l1_data_gas_price(l1_data_price)
            .tip(0);
        if let Some(proof) = proof {
            execution = execution
                .proof(proof.proof.clone())
                .proof_facts(proof.facts.clone());
        }
        let simulated = execution
            .simulate(false, true)
            .await
            .map_err(|error| format!("simulation: {}", sanitize(&error.to_string())))?;
        let reverted = match &simulated.transaction_trace {
            TransactionTrace::Invoke(trace) => match &trace.execute_invocation {
                ExecuteInvocation::Success(_) => None,
                ExecuteInvocation::Reverted(reverted) => Some(sanitize(&reverted.revert_reason)),
            },
            _ => Some("the simulation did not trace an invoke".into()),
        };
        Ok(Simulation {
            reverted,
            l2_gas: simulated.fee_estimation.l2_gas_consumed,
            fee: simulated.fee_estimation.overall_fee,
        })
    }

    /// the current l2 gas price, in fri.
    pub async fn l2_gas_price(&self) -> Result<u128, String> {
        Ok(self.latest_block().await?.1[1])
    }

    pub async fn block_hash(&self, number: u64) -> Result<Felt, String> {
        match self
            .provider
            .get_block_with_tx_hashes(BlockId::Number(number))
            .await
            .map_err(|error| format!("block {number}: {error}"))?
        {
            MaybePreConfirmedBlockWithTxHashes::Block(block) => Ok(block.block_hash),
            MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(_) => {
                Err(format!("block {number} is not accepted yet"))
            }
        }
    }

    pub async fn receipt(&self, hash: Felt) -> Option<Outcome> {
        self.provider
            .get_transaction_receipt(hash)
            .await
            .ok()
            .and_then(|receipt| outcome_of(&receipt))
    }

    /// waits until the transaction is accepted or reverted; nothing if it never appears.
    pub async fn wait(&self, hash: Felt) -> Option<Outcome> {
        for _ in 0..RECEIPT_POLL_ATTEMPTS {
            if let Ok(receipt) = self.provider.get_transaction_receipt(hash).await
                && let Some(outcome) = outcome_of(&receipt)
            {
                return Some(outcome);
            }
            sleep(Duration::from_millis(RECEIPT_POLL_INTERVAL_MS)).await;
        }
        None
    }

    pub async fn view(
        &self,
        contract: Felt,
        entrypoint: &str,
        calldata: Vec<Felt>,
    ) -> Result<Vec<Felt>, String> {
        self.view_at(
            contract,
            entrypoint,
            calldata,
            BlockId::Tag(BlockTag::PreConfirmed),
        )
        .await
    }

    pub async fn view_at(
        &self,
        contract: Felt,
        entrypoint: &str,
        calldata: Vec<Felt>,
        block: BlockId,
    ) -> Result<Vec<Felt>, String> {
        self.provider
            .call(
                FunctionCall {
                    contract_address: contract,
                    entry_point_selector: get_selector_from_name(entrypoint)
                        .expect("entrypoint names are ascii"),
                    calldata,
                },
                block,
            )
            .await
            .map_err(|error| format!("{entrypoint}: {error}"))
    }
}

fn outcome_of(receipt: &TransactionReceiptWithBlockInfo) -> Option<Outcome> {
    if let ExecutionResult::Reverted { reason } = receipt.receipt.execution_result() {
        return Some(Outcome::Reverted {
            reason: sanitize(reason),
        });
    }
    match receipt.receipt.finality_status() {
        TransactionFinalityStatus::AcceptedOnL2 | TransactionFinalityStatus::AcceptedOnL1 => {
            let fee = match &receipt.receipt {
                TransactionReceipt::Invoke(invoke) => {
                    u128::try_from(invoke.actual_fee.amount).unwrap_or(u128::MAX)
                }
                _ => 0,
            };
            Some(Outcome::Accepted {
                block_number: receipt.block.block_number(),
                fee,
            })
        }
        TransactionFinalityStatus::PreConfirmed => None,
    }
}

fn verify_job_identity(
    expected: &ProofJobDescriptor,
    actual: &ProofJobDescriptor,
) -> Result<(), String> {
    actual.validate()?;
    if expected.job_id != actual.job_id || actual.expected_job_id()? != actual.job_id {
        return Err("proof queue returned a different logical job".into());
    }
    Ok(())
}

fn proof_from_status(
    status: ProofJobStatus,
    expected_message: Option<Felt>,
) -> Result<Proof, String> {
    let result = status
        .result
        .ok_or_else(|| "completed proof job has no result".to_string())?;
    if result.proof.trim().is_empty() {
        return Err("completed proof job has an empty proof".into());
    }
    let facts = result
        .proof_facts
        .iter()
        .map(|value| Felt::from_hex(value).map_err(|_| "proof fact is not a felt".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let pinned_version = protocol_felt(&status.descriptor.proof_version, "proof version")?;
    let pinned_variant = protocol_felt(&status.descriptor.program_variant, "program variant")?;
    let pinned_program = Felt::from_hex(&status.descriptor.virtual_program_hash)
        .map_err(|_| "pinned virtual program hash is not a felt".to_string())?;
    let pinned_output = protocol_felt(
        &status.descriptor.starknet_os_output_version,
        "os output version",
    )?;
    let pinned_base_hash = Felt::from_hex(&status.descriptor.base_block_hash)
        .map_err(|_| "pinned base block hash is not a felt".to_string())?;
    let pinned_os = Felt::from_hex(&status.descriptor.starknet_os_config_hash)
        .map_err(|_| "pinned os config hash is not a felt".to_string())?;
    if facts.len() != 9
        || facts[0] != pinned_version
        || facts[1] != pinned_variant
        || facts[2] != pinned_program
        || facts[3] != pinned_output
        || facts[4] != Felt::from(status.descriptor.base_block_number)
        || facts[5] != pinned_base_hash
        || facts[6] != pinned_os
        || facts[7] != Felt::ONE
        || expected_message.is_some_and(|expected| facts[8] != expected)
    {
        return Err("proof facts do not match the expected job".into());
    }
    Ok(Proof {
        proof: result.proof.trim().to_owned(),
        facts,
    })
}

fn retryable(message: impl Into<String>) -> String {
    format!("retryable proof queue: {}", message.into())
}

fn protocol_felt(value: &str, label: &str) -> Result<Felt, String> {
    if value.starts_with("0x") {
        return Felt::from_hex(value).map_err(|_| format!("pinned {label} is not a felt"));
    }
    if value.is_empty() || value.len() > 31 || !value.is_ascii() {
        return Err(format!("pinned {label} is not a felt or short string"));
    }
    Ok(Felt::from_bytes_be_slice(value.as_bytes()))
}

pub fn is_retryable_proving_error(error: &str) -> bool {
    error.starts_with("retryable proof queue:")
}

pub fn canonical_witness_hash(witness: &[Felt]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zylith/proof-job/witness/v1:");
    hasher.update((witness.len() as u64).to_be_bytes());
    for value in witness {
        hasher.update(value.to_bytes_be());
    }
    hex::encode(hasher.finalize())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as u64
}

async fn read_bounded(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(format!("response exceeds {max_bytes} bytes"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("response read: {error}"))?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(format!("response exceeds {max_bytes} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// long hex and decimal runs are replaced so errors never echo witness data.
pub fn sanitize(value: &str) -> String {
    let mut output = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, output: &mut String| {
        if run.len() >= 32 {
            output.push_str("<felt>");
        } else {
            output.push_str(run);
        }
        run.clear();
    };
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            run.push(character);
        } else {
            flush(&mut run, &mut output);
            output.push(character);
        }
    }
    flush(&mut run, &mut output);
    output.chars().take(512).collect()
}

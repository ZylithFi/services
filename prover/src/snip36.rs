//! snip-36: prove a proof-program call with the starknet transaction prover, then submit the
//! exchange call carrying that proof and its proof facts.
//!
//! the proof-only request is an invoke from the proof account against a block
//! `proving_blocks_back` behind the tip (starknet exposes a block's hash only after a delay); the
//! statements read no chain state, so the base block's age costs nothing.
//!
//! privacy boundary: stwo proofs are not zero knowledge. the proof travels on the broadcast
//! invoke only (stored transactions keep the proof facts, not the proof), so it reaches the
//! operator's own transaction prover and the gateway and sequencer that verify it, and a holder
//! may learn linear information about the witness from its trace openings. privacy against the
//! sequencer is therefore an assumption until a zero-knowledge proving mode exists.

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use starknet_rust_accounts::{
    Account as _, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount,
};
use starknet_rust_core::types::{
    BlockId, BlockTag, Call, ExecuteInvocation, ExecutionResult, Felt, FunctionCall,
    MaybePreConfirmedBlockWithTxHashes, TransactionFinalityStatus, TransactionReceipt,
    TransactionReceiptWithBlockInfo, TransactionTrace,
};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::Provider;
use starknet_rust_providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust_signers::{LocalWallet, SigningKey};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::config::{Account, Config};

const PROOF_ONLY_L2_GAS: u64 = 10_000_000_000;
const PROOF_ONLY_L1_GAS: u64 = 1_000;
const PROOF_ONLY_L1_DATA_GAS: u64 = 8_000;
const SUBMIT_L1_GAS_FLOOR: u64 = 1_000;
const SUBMIT_L1_DATA_GAS_FLOOR: u64 = 8_000;
const SUBMIT_L2_GAS_FLOOR: u64 = 150_000_000;
const MAX_PROVER_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OHTTP_KEY_CONFIG_BYTES: usize = 4096;
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

#[derive(Deserialize)]
struct ProveResponse {
    result: Option<ProveResult>,
    error: Option<ProveError>,
}

#[derive(Deserialize)]
struct ProveResult {
    proof: String,
    proof_facts: Vec<String>,
}

#[derive(Deserialize)]
struct ProveError {
    code: i64,
    message: String,
}

/// a proof and the facts the proof-bearing invoke carries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub proof: String,
    pub facts: Vec<Felt>,
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
    tx_provers: Vec<String>,
    next_prover: AtomicUsize,
    ohttp_key_config: Option<Vec<u8>>,
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
    pub tx_provers: Vec<String>,
    pub ohttp_key_config: Option<Vec<u8>>,
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
            tx_provers: config.tx_provers.clone(),
            ohttp_key_config: config.tx_prover_ohttp_key_config.clone(),
            timeout_seconds: config.tx_prover_timeout_seconds,
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
            tx_provers: config.tx_provers,
            next_prover: AtomicUsize::new(0),
            ohttp_key_config: config.ohttp_key_config,
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

    /// proves one proof-program call and returns the proof with facts carrying `expected_message`.
    pub async fn prove(&self, calls: Vec<Call>, expected_message: Felt) -> Result<Proof, String> {
        self.prove_checked(calls, Some(expected_message)).await
    }

    /// proves one proof-program call; without an expected message only the facts' shape is checked.
    pub async fn prove_checked(
        &self,
        calls: Vec<Call>,
        expected_message: Option<Felt>,
    ) -> Result<Proof, String> {
        let (latest, _) = self.latest_block().await?;
        let base = latest.saturating_sub(self.blocks_back);
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
        let prover = &self.tx_provers
            [self.next_prover.fetch_add(1, Ordering::Relaxed) % self.tx_provers.len()];
        let response = tokio::time::timeout(self.timeout, self.send(prover, &request))
            .await
            .map_err(|_| {
                format!(
                    "transaction prover timed out after {}s",
                    self.timeout.as_secs()
                )
            })??;
        let response: ProveResponse = serde_json::from_slice(&response)
            .map_err(|error| format!("prover response: {error}"))?;
        let result = match (response.result, response.error) {
            (Some(result), None) => result,
            (_, Some(error)) => {
                return Err(format!(
                    "transaction prover error {}: {}",
                    error.code,
                    sanitize(&error.message)
                ));
            }
            _ => return Err("transaction prover returned no result".into()),
        };
        let facts = result
            .proof_facts
            .iter()
            .map(|value| Felt::from_hex(value).map_err(|_| "proof fact is not a felt".to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        // `[version, variant, program hash, output version, base block, base hash, os config,
        // message count, messages..]`: exactly the one statement message.
        if facts.len() != 9
            || facts[7] != Felt::ONE
            || expected_message.is_some_and(|expected| facts[8] != expected)
        {
            return Err("proof facts do not carry the expected statement message".into());
        }
        Ok(Proof {
            proof: result.proof.trim().to_owned(),
            facts,
        })
    }

    async fn send(&self, prover: &str, request: &ProveRequest<'_>) -> Result<Vec<u8>, String> {
        let body =
            serde_json::to_vec(request).map_err(|error| format!("prover request: {error}"))?;
        let Some(pinned) = &self.ohttp_key_config else {
            let response = self
                .http
                .post(prover)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|error| format!("transaction prover request: {error}"))?;
            return read_bounded(response, MAX_PROVER_RESPONSE_BYTES).await;
        };
        let key_config = if pinned.is_empty() {
            self.fetch_ohttp_keys(prover).await?
        } else {
            pinned.clone()
        };
        let client = ohttp::ClientRequest::from_encoded_config_list(&key_config)
            .map_err(|error| format!("ohttp key config: {error}"))?;
        let mut message = bhttp::Message::request(
            b"POST".to_vec(),
            b"https".to_vec(),
            b"ohttp-target.invalid".to_vec(),
            b"/".to_vec(),
        );
        message.put_header(b"content-type".to_vec(), b"application/json".to_vec());
        message.write_content(&body);
        let mut encoded = Vec::new();
        message
            .write_bhttp(bhttp::Mode::KnownLength, &mut encoded)
            .map_err(|error| format!("bhttp: {error}"))?;
        let (encrypted, context) = client
            .encapsulate(&encoded)
            .map_err(|error| format!("ohttp encapsulation: {error}"))?;
        let response = self
            .http
            .post(prover)
            .header("content-type", "message/ohttp-req")
            .body(encrypted)
            .send()
            .await
            .map_err(|error| format!("transaction prover ohttp request: {error}"))?;
        let bytes = read_bounded(response, MAX_PROVER_RESPONSE_BYTES).await?;
        let decrypted = context
            .decapsulate(&bytes)
            .map_err(|error| format!("ohttp decapsulation: {error}"))?;
        let message = bhttp::Message::read_bhttp(&mut Cursor::new(decrypted))
            .map_err(|error| format!("bhttp decode: {error}"))?;
        let status = message
            .control()
            .status()
            .map(|status| status.code())
            .unwrap_or(0);
        if status != 200 {
            return Err(format!(
                "transaction prover returned http {status}: {}",
                sanitize(&String::from_utf8_lossy(message.content()))
            ));
        }
        Ok(message.content().to_vec())
    }

    async fn fetch_ohttp_keys(&self, prover: &str) -> Result<Vec<u8>, String> {
        let response = self
            .http
            .get(format!("{}/ohttp-keys", prover.trim_end_matches('/')))
            .send()
            .await
            .map_err(|error| format!("ohttp key fetch: {error}"))?;
        read_bounded(response, MAX_OHTTP_KEY_CONFIG_BYTES).await
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
        // the proof's fixed charge plus room for execution, storage and every calldata felt.
        let calldata_felts: u64 = calls
            .iter()
            .map(|call| call.calldata.len() as u64 + 3)
            .sum();
        let l2_gas = simulated_l2_gas
            .map(|gas| gas + gas / 4)
            .unwrap_or(SUBMIT_L2_GAS_FLOOR + calldata_felts * 20_000);
        let _guard = self.submit_lock.lock().await;
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
        let mut last_error = String::new();
        for attempt in 1..=SUBMIT_ATTEMPTS {
            match account.provider().add_invoke_transaction(&request).await {
                Ok(result) => return Ok(result.transaction_hash),
                Err(error) => {
                    let message = error.to_string();
                    let lower = message.to_lowercase();
                    if lower.contains("already") && lower.contains("exist") {
                        return Ok(expected_hash);
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

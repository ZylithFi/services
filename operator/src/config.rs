//! the operator's configuration: the signed deployment manifest plus the secrets and service
//! endpoints that stay out of it.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use starknet_rust_core::types::Felt;
use url::Url;
use zeroize::Zeroizing;
use zylith_core::hash::felt_from_hex_str;
use zylith_core::{
    DeploymentManifest, PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig,
    PrivateExecutionKeyRegistry, validate_private_execution_keys,
};
use zylith_proof_job::{
    ProofCapacityProfile, ProofReleaseIdentity, ProofStatementKind,
    RESIDUAL_RECOVERY_STATEMENT_VERSION, STARKNET_OS_OUTPUT_VERSION, TRANSITION_STATEMENT_VERSION,
    VIRTUAL_PROGRAM_VARIANT, WITHDRAWAL_STATEMENT_VERSION,
};

pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3200";
pub const DEFAULT_DATA_DIR: &str = "data/operator";
const MAX_MANIFEST_BYTES: u64 = 1 << 20;
const MAX_CAPACITY_PROFILE_BYTES: u64 = 1 << 20;

#[derive(Clone)]
pub struct Account {
    pub address: Felt,
    pub private_key: Felt,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Account")
            .field("address", &self.address)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// one tradable pair as the exchange sees it.
#[derive(Clone, Debug)]
pub struct PairRuntime {
    pub name: String,
    pub base_name: String,
    pub quote_name: String,
    pub pair_id: Felt,
    pub base_asset_id: Felt,
    pub quote_asset_id: Felt,
    pub scale: u128,
    pub fee_bps: u128,
    pub reference_methodology: u8,
    pub derivation_base_market_id: Felt,
    pub derivation_quote_market_id: Felt,
    pub max_leg_skew_ms: u64,
    pub external_enabled: bool,
    /// quote atoms every permissionless fill pays onchain for settlement and a possible freeze.
    pub external_settlement_support_quote: u128,
    /// the smallest order the operator admits, in base atoms.
    pub min_order_amount: u128,
    /// the smallest limit-valued order the operator admits, in quote atoms.
    pub min_order_quote_amount: u128,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub epoch_ms: u64,
    /// how long before the boundary cutoff establishment and price sampling begin.
    pub epoch_prepare_ms: u64,
    /// how many transitions may be in flight (proving or submitted) ahead of the chain.
    pub pipeline_depth: usize,
    pub max_admissions: usize,
    pub max_book_orders: usize,
    pub max_pending_orders: usize,
    pub max_order_lifetime_ms: u64,
    /// conservative statement-only step guard used to trim early. This does not represent full
    /// SNIP-36/STWO capacity; the release-bound proof capacity profile is authoritative.
    pub step_budget: u64,
    /// a cancellation, expiry or pending outcome forces a transition after waiting this long.
    pub force_after_ms: u64,
    /// the longest a crossing waits for its fees to cover a transition before the reserve pays.
    pub uneconomic_max_wait_ms: u64,
    pub max_close_delay_ms: u64,
    pub external_window_seconds: u64,
}

#[derive(Clone)]
pub struct Config {
    pub bind_addr: String,
    pub data_dir: PathBuf,
    /// how deep a block must be before its events or a transition's receipt are folded in.
    pub confirmation_blocks: u64,
    /// a directory on another volume that keeps a replica of the sealed state.
    pub replica_dir: Option<PathBuf>,
    pub data_key: [u8; 32],
    pub manifest: DeploymentManifest,
    pub rpc_url: Url,
    pub chain_id: Felt,
    pub exchange: Felt,
    pub transition_proof_program: Felt,
    pub withdrawal_proof_program: Felt,
    pub residual_recovery_proof_program: Felt,
    pub router: Felt,
    pub settlement: Account,
    pub proof_account: Account,
    pub proof_queue_url: String,
    pub proof_queue_control_token: String,
    pub prover_build_id: String,
    /// Full-SNOS, release-bound capacity evidence. Statement-step estimates remain only an
    /// early, conservative trimming guard and never authorize a proof by themselves.
    pub proof_capacity_profiles: BTreeMap<ProofStatementKind, ProofCapacityProfile>,
    pub proof_job_timeout_seconds: u64,
    pub proving_blocks_back: u64,
    pub attestor_url: String,
    pub attestor_token: String,
    pub route_service_url: Option<String>,
    /// the margin a searcher leg must clear beyond its gas, per quote asset, in its atoms.
    pub searcher_min_profit: BTreeMap<Felt, u128>,
    pub searcher_headroom_bps: u128,
    /// the secret that blinds fee notes; the fee recipient needs it to recover and spend them.
    pub fee_key: Felt,
    /// the registry-selected gas asset id, the unit gas is paid and valued in.
    pub gas_fee_asset: Felt,
    /// the fixed objective numeraire; every enabled asset needs a direct observation against it.
    pub objective_numeraire_asset: Felt,
    /// the l2 gas a transition costs until landed transitions teach a better estimate.
    pub transition_gas_estimate: u64,
    /// the l2 gas a searcher leg adds, by its route's shape.
    pub leg_gas: crate::market::LegGas,
    /// the share of a transition's cost its fees must cover, in percent.
    pub fee_cover_percent: u64,
    /// the least a transition's fees must be worth, in strk atoms, whatever gas costs.
    pub min_transition_fee_strk: u128,
    /// fee notes are valued at attested rates less this haircut, in basis points.
    pub fee_rate_haircut_bps: u128,
    pub execution_keys: Vec<PrivateExecutionKeyPrivateConfig>,
    pub active_execution_key_id: String,
    pub fee_recipient: Felt,
    pub reference_price_signer: Felt,
    pub pairs: Vec<PairRuntime>,
    pub policy: Policy,
    pub control_token: String,
    pub allowed_origins: Vec<String>,
    pub private_rate_limit_per_minute: u32,
    pub trusted_proxies: Vec<ipnet::IpNet>,
    pub max_body_bytes: usize,
    pub sync_from_block: u64,
}

fn canonical_felt(value: &str, label: &str) -> Result<String, String> {
    Ok(format!("{:#x}", nonzero(value, label)?))
}

fn proof_program_class_hash<'a>(
    manifest: &'a DeploymentManifest,
    kind: &ProofStatementKind,
) -> &'a str {
    match kind {
        ProofStatementKind::Transition => &manifest.proof.transition_proof_program_class_hash,
        ProofStatementKind::Withdrawal => &manifest.proof.withdrawal_proof_program_class_hash,
        ProofStatementKind::ResidualRecovery => {
            &manifest.proof.residual_recovery_proof_program_class_hash
        }
        ProofStatementKind::Benchmark => "",
    }
}

fn statement_version(kind: &ProofStatementKind) -> Result<&'static str, String> {
    match kind {
        ProofStatementKind::Transition => Ok(TRANSITION_STATEMENT_VERSION),
        ProofStatementKind::Withdrawal => Ok(WITHDRAWAL_STATEMENT_VERSION),
        ProofStatementKind::ResidualRecovery => Ok(RESIDUAL_RECOVERY_STATEMENT_VERSION),
        ProofStatementKind::Benchmark => {
            Err("benchmark statements cannot have a production capacity profile".into())
        }
    }
}

fn expected_capacity_identity(
    manifest: &DeploymentManifest,
    kind: &ProofStatementKind,
) -> Result<ProofReleaseIdentity, String> {
    Ok(ProofReleaseIdentity {
        release_commit: manifest.deployment.release_commit.clone(),
        prover_build_id: manifest.proof.prover_build_id.clone(),
        proof_version: manifest.proof.proof_version.clone(),
        program_variant: VIRTUAL_PROGRAM_VARIANT.into(),
        virtual_program_hash: canonical_felt(
            &manifest.proof.virtual_program_hash,
            "manifest virtual program hash",
        )?,
        starknet_os_output_version: STARKNET_OS_OUTPUT_VERSION.into(),
        starknet_os_config_hash: canonical_felt(
            &manifest.proof.starknet_os_config_hash,
            "manifest starknet os config hash",
        )?,
        proof_account_class_hash: canonical_felt(
            &manifest.proof.proof_account_class_hash,
            "manifest proof account class hash",
        )?,
        proof_program_class_hash: canonical_felt(
            proof_program_class_hash(manifest, kind),
            "manifest proof program class hash",
        )?,
        statement_version: statement_version(kind)?.into(),
    })
}

fn parse_capacity_profile(
    raw: &str,
    expected_kind: ProofStatementKind,
    expected_identity: &ProofReleaseIdentity,
) -> Result<ProofCapacityProfile, String> {
    let profile: ProofCapacityProfile = serde_json::from_str(raw)
        .map_err(|error| format!("proof capacity profile schema: {error}"))?;
    if profile.statement_kind != expected_kind {
        return Err("proof capacity profile statement kind does not match its file".into());
    }
    profile.validate_identity(expected_identity)?;
    Ok(profile)
}

fn load_capacity_profiles(
    directory: &str,
    manifest: &DeploymentManifest,
) -> Result<BTreeMap<ProofStatementKind, ProofCapacityProfile>, String> {
    let directory = PathBuf::from(directory);
    let mut profiles = BTreeMap::new();
    for (kind, filename) in [
        (ProofStatementKind::Transition, "transition.json"),
        (ProofStatementKind::Withdrawal, "withdrawal.json"),
        (
            ProofStatementKind::ResidualRecovery,
            "residual_recovery.json",
        ),
    ] {
        let path = directory.join(filename);
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("proof capacity profile {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.len() > MAX_CAPACITY_PROFILE_BYTES {
            return Err(format!(
                "proof capacity profile {} must be a regular file no larger than {} bytes",
                path.display(),
                MAX_CAPACITY_PROFILE_BYTES
            ));
        }
        let raw = fs::read_to_string(&path)
            .map_err(|error| format!("proof capacity profile {}: {error}", path.display()))?;
        let identity = expected_capacity_identity(manifest, &kind)?;
        let profile = parse_capacity_profile(&raw, kind.clone(), &identity)
            .map_err(|error| format!("proof capacity profile {}: {error}", path.display()))?;
        profiles.insert(kind, profile);
    }
    Ok(profiles)
}

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn parsed<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match optional(name) {
        Some(value) => value
            .trim()
            .parse()
            .map_err(|_| format!("{name} is invalid")),
        None => Ok(default),
    }
}

pub fn felt(value: &str, label: &str) -> Result<Felt, String> {
    Felt::from_hex(value.trim()).map_err(|error| format!("{label} is not a felt: {error}"))
}

/// a starknet chain id as manifests write it: the hex felt (`0x534e5f5345504f4c4941`) or the short
/// string it encodes (sn_sepolia in capitals).
pub fn chain_id(value: &str) -> Result<Felt, String> {
    let value = value.trim();
    if value.starts_with("0x") {
        return nonzero(value, "chain id");
    }
    if value.is_empty() || value.len() > 31 || !value.is_ascii() {
        return Err(format!(
            "chain id {value} is neither a felt nor a short string"
        ));
    }
    Ok(Felt::from_bytes_be_slice(value.as_bytes()))
}

fn nonzero(value: &str, label: &str) -> Result<Felt, String> {
    let parsed = felt(value, label)?;
    if parsed == Felt::ZERO {
        return Err(format!("{label} cannot be zero"));
    }
    Ok(parsed)
}

/// the felt ids the contracts use for a named pair or asset.
pub fn pair_felt(name: &str) -> Felt {
    from_core(zylith_core::exchange::pair_id(name))
}

pub fn asset_felt(name: &str) -> Felt {
    from_core(zylith_core::exchange::asset_id(name))
}

fn core_felt(value: &str) -> Result<starknet_crypto::Felt, String> {
    felt_from_hex_str(value).map_err(|error| error.to_string())
}

pub fn load_manifest(path: &str) -> Result<DeploymentManifest, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("deployment manifest {path}: {error}"))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err("deployment manifest is too large".into());
    }
    let raw =
        fs::read_to_string(path).map_err(|error| format!("deployment manifest {path}: {error}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|error| format!("deployment manifest: {error}"))?;
    let manifest = value.get("manifest").cloned().unwrap_or(value);
    let manifest: DeploymentManifest = serde_json::from_value(manifest)
        .map_err(|error| format!("deployment manifest schema: {error}"))?;
    manifest.validate_market_registry()?;
    Ok(manifest)
}

pub(crate) fn load_execution_keys(
    path: &str,
    active_key_id: &str,
) -> Result<Vec<PrivateExecutionKeyPrivateConfig>, String> {
    let raw = Zeroizing::new(
        fs::read_to_string(path).map_err(|error| format!("execution keys {path}: {error}"))?,
    );
    let keys: Vec<PrivateExecutionKeyPrivateConfig> =
        serde_json::from_str(&raw).map_err(|error| format!("execution keys: {error}"))?;
    validate_private_execution_keys(&keys, active_key_id)
        .map_err(|error| format!("execution keys: {error}"))?;
    Ok(keys)
}

pub(crate) fn active_execution_registry(
    keys: &[PrivateExecutionKeyPrivateConfig],
    active_key_id: &str,
) -> Result<PrivateExecutionKeyRegistry, String> {
    validate_private_execution_keys(keys, active_key_id)
        .map_err(|error| format!("execution keys: {error}"))?;
    let active = keys
        .iter()
        .find(|key| key.key_id == active_key_id)
        .ok_or("active execution key id is absent")?;
    Ok(PrivateExecutionKeyRegistry {
        keys: vec![PrivateExecutionKeyPublicConfig {
            key_id: active.key_id.clone(),
            algorithm: active.algorithm.clone(),
            public_key: active.public_key.clone(),
        }],
    })
}

fn validate_execution_rotation(
    keys: &[PrivateExecutionKeyPrivateConfig],
    active_key_id: &str,
    pins: &[&str],
) -> Result<(), String> {
    active_execution_registry(keys, active_key_id)?;
    if pins.is_empty()
        || pins.len() > 2
        || pins.len() != keys.len()
        || pins.iter().any(|pin| {
            pin.len() != 64
                || !pin
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || pin.bytes().all(|byte| byte == b'0')
        })
        || pins.len() == 2 && pins[0] == pins[1]
    {
        return Err(
            "manifest execution key fingerprints must be one or two distinct canonical pins".into(),
        );
    }
    for key in keys {
        let registry = active_execution_registry(keys, &key.key_id)?;
        let fingerprint = registry.fingerprint().map_err(|error| error.to_string())?;
        if !pins.contains(&fingerprint.as_str()) {
            return Err(format!(
                "execution key {} (fingerprint {fingerprint}) is not pinned by the manifest",
                key.key_id
            ));
        }
    }
    Ok(())
}

fn data_key() -> Result<[u8; 32], String> {
    let hex = required("ZYLITH_OPERATOR_DATA_KEY_HEX")?;
    let bytes = hex::decode(hex.trim())
        .map_err(|_| "ZYLITH_OPERATOR_DATA_KEY_HEX is not hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "ZYLITH_OPERATOR_DATA_KEY_HEX must be 32 bytes".to_string())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let manifest_path = optional("ZYLITH_DEPLOYMENT_MANIFEST")
            .unwrap_or_else(|| "client/public/deployment.json".into());
        let manifest = load_manifest(&manifest_path)?;
        manifest.validate_production()?;
        if manifest.proof.proof_validity_blocks <= zylith_proof_job::PROOF_VALIDITY_HEADROOM_BLOCKS
        {
            return Err("proof validity must leave submission headroom after proving".into());
        }
        if manifest.deployment.release_commit.len() != 40
            || !manifest
                .deployment
                .release_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || manifest
                .deployment
                .release_commit
                .bytes()
                .all(|byte| byte == b'0')
        {
            return Err("the deployment manifest has no released commit".into());
        }
        let rpc_url = Url::parse(
            &optional("ZYLITH_STARKNET_RPC_URL").unwrap_or_else(|| manifest.rpc_url.clone()),
        )
        .map_err(|error| format!("starknet rpc url: {error}"))?;
        let chain_id = chain_id(&manifest.chain_id)?;
        let step_budget = parsed("ZYLITH_STEP_BUDGET", 700_000_u64)?;
        let settlement = Account {
            address: nonzero(
                &required("ZYLITH_STARKNET_ACCOUNT_ADDRESS")?,
                "settlement account",
            )?,
            private_key: nonzero(&required("ZYLITH_STARKNET_PRIVATE_KEY")?, "settlement key")?,
        };
        if settlement.address
            != felt(
                &manifest.proof.settlement_account_address,
                "manifest settlement account",
            )?
        {
            return Err("the settlement account does not match the deployment manifest".into());
        }
        let proof_account = Account {
            address: nonzero(
                &optional("ZYLITH_PROOF_ACCOUNT_ADDRESS")
                    .unwrap_or_else(|| manifest.proof.proof_account_address.clone()),
                "proof account",
            )?,
            private_key: nonzero(
                &required("ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY")?,
                "proof account key",
            )?,
        };
        if proof_account.address
            != felt(
                &manifest.proof.proof_account_address,
                "manifest proof account",
            )?
        {
            return Err("the proof account does not match the deployment manifest".into());
        }
        let proof_queue_url = required("ZYLITH_PROOF_QUEUE_URL")?;
        Url::parse(&proof_queue_url).map_err(|error| format!("proof queue url: {error}"))?;
        let prover_build_id = optional("ZYLITH_PROVER_BUILD_ID")
            .unwrap_or_else(|| manifest.proof.prover_build_id.clone());
        if prover_build_id != manifest.proof.prover_build_id
            || prover_build_id.trim().is_empty()
            || prover_build_id.len() > 256
        {
            return Err("the prover build id does not match the deployment manifest".into());
        }
        let proof_capacity_profiles =
            load_capacity_profiles(&required("ZYLITH_PROOF_CAPACITY_PROFILE_DIR")?, &manifest)?;

        for retired in [
            "ZYLITH_MIN_SETTLEMENT_FEES",
            "ZYLITH_SEARCHER_MIN_PROFIT_QUOTE",
            "ZYLITH_SEARCHER_MIN_PROFIT",
            "ZYLITH_MARKET_DATA_PAIRS",
            "ZYLITH_REFERENCE_PRICE_SOURCES_PATH",
            "ZYLITH_REFERENCE_PRICE_ATTESTATION_TTL_MS",
            "ZYLITH_PAIRS",
            "ZYLITH_TOKENS",
            "ZYLITH_EXTERNAL_PAIRS",
            "ZYLITH_PAIR_FEE_BPS",
            "ZYLITH_EXTERNAL_SETTLEMENT_SUPPORT_QUOTE",
            "ZYLITH_MAX_ADMISSIONS",
        ] {
            if optional(retired).is_some() {
                return Err(format!(
                    "{retired} is retired; use the canonical market registry"
                ));
            }
        }
        let mut pairs = Vec::new();
        let mut searcher_min_profit = BTreeMap::new();
        for pair in manifest.market_registry.enabled_markets() {
            let quote_asset_id = asset_felt(&pair.quote_asset_id.0);
            if pair.capabilities.external_matching
                && let Some(existing) = searcher_min_profit
                    .insert(quote_asset_id, pair.external_min_profit_quote)
                    .filter(|existing| *existing != pair.external_min_profit_quote)
            {
                return Err(format!(
                    "external markets sharing quote asset {} disagree on their minimum profit: {existing} and {}",
                    pair.quote_asset_id.0, pair.external_min_profit_quote
                ));
            }
            let (
                reference_methodology,
                derivation_base_market_id,
                derivation_quote_market_id,
                max_leg_skew_ms,
            ) = match &pair.reference_price {
                zylith_core::MarketReferencePrice::DirectBboMidpoint { .. } => (
                    zylith_core::exchange::REFERENCE_METHOD_DIRECT_BBO,
                    Felt::ZERO,
                    Felt::ZERO,
                    0,
                ),
                zylith_core::MarketReferencePrice::SyntheticCrossBboMidpoint {
                    base_market_id,
                    quote_market_id,
                    max_leg_skew_ms,
                    ..
                } => (
                    zylith_core::exchange::REFERENCE_METHOD_SYNTHETIC_CROSS_BBO,
                    pair_felt(&base_market_id.0),
                    pair_felt(&quote_market_id.0),
                    *max_leg_skew_ms,
                ),
            };
            pairs.push(PairRuntime {
                name: pair.market_id.0.clone(),
                base_name: pair.base_asset_id.0.clone(),
                quote_name: pair.quote_asset_id.0.clone(),
                pair_id: pair_felt(&pair.market_id.0),
                base_asset_id: asset_felt(&pair.base_asset_id.0),
                quote_asset_id,
                scale: pair.price_base_scale,
                fee_bps: u128::from(pair.taker_fee_bps),
                reference_methodology,
                derivation_base_market_id,
                derivation_quote_market_id,
                max_leg_skew_ms,
                external_enabled: pair.capabilities.external_matching,
                external_settlement_support_quote: pair.external_settlement_support_quote,
                min_order_amount: pair.min_order_amount,
                min_order_quote_amount: pair.min_order_quote_amount,
            });
        }
        // tiny funded orders would crowd the book and the proofs: every pair needs a minimum.
        if let Some(pair) = pairs.iter().find(|pair| pair.min_order_amount == 0) {
            return Err(format!("pair {} has no minimum order amount", pair.name));
        }
        if let Some(pair) = pairs.iter().find(|pair| pair.min_order_quote_amount == 0) {
            return Err(format!(
                "pair {} has no minimum quote order amount",
                pair.name
            ));
        }
        if let Some(pair) = pairs
            .iter()
            .find(|pair| pair.external_enabled != (pair.external_settlement_support_quote != 0))
        {
            return Err(format!(
                "pair {} must configure nonzero external settlement support exactly when external matching is enabled",
                pair.name
            ));
        }
        if pairs.len() > zylith_core::exchange::MAX_MARKETS {
            return Err(format!(
                "{} enabled pairs exceed the protocol maximum of {}",
                pairs.len(),
                zylith_core::exchange::MAX_MARKETS
            ));
        }
        pairs.sort_by_key(|pair| pair.pair_id.to_bytes_be());
        let objective_numeraire_asset =
            asset_felt(&manifest.market_registry.objective_numeraire_asset_id.0);
        let enabled_assets = pairs
            .iter()
            .flat_map(|pair| [pair.base_asset_id, pair.quote_asset_id])
            .collect::<BTreeSet<_>>();
        for asset in enabled_assets {
            if asset != objective_numeraire_asset
                && !pairs.iter().any(|pair| {
                    (pair.base_asset_id == asset
                        && pair.quote_asset_id == objective_numeraire_asset)
                        || (pair.quote_asset_id == asset
                            && pair.base_asset_id == objective_numeraire_asset)
                })
            {
                return Err("every enabled asset needs a direct objective-numeraire market".into());
            }
        }

        let runtime = &manifest.runtime;
        if runtime.max_internal_deferral_epochs == 0 {
            return Err("runtime.max_internal_deferral_epochs must be positive".into());
        }
        let epoch_ms = parsed("ZYLITH_EPOCH_MS", runtime.epoch_ms)?;
        if epoch_ms != runtime.epoch_ms {
            return Err("ZYLITH_EPOCH_MS differs from the deployment manifest".into());
        }
        let pipeline_depth = parsed("ZYLITH_PIPELINE_DEPTH", 2_usize)?;
        if !(1..=4).contains(&pipeline_depth) {
            return Err("ZYLITH_PIPELINE_DEPTH must be in [1, 4]".into());
        }
        let proof_book_limit = zylith_core::exchange::StepShape::max_book_orders(step_budget);
        if runtime.max_book_orders as usize > proof_book_limit {
            return Err(format!(
                "runtime.max_book_orders exceeds the step budget limit of {proof_book_limit}"
            ));
        }
        let proof_admission_limit = zylith_core::exchange::StepShape::max_admissions(step_budget);
        if runtime.max_admissions_per_transition as usize > proof_admission_limit {
            return Err(format!(
                "runtime.max_admissions_per_transition exceeds the worst-case step budget limit of {proof_admission_limit}"
            ));
        }
        let transition_capacity = proof_capacity_profiles
            .get(&ProofStatementKind::Transition)
            .ok_or("transition proof capacity profile is missing")?;
        let max_book_orders = runtime.max_book_orders;
        let max_admissions = runtime.max_admissions_per_transition;
        let padded_outputs = (2 * max_book_orders + zylith_core::exchange::MAX_ASSETS as u64)
            .max(zylith_core::exchange::MIN_OUTPUT_BUCKET as u64)
            .next_power_of_two();
        let required_shape = zylith_proof_job::ProofShapeLimits {
            markets: pairs.len() as u64,
            resting_orders: max_book_orders,
            admissions: max_admissions,
            crossings: max_book_orders,
            outcomes: max_book_orders,
            nullifiers: (max_book_orders
                + zylith_core::exchange::MAX_FUNDING_NOTES as u64 * max_admissions)
                .max(zylith_core::exchange::MIN_NULLIFIER_BUCKET as u64),
            retired_nullifiers: max_book_orders,
            outputs: padded_outputs,
            funding_notes: zylith_core::exchange::MAX_FUNDING_NOTES as u64 * max_admissions,
            membership_path_elements: (zylith_core::exchange::MAX_FUNDING_NOTES
                * (zylith_core::exchange::NOTE_ACCUMULATOR_DEPTH
                    + zylith_core::exchange::MAX_OUTPUT_SUBTREE_DEPTH))
                as u64
                * max_admissions,
        };
        if !transition_capacity.limits.covers(&required_shape) {
            return Err(format!(
                "runtime limits exceed measured full-proof capacity profile {}",
                transition_capacity.profile_id
            ));
        }
        let membership_path_elements = (zylith_core::exchange::NOTE_ACCUMULATOR_DEPTH
            + zylith_core::exchange::MAX_OUTPUT_SUBTREE_DEPTH)
            as u64;
        let withdrawal_shape = zylith_proof_job::ProofShapeLimits {
            nullifiers: 1,
            funding_notes: 1,
            membership_path_elements,
            ..Default::default()
        };
        let withdrawal_capacity = proof_capacity_profiles
            .get(&ProofStatementKind::Withdrawal)
            .ok_or("withdrawal proof capacity profile is missing")?;
        if !withdrawal_capacity.limits.covers(&withdrawal_shape) {
            return Err(format!(
                "maximum withdrawal membership exceeds measured full-proof capacity profile {}",
                withdrawal_capacity.profile_id
            ));
        }
        let recovery_shape = zylith_proof_job::ProofShapeLimits {
            resting_orders: 1,
            outcomes: 1,
            nullifiers: 1,
            retired_nullifiers: 1,
            funding_notes: 1,
            membership_path_elements,
            ..Default::default()
        };
        let recovery_capacity = proof_capacity_profiles
            .get(&ProofStatementKind::ResidualRecovery)
            .ok_or("residual recovery proof capacity profile is missing")?;
        if !recovery_capacity.limits.covers(&recovery_shape) {
            return Err(format!(
                "maximum residual recovery membership exceeds measured full-proof capacity profile {}",
                recovery_capacity.profile_id
            ));
        }
        let policy = Policy {
            epoch_ms,
            epoch_prepare_ms: parsed(
                "ZYLITH_EPOCH_PREPARE_MS",
                3_000_u64.min(epoch_ms.saturating_sub(1)),
            )?,
            pipeline_depth,
            max_admissions: runtime.max_admissions_per_transition as usize,
            max_book_orders: runtime.max_book_orders as usize,
            max_pending_orders: runtime.max_book_orders as usize,
            max_order_lifetime_ms: zylith_core::exchange::MAX_ORDER_LIFETIME_MS,
            step_budget,
            force_after_ms: parsed("ZYLITH_FORCE_AFTER_MS", 60_000_u64)?,
            uneconomic_max_wait_ms: epoch_ms
                .checked_mul(runtime.max_internal_deferral_epochs)
                .ok_or("internal deferral duration overflows")?,
            max_close_delay_ms: runtime.max_close_delay_ms,
            external_window_seconds: runtime.external_window_seconds,
        };
        if policy.epoch_ms < 1_000 {
            return Err("the epoch must be at least one second".into());
        }
        if policy.epoch_prepare_ms == 0 || policy.epoch_prepare_ms >= policy.epoch_ms {
            return Err(
                "ZYLITH_EPOCH_PREPARE_MS must be positive and shorter than the epoch".into(),
            );
        }
        let proving_blocks_back = parsed("ZYLITH_PROVING_BLOCKS_BACK", 1_u64)?;
        if proving_blocks_back == 0
            || proving_blocks_back.saturating_add(zylith_proof_job::PROOF_VALIDITY_HEADROOM_BLOCKS)
                >= manifest.proof.proof_validity_blocks
        {
            return Err("the proof base leaves no validity window for submission".into());
        }

        let active_execution_key_id = required("ZYLITH_ACTIVE_EXECUTION_KEY_ID")?;
        let config = Self {
            bind_addr: optional("ZYLITH_OPERATOR_BIND_ADDR")
                .unwrap_or_else(|| DEFAULT_BIND_ADDR.into()),
            data_dir: PathBuf::from(
                optional("ZYLITH_OPERATOR_DATA_DIR").unwrap_or_else(|| DEFAULT_DATA_DIR.into()),
            ),
            replica_dir: optional("ZYLITH_OPERATOR_REPLICA_DIR").map(PathBuf::from),
            confirmation_blocks: parsed("ZYLITH_CONFIRMATION_BLOCKS", 2_u64)?,
            data_key: data_key()?,
            rpc_url,
            chain_id,
            exchange: nonzero(&manifest.contracts.exchange, "exchange")?,
            transition_proof_program: nonzero(
                &manifest.proof.transition_proof_program_address,
                "transition proof program",
            )?,
            withdrawal_proof_program: nonzero(
                &manifest.proof.withdrawal_proof_program_address,
                "withdrawal proof program",
            )?,
            residual_recovery_proof_program: nonzero(
                &manifest.proof.residual_recovery_proof_program_address,
                "residual recovery proof program",
            )?,
            router: felt(&manifest.contracts.ekubo_external_match_router, "router")?,
            settlement,
            proof_account,
            proof_queue_url,
            proof_queue_control_token: required("ZYLITH_PROOF_QUEUE_CONTROL_TOKEN")?,
            prover_build_id,
            proof_capacity_profiles,
            proof_job_timeout_seconds: parsed("ZYLITH_PROOF_JOB_TIMEOUT_SECONDS", 120_u64)?,
            proving_blocks_back,
            attestor_url: required("ZYLITH_REFERENCE_PRICE_ATTESTOR_URL")?,
            attestor_token: required("ZYLITH_REFERENCE_PRICE_ATTESTOR_TOKEN")?,
            route_service_url: optional("ZYLITH_ROUTE_SERVICE_URL"),
            searcher_min_profit,
            searcher_headroom_bps: parsed("ZYLITH_SEARCHER_HEADROOM_BPS", 5_u128)?,
            fee_key: nonzero(&required("ZYLITH_FEE_NOTE_KEY")?, "fee note key")?,
            gas_fee_asset: asset_felt(&manifest.market_registry.gas_fee_asset_id.0),
            objective_numeraire_asset,
            transition_gas_estimate: parsed("ZYLITH_TRANSITION_GAS_ESTIMATE", 250_000_000_u64)?,
            leg_gas: crate::market::LegGas {
                base: parsed("ZYLITH_EXTERNAL_LEG_GAS", 25_000_000_u64)?,
                per_split: parsed("ZYLITH_EXTERNAL_LEG_SPLIT_GAS", 6_000_000_u64)?,
                per_hop: parsed("ZYLITH_EXTERNAL_LEG_HOP_GAS", 8_000_000_u64)?,
            },
            fee_cover_percent: parsed("ZYLITH_FEE_COVER_PERCENT", 100_u64)?,
            min_transition_fee_strk: parsed("ZYLITH_MIN_TRANSITION_FEE_STRK", 0_u128)?,
            fee_rate_haircut_bps: parsed("ZYLITH_FEE_RATE_HAIRCUT_BPS", 100_u128)?,
            execution_keys: load_execution_keys(
                &required("ZYLITH_EXECUTION_KEYS_PATH")?,
                &active_execution_key_id,
            )?,
            active_execution_key_id,
            fee_recipient: nonzero(
                &manifest.roles.protocol_fee_recipient,
                "protocol fee recipient",
            )?,
            reference_price_signer: nonzero(
                &manifest.roles.reference_price_signer,
                "reference price signer",
            )?,
            pairs,
            policy,
            control_token: required("ZYLITH_CONTROL_PLANE_TOKEN")?,
            allowed_origins: optional("ZYLITH_OPERATOR_ALLOWED_ORIGINS")
                .map(|value| {
                    value
                        .split(',')
                        .map(|origin| origin.trim().to_owned())
                        .filter(|origin| !origin.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            private_rate_limit_per_minute: parsed("ZYLITH_PRIVATE_RATE_LIMIT_PER_MINUTE", 120_u32)?,
            trusted_proxies: optional("ZYLITH_TRUSTED_PROXY_CIDRS")
                .unwrap_or_else(|| "127.0.0.1/32,::1/128".into())
                .split(',')
                .map(|cidr| {
                    cidr.trim()
                        .parse()
                        .map_err(|_| format!("invalid proxy cidr {cidr}"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            max_body_bytes: parsed("ZYLITH_OPERATOR_MAX_BODY_BYTES", 256 * 1024_usize)?,
            sync_from_block: parsed("ZYLITH_SYNC_FROM_BLOCK", 0_u64)?,
            manifest,
        };
        config.check_external_matching()?;
        config.check_fee_solvency()?;
        config.check_pinned_execution_keys()?;
        // the wallet seals within the shared wire limits; a smaller body limit would refuse
        // requests the wallet builds.
        if config.execution_keys.len() > zylith_core::exchange::MAX_EXECUTION_KEYS {
            return Err(format!(
                "at most {} execution keys are supported",
                zylith_core::exchange::MAX_EXECUTION_KEYS
            ));
        }
        if config.max_body_bytes < zylith_core::exchange::MAX_SEALED_REQUEST_BYTES {
            return Err(format!(
                "ZYLITH_OPERATOR_MAX_BODY_BYTES must be at least {}",
                zylith_core::exchange::MAX_SEALED_REQUEST_BYTES
            ));
        }
        Ok(config)
    }

    /// fees pay for gas only if every fee asset has a price in strk and a transition has a floor:
    /// each traded asset must reach strk through at most two traded pairs, whose attested rates
    /// value its fee notes, and the floor must be positive.
    fn check_fee_solvency(&self) -> Result<(), String> {
        if self.min_transition_fee_strk == 0 {
            return Err("ZYLITH_MIN_TRANSITION_FEE_STRK must be positive".into());
        }
        if self.fee_rate_haircut_bps >= 10_000 {
            return Err("ZYLITH_FEE_RATE_HAIRCUT_BPS must be below 10000".into());
        }
        let neighbours = |asset: Felt| {
            self.pairs.iter().filter_map(move |pair| {
                (pair.base_asset_id == asset)
                    .then_some(pair.quote_asset_id)
                    .or((pair.quote_asset_id == asset).then_some(pair.base_asset_id))
            })
        };
        for pair in &self.pairs {
            for (asset, name) in [
                (pair.base_asset_id, &pair.base_name),
                (pair.quote_asset_id, &pair.quote_name),
            ] {
                let priced = asset == self.gas_fee_asset
                    || neighbours(asset).any(|middle| {
                        middle == self.gas_fee_asset
                            || neighbours(middle).any(|end| end == self.gas_fee_asset)
                    });
                if !priced {
                    return Err(format!(
                        "{name} fees cannot be valued: no traded pair connects it to STRK within two hops"
                    ));
                }
            }
        }
        Ok(())
    }

    /// wallets seal only to the registry the manifest pins, so serving any other would strand
    /// every order: the operator refuses to start with keys the manifest does not pin.
    fn check_pinned_execution_keys(&self) -> Result<(), String> {
        let pinned = self
            .manifest
            .funding
            .starknet_privacy
            .pinned_registry_fingerprints()?;
        validate_execution_rotation(&self.execution_keys, &self.active_execution_key_id, &pinned)
    }

    /// a pair that routes through ekubo needs every piece of the route: a quoter, the router, a
    /// positive margin and an on-chain window for the fill.
    fn check_external_matching(&self) -> Result<(), String> {
        let Some(pair) = self.pairs.iter().find(|pair| pair.external_enabled) else {
            if self.route_service_url.is_some()
                || self.router != Felt::ZERO
                || self.policy.external_window_seconds != 0
            {
                return Err(
                    "external routing is configured while every registry market disables it".into(),
                );
            }
            return Ok(());
        };
        let missing = if self.route_service_url.is_none() {
            "ZYLITH_ROUTE_SERVICE_URL"
        } else if self.router == Felt::ZERO {
            "a deployed external match router"
        } else if self
            .pairs
            .iter()
            .filter(|pair| pair.external_enabled)
            .any(|pair| {
                self.searcher_min_profit
                    .get(&pair.quote_asset_id)
                    .is_none_or(|margin| *margin == 0)
            })
        {
            "a positive external_min_profit_quote in the market registry"
        } else if self.policy.external_window_seconds == 0 {
            "a nonzero runtime.external_window_seconds"
        } else {
            return Ok(());
        };
        Err(format!(
            "pair {} matches externally but has no {missing}",
            pair.name
        ))
    }

    pub fn pair(&self, pair_id: Felt) -> Option<&PairRuntime> {
        self.pairs.iter().find(|pair| pair.pair_id == pair_id)
    }

    pub fn active_execution_registry(&self) -> PrivateExecutionKeyRegistry {
        active_execution_registry(&self.execution_keys, &self.active_execution_key_id)
            .expect("execution key rotation was validated at startup")
    }

    pub fn proof_capacity(&self, kind: ProofStatementKind) -> &ProofCapacityProfile {
        self.proof_capacity_profiles
            .get(&kind)
            .expect("all production statement capacity profiles were validated at startup")
    }

    /// the exchange as the core types see it.
    pub fn chain_context(&self) -> starknet_crypto::Felt {
        core_felt(&format!("{:#x}", self.exchange)).expect("exchange is a felt")
    }
}

/// core and starknet-rust share the underlying felt type; these convert at the boundary.
pub fn to_core(value: Felt) -> starknet_crypto::Felt {
    starknet_crypto::Felt::from_bytes_be(&value.to_bytes_be())
}

pub fn from_core(value: starknet_crypto::Felt) -> Felt {
    Felt::from_bytes_be(&value.to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zylith_proof_job::{
        PROOF_CAPACITY_SCHEMA_VERSION, ProofCapacityVector, ProofResourceUsage, ProofShapeLimits,
    };

    fn key(id: &str, public_key: &str, private_key: &str) -> PrivateExecutionKeyPrivateConfig {
        PrivateExecutionKeyPrivateConfig {
            key_id: id.into(),
            algorithm: zylith_core::private_envelope::HPKE_PROFILE_ID.into(),
            private_key: private_key.into(),
            public_key: public_key.into(),
        }
    }

    fn rotation_keys() -> Vec<PrivateExecutionKeyPrivateConfig> {
        vec![
            key(
                "old",
                "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
                "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            ),
            key(
                "new",
                "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209",
                &hex::encode([1_u8; 32]),
            ),
        ]
    }

    fn resource(value: u64) -> ProofResourceUsage {
        let domain_log_size = if value >= 1_000 { 11 } else { 10 };
        let components = [
            "bitwise",
            "cpu",
            "ec_op",
            "ecdsa",
            "pedersen",
            "poseidon",
            "range_check",
        ];
        let mut usage = ProofResourceUsage {
            component_registry_id: String::new(),
            raw_snos_steps: value,
            adapted_rows: value,
            memory_words: value,
            memory_holes: value / 10,
            builtin_instances: components
                .into_iter()
                .map(|component| (component.into(), value))
                .collect(),
            component_log_sizes: components
                .into_iter()
                .map(|component| (component.into(), domain_log_size))
                .collect(),
            max_domain_log_size: domain_log_size,
            peak_rss_bytes: value,
            wall_time_ms: value,
        };
        usage.component_registry_id = usage.expected_component_registry_id().unwrap();
        usage
    }

    fn capacity_profile(identity: ProofReleaseIdentity) -> ProofCapacityProfile {
        let limits = ProofShapeLimits {
            markets: 3,
            resting_orders: 2,
            admissions: 2,
            crossings: 2,
            outcomes: 2,
            nullifiers: 8,
            retired_nullifiers: 2,
            outputs: 16,
            funding_notes: 8,
            membership_path_elements: 384,
        };
        let mut profile = ProofCapacityProfile {
            schema_version: PROOF_CAPACITY_SCHEMA_VERSION,
            profile_id: String::new(),
            statement_kind: ProofStatementKind::Transition,
            identity,
            vector_family: "transition-release-gate-v1".into(),
            safety_margin_bps: 1_000,
            capacity: resource(1_000),
            limits: limits.clone(),
            vectors: vec![ProofCapacityVector {
                vector_id: "limit".into(),
                evidence_sha256: "a".repeat(64),
                shape: limits,
                usage: resource(800),
            }],
        };
        profile.profile_id = profile.expected_profile_id().unwrap();
        profile
    }

    #[test]
    fn rotation_registry_publishes_only_explicit_active_key() {
        let keys = rotation_keys();
        let old = active_execution_registry(&keys, "old").unwrap();
        let new = active_execution_registry(&keys, "new").unwrap();
        assert_eq!(old.keys.len(), 1);
        assert_eq!(old.keys[0].key_id, "old");
        assert_eq!(new.keys.len(), 1);
        assert_eq!(new.keys[0].key_id, "new");
        assert_ne!(old.fingerprint().unwrap(), new.fingerprint().unwrap());
        assert!(active_execution_registry(&keys, "missing").is_err());
        assert!(active_execution_registry(&keys, "").is_err());
    }

    #[test]
    fn rotation_requires_pins_for_every_configured_private_key() {
        let keys = rotation_keys();
        let old = active_execution_registry(&keys, "old")
            .unwrap()
            .fingerprint()
            .unwrap();
        let new = active_execution_registry(&keys, "new")
            .unwrap()
            .fingerprint()
            .unwrap();
        validate_execution_rotation(&keys, "old", &[old.as_str(), new.as_str()]).unwrap();
        validate_execution_rotation(&keys, "new", &[old.as_str(), new.as_str()]).unwrap();
        assert!(
            validate_execution_rotation(&keys[1..], "new", &[old.as_str(), new.as_str()]).is_err()
        );
        assert!(validate_execution_rotation(&keys, "old", &[old.as_str()]).is_err());
        assert!(validate_execution_rotation(&keys, "new", &[old.as_str()]).is_err());
        assert!(validate_execution_rotation(&keys, "old", &["cd".repeat(32).as_str()]).is_err());
        assert!(validate_execution_rotation(&keys, "old", &[old.as_str(), old.as_str()]).is_err());
        let mut duplicate = keys.clone();
        duplicate[1].key_id = "old".into();
        assert!(
            validate_execution_rotation(&duplicate, "old", &[old.as_str(), new.as_str()]).is_err()
        );
        duplicate[1].key_id = "new".into();
        duplicate[1].public_key = duplicate[0].public_key.clone();
        assert!(
            validate_execution_rotation(&duplicate, "old", &[old.as_str(), new.as_str()]).is_err()
        );
        assert!(validate_execution_rotation(&[], "old", &[old.as_str()]).is_err());
        assert!(
            validate_execution_rotation(
                &[keys[0].clone(), keys[1].clone(), keys[0].clone()],
                "old",
                &[old.as_str(), new.as_str()]
            )
            .is_err()
        );
    }

    #[test]
    fn chain_ids_parse_from_hex_or_short_string() {
        let sepolia = Felt::from_hex("0x534e5f5345504f4c4941").unwrap();
        assert_eq!(chain_id("0x534e5f5345504f4c4941").unwrap(), sepolia);
        assert_eq!(chain_id(" SN_SEPOLIA ").unwrap(), sepolia);
        assert!(chain_id("0x0").is_err());
        assert!(chain_id("").is_err());
    }

    #[test]
    fn capacity_profiles_are_closed_and_release_bound() {
        let identity = ProofReleaseIdentity {
            release_commit: "release-1".into(),
            prover_build_id: "stwo-production-v1".into(),
            proof_version: "PROOF2".into(),
            program_variant: VIRTUAL_PROGRAM_VARIANT.into(),
            virtual_program_hash: "0x1".into(),
            starknet_os_output_version: STARKNET_OS_OUTPUT_VERSION.into(),
            starknet_os_config_hash: "0x2".into(),
            proof_account_class_hash: "0x3".into(),
            proof_program_class_hash: "0x4".into(),
            statement_version: TRANSITION_STATEMENT_VERSION.into(),
        };
        let profile = capacity_profile(identity.clone());
        let raw = serde_json::to_string(&profile).unwrap();
        assert!(parse_capacity_profile(&raw, ProofStatementKind::Transition, &identity).is_ok());

        let mut wrong_identity = identity.clone();
        wrong_identity.proof_program_class_hash = "0x5".into();
        assert!(
            parse_capacity_profile(&raw, ProofStatementKind::Transition, &wrong_identity)
                .unwrap_err()
                .contains("release identity")
        );
        assert!(
            parse_capacity_profile(&raw, ProofStatementKind::Withdrawal, &identity)
                .unwrap_err()
                .contains("statement kind")
        );

        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        value["unreviewed_limit"] = serde_json::json!(1);
        assert!(
            parse_capacity_profile(
                &serde_json::to_string(&value).unwrap(),
                ProofStatementKind::Transition,
                &identity,
            )
            .unwrap_err()
            .contains("unknown field")
        );
    }

    #[test]
    fn capacity_identity_pins_each_statement_class_hash() {
        let mut manifest: DeploymentManifest =
            serde_json::from_str(include_str!("../../client/public/deployment.example.json"))
                .unwrap();
        manifest.proof.virtual_program_hash = "0x01".into();
        manifest.proof.starknet_os_config_hash = "0x02".into();
        manifest.proof.proof_account_class_hash = "0x03".into();
        manifest.proof.transition_proof_program_class_hash = "0x04".into();
        manifest.proof.withdrawal_proof_program_class_hash = "0x05".into();
        manifest.proof.residual_recovery_proof_program_class_hash = "0x06".into();

        let transition =
            expected_capacity_identity(&manifest, &ProofStatementKind::Transition).unwrap();
        let withdrawal =
            expected_capacity_identity(&manifest, &ProofStatementKind::Withdrawal).unwrap();
        let recovery =
            expected_capacity_identity(&manifest, &ProofStatementKind::ResidualRecovery).unwrap();
        assert_eq!(transition.virtual_program_hash, "0x1");
        assert_eq!(transition.proof_account_class_hash, "0x3");
        assert_eq!(transition.proof_program_class_hash, "0x4");
        assert_eq!(withdrawal.proof_program_class_hash, "0x5");
        assert_eq!(recovery.proof_program_class_hash, "0x6");
        assert_ne!(transition.statement_version, recovery.statement_version);
    }
}

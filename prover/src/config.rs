//! the operator's configuration: the signed deployment manifest plus the secrets and service
//! endpoints that stay out of it.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use starknet_rust_core::types::Felt;
use url::Url;
use zylith_core::hash::felt_from_hex_str;
use zylith_core::{
    DeploymentManifest, PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig,
    PrivateExecutionKeyRegistry,
};

pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3200";
pub const DEFAULT_DATA_DIR: &str = "data/prover";
const MAX_MANIFEST_BYTES: u64 = 1 << 20;

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
    pub external_enabled: bool,
    /// the smallest order the operator admits, in base atoms.
    pub min_order_amount: u128,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub epoch_ms: u64,
    /// how many transitions may be in flight (proving or submitted) ahead of the chain.
    pub pipeline_depth: usize,
    pub max_admissions: usize,
    pub max_book_orders: usize,
    /// the most cairo steps a transition statement may take and still prove in one snip-36
    /// transaction; every transition is estimated against it before proving.
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
    pub proof_program: Felt,
    pub router: Felt,
    pub settlement: Account,
    pub proof_account: Account,
    pub tx_provers: Vec<String>,
    pub tx_prover_ohttp_key_config: Option<Vec<u8>>,
    pub tx_prover_timeout_seconds: u64,
    pub proving_blocks_back: u64,
    pub attestor_url: String,
    pub attestor_token: String,
    pub route_service_url: Option<String>,
    /// the margin a searcher leg must clear beyond its gas, per quote asset, in its atoms.
    pub searcher_min_profit: BTreeMap<Felt, u128>,
    pub searcher_headroom_bps: u128,
    /// the secret that blinds fee notes; the fee recipient needs it to recover and spend them.
    pub fee_key: Felt,
    /// the strk asset id, the unit gas is paid and valued in.
    pub strk_asset: Felt,
    /// the fixed objective numeraire; every enabled asset needs a direct observation against it.
    pub usdc_asset: Felt,
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
    pub fee_recipient: Felt,
    pub pairs: Vec<PairRuntime>,
    pub policy: Policy,
    pub control_token: String,
    pub allowed_origins: Vec<String>,
    pub private_rate_limit_per_minute: u32,
    pub trusted_proxies: Vec<ipnet::IpNet>,
    pub max_body_bytes: usize,
    pub sync_from_block: u64,
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

/// whether a service url names this machine or a private network, where the operator runs its
/// own transaction provers.
pub fn is_operator_host(url: &str) -> bool {
    let Some(host) = Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
    else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => host == "localhost" || host.ends_with(".internal") || host.ends_with(".local"),
    }
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

/// a json object of asset name to decimal atoms, keyed by asset id.
fn asset_amounts(name: &str) -> Result<BTreeMap<Felt, u128>, String> {
    let Some(raw) = optional(name) else {
        return Ok(BTreeMap::new());
    };
    let amounts: BTreeMap<String, String> =
        serde_json::from_str(&raw).map_err(|error| format!("{name}: {error}"))?;
    amounts
        .into_iter()
        .map(|(asset, amount)| {
            let amount = amount
                .trim()
                .parse::<u128>()
                .map_err(|_| format!("{name}: {asset} is not an integer amount"))?;
            Ok((asset_felt(&asset), amount))
        })
        .collect()
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
    serde_json::from_value(manifest).map_err(|error| format!("deployment manifest schema: {error}"))
}

fn load_execution_keys(path: &str) -> Result<Vec<PrivateExecutionKeyPrivateConfig>, String> {
    let raw =
        fs::read_to_string(path).map_err(|error| format!("execution keys {path}: {error}"))?;
    let keys: Vec<PrivateExecutionKeyPrivateConfig> =
        serde_json::from_str(&raw).map_err(|error| format!("execution keys: {error}"))?;
    if keys.is_empty() {
        return Err("at least one private execution key is required".into());
    }
    Ok(keys)
}

fn data_key() -> Result<[u8; 32], String> {
    let hex = required("ZYLITH_PROVER_DATA_KEY_HEX")?;
    let bytes =
        hex::decode(hex.trim()).map_err(|_| "ZYLITH_PROVER_DATA_KEY_HEX is not hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "ZYLITH_PROVER_DATA_KEY_HEX must be 32 bytes".to_string())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let manifest_path = optional("ZYLITH_DEPLOYMENT_MANIFEST")
            .unwrap_or_else(|| "client/public/deployment.json".into());
        let manifest = load_manifest(&manifest_path)?;
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
        let tx_provers = optional("ZYLITH_TX_PROVER_URLS")
            .map(|value| {
                value
                    .split(',')
                    .map(|url| url.trim().to_owned())
                    .filter(|url| !url.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec![manifest.proof.tx_prover_url.clone()]);
        if tx_provers.is_empty() {
            return Err("at least one transaction prover is required".into());
        }
        // the transaction prover executes the whole witness, every order and note in the clear,
        // so it must run under the operator's own control; ohttp would hide only who is asking.
        if optional("ZYLITH_TX_PROVER_REMOTE_TRUSTED").as_deref() != Some("1") {
            for prover in &tx_provers {
                if !is_operator_host(prover) {
                    return Err(format!(
                        "transaction prover {prover} is not on a loopback or private address; it sees every witness, so run it yourself or set ZYLITH_TX_PROVER_REMOTE_TRUSTED=1 for one you control"
                    ));
                }
            }
        }
        let tx_prover_ohttp_key_config = if manifest.proof.tx_prover_ohttp_enabled {
            match optional("ZYLITH_TX_PROVER_OHTTP_KEY_CONFIG_HEX") {
                Some(hex) => Some(
                    hex::decode(hex.trim())
                        .map_err(|_| "ohttp key config is not hex".to_string())?,
                ),
                None => Some(Vec::new()),
            }
        } else {
            None
        };

        if optional("ZYLITH_MIN_SETTLEMENT_FEES").is_some()
            || optional("ZYLITH_SEARCHER_MIN_PROFIT_QUOTE").is_some()
        {
            return Err("ZYLITH_MIN_SETTLEMENT_FEES and ZYLITH_SEARCHER_MIN_PROFIT_QUOTE are replaced by ZYLITH_MIN_TRANSITION_FEE_STRK and ZYLITH_SEARCHER_MIN_PROFIT".into());
        }
        let mut pairs = Vec::new();
        for pair in manifest.product.pairs.values().filter(|pair| pair.enabled) {
            pairs.push(PairRuntime {
                name: pair.pair_id.0.clone(),
                base_name: pair.base_asset_id.0.clone(),
                quote_name: pair.quote_asset_id.0.clone(),
                pair_id: pair_felt(&pair.pair_id.0),
                base_asset_id: asset_felt(&pair.base_asset_id.0),
                quote_asset_id: asset_felt(&pair.quote_asset_id.0),
                scale: pair.price_base_scale,
                fee_bps: u128::from(pair.taker_fee_bps),
                external_enabled: pair.external_match_enabled,
                min_order_amount: pair.min_order_amount,
            });
        }
        // tiny funded orders would crowd the book and the proofs: every pair needs a minimum.
        if let Some(pair) = pairs.iter().find(|pair| pair.min_order_amount == 0) {
            return Err(format!("pair {} has no minimum order amount", pair.name));
        }
        if pairs.len() > zylith_core::exchange::MAX_MARKETS {
            return Err(format!(
                "{} enabled pairs exceed the protocol maximum of {}",
                pairs.len(),
                zylith_core::exchange::MAX_MARKETS
            ));
        }
        pairs.sort_by_key(|pair| pair.pair_id.to_bytes_be());
        let usdc_asset = asset_felt("USDC");
        let enabled_assets = pairs
            .iter()
            .flat_map(|pair| [pair.base_asset_id, pair.quote_asset_id])
            .collect::<BTreeSet<_>>();
        for asset in enabled_assets {
            if asset != usdc_asset
                && !pairs.iter().any(|pair| {
                    (pair.base_asset_id == asset && pair.quote_asset_id == usdc_asset)
                        || (pair.quote_asset_id == asset && pair.base_asset_id == usdc_asset)
                })
            {
                return Err("every enabled asset needs a direct USDC observation pair".into());
            }
        }

        let runtime = &manifest.runtime;
        if runtime.max_internal_deferral_epochs == 0 {
            return Err("runtime.max_internal_deferral_epochs must be positive".into());
        }
        let epoch_ms = parsed("ZYLITH_EPOCH_MS", runtime.epoch_ms)?;
        let policy = Policy {
            epoch_ms,
            pipeline_depth: parsed("ZYLITH_PIPELINE_DEPTH", 2_usize)?.clamp(1, 4),
            max_admissions: parsed(
                "ZYLITH_MAX_ADMISSIONS",
                runtime.max_admissions_per_transition as usize,
            )?,
            // the manifest's book size, never beyond what the step budget proves when every
            // order crosses at once.
            max_book_orders: (runtime.max_book_orders as usize).min(
                zylith_core::exchange::StepShape::max_book_orders(step_budget),
            ),
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

        let config = Self {
            bind_addr: optional("ZYLITH_PROVER_BIND_ADDR")
                .unwrap_or_else(|| DEFAULT_BIND_ADDR.into()),
            data_dir: PathBuf::from(
                optional("ZYLITH_PROVER_DATA_DIR").unwrap_or_else(|| DEFAULT_DATA_DIR.into()),
            ),
            replica_dir: optional("ZYLITH_PROVER_REPLICA_DIR").map(PathBuf::from),
            confirmation_blocks: parsed("ZYLITH_CONFIRMATION_BLOCKS", 2_u64)?,
            data_key: data_key()?,
            rpc_url,
            chain_id,
            exchange: nonzero(&manifest.contracts.exchange, "exchange")?,
            proof_program: nonzero(&manifest.proof.proof_program_address, "proof program")?,
            router: felt(&manifest.contracts.ekubo_external_match_router, "router")?,
            settlement,
            proof_account,
            tx_provers,
            tx_prover_ohttp_key_config,
            tx_prover_timeout_seconds: parsed("ZYLITH_TX_PROVER_TIMEOUT_SECONDS", 120_u64)?,
            proving_blocks_back: parsed("ZYLITH_PROVING_BLOCKS_BACK", 1_u64)?,
            attestor_url: required("ZYLITH_REFERENCE_PRICE_ATTESTOR_URL")?,
            attestor_token: required("ZYLITH_REFERENCE_PRICE_ATTESTOR_TOKEN")?,
            route_service_url: optional("ZYLITH_ROUTE_SERVICE_URL"),
            searcher_min_profit: asset_amounts("ZYLITH_SEARCHER_MIN_PROFIT")?,
            searcher_headroom_bps: parsed("ZYLITH_SEARCHER_HEADROOM_BPS", 5_u128)?,
            fee_key: nonzero(&required("ZYLITH_FEE_NOTE_KEY")?, "fee note key")?,
            strk_asset: asset_felt("STRK"),
            usdc_asset,
            transition_gas_estimate: parsed("ZYLITH_TRANSITION_GAS_ESTIMATE", 250_000_000_u64)?,
            leg_gas: crate::market::LegGas {
                base: parsed("ZYLITH_EXTERNAL_LEG_GAS", 25_000_000_u64)?,
                per_split: parsed("ZYLITH_EXTERNAL_LEG_SPLIT_GAS", 6_000_000_u64)?,
                per_hop: parsed("ZYLITH_EXTERNAL_LEG_HOP_GAS", 8_000_000_u64)?,
            },
            fee_cover_percent: parsed("ZYLITH_FEE_COVER_PERCENT", 100_u64)?,
            min_transition_fee_strk: parsed("ZYLITH_MIN_TRANSITION_FEE_STRK", 0_u128)?,
            fee_rate_haircut_bps: parsed("ZYLITH_FEE_RATE_HAIRCUT_BPS", 100_u128)?,
            execution_keys: load_execution_keys(&required("ZYLITH_EXECUTION_KEYS_PATH")?)?,
            fee_recipient: nonzero(
                &manifest.roles.protocol_fee_recipient,
                "protocol fee recipient",
            )?,
            pairs,
            policy,
            control_token: required("ZYLITH_CONTROL_PLANE_TOKEN")?,
            allowed_origins: optional("ZYLITH_PROVER_ALLOWED_ORIGINS")
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
            max_body_bytes: parsed("ZYLITH_PROVER_MAX_BODY_BYTES", 256 * 1024_usize)?,
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
                "ZYLITH_PROVER_MAX_BODY_BYTES must be at least {}",
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
                let priced = asset == self.strk_asset
                    || neighbours(asset).any(|middle| {
                        middle == self.strk_asset
                            || neighbours(middle).any(|end| end == self.strk_asset)
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
        let fingerprint = self
            .registry()
            .fingerprint()
            .map_err(|error| format!("execution keys: {error}"))?;
        let pinned = self
            .manifest
            .funding
            .starknet_privacy
            .pinned_registry_fingerprints();
        if !pinned.contains(&fingerprint.as_str()) {
            return Err(format!(
                "the execution keys (fingerprint {fingerprint}) are not pinned by the manifest's ingress_key_registry_fingerprint"
            ));
        }
        Ok(())
    }

    /// a pair that routes through ekubo needs every piece of the route: a quoter, the router, a
    /// positive margin and an on-chain window for the fill.
    fn check_external_matching(&self) -> Result<(), String> {
        let Some(pair) = self.pairs.iter().find(|pair| pair.external_enabled) else {
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
            "positive ZYLITH_SEARCHER_MIN_PROFIT margin for its quote asset"
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

    pub fn registry(&self) -> PrivateExecutionKeyRegistry {
        PrivateExecutionKeyRegistry {
            keys: self
                .execution_keys
                .iter()
                .map(|key| PrivateExecutionKeyPublicConfig {
                    key_id: key.key_id.clone(),
                    public_key: key.public_key.clone(),
                })
                .collect(),
        }
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

    #[test]
    fn only_local_or_private_hosts_count_as_operator_run_provers() {
        for local in [
            "http://127.0.0.1:3000",
            "http://localhost:8080/prove",
            "http://10.0.3.7:3000",
            "http://192.168.1.2",
            "http://[::1]:3000",
            "http://prover.internal:3000",
        ] {
            assert!(is_operator_host(local), "{local}");
        }
        for remote in [
            "https://prover.example.com",
            "http://35.192.48.142:3000",
            "not a url",
        ] {
            assert!(!is_operator_host(remote), "{remote}");
        }
    }

    #[test]
    fn chain_ids_parse_from_hex_or_short_string() {
        let sepolia = Felt::from_hex("0x534e5f5345504f4c4941").unwrap();
        assert_eq!(chain_id("0x534e5f5345504f4c4941").unwrap(), sepolia);
        assert_eq!(chain_id(" SN_SEPOLIA ").unwrap(), sepolia);
        assert!(chain_id("0x0").is_err());
        assert!(chain_id("").is_err());
    }
}

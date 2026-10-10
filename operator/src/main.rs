//! the zylith operator: private order intake, the epoch pipeline that proves and submits one
//! transition per active epoch, and user withdrawals.

mod api;
mod chain;
mod config;
mod engine;
mod execution_key_cli;
mod market;
mod snip36;
mod state;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use starknet_rust_core::types::{BlockId, Felt};
use starknet_rust_providers::Provider;
use tokio::sync::Mutex;

use crate::config::{Account, Config, felt};
use crate::engine::Operator;
use crate::snip36::{ProofJobContext, Snip36, Snip36Config, call, canonical_witness_hash};
use crate::state::{OperatorState, Store};

#[tokio::main]
async fn main() -> Result<(), String> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "failed to install the tls crypto provider".to_string())?;
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        None | Some("serve") => serve().await,
        Some("bench") => bench(&args[1..]).await,
        Some("ids") => {
            // the felt ids the exchange registers for manifest asset and pair names.
            for name in &args[1..] {
                let id = if name.contains('/') {
                    zylith_core::exchange::pair_id(name)
                } else {
                    zylith_core::exchange::asset_id(name)
                };
                println!("{name}={id:#x}");
            }
            Ok(())
        }
        Some("fingerprint") => {
            // print exactly the selected key's one-key v2 registry pin.
            if args.len() != 3 {
                return Err("usage: fingerprint <execution-keys.json> <key-id>".into());
            }
            let path = &args[1];
            let key_id = &args[2];
            let keys = config::load_execution_keys(path, key_id)?;
            let registry = config::active_execution_registry(&keys, key_id)?;
            println!(
                "{}",
                registry.fingerprint().map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("generate-execution-key") => {
            let output = execution_key_cli::generate_execution_key_command(&args)?;
            println!("{output}");
            Ok(())
        }
        Some("proof-public-key") => {
            let private_key = felt(
                &env::var("ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY")
                    .map_err(|_| "ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY is required")?,
                "proof account key",
            )?;
            println!("{:#x}", starknet_crypto::get_public_key(&private_key));
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown command {other}; use `serve`, `bench <witness.json>...`, `ids <name>...`, `fingerprint <keys.json> <key-id>`, `generate-execution-key <key-id> <new-private-config.json>` or `proof-public-key`"
        )),
    }
}

/// every traded asset's decimals in the manifest must be its token's: prices, minimums and fee
/// values are all scaled by them, and one asset name can be a different token, with different
/// decimals, on another network.
async fn check_token_decimals(config: &Config, snip36: &Snip36) -> Result<(), String> {
    let manifest = &config.manifest;
    let bridge = felt(
        &manifest.contracts.privacy_deposit_bridge,
        "privacy deposit bridge",
    )?;
    let names = config
        .pairs
        .iter()
        .flat_map(|pair| [&pair.base_name, &pair.quote_name])
        .collect::<std::collections::BTreeSet<_>>();
    for name in names {
        let asset = manifest
            .market_registry
            .asset(name)
            .ok_or_else(|| format!("the market registry has no asset {name}"))?;
        let token = felt(&asset.token_address, "token address")?;
        let registered = snip36
            .view(bridge, "asset_token", vec![config::asset_felt(name)])
            .await?
            .first()
            .copied()
            .ok_or_else(|| format!("bridge returned no token for {name}"))?;
        if registered != token {
            return Err(format!(
                "bridge token for {name} differs from the market registry"
            ));
        }
        let decimals = snip36
            .view(token, "decimals", Vec::new())
            .await?
            .first()
            .and_then(|value| u8::try_from(*value).ok())
            .ok_or_else(|| format!("{name} token returned no decimals"))?;
        if decimals != asset.decimals {
            return Err(format!(
                "{name} is a {decimals}-decimal token on chain, but the manifest says {}",
                asset.decimals
            ));
        }
    }
    let expected_assets = manifest
        .market_registry
        .assets
        .iter()
        .filter(|asset| asset.enabled)
        .map(|asset| config::asset_felt(&asset.asset_id.0))
        .collect::<std::collections::BTreeSet<_>>();
    let asset_count = snip36
        .view(bridge, "supported_asset_count", Vec::new())
        .await?
        .first()
        .and_then(|value| u64::try_from(*value).ok())
        .ok_or("bridge returned no supported asset count")?;
    let mut registered_assets = std::collections::BTreeSet::new();
    for index in 0..asset_count {
        let asset_id = snip36
            .view(bridge, "supported_asset_id_at", vec![Felt::from(index)])
            .await?
            .first()
            .copied()
            .ok_or("bridge returned no supported asset id")?;
        if !registered_assets.insert(asset_id) {
            return Err("bridge repeats a supported asset id".into());
        }
    }
    if registered_assets != expected_assets {
        return Err("bridge supported assets differ from the market registry".into());
    }
    let registry = felt(
        &manifest.contracts.commitment_registry,
        "commitment registry",
    )?;
    let privacy_pool = felt(
        &manifest.funding.starknet_privacy.privacy_pool,
        "privacy pool",
    )?;
    for (contract, entrypoint, expected) in [
        (bridge, "exchange_address", config.exchange),
        (bridge, "commitment_registry_address", registry),
        (bridge, "privacy_pool_address", privacy_pool),
        (registry, "privacy_deposit_bridge_address", bridge),
        (registry, "exchange_address", config.exchange),
    ] {
        let actual = snip36
            .view(contract, entrypoint, Vec::new())
            .await?
            .first()
            .copied()
            .ok_or_else(|| format!("{contract:#x} returned no {entrypoint}"))?;
        if actual != expected {
            return Err(format!(
                "{contract:#x} {entrypoint} {actual:#x} differs from the deployment manifest's {expected:#x}"
            ));
        }
    }
    for (contract, label) in [
        (bridge, "custody bridge"),
        (registry, "commitment registry"),
    ] {
        let locked = snip36
            .view(contract, "config_is_locked", Vec::new())
            .await?
            .first()
            .copied()
            .ok_or_else(|| format!("{label} returned no configuration lock state"))?;
        if locked != Felt::ONE {
            return Err(format!("{label} configuration is not locked"));
        }
    }
    Ok(())
}

async fn check_exchange_configuration(config: &Config, snip36: &Snip36) -> Result<(), String> {
    let registry_hash = snip36
        .view(config.exchange, "market_registry_hash", Vec::new())
        .await?;
    let (high, low) = config.manifest.market_registry.hash_limbs()?;
    if registry_hash.as_slice() != [Felt::from(high), Felt::from(low)] {
        return Err("exchange market registry hash differs from the deployment manifest".into());
    }
    let objective_numeraire = snip36
        .view(config.exchange, "objective_numeraire", Vec::new())
        .await?
        .first()
        .copied()
        .ok_or("exchange returned no objective numeraire")?;
    if objective_numeraire != config.objective_numeraire_asset {
        return Err("exchange objective numeraire differs from the market registry".into());
    }
    let signer = snip36
        .view(config.exchange, "reference_signer", Vec::new())
        .await?
        .first()
        .copied()
        .ok_or("exchange returned no reference signer")?;
    if signer != config.reference_price_signer {
        return Err(format!(
            "exchange reference signer {signer:#x} differs from the manifest's {:#x}",
            config.reference_price_signer
        ));
    }
    let manifest = &config.manifest;
    let proof_version = config::chain_id(&manifest.proof.proof_version)
        .map_err(|_| "manifest proof version is not a felt or short string".to_string())?;
    for (entrypoint, expected) in [
        ("settlement_account", config.settlement.address),
        ("protocol_fee_recipient", config.fee_recipient),
        (
            "pause_guardian",
            felt(&manifest.roles.pause_guardian_address, "pause guardian")?,
        ),
        ("transition_proof_program", config.transition_proof_program),
        ("withdrawal_proof_program", config.withdrawal_proof_program),
        (
            "residual_recovery_proof_program",
            config.residual_recovery_proof_program,
        ),
        (
            "virtual_program_hash",
            felt(&manifest.proof.virtual_program_hash, "virtual program hash")?,
        ),
        ("proof_version", proof_version),
        (
            "starknet_os_config_hash",
            felt(
                &manifest.proof.starknet_os_config_hash,
                "starknet os config hash",
            )?,
        ),
        (
            "bridge",
            felt(&manifest.contracts.privacy_deposit_bridge, "custody bridge")?,
        ),
        (
            "deposit_root_registrar",
            felt(
                &manifest.contracts.commitment_registry,
                "deposit root registrar",
            )?,
        ),
        ("external_router", config.router),
    ] {
        let actual = snip36
            .view(config.exchange, entrypoint, Vec::new())
            .await?
            .first()
            .copied()
            .ok_or_else(|| format!("exchange returned no {entrypoint}"))?;
        if actual != expected {
            return Err(format!(
                "exchange {entrypoint} {actual:#x} differs from the deployment manifest's {expected:#x}"
            ));
        }
    }
    let proof_account_public_key =
        starknet_crypto::get_public_key(&config.proof_account.private_key);
    for (entrypoint, expected) in [
        ("public_key", proof_account_public_key),
        ("transition_program", config.transition_proof_program),
        ("withdrawal_program", config.withdrawal_proof_program),
        (
            "residual_recovery_program",
            config.residual_recovery_proof_program,
        ),
    ] {
        let actual = snip36
            .view(config.proof_account.address, entrypoint, Vec::new())
            .await?
            .first()
            .copied()
            .ok_or_else(|| format!("proof account returned no {entrypoint}"))?;
        if actual != expected {
            return Err(format!(
                "proof account {entrypoint} {actual:#x} differs from the configured {expected:#x}"
            ));
        }
    }
    let proof_validity_blocks = snip36
        .view(config.exchange, "proof_validity_blocks", Vec::new())
        .await?
        .first()
        .and_then(|value| u64::try_from(*value).ok())
        .ok_or("exchange returned no proof validity window")?;
    if proof_validity_blocks != manifest.proof.proof_validity_blocks {
        return Err(format!(
            "exchange proof validity window {proof_validity_blocks} differs from the deployment manifest's {}",
            manifest.proof.proof_validity_blocks
        ));
    }
    let epoch_ms = snip36
        .view(config.exchange, "epoch_length_ms", Vec::new())
        .await?
        .first()
        .and_then(|value| u64::try_from(*value).ok())
        .ok_or("exchange returned no epoch length")?;
    if epoch_ms != config.policy.epoch_ms {
        return Err(format!(
            "exchange epoch length {epoch_ms} differs from the configured {}",
            config.policy.epoch_ms
        ));
    }
    for (entrypoint, expected) in [
        ("max_close_delay_ms", config.policy.max_close_delay_ms),
        (
            "withdrawal_delay_seconds",
            config.manifest.runtime.withdrawal_delay_seconds,
        ),
        (
            "external_window_seconds",
            config.policy.external_window_seconds,
        ),
    ] {
        let actual = snip36
            .view(config.exchange, entrypoint, Vec::new())
            .await?
            .first()
            .and_then(|value| u64::try_from(*value).ok())
            .ok_or_else(|| format!("exchange returned no {entrypoint}"))?;
        if actual != expected {
            return Err(format!(
                "exchange {entrypoint} {actual} differs from the configured {expected}"
            ));
        }
    }
    let pair_count = snip36
        .view(config.exchange, "pair_count", Vec::new())
        .await?
        .first()
        .and_then(|value| u64::try_from(*value).ok())
        .ok_or("exchange returned no pair count")?;
    let expected_pair_ids = config
        .pairs
        .iter()
        .map(|pair| pair.pair_id)
        .collect::<std::collections::BTreeSet<_>>();
    let mut registered_pair_ids = std::collections::BTreeSet::new();
    for index in 0..pair_count {
        let pair_id = snip36
            .view(config.exchange, "pair_id_at", vec![Felt::from(index)])
            .await?
            .first()
            .copied()
            .ok_or("exchange returned no pair id")?;
        if !registered_pair_ids.insert(pair_id) {
            return Err("exchange repeats a registered pair id".into());
        }
    }
    if registered_pair_ids != expected_pair_ids {
        return Err("exchange registered pairs differ from the market registry".into());
    }
    for pair in &config.pairs {
        let values = snip36
            .view(config.exchange, "pair_config", vec![pair.pair_id])
            .await?;
        let expected = [
            pair.base_asset_id,
            pair.quote_asset_id,
            Felt::from(pair.scale),
            Felt::from(pair.fee_bps),
            Felt::from(pair.min_order_quote_amount),
            Felt::from(pair.external_settlement_support_quote),
            Felt::from(u64::from(pair.reference_methodology)),
            pair.derivation_base_market_id,
            pair.derivation_quote_market_id,
            Felt::from(pair.max_leg_skew_ms),
        ];
        if values.as_slice() != expected {
            return Err(format!(
                "exchange configuration for {} differs from the deployment manifest",
                pair.name
            ));
        }
    }
    let locked = snip36
        .view(config.exchange, "config_is_locked", Vec::new())
        .await?
        .first()
        .copied()
        .ok_or("exchange returned no configuration lock state")?;
    if locked != Felt::ONE {
        return Err("exchange configuration is not locked".into());
    }
    Ok(())
}

async fn serve() -> Result<(), String> {
    let config = Config::from_env()?;
    let store = Store::open(
        &config.data_dir,
        config.replica_dir.as_deref(),
        &config.data_key,
    )?;
    let snip36 = Snip36::new(&config);
    check_exchange_configuration(&config, &snip36).await?;
    check_token_decimals(&config, &snip36).await?;
    let mut state = match store.load()? {
        Some(state) => state,
        None => {
            // the book's order preimages exist only in this state; starting empty against an
            // exchange that already settled transitions would strand every resting order.
            let chain = chain::Chain {
                snip36: &snip36,
                exchange: config.exchange,
            };
            let seq = chain.exchange_view().await?.seq;
            if seq != 0 {
                return Err(format!(
                    "no operator state, but the exchange is at transition {seq}; restore the state or its replica before starting"
                ));
            }
            let state = OperatorState::new(config.sync_from_block);
            store.save(&state)?;
            state
        }
    };
    let transition_profile_id = config
        .proof_capacity(zylith_proof_job::ProofStatementKind::Transition)
        .profile_id
        .clone();
    if state.proof_capacity_profile_id.as_deref() != Some(transition_profile_id.as_str()) {
        state.proof_capacity_profile_id = Some(transition_profile_id);
        state.proof_capacity_admission_limit = None;
        store.save(&state)?;
    }
    let bind_addr: SocketAddr = config
        .bind_addr
        .parse()
        .map_err(|error| format!("bind address: {error}"))?;
    let operator = Arc::new(Operator {
        snip36,
        market: market::Market::new(&config)?,
        store,
        state: Mutex::new(state),
        withdrawals_running: Default::default(),
        transitions_running: Default::default(),
        closing_epoch: Default::default(),
        halted: Default::default(),
        config,
    });
    engine::spawn(operator.clone());
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|error| format!("bind: {error}"))?;
    eprintln!("zylith operator listening on http://{bind_addr}");
    axum::serve(
        listener,
        api::router(operator).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("server: {error}"))
}

/// proves transition witnesses through the durable queue and reports how long
/// each takes: `bench <witness.json>...`, where each file is a length-prefixed hex felt list as
/// `core/examples/exchange_vectors.rs` writes them.
async fn bench(paths: &[String]) -> Result<(), String> {
    let required = |name: &str| env::var(name).map_err(|_| format!("{name} is required"));
    let proof_account = Account {
        address: felt(&required("ZYLITH_PROOF_ACCOUNT_ADDRESS")?, "proof account")?,
        private_key: felt(
            &required("ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY")?,
            "proof account key",
        )?,
    };
    let proof_account_address = proof_account.address;
    let chain_id = config::chain_id(&required("ZYLITH_CHAIN_ID")?)?;
    let release_commit = required("ZYLITH_RELEASE_COMMIT")?;
    let prover_build_id = required("ZYLITH_PROVER_BUILD_ID")?;
    let proof_version = required("ZYLITH_PROOF_VERSION")?;
    let virtual_program_hash = format!(
        "{:#x}",
        felt(
            &required("ZYLITH_VIRTUAL_PROGRAM_HASH")?,
            "virtual program hash"
        )?
    );
    let starknet_os_config_hash = format!(
        "{:#x}",
        felt(
            &required("ZYLITH_STARKNET_OS_CONFIG_HASH")?,
            "starknet os config hash"
        )?
    );
    let snip36 = Snip36::from_parts(Snip36Config {
        rpc_url: url::Url::parse(&required("ZYLITH_STARKNET_RPC_URL")?)
            .map_err(|error| error.to_string())?,
        chain_id,
        settlement: proof_account.clone(),
        proof_account,
        proof_queue_url: required("ZYLITH_PROOF_QUEUE_URL")?,
        proof_queue_control_token: required("ZYLITH_PROOF_QUEUE_CONTROL_TOKEN")?,
        prover_build_id: prover_build_id.clone(),
        protocol_version: "zylith-v1".into(),
        config_version: release_commit.clone(),
        proof_version: proof_version.clone(),
        virtual_program_hash: virtual_program_hash.clone(),
        starknet_os_config_hash: starknet_os_config_hash.clone(),
        proof_validity_blocks: required("ZYLITH_PROOF_VALIDITY_BLOCKS")?
            .parse()
            .map_err(|_| "ZYLITH_PROOF_VALIDITY_BLOCKS is invalid".to_string())?,
        timeout_seconds: 900,
        blocks_back: 20,
    });
    let (
        statement_kind,
        proof_program_env,
        proof_program_label,
        program_entrypoint,
        statement_version,
    ) = match required("ZYLITH_BENCHMARK_STATEMENT_KIND")?.as_str() {
        "TRANSITION" => (
            zylith_proof_job::ProofStatementKind::Transition,
            "ZYLITH_TRANSITION_PROOF_PROGRAM_ADDRESS",
            "transition proof program",
            "compile_transition_proof",
            zylith_proof_job::TRANSITION_STATEMENT_VERSION,
        ),
        "WITHDRAWAL" => (
            zylith_proof_job::ProofStatementKind::Withdrawal,
            "ZYLITH_WITHDRAWAL_PROOF_PROGRAM_ADDRESS",
            "withdrawal proof program",
            "compile_withdrawal_proof",
            zylith_proof_job::WITHDRAWAL_STATEMENT_VERSION,
        ),
        "RESIDUAL_RECOVERY" => (
            zylith_proof_job::ProofStatementKind::ResidualRecovery,
            "ZYLITH_RESIDUAL_RECOVERY_PROOF_PROGRAM_ADDRESS",
            "residual recovery proof program",
            "compile_residual_recovery_proof",
            zylith_proof_job::RESIDUAL_RECOVERY_STATEMENT_VERSION,
        ),
        _ => {
            return Err(
                    "ZYLITH_BENCHMARK_STATEMENT_KIND must be TRANSITION, WITHDRAWAL, or RESIDUAL_RECOVERY"
                        .into(),
                );
        }
    };
    let proof_program = felt(&required(proof_program_env)?, proof_program_label)?;
    let exchange = felt(&required("ZYLITH_EXCHANGE_ADDRESS")?, "exchange")?;
    let require_resource_usage = env::var("ZYLITH_BENCHMARK_REQUIRE_RESOURCE_USAGE")
        .ok()
        .is_some_and(|value| value == "1");
    for path in paths {
        let raw = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
        let values: Vec<String> =
            serde_json::from_str(&raw).map_err(|error| format!("{path}: {error}"))?;
        let witness = values
            .iter()
            .skip(1)
            .map(|value| felt(value, "witness felt"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut calldata = vec![starknet_rust_core::types::Felt::from(witness.len() as u64)];
        calldata.extend(witness.iter().copied());
        let started = Instant::now();
        let result = snip36
            .prove_checked(
                vec![call(proof_program, program_entrypoint, calldata)],
                None,
                ProofJobContext {
                    statement_kind: statement_kind.clone(),
                    transition_id: format!("benchmark:{}", canonical_witness_hash(&witness)),
                    epoch_id: None,
                    exchange_address: format!("{exchange:#x}"),
                    input_state_root: None,
                    expected_output_state_root: None,
                    statement_commitment: "0x0".into(),
                    witness_hash: canonical_witness_hash(&witness),
                    program_entrypoint: program_entrypoint.into(),
                },
            )
            .await;
        match result {
            // the facts carry what the exchange pins: the proof version, the virtual program hash and
            // the os config hash.
            Ok(proof) => {
                if require_resource_usage && proof.resource_usage.is_none() {
                    return Err(format!(
                        "{path}: pinned prover adapter omitted structured full-SNOS resource usage"
                    ));
                }
                let base_block_number: u64 = proof.facts[4]
                    .try_into()
                    .map_err(|_| "proof base block exceeds u64".to_string())?;
                let proof_account_class_hash = snip36
                    .provider
                    .get_class_hash_at(BlockId::Number(base_block_number), proof_account_address)
                    .await
                    .map_err(|error| format!("benchmark proof-account class hash: {error}"))?;
                let proof_program_class_hash = snip36
                    .provider
                    .get_class_hash_at(BlockId::Number(base_block_number), proof_program)
                    .await
                    .map_err(|error| format!("benchmark proof-program class hash: {error}"))?;
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 3,
                        "statement_kind": statement_kind,
                        "witness_path": path,
                        "elapsed_ms": started.elapsed().as_millis(),
                        "proof_bytes": proof.proof.len(),
                        "base_block_number": base_block_number,
                        "identity": {
                            "release_commit": &release_commit,
                            "prover_build_id": &prover_build_id,
                            "proof_version": &proof_version,
                            "program_variant": zylith_proof_job::VIRTUAL_PROGRAM_VARIANT,
                            "virtual_program_hash": &virtual_program_hash,
                            "starknet_os_output_version": zylith_proof_job::STARKNET_OS_OUTPUT_VERSION,
                            "starknet_os_config_hash": &starknet_os_config_hash,
                            "proof_account_class_hash": format!("{proof_account_class_hash:#x}"),
                            "proof_program_class_hash": format!("{proof_program_class_hash:#x}"),
                            "statement_version": statement_version,
                        },
                        "resource_usage": proof.resource_usage,
                    })
                );
            }
            Err(error) => println!(
                "{path}: failed after {} ms: {error}",
                started.elapsed().as_millis()
            ),
        }
    }
    Ok(())
}

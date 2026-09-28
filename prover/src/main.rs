//! the zylith operator: private order intake, the epoch pipeline that proves and submits one
//! transition per active epoch, and user withdrawals.

mod api;
mod chain;
mod config;
mod engine;
mod market;
mod snip36;
mod state;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use starknet_rust_core::types::Felt;
use tokio::sync::Mutex;

use crate::config::{Account, Config, felt};
use crate::engine::Operator;
use crate::snip36::{Snip36, Snip36Config, call};
use crate::state::{OperatorState, Store};

#[tokio::main]
async fn main() -> Result<(), String> {
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
            // the manifest pin for an execution key file; only public keys enter it.
            let path = args
                .get(1)
                .ok_or("usage: fingerprint <execution-keys.json>")?;
            let raw = std::fs::read_to_string(path)
                .map_err(|error| format!("execution keys {path}: {error}"))?;
            let keys: Vec<zylith_core::PrivateExecutionKeyPrivateConfig> =
                serde_json::from_str(&raw).map_err(|error| format!("execution keys: {error}"))?;
            zylith_core::validate_private_execution_keys(&keys)
                .map_err(|error| format!("execution keys: {error}"))?;
            let registry = zylith_core::PrivateExecutionKeyRegistry {
                keys: keys
                    .iter()
                    .map(|key| zylith_core::PrivateExecutionKeyPublicConfig {
                        key_id: key.key_id.clone(),
                        public_key: key.public_key.clone(),
                    })
                    .collect(),
            };
            println!(
                "{}",
                registry.fingerprint().map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown command {other}; use `serve`, `bench <witness.json>...`, `ids <name>...` or `fingerprint <keys.json>`"
        )),
    }
}

/// every traded asset's decimals in the manifest must be its token's: prices, minimums and fee
/// values are all scaled by them, and one asset name can be a different token, with different
/// decimals, on another network.
async fn check_token_decimals(config: &Config, snip36: &Snip36) -> Result<(), String> {
    let manifest = &config.manifest;
    let names = config
        .pairs
        .iter()
        .flat_map(|pair| [&pair.base_name, &pair.quote_name])
        .collect::<std::collections::BTreeSet<_>>();
    for name in names {
        let asset = manifest
            .product
            .assets
            .get(name)
            .ok_or_else(|| format!("the manifest has no product asset {name}"))?;
        let token = felt(
            manifest
                .token_addresses
                .get(name)
                .ok_or_else(|| format!("the manifest has no token address for {name}"))?,
            "token address",
        )?;
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
    Ok(())
}

async fn check_exchange_configuration(config: &Config, snip36: &Snip36) -> Result<(), String> {
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
    let state = match store.load()? {
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

/// proves transition witnesses through the configured transaction prover and reports how long
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
    let chain_id = config::chain_id(&required("ZYLITH_CHAIN_ID")?)?;
    let snip36 = Snip36::from_parts(Snip36Config {
        rpc_url: url::Url::parse(&required("ZYLITH_STARKNET_RPC_URL")?)
            .map_err(|error| error.to_string())?,
        chain_id,
        settlement: proof_account.clone(),
        proof_account,
        tx_provers: required("ZYLITH_TX_PROVER_URLS")?
            .split(',')
            .map(str::to_owned)
            .collect(),
        ohttp_key_config: env::var("ZYLITH_TX_PROVER_OHTTP_KEY_CONFIG_HEX")
            .ok()
            .map(|hex| hex::decode(hex.trim()).unwrap_or_default()),
        timeout_seconds: 900,
        blocks_back: 20,
    });
    let proof_program = felt(&required("ZYLITH_PROOF_PROGRAM_ADDRESS")?, "proof program")?;
    let exchange = felt(&required("ZYLITH_EXCHANGE_ADDRESS")?, "exchange")?;
    for path in paths {
        let raw = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
        let values: Vec<String> =
            serde_json::from_str(&raw).map_err(|error| format!("{path}: {error}"))?;
        let witness = values
            .iter()
            .skip(1)
            .map(|value| felt(value, "witness felt"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut calldata = vec![
            exchange,
            starknet_rust_core::types::Felt::from(witness.len() as u64),
        ];
        calldata.extend(witness);
        let started = Instant::now();
        let result = snip36
            .prove_checked(
                vec![call(proof_program, "compile_transition_proof", calldata)],
                None,
            )
            .await;
        match result {
            // the facts carry what the exchange pins: the proof version, the virtual program hash and
            // the os config hash.
            Ok(proof) => println!(
                "{path}: proven in {} ms ({} proof bytes); proof_version={:#x} virtual_program_hash={:#x} os_config_hash={:#x}",
                started.elapsed().as_millis(),
                proof.proof.len(),
                proof.facts[0],
                proof.facts[2],
                proof.facts[6]
            ),
            Err(error) => println!(
                "{path}: failed after {} ms: {error}",
                started.elapsed().as_millis()
            ),
        }
    }
    Ok(())
}

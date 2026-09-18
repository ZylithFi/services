use std::{
    collections::BTreeMap,
    env, fs,
    io::Read,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Serialize;
use starknet_rust_accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
use starknet_rust_core::{
    types::{Call, Felt},
    utils::get_selector_from_name,
};
use starknet_rust_providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust_signers::{LocalWallet, SigningKey};
use url::Url;
use zylith_core::{
    ExternalMatchRequest, MatchProfitabilityCosts, StarknetCall, hash::normalize_felt_hex,
};
use zylith_matcher::{
    EkuboRouteAdapterConfig, ExternalMatchRequestSnapshot, MatchPlanInput, PlannedMatchReport,
    RequestRouteSet, RouteQuoteBatchRequest, RouteQuoteBatchResponse, SkipReason,
    SkippedMatchRequest, build_route_quote_request, fetch_onchain_external_match_requests,
    plan_external_match_requests, plan_external_match_snapshot, quote_ekubo_routes,
    validate_execution_plan_contracts,
};

const DEFAULT_MAX_ROUTE_AGE_MS: u64 = 2_000;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "shadow".into());

    if command == "serve-ekubo" {
        let bind = args.next().unwrap_or_else(|| "127.0.0.1:8788".into());
        if args.next().is_some() {
            return Err(usage());
        }
        return serve_ekubo(&bind).await;
    }

    if command == "snapshot-plan" {
        let snapshot_path = args.next().ok_or_else(usage)?;
        let routes_path = args.next().ok_or_else(usage)?;
        if args.next().is_some() {
            return Err(usage());
        }
        let snapshot = read_input(&snapshot_path)?;
        let routes = read_input(&routes_path)?;
        let output = zylith_matcher::plan_external_match_snapshot_json(&snapshot, &routes)
            .map_err(|error| error.to_string())?;
        println!("{output}");
        return Ok(());
    }

    if command == "poll-once" {
        let snapshot_url = args.next().ok_or_else(usage)?;
        let routes_url = args.next().ok_or_else(usage)?;
        if args.next().is_some() {
            return Err(usage());
        }
        let output = poll_once(&snapshot_url, &routes_url).await?;
        println!("{output}");
        return Ok(());
    }

    if command == "chain-poll-once" || command == "chain-execute-once" {
        let rpc_url = args.next().ok_or_else(usage)?;
        let executor_address = args.next().ok_or_else(usage)?;
        let routes_url = args.next().ok_or_else(usage)?;
        if args.next().is_some() {
            return Err(usage());
        }
        let report = plan_from_chain(&rpc_url, &executor_address, &routes_url).await?;
        if command == "chain-execute-once" {
            let submission = execute_best_plan(&rpc_url, &executor_address, report).await?;
            println!(
                "{}",
                serde_json::to_string(&submission)
                    .map_err(|error| format!("failed to encode submission: {error}"))?
            );
        } else {
            println!(
                "{}",
                serde_json::to_string(&report)
                    .map_err(|error| format!("failed to encode plan: {error}"))?
            );
        }
        return Ok(());
    }

    if command == "chain-run" {
        let rpc_url = args.next().ok_or_else(usage)?;
        let executor_address = args.next().ok_or_else(usage)?;
        let routes_url = args.next().ok_or_else(usage)?;
        if args.next().is_some() {
            return Err(usage());
        }
        return run_chain_matcher(&rpc_url, &executor_address, &routes_url).await;
    }

    if command != "shadow" && command != "plan" && command != "quote-request" {
        return Err(usage());
    }
    let input_path = args.next().unwrap_or_else(|| "-".into());
    if args.next().is_some() {
        return Err(usage());
    }
    let input = read_input(&input_path)?;
    let output = match command.as_str() {
        "shadow" => zylith_matcher::evaluate_shadow_input_json(&input),
        "plan" => zylith_matcher::plan_external_match_requests_json(&input),
        "quote-request" => zylith_matcher::build_route_quote_request_json(&input),
        _ => unreachable!(),
    }
    .map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    "usage: zylith-matcher <shadow|plan|quote-request> [input.json|-] | snapshot-plan <snapshot.json|-> <routes.json|-> | poll-once <snapshot-url> <routes-url> | <chain-poll-once|chain-execute-once|chain-run> <rpc-url> <external-match-executor> <routes-url> | serve-ekubo [bind-address]".into()
}

async fn run_chain_matcher(
    rpc_url: &str,
    executor_address: &str,
    routes_url: &str,
) -> Result<(), String> {
    let poll_interval =
        std::time::Duration::from_millis(env_u64("ZYLITH_MATCHER_POLL_INTERVAL_MS", 500)?);
    let error_backoff =
        std::time::Duration::from_millis(env_u64("ZYLITH_MATCHER_ERROR_BACKOFF_MS", 2_000)?);
    let post_submission_delay = std::time::Duration::from_millis(env_u64(
        "ZYLITH_MATCHER_POST_SUBMISSION_DELAY_MS",
        12_000,
    )?);
    if poll_interval.is_zero() || error_backoff.is_zero() || post_submission_delay.is_zero() {
        return Err("matcher timing intervals must be greater than zero".into());
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            outcome = plan_from_chain(rpc_url, executor_address, routes_url) => {
                match outcome {
                    Ok(report) if report.plans.is_empty() => {
                        tokio::time::sleep(poll_interval).await;
                    }
                    Ok(report) => match execute_best_plan(rpc_url, executor_address, report).await {
                        Ok(submission) => {
                            println!(
                                "{}",
                                serde_json::to_string(&submission)
                                    .map_err(|error| format!("failed to encode submission: {error}"))?
                            );
                            tokio::time::sleep(post_submission_delay).await;
                        }
                        Err(error) => {
                            eprintln!("external match execution cycle failed: {error}");
                            tokio::time::sleep(error_backoff).await;
                        }
                    },
                    Err(error) => {
                        eprintln!("external match planning cycle failed: {error}");
                        tokio::time::sleep(error_backoff).await;
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct EkuboServerState {
    client: reqwest::Client,
    config: EkuboRouteAdapterConfig,
}

async fn serve_ekubo(bind: &str) -> Result<(), String> {
    let bind = bind
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid Ekubo adapter bind address: {error}"))?;
    let asset_tokens = serde_json::from_str::<BTreeMap<String, String>>(
        &env::var("ZYLITH_MATCHER_ASSET_TOKENS_JSON")
            .map_err(|_| "ZYLITH_MATCHER_ASSET_TOKENS_JSON is required".to_string())?,
    )
    .map_err(|error| format!("invalid ZYLITH_MATCHER_ASSET_TOKENS_JSON: {error}"))?;
    if asset_tokens.is_empty() {
        return Err("ZYLITH_MATCHER_ASSET_TOKENS_JSON must not be empty".into());
    }
    let state = EkuboServerState {
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|error| format!("failed to build Ekubo HTTP client: {error}"))?,
        config: EkuboRouteAdapterConfig {
            chain_id: env::var("ZYLITH_MATCHER_EKUBO_CHAIN_ID")
                .unwrap_or_else(|_| "23448594291968334".into()),
            quoter_base_url: env::var("ZYLITH_MATCHER_EKUBO_QUOTER_URL")
                .unwrap_or_else(|_| "https://prod-api-quoter.ekubo.org".into()),
            atomic_router_address: env::var("ZYLITH_MATCHER_EKUBO_ATOMIC_ROUTER")
                .map_err(|_| "ZYLITH_MATCHER_EKUBO_ATOMIC_ROUTER is required".to_string())?,
            asset_tokens,
        },
    };
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/routes/ekubo", post(ekubo_routes_handler))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| format!("failed to bind Ekubo adapter: {error}"))?;
    axum::serve(listener, app)
        .await
        .map_err(|error| format!("Ekubo adapter failed: {error}"))
}

async fn ekubo_routes_handler(
    State(state): State<EkuboServerState>,
    Json(request): Json<RouteQuoteBatchRequest>,
) -> Result<Json<RouteQuoteBatchResponse>, (StatusCode, String)> {
    quote_ekubo_routes(&state.client, request, &state.config)
        .await
        .map(Json)
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))
}

fn read_input(input_path: &str) -> Result<String, String> {
    if input_path == "-" {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| format!("failed to read stdin: {error}"))?;
        Ok(input)
    } else {
        fs::read_to_string(input_path)
            .map_err(|error| format!("failed to read {input_path}: {error}"))
    }
}

async fn poll_once(snapshot_url: &str, routes_url: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let snapshot = client
        .get(snapshot_url)
        .send()
        .await
        .map_err(|error| format!("failed to fetch external match snapshot: {error}"))?
        .error_for_status()
        .map_err(|error| format!("external match snapshot endpoint failed: {error}"))?
        .json::<ExternalMatchRequestSnapshot>()
        .await
        .map_err(|error| format!("failed to decode external match snapshot: {error}"))?;
    let quote_request = build_route_quote_request(&snapshot);
    let routes = client
        .post(routes_url)
        .json(&quote_request)
        .send()
        .await
        .map_err(|error| format!("failed to fetch venue route quotes: {error}"))?
        .error_for_status()
        .map_err(|error| format!("venue route quote endpoint failed: {error}"))?
        .json::<RouteQuoteBatchResponse>()
        .await
        .map_err(|error| format!("failed to decode venue route quotes: {error}"))?;
    let report =
        plan_external_match_snapshot(snapshot, routes).map_err(|error| error.to_string())?;
    serde_json::to_string(&report).map_err(|error| format!("failed to encode plan: {error}"))
}

async fn plan_from_chain(
    rpc_url: &str,
    executor_address: &str,
    routes_url: &str,
) -> Result<PlannedMatchReport, String> {
    let client = reqwest::Client::new();
    let requests = fetch_onchain_external_match_requests(&client, rpc_url, executor_address)
        .await
        .map_err(|error| error.to_string())?;
    let costs_by_quote_asset = live_costs_by_quote_asset()?;
    let now_unix_ms = now_unix_ms()?;
    let max_route_age_ms = env_u64("ZYLITH_MATCHER_MAX_ROUTE_AGE_MS", DEFAULT_MAX_ROUTE_AGE_MS)?;
    let snapshot = ExternalMatchRequestSnapshot {
        now_unix_ms,
        max_route_age_ms,
        executor_contract_address: executor_address.to_owned(),
        requests: requests.clone(),
        costs: MatchProfitabilityCosts::default(),
        consumed_request_ids: Vec::new(),
        require_atomic_venue_calls: true,
    };
    let quote_request = build_route_quote_request(&snapshot);
    let mut request = client.post(routes_url).json(&quote_request);
    if let Ok(token) = env::var("ZYLITH_MATCHER_ROUTE_API_TOKEN") {
        let token = token.trim();
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
    }
    let routes = request
        .send()
        .await
        .map_err(|error| format!("failed to fetch venue route quotes: {error}"))?
        .error_for_status()
        .map_err(|error| format!("venue route quote endpoint failed: {error}"))?
        .json::<RouteQuoteBatchResponse>()
        .await
        .map_err(|error| format!("failed to decode venue route quotes: {error}"))?;
    plan_live_requests(
        requests,
        routes.request_routes,
        costs_by_quote_asset,
        now_unix_ms,
        max_route_age_ms,
        executor_address,
    )
}

fn live_costs_by_quote_asset() -> Result<BTreeMap<String, MatchProfitabilityCosts>, String> {
    let encoded = env::var("ZYLITH_MATCHER_COSTS_BY_QUOTE_ASSET_JSON")
        .map_err(|_| "ZYLITH_MATCHER_COSTS_BY_QUOTE_ASSET_JSON is required".to_string())?;
    parse_costs_by_quote_asset(&encoded)
}

fn parse_costs_by_quote_asset(
    encoded: &str,
) -> Result<BTreeMap<String, MatchProfitabilityCosts>, String> {
    let parsed = serde_json::from_str::<BTreeMap<String, MatchProfitabilityCosts>>(encoded)
        .map_err(|error| format!("invalid ZYLITH_MATCHER_COSTS_BY_QUOTE_ASSET_JSON: {error}"))?;
    if parsed.is_empty() {
        return Err("ZYLITH_MATCHER_COSTS_BY_QUOTE_ASSET_JSON must not be empty".into());
    }
    parsed
        .into_iter()
        .map(|(asset_id, costs)| {
            if costs.rebate_quote_amount != 0 {
                return Err("live matcher cost policies must use zero rebate".to_string());
            }
            if costs.min_profit_quote_amount <= 0 {
                return Err("live matcher minimum profit must be greater than zero".to_string());
            }
            normalize_felt_hex(&asset_id)
                .map(|asset_id| (asset_id, costs))
                .map_err(|error| format!("invalid matcher quote asset id {asset_id}: {error}"))
        })
        .collect()
}

fn plan_live_requests(
    requests: Vec<ExternalMatchRequest>,
    request_routes: Vec<RequestRouteSet>,
    costs_by_quote_asset: BTreeMap<String, MatchProfitabilityCosts>,
    now_unix_ms: u64,
    max_route_age_ms: u64,
    executor_address: &str,
) -> Result<PlannedMatchReport, String> {
    let mut routes_by_request = request_routes
        .into_iter()
        .map(|routes| (routes.request_id.clone(), routes))
        .collect::<BTreeMap<_, _>>();
    let mut combined = PlannedMatchReport {
        plans: Vec::new(),
        skipped: Vec::new(),
    };
    for request in requests {
        let quote_asset_id = normalize_felt_hex(&request.quote_asset_id.0)
            .map_err(|error| format!("invalid onchain quote asset id: {error}"))?;
        let Some(costs) = costs_by_quote_asset.get(&quote_asset_id).copied() else {
            combined.skipped.push(SkippedMatchRequest {
                request_id: request.request_id,
                reason: SkipReason::MissingCostPolicy,
            });
            continue;
        };
        let routes = routes_by_request
            .remove(&request.request_id)
            .into_iter()
            .collect();
        let report = plan_external_match_requests(MatchPlanInput {
            now_unix_ms,
            max_route_age_ms,
            executor_contract_address: executor_address.to_owned(),
            requests: vec![request],
            request_routes: routes,
            costs,
            consumed_request_ids: Vec::new(),
            require_atomic_venue_calls: true,
        })
        .map_err(|error| error.to_string())?;
        combined.plans.extend(report.plans);
        combined.skipped.extend(report.skipped);
    }
    Ok(combined)
}

#[derive(Serialize)]
struct ExecutionSubmission {
    request_id: String,
    transaction_hash: String,
    net_profit_quote_amount: i128,
}

async fn execute_best_plan(
    rpc_url: &str,
    executor_address: &str,
    report: PlannedMatchReport,
) -> Result<ExecutionSubmission, String> {
    let plan = report
        .plans
        .into_iter()
        .max_by_key(|plan| (plan.net_profit_quote_amount, plan.fill_base_amount))
        .ok_or_else(|| "no profitable executable external match plan".to_string())?;
    let allowed_contracts = required_address_list_env("ZYLITH_MATCHER_ALLOWED_ROUTE_CONTRACTS")?;
    validate_execution_plan_contracts(&plan, executor_address, &allowed_contracts)
        .map_err(|error| error.to_string())?;

    let rpc_url =
        Url::parse(rpc_url).map_err(|error| format!("invalid Starknet RPC URL: {error}"))?;
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));
    let private_key = required_felt_env("ZYLITH_MATCHER_ACCOUNT_PRIVATE_KEY")?;
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    let account_address = required_felt_env("ZYLITH_MATCHER_ACCOUNT_ADDRESS")?;
    let chain_id = required_felt_env("ZYLITH_MATCHER_CHAIN_ID")?;
    let account = SingleOwnerAccount::new(
        provider,
        signer,
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );
    let calls = plan
        .execution_calls
        .iter()
        .map(starknet_call_to_call)
        .collect::<Result<Vec<_>, _>>()?;
    account
        .execute_v3(calls.clone())
        .simulate(false, false)
        .await
        .map_err(|error| format!("external match simulation failed: {error}"))?;
    let sent = account
        .execute_v3(calls)
        .send()
        .await
        .map_err(|error| format!("external match broadcast failed: {error}"))?;
    Ok(ExecutionSubmission {
        request_id: plan.request_id,
        transaction_hash: format!("{:#x}", sent.transaction_hash),
        net_profit_quote_amount: plan.net_profit_quote_amount,
    })
}

fn starknet_call_to_call(call: &StarknetCall) -> Result<Call, String> {
    Ok(Call {
        to: parse_felt(&call.contract_address, "contract address")?,
        selector: get_selector_from_name(&call.entrypoint)
            .map_err(|error| format!("invalid entrypoint {}: {error}", call.entrypoint))?,
        calldata: call
            .calldata
            .iter()
            .map(|value| parse_felt(value, "calldata felt"))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn required_address_list_env(name: &str) -> Result<Vec<String>, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required for live execution"))?;
    let addresses = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(format!("{name} must contain at least one contract address"));
    }
    Ok(addresses)
}

fn required_felt_env(name: &str) -> Result<Felt, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required for live execution"))?;
    parse_felt(value.trim(), name)
}

fn parse_felt(value: &str, label: &str) -> Result<Felt, String> {
    Felt::from_hex(value).map_err(|error| format!("invalid {label} {value}: {error}"))
}

fn env_u64(name: &str, default: u64) -> Result<u64, String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn now_unix_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| "current Unix timestamp does not fit u64".into())
}

#[cfg(test)]
mod tests {
    use super::parse_costs_by_quote_asset;

    #[test]
    fn live_costs_are_quote_asset_scoped_and_normalized() {
        let costs = parse_costs_by_quote_asset(
            r#"{
                "0x000abc": {
                    "rebate_quote_amount": "0",
                    "gas_quote_amount": "100",
                    "tip_quote_amount": "20",
                    "safety_buffer_quote_amount": "30",
                    "min_profit_quote_amount": 50
                }
            }"#,
        )
        .expect("valid costs");
        let policy = costs.get("0xabc").expect("normalized asset policy");
        assert_eq!(policy.gas_quote_amount, 100);
        assert_eq!(policy.min_profit_quote_amount, 50);
    }

    #[test]
    fn live_costs_reject_rebates_and_nonpositive_profit() {
        let rebate = parse_costs_by_quote_asset(
            r#"{"0xabc":{"rebate_quote_amount":"1","gas_quote_amount":"0","tip_quote_amount":"0","safety_buffer_quote_amount":"0","min_profit_quote_amount":1}}"#,
        );
        assert!(rebate.is_err());
        let zero_profit = parse_costs_by_quote_asset(
            r#"{"0xabc":{"rebate_quote_amount":"0","gas_quote_amount":"0","tip_quote_amount":"0","safety_buffer_quote_amount":"0","min_profit_quote_amount":0}}"#,
        );
        assert!(zero_profit.is_err());
    }
}

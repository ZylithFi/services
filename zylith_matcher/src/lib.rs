use std::collections::{BTreeMap, BTreeSet};

use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use starknet_rust_core::{types::Felt, utils::get_selector_from_name};
use zylith_core::{
    ExternalHedgeQuote, ExternalMatchRequest, ExternalMatchRouteQuote, MatchProfitabilityCosts,
    OrderSide, PairId, StarknetCall, hash::normalize_felt_hex, optimal_external_match_fill,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VenueRouteSet {
    pub venue: String,
    pub observed_at_unix_ms: u64,
    pub routes: Vec<VenueRouteQuote>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VenueRouteQuote {
    #[serde(with = "serde_u128_decimal")]
    pub fill_base_amount: u128,
    pub hedge: ExternalHedgeQuote,
    #[serde(default)]
    pub calls_before_fill: Vec<StarknetCall>,
    #[serde(default)]
    pub calls_after_fill: Vec<StarknetCall>,
    #[serde(default)]
    pub atomic_execution_call: Option<StarknetCall>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MatchDecision {
    Wait,
    Fill {
        venue: String,
        fill_base_amount: u128,
        fill_quote_amount: u128,
        net_profit_quote_amount: i128,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowEvaluation {
    pub request_id: String,
    pub pair_id: PairId,
    pub side: OrderSide,
    pub zero_rebate_profitable: bool,
    pub decision: MatchDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowEvaluationInput {
    pub request: ExternalMatchRequest,
    pub venue_routes: Vec<VenueRouteSet>,
    pub costs: MatchProfitabilityCosts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRouteSet {
    pub request_id: String,
    pub venue_routes: Vec<VenueRouteSet>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchPlanInput {
    pub now_unix_ms: u64,
    pub max_route_age_ms: u64,
    pub executor_contract_address: String,
    pub requests: Vec<ExternalMatchRequest>,
    pub request_routes: Vec<RequestRouteSet>,
    pub costs: MatchProfitabilityCosts,
    pub consumed_request_ids: Vec<String>,
    pub require_atomic_venue_calls: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMatchRequestSnapshot {
    pub now_unix_ms: u64,
    pub max_route_age_ms: u64,
    pub executor_contract_address: String,
    pub requests: Vec<ExternalMatchRequest>,
    pub costs: MatchProfitabilityCosts,
    pub consumed_request_ids: Vec<String>,
    pub require_atomic_venue_calls: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnchainExternalMatchRequest {
    pub request_id: String,
    pub batch_id: String,
    pub pair_id: String,
    pub side: OrderSide,
    pub input_asset_id: String,
    pub output_asset_id: String,
    #[serde(with = "serde_u128_decimal")]
    pub max_base_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub reference_midpoint_price: u128,
    #[serde(with = "serde_u128_decimal")]
    pub price_base_scale: u128,
    pub valid_until_unix_ms: u64,
    pub match_deadline_unix_ms: u64,
    #[serde(with = "serde_u128_decimal")]
    pub consumed_base_amount: u128,
    pub closed: bool,
    pub settlement_consumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteQuoteBatchRequest {
    pub now_unix_ms: u64,
    pub requests: Vec<RouteQuoteRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteQuoteRequest {
    pub request: ExternalMatchRequest,
    #[serde(with = "serde_u128_decimal_vec")]
    pub candidate_fill_base_amounts: Vec<u128>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteQuoteBatchResponse {
    pub request_routes: Vec<RequestRouteSet>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EkuboRouteAdapterConfig {
    pub chain_id: String,
    pub quoter_base_url: String,
    pub atomic_router_address: String,
    pub asset_tokens: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
struct EkuboQuoteResponse {
    total_calculated: String,
    splits: Vec<EkuboSplit>,
}

#[derive(Clone, Debug, Deserialize)]
struct EkuboSplit {
    amount_specified: String,
    route: Vec<EkuboRouteNode>,
}

#[derive(Clone, Debug, Deserialize)]
struct EkuboRouteNode {
    pool_key: EkuboPoolKey,
    sqrt_ratio_limit: String,
    skip_ahead: u128,
}

#[derive(Clone, Debug, Deserialize)]
struct EkuboPoolKey {
    token0: String,
    token1: String,
    fee: String,
    tick_spacing: u128,
    extension: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedMatchReport {
    pub plans: Vec<ExecutableMatchPlan>,
    pub skipped: Vec<SkippedMatchRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableMatchPlan {
    pub request_id: String,
    pub pair_id: PairId,
    pub side: OrderSide,
    pub venue: String,
    pub route_observed_at_unix_ms: u64,
    #[serde(with = "serde_u128_decimal")]
    pub fill_base_amount: u128,
    #[serde(with = "serde_u128_decimal")]
    pub fill_quote_amount: u128,
    pub net_profit_quote_amount: i128,
    #[serde(with = "serde_u128_decimal")]
    pub minimum_onchain_profit_quote_amount: u128,
    pub executor_call: StarknetCall,
    pub calls_before_fill: Vec<StarknetCall>,
    pub calls_after_fill: Vec<StarknetCall>,
    pub atomic_execution_call: Option<StarknetCall>,
    pub execution_calls: Vec<StarknetCall>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedMatchRequest {
    pub request_id: String,
    pub reason: SkipReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkipReason {
    Expired,
    AlreadyConsumed,
    NoRoutes,
    StaleRoutes,
    NoExecutionCalls,
    NotProfitable,
    MissingCostPolicy,
}

pub fn candidate_fill_sizes(max_base_amount: u128) -> Vec<u128> {
    if max_base_amount == 0 {
        return Vec::new();
    }
    let mut candidates = [
        fraction(max_base_amount, 1, 100),
        fraction(max_base_amount, 1, 40),
        fraction(max_base_amount, 1, 20),
        fraction(max_base_amount, 1, 10),
        fraction(max_base_amount, 1, 4),
        fraction(max_base_amount, 1, 2),
        fraction(max_base_amount, 3, 4),
        max_base_amount,
    ]
    .into_iter()
    .filter(|amount| *amount > 0 && *amount <= max_base_amount)
    .collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn fraction(value: u128, numerator: u128, denominator: u128) -> u128 {
    value
        .checked_mul(numerator)
        .and_then(|scaled| scaled.checked_div(denominator))
        .unwrap_or(value)
}

pub fn evaluate_shadow_input(input: ShadowEvaluationInput) -> ShadowEvaluation {
    evaluate_external_match_request(&input.request, &input.venue_routes, input.costs)
}

pub fn evaluate_shadow_input_json(payload: &str) -> Result<String, MatcherError> {
    let input: ShadowEvaluationInput = serde_json::from_str(payload)?;
    let evaluation = evaluate_shadow_input(input);
    Ok(serde_json::to_string(&evaluation)?)
}

pub fn plan_external_match_requests_json(payload: &str) -> Result<String, MatcherError> {
    let input: MatchPlanInput = serde_json::from_str(payload)?;
    let report = plan_external_match_requests(input)?;
    Ok(serde_json::to_string(&report)?)
}

pub fn build_route_quote_request_json(payload: &str) -> Result<String, MatcherError> {
    let snapshot: ExternalMatchRequestSnapshot = serde_json::from_str(payload)?;
    Ok(serde_json::to_string(&build_route_quote_request(
        &snapshot,
    ))?)
}

pub fn plan_external_match_snapshot_json(
    snapshot_payload: &str,
    routes_payload: &str,
) -> Result<String, MatcherError> {
    let snapshot: ExternalMatchRequestSnapshot = serde_json::from_str(snapshot_payload)?;
    let routes: RouteQuoteBatchResponse = serde_json::from_str(routes_payload)?;
    let report = plan_external_match_snapshot(snapshot, routes)?;
    Ok(serde_json::to_string(&report)?)
}

pub fn build_route_quote_request(
    snapshot: &ExternalMatchRequestSnapshot,
) -> RouteQuoteBatchRequest {
    RouteQuoteBatchRequest {
        now_unix_ms: snapshot.now_unix_ms,
        requests: snapshot
            .requests
            .iter()
            .cloned()
            .map(|request| RouteQuoteRequest {
                candidate_fill_base_amounts: candidate_fill_sizes(request.max_base_amount),
                request,
            })
            .collect(),
    }
}

pub async fn quote_ekubo_routes(
    client: &reqwest::Client,
    request: RouteQuoteBatchRequest,
    config: &EkuboRouteAdapterConfig,
) -> Result<RouteQuoteBatchResponse, MatcherError> {
    let observed_at_unix_ms = request.now_unix_ms;
    let quoted = stream::iter(
        request
            .requests
            .into_iter()
            .map(|route_request| async move {
                quote_ekubo_request(client, route_request, config, observed_at_unix_ms).await
            }),
    )
    .buffer_unordered(8)
    .collect::<Vec<_>>()
    .await;
    let mut request_routes = Vec::with_capacity(quoted.len());
    for result in quoted {
        request_routes.push(result?);
    }
    request_routes.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(RouteQuoteBatchResponse { request_routes })
}

async fn quote_ekubo_request(
    client: &reqwest::Client,
    route_request: RouteQuoteRequest,
    config: &EkuboRouteAdapterConfig,
    observed_at_unix_ms: u64,
) -> Result<RequestRouteSet, MatcherError> {
    let base_token = configured_asset_token(config, &route_request.request.base_asset_id.0)?;
    let quote_token = configured_asset_token(config, &route_request.request.quote_asset_id.0)?;
    let request_id = normalize_request_id(&route_request.request.request_id)?;
    let mut routes = Vec::new();
    for fill_base_amount in route_request.candidate_fill_base_amounts {
        if fill_base_amount == 0 || fill_base_amount > route_request.request.max_base_amount {
            continue;
        }
        let signed_amount = match route_request.request.side {
            OrderSide::Buy => format!("-{fill_base_amount}"),
            OrderSide::Sell => fill_base_amount.to_string(),
        };
        let url = format!(
            "{}/{}/{}/{}/{}",
            config.quoter_base_url.trim_end_matches('/'),
            config.chain_id,
            signed_amount,
            base_token,
            quote_token,
        );
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|error| MatcherError::Route(format!("Ekubo quote failed: {error}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            continue;
        }
        let quote = response
            .error_for_status()
            .map_err(|error| MatcherError::Route(format!("Ekubo quote failed: {error}")))?
            .json::<EkuboQuoteResponse>()
            .await
            .map_err(|error| MatcherError::Route(format!("invalid Ekubo quote: {error}")))?;
        if quote.splits.is_empty() {
            continue;
        }
        let calculated = parse_signed_magnitude(&quote.total_calculated, "Ekubo total")?;
        let hedge = match route_request.request.side {
            OrderSide::Buy => ExternalHedgeQuote::BuyBase {
                quote_cost_amount: calculated,
            },
            OrderSide::Sell => ExternalHedgeQuote::SellBase {
                quote_proceeds_amount: calculated,
            },
        };
        let atomic_execution_call = StarknetCall {
            contract_address: normalize_felt_hex(&config.atomic_router_address).map_err(
                |error| {
                    MatcherError::Route(format!("invalid Ekubo atomic router address: {error}"))
                },
            )?,
            entrypoint: "execute_external_match".into(),
            calldata: encode_ekubo_atomic_call(
                &request_id,
                fill_base_amount,
                &base_token,
                &quote.splits,
            )?,
        };
        routes.push(VenueRouteQuote {
            fill_base_amount,
            hedge,
            calls_before_fill: Vec::new(),
            calls_after_fill: Vec::new(),
            atomic_execution_call: Some(atomic_execution_call),
        });
    }
    Ok(RequestRouteSet {
        request_id,
        venue_routes: vec![VenueRouteSet {
            venue: "ekubo-flash".into(),
            observed_at_unix_ms,
            routes,
        }],
    })
}

fn configured_asset_token(
    config: &EkuboRouteAdapterConfig,
    asset_id: &str,
) -> Result<String, MatcherError> {
    let token = config.asset_tokens.get(asset_id).ok_or_else(|| {
        MatcherError::Route(format!("no Ekubo token configured for asset {asset_id}"))
    })?;
    normalize_felt_hex(token)
        .map_err(|error| MatcherError::Route(format!("invalid token for {asset_id}: {error}")))
}

fn encode_ekubo_atomic_call(
    request_id: &str,
    fill_base_amount: u128,
    base_token: &str,
    splits: &[EkuboSplit],
) -> Result<Vec<String>, MatcherError> {
    let mut calldata = vec![
        "0x0".into(),
        request_id.to_owned(),
        encode_u128(fill_base_amount),
        "0x0".into(),
        encode_u128(splits.len() as u128),
    ];
    let mut total_specified = 0_u128;
    let expected_sign = splits
        .first()
        .map(|split| split.amount_specified.starts_with('-'))
        .unwrap_or(false);
    for split in splits {
        if split.route.is_empty() {
            return Err(MatcherError::Route("Ekubo returned an empty route".into()));
        }
        calldata.push(encode_u128(split.route.len() as u128));
        for node in &split.route {
            calldata.push(normalize_route_felt(&node.pool_key.token0, "pool token0")?);
            calldata.push(normalize_route_felt(&node.pool_key.token1, "pool token1")?);
            calldata.push(normalize_route_felt(&node.pool_key.fee, "pool fee")?);
            calldata.push(encode_u128(node.pool_key.tick_spacing));
            calldata.push(normalize_route_felt(
                &node.pool_key.extension,
                "pool extension",
            )?);
            let (sqrt_low, sqrt_high) = split_u256_hex(&node.sqrt_ratio_limit)?;
            calldata.push(sqrt_low);
            calldata.push(sqrt_high);
            calldata.push(encode_u128(node.skip_ahead));
        }
        let sign = split.amount_specified.starts_with('-');
        if sign != expected_sign {
            return Err(MatcherError::Route(
                "Ekubo quote mixed exact-input and exact-output splits".into(),
            ));
        }
        let amount = parse_signed_magnitude(&split.amount_specified, "Ekubo split amount")?;
        total_specified = total_specified
            .checked_add(amount)
            .ok_or_else(|| MatcherError::Route("Ekubo split amount overflow".into()))?;
        calldata.push(base_token.to_owned());
        calldata.push(encode_u128(amount));
        calldata.push(if sign { "0x1".into() } else { "0x0".into() });
    }
    if total_specified != fill_base_amount {
        return Err(MatcherError::Route(format!(
            "Ekubo split total {total_specified} does not match fill {fill_base_amount}"
        )));
    }
    Ok(calldata)
}

fn normalize_route_felt(value: &str, label: &str) -> Result<String, MatcherError> {
    let felt = if value.starts_with("0x") {
        Felt::from_hex(value)
    } else {
        Felt::from_dec_str(value)
    }
    .map_err(|error| MatcherError::Route(format!("invalid {label}: {error}")))?;
    Ok(format!("{felt:#x}"))
}

fn split_u256_hex(value: &str) -> Result<(String, String), MatcherError> {
    let felt = Felt::from_hex(value)
        .map_err(|error| MatcherError::Route(format!("invalid sqrt ratio: {error}")))?;
    let bytes = felt.to_bytes_be();
    let high = u128::from_be_bytes(
        bytes[..16]
            .try_into()
            .map_err(|_| MatcherError::Route("invalid sqrt ratio high limb".into()))?,
    );
    let low = u128::from_be_bytes(
        bytes[16..]
            .try_into()
            .map_err(|_| MatcherError::Route("invalid sqrt ratio low limb".into()))?,
    );
    Ok((encode_u128(low), encode_u128(high)))
}

fn parse_signed_magnitude(value: &str, label: &str) -> Result<u128, MatcherError> {
    value
        .strip_prefix('-')
        .unwrap_or(value)
        .parse::<u128>()
        .map_err(|error| MatcherError::Route(format!("invalid {label}: {error}")))
}

pub fn request_from_onchain_state(
    state: OnchainExternalMatchRequest,
) -> Option<ExternalMatchRequest> {
    if state.closed || state.settlement_consumed {
        return None;
    }
    let remaining_base_amount = state
        .max_base_amount
        .checked_sub(state.consumed_base_amount)?;
    if remaining_base_amount == 0 {
        return None;
    }
    let (base_asset_id, quote_asset_id) = match state.side {
        OrderSide::Buy => (state.output_asset_id, state.input_asset_id),
        OrderSide::Sell => (state.input_asset_id, state.output_asset_id),
    };
    Some(ExternalMatchRequest {
        request_id: state.request_id.clone(),
        batch_id: zylith_core::BatchId(state.batch_id),
        pair_id: PairId(state.pair_id),
        base_asset_id: zylith_core::AssetId(base_asset_id),
        quote_asset_id: zylith_core::AssetId(quote_asset_id),
        side: state.side,
        max_base_amount: remaining_base_amount,
        reference_midpoint_price: state.reference_midpoint_price,
        price_base_scale: state.price_base_scale,
        valid_until_unix_ms: state.match_deadline_unix_ms,
    })
}

const ONCHAIN_REQUEST_PAGE_SIZE: u32 = 256;
const ONCHAIN_REQUEST_FETCH_CONCURRENCY: usize = 16;

#[derive(Serialize)]
struct StarknetRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct StarknetRpcResponse {
    result: Option<Vec<String>>,
    error: Option<serde_json::Value>,
}

pub async fn fetch_onchain_external_match_requests(
    client: &reqwest::Client,
    rpc_url: &str,
    executor_contract_address: &str,
) -> Result<Vec<ExternalMatchRequest>, MatcherError> {
    let executor_contract_address = normalize_felt_hex(executor_contract_address)
        .map_err(|error| MatcherError::Rpc(format!("invalid executor address: {error}")))?;
    let count_result = starknet_call(
        client,
        rpc_url,
        &executor_contract_address,
        "request_count",
        Vec::new(),
    )
    .await?;
    let request_count = decode_single_u64(&count_result, "request_count")?;
    let mut request_ids = Vec::with_capacity(usize::try_from(request_count).unwrap_or(usize::MAX));
    let mut start = 0_u64;
    while start < request_count {
        let limit =
            u32::try_from((request_count - start).min(u64::from(ONCHAIN_REQUEST_PAGE_SIZE)))
                .map_err(|_| MatcherError::Rpc("external match page length overflow".into()))?;
        let page = starknet_call(
            client,
            rpc_url,
            &executor_contract_address,
            "request_ids",
            vec![format!("0x{start:x}"), format!("0x{limit:x}")],
        )
        .await?;
        let mut page_ids = decode_felt_span(&page, "request_ids")?;
        if page_ids.len() != usize::try_from(limit).unwrap_or(usize::MAX) {
            return Err(MatcherError::Rpc(format!(
                "request_ids returned {} ids for requested page length {limit}",
                page_ids.len()
            )));
        }
        request_ids.append(&mut page_ids);
        start = start.saturating_add(u64::from(limit));
    }

    let states = stream::iter(request_ids.into_iter().map(|request_id| {
        let client = client.clone();
        let rpc_url = rpc_url.to_owned();
        let executor_contract_address = executor_contract_address.clone();
        async move {
            let result = starknet_call(
                &client,
                &rpc_url,
                &executor_contract_address,
                "external_match_request",
                vec![request_id.clone()],
            )
            .await?;
            decode_onchain_request(&request_id, &result)
        }
    }))
    .buffer_unordered(ONCHAIN_REQUEST_FETCH_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;

    let mut requests = states
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(request_from_onchain_state)
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(requests)
}

async fn starknet_call(
    client: &reqwest::Client,
    rpc_url: &str,
    contract_address: &str,
    entrypoint: &str,
    calldata: Vec<String>,
) -> Result<Vec<String>, MatcherError> {
    let selector = get_selector_from_name(entrypoint)
        .map_err(|error| MatcherError::Rpc(format!("invalid entrypoint {entrypoint}: {error}")))?;
    let request = StarknetRpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "starknet_call",
        params: serde_json::json!([
            {
                "contract_address": contract_address,
                "entry_point_selector": format!("{selector:#x}"),
                "calldata": calldata,
            },
            "latest"
        ]),
    };
    let response = client
        .post(rpc_url)
        .json(&request)
        .send()
        .await
        .map_err(|error| MatcherError::Rpc(format!("starknet rpc request failed: {error}")))?
        .error_for_status()
        .map_err(|error| MatcherError::Rpc(format!("starknet rpc http failure: {error}")))?
        .json::<StarknetRpcResponse>()
        .await
        .map_err(|error| MatcherError::Rpc(format!("invalid starknet rpc response: {error}")))?;
    response.result.ok_or_else(|| {
        MatcherError::Rpc(format!(
            "starknet rpc call {entrypoint} failed: {}",
            response.error.unwrap_or(serde_json::Value::Null)
        ))
    })
}

fn decode_single_u64(result: &[String], label: &str) -> Result<u64, MatcherError> {
    if result.len() != 1 {
        return Err(MatcherError::Rpc(format!(
            "{label} returned {} values, expected 1",
            result.len()
        )));
    }
    decode_u64(&result[0], label)
}

fn decode_felt_span(result: &[String], label: &str) -> Result<Vec<String>, MatcherError> {
    let Some(encoded_len) = result.first() else {
        return Err(MatcherError::Rpc(format!(
            "{label} returned an empty result"
        )));
    };
    let len = usize::try_from(decode_u64(encoded_len, label)?)
        .map_err(|_| MatcherError::Rpc(format!("{label} length does not fit usize")))?;
    if result.len() != len.saturating_add(1) {
        return Err(MatcherError::Rpc(format!(
            "{label} encoded length {len} does not match {} values",
            result.len().saturating_sub(1)
        )));
    }
    result[1..]
        .iter()
        .map(|value| {
            normalize_felt_hex(value)
                .map_err(|error| MatcherError::Rpc(format!("invalid {label} felt: {error}")))
        })
        .collect()
}

fn decode_onchain_request(
    request_id: &str,
    result: &[String],
) -> Result<OnchainExternalMatchRequest, MatcherError> {
    if result.len() != 13 {
        return Err(MatcherError::Rpc(format!(
            "external_match_request returned {} values, expected 13",
            result.len()
        )));
    }
    let side = match decode_u64(&result[2], "request side")? {
        0 => OrderSide::Buy,
        1 => OrderSide::Sell,
        side => return Err(MatcherError::Rpc(format!("invalid request side {side}"))),
    };
    Ok(OnchainExternalMatchRequest {
        request_id: normalize_request_id(request_id)?,
        batch_id: normalize_rpc_felt(&result[0], "batch id")?,
        pair_id: normalize_rpc_felt(&result[1], "pair id")?,
        side,
        input_asset_id: normalize_rpc_felt(&result[3], "input asset id")?,
        output_asset_id: normalize_rpc_felt(&result[4], "output asset id")?,
        max_base_amount: decode_u128(&result[5], "max base amount")?,
        reference_midpoint_price: decode_u128(&result[6], "reference midpoint price")?,
        price_base_scale: decode_u128(&result[7], "price base scale")?,
        valid_until_unix_ms: decode_u64(&result[8], "valid until")?,
        match_deadline_unix_ms: decode_u64(&result[9], "match deadline")?,
        consumed_base_amount: decode_u128(&result[10], "consumed base amount")?,
        closed: decode_bool(&result[11], "request closed")?,
        settlement_consumed: decode_bool(&result[12], "request settlement consumed")?,
    })
}

fn normalize_rpc_felt(value: &str, label: &str) -> Result<String, MatcherError> {
    normalize_felt_hex(value)
        .map_err(|error| MatcherError::Rpc(format!("invalid {label}: {error}")))
}

fn decode_bool(value: &str, label: &str) -> Result<bool, MatcherError> {
    match decode_u64(value, label)? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(MatcherError::Rpc(format!("invalid {label} flag {value}"))),
    }
}

fn decode_u128(value: &str, label: &str) -> Result<u128, MatcherError> {
    let felt = Felt::from_hex(value)
        .map_err(|error| MatcherError::Rpc(format!("invalid {label} {value}: {error}")))?;
    let bytes = felt.to_bytes_be();
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return Err(MatcherError::Rpc(format!("{label} exceeds u128")));
    }
    Ok(u128::from_be_bytes(bytes[16..].try_into().map_err(
        |_| MatcherError::Rpc(format!("invalid {label} byte length")),
    )?))
}

fn decode_u64(value: &str, label: &str) -> Result<u64, MatcherError> {
    let decoded = decode_u128(value, label)?;
    u64::try_from(decoded).map_err(|_| MatcherError::Rpc(format!("{label} exceeds u64")))
}

pub fn plan_external_match_snapshot(
    snapshot: ExternalMatchRequestSnapshot,
    routes: RouteQuoteBatchResponse,
) -> Result<PlannedMatchReport, MatcherError> {
    plan_external_match_requests(MatchPlanInput {
        now_unix_ms: snapshot.now_unix_ms,
        max_route_age_ms: snapshot.max_route_age_ms,
        executor_contract_address: snapshot.executor_contract_address,
        requests: snapshot.requests,
        request_routes: routes.request_routes,
        costs: snapshot.costs,
        consumed_request_ids: snapshot.consumed_request_ids,
        require_atomic_venue_calls: snapshot.require_atomic_venue_calls,
    })
}

pub fn plan_external_match_requests(
    input: MatchPlanInput,
) -> Result<PlannedMatchReport, MatcherError> {
    let executor_contract_address = normalize_felt_hex(&input.executor_contract_address)
        .map_err(|error| MatcherError::InvalidPlan(format!("invalid executor address: {error}")))?;
    let consumed = input
        .consumed_request_ids
        .iter()
        .map(|request_id| normalize_request_id(request_id))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut routes_by_request = BTreeMap::<String, Vec<VenueRouteSet>>::new();
    for request_routes in input.request_routes {
        let request_id = normalize_request_id(&request_routes.request_id)?;
        routes_by_request.insert(request_id, request_routes.venue_routes);
    }

    let mut plans = Vec::new();
    let mut skipped = Vec::new();
    for request in input.requests {
        let request_id = normalize_request_id(&request.request_id)?;
        if input.now_unix_ms > request.valid_until_unix_ms {
            skipped.push(skipped_request(request_id, SkipReason::Expired));
            continue;
        }
        if consumed.contains(&request_id) {
            skipped.push(skipped_request(request_id, SkipReason::AlreadyConsumed));
            continue;
        }
        let Some(routes) = routes_by_request.get(&request_id) else {
            skipped.push(skipped_request(request_id, SkipReason::NoRoutes));
            continue;
        };
        if routes.is_empty() {
            skipped.push(skipped_request(request_id, SkipReason::NoRoutes));
            continue;
        }
        let fresh_routes = fresh_route_sets(routes, input.now_unix_ms, input.max_route_age_ms);
        if fresh_routes.is_empty() {
            skipped.push(skipped_request(request_id, SkipReason::StaleRoutes));
            continue;
        }
        if input.require_atomic_venue_calls && !contains_executable_route(&fresh_routes) {
            skipped.push(skipped_request(request_id, SkipReason::NoExecutionCalls));
            continue;
        }
        let Some((venue, route_observed_at_unix_ms, route, fill)) = best_venue_fill(
            &request,
            &fresh_routes,
            input.costs,
            input.require_atomic_venue_calls,
        ) else {
            skipped.push(skipped_request(request_id, SkipReason::NotProfitable));
            continue;
        };
        let executor_call =
            external_match_executor_call(&executor_contract_address, &request, &fill)?;
        let minimum_onchain_profit_quote_amount = minimum_onchain_profit(input.costs)?;
        let atomic_execution_call = route
            .atomic_execution_call
            .as_ref()
            .map(|call| {
                bind_atomic_execution_call(
                    call,
                    &executor_contract_address,
                    &request_id,
                    fill.fill_base_amount,
                    minimum_onchain_profit_quote_amount,
                )
            })
            .transpose()?;
        let execution_calls = ordered_execution_calls(
            &route.calls_before_fill,
            &executor_call,
            &route.calls_after_fill,
            atomic_execution_call.as_ref(),
        );
        plans.push(ExecutableMatchPlan {
            request_id,
            pair_id: request.pair_id,
            side: request.side,
            venue,
            route_observed_at_unix_ms,
            fill_base_amount: fill.fill_base_amount,
            fill_quote_amount: fill.fill_quote_amount,
            net_profit_quote_amount: fill.net_profit_quote_amount,
            minimum_onchain_profit_quote_amount,
            executor_call,
            calls_before_fill: route.calls_before_fill.clone(),
            calls_after_fill: route.calls_after_fill.clone(),
            atomic_execution_call,
            execution_calls,
        });
    }

    Ok(PlannedMatchReport { plans, skipped })
}

pub fn validate_execution_plan_contracts(
    plan: &ExecutableMatchPlan,
    executor_contract_address: &str,
    allowed_route_contract_addresses: &[String],
) -> Result<(), MatcherError> {
    if plan.net_profit_quote_amount <= 0 {
        return Err(MatcherError::InvalidPlan(format!(
            "request {} is not net profitable",
            plan.request_id
        )));
    }
    let executor = normalize_felt_hex(executor_contract_address).map_err(|error| {
        MatcherError::InvalidPlan(format!("invalid executor contract address: {error}"))
    })?;
    let allowed = allowed_route_contract_addresses
        .iter()
        .map(|address| {
            normalize_felt_hex(address).map_err(|error| {
                MatcherError::InvalidPlan(format!("invalid allowed route contract: {error}"))
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_calls = ordered_execution_calls(
        &plan.calls_before_fill,
        &plan.executor_call,
        &plan.calls_after_fill,
        plan.atomic_execution_call.as_ref(),
    );
    if plan.execution_calls != expected_calls {
        return Err(MatcherError::InvalidPlan(format!(
            "request {} execution call order does not match the planned route",
            plan.request_id
        )));
    }
    let normalized_executor_call_address = normalize_felt_hex(&plan.executor_call.contract_address)
        .map_err(|error| MatcherError::InvalidPlan(format!("invalid executor call: {error}")))?;
    if normalized_executor_call_address != executor
        || plan.executor_call.entrypoint != "settle_external_match_fill"
    {
        return Err(MatcherError::InvalidPlan(format!(
            "request {} has an invalid external match fill call",
            plan.request_id
        )));
    }

    if let Some(atomic_call) = &plan.atomic_execution_call {
        if !plan.calls_before_fill.is_empty() || !plan.calls_after_fill.is_empty() {
            return Err(MatcherError::InvalidPlan(format!(
                "request {} mixes an atomic wrapper with account-level route calls",
                plan.request_id
            )));
        }
        let atomic_address =
            normalize_felt_hex(&atomic_call.contract_address).map_err(|error| {
                MatcherError::InvalidPlan(format!("invalid atomic wrapper address: {error}"))
            })?;
        if !allowed.contains(&atomic_address) {
            return Err(MatcherError::InvalidPlan(format!(
                "request {} calls untrusted atomic wrapper {atomic_address}",
                plan.request_id
            )));
        }
        if atomic_call.entrypoint != "execute_external_match" || atomic_call.calldata.len() < 4 {
            return Err(MatcherError::InvalidPlan(format!(
                "request {} has an invalid atomic wrapper call",
                plan.request_id
            )));
        }
        let wrapper_executor = normalize_felt_hex(&atomic_call.calldata[0]).map_err(|error| {
            MatcherError::InvalidPlan(format!("invalid atomic wrapper executor: {error}"))
        })?;
        let wrapper_request = normalize_request_id(&atomic_call.calldata[1])?;
        let wrapper_fill = decode_u128(&atomic_call.calldata[2], "atomic wrapper fill amount")?;
        let wrapper_minimum_profit =
            decode_u128(&atomic_call.calldata[3], "atomic wrapper minimum profit")?;
        if wrapper_executor != executor
            || wrapper_request != normalize_request_id(&plan.request_id)?
            || wrapper_fill != plan.fill_base_amount
            || wrapper_minimum_profit != plan.minimum_onchain_profit_quote_amount
        {
            return Err(MatcherError::InvalidPlan(format!(
                "request {} atomic wrapper is not bound to the planned fill",
                plan.request_id
            )));
        }
        return Ok(());
    }

    let mut exact_fill_call_count = 0_usize;
    for call in &plan.execution_calls {
        let address = normalize_felt_hex(&call.contract_address).map_err(|error| {
            MatcherError::InvalidPlan(format!("invalid execution call address: {error}"))
        })?;
        if address == executor {
            if call != &plan.executor_call {
                return Err(MatcherError::InvalidPlan(format!(
                    "request {} contains an unauthorized executor call",
                    plan.request_id
                )));
            }
            exact_fill_call_count += 1;
        } else if !allowed.contains(&address) {
            return Err(MatcherError::InvalidPlan(format!(
                "request {} calls untrusted route contract {address}",
                plan.request_id
            )));
        }
    }
    if exact_fill_call_count != 1 {
        return Err(MatcherError::InvalidPlan(format!(
            "request {} must contain exactly one external match fill call",
            plan.request_id
        )));
    }
    Ok(())
}

fn minimum_onchain_profit(costs: MatchProfitabilityCosts) -> Result<u128, MatcherError> {
    let minimum_profit = u128::try_from(costs.min_profit_quote_amount.max(0)).map_err(|_| {
        MatcherError::InvalidPlan("minimum profit does not fit the onchain amount".into())
    })?;
    costs
        .gas_quote_amount
        .checked_add(costs.tip_quote_amount)
        .and_then(|amount| amount.checked_add(costs.safety_buffer_quote_amount))
        .and_then(|amount| amount.checked_add(minimum_profit))
        .ok_or_else(|| MatcherError::InvalidPlan("onchain profit floor overflow".into()))
}

fn bind_atomic_execution_call(
    call: &StarknetCall,
    executor_contract_address: &str,
    request_id: &str,
    fill_base_amount: u128,
    minimum_profit_quote_amount: u128,
) -> Result<StarknetCall, MatcherError> {
    if call.entrypoint != "execute_external_match" || call.calldata.len() < 4 {
        return Err(MatcherError::InvalidPlan(
            "atomic route must call execute_external_match with wrapper calldata".into(),
        ));
    }
    let mut bound = call.clone();
    bound.calldata[0] = executor_contract_address.to_owned();
    bound.calldata[1] = request_id.to_owned();
    bound.calldata[2] = encode_u128(fill_base_amount);
    bound.calldata[3] = encode_u128(minimum_profit_quote_amount);
    Ok(bound)
}

pub fn evaluate_external_match_request(
    request: &ExternalMatchRequest,
    venue_routes: &[VenueRouteSet],
    costs: MatchProfitabilityCosts,
) -> ShadowEvaluation {
    let venue_routes = venue_routes.iter().collect::<Vec<_>>();
    let zero_rebate_profitable =
        best_venue_fill(request, &venue_routes, costs_without_rebate(costs), false).is_some();
    let decision = best_venue_fill(request, &venue_routes, costs, false)
        .map(|(venue, _, _, fill)| MatchDecision::Fill {
            venue,
            fill_base_amount: fill.fill_base_amount,
            fill_quote_amount: fill.fill_quote_amount,
            net_profit_quote_amount: fill.net_profit_quote_amount,
        })
        .unwrap_or(MatchDecision::Wait);
    ShadowEvaluation {
        request_id: request.request_id.clone(),
        pair_id: request.pair_id.clone(),
        side: request.side,
        zero_rebate_profitable,
        decision,
    }
}

fn best_venue_fill(
    request: &ExternalMatchRequest,
    venue_routes: &[&VenueRouteSet],
    costs: MatchProfitabilityCosts,
    require_atomic_venue_calls: bool,
) -> Option<(String, u64, VenueRouteQuote, zylith_core::ExternalMatchFill)> {
    venue_routes
        .iter()
        .flat_map(|venue| {
            venue.routes.iter().filter_map(|route| {
                if require_atomic_venue_calls && !route_has_executable_calls(route) {
                    return None;
                }
                let core_route = core_route_quote(route);
                let fill = optimal_external_match_fill(request, &[core_route], costs)?;
                Some((
                    venue.venue.clone(),
                    venue.observed_at_unix_ms,
                    route.clone(),
                    fill,
                ))
            })
        })
        .max_by_key(|(_, _, _, fill)| (fill.net_profit_quote_amount, fill.fill_base_amount))
}

fn contains_executable_route(venue_routes: &[&VenueRouteSet]) -> bool {
    venue_routes
        .iter()
        .any(|venue| venue.routes.iter().any(route_has_executable_calls))
}

fn route_has_executable_calls(route: &VenueRouteQuote) -> bool {
    route.atomic_execution_call.is_some()
        || !route.calls_before_fill.is_empty()
        || !route.calls_after_fill.is_empty()
}

fn fresh_route_sets(
    route_sets: &[VenueRouteSet],
    now_unix_ms: u64,
    max_route_age_ms: u64,
) -> Vec<&VenueRouteSet> {
    route_sets
        .iter()
        .filter(|routes| {
            routes.observed_at_unix_ms <= now_unix_ms
                && now_unix_ms - routes.observed_at_unix_ms <= max_route_age_ms
        })
        .collect()
}

fn core_route_quote(route: &VenueRouteQuote) -> ExternalMatchRouteQuote {
    ExternalMatchRouteQuote {
        fill_base_amount: route.fill_base_amount,
        hedge: route.hedge.clone(),
    }
}

fn ordered_execution_calls(
    calls_before_fill: &[StarknetCall],
    executor_call: &StarknetCall,
    calls_after_fill: &[StarknetCall],
    atomic_execution_call: Option<&StarknetCall>,
) -> Vec<StarknetCall> {
    if let Some(call) = atomic_execution_call {
        return vec![call.clone()];
    }
    let mut calls = Vec::with_capacity(calls_before_fill.len() + 1 + calls_after_fill.len());
    calls.extend(calls_before_fill.iter().cloned());
    calls.push(executor_call.clone());
    calls.extend(calls_after_fill.iter().cloned());
    calls
}

fn costs_without_rebate(mut costs: MatchProfitabilityCosts) -> MatchProfitabilityCosts {
    costs.rebate_quote_amount = 0;
    costs
}

fn external_match_executor_call(
    executor_contract_address: &str,
    request: &ExternalMatchRequest,
    fill: &zylith_core::ExternalMatchFill,
) -> Result<StarknetCall, MatcherError> {
    let request_id = normalize_request_id(&request.request_id)?;
    Ok(StarknetCall {
        contract_address: executor_contract_address.to_owned(),
        entrypoint: "settle_external_match_fill".into(),
        calldata: vec![request_id, encode_u128(fill.fill_base_amount)],
    })
}

fn normalize_request_id(request_id: &str) -> Result<String, MatcherError> {
    normalize_felt_hex(request_id)
        .map_err(|error| MatcherError::InvalidPlan(format!("invalid request id: {error}")))
}

fn skipped_request(request_id: String, reason: SkipReason) -> SkippedMatchRequest {
    SkippedMatchRequest { request_id, reason }
}

fn encode_u128(value: u128) -> String {
    format!("0x{value:x}")
}

mod serde_u128_decimal {
    use std::fmt;

    use serde::{
        Deserializer, Serializer,
        de::{self, Visitor},
    };

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(U128DecimalVisitor)
    }

    struct U128DecimalVisitor;

    impl<'de> Visitor<'de> for U128DecimalVisitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a u128 decimal string or integer")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(u128::from(value))
        }

        fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value != value.trim() {
                return Err(E::custom(
                    "u128 string must not include surrounding whitespace",
                ));
            }
            value
                .parse::<u128>()
                .map_err(|error| E::custom(format!("invalid u128: {error}")))
        }
    }
}

mod serde_u128_decimal_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &[u128], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_strings = value.iter().map(u128::to_string).collect::<Vec<_>>();
        as_strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<crate::serde_u128_decimal_vec::U128StringOrInteger>::deserialize(deserializer)
            .map(|values| values.into_iter().map(|value| value.0).collect())
    }

    #[derive(Deserialize)]
    #[serde(transparent)]
    pub struct U128StringOrInteger(#[serde(with = "crate::serde_u128_decimal")] pub u128);
}

#[derive(Debug, thiserror::Error)]
pub enum MatcherError {
    #[error("invalid shadow input: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("invalid match plan: {0}")]
    InvalidPlan(String),
    #[error("external match rpc failure: {0}")]
    Rpc(String),
    #[error("external match route failure: {0}")]
    Route(String),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Json, Router,
        extract::State,
        http::Uri,
        routing::{get, post},
    };
    use zylith_core::{
        AssetId, BatchId, ExternalHedgeQuote, ExternalMatchRequest, MatchProfitabilityCosts,
        OrderSide, PairId, StarknetCall,
    };

    use crate::{
        EkuboRouteAdapterConfig, ExecutableMatchPlan, ExternalMatchRequestSnapshot, MatchDecision,
        MatchPlanInput, OnchainExternalMatchRequest, PlannedMatchReport, RequestRouteSet,
        RouteQuoteBatchRequest, RouteQuoteBatchResponse, RouteQuoteRequest, ShadowEvaluation,
        ShadowEvaluationInput, SkipReason, VenueRouteQuote, VenueRouteSet,
        build_route_quote_request, build_route_quote_request_json, candidate_fill_sizes,
        evaluate_external_match_request, evaluate_shadow_input, evaluate_shadow_input_json,
        fetch_onchain_external_match_requests, plan_external_match_requests,
        plan_external_match_requests_json, plan_external_match_snapshot, quote_ekubo_routes,
        request_from_onchain_state, validate_execution_plan_contracts,
    };

    fn request(side: OrderSide) -> ExternalMatchRequest {
        ExternalMatchRequest {
            request_id: "req-1".into(),
            batch_id: BatchId("batch-1".into()),
            pair_id: PairId("ETH/USDC".into()),
            base_asset_id: AssetId("ETH".into()),
            quote_asset_id: AssetId("USDC".into()),
            side,
            max_base_amount: 500,
            reference_midpoint_price: 4_000_000_000,
            price_base_scale: 1_000_000,
            valid_until_unix_ms: 1_900_000_000_000,
        }
    }

    fn route(fill_base_amount: u128, hedge: ExternalHedgeQuote) -> VenueRouteQuote {
        VenueRouteQuote {
            fill_base_amount,
            hedge,
            calls_before_fill: Vec::new(),
            calls_after_fill: Vec::new(),
            atomic_execution_call: None,
        }
    }

    fn route_with_calls(
        fill_base_amount: u128,
        hedge: ExternalHedgeQuote,
        calls_before_fill: Vec<StarknetCall>,
        calls_after_fill: Vec<StarknetCall>,
    ) -> VenueRouteQuote {
        VenueRouteQuote {
            fill_base_amount,
            hedge,
            calls_before_fill,
            calls_after_fill,
            atomic_execution_call: None,
        }
    }

    fn route_with_atomic_call(
        fill_base_amount: u128,
        hedge: ExternalHedgeQuote,
        atomic_execution_call: StarknetCall,
    ) -> VenueRouteQuote {
        VenueRouteQuote {
            fill_base_amount,
            hedge,
            calls_before_fill: Vec::new(),
            calls_after_fill: Vec::new(),
            atomic_execution_call: Some(atomic_execution_call),
        }
    }

    fn venue(venue: &str, routes: Vec<VenueRouteQuote>) -> VenueRouteSet {
        VenueRouteSet {
            venue: venue.into(),
            observed_at_unix_ms: 1_800_000_000_000,
            routes,
        }
    }

    fn venue_observed_at(
        venue: &str,
        observed_at_unix_ms: u64,
        routes: Vec<VenueRouteQuote>,
    ) -> VenueRouteSet {
        VenueRouteSet {
            venue: venue.into(),
            observed_at_unix_ms,
            routes,
        }
    }

    fn starknet_call(contract_address: &str, entrypoint: &str) -> StarknetCall {
        StarknetCall {
            contract_address: contract_address.into(),
            entrypoint: entrypoint.into(),
            calldata: vec!["0x1".into()],
        }
    }

    fn snapshot(requests: Vec<ExternalMatchRequest>) -> ExternalMatchRequestSnapshot {
        ExternalMatchRequestSnapshot {
            now_unix_ms: 1_800_000_000_000,
            max_route_age_ms: 1_000,
            executor_contract_address: "0x123".into(),
            requests,
            costs: MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 100,
                tip_quote_amount: 100,
                safety_buffer_quote_amount: 100,
                min_profit_quote_amount: 1,
            },
            consumed_request_ids: Vec::new(),
            require_atomic_venue_calls: false,
        }
    }

    #[test]
    fn chooses_best_profitable_venue_and_size_for_shadow_mode() {
        let evaluation = evaluate_external_match_request(
            &request(OrderSide::Buy),
            &[
                venue(
                    "ekubo",
                    vec![
                        route(
                            500,
                            ExternalHedgeQuote::BuyBase {
                                quote_cost_amount: 2_010_000,
                            },
                        ),
                        route(
                            100,
                            ExternalHedgeQuote::BuyBase {
                                quote_cost_amount: 397_000,
                            },
                        ),
                    ],
                ),
                venue(
                    "backup-hedge",
                    vec![route(
                        100,
                        ExternalHedgeQuote::BuyBase {
                            quote_cost_amount: 398_000,
                        },
                    )],
                ),
            ],
            MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 500,
                tip_quote_amount: 250,
                safety_buffer_quote_amount: 250,
                min_profit_quote_amount: 1,
            },
        );

        assert_eq!(evaluation.request_id, "req-1");
        assert!(evaluation.zero_rebate_profitable);
        assert_eq!(
            evaluation.decision,
            MatchDecision::Fill {
                venue: "ekubo".into(),
                fill_base_amount: 100,
                fill_quote_amount: 400_000,
                net_profit_quote_amount: 2_000,
            }
        );
    }

    #[test]
    fn candidate_fill_sizes_cover_partial_and_full_residuals() {
        assert_eq!(
            candidate_fill_sizes(1_000),
            vec![10, 25, 50, 100, 250, 500, 750, 1_000]
        );
        assert_eq!(candidate_fill_sizes(3), vec![1, 2, 3]);
        assert!(candidate_fill_sizes(0).is_empty());
    }

    #[test]
    fn reconstructs_only_remaining_buy_residual_from_onchain_state() {
        let request = request_from_onchain_state(OnchainExternalMatchRequest {
            request_id: "0xabc".into(),
            batch_id: "0x4241544348".into(),
            pair_id: "0x45544855534443".into(),
            side: OrderSide::Buy,
            input_asset_id: "0x55534443".into(),
            output_asset_id: "0x455448".into(),
            max_base_amount: 100,
            reference_midpoint_price: 4_000_000_000,
            price_base_scale: 1_000_000,
            valid_until_unix_ms: 1_900_000_000_000,
            match_deadline_unix_ms: 1_900_000_010_000,
            consumed_base_amount: 40,
            closed: false,
            settlement_consumed: false,
        })
        .expect("remaining request");

        assert_eq!(request.request_id, "0xabc");
        assert_eq!(request.base_asset_id, AssetId("0x455448".into()));
        assert_eq!(request.quote_asset_id, AssetId("0x55534443".into()));
        assert_eq!(request.batch_id, BatchId("0x4241544348".into()));
        assert_eq!(request.pair_id, PairId("0x45544855534443".into()));
        assert_eq!(request.max_base_amount, 60);
    }

    #[test]
    fn omits_fully_consumed_onchain_request() {
        assert!(
            request_from_onchain_state(OnchainExternalMatchRequest {
                request_id: "0xabc".into(),
                batch_id: "0x4241544348".into(),
                pair_id: "0x45544855534443".into(),
                side: OrderSide::Sell,
                input_asset_id: "0x455448".into(),
                output_asset_id: "0x55534443".into(),
                max_base_amount: 100,
                reference_midpoint_price: 4_000_000_000,
                price_base_scale: 1_000_000,
                valid_until_unix_ms: 1_900_000_000_000,
                match_deadline_unix_ms: 1_900_000_010_000,
                consumed_base_amount: 100,
                closed: false,
                settlement_consumed: false,
            })
            .is_none()
        );
    }

    #[test]
    fn reports_wait_when_no_route_is_profitable_without_subsidy() {
        let evaluation = evaluate_external_match_request(
            &request(OrderSide::Sell),
            &[venue(
                "ekubo",
                vec![route(
                    100,
                    ExternalHedgeQuote::SellBase {
                        quote_proceeds_amount: 399_000,
                    },
                )],
            )],
            MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 0,
                tip_quote_amount: 0,
                safety_buffer_quote_amount: 0,
                min_profit_quote_amount: 1,
            },
        );

        assert_eq!(
            evaluation,
            ShadowEvaluation {
                request_id: "req-1".into(),
                pair_id: PairId("ETH/USDC".into()),
                side: OrderSide::Sell,
                zero_rebate_profitable: false,
                decision: MatchDecision::Wait,
            }
        );
    }

    #[test]
    fn evaluates_shadow_input_payload() {
        let evaluation = evaluate_shadow_input(ShadowEvaluationInput {
            request: request(OrderSide::Buy),
            venue_routes: vec![venue(
                "ekubo",
                vec![route(
                    100,
                    ExternalHedgeQuote::BuyBase {
                        quote_cost_amount: 397_500,
                    },
                )],
            )],
            costs: MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 100,
                tip_quote_amount: 100,
                safety_buffer_quote_amount: 100,
                min_profit_quote_amount: 1,
            },
        });

        assert_eq!(
            evaluation.decision,
            MatchDecision::Fill {
                venue: "ekubo".into(),
                fill_base_amount: 100,
                fill_quote_amount: 400_000,
                net_profit_quote_amount: 2_200,
            }
        );
    }

    #[test]
    fn parses_shadow_input_json_payload() {
        let payload = r#"
        {
          "request": {
            "request_id": "req-json",
            "batch_id": "batch-json",
            "pair_id": "ETH/USDC",
            "base_asset_id": "ETH",
            "quote_asset_id": "USDC",
            "side": "Buy",
            "max_base_amount": "100",
            "reference_midpoint_price": "4000000000",
            "price_base_scale": "1000000",
            "valid_until_unix_ms": 1900000000000
          },
          "venue_routes": [
            {
              "venue": "ekubo",
              "observed_at_unix_ms": 1800000000000,
              "routes": [
                {
                  "fill_base_amount": "100",
                  "hedge": {
                    "BuyBase": {
                      "quote_cost_amount": "397500"
                    }
                  }
                }
              ]
            }
          ],
          "costs": {
            "rebate_quote_amount": "0",
            "gas_quote_amount": "100",
            "tip_quote_amount": "100",
            "safety_buffer_quote_amount": "100",
            "min_profit_quote_amount": 1
          }
        }
        "#;

        let input: ShadowEvaluationInput =
            serde_json::from_str(payload).expect("shadow input json");
        let evaluation = evaluate_shadow_input(input);

        assert_eq!(evaluation.request_id, "req-json");
        assert!(evaluation.zero_rebate_profitable);
    }

    #[test]
    fn evaluates_shadow_input_json_to_json_output() {
        let payload = r#"
        {
          "request": {
            "request_id": "req-json",
            "batch_id": "batch-json",
            "pair_id": "ETH/USDC",
            "base_asset_id": "ETH",
            "quote_asset_id": "USDC",
            "side": "Sell",
            "max_base_amount": "100",
            "reference_midpoint_price": "4000000000",
            "price_base_scale": "1000000",
            "valid_until_unix_ms": 1900000000000
          },
          "venue_routes": [
            {
              "venue": "ekubo",
              "observed_at_unix_ms": 1800000000000,
              "routes": [
                {
                  "fill_base_amount": "100",
                  "hedge": {
                    "SellBase": {
                      "quote_proceeds_amount": "403000"
                    }
                  }
                }
              ]
            }
          ],
          "costs": {
            "rebate_quote_amount": "0",
            "gas_quote_amount": "100",
            "tip_quote_amount": "100",
            "safety_buffer_quote_amount": "100",
            "min_profit_quote_amount": 1
          }
        }
        "#;

        let output = evaluate_shadow_input_json(payload).expect("json output");

        assert!(output.contains("\"request_id\":\"req-json\""));
        assert!(output.contains("\"venue\":\"ekubo\""));
        assert!(output.contains("\"net_profit_quote_amount\":2700"));
    }

    #[test]
    fn plans_executable_match_call_for_profitable_request() {
        let mut match_request = request(OrderSide::Sell);
        match_request.request_id = "0xabc".into();
        let report = plan_external_match_requests(MatchPlanInput {
            now_unix_ms: 1_800_000_000_000,
            max_route_age_ms: 1_000,
            executor_contract_address: "0x123".into(),
            requests: vec![match_request],
            request_routes: vec![RequestRouteSet {
                request_id: "0xabc".into(),
                venue_routes: vec![venue(
                    "ekubo",
                    vec![route(
                        100,
                        ExternalHedgeQuote::SellBase {
                            quote_proceeds_amount: 403_000,
                        },
                    )],
                )],
            }],
            costs: MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 100,
                tip_quote_amount: 100,
                safety_buffer_quote_amount: 100,
                min_profit_quote_amount: 1,
            },
            consumed_request_ids: Vec::new(),
            require_atomic_venue_calls: false,
        })
        .expect("plan");

        assert_eq!(
            report,
            PlannedMatchReport {
                plans: vec![ExecutableMatchPlan {
                    request_id: "0xabc".into(),
                    pair_id: PairId("ETH/USDC".into()),
                    side: OrderSide::Sell,
                    venue: "ekubo".into(),
                    route_observed_at_unix_ms: 1_800_000_000_000,
                    fill_base_amount: 100,
                    fill_quote_amount: 400_000,
                    net_profit_quote_amount: 2_700,
                    minimum_onchain_profit_quote_amount: 301,
                    executor_call: StarknetCall {
                        contract_address: "0x123".into(),
                        entrypoint: "settle_external_match_fill".into(),
                        calldata: vec!["0xabc".into(), "0x64".into()],
                    },
                    calls_before_fill: Vec::new(),
                    calls_after_fill: Vec::new(),
                    atomic_execution_call: None,
                    execution_calls: vec![StarknetCall {
                        contract_address: "0x123".into(),
                        entrypoint: "settle_external_match_fill".into(),
                        calldata: vec!["0xabc".into(), "0x64".into()],
                    }],
                }],
                skipped: Vec::new(),
            }
        );
    }

    #[test]
    fn skips_expired_duplicate_missing_route_and_unprofitable_requests() {
        let mut expired = request(OrderSide::Buy);
        expired.request_id = "0x1".into();
        expired.valid_until_unix_ms = 99;
        let mut duplicate = request(OrderSide::Buy);
        duplicate.request_id = "0x2".into();
        let mut missing_routes = request(OrderSide::Buy);
        missing_routes.request_id = "0x3".into();
        let mut unprofitable = request(OrderSide::Sell);
        unprofitable.request_id = "0x4".into();

        let report = plan_external_match_requests(MatchPlanInput {
            now_unix_ms: 100,
            max_route_age_ms: 1_000,
            executor_contract_address: "0x123".into(),
            requests: vec![expired, duplicate, missing_routes, unprofitable],
            request_routes: vec![RequestRouteSet {
                request_id: "0x4".into(),
                venue_routes: vec![venue_observed_at(
                    "ekubo",
                    100,
                    vec![route(
                        100,
                        ExternalHedgeQuote::SellBase {
                            quote_proceeds_amount: 399_000,
                        },
                    )],
                )],
            }],
            costs: MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 0,
                tip_quote_amount: 0,
                safety_buffer_quote_amount: 0,
                min_profit_quote_amount: 1,
            },
            consumed_request_ids: vec!["0x2".into()],
            require_atomic_venue_calls: false,
        })
        .expect("plan");

        assert!(report.plans.is_empty());
        assert_eq!(
            report
                .skipped
                .iter()
                .map(|skipped| (&skipped.request_id, skipped.reason))
                .collect::<Vec<_>>(),
            vec![
                (&"0x1".to_string(), SkipReason::Expired),
                (&"0x2".to_string(), SkipReason::AlreadyConsumed),
                (&"0x3".to_string(), SkipReason::NoRoutes),
                (&"0x4".to_string(), SkipReason::NotProfitable),
            ]
        );
    }

    #[test]
    fn skips_stale_route_quotes_before_profitability_evaluation() {
        let mut match_request = request(OrderSide::Buy);
        match_request.request_id = "0xabc".into();

        let report = plan_external_match_requests(MatchPlanInput {
            now_unix_ms: 1_800_000_010_000,
            max_route_age_ms: 5_000,
            executor_contract_address: "0x123".into(),
            requests: vec![match_request],
            request_routes: vec![RequestRouteSet {
                request_id: "0xabc".into(),
                venue_routes: vec![venue_observed_at(
                    "ekubo",
                    1_800_000_000_000,
                    vec![route(
                        100,
                        ExternalHedgeQuote::BuyBase {
                            quote_cost_amount: 397_000,
                        },
                    )],
                )],
            }],
            costs: MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 0,
                tip_quote_amount: 0,
                safety_buffer_quote_amount: 0,
                min_profit_quote_amount: 1,
            },
            consumed_request_ids: Vec::new(),
            require_atomic_venue_calls: false,
        })
        .expect("plan");

        assert!(report.plans.is_empty());
        assert_eq!(
            report.skipped,
            vec![crate::SkippedMatchRequest {
                request_id: "0xabc".into(),
                reason: SkipReason::StaleRoutes,
            }]
        );
    }

    #[test]
    fn atomic_mode_requires_executable_venue_calls_and_orders_them_around_fill() {
        let mut missing_calls = request(OrderSide::Buy);
        missing_calls.request_id = "0xaaa".into();
        let mut with_calls = request(OrderSide::Sell);
        with_calls.request_id = "0xbbb".into();

        let hedge_before = starknet_call("0x456", "open_lock");
        let hedge_after = starknet_call("0x456", "settle_lock");
        let report = plan_external_match_requests(MatchPlanInput {
            now_unix_ms: 1_800_000_000_000,
            max_route_age_ms: 1_000,
            executor_contract_address: "0x123".into(),
            requests: vec![missing_calls, with_calls],
            request_routes: vec![
                RequestRouteSet {
                    request_id: "0xaaa".into(),
                    venue_routes: vec![venue(
                        "ekubo",
                        vec![route(
                            100,
                            ExternalHedgeQuote::BuyBase {
                                quote_cost_amount: 397_000,
                            },
                        )],
                    )],
                },
                RequestRouteSet {
                    request_id: "0xbbb".into(),
                    venue_routes: vec![venue(
                        "ekubo",
                        vec![route_with_calls(
                            100,
                            ExternalHedgeQuote::SellBase {
                                quote_proceeds_amount: 403_000,
                            },
                            vec![hedge_before.clone()],
                            vec![hedge_after.clone()],
                        )],
                    )],
                },
            ],
            costs: MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 100,
                tip_quote_amount: 100,
                safety_buffer_quote_amount: 100,
                min_profit_quote_amount: 1,
            },
            consumed_request_ids: Vec::new(),
            require_atomic_venue_calls: true,
        })
        .expect("plan");

        assert_eq!(
            report.skipped,
            vec![crate::SkippedMatchRequest {
                request_id: "0xaaa".into(),
                reason: SkipReason::NoExecutionCalls,
            }]
        );
        assert_eq!(report.plans.len(), 1);
        let plan = &report.plans[0];
        assert_eq!(plan.request_id, "0xbbb");
        assert_eq!(plan.calls_before_fill, vec![hedge_before.clone()]);
        assert_eq!(plan.calls_after_fill, vec![hedge_after.clone()]);
        assert_eq!(
            plan.execution_calls,
            vec![
                hedge_before,
                StarknetCall {
                    contract_address: "0x123".into(),
                    entrypoint: "settle_external_match_fill".into(),
                    calldata: vec!["0xbbb".into(), "0x64".into()],
                },
                hedge_after,
            ]
        );
    }

    #[test]
    fn atomic_mode_ranks_only_quotes_with_executable_calls() {
        let mut match_request = request(OrderSide::Buy);
        match_request.request_id = "0xabc".into();

        let hedge_before = starknet_call("0x456", "open_lock");
        let report = plan_external_match_requests(MatchPlanInput {
            now_unix_ms: 1_800_000_000_000,
            max_route_age_ms: 1_000,
            executor_contract_address: "0x123".into(),
            requests: vec![match_request],
            request_routes: vec![RequestRouteSet {
                request_id: "0xabc".into(),
                venue_routes: vec![venue(
                    "ekubo",
                    vec![
                        route(
                            100,
                            ExternalHedgeQuote::BuyBase {
                                quote_cost_amount: 397_000,
                            },
                        ),
                        route_with_calls(
                            50,
                            ExternalHedgeQuote::BuyBase {
                                quote_cost_amount: 198_800,
                            },
                            vec![hedge_before.clone()],
                            Vec::new(),
                        ),
                    ],
                )],
            }],
            costs: MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 100,
                tip_quote_amount: 100,
                safety_buffer_quote_amount: 100,
                min_profit_quote_amount: 1,
            },
            consumed_request_ids: Vec::new(),
            require_atomic_venue_calls: true,
        })
        .expect("plan");

        assert!(report.skipped.is_empty());
        assert_eq!(report.plans.len(), 1);
        assert_eq!(report.plans[0].fill_base_amount, 50);
        assert_eq!(report.plans[0].calls_before_fill, vec![hedge_before]);
    }

    #[test]
    fn request_snapshot_builds_route_quote_request_with_candidate_sizes() {
        let mut first = request(OrderSide::Buy);
        first.request_id = "0xabc".into();
        first.max_base_amount = 1_000;
        let mut second = request(OrderSide::Sell);
        second.request_id = "0xdef".into();
        second.max_base_amount = 3;

        let quote_request =
            build_route_quote_request(&snapshot(vec![first.clone(), second.clone()]));

        assert_eq!(quote_request.now_unix_ms, 1_800_000_000_000);
        assert_eq!(
            quote_request.requests,
            vec![
                RouteQuoteRequest {
                    request: first,
                    candidate_fill_base_amounts: vec![10, 25, 50, 100, 250, 500, 750, 1_000],
                },
                RouteQuoteRequest {
                    request: second,
                    candidate_fill_base_amounts: vec![1, 2, 3],
                },
            ]
        );
    }

    #[test]
    fn snapshot_and_route_response_plan_executable_fill() {
        let mut match_request = request(OrderSide::Sell);
        match_request.request_id = "0xabc".into();

        let report = plan_external_match_snapshot(
            snapshot(vec![match_request]),
            RouteQuoteBatchResponse {
                request_routes: vec![RequestRouteSet {
                    request_id: "0xabc".into(),
                    venue_routes: vec![venue(
                        "ekubo",
                        vec![route(
                            100,
                            ExternalHedgeQuote::SellBase {
                                quote_proceeds_amount: 403_000,
                            },
                        )],
                    )],
                }],
            },
        )
        .expect("snapshot plan");

        assert_eq!(report.plans.len(), 1);
        assert!(report.skipped.is_empty());
        assert_eq!(report.plans[0].request_id, "0xabc");
        assert_eq!(report.plans[0].venue, "ekubo");
    }

    #[test]
    fn request_snapshot_json_builds_route_quote_request_json() {
        let payload = r#"
        {
          "now_unix_ms": 1800000000000,
          "max_route_age_ms": 1000,
          "executor_contract_address": "0x123",
          "requests": [
            {
              "request_id": "0xabc",
              "batch_id": "batch-json",
              "pair_id": "ETH/USDC",
              "base_asset_id": "ETH",
              "quote_asset_id": "USDC",
              "side": "Buy",
              "max_base_amount": "100",
              "reference_midpoint_price": "4000000000",
              "price_base_scale": "1000000",
              "valid_until_unix_ms": 1900000000000
            }
          ],
          "costs": {
            "rebate_quote_amount": "0",
            "gas_quote_amount": "100",
            "tip_quote_amount": "100",
            "safety_buffer_quote_amount": "100",
            "min_profit_quote_amount": 1
          },
          "consumed_request_ids": [],
          "require_atomic_venue_calls": true
        }
        "#;

        let output = build_route_quote_request_json(payload).expect("quote request");

        assert!(output.contains("\"request_id\":\"0xabc\""));
        assert!(output.contains("\"candidate_fill_base_amounts\":[\"1\",\"2\",\"5\""));
    }

    #[test]
    fn plans_external_match_requests_json_to_json_output() {
        let payload = r#"
        {
          "now_unix_ms": 1800000000000,
          "max_route_age_ms": 1000,
          "executor_contract_address": "0x123",
          "requests": [
            {
              "request_id": "0xabc",
              "batch_id": "batch-json",
              "pair_id": "ETH/USDC",
              "base_asset_id": "ETH",
              "quote_asset_id": "USDC",
              "side": "Buy",
              "max_base_amount": "100",
              "reference_midpoint_price": "4000000000",
              "price_base_scale": "1000000",
              "valid_until_unix_ms": 1900000000000
            }
          ],
          "request_routes": [
            {
              "request_id": "0xabc",
              "venue_routes": [
                {
                  "venue": "ekubo",
                  "observed_at_unix_ms": 1800000000000,
                  "routes": [
                    {
                      "fill_base_amount": "100",
                      "hedge": {
                        "BuyBase": {
                          "quote_cost_amount": "397500"
                        }
                      }
                    }
                  ]
                }
              ]
            }
          ],
          "costs": {
            "rebate_quote_amount": "0",
            "gas_quote_amount": "100",
            "tip_quote_amount": "100",
            "safety_buffer_quote_amount": "100",
            "min_profit_quote_amount": 1
          },
          "consumed_request_ids": [],
          "require_atomic_venue_calls": false
        }
        "#;

        let output = plan_external_match_requests_json(payload).expect("json output");

        assert!(output.contains("\"entrypoint\":\"settle_external_match_fill\""));
        assert!(output.contains("\"request_id\":\"0xabc\""));
        assert!(output.contains("\"venue\":\"ekubo\""));
    }

    #[tokio::test]
    async fn fetches_remaining_requests_from_authoritative_onchain_index() {
        async fn rpc(
            State(counter): State<Arc<AtomicUsize>>,
            Json(_request): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            let result = match counter.fetch_add(1, Ordering::SeqCst) {
                0 => serde_json::json!(["0x1"]),
                1 => serde_json::json!(["0x1", "0xabc"]),
                2 => serde_json::json!([
                    "0x4241544348",
                    "0x45544855534443",
                    "0x0",
                    "0x55534443",
                    "0x455448",
                    "0x64",
                    "0xee6b2800",
                    "0xf4240",
                    "0x1ba60d33800",
                    "0x1ba60d35f10",
                    "0x28",
                    "0x0",
                    "0x0"
                ]),
                _ => panic!("unexpected rpc call"),
            };
            Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}))
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/", post(rpc))
            .with_state(counter.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind rpc fixture");
        let address = listener.local_addr().expect("rpc fixture address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve rpc fixture");
        });

        let requests = fetch_onchain_external_match_requests(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            "0x123",
        )
        .await
        .expect("onchain requests");

        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].request_id, "0xabc");
        assert_eq!(requests[0].max_base_amount, 60);
        assert_eq!(requests[0].side, OrderSide::Buy);
    }

    #[test]
    fn live_execution_rejects_untrusted_route_contracts() {
        let plan = ExecutableMatchPlan {
            request_id: "0xabc".into(),
            pair_id: PairId("ETH/USDC".into()),
            side: OrderSide::Buy,
            venue: "ekubo".into(),
            route_observed_at_unix_ms: 1,
            fill_base_amount: 100,
            fill_quote_amount: 400_000,
            net_profit_quote_amount: 1_000,
            minimum_onchain_profit_quote_amount: 0,
            executor_call: StarknetCall {
                contract_address: "0x123".into(),
                entrypoint: "settle_external_match_fill".into(),
                calldata: vec!["0xabc".into(), "0x64".into()],
            },
            calls_before_fill: vec![starknet_call("0x999", "steal")],
            calls_after_fill: Vec::new(),
            atomic_execution_call: None,
            execution_calls: vec![
                starknet_call("0x999", "steal"),
                StarknetCall {
                    contract_address: "0x123".into(),
                    entrypoint: "settle_external_match_fill".into(),
                    calldata: vec!["0xabc".into(), "0x64".into()],
                },
            ],
        };

        let error = validate_execution_plan_contracts(&plan, "0x123", &["0x456".into()])
            .expect_err("untrusted route must fail");

        assert!(error.to_string().contains("0x999"));
    }

    #[test]
    fn live_execution_accepts_exact_fill_once_and_allowlisted_route_calls() {
        let executor_call = StarknetCall {
            contract_address: "0x123".into(),
            entrypoint: "settle_external_match_fill".into(),
            calldata: vec!["0xabc".into(), "0x64".into()],
        };
        let route_call = starknet_call("0x456", "atomic_match");
        let plan = ExecutableMatchPlan {
            request_id: "0xabc".into(),
            pair_id: PairId("ETH/USDC".into()),
            side: OrderSide::Buy,
            venue: "ekubo".into(),
            route_observed_at_unix_ms: 1,
            fill_base_amount: 100,
            fill_quote_amount: 400_000,
            net_profit_quote_amount: 1_000,
            minimum_onchain_profit_quote_amount: 0,
            executor_call: executor_call.clone(),
            calls_before_fill: vec![route_call.clone()],
            calls_after_fill: Vec::new(),
            atomic_execution_call: None,
            execution_calls: vec![route_call, executor_call],
        };

        validate_execution_plan_contracts(&plan, "0x123", &["0x456".into()])
            .expect("allowlisted plan");
    }

    #[test]
    fn atomic_wrapper_replaces_the_direct_fill_call_and_is_bound_to_request() {
        let mut match_request = request(OrderSide::Buy);
        match_request.request_id = "0xabc".into();
        let atomic_call = StarknetCall {
            contract_address: "0x456".into(),
            entrypoint: "execute_external_match".into(),
            calldata: vec![
                "0x123".into(),
                "0xabc".into(),
                "0x64".into(),
                "0xfeed".into(),
            ],
        };
        let report = plan_external_match_requests(MatchPlanInput {
            now_unix_ms: 1_800_000_000_000,
            max_route_age_ms: 1_000,
            executor_contract_address: "0x123".into(),
            requests: vec![match_request],
            request_routes: vec![RequestRouteSet {
                request_id: "0xabc".into(),
                venue_routes: vec![venue(
                    "ekubo-flash",
                    vec![route_with_atomic_call(
                        100,
                        ExternalHedgeQuote::BuyBase {
                            quote_cost_amount: 397_000,
                        },
                        atomic_call.clone(),
                    )],
                )],
            }],
            costs: MatchProfitabilityCosts {
                rebate_quote_amount: 0,
                gas_quote_amount: 100,
                tip_quote_amount: 100,
                safety_buffer_quote_amount: 100,
                min_profit_quote_amount: 1,
            },
            consumed_request_ids: Vec::new(),
            require_atomic_venue_calls: true,
        })
        .expect("atomic plan");

        assert_eq!(report.plans.len(), 1);
        let mut expected_atomic_call = atomic_call;
        expected_atomic_call.calldata[3] = "0x12d".into();
        assert_eq!(report.plans[0].execution_calls, vec![expected_atomic_call]);
        validate_execution_plan_contracts(&report.plans[0], "0x123", &["0x456".into()])
            .expect("bound atomic wrapper");
    }

    #[tokio::test]
    async fn ekubo_adapter_quotes_exact_output_buy_and_encodes_atomic_wrapper_call() {
        async fn quote(
            State(paths): State<Arc<Mutex<Vec<String>>>>,
            uri: Uri,
        ) -> Json<serde_json::Value> {
            paths.lock().expect("paths").push(uri.path().to_owned());
            Json(serde_json::json!({
                "total_calculated": "-397000",
                "splits": [{
                    "amount_specified": "-100",
                    "route": [{
                        "pool_key": {
                            "token0": "0x10",
                            "token1": "0x20",
                            "fee": "123",
                            "tick_spacing": 1000,
                            "extension": "0x0"
                        },
                        "sqrt_ratio_limit": "0x100000000000000000000000000000001",
                        "skip_ahead": 7
                    }]
                }]
            }))
        }

        let paths = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*path}", get(quote))
            .with_state(paths.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind quoter fixture");
        let address = listener.local_addr().expect("quoter address");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve quoter") });

        let mut buy = request(OrderSide::Buy);
        buy.request_id = "0xabc".into();
        buy.max_base_amount = 100;
        let response = quote_ekubo_routes(
            &reqwest::Client::new(),
            RouteQuoteBatchRequest {
                now_unix_ms: 1000,
                requests: vec![RouteQuoteRequest {
                    request: buy,
                    candidate_fill_base_amounts: vec![100],
                }],
            },
            &EkuboRouteAdapterConfig {
                chain_id: "main".into(),
                quoter_base_url: format!("http://{address}"),
                atomic_router_address: "0x456".into(),
                asset_tokens: BTreeMap::from([
                    ("ETH".into(), "0x20".into()),
                    ("USDC".into(), "0x10".into()),
                ]),
            },
        )
        .await
        .expect("Ekubo routes");

        assert_eq!(paths.lock().expect("paths")[0], "/main/-100/0x20/0x10");
        let route = &response.request_routes[0].venue_routes[0].routes[0];
        assert_eq!(
            route.hedge,
            ExternalHedgeQuote::BuyBase {
                quote_cost_amount: 397_000
            }
        );
        let call = route.atomic_execution_call.as_ref().expect("atomic call");
        assert_eq!(call.contract_address, "0x456");
        assert_eq!(&call.calldata[..5], &["0x0", "0xabc", "0x64", "0x0", "0x1"]);
        assert_eq!(call.calldata[10], "0x0");
        assert_eq!(call.calldata[11], "0x1");
        assert_eq!(call.calldata[12], "0x1");
        assert_eq!(&call.calldata[14..], &["0x20", "0x64", "0x1"]);
    }
}

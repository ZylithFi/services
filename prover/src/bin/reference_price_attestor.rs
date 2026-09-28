use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
};
use reqwest::{Client, Response, header::USER_AGENT};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use starknet_rust_core::types::Felt;
use url::Url;
use zeroize::Zeroizing;
use zylith_core::{
    AssetId, PairId, ReferencePriceAttestation, ReferencePriceBatchEntry, ReferencePriceEnvelope,
    ReferencePriceSample, build_reference_price_envelope, reference_price_batch_commitment,
    reference_price_policy_for_pair, reference_price_source_set_commitment,
    sign_reference_price_attestation, sign_reference_price_attestation_in_batch,
};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8790";
const DEFAULT_ATTESTATION_TTL_MS: u64 = 5_000;
const MAX_ATTESTATION_TTL_MS: u64 = 15_000;
/// sources are fetched together and the envelope is stamped before they are, so a source that
/// answers later than this is dropped rather than aging every attestation past the prover's
/// five-second freshness bound.
const DEFAULT_SOURCE_REQUEST_TIMEOUT_MS: u64 = 1_500;
/// the prover rejects envelopes older than five seconds.
const MAX_SOURCE_REQUEST_TIMEOUT_MS: u64 = 4_000;
const MAX_CEX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct AppState {
    client: Client,
    /// the exchange every attestation is bound to.
    exchange_address: Felt,
    signer_private_key: Arc<Zeroizing<String>>,
    auth_token_digest: [u8; 32],
    attestation_ttl_ms: u64,
    /// each asset's token decimals, from the deployment manifest: the same asset name can be a
    /// different token, with other decimals, on another network.
    decimals: Arc<HashMap<String, u8>>,
    nonce: Arc<AtomicU64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationRequest {
    pair_id: PairId,
    base_asset_id: AssetId,
    quote_asset_id: AssetId,
    price_base_scale: u128,
    exchange_address: String,
}

#[derive(Clone, Debug, Serialize)]
struct AttestationResponse {
    attestation: ReferencePriceAttestation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PriceBatchRequest {
    markets: Vec<AttestationRequest>,
}

#[derive(Clone, Debug, Serialize)]
struct PriceBatchResponse {
    attestations: Vec<ReferencePriceAttestation>,
}

struct UnsignedEntry {
    envelope: ReferencePriceEnvelope,
    source_set_commitment: String,
}

/// the exact binance book that supplies the market's settlement midpoint.
#[derive(Clone, Copy)]
struct BinanceSource {
    symbol: &'static str,
}

#[derive(Clone, Copy)]
enum ReferenceMarket {
    Direct {
        binance: BinanceSource,
        coinbase_base: &'static str,
        coinbase_usdt_usd: &'static str,
        coinbase_usdt_usdc: &'static str,
        okx_base: Option<&'static str>,
        okx_quote: Option<&'static str>,
        kraken_base: &'static str,
        kraken_quote: &'static str,
    },
}

#[derive(Clone, Copy)]
struct PairMarket {
    base_asset_id: &'static str,
    quote_asset_id: &'static str,
    market: ReferenceMarket,
}

#[derive(Clone, Debug)]
struct Book {
    bid: String,
    ask: String,
}

#[derive(Clone, Copy)]
struct DecimalRatio {
    numerator: u128,
    denominator: u128,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let signer_private_key = required_env("ZYLITH_REFERENCE_PRICE_SIGNER_PRIVATE_KEY")?;
    let auth_token = required_env("ZYLITH_REFERENCE_PRICE_ATTESTOR_TOKEN")?;
    let exchange_address = required_felt_env("ZYLITH_EXCHANGE_ADDRESS")?;
    let attestation_ttl_ms = env::var("ZYLITH_REFERENCE_PRICE_ATTESTATION_TTL_MS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|error| format!("invalid attestation TTL: {error}"))?
        .unwrap_or(DEFAULT_ATTESTATION_TTL_MS);
    if !(1..=MAX_ATTESTATION_TTL_MS).contains(&attestation_ttl_ms) {
        return Err(format!(
            "attestation TTL must be between 1 and {MAX_ATTESTATION_TTL_MS} milliseconds"
        ));
    }
    let source_request_timeout_ms = env::var("ZYLITH_REFERENCE_SOURCE_TIMEOUT_MS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|error| format!("invalid reference source timeout: {error}"))?
        .unwrap_or(DEFAULT_SOURCE_REQUEST_TIMEOUT_MS);
    if !(1..=MAX_SOURCE_REQUEST_TIMEOUT_MS).contains(&source_request_timeout_ms) {
        return Err(format!(
            "reference source timeout must be between 1 and {MAX_SOURCE_REQUEST_TIMEOUT_MS} milliseconds"
        ));
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_millis(source_request_timeout_ms))
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;
    let state = AppState {
        client,
        exchange_address,
        signer_private_key: Arc::new(Zeroizing::new(signer_private_key)),
        auth_token_digest: sha256(auth_token.as_bytes()),
        attestation_ttl_ms,
        decimals: Arc::new(manifest_decimals(
            &std::fs::read_to_string(required_env("ZYLITH_DEPLOYMENT_MANIFEST")?)
                .map_err(|error| format!("deployment manifest: {error}"))?,
        )?),
        nonce: Arc::new(AtomicU64::new(now_unix_ms()?)),
    };
    let app = Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route(
            "/api/v1/reference-price-attestations",
            post(attest_reference_price),
        )
        .route("/api/v1/reference-price-batches", post(attest_price_batch))
        .with_state(state);
    let bind_addr = env::var("ZYLITH_REFERENCE_PRICE_ATTESTOR_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.into());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|error| format!("failed to bind reference-price attestor: {error}"))?;
    println!("Zylith reference-price attestor listening on http://{bind_addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("reference-price attestor failed: {error}"))
}

async fn attest_reference_price(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AttestationRequest>,
) -> Result<Json<AttestationResponse>, StatusCode> {
    authenticate(&state, &headers)?;
    let unsigned = build_unsigned_entry(&state, &request).await?;
    let valid_until_unix_ms = now_unix_ms()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .checked_add(state.attestation_ttl_ms)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let nonce = state.nonce.fetch_add(1, Ordering::Relaxed);
    let attestation = sign_reference_price_attestation(
        state.signer_private_key.as_str(),
        &request.exchange_address,
        unsigned.envelope,
        &unsigned.source_set_commitment,
        valid_until_unix_ms,
        nonce,
    )
    .map_err(|error| {
        eprintln!("reference attestation signing failed: {error}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(AttestationResponse { attestation }))
}

async fn attest_price_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut request): Json<PriceBatchRequest>,
) -> Result<Json<PriceBatchResponse>, StatusCode> {
    authenticate(&state, &headers)?;
    if request.markets.is_empty() || request.markets.len() > 8 {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    request.markets.sort_by_key(|market| {
        Felt::from_hex(&zylith_core::hash::encode_starknet_felt(
            "pair-id",
            &market.pair_id.0,
        ))
        .expect("encoded pair id")
        .to_bytes_be()
    });
    if request
        .markets
        .windows(2)
        .any(|pair| pair[0].pair_id == pair[1].pair_id)
    {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let unsigned = futures::future::join_all(
        request
            .markets
            .iter()
            .map(|market| build_unsigned_entry(&state, market)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let valid_until_unix_ms = now_unix_ms()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .checked_add(state.attestation_ttl_ms)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let entries = unsigned
        .iter()
        .map(|entry| ReferencePriceBatchEntry {
            envelope: entry.envelope.clone(),
            source_set_commitment: entry.source_set_commitment.clone(),
            valid_until_unix_ms,
            nonce: state.nonce.fetch_add(1, Ordering::Relaxed),
        })
        .collect::<Vec<_>>();
    let exchange_address = request.markets[0].exchange_address.clone();
    let batch_commitment = reference_price_batch_commitment(&exchange_address, &entries)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let attestations = entries
        .into_iter()
        .map(|entry| {
            sign_reference_price_attestation_in_batch(
                state.signer_private_key.as_str(),
                &exchange_address,
                entry.envelope,
                &entry.source_set_commitment,
                entry.valid_until_unix_ms,
                entry.nonce,
                &batch_commitment,
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PriceBatchResponse { attestations }))
}

async fn build_unsigned_entry(
    state: &AppState,
    request: &AttestationRequest,
) -> Result<UnsignedEntry, StatusCode> {
    // attestations are bound to the exchange; never sign for another context.
    if parse_felt(&request.exchange_address) != Some(state.exchange_address) {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let pair = pair_market(&request.pair_id.0).ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    if request.base_asset_id.0 != pair.base_asset_id
        || request.quote_asset_id.0 != pair.quote_asset_id
        || request.price_base_scale == 0
    {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let (Some(&base_decimals), Some(&quote_decimals)) = (
        state.decimals.get(pair.base_asset_id),
        state.decimals.get(pair.quote_asset_id),
    ) else {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    };
    let observed_at_unix_ms = now_unix_ms().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let base_asset_scale = 10_u128
        .checked_pow(u32::from(base_decimals))
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let samples = fetch_samples(
        &state.client,
        pair.market,
        quote_decimals,
        base_asset_scale,
        request.price_base_scale,
        observed_at_unix_ms,
    )
    .await
    .map_err(|error| {
        eprintln!(
            "reference source failure pair={}: {error}",
            request.pair_id.0
        );
        StatusCode::BAD_GATEWAY
    })?;
    let reference_policy = reference_price_policy_for_pair(&request.pair_id);
    let envelope = build_reference_price_envelope(
        request.pair_id.clone(),
        request.base_asset_id.clone(),
        request.quote_asset_id.clone(),
        request.price_base_scale,
        observed_at_unix_ms,
        &samples,
        &reference_policy,
    )
    .map_err(|error| {
        eprintln!("reference envelope rejected: {error}");
        StatusCode::BAD_GATEWAY
    })?;
    let source_set_commitment =
        reference_price_source_set_commitment(&samples).map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(UnsignedEntry {
        envelope,
        source_set_commitment,
    })
}

fn parse_felt(value: &str) -> Option<Felt> {
    Felt::from_hex(value.trim())
        .ok()
        .filter(|felt| *felt != Felt::ZERO)
}

fn required_felt_env(name: &str) -> Result<Felt, String> {
    let value = required_env(name)?;
    parse_felt(&value).ok_or_else(|| format!("{name} must be a nonzero Starknet felt"))
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !constant_time_eq(&sha256(token.as_bytes()), &state.auth_token_digest) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

/// every asset's token decimals from the deployment manifest (`product.assets.<name>.decimals`).
fn manifest_decimals(raw: &str) -> Result<HashMap<String, u8>, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|error| format!("deployment manifest: {error}"))?;
    let manifest = value.get("manifest").unwrap_or(&value);
    let assets = manifest
        .pointer("/product/assets")
        .and_then(serde_json::Value::as_object)
        .ok_or("deployment manifest has no product assets")?;
    assets
        .iter()
        .map(|(name, asset)| {
            let decimals = asset
                .get("decimals")
                .and_then(serde_json::Value::as_u64)
                .filter(|decimals| *decimals <= 36)
                .ok_or_else(|| format!("deployment manifest asset {name} has no decimals"))?;
            Ok((name.clone(), decimals as u8))
        })
        .collect()
}

fn pair_market(pair_id: &str) -> Option<PairMarket> {
    match pair_id {
        "STRK/USDC" => Some(PairMarket {
            base_asset_id: "STRK",
            quote_asset_id: "USDC",
            market: ReferenceMarket::Direct {
                binance: BinanceSource { symbol: "STRKUSDC" },
                coinbase_base: "STRK-USD",
                coinbase_usdt_usd: "USDT-USD",
                coinbase_usdt_usdc: "USDT-USDC",
                okx_base: Some("STRK-USDT"),
                okx_quote: Some("USDC-USDT"),
                kraken_base: "STRKUSD",
                kraken_quote: "USDCUSD",
            },
        }),
        "ETH/USDC" => Some(PairMarket {
            base_asset_id: "ETH",
            quote_asset_id: "USDC",
            market: ReferenceMarket::Direct {
                binance: BinanceSource { symbol: "ETHUSDC" },
                coinbase_base: "ETH-USD",
                coinbase_usdt_usd: "USDT-USD",
                coinbase_usdt_usdc: "USDT-USDC",
                okx_base: Some("ETH-USDT"),
                okx_quote: Some("USDC-USDT"),
                kraken_base: "XETHZUSD",
                kraken_quote: "USDCUSD",
            },
        }),
        _ => None,
    }
}

async fn fetch_samples(
    client: &Client,
    market: ReferenceMarket,
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    observed_at_unix_ms: u64,
) -> Result<Vec<ReferencePriceSample>, String> {
    let samples = match market {
        ReferenceMarket::Direct {
            binance,
            coinbase_base,
            coinbase_usdt_usd,
            coinbase_usdt_usdc,
            okx_base,
            okx_quote,
            kraken_base,
            kraken_quote,
        } => {
            let (
                binance_sample,
                coinbase_base,
                coinbase_usdt_usd,
                coinbase_usdt_usdc,
                okx_base_result,
                okx_quote_result,
                kraken_base,
                kraken_quote,
            ) = tokio::join!(
                fetch_binance_sample(
                    client,
                    binance,
                    quote_decimals,
                    base_asset_scale,
                    price_base_scale,
                    observed_at_unix_ms,
                ),
                fetch_coinbase_book(client, coinbase_base),
                fetch_coinbase_book(client, coinbase_usdt_usd),
                fetch_coinbase_book(client, coinbase_usdt_usdc),
                fetch_optional_okx_book(client, okx_base),
                fetch_optional_okx_book(client, okx_quote),
                fetch_kraken_book(client, kraken_base),
                fetch_kraken_book(client, kraken_quote),
            );
            let mut samples = Vec::new();
            samples.push(binance_sample?);
            if let (Ok(base), Ok(usdt_usd), Ok(usdt_usdc)) =
                (coinbase_base, coinbase_usdt_usd, coinbase_usdt_usdc)
                && let Ok(sample) = sample_from_coinbase_usdc_proxy_books(
                    "coinbase",
                    [base, usdt_usd, usdt_usdc],
                    quote_decimals,
                    base_asset_scale,
                    price_base_scale,
                    observed_at_unix_ms,
                )
            {
                samples.push(sample);
            }
            if let (Ok(Some(base)), Ok(Some(quote))) = (okx_base_result, okx_quote_result)
                && let Ok(sample) = sample_from_ratio_books(
                    "okx",
                    base,
                    quote,
                    quote_decimals,
                    base_asset_scale,
                    price_base_scale,
                    observed_at_unix_ms,
                )
            {
                samples.push(sample);
            }
            if let (Ok(base), Ok(quote)) = (kraken_base, kraken_quote)
                && let Ok(sample) = sample_from_ratio_books(
                    "kraken",
                    base,
                    quote,
                    quote_decimals,
                    base_asset_scale,
                    price_base_scale,
                    observed_at_unix_ms,
                )
            {
                samples.push(sample);
            }
            samples
        }
    };
    Ok(samples)
}

/// the exact direct binance book sample for the market.
async fn fetch_binance_sample(
    client: &Client,
    source: BinanceSource,
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    observed_at_unix_ms: u64,
) -> Result<ReferencePriceSample, String> {
    let book = fetch_binance_book(client, source.symbol).await?;
    sample_from_book(
        &format!("binance:{}", source.symbol),
        book,
        quote_decimals,
        base_asset_scale,
        price_base_scale,
        observed_at_unix_ms,
    )
}

async fn fetch_binance_book(client: &Client, symbol: &str) -> Result<Book, String> {
    let mut url = Url::parse("https://api.binance.com/api/v3/ticker/bookTicker")
        .map_err(|error| error.to_string())?;
    url.query_pairs_mut().append_pair("symbol", symbol);
    let value: serde_json::Value = get_json(client, url, "Binance book").await?;
    Ok(Book {
        bid: json_scalar(value.get("bidPrice"), "Binance bid")?,
        ask: json_scalar(value.get("askPrice"), "Binance ask")?,
    })
}

async fn fetch_coinbase_book(client: &Client, product: &str) -> Result<Book, String> {
    let url = Url::parse(&format!(
        "https://api.exchange.coinbase.com/products/{product}/book?level=1"
    ))
    .map_err(|error| error.to_string())?;
    let value: serde_json::Value = get_json(client, url, "Coinbase book").await?;
    Ok(Book {
        bid: json_array_scalar(value.get("bids"), 0, 0, "Coinbase bid")?,
        ask: json_array_scalar(value.get("asks"), 0, 0, "Coinbase ask")?,
    })
}

async fn fetch_kraken_book(client: &Client, pair: &str) -> Result<Book, String> {
    let mut url =
        Url::parse("https://api.kraken.com/0/public/Ticker").map_err(|error| error.to_string())?;
    url.query_pairs_mut().append_pair("pair", pair);
    let value: serde_json::Value = get_json(client, url, "Kraken ticker").await?;
    if value
        .get("error")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        return Err("Kraken returned a ticker error".into());
    }
    let ticker = value
        .get("result")
        .and_then(serde_json::Value::as_object)
        .and_then(|result| result.values().next())
        .ok_or_else(|| "Kraken ticker result is empty".to_string())?;
    Ok(Book {
        bid: json_indexed_scalar(ticker.get("b"), 0, "Kraken bid")?,
        ask: json_indexed_scalar(ticker.get("a"), 0, "Kraken ask")?,
    })
}

async fn fetch_okx_book(client: &Client, instrument: &str) -> Result<Book, String> {
    let mut url = Url::parse("https://www.okx.com/api/v5/market/ticker")
        .map_err(|error| error.to_string())?;
    url.query_pairs_mut().append_pair("instId", instrument);
    let value: serde_json::Value = get_json(client, url, "OKX ticker").await?;
    parse_okx_book(&value)
}

async fn fetch_optional_okx_book(
    client: &Client,
    instrument: Option<&str>,
) -> Result<Option<Book>, String> {
    match instrument {
        Some(instrument) => fetch_okx_book(client, instrument).await.map(Some),
        None => Ok(None),
    }
}

fn parse_okx_book(value: &serde_json::Value) -> Result<Book, String> {
    if value.get("code").and_then(serde_json::Value::as_str) != Some("0") {
        return Err("OKX returned a ticker error".into());
    }
    let ticker = value
        .get("data")
        .and_then(serde_json::Value::as_array)
        .and_then(|data| data.first())
        .ok_or_else(|| "OKX ticker result is empty".to_string())?;
    Ok(Book {
        bid: json_scalar(ticker.get("bidPx"), "OKX bid")?,
        ask: json_scalar(ticker.get("askPx"), "OKX ask")?,
    })
}

async fn get_json<T: DeserializeOwned>(
    client: &Client,
    url: Url,
    label: &str,
) -> Result<T, String> {
    let response = client
        .get(url)
        .header(USER_AGENT, "zylith-reference-attestor/0.1")
        .send()
        .await
        .map_err(|error| format!("{label} request failed: {error}"))?;
    decode_bounded_json(response, label).await
}

async fn decode_bounded_json<T: DeserializeOwned>(
    response: Response,
    label: &str,
) -> Result<T, String> {
    if !response.status().is_success() {
        return Err(format!("{label} returned HTTP {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_CEX_RESPONSE_BYTES as u64)
    {
        return Err(format!("{label} response is too large"));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| format!("{label} body failed: {error}"))?;
    if body.len() > MAX_CEX_RESPONSE_BYTES {
        return Err(format!("{label} response is too large"));
    }
    serde_json::from_slice(&body).map_err(|error| format!("{label} decode failed: {error}"))
}

fn sample_from_book(
    source: &str,
    book: Book,
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    observed_at_unix_ms: u64,
) -> Result<ReferencePriceSample, String> {
    sample_from_ratios(
        source,
        parse_decimal_ratio(&book.bid)?,
        parse_decimal_ratio(&book.ask)?,
        quote_decimals,
        base_asset_scale,
        price_base_scale,
        observed_at_unix_ms,
    )
}

fn sample_from_ratio_books(
    source: &str,
    base: Book,
    quote: Book,
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    observed_at_unix_ms: u64,
) -> Result<ReferencePriceSample, String> {
    let base_bid = parse_decimal_ratio(&base.bid)?;
    let base_ask = parse_decimal_ratio(&base.ask)?;
    let quote_bid = parse_decimal_ratio(&quote.bid)?;
    let quote_ask = parse_decimal_ratio(&quote.ask)?;
    sample_from_ratios(
        source,
        divide_ratio(base_bid, quote_ask)?,
        divide_ratio(base_ask, quote_bid)?,
        quote_decimals,
        base_asset_scale,
        price_base_scale,
        observed_at_unix_ms,
    )
}

fn sample_from_coinbase_usdc_proxy_books(
    source: &str,
    books: [Book; 3],
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    observed_at_unix_ms: u64,
) -> Result<ReferencePriceSample, String> {
    let [base_usd, usdt_usd, usdt_usdc] = books;
    let base_bid = parse_decimal_ratio(&base_usd.bid)?;
    let base_ask = parse_decimal_ratio(&base_usd.ask)?;
    let usdt_usd_bid = parse_decimal_ratio(&usdt_usd.bid)?;
    let usdt_usd_ask = parse_decimal_ratio(&usdt_usd.ask)?;
    let usdt_usdc_bid = parse_decimal_ratio(&usdt_usdc.bid)?;
    let usdt_usdc_ask = parse_decimal_ratio(&usdt_usdc.ask)?;
    sample_from_ratios(
        source,
        divide_ratio(multiply_ratio(base_bid, usdt_usdc_bid)?, usdt_usd_ask)?,
        divide_ratio(multiply_ratio(base_ask, usdt_usdc_ask)?, usdt_usd_bid)?,
        quote_decimals,
        base_asset_scale,
        price_base_scale,
        observed_at_unix_ms,
    )
}

fn sample_from_ratios(
    source: &str,
    bid: DecimalRatio,
    ask: DecimalRatio,
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    observed_at_unix_ms: u64,
) -> Result<ReferencePriceSample, String> {
    let bid_price = ratio_to_units(
        bid,
        quote_decimals,
        base_asset_scale,
        price_base_scale,
        false,
    )?;
    let ask_price = ratio_to_units(
        ask,
        quote_decimals,
        base_asset_scale,
        price_base_scale,
        true,
    )?;
    if bid_price == 0 || bid_price > ask_price {
        return Err(format!("{source} produced an invalid bid/ask"));
    }
    Ok(ReferencePriceSample {
        source: source.into(),
        bid_price,
        ask_price,
        price_base_scale,
        observed_at_unix_ms,
    })
}

fn parse_decimal_ratio(value: &str) -> Result<DecimalRatio, String> {
    let value = value.trim();
    if value.is_empty() || value.starts_with(['-', '+']) {
        return Err("price must be a positive decimal".into());
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || !whole.chars().all(|character| character.is_ascii_digit())
        || !fraction.chars().all(|character| character.is_ascii_digit())
    {
        return Err(format!("invalid decimal {value}"));
    }
    let denominator = 10_u128
        .checked_pow(
            fraction
                .len()
                .try_into()
                .map_err(|_| "decimal is too precise")?,
        )
        .ok_or_else(|| "decimal precision overflows".to_string())?;
    let whole_value = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<u128>()
            .map_err(|_| "decimal overflows".to_string())?
    };
    let numerator = whole_value
        .checked_mul(denominator)
        .and_then(|scaled| {
            scaled.checked_add(if fraction.is_empty() {
                0
            } else {
                fraction.parse::<u128>().ok()?
            })
        })
        .ok_or_else(|| "decimal overflows".to_string())?;
    if numerator == 0 {
        return Err("price must be positive".into());
    }
    Ok(DecimalRatio {
        numerator,
        denominator,
    })
}

fn divide_ratio(left: DecimalRatio, right: DecimalRatio) -> Result<DecimalRatio, String> {
    if right.numerator == 0 {
        return Err("division by zero".into());
    }
    Ok(DecimalRatio {
        numerator: left
            .numerator
            .checked_mul(right.denominator)
            .ok_or_else(|| "ratio overflows".to_string())?,
        denominator: left
            .denominator
            .checked_mul(right.numerator)
            .ok_or_else(|| "ratio overflows".to_string())?,
    })
}

fn multiply_ratio(left: DecimalRatio, right: DecimalRatio) -> Result<DecimalRatio, String> {
    Ok(DecimalRatio {
        numerator: left
            .numerator
            .checked_mul(right.numerator)
            .ok_or_else(|| "ratio overflows".to_string())?,
        denominator: left
            .denominator
            .checked_mul(right.denominator)
            .ok_or_else(|| "ratio overflows".to_string())?,
    })
}

fn ratio_to_units(
    value: DecimalRatio,
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    round_up: bool,
) -> Result<u128, String> {
    let quote_scale = 10_u128
        .checked_pow(u32::from(quote_decimals))
        .ok_or_else(|| "quote scale overflows".to_string())?;
    let mut numerator = value.numerator;
    let mut denominator = value.denominator;
    multiply_denominator(&mut numerator, &mut denominator, base_asset_scale)?;
    multiply_numerator(&mut numerator, &mut denominator, quote_scale)?;
    multiply_numerator(&mut numerator, &mut denominator, price_base_scale)?;
    let value = numerator / denominator;
    if round_up && !numerator.is_multiple_of(denominator) {
        value
            .checked_add(1)
            .ok_or_else(|| "rounded value overflows".to_string())
    } else {
        Ok(value)
    }
}

fn multiply_numerator(
    numerator: &mut u128,
    denominator: &mut u128,
    factor: u128,
) -> Result<(), String> {
    let divisor = gcd(*denominator, factor);
    *denominator /= divisor;
    *numerator = numerator
        .checked_mul(factor / divisor)
        .ok_or_else(|| "scaled numerator overflows".to_string())?;
    Ok(())
}

fn multiply_denominator(
    numerator: &mut u128,
    denominator: &mut u128,
    factor: u128,
) -> Result<(), String> {
    let divisor = gcd(*numerator, factor);
    *numerator /= divisor;
    *denominator = denominator
        .checked_mul(factor / divisor)
        .ok_or_else(|| "scaled denominator overflows".to_string())?;
    Ok(())
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left.max(1)
}

fn json_scalar(value: Option<&serde_json::Value>, label: &str) -> Result<String, String> {
    match value {
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
            Ok(value.trim().into())
        }
        Some(serde_json::Value::Number(value)) => Ok(value.to_string()),
        _ => Err(format!("{label} is missing")),
    }
}

fn json_array_scalar(
    value: Option<&serde_json::Value>,
    outer: usize,
    inner: usize,
    label: &str,
) -> Result<String, String> {
    value
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.get(outer))
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.get(inner))
        .map_or_else(
            || Err(format!("{label} is missing")),
            |value| json_scalar(Some(value), label),
        )
}

fn json_indexed_scalar(
    value: Option<&serde_json::Value>,
    index: usize,
    label: &str,
) -> Result<String, String> {
    value
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.get(index))
        .map_or_else(
            || Err(format!("{label} is missing")),
            |value| json_scalar(Some(value), label),
        )
}

fn now_unix_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("clock error: {error}"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| "clock does not fit u64".into())
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::{
        BinanceSource, Book, ReferenceMarket, constant_time_eq, manifest_decimals, pair_market,
        parse_decimal_ratio, parse_okx_book, ratio_to_units, sample_from_coinbase_usdc_proxy_books,
    };

    #[test]
    fn supported_pair_metadata_is_pinned() {
        let strk_usdc = pair_market("STRK/USDC").expect("supported pair");
        assert!(matches!(
            strk_usdc.market,
            ReferenceMarket::Direct {
                binance: BinanceSource { symbol: "STRKUSDC" },
                ..
            }
        ));

        let eth_usdc = pair_market("ETH/USDC").expect("supported pair");
        assert!(matches!(
            eth_usdc.market,
            ReferenceMarket::Direct {
                binance: BinanceSource { symbol: "ETHUSDC" },
                kraken_base: "XETHZUSD",
                ..
            }
        ));

        // the derivative token is its own asset, so no underlying midpoint prices it.
        for unsupported in ["STRK/ETH", "strkBTC/USDC", "strkBTC/ETH", "STRK/strkBTC"] {
            assert!(pair_market(unsupported).is_none());
        }
        assert!(pair_market("USDC/USDT").is_none());
    }

    #[test]
    fn decimals_come_from_the_deployment_manifest() {
        // the same asset name can be a different token, with other decimals, on another
        // network: the manifest of the network being attested decides.
        let decimals = manifest_decimals(
            r#"{"manifest":{"product":{"assets":{"STRK":{"decimals":18},"USDC":{"decimals":6}}}}}"#,
        )
        .unwrap();
        assert_eq!(decimals["STRK"], 18);
        assert_eq!(decimals["USDC"], 6);
        assert!(manifest_decimals(r#"{"product":{"assets":{"USDC":{}}}}"#).is_err());
        assert!(manifest_decimals(r#"{"product":{}}"#).is_err());
    }

    #[test]
    fn okx_ticker_requires_success_and_best_prices() {
        let book = parse_okx_book(&serde_json::json!({
            "code": "0",
            "data": [{ "bidPx": "0.03695", "askPx": "0.03697" }]
        }))
        .expect("valid OKX ticker");
        assert_eq!(book.bid, "0.03695");
        assert_eq!(book.ask, "0.03697");
        assert!(parse_okx_book(&serde_json::json!({ "code": "1", "data": [] })).is_err());
        assert!(parse_okx_book(&serde_json::json!({ "code": "0", "data": [{}] })).is_err());
    }

    #[test]
    fn decimal_conversion_preserves_fractional_prices() {
        let price = parse_decimal_ratio("2499.125").expect("decimal");
        assert_eq!(
            ratio_to_units(price, 6, 10_u128.pow(18), 10_u128.pow(18), false).unwrap(),
            2_499_125_000
        );
    }

    #[test]
    fn coinbase_usdc_proxy_uses_executable_three_book_bounds() {
        let sample = sample_from_coinbase_usdc_proxy_books(
            "coinbase",
            [
                Book {
                    bid: "4000".into(),
                    ask: "4001".into(),
                },
                Book {
                    bid: "0.999".into(),
                    ask: "1.001".into(),
                },
                Book {
                    bid: "0.998".into(),
                    ask: "1.002".into(),
                },
            ],
            6,
            10_u128.pow(18),
            10_u128.pow(18),
            42,
        )
        .expect("three-book sample");

        assert_eq!(sample.source, "coinbase");
        assert!(sample.bid_price < 4_000_000_000);
        assert!(sample.ask_price > 4_001_000_000);
        assert!(sample.bid_price < sample.ask_price);
    }

    #[test]
    fn token_comparison_does_not_accept_prefixes() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"token2"));
        assert!(!constant_time_eq(b"token", b"tokem"));
    }
}

use std::{
    collections::{BTreeMap, HashMap},
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
    AssetId, DeploymentManifest, PairId, ReferencePriceAttestation, ReferencePriceBatchEntry,
    ReferencePriceEnvelope, ReferencePricePolicy, ReferencePriceSample, VenueAdapter,
    VenueObservation, build_reference_price_envelope, build_synthetic_cross_envelope,
    reference_price_batch_commitment, reference_price_source_set_commitment,
    sign_reference_price_attestation, sign_reference_price_attestation_in_batch,
};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8790";
/// sources are fetched together and the envelope is stamped before they are, so a source that
/// answers later than this is dropped rather than aging every attestation past the operator's
/// five-second freshness bound.
const DEFAULT_SOURCE_REQUEST_TIMEOUT_MS: u64 = 1_500;
/// the operator rejects envelopes older than five seconds.
const MAX_SOURCE_REQUEST_TIMEOUT_MS: u64 = 4_000;
const MAX_CEX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct AppState {
    client: Client,
    /// the exchange every attestation is bound to.
    exchange_address: Felt,
    signer_private_key: Arc<Zeroizing<String>>,
    auth_token_digest: [u8; 32],
    /// each asset's token decimals, from the deployment manifest: the same asset name can be a
    /// different token, with other decimals, on another network.
    decimals: Arc<HashMap<String, u8>>,
    markets: Arc<HashMap<String, PairMarket>>,
    registry_version: u64,
    registry_hash: String,
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

#[derive(Clone)]
struct UnsignedEntry {
    envelope: ReferencePriceEnvelope,
    source_set_commitment: String,
    max_age_ms: u64,
    attestation_ttl_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PairMarket {
    base_asset_id: String,
    quote_asset_id: String,
    price_base_scale: u128,
    reference: PairReference,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PairReference {
    Direct(DirectMarket),
    Synthetic {
        base_market_id: String,
        quote_market_id: String,
        max_leg_skew_ms: u64,
        max_age_ms: u64,
        envelope_bps: u32,
        attestation_ttl_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DirectMarket {
    binance_symbol: String,
    coinbase_base: String,
    coinbase_quote: String,
    okx_base: Option<String>,
    okx_quote: Option<String>,
    kraken_base: String,
    kraken_quote: String,
    reference_policy: ReferencePricePolicy,
    attestation_ttl_ms: u64,
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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "failed to install the tls crypto provider".to_string())?;
    let signer_private_key = required_env("ZYLITH_REFERENCE_PRICE_SIGNER_PRIVATE_KEY")?;
    let auth_token = required_env("ZYLITH_REFERENCE_PRICE_ATTESTOR_TOKEN")?;
    let exchange_address = required_felt_env("ZYLITH_EXCHANGE_ADDRESS")?;
    if env::var_os("ZYLITH_REFERENCE_PRICE_ATTESTATION_TTL_MS").is_some() {
        return Err(
            "ZYLITH_REFERENCE_PRICE_ATTESTATION_TTL_MS is retired; use the market registry".into(),
        );
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
    let manifest_raw = std::fs::read_to_string(required_env("ZYLITH_DEPLOYMENT_MANIFEST")?)
        .map_err(|error| format!("deployment manifest: {error}"))?;
    let expected_signer = manifest_reference_signer(&manifest_raw)?;
    let signer_secret = parse_felt(&signer_private_key)
        .ok_or("ZYLITH_REFERENCE_PRICE_SIGNER_PRIVATE_KEY must be a nonzero Starknet felt")?;
    if starknet_crypto::get_public_key(&signer_secret) != expected_signer {
        return Err("reference price private key does not match the deployment manifest".into());
    }
    let manifest = parse_manifest(&manifest_raw)?;
    let markets = reference_markets(&manifest)?;
    let state = AppState {
        client,
        exchange_address,
        signer_private_key: Arc::new(Zeroizing::new(signer_private_key)),
        auth_token_digest: sha256(auth_token.as_bytes()),
        decimals: Arc::new(manifest_decimals(&manifest_raw)?),
        markets: Arc::new(markets),
        registry_version: manifest.market_registry.registry_version,
        registry_hash: manifest.market_registry.registry_hash.clone(),
        nonce: Arc::new(AtomicU64::new(now_unix_ms()?)),
    };
    let app = Router::new()
        .route("/health", get(health))
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

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    registry_version: u64,
    registry_hash: String,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        registry_version: state.registry_version,
        registry_hash: state.registry_hash.clone(),
    })
}

async fn attest_reference_price(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AttestationRequest>,
) -> Result<Json<AttestationResponse>, StatusCode> {
    authenticate(&state, &headers)?;
    let unsigned = build_unsigned_entry(&state, &request).await?;
    let signed_at = now_unix_ms().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let valid_until_unix_ms = attestation_expiry(&unsigned, signed_at)?;
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
    for market in &request.markets {
        validate_request(&state, market)?;
    }
    let direct = futures::future::join_all(request.markets.iter().filter_map(|request| {
        let market = state.markets.get(&request.pair_id.0)?;
        matches!(market.reference, PairReference::Direct(_)).then(|| async {
            Ok::<_, StatusCode>((
                request.pair_id.0.clone(),
                build_unsigned_direct(&state, request, market).await?,
            ))
        })
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let mut unsigned_by_pair = direct.into_iter().collect::<BTreeMap<_, _>>();
    for request in &request.markets {
        let market = &state.markets[&request.pair_id.0];
        let PairReference::Synthetic {
            base_market_id,
            quote_market_id,
            max_leg_skew_ms,
            max_age_ms,
            envelope_bps,
            attestation_ttl_ms,
        } = &market.reference
        else {
            continue;
        };
        let base = unsigned_by_pair
            .get(base_market_id)
            .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
        let quote = unsigned_by_pair
            .get(quote_market_id)
            .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
        let now = now_unix_ms().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let entry = derive_synthetic_entry(
            request,
            base_market_id,
            quote_market_id,
            *max_leg_skew_ms,
            *max_age_ms,
            *envelope_bps,
            *attestation_ttl_ms,
            base,
            quote,
            now,
        )
        .map_err(|error| {
            eprintln!("synthetic reference envelope rejected: {error}");
            StatusCode::BAD_GATEWAY
        })?;
        unsigned_by_pair.insert(request.pair_id.0.clone(), entry);
    }
    let unsigned = request
        .markets
        .iter()
        .map(|market| {
            unsigned_by_pair
                .remove(&market.pair_id.0)
                .ok_or(StatusCode::UNPROCESSABLE_ENTITY)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let valid_from_unix_ms = now_unix_ms().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let entries = unsigned
        .iter()
        .map(|entry| {
            Ok(ReferencePriceBatchEntry {
                envelope: entry.envelope.clone(),
                source_set_commitment: entry.source_set_commitment.clone(),
                valid_until_unix_ms: attestation_expiry(entry, valid_from_unix_ms)?,
                nonce: state.nonce.fetch_add(1, Ordering::Relaxed),
            })
        })
        .collect::<Result<Vec<_>, StatusCode>>()?;
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
    validate_request(state, request)?;
    let pair = &state.markets[&request.pair_id.0];
    let PairReference::Synthetic {
        base_market_id,
        quote_market_id,
        max_leg_skew_ms,
        max_age_ms,
        envelope_bps,
        attestation_ttl_ms,
    } = &pair.reference
    else {
        return build_unsigned_direct(state, request, pair).await;
    };
    let base_market = state
        .markets
        .get(base_market_id)
        .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    let quote_market = state
        .markets
        .get(quote_market_id)
        .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    let direct_request = |market_id: &str, market: &PairMarket| AttestationRequest {
        pair_id: PairId(market_id.into()),
        base_asset_id: AssetId(market.base_asset_id.clone()),
        quote_asset_id: AssetId(market.quote_asset_id.clone()),
        price_base_scale: market.price_base_scale,
        exchange_address: request.exchange_address.clone(),
    };
    let base_request = direct_request(base_market_id, base_market);
    let quote_request = direct_request(quote_market_id, quote_market);
    let (base, quote) = tokio::join!(
        build_unsigned_direct(state, &base_request, base_market),
        build_unsigned_direct(state, &quote_request, quote_market),
    );
    let now = now_unix_ms().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    derive_synthetic_entry(
        request,
        base_market_id,
        quote_market_id,
        *max_leg_skew_ms,
        *max_age_ms,
        *envelope_bps,
        *attestation_ttl_ms,
        &base?,
        &quote?,
        now,
    )
    .map_err(|error| {
        eprintln!("synthetic reference envelope rejected: {error}");
        StatusCode::BAD_GATEWAY
    })
}

#[allow(clippy::too_many_arguments)]
fn derive_synthetic_entry(
    request: &AttestationRequest,
    base_market_id: &str,
    quote_market_id: &str,
    max_leg_skew_ms: u64,
    max_age_ms: u64,
    envelope_bps: u32,
    attestation_ttl_ms: u64,
    base: &UnsignedEntry,
    quote: &UnsignedEntry,
    now_unix_ms: u64,
) -> Result<UnsignedEntry, String> {
    let envelope = build_synthetic_cross_envelope(
        request.pair_id.clone(),
        request.base_asset_id.clone(),
        request.quote_asset_id.clone(),
        request.price_base_scale,
        PairId(base_market_id.into()),
        PairId(quote_market_id.into()),
        &base.envelope,
        &quote.envelope,
        now_unix_ms,
        max_leg_skew_ms,
        max_age_ms,
        envelope_bps,
    )
    .map_err(|error| error.to_string())?;
    let source_set_commitment = reference_price_source_set_commitment(&(
        "synthetic_cross_bbo_v1",
        base_market_id,
        &base.source_set_commitment,
        quote_market_id,
        &quote.source_set_commitment,
    ))
    .map_err(|error| error.to_string())?;
    Ok(UnsignedEntry {
        envelope,
        source_set_commitment,
        max_age_ms,
        attestation_ttl_ms,
    })
}

fn validate_request(state: &AppState, request: &AttestationRequest) -> Result<(), StatusCode> {
    if parse_felt(&request.exchange_address) != Some(state.exchange_address) {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let pair = state
        .markets
        .get(&request.pair_id.0)
        .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
    if request.base_asset_id.0 != pair.base_asset_id
        || request.quote_asset_id.0 != pair.quote_asset_id
        || request.price_base_scale != pair.price_base_scale
    {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    Ok(())
}

async fn build_unsigned_direct(
    state: &AppState,
    request: &AttestationRequest,
    pair: &PairMarket,
) -> Result<UnsignedEntry, StatusCode> {
    let PairReference::Direct(reference) = &pair.reference else {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    };
    let (Some(&base_decimals), Some(&quote_decimals)) = (
        state.decimals.get(&pair.base_asset_id),
        state.decimals.get(&pair.quote_asset_id),
    ) else {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    };
    let base_asset_scale = 10_u128
        .checked_pow(u32::from(base_decimals))
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut samples = fetch_samples(
        &state.client,
        reference,
        quote_decimals,
        base_asset_scale,
        request.price_base_scale,
        0,
    )
    .await
    .map_err(|error| {
        eprintln!(
            "reference source failure pair={}: {error}",
            request.pair_id.0
        );
        StatusCode::BAD_GATEWAY
    })?;
    let observed_at_unix_ms = now_unix_ms().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for sample in &mut samples {
        sample.observed_at_unix_ms = observed_at_unix_ms;
    }
    let envelope = build_reference_price_envelope(
        request.pair_id.clone(),
        request.base_asset_id.clone(),
        request.quote_asset_id.clone(),
        request.price_base_scale,
        observed_at_unix_ms,
        &samples,
        &reference.reference_policy,
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
        max_age_ms: reference.reference_policy.max_age_ms,
        attestation_ttl_ms: reference.attestation_ttl_ms,
    })
}

fn attestation_expiry(entry: &UnsignedEntry, signed_at_ms: u64) -> Result<u64, StatusCode> {
    let source_deadline = entry
        .envelope
        .observed_at_unix_ms
        .checked_add(entry.max_age_ms)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let signature_deadline = signed_at_ms
        .checked_add(entry.attestation_ttl_ms)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let valid_until = source_deadline.min(signature_deadline);
    if valid_until <= signed_at_ms {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(valid_until)
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

fn manifest_decimals(raw: &str) -> Result<HashMap<String, u8>, String> {
    Ok(parse_manifest(raw)?
        .market_registry
        .assets
        .into_iter()
        .map(|asset| (asset.asset_id.0, asset.decimals))
        .collect())
}

fn parse_manifest(raw: &str) -> Result<DeploymentManifest, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|error| format!("deployment manifest: {error}"))?;
    let value = value.get("manifest").cloned().unwrap_or(value);
    let manifest: DeploymentManifest = serde_json::from_value(value)
        .map_err(|error| format!("deployment manifest schema: {error}"))?;
    manifest.validate_market_registry()?;
    Ok(manifest)
}

fn manifest_reference_signer(raw: &str) -> Result<Felt, String> {
    let manifest = parse_manifest(raw)?;
    manifest.validate_production()?;
    parse_felt(&manifest.roles.reference_price_signer)
        .ok_or_else(|| "deployment manifest has no reference price signer".into())
}

fn reference_markets(manifest: &DeploymentManifest) -> Result<HashMap<String, PairMarket>, String> {
    manifest
        .market_registry
        .enabled_markets()
        .map(|market| {
            let reference = match &market.reference_price {
                zylith_core::MarketReferencePrice::DirectBboMidpoint {
                    primary,
                    corroborating,
                    ..
                } => {
                    let VenueObservation::Direct {
                        adapter: VenueAdapter::Binance,
                        symbol: binance_symbol,
                    } = primary
                    else {
                        return Err(format!(
                            "market {} primary source is not supported by the attestor",
                            market.market_id.0
                        ));
                    };
                    let mut coinbase = None;
                    let mut kraken = None;
                    let mut okx = None;
                    for observation in corroborating {
                        let VenueObservation::SameVenueRatio {
                            adapter,
                            base_symbol,
                            quote_symbol,
                        } = observation
                        else {
                            return Err(format!(
                                "market {} has an unsupported corroborating source",
                                market.market_id.0
                            ));
                        };
                        let slot = match adapter {
                            VenueAdapter::Coinbase => &mut coinbase,
                            VenueAdapter::Kraken => &mut kraken,
                            VenueAdapter::Okx => &mut okx,
                            VenueAdapter::Binance => {
                                return Err(format!(
                                    "market {} repeats the primary venue",
                                    market.market_id.0
                                ));
                            }
                        };
                        if slot
                            .replace((base_symbol.clone(), quote_symbol.clone()))
                            .is_some()
                        {
                            return Err(format!(
                                "market {} repeats a corroborating venue",
                                market.market_id.0
                            ));
                        }
                    }
                    let (coinbase_base, coinbase_quote) = coinbase.ok_or_else(|| {
                        format!("market {} has no Coinbase source", market.market_id.0)
                    })?;
                    let (kraken_base, kraken_quote) = kraken.ok_or_else(|| {
                        format!("market {} has no Kraken source", market.market_id.0)
                    })?;
                    let (okx_base, okx_quote) = okx.unzip();
                    PairReference::Direct(DirectMarket {
                        binance_symbol: binance_symbol.clone(),
                        coinbase_base,
                        coinbase_quote,
                        okx_base,
                        okx_quote,
                        kraken_base,
                        kraken_quote,
                        reference_policy: market.reference_price_policy().ok_or_else(|| {
                            format!("market {} has no direct price policy", market.market_id.0)
                        })?,
                        attestation_ttl_ms: market.reference_price.attestation_ttl_ms(),
                    })
                }
                zylith_core::MarketReferencePrice::SyntheticCrossBboMidpoint {
                    base_market_id,
                    quote_market_id,
                    max_leg_skew_ms,
                    max_age_ms,
                    envelope_bps,
                    attestation_ttl_ms,
                } => PairReference::Synthetic {
                    base_market_id: base_market_id.0.clone(),
                    quote_market_id: quote_market_id.0.clone(),
                    max_leg_skew_ms: *max_leg_skew_ms,
                    max_age_ms: *max_age_ms,
                    envelope_bps: *envelope_bps,
                    attestation_ttl_ms: *attestation_ttl_ms,
                },
            };
            Ok((
                market.market_id.0.clone(),
                PairMarket {
                    base_asset_id: market.base_asset_id.0.clone(),
                    quote_asset_id: market.quote_asset_id.0.clone(),
                    price_base_scale: market.price_base_scale,
                    reference,
                },
            ))
        })
        .collect()
}

async fn fetch_samples(
    client: &Client,
    market: &DirectMarket,
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    observed_at_unix_ms: u64,
) -> Result<Vec<ReferencePriceSample>, String> {
    let (
        binance_sample,
        coinbase_base,
        coinbase_quote,
        okx_base,
        okx_quote,
        kraken_base,
        kraken_quote,
    ) = tokio::join!(
        fetch_binance_sample(
            client,
            &market.binance_symbol,
            quote_decimals,
            base_asset_scale,
            price_base_scale,
            observed_at_unix_ms,
        ),
        fetch_coinbase_book(client, &market.coinbase_base),
        fetch_coinbase_book(client, &market.coinbase_quote),
        fetch_optional_okx_book(client, market.okx_base.as_deref()),
        fetch_optional_okx_book(client, market.okx_quote.as_deref()),
        fetch_kraken_book(client, &market.kraken_base),
        fetch_kraken_book(client, &market.kraken_quote),
    );
    let mut samples = vec![binance_sample?];
    if let (Ok(base), Ok(quote)) = (coinbase_base, coinbase_quote)
        && let Ok(sample) = sample_from_ratio_books(
            "coinbase",
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
    if let (Ok(Some(base)), Ok(Some(quote))) = (okx_base, okx_quote)
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
    Ok(samples)
}

/// the exact direct binance book sample for the market.
async fn fetch_binance_sample(
    client: &Client,
    symbol: &str,
    quote_decimals: u8,
    base_asset_scale: u128,
    price_base_scale: u128,
    observed_at_unix_ms: u64,
) -> Result<ReferencePriceSample, String> {
    let book = fetch_binance_book(client, symbol).await?;
    sample_from_book(
        &format!("binance:{symbol}"),
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
    use starknet_rust_core::types::Felt;

    use super::{
        AttestationRequest, Book, PairReference, UnsignedEntry, attestation_expiry,
        constant_time_eq, derive_synthetic_entry, manifest_decimals, manifest_reference_signer,
        parse_decimal_ratio, parse_manifest, parse_okx_book, ratio_to_units, reference_markets,
        sample_from_ratio_books,
    };
    use zylith_core::{AssetId, PairId, ReferencePriceDerivation, ReferencePriceEnvelope};

    #[test]
    fn reference_markets_are_data_driven_and_match_the_manifest() {
        let manifest = parse_manifest(include_str!(
            "../../../client/public/deployment.example.json"
        ))
        .unwrap();
        let markets = reference_markets(&manifest).unwrap();
        let PairReference::Direct(strk) = &markets["STRK/USDC"].reference else {
            panic!("expected direct STRK market")
        };
        let PairReference::Direct(eth) = &markets["ETH/USDC"].reference else {
            panic!("expected direct ETH market")
        };
        assert_eq!(strk.binance_symbol, "STRKUSDC");
        assert_eq!(eth.kraken_base, "XETHZUSD");
        assert!(matches!(
            markets["STRK/ETH"].reference,
            PairReference::Synthetic { .. }
        ));
    }

    #[test]
    fn decimals_come_from_the_deployment_manifest() {
        // the same asset name can be a different token, with other decimals, on another
        // network: the manifest of the network being attested decides.
        let decimals = manifest_decimals(include_str!(
            "../../../client/public/deployment.example.json"
        ))
        .unwrap();
        assert_eq!(decimals["STRK"], 18);
        assert_eq!(decimals["USDC"], 6);
        assert!(manifest_decimals(r#"{"market_registry":{}}"#).is_err());
    }

    #[test]
    fn signer_pin_requires_a_finalized_locked_manifest() {
        let mut manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../client/public/deployment.example.json"
        ))
        .unwrap();
        manifest["deployment"]["finalized"] = serde_json::json!(true);
        manifest["deployment"]["release_commit"] =
            serde_json::json!("1111111111111111111111111111111111111111");
        manifest["proof"]["config_locked_after_deploy"] = serde_json::json!(true);
        for field in [
            "transition_proof_program_address",
            "withdrawal_proof_program_address",
            "residual_recovery_proof_program_address",
            "virtual_program_hash",
            "starknet_os_config_hash",
            "proof_account_address",
            "proof_account_class_hash",
            "transition_proof_program_class_hash",
            "withdrawal_proof_program_class_hash",
            "residual_recovery_proof_program_class_hash",
            "settlement_account_address",
        ] {
            manifest["proof"][field] = serde_json::json!("0x1");
        }
        manifest["funding"]["starknet_privacy"]["ingress_key_registry_fingerprint"] =
            serde_json::json!("abababababababababababababababababababababababababababababababab");
        manifest["roles"]["reference_price_signer"] = serde_json::json!("0x123");
        let valid = manifest.to_string();
        assert_eq!(
            manifest_reference_signer(&valid).unwrap(),
            Felt::from(0x123_u16)
        );
        assert!(manifest_reference_signer(&valid.replace("true", "false")).is_err());
        assert!(manifest_reference_signer(&valid.replace("0x123", "0x0")).is_err());
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
    fn corroborating_ratio_books_use_executable_bounds() {
        let sample = sample_from_ratio_books(
            "coinbase",
            Book {
                bid: "4000".into(),
                ask: "4001".into(),
            },
            Book {
                bid: "0.999".into(),
                ask: "1.001".into(),
            },
            6,
            10_u128.pow(18),
            10_u128.pow(18),
            42,
        )
        .expect("ratio sample");

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

    #[test]
    fn attestation_expiry_never_outlives_the_primary_observation() {
        let entry = UnsignedEntry {
            envelope: ReferencePriceEnvelope {
                pair_id: PairId("ETH/USDC".into()),
                base_asset_id: AssetId("ETH".into()),
                quote_asset_id: AssetId("USDC".into()),
                midpoint_price: 1,
                lower_price: 1,
                upper_price: 1,
                price_base_scale: 1,
                source_count: 3,
                observed_at_unix_ms: 1_000,
                derivation: ReferencePriceDerivation::DirectBbo {
                    bid_price: 1,
                    ask_price: 1,
                },
            },
            source_set_commitment: "commitment".into(),
            max_age_ms: 5_000,
            attestation_ttl_ms: 5_000,
        };
        assert_eq!(attestation_expiry(&entry, 2_000).unwrap(), 6_000);
        assert!(attestation_expiry(&entry, 6_000).is_err());
    }

    #[test]
    fn a_single_synthetic_attestation_is_derived_from_both_direct_legs() {
        let direct = |pair: &str, base: &str, bid: u128, ask: u128| UnsignedEntry {
            envelope: ReferencePriceEnvelope {
                pair_id: PairId(pair.into()),
                base_asset_id: AssetId(base.into()),
                quote_asset_id: AssetId("USDC".into()),
                midpoint_price: (bid + ask) / 2,
                lower_price: bid,
                upper_price: ask,
                price_base_scale: 1_000_000,
                source_count: 3,
                observed_at_unix_ms: 9_900,
                derivation: ReferencePriceDerivation::DirectBbo {
                    bid_price: bid,
                    ask_price: ask,
                },
            },
            source_set_commitment: format!("{pair}-sources"),
            max_age_ms: 5_000,
            attestation_ttl_ms: 5_000,
        };
        let request = AttestationRequest {
            pair_id: PairId("STRK/ETH".into()),
            base_asset_id: AssetId("STRK".into()),
            quote_asset_id: AssetId("ETH".into()),
            price_base_scale: 1_000_000,
            exchange_address: "0x1".into(),
        };
        let entry = derive_synthetic_entry(
            &request,
            "STRK/USDC",
            "ETH/USDC",
            1_500,
            5_000,
            15,
            5_000,
            &direct("STRK/USDC", "STRK", 41_000, 42_000),
            &direct("ETH/USDC", "ETH", 2_600_000_000, 2_700_000_000),
            10_000,
        )
        .unwrap();
        assert_eq!(entry.envelope.pair_id.0, "STRK/ETH");
        assert!(matches!(
            entry.envelope.derivation,
            ReferencePriceDerivation::SyntheticCrossBbo { .. }
        ));
        assert_ne!(entry.source_set_commitment, "STRK/USDC-sources");
    }
}

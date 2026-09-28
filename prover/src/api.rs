//! the operator's http surface.
//!
//! private requests, status lookups included, arrive sealed to every execution key
//! (`zylith_core::exchange::seal_request`) at one endpoint. every request that opens is answered
//! with http 200 and a padded body sealed under the request's response key, so neither the url,
//! the status code nor the size says what was asked or what came back.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use zylith_core::exchange::{
    CancelRequest, MAX_STATUS_EVENTS_PER_ORDER, MAX_STATUS_ITEMS, PrivateRequest, SealedRequest,
    StatusRequest, cancel_message, open_request, seal_response, verify_message,
};

use crate::config::{from_core, to_core};
use crate::engine::{Operator, now_ms, start_withdrawal};
use crate::state::{CancellationTombstone, PendingOrder, key};

#[derive(Clone)]
struct Api {
    operator: Arc<Operator>,
    limiter: Arc<Mutex<HashMap<IpAddr, (u64, u32)>>>,
}

type Response = Result<Json<Value>, (StatusCode, Json<Value>)>;

fn reject(status: StatusCode, reason: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": reason })))
}

pub fn router(operator: Arc<Operator>) -> Router {
    let origins = operator
        .config
        .allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect::<Vec<_>>();
    let max_body = operator.config.max_body_bytes;
    let api = Api {
        operator,
        limiter: Arc::new(Mutex::new(HashMap::new())),
    };
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/public/execution-keys", get(execution_keys))
        .route("/api/public/exchange", get(exchange_status))
        .route(
            "/api/public/reference-prices/{base}/{quote}",
            get(reference_price),
        )
        .route("/api/private/requests", post(private_request))
        .route("/api/internal/status", get(internal_status))
        .with_state(api)
        .layer(DefaultBodyLimit::max(max_body))
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any)
                .allow_origin(AllowOrigin::list(origins)),
        )
}

async fn execution_keys(State(api): State<Api>) -> Json<Value> {
    Json(serde_json::to_value(api.operator.config.registry()).expect("registry serializes"))
}

async fn exchange_status(State(api): State<Api>) -> Json<Value> {
    let state = api.operator.state.lock().await;
    let config = &api.operator.config;
    Json(json!({
        "exchange": format!("{:#x}", config.exchange),
        "seq": state.confirmed_seq,
        "last_close_ms": state.confirmed_close_ms,
        "epoch_ms": config.policy.epoch_ms,
        "in_flight": state.in_flight.len(),
        "pairs": config.pairs.iter().map(|pair| pair.name.clone()).collect::<Vec<_>>(),
    }))
}

async fn reference_price(
    State(api): State<Api>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((base, quote)): Path<(String, String)>,
) -> Response {
    if !allow(&api, client_ip(&api, peer, &headers)).await {
        return Err(reject(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let name = format!("{base}/{quote}");
    let pair = api
        .operator
        .config
        .pairs
        .iter()
        .find(|pair| pair.name == name)
        .ok_or_else(|| reject(StatusCode::NOT_FOUND, "the pair is not traded"))?;
    let attestation = api
        .operator
        .market
        .reference(pair, now_ms())
        .await
        .map_err(|_| {
            reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "the reference price is unavailable",
            )
        })?;
    Ok(Json(json!({
        "pair": name,
        "midpoint": attestation.midpoint.to_string(),
        "scale": attestation.scale.to_string(),
        "observed_at_ms": attestation.observed_at_ms,
        "valid_until_ms": attestation.valid_until_ms,
    })))
}

async fn allow(api: &Api, peer: IpAddr) -> bool {
    let limit = api.operator.config.private_rate_limit_per_minute;
    let minute = now_ms() / 60_000;
    let mut limiter = api.limiter.lock().await;
    if limiter.len() > 100_000 {
        limiter.retain(|_, (window, _)| *window == minute);
    }
    let entry = limiter.entry(peer).or_insert((minute, 0));
    if entry.0 != minute {
        *entry = (minute, 0);
    }
    entry.1 += 1;
    entry.1 <= limit
}

/// the client's address: the peer, or behind a trusted proxy the last forwarded hop.
fn client_ip(api: &Api, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = peer.ip();
    if !api
        .operator
        .config
        .trusted_proxies
        .iter()
        .any(|network| network.contains(&peer_ip))
    {
        return peer_ip;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(peer_ip)
}

async fn private_request(
    State(api): State<Api>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(sealed): Json<SealedRequest>,
) -> Result<([(header::HeaderName, &'static str); 1], Json<Value>), (StatusCode, Json<Value>)> {
    if !allow(&api, client_ip(&api, peer, &headers)).await {
        return Err(reject(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let opened = open_request(&sealed, &api.operator.config.execution_keys)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "the request does not open"))?;
    let answer = match answer(&api.operator, opened.request).await {
        Ok(Value::Object(mut fields)) => {
            fields.insert("ok".into(), Value::Bool(true));
            Value::Object(fields)
        }
        Ok(_) => unreachable!("answers are objects"),
        Err(reason) => json!({ "ok": false, "error": reason }),
    };
    let response = seal_response(&opened.response_key, &sealed.digest, &answer)
        .map_err(|_| reject(StatusCode::INTERNAL_SERVER_ERROR, "the answer did not seal"))?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::to_value(response).expect("a sealed response serializes")),
    ))
}

async fn answer(operator: &Arc<Operator>, request: PrivateRequest) -> Result<Value, String> {
    operator.running()?;
    let chain_context = operator.config.chain_context();
    match request {
        PrivateRequest::Order(request) => {
            let pair = operator
                .config
                .pair(from_core(request.terms.pair_id))
                .ok_or("the pair is not traded")?;
            if request.terms.external && !pair.external_enabled {
                return Err("external execution is disabled for the pair".into());
            }
            let input_asset = if request.terms.sell {
                pair.base_asset_id
            } else {
                pair.quote_asset_id
            };
            request
                .validate(chain_context, to_core(input_asset), pair.min_order_amount)
                .map_err(|error| error.to_string())?;
            if request.terms.expiry_ms <= now_ms() {
                return Err("the order is already expired".into());
            }
            let order_id = from_core(request.order_id());
            let mut state = operator.state.lock().await;
            if state.cancelled_orders.contains_key(&key(&order_id)) {
                return Err("this immutable order id was already cancelled".into());
            }
            let in_book = state
                .book
                .iter()
                .any(|entry| entry.order.order_id == request.order_id());
            if !in_book && !state.pending_orders.contains_key(&key(&order_id)) {
                state.pending_orders.insert(
                    key(&order_id),
                    PendingOrder {
                        request,
                        received_at_ms: now_ms(),
                    },
                );
                operator.save(&state).await?;
            }
            Ok(json!({ "order_id": key(&order_id), "state": "received" }))
        }
        PrivateRequest::Cancel(request) => cancel(operator, chain_context, request).await,
        PrivateRequest::Withdraw(request) => {
            let nullifier = start_withdrawal(operator, request)
                .await
                .map_err(|error| crate::snip36::sanitize(&error))?;
            Ok(json!({ "nullifier": key(&nullifier) }))
        }
        PrivateRequest::Status(request) => status(operator, request).await,
    }
}

async fn cancel(
    operator: &Operator,
    chain_context: starknet_crypto::Felt,
    request: CancelRequest,
) -> Result<Value, String> {
    let order_id = from_core(request.order_id);
    let order_key = key(&order_id);
    let mut state = operator.state.lock().await;
    if let Some(tombstone) = state.cancelled_orders.get(&order_key) {
        if !verify_message(
            &to_core(tombstone.cancel_authority),
            &cancel_message(chain_context, request.order_id),
            &request.signature,
        ) {
            return Err("the cancellation is not signed by the order's cancel key".into());
        }
        return Ok(json!({
            "order_id": order_key,
            "state": "cancelled",
            "effective_after_seq": tombstone.effective_after_seq,
        }));
    }
    let (owner, expires_at_ms) = state
        .book
        .iter()
        .find(|entry| entry.order.order_id == request.order_id)
        .map(|entry| (entry.owner.clone(), entry.order.expiry_ms))
        .or_else(|| {
            state.pending_orders.get(&order_key).map(|order| {
                (
                    order.request.terms.owner.clone(),
                    order.request.terms.expiry_ms,
                )
            })
        })
        .or_else(|| {
            state.in_flight.iter().find_map(|transition| {
                transition
                    .result
                    .new_book
                    .iter()
                    .find(|entry| entry.order.order_id == request.order_id)
                    .map(|entry| (entry.owner.clone(), entry.order.expiry_ms))
            })
        })
        .ok_or("no such order")?;
    if !verify_message(
        &owner.cancel_authority,
        &cancel_message(chain_context, request.order_id),
        &request.signature,
    ) {
        return Err("the cancellation is not signed by the order's cancel key".into());
    }
    let in_flight_position = state.in_flight.iter().position(|transition| {
        transition
            .result
            .reports
            .iter()
            .any(|report| report.order_id == request.order_id)
    });
    let submitted_cutoff = in_flight_position.is_some_and(|position| {
        matches!(
            state.in_flight[position].stage,
            crate::state::TransitionStage::Submitted { .. }
        )
    });
    if let Some(position) = in_flight_position {
        // an unsent transition is not firm and is rebuilt without the cancelled order. once a
        // transaction is submitted, preserve it and discard only speculative descendants; if it
        // lands, the cancellation applies to whatever quantity remains.
        state.in_flight.truncate(if submitted_cutoff {
            position + 1
        } else {
            position
        });
    }
    // a pending order simply leaves; a live one leaves at the next transition.
    let cancelled_at = now_ms();
    let pending_removed = !submitted_cutoff && state.pending_orders.remove(&order_key).is_some();
    if !pending_removed {
        state
            .cancellations
            .insert(order_key.clone(), (request, cancelled_at));
    }
    let effective_after_seq = state
        .in_flight
        .iter()
        .filter(|transition| {
            transition
                .result
                .reports
                .iter()
                .any(|report| from_core(report.order_id) == order_id)
        })
        .map(|transition| transition.seq)
        .max()
        .unwrap_or(state.confirmed_seq);
    if pending_removed {
        state.cancelled_orders.insert(
            order_key.clone(),
            CancellationTombstone {
                cancel_authority: from_core(owner.cancel_authority),
                cancelled_at_ms: cancelled_at,
                expires_at_ms,
                effective_after_seq,
            },
        );
    }
    operator.save(&state).await?;
    Ok(json!({
        "order_id": order_key,
        "state": if pending_removed { "cancelled" } else { "scheduled" },
        "effective_after_seq": effective_after_seq,
    }))
}

/// the state of every order and withdrawal the wallet asks about. fills are reported without
/// their output notes: the wallet recovers those from the public transitions.
async fn status(operator: &Operator, request: StatusRequest) -> Result<Value, String> {
    if request.orders.len() + request.nullifiers.len() > MAX_STATUS_ITEMS {
        return Err("too many items in one status request".into());
    }
    let state = operator.state.lock().await;
    let orders = request
        .orders
        .iter()
        .map(|query| {
            let order_id = from_core(query.order_id);
            let events = state
                .orders
                .get(&key(&order_id))
                .map(Vec::as_slice)
                .unwrap_or_default();
            let status = if state.pending_orders.contains_key(&key(&order_id)) {
                "pending"
            } else if state
                .book
                .iter()
                .any(|entry| entry.order.order_id == query.order_id)
            {
                "live"
            } else if !events.is_empty() || state.closed_orders.contains_key(&key(&order_id)) {
                "closed"
            } else {
                "unknown"
            };
            // how and when a closed order left the book: from its last event, or from the
            // tombstone its pruned history left.
            let closed = events
                .last()
                .and_then(|event| {
                    event
                        .report
                        .removal
                        .clone()
                        .map(|removal| (event.seq, removal))
                })
                .or_else(|| {
                    state
                        .closed_orders
                        .get(&key(&order_id))
                        .map(|closed| (closed.seq, closed.removal.clone()))
                });
            // the oldest unseen events first, a bounded number per answer: a wallet further
            // behind advances its cursor and asks again.
            let unseen = events
                .iter()
                .filter(|event| event.seq > query.after_seq)
                .collect::<Vec<_>>();
            json!({
                "order_id": key(&order_id),
                "status": status,
                "cancel_requested": state.cancellations.contains_key(&key(&order_id)),
                "more_events": unseen.len() > MAX_STATUS_EVENTS_PER_ORDER,
                "closed_seq": closed.as_ref().map(|(seq, _)| seq),
                "removal": closed.map(|(_, removal)| removal),
                "events": unseen
                    .iter()
                    .take(MAX_STATUS_EVENTS_PER_ORDER)
                    .map(|event| json!({
                        "seq": event.seq,
                        "close_time_ms": event.close_time_ms,
                        "report": event.report,
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let withdrawals = request
        .nullifiers
        .iter()
        .map(|nullifier| {
            let nullifier = from_core(*nullifier);
            let job = state.withdrawals.get(&key(&nullifier));
            json!({
                "nullifier": key(&nullifier),
                "stage": job.map(|job| &job.stage),
                "updated_at_ms": job.map(|job| job.updated_at_ms),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "orders": orders, "withdrawals": withdrawals }))
}

async fn internal_status(State(api): State<Api>, headers: HeaderMap) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if !zylith_core::constant_time_eq(token, &api.operator.config.control_token) {
        return Err(reject(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let state = api.operator.state.lock().await;
    Ok(Json(json!({
        "confirmed_seq": state.confirmed_seq,
        "book_orders": state.book.len(),
        "pending_orders": state.pending_orders.len(),
        "cancellations": state.cancellations.len(),
        "open_capacities": state.capacities.len(),
        "in_flight": state.in_flight.iter().map(|entry| json!({ "seq": entry.seq, "stage": entry.stage })).collect::<Vec<_>>(),
        "note_batches": state.notes.batches.len(),
        "withdrawals": state.withdrawals.len(),
    })))
}

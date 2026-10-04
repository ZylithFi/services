//! the operator's http surface.
//!
//! private requests, status lookups included, arrive sealed to every execution key
//! (`zylith_core::exchange::seal_request`) at one endpoint. every request that opens is answered
//! with http 200 and a padded body sealed under the request's response key, so neither the url,
//! the status code nor the size says what was asked or what came back.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use zylith_core::exchange::{
    CancelRequest, MAX_STATUS_EVENTS_PER_ORDER, MAX_STATUS_ITEMS, PrivateRequest, SealedRequest,
    StatusRequest, WithdrawalQuery, cancel_message, open_request, seal_response, verify_message,
    withdrawal_status_message,
};

use crate::config::{from_core, to_core};
use crate::engine::{
    Operator, active_closing_epoch, cancellation_can_settle_offchain, now_ms, start_withdrawal,
};
use crate::state::{CancellationTombstone, PendingOrder, key};

#[derive(Clone)]
struct Api {
    operator: Arc<Operator>,
    private_limiter: Arc<Mutex<HashMap<IpAddr, (u64, u32)>>>,
    public_limiter: Arc<Mutex<HashMap<IpAddr, (u64, u32)>>>,
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
        private_limiter: Arc::new(Mutex::new(HashMap::new())),
        public_limiter: Arc::new(Mutex::new(HashMap::new())),
    };
    Router::new()
        .route("/health", get(health))
        .route("/api/public/execution-keys", get(execution_keys))
        .route("/api/public/exchange", get(exchange_status))
        .route("/api/public/reference-prices", get(reference_prices))
        .route("/api/private/requests", post(private_request))
        .route("/api/internal/status", get(internal_status))
        .with_state(api)
        .layer(DefaultBodyLimit::max(max_body))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any)
                .allow_origin(AllowOrigin::list(origins)),
        )
}

async fn health(State(api): State<Api>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "registry_version": api.operator.config.manifest.market_registry.registry_version,
        "registry_hash": api.operator.config.manifest.market_registry.registry_hash,
    }))
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
        "pairs": config.pairs.iter().map(|pair| pair.name.clone()).collect::<Vec<_>>(),
        "registry_version": config.manifest.market_registry.registry_version,
        "registry_hash": config.manifest.market_registry.registry_hash,
    }))
}

async fn reference_prices(
    State(api): State<Api>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !allow(
        &api.public_limiter,
        api.operator.config.private_rate_limit_per_minute,
        client_ip(&api, peer, &headers),
    )
    .await
    {
        return Err(reject(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let prices = api
        .operator
        .market
        .references(&api.operator.config.pairs, now_ms())
        .await
        .map_err(|_| {
            reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "reference prices are unavailable",
            )
        })?;
    Ok(Json(
        json!({ "prices": api.operator.config.pairs.iter().zip(prices).map(|(pair, attestation)| json!({
        "pair": pair.name,
        "midpoint": attestation.midpoint.to_string(),
        "scale": attestation.scale.to_string(),
        "observed_at_ms": attestation.observed_at_ms,
        "valid_until_ms": attestation.valid_until_ms,
    })).collect::<Vec<_>>() }),
    ))
}

async fn allow(limiter: &Mutex<HashMap<IpAddr, (u64, u32)>>, limit: u32, peer: IpAddr) -> bool {
    let minute = now_ms() / 60_000;
    let mut limiter = limiter.lock().await;
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

/// the client's address, resolved right-to-left through only configured proxy hops.
fn client_ip(api: &Api, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = peer.ip();
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    zylith_core::forwarded_client_ip(peer_ip, forwarded, |address| {
        api.operator
            .config
            .trusted_proxies
            .iter()
            .any(|network| network.contains(&address))
    })
}

async fn private_request(
    State(api): State<Api>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(sealed): Json<SealedRequest>,
) -> Result<([(header::HeaderName, &'static str); 1], Json<Value>), (StatusCode, Json<Value>)> {
    if !allow(
        &api.private_limiter,
        api.operator.config.private_rate_limit_per_minute,
        client_ip(&api, peer, &headers),
    )
    .await
    {
        return Err(reject(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let opened = open_request(&sealed, &api.operator.config.execution_keys)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "the request does not open"))?;
    // membership is determined when the authenticated request has opened, not when a contended
    // state lock later becomes available.
    let received_at_ms = now_ms();
    let answer = match answer(&api.operator, opened.request, received_at_ms).await {
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

async fn answer(
    operator: &Arc<Operator>,
    request: PrivateRequest,
    received_at_ms: u64,
) -> Result<Value, String> {
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
                .validate(
                    chain_context,
                    to_core(input_asset),
                    pair.min_order_amount,
                    pair.min_order_quote_amount,
                    pair.scale,
                )
                .map_err(|error| error.to_string())?;
            if request.terms.expiry_ms <= received_at_ms {
                return Err("the order is already expired".into());
            }
            if request.terms.expiry_ms
                > received_at_ms
                    .checked_add(operator.config.policy.max_order_lifetime_ms)
                    .ok_or("the order lifetime overflows")?
            {
                return Err("the order expires too far in the future".into());
            }
            let order_id = from_core(request.order_id());
            let order_key = key(&order_id);
            {
                let state = operator.state.lock().await;
                validate_pending_order(
                    &state,
                    &request,
                    &order_key,
                    operator.config.policy.max_pending_orders,
                )?;
                if state
                    .book
                    .iter()
                    .any(|entry| entry.order.order_id == request.order_id())
                    || state
                        .pending_orders
                        .get(&order_key)
                        .is_some_and(|pending| pending.request == request)
                {
                    return Ok(json!({ "order_id": order_key, "state": "received" }));
                }
            }
            for note in &request.funding {
                if operator
                    .chain()
                    .nullifier_state(from_core(note.nullifier()))
                    .await?
                    != 0
                {
                    return Err("an order funding note is already spent or exiting".into());
                }
            }
            let mut state = operator.state.lock().await;
            validate_pending_order(
                &state,
                &request,
                &order_key,
                operator.config.policy.max_pending_orders,
            )?;
            if !state
                .book
                .iter()
                .any(|entry| entry.order.order_id == request.order_id())
                && !state.pending_orders.contains_key(&order_key)
            {
                state.pending_orders.insert(
                    order_key.clone(),
                    PendingOrder {
                        request,
                        received_at_ms,
                    },
                );
                operator.save(&state).await?;
            }
            Ok(json!({ "order_id": order_key, "state": "received" }))
        }
        PrivateRequest::Cancel(request) => {
            cancel(operator, chain_context, request, received_at_ms).await
        }
        PrivateRequest::Withdraw(request) => {
            let nullifier = start_withdrawal(operator, request)
                .await
                .map_err(|error| crate::snip36::sanitize(&error))?;
            Ok(json!({ "nullifier": key(&nullifier) }))
        }
        PrivateRequest::Status(request) => status(operator, request).await,
    }
}

fn validate_pending_order(
    state: &crate::state::OperatorState,
    request: &zylith_core::exchange::OrderRequest,
    order_key: &str,
    max_pending: usize,
) -> Result<(), String> {
    if state.cancelled_orders.contains_key(order_key) {
        return Err("this immutable order id was already cancelled".into());
    }
    if let Some(existing) = state.pending_orders.get(order_key) {
        return if existing.request == *request {
            Ok(())
        } else {
            Err("this immutable order id is already used by another request".into())
        };
    }
    if state
        .book
        .iter()
        .any(|entry| entry.order.order_id == request.order_id())
    {
        return Ok(());
    }
    if state.pending_orders.len() >= max_pending {
        return Err("the pending-order capacity is full".into());
    }
    let requested = request
        .funding
        .iter()
        .map(|note| from_core(note.nullifier()).to_bytes_be())
        .collect::<BTreeSet<_>>();
    if requested.len() != request.funding.len() {
        return Err("an order cannot use the same funding note twice".into());
    }
    if request.funding.iter().any(|note| {
        state
            .notes
            .membership(from_core(note.output_leaf()))
            .is_none()
    }) {
        return Err("an order funding note is not in the authenticated note index".into());
    }
    let already_reserved = state.pending_orders.values().any(|pending| {
        pending
            .request
            .funding
            .iter()
            .any(|note| requested.contains(&from_core(note.nullifier()).to_bytes_be()))
    });
    if already_reserved {
        return Err("an order funding note is already reserved by another pending order".into());
    }
    let in_flight_spent = state.in_flight.iter().any(|transition| {
        transition
            .result
            .public
            .nullifiers
            .iter()
            .any(|nullifier| requested.contains(&from_core(*nullifier).to_bytes_be()))
    });
    if in_flight_spent {
        return Err("an order funding note is already reserved by an in-flight transition".into());
    }
    Ok(())
}

async fn cancel(
    operator: &Operator,
    chain_context: starknet_crypto::Felt,
    request: CancelRequest,
    cancelled_at: u64,
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
    let safe_truncation_position =
        cancellation_truncation_position(&state.in_flight, request.order_id, cancelled_at);
    let included_in_closed_epoch = state.in_flight.iter().any(|transition| {
        (transition.close_time_ms <= cancelled_at
            || transition.prepared_submission.is_some()
            || matches!(
                transition.stage,
                crate::state::TransitionStage::Submitted { .. }
            ))
            && transition
                .result
                .reports
                .iter()
                .any(|report| report.order_id == request.order_id)
    });
    if let Some(position) = safe_truncation_position {
        state.in_flight.truncate(position);
    }
    // only an order outside every already-closed snapshot can leave purely offchain.
    let pending_removed = !included_in_closed_epoch
        && cancellation_can_settle_offchain(
            &state,
            &order_key,
            cancelled_at,
            active_closing_epoch(operator)?,
        )
        && state.pending_orders.remove(&order_key).is_some();
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

fn transition_is_firm(transition: &crate::state::InFlight) -> bool {
    transition.prepared_submission.is_some()
        || matches!(
            transition.stage,
            crate::state::TransitionStage::Submitted { .. }
        )
}

fn cancellation_truncation_position(
    in_flight: &[crate::state::InFlight],
    order_id: starknet_crypto::Felt,
    cancelled_at: u64,
) -> Option<usize> {
    in_flight
        .iter()
        .position(|transition| {
            transition
                .result
                .reports
                .iter()
                .any(|report| report.order_id == order_id)
                && transition.close_time_ms > cancelled_at
        })
        .filter(|position| !in_flight[*position..].iter().any(transition_is_firm))
}

/// the state of every order and withdrawal the wallet asks about. fills are reported without
/// their output notes: the wallet recovers those from the public transitions.
async fn status(operator: &Operator, request: StatusRequest) -> Result<Value, String> {
    if request.orders.len() + request.withdrawals.len() > MAX_STATUS_ITEMS {
        return Err("too many items in one status request".into());
    }
    let chain_context = operator.config.chain_context();
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
        .withdrawals
        .iter()
        .map(|query| {
            let nullifier = from_core(query.nullifier);
            let job = state.withdrawals.get(&key(&nullifier));
            json!({
                "nullifier": key(&nullifier),
                "stage": authenticated_withdrawal_stage(job, chain_context, query),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "orders": orders, "withdrawals": withdrawals }))
}

fn authenticated_withdrawal_stage<'a>(
    job: Option<&'a crate::state::WithdrawalJob>,
    chain_context: starknet_crypto::Felt,
    query: &WithdrawalQuery,
) -> Option<&'a crate::state::WithdrawalStage> {
    job.filter(|job| {
        verify_message(
            &job.request.note.withdraw_authority,
            &withdrawal_status_message(chain_context, query.nullifier),
            &query.authorization,
        )
    })
    .map(|job| &job.stage)
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

#[cfg(test)]
mod tests {
    use starknet_rust_core::types::Felt;
    use zylith_core::exchange::fixtures::{BASE, Notes, User, deposit, input, new_order, user};
    use zylith_core::exchange::{
        NoteFields, OrderRequest, WithdrawRequest, build_transition, sign_message,
        withdrawal_status_message,
    };

    use super::*;
    use crate::chain::NoteBatch;
    use crate::config::from_core;
    use crate::state::{InFlight, OperatorState, TransitionStage, WithdrawalJob, WithdrawalStage};

    fn request(notes: &Notes, owner: &User, note: &NoteFields, amount: u128) -> OrderRequest {
        let order = new_order(
            notes,
            owner,
            true,
            false,
            amount,
            1,
            std::slice::from_ref(note),
        );
        OrderRequest {
            terms: order.terms,
            funding: vec![note.clone()],
            authorization: order.authorization,
        }
    }

    #[test]
    fn pending_admission_requires_an_indexed_unreserved_note_and_capacity() {
        let owner = user(201);
        let note = deposit(&owner, BASE, 10, 201);
        let mut notes = Notes::default();
        notes.add_deposit(&note);
        let first = request(&notes, &owner, &note, 10);
        let second = request(&notes, &owner, &note, 9);
        let mut state = OperatorState::new(0);
        let first_key = key(&from_core(first.order_id()));

        assert!(validate_pending_order(&state, &first, &first_key, 1).is_err());
        state
            .notes
            .append(NoteBatch {
                root: from_core(note.output_leaf()),
                leaves: vec![from_core(note.output_leaf())],
                seq: None,
                block: 1,
            })
            .unwrap();
        validate_pending_order(&state, &first, &first_key, 1).unwrap();
        state.pending_orders.insert(
            first_key,
            PendingOrder {
                request: first,
                received_at_ms: 1,
            },
        );
        assert!(
            validate_pending_order(&state, &second, &key(&from_core(second.order_id())), 2)
                .unwrap_err()
                .contains("reserved")
        );

        let other = user(202);
        let other_note = deposit(&other, BASE, 10, 202);
        let mut other_notes = Notes::default();
        other_notes.add_deposit(&other_note);
        let other_request = request(&other_notes, &other, &other_note, 10);
        assert!(
            validate_pending_order(
                &state,
                &other_request,
                &key(&from_core(other_request.order_id())),
                1,
            )
            .unwrap_err()
            .contains("capacity")
        );
    }

    #[test]
    fn a_firm_transition_is_never_discarded_for_a_later_cancellation() {
        let owner = user(203);
        let note = deposit(&owner, BASE, 10, 203);
        let mut notes = Notes::default();
        notes.add_deposit(&note);
        let order = new_order(
            &notes,
            &owner,
            true,
            false,
            10,
            1,
            std::slice::from_ref(&note),
        );
        let result = build_transition(&input(1, vec![], vec![order], notes.root(), 100)).unwrap();
        let order_id = result.reports[0].order_id;
        let mut transition = InFlight {
            seq: 1,
            close_time_ms: 10_001,
            result,
            calldata: vec![],
            admitted: vec![],
            cancelled: vec![],
            applied_capacities: vec![],
            stage: TransitionStage::Proven,
            proof: None,
            prepared_submission: None,
            prepared_legged: vec![],
            built_at_ms: 10_000,
            legged: vec![],
            leg_dropped: false,
            for_legs: false,
        };
        assert!(!transition_is_firm(&transition));
        assert_eq!(
            cancellation_truncation_position(std::slice::from_ref(&transition), order_id, 10_000,),
            Some(0),
        );
        transition.stage = TransitionStage::Submitted {
            transaction_hash: Felt::ONE,
        };
        assert!(transition_is_firm(&transition));
        assert_eq!(
            cancellation_truncation_position(&[transition], order_id, 10_000),
            None,
        );
    }

    #[test]
    fn withdrawal_status_requires_the_notes_withdraw_authority() {
        let owner = user(204);
        let note = deposit(&owner, BASE, 10, 204);
        let chain_context = starknet_crypto::Felt::from(0x123_u64);
        let nullifier = note.nullifier();
        let query = WithdrawalQuery {
            nullifier,
            authorization: sign_message(
                &owner.withdraw_key,
                &withdrawal_status_message(chain_context, nullifier),
            )
            .unwrap(),
        };
        let job = WithdrawalJob {
            request: WithdrawRequest {
                note,
                exit_commitment: starknet_crypto::Felt::ONE,
                exit_authority: starknet_crypto::Felt::ONE,
                authorization: query.authorization,
            },
            nullifier: from_core(nullifier),
            stage: WithdrawalStage::Proving,
            prepared_submission: None,
            updated_at_ms: 1,
        };
        assert!(matches!(
            authenticated_withdrawal_stage(Some(&job), chain_context, &query),
            Some(WithdrawalStage::Proving)
        ));
        let forged = WithdrawalQuery {
            nullifier,
            authorization: sign_message(
                &user(205).withdraw_key,
                &withdrawal_status_message(chain_context, nullifier),
            )
            .unwrap(),
        };
        assert!(authenticated_withdrawal_stage(Some(&job), chain_context, &forged).is_none());
        assert!(authenticated_withdrawal_stage(None, chain_context, &query).is_none());
    }
}

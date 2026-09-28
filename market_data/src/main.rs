//! same-origin market data proxy.
//!
//! browsers never talk to exchanges directly: every third-party market data
//! request goes through this service, which keeps one shared upstream
//! websocket to binance, caches rest lookups with single-flight fetching, and
//! fans data out to clients over server-sent events. upstream venues only ever
//! see zylith's egress address, never a trader's ip, origin or pair interest.

use std::{
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    future::Future,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use futures_util::{SinkExt, StreamExt, stream};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{OnceCell, broadcast, mpsc};
use tokio_tungstenite::tungstenite::Message;

const BIND_ADDR_ENV: &str = "ZYLITH_MARKET_DATA_BIND_ADDR";
const PAIRS_ENV: &str = "ZYLITH_MARKET_DATA_PAIRS";
const MANIFEST_ENV: &str = "ZYLITH_DEPLOYMENT_MANIFEST";
const MAX_STREAMS_ENV: &str = "ZYLITH_MARKET_DATA_MAX_STREAMS";
const MAX_STREAMS_PER_CLIENT_ENV: &str = "ZYLITH_MARKET_DATA_MAX_STREAMS_PER_CLIENT";
const MAX_STREAM_LIFETIME_SECONDS_ENV: &str = "ZYLITH_MARKET_DATA_MAX_STREAM_LIFETIME_SECONDS";
const TRUSTED_PROXY_CIDRS_ENV: &str = "ZYLITH_TRUSTED_PROXY_CIDRS";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3500";
#[cfg(test)]
const DEFAULT_PAIRS: &str = "STRK/USDC,ETH/USDC";
const DEFAULT_MAX_STREAMS: usize = 4_096;
const DEFAULT_MAX_STREAMS_PER_CLIENT: usize = 64;
const DEFAULT_MAX_STREAM_LIFETIME: Duration = Duration::from_secs(300);

const BINANCE_REST_ORIGINS: [&str; 2] =
    ["https://api.binance.com", "https://data-api.binance.vision"];
const BINANCE_STREAM_ORIGINS: [&str; 3] = [
    "wss://data-stream.binance.vision",
    "wss://stream.binance.com:443",
    "wss://stream.binance.com:9443",
];
const COINBASE_ORIGIN: &str = "https://api.exchange.coinbase.com";
const KRAKEN_ORIGIN: &str = "https://api.kraken.com";
const OKX_ORIGINS: [&str; 2] = ["https://www.okx.com", "https://www.okx.cab"];

const CHART_INTERVALS: [&str; 8] = ["1m", "5m", "15m", "1h", "4h", "1d", "1w", "1M"];
const MAX_CANDLES: usize = 500;
const SUMMARY_TTL: Duration = Duration::from_secs(5);
const CANDLES_TTL: Duration = Duration::from_secs(30);
const SUMMARY_PUSH_INTERVAL: Duration = Duration::from_secs(15);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UPSTREAM_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_ASSET_SYMBOL_LEN: usize = 12;

type UpstreamFuture = Pin<Box<dyn Future<Output = Option<Value>> + Send>>;
/// fetches one upstream json document; injectable so tests never touch the network.
type Fetcher = Arc<dyn Fn(String) -> UpstreamFuture + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
struct Book {
    bid: f64,
    ask: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
struct Candle {
    time: i64,
    open: f64,
    high: f64,
    low: f64,
    close: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Ticker {
    last: f64,
    previous_close: f64,
    high: f64,
    low: f64,
    quote_volume: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
struct MarketStats {
    last: f64,
    change_percent: f64,
    high: f64,
    low: f64,
    quote_volume: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct VenueQuote {
    venue: &'static str,
    bid: f64,
    ask: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct MarketSummary {
    bbos: Vec<VenueQuote>,
    stats: Option<MarketStats>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct CandleHistory {
    candles: Vec<Candle>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Pair {
    base: String,
    quote: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BinanceMarket {
    Direct(String),
    Ratio { base: String, quote: String },
}

fn normalize_asset(raw: &str) -> String {
    raw.trim().to_ascii_uppercase()
}

/// the pair's own binance book when it has one, as the reference price attestor prices it;
/// otherwise the ratio of both assets' usdc books.
fn binance_market(pair: &Pair) -> BinanceMarket {
    if pair.quote == "USDT" || pair.quote == "USDC" {
        BinanceMarket::Direct(format!("{}{}", pair.base, pair.quote))
    } else {
        BinanceMarket::Ratio {
            base: format!("{}USDC", pair.base),
            quote: format!("{}USDC", pair.quote),
        }
    }
}

fn valid_book(bid: f64, ask: f64) -> Option<Book> {
    (bid.is_finite() && ask.is_finite() && bid > 0.0 && ask >= bid).then_some(Book { bid, ask })
}

fn ratio_book(base: Book, quote: Book) -> Option<Book> {
    valid_book(base.bid / quote.ask, base.ask / quote.bid)
}

fn number(value: &Value) -> f64 {
    match value {
        Value::String(text) => text.parse().unwrap_or(f64::NAN),
        Value::Number(number) => number.as_f64().unwrap_or(f64::NAN),
        _ => f64::NAN,
    }
}

fn parse_binance_book(value: &Value) -> Option<Book> {
    valid_book(number(&value["bidPrice"]), number(&value["askPrice"]))
}

fn parse_binance_ticker(value: &Value) -> Option<Ticker> {
    let ticker = Ticker {
        last: number(&value["lastPrice"]),
        previous_close: number(&value["prevClosePrice"]),
        high: number(&value["highPrice"]),
        low: number(&value["lowPrice"]),
        quote_volume: number(&value["quoteVolume"]),
    };
    let positive = |value: f64| value.is_finite() && value > 0.0;
    (positive(ticker.last)
        && positive(ticker.previous_close)
        && positive(ticker.high)
        && positive(ticker.low)
        && ticker.quote_volume.is_finite()
        && ticker.quote_volume >= 0.0)
        .then_some(ticker)
}

fn combine_tickers(base: Ticker, quote: Option<Ticker>) -> MarketStats {
    let Some(quote) = quote else {
        return MarketStats {
            last: base.last,
            change_percent: (base.last - base.previous_close) / base.previous_close * 100.0,
            high: base.high,
            low: base.low,
            quote_volume: base.quote_volume,
        };
    };
    let last = base.last / quote.last;
    let previous_close = base.previous_close / quote.previous_close;
    MarketStats {
        last,
        change_percent: (last - previous_close) / previous_close * 100.0,
        high: base.high / quote.low,
        low: base.low / quote.high,
        // the base leg is usdt-denominated, the closest usd notional for a ratio market.
        quote_volume: base.quote_volume,
    }
}

fn parse_kline_row(row: &Value) -> Option<Candle> {
    let row = row.as_array()?;
    if row.len() < 5 {
        return None;
    }
    candle_from_parts(&row[0], &row[1], &row[2], &row[3], &row[4])
}

fn candle_from_parts(
    open_time_ms: &Value,
    open: &Value,
    high: &Value,
    low: &Value,
    close: &Value,
) -> Option<Candle> {
    let time = number(open_time_ms);
    let candle = Candle {
        time: (time / 1_000.0).floor() as i64,
        open: number(open),
        high: number(high),
        low: number(low),
        close: number(close),
    };
    let finite = [time, candle.open, candle.high, candle.low, candle.close]
        .iter()
        .all(|value| value.is_finite());
    (finite
        && candle.time > 0
        && candle.open > 0.0
        && candle.low > 0.0
        && candle.high >= candle.open.max(candle.close)
        && candle.low <= candle.open.min(candle.close))
    .then_some(candle)
}

fn parse_klines(value: &Value) -> Vec<Candle> {
    value
        .as_array()
        .map(|rows| rows.iter().filter_map(parse_kline_row).collect())
        .unwrap_or_default()
}

fn combine_candles(base: Candle, quote: Option<Candle>) -> Option<Candle> {
    let Some(quote) = quote else {
        return Some(base);
    };
    (base.time == quote.time).then(|| Candle {
        time: base.time,
        open: base.open / quote.open,
        high: base.high / quote.low,
        low: base.low / quote.high,
        close: base.close / quote.close,
    })
}

fn combine_klines(base: Vec<Candle>, quote: Option<Vec<Candle>>) -> Vec<Candle> {
    let Some(quote) = quote else {
        return base;
    };
    let quote_by_time = quote
        .into_iter()
        .map(|candle| (candle.time, candle))
        .collect::<HashMap<_, _>>();
    base.into_iter()
        .filter_map(|candle| combine_candles(candle, Some(*quote_by_time.get(&candle.time)?)))
        .collect()
}

/// parses one combined-stream kline frame into (stream name, candle).
fn parse_stream_kline(text: &str) -> Option<(String, Candle)> {
    let value = serde_json::from_str::<Value>(text).ok()?;
    let stream = value["stream"].as_str()?.to_owned();
    let kline = &value["data"]["k"];
    let candle = candle_from_parts(
        &kline["t"],
        &kline["o"],
        &kline["h"],
        &kline["l"],
        &kline["c"],
    )?;
    Some((stream, candle))
}

fn kline_stream_name(symbol: &str, interval: &str) -> String {
    format!("{}@kline_{interval}", symbol.to_ascii_lowercase())
}

fn subscribe_message(streams: &[String], id: u64) -> String {
    serde_json::json!({ "method": "SUBSCRIBE", "params": streams, "id": id }).to_string()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// fill time plus the single-flight cell every concurrent reader awaits.
type CacheEntry<V> = (Instant, Arc<OnceCell<Arc<V>>>);

/// short-lived cache with single-flight fills: concurrent requests for one key
/// share a single upstream fetch, so client count never multiplies upstream load.
struct Cache<K, V> {
    ttl: Duration,
    entries: tokio::sync::Mutex<HashMap<K, CacheEntry<V>>>,
}

impl<K: Eq + Hash + Clone, V> Cache<K, V> {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn get_or_fetch<F, Fut>(&self, key: K, fetch: F) -> Arc<V>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
    {
        let cell = {
            let mut entries = self.entries.lock().await;
            let now = Instant::now();
            entries.retain(|_, (filled_at, _)| now.duration_since(*filled_at) < self.ttl * 4);
            match entries.get(&key) {
                Some((filled_at, cell)) if now.duration_since(*filled_at) < self.ttl => {
                    cell.clone()
                }
                _ => {
                    let cell = Arc::new(OnceCell::new());
                    entries.insert(key, (now, cell.clone()));
                    cell
                }
            }
        };
        cell.get_or_init(|| async { Arc::new(fetch().await) })
            .await
            .clone()
    }
}

/// one shared binance websocket for every client. kline streams are subscribed
/// lazily and kept for the process lifetime; the set is bounded by the asset
/// and interval allowlists, which keeps upstream subscription churn at zero.
struct BinanceStreamHub {
    channels: std::sync::Mutex<HashMap<String, broadcast::Sender<Candle>>>,
    subscribe_requests: mpsc::UnboundedSender<String>,
}

impl BinanceStreamHub {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        let (subscribe_requests, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                channels: std::sync::Mutex::new(HashMap::new()),
                subscribe_requests,
            }),
            receiver,
        )
    }

    fn subscribe(&self, stream: &str) -> broadcast::Receiver<Candle> {
        let mut channels = self
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sender) = channels.get(stream) {
            return sender.subscribe();
        }
        let (sender, receiver) = broadcast::channel(64);
        channels.insert(stream.to_owned(), sender);
        let _ = self.subscribe_requests.send(stream.to_owned());
        receiver
    }

    fn stream_names(&self) -> Vec<String> {
        let channels = self
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        channels.keys().cloned().collect()
    }

    fn dispatch(&self, text: &str) {
        let Some((stream, candle)) = parse_stream_kline(text) else {
            return;
        };
        let channels = self
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sender) = channels.get(&stream) {
            let _ = sender.send(candle);
        }
    }
}

async fn run_binance_stream(
    hub: Arc<BinanceStreamHub>,
    mut subscribe_requests: mpsc::UnboundedReceiver<String>,
) {
    let mut origin_index = 0;
    let mut backoff = Duration::from_secs(1);
    let mut next_id = 1_u64;
    loop {
        let url = format!("{}/stream", BINANCE_STREAM_ORIGINS[origin_index]);
        if let Ok((mut socket, _)) = tokio_tungstenite::connect_async(url.as_str()).await {
            backoff = Duration::from_secs(1);
            // drain queued requests: the full current set is resubscribed below.
            while subscribe_requests.try_recv().is_ok() {}
            let current = hub.stream_names();
            let resubscribed = current.is_empty()
                || socket
                    .send(Message::Text(subscribe_message(&current, next_id).into()))
                    .await
                    .is_ok();
            next_id += 1;
            if resubscribed {
                loop {
                    tokio::select! {
                        request = subscribe_requests.recv() => {
                            let Some(first) = request else { return };
                            let mut streams = vec![first];
                            while let Ok(more) = subscribe_requests.try_recv() {
                                streams.push(more);
                            }
                            next_id += 1;
                            if socket
                                .send(Message::Text(subscribe_message(&streams, next_id).into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        frame = socket.next() => match frame {
                            // pings are answered by tungstenite while reading.
                            Some(Ok(Message::Text(text))) => hub.dispatch(text.as_str()),
                            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                            Some(Ok(_)) => {}
                        },
                    }
                }
            }
        }
        origin_index = (origin_index + 1) % BINANCE_STREAM_ORIGINS.len();
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

struct Inner {
    fetch: Fetcher,
    pairs: BTreeSet<Pair>,
    summaries: Cache<Pair, MarketSummary>,
    candles: Cache<(Pair, &'static str), CandleHistory>,
    binance: Arc<BinanceStreamHub>,
    active_streams: AtomicUsize,
    active_streams_by_client: Mutex<HashMap<IpAddr, usize>>,
    max_streams: usize,
    max_streams_per_client: usize,
    max_stream_lifetime: Duration,
    trusted_proxies: Vec<ipnet::IpNet>,
}

#[derive(Clone)]
struct AppState(Arc<Inner>);

impl AppState {
    fn new(
        fetch: Fetcher,
        pairs: BTreeSet<Pair>,
        max_streams: usize,
        max_streams_per_client: usize,
        max_stream_lifetime: Duration,
        trusted_proxies: Vec<ipnet::IpNet>,
        binance: Arc<BinanceStreamHub>,
    ) -> Self {
        Self(Arc::new(Inner {
            fetch,
            pairs,
            summaries: Cache::new(SUMMARY_TTL),
            candles: Cache::new(CANDLES_TTL),
            binance,
            active_streams: AtomicUsize::new(0),
            active_streams_by_client: Mutex::new(HashMap::new()),
            max_streams,
            max_streams_per_client,
            max_stream_lifetime,
            trusted_proxies,
        }))
    }

    fn pair(&self, base: &str, quote: &str) -> Result<Pair, StatusCode> {
        let pair = Pair {
            base: normalize_asset(base),
            quote: normalize_asset(quote),
        };
        (valid_asset_symbol(&pair.base)
            && valid_asset_symbol(&pair.quote)
            && self.0.pairs.contains(&pair))
        .then_some(pair)
        .ok_or(StatusCode::NOT_FOUND)
    }

    async fn json(&self, url: String) -> Option<Value> {
        (self.0.fetch)(url).await
    }

    async fn binance_json(&self, path: &str) -> Option<Value> {
        for origin in BINANCE_REST_ORIGINS {
            if let Some(value) = self.json(format!("{origin}{path}")).await {
                return Some(value);
            }
        }
        None
    }

    async fn binance_book(&self, symbol: &str) -> Option<Book> {
        parse_binance_book(
            &self
                .binance_json(&format!("/api/v3/ticker/bookTicker?symbol={symbol}"))
                .await?,
        )
    }

    async fn binance_ticker(&self, symbol: &str) -> Option<Ticker> {
        parse_binance_ticker(
            &self
                .binance_json(&format!("/api/v3/ticker/24hr?symbol={symbol}"))
                .await?,
        )
    }

    async fn binance_quote_and_stats(&self, pair: &Pair) -> (Option<Book>, Option<MarketStats>) {
        match binance_market(pair) {
            BinanceMarket::Direct(symbol) => {
                let (book, ticker) =
                    tokio::join!(self.binance_book(&symbol), self.binance_ticker(&symbol));
                (book, ticker.map(|ticker| combine_tickers(ticker, None)))
            }
            BinanceMarket::Ratio { base, quote } => {
                let (base_book, quote_book, base_ticker, quote_ticker) = tokio::join!(
                    self.binance_book(&base),
                    self.binance_book(&quote),
                    self.binance_ticker(&base),
                    self.binance_ticker(&quote),
                );
                let book = base_book
                    .zip(quote_book)
                    .and_then(|(base, quote)| ratio_book(base, quote));
                let stats = base_ticker
                    .zip(quote_ticker)
                    .map(|(base, quote)| combine_tickers(base, Some(quote)));
                (book, stats)
            }
        }
    }

    async fn venue_book(&self, venue: Venue, symbol: &str) -> Option<Book> {
        match venue {
            Venue::Coinbase => {
                let value = self
                    .json(format!("{COINBASE_ORIGIN}/products/{symbol}/ticker"))
                    .await?;
                valid_book(number(&value["bid"]), number(&value["ask"]))
            }
            Venue::Kraken => {
                let value = self
                    .json(format!("{KRAKEN_ORIGIN}/0/public/Ticker?pair={symbol}"))
                    .await?;
                let ticker = value["result"].as_object()?.values().next()?;
                valid_book(number(&ticker["b"][0]), number(&ticker["a"][0]))
            }
            Venue::Okx => {
                for origin in OKX_ORIGINS {
                    let Some(value) = self
                        .json(format!("{origin}/api/v5/market/books?instId={symbol}&sz=1"))
                        .await
                    else {
                        continue;
                    };
                    let book = &value["data"][0];
                    if let Some(book) =
                        valid_book(number(&book["bids"][0][0]), number(&book["asks"][0][0]))
                    {
                        return Some(book);
                    }
                }
                None
            }
        }
    }

    /// direct market first, else a cross through the venue's bridge asset using
    /// only that venue's own books.
    async fn synthetic_book(&self, venue: Venue, base: &str, quote: &str) -> Option<Book> {
        let separator = venue.separator();
        let bridge = venue.bridge();
        if let Some(direct) = self
            .venue_book(venue, &format!("{base}{separator}{quote}"))
            .await
        {
            return Some(direct);
        }
        let base_symbol = format!("{base}{separator}{bridge}");
        let quote_symbol = format!("{quote}{separator}{bridge}");
        let (base_leg, quote_leg) = tokio::join!(self.venue_book(venue, &base_symbol), async {
            if quote == bridge {
                Some(Book { bid: 1.0, ask: 1.0 })
            } else {
                self.venue_book(venue, &quote_symbol).await
            }
        });
        ratio_book(base_leg?, quote_leg?)
    }

    async fn venue_quote(&self, venue: Venue, pair: &Pair) -> Option<Book> {
        let symbol = |asset: &str| venue.symbol(asset);
        let (base, quote) = (symbol(&pair.base), symbol(&pair.quote));
        if venue == Venue::Coinbase {
            if let Some(direct) = self.venue_book(venue, &format!("{base}-{quote}")).await {
                return Some(direct);
            }
            if quote == "USDC" {
                return self.venue_book(venue, &format!("{base}-USD")).await;
            }
        }
        self.synthetic_book(venue, &base, &quote).await
    }

    async fn fetch_summary(&self, pair: &Pair) -> MarketSummary {
        let observed_at = now_unix_ms();
        let quote = |venue: &'static str, book: Option<Book>| {
            book.map(|book| VenueQuote {
                venue,
                bid: book.bid,
                ask: book.ask,
                observed_at_unix_ms: Some(observed_at),
            })
        };
        let ((binance, stats), coinbase, kraken, okx) = tokio::join!(
            self.binance_quote_and_stats(pair),
            self.venue_quote(Venue::Coinbase, pair),
            self.venue_quote(Venue::Kraken, pair),
            self.venue_quote(Venue::Okx, pair),
        );
        MarketSummary {
            bbos: [
                quote("Binance", binance),
                quote("Coinbase", coinbase),
                quote("Kraken", kraken),
                quote("OKX", okx),
            ]
            .into_iter()
            .flatten()
            .collect(),
            stats,
        }
    }

    async fn summary(&self, pair: &Pair) -> Arc<MarketSummary> {
        self.0
            .summaries
            .get_or_fetch(pair.clone(), || self.fetch_summary(pair))
            .await
    }

    async fn fetch_candles(&self, pair: &Pair, interval: &str) -> CandleHistory {
        let klines = |symbol: String| async move {
            self.binance_json(&format!(
                "/api/v3/klines?symbol={symbol}&interval={interval}&limit={MAX_CANDLES}"
            ))
            .await
            .map(|value| parse_klines(&value))
        };
        let candles = match binance_market(pair) {
            BinanceMarket::Direct(symbol) => klines(symbol).await.unwrap_or_default(),
            BinanceMarket::Ratio { base, quote } => {
                let (base, quote) = tokio::join!(klines(base), klines(quote));
                match (base, quote) {
                    (Some(base), Some(quote)) => combine_klines(base, Some(quote)),
                    _ => Vec::new(),
                }
            }
        };
        let skip = candles.len().saturating_sub(MAX_CANDLES);
        CandleHistory {
            candles: candles.into_iter().skip(skip).collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Venue {
    Coinbase,
    Kraken,
    Okx,
}

impl Venue {
    fn separator(self) -> &'static str {
        match self {
            Venue::Kraken => "",
            Venue::Coinbase | Venue::Okx => "-",
        }
    }

    fn bridge(self) -> &'static str {
        match self {
            Venue::Okx => "USDT",
            Venue::Coinbase | Venue::Kraken => "USD",
        }
    }

    fn symbol(self, asset: &str) -> String {
        asset.into()
    }
}

fn chart_interval(raw: &str) -> Result<&'static str, StatusCode> {
    CHART_INTERVALS
        .iter()
        .copied()
        .find(|interval| *interval == raw)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn health() -> Json<Value> {
    Json(serde_json::json!({ "service": "zylith-market-data", "ok": true }))
}

async fn candle_history(
    State(state): State<AppState>,
    Path((base, quote, interval)): Path<(String, String, String)>,
) -> Result<Response, StatusCode> {
    let pair = state.pair(&base, &quote)?;
    let interval = chart_interval(&interval)?;
    let history = state
        .0
        .candles
        .get_or_fetch((pair.clone(), interval), || {
            state.fetch_candles(&pair, interval)
        })
        .await;
    // generic public data: identical for every viewer, safe for shared caches.
    Ok((
        [(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=10"),
        )],
        Json(&*history),
    )
        .into_response())
}

/// releases global and per-client stream capacity when fan-out ends.
struct StreamSlot {
    state: AppState,
    client_ip: IpAddr,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let inner = &self.state.0;
        inner.active_streams.fetch_sub(1, Ordering::Relaxed);
        let mut clients = inner
            .active_streams_by_client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(active) = clients.get_mut(&self.client_ip) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                clients.remove(&self.client_ip);
            }
        }
    }
}

impl AppState {
    fn acquire_stream_slot(&self, client_ip: IpAddr) -> Result<StreamSlot, StatusCode> {
        let inner = &self.0;
        let mut clients = inner
            .active_streams_by_client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let active_for_client = clients.entry(client_ip).or_default();
        if *active_for_client >= inner.max_streams_per_client {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        if inner.active_streams.fetch_add(1, Ordering::Relaxed) >= inner.max_streams {
            inner.active_streams.fetch_sub(1, Ordering::Relaxed);
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        *active_for_client += 1;
        Ok(StreamSlot {
            state: self.clone(),
            client_ip,
        })
    }
}

async fn market_stream(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((base, quote, interval)): Path<(String, String, String)>,
) -> Result<Response, StatusCode> {
    let pair = state.pair(&base, &quote)?;
    let interval = chart_interval(&interval)?;
    let client_ip = trusted_proxy_client_ip(&state, peer.ip(), &headers);
    let slot = state.acquire_stream_slot(client_ip)?;
    let max_stream_lifetime = state.0.max_stream_lifetime;
    let (events, receiver) = mpsc::channel::<Event>(32);
    tokio::spawn(async move {
        let _slot = slot;
        tokio::select! {
            _ = fan_out_market_stream(state, pair, interval, events) => {}
            _ = tokio::time::sleep(max_stream_lifetime) => {}
        }
    });
    let stream = stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|event| (Ok::<_, Infallible>(event), receiver))
    });
    Ok((
        [
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            // proxies must pass events through immediately.
            (
                HeaderName::from_static("x-accel-buffering"),
                HeaderValue::from_static("no"),
            ),
        ],
        Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))),
    )
        .into_response())
}

fn trusted_proxy_client_ip(state: &AppState, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    zylith_core::forwarded_client_ip(peer, forwarded, |address| {
        state
            .0
            .trusted_proxies
            .iter()
            .any(|network| network.contains(&address))
    })
}

async fn recv_optional(
    receiver: &mut Option<broadcast::Receiver<Candle>>,
) -> Result<Candle, broadcast::error::RecvError> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// per-client task: pushes the shared cached summary on a fixed cadence and
/// live candles from the shared upstream socket. ends when the client leaves.
async fn fan_out_market_stream(
    state: AppState,
    pair: Pair,
    interval: &'static str,
    events: mpsc::Sender<Event>,
) {
    let hub = state.0.binance.clone();
    let (mut base_updates, mut quote_updates) = match binance_market(&pair) {
        BinanceMarket::Direct(symbol) => {
            (hub.subscribe(&kline_stream_name(&symbol, interval)), None)
        }
        BinanceMarket::Ratio { base, quote } => (
            hub.subscribe(&kline_stream_name(&base, interval)),
            Some(hub.subscribe(&kline_stream_name(&quote, interval))),
        ),
    };
    let ratio = quote_updates.is_some();
    let mut latest_base: Option<Candle> = None;
    let mut latest_quote: Option<Candle> = None;
    let mut summary_tick = tokio::time::interval(SUMMARY_PUSH_INTERVAL);
    summary_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let candle = tokio::select! {
            _ = events.closed() => return,
            _ = summary_tick.tick() => {
                let summary = state.summary(&pair).await;
                let Ok(event) = Event::default().event("summary").json_data(&*summary) else { continue };
                if events.send(event).await.is_err() {
                    return;
                }
                continue;
            }
            update = base_updates.recv() => match update {
                Ok(candle) => {
                    latest_base = Some(candle);
                    if ratio {
                        latest_quote.and_then(|quote| combine_candles(candle, Some(quote)))
                    } else {
                        Some(candle)
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            },
            update = recv_optional(&mut quote_updates) => match update {
                Ok(candle) => {
                    latest_quote = Some(candle);
                    latest_base.and_then(|base| combine_candles(base, Some(candle)))
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            },
        };
        let Some(candle) = candle else { continue };
        let Ok(event) = Event::default().event("candle").json_data(candle) else {
            continue;
        };
        if events.send(event).await.is_err() {
            return;
        }
    }
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/market-data/health", get(health))
        .route(
            "/market-data/v1/{base}/{quote}/candles/{interval}",
            get(candle_history),
        )
        .route(
            "/market-data/v1/{base}/{quote}/stream/{interval}",
            get(market_stream),
        )
        .with_state(state)
}

fn http_fetcher() -> Fetcher {
    // some venues (coinbase) reject requests without a user agent.
    let client = reqwest::Client::builder()
        .user_agent("zylith-market-data")
        .timeout(UPSTREAM_TIMEOUT)
        .build()
        .expect("market data http client");
    Arc::new(move |url: String| {
        let client = client.clone();
        Box::pin(async move {
            let response = client.get(url).send().await.ok()?;
            if !response.status().is_success()
                || response
                    .content_length()
                    .is_some_and(|length| length > MAX_UPSTREAM_BODY_BYTES as u64)
            {
                return None;
            }
            let body = response.bytes().await.ok()?;
            if body.len() > MAX_UPSTREAM_BODY_BYTES {
                return None;
            }
            serde_json::from_slice(&body).ok()
        }) as UpstreamFuture
    })
}

fn valid_asset_symbol(asset: &str) -> bool {
    !asset.is_empty()
        && asset.len() <= MAX_ASSET_SYMBOL_LEN
        && asset
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

fn configured_pairs(raw: &str) -> Result<BTreeSet<Pair>, String> {
    let mut pairs = BTreeSet::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some((base, quote)) = entry.split_once('/') else {
            return Err(format!("{PAIRS_ENV} entry {entry} must be BASE/QUOTE"));
        };
        if quote.contains('/') {
            return Err(format!("{PAIRS_ENV} entry {entry} must be BASE/QUOTE"));
        }
        let pair = Pair {
            base: normalize_asset(base),
            quote: normalize_asset(quote),
        };
        if !valid_asset_symbol(&pair.base)
            || !valid_asset_symbol(&pair.quote)
            || pair.base == pair.quote
        {
            return Err(format!("{PAIRS_ENV} contains invalid pair {entry}"));
        }
        pairs.insert(pair);
    }
    if pairs.is_empty() {
        return Err(format!("{PAIRS_ENV} must list at least one pair"));
    }
    Ok(pairs)
}

fn manifest_pairs(raw: &str) -> Result<BTreeSet<Pair>, String> {
    let value: Value =
        serde_json::from_str(raw).map_err(|error| format!("deployment manifest: {error}"))?;
    let manifest = value.get("manifest").unwrap_or(&value);
    let pairs = manifest
        .pointer("/product/pairs")
        .and_then(Value::as_object)
        .ok_or("deployment manifest has no product pairs")?;
    let names = pairs
        .values()
        .filter(|pair| pair.get("enabled").and_then(Value::as_bool) == Some(true))
        .map(|pair| {
            let base = pair
                .get("base_asset_id")
                .and_then(Value::as_str)
                .ok_or("enabled manifest pair has no base asset")?;
            let quote = pair
                .get("quote_asset_id")
                .and_then(Value::as_str)
                .ok_or("enabled manifest pair has no quote asset")?;
            Ok(format!("{base}/{quote}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    configured_pairs(&names.join(","))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let bind_addr = std::env::var(BIND_ADDR_ENV)
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.into())
        .parse::<SocketAddr>()
        .map_err(|error| format!("{BIND_ADDR_ENV} is invalid: {error}"))?;
    let manifest_path =
        std::env::var(MANIFEST_ENV).map_err(|_| format!("{MANIFEST_ENV} is required"))?;
    let pairs = manifest_pairs(
        &std::fs::read_to_string(&manifest_path)
            .map_err(|error| format!("deployment manifest {manifest_path}: {error}"))?,
    )?;
    if let Ok(configured) = std::env::var(PAIRS_ENV)
        && configured_pairs(&configured)? != pairs
    {
        return Err(format!(
            "{PAIRS_ENV} differs from the enabled deployment manifest pairs"
        ));
    }
    let max_streams = match std::env::var(MAX_STREAMS_ENV) {
        Ok(raw) => raw
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("{MAX_STREAMS_ENV} must be a positive integer"))?,
        Err(_) => DEFAULT_MAX_STREAMS,
    };
    let max_streams_per_client = match std::env::var(MAX_STREAMS_PER_CLIENT_ENV) {
        Ok(raw) => raw
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|value| *value > 0 && *value <= max_streams)
            .ok_or_else(|| {
                format!(
                    "{MAX_STREAMS_PER_CLIENT_ENV} must be a positive integer no larger than {MAX_STREAMS_ENV}"
                )
            })?,
        Err(_) => DEFAULT_MAX_STREAMS_PER_CLIENT.min(max_streams),
    };
    let max_stream_lifetime = match std::env::var(MAX_STREAM_LIFETIME_SECONDS_ENV) {
        Ok(raw) => Duration::from_secs(
            raw.trim()
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    format!("{MAX_STREAM_LIFETIME_SECONDS_ENV} must be a positive integer")
                })?,
        ),
        Err(_) => DEFAULT_MAX_STREAM_LIFETIME,
    };
    let trusted_proxies = std::env::var(TRUSTED_PROXY_CIDRS_ENV)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse::<ipnet::IpNet>().map_err(|error| {
                format!("invalid {TRUSTED_PROXY_CIDRS_ENV} entry {value}: {error}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (hub, subscribe_requests) = BinanceStreamHub::new();
    tokio::spawn(run_binance_stream(hub.clone(), subscribe_requests));
    let state = AppState::new(
        http_fetcher(),
        pairs,
        max_streams,
        max_streams_per_client,
        max_stream_lifetime,
        trusted_proxies,
        hub,
    );
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|error| format!("bind {bind_addr}: {error}"))?;
    println!("zylith market data listening on http://{bind_addr}");
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("serve: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use std::sync::atomic::AtomicUsize;
    use tower::ServiceExt;

    fn fake_fetcher(responses: Vec<(&'static str, Value)>, calls: Arc<AtomicUsize>) -> Fetcher {
        let responses = Arc::new(responses);
        Arc::new(move |url: String| {
            let responses = responses.clone();
            let calls = calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                responses
                    .iter()
                    .find(|(needle, _)| url.contains(needle))
                    .map(|(_, value)| value.clone())
            }) as UpstreamFuture
        })
    }

    fn state_with(responses: Vec<(&'static str, Value)>) -> (AppState, Arc<AtomicUsize>) {
        state_with_pairs(responses, DEFAULT_PAIRS)
    }

    fn state_with_pairs(
        responses: Vec<(&'static str, Value)>,
        pairs: &str,
    ) -> (AppState, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let (hub, _requests) = BinanceStreamHub::new();
        let state = AppState::new(
            fake_fetcher(responses, calls.clone()),
            configured_pairs(pairs).expect("pairs"),
            2,
            1,
            DEFAULT_MAX_STREAM_LIFETIME,
            vec!["127.0.0.1/32".parse().unwrap()],
            hub,
        );
        (state, calls)
    }

    #[test]
    fn pairs_are_normalized_and_allowlisted() {
        let (state, _) = state_with(vec![]);
        assert_eq!(
            state.pair("eth", "usdc"),
            Ok(Pair {
                base: "ETH".into(),
                quote: "USDC".into()
            })
        );
        assert_eq!(state.pair("STRK", "ETH"), Err(StatusCode::NOT_FOUND));
        // the derivative token is its own asset and is not traded.
        assert_eq!(state.pair("strkBTC", "USDC"), Err(StatusCode::NOT_FOUND));
        assert_eq!(state.pair("BTC", "USDC"), Err(StatusCode::NOT_FOUND));
        assert_eq!(state.pair("STRK", "USDT"), Err(StatusCode::NOT_FOUND));
        assert_eq!(state.pair("USDC", "STRK"), Err(StatusCode::NOT_FOUND));
        assert_eq!(state.pair("DOGE", "USDC"), Err(StatusCode::NOT_FOUND));
        assert_eq!(state.pair("STRK", "STRK"), Err(StatusCode::NOT_FOUND));
        assert_eq!(state.pair("STRK/../x", "USDC"), Err(StatusCode::NOT_FOUND));
        assert_eq!(chart_interval("1M"), Ok("1M"));
        assert_eq!(chart_interval("2m"), Err(StatusCode::NOT_FOUND));
        assert!(configured_pairs("STRK/USDC,STRK/??").is_err());
    }

    #[test]
    fn enabled_market_data_pairs_come_from_the_deployment_manifest() {
        let pairs = manifest_pairs(
            r#"{"product":{"pairs":{"a":{"base_asset_id":"STRK","quote_asset_id":"USDC","enabled":true},"b":{"base_asset_id":"ETH","quote_asset_id":"USDC","enabled":false}}}}"#,
        )
        .unwrap();
        assert_eq!(pairs, configured_pairs("STRK/USDC").unwrap());
        assert!(manifest_pairs(r#"{"product":{"pairs":{}}}"#).is_err());
    }

    #[test]
    fn client_identity_only_accepts_headers_from_configured_proxies() {
        let (state, _) = state_with(vec![]);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.10"));
        assert_eq!(
            trusted_proxy_client_ip(&state, "127.0.0.1".parse().expect("ip"), &headers),
            "192.0.2.10".parse::<IpAddr>().expect("ip")
        );
        assert_eq!(
            trusted_proxy_client_ip(&state, "198.51.100.8".parse().expect("ip"), &headers,),
            "198.51.100.8".parse::<IpAddr>().expect("ip")
        );
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        assert_eq!(
            trusted_proxy_client_ip(&state, "127.0.0.1".parse().expect("ip"), &headers),
            "127.0.0.1".parse::<IpAddr>().expect("ip")
        );
    }

    #[test]
    fn binance_markets_use_the_pairs_own_book() {
        let pair = |base: &str, quote: &str| Pair {
            base: base.into(),
            quote: quote.into(),
        };
        assert_eq!(
            binance_market(&pair("STRK", "USDT")),
            BinanceMarket::Direct("STRKUSDT".into())
        );
        assert_eq!(
            binance_market(&pair("STRK", "USDC")),
            BinanceMarket::Direct("STRKUSDC".into())
        );
        assert_eq!(
            binance_market(&pair("STRK", "ETH")),
            BinanceMarket::Ratio {
                base: "STRKUSDC".into(),
                quote: "ETHUSDC".into()
            }
        );
    }

    #[test]
    fn ratio_math_matches_the_former_client_logic() {
        let base = Ticker {
            last: 2.0,
            previous_close: 1.0,
            high: 3.0,
            low: 1.5,
            quote_volume: 10.0,
        };
        let quote = Ticker {
            last: 1.0,
            previous_close: 1.0,
            high: 1.0,
            low: 0.5,
            quote_volume: 5.0,
        };
        let stats = combine_tickers(base, Some(quote));
        assert_eq!(stats.last, 2.0);
        assert_eq!(stats.change_percent, 100.0);
        assert_eq!(stats.high, 6.0);
        assert_eq!(stats.low, 1.5);
        assert_eq!(stats.quote_volume, 10.0);

        let candle = |time, value| Candle {
            time,
            open: value,
            high: value,
            low: value,
            close: value,
        };
        assert_eq!(
            combine_candles(candle(1, 2.0), Some(candle(1, 0.5))),
            Some(candle(1, 4.0))
        );
        assert_eq!(combine_candles(candle(1, 2.0), Some(candle(2, 0.5))), None);
        assert_eq!(
            combine_klines(
                vec![candle(1, 2.0), candle(2, 2.0)],
                Some(vec![candle(2, 1.0)])
            ),
            vec![candle(2, 2.0)]
        );
        assert!(parse_klines(&serde_json::json!([[1_000, "1", "0.5", "1", "1"]])).is_empty());
    }

    #[test]
    fn stream_frames_route_to_their_subscribers() {
        let (hub, mut requests) = BinanceStreamHub::new();
        let mut receiver = hub.subscribe("strkusdt@kline_15m");
        assert_eq!(
            requests.try_recv().ok().as_deref(),
            Some("strkusdt@kline_15m")
        );
        let _second = hub.subscribe("strkusdt@kline_15m");
        assert!(
            requests.try_recv().is_err(),
            "a stream is subscribed upstream once"
        );
        hub.dispatch(
            r#"{"stream":"strkusdt@kline_15m","data":{"s":"STRKUSDT","k":{"t":60000,"o":"1","h":"2","l":"0.5","c":"1.5"}}}"#,
        );
        assert_eq!(
            receiver.try_recv().expect("candle"),
            Candle {
                time: 60,
                open: 1.0,
                high: 2.0,
                low: 0.5,
                close: 1.5
            }
        );
        // key order follows serde_json's map feature, which workspace builds may unify.
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&subscribe_message(&["a".into()], 7))
                .expect("json"),
            serde_json::json!({ "id": 7, "method": "SUBSCRIBE", "params": ["a"] })
        );
    }

    #[tokio::test]
    async fn venue_quotes_cross_only_through_the_same_venue() {
        let (state, _) = state_with(vec![
            (
                "kraken.com/0/public/Ticker?pair=STRKUSDC",
                serde_json::json!({ "result": {} }),
            ),
            (
                "coinbase.com/products/STRK-USD/",
                serde_json::json!({ "bid": "0.0463", "ask": "0.0465" }),
            ),
            (
                "kraken.com/0/public/Ticker?pair=STRKUSD",
                serde_json::json!({ "result": { "STRKUSD": { "a": ["0.0464"], "b": ["0.0462"] } } }),
            ),
            (
                "kraken.com/0/public/Ticker?pair=USDCUSD",
                serde_json::json!({ "result": { "USDCUSD": { "a": ["1.0002"], "b": ["0.9998"] } } }),
            ),
            (
                "instId=STRK-USDT",
                serde_json::json!({ "data": [{ "bids": [["0.0463"]], "asks": [["0.0465"]] }] }),
            ),
            (
                "instId=USDC-USDT",
                serde_json::json!({ "data": [{ "bids": [["0.9999"]], "asks": [["1.0001"]] }] }),
            ),
        ]);
        let pair = state.pair("STRK", "USDC").expect("pair");
        let summary = state.fetch_summary(&pair).await;
        let venue = |name: &str| {
            summary
                .bbos
                .iter()
                .find(|quote| quote.venue == name)
                .expect("venue")
                .clone()
        };
        assert_eq!(
            (venue("Coinbase").bid, venue("Coinbase").ask),
            (0.0463, 0.0465)
        );
        assert_eq!(
            (venue("Kraken").bid, venue("Kraken").ask),
            (0.0462 / 1.0002, 0.0464 / 0.9998)
        );
        assert_eq!(
            (venue("OKX").bid, venue("OKX").ask),
            (0.0463 / 1.0001, 0.0465 / 0.9999)
        );
        assert!(
            summary.bbos.iter().all(|quote| quote.venue != "Binance"),
            "an unavailable venue must be omitted instead of emitted as a zero book"
        );
        assert!(summary.stats.is_none());
    }

    #[tokio::test]
    async fn concurrent_candle_requests_share_one_upstream_fetch() {
        let klines = serde_json::json!([[60_000, "1", "2", "0.5", "1.5"]]);
        let bridge = serde_json::json!([[60_000, "1", "1", "1", "1"]]);
        let (state, calls) = state_with_pairs(
            vec![
                ("symbol=STRKUSDC&interval=15m", klines),
                ("symbol=ETHUSDC&interval=15m", bridge),
            ],
            "STRK/ETH",
        );
        let router = app(state);
        let request = || {
            Request::builder()
                .uri("/market-data/v1/STRK/ETH/candles/15m")
                .body(Body::empty())
                .expect("request")
        };
        let (first, second) = tokio::join!(
            router.clone().oneshot(request()),
            router.clone().oneshot(request())
        );
        for response in [first.expect("first"), second.expect("second")] {
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let json = serde_json::from_slice::<Value>(&body).expect("json");
            assert_eq!(json["candles"][0]["close"], 1.5);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "one fetch per shared ratio leg"
        );
    }

    #[tokio::test]
    async fn unknown_markets_and_stream_overload_are_rejected() {
        let (state, calls) = state_with(vec![]);
        let router = app(state.clone());
        for uri in [
            "/market-data/v1/DOGE/USDC/candles/15m",
            "/market-data/v1/STRK/USDC/candles/2m",
            "/market-data/v1/DOGE/USDC/stream/15m",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "rejected requests never reach upstream"
        );
        let first_client = "192.0.2.1".parse().expect("ip");
        let second_client = "192.0.2.2".parse().expect("ip");
        let _first = state.acquire_stream_slot(first_client).expect("slot");
        assert!(state.acquire_stream_slot(first_client).is_err());
        let _second = state.acquire_stream_slot(second_client).expect("slot");
        assert!(state.acquire_stream_slot(second_client).is_err());
        drop(_first);
        assert!(state.acquire_stream_slot(first_client).is_ok());
    }

    #[tokio::test]
    async fn stream_capacity_is_reclaimed_after_the_maximum_lifetime() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (hub, _requests) = BinanceStreamHub::new();
        let state = AppState::new(
            fake_fetcher(vec![], calls),
            configured_pairs(DEFAULT_PAIRS).expect("pairs"),
            2,
            1,
            Duration::from_millis(1),
            Vec::new(),
            hub,
        );
        let client = SocketAddr::from(([192, 0, 2, 1], 12345));
        let response = market_stream(
            State(state.clone()),
            ConnectInfo(client),
            HeaderMap::new(),
            Path(("STRK".into(), "USDC".into(), "15m".into())),
        )
        .await
        .expect("stream");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.acquire_stream_slot(client.ip()).is_err());
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(state.acquire_stream_slot(client.ip()).is_ok());
    }
}

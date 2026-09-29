#!/usr/bin/env node
// probes every running service and checks the invariants an operator watches: each service
// answers, the indexer keeps up with the chain, and the operator's pipeline is not backed up.
import { readFileSync } from "node:fs";

const timeoutMs = Number(process.env.ZYLITH_MONITORING_DRILL_TIMEOUT_MS || 8_000);
const maxIndexerLagMs = Number(process.env.ZYLITH_MONITORING_MAX_INDEXER_LAG_MS || 60_000);
const maxIndexerSeqLag = Number(process.env.ZYLITH_MONITORING_MAX_INDEXER_SEQ_LAG || 1);
const maxInFlight = Number(process.env.ZYLITH_MONITORING_MAX_IN_FLIGHT || 3);
const maxProofPendingMs = Number(process.env.ZYLITH_MONITORING_MAX_PROOF_PENDING_MS || 120_000);
const controlToken = process.env.ZYLITH_CONTROL_PLANE_TOKEN || "";
const proofQueueMonitorToken = process.env.ZYLITH_PROOF_QUEUE_MONITOR_TOKEN || "";
const trim = (value) => value.replace(/\/+$/, "");
const failures = [];
const observations = [];
const manifestPath = process.env.ZYLITH_DEPLOYMENT_MANIFEST || "client/public/deployment.json";
let expectedRegistry = null;
try {
  const document = JSON.parse(readFileSync(manifestPath, "utf8"));
  const manifest = document.manifest ?? document;
  expectedRegistry = {
    registry_version: manifest.market_registry.registry_version,
    registry_hash: manifest.market_registry.registry_hash,
  };
} catch (error) {
  failures.push(`deployment manifest is unreadable: ${error instanceof Error ? error.message : "error"}`);
}
const requiredHealthUrl = (name) => {
  const value = trim(process.env[name] || "");
  if (!value) failures.push(`${name} is required`);
  return value;
};
const services = {
  operator: trim(process.env.ZYLITH_OPERATOR_URL || "http://127.0.0.1:3200"),
  attestor: trim(process.env.ZYLITH_REFERENCE_PRICE_ATTESTOR_URL || "http://127.0.0.1:8790"),
  indexer: trim(process.env.ZYLITH_INDEXER_URL || "http://127.0.0.1:3300"),
  backup: trim(process.env.ZYLITH_COORDINATOR_URL || "http://127.0.0.1:3000"),
  marketData: trim(process.env.ZYLITH_MARKET_DATA_URL || "http://127.0.0.1:3500"),
  paymasterHealth: requiredHealthUrl("ZYLITH_PAYMASTER_HEALTH_URL"),
  privacyDiscoveryHealth: requiredHealthUrl("ZYLITH_PRIVACY_DISCOVERY_HEALTH_URL"),
  privacyProverHealth: requiredHealthUrl("ZYLITH_PRIVACY_PROVER_HEALTH_URL"),
};
const proofQueueHealthUrl = requiredHealthUrl("ZYLITH_PROOF_QUEUE_HEALTH_URL");
const routeHealthUrl = trim(process.env.ZYLITH_ROUTE_SERVICE_HEALTH_URL || "");
if (process.env.ZYLITH_ROUTE_SERVICE_URL && !routeHealthUrl) failures.push("ZYLITH_ROUTE_SERVICE_HEALTH_URL is required when external routing is configured");

const exchange = await json("operator exchange", `${services.operator}/api/public/exchange`);
if (exchange) {
  checkRegistryIdentity("operator", exchange);
  if (!(exchange.epoch_ms > 0)) failures.push("operator reports no epoch length");
  if (!Array.isArray(exchange.pairs) || exchange.pairs.length === 0) failures.push("operator trades no pairs");
  if (exchange.in_flight > maxInFlight) failures.push(`operator has ${exchange.in_flight} transitions in flight (max ${maxInFlight})`);
  observations.push(`seq ${exchange.seq}, ${exchange.in_flight} in flight`);
  const referenceBatch = await json("reference-price batch", `${services.operator}/api/public/reference-prices`);
  if (referenceBatch) {
    const prices = Array.isArray(referenceBatch.prices) ? referenceBatch.prices : [];
    const expectedPairs = new Set(exchange.pairs ?? []);
    const actualPairs = new Set(prices.map((price) => price.pair));
    if (prices.length !== expectedPairs.size || actualPairs.size !== expectedPairs.size) {
      failures.push("reference-price batch does not contain exactly the enabled pairs");
    }
    for (const pair of expectedPairs) {
      const price = prices.find((candidate) => candidate.pair === pair);
      if (!price) failures.push(`reference-price batch omits ${pair}`);
      else if (!(BigInt(price.midpoint) > 0n)) failures.push(`reference price for ${pair} is zero`);
    }
  }
}
if (controlToken) {
  const status = await json("operator internal status", `${services.operator}/api/internal/status`, { authorization: `Bearer ${controlToken}` });
  if (status) observations.push(`${status.book_orders} resting, ${status.pending_orders} pending, ${status.withdrawals} withdrawals`);
}
const keys = await json("execution keys", `${services.operator}/api/public/execution-keys`);
if (keys && !(keys.keys?.length > 0)) failures.push("the operator publishes no execution keys");

const indexer = await json("indexer health", `${services.indexer}/health`);
if (indexer) {
  if (indexer.ready !== true || indexer.last_successful_sync_unix_ms === 0) failures.push("indexer has never completed a successful sync");
  if (indexer.sync_lag_ms > maxIndexerLagMs) failures.push(`indexer is ${indexer.sync_lag_ms} ms behind (max ${maxIndexerLagMs})`);
  if (exchange && indexer.latest_seq > exchange.seq) failures.push(`indexer seq ${indexer.latest_seq} is ahead of the operator's ${exchange.seq}`);
  if (exchange && exchange.seq - indexer.latest_seq > maxIndexerSeqLag) failures.push(`indexer seq ${indexer.latest_seq} trails the operator's ${exchange.seq} by more than ${maxIndexerSeqLag}`);
  observations.push(`indexer at seq ${indexer.latest_seq}, ${indexer.sync_lag_ms} ms lag`);
}

const attestor = await json("attestor health", `${services.attestor}/health`);
if (attestor) checkRegistryIdentity("attestor", attestor);
await text("backup service health", `${services.backup}/health`);
const marketData = await json("market data health", `${services.marketData}/market-data/health`);
if (marketData) checkRegistryIdentity("market data", marketData);
if (services.paymasterHealth) {
  const paymaster = await json("paymaster health", services.paymasterHealth);
  if (paymaster) checkRegistryIdentity("paymaster", paymaster);
}
if (services.privacyDiscoveryHealth) await text("privacy discovery health", services.privacyDiscoveryHealth);
if (services.privacyProverHealth) await text("privacy prover health", services.privacyProverHealth);
if (proofQueueHealthUrl) {
  const proofQueue = await json("proof queue health", proofQueueHealthUrl, { "x-zylith-proof-monitor-token": proofQueueMonitorToken });
  if (proofQueue) {
    if (proofQueue.pending_jobs > 0 && proofQueue.registered_workers === 0) failures.push("proof jobs are pending with no registered workers");
    if (proofQueue.oldest_pending_age_ms > maxProofPendingMs) failures.push(`oldest proof job has waited ${proofQueue.oldest_pending_age_ms} ms (max ${maxProofPendingMs})`);
    if (proofQueue.expired_active_jobs > 0) failures.push(`${proofQueue.expired_active_jobs} proof-job leases expired without being reclaimed`);
    observations.push(`${proofQueue.pending_jobs} proof jobs pending, ${proofQueue.active_jobs} active, ${proofQueue.registered_workers} workers`);
  }
}
if (routeHealthUrl) await text("external route service health", routeHealthUrl);

for (const observation of observations) console.log(`observed: ${observation}`);
if (failures.length > 0) {
  console.error("monitoring drill failed");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log("monitoring drill passed");

function checkRegistryIdentity(label, value) {
  if (!expectedRegistry) return;
  if (
    value.registry_version !== expectedRegistry.registry_version ||
    value.registry_hash !== expectedRegistry.registry_hash
  ) {
    failures.push(`${label} market registry identity differs from the deployment manifest`);
  }
}

async function json(label, url, headers = {}) {
  const body = await text(label, url, headers);
  if (body === null) return null;
  try {
    return JSON.parse(body);
  } catch {
    failures.push(`${label} returned invalid json`);
    return null;
  }
}

async function text(label, url, headers = {}) {
  try {
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) {
      failures.push(`${label} returned http ${response.status}`);
      return null;
    }
    return await response.text();
  } catch (error) {
    failures.push(`${label} is unreachable: ${error instanceof Error ? error.name : "error"}`);
    return null;
  }
}

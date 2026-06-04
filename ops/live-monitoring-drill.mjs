#!/usr/bin/env node

const args = new Set(process.argv.slice(2));
const activeRelayTick = args.has("--active-relay-tick");
const timeoutMs = Number(process.env.ZYLITH_MONITORING_DRILL_TIMEOUT_MS || 8_000);
const failures = [];
const warnings = [];
const observations = [];

const services = {
  coordinator: trimUrl(process.env.ZYLITH_COORDINATOR_URL || "http://127.0.0.1:3000"),
  prover: trimUrl(process.env.ZYLITH_PROVER_URL || "http://127.0.0.1:3200"),
  indexer: trimUrl(process.env.ZYLITH_INDEXER_URL || "http://127.0.0.1:3300"),
  paymaster: trimUrl(process.env.ZYLITH_PAYMASTER_URL || "http://127.0.0.1:8787"),
  relayer: trimUrl(process.env.ZYLITH_RENEWAL_RELAY_URL || "http://127.0.0.1:3400"),
};
const controlToken = process.env.ZYLITH_CONTROL_PLANE_TOKEN || "";
const relayerToken =
  process.env.ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN ||
  process.env.ZYLITH_RENEWAL_RELAY_COORDINATOR_CONTROL_TOKEN ||
  process.env.ZYLITH_CONTROL_PLANE_TOKEN ||
  "";

await checkJson("coordinator health", `${services.coordinator}/health`, (body) => {
  expectEqual(body.service, "zylith-coordinator", "coordinator service label");
  expectPositive(body.batch_window_ms, "coordinator batch window");
});

await checkJson("prover health", `${services.prover}/health`, (body) => {
  expectEqual(body.service, "zylith-prover", "prover service label");
});

await checkJson("prover internal health", `${services.prover}/api/internal/health`, (body) => {
  expectTrue(body.native_tx_prover_enabled, "native transaction prover must be enabled");
  expectTrue(body.prover_worker_enabled, "prover worker must be enabled");
  expectTrue(body.starknet_executor_enabled, "Starknet executor must be enabled");
}, bearerOptions(controlToken));

await checkJson("indexer health", `${services.indexer}/health`, (body) => {
  expectDefined(body, "indexer health body");
});

await checkJson("paymaster health", `${services.paymaster}/health`, (body) => {
  expectDefined(body, "paymaster health body");
});

await checkJson("renewal relayer health", `${services.relayer}/health`, (body) => {
  expectEqual(body.status, "ok", "renewal relayer health status");
});

await checkJson("renewal relayer ops summary", `${services.relayer}/ops/summary`, (body) => {
  expectTrue(body.strict_mode, "renewal relayer strict mode");
  expectTrue(body.worker_enabled, "renewal relayer worker");
  expectTrue(body.store_ok, "renewal relayer durable store");
  expectTrue(body.ready, "renewal relayer readiness");
  const maxPackageSlots = Number(process.env.ZYLITH_RENEWAL_RELAY_MAX_PACKAGE_SLOTS || 0);
  expectAtLeast(maxPackageSlots, 86_400, "renewal relayer max package slots");
  observations.push(`renewal relayer packages=${body.package_count}`);
}, bearerOptions(relayerToken));

await checkJson("renewal relayer readiness", `${services.relayer}/ready`, (body) => {
  expectEqual(body.status, "ready", "renewal relayer readiness");
});

await checkText("renewal relayer metrics", `${services.relayer}/metrics`, (body) => {
  const metrics = parsePrometheusMetrics(body);
  for (const metric of [
    "zylith_renewal_relay_packages",
    "zylith_renewal_relay_slots",
    "zylith_renewal_relay_submitted_slots",
    "zylith_renewal_relay_missed_slots",
    "zylith_renewal_relay_failed_slots",
  ]) {
    if (!metrics.has(metric)) failures.push(`renewal relayer metric ${metric} is missing`);
  }
  const missed = metrics.get("zylith_renewal_relay_missed_slots") ?? 0;
  const failed = metrics.get("zylith_renewal_relay_failed_slots") ?? 0;
  if (missed > 0) warnings.push(`renewal relayer has ${missed} missed slots`);
  if (failed > 0) warnings.push(`renewal relayer has ${failed} failed slots`);
}, bearerOptions(relayerToken));

if (activeRelayTick) {
  const token = process.env.ZYLITH_RENEWAL_RELAY_COORDINATOR_CONTROL_TOKEN || process.env.ZYLITH_CONTROL_PLANE_TOKEN;
  if (!token) {
    failures.push("active relay tick requested but no control-plane token is configured");
  } else {
    await checkJson(
      "renewal relayer active tick",
      `${services.relayer}/api/internal/relay/tick`,
      (body) => {
        if (!Array.isArray(body)) failures.push("active relay tick did not return a result array");
        observations.push(`active relay tick emitted ${Array.isArray(body) ? body.length : 0} results`);
      },
      {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
      },
    );
  }
}

for (const observation of observations) console.log(observation);

if (warnings.length > 0) {
  console.error("monitoring drill warnings");
  for (const warning of warnings) console.error(`- ${warning}`);
}

if (failures.length > 0) {
  console.error("monitoring drill failed");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("monitoring drill passed");

async function checkJson(label, url, validate, options = {}) {
  await check(label, url, async (response) => {
    const body = await response.json();
    validate(body);
  }, options);
}

async function checkText(label, url, validate, options = {}) {
  await check(label, url, async (response) => {
    validate(await response.text());
  }, options);
}

async function check(label, url, validate, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: options.method || "GET",
      headers: { accept: "application/json", ...(options.headers || {}) },
      signal: controller.signal,
    });
    if (!response.ok) {
      failures.push(`${label} returned HTTP ${response.status}`);
      return;
    }
    await validate(response);
  } catch (error) {
    failures.push(`${label} request failed: ${error.message}`);
  } finally {
    clearTimeout(timer);
  }
}

function parsePrometheusMetrics(body) {
  const metrics = new Map();
  for (const line of body.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const [name, value] = trimmed.split(/\s+/, 2);
    const parsed = Number(value);
    if (name && Number.isFinite(parsed)) metrics.set(name, parsed);
  }
  return metrics;
}

function expectDefined(value, label) {
  if (value === null || value === undefined) failures.push(`${label} is missing`);
}

function expectTrue(value, label) {
  if (value !== true) failures.push(`${label} must be true`);
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) failures.push(`${label} expected ${expected}, got ${actual}`);
}

function expectPositive(value, label) {
  if (!Number.isFinite(Number(value)) || Number(value) <= 0) failures.push(`${label} must be positive`);
}

function expectAtLeast(value, minimum, label) {
  if (!Number.isFinite(Number(value)) || Number(value) < minimum) failures.push(`${label} must be at least ${minimum}`);
}

function trimUrl(value) {
  return value.replace(/\/+$/, "");
}

function bearerOptions(token) {
  if (!token) return {};
  return { headers: { authorization: `Bearer ${token}` } };
}

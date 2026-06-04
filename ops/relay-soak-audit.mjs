#!/usr/bin/env node
import { readFileSync } from "node:fs";

const args = parseArgs(process.argv.slice(2));
const logPath = args.log || process.env.ZYLITH_RELAY_SOAK_LOG;
const expectedSamples = parsePositiveInt(args.samples || process.env.ZYLITH_RELAY_SOAK_EXPECTED_SAMPLES || "960", "expected samples");
const minHours = parsePositiveNumber(args.hours || process.env.ZYLITH_RELAY_SOAK_MIN_HOURS || "24", "minimum hours");

if (!logPath) {
  console.error("relay soak audit failed");
  console.error("- provide --log <path> or ZYLITH_RELAY_SOAK_LOG");
  process.exit(1);
}

let body;
try {
  body = readFileSync(logPath, "utf8");
} catch (error) {
  console.error("relay soak audit failed");
  console.error(`- cannot read ${logPath}: ${error.message}`);
  process.exit(1);
}

const samples = parseSamples(body);
const failures = [];
const warnings = [];

if (samples.length < expectedSamples) {
  failures.push(`expected at least ${expectedSamples} samples, found ${samples.length}`);
}

if (samples.length > 0) {
  const first = samples[0];
  const last = samples[samples.length - 1];
  const elapsedHours = (last.timestampMs - first.timestampMs) / 3_600_000;
  if (elapsedHours < minHours) {
    failures.push(`expected at least ${minHours}h elapsed, found ${elapsedHours.toFixed(2)}h`);
  }
  if (last.failedSlots > first.failedSlots) {
    failures.push(`failed slots increased from ${first.failedSlots} to ${last.failedSlots}`);
  }
  if (last.missedSlots > first.missedSlots) {
    failures.push(`missed slots increased from ${first.missedSlots} to ${last.missedSlots}`);
  }
}

for (const sample of samples) {
  if (!sample.active) failures.push(`sample ${sample.index} relayer service was not active`);
  if (sample.health?.status !== "ok") failures.push(`sample ${sample.index} health status is not ok`);
  if (sample.health?.strict_mode !== true) failures.push(`sample ${sample.index} strict mode is not enabled`);
  if (sample.health?.worker_enabled !== true) failures.push(`sample ${sample.index} worker is not enabled`);
  if (sample.health?.max_package_slots < 86_400) {
    failures.push(`sample ${sample.index} max package slots below 90d window: ${sample.health?.max_package_slots}`);
  }
  if (sample.ready?.status !== "ready") failures.push(`sample ${sample.index} readiness status is not ready`);
  if (sample.ready?.store_ok !== true) failures.push(`sample ${sample.index} durable store is not ok`);
  if (sample.ready?.coordinator_pinned !== true) failures.push(`sample ${sample.index} coordinator pin is not set`);
  if (sample.ready?.prover_pinned !== true) failures.push(`sample ${sample.index} prover pin is not set`);
}

if (samples.length > 0) {
  const last = samples[samples.length - 1];
  if (last.missedSlots > 0) warnings.push(`latest missed slots is ${last.missedSlots}; accepted only if historical and non-increasing`);
}

if (failures.length > 0) {
  console.error("relay soak audit failed");
  for (const failure of failures) console.error(`- ${failure}`);
  if (warnings.length > 0) {
    console.error("warnings");
    for (const warning of warnings) console.error(`- ${warning}`);
  }
  process.exit(1);
}

if (warnings.length > 0) {
  console.error("relay soak audit warnings");
  for (const warning of warnings) console.error(`- ${warning}`);
}

const first = samples[0];
const last = samples[samples.length - 1];
const elapsedHours = first && last ? (last.timestampMs - first.timestampMs) / 3_600_000 : 0;
console.log(`relay soak audit passed samples=${samples.length} elapsed_hours=${elapsedHours.toFixed(2)} failed_slots=${last?.failedSlots ?? 0} missed_slots=${last?.missedSlots ?? 0}`);

function parseSamples(input) {
  const chunks = input.split(/^---$/m);
  const parsed = [];
  for (const chunk of chunks) {
    const header = chunk.match(/sample=(\d+)\s+time=([^\s]+)/);
    if (!header) continue;
    const jsonObjects = [...chunk.matchAll(/^\{.*\}$/gm)].map((match) => safeJson(match[0])).filter(Boolean);
    const metrics = parseMetrics(chunk);
    parsed.push({
      index: Number(header[1]),
      timestampMs: Date.parse(header[2]),
      active: /^active$/m.test(chunk),
      health: jsonObjects.find((item) => Object.prototype.hasOwnProperty.call(item, "max_package_slots")),
      ready: jsonObjects.find((item) => Object.prototype.hasOwnProperty.call(item, "store_ok")),
      failedSlots: metrics.get("zylith_renewal_relay_failed_slots") ?? 0,
      missedSlots: metrics.get("zylith_renewal_relay_missed_slots") ?? 0,
    });
  }
  return parsed.filter((sample) => Number.isFinite(sample.index) && Number.isFinite(sample.timestampMs));
}

function parseMetrics(chunk) {
  const metrics = new Map();
  for (const line of chunk.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const [name, value] = trimmed.split(/\s+/, 2);
    const parsed = Number(value);
    if (name?.startsWith("zylith_") && Number.isFinite(parsed)) metrics.set(name, parsed);
  }
  return metrics;
}

function safeJson(input) {
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}

function parseArgs(items) {
  const parsed = {};
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (item === "--log") parsed.log = items[++index];
    else if (item === "--samples") parsed.samples = items[++index];
    else if (item === "--hours") parsed.hours = items[++index];
  }
  return parsed;
}

function parsePositiveInt(input, label) {
  const parsed = Number(input);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    console.error(`relay soak audit failed\n- ${label} must be a positive integer`);
    process.exit(1);
  }
  return parsed;
}

function parsePositiveNumber(input, label) {
  const parsed = Number(input);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    console.error(`relay soak audit failed\n- ${label} must be positive`);
    process.exit(1);
  }
  return parsed;
}

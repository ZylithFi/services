#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const DEFAULT_STATE_PATH = ".deploy/offline-renewal-operator.state.json";
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const renewalPackage = JSON.parse(await readFile(args.packagePath, "utf8"));
  validatePackage(renewalPackage);
  const state = await readState(args.statePath);
  const results = await relayPackageOnce(renewalPackage, state, args);
  await mkdir(dirname(args.statePath), { recursive: true });
  await writeFile(args.statePath, JSON.stringify(state, null, 2));
  console.log(JSON.stringify({ package_id: renewalPackage.package_id, results }, null, 2));
}

function parseArgs(argv) {
  let packagePath = "";
  let statePath = DEFAULT_STATE_PATH;
  let coordinatorUrl = "";
  let proverUrl = "";
  let requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--package") packagePath = argv[++index] ?? "";
    else if (arg === "--state") statePath = argv[++index] ?? "";
    else if (arg === "--coordinator-url") coordinatorUrl = argv[++index] ?? "";
    else if (arg === "--prover-url") proverUrl = argv[++index] ?? "";
    else if (arg === "--request-timeout-ms") requestTimeoutMs = parsePositiveInt(argv[++index], "request timeout");
    else if (arg === "--help" || arg === "-h") {
      console.log("Usage: node ops/offline-renewal-operator.mjs --package PATH [--state PATH] [--coordinator-url URL] [--prover-url URL] [--request-timeout-ms MS]");
      process.exit(0);
    } else {
      throw new Error(`unexpected argument: ${arg}`);
    }
  }
  if (!packagePath) throw new Error("missing --package PATH");
  return { packagePath, statePath, coordinatorUrl, proverUrl, requestTimeoutMs };
}

export async function relayPackageOnce(renewalPackage, state, args) {
  const coordinatorUrl = normalizeUrl(args.coordinatorUrl || renewalPackage.relay_policy.coordinator_url);
  const proverUrl = normalizeUrl(args.proverUrl || renewalPackage.relay_policy.prover_url);
  if (!coordinatorUrl || !proverUrl) throw new Error("coordinator and prover URLs are required");
  const results = [];
  for (const slot of renewalPackage.slots) {
    if (state.submitted_order_commitments.includes(slot.order_commitment)) {
      results.push(slotResult(slot, "already_submitted"));
      continue;
    }
    const cancelStatus = await fetchJson(
      coordinatorUrl,
      `/api/renewal/cancel-markers/${encodeURIComponent(renewalPackage.parent_cancel_marker ?? "")}`,
      args,
    );
    if (!cancelStatus) {
      results.push(slotResult(slot, "awaiting_settlement", "Waiting for renewal cancellation status before submitting child orders."));
      continue;
    }
    if (cancelStatus.recorded) {
      results.push(slotResult(slot, "missed", "Renewal parent cancellation marker is recorded."));
      continue;
    }
    const reuseGuard = await priorSlotReuseGuard(proverUrl, renewalPackage, slot, state, args);
    if (reuseGuard) {
      results.push(reuseGuard);
      continue;
    }
    try {
      const batch = await fetchRelayPairBatch(coordinatorUrl, slot.pair, args);
      if (!batch || batch.batch_id !== slot.batch_id || batch.epoch_id !== slot.epoch_id) {
        results.push(slotResult(slot, "not_due"));
        continue;
      }
      if (batch.status !== "Open") {
        results.push(slotResult(slot, "batch_not_open", batch.status));
        continue;
      }
      if (batch.close_time_unix_ms - Date.now() <= renewalPackage.relay_policy.submission_safety_buffer_ms) {
        results.push(slotResult(slot, "safety_buffer"));
        continue;
      }
      await sleep(sampleRelayDelayMs(batch, renewalPackage));
      if (batch.close_time_unix_ms - Date.now() <= renewalPackage.relay_policy.submission_safety_buffer_ms) {
        results.push(slotResult(slot, "safety_buffer"));
        continue;
      }
      const ingress = await postJson(proverUrl, "/api/private/orders", attestedIngressRequest(renewalPackage, slot), args);
      validateIngressForSlot(renewalPackage, slot, ingress.receipt);
      const accepted = await postJson(coordinatorUrl, "/api/orders", ingress.coordinator_submission, args);
      validateAcceptedForSlot(slot, accepted);
      state.submitted_order_commitments.push(slot.order_commitment);
      state.submitted_slots.push({
        order_commitment: slot.order_commitment,
        batch_id: slot.batch_id,
        epoch_id: slot.epoch_id,
        parent_child_index: slot.parent_child_index,
        funding_note_commitments: slot.funding_note_commitments ?? [],
      });
      results.push({ ...slotResult(slot, "submitted"), accepted });
    } catch (error) {
      results.push(slotResult(slot, "failed", error instanceof Error ? error.message : "relay failed"));
    }
  }
  return results;
}

async function fetchSubmittablePairBatch(coordinatorUrl, pair, args) {
  const [base, quote] = pair.split("/");
  const response = await fetchWithTimeout(`${coordinatorUrl}/api/pairs/${encodeURIComponent(base)}/${encodeURIComponent(quote)}/batches/submittable`, {
    headers: { accept: "application/json" },
  }, args);
  if (!response.ok) return null;
  return response.json();
}

async function fetchRelayPairBatch(coordinatorUrl, pair, args) {
  return fetchSubmittablePairBatch(coordinatorUrl, pair, args);
}

async function postJson(baseUrl, path, body, args) {
  const response = await fetchWithTimeout(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  }, args);
  if (!response.ok) {
    throw new Error((await response.text().catch(() => "")) || `request failed with HTTP ${response.status}`);
  }
  return response.json();
}

async function readState(path) {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    return {
      submitted_order_commitments: Array.isArray(parsed.submitted_order_commitments)
        ? parsed.submitted_order_commitments
        : [],
      submitted_slots: Array.isArray(parsed.submitted_slots) ? parsed.submitted_slots : [],
    };
  } catch {
    return { submitted_order_commitments: [], submitted_slots: [] };
  }
}

export function validatePackage(renewalPackage) {
  if (renewalPackage.version !== 1) throw new Error("unsupported package version");
  if (!Array.isArray(renewalPackage.slots)) throw new Error("package slots must be an array");
  if (renewalPackage.slot_count !== renewalPackage.slots.length) {
    throw new Error("package slot_count does not match slots length");
  }
  if (!renewalPackage.parent_cancel_authority || !renewalPackage.parent_cancel_marker) {
    throw new Error("package cancellation marker is missing");
  }
  const commitments = new Set();
  for (const slot of renewalPackage.slots) {
    if (slot.pair !== renewalPackage.pair) throw new Error("slot pair mismatch");
    if (slot.epoch_id < renewalPackage.start_epoch || slot.epoch_id > renewalPackage.end_epoch) {
      throw new Error("slot epoch outside package range");
    }
    if (commitments.has(slot.order_commitment)) throw new Error("duplicate slot order commitment");
    commitments.add(slot.order_commitment);
  }
  const expectedCommitment = renewalPackageCommitment(renewalPackage);
  if (String(renewalPackage.package_commitment ?? "").toLowerCase() !== expectedCommitment) {
    throw new Error("package commitment does not match package body");
  }
}

export function renewalPackageCommitment(renewalPackage) {
  const value = JSON.parse(JSON.stringify(renewalPackage));
  delete value.package_commitment;
  delete value.relay_authorization;
  delete value.access_token;
  return `0x${createHash("sha256").update(stableJsonString(value)).digest("hex")}`;
}

function stableJsonString(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJsonString).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJsonString(value[key])}`)
      .join(",")}}`;
  }
  throw new Error(`unsupported package commitment value: ${typeof value}`);
}

function sampleRelayDelayMs(batch, renewalPackage) {
  const maxDelay = Math.min(
    renewalPackage.relay_policy.max_submission_delay_ms,
    batch.close_time_unix_ms - Date.now() - renewalPackage.relay_policy.submission_safety_buffer_ms,
  );
  return maxDelay > 0 ? Math.floor(Math.random() * maxDelay) : 0;
}

async function priorSlotReuseGuard(proverUrl, renewalPackage, slot, state, args) {
  const priorSlots = state.submitted_slots.filter((candidate) =>
    candidate.parent_child_index < slot.parent_child_index &&
    slotsReuseFundingNotes(candidate, slot)
  );
  for (const prior of priorSlots) {
    const status = await fetchJson(proverUrl, `/api/public/proof-jobs/${encodeURIComponent(prior.batch_id)}`, args);
    if (!status) {
      return slotResult(slot, "awaiting_settlement", `Waiting for prior child batch ${prior.batch_id} proof status.`);
    }
    if (proofJobFailed(status)) {
      return slotResult(slot, "awaiting_settlement", `Prior child batch ${prior.batch_id} proof failed; refresh this package before reusing liquidity capital.`);
    }
    if (proofJobConfirmed(status)) {
      if (status.reuse_state === "no_fill") continue;
      if (status.reuse_state === "matched") {
        return slotResult(slot, "awaiting_wallet_refresh", `Prior child batch ${prior.batch_id} settled; refresh this package before reusing liquidity capital.`);
      }
      return slotResult(slot, "awaiting_settlement", `Prior child batch ${prior.batch_id} is confirmed without a no-fill reuse attestation.`);
    }
    return slotResult(slot, "awaiting_settlement", `Waiting for prior child batch ${prior.batch_id} to settle.`);
  }
  return null;
}

async function fetchJson(baseUrl, path, args) {
  const response = await fetchWithTimeout(`${baseUrl}${path}`, {
    headers: { accept: "application/json" },
  }, args);
  if (!response.ok) return null;
  return response.json();
}

async function fetchWithTimeout(url, init = {}, args = {}) {
  const timeoutMs = parsePositiveInt(args.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS, "request timeout");
  const controller = new AbortController();
  let timer;
  const timeoutGuard = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort(new DOMException("offline renewal request timed out", "TimeoutError"));
      reject(new Error(`request timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([
      fetch(url, { ...init, signal: controller.signal }),
      timeoutGuard,
    ]);
  } catch (error) {
    throw new Error(normalizedNetworkErrorMessage(error, timeoutMs));
  } finally {
    clearTimeout(timer);
  }
}

export function normalizedNetworkErrorMessage(error, timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS) {
  const message = error instanceof Error ? error.message : String(error ?? "");
  const name = error instanceof Error ? error.name : "";
  if (
    /AbortError|TimeoutError/i.test(name) ||
    /signal is aborted|aborted without reason|operation was aborted/i.test(message)
  ) {
    return `request timed out after ${timeoutMs}ms`;
  }
  if (/failed to fetch|networkerror|network request failed|load failed|fetch failed/i.test(message)) {
    return "network request failed";
  }
  return message || "request failed";
}

function validateIngressForSlot(renewalPackage, slot, receipt) {
  if (!receipt) throw new Error("private ingress response is missing receipt");
  if (receipt.order_commitment !== slot.order_commitment) throw new Error("private ingress receipt order commitment mismatch");
  if (receipt.pair_id !== slot.pair) throw new Error("private ingress receipt pair mismatch");
  if (receipt.batch_id !== slot.batch_id) throw new Error("private ingress receipt batch mismatch");
  if (receipt.epoch_id !== slot.epoch_id) throw new Error("private ingress receipt epoch mismatch");
  if (receipt.relay_mode !== renewalPackage.relay_mode) throw new Error("private ingress receipt relay mode mismatch");
  if (receipt.renewal_package_id !== renewalPackage.package_id) throw new Error("private ingress receipt package id mismatch");
  if (receipt.renewal_package_commitment !== renewalPackage.package_commitment) throw new Error("private ingress receipt package commitment mismatch");
}

function attestedIngressRequest(renewalPackage, slot) {
  if (!slot.ingress_request || typeof slot.ingress_request !== "object" || Array.isArray(slot.ingress_request)) {
    throw new Error("slot ingress request must be an object");
  }
  return {
    ...slot.ingress_request,
    renewal_package_id: renewalPackage.package_id,
    renewal_package_commitment: renewalPackage.package_commitment,
    renewal_relay_mode: renewalPackage.relay_mode,
    renewal_slot_order_commitment: slot.order_commitment,
    renewal_slot_pair: slot.pair,
    renewal_slot_batch_id: slot.batch_id,
    renewal_slot_epoch_id: slot.epoch_id,
  };
}

function validateAcceptedForSlot(slot, accepted) {
  if (!accepted) throw new Error("coordinator response is missing acceptance record");
  if (accepted.order_commitment !== slot.order_commitment) throw new Error("coordinator accepted order commitment mismatch");
  if (accepted.batch_id !== slot.batch_id) throw new Error("coordinator accepted batch mismatch");
}

function slotsReuseFundingNotes(candidate, slot) {
  const current = new Set(slot.funding_note_commitments ?? []);
  const prior = candidate.funding_note_commitments ?? [];
  if (current.size === 0 || prior.length === 0) return true;
  return prior.some((commitment) => current.has(commitment));
}

function proofJobConfirmed(status) {
  return String(status.state ?? "").toLowerCase() === "confirmed-onchain";
}

function proofJobFailed(status) {
  return Boolean(status.failure) || String(status.state ?? "").toLowerCase().includes("failed");
}

function slotResult(slot, status, detail) {
  return {
    slot_id: slot.slot_id,
    order_commitment: slot.order_commitment,
    batch_id: slot.batch_id,
    epoch_id: slot.epoch_id,
    status,
    detail,
  };
}

function normalizeUrl(value) {
  return String(value || "").replace(/\/+$/, "");
}

function parsePositiveInt(value, label) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

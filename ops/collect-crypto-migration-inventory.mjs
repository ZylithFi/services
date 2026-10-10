#!/usr/bin/env node
// read-only cutover inventory. it consumes authenticated aggregate service views and never asks
// for wallet seeds, note preimages, order-owner preimages, ciphertext plaintext, or signing keys.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const HASH_ID = /^(?:0x)?[0-9a-f]{1,128}$/;

function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a nonnegative safe integer`);
  return value;
}

function identifiers(value, label) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || !HASH_ID.test(entry))) throw new Error(`${label} must contain canonical public identifiers`);
  if (new Set(value).size !== value.length) throw new Error(`${label} repeats an identifier`);
  return [...value].sort();
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

function records(value, label, idField) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const ids = value.map((entry, index) => {
    object(entry, `${label}[${index}]`);
    const id = entry[idField];
    if (typeof id !== "string" || !HASH_ID.test(id)) throw new Error(`${label}[${index}].${idField} is invalid`);
    return id;
  });
  if (new Set(ids).size !== ids.length) throw new Error(`${label} repeats ${idField}`);
  return value;
}

export function buildMigrationInventory(sources, decisions = {}, collectedAtUnixMs = Date.now()) {
  object(sources, "sources");
  const operator = object(sources.operator, "operator");
  const op = object(operator.migration_inventory, "operator.migration_inventory");
  const indexer = object(sources.indexer, "indexer");
  const coordinator = object(sources.coordinator, "coordinator");
  const proofQueue = object(sources.proof_queue, "proof_queue");
  object(decisions, "decisions");
  integer(collectedAtUnixMs, "collected_at_unix_ms");

  if (op.schema_version !== 1 || indexer.schema_version !== 1 || coordinator.schema_version !== 1) throw new Error("migration source schema version is unsupported");
  if (indexer.ready !== true || integer(indexer.last_successful_sync_unix_ms, "indexer.last_successful_sync_unix_ms") === 0) throw new Error("indexer has no completed authoritative sync");

  const restingOrders = records(op.resting_orders, "operator.resting_orders", "order_id");
  const pendingOrderIds = identifiers(op.pending_order_ids, "operator.pending_order_ids");
  const pendingWithdrawals = identifiers(op.pending_withdrawal_nullifiers, "operator.pending_withdrawal_nullifiers");
  const pendingRecoveries = identifiers(op.pending_residual_recovery_nullifiers, "operator.pending_residual_recovery_nullifiers");
  const inFlight = op.in_flight_sequences;
  if (!Array.isArray(inFlight) || inFlight.some((seq) => !Number.isSafeInteger(seq) || seq < 1) || new Set(inFlight).size !== inFlight.length) throw new Error("operator.in_flight_sequences is invalid");
  const feeOutputs = records(op.fee_outputs, "operator.fee_outputs", "leaf");
  const recoveryRecords = records(object(coordinator.recovery_artifacts, "coordinator.recovery_artifacts").records, "coordinator.recovery_artifacts.records", "artifact_id");
  if (integer(coordinator.recovery_artifacts.count, "coordinator.recovery_artifacts.count") !== recoveryRecords.length) throw new Error("coordinator recovery-artifact count is inconsistent");
  const recoveryAccounts = object(coordinator.recovery_accounts, "coordinator.recovery_accounts");
  const recoveryAccountIds = identifiers(recoveryAccounts.account_ids, "coordinator.recovery_accounts.account_ids");
  if (integer(recoveryAccounts.count, "coordinator.recovery_accounts.count") !== recoveryAccountIds.length) throw new Error("coordinator recovery-account count is inconsistent");
  const vaults = object(coordinator.wallet_vaults, "coordinator.wallet_vaults");
  if (!Array.isArray(vaults.wallet_auth_ids)) throw new Error("coordinator.wallet_vaults.wallet_auth_ids must contain canonical public identifiers");
  identifiers(vaults.wallet_auth_ids, "coordinator.wallet_vaults.wallet_auth_ids");
  if (integer(vaults.count, "coordinator.wallet_vaults.count") !== vaults.wallet_auth_ids.length || !Array.isArray(vaults.versions) || vaults.versions.length !== vaults.wallet_auth_ids.length || vaults.versions.some((version) => !Number.isSafeInteger(version))) throw new Error("coordinator wallet-vault versions are inconsistent");
  const vaultRecords = vaults.wallet_auth_ids
    .map((id, index) => ({ id, version: vaults.versions[index] }))
    .sort((left, right) => left.id.localeCompare(right.id));
  const vaultIds = vaultRecords.map((record) => record.id);
  const jobs = records(proofQueue.jobs, "proof_queue.jobs", "job_id");
  if (jobs.some((job) => typeof job.state !== "string" || !/^[A-Z_]{1,32}$/.test(job.state))) throw new Error("proof_queue.jobs contains an invalid state");
  for (const [field, state] of [["pending_jobs", "PENDING"], ["active_jobs", "CLAIMED"], ["failed_retryable_jobs", "FAILED_RETRYABLE"], ["failed_permanent_jobs", "FAILED_PERMANENT"]]) {
    const declared = integer(proofQueue[field], `proof_queue.${field}`);
    const actual = state === "CLAIMED"
      ? jobs.filter((job) => ["CLAIMED", "PROVING"].includes(job.state)).length
      : jobs.filter((job) => job.state === state).length;
    if (declared !== actual) throw new Error(`proof_queue.${field} is inconsistent with jobs`);
  }

  const depositView = object(indexer.deposits, "indexer.deposits");
  const depositIds = depositView.activation_ids;
  if (!Array.isArray(depositIds) || depositIds.some((id) => !Number.isSafeInteger(id) || id < 0) || new Set(depositIds).size !== depositIds.length || integer(depositView.count, "indexer.deposits.count") !== depositIds.length) throw new Error("indexer deposit identifiers are inconsistent");
  const transitionView = object(indexer.transitions, "indexer.transitions");
  if (!Array.isArray(transitionView.sequences) || transitionView.sequences.some((seq) => !Number.isSafeInteger(seq) || seq < 0) || new Set(transitionView.sequences).size !== transitionView.sequences.length || integer(transitionView.count, "indexer.transitions.count") !== transitionView.sequences.length) throw new Error("indexer transition identifiers are inconsistent");
  const latestSeq = integer(transitionView.latest_seq, "indexer.transitions.latest_seq");
  const noteBatchView = object(indexer.note_batches, "indexer.note_batches");
  const noteBatchRoots = identifiers(noteBatchView.roots, "indexer.note_batches.roots");
  if (integer(noteBatchView.count, "indexer.note_batches.count") !== noteBatchRoots.length) throw new Error("indexer note-batch identifiers are inconsistent");
  const confirmedSeq = integer(operator.confirmed_seq, "operator.confirmed_seq");
  const chainAhead = latestSeq > confirmedSeq;
  const operatorAhead = confirmedSeq > latestSeq;

  const incompatible = [];
  for (const vault of vaultRecords) {
    if (vault.version !== 3) incompatible.push(`wallet_vault:${vault.id}`);
  }
  for (const artifact of recoveryRecords) {
    if (artifact.key_schedule_version !== 2) incompatible.push(`recovery_artifact:${artifact.artifact_id}`);
  }
  const dispositions = incompatible.map((id) => ({ id, status: decisions[id] }));
  const undisposed = dispositions.filter((entry) => entry.status !== "safely_migrated").map((entry) => entry.id);
  if (undisposed.length !== 0) throw new Error(`incompatible wallet objects lack a safely_migrated disposition: ${undisposed.join(",")}`);
  const unexpectedDecisions = Object.keys(decisions).filter((id) => !incompatible.includes(id));
  if (unexpectedDecisions.length !== 0) throw new Error(`migration dispositions name unknown objects: ${unexpectedDecisions.join(",")}`);

  const noteLeaves = integer(op.note_leaves, "operator.note_leaves");
  const residualAuthorities = integer(op.residual_authorities, "operator.residual_authorities");
  const pendingProofJobs = jobs.filter((job) => !["COMPLETE", "FAILED_PERMANENT"].includes(job.state));
  const pending = pendingOrderIds.length + pendingWithdrawals.length + pendingRecoveries.length + inFlight.length + pendingProofJobs.length;
  const valueBearing = restingOrders.length + noteLeaves + depositIds.length + residualAuthorities + feeOutputs.length + recoveryRecords.length + vaultIds.length;
  const synchronized = !chainAhead && !operatorAhead;
  const safeToReset = synchronized && pending === 0 && valueBearing === 0 && incompatible.length === 0;

  return {
    schema_version: 1,
    collected_at_unix_ms: collectedAtUnixMs,
    source_sha256: {
      operator: digest(operator),
      indexer: digest(indexer),
      coordinator: digest(coordinator),
      proof_queue: digest(proofQueue),
    },
    synchronization: { operator_confirmed_seq: confirmedSeq, indexer_latest_seq: latestSeq, chain_ahead: chainAhead, operator_ahead: operatorAhead, synchronized },
    objects: {
      resting_book: { count: restingOrders.length, identifiers: restingOrders.map((entry) => entry.order_id).sort() },
      notes: { count: noteLeaves },
      deposits: { count: depositIds.length, identifiers: [...depositIds].sort((a, b) => a - b) },
      residual_authorities: { count: residualAuthorities },
      pending_orders: { count: pendingOrderIds.length, identifiers: pendingOrderIds },
      pending_withdrawals: { count: pendingWithdrawals.length, identifiers: pendingWithdrawals },
      pending_residual_recoveries: { count: pendingRecoveries.length, identifiers: pendingRecoveries },
      in_flight_transitions: { count: inFlight.length, identifiers: [...inFlight].sort((a, b) => a - b) },
      fee_outputs: { count: feeOutputs.length, identifiers: feeOutputs.map((entry) => entry.leaf).sort() },
      proof_jobs: { count: jobs.length, pending_count: pendingProofJobs.length, records: jobs },
      recovery_artifacts: { count: recoveryRecords.length, identifiers: recoveryRecords.map((entry) => entry.artifact_id).sort() },
      wallet_vaults: { count: vaultIds.length, identifiers: vaultIds },
    },
    incompatible_wallet_objects: { count: incompatible.length, dispositions },
    decision: {
      safe_to_reset: safeToReset,
      reason: safeToReset ? "all authoritative inventories are synchronized and empty" : "live, pending, incompatible, or unsynchronized state remains",
    },
  };
}

async function fetchJson(url, headers, method = "GET") {
  const response = await fetch(url, { method, headers, signal: AbortSignal.timeout(15_000), cache: "no-store" });
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
  const text = await response.text();
  if (text.length > 16 * 1024 * 1024) throw new Error(`${url} response exceeds 16 MiB`);
  try { return JSON.parse(text); } catch { throw new Error(`${url} returned malformed JSON`); }
}

async function main() {
  if (process.argv.length < 3 || process.argv.length > 4) throw new Error("usage: collect-crypto-migration-inventory.mjs <exclusive-output.json> [dispositions.json]");
  const required = (name) => {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`${name} is required`);
    return value;
  };
  const control = required("ZYLITH_CONTROL_PLANE_TOKEN");
  const monitor = required("ZYLITH_PROOF_QUEUE_MONITOR_TOKEN");
  await fetchJson(required("ZYLITH_INDEXER_SYNC_URL"), { authorization: `Bearer ${control}` }, "POST");
  const [operator, indexer, coordinator, proofQueue] = await Promise.all([
    fetchJson(required("ZYLITH_OPERATOR_MIGRATION_INVENTORY_URL"), { authorization: `Bearer ${control}` }),
    fetchJson(required("ZYLITH_INDEXER_MIGRATION_INVENTORY_URL"), { authorization: `Bearer ${control}` }),
    fetchJson(required("ZYLITH_COORDINATOR_MIGRATION_INVENTORY_URL"), { "x-zylith-proof-monitor-token": monitor }),
    fetchJson(required("ZYLITH_PROOF_QUEUE_HEALTH_URL"), { "x-zylith-proof-monitor-token": monitor }),
  ]);
  const decisions = process.argv[3] ? JSON.parse(readFileSync(process.argv[3], "utf8")) : {};
  const inventory = buildMigrationInventory({ operator, indexer, coordinator, proof_queue: proofQueue }, decisions);
  writeFileSync(process.argv[2], `${JSON.stringify(inventory, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main().catch((error) => { console.error(error.message); process.exitCode = 1; });

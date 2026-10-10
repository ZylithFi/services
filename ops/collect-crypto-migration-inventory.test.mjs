import assert from "node:assert/strict";
import test from "node:test";

import { buildMigrationInventory } from "./collect-crypto-migration-inventory.mjs";

const id = (digit) => `0x${digit.repeat(64)}`;

function emptySources() {
  return {
    operator: {
      confirmed_seq: 0,
      migration_inventory: {
        schema_version: 1,
        state_version: 3,
        resting_orders: [], pending_order_ids: [], note_batches: [], note_leaves: 0,
        residual_authorities: 0, pending_withdrawal_nullifiers: [],
        pending_residual_recovery_nullifiers: [], in_flight_sequences: [], fee_outputs: [],
      },
    },
    indexer: {
      schema_version: 1, ready: true, next_block: 1, cursor_hash: "0x1", last_successful_sync_unix_ms: 1,
      deposits: { count: 0, activation_ids: [] }, transitions: { count: 0, sequences: [], latest_seq: 0 },
      note_batches: { count: 0, roots: [] },
    },
    coordinator: {
      schema_version: 1,
      recovery_accounts: { count: 0, account_ids: [] },
      recovery_artifacts: { count: 0, records: [] },
      wallet_vaults: { count: 0, wallet_auth_ids: [], versions: [] },
    },
    proof_queue: { status: "ok", pending_jobs: 0, active_jobs: 0, failed_retryable_jobs: 0, failed_permanent_jobs: 0, jobs: [] },
  };
}

test("empty synchronized inventory is the only automatic safe-reset result", () => {
  const inventory = buildMigrationInventory(emptySources(), {}, 7);
  assert.equal(inventory.decision.safe_to_reset, true);
  assert.equal(inventory.collected_at_unix_ms, 7);
});

test("nonempty value-bearing inventory is preserved and blocks reset", () => {
  const sources = emptySources();
  sources.operator.migration_inventory.resting_orders.push({ order_id: id("1"), residual_commitment: id("2"), residual_generation: 1 });
  sources.operator.migration_inventory.residual_authorities = 1;
  const inventory = buildMigrationInventory(sources);
  assert.equal(inventory.objects.resting_book.count, 1);
  assert.equal(inventory.decision.safe_to_reset, false);
});

test("malformed source counts and identifiers fail closed", () => {
  const sources = emptySources();
  sources.indexer.deposits = { count: 1, activation_ids: [] };
  assert.throws(() => buildMigrationInventory(sources), /deposit identifiers are inconsistent/);
  sources.indexer.deposits = { count: 1, activation_ids: [1] };
  sources.operator.migration_inventory.pending_order_ids = ["private preimage"];
  assert.throws(() => buildMigrationInventory(sources), /canonical public identifiers/);
});

test("chain-ahead and operator-ahead inventories are explicit and unsafe", () => {
  const chainAhead = emptySources();
  chainAhead.indexer.transitions = { count: 1, sequences: [1], latest_seq: 1 };
  assert.equal(buildMigrationInventory(chainAhead).synchronization.chain_ahead, true);
  assert.equal(buildMigrationInventory(chainAhead).decision.safe_to_reset, false);

  const operatorAhead = emptySources();
  operatorAhead.operator.confirmed_seq = 1;
  assert.equal(buildMigrationInventory(operatorAhead).synchronization.operator_ahead, true);
  assert.equal(buildMigrationInventory(operatorAhead).decision.safe_to_reset, false);
});

test("pending work is counted and blocks reset", () => {
  const sources = emptySources();
  sources.operator.migration_inventory.pending_withdrawal_nullifiers = [id("3")];
  sources.proof_queue.jobs = [{ job_id: "a".repeat(64), state: "PENDING" }];
  sources.proof_queue.pending_jobs = 1;
  const inventory = buildMigrationInventory(sources);
  assert.equal(inventory.objects.pending_withdrawals.count, 1);
  assert.equal(inventory.objects.proof_jobs.pending_count, 1);
  assert.equal(inventory.decision.safe_to_reset, false);
});

test("partially migrated wallet objects require an explicit complete disposition", () => {
  const sources = emptySources();
  sources.coordinator.recovery_artifacts = {
    count: 1,
    records: [{ account_id: id("4"), artifact_id: id("5"), key_schedule_version: 1, sequence: 1 }],
  };
  assert.throws(() => buildMigrationInventory(sources), /lack a safely_migrated disposition/);
  const inventory = buildMigrationInventory(sources, { [`recovery_artifact:${id("5")}`]: "safely_migrated" });
  assert.equal(inventory.incompatible_wallet_objects.count, 1);
  assert.equal(inventory.decision.safe_to_reset, false);
});

test("wallet-vault versions stay attached to their identifiers before canonical sorting", () => {
  const sources = emptySources();
  const legacy = id("2");
  const current = id("1");
  sources.coordinator.wallet_vaults = {
    count: 2,
    // Deliberately reverse canonical order and give the entries different versions. Sorting the
    // identifiers separately from this parallel version list would attribute v1 to the wrong ID.
    wallet_auth_ids: [legacy, current],
    versions: [1, 3],
  };
  const inventory = buildMigrationInventory(sources, {
    [`wallet_vault:${legacy}`]: "safely_migrated",
  });
  assert.deepEqual(inventory.objects.wallet_vaults.identifiers, [current, legacy]);
  assert.deepEqual(inventory.incompatible_wallet_objects.dispositions, [
    { id: `wallet_vault:${legacy}`, status: "safely_migrated" },
  ]);
});

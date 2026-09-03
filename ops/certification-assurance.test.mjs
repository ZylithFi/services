import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);

class ProtocolModel {
  constructor() {
    this.noteRoot = 0;
    this.nullifierRoot = 0;
    this.renewalRoot = 0;
    this.feeRoot = 0;
    this.escrow = 0n;
    this.depositNotes = new Map();
    this.outputNotes = new Map();
    this.stagedStrk20Exits = new Map();
    this.feeNotes = 0n;
    this.consumedNullifiers = new Set();
    this.withdrawnOutputs = new Set();
    this.claimedStrk20Exits = new Map();
    this.cancelMarkers = new Set();
    this.settledBatches = new Set();
    this.pendingRootBatch = null;
  }

  clone() {
    const next = new ProtocolModel();
    next.noteRoot = this.noteRoot;
    next.nullifierRoot = this.nullifierRoot;
    next.renewalRoot = this.renewalRoot;
    next.feeRoot = this.feeRoot;
    next.escrow = this.escrow;
    next.depositNotes = new Map(this.depositNotes);
    next.outputNotes = new Map(this.outputNotes);
    next.stagedStrk20Exits = new Map(this.stagedStrk20Exits);
    next.feeNotes = this.feeNotes;
    next.consumedNullifiers = new Set(this.consumedNullifiers);
    next.withdrawnOutputs = new Set(this.withdrawnOutputs);
    next.claimedStrk20Exits = new Map(this.claimedStrk20Exits);
    next.cancelMarkers = new Set(this.cancelMarkers);
    next.settledBatches = new Set(this.settledBatches);
    next.pendingRootBatch = this.pendingRootBatch ? { ...this.pendingRootBatch } : null;
    return next;
  }

  liveValue() {
    return (
      sum(this.depositNotes.values()) +
      sum(this.outputNotes.values()) +
      sum(this.stagedStrk20Exits.values()) +
      this.feeNotes
    );
  }

  assertConserved() {
    assert.equal(this.escrow, this.liveValue(), "adapter escrow must equal live notes plus fee notes");
    assert(this.escrow >= 0n, "escrow cannot become negative");
  }

  assertNoPendingRootTransition() {
    if (this.pendingRootBatch) {
      throw new Error("root transition is pending");
    }
  }

  deposit(noteId, amount) {
    this.assertNoPendingRootTransition();
    assertPositiveAmount(amount);
    if (this.depositNotes.has(noteId) || this.outputNotes.has(noteId)) {
      throw new Error("duplicate note commitment");
    }
    this.depositNotes.set(noteId, BigInt(amount));
    this.escrow += BigInt(amount);
    this.noteRoot += 1;
    this.assertConserved();
  }

  recordSplitRoots(batchId, { priorNullifierRoot, priorRenewalRoot } = {}) {
    if (this.pendingRootBatch && this.pendingRootBatch.batchId !== batchId) {
      throw new Error("another batch owns the pending root transition");
    }
    if (priorNullifierRoot !== undefined && priorNullifierRoot !== this.nullifierRoot) {
      throw new Error("stale prior nullifier root");
    }
    if (priorRenewalRoot !== undefined && priorRenewalRoot !== this.renewalRoot) {
      throw new Error("stale prior renewal root");
    }
    this.pendingRootBatch = { batchId, priorNullifierRoot, priorRenewalRoot };
  }

  clearPendingRootTransition(batchId, { authorized }) {
    if (!authorized) throw new Error("unauthorized root cleanup");
    if (!this.pendingRootBatch) throw new Error("no pending root transition");
    if (this.pendingRootBatch.batchId !== batchId) throw new Error("wrong pending root batch");
    this.pendingRootBatch = null;
  }

  settle(batchId, { inputs, outputs, fees = 0n, nullifiers = [] }) {
    if (this.pendingRootBatch && this.pendingRootBatch.batchId !== batchId) {
      throw new Error("pending root transition belongs to a different batch");
    }
    if (this.settledBatches.has(batchId)) throw new Error("batch already settled");
    const inputValue = this.consumeInputs(inputs, nullifiers);
    const outputValue = sumValues(outputs);
    if (inputValue !== outputValue + BigInt(fees)) {
      throw new Error("settlement value is not conserved");
    }
    this.addOutputs(outputs);
    this.feeNotes += BigInt(fees);
    this.noteRoot += 1;
    this.nullifierRoot += 1;
    this.renewalRoot += 1;
    this.feeRoot += fees > 0n ? 1 : 0;
    this.settledBatches.add(batchId);
    this.pendingRootBatch = null;
    this.assertConserved();
  }

  aggregateSettle(records) {
    if (records.length === 0) throw new Error("empty aggregate");
    const seen = new Set();
    let expectedNoteRoot = this.noteRoot;
    let expectedNullifierRoot = this.nullifierRoot;
    let expectedRenewalRoot = this.renewalRoot;
    let expectedFeeRoot = this.feeRoot;
    for (const record of records) {
      if (seen.has(record.batchId)) throw new Error("duplicate aggregate batch");
      seen.add(record.batchId);
      if (record.priorNoteRoot !== expectedNoteRoot) throw new Error("aggregate stale note root");
      if (record.priorNullifierRoot !== expectedNullifierRoot) {
        throw new Error("aggregate stale nullifier root");
      }
      if (record.priorRenewalRoot !== expectedRenewalRoot) {
        throw new Error("aggregate stale renewal root");
      }
      if (record.priorFeeRoot !== expectedFeeRoot) throw new Error("aggregate stale fee root");
      this.settle(record.batchId, record);
      expectedNoteRoot = this.noteRoot;
      expectedNullifierRoot = this.nullifierRoot;
      expectedRenewalRoot = this.renewalRoot;
      expectedFeeRoot = this.feeRoot;
    }
  }

  consolidate({ inputs, outputs, nullifiers }) {
    this.assertNoPendingRootTransition();
    const inputValue = this.consumeInputs(inputs, nullifiers);
    const outputValue = sumValues(outputs);
    if (inputValue !== outputValue) throw new Error("consolidation value is not conserved");
    this.addOutputs(outputs);
    this.noteRoot += 1;
    this.nullifierRoot += 1;
    this.assertConserved();
  }

  stageStrk20Exit(outputId, nullifier, exitId) {
    this.assertNoPendingRootTransition();
    if (this.withdrawnOutputs.has(outputId)) throw new Error("output already withdrawn");
    if (this.consumedNullifiers.has(nullifier)) throw new Error("duplicate nullifier");
    if (this.stagedStrk20Exits.has(exitId) || this.claimedStrk20Exits.has(exitId)) {
      throw new Error("exit already exists");
    }
    const amount = this.outputNotes.get(outputId);
    if (amount === undefined) throw new Error("unknown output note");
    this.outputNotes.delete(outputId);
    this.withdrawnOutputs.add(outputId);
    this.consumedNullifiers.add(nullifier);
    this.stagedStrk20Exits.set(exitId, amount);
    this.nullifierRoot += 1;
    this.assertConserved();
  }

  claimStrk20Exit(exitId, openNoteId) {
    if (this.claimedStrk20Exits.has(exitId)) throw new Error("exit already claimed");
    const amount = this.stagedStrk20Exits.get(exitId);
    if (amount === undefined) throw new Error("unknown exit");
    this.stagedStrk20Exits.delete(exitId);
    this.claimedStrk20Exits.set(exitId, openNoteId);
    this.escrow -= amount;
    this.assertConserved();
  }

  cancelRenewalParent(marker) {
    this.assertNoPendingRootTransition();
    if (this.cancelMarkers.has(marker)) throw new Error("duplicate renewal cancel marker");
    this.cancelMarkers.add(marker);
    this.renewalRoot += 1;
  }

  consumeInputs(inputs, nullifiers) {
    if (inputs.length !== nullifiers.length) throw new Error("input/nullifier length mismatch");
    let total = 0n;
    for (let index = 0; index < inputs.length; index += 1) {
      const input = inputs[index];
      const nullifier = nullifiers[index];
      if (this.consumedNullifiers.has(nullifier)) throw new Error("duplicate nullifier");
      const amount = this.depositNotes.get(input) ?? this.outputNotes.get(input);
      if (amount === undefined) throw new Error("input note is not live");
      this.depositNotes.delete(input);
      this.outputNotes.delete(input);
      this.consumedNullifiers.add(nullifier);
      total += amount;
    }
    return total;
  }

  addOutputs(outputs) {
    for (const [noteId, amount] of Object.entries(outputs)) {
      assertPositiveAmount(amount);
      if (this.depositNotes.has(noteId) || this.outputNotes.has(noteId)) {
        throw new Error("duplicate output note");
      }
      this.outputNotes.set(noteId, BigInt(amount));
    }
  }
}

class AdapterEscrowModel {
  constructor() {
    this.ownerBalance = 0n;
    this.adapterBalance = 0n;
    this.recipientBalance = 0n;
    this.escrowedBalance = 0n;
  }

  mintOwner(amount) {
    this.ownerBalance += BigInt(amount);
  }

  registerDeposit(amount, { tokenCreditDelta = amount } = {}) {
    amount = BigInt(amount);
    tokenCreditDelta = BigInt(tokenCreditDelta);
    const adapterBefore = this.adapterBalance;
    this.ownerBalance -= amount;
    this.adapterBalance += tokenCreditDelta;
    if (this.adapterBalance !== adapterBefore + amount) {
      throw new Error("deposit token balance delta mismatch");
    }
    this.escrowedBalance += amount;
    this.assertAdapterCoversEscrow();
  }

  withdrawVerified(amount, { adapterDebitDelta = amount, recipientCreditDelta = amount, rebaseDelta = 0n } = {}) {
    amount = BigInt(amount);
    adapterDebitDelta = BigInt(adapterDebitDelta);
    recipientCreditDelta = BigInt(recipientCreditDelta);
    rebaseDelta = BigInt(rebaseDelta);
    const adapterBefore = this.adapterBalance;
    const recipientBefore = this.recipientBalance;
    this.adapterBalance += rebaseDelta;
    this.adapterBalance -= adapterDebitDelta;
    this.recipientBalance += recipientCreditDelta;
    if (adapterBefore - this.adapterBalance !== amount) {
      throw new Error("withdraw token balance delta mismatch");
    }
    if (this.recipientBalance !== recipientBefore + amount) {
      throw new Error("withdraw recipient balance delta mismatch");
    }
    this.escrowedBalance -= amount;
    this.assertAdapterCoversEscrow();
  }

  assertAdapterCoversEscrow() {
    assert(this.adapterBalance >= this.escrowedBalance, "adapter token balance must cover escrow");
  }
}

test("ERC20-001 malicious token model rejects fee-on-transfer and rebase balance deltas", () => {
  const vanilla = new AdapterEscrowModel();
  vanilla.mintOwner(100n);
  vanilla.registerDeposit(100n);
  vanilla.withdrawVerified(40n);
  vanilla.assertAdapterCoversEscrow();

  const feeOnTransferDeposit = new AdapterEscrowModel();
  feeOnTransferDeposit.mintOwner(100n);
  assertRejects(() => feeOnTransferDeposit.registerDeposit(100n, { tokenCreditDelta: 99n }));

  const rebasingDeposit = new AdapterEscrowModel();
  rebasingDeposit.mintOwner(100n);
  assertRejects(() => rebasingDeposit.registerDeposit(100n, { tokenCreditDelta: 101n }));

  const shortWithdrawal = new AdapterEscrowModel();
  shortWithdrawal.mintOwner(100n);
  shortWithdrawal.registerDeposit(100n);
  assertRejects(() => shortWithdrawal.withdrawVerified(50n, { adapterDebitDelta: 49n }));

  const shortRecipientCredit = new AdapterEscrowModel();
  shortRecipientCredit.mintOwner(100n);
  shortRecipientCredit.registerDeposit(100n);
  assertRejects(() => shortRecipientCredit.withdrawVerified(50n, { recipientCreditDelta: 49n }));

  const withdrawalRebase = new AdapterEscrowModel();
  withdrawalRebase.mintOwner(100n);
  withdrawalRebase.registerDeposit(100n);
  assertRejects(() => withdrawalRebase.withdrawVerified(50n, { rebaseDelta: 1n }));
});

test("FV-001/FV-002/FV-003 bounded model preserves assets and rejects nullifier/output replay", () => {
  const model = new ProtocolModel();
  model.deposit("deposit-a", 100n);
  model.deposit("deposit-b", 50n);
  model.settle("batch-a", {
    inputs: ["deposit-a"],
    outputs: { "output-a": 90n },
    fees: 10n,
    nullifiers: ["nullifier-a"],
  });
  assertRejects(() =>
    model.consolidate({
      inputs: ["deposit-a"],
      outputs: { "output-replay": 100n },
      nullifiers: ["nullifier-a-different-calldata"],
    })
  );
  assertRejects(() =>
    model.settle("batch-replay", {
      inputs: ["deposit-b"],
      outputs: { "output-b": 50n },
      nullifiers: ["nullifier-a"],
    })
  );
  model.stageStrk20Exit("output-a", "withdraw-nullifier-a", "exit-a");
  assertRejects(() => model.stageStrk20Exit("output-a", "withdraw-nullifier-a-2", "exit-b"));
  model.claimStrk20Exit("exit-a", "open-note-a");
  model.assertConserved();
});

test("FV-002 mutation rejects duplicate nullifier inside one settlement", () => {
  const valid = new ProtocolModel();
  valid.deposit("deposit-a", 70n);
  valid.deposit("deposit-b", 30n);
  valid.settle("batch-a", {
    inputs: ["deposit-a", "deposit-b"],
    outputs: { "output-a": 100n },
    nullifiers: ["nullifier-a", "nullifier-b"],
  });
  valid.assertConserved();

  const mutated = new ProtocolModel();
  mutated.deposit("deposit-a", 70n);
  mutated.deposit("deposit-b", 30n);
  assertRejects(() =>
    mutated.settle("batch-a", {
      inputs: ["deposit-a", "deposit-b"],
      outputs: { "output-a": 100n },
      nullifiers: ["duplicate-nullifier", "duplicate-nullifier"],
    })
  );
});

test("FV-003 STRK20 staged exits preserve custody and reject replay", () => {
  const claimPath = new ProtocolModel();
  claimPath.deposit("deposit-a", 100n);
  claimPath.settle("batch-a", {
    inputs: ["deposit-a"],
    outputs: { "output-a": 100n },
    nullifiers: ["settlement-nullifier-a"],
  });
  claimPath.stageStrk20Exit("output-a", "withdraw-nullifier-a", "exit-a");
  assert.equal(claimPath.escrow, 100n);
  assert.equal(claimPath.liveValue(), 100n);
  assertRejects(() => claimPath.stageStrk20Exit("output-a", "withdraw-nullifier-c", "exit-b"));
  claimPath.claimStrk20Exit("exit-a", "open-note-a");
  assert.equal(claimPath.escrow, 0n);
  assert.equal(claimPath.liveValue(), 0n);
  assertRejects(() => claimPath.claimStrk20Exit("exit-a", "open-note-b"));
  claimPath.assertConserved();
});

test("FV-004/FV-008 bounded model rejects root-transition interleaving and stale maintenance", () => {
  const model = new ProtocolModel();
  model.deposit("deposit-a", 100n);
  model.recordSplitRoots("batch-a", {
    priorNullifierRoot: model.nullifierRoot,
    priorRenewalRoot: model.renewalRoot,
  });
  assertRejects(() =>
    model.recordSplitRoots("batch-b", {
      priorNullifierRoot: model.nullifierRoot,
      priorRenewalRoot: model.renewalRoot,
    })
  );
  assertRejects(() => model.deposit("deposit-b", 1n));
  assertRejects(() => model.clearPendingRootTransition("batch-a", { authorized: false }));
  assertRejects(() => model.clearPendingRootTransition("batch-b", { authorized: true }));
  model.clearPendingRootTransition("batch-a", { authorized: true });
  assertRejects(() => model.clearPendingRootTransition("batch-a", { authorized: true }));
  model.cancelRenewalParent("cancel-a");
  assertRejects(() => model.cancelRenewalParent("cancel-a"));
  assertRejects(() =>
    model.recordSplitRoots("batch-c", {
      priorNullifierRoot: model.nullifierRoot,
      priorRenewalRoot: model.renewalRoot - 1,
    })
  );
});

test("FV-004/FV-006 bounded aggregate model rejects stale, duplicate, and reordered root records", () => {
  const valid = new ProtocolModel();
  valid.deposit("deposit-a", 100n);
  valid.deposit("deposit-b", 50n);
  valid.aggregateSettle([
    {
      batchId: "batch-a",
      priorNoteRoot: 2,
      priorNullifierRoot: 0,
      priorRenewalRoot: 0,
      priorFeeRoot: 0,
      inputs: ["deposit-a"],
      outputs: { "output-a": 100n },
      nullifiers: ["nullifier-a"],
    },
    {
      batchId: "batch-b",
      priorNoteRoot: 3,
      priorNullifierRoot: 1,
      priorRenewalRoot: 1,
      priorFeeRoot: 0,
      inputs: ["deposit-b"],
      outputs: { "output-b": 45n },
      fees: 5n,
      nullifiers: ["nullifier-b"],
    },
  ]);
  valid.assertConserved();

  for (const mutate of [
    (records) => [],
    (records) => [records[0], { ...records[0] }],
    (records) => [{ ...records[0], priorNoteRoot: records[0].priorNoteRoot - 1 }, records[1]],
    (records) => [records[1], records[0]],
    (records) => [records[0], { ...records[1], priorNullifierRoot: 0 }],
    (records) => [records[0], { ...records[1], priorRenewalRoot: 0 }],
    (records) => [records[0], { ...records[1], priorFeeRoot: 7 }],
    (records) => [records[0], { ...records[1], nullifiers: ["nullifier-a"] }],
  ]) {
    const model = new ProtocolModel();
    model.deposit("deposit-a", 100n);
    model.deposit("deposit-b", 50n);
    const records = [
      {
        batchId: "batch-a",
        priorNoteRoot: 2,
        priorNullifierRoot: 0,
        priorRenewalRoot: 0,
        priorFeeRoot: 0,
        inputs: ["deposit-a"],
        outputs: { "output-a": 100n },
        nullifiers: ["nullifier-a"],
      },
      {
        batchId: "batch-b",
        priorNoteRoot: 3,
        priorNullifierRoot: 1,
        priorRenewalRoot: 1,
        priorFeeRoot: 0,
        inputs: ["deposit-b"],
        outputs: { "output-b": 45n },
        fees: 5n,
        nullifiers: ["nullifier-b"],
      },
    ];
    assertRejects(() => model.aggregateSettle(mutate(records)));
  }
});

test("FV-005 fee-root accounting model includes each nonzero fee row exactly once", () => {
  const rows = [
    { domain: "protocol", asset: "USDC", recipient: "treasury", amount: 4n },
    { domain: "relay", asset: "USDC", recipient: "relay", amount: 2n },
    { domain: "padding", asset: "USDC", recipient: "0x0", amount: 0n },
  ];
  const root = feeRoot(rows);
  assert.notEqual(root, feeRoot(rows.map((row) => (row.domain === "relay" ? { ...row, amount: 1n } : row))));
  assert.notEqual(root, feeRoot(rows.map((row) => (row.domain === "relay" ? { ...row, asset: "STRK" } : row))));
  assert.notEqual(
    root,
    feeRoot(rows.map((row) => (row.domain === "protocol" ? { ...row, recipient: "attacker" } : row)))
  );
  assert.equal(root, feeRoot([...rows, { domain: "padding", asset: "ETH", recipient: "0x0", amount: 0n }]));
  assertRejects(() => assertFeeBps({ fillAmount: 100n, feeAmount: 11n, configuredBps: 1_000n }));
  assertFeeBps({ fillAmount: 100n, feeAmount: 10n, configuredBps: 1_000n });
});

test("FV-005 mutation rejects duplicate, omitted, and nonzero padding fee rows", () => {
  const rows = [
    { domain: "protocol", asset: "USDC", recipient: "treasury", amount: 4n },
    { domain: "relay", asset: "USDC", recipient: "relay", amount: 2n },
    { domain: "padding", asset: "USDC", recipient: "0x0", amount: 0n },
  ];
  const expected = feeRoot(rows);
  assertFeeRootMatches(expected, rows);
  assertFeeRootMatches(expected, [...rows, { domain: "padding", asset: "ETH", recipient: "0x0", amount: 0n }]);

  for (const mutation of [
    [...rows, rows[0]],
    rows.filter((row) => row.domain !== "relay"),
    rows.map((row) => (row.domain === "padding" ? { ...row, amount: 1n } : row)),
    rows.map((row) => (row.domain === "protocol" ? { ...row, recipient: "attacker" } : row)),
  ]) {
    assertRejects(() => assertFeeRootMatches(expected, mutation));
  }
});

test("FV-006 vector-suite manifest covers required cross-language binding surfaces", () => {
  const source = readAllSourceText();
  const required = [
    ["order commitment", ["order_commitments_are_deterministic", "builds_private_order_submission_from_seed_and_funding_notes"]],
    ["note commitment", ["note_commitments_are_deterministic", "output_note_root_rejects_duplicate_commitments"]],
    ["nullifier derivation", ["nullifier_derivation_uses_note_secret", "nullifier_proof_message_hash_binds_statement_roots"]],
    [
      "settlement transcript commitment",
      ["settlement_transcript_commitment_matches_cairo_contract_formula", "settlement_transcript_commitment_binds_every_public_field"],
    ],
    ["admission message hash", ["admission_serialized_input_binds_full_order_preimages", "auction_verifier_rejects_admission_proof_for_wrong_batch"]],
    ["auction result message hash", ["split_auction_inputs_bind_admission_and_result_roots", "auction_verifier_rejects_auction_result_for_wrong_transcript_commitment"]],
    ["native proof message hash", ["native_settlement_message_hash_matches_cairo_contract_formula", "settlement_message_hash_matches_native_payload_binding"]],
    ["withdrawal message hash", ["settlement_output_withdrawal_hash_is_chain_verifier_and_adapter_bound", "withdrawal_message_hash_matches_native_payload_binding"]],
    ["relay package hash", ["renewal_relay_package_authorization_round_trips", "verifies_renewal_relay_package_commitment_and_authorization"]],
    ["recovery auth tag", ["recovery_auth_tag_matches_client_vector", "recovery_snapshot_roundtrip_uses_seed_bound_auth"]],
    ["fee root", ["fee_root_separates_protocol_and_relay_rows", "auction_verifier_rejects_wrong_fee_root_at_settlement"]],
    ["output bundle ref", ["output_recovery_bundle_rejects_mismatched_bundle_ref", "transcript_shape_policy_recomputes_output_bundle_commitment"]],
  ];
  for (const [surface, tests] of required) {
    for (const testName of tests) {
      assert(source.includes(testName), `${surface} is missing executable vector/binding coverage: ${testName}`);
    }
  }
});

test("FV-009/FV-010 route inventory keeps public and internal data boundaries classified", () => {
  const routeFiles = [
    "coordinator/src/main.rs",
    "prover/src/main.rs",
    "indexer/src/main.rs",
    "renewal_relayer/src/main.rs",
    "paymaster/src/server.ts",
  ];
  for (const file of routeFiles) {
    assert(readSource(file).length > 0, `${file} route source is missing`);
  }

  const requiredRoutes = {
    "coordinator/src/main.rs": [
      "/health",
      "/api/batches",
      "/api/batches/current",
      "/api/batches/{batch_id}/transcript",
      "/api/batches/{batch_id}/output-bundle",
      "/api/internal/batches/{batch_id}/orders",
      "/api/internal/batches/{batch_id}/witness",
      "/api/orders",
      "/api/orders/cancel",
    ],
    "prover/src/main.rs": [
      "/health",
      "/api/public/auction-keys",
      "/api/public/proof-jobs/{batch_id}",
      "/api/private/orders",
      "/api/private/withdrawals/prepare",
      "/api/internal/settlement-witnesses/{batch_id}",
      "/api/internal/proof-artifacts/{batch_id}",
    ],
    "indexer/src/main.rs": [
      "/health",
      "/api/deposits/confirmations",
      "/api/deposits/range/{start}/{end}",
      "/api/batches/{batch_id}/transcript",
      "/api/internal/batches/{batch_id}/transcript",
    ],
    "renewal_relayer/src/main.rs": [
      "/health",
      "/ready",
      "/packages",
      "/packages/{package_id}",
      "/packages/{package_id}/results",
      "/api/internal/relay/tick",
    ],
    "paymaster/src/server.ts": [
      "/health",
      "/privacy-signer/ensure",
      "/privacy-signer/relay",
      "/execute-outside",
    ],
  };

  for (const [file, paths] of Object.entries(requiredRoutes)) {
    const source = readSource(file);
    for (const path of paths) {
      assert(source.includes(`"${path}"`), `${file} is missing route ${path}`);
    }
  }

  const source = routeFiles.map((file) => readSource(file)).join("\n") + readSource("ops/certification-assurance.test.mjs");
  assert(source.includes("internal_routes_require_control_plane_bearer_token"));
  assert(source.includes("strict_ops_endpoints_require_internal_token"));
  assert(source.includes("public_proof_job_status_never_exposes_exact_reuse_state_or_count"));
  assert(source.includes("DEP-001 Zylith funding bridge activation is custody-bound and does not expose note secrets"));
});

test("ROUTE-001 public route schema denylist rejects private response types", () => {
  const forbiddenPublicReturnTypes = [
    ["SettlementTranscript", /\bSettlementTranscript\b/],
    ["SettlementWitness", /\bSettlementWitness\b/],
    ["SettlementSubmissionPlan", /\bSettlementSubmissionPlan\b/],
    ["ProofArtifactRecord", /\bProofArtifactRecord\b/],
    ["BatchOrderSet", /\bBatchOrderSet\b/],
  ];
  const publicHandlers = [
    ["coordinator/src/main.rs", "list_batches"],
    ["coordinator/src/main.rs", "current_batch"],
    ["coordinator/src/main.rs", "list_published_transcripts"],
    ["coordinator/src/main.rs", "get_published_transcript"],
    ["coordinator/src/main.rs", "get_published_output_bundle"],
    ["prover/src/main.rs", "public_auction_keys"],
    ["prover/src/main.rs", "public_auction_keys_fingerprint"],
    ["prover/src/main.rs", "get_public_proof_job"],
    ["prover/src/main.rs", "list_public_proof_jobs"],
    ["indexer/src/main.rs", "list_confirmed_deposits_range"],
    ["indexer/src/main.rs", "list_archived_transcripts"],
    ["indexer/src/main.rs", "get_archived_transcript"],
    ["indexer/src/main.rs", "get_archived_output_bundle"],
  ];

  for (const [file, handler] of publicHandlers) {
    const returnType = rustFunctionReturnType(readSource(file), handler);
    for (const [label, pattern] of forbiddenPublicReturnTypes) {
      assert(!pattern.test(returnType), `${file}:${handler} exposes forbidden public return type ${label}`);
    }
  }

  const depositRecord = extractRustStruct(readSource("core/src/types.rs"), "DepositActivationRecord");
  assert(!/\basset_id\b/.test(depositRecord), "public deposit activation record must not expose asset_id");
  assert(!/\bamount\b/.test(depositRecord), "public deposit activation record must not expose amount");
  assert(!/\bnote_commitment\b/.test(depositRecord), "public deposit activation record must not expose note_commitment");
});

test("ROUTE-002 generated backend route inventory has explicit privacy classification", () => {
  const expectedRoutes = {
    "coordinator/src/main.rs": [
      "/api/batches",
      "/api/batches/current",
      "/api/batches/submittable",
      "/api/batches/transcripts",
      "/api/batches/{batch_id}",
      "/api/batches/{batch_id}/output-bundle",
      "/api/batches/{batch_id}/transcript",
      "/api/internal/batches/proof-work",
      "/api/internal/batches/{batch_id}/artifacts",
      "/api/internal/batches/{batch_id}/orders",
      "/api/internal/batches/{batch_id}/settled-at",
      "/api/internal/batches/{batch_id}/transcript",
      "/api/internal/batches/{batch_id}/witness",
      "/api/internal/metrics",
      "/api/internal/renewal/cancel-markers",
      "/api/liquidity-positions/lifecycle",
      "/api/orders",
      "/api/orders/cancel",
      "/api/pairs/{base}/{quote}/batches/current",
      "/api/pairs/{base}/{quote}/batches/submittable",
      "/api/recovery/{account_id}/artifacts",
      "/api/recovery/{account_id}/artifacts/range/{start_sequence}/{end_sequence}",
      "/api/renewal/cancel-markers",
      "/api/renewal/cancel-markers/{cancel_marker}",
      "/api/renewal/cancel-witness/{cancel_marker}",
      "/api/settlement-reports/{batch_id}",
      "/api/wallet-vaults/{wallet_auth_id}",
      "/health",
    ],
    "indexer/src/main.rs": [
      "/api/batches/artifact-bundles",
      "/api/batches/artifact-bundles/epochs/{start_epoch}/{end_epoch}",
      "/api/batches/artifacts",
      "/api/batches/artifacts/epochs/{start_epoch}/{end_epoch}",
      "/api/batches/transcripts",
      "/api/batches/{batch_id}/output-bundle",
      "/api/batches/{batch_id}/transcript",
      "/api/deposits/confirmations",
      "/api/deposits/range/{start}/{end}",
      "/api/internal/batches/root-history/epochs/{start_epoch}/{end_epoch}",
      "/api/internal/batches/{batch_id}/artifacts",
      "/api/internal/batches/{batch_id}/settled-at",
      "/api/internal/batches/{batch_id}/transcript",
      "/api/internal/sync/deposits",
      "/api/privacy/artifact-aggregation-policy",
      "/api/privacy/claim-window-policy",
      "/api/privacy/withdrawal-amount-bucket-policy",
      "/health",
    ],
    "prover/src/main.rs": [
      "/api/internal/batches/{batch_id}/prepare",
      "/api/internal/health",
      "/api/internal/metrics",
      "/api/internal/onchain-submissions/{batch_id}",
      "/api/internal/onchain-submissions/{batch_id}/refresh",
      "/api/internal/proof-aggregation-manifests/epochs/{start_epoch}/{end_epoch}",
      "/api/internal/proof-aggregation-manifests/epochs/{start_epoch}/{end_epoch}/submit",
      "/api/internal/proof-artifacts/{batch_id}",
      "/api/internal/proof-jobs/{batch_id}",
      "/api/internal/proof-jobs/{batch_id}/prove",
      "/api/internal/proof-jobs/{batch_id}/submit",
      "/api/internal/settlement-plans/{batch_id}",
      "/api/internal/settlement-witnesses/{batch_id}",
      "/api/private/liquidity-positions/insertion-witness",
      "/api/private/liquidity-positions/lifecycle",
      "/api/private/liquidity-positions/state",
      "/api/private/liquidity-positions/state-update-witness",
      "/api/private/note-consolidations/prepare",
      "/api/private/note-consolidations/submit",
      "/api/private/orders",
      "/api/private/withdrawals/prepare",
      "/api/private/withdrawals/submit",
      "/api/public/auction-keys",
      "/api/public/auction-keys/fingerprint",
      "/api/public/proof-jobs",
      "/api/public/proof-jobs/{batch_id}",
      "/health",
    ],
    "renewal_relayer/src/main.rs": [
      "/api/internal/relay/tick",
      "/health",
      "/metrics",
      "/ops/alerts",
      "/ops/summary",
      "/packages",
      "/packages/{package_id}",
      "/packages/{package_id}/attest-order",
      "/packages/{package_id}/results",
      "/packages/{package_id}/results.csv",
      "/ready",
    ],
  };
  for (const [file, routes] of Object.entries(expectedRoutes)) {
    assert.deepEqual(extractRustRouteInventory(file), routes, `${file} route inventory changed without classification`);
  }
  assert.deepEqual(extractPaymasterRouteInventory(), ["/execute-outside", "/health", "/metrics", "/privacy-signer/ensure", "/privacy-signer/relay"]);

  for (const [file, routes] of Object.entries(expectedRoutes)) {
    const source = readSource(file);
    for (const route of routes) {
      assert(classifyRoute(file, route), `${file}:${route} has no explicit privacy classification`);
    }
    if (file !== "renewal_relayer/src/main.rs" && routes.some((route) => route.startsWith("/api/internal/"))) {
      assert.match(source, /starts_with\("\/api\/internal\/"\)[\s\S]*require_internal_auth/);
    }
  }
  assert.doesNotMatch(readSource("coordinator/src/main.rs"), /\/api\/liquidity\//);
  assert.match(readSource("renewal_relayer/src/main.rs"), /async fn metrics\([\s\S]*require_internal_auth/);
  assert.match(readSource("renewal_relayer/src/main.rs"), /async fn ops_summary\([\s\S]*require_internal_auth/);
  assert.match(readSource("renewal_relayer/src/main.rs"), /async fn ops_alerts\([\s\S]*require_internal_auth/);
  assert.match(readSource("renewal_relayer/src/main.rs"), /async fn trigger_tick\([\s\S]*require_internal_auth/);
});

test("ROUTE-003 generated public and capability route schema snapshot stays redacted", () => {
  const expectedPublicReturns = {
    "coordinator/src/main.rs": {
      list_batches: "Result<Json<Vec<PublicBatchSummary>>, StatusCode>",
      current_batch: "Result<Json<PublicBatchSummary>, StatusCode>",
      submittable_batch: "Result<Json<PublicBatchSummary>, StatusCode>",
      get_batch: "Result<Json<PublicBatchSummary>, StatusCode>",
      get_published_transcript: "Result<Json<PublicSettlementTranscript>, StatusCode>",
      list_published_transcripts: "Result<Json<Vec<PublicSettlementTranscript>>, StatusCode>",
      get_published_output_bundle: "Result<Json<zylith_core::OutputCiphertextBundle>, StatusCode>",
    },
    "prover/src/main.rs": {
      public_auction_keys: "Result<Json<PrivateExecutionKeyRegistry>, StatusCode>",
      public_auction_keys_fingerprint: "Result<Json<serde_json::Value>, StatusCode>",
      get_public_proof_job: "Result<Json<PublicProofJobStatus>, StatusCode>",
      list_public_proof_jobs: "Result<Json<Vec<PublicProofJobStatus>>, StatusCode>",
    },
    "indexer/src/main.rs": {
      list_confirmed_deposits_range: "Result<Json<DepositActivationRecordList>, StatusCode>",
      get_archived_transcript: "Result<Json<PublicSettlementTranscript>, StatusCode>",
      list_archived_transcripts: "Result<Json<Vec<PublicSettlementTranscript>>, StatusCode>",
      get_archived_output_bundle: "Result<Json<OutputCiphertextBundle>, StatusCode>",
    },
  };
  for (const [file, handlers] of Object.entries(expectedPublicReturns)) {
    const source = readSource(file);
    for (const [handler, expectedReturn] of Object.entries(handlers)) {
      assert.equal(rustFunctionReturnType(source, handler), expectedReturn, `${file}:${handler} schema drifted`);
    }
  }

  assert.equal(
    rustFunctionReturnType(readSource("coordinator/src/main.rs"), "query_private_settlement_report_by_batch"),
    "Result<Json<PrivateSettlementReport>, StatusCode>",
    "settlement report route must remain capability-scoped and not be treated as a public artifact",
  );

  const coreTypes = readSource("core/src/types.rs");
  const publicTranscript = extractRustStruct(coreTypes, "PublicSettlementTranscript");
  for (const field of [
    "matched_orders",
    "consumed_inputs",
    "output_notes",
    "output_note_preimages",
    "order_execution_reports",
    "output_recovery_records",
  ]) {
    assert(!new RegExp(`\\b${field}\\b`).test(publicTranscript), `public transcript exposes ${field}`);
  }
  const privateReportQuery = sourceAround(coreTypes, "struct PrivateSettlementReportQuery", 120);
  assert.match(privateReportQuery, /deny_unknown_fields/);
  const privateReport = extractRustStruct(coreTypes, "PrivateSettlementReport");
  assert.match(privateReport, /\bmatched_order_count_bucket\b/);
  assert.doesNotMatch(privateReport, /\bmatched_order_count\b/);
  const publicProofJob = extractRustStruct(readSource("prover/src/main.rs"), "PublicProofJobStatus");
  assert.doesNotMatch(publicProofJob, /\breuse_count\b/);
  assert.doesNotMatch(publicProofJob, /\bsettlement_witness\b/);
  assert.doesNotMatch(publicProofJob, /\bprivate_order_payload\b/);
  const publicDeposits = extractRustStruct(coreTypes, "DepositActivationRecord");
  assert.doesNotMatch(publicDeposits, /\b(asset_id|amount|note_commitment)\b/);
});

test("SURFACE-001 liquidity product surface has no retired hosted-liquidity entrypoints", () => {
  const retiredProductTerm = ["ma", "ker"].join("");
  const deletedSurfaces = [
    "client/src/domain/managedRenewalRelay.ts",
    "client/src/domain/managedRenewalRelay.test.ts",
    `ops/config/managed-${retiredProductTerm}-price-sources.mainnet.json`,
    `ops/managed-${retiredProductTerm}-chaos-test.mjs`,
    `ops/managed-${retiredProductTerm}-daemon.mjs`,
    `ops/managed-${retiredProductTerm}-daemon.test.mjs`,
    "renewal_relayer/MANAGED_SERVICE.md",
    `sdk/src/${retiredProductTerm}.ts`,
  ];

  for (const file of deletedSurfaces) {
    assert.equal(sourceExists(file), false, `${file} must stay removed`);
  }

  assert.equal(sourceExists("sdk/src/liquidity.ts"), true, "LP SDK surface is required");
  assert.doesNotMatch(readSource("coordinator/src/main.rs"), /\/api\/liquidity\//);
  assert.match(readSource("sdk/src/index.ts"), /liquidity\.js|from "\.\/liquidity"/);
  const orderLifecycleSource = readSource("client/src/domain/orderLifecycle.ts");
  const localOrderType = orderLifecycleSource.match(/export type LocalOrder = \{([\s\S]*?)\n\};/);
  const privateStrategyType = orderLifecycleSource.match(/export type PrivateStrategySummary = \{([\s\S]*?)\n\};/);
  assert(localOrderType, "LocalOrder type must be discoverable");
  assert(privateStrategyType, "PrivateStrategySummary type must be discoverable");
  assert.match(localOrderType[1], /\bliquidityBandPoints\?:/);
  assert.match(localOrderType[1], /\bliquidityBandAttribution\?:/);
  assert.match(privateStrategyType[1], /\bliquidity_curve_points\?:/);
  assert.match(privateStrategyType[1], /\bliquidity_inventory_cap\?:/);
  assert.match(readSource("client/src/domain/liquidityAutomationRelay.ts"), /LiquidityAutomationRelay/);
  assert.match(readSource("client/src/zylithWalletRuntime.ts"), /\bliquidity_attribution_batch_ids\b/);
  assert.match(readSource("client/src/zylithWalletRuntime.ts"), /\bliquidity_provider_attribution_artifacts\b/);
  assert.doesNotMatch(readSource("sdk/src/trader.ts"), /\bliquidity_attribution\b/);
});

test("SURFACE-002 generated ABI, env, and proof-input drift checks stay current", () => {
  const auctionVerifier = readSource("contracts/src/auction_verifier.cairo");
  assert.deepEqual(extractCairoInterfaceFunctions(auctionVerifier, "IAuctionVerifier"), [
    "propose_admin",
    "accept_admin",
    "set_pause_guardian",
    "pause",
    "unpause",
    "lock_operational_config",
    "set_authorized_settlement_account",
    "set_proof_program",
    "set_statement_proof_program_hash",
    "statement_proof_program_hash",
    "lock_proof_program",
    "set_proof_validity_blocks",
    "set_expected_starknet_os_config_hash",
    "set_shielded_asset_adapter",
    "set_deposit_root_registrar",
    "set_output_claim_delay_seconds",
    "set_protocol_fee_recipient",
    "propose_protocol_fee_recipient",
    "execute_protocol_fee_recipient",
    "set_relay_fee_recipient",
    "propose_relay_fee_recipient",
    "execute_relay_fee_recipient",
    "set_pair_fee_config",
    "propose_pair_fee_config",
    "execute_pair_fee_config",
    "cancel_renewal_parent_marker",
    "activate_deposit_root",
    "record_admission_root_with_proof_facts",
    "record_auction_result_with_proof_facts",
    "record_multi_pair_solution_with_proof_facts",
    "record_nullifier_roots_with_proof_facts",
    "record_renewal_roots_with_proof_facts",
    "record_liquidity_position_roots_with_proof_facts",
    "record_settlement_order_with_proof_facts",
    "record_settlement_input_membership_with_proof_facts",
    "record_settlement_output_recovery_with_proof_facts",
    "clear_unsettled_root_transition",
    "submit_note_consolidation_with_proof_facts",
    "submit_settlement_with_proof_facts",
    "submit_aggregate_settlements_with_proof_facts",
    "withdraw_settlement_output_to_strk20_with_proof_facts",
    "is_batch_settled",
    "is_consolidation_settled",
    "verified_admission_root",
    "verified_auction_transcript",
    "verified_multi_pair_solution",
    "output_note_root",
    "current_settlement_roots",
    "current_liquidity_position_root",
    "renewal_cancel_marker_recorded",
    "pair_fee_config",
    "pending_pair_fee_config",
    "admin_address",
    "pending_admin_address",
    "admin_transfer_pending",
    "pause_guardian_address",
    "is_paused",
    "proof_program_is_locked",
    "protocol_fee_recipient",
    "pending_protocol_fee_recipient",
    "relay_fee_recipient",
    "pending_relay_fee_recipient",
    "note_root_transition_count",
    "note_root_transition",
    "settlement_proof_message_hash",
    "note_consolidation_proof_message_hash",
    "withdrawal_proof_message_hash",
    "multi_pair_proof_message_hash",
  ]);
  assert.match(auctionVerifier, /fn set_pause_guardian[\s\S]*assert\(!guardian\.is_zero\(\), 'BAD_GUARDIAN'\)/);
  for (const removedAbi of ["withdraw_settlement_output_to_l2", "withdraw_fee", "set_fee_ledger"]) {
    assert.doesNotMatch(auctionVerifier, new RegExp(`\\b${removedAbi}\\b`));
  }

  const envCorpus = [
    "coordinator/src/main.rs",
    "prover/src/main.rs",
    "indexer/src/main.rs",
    "renewal_relayer/src/main.rs",
    "paymaster/src/config.ts",
    "core/src/auth.rs",
  ].map(readSource).join("\n");
  const envNames = extractEnvNames(envCorpus);
  for (const envName of [
    "ZYLITH_STARKNET_CHAIN_ID",
    "ZYLITH_CONTROL_PLANE_TOKEN",
    "ZYLITH_COORDINATOR_TRUSTED_PROXY_CIDRS",
    "ZYLITH_PROVER_TRUSTED_PROXY_CIDRS",
    "ZYLITH_INDEXER_TRUSTED_PROXY_CIDRS",
    "ZYLITH_RENEWAL_RELAY_TRUSTED_PROXY_CIDRS",
    "ZYLITH_PAYMASTER_TRUSTED_PROXY_CIDRS",
    "ZYLITH_PRIVATE_PAYLOAD_RETENTION_MS",
    "ZYLITH_PROVER_MAX_STORED_PRIVATE_PAYLOADS",
    "ZYLITH_NATIVE_TX_PROVER_URL",
    "ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS",
    "ZYLITH_MAX_LIQUIDITY_CURVE_BASE_AMOUNT",
    "ZYLITH_MAX_LIQUIDITY_CURVE_QUOTE_NOTIONAL",
    "ZYLITH_PAYMASTER_INTERNAL_TOKEN",
    "ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN",
    "ZYLITH_AUCTION_VERIFIER_ADDRESS",
    "ZYLITH_SHIELDED_ASSET_ADAPTER_ADDRESS",
  ]) {
    assert(envNames.includes(envName), `${envName} drifted out of service env surface`);
  }
  assert(!envNames.includes("ZYLITH_MAX_liquidity_CURVE_BASE_AMOUNT"));
  assert(!envNames.includes("ZYLITH_MAX_liquidity_CURVE_QUOTE_NOTIONAL"));

  const crypto = readSource("core/src/crypto.rs");
  for (const bindingSurface of [
    "build_stwo_serialized_input",
    "settlement_consumed_nullifier_root",
    "root_only_settlement_commitments",
    "liquidity_position_transition_root",
    "build_note_consolidation_serialized_input",
    "note_consolidation_commitment",
    "stwo_serialized_input_includes_expected_sections",
    "admission_serialized_input_binds_full_order_preimages",
    "note_consolidation_serialization_and_submission_plan_bind_roots",
  ]) {
    assert(crypto.includes(bindingSurface), `proof input surface missing ${bindingSurface}`);
  }
  const prover = readSource("prover/src/main.rs");
  for (const nativeSurface of [
    "build_native_proof_program_calldata",
    "native_proof_program_calldata_prefixes_verifier_address",
  ]) {
    assert(prover.includes(nativeSurface), `native proof input surface missing ${nativeSurface}`);
  }
  assert.match(
    readSource("ops/production-readiness-check.mjs"),
    /deployment manifest chain_id must match ZYLITH_STARKNET_CHAIN_ID/,
  );
});

test("LOG-001 backend log statements do not name private payload fields", () => {
  const forbiddenLogTerms = [
    /\bnote[_ -]?preimage\b/i,
    /\bmatched_orders\b/i,
    /\bconsumed_inputs\b/i,
    /\boutput_notes\b/i,
    /\bfee_rows\b/i,
    /\bprivate_report\b/i,
    /\brecovery_records\b/i,
    /\bsettlement_witness\b/i,
    /\bsignature_[rs]\b/i,
    /\bprivate_key\b/i,
    /\bsecret\b/i,
  ];
  const files = [
    ...sourceFilesUnder("coordinator/src"),
    ...sourceFilesUnder("prover/src"),
    ...sourceFilesUnder("indexer/src"),
    ...sourceFilesUnder("renewal_relayer/src"),
    ...sourceFilesUnder("paymaster/src"),
  ];
  const failures = [];
  for (const file of files) {
    for (const statement of logStatementWindows(file)) {
      for (const pattern of forbiddenLogTerms) {
        if (pattern.test(statement.text)) failures.push(`${file}:${statement.line}: ${pattern}`);
      }
    }
  }
  assert.deepEqual(failures, []);
});

test("LOG-002 runtime log redaction and retention controls are test-backed", () => {
  const source = [
    "coordinator/src/main.rs",
    "prover/src/main.rs",
    "renewal_relayer/src/main.rs",
    "paymaster/src/server.test.ts",
    "paymaster/src/starknetSubmitter.test.ts",
    "paymaster/src/submissionStore.test.ts",
  ].map(readSource).join("\n");
  for (const testOrControl of [
    "redacts private calldata and proof material from server error logs",
    "native_request_redaction_removes_private_witness_calldata",
    "native_prover_request_redaction_removes_nested_private_calldata",
    "native_prover_error_sanitizer_redacts_private_like_payloads",
    "default_private_payload_retention_is_short_operational_window",
    "prune_private_order_payloads",
    "batch_store_retention_prunes_old_empty_history_but_keeps_active_and_proof_work",
    "prune_store_removes_expired_packages_and_cancel_tombstones",
    "prunes expired replay records when loading after restart",
  ]) {
    assert(source.includes(testOrControl), `runtime log or retention coverage missing ${testOrControl}`);
  }
});

test("LOAD-001 rate-limit model isolates peer-IP subjects under abusive load", () => {
  const limiter = new TokenBucketLimiter(60);
  for (let i = 0; i < 60; i += 1) assert(limiter.allow("203.0.113.1"));
  assert.equal(limiter.allow("203.0.113.1"), false, "abusive peer should exhaust only its own bucket");
  for (let i = 2; i < 258; i += 1) {
    assert.equal(limiter.allow(`203.0.113.${i}`), true, `peer ${i} should retain its own budget`);
  }
});

test("LOAD-002 trusted proxy model rejects spoofed forwarded-for subjects", () => {
  assert.equal(rateLimitSubject({ peer: "198.51.100.4", forwardedFor: "10.0.0.9", trustedCidrs: [] }), "198.51.100.4");
  assert.equal(rateLimitSubject({ peer: "198.51.100.4", forwardedFor: "10.0.0.9", trustedCidrs: ["198.51.100.0/24"] }), "10.0.0.9");
  assert.equal(rateLimitSubject({ peer: "203.0.113.4", forwardedFor: "10.0.0.9", trustedCidrs: ["198.51.100.0/24"] }), "203.0.113.4");
});

test("LOAD-003 service route tests cover public rate limits and trusted proxy abuse", () => {
  const source = [
    "coordinator/src/main.rs",
    "prover/src/main.rs",
    "indexer/src/main.rs",
    "renewal_relayer/src/main.rs",
    "paymaster/src/server.test.ts",
  ].map(readSource).join("\n");
  for (const testName of [
    "public_batch_reads_are_rate_limited",
    "renewal_cancel_public_reads_are_rate_limited",
    "rate_limit_subject_uses_forwarded_headers_only_from_trusted_proxy_cidrs",
    "public_proof_job_reads_are_rate_limited",
    "rate_limit_subject_uses_peer_ip_without_trusted_proxy_cidr",
    "rate_limit_subject_uses_forwarded_ip_only_from_trusted_cidr",
    "trusted_proxy_rate_limit_subject_ignores_untrusted_forwarded_headers",
    "trusted_proxy_rate_limit_subject_accepts_forwarded_headers_from_trusted_cidr",
    "ignores forwarded IP headers from untrusted direct clients",
    "uses valid forwarded client IPs only from trusted proxies",
    "ignores malformed forwarded IP headers even from trusted proxies",
  ]) {
    assert(source.includes(testName), `load/proxy abuse coverage missing ${testName}`);
  }
});

test("DEP-001 Zylith funding bridge activation is custody-bound and does not expose note secrets", () => {
  const bridge = readSource("contracts/src/privacy_deposit_bridge.cairo");
  const registry = readSource("contracts/src/commitment_registry.cairo");
  const coreTypes = readSource("core/src/types.rs");
  const indexer = readSource("indexer/src/main.rs");

  const privacyInvokeParams = [...bridge.matchAll(/fn\s+privacy_invoke\s*\(([\s\S]*?)\)\s*->/g)].map((match) => match[1]);
  assert(privacyInvokeParams.length >= 1, "privacy_invoke signatures must be scanned");
  for (const params of privacyInvokeParams) {
    assert.doesNotMatch(params, /\bdeposit_nonce\b/);
    assert.doesNotMatch(params, /\btoken_address\b/);
    assert.match(params, /\bfunding_commitments\b/);
    assert.match(params, /\bdeposit_roots\b/);
    assert.match(params, /\bencrypted_note_activations\b/);
    assert.match(params, /\bnote_commitments\b/);
    assert.match(params, /\basset_ids\b/);
    assert.match(params, /\bamounts\b/);
    assert.match(params, /\bwithdraw_authorities\b/);
  }
  assert.match(bridge, /get_caller_address\(\) == self\.privacy_pool\.read\(\)/);
  assert.match(
    bridge,
    /if\s+funding_commitments\.len\(\)\s*==\s*0\s*\{[\s\S]*open_note_deposits\s*\.\s*append\(/,
    "STRK20 exit claims must return one OpenNoteDeposit through privacy_invoke",
  );
  assert.match(
    bridge,
    /register_funding_activation_internal\([\s\S]*funding_commitments[\s\S]*deposit_roots[\s\S]*encrypted_note_activations[\s\S]*note_commitments[\s\S]*asset_ids[\s\S]*amounts[\s\S]*withdraw_authorities[\s\S]*\);[\s\S]*open_note_deposits\.span\(\)/,
    "funding activation must still return no open deposits",
  );
  assert.match(bridge, /DEPOSIT_ROOT_MISMATCH/);
  assert.match(bridge, /TOKEN_CUSTODY_LOW/);
  assert.match(bridge, /escrowed_asset_amounts/);

  assert.match(registry, /\bregister_funding_activation\b/);

  const depositCallArguments = extractRustStruct(coreTypes, "DepositCallArguments");
  assert.match(coreTypes, /pub struct DepositActivationRecord/);
  assert.match(depositCallArguments, /\bfunding_commitments\b/);
  assert.match(depositCallArguments, /\bdeposit_roots\b/);
  assert.match(depositCallArguments, /\bencrypted_note_activations\b/);
  assert.match(depositCallArguments, /\basset_ids\b/);
  assert.match(depositCallArguments, /\bamounts\b/);
  assert.match(depositCallArguments, /\bnote_commitments\b/);
  assert.match(depositCallArguments, /\bwithdraw_authorities\b/);
  assert.doesNotMatch(depositCallArguments, /\btoken_address\b/);

  assert.match(indexer, /DepositActivationRecordList/);
});

function assertPositiveAmount(amount) {
  if (BigInt(amount) <= 0n) throw new Error("amount must be positive");
}

function assertRejects(action) {
  assert.throws(action, /.+/);
}

function sum(values) {
  let total = 0n;
  for (const value of values) total += BigInt(value);
  return total;
}

function sumValues(record) {
  return sum(Object.values(record));
}

function feeRoot(rows) {
  return JSON.stringify(
    rows
      .filter((row) => BigInt(row.amount) > 0n)
      .map((row) => ({
        domain: row.domain,
        asset: row.asset,
        recipient: row.recipient,
        amount: BigInt(row.amount).toString(),
      }))
      .sort((left, right) => `${left.domain}:${left.asset}`.localeCompare(`${right.domain}:${right.asset}`))
  );
}

function assertFeeBps({ fillAmount, feeAmount, configuredBps }) {
  if (feeAmount * 10_000n > fillAmount * configuredBps) {
    throw new Error("fee exceeds configured bps");
  }
}

function assertFeeRootMatches(expected, rows) {
  const actual = feeRoot(rows);
  if (actual !== expected) throw new Error("fee root mismatch");
}

class TokenBucketLimiter {
  constructor(limit) {
    this.limit = limit;
    this.buckets = new Map();
  }

  allow(subject) {
    const used = this.buckets.get(subject) ?? 0;
    if (used >= this.limit) return false;
    this.buckets.set(subject, used + 1);
    return true;
  }
}

function rateLimitSubject({ peer, forwardedFor, trustedCidrs }) {
  return trustedCidrs.some((cidr) => ipInCidr(peer, cidr)) && forwardedFor ? forwardedFor : peer;
}

function ipInCidr(ip, cidr) {
  const [base, bitsText] = cidr.split("/");
  const bits = Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

function ipToInt(ip) {
  return ip
    .split(".")
    .map((part) => Number(part))
    .reduce((acc, part) => ((acc << 8) + part) >>> 0, 0);
}

function readSource(path) {
  return readFileSync(resolveSourcePath(path), "utf8");
}

function extractRustStruct(source, name) {
  const match = source.match(new RegExp(`(?:pub\\s+)?struct ${name} \\{([\\s\\S]*?)\\n\\}`));
  assert(match, `${name} must exist`);
  return match[1];
}

function sourceAround(source, marker, lineCount) {
  const index = source.indexOf(marker);
  assert.notEqual(index, -1, `${marker} must exist`);
  return source.slice(Math.max(0, index - 300), index + lineCount * 80);
}

function rustFunctionReturnType(source, name) {
  const match = source.match(new RegExp(`async fn ${name}\\b[\\s\\S]*?\\)\\s*->\\s*([^\\{]+)\\{`));
  assert(match, `${name} return type must be discoverable from source`);
  return match[1].replace(/\s+/g, " ").trim();
}

function extractCairoInterfaceFunctions(source, name) {
  const match = source.match(new RegExp(`pub trait ${name}<[\\s\\S]*?\\{([\\s\\S]*?)\\n\\}`));
  assert(match, `${name} interface must exist`);
  return [...match[1].matchAll(/\bfn\s+([A-Za-z0-9_]+)\b/g)].map((entry) => entry[1]);
}

function extractEnvNames(source) {
  return [
    ...new Set([
      ...[...source.matchAll(/"((?:ZYLITH|SN)_[A-Z0-9_]+)"/g)].map((match) => match[1]),
      ...[...source.matchAll(/\benv\.((?:ZYLITH|SN)_[A-Z0-9_]+)\b/g)].map((match) => match[1]),
      ...[...source.matchAll(/\bprocess\.env\.((?:ZYLITH|SN)_[A-Z0-9_]+)\b/g)].map((match) => match[1]),
    ]),
  ].sort();
}

function extractRustRouteInventory(file) {
  const source = readSource(file).split(/\n#\[cfg\(test\)\]\s*\nmod tests/)[0];
  return [...new Set([...source.matchAll(/\.route\(\s*"([^"]+)"/g)].map((match) => match[1]))].sort();
}

function extractPaymasterRouteInventory() {
  const source = readSource("paymaster/src/server.ts");
  return [...new Set([...source.matchAll(/request\.url\s*(?:===|!==)\s*"([^"]+)"/g)].map((match) => match[1]))].sort();
}

function classifyRoute(file, route) {
  if (route === "/health" || route === "/ready") return "public-health";
  if (route.startsWith("/api/internal/")) return "internal-control-plane";
  if (file === "prover/src/main.rs" && route.startsWith("/api/private/")) return "private-proof-payload";
  if (file === "prover/src/main.rs" && route.startsWith("/api/public/")) return "public-redacted";
  if (file === "coordinator/src/main.rs" && route.startsWith("/api/wallet-vaults/")) return "wallet-vault-authenticated";
  if (route.startsWith("/api/recovery/") || route.startsWith("/api/settlement-reports/")) return "recovery-authenticated";
  if (route.startsWith("/api/renewal/cancel-")) return "public-renewal-state";
  if (route.includes("/attribution/")) return "public-delayed-attribution";
  if (file === "renewal_relayer/src/main.rs" && ["/metrics", "/ops/alerts", "/ops/summary"].includes(route)) {
    return "internal-ops";
  }
  if (file === "renewal_relayer/src/main.rs" && route.startsWith("/packages")) return "package-authenticated";
  if (route.startsWith("/api/privacy/")) return "public-policy";
  if (route.startsWith("/api/batches") || route.startsWith("/api/pairs/")) return "public-artifact";
  if (route.startsWith("/api/deposits")) return "public-chain-index";
  if (route.startsWith("/api/liquidity-positions/")) return "public-liquidity-lifecycle-ingress";
  if (route.startsWith("/api/orders")) return "public-order-ingress";
  return null;
}

function sourceFilesUnder(dir) {
  const root = resolveSourcePath(dir);
  const files = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      files.push(...sourceFilesUnderAbsolute(path));
    } else if (/\.(rs|ts|js|mjs)$/.test(entry)) {
      files.push(path);
    }
  }
  return files;
}

function sourceFilesUnderAbsolute(root) {
  const files = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      files.push(...sourceFilesUnderAbsolute(path));
    } else if (/\.(rs|ts|js|mjs)$/.test(entry)) {
      files.push(path);
    }
  }
  return files;
}

function logStatementWindows(file) {
  const lines = readFileSync(file, "utf8").split("\n");
  const windows = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (/\b(eprintln!|println!|console\.(log|error|warn)|tracing::(info|warn|error|debug)!|log::(info|warn|error|debug)!)\b/.test(lines[index])) {
      windows.push({
        line: index + 1,
        text: lines.slice(index, Math.min(lines.length, index + 6)).join("\n"),
      });
    }
  }
  return windows;
}

function readFile(path) {
  return readSource(path);
}

function readAllSourceText() {
  const dirs = [
    "core/src",
    "contracts/tests",
    "proof_program/tests",
    "stwo_statement/src",
    "wallet_wasm/src",
    "client/src",
  ];
  return dirs.map((dir) => readRecursive(resolveSourcePath(dir))).join("\n");
}

function readRecursive(path) {
  const stat = statSync(path);
  if (stat.isFile()) return readFileSync(path, "utf8");
  return readdirSync(path)
    .map((entry) => readRecursive(join(path, entry)))
    .join("\n");
}

function sourceExists(path) {
  return candidateSourcePaths(path).some((candidate) => existsSync(candidate));
}

function resolveSourcePath(path) {
  const candidate = candidateSourcePaths(path).find((entry) => existsSync(entry));
  return candidate ?? join(repoRoot, path);
}

function candidateSourcePaths(path) {
  const siblingRoot = resolve(repoRoot, "..");
  const candidates = [join(repoRoot, path)];
  const remapped = splitRepoSourcePath(siblingRoot, path);
  if (remapped) candidates.push(remapped);
  return candidates;
}

function splitRepoSourcePath(siblingRoot, path) {
  if (path.startsWith("client/")) {
    return join(siblingRoot, "client", path.slice("client/".length));
  }
  if (path.startsWith("sdk/")) {
    return join(siblingRoot, "client", path);
  }
  if (path.startsWith("wallet_wasm/")) {
    return join(siblingRoot, "client", path);
  }
  if (
    path.startsWith("contracts/") ||
    path.startsWith("proof_program/") ||
    path.startsWith("stwo_statement/") ||
    path.startsWith("smoke/")
  ) {
    return join(siblingRoot, "protocol", path);
  }
  return null;
}

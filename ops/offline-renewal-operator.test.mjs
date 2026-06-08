import assert from "node:assert/strict";
import test from "node:test";

import {
  renewalPackageCommitment,
  validatePackage,
} from "./offline-renewal-operator.mjs";

test("offline renewal operator rejects tampered package commitments", () => {
  const renewalPackage = samplePackage();
  renewalPackage.package_commitment = renewalPackageCommitment(renewalPackage);
  assert.doesNotThrow(() => validatePackage(renewalPackage));

  const tampered = structuredClone(renewalPackage);
  tampered.slots[0].order_commitment = "0xorder-tampered";
  assert.throws(
    () => validatePackage(tampered),
    /package commitment does not match package body/,
  );
});

function samplePackage() {
  return {
    version: 1,
    package_id: "pkg-1",
    package_commitment: "",
    created_at_unix_ms: 1,
    pair: "STRK/USDC",
    start_epoch: 1,
    end_epoch: 1,
    slot_count: 1,
    relay_mode: "SelfRelay",
    parent_cancel_authority: "0xparent",
    parent_cancel_marker: "0xcancel",
    relay_policy: {
      coordinator_url: "https://coordinator.example",
      prover_url: "https://prover.example",
      submission_safety_buffer_ms: 1000,
      max_submission_delay_ms: 0,
    },
    slots: [
      {
        slot_id: "pkg-1:1",
        pair: "STRK/USDC",
        batch_id: "STRK-USDC-1",
        epoch_id: 1,
        parent_child_index: 1,
        order_commitment: "0xorder1",
        funding_note_commitments: ["0xlabel"],
        ingress_request: { order_submission: {} },
      },
    ],
  };
}

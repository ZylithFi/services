import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizedNetworkErrorMessage,
  relayPackageOnce,
  renewalPackageCommitment,
  validatePackage,
} from "./offline-renewal-operator.mjs";

test("offline renewal operator rejects tampered package commitments", () => {
  const renewalPackage = samplePackage();
  renewalPackage.package_commitment = renewalPackageCommitment(renewalPackage);
  renewalPackage.access_token = "relay-token";
  assert.doesNotThrow(() => validatePackage(renewalPackage));

  const tampered = structuredClone(renewalPackage);
  tampered.slots[0].order_commitment = "0xorder-tampered";
  assert.throws(
    () => validatePackage(tampered),
    /package commitment does not match package body/,
  );
});

test("offline renewal operator normalizes abort and network failures", () => {
  assert.equal(
    normalizedNetworkErrorMessage(new DOMException("Signal is aborted without reason", "AbortError"), 1200),
    "request timed out after 1200ms",
  );
  assert.equal(
    normalizedNetworkErrorMessage(new Error("fetch failed")),
    "network request failed",
  );
});

test("offline renewal operator injects and verifies package-bound private ingress", async () => {
  const renewalPackage = samplePackage();
  renewalPackage.package_commitment = renewalPackageCommitment(renewalPackage);
  const state = { submitted_order_commitments: [], submitted_slots: [] };
  let ingressBody;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = String(input);
    if (url.includes("/api/renewal/cancel-markers/")) {
      return jsonResponse({ recorded: false });
    }
    if (url.includes("/api/pairs/STRK/USDC/batches/submittable")) {
      return jsonResponse({
        batch_id: "STRK-USDC-1",
        pair_id: "STRK/USDC",
        epoch_id: 1,
        close_time_unix_ms: Date.now() + 60_000,
        status: "Open",
      });
    }
    if (url.includes("/api/private/orders")) {
      ingressBody = JSON.parse(String(init?.body ?? "{}"));
      return jsonResponse({
        receipt: {
          order_commitment: "0xorder1",
          pair_id: "STRK/USDC",
          batch_id: "STRK-USDC-1",
          epoch_id: 1,
          relay_mode: "SelfRelay",
          renewal_package_id: "pkg-1",
          renewal_package_commitment: renewalPackage.package_commitment,
        },
        coordinator_submission: {
          order_commitment: "0xorder1",
          batch_id: "STRK-USDC-1",
        },
      });
    }
    if (url.includes("/api/orders")) {
      return jsonResponse({
        order_commitment: "0xorder1",
        batch_id: "STRK-USDC-1",
        accepted_at_unix_ms: Date.now(),
      });
    }
    return new Response(null, { status: 404 });
  };
  try {
    const results = await relayPackageOnce(renewalPackage, state, {
      requestTimeoutMs: 1_000,
    });
    assert.equal(results[0]?.status, "submitted");
    assert.deepEqual(ingressBody, {
      order_submission: {},
      renewal_package_id: "pkg-1",
      renewal_package_commitment: renewalPackage.package_commitment,
      renewal_relay_mode: "SelfRelay",
      renewal_slot_order_commitment: "0xorder1",
      renewal_slot_pair: "STRK/USDC",
      renewal_slot_batch_id: "STRK-USDC-1",
      renewal_slot_epoch_id: 1,
    });
    assert.deepEqual(state.submitted_order_commitments, ["0xorder1"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("offline renewal operator rejects private ingress receipts without package binding", async () => {
  const renewalPackage = samplePackage();
  renewalPackage.package_commitment = renewalPackageCommitment(renewalPackage);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.includes("/api/renewal/cancel-markers/")) {
      return jsonResponse({ recorded: false });
    }
    if (url.includes("/api/pairs/STRK/USDC/batches/submittable")) {
      return jsonResponse({
        batch_id: "STRK-USDC-1",
        pair_id: "STRK/USDC",
        epoch_id: 1,
        close_time_unix_ms: Date.now() + 60_000,
        status: "Open",
      });
    }
    if (url.includes("/api/private/orders")) {
      return jsonResponse({
        receipt: {
          order_commitment: "0xorder1",
          pair_id: "STRK/USDC",
          batch_id: "STRK-USDC-1",
          epoch_id: 1,
          relay_mode: "SelfRelay",
          renewal_package_id: "pkg-1",
          renewal_package_commitment: "0xwrong",
        },
        coordinator_submission: {
          order_commitment: "0xorder1",
          batch_id: "STRK-USDC-1",
        },
      });
    }
    return new Response(null, { status: 404 });
  };
  try {
    const results = await relayPackageOnce(
      renewalPackage,
      { submitted_order_commitments: [], submitted_slots: [] },
      { requestTimeoutMs: 1_000 },
    );
    assert.equal(results[0]?.status, "failed");
    assert.match(results[0]?.detail, /package commitment mismatch/);
  } finally {
    globalThis.fetch = originalFetch;
  }
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

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

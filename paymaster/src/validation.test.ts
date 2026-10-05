import { describe, expect, it } from "vitest";
import { selector } from "starknet";

import type { PaymasterConfig } from "./config.js";
import { validateExecuteOutsideRequest } from "./validation.js";

const config: Pick<
  PaymasterConfig,
  | "accountAddress"
  | "allowedContracts"
  | "allowedEntrypoints"
  | "chainId"
  | "proofRequiredEntrypoints"
  | "privacyBridgeAddress"
  | "privacyPoolAddress"
  | "feeTokenAddress"
> = {
  accountAddress: "0xabc",
  chainId: "0x534e5f5345504f4c4941",
  allowedContracts: new Set(["0x123", "0x789"]),
  allowedEntrypoints: new Set(["apply_actions"]),
  proofRequiredEntrypoints: new Set(["apply_actions"]),
  privacyBridgeAddress: "0x789",
  privacyPoolAddress: "0x123",
  feeTokenAddress: "0x456",
};

describe("validateExecuteOutsideRequest", () => {
  it("accepts a matching SNIP-9 V2 request", () => {
    const request = baseRequest();
    const validated = validateExecuteOutsideRequest(request, config, 1_700_000_000);

    expect(validated.paymaster_address).toBe("0xabc");
    expect(validated.call.contract_address).toBe("0x123");
    expect(validated.proof_facts).toEqual(["0x1"]);
  });

  it("rejects unknown execute-outside request fields", () => {
    const request = baseRequest() as ReturnType<typeof baseRequest> & { unsupported_payload?: string };
    request.unsupported_payload = "unexpected";

    expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
      "request.unsupported_payload is not supported"
    );
  });

  it("rejects unknown nested execute-outside fields", () => {
    const request = baseRequest();
    (request.call as { unsupported_selector?: string }).unsupported_selector = "unexpected";
    expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
      "call.unsupported_selector is not supported"
    );

    const outsideRequest = baseRequest();
    (outsideRequest.outside_transaction.outsideExecution as { unsupported_window?: string }).unsupported_window =
      "unexpected";
    expect(() => validateExecuteOutsideRequest(outsideRequest, config, 1_700_000_000)).toThrow(
      "outside_transaction.outsideExecution.unsupported_window is not supported"
    );

    const callRequest = baseRequest();
    (callRequest.outside_transaction.outsideExecution.calls[0] as { unsupported_call?: string })
      .unsupported_call = "unexpected";
    expect(() => validateExecuteOutsideRequest(callRequest, config, 1_700_000_000)).toThrow(
      "outsideExecution.calls[0].unsupported_call is not supported"
    );
  });

  it("rejects an outside execution whose signed call differs from the payload call", () => {
    const request = baseRequest();
    request.outside_transaction.outsideExecution.calls[0]!.calldata = ["0x3"];

    expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
      "outside execution calldata does not match payload call"
    );
  });

  it("rejects calls outside the privacy-pool allowlist", () => {
    const request = baseRequest();
    request.call.contract_address = "0x456";

    expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
      "call contract is not allowlisted"
    );
  });

  it("rejects malformed outside execution nonce and missing signature", () => {
    const missingNonce = baseRequest();
    delete (missingNonce.outside_transaction.outsideExecution as { nonce?: unknown }).nonce;

    expect(() => validateExecuteOutsideRequest(missingNonce, config, 1_700_000_000)).toThrow(
      "outsideExecution.nonce must be a felt string or non-negative integer"
    );

    const missingSignature = baseRequest();
    missingSignature.outside_transaction.signature = [];

    expect(() => validateExecuteOutsideRequest(missingSignature, config, 1_700_000_000)).toThrow(
      "outside_transaction.signature must be a non-empty string array"
    );
  });

  it("accepts Starknet.js object-shaped outside execution signatures", () => {
    const request = baseRequest();
    request.outside_transaction.signature = { r: "0xa", s: "0xb" };
    const validated = validateExecuteOutsideRequest(request, config, 1_700_000_000);

    expect(validated.signer_address).toBe("0x999");
  });

  it("rejects long-lived outside execution windows", () => {
    const request = baseRequest();
    request.outside_transaction.outsideExecution.execute_before = "1700007200";

    expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
      "outside execution time window is too long"
    );
  });

  it("accepts direct proof-bearing apply_actions relays", () => {
    const request = baseRequest();
    delete (request as { outside_transaction?: unknown }).outside_transaction;

    const validated = validateExecuteOutsideRequest(request, config, 1_700_000_000);

    expect(validated.call.entrypoint).toBe("apply_actions");
    expect(validated.outside_transaction).toBeUndefined();
  });

  it("rejects a claim without its atomic bridge authorization", () => {
    const request = baseRequest();
    delete (request as { authorization_call?: unknown }).authorization_call;
    delete (request as { outside_transaction?: unknown }).outside_transaction;

    expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
      "requires an atomic Zylith claim authorization"
    );
  });

  it("rejects apply_actions on any contract except the pinned privacy pool", () => {
    const request = baseRequest();
    request.call.contract_address = "0x789";
    request.outside_transaction.outsideExecution.calls[0]!.to = "0x789";

    expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
      "must target the pinned privacy pool"
    );
  });

  it("rejects exit and sponsoring-principal mismatches", () => {
    const exitMismatch = baseRequest();
    exitMismatch.authorization_call.calldata[0] = "0x667";
    expect(() => validateExecuteOutsideRequest(exitMismatch, config, 1_700_000_000)).toThrow(
      "requires one exactly bound Zylith claim"
    );

    const principalMismatch = baseRequest();
    principalMismatch.signer_address = "0x998";
    delete (principalMismatch as { outside_transaction?: unknown }).outside_transaction;
    expect(() => validateExecuteOutsideRequest(principalMismatch, config, 1_700_000_000)).toThrow(
      "requires one exactly bound Zylith claim"
    );
  });

  it("rejects a claim whose exact open note differs from its authorization", () => {
    const request = baseRequest();
    request.call.calldata[17] = "0x778";
    delete (request as { outside_transaction?: unknown }).outside_transaction;

    expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
      "requires one exactly bound Zylith claim"
    );
  });

  it("requires exactly one structurally bound pool-fee reimbursement", () => {
    for (const [index, value] of [[2, "0xdef"], [3, "0x457"], [4, "0x0"]] as const) {
      const request = baseRequest();
      request.call.calldata[index] = value;
      request.outside_transaction.outsideExecution.calls[0]!.calldata = request.call.calldata;
      expect(() => validateExecuteOutsideRequest(request, config, 1_700_000_000)).toThrow(
        "requires one exactly bound Zylith claim",
      );
    }
  });

  it("rejects privacy-pool actions that are not bound to the Zylith bridge", () => {
    const missing = baseRequest();
    missing.call.calldata = ["0x1", "0x2", "0x777", "0x456", "0x1"];
    missing.outside_transaction.outsideExecution.calls[0]!.calldata = missing.call.calldata;
    expect(() => validateExecuteOutsideRequest(missing, config, 1_700_000_000)).toThrow(
      "requires exactly one Zylith bridge invoke"
    );

    const foreign = baseRequest();
    foreign.call.calldata = [
      "0x2",
      "0xa", "0x789", "0x1", "0x0",
      "0xa", "0x999", "0x1", "0x0",
    ];
    foreign.outside_transaction.outsideExecution.calls[0]!.calldata = foreign.call.calldata;
    expect(() => validateExecuteOutsideRequest(foreign, config, 1_700_000_000)).toThrow(
      /exactly bound Zylith claim|cannot invoke another contract/
    );

    const duplicate = baseRequest();
    duplicate.call.calldata = [
      "0x2",
      "0xa", "0x789", "0x1", "0x0",
      "0xa", "0x789", "0x1", "0x0",
    ];
    duplicate.outside_transaction.outsideExecution.calls[0]!.calldata = duplicate.call.calldata;
    expect(() => validateExecuteOutsideRequest(duplicate, config, 1_700_000_000)).toThrow(
      "requires exactly one Zylith bridge invoke"
    );
  });

  it("accepts a direct proof-bearing residual recovery request", () => {
    const request = baseRequest();
    request.call.entrypoint = "request_residual_recovery";
    request.call.calldata = ["0x1", "0x2", "0x3"];
    delete (request as { authorization_call?: unknown }).authorization_call;
    delete (request as { outside_transaction?: unknown }).outside_transaction;
    const recoveryConfig = {
      ...config,
      allowedEntrypoints: new Set(["request_residual_recovery"]),
      proofRequiredEntrypoints: new Set(["request_residual_recovery"]),
    };

    const validated = validateExecuteOutsideRequest(request, recoveryConfig, 1_700_000_000);

    expect(validated.call.entrypoint).toBe("request_residual_recovery");
    expect(validated.outside_transaction).toBeUndefined();
  });

  it("rejects direct settlement relays even when settlement is allowlisted", () => {
    const request = baseRequest();
    request.call.entrypoint = "submit_settlement_with_proof_facts";
    request.call.calldata = ["0x1", "0x2", "0x3"];
    delete (request as { outside_transaction?: unknown }).outside_transaction;

    const settlementConfig = {
      ...config,
      allowedEntrypoints: new Set(["submit_settlement_with_proof_facts"]),
      proofRequiredEntrypoints: new Set(["submit_settlement_with_proof_facts"]),
    };

    expect(() =>
      validateExecuteOutsideRequest(request, settlementConfig, 1_700_000_000)
    ).toThrow("call entrypoint is not supported by paymaster");
  });

  it("rejects direct proof-bearing calls outside the supported entrypoint set", () => {
    const request = baseRequest();
    request.call.entrypoint = "unsupported_private_call";
    request.call.calldata = ["0x1", "0x2", "0x3", "0x4", "0x5", "0x6", "0x7", "0x64"];
    delete (request as { outside_transaction?: unknown }).outside_transaction;

    const unsupportedEntrypointConfig = {
      ...config,
      allowedEntrypoints: new Set(["unsupported_private_call"]),
      proofRequiredEntrypoints: new Set(["unsupported_private_call"]),
    };
    expect(() =>
      validateExecuteOutsideRequest(request, unsupportedEntrypointConfig, 1_700_000_000)
    ).toThrow("call entrypoint is not supported by paymaster");
  });

  it("rejects direct relays for unsupported entrypoints", () => {
    const request = baseRequest();
    request.call.entrypoint = "cancel_private_order";
    request.outside_transaction.outsideExecution.calls[0]!.selector =
      String(selector.getSelectorFromName("cancel_private_order"));
    delete (request as { outside_transaction?: unknown }).outside_transaction;
    delete (request as { proof?: unknown }).proof;
    delete (request as { proof_facts?: unknown }).proof_facts;

    const directConfig = {
      ...config,
      allowedEntrypoints: new Set(["cancel_private_order"]),
      proofRequiredEntrypoints: new Set<string>()
    };
    expect(() => validateExecuteOutsideRequest(request, directConfig, 1_700_000_000)).toThrow(
      "call entrypoint is not supported by paymaster"
    );
  });

  it("rejects supported entrypoints that are not configured as proof-required", () => {
    const request = baseRequest();
    const unsafeConfig = {
      ...config,
      proofRequiredEntrypoints: new Set<string>(),
    };

    expect(() =>
      validateExecuteOutsideRequest(request, unsafeConfig, 1_700_000_000)
    ).toThrow("supported paymaster entrypoint must be proof-required");
  });
});

function baseRequest() {
  const calldata = [
    "0x3",
    "0x2", "0xabc", "0x456", "0x5",
    "0x7", "0xaaa", "0xbbb", "0xccc", "0x456", "0x999",
    "0xa", "0x789", "0x9",
    "0x0", "0x2", "0x666", "0x999",
    "0x0", "0x0", "0x0", "0x0", "0x0",
  ];
  return {
    chain_id: "0x534e5f5345504f4c4941",
    signer_address: "0x999",
    paymaster_address: "0xabc",
    call: {
      contract_address: "0x123",
      entrypoint: "apply_actions",
      calldata
    },
    authorization_call: {
      contract_address: "0x789",
      entrypoint: "authorize_strk20_exit_claim",
      calldata: ["0x666", "0x999", "0x1", "0x2"],
    },
    outside_transaction: {
      outsideExecution: {
        caller: "0xabc",
        nonce: "0x9",
        execute_after: "1699999940",
        execute_before: "1700003600",
        calls: [
          {
            to: "0x123",
            selector: "0x246333a752c1ac637ff1591c5c885e27d56060d241a29aad8475072da0777db",
            calldata
          }
        ]
      },
      signerAddress: "0x999",
      version: "2",
      signature: ["0xa", "0xb"]
    },
    proof: "proof-bytes",
    proof_facts: ["0x1"]
  };
}

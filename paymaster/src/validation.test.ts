import { describe, expect, it } from "vitest";
import { selector } from "starknet";

import type { PaymasterConfig } from "./config.js";
import {
  validateEnsurePrivacySignerRequest,
  validateExecuteOutsideRequest,
  validateRelayPrivacySignerRequest
} from "./validation.js";

const config: Pick<
  PaymasterConfig,
  | "accountAddress"
  | "allowedContracts"
  | "allowedEntrypoints"
  | "chainId"
  | "proofRequiredEntrypoints"
> = {
  accountAddress: "0xabc",
  chainId: "0x534e5f5345504f4c4941",
  allowedContracts: new Set(["0x123"]),
  allowedEntrypoints: new Set(["apply_actions"]),
  proofRequiredEntrypoints: new Set(["apply_actions"]),
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

    expect(validated.signer_address).toBe("0x777");
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
    ).toThrow("direct paymaster relay requires proof facts for supported direct calls");
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

describe("validateEnsurePrivacySignerRequest", () => {
  it("rejects unknown signer deployment fields", () => {
    expect(() =>
      validateEnsurePrivacySignerRequest(
        {
          signer_public_key: "0x1",
          salt: "0x2",
          class_hash: "0x123",
          unsupported_owner: "0xabc",
        },
        { privacySignerClassHash: "0x123" }
      )
    ).toThrow("request.unsupported_owner is not supported");
  });
});

describe("validateRelayPrivacySignerRequest", () => {
  it("accepts a signer-owned token approve to the allowlisted privacy pool", () => {
    const validated = validateRelayPrivacySignerRequest(
      {
        account_address: "0x777",
        calls: [{
          contract_address: "0x456",
          entrypoint: "approve",
          calldata: ["0x123", "0x64", "0x0"]
        }],
        nonce: "0x999",
        signature_r: "0xa",
        signature_s: "0xb"
      },
      { allowedContracts: new Set(["0x456"]), approvalSpenders: new Set(["0x123"]) }
    );

    expect(validated.account_address).toBe("0x777");
    expect(validated.calls[0]?.entrypoint).toBe("approve");
  });

  it("rejects unknown signer relay request fields", () => {
    expect(() =>
      validateRelayPrivacySignerRequest(
        {
          account_address: "0x777",
          calls: [{
            contract_address: "0x456",
            entrypoint: "approve",
            calldata: ["0x123", "0x64", "0x0"]
          }],
          nonce: "0x999",
          signature_r: "0xa",
          signature_s: "0xb",
          unsupported_paymaster_hint: "unexpected",
        },
        { allowedContracts: new Set(["0x456"]), approvalSpenders: new Set(["0x123"]) }
      )
    ).toThrow("request.unsupported_paymaster_hint is not supported");
  });

  it("rejects signer relays that approve an unallowlisted spender", () => {
    expect(() =>
      validateRelayPrivacySignerRequest(
        {
          account_address: "0x777",
          calls: [{
            contract_address: "0x456",
            entrypoint: "approve",
            calldata: ["0xdead", "0x64", "0x0"]
          }],
          nonce: "0x999",
          signature_r: "0xa",
          signature_s: "0xb"
        },
        { allowedContracts: new Set(["0x456"]), approvalSpenders: new Set(["0x123"]) }
      )
    ).toThrow("token approve spender is not allowlisted");
  });

  it("does not allow token contracts themselves as approval spenders", () => {
    expect(() =>
      validateRelayPrivacySignerRequest(
        {
          account_address: "0x777",
          calls: [{
            contract_address: "0x456",
            entrypoint: "approve",
            calldata: ["0x456", "0x64", "0x0"]
          }],
          nonce: "0x999",
          signature_r: "0xa",
          signature_s: "0xb"
        },
        { allowedContracts: new Set(["0x456"]), approvalSpenders: new Set(["0x123"]) }
      )
    ).toThrow("token approve spender is not allowlisted");
  });

  it("rejects privacy signer multicall bundles", () => {
    expect(() =>
      validateRelayPrivacySignerRequest(
        {
          account_address: "0x777",
          calls: [
            {
              contract_address: "0x456",
              entrypoint: "approve",
              calldata: ["0x123", "0x64", "0x0"]
            },
            {
              contract_address: "0x456",
              entrypoint: "approve",
              calldata: ["0x123", "0x64", "0x0"]
            }
          ],
          nonce: "0x999",
          signature_r: "0xa",
          signature_s: "0xb"
        },
        { allowedContracts: new Set(["0x456"]), approvalSpenders: new Set(["0x123"]) }
      )
    ).toThrow("privacy signer relay requires exactly one call");
  });

  it("rejects privacy signer relays for non-approve entrypoints", () => {
    expect(() =>
      validateRelayPrivacySignerRequest(
        {
          account_address: "0x777",
          calls: [{
            contract_address: "0x456",
            entrypoint: "transfer",
            calldata: ["0x123", "0x64", "0x0"]
          }],
          nonce: "0x999",
          signature_r: "0xa",
          signature_s: "0xb"
        },
        { allowedContracts: new Set(["0x456"]), approvalSpenders: new Set(["0x123"]) }
      )
    ).toThrow("privacy signer relay only supports token approve");
  });
});

function baseRequest() {
  return {
    chain_id: "0x534e5f5345504f4c4941",
    signer_address: "0x777",
    paymaster_address: "0xabc",
    call: {
      contract_address: "0x123",
      entrypoint: "apply_actions",
      calldata: ["0x1", "0x2"]
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
            calldata: ["0x1", "0x2"]
          }
        ]
      },
      signerAddress: "0x777",
      version: "2",
      signature: ["0xa", "0xb"]
    },
    proof: "proof-bytes",
    proof_facts: ["0x1"]
  };
}

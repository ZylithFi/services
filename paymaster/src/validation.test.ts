import { describe, expect, it } from "vitest";
import { selector } from "starknet";

import type { PaymasterConfig } from "./config.js";
import {
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
  | "withdrawalAmountBuckets"
  | "allowDirectWithdrawalRelays"
> = {
  accountAddress: "0xabc",
  chainId: "0x534e5f5345504f4c4941",
  allowedContracts: new Set(["0x123"]),
  allowedEntrypoints: new Set(["apply_actions"]),
  proofRequiredEntrypoints: new Set(["apply_actions"]),
  withdrawalAmountBuckets: new Set(),
  allowDirectWithdrawalRelays: false
};

describe("validateExecuteOutsideRequest", () => {
  it("accepts a matching SNIP-9 V2 request", () => {
    const request = baseRequest();
    const validated = validateExecuteOutsideRequest(request, config, 1_700_000_000);

    expect(validated.paymaster_address).toBe("0xabc");
    expect(validated.call.contract_address).toBe("0x123");
    expect(validated.proof_facts).toEqual(["0x1"]);
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

  it("allows plain relayed withdrawals while enforcing amount buckets", () => {
    const request = baseRequest();
    request.call.entrypoint = "withdraw_settlement_output_to_l2";
    request.call.calldata = ["0x1", "0x2", "0x3", "0x64"];
    request.outside_transaction.outsideExecution.calls[0]!.selector =
      String(selector.getSelectorFromName("withdraw_settlement_output_to_l2"));
    request.outside_transaction.outsideExecution.calls[0]!.calldata = request.call.calldata;
    delete (request as { proof?: unknown }).proof;
    delete (request as { proof_facts?: unknown }).proof_facts;

    const withdrawalConfig = {
      ...config,
      allowedEntrypoints: new Set(["withdraw_settlement_output_to_l2"]),
      proofRequiredEntrypoints: new Set<string>(),
      withdrawalAmountBuckets: new Set(["100"]),
      allowDirectWithdrawalRelays: true
    };
    const validated = validateExecuteOutsideRequest(request, withdrawalConfig, 1_700_000_000);

    expect(validated.proof).toBeUndefined();
    expect(validated.call.entrypoint).toBe("withdraw_settlement_output_to_l2");

    request.call.calldata = ["0x1", "0x2", "0x3", "0x65"];
    request.outside_transaction.outsideExecution.calls[0]!.calldata = request.call.calldata;
    expect(() =>
      validateExecuteOutsideRequest(request, withdrawalConfig, 1_700_000_000)
    ).toThrow("withdrawal amount is not in an allowed privacy bucket");
  });

  it("accepts direct embedded-wallet withdrawal relays without SNIP-9 outside execution", () => {
    const request = baseRequest();
    request.call.entrypoint = "withdraw_settlement_output_to_l2";
    request.call.calldata = ["0x1", "0x2", "0x3", "0x64"];
    delete (request as { outside_transaction?: unknown }).outside_transaction;
    delete (request as { proof?: unknown }).proof;
    delete (request as { proof_facts?: unknown }).proof_facts;
    (request as { relay_nonce?: string }).relay_nonce = "0x456";

    const withdrawalConfig = {
      ...config,
      allowedEntrypoints: new Set(["withdraw_settlement_output_to_l2"]),
      proofRequiredEntrypoints: new Set<string>(),
      withdrawalAmountBuckets: new Set(["100"]),
      allowDirectWithdrawalRelays: true
    };
    const validated = validateExecuteOutsideRequest(request, withdrawalConfig, 1_700_000_000);

    expect(validated.outside_transaction).toBeUndefined();
    expect(validated.relay_nonce).toBe("0x456");
  });

  it("rejects direct adapter note withdrawals by default", () => {
    const request = baseRequest();
    request.call.entrypoint = "withdraw_to_l2";
    request.call.calldata = ["0xabc", "0x11", "0x22", "0x1234"];
    delete (request as { outside_transaction?: unknown }).outside_transaction;

    const withdrawalConfig = {
      ...config,
      allowedEntrypoints: new Set(["withdraw_to_l2"]),
      proofRequiredEntrypoints: new Set<string>()
    };
    expect(() => validateExecuteOutsideRequest(request, withdrawalConfig, 1_700_000_000)).toThrow(
      "direct withdrawal relay sponsorship is disabled"
    );
  });

  it("accepts direct proof-bearing apply_actions relays", () => {
    const request = baseRequest();
    delete (request as { outside_transaction?: unknown }).outside_transaction;

    const validated = validateExecuteOutsideRequest(request, config, 1_700_000_000);

    expect(validated.call.entrypoint).toBe("apply_actions");
    expect(validated.outside_transaction).toBeUndefined();
  });

  it("accepts direct renewal parent cancellation relays", () => {
    const request = baseRequest();
    request.call.entrypoint = "cancel_renewal_parent_marker";
    request.call.calldata = [
      "0x111",
      "0x222",
      "0x111",
      "0x0",
      "0x0",
      "0x0",
      "0x333",
      "0x444"
    ];
    delete (request as { outside_transaction?: unknown }).outside_transaction;
    delete (request as { proof?: unknown }).proof;
    delete (request as { proof_facts?: unknown }).proof_facts;

    const cancelConfig = {
      ...config,
      allowedEntrypoints: new Set(["cancel_renewal_parent_marker"]),
      proofRequiredEntrypoints: new Set<string>()
    };
    const validated = validateExecuteOutsideRequest(request, cancelConfig, 1_700_000_000);

    expect(validated.call.entrypoint).toBe("cancel_renewal_parent_marker");
    expect(validated.outside_transaction).toBeUndefined();
  });

  it("rejects direct relays for non-withdrawal entrypoints", () => {
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
      "direct paymaster relay is only allowed for withdrawals"
    );
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
      { allowedContracts: new Set(["0x123", "0x456"]) }
    );

    expect(validated.account_address).toBe("0x777");
    expect(validated.calls[0]?.entrypoint).toBe("approve");
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
        { allowedContracts: new Set(["0x123", "0x456"]) }
      )
    ).toThrow("token approve spender is not allowlisted");
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

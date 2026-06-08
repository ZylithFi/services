import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

describe("paymaster config", () => {
  it("loads the production allowlist snapshot exactly", () => {
    const config = loadConfig({
      ZYLITH_PAYMASTER_RPC_URL: "https://rpc.zylith.example",
      ZYLITH_PAYMASTER_CHAIN_ID: "0x534e5f5345504f4c4941",
      ZYLITH_PAYMASTER_ACCOUNT_ADDRESS: "0xabc",
      ZYLITH_PAYMASTER_PRIVATE_KEY: "1".repeat(64),
      ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x987",
      ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: "0x101,0x102",
      ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS:
        "apply_actions,submit_settlement_with_proof_facts,withdraw_settlement_output_with_proof_facts,cancel_renewal_parent_marker",
      ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS:
        "apply_actions,submit_settlement_with_proof_facts,withdraw_settlement_output_with_proof_facts",
      ZYLITH_PAYMASTER_WITHDRAWAL_BUCKETS: "1000000,0x1e8480",
      ZYLITH_PAYMASTER_ALLOWED_ORIGINS: "https://app.zylith.example,https://preview-*.zylith.example",
    });

    expect({
      privacySignerClassHash: config.privacySignerClassHash,
      allowedContracts: [...config.allowedContracts].sort(),
      allowedEntrypoints: [...config.allowedEntrypoints].sort(),
      proofRequiredEntrypoints: [...config.proofRequiredEntrypoints].sort(),
      withdrawalAmountBuckets: [...config.withdrawalAmountBuckets].sort(),
      allowedOrigins: [...config.allowedOrigins].sort(),
      allowedOriginPatterns: config.allowedOriginPatterns.map((pattern) => pattern.source),
      allowDirectWithdrawalRelays: config.allowDirectWithdrawalRelays,
    }).toMatchInlineSnapshot(`
      {
        "allowDirectWithdrawalRelays": false,
        "allowedContracts": [
          "0x101",
          "0x102",
        ],
        "allowedEntrypoints": [
          "apply_actions",
          "cancel_renewal_parent_marker",
          "submit_settlement_with_proof_facts",
          "withdraw_settlement_output_with_proof_facts",
        ],
        "allowedOriginPatterns": [
          "^https:\\/\\/preview-[^/]*\\.zylith\\.example$",
        ],
        "allowedOrigins": [
          "https://app.zylith.example",
        ],
        "privacySignerClassHash": "0x987",
        "proofRequiredEntrypoints": [
          "apply_actions",
          "submit_settlement_with_proof_facts",
          "withdraw_settlement_output_with_proof_facts",
        ],
        "withdrawalAmountBuckets": [
          "1000000",
          "2000000",
        ],
      }
    `);
  });

  it("rejects direct withdrawal sponsorship without explicit acknowledgement", () => {
    expect(() =>
      loadConfig({
        ZYLITH_PAYMASTER_RPC_URL: "https://rpc.zylith.example",
        ZYLITH_PAYMASTER_CHAIN_ID: "0x534e5f5345504f4c4941",
        ZYLITH_PAYMASTER_ACCOUNT_ADDRESS: "0xabc",
        ZYLITH_PAYMASTER_PRIVATE_KEY: "1".repeat(64),
        ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x987",
        ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: "0x101",
        ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS: "withdraw_settlement_output_with_proof_facts",
        ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS: "withdraw_settlement_output_with_proof_facts",
        ZYLITH_PAYMASTER_WITHDRAWAL_BUCKETS: "1000000",
        ZYLITH_PAYMASTER_ALLOW_DIRECT_WITHDRAWALS: "true",
      }),
    ).toThrow(/ACK_DIRECT_WITHDRAWAL_SPONSORSHIP_RISK/);
  });

  it("rejects trusted proxy headers without trusted proxy CIDRs", () => {
    expect(() =>
      loadConfig({
        ZYLITH_PAYMASTER_RPC_URL: "https://rpc.zylith.example",
        ZYLITH_PAYMASTER_CHAIN_ID: "0x534e5f5345504f4c4941",
        ZYLITH_PAYMASTER_ACCOUNT_ADDRESS: "0xabc",
        ZYLITH_PAYMASTER_PRIVATE_KEY: "1".repeat(64),
        ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: "0x101",
        ZYLITH_PAYMASTER_TRUST_PROXY_HEADERS: "true",
      }),
    ).toThrow(/TRUSTED_PROXY_CIDRS/);
  });
});

import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

const BASE_ENV = {
  ZYLITH_PAYMASTER_RPC_URL: "https://rpc.zylith.example",
  ZYLITH_PAYMASTER_CHAIN_ID: "0x534e5f5345504f4c4941",
  ZYLITH_PAYMASTER_ACCOUNT_ADDRESS: "0xabc",
  ZYLITH_PAYMASTER_PRIVATE_KEY: "1".repeat(64),
  ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: "0x101",
  ZYLITH_PAYMASTER_APPROVAL_SPENDERS: "0x201",
  ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS: "apply_actions",
  ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS:
    "apply_actions,submit_settlement_with_proof_facts",
  ZYLITH_PAYMASTER_INTERNAL_TOKEN: "test-paymaster-token",
  ZYLITH_PAYMASTER_ALLOWED_ORIGINS: "https://app.zylith.example",
  ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x987",
} satisfies NodeJS.ProcessEnv;

describe("paymaster config", () => {
  it("loads the production allowlist snapshot exactly", () => {
    const config = loadConfig({
      ...BASE_ENV,
      ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x987",
      ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: "0x101,0x102",
      ZYLITH_PAYMASTER_APPROVAL_SPENDERS: "0x201",
      ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS:
        "apply_actions,submit_settlement_with_proof_facts",
      ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS:
        "apply_actions,submit_settlement_with_proof_facts",
      ZYLITH_PAYMASTER_ALLOWED_ORIGINS: "https://app.zylith.example,https://preview.zylith.example",
    });

    expect({
      privacySignerClassHash: config.privacySignerClassHash,
      allowedContracts: [...config.allowedContracts].sort(),
      approvalSpenders: [...config.approvalSpenders].sort(),
      allowedEntrypoints: [...config.allowedEntrypoints].sort(),
      proofRequiredEntrypoints: [...config.proofRequiredEntrypoints].sort(),
      allowedOrigins: [...config.allowedOrigins].sort(),
    }).toMatchInlineSnapshot(`
      {
        "allowedContracts": [
          "0x101",
          "0x102",
        ],
        "allowedEntrypoints": [
          "apply_actions",
          "submit_settlement_with_proof_facts",
        ],
        "allowedOrigins": [
          "https://app.zylith.example",
          "https://preview.zylith.example",
        ],
        "approvalSpenders": [
          "0x201",
        ],
        "privacySignerClassHash": "0x987",
        "proofRequiredEntrypoints": [
          "apply_actions",
          "submit_settlement_with_proof_facts",
        ],
      }
    `);
  });

  it("rejects trusted proxy headers without trusted proxy CIDRs", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_TRUST_PROXY_HEADERS: "true",
      }),
    ).toThrow(/TRUSTED_PROXY_CIDRS/);
  });

  it("rejects wildcard origins", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ALLOWED_ORIGINS: "https://preview-*.zylith.example",
      }),
    ).toThrow(/exact origins only/);
  });

  it("requires at least one explicit browser origin", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ALLOWED_ORIGINS: undefined,
      }),
    ).toThrow(/ZYLITH_PAYMASTER_ALLOWED_ORIGINS must contain at least one exact origin/);
  });

  it("requires production RPC URLs to be valid HTTPS endpoints", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_RPC_URL: "not-a-url",
      }),
    ).toThrow(/valid http\(s\) URL/);

    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_RPC_URL: "http://35.192.48.142:9545",
      }),
    ).toThrow(/must use https outside local development/);
  });

  it("allows localhost RPC URLs for local development", () => {
    expect(
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_RPC_URL: "http://127.0.0.1:9545",
      }).rpcUrl,
    ).toBe("http://127.0.0.1:9545");
  });

  it("requires explicit contract and entrypoint allowlists", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: undefined,
      }),
    ).toThrow(/ZYLITH_PAYMASTER_ALLOWED_CONTRACTS is required/);

    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_APPROVAL_SPENDERS: undefined,
      }),
    ).toThrow(/ZYLITH_PAYMASTER_APPROVAL_SPENDERS is required/);

    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS: undefined,
      }),
    ).toThrow(/ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS is required/);

    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS: undefined,
      }),
    ).toThrow(/ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS is required/);
  });

  it("rejects zero deployment felts", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ACCOUNT_ADDRESS: "0x0",
      }),
    ).toThrow(/felt value cannot be zero/);

    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: "0x0",
      }),
    ).toThrow(/felt value cannot be zero/);

    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_APPROVAL_SPENDERS: "0x0",
      }),
    ).toThrow(/felt value cannot be zero/);

    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x0",
      }),
    ).toThrow(/felt value cannot be zero/);
  });

  it("rejects out-of-field deployment felts", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ACCOUNT_ADDRESS:
          "0x800000000000011000000000000000000000000000000000000000000000001",
      }),
    ).toThrow(/invalid felt value/);
  });

  it("requires an internal metrics token", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_INTERNAL_TOKEN: undefined,
      }),
    ).toThrow(/ZYLITH_PAYMASTER_INTERNAL_TOKEN or ZYLITH_CONTROL_PLANE_TOKEN is required/);
  });

  it("requires the privacy proof signer class hash for current deposits", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: undefined,
      }),
    ).toThrow(/ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH is required/);
  });
});

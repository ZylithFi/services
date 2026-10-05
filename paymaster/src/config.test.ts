import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "./config.js";

const manifest = JSON.parse(readFileSync("../client/public/deployment.example.json", "utf8"));
manifest.funding.starknet_privacy.privacy_pool = "0x123";
manifest.funding.starknet_privacy.privacy_pool_class_hash = "0x124";
manifest.funding.starknet_privacy.paymaster_address = "0xabc";
manifest.funding.starknet_privacy.proof_signer_class_hash = "0x987";
manifest.contracts.exchange = "0x456";
manifest.contracts.privacy_deposit_bridge = "0x789";
manifest.deployment = { finalized: true, release_commit: "a".repeat(40) };
manifest.proof.config_locked_after_deploy = true;
const manifestPath = join(mkdtempSync(join(tmpdir(), "zylith-paymaster-test-")), "deployment.json");
writeFileSync(manifestPath, JSON.stringify(manifest));

const BASE_ENV = {
  ZYLITH_PAYMASTER_RPC_URL: "https://rpc.zylith.example",
  ZYLITH_PAYMASTER_CHAIN_ID: "0x534e5f5345504f4c4941",
  ZYLITH_PAYMASTER_ACCOUNT_ADDRESS: "0xabc",
  ZYLITH_PAYMASTER_PRIVATE_KEY: "1".repeat(64),
  ZYLITH_DEPLOYMENT_MANIFEST: manifestPath,
  ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS: "apply_actions",
  ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS: "apply_actions",
  ZYLITH_PAYMASTER_INTERNAL_TOKEN: "test-paymaster-token",
  ZYLITH_PAYMASTER_ALLOWED_ORIGINS: "https://app.zylith.example",
  ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x987",
  ZYLITH_PAYMASTER_SUBMISSION_LOG_PATH: "/var/lib/zylith/submissions.json",
  ZYLITH_PAYMASTER_SPONSORED_FEE_LOG_PATH: "/var/lib/zylith/sponsored-fees.json",
} satisfies NodeJS.ProcessEnv;

describe("paymaster config", () => {
  it("loads bounded sponsorship controls", () => {
    const config = loadConfig({
      ...BASE_ENV,
      ZYLITH_PAYMASTER_MAX_SPONSORED_FEE_FRI: "900000000000000000",
    });

    expect(config.maxSponsoredFeeFri).toBe(900_000_000_000_000_000n);
    expect(config.dailySponsoredFeePerPrincipalFri).toBe(5_000_000_000_000_000_000n);
  });

  it("rejects non-positive sponsored fee limits", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_MAX_SPONSORED_FEE_FRI: "0",
      })
    ).toThrow(/positive integer/);
  });

  it("requires the daily fee budget to cover one maximum transaction", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_MAX_SPONSORED_FEE_FRI: "100",
        ZYLITH_PAYMASTER_DAILY_SPONSORED_FEE_FRI: "99",
      }),
    ).toThrow(/cover at least one transaction/);
  });

  it("loads the production allowlist snapshot exactly", () => {
    const config = loadConfig({
      ...BASE_ENV,
      ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x987",
      ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS: "apply_actions",
      ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS: "apply_actions",
      ZYLITH_PAYMASTER_ALLOWED_ORIGINS: "https://app.zylith.example,https://preview.zylith.example",
    });

    expect({
      privacySignerClassHash: config.privacySignerClassHash,
      allowedContracts: [...config.allowedContracts].sort(),
      allowedEntrypoints: [...config.allowedEntrypoints].sort(),
      proofRequiredEntrypoints: [...config.proofRequiredEntrypoints].sort(),
      allowedOrigins: [...config.allowedOrigins].sort(),
    }).toMatchInlineSnapshot(`
      {
        "allowedContracts": [
          "0x123",
          "0x456",
          "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
          "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
          "0x512feac6339ff7889822cb5aa2a86c848e9d392bb0e3e237c008674feed8343",
          "0x789",
        ],
        "allowedEntrypoints": [
          "apply_actions",
        ],
        "allowedOrigins": [
          "https://app.zylith.example",
          "https://preview.zylith.example",
        ],
        "privacySignerClassHash": "0x987",
        "proofRequiredEntrypoints": [
          "apply_actions",
        ],
      }
    `);
  });

  it("fails closed when the runtime identity differs from the deployment", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_CHAIN_ID: "0x1",
      })
    ).toThrow(/chain id differs/);
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ACCOUNT_ADDRESS: "0xdef",
      })
    ).toThrow(/account differs/);
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x654",
      })
    ).toThrow(/class hash differs/);
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

  it("derives contract and spender allowlists from the deployment registry", () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: "0x456",
      }),
    ).toThrow(/allowlist overrides are retired/);

    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ZYLITH_DEPLOYMENT_MANIFEST: undefined,
      }),
    ).toThrow(/ZYLITH_DEPLOYMENT_MANIFEST is required/);

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

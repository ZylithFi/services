import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";

const script = resolve("ops/production-readiness-check.mjs");

test("production readiness accepts a hardened minimal configuration", () => {
  const { env } = fixtureEnv();
  const result = runReadiness(env);
  assert.equal(result.status, 0, result.stderr);
});

test("production readiness rejects missing audited ERC20 allowlist acknowledgement", () => {
  const { env } = fixtureEnv();
  delete env.ZYLITH_AUDITED_ERC20_ALLOWLIST_ACK;
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_AUDITED_ERC20_ALLOWLIST_ACK/);
});

test("production readiness rejects unlocked proof or operational config manifests", () => {
  const { env, manifest } = fixtureEnv({
    proofOverrides: {
      proof_program_locked_after_deploy: false,
      operational_config_locked_after_deploy: false,
    },
  });
  writeManifest(env, manifest);

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /proof_program_locked_after_deploy/);
  assert.match(result.stderr, /operational_config_locked_after_deploy/);
});

test("production readiness rejects stale pair fee manifest values", () => {
  const { env, manifest } = fixtureEnv();
  manifest.product.pairs["STRK/USDC"].taker_fee_bps = 0;
  manifest.product.pairs["STRK/USDC"].maker_fee_bps = 1;
  writeManifest(env, manifest);

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /product\.pairs\.STRK\/USDC\.taker_fee_bps must be 4/);
  assert.match(result.stderr, /product\.pairs\.STRK\/USDC\.maker_fee_bps must be 0/);
});

test("production readiness rejects unresolved high severity audit findings when audit is required", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_EXTERNAL_AUDIT_REQUIRED = "true";
  env.ZYLITH_EXTERNAL_AUDIT_COMPLETE = "true";
  env.ZYLITH_EXTERNAL_AUDIT_CRITICAL_OPEN = "0";
  env.ZYLITH_EXTERNAL_AUDIT_HIGH_OPEN = "1";
  env.ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256 = "b".repeat(64);
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_EXTERNAL_AUDIT_HIGH_OPEN must be 0/);
});

test("production readiness rejects missing first-set config acknowledgement", () => {
  const { env } = fixtureEnv();
  delete env.ZYLITH_ACK_FIRST_SET_CONFIG_NO_TIMELOCK_RISK;
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_ACK_FIRST_SET_CONFIG_NO_TIMELOCK_RISK/);
});

test("production readiness rejects weak key custody mode when configured", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_KEY_CUSTODY_MODE = "single-hot-wallet";
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_KEY_CUSTODY_MODE/);
});

test("production readiness rejects stale deployment manifest hash", () => {
  const { env, manifest } = fixtureEnv();
  manifest.deployment.finalized = false;
  writeFileSync(env.ZYLITH_DEPLOYMENT_MANIFEST_PATH, JSON.stringify({ manifest }, null, 2));
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /deployment manifest sha256/);
});

test("production readiness rejects manifest chain id mismatch", () => {
  const { env, manifest } = fixtureEnv();
  manifest.chain_id = "0x1234";
  writeManifest(env, manifest);
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /deployment manifest chain_id/);
});

test("production readiness rejects unaudited or non-exact-delta asset metadata", () => {
  const { env, manifest } = fixtureEnv();
  manifest.product.assets.STRK.erc20_behavior = "fee-on-transfer";
  manifest.product.assets.USDC.audit_status = "pending";
  writeManifest(env, manifest);
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /product\.assets\.STRK\.erc20_behavior must be vanilla-exact-delta/);
  assert.match(result.stderr, /product\.assets\.USDC\.audit_status must be approved/);
});

test("production readiness rejects stale funding verifier manifests", () => {
  const { env, manifest } = fixtureEnv();
  manifest.funding.starknet_privacy.funding_verifier = "0x999";
  writeManifest(env, manifest);
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /funding_verifier must be absent/);
});

function runReadiness(env) {
  return spawnSync(process.execPath, [script], {
    env,
    encoding: "utf8",
  });
}

function fixtureEnv({ proofOverrides = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "zylith-readiness-"));
  const manifestPath = join(dir, "deployment.json");
  const manifest = fixtureManifest(proofOverrides);

  const env = {
    ...process.env,
    ZYLITH_DEPLOYMENT_MANIFEST_PATH: manifestPath,
    ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET: "a".repeat(32),
    ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS: "b".repeat(32),
    ZYLITH_HEARTBEAT_COVER_SECRET: "c".repeat(32),
    ZYLITH_REQUIRE_TRUSTED_ORDER_INGRESS: "true",
    ZYLITH_REQUIRE_ARTIFACT_ONCHAIN_VERIFICATION: "true",
    ZYLITH_AUDITED_ERC20_ALLOWLIST_ACK: "true",
    ZYLITH_COORDINATOR_ALLOWED_ORIGINS: "https://app.zylith.fi",
    ZYLITH_PROVER_ALLOWED_ORIGINS: "https://app.zylith.fi",
    ZYLITH_INDEXER_ALLOWED_ORIGINS: "https://app.zylith.fi",
    ZYLITH_PAYMASTER_ALLOWED_ORIGINS: "https://app.zylith.fi",
    ZYLITH_RENEWAL_RELAY_ALLOWED_ORIGINS: "https://app.zylith.fi",
    ZYLITH_COORDINATOR_MAX_BODY_BYTES: "1000000",
    ZYLITH_PROVER_MAX_BODY_BYTES: "1000000",
    ZYLITH_PAYMASTER_MAX_BODY_BYTES: "1000000",
    ZYLITH_RENEWAL_RELAY_MAX_BODY_BYTES: "128000000",
    ZYLITH_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE: "60",
    ZYLITH_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE: "60",
    ZYLITH_PAYMASTER_SIGNER_LIMIT_PER_MINUTE: "60",
    ZYLITH_RENEWAL_RELAY_RATE_LIMIT_PER_MINUTE: "60",
    ZYLITH_PROVER_MAX_STORED_PRIVATE_PAYLOADS: "1000",
    ZYLITH_PRIVATE_PAYLOAD_RETENTION_MS: "60000",
    ZYLITH_RENEWAL_RELAY_PACKAGE_RETENTION_MS: "86400000",
    ZYLITH_RENEWAL_RELAY_MAX_PACKAGE_SLOTS: "86400",
    ZYLITH_COORDINATOR_MAX_ORDERS_PER_BATCH: "100",
    ZYLITH_BATCH_WINDOW_MS: "90000",
    ZYLITH_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS: "3",
    ZYLITH_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS: "3",
    ZYLITH_ARTIFACT_EPOCH_BUCKET_SIZE: "8",
    ZYLITH_OUTPUT_CLAIM_DELAY_SECONDS: "60",
    ZYLITH_AUCTION_PROVER_KEYS_PATH: join(dir, "keys.json"),
    VITE_ZYLITH_INGRESS_KEY_REGISTRY_PIN: "pin",
    ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS: "0x101",
    ZYLITH_NATIVE_PROOF_PROGRAM_HASH: "0x102",
    ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS: "0x103",
    ZYLITH_NATIVE_TX_PROVER_URL: "https://prover.zylith.fi",
    ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS: "0x104",
    ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS: "0x105",
    ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS: "0x106",
    ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS: "0x107",
    ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS: "0x108",
    ZYLITH_STARKNET_OS_CONFIG_HASH: "0x109",
    ZYLITH_STARKNET_CHAIN_ID: "0x534e5f5345504f4c4941",
    ZYLITH_PROTOCOL_ADMIN_ADDRESS: "0x201",
    ZYLITH_PAUSE_GUARDIAN_ADDRESS: "0x202",
    ZYLITH_PROTOCOL_TREASURY_ADDRESS: "0x203",
    ZYLITH_PROTOCOL_FEE_RECIPIENT: "0x204",
    ZYLITH_PROTOCOL_FEE_OWNER_KEY_HEX: "11".repeat(32),
    ZYLITH_PROTOCOL_FEE_WITHDRAW_KEY_HEX: "12".repeat(32),
    ZYLITH_RELAY_FEE_OWNER_KEY_HEX: "13".repeat(32),
    ZYLITH_RELAY_FEE_WITHDRAW_KEY_HEX: "14".repeat(32),
    ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS: "0x205",
    ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS: "0x206",
    ZYLITH_PAYMASTER_RPC_URL: "https://rpc.zylith.fi",
    ZYLITH_PAYMASTER_CHAIN_ID: "0x534e5f5345504f4c4941",
    ZYLITH_PAYMASTER_ACCOUNT_ADDRESS: "0x207",
    ZYLITH_PAYMASTER_PRIVATE_KEY: "15".repeat(32),
    ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH: "0x208",
    ZYLITH_PAYMASTER_ALLOWED_CONTRACTS: "0x301",
    ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS: "0x302",
    ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS: "0x303",
    ZYLITH_PAYMASTER_WITHDRAWAL_BUCKETS: "1000000",
    ZYLITH_RENEWAL_RELAY_STRICT: "true",
    ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE: "SelfRelay",
    ZYLITH_RENEWAL_RELAY_STORE_PATH: join(dir, "relay.sqlite"),
    ZYLITH_RENEWAL_RELAY_PROVER_CONTROL_TOKEN: "d".repeat(32),
    ZYLITH_RENEWAL_RELAY_COORDINATOR_URL: "https://coordinator.zylith.fi",
    ZYLITH_RENEWAL_RELAY_PROVER_URL: "https://prover.zylith.fi",
    ZYLITH_ACK_FIRST_SET_CONFIG_NO_TIMELOCK_RISK: "true",
    ZYLITH_EXTERNAL_AUDIT_REQUIRED: "false",
    ZYLITH_KEY_CUSTODY_MODE: "hardware-multisig",
    ZYLITH_DEPLOYMENT_RELEASE_COMMIT: fixtureReleaseCommit(),
  };
  env.ZYLITH_DEPLOYMENT_MANIFEST_PATH = manifestPath;
  writeManifest(env, manifest);

  return { env, manifest };
}

function fixtureManifest(proofOverrides) {
  const requiredAssets = ["STRK", "ETH", "USDC", "strkBTC", "WBTC", "USDT"];
  const pairs = {
    "STRK/USDC": ["STRK", "USDC", 4, 0],
    "ETH/USDC": ["ETH", "USDC", 4, 0],
    "strkBTC/USDC": ["strkBTC", "USDC", 4, 0],
    "STRK/ETH": ["STRK", "ETH", 4, 0],
    "STRK/strkBTC": ["STRK", "strkBTC", 4, 0],
    "WBTC/strkBTC": ["WBTC", "strkBTC", 2, 0],
    "USDC/USDT": ["USDC", "USDT", 2, 0],
  };
  return {
    chain_id: "0x534e5f5345504f4c4941",
    deployment: {
      release_commit: fixtureReleaseCommit(),
      finalized: true,
    },
    contracts: {
      auction_verifier: "0x401",
      batch_registry: "0x402",
      commitment_registry: "0x403",
      shielded_asset_adapter: "0x404",
      privacy_deposit_bridge: "0x405",
    },
    token_addresses: Object.fromEntries(
      requiredAssets.map((asset, index) => [asset, `0x${(0x500 + index).toString(16)}`]),
    ),
    product: {
      assets: Object.fromEntries(
        requiredAssets.map((asset) => [
          asset,
          {
            asset_id: asset,
            enabled: true,
            erc20_behavior: "vanilla-exact-delta",
            audit_status: "approved",
          },
        ]),
      ),
      pairs: Object.fromEntries(
        Object.entries(pairs).map(([pair, [base, quote, taker, maker]]) => [
          pair,
          {
            pair_id: pair,
            base_asset_id: base,
            quote_asset_id: quote,
            enabled: true,
            taker_fee_bps: taker,
            maker_fee_bps: maker,
          },
        ]),
      ),
    },
    funding: {
      primary: "starknet_privacy",
      starknet_privacy: {
        privacy_pool: "0x300",
        bridge_adapter: "0x405",
        shielded_asset_adapter: "0x404",
        discovery_url: "https://discovery.zylith.fi",
        proving_url: "https://privacy-prover.zylith.fi",
        paymaster_address: "0x207",
        paymaster_url: "https://paymaster.zylith.fi/execute-outside",
      },
    },
    proof: {
      proof_program_address: "0x601",
      proof_program_hash: "0x602",
      settlement_statement_program_address: "0x603",
      nullifier_statement_program_address: "0x604",
      renewal_statement_program_address: "0x605",
      note_consolidation_statement_program_address: "0x606",
      withdrawal_statement_program_address: "0x607",
      proof_account_address: "0x608",
      settlement_account_address: "0x609",
      proof_program_locked_after_deploy: true,
      operational_config_locked_after_deploy: true,
      ...proofOverrides,
    },
  };
}

function fixtureReleaseCommit() {
  return "a".repeat(40);
}

function writeManifest(env, manifest) {
  const body = JSON.stringify({ manifest }, null, 2);
  writeFileSync(env.ZYLITH_DEPLOYMENT_MANIFEST_PATH, body);
  env.ZYLITH_EXPECTED_DEPLOYMENT_MANIFEST_SHA256 = createHash("sha256")
    .update(body)
    .digest("hex");
}

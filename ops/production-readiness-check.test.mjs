import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";

const script = resolve("ops/production-readiness-check.mjs");

test("production readiness accepts a hardened minimal configuration", () => {
  const { env } = fixtureEnv();
  const result = runReadiness(env);
  assert.equal(result.status, 0, result.stderr);
});

test("production readiness accepts separate native proof account with explicit private key", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS = "0x999";
  env.ZYLITH_NATIVE_PROOF_PRIVATE_KEY = "16".repeat(32);
  const result = runReadiness(env);
  assert.equal(result.status, 0, result.stderr);
});

test("production readiness rejects separate native proof account without private key", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS = "0x999";
  delete env.ZYLITH_NATIVE_PROOF_PRIVATE_KEY;
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_NATIVE_PROOF_PRIVATE_KEY/);
});

test("production readiness rejects missing base Starknet executor signer", () => {
  const { env } = fixtureEnv();
  delete env.ZYLITH_STARKNET_ACCOUNT_ADDRESS;
  delete env.ZYLITH_STARKNET_PRIVATE_KEY;
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_STARKNET_ACCOUNT_ADDRESS/);
  assert.match(result.stderr, /ZYLITH_STARKNET_PRIVATE_KEY/);
});

test("production readiness rejects missing prover strict mode", () => {
  const { env } = fixtureEnv();
  delete env.ZYLITH_PROVER_STRICT;
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_PROVER_STRICT/);
});

test("production readiness rejects prover worker without on-chain submission", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_PROVER_WORKER_SUBMIT_ONCHAIN = "false";
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_PROVER_WORKER_SUBMIT_ONCHAIN/);
});

test("production readiness rejects paymaster proxy trust without trusted CIDRs", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_PAYMASTER_TRUST_PROXY_HEADERS = "true";
  delete env.ZYLITH_PAYMASTER_TRUSTED_PROXY_CIDRS;
  delete env.ZYLITH_TRUSTED_PROXY_CIDRS;
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /PAYMASTER_TRUSTED_PROXY_CIDRS/);
});

test("production readiness rejects coordinator proxy trust without trusted CIDRs", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_TRUST_PROXY_HEADERS = "true";
  delete env.ZYLITH_COORDINATOR_TRUSTED_PROXY_CIDRS;
  delete env.ZYLITH_TRUSTED_PROXY_CIDRS;
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /COORDINATOR_TRUSTED_PROXY_CIDRS/);
});

test("production readiness rejects self-hosted native prover endpoints", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_NATIVE_TX_PROVER_URL = "http://127.0.0.1:18090";
  let result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must not use local, private, or self-hosted native prover URLs/);

  env.ZYLITH_NATIVE_TX_PROVER_URL = "http://10.1.2.3:18090";
  result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must not use local, private, or self-hosted native prover URLs/);
});

test("production readiness rejects a manifest that names a different native prover", () => {
  const { env, manifest } = fixtureEnv();
  manifest.proof.native_tx_prover_url = "https://different-prover.example";
  writeManifest(env, manifest);
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /proof\.native_tx_prover_url must match ZYLITH_NATIVE_TX_PROVER_URL/);
});

test("production readiness rejects browser proving without OHTTP", () => {
  const { env, manifest } = fixtureEnv();
  manifest.funding.starknet_privacy.proving_ohttp_enabled = false;
  writeManifest(env, manifest);
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /funding\.starknet_privacy\.proving_ohttp_enabled must be true/);
});

test("production readiness rejects unlocked proof or operational config manifests", () => {
  const { env, manifest } = fixtureEnv({
    proofOverrides: {
      proof_program_locked_after_deploy: false,
      operational_config_locked_after_deploy: false,
      commitment_registry_config_locked_after_deploy: false,
      batch_registry_config_locked_after_deploy: false,
      privacy_deposit_bridge_config_locked_after_deploy: false,
    },
  });
  writeManifest(env, manifest);

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /proof_program_locked_after_deploy/);
  assert.match(result.stderr, /operational_config_locked_after_deploy/);
  assert.match(result.stderr, /commitment_registry_config_locked_after_deploy/);
  assert.match(result.stderr, /batch_registry_config_locked_after_deploy/);
  assert.match(result.stderr, /privacy_deposit_bridge_config_locked_after_deploy/);
});

test("production readiness rejects an obsolete proof protocol version", () => {
  const { env, manifest } = fixtureEnv();
  manifest.proof.proof_version = "PROOF0";
  writeManifest(env, manifest);

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /proof\.proof_version must be PROOF1/);
});

test("production readiness rejects stale pair fee manifest values", () => {
  const { env, manifest } = fixtureEnv();
  manifest.product.pairs["STRK/USDC"].taker_fee_bps = 0;
  writeManifest(env, manifest);

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /product\.pairs\.STRK\/USDC\.taker_fee_bps must be 4/);
});

test("production readiness rejects missing explicit product pairs", () => {
  const { env } = fixtureEnv();
  delete env.ZYLITH_PRODUCT_PAIRS;

  const result = runReadiness(env);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_PRODUCT_PAIRS must be configured/);
});

test("production readiness rejects incomplete liquidity price policy", () => {
  const { env } = fixtureEnv();
  const policyPath = join(mkdtempSync(join(tmpdir(), "zylith-price-policy-")), "policy.json");
  const policy = JSON.parse(readFileSync("ops/config/liquidity-price-sources.mainnet.json", "utf8"));
  delete policy.pairs["ETH/USDC"];
  policy.pairs["STRK/USDC"].confirmations = ["last-cleared-price"];
  policy.pairs["STRK/ETH"].confirmations = [
    "coinbase:STRK-USD divided by coinbase:ETH-USD",
    "coinbase:STRK-USD divided by coinbase:ETH-USD",
  ];
  policy.global_policy.large_move_policy = "clip-to-previous-price";
  writeFileSync(policyPath, JSON.stringify(policy, null, 2));
  env.ZYLITH_LIQUIDITY_PRICE_POLICY_PATH = policyPath;

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /liquidity price policy must include ETH\/USDC/);
  assert.match(result.stderr, /global_policy\.large_move_policy must require confirmation/);
  assert.match(result.stderr, /liquidity price policy STRK\/USDC\.confirmations must include at least two independent confirmations/);
  assert.match(result.stderr, /liquidity price policy STRK\/USDC must not include last-cleared/);
  assert.match(result.stderr, /liquidity price policy STRK\/ETH\.confirmations must be unique independent sources/);
});

test("production readiness rejects unresolved high severity audit findings", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_EXTERNAL_AUDIT_COMPLETE = "true";
  env.ZYLITH_EXTERNAL_AUDIT_CRITICAL_OPEN = "0";
  env.ZYLITH_EXTERNAL_AUDIT_HIGH_OPEN = "1";
  env.ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256 = "b".repeat(64);
  env.ZYLITH_EXTERNAL_AUDIT_REPORT_URI = "https://audit.example/report.pdf";
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_EXTERNAL_AUDIT_HIGH_OPEN must be 0/);
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

test("production readiness rejects invalid deployment manifest signature", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_DEPLOYMENT_MANIFEST_SIGNATURE = Buffer.from("not a valid signature").toString("base64");
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /deployment manifest signature/);
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
  delete manifest.product.assets.ETH.audit_evidence;
  writeManifest(env, manifest);
  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /product\.assets\.STRK\.erc20_behavior must be vanilla-exact-delta/);
  assert.match(result.stderr, /product\.assets\.USDC\.audit_status must be approved/);
  assert.match(result.stderr, /product\.assets\.ETH\.audit_evidence is required/);
});

test("production readiness rejects invalid private funding manifest config", () => {
  const { env, manifest } = fixtureEnv();
  manifest.funding.starknet_privacy.discovery_url = "http://privacy-discovery.example";
  manifest.funding.starknet_privacy.proving_url = "http://privacy-prover.example";
  manifest.funding.starknet_privacy.paymaster_address = "0x999";
  manifest.funding.starknet_privacy.bridge_adapter = "0x406";
  manifest.contracts.shielded_asset_adapter = "0x404";
  delete manifest.funding.starknet_privacy.proof_signer_class_hash;
  writeManifest(env, manifest);

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /funding\.starknet_privacy\.discovery_url must use https/);
  assert.match(result.stderr, /funding\.starknet_privacy\.proving_url must use https/);
  assert.match(result.stderr, /funding\.starknet_privacy\.paymaster_address must match ZYLITH_PAYMASTER_ACCOUNT_ADDRESS/);
  assert.match(result.stderr, /funding\.starknet_privacy\.bridge_adapter must match contracts\.privacy_deposit_bridge/);
  assert.match(result.stderr, /contracts\.shielded_asset_adapter must match contracts\.privacy_deposit_bridge/);
  assert.match(result.stderr, /funding\.starknet_privacy\.proof_signer_class_hash must be configured/);
});

test("production readiness rejects deployment JSON drift from the signed manifest", () => {
  const { env, manifest } = fixtureEnv();
  const driftedManifest = structuredClone(manifest);
  driftedManifest.funding.starknet_privacy.bridge_adapter = "0x999";
  env.ZYLITH_DEPLOYMENT_JSON = JSON.stringify(driftedManifest);

  const result = runReadiness(env);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_DEPLOYMENT_JSON must match the signed deployment manifest/);
});

test("production readiness rejects product and funding token alias drift", () => {
  const { env, manifest } = fixtureEnv();
  manifest.product.assets.STRK.token_address = "0x999";
  manifest.funding.assets.ETH.token_address = "0x998";
  manifest.funding.assets.USDC.rail_token_address = "0x997";
  writeManifest(env, manifest);

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /product\.assets\.STRK\.token_address must match token_addresses\.STRK/);
  assert.match(result.stderr, /funding\.assets\.ETH\.token_address must match token_addresses\.ETH/);
  assert.match(result.stderr, /funding\.assets\.USDC\.rail_token_address must match token_addresses\.USDC/);
});

test("production readiness rejects invalid or zero deployment felt env", () => {
  const { env } = fixtureEnv();
  env.ZYLITH_PAYMASTER_ACCOUNT_ADDRESS = "not-a-felt";
  env.ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS = "0x0";

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ZYLITH_PAYMASTER_ACCOUNT_ADDRESS must be a valid Starknet felt/);
  assert.match(result.stderr, /ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS must be non-zero/);
});

test("production readiness rejects invalid or zero manifest felts", () => {
  const { env, manifest } = fixtureEnv();
  manifest.token_addresses.STRK = "not-a-felt";
  manifest.token_addresses.USDC =
    "0x800000000000011000000000000000000000000000000000000000000000001";
  manifest.contracts.auction_verifier = "0x0";
  manifest.funding.starknet_privacy.privacy_pool = "0x0";
  writeManifest(env, manifest);

  const result = runReadiness(env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /token_addresses\.STRK must be a valid Starknet felt/);
  assert.match(result.stderr, /token_addresses\.USDC must be a valid Starknet felt/);
  assert.match(result.stderr, /contracts\.auction_verifier must be non-zero/);
  assert.match(result.stderr, /funding\.starknet_privacy\.privacy_pool must be non-zero/);
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
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  const env = {
    ...process.env,
    ZYLITH_DEPLOYMENT_MANIFEST_PATH: manifestPath,
    ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET: "a".repeat(32),
    ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS: "b".repeat(32),
    ZYLITH_HEARTBEAT_COVER_SECRET: "c".repeat(32),
    ZYLITH_PROVER_STRICT: "true",
    ZYLITH_PROVER_WORKER_SUBMIT_ONCHAIN: "true",
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
    ZYLITH_PRODUCT_PAIRS: "STRK/USDC,ETH/USDC,strkBTC/USDC,STRK/ETH,STRK/strkBTC,WBTC/strkBTC,USDC/USDT",
    ZYLITH_BATCH_WINDOW_MS: "20000",
    ZYLITH_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS: "14",
    ZYLITH_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS: "36",
    ZYLITH_ARTIFACT_EPOCH_BUCKET_SIZE: "8",
    ZYLITH_OUTPUT_CLAIM_DELAY_SECONDS: "60",
    ZYLITH_AUCTION_PROVER_KEYS_PATH: join(dir, "keys.json"),
    VITE_ZYLITH_INGRESS_KEY_REGISTRY_PIN: "pin",
    ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS: "0x101",
    ZYLITH_NATIVE_PROOF_PROGRAM_HASH: "0x102",
    ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS: "0x205",
    ZYLITH_NATIVE_TX_PROVER_URL: "https://prover.zylith.fi",
    ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS: "0x104",
    ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS: "0x105",
    ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS: "0x106",
    ZYLITH_NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS: "0x107",
    ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS: "0x107",
    ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS: "0x108",
    ZYLITH_NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS: "0x109",
    ZYLITH_NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS: "0x10a",
    ZYLITH_NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS: "0x10b",
    ZYLITH_STARKNET_OS_CONFIG_HASH: "0x109",
    ZYLITH_STARKNET_CHAIN_ID: "0x534e5f5345504f4c4941",
    ZYLITH_STARKNET_ACCOUNT_ADDRESS: "0x205",
    ZYLITH_STARKNET_PRIVATE_KEY: "16".repeat(32),
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
    ZYLITH_PAYMASTER_APPROVAL_SPENDERS: "0x302",
    ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS: "0x302",
    ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS: "0x303",
    ZYLITH_RENEWAL_RELAY_STRICT: "true",
    ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE: "SelfRelay",
    ZYLITH_RENEWAL_RELAY_STORE_PATH: join(dir, "relay.sqlite"),
    ZYLITH_RENEWAL_RELAY_PACKAGE_TOKEN: "e".repeat(32),
    ZYLITH_RENEWAL_RELAY_PROVER_CONTROL_TOKEN: "d".repeat(32),
    ZYLITH_RENEWAL_RELAY_COORDINATOR_URL: "https://coordinator.zylith.fi",
    ZYLITH_RENEWAL_RELAY_PROVER_URL: "https://prover.zylith.fi",
    ZYLITH_ALERT_WEBHOOK_URL: "https://alerts.zylith.fi/hooks/prod",
    ZYLITH_MONITORING_ENV: "production",
    ZYLITH_CRASH_DUMP_POLICY: "disabled",
    ZYLITH_EXTERNAL_AUDIT_COMPLETE: "true",
    ZYLITH_EXTERNAL_AUDIT_CRITICAL_OPEN: "0",
    ZYLITH_EXTERNAL_AUDIT_HIGH_OPEN: "0",
    ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256: "b".repeat(64),
    ZYLITH_EXTERNAL_AUDIT_REPORT_URI: "https://audit.example/report.pdf",
    ZYLITH_KEY_CUSTODY_MODE: "hardware-multisig",
    ZYLITH_DEPLOYMENT_RELEASE_COMMIT: fixtureReleaseCommit(),
    ZYLITH_DEPLOYMENT_MANIFEST_SIGNER_PUBLIC_KEY_PEM: publicKey.export({ type: "spki", format: "pem" }),
  };
  Object.defineProperty(env, "__manifestPrivateKeyPem", {
    value: privateKey.export({ type: "pkcs8", format: "pem" }),
    enumerable: false,
  });
  env.ZYLITH_DEPLOYMENT_MANIFEST_PATH = manifestPath;
  writeManifest(env, manifest);

  return { env, manifest };
}

function fixtureManifest(proofOverrides) {
  const requiredAssets = ["STRK", "ETH", "USDC", "strkBTC", "WBTC", "USDT"];
  const pairs = {
    "STRK/USDC": ["STRK", "USDC", 4],
    "ETH/USDC": ["ETH", "USDC", 4],
    "strkBTC/USDC": ["strkBTC", "USDC", 4],
    "STRK/ETH": ["STRK", "ETH", 4],
    "STRK/strkBTC": ["STRK", "strkBTC", 4],
    "WBTC/strkBTC": ["WBTC", "strkBTC", 1],
    "USDC/USDT": ["USDC", "USDT", 1],
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
      shielded_asset_adapter: "0x405",
      privacy_deposit_bridge: "0x405",
    },
    token_addresses: Object.fromEntries(
      requiredAssets.map((asset, index) => [asset, `0x${(0x500 + index).toString(16)}`]),
    ),
    product: {
      assets: Object.fromEntries(
        requiredAssets.map((asset, index) => [
          asset,
          {
            asset_id: asset,
            enabled: true,
            token_address: `0x${(0x500 + index).toString(16)}`,
            erc20_behavior: "vanilla-exact-delta",
            audit_status: "approved",
            audit_evidence: {
              auditor: "fixture-auditor",
              report_uri: `https://audit.example/${asset}.pdf`,
              report_sha256: "c".repeat(64),
              approved_at: "2026-06-18",
            },
          },
        ]),
      ),
      pairs: Object.fromEntries(
        Object.entries(pairs).map(([pair, [base, quote, taker]]) => [
          pair,
          {
            pair_id: pair,
            base_asset_id: base,
            quote_asset_id: quote,
            enabled: true,
            taker_fee_bps: taker,
          },
        ]),
      ),
    },
    funding: {
      primary: "starknet_privacy",
      assets: Object.fromEntries(
        requiredAssets.map((asset, index) => [
          asset,
          {
            asset_id: asset,
            token_address: `0x${(0x500 + index).toString(16)}`,
            rail_token_address: `0x${(0x500 + index).toString(16)}`,
          },
        ]),
      ),
      starknet_privacy: {
        privacy_pool: "0x300",
        bridge_adapter: "0x405",
        discovery_url: "https://discovery.zylith.fi",
        proving_url: "https://privacy-prover.zylith.fi",
        proving_ohttp_enabled: true,
        paymaster_address: "0x207",
        paymaster_url: "https://paymaster.zylith.fi/execute-outside",
        proof_signer_class_hash: "0x208",
      },
    },
    proof: {
      proof_version: "PROOF1",
      proof_program_address: "0x601",
      proof_program_hash: "0x602",
      admission_proof_program_hash: "0x701",
      auction_result_proof_program_hash: "0x702",
      nullifier_proof_program_hash: "0x703",
      renewal_proof_program_hash: "0x704",
      liquidity_position_proof_program_hash: "0x705",
      settlement_proof_program_hash: "0x706",
      settlement_order_proof_program_hash: "0x707",
      settlement_input_membership_proof_program_hash: "0x708",
      settlement_output_recovery_proof_program_hash: "0x709",
      note_consolidation_proof_program_hash: "0x70a",
      aggregate_settlement_proof_program_hash: "0x70b",
      withdrawal_proof_program_hash: "0x70c",
      multi_pair_proof_program_hash: "0x70d",
      statement_proof_program_hashes: {
        ADMISSION: "0x701",
        AUCTION_RESULT: "0x702",
        NULLIFIER: "0x703",
        RENEWAL: "0x704",
        LIQUIDITY_POSITION: "0x705",
        SETTLEMENT: "0x706",
        SETTLEMENT_ORDER: "0x707",
        SETTLEMENT_INPUT_MEMBERSHIP: "0x708",
        SETTLEMENT_OUTPUT_RECOVERY: "0x709",
        NOTE_CONSOLIDATION: "0x70a",
        AGGREGATE_SETTLEMENT: "0x70b",
        WITHDRAWAL: "0x70c",
        MULTI_PAIR: "0x70d",
      },
      settlement_statement_program_address: "0x603",
      settlement_note_fee_statement_program_address: "0x610",
      settlement_order_statement_program_address: "0x611",
      settlement_input_membership_statement_program_address: "0x612",
      settlement_output_recovery_statement_program_address: "0x613",
      nullifier_statement_program_address: "0x604",
      renewal_statement_program_address: "0x605",
      liquidity_position_statement_program_address: "0x606",
      note_consolidation_statement_program_address: "0x606",
      withdrawal_statement_program_address: "0x607",
      admission_statement_program_address: "0x608",
      auction_result_statement_program_address: "0x609",
      multi_pair_statement_program_address: "0x60a",
      proof_account_address: "0x608",
      settlement_account_address: "0x609",
      native_tx_prover_url: "https://prover.zylith.fi",
      native_tx_prover_ohttp_enabled: true,
      proof_program_locked_after_deploy: true,
      operational_config_locked_after_deploy: true,
      commitment_registry_config_locked_after_deploy: true,
      batch_registry_config_locked_after_deploy: true,
      privacy_deposit_bridge_config_locked_after_deploy: true,
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
  env.ZYLITH_DEPLOYMENT_MANIFEST_SIGNATURE = sign(
    null,
    Buffer.from(body),
    env.__manifestPrivateKeyPem,
  ).toString("base64");
}

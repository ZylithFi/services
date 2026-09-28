import assert from "node:assert/strict";
import test from "node:test";
import { check } from "./production-readiness-check.mjs";

const felt = (n) => `0x${n.toString(16)}`;
const manifest = {
  deployment: { finalized: true, release_commit: "a".repeat(40) },
  contracts: { commitment_registry: felt(1), privacy_deposit_bridge: felt(2), ekubo_external_match_router: felt(3), exchange: felt(4) },
  token_addresses: { STRK: felt(5), USDC: felt(6) },
  funding: { starknet_privacy: { ingress_key_registry_fingerprint: "ab".repeat(32) } },
  proof: {
    proof_program_address: felt(7),
    virtual_program_hash: felt(8),
    starknet_os_config_hash: felt(9),
    proof_account_address: felt(10),
    settlement_account_address: felt(11),
    config_locked_after_deploy: true,
  },
  roles: { reference_price_signer: felt(14) },
  product: { assets: { STRK: { decimals: 18 }, USDC: { decimals: 6 } }, pairs: { "STRK/USDC": { pair_id: "STRK/USDC", base_asset_id: "STRK", quote_asset_id: "USDC", taker_fee_bps: 4, min_order_amount: "1000", enabled: true } } },
  runtime: { epoch_ms: 6000 },
};

const env = {
  ZYLITH_STARKNET_RPC_URL: "https://rpc.example",
  ZYLITH_STARKNET_ACCOUNT_ADDRESS: felt(11),
  ZYLITH_STARKNET_PRIVATE_KEY: felt(12),
  ZYLITH_PROOF_ACCOUNT_ADDRESS: felt(10),
  ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY: felt(13),
  ZYLITH_FEE_NOTE_KEY: felt(15),
  ZYLITH_PROVER_DATA_KEY_HEX: "ab".repeat(32),
  ZYLITH_CONTROL_PLANE_TOKEN: "t".repeat(32),
  ZYLITH_REFERENCE_PRICE_ATTESTOR_TOKEN: "a".repeat(32),
  ZYLITH_REFERENCE_PRICE_ATTESTOR_URL: "https://attestor.example",
  ZYLITH_TX_PROVER_URLS: "http://10.0.0.5:3000,http://127.0.0.1:3001",
  ZYLITH_TX_PROVER_HEALTH_URLS: "http://10.0.0.5:3000/health,http://127.0.0.1:3001/health",
  ZYLITH_PAYMASTER_HEALTH_URL: "http://127.0.0.1:8787/health",
  ZYLITH_PRIVACY_DISCOVERY_HEALTH_URL: "https://api.example/discovery/health",
  ZYLITH_PRIVACY_PROVER_HEALTH_URL: "https://api.example/prover/health",
  ZYLITH_PROVER_ALLOWED_ORIGINS: "https://app.zylith.fi",
  ZYLITH_EXECUTION_KEYS_PATH: "/secrets/keys.json",
  ZYLITH_REFERENCE_PRICE_SIGNER_PRIVATE_KEY: felt(14),
  ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY: felt(14),
  ZYLITH_EXCHANGE_ADDRESS: felt(4),
  ZYLITH_INDEXER_ALLOWED_ORIGINS: "https://app.zylith.fi",
  ZYLITH_COORDINATOR_ALLOWED_ORIGINS: "https://app.zylith.fi",
  ZYLITH_INDEXER_DATA_PATH: "/data/index.sqlite",
  ZYLITH_COORDINATOR_RECOVERY_PATH: "/data/recovery.sqlite",
  ZYLITH_MIN_TRANSITION_FEE_STRK: "1000000000000000000",
  ZYLITH_EXTERNAL_MATCHING_DISABLED: "1",
};

const run = (overrides = {}, manifestOverride = manifest) =>
  check({ ...env, ...overrides }, () => JSON.stringify({ manifest: manifestOverride }), () => true);

test("a complete production environment passes", () => {
  assert.deepEqual(run(), []);
});

test("missing secrets, untrusted prover names and wildcard origins fail", () => {
  const failures = run({ ZYLITH_PROVER_DATA_KEY_HEX: "", ZYLITH_TX_PROVER_URLS: "https://prover.example", ZYLITH_PROVER_ALLOWED_ORIGINS: "*" });
  assert.ok(failures.some((failure) => failure.includes("ZYLITH_PROVER_DATA_KEY_HEX is required")));
  assert.ok(failures.some((failure) => failure.includes("is not local or explicitly listed")));
  assert.deepEqual(run({ ZYLITH_TX_PROVER_URLS: "https://prover.example", ZYLITH_TX_PROVER_HEALTH_URLS: "https://prover.example/health", ZYLITH_TX_PROVER_TRUSTED_HOSTS: "prover.example" }), []);
  assert.ok(failures.some((failure) => failure.includes("ZYLITH_PROVER_ALLOWED_ORIGINS must list exact https origins")));
});

test("the accounts and exchange must match the manifest, and the two accounts must differ", () => {
  const failures = run({ ZYLITH_EXCHANGE_ADDRESS: felt(99), ZYLITH_PROOF_ACCOUNT_ADDRESS: felt(11) });
  assert.ok(failures.some((failure) => failure.includes("ZYLITH_EXCHANGE_ADDRESS does not match")));
  assert.ok(failures.some((failure) => failure.includes("must differ")));
});

test("an unfinished deployment fails", () => {
  const failures = run({}, { ...manifest, proof: { ...manifest.proof, virtual_program_hash: "0x0", config_locked_after_deploy: false }, deployment: { finalized: false, release_commit: "0".repeat(40) } });
  assert.ok(failures.some((failure) => failure.includes("proof.virtual_program_hash")));
  assert.ok(failures.some((failure) => failure.includes("config_locked_after_deploy")));
  assert.ok(failures.some((failure) => failure.includes("finalized")));
  assert.ok(failures.some((failure) => failure.includes("release_commit")));
});

test("a pair without a minimum order size fails", () => {
  const pair = { ...manifest.product.pairs["STRK/USDC"], min_order_amount: "0" };
  assert.ok(run({}, { ...manifest, product: { ...manifest.product, pairs: { "STRK/USDC": pair } } }).some((failure) => failure.includes("min_order_amount")));
});

test("an unpinned execution key registry fails", () => {
  for (const pin of ["0".repeat(64), "xyz", undefined]) {
    const failures = run({}, { ...manifest, funding: { starknet_privacy: { ingress_key_registry_fingerprint: pin } } });
    assert.ok(failures.some((failure) => failure.includes("ingress_key_registry_fingerprint")), String(pin));
  }
});

test("a missing fee floor, retired fee settings and epoch drift fail", () => {
  const failures = run({ ZYLITH_MIN_TRANSITION_FEE_STRK: "0", ZYLITH_MIN_SETTLEMENT_FEES: '{"STRK/USDC":"1"}', ZYLITH_EPOCH_MS: "8000" });
  assert.ok(failures.some((failure) => failure.includes("ZYLITH_MIN_TRANSITION_FEE_STRK must")));
  assert.ok(failures.some((failure) => failure.includes("ZYLITH_MIN_SETTLEMENT_FEES is retired")));
  assert.ok(failures.some((failure) => failure.includes("epoch_ms")));
});

test("external matching is either fully configured or explicitly disabled", () => {
  const external = (window) => ({
    ...manifest,
    product: { ...manifest.product, pairs: { "STRK/USDC": { ...manifest.product.pairs["STRK/USDC"], external_match_enabled: true } } },
    runtime: { ...manifest.runtime, external_window_seconds: window },
  });
  assert.ok(run({ ZYLITH_EXTERNAL_MATCHING_DISABLED: "" }).some((failure) => failure.includes("ZYLITH_EXTERNAL_MATCHING_DISABLED=1")));
  const incomplete = run({ ZYLITH_EXTERNAL_MATCHING_DISABLED: "" }, external(0));
  assert.ok(incomplete.some((failure) => failure.includes("ZYLITH_ROUTE_SERVICE_URL")));
  assert.ok(incomplete.some((failure) => failure.includes("ZYLITH_SEARCHER_MIN_PROFIT.USDC")));
  assert.ok(incomplete.some((failure) => failure.includes("external_window_seconds")));
  assert.ok(run({}, external(12)).some((failure) => failure.includes("match externally")));
  const configured = { ZYLITH_EXTERNAL_MATCHING_DISABLED: "", ZYLITH_ROUTE_SERVICE_URL: "https://quoter.example", ZYLITH_ROUTE_SERVICE_HEALTH_URL: "https://quoter.example/health", ZYLITH_SEARCHER_MIN_PROFIT: '{"USDC":"1000"}' };
  assert.deepEqual(run(configured, external(12)), []);
});

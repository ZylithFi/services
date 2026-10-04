import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { check } from "./production-readiness-check.mjs";

const felt = (n) => `0x${n.toString(16)}`;
const manifest = JSON.parse(readFileSync(new URL("../client/public/deployment.example.json", import.meta.url), "utf8"));
Object.assign(manifest, {
  deployment: { finalized: true, release_commit: "a".repeat(40) },
  contracts: { commitment_registry: felt(1), privacy_deposit_bridge: felt(2), ekubo_external_match_router: felt(0), exchange: felt(4) },
  roles: { ...manifest.roles, reference_price_signer: felt(14) },
});
Object.assign(manifest.proof, {
  transition_proof_program_address: felt(7), withdrawal_proof_program_address: felt(17), residual_recovery_proof_program_address: felt(18), virtual_program_hash: felt(8), starknet_os_config_hash: felt(9),
  proof_account_address: felt(10), settlement_account_address: felt(11), proof_validity_blocks: 450,
  config_locked_after_deploy: true, prover_build_id: "stwo-production-v1",
});
manifest.funding.starknet_privacy.ingress_key_registry_fingerprint = "ab".repeat(32);
manifest.funding.starknet_privacy.proving_ohttp_policy = "best_effort";
Object.assign(manifest.funding.starknet_privacy, {
  privacy_pool: felt(16),
  privacy_pool_class_hash: felt(19),
  bridge_adapter: felt(2),
  discovery_url: "https://discovery.example",
  proving_url: "https://prover.example",
  paymaster_address: felt(17),
  paymaster_url: "https://paymaster.example",
  proof_signer_class_hash: felt(18),
});

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(",")}}`;
}

function rehash(value) {
  const registry = value.market_registry;
  const hashInput = { ...registry };
  delete hashInput.registry_hash;
  registry.registry_hash = createHash("sha256").update(canonicalJson(hashInput)).digest("hex");
  return value;
}

function externallyEnabledManifest() {
  const value = structuredClone(manifest);
  const market = value.market_registry.markets.find((candidate) => candidate.market_id === "STRK/ETH");
  assert.ok(market);
  market.capabilities.external_matching = true;
  market.external_settlement_support_quote = "1";
  market.external_min_profit_quote = "1";
  value.contracts.ekubo_external_match_router = felt(3);
  value.runtime.external_window_seconds = 30;
  return rehash(value);
}

const env = {
  ZYLITH_STARKNET_RPC_URL: "https://rpc.example",
  ZYLITH_STARKNET_ACCOUNT_ADDRESS: felt(11),
  ZYLITH_STARKNET_PRIVATE_KEY: felt(12),
  ZYLITH_PROOF_ACCOUNT_ADDRESS: felt(10),
  ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY: felt(13),
  ZYLITH_FEE_NOTE_KEY: felt(15),
  ZYLITH_OPERATOR_DATA_KEY_HEX: "ab".repeat(32),
  ZYLITH_CONTROL_PLANE_TOKEN: "t".repeat(32),
  ZYLITH_REFERENCE_PRICE_ATTESTOR_TOKEN: "a".repeat(32),
  ZYLITH_REFERENCE_PRICE_ATTESTOR_URL: "https://attestor.example",
  ZYLITH_PROOF_QUEUE_URL: "http://127.0.0.1:3000",
  ZYLITH_PROOF_QUEUE_HEALTH_URL: "http://127.0.0.1:3000/internal/proof-queue/health",
  ZYLITH_PROOF_QUEUE_CONTROL_TOKEN: "q".repeat(32),
  ZYLITH_PROOF_QUEUE_MONITOR_TOKEN: "m".repeat(32),
  ZYLITH_PROVER_BUILD_ID: "stwo-production-v1",
  ZYLITH_PAYMASTER_HEALTH_URL: "http://127.0.0.1:8787/health",
  ZYLITH_PRIVACY_DISCOVERY_HEALTH_URL: "https://api.example/discovery/health",
  ZYLITH_PRIVACY_PROVER_HEALTH_URL: "https://api.example/prover/health",
  ZYLITH_OPERATOR_ALLOWED_ORIGINS: "https://app.zylith.fi",
  ZYLITH_EXECUTION_KEYS_PATH: "/secrets/keys.json",
  ZYLITH_REFERENCE_PRICE_SIGNER_PRIVATE_KEY: felt(14),
  ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY: felt(14),
  ZYLITH_EXCHANGE_ADDRESS: felt(4),
  ZYLITH_INDEXER_ALLOWED_ORIGINS: "https://app.zylith.fi",
  ZYLITH_COORDINATOR_ALLOWED_ORIGINS: "https://app.zylith.fi",
  ZYLITH_INDEXER_DATA_PATH: "/data/index.sqlite",
  ZYLITH_COORDINATOR_RECOVERY_PATH: "/data/recovery.sqlite",
  ZYLITH_PROOF_QUEUE_DATABASE_PATH: "/data/control-plane.sqlite",
  ZYLITH_PROOF_ARTIFACT_DIRECTORY: "/data/proof-artifacts",
  ZYLITH_PROOF_ARTIFACT_KEY_HEX: "cd".repeat(32),
  ZYLITH_PROOF_WORKER_GRANT_TTL_MS: "300000",
  ZYLITH_PROOF_WORKER_SESSION_TTL_MS: "1800000",
  ZYLITH_PROOF_WORKER_MAX_LIFETIME_MS: "14400000",
  ZYLITH_PROOF_JOB_LEASE_MS: "60000",
  ZYLITH_PROOF_WORKER_REQUEST_TIMEOUT_SECONDS: "900",
  ZYLITH_PROOF_JOB_COMPLETED_RETENTION_MS: "3600000",
  ZYLITH_PROOF_JOB_ABANDONED_RETENTION_MS: "604800000",
  ZYLITH_PROOF_JOB_CLEANUP_INTERVAL_MS: "60000",
  ZYLITH_MIN_TRANSITION_FEE_STRK: "1000000000000000000",
  ZYLITH_EXTERNAL_MATCHING_DISABLED: "1",
  ZYLITH_ROUTE_SERVICE_URL: "",
  ZYLITH_ROUTE_SERVICE_HEALTH_URL: "",
};

const run = (overrides = {}, manifestOverride = manifest) =>
  check({ ...env, ...overrides }, () => JSON.stringify({ manifest: manifestOverride }), () => true);

test("a complete production environment passes", () => {
  assert.deepEqual(run(), []);
  assert.deepEqual(run({ ZYLITH_REFERENCE_PRICE_ATTESTOR_URL: "http://127.0.0.1:8790" }), []);
});

test("funding services cannot remain placeholders", () => {
  const incomplete = structuredClone(manifest);
  incomplete.funding.starknet_privacy.paymaster_address = "0x0";
  incomplete.funding.starknet_privacy.proving_url = "http://prover.example";
  const failures = run({}, incomplete);
  assert.ok(failures.some((failure) => failure.includes("paymaster_address must be set")));
  assert.ok(failures.some((failure) => failure.includes("proving_url must use https")));
});

test("the proof queue monitor cannot reuse the control credential", () => {
  const failures = run({ ZYLITH_PROOF_QUEUE_MONITOR_TOKEN: "q".repeat(32) });
  assert.ok(failures.some((failure) => failure.includes("monitoring and control tokens must differ")));
});

test("a worker session covers the complete proof timeout and lease", () => {
  const failures = run({ ZYLITH_PROOF_WORKER_SESSION_TTL_MS: "959999" });
  assert.ok(failures.some((failure) => failure.includes("proof timeout plus one proof-job lease")));
  assert.deepEqual(run({ ZYLITH_PROOF_WORKER_SESSION_TTL_MS: "960000" }), []);
});

test("missing secrets and wildcard origins fail", () => {
  const failures = run({ ZYLITH_OPERATOR_DATA_KEY_HEX: "", ZYLITH_OPERATOR_ALLOWED_ORIGINS: "*" });
  assert.ok(failures.some((failure) => failure.includes("ZYLITH_OPERATOR_DATA_KEY_HEX is required")));
  assert.ok(failures.some((failure) => failure.includes("ZYLITH_OPERATOR_ALLOWED_ORIGINS must list exact https origins")));
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
  const changed = structuredClone(manifest);
  changed.market_registry.markets[0].min_order_amount = "0";
  rehash(changed);
  assert.ok(run({}, changed).some((failure) => failure.includes("min_order_amount")));
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
  const incomplete = externallyEnabledManifest();
  incomplete.runtime.external_window_seconds = 0;
  assert.ok(run({ ZYLITH_EXTERNAL_MATCHING_DISABLED: "", ZYLITH_ROUTE_SERVICE_URL: "" }, incomplete).some((failure) => failure.includes("ZYLITH_ROUTE_SERVICE_URL")));
  const failures = run({ ZYLITH_EXTERNAL_MATCHING_DISABLED: "", ZYLITH_ROUTE_SERVICE_URL: "https://quoter.example", ZYLITH_ROUTE_SERVICE_HEALTH_URL: "https://quoter.example/393402133025997798000961/health" }, incomplete);
  assert.ok(failures.some((failure) => failure.includes("external_window_seconds")));
  assert.ok(run({ ZYLITH_EXTERNAL_MATCHING_DISABLED: "1" }, externallyEnabledManifest()).some((failure) => failure.includes("match externally")));

  const disabled = structuredClone(manifest);
  disabled.contracts.ekubo_external_match_router = felt(0);
  disabled.runtime.external_window_seconds = 0;
  for (const market of disabled.market_registry.markets) {
    market.capabilities.external_matching = false;
    market.external_settlement_support_quote = "0";
    market.external_min_profit_quote = "0";
  }
  rehash(disabled);
  const disabledEnv = { ZYLITH_EXTERNAL_MATCHING_DISABLED: "1", ZYLITH_ROUTE_SERVICE_URL: "", ZYLITH_ROUTE_SERVICE_HEALTH_URL: "" };
  assert.deepEqual(run(disabledEnv, disabled), []);
});

test("external route health probes the configured chain", () => {
  const failures = run({ ZYLITH_EXTERNAL_MATCHING_DISABLED: "", ZYLITH_ROUTE_SERVICE_URL: "https://quoter.example", ZYLITH_ROUTE_SERVICE_HEALTH_URL: "https://quoter.example/health" }, externallyEnabledManifest());
  assert.ok(failures.some((failure) => failure.includes("must probe the configured chain")));
});

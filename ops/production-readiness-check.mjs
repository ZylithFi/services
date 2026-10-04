#!/usr/bin/env node
// validates a production environment before the services start: every secret, url, key and
// limit the operator, attestor, indexer and backup service read, and the deployment manifest they
// share. exits non-zero with every failure listed.
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";

export function check(env, readFile = (path) => readFileSync(path, "utf8"), fileExists = existsSync) {
  const failures = [];
  const value = (name) => (env[name] ?? "").trim();
  const fail = (message) => failures.push(message);
  const required = (name) => value(name) || (fail(`${name} is required`), "");
  const felt = (name) => {
    const raw = required(name);
    if (raw && !isNonZeroFelt(raw)) fail(`${name} must be a nonzero felt`);
    return raw;
  };
  const hexKey = (name, bytes) => {
    const raw = required(name).replace(/^0x/i, "");
    if (raw && !new RegExp(`^[0-9a-f]{${bytes * 2}}$`, "i").test(raw)) fail(`${name} must be ${bytes} hex bytes`);
  };
  const secret = (name, minimum) => {
    const raw = required(name);
    if (raw && raw.length < minimum) fail(`${name} must be at least ${minimum} characters`);
  };
  const integer = (name, minimum, maximum, fallback) => {
    const raw = value(name);
    if (!raw && fallback !== undefined) return fallback;
    const parsed = Number(required(name));
    if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) fail(`${name} must be an integer in [${minimum}, ${maximum}]`);
    return parsed;
  };
  const httpsUrls = (name, { optional = false } = {}) => {
    const raw = optional ? value(name) : required(name);
    for (const url of raw.split(",").map((entry) => entry.trim()).filter(Boolean)) {
      if (!/^https:\/\//i.test(url)) fail(`${name} must use https: ${url}`);
    }
  };
  const healthUrls = (name) => {
    const raw = required(name);
    for (const url of raw.split(",").map((entry) => entry.trim()).filter(Boolean)) {
      let parsed;
      try {
        parsed = new URL(url);
      } catch {
        fail(`${name} contains an invalid url: ${url}`);
        continue;
      }
      if (parsed.protocol !== "https:" && !isOperatorHost(url)) fail(`${name} must use https or an operator-local address: ${url}`);
    }
  };
  const origins = (name) => {
    const raw = required(name);
    for (const origin of raw.split(",").map((entry) => entry.trim()).filter(Boolean)) {
      if (origin.includes("*") || !/^https:\/\/[^/]+$/i.test(origin)) fail(`${name} must list exact https origins: ${origin}`);
    }
  };

  // the operator.
  httpsUrls("ZYLITH_STARKNET_RPC_URL");
  felt("ZYLITH_STARKNET_ACCOUNT_ADDRESS");
  felt("ZYLITH_STARKNET_PRIVATE_KEY");
  felt("ZYLITH_PROOF_ACCOUNT_ADDRESS");
  felt("ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY");
  felt("ZYLITH_FEE_NOTE_KEY");
  if (value("ZYLITH_STARKNET_ACCOUNT_ADDRESS") && value("ZYLITH_STARKNET_ACCOUNT_ADDRESS") === value("ZYLITH_PROOF_ACCOUNT_ADDRESS")) {
    fail("the settlement and proof accounts must differ so their nonces never race");
  }
  hexKey("ZYLITH_OPERATOR_DATA_KEY_HEX", 32);
  secret("ZYLITH_CONTROL_PLANE_TOKEN", 32);
  secret("ZYLITH_REFERENCE_PRICE_ATTESTOR_TOKEN", 32);
  healthUrls("ZYLITH_REFERENCE_PRICE_ATTESTOR_URL");
  healthUrls("ZYLITH_PROOF_QUEUE_URL");
  secret("ZYLITH_PROOF_QUEUE_CONTROL_TOKEN", 32);
  required("ZYLITH_PROVER_BUILD_ID");
  httpsUrls("ZYLITH_ROUTE_SERVICE_URL", { optional: true });
  healthUrls("ZYLITH_PAYMASTER_HEALTH_URL");
  healthUrls("ZYLITH_PRIVACY_DISCOVERY_HEALTH_URL");
  healthUrls("ZYLITH_PRIVACY_PROVER_HEALTH_URL");
  healthUrls("ZYLITH_PROOF_QUEUE_HEALTH_URL");
  origins("ZYLITH_OPERATOR_ALLOWED_ORIGINS");
  const executionKeys = required("ZYLITH_EXECUTION_KEYS_PATH");
  if (executionKeys && !fileExists(executionKeys)) fail(`ZYLITH_EXECUTION_KEYS_PATH does not exist: ${executionKeys}`);
  const epochMs = integer("ZYLITH_EPOCH_MS", 1_000, 300_000, 6_000);
  integer("ZYLITH_PIPELINE_DEPTH", 1, 4, 2);
  const provingBlocksBack = integer("ZYLITH_PROVING_BLOCKS_BACK", 1, 1_000, 1);
  integer("ZYLITH_PRIVATE_RATE_LIMIT_PER_MINUTE", 1, 600, 60);
  // fees pay for gas: every transition's fees must be worth a positive floor in strk, valued
  // at attested rates less a haircut.
  if (!/^[1-9]\d*$/.test(value("ZYLITH_MIN_TRANSITION_FEE_STRK"))) fail("ZYLITH_MIN_TRANSITION_FEE_STRK must be a positive integer of strk atoms");
  integer("ZYLITH_FEE_RATE_HAIRCUT_BPS", 0, 5_000, 100);
  for (const retired of ["ZYLITH_MIN_SETTLEMENT_FEES", "ZYLITH_SEARCHER_MIN_PROFIT_QUOTE", "ZYLITH_SEARCHER_MIN_PROFIT", "ZYLITH_MARKET_DATA_PAIRS", "ZYLITH_REFERENCE_PRICE_SOURCES_PATH", "ZYLITH_REFERENCE_PRICE_ATTESTATION_TTL_MS", "ZYLITH_PAIRS", "ZYLITH_TOKENS", "ZYLITH_EXTERNAL_PAIRS", "ZYLITH_PAIR_FEE_BPS", "ZYLITH_EXTERNAL_SETTLEMENT_SUPPORT_QUOTE"]) {
    if (value(retired)) fail(`${retired} is retired; use the canonical market registry`);
  }

  // the attestor signs only for the exchange.
  felt("ZYLITH_REFERENCE_PRICE_SIGNER_PRIVATE_KEY");
  felt("ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY");
  felt("ZYLITH_EXCHANGE_ADDRESS");

  // the indexer and the backup service.
  origins("ZYLITH_INDEXER_ALLOWED_ORIGINS");
  origins("ZYLITH_COORDINATOR_ALLOWED_ORIGINS");
  required("ZYLITH_INDEXER_DATA_PATH");
  required("ZYLITH_COORDINATOR_RECOVERY_PATH");
  required("ZYLITH_PROOF_QUEUE_DATABASE_PATH");
  required("ZYLITH_PROOF_ARTIFACT_DIRECTORY");
  hexKey("ZYLITH_PROOF_ARTIFACT_KEY_HEX", 32);
  secret("ZYLITH_PROOF_QUEUE_MONITOR_TOKEN", 32);
  if (value("ZYLITH_PROOF_QUEUE_MONITOR_TOKEN") === value("ZYLITH_PROOF_QUEUE_CONTROL_TOKEN")) fail("proof queue monitoring and control tokens must differ");
  integer("ZYLITH_PROOF_WORKER_GRANT_TTL_MS", 1_000, 15 * 60_000, 5 * 60_000);
  const proofWorkerSessionMs = integer("ZYLITH_PROOF_WORKER_SESSION_TTL_MS", 60_000, 60 * 60_000, 30 * 60_000);
  const proofWorkerLifetimeMs = integer("ZYLITH_PROOF_WORKER_MAX_LIFETIME_MS", 5 * 60_000, 24 * 60 * 60_000, 4 * 60 * 60_000);
  const proofJobLeaseMs = integer("ZYLITH_PROOF_JOB_LEASE_MS", 1_000, 15 * 60_000, 60_000);
  const proofWorkerRequestTimeoutSeconds = integer("ZYLITH_PROOF_WORKER_REQUEST_TIMEOUT_SECONDS", 1, 60 * 60, 900);
  const completedRetentionMs = integer("ZYLITH_PROOF_JOB_COMPLETED_RETENTION_MS", 60_000, 24 * 60 * 60_000, 60 * 60_000);
  const abandonedRetentionMs = integer("ZYLITH_PROOF_JOB_ABANDONED_RETENTION_MS", 60_000, 30 * 24 * 60 * 60_000, 7 * 24 * 60 * 60_000);
  integer("ZYLITH_PROOF_JOB_CLEANUP_INTERVAL_MS", 1_000, 60 * 60_000, 60_000);
  if (abandonedRetentionMs <= completedRetentionMs) fail("abandoned proof jobs must outlive completed proof jobs");
  if (proofWorkerSessionMs < proofWorkerRequestTimeoutSeconds * 1_000 + proofJobLeaseMs) fail("proof worker sessions must cover the proof timeout plus one proof-job lease");
  if (proofWorkerLifetimeMs < proofWorkerSessionMs) fail("proof worker maximum lifetime must cover one session");

  // the shared manifest.
  const manifestPath = value("ZYLITH_DEPLOYMENT_MANIFEST") || "client/public/deployment.json";
  let manifest = null;
  try {
    const parsed = JSON.parse(readFile(manifestPath));
    manifest = parsed.manifest ?? parsed;
  } catch {
    fail(`deployment manifest ${manifestPath} is unreadable`);
  }
  if (manifest) {
    for (const contract of ["commitment_registry", "privacy_deposit_bridge", "exchange"]) {
      if (!isNonZeroFelt(manifest.contracts?.[contract])) fail(`manifest contracts.${contract} must be deployed`);
    }
    for (const field of ["transition_proof_program_address", "withdrawal_proof_program_address", "residual_recovery_proof_program_address", "virtual_program_hash", "starknet_os_config_hash", "proof_account_address", "settlement_account_address"]) {
      if (!isNonZeroFelt(manifest.proof?.[field])) fail(`manifest proof.${field} must be set`);
    }
    // wallets seal only to the execution keys the manifest pins; the operator checks its own
    // keys against the pin at startup.
    const pins = [manifest.funding?.starknet_privacy?.ingress_key_registry_fingerprint, manifest.funding?.starknet_privacy?.ingress_key_registry_next_fingerprint].filter((pin) => pin !== undefined);
    if (!pins.length || pins.some((pin) => !/^[0-9a-f]{64}$/.test(pin) || /^0+$/.test(pin))) fail("manifest funding.starknet_privacy.ingress_key_registry_fingerprint must pin the execution keys");
    if (manifest.funding?.starknet_privacy?.proving_ohttp_policy !== "best_effort") fail("production funding proving_ohttp_policy must be best_effort");
    const privacyFunding = manifest.funding?.starknet_privacy;
    for (const field of ["privacy_pool", "privacy_pool_class_hash", "bridge_adapter", "paymaster_address", "proof_signer_class_hash"]) {
      if (!isNonZeroFelt(privacyFunding?.[field])) fail(`manifest funding.starknet_privacy.${field} must be set`);
    }
    for (const field of ["discovery_url", "proving_url", "paymaster_url"]) {
      if (!/^https:\/\//i.test(privacyFunding?.[field] ?? "")) fail(`manifest funding.starknet_privacy.${field} must use https`);
    }
    if (manifest.proof?.config_locked_after_deploy !== true) fail("manifest proof.config_locked_after_deploy must be true");
    if (!Number.isInteger(manifest.proof?.proof_validity_blocks) || manifest.proof.proof_validity_blocks <= 5) fail("manifest proof.proof_validity_blocks must leave submission headroom");
    if (provingBlocksBack + 5 >= manifest.proof?.proof_validity_blocks) fail("ZYLITH_PROVING_BLOCKS_BACK leaves no validity window for submission");
    if (!manifest.proof?.prover_build_id) fail("manifest proof.prover_build_id must be set");
    if (value("ZYLITH_PROVER_BUILD_ID") && value("ZYLITH_PROVER_BUILD_ID") !== manifest.proof?.prover_build_id) fail("ZYLITH_PROVER_BUILD_ID does not match the manifest's proof.prover_build_id");
    if (manifest.deployment?.finalized !== true) fail("manifest deployment.finalized must be true");
    if (!/^[0-9a-f]{40}$/.test(manifest.deployment?.release_commit ?? "") || /^0+$/.test(manifest.deployment.release_commit)) {
      fail("manifest deployment.release_commit must name the released commit");
    }
    if (value("ZYLITH_EXCHANGE_ADDRESS") && !sameFelt(value("ZYLITH_EXCHANGE_ADDRESS"), manifest.contracts?.exchange)) {
      fail("ZYLITH_EXCHANGE_ADDRESS does not match the manifest's exchange");
    }
    if (!isNonZeroFelt(manifest.roles?.reference_price_signer)) fail("manifest roles.reference_price_signer must be set");
    if (value("ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY") && !sameFelt(value("ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY"), manifest.roles?.reference_price_signer)) {
      fail("ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY does not match the manifest's roles.reference_price_signer");
    }
    for (const [account, field] of [["ZYLITH_STARKNET_ACCOUNT_ADDRESS", "settlement_account_address"], ["ZYLITH_PROOF_ACCOUNT_ADDRESS", "proof_account_address"]]) {
      if (value(account) && !sameFelt(value(account), manifest.proof?.[field])) fail(`${account} does not match the manifest's proof.${field}`);
    }
    if (manifest.runtime?.epoch_ms !== epochMs) fail(`manifest runtime.epoch_ms (${manifest.runtime?.epoch_ms}) differs from ZYLITH_EPOCH_MS (${epochMs})`);
    const registry = manifest.market_registry;
    if (!registry || registry.schema_version !== 1 || !Number.isSafeInteger(registry.registry_version) || registry.registry_version <= 0 || !/^[0-9a-f]{64}$/.test(registry.registry_hash ?? "")) {
      fail("manifest market_registry identity is invalid");
    } else {
      const hashInput = { ...registry };
      delete hashInput.registry_hash;
      const computed = createHash("sha256").update(canonicalJson(hashInput)).digest("hex");
      if (computed !== registry.registry_hash) fail("manifest market_registry hash is invalid");
      if (registry.network !== manifest.network || registry.chain_id !== manifest.chain_id) fail("manifest and market_registry identities differ");
      if (!/^[a-z0-9_-]{1,32}$/.test(registry.network)) fail("manifest market_registry network is invalid");
    }
    const rawAssets = registry?.assets ?? [];
    const assetIds = rawAssets.map((asset) => asset.asset_id);
    const assets = new Map(rawAssets.map((asset) => [asset.asset_id, asset]));
    const marketIds = (registry?.markets ?? []).map((market) => market.market_id);
    if (!strictlySortedUnique(assetIds) || !strictlySortedUnique(marketIds)) fail("market registry assets and markets must be sorted and unique");
    if (!assets.get(registry?.gas_fee_asset_id)?.enabled || !assets.get(registry?.objective_numeraire_asset_id)?.enabled) fail("market registry gas and numeraire assets must be enabled");
    if (!/^[1-9]\d*$/.test(String(registry?.connected_wallet_fee_reserve_amount ?? ""))) fail("market registry connected-wallet fee reserve must be positive");
    const tokenAddresses = new Set();
    for (const asset of rawAssets) {
      if (!isNonZeroFelt(asset.token_address) || !Number.isInteger(asset.decimals) || asset.decimals < 0 || asset.decimals > 36) fail(`asset ${asset.asset_id} has invalid token configuration`);
      const token = isNonZeroFelt(asset.token_address) ? `0x${BigInt(asset.token_address).toString(16)}` : "";
      if (tokenAddresses.has(token)) fail(`asset ${asset.asset_id} repeats a token address`);
      tokenAddresses.add(token);
      if (asset.enabled && !asset.funding_enabled) fail(`enabled asset ${asset.asset_id} is missing funding capability`);
      if (!asset.enabled && asset.funding_enabled) fail(`disabled asset ${asset.asset_id} cannot enable funding`);
      const relationship = asset.reference_identity?.relationship;
      const reference = asset.reference_identity?.reference_asset_id;
      if (!["native", "wrapped_one_to_one", "stable_one_to_one"].includes(relationship) || typeof reference !== "string" || (relationship === "native") !== (reference === asset.asset_id)) fail(`asset ${asset.asset_id} has invalid reference identity`);
    }
    const pairs = (registry?.markets ?? []).filter((pair) => pair.enabled);
    for (const pair of registry?.markets ?? []) if (!pair.enabled && pair.capabilities?.external_matching) fail(`disabled market ${pair.market_id} cannot enable external matching`);
    if (pairs.length === 0) fail("market registry enables no markets");
    for (const pair of pairs) {
      if (!Number.isInteger(pair.taker_fee_bps) || pair.taker_fee_bps < 1 || pair.taker_fee_bps > 100) fail(`market ${pair.market_id} fee must be 1..100 bps`);
      if (!/^[1-9]\d*$/.test(String(pair.min_order_amount ?? ""))) fail(`market ${pair.market_id} needs a positive min_order_amount`);
      if (!/^[1-9]\d*$/.test(String(pair.min_order_quote_amount ?? ""))) fail(`market ${pair.market_id} needs a positive min_order_quote_amount`);
      if (/^[1-9]\d*$/.test(String(pair.min_order_amount ?? "")) && /^[1-9]\d*$/.test(String(assets.get(pair.base_asset_id)?.min_trade_amount ?? "")) && BigInt(pair.min_order_amount) < BigInt(assets.get(pair.base_asset_id).min_trade_amount)) fail(`market ${pair.market_id} minimum is below its base asset minimum`);
      if (/^[1-9]\d*$/.test(String(pair.min_order_quote_amount ?? "")) && /^[1-9]\d*$/.test(String(assets.get(pair.quote_asset_id)?.min_trade_amount ?? "")) && BigInt(pair.min_order_quote_amount) < BigInt(assets.get(pair.quote_asset_id).min_trade_amount)) fail(`market ${pair.market_id} minimum value is below its quote asset minimum`);
      const support = String(pair.external_settlement_support_quote ?? "");
      const profit = String(pair.external_min_profit_quote ?? "");
      if (!/^\d+$/.test(support) || !/^\d+$/.test(profit) || pair.capabilities?.external_matching !== (BigInt(/^\d+$/.test(support) ? support : 0) > 0n && BigInt(/^\d+$/.test(profit) ? profit : 0) > 0n)) {
        fail(`market ${pair.market_id} has incomplete external matching configuration`);
      }
      for (const asset of [pair.base_asset_id, pair.quote_asset_id]) {
        if (!assets.has(asset)) fail(`market ${pair.market_id} refers to unknown asset ${asset}`);
      }
      if (pair.capabilities?.market_data !== true) fail(`enabled market ${pair.market_id} is missing market-data capability`);
      const policy = pair.reference_price ?? {};
      if (!Number.isSafeInteger(policy.max_age_ms) || policy.max_age_ms < 1 || policy.max_age_ms > 15_000 || !Number.isSafeInteger(policy.attestation_ttl_ms) || policy.attestation_ttl_ms < 1 || policy.attestation_ttl_ms > 15_000 || !Number.isSafeInteger(policy.envelope_bps) || policy.envelope_bps < 1 || policy.envelope_bps >= 10_000) fail(`market ${pair.market_id} has invalid reference policy`);
      if (policy.methodology === "direct_bbo_midpoint") {
        const sources = [policy.primary, ...(policy.corroborating ?? [])];
        const adapters = sources.map((source) => source?.adapter);
        if (pair.quote_asset_id !== registry.objective_numeraire_asset_id || policy.primary?.kind !== "direct" || policy.primary?.adapter !== "binance" || sources.length < 3 || new Set(adapters).size !== adapters.length || adapters.some((adapter) => !["binance", "coinbase", "kraken", "okx"].includes(adapter))) fail(`market ${pair.market_id} has invalid direct reference sources`);
        if (!Number.isSafeInteger(policy.min_sources) || policy.min_sources < 3 || policy.min_sources > sources.length || [policy.max_source_spread_bps, policy.max_cross_source_deviation_bps].some((number) => !Number.isSafeInteger(number) || number < 1 || number >= 10_000)) fail(`market ${pair.market_id} has invalid direct reference policy`);
      } else if (policy.methodology === "synthetic_cross_bbo_midpoint") {
        const base = pairs.find((candidate) => candidate.market_id === policy.base_market_id);
        const quote = pairs.find((candidate) => candidate.market_id === policy.quote_market_id);
        if (!base || !quote || base.reference_price?.methodology !== "direct_bbo_midpoint" || quote.reference_price?.methodology !== "direct_bbo_midpoint" || base.base_asset_id !== pair.base_asset_id || quote.base_asset_id !== pair.quote_asset_id || base.quote_asset_id !== registry.objective_numeraire_asset_id || quote.quote_asset_id !== registry.objective_numeraire_asset_id || base.price_base_scale !== pair.price_base_scale || quote.price_base_scale !== pair.price_base_scale || !Number.isSafeInteger(policy.max_leg_skew_ms) || policy.max_leg_skew_ms < 1 || policy.max_leg_skew_ms > policy.max_age_ms) fail(`market ${pair.market_id} has invalid synthetic reference policy`);
      } else {
        fail(`market ${pair.market_id} has unsupported reference pricing`);
      }
    }
    for (const asset of rawAssets.filter((candidate) => candidate.enabled && candidate.asset_id !== registry?.objective_numeraire_asset_id)) {
      const direct = pairs.filter((pair) => (pair.base_asset_id === asset.asset_id && pair.quote_asset_id === registry.objective_numeraire_asset_id) || (pair.quote_asset_id === asset.asset_id && pair.base_asset_id === registry.objective_numeraire_asset_id));
      if (direct.length !== 1) fail(`asset ${asset.asset_id} must have exactly one direct objective-numeraire market`);
    }
    // external matching is either fully configured or explicitly off.
    const external = pairs.filter((pair) => pair.capabilities?.external_matching === true);
    if (external.length === 0) {
      if (value("ZYLITH_EXTERNAL_MATCHING_DISABLED") !== "1") fail("no pair matches externally: set ZYLITH_EXTERNAL_MATCHING_DISABLED=1 to confirm routing is off");
      if (value("ZYLITH_ROUTE_SERVICE_URL")) fail("external route service must be unset when every registry market disables external matching");
      if (isNonZeroFelt(manifest.contracts?.ekubo_external_match_router)) fail("external router must be zero when every registry market disables external matching");
      if (manifest.runtime?.external_window_seconds !== 0) fail("external window must be zero when every registry market disables external matching");
    } else {
      if (value("ZYLITH_EXTERNAL_MATCHING_DISABLED") === "1") fail(`ZYLITH_EXTERNAL_MATCHING_DISABLED is set but ${external.map((pair) => pair.market_id).join(", ")} match externally`);
      const routeServiceUrl = value("ZYLITH_ROUTE_SERVICE_URL");
      if (!routeServiceUrl) fail("external matching needs ZYLITH_ROUTE_SERVICE_URL");
      healthUrls("ZYLITH_ROUTE_SERVICE_HEALTH_URL");
      const routeHealthUrl = value("ZYLITH_ROUTE_SERVICE_HEALTH_URL");
      if (routeServiceUrl && routeHealthUrl) {
        let expected;
        try {
          const chainId = BigInt(manifest.chain_id).toString(10);
          expected = new URL(`${routeServiceUrl.replace(/\/+$/, "")}/${chainId}/health`).href;
        } catch {
          fail("deployment chain_id or ZYLITH_ROUTE_SERVICE_URL is invalid for route health validation");
        }
        if (expected) {
          let actual;
          try {
            actual = new URL(routeHealthUrl).href;
          } catch {
            actual = "";
          }
          if (actual !== expected) fail(`ZYLITH_ROUTE_SERVICE_HEALTH_URL must probe the configured chain: ${expected}`);
        }
      }
      integer("ZYLITH_SEARCHER_HEADROOM_BPS", 1, 500, 5);
      const window = manifest.runtime?.external_window_seconds;
      if (!Number.isSafeInteger(window) || window < 1 || window > 300) fail("external matching needs runtime.external_window_seconds in [1, 300]");
    }
  }
  return failures;
}

function isOperatorHost(url) {
  let host;
  try {
    host = new URL(url).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return false;
  }
  if (host === "localhost" || host === "::1") return true;
  const octets = host.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet))) return /^f[cd]/i.test(host);
  return octets[0] === 127 || octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168);
}

function isNonZeroFelt(raw) {
  if (typeof raw !== "string" || !/^0x[0-9a-f]{1,64}$/i.test(raw.trim())) return false;
  const value = BigInt(raw.trim());
  return value > 0n && value < 3618502788666131213697322783095070105623107215331596699973092056135872020481n;
}

function sameFelt(left, right) {
  return isNonZeroFelt(left) && isNonZeroFelt(right) && BigInt(left) === BigInt(right);
}

function strictlySortedUnique(values) {
  return values.every((value, index) => index === 0 || values[index - 1] < value);
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("market registry contains a non-json value");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
    .join(",")}}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const failures = check(process.env);
  if (failures.length > 0) {
    console.error("production readiness check failed");
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }
  console.log("production readiness check passed");
}

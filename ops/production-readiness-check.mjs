#!/usr/bin/env node
// validates a production environment before the services start: every secret, url, key and
// limit the operator, attestor, indexer and backup service read, and the deployment manifest they
// share. exits non-zero with every failure listed.
import { existsSync, readFileSync } from "node:fs";

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
  hexKey("ZYLITH_PROVER_DATA_KEY_HEX", 32);
  secret("ZYLITH_CONTROL_PLANE_TOKEN", 32);
  secret("ZYLITH_REFERENCE_PRICE_ATTESTOR_TOKEN", 32);
  httpsUrls("ZYLITH_REFERENCE_PRICE_ATTESTOR_URL");
  // the transaction prover sees every witness: it runs on the operator's own hosts.
  for (const prover of required("ZYLITH_TX_PROVER_URLS").split(",").map((entry) => entry.trim()).filter(Boolean)) {
    if (!isOperatorHost(prover) && value("ZYLITH_TX_PROVER_REMOTE_TRUSTED") !== "1") {
      fail(`transaction prover ${prover} is not operator-run; it sees every witness`);
    }
  }
  httpsUrls("ZYLITH_ROUTE_SERVICE_URL", { optional: true });
  origins("ZYLITH_PROVER_ALLOWED_ORIGINS");
  const executionKeys = required("ZYLITH_EXECUTION_KEYS_PATH");
  if (executionKeys && !fileExists(executionKeys)) fail(`ZYLITH_EXECUTION_KEYS_PATH does not exist: ${executionKeys}`);
  const epochMs = integer("ZYLITH_EPOCH_MS", 1_000, 300_000, 6_000);
  integer("ZYLITH_PIPELINE_DEPTH", 1, 4, 2);
  integer("ZYLITH_PRIVATE_RATE_LIMIT_PER_MINUTE", 1, 600, 60);
  // fees pay for gas: every transition's fees must be worth a positive floor in strk, valued
  // at attested rates less a haircut.
  if (!/^[1-9]\d*$/.test(value("ZYLITH_MIN_TRANSITION_FEE_STRK"))) fail("ZYLITH_MIN_TRANSITION_FEE_STRK must be a positive integer of strk atoms");
  integer("ZYLITH_FEE_RATE_HAIRCUT_BPS", 0, 5_000, 100);
  for (const retired of ["ZYLITH_MIN_SETTLEMENT_FEES", "ZYLITH_SEARCHER_MIN_PROFIT_QUOTE"]) {
    if (value(retired)) fail(`${retired} is retired; see ZYLITH_MIN_TRANSITION_FEE_STRK and ZYLITH_SEARCHER_MIN_PROFIT`);
  }

  // the attestor signs only for the exchange.
  felt("ZYLITH_REFERENCE_PRICE_SIGNER_PRIVATE_KEY");
  felt("ZYLITH_EXCHANGE_ADDRESS");

  // the indexer and the backup service.
  origins("ZYLITH_INDEXER_ALLOWED_ORIGINS");
  origins("ZYLITH_COORDINATOR_ALLOWED_ORIGINS");
  required("ZYLITH_INDEXER_DATA_PATH");
  required("ZYLITH_COORDINATOR_RECOVERY_PATH");

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
    for (const contract of ["commitment_registry", "privacy_deposit_bridge", "ekubo_external_match_router", "exchange"]) {
      if (!isNonZeroFelt(manifest.contracts?.[contract])) fail(`manifest contracts.${contract} must be deployed`);
    }
    for (const field of ["proof_program_address", "virtual_program_hash", "starknet_os_config_hash", "proof_account_address", "settlement_account_address"]) {
      if (!isNonZeroFelt(manifest.proof?.[field])) fail(`manifest proof.${field} must be set`);
    }
    // wallets seal only to the execution keys the manifest pins; the operator checks its own
    // keys against the pin at startup.
    const pins = [manifest.funding?.starknet_privacy?.ingress_key_registry_fingerprint, manifest.funding?.starknet_privacy?.ingress_key_registry_next_fingerprint].filter((pin) => pin !== undefined);
    if (!pins.length || pins.some((pin) => !/^[0-9a-f]{64}$/.test(pin) || /^0+$/.test(pin))) fail("manifest funding.starknet_privacy.ingress_key_registry_fingerprint must pin the execution keys");
    if (manifest.proof?.config_locked_after_deploy !== true) fail("manifest proof.config_locked_after_deploy must be true");
    if (manifest.deployment?.finalized !== true) fail("manifest deployment.finalized must be true");
    if (!/^[0-9a-f]{40}$/.test(manifest.deployment?.release_commit ?? "") || /^0+$/.test(manifest.deployment.release_commit)) {
      fail("manifest deployment.release_commit must name the released commit");
    }
    if (value("ZYLITH_EXCHANGE_ADDRESS") && !sameFelt(value("ZYLITH_EXCHANGE_ADDRESS"), manifest.contracts?.exchange)) {
      fail("ZYLITH_EXCHANGE_ADDRESS does not match the manifest's exchange");
    }
    for (const [account, field] of [["ZYLITH_STARKNET_ACCOUNT_ADDRESS", "settlement_account_address"], ["ZYLITH_PROOF_ACCOUNT_ADDRESS", "proof_account_address"]]) {
      if (value(account) && !sameFelt(value(account), manifest.proof?.[field])) fail(`${account} does not match the manifest's proof.${field}`);
    }
    if (manifest.runtime?.epoch_ms !== epochMs) fail(`manifest runtime.epoch_ms (${manifest.runtime?.epoch_ms}) differs from ZYLITH_EPOCH_MS (${epochMs})`);
    const pairs = Object.values(manifest.product?.pairs ?? {}).filter((pair) => pair.enabled);
    if (pairs.length === 0) fail("manifest enables no pairs");
    for (const pair of pairs) {
      if (!Number.isInteger(pair.taker_fee_bps) || pair.taker_fee_bps < 1 || pair.taker_fee_bps > 100) fail(`pair ${pair.pair_id} fee must be 1..100 bps`);
      if (!/^[1-9]\d*$/.test(String(pair.min_order_amount ?? ""))) fail(`pair ${pair.pair_id} needs a positive min_order_amount`);
      for (const asset of [pair.base_asset_id, pair.quote_asset_id]) {
        const decimals = manifest.product?.assets?.[asset]?.decimals;
        if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) fail(`asset ${asset} needs its token's decimals in the manifest`);
      }
      for (const asset of [pair.base_asset_id, pair.quote_asset_id]) {
        if (!isNonZeroFelt(manifest.token_addresses?.[asset])) fail(`pair ${pair.pair_id} asset ${asset} has no token address`);
      }
    }
    // external matching is either fully configured or explicitly off.
    const external = pairs.filter((pair) => pair.external_match_enabled === true);
    if (external.length === 0) {
      if (value("ZYLITH_EXTERNAL_MATCHING_DISABLED") !== "1") fail("no pair matches externally: set ZYLITH_EXTERNAL_MATCHING_DISABLED=1 to confirm routing is off");
    } else {
      if (value("ZYLITH_EXTERNAL_MATCHING_DISABLED") === "1") fail(`ZYLITH_EXTERNAL_MATCHING_DISABLED is set but ${external.map((pair) => pair.pair_id).join(", ")} match externally`);
      if (!value("ZYLITH_ROUTE_SERVICE_URL")) fail("external matching needs ZYLITH_ROUTE_SERVICE_URL");
      // margins are per quote asset: raw atoms of different assets are never compared.
      let margins = {};
      try {
        margins = JSON.parse(value("ZYLITH_SEARCHER_MIN_PROFIT") || "{}");
      } catch {
        fail("ZYLITH_SEARCHER_MIN_PROFIT must be a json object of quote asset to atoms");
      }
      for (const pair of external) {
        if (!/^[1-9]\d*$/.test(String(margins?.[pair.quote_asset_id] ?? ""))) fail(`external matching on ${pair.pair_id} needs a positive ZYLITH_SEARCHER_MIN_PROFIT.${pair.quote_asset_id}`);
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
  if (host === "localhost" || host.endsWith(".internal") || host.endsWith(".local") || host === "::1") return true;
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

if (import.meta.url === `file://${process.argv[1]}`) {
  const failures = check(process.env);
  if (failures.length > 0) {
    console.error("production readiness check failed");
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }
  console.log("production readiness check passed");
}

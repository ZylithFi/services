#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";

const args = new Set(process.argv.slice(2));
const strict = args.has("--strict");
const env = process.env;
const failures = [];
const warnings = [];

checkSecret("ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET", 32);
checkOptionalSecretList("ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS", 32);
checkSecret("ZYLITH_HEARTBEAT_COVER_SECRET", 32);

expectNot("ZYLITH_ALLOW_DIRECT_PRIVATE_ORDER_PAYLOADS", "true", "direct private order payloads must stay disabled");
expectNot("ZYLITH_AUCTION_PROVER_ALLOW_KEYGEN", "1", "prover keygen must be disabled in production");
expectNot("ZYLITH_AUCTION_PROVER_ALLOW_KEYGEN", "true", "prover keygen must be disabled in production");
expectNot("ZYLITH_COORDINATOR_EMERGENCY_PAUSED", "true", "coordinator is currently paused");
expectNot("ZYLITH_PROVER_EMERGENCY_PAUSED", "true", "prover is currently paused");

checkBoolDefault("ZYLITH_REQUIRE_TRUSTED_ORDER_INGRESS", true);

checkCsv("ZYLITH_COORDINATOR_ALLOWED_ORIGINS");
checkCsv("ZYLITH_PROVER_ALLOWED_ORIGINS");
checkCsv("ZYLITH_INDEXER_ALLOWED_ORIGINS");
checkCsv("ZYLITH_PAYMASTER_ALLOWED_ORIGINS");

checkPositiveInt("ZYLITH_COORDINATOR_MAX_BODY_BYTES", 1, 1_000_000);
checkPositiveInt("ZYLITH_PROVER_MAX_BODY_BYTES", 1, 1_000_000);
checkPositiveInt("ZYLITH_PAYMASTER_MAX_BODY_BYTES", 1, 1_000_000);
checkPositiveInt("ZYLITH_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE", 1, 600);
checkPositiveInt("ZYLITH_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE", 1, 600);
checkPositiveInt("ZYLITH_PAYMASTER_SIGNER_LIMIT_PER_MINUTE", 1, 120);
checkPositiveInt("ZYLITH_PROVER_MAX_STORED_PRIVATE_PAYLOADS", 1, 250_000);
checkPositiveInt("ZYLITH_PRIVATE_PAYLOAD_RETENTION_MS", 60_000, 86_400_000);
checkPositiveInt("ZYLITH_COORDINATOR_MAX_ORDERS_PER_BATCH", 1, 10_000);
checkExactInt("ZYLITH_BATCH_WINDOW_MS", 90_000);
checkPositiveInt("ZYLITH_PUBLIC_ARTIFACT_DELAY_EPOCHS", 1, 100);
checkPositiveInt("ZYLITH_OUTPUT_CLAIM_DELAY_SECONDS", 60, 86_400);

checkRequired("ZYLITH_AUCTION_PROVER_KEYS_PATH");
checkRequired("VITE_ZYLITH_INGRESS_KEY_REGISTRY_PIN");
checkRequired("ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_PROOF_PROGRAM_HASH");
checkRequired("ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS");
checkRequired("ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS");

checkFelt("ZYLITH_PROTOCOL_ADMIN_ADDRESS");
checkFelt("ZYLITH_PAUSE_GUARDIAN_ADDRESS");
checkFelt("ZYLITH_PROTOCOL_TREASURY_ADDRESS");
checkFelt("ZYLITH_PROTOCOL_FEE_RECIPIENT");
checkFelt("ZYLITH_FEE_CLAIM_AUTHORITY_ADDRESS");
checkFelt("ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS");
checkFelt("ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS");
checkDistinctRoles([
  "ZYLITH_PROTOCOL_ADMIN_ADDRESS",
  "ZYLITH_PROTOCOL_TREASURY_ADDRESS",
  "ZYLITH_FEE_CLAIM_AUTHORITY_ADDRESS",
  "ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS",
  "ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS",
  "ZYLITH_PAYMASTER_ACCOUNT_ADDRESS",
]);

checkRequired("ZYLITH_PAYMASTER_RPC_URL");
checkFelt("ZYLITH_PAYMASTER_CHAIN_ID");
checkFelt("ZYLITH_PAYMASTER_ACCOUNT_ADDRESS");
checkRequired("ZYLITH_PAYMASTER_PRIVATE_KEY");
checkCsv("ZYLITH_PAYMASTER_ALLOWED_CONTRACTS");
checkCsv("ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS");
checkCsv("ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS");
checkCsv("ZYLITH_PAYMASTER_WITHDRAWAL_BUCKETS");

checkRecommended("ZYLITH_ALERT_WEBHOOK_URL", "monitoring alerts have no destination");
checkRecommended("ZYLITH_MONITORING_ENV", "monitoring environment label is unset");
checkRecommended("ZYLITH_INCIDENT_RUNBOOK_URL", "incident response runbook URL is unset");
checkRecommended("ZYLITH_CRASH_DUMP_POLICY", "crash dump policy is unset");
checkDeploymentManifest();

if (failures.length > 0) {
  console.error("production readiness failed");
  for (const failure of failures) console.error(`- ${failure}`);
  if (warnings.length > 0) {
    console.error("warnings");
    for (const warning of warnings) console.error(`- ${warning}`);
  }
  process.exit(1);
}

if (warnings.length > 0) {
  const heading = strict ? "production readiness warnings treated as failures" : "production readiness warnings";
  console.error(heading);
  for (const warning of warnings) console.error(`- ${warning}`);
  if (strict) process.exit(1);
}

console.log("production readiness checks passed");

function checkRequired(name) {
  if (!value(name)) failures.push(`${name} is required`);
}

function checkRecommended(name, message) {
  if (!value(name)) warnings.push(`${name}: ${message}`);
}

function checkSecret(name, minLength) {
  const current = value(name);
  if (!current) {
    failures.push(`${name} is required`);
    return;
  }
  if (current.length < minLength) {
    failures.push(`${name} must be at least ${minLength} characters`);
  }
}

function checkOptionalSecretList(name, minLength) {
  const current = value(name);
  if (!current) {
    warnings.push(`${name} is empty; rotation is configured only after the first key roll`);
    return;
  }
  for (const [index, item] of current.split(",").map((entry) => entry.trim()).filter(Boolean).entries()) {
    if (item.length < minLength) failures.push(`${name}[${index}] must be at least ${minLength} characters`);
  }
}

function checkCsv(name) {
  const current = value(name);
  if (!current) {
    failures.push(`${name} must be configured`);
    return;
  }
  const items = current.split(",").map((item) => item.trim()).filter(Boolean);
  if (items.length === 0) failures.push(`${name} must contain at least one value`);
  if (items.includes("*")) failures.push(`${name} must not use wildcard origins or values`);
}

function checkFelt(name) {
  const current = value(name);
  if (!current) {
    failures.push(`${name} is required`);
    return;
  }
  if (!/^0x[0-9a-fA-F]+$/.test(current) && !/^[0-9]+$/.test(current)) {
    failures.push(`${name} must be a felt string`);
  }
}

function checkPositiveInt(name, min, max) {
  const current = value(name);
  if (!current) {
    failures.push(`${name} is required`);
    return;
  }
  const parsed = Number(current);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    failures.push(`${name} must be an integer in [${min}, ${max}]`);
  }
}

function checkExactInt(name, expected) {
  const current = value(name);
  if (!current) {
    failures.push(`${name} is required and must be ${expected}`);
    return;
  }
  const parsed = Number(current);
  if (!Number.isSafeInteger(parsed) || parsed !== expected) {
    failures.push(`${name} must be ${expected}`);
  }
}

function checkBoolDefault(name, expectedDefault) {
  const current = value(name);
  if (!current) {
    warnings.push(`${name} is unset; service default must remain ${expectedDefault}`);
    return;
  }
  const normalized = current.toLowerCase();
  if (!["true", "false", "1", "0"].includes(normalized)) {
    failures.push(`${name} must be boolean-like`);
  }
  const actual = normalized === "true" || normalized === "1";
  if (actual !== expectedDefault) {
    failures.push(`${name} must be ${expectedDefault}`);
  }
}

function checkDistinctRoles(names) {
  const seen = new Map();
  for (const name of names) {
    const current = normalizeFelt(value(name));
    if (!current) continue;
    const prior = seen.get(current);
    if (prior) {
      failures.push(`${name} must be distinct from ${prior}`);
    } else {
      seen.set(current, name);
    }
  }
}

function expectNot(name, forbidden, message) {
  if (value(name)?.toLowerCase() === forbidden) failures.push(`${name}: ${message}`);
}

function value(name) {
  return env[name]?.trim();
}

function normalizeFelt(input) {
  if (!input) return "";
  if (/^0x[0-9a-fA-F]+$/.test(input)) {
    return `0x${BigInt(input).toString(16)}`;
  }
  if (/^[0-9]+$/.test(input)) {
    return `0x${BigInt(input).toString(16)}`;
  }
  return input.toLowerCase();
}

function checkDeploymentManifest() {
  const manifestPath = value("ZYLITH_DEPLOYMENT_MANIFEST_PATH") || "client/public/deployment.json";
  if (!existsSync(manifestPath)) {
    failures.push(`deployment manifest is required at ${manifestPath}`);
    return;
  }

  let manifest;
  try {
    const data = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest = data.manifest || data;
  } catch (error) {
    failures.push(`deployment manifest at ${manifestPath} is not valid JSON: ${error.message}`);
    return;
  }

  const requiredAssets = ["STRK", "ETH", "USDC", "strkBTC", "WBTC", "USDT"];
  const requiredPairs = {
    "STRK/USDC": [4, 0],
    "ETH/USDC": [4, 0],
    "strkBTC/USDC": [4, 0],
    "STRK/ETH": [4, 0],
    "STRK/strkBTC": [4, 0],
    "WBTC/strkBTC": [2, 0],
    "USDC/USDT": [2, 0],
  };

  for (const asset of requiredAssets) {
    checkManifestNonZero(manifest.token_addresses?.[asset], `token_addresses.${asset}`);
    const assetConfig = manifest.product?.assets?.[asset];
    if (!assetConfig?.enabled) failures.push(`product.assets.${asset} must be enabled`);
  }

  for (const [pair, [taker, maker]] of Object.entries(requiredPairs)) {
    const pairConfig = manifest.product?.pairs?.[pair];
    if (!pairConfig?.enabled) {
      failures.push(`product.pairs.${pair} must be enabled`);
      continue;
    }
    if (pairConfig.taker_fee_bps !== taker) {
      failures.push(`product.pairs.${pair}.taker_fee_bps must be ${taker}`);
    }
    if (pairConfig.maker_fee_bps !== maker) {
      failures.push(`product.pairs.${pair}.maker_fee_bps must be ${maker}`);
    }
  }

  for (const [key, current] of Object.entries(manifest.contracts || {})) {
    checkManifestNonZero(current, `contracts.${key}`);
  }
  for (const key of [
    "proof_program_address",
    "proof_program_hash",
    "settlement_statement_program_address",
    "nullifier_statement_program_address",
    "renewal_statement_program_address",
    "note_consolidation_statement_program_address",
    "proof_account_address",
    "settlement_account_address",
  ]) {
    checkManifestNonZero(manifest.proof?.[key], `proof.${key}`);
  }

  if (JSON.stringify(manifest).includes("example.invalid")) {
    failures.push("deployment manifest must not contain example.invalid placeholders");
  }
}

function checkManifestNonZero(current, label) {
  if (typeof current !== "string" || current.trim() === "") {
    failures.push(`${label} must be configured`);
    return;
  }
  const normalized = current.startsWith("0x") || current.startsWith("0X")
    ? current.slice(2)
    : current;
  if (/^0*$/i.test(normalized)) {
    failures.push(`${label} must be non-zero`);
  }
}

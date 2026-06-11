#!/usr/bin/env node
import { createHash } from "node:crypto";
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
checkRequired("ZYLITH_PROVER_STRICT");
expectValue("ZYLITH_PROVER_STRICT", "true", "prover strict mode must be enabled in production");
expectValue("ZYLITH_REQUIRE_ARTIFACT_ONCHAIN_VERIFICATION", "true", "artifact publication must verify on-chain output root and transcript commitment");
expectValue(
  "ZYLITH_AUDITED_ERC20_ALLOWLIST_ACK",
  "true",
  "supported assets must be restricted to audited vanilla ERC20s with exact balance-delta behavior",
);
checkHostedWithdrawalDisclosure();
checkHostedConsolidationDisclosure();

checkCsv("ZYLITH_COORDINATOR_ALLOWED_ORIGINS");
checkCsv("ZYLITH_PROVER_ALLOWED_ORIGINS");
checkCsv("ZYLITH_INDEXER_ALLOWED_ORIGINS");
checkCsv("ZYLITH_PAYMASTER_ALLOWED_ORIGINS");
checkCsv("ZYLITH_RENEWAL_RELAY_ALLOWED_ORIGINS");

checkPositiveInt("ZYLITH_COORDINATOR_MAX_BODY_BYTES", 1, 1_000_000);
checkPositiveInt("ZYLITH_PROVER_MAX_BODY_BYTES", 1, 1_000_000);
checkPositiveInt("ZYLITH_PAYMASTER_MAX_BODY_BYTES", 1, 1_000_000);
checkPositiveInt("ZYLITH_RENEWAL_RELAY_MAX_BODY_BYTES", 1, 128_000_000);
checkPositiveInt("ZYLITH_COORDINATOR_PUBLIC_RATE_LIMIT_PER_MINUTE", 1, 600);
checkPositiveInt("ZYLITH_PROVER_PRIVATE_INGRESS_RATE_LIMIT_PER_MINUTE", 1, 600);
checkPositiveInt("ZYLITH_PAYMASTER_SIGNER_LIMIT_PER_MINUTE", 1, 120);
checkPositiveInt("ZYLITH_RENEWAL_RELAY_RATE_LIMIT_PER_MINUTE", 1, 600);
checkPositiveInt("ZYLITH_PROVER_MAX_STORED_PRIVATE_PAYLOADS", 1, 250_000);
checkPositiveInt("ZYLITH_PRIVATE_PAYLOAD_RETENTION_MS", 60_000, 86_400_000);
checkPositiveInt("ZYLITH_RENEWAL_RELAY_PACKAGE_RETENTION_MS", 86_400_000, 31_536_000_000);
checkPositiveInt("ZYLITH_RENEWAL_RELAY_MAX_PACKAGE_SLOTS", 86_400, 100_000);
checkPositiveInt("ZYLITH_COORDINATOR_MAX_ORDERS_PER_BATCH", 1, 10_000);
checkExactInt("ZYLITH_BATCH_WINDOW_MS", 90_000);
checkPositiveInt("ZYLITH_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS", 3, 100);
checkPositiveInt("ZYLITH_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS", 3, 100);
checkPositiveInt("ZYLITH_ARTIFACT_EPOCH_BUCKET_SIZE", 1, 64);
if (
  env.ZYLITH_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS &&
  env.ZYLITH_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS &&
  Number(env.ZYLITH_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS) < Number(env.ZYLITH_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS)
) {
  failures.push("ZYLITH_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS must be >= ZYLITH_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS");
}
checkPositiveInt("ZYLITH_OUTPUT_CLAIM_DELAY_SECONDS", 60, 86_400);

checkRequired("ZYLITH_AUCTION_PROVER_KEYS_PATH");
checkRequired("VITE_ZYLITH_INGRESS_KEY_REGISTRY_PIN");
checkRequired("ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_PROOF_PROGRAM_HASH");
checkRequired("ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS");
checkNativeProofAccountSigner();
checkRequired("ZYLITH_NATIVE_TX_PROVER_URL");
checkNativeProverOhttpPolicy();
checkRequired("ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS");
checkRequired("ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_STARKNET_OS_CONFIG_HASH");
checkFelt("ZYLITH_STARKNET_CHAIN_ID");
checkFelt("ZYLITH_STARKNET_ACCOUNT_ADDRESS");
checkPrivateKeyHex("ZYLITH_STARKNET_PRIVATE_KEY");

checkFelt("ZYLITH_PROTOCOL_ADMIN_ADDRESS");
checkFelt("ZYLITH_PAUSE_GUARDIAN_ADDRESS");
checkFelt("ZYLITH_PROTOCOL_TREASURY_ADDRESS");
checkFelt("ZYLITH_PROTOCOL_FEE_RECIPIENT");
checkFeeKey("ZYLITH_PROTOCOL_FEE_OWNER_KEY_HEX", "7171717171717171717171717171717171717171717171717171717171717171");
checkFeeKey("ZYLITH_PROTOCOL_FEE_WITHDRAW_KEY_HEX", "7373737373737373737373737373737373737373737373737373737373737373");
checkFeeKey("ZYLITH_RELAY_FEE_OWNER_KEY_HEX", "8181818181818181818181818181818181818181818181818181818181818181");
checkFeeKey("ZYLITH_RELAY_FEE_WITHDRAW_KEY_HEX", "8383838383838383838383838383838383838383838383838383838383838383");
checkFelt("ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS");
checkFelt("ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS");
checkDistinctRoles([
  "ZYLITH_PROTOCOL_ADMIN_ADDRESS",
  "ZYLITH_PROTOCOL_TREASURY_ADDRESS",
  "ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS",
  "ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS",
  "ZYLITH_PAYMASTER_ACCOUNT_ADDRESS",
]);

checkRequired("ZYLITH_PAYMASTER_RPC_URL");
checkFelt("ZYLITH_PAYMASTER_CHAIN_ID");
checkFelt("ZYLITH_PAYMASTER_ACCOUNT_ADDRESS");
checkRequired("ZYLITH_PAYMASTER_PRIVATE_KEY");
checkFelt("ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH");
checkCsv("ZYLITH_PAYMASTER_ALLOWED_CONTRACTS");
checkCsv("ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS");
checkCsv("ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS");
if ((value("ZYLITH_PAYMASTER_TRUST_PROXY_HEADERS") || "").toLowerCase() === "true") {
  checkAnyCsv(
    ["ZYLITH_PAYMASTER_TRUSTED_PROXY_CIDRS", "ZYLITH_TRUSTED_PROXY_CIDRS"],
    "paymaster trusted proxy headers require trusted proxy CIDRs",
  );
}
if ((value("ZYLITH_TRUST_PROXY_HEADERS") || "").toLowerCase() === "true") {
  checkAnyCsv(
    ["ZYLITH_COORDINATOR_TRUSTED_PROXY_CIDRS", "ZYLITH_TRUSTED_PROXY_CIDRS"],
    "coordinator trusted proxy headers require trusted proxy CIDRs",
  );
}
if ((value("ZYLITH_PAYMASTER_ALLOW_DIRECT_WITHDRAWALS") || "").toLowerCase() === "true") {
  checkCsv("ZYLITH_PAYMASTER_WITHDRAWAL_BUCKETS");
}

checkRequired("ZYLITH_RENEWAL_RELAY_STRICT");
expectValue("ZYLITH_RENEWAL_RELAY_STRICT", "true", "renewal relay strict mode must be enabled in production");
checkRequired("ZYLITH_RENEWAL_RELAY_STORE_PATH");
checkRecommended("ZYLITH_RENEWAL_RELAY_PACKAGE_TOKEN", "renewal relay package read/delete access token is unset; status/results/delete endpoints will be inaccessible to clients");
if (relayAcceptsManagedMode()) {
  checkSecret("ZYLITH_RENEWAL_RELAY_COORDINATOR_CONTROL_TOKEN", 32);
}
checkSecret("ZYLITH_RENEWAL_RELAY_PROVER_CONTROL_TOKEN", 32);
checkRequired("ZYLITH_RENEWAL_RELAY_COORDINATOR_URL");
checkRequired("ZYLITH_RENEWAL_RELAY_PROVER_URL");

checkRecommended("ZYLITH_ALERT_WEBHOOK_URL", "monitoring alerts have no destination");
checkRecommended("ZYLITH_MONITORING_ENV", "monitoring environment label is unset");
checkRecommended("ZYLITH_CRASH_DUMP_POLICY", "crash dump policy is unset");
expectValue(
  "ZYLITH_ACK_FIRST_SET_CONFIG_NO_TIMELOCK_RISK",
  "true",
  "first-set fee/config values are not timelocked on-chain and require explicit launch acknowledgement",
);
checkExternalAuditSignals();
checkKeyCustodySignals();
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

function checkFeeKey(name, defaultValue) {
  const current = value(name);
  if (!current) {
    failures.push(`${name} is required`);
    return;
  }
  if (!/^[0-9a-fA-F]{64}$/.test(current)) {
    failures.push(`${name} must be a 32-byte hex string without 0x prefix`);
    return;
  }
  if (current.toLowerCase() === defaultValue.toLowerCase()) {
    failures.push(`${name} must not use the development default`);
  }
}

function checkPrivateKeyHex(name) {
  const current = value(name);
  if (!current) {
    failures.push(`${name} is required`);
    return;
  }
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(current) && !/^[0-9a-fA-F]{1,64}$/.test(current)) {
    failures.push(`${name} must be a Starknet private-key felt`);
  }
}

function checkNativeProofAccountSigner() {
  const proofAccount = normalizeFelt(value("ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS"));
  const submitAccount = normalizeFelt(value("ZYLITH_STARKNET_ACCOUNT_ADDRESS"));
  if (!proofAccount || !submitAccount || proofAccount === submitAccount) return;
  checkPrivateKeyHex("ZYLITH_NATIVE_PROOF_PRIVATE_KEY");
}

function checkNativeProverOhttpPolicy() {
  const enabled = (value("ZYLITH_NATIVE_TX_PROVER_OHTTP_ENABLED") || "true").toLowerCase();
  if (["0", "false", "no"].includes(enabled)) {
    failures.push("ZYLITH_NATIVE_TX_PROVER_OHTTP_ENABLED must not be disabled in production");
  }
}

function anyTrue(names) {
  return names.some((name) => (value(name) || "").toLowerCase() === "true");
}

function expectAnyTrue(names, message) {
  if (anyTrue(names)) return;
  failures.push(`${names.join(" or ")} must be true: ${message}`);
}

function checkHostedConsolidationDisclosure() {
  const hosted =
    (value("ZYLITH_ENABLE_HOSTED_NOTE_CONSOLIDATION") || "").toLowerCase() === "true" ||
    (value("VITE_ZYLITH_ENABLE_HOSTED_NOTE_CONSOLIDATION") || "").toLowerCase() === "true";
  if (!hosted) return;
  expectAnyTrue(
    [
      "ZYLITH_ACK_HOSTED_NOTE_PROOF_PRIVACY",
      "VITE_ZYLITH_ACK_HOSTED_NOTE_PROOF_PRIVACY",
      "ZYLITH_ACK_HOSTED_NOTE_CONSOLIDATION_PRIVACY_SINK",
    ],
    "hosted consolidation receives note preimages and requires explicit operator acknowledgement",
  );
}

function checkHostedWithdrawalDisclosure() {
  const hosted =
    (value("ZYLITH_ENABLE_HOSTED_WITHDRAWALS") || "").toLowerCase() === "true" ||
    (value("VITE_ZYLITH_ENABLE_HOSTED_WITHDRAWALS") || "").toLowerCase() === "true";
  if (!hosted) return;
  expectAnyTrue(
    [
      "ZYLITH_ACK_HOSTED_NOTE_PROOF_PRIVACY",
      "VITE_ZYLITH_ACK_HOSTED_NOTE_PROOF_PRIVACY",
      "ZYLITH_ACK_HOSTED_WITHDRAWAL_PRIVACY_SINK",
    ],
    "hosted withdrawals receive output-note preimages and require explicit operator acknowledgement",
  );
}

function checkExternalAuditSignals() {
  const required = (value("ZYLITH_EXTERNAL_AUDIT_REQUIRED") || "").toLowerCase() === "true";
  if (!required) {
    warnings.push("ZYLITH_EXTERNAL_AUDIT_REQUIRED is not true; external audit is not enforced by this environment");
    return;
  }
  expectValue("ZYLITH_EXTERNAL_AUDIT_COMPLETE", "true", "external audit must be complete when required");
  checkExactInt("ZYLITH_EXTERNAL_AUDIT_CRITICAL_OPEN", 0);
  checkExactInt("ZYLITH_EXTERNAL_AUDIT_HIGH_OPEN", 0);
  const reportHash = value("ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256");
  if (!reportHash) {
    failures.push("ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256 is required when external audit is required");
  } else if (!/^[0-9a-fA-F]{64}$/.test(reportHash)) {
    failures.push("ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256 must be a 64-character hex digest");
  }
}

function checkKeyCustodySignals() {
  const mode = (value("ZYLITH_KEY_CUSTODY_MODE") || "").toLowerCase();
  if (!mode) {
    warnings.push("ZYLITH_KEY_CUSTODY_MODE is unset; key custody is not described in deploy env");
    return;
  }
  if (!["hsm", "multisig", "hardware-multisig", "hardware"].includes(mode)) {
    failures.push("ZYLITH_KEY_CUSTODY_MODE must be hsm, multisig, hardware-multisig, or hardware");
  }
}

function relayAcceptsManagedMode() {
  const mode = (value("ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE") || "ZylithRelay").toLowerCase();
  return ["", "zylith", "zylithrelay", "managed", "any", "both"].includes(mode);
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

function checkAnyCsv(names, message) {
  if (names.some((name) => value(name))) {
    for (const name of names) {
      if (value(name)) checkCsv(name);
    }
    return;
  }
  failures.push(`${names.join(" or ")} must be configured: ${message}`);
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

function expectValue(name, expected, message) {
  if (value(name)?.toLowerCase() !== expected) failures.push(`${name}: ${message}`);
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

  const manifestBytes = readFileSync(manifestPath);
  const expectedManifestHash = value("ZYLITH_EXPECTED_DEPLOYMENT_MANIFEST_SHA256");
  if (!expectedManifestHash) {
    failures.push("ZYLITH_EXPECTED_DEPLOYMENT_MANIFEST_SHA256 is required");
  } else if (!/^[0-9a-fA-F]{64}$/.test(expectedManifestHash)) {
    failures.push("ZYLITH_EXPECTED_DEPLOYMENT_MANIFEST_SHA256 must be a 64-character hex digest");
  } else {
    const actualManifestHash = createHash("sha256").update(manifestBytes).digest("hex");
    if (actualManifestHash !== expectedManifestHash.toLowerCase()) {
      failures.push("deployment manifest sha256 does not match ZYLITH_EXPECTED_DEPLOYMENT_MANIFEST_SHA256");
    }
  }

  let manifest;
  try {
    const data = JSON.parse(manifestBytes.toString("utf8"));
    manifest = data.manifest || data;
  } catch (error) {
    failures.push(`deployment manifest at ${manifestPath} is not valid JSON: ${error.message}`);
    return;
  }

  const releaseCommit = value("ZYLITH_DEPLOYMENT_RELEASE_COMMIT");
  if (!releaseCommit || !/^[0-9a-fA-F]{40}$/.test(releaseCommit)) {
    failures.push("ZYLITH_DEPLOYMENT_RELEASE_COMMIT must be a 40-character git commit");
  } else if ((manifest.deployment?.release_commit || manifest.release_commit) !== releaseCommit.toLowerCase()) {
    failures.push("deployment manifest release commit does not match ZYLITH_DEPLOYMENT_RELEASE_COMMIT");
  }
  if (manifest.deployment?.finalized !== true) {
    failures.push("deployment manifest deployment.finalized must be true");
  }
  const envChainId = normalizeFeltText(value("ZYLITH_STARKNET_CHAIN_ID"));
  const manifestChainId = normalizeFeltText(manifest.chain_id || manifest.network?.chain_id);
  if (envChainId && manifestChainId && envChainId !== manifestChainId) {
    failures.push("deployment manifest chain_id must match ZYLITH_STARKNET_CHAIN_ID");
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
    if (assetConfig?.erc20_behavior !== "vanilla-exact-delta") {
      failures.push(`product.assets.${asset}.erc20_behavior must be vanilla-exact-delta`);
    }
    if (assetConfig?.audit_status !== "approved") {
      failures.push(`product.assets.${asset}.audit_status must be approved`);
    }
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

  if (manifest.contracts?.privacy_funding_verifier || manifest.funding?.starknet_privacy?.funding_verifier) {
    failures.push("privacy_funding_verifier/funding_verifier must be absent; PrivacyDepositBridge uses custody-checked privacy-pool activation");
  }
  if (manifest.funding?.primary !== "starknet_privacy") {
    failures.push("funding.primary must be starknet_privacy");
  }
  const privacyFunding = manifest.funding?.starknet_privacy || {};
  checkManifestNonZero(privacyFunding.privacy_pool, "funding.starknet_privacy.privacy_pool");
  checkManifestNonZero(privacyFunding.bridge_adapter, "funding.starknet_privacy.bridge_adapter");
  checkManifestNonZero(privacyFunding.shielded_asset_adapter, "funding.starknet_privacy.shielded_asset_adapter");
  checkManifestNonZero(privacyFunding.paymaster_address, "funding.starknet_privacy.paymaster_address");
  checkManifestNonZero(privacyFunding.proof_signer_class_hash, "funding.starknet_privacy.proof_signer_class_hash");
  checkManifestUrl(privacyFunding.discovery_url, "funding.starknet_privacy.discovery_url");
  checkManifestUrl(privacyFunding.proving_url, "funding.starknet_privacy.proving_url");
  checkManifestUrl(privacyFunding.paymaster_url, "funding.starknet_privacy.paymaster_url");
  checkManifestFeltEquals(
    privacyFunding.bridge_adapter,
    manifest.contracts?.privacy_deposit_bridge,
    "funding.starknet_privacy.bridge_adapter",
    "contracts.privacy_deposit_bridge",
  );
  checkManifestFeltEquals(
    privacyFunding.shielded_asset_adapter,
    manifest.contracts?.privacy_deposit_bridge,
    "funding.starknet_privacy.shielded_asset_adapter",
    "contracts.privacy_deposit_bridge",
  );
  checkManifestFeltEquals(
    manifest.contracts?.shielded_asset_adapter,
    manifest.contracts?.privacy_deposit_bridge,
    "contracts.shielded_asset_adapter",
    "contracts.privacy_deposit_bridge",
  );
  checkManifestFeltEquals(
    privacyFunding.paymaster_address,
    value("ZYLITH_PAYMASTER_ACCOUNT_ADDRESS"),
    "funding.starknet_privacy.paymaster_address",
    "ZYLITH_PAYMASTER_ACCOUNT_ADDRESS",
  );
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
    "withdrawal_statement_program_address",
    "proof_account_address",
    "settlement_account_address",
  ]) {
    checkManifestNonZero(manifest.proof?.[key], `proof.${key}`);
  }
  for (const key of ["proof_program_locked_after_deploy", "operational_config_locked_after_deploy"]) {
    if (manifest.proof?.[key] !== true) {
      failures.push(`proof.${key} must be true for production readiness`);
    }
  }

  if (JSON.stringify(manifest).includes("example.invalid")) {
    failures.push("deployment manifest must not contain example.invalid placeholders");
  }
}

function normalizeFeltText(current) {
  if (typeof current !== "string" || current.trim() === "") return null;
  const trimmed = current.trim();
  try {
    if (/^0x[0-9a-fA-F]+$/.test(trimmed)) return `0x${BigInt(trimmed).toString(16)}`;
    if (/^[0-9]+$/.test(trimmed)) return `0x${BigInt(trimmed).toString(16)}`;
  } catch {
    return null;
  }
  return null;
}

function parseManifestNonNegativeInteger(current) {
  if (typeof current === "number") {
    if (!Number.isSafeInteger(current) || current < 0) return null;
    return BigInt(current);
  }
  if (typeof current === "string" && /^[0-9]+$/.test(current)) {
    return BigInt(current);
  }
  return null;
}

function checkManifestNonZero(current, label) {
  if (typeof current !== "string" || current.trim() === "") {
    failures.push(`${label} must be configured`);
    return;
  }
  if (isZeroFelt(current)) {
    failures.push(`${label} must be non-zero`);
  }
}

function checkManifestFeltEquals(current, expected, label, expectedLabel) {
  const normalizedCurrent = normalizeFeltText(current);
  const normalizedExpected = normalizeFeltText(expected);
  if (!normalizedCurrent || !normalizedExpected) return;
  if (normalizedCurrent !== normalizedExpected) {
    failures.push(`${label} must match ${expectedLabel}`);
  }
}

function checkManifestUrl(current, label) {
  if (typeof current !== "string" || current.trim() === "") {
    failures.push(`${label} must be configured`);
    return;
  }
  const trimmed = current.trim();
  if (trimmed.startsWith("/")) return;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:") {
      failures.push(`${label} must use https or a same-origin path`);
    }
  } catch {
    failures.push(`${label} must be a valid URL or same-origin path`);
  }
}

function isZeroFelt(current) {
  if (typeof current !== "string" || current.trim() === "") return false;
  const normalized = current.startsWith("0x") || current.startsWith("0X")
    ? current.slice(2)
    : current;
  return /^0*$/i.test(normalized);
}

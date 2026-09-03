#!/usr/bin/env node
import { createHash, verify } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

const env = process.env;
const failures = [];
const STARKNET_FIELD_PRIME =
  3618502788666131213697322783095070105623107215331596699973092056135872020481n;

checkSecret("ZYLITH_TRUSTED_INGRESS_RECEIPT_SECRET", 32);
checkOptionalSecretList("ZYLITH_TRUSTED_INGRESS_RECEIPT_PREVIOUS_SECRETS", 32);
checkSecret("ZYLITH_HEARTBEAT_COVER_SECRET", 32);

expectNot("ZYLITH_COORDINATOR_EMERGENCY_PAUSED", "true", "coordinator is currently paused");
expectNot("ZYLITH_PROVER_EMERGENCY_PAUSED", "true", "prover is currently paused");

checkRequired("ZYLITH_PROVER_STRICT");
expectValue("ZYLITH_PROVER_STRICT", "true", "prover strict mode must be enabled in production");
checkRequired("ZYLITH_PROVER_WORKER_SUBMIT_ONCHAIN");
expectValue("ZYLITH_PROVER_WORKER_SUBMIT_ONCHAIN", "true", "prover worker must submit proofs on-chain in production");
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
checkCsv("ZYLITH_PRODUCT_PAIRS");
checkExactInt("ZYLITH_BATCH_WINDOW_MS", 20_000);
checkExactInt("ZYLITH_PUBLIC_ARTIFACT_DELAY_MIN_EPOCHS", 14);
checkExactInt("ZYLITH_PUBLIC_ARTIFACT_DELAY_MAX_EPOCHS", 36);
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
checkFelt("ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_PROOF_PROGRAM_HASH");
checkFelt("ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS");
checkNativeProofAccountSigner();
checkRequired("ZYLITH_NATIVE_TX_PROVER_URL");
checkNativeProverOhttpPolicy();
checkFelt("ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS");
checkFelt("ZYLITH_NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS");
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
checkCsv("ZYLITH_PAYMASTER_APPROVAL_SPENDERS");
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
checkRequired("ZYLITH_RENEWAL_RELAY_STRICT");
expectValue("ZYLITH_RENEWAL_RELAY_STRICT", "true", "renewal relay strict mode must be enabled in production");
checkRequired("ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE");
checkRequired("ZYLITH_RENEWAL_RELAY_STORE_PATH");
checkRequired("ZYLITH_RENEWAL_RELAY_PACKAGE_TOKEN");
if (relayAcceptsHostedMode()) {
  checkSecret("ZYLITH_RENEWAL_RELAY_COORDINATOR_CONTROL_TOKEN", 32);
}
checkSecret("ZYLITH_RENEWAL_RELAY_PROVER_CONTROL_TOKEN", 32);
checkRequired("ZYLITH_RENEWAL_RELAY_COORDINATOR_URL");
checkRequired("ZYLITH_RENEWAL_RELAY_PROVER_URL");

checkRequired("ZYLITH_ALERT_WEBHOOK_URL");
checkRequired("ZYLITH_MONITORING_ENV");
checkRequired("ZYLITH_CRASH_DUMP_POLICY");
checkExternalAuditSignals();
checkKeyCustodySignals();
checkDeploymentManifest();
checkLiquidityPricePolicy();

if (failures.length > 0) {
  console.error("production readiness failed");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("production readiness checks passed");

function checkRequired(name) {
  if (!value(name)) failures.push(`${name} is required`);
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
  const proverUrl = value("ZYLITH_NATIVE_TX_PROVER_URL");
  if (isPrivateOrLocalUrl(proverUrl)) {
    failures.push(
      "ZYLITH_NATIVE_TX_PROVER_URL must use the configured external Starknet prover endpoint; production must not use local, private, or self-hosted native prover URLs",
    );
    return;
  }
  if (!isHttpsUrl(proverUrl) && !value("ZYLITH_NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX")) {
    failures.push(
      "ZYLITH_NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX is required when the external native prover URL is not HTTPS",
    );
  }
}

function isPrivateOrLocalUrl(current) {
  try {
    const hostname = new URL(current).hostname.toLowerCase();
    const host = hostname.replace(/^\[|\]$/g, "");
    if (host === "localhost" || host === "::1") return true;
    if (host.includes(":")) {
      return (
        host === "::" ||
        host.startsWith("fc") ||
        host.startsWith("fd") ||
        host.startsWith("fe80:") ||
        host.startsWith("ff") ||
        host.startsWith("2001:db8:")
      );
    }
    const ipv4 = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!ipv4) return false;
    const octets = ipv4.slice(1).map(Number);
    if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false;
    const [a, b] = octets;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a === 169 && b === 254 ||
      a === 172 && b >= 16 && b <= 31 ||
      a === 192 && b === 168 ||
      a >= 224 && a <= 239 ||
      a >= 240 ||
      a === 100 && b >= 64 && b <= 127 ||
      a === 192 && b === 0 ||
      a === 192 && b === 0 && octets[2] === 2 ||
      a === 198 && (b === 18 || b === 19) ||
      a === 203 && b === 0 && octets[2] === 113
    );
  } catch {
    return false;
  }
}

function isHttpsUrl(current) {
  try {
    return new URL(current).protocol === "https:";
  } catch {
    return false;
  }
}

function normalizeEndpointUrl(current) {
  if (typeof current !== "string" || current.trim() === "") return null;
  try {
    const parsed = new URL(current.trim());
    parsed.hash = "";
    parsed.search = "";
    parsed.pathname = parsed.pathname.replace(/\/+$/, "") || "/";
    return parsed.toString();
  } catch {
    return null;
  }
}

function checkExternalAuditSignals() {
  expectValue("ZYLITH_EXTERNAL_AUDIT_COMPLETE", "true", "external audit must be complete when required");
  checkExactInt("ZYLITH_EXTERNAL_AUDIT_CRITICAL_OPEN", 0);
  checkExactInt("ZYLITH_EXTERNAL_AUDIT_HIGH_OPEN", 0);
  const reportHash = value("ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256");
  if (!reportHash) {
    failures.push("ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256 is required when external audit is required");
  } else if (!/^[0-9a-fA-F]{64}$/.test(reportHash)) {
    failures.push("ZYLITH_EXTERNAL_AUDIT_REPORT_SHA256 must be a 64-character hex digest");
  }
  const reportUri = value("ZYLITH_EXTERNAL_AUDIT_REPORT_URI");
  if (!reportUri) {
    failures.push("ZYLITH_EXTERNAL_AUDIT_REPORT_URI is required when external audit is required");
  } else if (!/^https:\/\//.test(reportUri)) {
    failures.push("ZYLITH_EXTERNAL_AUDIT_REPORT_URI must be an https URL");
  }
}

function checkKeyCustodySignals() {
  const mode = (value("ZYLITH_KEY_CUSTODY_MODE") || "").toLowerCase();
  if (!mode) {
    failures.push("ZYLITH_KEY_CUSTODY_MODE is required");
    return;
  }
  if (!["hsm", "multisig", "hardware-multisig", "hardware"].includes(mode)) {
    failures.push("ZYLITH_KEY_CUSTODY_MODE must be hsm, multisig, hardware-multisig, or hardware");
  }
}

function relayAcceptsHostedMode() {
  const mode = (value("ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE") || "").toLowerCase();
  if (!["zylith", "zylithrelay", "self", "selfrelay", "self-hosted", "selfhosted"].includes(mode)) {
    failures.push("ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE must be ZylithRelay or SelfRelay");
    return false;
  }
  return ["zylith", "zylithrelay"].includes(mode);
}

function checkOptionalSecretList(name, minLength) {
  const current = value(name);
  if (!current) {
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
  const normalized = normalizeFeltText(current);
  if (!normalized) {
    failures.push(`${name} must be a valid Starknet felt`);
  } else if (normalized === "0x0") {
    failures.push(`${name} must be non-zero`);
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
  return normalizeFeltText(input) || "";
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
  const manifestSignature = value("ZYLITH_DEPLOYMENT_MANIFEST_SIGNATURE");
  const manifestSigner = value("ZYLITH_DEPLOYMENT_MANIFEST_SIGNER_PUBLIC_KEY_PEM");
  if (!manifestSignature) {
    failures.push("ZYLITH_DEPLOYMENT_MANIFEST_SIGNATURE is required");
  }
  if (!manifestSigner) {
    failures.push("ZYLITH_DEPLOYMENT_MANIFEST_SIGNER_PUBLIC_KEY_PEM is required");
  }
  if (manifestSignature && manifestSigner) {
    try {
      const signature = Buffer.from(manifestSignature, "base64");
      if (!verify(null, manifestBytes, manifestSigner, signature)) {
        failures.push("deployment manifest signature does not verify");
      }
    } catch (error) {
      failures.push(`deployment manifest signature verification failed: ${error.message}`);
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
  checkDeploymentJsonEnv(manifest);

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
    "STRK/USDC": 4,
    "ETH/USDC": 4,
    "strkBTC/USDC": 4,
    "STRK/ETH": 4,
    "STRK/strkBTC": 4,
    "WBTC/strkBTC": 1,
    "USDC/USDT": 1,
  };

  for (const asset of requiredAssets) {
    checkManifestNonZero(manifest.token_addresses?.[asset], `token_addresses.${asset}`);
    const assetConfig = manifest.product?.assets?.[asset];
    if (!assetConfig?.enabled) failures.push(`product.assets.${asset} must be enabled`);
    checkManifestAssetTokenAliases(manifest, asset);
    if (assetConfig?.erc20_behavior !== "vanilla-exact-delta") {
      failures.push(`product.assets.${asset}.erc20_behavior must be vanilla-exact-delta`);
    }
    if (assetConfig?.audit_status !== "approved") {
      failures.push(`product.assets.${asset}.audit_status must be approved`);
    }
    checkAssetAuditEvidence(assetConfig, `product.assets.${asset}`);
  }

  for (const [pair, taker] of Object.entries(requiredPairs)) {
    const pairConfig = manifest.product?.pairs?.[pair];
    if (!pairConfig?.enabled) {
      failures.push(`product.pairs.${pair} must be enabled`);
      continue;
    }
    if (pairConfig.taker_fee_bps !== taker) {
      failures.push(`product.pairs.${pair}.taker_fee_bps must be ${taker}`);
    }
  }

  if (manifest.funding?.primary !== "starknet_privacy") {
    failures.push("funding.primary must be starknet_privacy");
  }
  const privacyFunding = manifest.funding?.starknet_privacy || {};
  checkManifestNonZero(privacyFunding.privacy_pool, "funding.starknet_privacy.privacy_pool");
  checkManifestNonZero(privacyFunding.bridge_adapter, "funding.starknet_privacy.bridge_adapter");
  checkManifestNonZero(privacyFunding.paymaster_address, "funding.starknet_privacy.paymaster_address");
  checkManifestNonZero(privacyFunding.proof_signer_class_hash, "funding.starknet_privacy.proof_signer_class_hash");
  checkManifestUrl(privacyFunding.discovery_url, "funding.starknet_privacy.discovery_url");
  checkManifestUrl(privacyFunding.proving_url, "funding.starknet_privacy.proving_url");
  if (privacyFunding.proving_ohttp_enabled !== true) {
    failures.push("funding.starknet_privacy.proving_ohttp_enabled must be true");
  }
  checkManifestUrl(privacyFunding.paymaster_url, "funding.starknet_privacy.paymaster_url");
  checkManifestFeltEquals(
    privacyFunding.bridge_adapter,
    manifest.contracts?.privacy_deposit_bridge,
    "funding.starknet_privacy.bridge_adapter",
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
    "admission_proof_program_hash",
    "auction_result_proof_program_hash",
    "nullifier_proof_program_hash",
    "renewal_proof_program_hash",
    "liquidity_position_proof_program_hash",
    "settlement_proof_program_hash",
    "settlement_order_proof_program_hash",
    "settlement_input_membership_proof_program_hash",
    "settlement_output_recovery_proof_program_hash",
    "note_consolidation_proof_program_hash",
    "aggregate_settlement_proof_program_hash",
    "withdrawal_proof_program_hash",
    "multi_pair_proof_program_hash",
    "settlement_statement_program_address",
    "settlement_note_fee_statement_program_address",
    "settlement_order_statement_program_address",
    "settlement_input_membership_statement_program_address",
    "settlement_output_recovery_statement_program_address",
    "nullifier_statement_program_address",
    "renewal_statement_program_address",
    "liquidity_position_statement_program_address",
    "note_consolidation_statement_program_address",
    "withdrawal_statement_program_address",
    "admission_statement_program_address",
    "auction_result_statement_program_address",
    "multi_pair_statement_program_address",
    "proof_account_address",
    "settlement_account_address",
  ]) {
    checkManifestNonZero(manifest.proof?.[key], `proof.${key}`);
  }
  const statementProofHashes = manifest.proof?.statement_proof_program_hashes || {};
  for (const [statementKind, proofField] of [
    ["ADMISSION", "admission_proof_program_hash"],
    ["AUCTION_RESULT", "auction_result_proof_program_hash"],
    ["NULLIFIER", "nullifier_proof_program_hash"],
    ["RENEWAL", "renewal_proof_program_hash"],
    ["LIQUIDITY_POSITION", "liquidity_position_proof_program_hash"],
    ["SETTLEMENT", "settlement_proof_program_hash"],
    ["SETTLEMENT_ORDER", "settlement_order_proof_program_hash"],
    [
      "SETTLEMENT_INPUT_MEMBERSHIP",
      "settlement_input_membership_proof_program_hash",
    ],
    [
      "SETTLEMENT_OUTPUT_RECOVERY",
      "settlement_output_recovery_proof_program_hash",
    ],
    ["NOTE_CONSOLIDATION", "note_consolidation_proof_program_hash"],
    ["AGGREGATE_SETTLEMENT", "aggregate_settlement_proof_program_hash"],
    ["WITHDRAWAL", "withdrawal_proof_program_hash"],
    ["MULTI_PAIR", "multi_pair_proof_program_hash"],
  ]) {
    const mapValue = statementProofHashes[statementKind];
    checkManifestNonZero(mapValue, `proof.statement_proof_program_hashes.${statementKind}`);
    checkManifestFeltEquals(
      mapValue,
      manifest.proof?.[proofField],
      `proof.statement_proof_program_hashes.${statementKind}`,
      `proof.${proofField}`,
    );
  }
  if (manifest.proof?.proof_version !== "PROOF1") {
    failures.push("proof.proof_version must be PROOF1");
  }
  const manifestNativeProverUrl = normalizeEndpointUrl(manifest.proof?.native_tx_prover_url);
  const configuredNativeProverUrl = normalizeEndpointUrl(value("ZYLITH_NATIVE_TX_PROVER_URL"));
  if (!manifestNativeProverUrl) {
    failures.push("proof.native_tx_prover_url must be a valid external URL");
  } else if (isPrivateOrLocalUrl(manifestNativeProverUrl)) {
    failures.push("proof.native_tx_prover_url must not reference local, private, or self-hosted prover URLs");
  } else if (configuredNativeProverUrl && manifestNativeProverUrl !== configuredNativeProverUrl) {
    failures.push("proof.native_tx_prover_url must match ZYLITH_NATIVE_TX_PROVER_URL");
  }
  if (manifest.proof?.native_tx_prover_ohttp_enabled !== true) {
    failures.push("proof.native_tx_prover_ohttp_enabled must be true");
  }
  for (const key of [
    "proof_program_locked_after_deploy",
    "operational_config_locked_after_deploy",
    "commitment_registry_config_locked_after_deploy",
    "batch_registry_config_locked_after_deploy",
    "privacy_deposit_bridge_config_locked_after_deploy",
  ]) {
    if (manifest.proof?.[key] !== true) {
      failures.push(`proof.${key} must be true for production readiness`);
    }
  }

  if (JSON.stringify(manifest).includes("example.invalid")) {
    failures.push("deployment manifest must not contain example.invalid placeholders");
  }
}

function checkDeploymentJsonEnv(manifest) {
  const deploymentJson = value("ZYLITH_DEPLOYMENT_JSON");
  if (!deploymentJson) return;
  let envManifest;
  try {
    const parsed = JSON.parse(deploymentJson);
    envManifest = parsed.manifest || parsed;
  } catch (error) {
    failures.push(`ZYLITH_DEPLOYMENT_JSON is not valid JSON: ${error.message}`);
    return;
  }
  if (stableJson(envManifest) !== stableJson(manifest)) {
    failures.push("ZYLITH_DEPLOYMENT_JSON must match the signed deployment manifest");
  }
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function checkAssetAuditEvidence(assetConfig, label) {
  const evidence = assetConfig?.audit_evidence;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    failures.push(`${label}.audit_evidence is required`);
    return;
  }
  if (typeof evidence.auditor !== "string" || evidence.auditor.trim() === "") {
    failures.push(`${label}.audit_evidence.auditor is required`);
  }
  if (typeof evidence.report_uri !== "string" || !/^https:\/\//.test(evidence.report_uri)) {
    failures.push(`${label}.audit_evidence.report_uri must be an https URL`);
  }
  if (typeof evidence.report_sha256 !== "string" || !/^[0-9a-fA-F]{64}$/.test(evidence.report_sha256)) {
    failures.push(`${label}.audit_evidence.report_sha256 must be a 64-character hex digest`);
  }
  if (typeof evidence.approved_at !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(evidence.approved_at)) {
    failures.push(`${label}.audit_evidence.approved_at must be YYYY-MM-DD`);
  }
}

function checkManifestAssetTokenAliases(manifest, asset) {
  const canonical = manifest.token_addresses?.[asset];
  const productToken = manifest.product?.assets?.[asset]?.token_address;
  const fundingToken = manifest.funding?.assets?.[asset]?.token_address;
  const railToken = manifest.funding?.assets?.[asset]?.rail_token_address;

  checkManifestNonZero(productToken, `product.assets.${asset}.token_address`);
  checkManifestNonZero(fundingToken, `funding.assets.${asset}.token_address`);
  checkManifestNonZero(railToken, `funding.assets.${asset}.rail_token_address`);
  checkManifestFeltEquals(productToken, canonical, `product.assets.${asset}.token_address`, `token_addresses.${asset}`);
  checkManifestFeltEquals(fundingToken, canonical, `funding.assets.${asset}.token_address`, `token_addresses.${asset}`);
  checkManifestFeltEquals(railToken, canonical, `funding.assets.${asset}.rail_token_address`, `token_addresses.${asset}`);
}

function checkLiquidityPricePolicy() {
  const policyPath = value("ZYLITH_LIQUIDITY_PRICE_POLICY_PATH") || "ops/config/liquidity-price-sources.mainnet.json";
  if (!existsSync(policyPath)) {
    failures.push(`liquidity price policy is required at ${policyPath}`);
    return;
  }
  let policy;
  try {
    policy = JSON.parse(readFileSync(policyPath, "utf8"));
  } catch (error) {
    failures.push(`liquidity price policy at ${policyPath} is not valid JSON: ${error.message}`);
    return;
  }
  if (policy.version !== 1) failures.push("liquidity price policy version must be 1");
  if (policy.network !== "mainnet") failures.push("liquidity price policy network must be mainnet");
  if (policy.description && /last[- ]?cleared/i.test(policy.description) && !/intentionally not/i.test(policy.description)) {
    failures.push("liquidity price policy must not use last-cleared prices as a fallback");
  }
  checkManifestNonZero(policy.pragma?.oracle_address, "liquidity price policy pragma.oracle_address");
  checkManifestNonZero(policy.pragma?.entrypoint, "liquidity price policy pragma.entrypoint");
  if (Number(policy.pragma?.min_source_count ?? 0) < 2) {
    failures.push("liquidity price policy pragma.min_source_count must be at least 2");
  }
  const forbidden = (policy.global_policy?.forbidden_fallbacks || []).map((entry) => String(entry).toLowerCase());
  for (const required of ["last-cleared-price", "fixed-price", "single-exchange-only"]) {
    if (!forbidden.includes(required)) {
      failures.push(`liquidity price policy must forbid ${required}`);
    }
  }
  if (policy.global_policy?.large_move_policy !== "require-confirmation-widen-size-reduce-or-halt") {
    failures.push("liquidity price policy global_policy.large_move_policy must require confirmation, widening, size reduction, or halt");
  }
  const requiredPairs = ["STRK/USDC", "ETH/USDC", "strkBTC/USDC", "STRK/ETH", "STRK/strkBTC", "WBTC/strkBTC", "USDC/USDT"];
  const minSources = Number(policy.global_policy?.min_sources ?? 0);
  if (minSources < 3) failures.push("liquidity price policy global_policy.min_sources must be at least 3");
  for (const pair of requiredPairs) {
    const pairPolicy = policy.pairs?.[pair];
    if (!pairPolicy) {
      failures.push(`liquidity price policy must include ${pair}`);
      continue;
    }
    if (!String(pairPolicy.primary ?? "").startsWith("pragma:")) {
      failures.push(`liquidity price policy ${pair}.primary must use Pragma as primary source`);
    }
    const confirmations = Array.isArray(pairPolicy.confirmations) ? pairPolicy.confirmations : [];
    if (confirmations.length < 2) {
      failures.push(`liquidity price policy ${pair}.confirmations must include at least two independent confirmations`);
    }
    const uniqueConfirmations = new Set(confirmations.map((entry) => String(entry).trim().toLowerCase()).filter(Boolean));
    if (uniqueConfirmations.size !== confirmations.length) {
      failures.push(`liquidity price policy ${pair}.confirmations must be unique independent sources`);
    }
    if (Number(pairPolicy.min_independent_sources ?? 0) < minSources) {
      failures.push(`liquidity price policy ${pair}.min_independent_sources must be >= global_policy.min_sources`);
    }
    const serialized = JSON.stringify(pairPolicy).toLowerCase();
    if (serialized.includes("last-cleared") || serialized.includes("last cleared") || serialized.includes("\"fixed\"")) {
      failures.push(`liquidity price policy ${pair} must not include last-cleared or fixed-price fallbacks`);
    }
  }
}

function normalizeFeltText(current) {
  if (typeof current !== "string" || current.trim() === "") return null;
  const trimmed = current.trim();
  try {
    let parsed = null;
    if (/^0x[0-9a-fA-F]+$/.test(trimmed)) parsed = BigInt(trimmed);
    if (/^[0-9]+$/.test(trimmed)) parsed = BigInt(trimmed);
    if (parsed === null || parsed < 0n || parsed >= STARKNET_FIELD_PRIME) return null;
    return `0x${parsed.toString(16)}`;
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
  const normalized = normalizeFeltText(current);
  if (!normalized) {
    failures.push(`${label} must be a valid Starknet felt`);
    return;
  }
  if (normalized === "0x0") {
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
  return normalizeFeltText(current) === "0x0";
}

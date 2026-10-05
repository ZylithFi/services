import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export type PaymasterConfig = {
  registryVersion: number;
  registryHash: string;
  rpcUrl: string;
  chainId: string;
  accountAddress: string;
  privateKey: string;
  privacySignerClassHash: string;
  feeTokenAddress: string;
  privacyBridgeAddress: string;
  privacyPoolAddress: string;
  privacyPoolClassHash: string;
  allowedContracts: Set<string>;
  allowedEntrypoints: Set<string>;
  proofRequiredEntrypoints: Set<string>;
  bindHost: string;
  port: number;
  maxBodyBytes: number;
  allowedOrigins: Set<string>;
  signerLimitPerMinute: number;
  maxSponsoredFeeFri: bigint;
  dailySponsoredFeeFri: bigint;
  dailySponsoredFeePerPrincipalFri: bigint;
  trustProxyHeaders: boolean;
  trustedProxyCidrs: string[];
  internalApiToken: string;
  submissionLogPath: string | null;
  sponsoredFeeLogPath: string | null;
};

const DEFAULT_PORT = 8787;
const DEFAULT_MAX_BODY_BYTES = 1_000_000;
const DEFAULT_SIGNER_LIMIT_PER_MINUTE = 20;
const DEFAULT_MAX_SPONSORED_FEE_FRI = 1_000_000_000_000_000_000n;
const DEFAULT_DAILY_SPONSORED_FEE_FRI = 100_000_000_000_000_000_000n;
const DEFAULT_DAILY_SPONSORED_FEE_PER_PRINCIPAL_FRI = 5_000_000_000_000_000_000n;
const STARKNET_FIELD_PRIME =
  3618502788666131213697322783095070105623107215331596699973092056135872020481n;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): PaymasterConfig {
  const rpcUrl = requiredServiceUrl(env, "ZYLITH_PAYMASTER_RPC_URL");
  const chainId = normalizeNonZeroFelt(requiredEnv(env, "ZYLITH_PAYMASTER_CHAIN_ID"));
  const accountAddress = normalizeNonZeroFelt(requiredEnv(env, "ZYLITH_PAYMASTER_ACCOUNT_ADDRESS"));
  const privateKey = requiredEnv(env, "ZYLITH_PAYMASTER_PRIVATE_KEY");
  const privacySignerClassHash = normalizeNonZeroFelt(
    requiredEnv(env, "ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH")
  );
  if (env.ZYLITH_PAYMASTER_ALLOWED_CONTRACTS || env.ZYLITH_PAYMASTER_APPROVAL_SPENDERS) {
    throw new Error("paymaster market allowlist overrides are retired; use the deployment market registry");
  }
  const authority = loadDeploymentAuthority(requiredEnv(env, "ZYLITH_DEPLOYMENT_MANIFEST"));
  if (chainId !== authority.chainId) {
    throw new Error("paymaster chain id differs from the deployment market registry");
  }
  if (accountAddress !== authority.paymasterAddress) {
    throw new Error("paymaster account differs from the deployment manifest");
  }
  if (privacySignerClassHash !== authority.proofSignerClassHash) {
    throw new Error("privacy signer class hash differs from the deployment manifest");
  }
  const allowedContracts = new Set([
    ...authority.fundingTokens,
    authority.privacyPool,
    authority.exchange,
    authority.privacyBridge,
  ]);
  const allowedEntrypoints = parseNameSet(requiredEnv(env, "ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS"));
  const proofRequiredEntrypoints = parseOptionalNameSet(
    requiredEnv(env, "ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS")
  );
  const allowedOrigins = parseOrigins(env.ZYLITH_PAYMASTER_ALLOWED_ORIGINS);
  const internalApiToken =
    env.ZYLITH_PAYMASTER_INTERNAL_TOKEN?.trim() ||
    env.ZYLITH_CONTROL_PLANE_TOKEN?.trim() ||
    "";
  const trustProxyHeaders = parseBool(env.ZYLITH_PAYMASTER_TRUST_PROXY_HEADERS, false);
  const trustedProxyCidrs = parseCsv(
    env.ZYLITH_PAYMASTER_TRUSTED_PROXY_CIDRS ?? env.ZYLITH_TRUSTED_PROXY_CIDRS
  );

  if (allowedOrigins.size === 0) {
    throw new Error("ZYLITH_PAYMASTER_ALLOWED_ORIGINS must contain at least one exact origin");
  }
  if (trustProxyHeaders && trustedProxyCidrs.length === 0) {
    throw new Error(
      "ZYLITH_PAYMASTER_TRUSTED_PROXY_CIDRS or ZYLITH_TRUSTED_PROXY_CIDRS is required when ZYLITH_PAYMASTER_TRUST_PROXY_HEADERS=true"
    );
  }
  if (!internalApiToken) {
    throw new Error("ZYLITH_PAYMASTER_INTERNAL_TOKEN or ZYLITH_CONTROL_PLANE_TOKEN is required");
  }

  const maxSponsoredFeeFri = parsePositiveBigInt(
    env.ZYLITH_PAYMASTER_MAX_SPONSORED_FEE_FRI,
    DEFAULT_MAX_SPONSORED_FEE_FRI,
    "ZYLITH_PAYMASTER_MAX_SPONSORED_FEE_FRI"
  );
  const dailySponsoredFeeFri = parsePositiveBigInt(
    env.ZYLITH_PAYMASTER_DAILY_SPONSORED_FEE_FRI,
    DEFAULT_DAILY_SPONSORED_FEE_FRI,
    "ZYLITH_PAYMASTER_DAILY_SPONSORED_FEE_FRI"
  );
  const dailySponsoredFeePerPrincipalFri = parsePositiveBigInt(
    env.ZYLITH_PAYMASTER_DAILY_SPONSORED_FEE_PER_PRINCIPAL_FRI,
    DEFAULT_DAILY_SPONSORED_FEE_PER_PRINCIPAL_FRI,
    "ZYLITH_PAYMASTER_DAILY_SPONSORED_FEE_PER_PRINCIPAL_FRI"
  );
  if (dailySponsoredFeeFri < maxSponsoredFeeFri) {
    throw new Error("daily sponsored fee limit must cover at least one transaction");
  }
  if (
    dailySponsoredFeePerPrincipalFri < maxSponsoredFeeFri
    || dailySponsoredFeePerPrincipalFri > dailySponsoredFeeFri
  ) {
    throw new Error("per-principal sponsored fee limit is inconsistent");
  }

  return {
    registryVersion: authority.registryVersion,
    registryHash: authority.registryHash,
    rpcUrl,
    chainId,
    accountAddress,
    privateKey,
    privacySignerClassHash,
    feeTokenAddress: authority.feeTokenAddress,
    privacyBridgeAddress: authority.privacyBridge,
    privacyPoolAddress: authority.privacyPool,
    privacyPoolClassHash: authority.privacyPoolClassHash,
    allowedContracts,
    allowedEntrypoints,
    proofRequiredEntrypoints,
    bindHost: env.ZYLITH_PAYMASTER_HOST ?? "127.0.0.1",
    port: parsePositiveInt(env.ZYLITH_PAYMASTER_PORT, DEFAULT_PORT, "ZYLITH_PAYMASTER_PORT"),
    maxBodyBytes: parsePositiveInt(
      env.ZYLITH_PAYMASTER_MAX_BODY_BYTES,
      DEFAULT_MAX_BODY_BYTES,
      "ZYLITH_PAYMASTER_MAX_BODY_BYTES"
    ),
    allowedOrigins,
    signerLimitPerMinute: parsePositiveInt(
      env.ZYLITH_PAYMASTER_SIGNER_LIMIT_PER_MINUTE,
      DEFAULT_SIGNER_LIMIT_PER_MINUTE,
      "ZYLITH_PAYMASTER_SIGNER_LIMIT_PER_MINUTE"
    ),
    maxSponsoredFeeFri,
    dailySponsoredFeeFri,
    dailySponsoredFeePerPrincipalFri,
    trustProxyHeaders,
    trustedProxyCidrs,
    internalApiToken,
    submissionLogPath: requiredEnv(env, "ZYLITH_PAYMASTER_SUBMISSION_LOG_PATH"),
    sponsoredFeeLogPath: requiredEnv(env, "ZYLITH_PAYMASTER_SPONSORED_FEE_LOG_PATH")
  };
}

type DeploymentAuthority = {
  fundingTokens: string[];
  privacyPool: string;
  privacyPoolClassHash: string;
  exchange: string;
  privacyBridge: string;
  chainId: string;
  paymasterAddress: string;
  proofSignerClassHash: string;
  feeTokenAddress: string;
  registryVersion: number;
  registryHash: string;
};

function loadDeploymentAuthority(path: string): DeploymentAuthority {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`deployment manifest ${path}: ${String(error)}`);
  }
  const wrapper = expectRecord(parsed, "deployment manifest");
  const manifest = expectRecord(wrapper.manifest ?? wrapper, "deployment manifest");
  const allowedManifestFields = new Set(["network", "rpc_url", "chain_id", "contracts", "market_registry", "funding", "proof", "deployment", "roles", "runtime"]);
  for (const field of Object.keys(manifest)) {
    if (!allowedManifestFields.has(field)) throw new Error(`deployment manifest contains obsolete or unknown field ${field}`);
  }
  const deployment = expectRecord(manifest.deployment, "deployment");
  const proof = expectRecord(manifest.proof, "proof");
  const releaseCommit = expectString(deployment.release_commit, "deployment.release_commit");
  if (deployment.finalized !== true || proof.config_locked_after_deploy !== true || !/^[0-9a-f]{40}$/.test(releaseCommit) || /^0+$/.test(releaseCommit)) {
    throw new Error("paymaster requires a finalized, locked deployment manifest");
  }
  const registry = expectRecord(manifest.market_registry, "market_registry");
  if (registry.schema_version !== 1 || !Number.isSafeInteger(registry.registry_version) || Number(registry.registry_version) <= 0) {
    throw new Error("deployment market registry identity is invalid");
  }
  const declaredHash = expectString(registry.registry_hash, "registry_hash").toLowerCase();
  const hashInput = { ...registry };
  delete hashInput.registry_hash;
  const computedHash = createHash("sha256").update(canonicalJson(hashInput)).digest("hex");
  if (declaredHash !== computedHash) {
    throw new Error("deployment market registry hash mismatch");
  }
  if (manifest.network !== registry.network || manifest.chain_id !== registry.chain_id) {
    throw new Error("deployment and market registry identities differ");
  }
  if (typeof registry.network !== "string" || !/^[a-z0-9_-]{1,32}$/.test(registry.network)) {
    throw new Error("deployment market registry network is invalid");
  }
  if (!Array.isArray(registry.assets) || !Array.isArray(registry.markets) || registry.assets.length === 0 || registry.markets.length === 0) {
    throw new Error("deployment market registry has no assets or markets");
  }
  const allAssets = registry.assets.map((value, index) => expectRecord(value, `market_registry.assets[${index}]`));
  const assetIds = allAssets.map((asset) => expectRegistryIdentifier(asset.asset_id, "asset_id"));
  if (!strictlySortedUnique(assetIds)) throw new Error("deployment market registry asset ids must be sorted and unique");
  const enabledAssets = allAssets.filter((asset) => asset.enabled === true);
  if (allAssets.some((asset) => asset.enabled !== true && asset.funding_enabled === true)) {
    throw new Error("disabled market-registry assets cannot enable funding");
  }
  if (enabledAssets.some((asset) => asset.funding_enabled !== true)) {
    throw new Error("every enabled market-registry asset must enable funding");
  }
  const allTokens = allAssets.map((asset) => normalizeNonZeroFelt(expectString(asset.token_address, "token_address")));
  if (new Set(allTokens).size !== allTokens.length) {
    throw new Error("deployment market registry has invalid funding token configuration");
  }
  const fundingTokens = enabledAssets.map((asset) => normalizeNonZeroFelt(expectString(asset.token_address, "token_address")));
  if (fundingTokens.length === 0) throw new Error("deployment market registry enables no funding assets");
  const assetsById = new Map(allAssets.map((asset, index) => [assetIds[index], asset]));
  const markets = registry.markets.map((value, index) => expectRecord(value, `market_registry.markets[${index}]`));
  const marketIds = markets.map((market) => expectRegistryIdentifier(market.market_id, "market_id"));
  if (!strictlySortedUnique(marketIds)) throw new Error("deployment market registry market ids must be sorted and unique");
  const objectiveNumeraire = expectRegistryIdentifier(registry.objective_numeraire_asset_id, "objective_numeraire_asset_id");
  for (const market of markets) {
    const capabilities = expectRecord(market.capabilities, `${String(market.market_id)}.capabilities`);
    if (market.enabled !== true && capabilities.external_matching === true) {
      throw new Error(`deployment market registry disabled market ${String(market.market_id)} cannot enable external matching`);
    }
  }
  for (const market of markets.filter((candidate) => candidate.enabled === true)) {
    const id = expectString(market.market_id, "market_id");
    const base = expectRegistryIdentifier(market.base_asset_id, "base_asset_id");
    const quote = expectRegistryIdentifier(market.quote_asset_id, "quote_asset_id");
    if (id !== `${base}/${quote}` || assetsById.get(base)?.enabled !== true || assetsById.get(quote)?.enabled !== true) {
      throw new Error(`deployment market registry market ${id} is invalid`);
    }
    const capabilities = expectRecord(market.capabilities, `${id}.capabilities`);
    if (capabilities.market_data !== true) throw new Error(`deployment market registry market ${id} has no market data`);
    validateReferencePrice(expectRecord(market.reference_price, `${id}.reference_price`), market, markets, objectiveNumeraire);
  }
  const enabledMarkets = markets.filter((candidate) => candidate.enabled === true);
  for (const [assetId, asset] of assetsById) {
    if (asset.enabled !== true) continue;
    const used = enabledMarkets.some((market) => market.base_asset_id === assetId || market.quote_asset_id === assetId);
    if (!used) throw new Error(`deployment market registry enabled asset ${assetId} is unused`);
    if (assetId !== objectiveNumeraire) {
      const direct = enabledMarkets.filter((market) => (market.base_asset_id === assetId && market.quote_asset_id === objectiveNumeraire) || (market.quote_asset_id === assetId && market.base_asset_id === objectiveNumeraire));
      if (direct.length !== 1) throw new Error(`deployment market registry asset ${assetId} must have exactly one direct numeraire market`);
    }
  }
  const funding = expectRecord(manifest.funding, "funding");
  const privacy = expectRecord(funding.starknet_privacy, "funding.starknet_privacy");
  if (funding.primary !== "starknet_privacy" || privacy.proving_ohttp_policy !== "best_effort") {
    throw new Error("production funding must use best-effort ohttp");
  }
  const gasFeeAssetId = expectString(registry.gas_fee_asset_id, "market_registry.gas_fee_asset_id");
  const gasFeeAsset = enabledAssets.find(
    (asset) => expectString(asset.asset_id, "asset_id") === gasFeeAssetId
  );
  if (!gasFeeAsset) {
    throw new Error("market registry gas fee asset is not an enabled funding asset");
  }
  return {
    fundingTokens,
    privacyPool: normalizeNonZeroFelt(expectString(privacy.privacy_pool, "privacy_pool")),
    privacyPoolClassHash: normalizeNonZeroFelt(
      expectString(privacy.privacy_pool_class_hash, "funding.starknet_privacy.privacy_pool_class_hash")
    ),
    exchange: normalizeNonZeroFelt(
      expectString(expectRecord(manifest.contracts, "contracts").exchange, "contracts.exchange")
    ),
    privacyBridge: normalizeNonZeroFelt(
      expectString(
        expectRecord(manifest.contracts, "contracts").privacy_deposit_bridge,
        "contracts.privacy_deposit_bridge"
      )
    ),
    chainId: normalizeNonZeroFelt(expectString(registry.chain_id, "market_registry.chain_id")),
    paymasterAddress: normalizeNonZeroFelt(
      expectString(privacy.paymaster_address, "funding.starknet_privacy.paymaster_address")
    ),
    proofSignerClassHash: normalizeNonZeroFelt(
      expectString(
        privacy.proof_signer_class_hash,
        "funding.starknet_privacy.proof_signer_class_hash"
      )
    ),
    feeTokenAddress: normalizeNonZeroFelt(
      expectString(gasFeeAsset.token_address, "gas fee asset token_address")
    ),
    registryVersion: Number(registry.registry_version),
    registryHash: declaredHash,
  };
}

function validateReferencePrice(
  reference: Record<string, unknown>,
  market: Record<string, unknown>,
  markets: Record<string, unknown>[],
  objectiveNumeraire: string,
): void {
  const marketId = expectString(market.market_id, "market_id");
  const maxAgeMs = Number(reference.max_age_ms);
  const attestationTtlMs = Number(reference.attestation_ttl_ms);
  const envelopeBps = Number(reference.envelope_bps);
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1 || maxAgeMs > 15_000 || !Number.isSafeInteger(attestationTtlMs) || attestationTtlMs < 1 || attestationTtlMs > 15_000 || !Number.isSafeInteger(envelopeBps) || envelopeBps < 1 || envelopeBps >= 10_000) {
    throw new Error(`deployment market registry market ${marketId} has invalid reference policy`);
  }
  if (reference.methodology === "synthetic_cross_bbo_midpoint") {
    const baseMarketId = expectString(reference.base_market_id, `${marketId}.base_market_id`);
    const quoteMarketId = expectString(reference.quote_market_id, `${marketId}.quote_market_id`);
    const base = markets.find((candidate) => candidate.market_id === baseMarketId);
    const quote = markets.find((candidate) => candidate.market_id === quoteMarketId);
    const maxLegSkewMs = Number(reference.max_leg_skew_ms);
    if (!base || !quote || base.enabled !== true || quote.enabled !== true || expectRecord(base.reference_price, "base reference").methodology !== "direct_bbo_midpoint" || expectRecord(quote.reference_price, "quote reference").methodology !== "direct_bbo_midpoint" || base.base_asset_id !== market.base_asset_id || quote.base_asset_id !== market.quote_asset_id || base.quote_asset_id !== objectiveNumeraire || quote.quote_asset_id !== objectiveNumeraire || base.price_base_scale !== market.price_base_scale || quote.price_base_scale !== market.price_base_scale || baseMarketId === quoteMarketId || !Number.isSafeInteger(maxLegSkewMs) || maxLegSkewMs < 1 || maxLegSkewMs > maxAgeMs) {
      throw new Error(`deployment market registry market ${marketId} has invalid synthetic reference policy`);
    }
    return;
  }
  const primary = expectRecord(reference.primary, `${marketId}.reference_price.primary`);
  const corroborating = Array.isArray(reference.corroborating)
    ? reference.corroborating.map((value, index) => expectRecord(value, `${marketId}.reference_price.corroborating[${index}]`))
    : [];
  const sources = [primary, ...corroborating];
  const adapters = sources.map((source) => expectString(source.adapter, "reference adapter"));
  const validSymbol = (value: unknown) => typeof value === "string" && /^[A-Za-z0-9._-]{1,40}$/.test(value);
  const corroboratingAdapters = new Set(corroborating.map((source) => source.adapter));
  if (reference.methodology !== "direct_bbo_midpoint" || primary.kind !== "direct" || primary.adapter !== "binance" || !validSymbol(primary.symbol) || corroborating.length < 2 || corroborating.some((source) => source.kind !== "same_venue_ratio" || !["coinbase", "kraken", "okx"].includes(String(source.adapter)) || !validSymbol(source.base_symbol) || !validSymbol(source.quote_symbol)) || !corroboratingAdapters.has("coinbase") || !corroboratingAdapters.has("kraken") || new Set(adapters).size !== adapters.length) {
    throw new Error(`deployment market registry market ${marketId} has invalid reference sources`);
  }
  const minSources = Number(reference.min_sources);
  const bps = [reference.max_source_spread_bps, reference.max_cross_source_deviation_bps].map(Number);
  if (market.quote_asset_id !== objectiveNumeraire || !Number.isSafeInteger(minSources) || minSources < 3 || minSources > sources.length || bps.some((value) => !Number.isSafeInteger(value) || value < 1 || value >= 10_000)) {
    throw new Error(`deployment market registry market ${marketId} has invalid reference policy`);
  }
}

function expectRegistryIdentifier(value: unknown, label: string): string {
  const identifier = expectString(value, label);
  if (!/^[A-Za-z0-9_\/-]{1,64}$/.test(identifier)) throw new Error(`${label} is invalid`);
  return identifier;
}

function strictlySortedUnique(values: string[]): boolean {
  return values.every((value, index) => index === 0 || values[index - 1]! < value);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("market registry contains a non-json value");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
    .join(",")}}`;
}

function expectRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function expectString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must be a string`);
  return value.trim();
}

export function normalizeFelt(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("felt value cannot be empty");
  }

  let parsed: bigint;
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    parsed = BigInt(trimmed);
  } else if (/^[0-9]+$/.test(trimmed)) {
    parsed = BigInt(trimmed);
  } else {
    throw new Error(`invalid felt value: ${value}`);
  }
  if (parsed >= STARKNET_FIELD_PRIME) {
    throw new Error(`invalid felt value: ${value}`);
  }
  return `0x${parsed.toString(16)}`;
}

function requiredEnv(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]?.trim();
  if (!value) {
    throw new Error(`${key} is required`);
  }
  return value;
}

function requiredServiceUrl(env: NodeJS.ProcessEnv, key: string): string {
  const value = requiredEnv(env, key);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${key} must be a valid http(s) URL`);
  }
  if (parsed.protocol === "https:") return value;
  if (parsed.protocol === "http:" && isLocalServiceHost(parsed.hostname)) {
    return value;
  }
  throw new Error(`${key} must use https outside local development`);
}

function parseFeltSet(value: string | undefined): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .map(normalizeNonZeroFelt)
  );
}

function normalizeNonZeroFelt(value: string): string {
  const normalized = normalizeFelt(value);
  if (normalized === "0x0") {
    throw new Error("felt value cannot be zero");
  }
  return normalized;
}

function parseNameSet(value: string): Set<string> {
  const names = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (names.length === 0) {
    throw new Error("allowed entrypoint set cannot be empty");
  }
  return new Set(names);
}

function parseOptionalNameSet(value: string): Set<string> {
  return new Set(
    value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
  );
}

function parseBool(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined || value.trim() === "") return defaultValue;
  return ["1", "true", "TRUE", "yes", "YES"].includes(value.trim());
}

function parseOrigins(value: string | undefined): Set<string> {
  const exact = new Set<string>();
  for (const item of (value ?? "").split(",").map((entry) => entry.trim()).filter(Boolean)) {
    if (item.includes("*")) {
      throw new Error("ZYLITH_PAYMASTER_ALLOWED_ORIGINS must contain exact origins only");
    }
    exact.add(item);
  }
  return exact;
}

function isLocalServiceHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]"
  );
}

function parseCsv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parsePositiveInt(value: string | undefined, defaultValue: number, key: string): number {
  if (!value) {
    return defaultValue;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${key} must be a positive integer`);
  }
  return parsed;
}

function parsePositiveBigInt(
  value: string | undefined,
  defaultValue: bigint,
  key: string
): bigint {
  if (!value) return defaultValue;
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`${key} must be a positive integer`);
  }
  const parsed = BigInt(value);
  if (parsed <= 0n) {
    throw new Error(`${key} must be a positive integer`);
  }
  return parsed;
}

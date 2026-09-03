export type PaymasterConfig = {
  rpcUrl: string;
  chainId: string;
  accountAddress: string;
  privateKey: string;
  privacySignerClassHash: string;
  allowedContracts: Set<string>;
  approvalSpenders: Set<string>;
  allowedEntrypoints: Set<string>;
  proofRequiredEntrypoints: Set<string>;
  bindHost: string;
  port: number;
  maxBodyBytes: number;
  allowedOrigins: Set<string>;
  signerLimitPerMinute: number;
  trustProxyHeaders: boolean;
  trustedProxyCidrs: string[];
  internalApiToken: string;
  submissionLogPath: string | null;
};

const DEFAULT_PORT = 8787;
const DEFAULT_MAX_BODY_BYTES = 1_000_000;
const DEFAULT_SIGNER_LIMIT_PER_MINUTE = 20;
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
  const allowedContracts = parseFeltSet(requiredEnv(env, "ZYLITH_PAYMASTER_ALLOWED_CONTRACTS"));
  const approvalSpenders = parseFeltSet(requiredEnv(env, "ZYLITH_PAYMASTER_APPROVAL_SPENDERS"));
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

  if (allowedContracts.size === 0) {
    throw new Error("ZYLITH_PAYMASTER_ALLOWED_CONTRACTS must be configured");
  }
  if (approvalSpenders.size === 0) {
    throw new Error("ZYLITH_PAYMASTER_APPROVAL_SPENDERS must be configured");
  }
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

  return {
    rpcUrl,
    chainId,
    accountAddress,
    privateKey,
    privacySignerClassHash,
    allowedContracts,
    approvalSpenders,
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
    trustProxyHeaders,
    trustedProxyCidrs,
    internalApiToken,
    submissionLogPath: env.ZYLITH_PAYMASTER_SUBMISSION_LOG_PATH?.trim() || "state/submissions.json"
  };
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

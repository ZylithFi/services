export type PaymasterConfig = {
  rpcUrl: string;
  chainId: string;
  accountAddress: string;
  privateKey: string;
  privacySignerClassHash: string | null;
  allowedContracts: Set<string>;
  allowedEntrypoints: Set<string>;
  proofRequiredEntrypoints: Set<string>;
  withdrawalAmountBuckets: Set<string>;
  allowDirectWithdrawalRelays: boolean;
  bindHost: string;
  port: number;
  maxBodyBytes: number;
  allowedOrigins: Set<string>;
  allowedOriginPatterns: RegExp[];
  signerLimitPerMinute: number;
  trustProxyHeaders: boolean;
  submissionLogPath: string | null;
};

const DEFAULT_PORT = 8787;
const DEFAULT_MAX_BODY_BYTES = 1_000_000;
const DEFAULT_SIGNER_LIMIT_PER_MINUTE = 20;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): PaymasterConfig {
  const rpcUrl = requiredEnv(env, "ZYLITH_PAYMASTER_RPC_URL");
  const chainId = normalizeFelt(requiredEnv(env, "ZYLITH_PAYMASTER_CHAIN_ID"));
  const accountAddress = normalizeFelt(requiredEnv(env, "ZYLITH_PAYMASTER_ACCOUNT_ADDRESS"));
  const privateKey = requiredEnv(env, "ZYLITH_PAYMASTER_PRIVATE_KEY");
  const privacySignerClassHash = optionalFelt(env.ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH);
  const allowedContracts = parseFeltSet(
    env.ZYLITH_PAYMASTER_ALLOWED_CONTRACTS ?? env.ZYLITH_PRIVACY_POOL_ADDRESS
  );
  const allowedEntrypoints = parseNameSet(
    env.ZYLITH_PAYMASTER_ALLOWED_ENTRYPOINTS ?? "apply_actions"
  );
  const proofRequiredEntrypoints = parseOptionalNameSet(
    env.ZYLITH_PAYMASTER_PROOF_REQUIRED_ENTRYPOINTS ??
      "apply_actions,submit_settlement_with_proof_facts,withdraw_settlement_output_with_proof_facts"
  );
  const withdrawalAmountBuckets = parseAmountBucketSet(env.ZYLITH_PAYMASTER_WITHDRAWAL_BUCKETS);
  const allowDirectWithdrawalRelays = parseBool(env.ZYLITH_PAYMASTER_ALLOW_DIRECT_WITHDRAWALS, false);
  const allowedOriginRules = parseOriginRules(env.ZYLITH_PAYMASTER_ALLOWED_ORIGINS);

  if (allowedContracts.size === 0) {
    throw new Error(
      "ZYLITH_PAYMASTER_ALLOWED_CONTRACTS or ZYLITH_PRIVACY_POOL_ADDRESS must be configured"
    );
  }
  if (allowDirectWithdrawalRelays && withdrawalAmountBuckets.size === 0) {
    throw new Error(
      "ZYLITH_PAYMASTER_WITHDRAWAL_BUCKETS is required when ZYLITH_PAYMASTER_ALLOW_DIRECT_WITHDRAWALS=true"
    );
  }
  if (
    allowDirectWithdrawalRelays &&
    !parseBool(env.ZYLITH_PAYMASTER_ACK_DIRECT_WITHDRAWAL_SPONSORSHIP_RISK, false)
  ) {
    throw new Error(
      "ZYLITH_PAYMASTER_ACK_DIRECT_WITHDRAWAL_SPONSORSHIP_RISK=true is required when ZYLITH_PAYMASTER_ALLOW_DIRECT_WITHDRAWALS=true"
    );
  }

  return {
    rpcUrl,
    chainId,
    accountAddress,
    privateKey,
    privacySignerClassHash,
    allowedContracts,
    allowedEntrypoints,
    proofRequiredEntrypoints,
    withdrawalAmountBuckets,
    allowDirectWithdrawalRelays,
    bindHost: env.ZYLITH_PAYMASTER_HOST ?? "127.0.0.1",
    port: parsePositiveInt(env.ZYLITH_PAYMASTER_PORT, DEFAULT_PORT, "ZYLITH_PAYMASTER_PORT"),
    maxBodyBytes: parsePositiveInt(
      env.ZYLITH_PAYMASTER_MAX_BODY_BYTES,
      DEFAULT_MAX_BODY_BYTES,
      "ZYLITH_PAYMASTER_MAX_BODY_BYTES"
    ),
    allowedOrigins: allowedOriginRules.exact,
    allowedOriginPatterns: allowedOriginRules.patterns,
    signerLimitPerMinute: parsePositiveInt(
      env.ZYLITH_PAYMASTER_SIGNER_LIMIT_PER_MINUTE,
      DEFAULT_SIGNER_LIMIT_PER_MINUTE,
      "ZYLITH_PAYMASTER_SIGNER_LIMIT_PER_MINUTE"
    ),
    trustProxyHeaders: parseBool(env.ZYLITH_PAYMASTER_TRUST_PROXY_HEADERS, false),
    submissionLogPath: env.ZYLITH_PAYMASTER_SUBMISSION_LOG_PATH?.trim() || "state/submissions.json"
  };
}

function optionalFelt(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed ? normalizeFelt(trimmed) : null;
}

export function normalizeFelt(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("felt value cannot be empty");
  }

  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    return `0x${BigInt(trimmed).toString(16)}`;
  }
  if (/^[0-9]+$/.test(trimmed)) {
    return `0x${BigInt(trimmed).toString(16)}`;
  }

  throw new Error(`invalid felt value: ${value}`);
}

function requiredEnv(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]?.trim();
  if (!value) {
    throw new Error(`${key} is required`);
  }
  return value;
}

function parseFeltSet(value: string | undefined): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .map(normalizeFelt)
  );
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

function parseAmountBucketSet(value: string | undefined): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .map((item) => {
        if (/^0x[0-9a-fA-F]+$/.test(item)) {
          return BigInt(item).toString();
        }
        if (/^[0-9]+$/.test(item)) {
          return BigInt(item).toString();
        }
        throw new Error(`invalid withdrawal amount bucket: ${item}`);
      })
  );
}

function parseBool(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined || value.trim() === "") return defaultValue;
  return ["1", "true", "TRUE", "yes", "YES"].includes(value.trim());
}

function parseOriginRules(value: string | undefined): { exact: Set<string>; patterns: RegExp[] } {
  const exact = new Set<string>();
  const patterns: RegExp[] = [];
  for (const item of (value ?? "").split(",").map((entry) => entry.trim()).filter(Boolean)) {
    if (item.includes("*")) {
      patterns.push(wildcardOriginPattern(item));
    } else {
      exact.add(item);
    }
  }
  return { exact, patterns };
}

function wildcardOriginPattern(value: string): RegExp {
  const escaped = value
    .split("*")
    .map((part) => part.replace(/[|\\{}()[\]^$+?.]/g, "\\$&"))
    .join("[^/]*");
  return new RegExp(`^${escaped}$`);
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

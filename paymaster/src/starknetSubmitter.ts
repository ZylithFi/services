import {
  Account,
  CallData,
  EDataAvailabilityMode,
  ETransactionVersion3,
  RpcProvider,
  outsideExecution
} from "starknet";
import type {
  Call,
  OutsideTransaction
} from "starknet";
import { selector } from "starknet";

import type { PaymasterConfig } from "./config.js";
import type {
  ExecuteOutsideRequest,
  ExecuteOutsideResponse,
  RpcResponse
} from "./types.js";
import { parsePrivacyPoolActions } from "./privacyPoolActions.js";

type AccountInstance = {
  getNonce(blockIdentifier?: string): Promise<string>;
  getCairoVersion(): Promise<string>;
  buildInvocation(calls: Call[], details: Record<string, unknown>): Promise<{
    contractAddress: unknown;
    calldata: unknown[];
    signature: unknown;
    nonce: unknown;
    resourceBounds: unknown;
    tip: unknown;
    paymasterData: unknown[];
    accountDeploymentData: unknown[];
    nonceDataAvailabilityMode: unknown;
    feeDataAvailabilityMode: unknown;
  }>;
};

type RpcProviderInstance = {
  getClassHashAt(contractAddress: string, blockIdentifier?: string): Promise<string>;
};

type ResourceBoundsLike = {
  l1_gas: { max_amount: bigint; max_price_per_unit: bigint };
  l2_gas: { max_amount: bigint; max_price_per_unit: bigint };
  l1_data_gas: { max_amount: bigint; max_price_per_unit: bigint };
};

export type StarknetRuntime = {
  Account: new (options: Record<string, unknown>) => AccountInstance;
  RpcProvider: new (options: { nodeUrl: string }) => RpcProviderInstance;
  CallData: {
    toHex(raw?: unknown): string[];
  };
  EDataAvailabilityMode: Pick<typeof EDataAvailabilityMode, "L1">;
  ETransactionVersion3: Pick<typeof ETransactionVersion3, "V3">;
  outsideExecution: Pick<typeof outsideExecution, "buildExecuteFromOutsideCall">;
};

const defaultRuntime: StarknetRuntime = {
  Account: Account as unknown as StarknetRuntime["Account"],
  RpcProvider: RpcProvider as unknown as StarknetRuntime["RpcProvider"],
  CallData,
  EDataAvailabilityMode,
  ETransactionVersion3,
  outsideExecution
};

const PAYMASTER_SUBMISSION_RETRY_ATTEMPTS = 3;
const PAYMASTER_NONCE_RETRY_DELAY_MS = 1_500;
const PAYMASTER_RPC_TIMEOUT_MS = 30_000;
const PAYMASTER_RPC_MAX_RESPONSE_BYTES = 1_000_000;
const DEFAULT_MAX_SPONSORED_FEE_FRI = 1_000_000_000_000_000_000n;
type ProofSubmissionConfig = Pick<
  PaymasterConfig,
  "rpcUrl" | "chainId" | "accountAddress" | "privateKey"
> &
  Partial<Pick<PaymasterConfig, "feeTokenAddress" | "maxSponsoredFeeFri">>;

export type SubmitterDeps = {
  runtime?: StarknetRuntime;
  fetchImpl?: typeof fetch;
  reserveSponsoredFee?: (maximumFeeFri: bigint) => Promise<() => Promise<void>>;
};

async function deployedClassHash(
  provider: RpcProviderInstance,
  contractAddress: string
): Promise<string | null> {
  return (
    await provider.getClassHashAt(contractAddress, "pre_confirmed").catch(() => null)
  ) ?? (
    await provider.getClassHashAt(contractAddress, "latest").catch(() => null)
  );
}

export async function submitProofBearingOutsideExecution(
  request: ExecuteOutsideRequest,
  config: ProofSubmissionConfig,
  deps: SubmitterDeps = {}
): Promise<ExecuteOutsideResponse> {
  if (!request.proof || !request.proof_facts || request.proof_facts.length === 0) {
    throw new Error("proof and proof_facts are required for paymaster execution");
  }
  const runtime = deps.runtime ?? defaultRuntime;
  const calls = [
    ...(request.authorization_call
      ? [callPayloadToStarknetCall(request.authorization_call)]
      : []),
    ...(request.outside_transaction
      ? (runtime.outsideExecution.buildExecuteFromOutsideCall(
          request.outside_transaction as OutsideTransaction
        ) as Call[])
      : [callPayloadToStarknetCall(request.call)]),
  ];
  return submitPaymasterCalls(calls, config, deps, request.proof, request.proof_facts);
}

async function submitPaymasterCalls(
  calls: Call[],
  config: ProofSubmissionConfig,
  deps: SubmitterDeps = {},
  proof?: string,
  proofFacts?: string[]
): Promise<ExecuteOutsideResponse> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < PAYMASTER_SUBMISSION_RETRY_ATTEMPTS; attempt += 1) {
    try {
      return await submitPaymasterCallsOnce(calls, config, deps, proof, proofFacts);
    } catch (error) {
      lastError = error;
      if (
        attempt < PAYMASTER_SUBMISSION_RETRY_ATTEMPTS - 1 &&
        isRetryableNonceError(error)
      ) {
        await sleep(PAYMASTER_NONCE_RETRY_DELAY_MS * (attempt + 1));
        continue;
      }
      throw error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

async function submitPaymasterCallsOnce(
  calls: Call[],
  config: ProofSubmissionConfig,
  deps: SubmitterDeps = {},
  proof?: string,
  proofFacts?: string[]
): Promise<ExecuteOutsideResponse> {
  const runtime = deps.runtime ?? defaultRuntime;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const provider = new runtime.RpcProvider({ nodeUrl: config.rpcUrl });
  const account = new runtime.Account({
    provider,
    address: config.accountAddress,
    signer: config.privateKey,
    transactionVersion: runtime.ETransactionVersion3.V3
  });
  const nonce = await account.getNonce();
  const cairoVersion = await account.getCairoVersion();
  const proofDetails =
    proof && proofFacts
      ? {
          proof,
          proofFacts
        }
      : {};
  const hasPoolCall = calls.some((call) => call.entrypoint === "apply_actions");
  const hasClaimAuthorization = calls.some(
    (call) => call.entrypoint === "authorize_strk20_exit_claim",
  );
  if (hasPoolCall && hasClaimAuthorization && !config.feeTokenAddress) {
    throw new Error("privacy-pool fee token is not configured");
  }
  if (config.feeTokenAddress) {
    const poolFee = await poolApplyActionsFee(fetchImpl, config.rpcUrl, calls);
    assertAtomicPoolFeeReimbursement(
      calls,
      { accountAddress: config.accountAddress, feeTokenAddress: config.feeTokenAddress },
      poolFee,
    );
  }
  const feeResourceBounds = await estimateProofBearingInvokeResourceBounds({
    account,
    calls,
    config,
    runtime,
    fetchImpl,
    nonce,
    cairoVersion,
    ...(proof && proofFacts
      ? {
          proof,
          proofFacts
        }
      : {})
  });
  assertSponsoredFeeWithinLimit(
    feeResourceBounds,
    config.maxSponsoredFeeFri ?? DEFAULT_MAX_SPONSORED_FEE_FRI
  );
  const details = {
    resourceBounds: feeResourceBounds,
    walletAddress: config.accountAddress,
    cairoVersion,
    chainId: config.chainId,
    version: runtime.ETransactionVersion3.V3,
    nonce,
    tip: 0,
    paymasterData: [],
    accountDeploymentData: [],
    nonceDataAvailabilityMode: runtime.EDataAvailabilityMode.L1,
    feeDataAvailabilityMode: runtime.EDataAvailabilityMode.L1,
    ...proofDetails
  };
  const invocation = await account.buildInvocation(calls, details);
  const invokeTransaction = {
    type: "INVOKE",
    sender_address: toRpcFelt(invocation.contractAddress, "sender_address"),
    calldata: runtime.CallData.toHex(invocation.calldata),
    signature: signatureToHexArray(invocation.signature),
    nonce: toRpcFelt(invocation.nonce ?? nonce, "nonce"),
    resource_bounds: resourceBoundsToRpc(invocation.resourceBounds ?? feeResourceBounds),
    tip: toRpcFelt(invocation.tip ?? 0, "tip"),
    paymaster_data: (invocation.paymasterData ?? []).map((value) =>
      toRpcFelt(value, "paymaster_data")
    ),
    account_deployment_data: (invocation.accountDeploymentData ?? []).map((value) =>
      toRpcFelt(value, "account_deployment_data")
    ),
    nonce_data_availability_mode: invocation.nonceDataAvailabilityMode ?? runtime.EDataAvailabilityMode.L1,
    fee_data_availability_mode: invocation.feeDataAvailabilityMode ?? runtime.EDataAvailabilityMode.L1,
    version: runtime.ETransactionVersion3.V3
  };
  if (proof && proofFacts) {
    Object.assign(invokeTransaction, {
      proof,
      proof_facts: proofFacts
    });
  }
  const releaseSponsoredFee = deps.reserveSponsoredFee
    ? await deps.reserveSponsoredFee(
      maximumSponsoredFee(feeResourceBounds)
    )
    : null;
  let transactionHash: string | undefined;
  try {
    transactionHash = await submitInvokeToRpc(fetchImpl, config.rpcUrl, invokeTransaction);
  } catch (error) {
    await releaseSponsoredFee?.();
    throw error;
  }
  if (!transactionHash) {
    await releaseSponsoredFee?.();
    throw new Error("Starknet submission response did not include transaction_hash");
  }

  return { transaction_hash: transactionHash };
}

function assertAtomicPoolFeeReimbursement(
  calls: Call[],
  config: Pick<ProofSubmissionConfig, "accountAddress" | "feeTokenAddress">,
  poolFee: bigint,
) {
  const poolCall = calls.find((call) => call.entrypoint === "apply_actions");
  if (!poolCall) return;
  if (poolFee <= 0n) throw new Error("privacy pool returned an invalid fee amount");
  const rawCalldata = Array.isArray(poolCall.calldata) ? poolCall.calldata : [];
  const actions = parsePrivacyPoolActions(
    rawCalldata.map((value: unknown) => String(value)),
    (value) => toRpcFelt(value),
  );
  const reimbursements = actions?.filter((action) => action.variant === 2) ?? [];
  if (
    reimbursements.length !== 1
    || reimbursements[0]?.recipient !== toRpcFelt(config.accountAddress)
    || reimbursements[0]?.token !== toRpcFelt(config.feeTokenAddress)
    || reimbursements[0]?.amount !== poolFee
  ) {
    throw new Error("privacy-pool claim must atomically reimburse its exact pool fee");
  }
}

export async function verifyPinnedPrivacyPoolClass(
  config: Pick<PaymasterConfig, "rpcUrl" | "privacyPoolAddress" | "privacyPoolClassHash">,
  deps: SubmitterDeps = {}
): Promise<void> {
  const runtime = deps.runtime ?? defaultRuntime;
  const provider = new runtime.RpcProvider({ nodeUrl: config.rpcUrl });
  const classHash = await deployedClassHash(provider, config.privacyPoolAddress);
  if (!classHash || toRpcFelt(classHash) !== config.privacyPoolClassHash) {
    throw new Error("privacy pool class hash differs from the pinned deployment");
  }
}

async function submitInvokeToRpc(
  fetchImpl: typeof fetch,
  rpcUrl: string,
  invokeTransaction: Record<string, unknown>
): Promise<string | undefined> {
  const rpc = await rpcRequestJson(fetchImpl, rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "starknet_addInvokeTransaction",
      params: { invoke_transaction: invokeTransaction }
    })
  });
  if ("error" in rpc && rpc.error) {
    throw new Error(`Starknet RPC rejected invoke: ${rpcErrorSummary(rpc.error)}`);
  }
  if (!("result" in rpc)) {
    throw new Error("Starknet RPC response did not include result");
  }
  return rpc.result.transaction_hash;
}

function isRetryableNonceError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /NonceTooOld|DuplicateNonce|Invalid transaction nonce|nonce.*too old|tx_nonce.*account_nonce/i.test(message);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function callPayloadToStarknetCall(call: ExecuteOutsideRequest["call"]): Call {
  return {
    contractAddress: call.contract_address,
    entrypoint: call.entrypoint,
    calldata: call.calldata
  };
}

async function estimateProofBearingInvokeResourceBounds(input: {
  account: AccountInstance;
  calls: Call[];
  config: Pick<PaymasterConfig, "rpcUrl" | "chainId" | "accountAddress">;
  runtime: StarknetRuntime;
  fetchImpl: typeof fetch;
  nonce: string;
  cairoVersion: string;
  proof?: string;
  proofFacts?: string[];
}): Promise<ResourceBoundsLike> {
  const zeroResourceBounds = {
    l1_gas: { max_amount: 0n, max_price_per_unit: 0n },
    l2_gas: { max_amount: 0n, max_price_per_unit: 0n },
    l1_data_gas: { max_amount: 0n, max_price_per_unit: 0n }
  };
  const invocation = await input.account.buildInvocation(input.calls, {
    resourceBounds: zeroResourceBounds,
    walletAddress: input.config.accountAddress,
    cairoVersion: input.cairoVersion,
    chainId: input.config.chainId,
    version: input.runtime.ETransactionVersion3.V3,
    nonce: input.nonce,
    tip: 0,
    paymasterData: [],
    accountDeploymentData: [],
    nonceDataAvailabilityMode: input.runtime.EDataAvailabilityMode.L1,
    feeDataAvailabilityMode: input.runtime.EDataAvailabilityMode.L1
  });
  const estimateTransaction = {
    type: "INVOKE",
    sender_address: toRpcFelt(invocation.contractAddress, "estimate.sender_address"),
    calldata: input.runtime.CallData.toHex(invocation.calldata),
    signature: [],
    nonce: toRpcFelt(invocation.nonce ?? input.nonce, "estimate.nonce"),
    resource_bounds: resourceBoundsToRpc(zeroResourceBounds),
    tip: "0x0",
    paymaster_data: [],
    account_deployment_data: [],
    nonce_data_availability_mode: input.runtime.EDataAvailabilityMode.L1,
    fee_data_availability_mode: input.runtime.EDataAvailabilityMode.L1,
    version: input.runtime.ETransactionVersion3.V3
  };
  if (input.proof && input.proofFacts) {
    Object.assign(estimateTransaction, {
      proof: input.proof,
      proof_facts: input.proofFacts
    });
  }

  const rpc = await rpcRequestJson(input.fetchImpl, input.config.rpcUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "starknet_estimateFee",
      params: {
        request: [estimateTransaction],
        block_id: "latest",
        simulation_flags: ["SKIP_VALIDATE"]
      }
    })
  });

  if ("error" in rpc && rpc.error) {
    throw new Error(`Starknet RPC rejected proof-bearing fee estimate: ${rpcErrorSummary(rpc.error)}`);
  }

  const estimateResult = "result" in rpc ? (rpc.result as unknown) : undefined;
  if (!Array.isArray(estimateResult) || !estimateResult[0]) {
    throw new Error("Starknet RPC fee estimate response did not include result");
  }

  const resourceBounds =
    (estimateResult[0] as { resource_bounds?: unknown; resourceBounds?: unknown }).resource_bounds ??
    (estimateResult[0] as { resource_bounds?: unknown; resourceBounds?: unknown }).resourceBounds ??
    estimateResult[0];
  try {
    return resourceBoundsFromRpc(resourceBounds);
  } catch (error) {
    throw new Error(
      `failed to parse proof-bearing fee estimate resource bounds: ${sanitizeErrorText(error instanceof Error ? error.message : String(error))}`
    );
  }
}

async function poolApplyActionsFee(
  fetchImpl: typeof fetch,
  rpcUrl: string,
  calls: Call[]
): Promise<bigint> {
  const poolCalls = calls.filter((call) => call.entrypoint === "apply_actions");
  if (poolCalls.length !== 1) return 0n;
  return starknetCallFelt(
    fetchImpl,
    rpcUrl,
    poolCalls[0]!.contractAddress,
    "get_fee_amount",
    []
  );
}

async function starknetCallFelt(
  fetchImpl: typeof fetch,
  rpcUrl: string,
  contractAddress: string,
  entrypoint: string,
  calldata: string[]
): Promise<bigint> {
  const rpc = await rpcRequestJson(fetchImpl, rpcUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "starknet_call",
      params: {
        request: {
          contract_address: toRpcFelt(contractAddress),
          entry_point_selector: toRpcFelt(selector.getSelectorFromName(entrypoint)),
          calldata: calldata.map((value) => toRpcFelt(value))
        },
        block_id: "latest"
      }
    })
  });
  if ("error" in rpc && rpc.error) {
    throw new Error(`Starknet RPC rejected ${entrypoint}: ${rpcErrorSummary(rpc.error)}`);
  }
  const result = "result" in rpc ? rpc.result : null;
  if (!Array.isArray(result) || result.length < 1) {
    throw new Error(`Starknet RPC ${entrypoint} response did not include felt result`);
  }
  return toBigIntFelt(result[0]);
}

function hasMeaningfulRpcErrorData(data: unknown): boolean {
  if (data === null || data === undefined) return false;
  if (typeof data === "string") return data.trim().length > 0;
  if (Array.isArray(data)) return data.length > 0;
  if (typeof data === "object") return Object.keys(data).length > 0;
  return true;
}

function rpcErrorSummary(error: unknown): string {
  if (!error || typeof error !== "object") {
    return sanitizeErrorText(String(error));
  }
  const record = error as Record<string, unknown>;
  const code = record.code;
  const message = record.message;
  const data = record.data;
  const parts: string[] = [];
  if (typeof code === "number" || typeof code === "string") {
    parts.push(`code=${sanitizeErrorText(String(code))}`);
  }
  if (typeof message === "string" && message.trim()) {
    parts.push(`message=${sanitizeErrorText(message)}`);
  }
  if (typeof data === "string" && data.trim()) {
    parts.push(`data=${sanitizeErrorText(data)}`);
  } else if (hasMeaningfulRpcErrorData(data)) {
    parts.push(`data=${sanitizeErrorText(JSON.stringify(data))}`);
  }
  return parts.length > 0 ? parts.join(" ") : "redacted_rpc_error";
}

function sanitizeErrorText(value: string): string {
  return value
    .replace(/0x[0-9a-fA-F]{33,}/g, "<felt>")
    .replace(/\b[0-9]{32,}\b/g, "<number>")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 400);
}

async function rpcRequestJson(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit
): Promise<RpcResponse> {
  const controller = new AbortController();
  let rejectTimeout: ((error: Error) => void) | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    rejectTimeout = reject;
  });
  const timeout = setTimeout(() => {
    const error = new Error("Starknet RPC request timed out");
    controller.abort(error);
    rejectTimeout?.(error);
  }, PAYMASTER_RPC_TIMEOUT_MS);
  try {
    const response = await Promise.race([
      fetchImpl(url, { ...init, signal: controller.signal }),
      timeoutPromise
    ]);
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error(`Starknet RPC returned HTTP ${response.status}`);
    }
    const contentLength = response.headers.get("content-length");
    if (
      contentLength &&
      Number.isSafeInteger(Number(contentLength)) &&
      Number(contentLength) > PAYMASTER_RPC_MAX_RESPONSE_BYTES
    ) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error("Starknet RPC response body is too large");
    }
    if (!response.body) {
      throw new Error("Starknet RPC response body is empty");
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
      while (true) {
        const next = await Promise.race([reader.read(), timeoutPromise]);
        if (next.done) break;
        totalBytes += next.value.byteLength;
        if (totalBytes > PAYMASTER_RPC_MAX_RESPONSE_BYTES) {
          throw new Error("Starknet RPC response body is too large");
        }
        chunks.push(next.value);
      }
    } finally {
      await reader.cancel().catch(() => undefined);
    }

    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      throw new Error("Starknet RPC returned invalid JSON");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Starknet RPC returned an invalid response object");
    }
    return parsed as RpcResponse;
  } catch (error) {
    if (isAbortLikeError(error)) {
      throw new Error("Starknet RPC request timed out");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function isAbortLikeError(error: unknown): boolean {
  const message =
    error instanceof Error ? error.message : typeof error === "string" ? error : "";
  return (
    (error instanceof Error && /abort|timed out|timeout/i.test(`${error.name} ${message}`)) ||
    /signal is aborted|aborted without reason|operation was aborted/i.test(message)
  );
}

function signatureToHexArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((nested) => toRpcFelt(nested, "signature"));
  }
  if (value && typeof value === "object") {
    const signature = value as { r?: unknown; s?: unknown };
    if (signature.r !== undefined && signature.s !== undefined) {
      return [toRpcFelt(signature.r, "signature.r"), toRpcFelt(signature.s, "signature.s")];
    }
  }
  throw new Error("unsupported account signature format");
}

function resourceBoundsToRpc(resourceBounds: unknown): unknown {
  return mapNested(resourceBounds, (value) => toRpcFelt(value, "resource_bounds"));
}

function resourceBoundsFromRpc(resourceBounds: unknown): ResourceBoundsLike {
  const raw = resourceBounds as Record<string, unknown>;
  if (!raw.l1_gas && !raw.l1Gas && !raw.l2_gas && !raw.l2Gas) {
    return feeEstimateToResourceBounds(raw);
  }
  return {
    l1_gas: resourceBoundFromRpc(raw.l1_gas ?? raw.l1Gas),
    l2_gas: resourceBoundFromRpc(raw.l2_gas ?? raw.l2Gas),
    l1_data_gas: resourceBoundFromRpc(raw.l1_data_gas ?? raw.l1DataGas)
  };
}

export function assertSponsoredFeeWithinLimit(
  resourceBounds: ResourceBoundsLike,
  maxSponsoredFeeFri: bigint
): void {
  const maximumFee = maximumSponsoredFee(resourceBounds);
  if (maximumFee > maxSponsoredFeeFri) {
    throw new Error("sponsored fee limit exceeded");
  }
}

export function maximumSponsoredFee(resourceBounds: ResourceBoundsLike): bigint {
  return [
    resourceBounds.l1_gas,
    resourceBounds.l2_gas,
    resourceBounds.l1_data_gas,
  ].reduce(
    (total, bound) => total + bound.max_amount * bound.max_price_per_unit,
    0n
  );
}

function resourceBoundFromRpc(value: unknown): ResourceBoundsLike["l1_gas"] {
  const raw = value as {
    max_amount?: unknown;
    maxAmount?: unknown;
    max_price_per_unit?: unknown;
    maxPricePerUnit?: unknown;
  };
  return {
    max_amount: toBigIntFelt(raw.max_amount ?? raw.maxAmount),
    max_price_per_unit: toBigIntFelt(raw.max_price_per_unit ?? raw.maxPricePerUnit)
  };
}

function feeEstimateToResourceBounds(estimate: Record<string, unknown>): ResourceBoundsLike {
  return {
    l1_gas: {
      max_amount: addPercent(toBigIntFelt(estimate.l1_gas_consumed), 50n),
      max_price_per_unit: addPercent(toBigIntFelt(estimate.l1_gas_price), 50n)
    },
    l2_gas: {
      max_amount: addPercent(toBigIntFelt(estimate.l2_gas_consumed), 50n),
      max_price_per_unit: addPercent(toBigIntFelt(estimate.l2_gas_price), 50n)
    },
    l1_data_gas: {
      max_amount: addPercent(
        toBigIntFelt(estimate.l1_data_gas_consumed ?? estimate.data_gas_consumed),
        50n
      ),
      max_price_per_unit: addPercent(
        toBigIntFelt(estimate.l1_data_gas_price ?? estimate.data_gas_price),
        50n
      )
    }
  };
}

function addPercent(value: bigint, percent: bigint): bigint {
  return value + (value * percent) / 100n;
}

function mapNested(value: unknown, mapper: (value: unknown) => string): unknown {
  if (
    typeof value === "bigint" ||
    typeof value === "number" ||
    (typeof value === "string" && (/^[0-9]+$/.test(value) || /^0x[0-9a-fA-F]+$/.test(value)))
  ) {
    return mapper(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => mapNested(item, mapper));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, mapNested(nested, mapper)])
    );
  }
  return value;
}

function toBigIntFelt(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`invalid numeric felt value: ${value}`);
    }
    return BigInt(value);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(trimmed) || /^[0-9]+$/.test(trimmed)) {
      return BigInt(trimmed);
    }
  }
  throw new Error(`invalid felt value: ${String(value)}`);
}

function toRpcFelt(value: unknown, label = "felt"): string {
  if (typeof value === "bigint") {
    return `0x${value.toString(16)}`;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`invalid numeric felt value: ${value}`);
    }
    return `0x${BigInt(value).toString(16)}`;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
      return `0x${BigInt(trimmed).toString(16)}`;
    }
    if (/^[0-9]+$/.test(trimmed)) {
      return `0x${BigInt(trimmed).toString(16)}`;
    }
  }
  throw new Error(`invalid ${label} value: ${String(value)}`);
}

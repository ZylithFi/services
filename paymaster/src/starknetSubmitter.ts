import {
  Account,
  CallData,
  EDataAvailabilityMode,
  ETransactionVersion3,
  RpcProvider,
  hash,
  outsideExecution
} from "starknet";
import type {
  Call,
  OutsideTransaction
} from "starknet";
import { selector } from "starknet";

import type { PaymasterConfig } from "./config.js";
import type {
  EnsurePrivacySignerRequest,
  EnsurePrivacySignerResponse,
  ExecuteOutsideRequest,
  ExecuteOutsideResponse,
  RelayPrivacySignerRequest,
  RpcResponse
} from "./types.js";

type AccountInstance = {
  getNonce(blockIdentifier?: string): Promise<string>;
  getCairoVersion(): Promise<string>;
  deploy(payload: {
    classHash: string;
    salt: string;
    unique: boolean;
    constructorCalldata: string[];
  }, details?: Record<string, unknown>): Promise<{
    transaction_hash?: string;
    transactionHash?: string;
    contract_address?: string | string[];
    contractAddress?: string | string[];
  }>;
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
  hash: Pick<typeof hash, "calculateContractAddressFromHash">;
  outsideExecution: Pick<typeof outsideExecution, "buildExecuteFromOutsideCall">;
};

const defaultRuntime: StarknetRuntime = {
  Account: Account as unknown as StarknetRuntime["Account"],
  RpcProvider: RpcProvider as unknown as StarknetRuntime["RpcProvider"],
  CallData,
  EDataAvailabilityMode,
  ETransactionVersion3,
  hash,
  outsideExecution
};

const PAYMASTER_SUBMISSION_RETRY_ATTEMPTS = 3;
const PAYMASTER_NONCE_RETRY_DELAY_MS = 1_500;
const PAYMASTER_DEPLOY_RETRY_ATTEMPTS = 5;

export type SubmitterDeps = {
  runtime?: StarknetRuntime;
  fetchImpl?: typeof fetch;
};

export async function ensurePrivacyProofSignerContract(
  request: EnsurePrivacySignerRequest,
  config: Pick<PaymasterConfig, "rpcUrl" | "accountAddress" | "privateKey">,
  deps: SubmitterDeps = {}
): Promise<EnsurePrivacySignerResponse> {
  const runtime = deps.runtime ?? defaultRuntime;
  const provider = new runtime.RpcProvider({ nodeUrl: config.rpcUrl });
  const classHash = toRpcFelt(request.class_hash, "class_hash");
  const salt = toRpcFelt(request.salt, "salt");
  const signerPublicKey = toRpcFelt(request.signer_public_key, "signer_public_key");
  const constructorCalldata = runtime.CallData.toHex([signerPublicKey]);
  const contractAddress = toRpcFelt(
    runtime.hash.calculateContractAddressFromHash(
      salt,
      classHash,
      constructorCalldata,
      0
    ),
    "contract_address"
  );

  const existingClassHash = await deployedClassHash(provider, contractAddress);
  if (existingClassHash) {
    return { contract_address: contractAddress, deployed: false };
  }

  const account = new runtime.Account({
    provider,
    address: config.accountAddress,
    signer: config.privateKey,
    transactionVersion: runtime.ETransactionVersion3.V3
  });
  const result = await deployWithNonceRetry(account, provider, contractAddress, {
    classHash,
    salt,
    unique: false,
    constructorCalldata: [signerPublicKey]
  });
  const transactionHash = result.transaction_hash ?? result.transactionHash;
  return {
    contract_address: contractAddress,
    deployed: true,
    ...(transactionHash ? { transaction_hash: transactionHash } : {})
  };
}

async function deployWithNonceRetry(
  account: AccountInstance,
  provider: RpcProviderInstance,
  contractAddress: string,
  payload: {
    classHash: string;
    salt: string;
    unique: boolean;
    constructorCalldata: string[];
  }
): ReturnType<AccountInstance["deploy"]> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < PAYMASTER_DEPLOY_RETRY_ATTEMPTS; attempt += 1) {
    const existingClassHash = await deployedClassHash(provider, contractAddress);
    if (existingClassHash) {
      return { contract_address: contractAddress };
    }
    try {
      const nonce = await account.getNonce("pre_confirmed")
        .catch(() => account.getNonce());
      return await account.deploy(payload, { nonce });
    } catch (error) {
      lastError = error;
      if (
        attempt < PAYMASTER_DEPLOY_RETRY_ATTEMPTS - 1 &&
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

export async function relayPrivacyProofSignerCall(
  request: RelayPrivacySignerRequest,
  config: Pick<PaymasterConfig, "rpcUrl" | "chainId" | "accountAddress" | "privateKey">,
  deps: SubmitterDeps = {}
): Promise<ExecuteOutsideResponse> {
  const calls = request.calls.map((call) => ({
    contractAddress: call.contract_address,
    entrypoint: call.entrypoint,
    calldata: call.calldata,
  }));
  const relayCall: Call = {
    contractAddress: request.account_address,
    entrypoint: "execute_from_relayer",
    calldata: [
      String(calls.length),
      ...calls.flatMap((call) => [
        call.contractAddress,
        selector.getSelectorFromName(call.entrypoint),
        String(call.calldata?.length ?? 0),
        ...(call.calldata ?? []),
      ]),
      request.nonce,
      request.signature_r,
      request.signature_s,
    ],
  };
  return submitPaymasterCalls([relayCall], config, deps);
}

export async function submitProofBearingOutsideExecution(
  request: ExecuteOutsideRequest,
  config: Pick<PaymasterConfig, "rpcUrl" | "chainId" | "accountAddress" | "privateKey">,
  deps: SubmitterDeps = {}
): Promise<ExecuteOutsideResponse> {
  const runtime = deps.runtime ?? defaultRuntime;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const calls = request.outside_transaction
    ? (runtime.outsideExecution.buildExecuteFromOutsideCall(
        request.outside_transaction as OutsideTransaction
      ) as Call[])
    : [callPayloadToStarknetCall(request.call)];
  return submitPaymasterCalls(calls, config, deps, request.proof, request.proof_facts);
}

async function submitPaymasterCalls(
  calls: Call[],
  config: Pick<PaymasterConfig, "rpcUrl" | "chainId" | "accountAddress" | "privateKey">,
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
  config: Pick<PaymasterConfig, "rpcUrl" | "chainId" | "accountAddress" | "privateKey">,
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

  const response = await fetchImpl(config.rpcUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "starknet_addInvokeTransaction",
      params: {
        invoke_transaction: invokeTransaction
      }
    })
  });

  if (!response.ok) {
    throw new Error(`Starknet RPC returned HTTP ${response.status}`);
  }

  const rpc = (await response.json()) as unknown as RpcResponse;
  if ("error" in rpc && rpc.error) {
    throw new Error(`Starknet RPC rejected proof-bearing invoke: ${JSON.stringify(rpc.error)}`);
  }

  if (!("result" in rpc)) {
    throw new Error("Starknet RPC response did not include result");
  }

  const transactionHash = rpc.result.transaction_hash;
  if (!transactionHash) {
    throw new Error("Starknet RPC response did not include transaction_hash");
  }

  return { transaction_hash: transactionHash };
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

  const response = await input.fetchImpl(input.config.rpcUrl, {
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

  if (!response.ok) {
    throw new Error(`Starknet RPC returned HTTP ${response.status}`);
  }

  const rpc = (await response.json()) as RpcResponse;
  if ("error" in rpc && rpc.error) {
    throw new Error(`Starknet RPC rejected proof-bearing fee estimate: ${JSON.stringify(rpc.error)}`);
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
    const snippet = JSON.stringify(resourceBounds).slice(0, 500);
    throw new Error(
      `failed to parse proof-bearing fee estimate resource bounds: ${error instanceof Error ? error.message : String(error)}; response=${snippet}`
    );
  }
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

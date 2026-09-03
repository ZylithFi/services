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
const PAYMASTER_RPC_TIMEOUT_MS = 30_000;
const PAYMASTER_RPC_MAX_RESPONSE_BYTES = 1_000_000;
const DEFAULT_PAYMASTER_L1_GAS_FLOOR = 0n;
const DEFAULT_PAYMASTER_L1_DATA_GAS_FLOOR = 8_000n;
const DEFAULT_PAYMASTER_L2_GAS_FLOOR = 180_000_000n;
const PAYMASTER_GAS_PRICE_MULTIPLIER = 2n;
const STARKNET_STRK_TOKEN_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

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
  config: Pick<PaymasterConfig, "rpcUrl" | "chainId" | "accountAddress" | "privateKey" | "privacySignerClassHash">,
  deps: SubmitterDeps = {}
): Promise<ExecuteOutsideResponse> {
  const runtime = deps.runtime ?? defaultRuntime;
  const provider = new runtime.RpcProvider({ nodeUrl: config.rpcUrl });
  const deployed = await deployedClassHash(provider, request.account_address);
  if (!deployed) {
    throw new Error("privacy proof signer account is not deployed");
  }
  if (toRpcFelt(deployed, "privacy signer class hash") !== config.privacySignerClassHash) {
    throw new Error("privacy proof signer account class is not allowlisted");
  }
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
  if (!request.proof || !request.proof_facts || request.proof_facts.length === 0) {
    throw new Error("proof and proof_facts are required for paymaster execution");
  }
  const runtime = deps.runtime ?? defaultRuntime;
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

  const rpc = await rpcRequestJson(fetchImpl, config.rpcUrl, {
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

  if ("error" in rpc && rpc.error) {
    throw new Error(`Starknet RPC rejected proof-bearing invoke: ${rpcErrorSummary(rpc.error)}`);
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
    if (
      input.proof &&
      input.proofFacts &&
      (await shouldFallbackProofBearingFeeEstimate(rpc.error, input))
    ) {
      return fallbackProofBearingResourceBounds(input.fetchImpl, input.config.rpcUrl);
    }
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

async function fallbackProofBearingResourceBounds(
  fetchImpl: typeof fetch,
  rpcUrl: string
): Promise<ResourceBoundsLike> {
  const rpc = await rpcRequestJson(fetchImpl, rpcUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "starknet_getBlockWithTxHashes",
      params: {
        block_id: "latest"
      }
    })
  });

  if ("error" in rpc && rpc.error) {
    throw new Error(`Starknet RPC rejected fallback gas-price query: ${rpcErrorSummary(rpc.error)}`);
  }
  if (!("result" in rpc)) {
    throw new Error("Starknet RPC fallback gas-price response did not include result");
  }

  return {
    l1_gas: {
      max_amount: DEFAULT_PAYMASTER_L1_GAS_FLOOR,
      max_price_per_unit: gasPriceBound(rpc.result, "l1_gas_price")
    },
    l2_gas: {
      max_amount: DEFAULT_PAYMASTER_L2_GAS_FLOOR,
      max_price_per_unit: gasPriceBound(rpc.result, "l2_gas_price")
    },
    l1_data_gas: {
      max_amount: DEFAULT_PAYMASTER_L1_DATA_GAS_FLOOR,
      max_price_per_unit: gasPriceBound(rpc.result, "l1_data_gas_price")
    }
  };
}

async function shouldFallbackProofBearingFeeEstimate(
  error: unknown,
  input: {
    calls: Call[];
    config: Pick<PaymasterConfig, "rpcUrl" | "accountAddress">;
    fetchImpl: typeof fetch;
  }
): Promise<boolean> {
  if (!error || typeof error !== "object") return false;
  const record = error as Record<string, unknown>;
  const code = String(record.code ?? "");
  const message = String(record.message ?? "");
  const data = record.data;
  if (hasMeaningfulRpcErrorData(data)) {
    return (
      isInsufficientErc20AllowanceEstimateError(data) &&
      (await transferFromActionsAreFunded(input.fetchImpl, input.config.rpcUrl, input.calls)) &&
      (await poolApplyActionsFeeIsFunded(
        input.fetchImpl,
        input.config.rpcUrl,
        input.calls,
        input.config.accountAddress
      ))
    );
  }
  if (code === "41" && /transaction execution error/i.test(message)) return true;
  return /PROOF_FACTS_MISSING|EMPTY_PROOF_FACTS/i.test(message);
}

function isInsufficientErc20AllowanceEstimateError(data: unknown): boolean {
  return /insufficient erc20 allowance/i.test(JSON.stringify(data));
}

type TransferFromAction = {
  from: string;
  token: string;
  amount: bigint;
  spender: string;
};

async function transferFromActionsAreFunded(
  fetchImpl: typeof fetch,
  rpcUrl: string,
  calls: Call[]
): Promise<boolean> {
  const actions = extractTransferFromActions(calls);
  if (!actions || actions.length === 0) {
    console.error(JSON.stringify({
      event: "paymaster_transfer_preflight_failed",
      reason: actions ? "no_transfer_from_actions" : "unparsed_apply_actions",
      call_count: calls.length,
      entrypoint: calls[0]?.entrypoint ?? null,
      calldata_count: Array.isArray(calls[0]?.calldata) ? calls[0].calldata.length : null
    }));
    return false;
  }
  const totals = new Map<string, TransferFromAction>();
  for (const action of actions) {
    const key = `${toRpcFelt(action.from)}:${toRpcFelt(action.token)}:${toRpcFelt(action.spender)}`;
    const existing = totals.get(key);
    if (existing) {
      existing.amount += action.amount;
    } else {
      totals.set(key, { ...action });
    }
  }
  for (const action of totals.values()) {
    const [balance, allowance] = await Promise.all([
      starknetCallU256(fetchImpl, rpcUrl, action.token, "balance_of", [
        action.from
      ]),
      starknetCallU256(fetchImpl, rpcUrl, action.token, "allowance", [
        action.from,
        action.spender
      ])
    ]);
    if (balance < action.amount || allowance < action.amount) {
      console.error(JSON.stringify({
        event: "paymaster_transfer_preflight_failed",
        reason: balance < action.amount ? "insufficient_balance" : "insufficient_allowance",
        from: shortFelt(action.from),
        token: shortFelt(action.token),
        spender: shortFelt(action.spender),
        amount: action.amount.toString(),
        balance: balance.toString(),
        allowance: allowance.toString()
      }));
      return false;
    }
  }
  return true;
}

async function poolApplyActionsFeeIsFunded(
  fetchImpl: typeof fetch,
  rpcUrl: string,
  calls: Call[],
  paymasterAddress: string
): Promise<boolean> {
  if (calls.length !== 1 || calls[0]?.entrypoint !== "apply_actions") return false;
  const poolAddress = calls[0].contractAddress;
  const feeAmount = await starknetCallFelt(fetchImpl, rpcUrl, poolAddress, "get_fee_amount", []);
  if (feeAmount === 0n) return true;
  const [balance, allowance] = await Promise.all([
    starknetCallU256(fetchImpl, rpcUrl, STARKNET_STRK_TOKEN_ADDRESS, "balance_of", [
      paymasterAddress
    ]),
    starknetCallU256(fetchImpl, rpcUrl, STARKNET_STRK_TOKEN_ADDRESS, "allowance", [
      paymasterAddress,
      poolAddress
    ])
  ]);
  if (balance < feeAmount || allowance < feeAmount) {
    console.error(JSON.stringify({
      event: "paymaster_transfer_preflight_failed",
      reason: balance < feeAmount ? "insufficient_pool_fee_balance" : "insufficient_pool_fee_allowance",
      owner: shortFelt(paymasterAddress),
      token: shortFelt(STARKNET_STRK_TOKEN_ADDRESS),
      spender: shortFelt(poolAddress),
      amount: feeAmount.toString(),
      balance: balance.toString(),
      allowance: allowance.toString()
    }));
    return false;
  }
  return true;
}

function shortFelt(value: string): string {
  const felt = toRpcFelt(value);
  return felt.length <= 18 ? felt : `${felt.slice(0, 10)}...${felt.slice(-6)}`;
}

function extractTransferFromActions(calls: Call[]): TransferFromAction[] | null {
  if (calls.length !== 1) return null;
  const call = calls[0];
  if (!call) return null;
  if (call.entrypoint !== "apply_actions") return null;
  if (!Array.isArray(call.calldata)) return null;
  const calldata = call.calldata.map((value: unknown) => toRpcFelt(value));
  if (calldata.length === 0) return null;
  const count = Number(toBigIntFelt(calldata[0]));
  if (!Number.isSafeInteger(count) || count < 0) return null;
  const actions: TransferFromAction[] = [];
  let offset = 1;
  for (let index = 0; index < count; index += 1) {
    if (offset >= calldata.length) return null;
    const variant = Number(toBigIntFelt(calldata[offset]));
    if (!Number.isSafeInteger(variant) || variant < 0) return null;
    if (variant === 0) {
      if (offset + 2 >= calldata.length) return null;
      const spanLength = Number(toBigIntFelt(calldata[offset + 2]));
      if (!Number.isSafeInteger(spanLength) || spanLength < 0) return null;
      offset += 3 + spanLength;
      continue;
    }
    if (variant === 1 || variant === 6) {
      offset += variant === 1 ? 5 : 4;
      continue;
    }
    if (variant === 2 || variant === 3) {
      if (offset + 3 >= calldata.length) return null;
      if (variant === 2) {
        const from = calldata[offset + 1];
        const token = calldata[offset + 2];
        const amount = calldata[offset + 3];
        if (!from || !token || !amount) return null;
        actions.push({
          from,
          token,
          amount: toBigIntFelt(amount),
          spender: call.contractAddress
        });
      }
      offset += 4;
      continue;
    }
    if (variant === 4) {
      offset += 6;
      continue;
    }
    if (variant === 5 || variant === 7) {
      offset += variant === 5 ? 7 : 6;
      continue;
    }
    if (variant === 8 || variant === 9) {
      offset += variant === 8 ? 3 : 2;
      continue;
    }
    if (variant === 10 || variant === 11) {
      if (offset + 2 >= calldata.length) return null;
      const spanLength = Number(toBigIntFelt(calldata[offset + 2]));
      if (!Number.isSafeInteger(spanLength) || spanLength < 0) return null;
      offset += 3 + spanLength;
      continue;
    }
    return null;
  }
  return hasValidScreeningSuffix(calldata, offset) ? actions : null;
}

function hasValidScreeningSuffix(calldata: string[], offset: number): boolean {
  if (offset === calldata.length) return true;
  if (offset >= calldata.length) return false;
  const variant = Number(toBigIntFelt(calldata[offset]));
  if (!Number.isSafeInteger(variant) || variant < 0) return false;
  if (variant === 1) return offset + 1 === calldata.length;
  if (variant === 0) return offset + 4 === calldata.length;
  return false;
}

async function starknetCallU256(
  fetchImpl: typeof fetch,
  rpcUrl: string,
  contractAddress: string,
  entrypoint: "allowance" | "balance_of",
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
  if (!Array.isArray(result) || result.length < 2) {
    throw new Error(`Starknet RPC ${entrypoint} response did not include u256 result`);
  }
  return toBigIntFelt(result[0]) + (toBigIntFelt(result[1]) << 128n);
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

function gasPriceBound(block: unknown, field: string): bigint {
  if (!block || typeof block !== "object") {
    throw new Error("Starknet RPC fallback gas-price result is invalid");
  }
  const raw = (block as Record<string, unknown>)[field];
  if (!raw || typeof raw !== "object") {
    throw new Error(`Starknet RPC fallback gas-price result is missing ${field}`);
  }
  const record = raw as Record<string, unknown>;
  const price = toBigIntFelt(record.price_in_fri ?? record.priceInFri);
  return price > 0n ? price * PAYMASTER_GAS_PRICE_MULTIPLIER : 1n;
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

import { selector } from "starknet";

import type { PaymasterConfig } from "./config.js";
import { normalizeFelt } from "./config.js";
import type {
  EnsurePrivacySignerRequest,
  ExecuteOutsideRequest,
  RelayPrivacySignerRequest,
  StarknetCallPayload
} from "./types.js";

const MAX_OUTSIDE_EXECUTION_WINDOW_SECONDS = 3_900;
const RENEWAL_SPARSE_TREE_DEPTH = 128;
const U128_MAX = (1n << 128n) - 1n;

export function validateExecuteOutsideRequest(
  value: unknown,
  config: Pick<
    PaymasterConfig,
    | "accountAddress"
    | "allowedContracts"
    | "allowedEntrypoints"
    | "chainId"
    | "proofRequiredEntrypoints"
    | "withdrawalAmountBuckets"
    | "allowDirectWithdrawalRelays"
  >,
  nowUnixSeconds = Math.floor(Date.now() / 1000)
): ExecuteOutsideRequest {
  const request = expectRecord(value, "request") as Partial<ExecuteOutsideRequest>;
  const call = validateCall(request.call);

  const chainId = normalizeFelt(expectString(request.chain_id, "chain_id"));
  const signerAddress = normalizeFelt(expectString(request.signer_address, "signer_address"));
  const paymasterAddress = normalizeFelt(
    expectString(request.paymaster_address, "paymaster_address")
  );
  const proof = optionalString(request.proof, "proof")?.trim();
  const proofFacts = optionalStringArray(request.proof_facts, "proof_facts")?.map(normalizeFelt);

  if (chainId !== config.chainId) {
    throw new Error("chain_id does not match paymaster configuration");
  }
  if (paymasterAddress !== config.accountAddress) {
    throw new Error("paymaster_address does not match paymaster configuration");
  }
  if (!config.allowedContracts.has(call.contract_address)) {
    throw new Error("call contract is not allowlisted");
  }
  if (!config.allowedEntrypoints.has(call.entrypoint)) {
    throw new Error("call entrypoint is not allowlisted");
  }
  if (isPausedWithdrawalEntrypoint(call.entrypoint)) {
    throw new Error("withdrawals are paused until nullifier-consuming exits are available");
  }
  if (config.proofRequiredEntrypoints.has(call.entrypoint)) {
    if (!proof) {
      throw new Error("proof cannot be empty for proof-required entrypoint");
    }
    if (!proofFacts || proofFacts.length === 0) {
      throw new Error("proof_facts cannot be empty for proof-required entrypoint");
    }
  }
  if (!proof && proofFacts && proofFacts.length > 0) {
    throw new Error("proof_facts require proof");
  }
  assertWithdrawalAmountBucket(call, config.withdrawalAmountBuckets);

  const outsideTransaction = request.outside_transaction
    ? (expectRecord(request.outside_transaction, "outside_transaction") as unknown as ExecuteOutsideRequest["outside_transaction"])
    : undefined;

  if (outsideTransaction) {
    validateOutsideTransaction(outsideTransaction, signerAddress, config.accountAddress, call, nowUnixSeconds);
  } else {
    validateDirectRelayedCall(
      call,
      Boolean(proof && proofFacts && proofFacts.length > 0),
      config.allowDirectWithdrawalRelays,
    );
    if (request.relay_nonce !== undefined) {
      normalizeFeltValue(request.relay_nonce, "relay_nonce");
    }
  }

  const validated: ExecuteOutsideRequest = {
    chain_id: chainId,
    signer_address: signerAddress,
    paymaster_address: paymasterAddress,
    call,
  };
  if (outsideTransaction) validated.outside_transaction = outsideTransaction;
  if (request.relay_nonce !== undefined) validated.relay_nonce = normalizeFelt(String(request.relay_nonce));
  if (proof) {
    validated.proof = proof;
  }
  if (proofFacts) {
    validated.proof_facts = proofFacts;
  }
  return validated;
}

function validateOutsideTransaction(
  outsideTransaction: NonNullable<ExecuteOutsideRequest["outside_transaction"]>,
  signerAddress: string,
  paymasterAddress: string,
  call: StarknetCallPayload,
  nowUnixSeconds: number
): void {
  const outsideExecution = expectRecord(
    outsideTransaction.outsideExecution,
    "outside_transaction.outsideExecution"
  );
  const caller = normalizeFelt(expectString(outsideExecution.caller, "outsideExecution.caller"));
  normalizeFeltValue(outsideExecution.nonce, "outsideExecution.nonce");
  const executeAfter = expectUnixSeconds(
    outsideExecution.execute_after,
    "outsideExecution.execute_after"
  );
  const executeBefore = expectUnixSeconds(
    outsideExecution.execute_before,
    "outsideExecution.execute_before"
  );
  const outsideSigner = normalizeFelt(String(outsideTransaction.signerAddress ?? ""));
  const version = String(outsideTransaction.version ?? "");
  expectSignature(outsideTransaction.signature, "outside_transaction.signature");

  if (caller !== paymasterAddress) {
    throw new Error("outside execution caller must be this paymaster account");
  }
  if (outsideSigner !== signerAddress) {
    throw new Error("signer_address does not match outside transaction signer");
  }
  if (version !== "2") {
    throw new Error("only SNIP-9 outside execution V2 is supported");
  }
  if (executeBefore <= executeAfter) {
    throw new Error("outside execution time window is invalid");
  }
  if (executeBefore - executeAfter > MAX_OUTSIDE_EXECUTION_WINDOW_SECONDS) {
    throw new Error("outside execution time window is too long");
  }
  if (executeBefore <= nowUnixSeconds) {
    throw new Error("outside execution is expired");
  }
  if (executeAfter > nowUnixSeconds + 60) {
    throw new Error("outside execution is not active yet");
  }
  assertOutsideCallMatchesPayload(call, outsideExecution);
}

export function validateEnsurePrivacySignerRequest(
  value: unknown,
  config: Pick<PaymasterConfig, "privacySignerClassHash">
): EnsurePrivacySignerRequest {
  if (!config.privacySignerClassHash) {
    throw new Error("privacy proof signer deployment is not configured");
  }
  const request = expectRecord(value, "request") as Partial<EnsurePrivacySignerRequest>;
  const signerPublicKey = normalizeFelt(expectString(request.signer_public_key, "signer_public_key"));
  const salt = normalizeFelt(expectString(request.salt, "salt"));
  const classHash = request.class_hash === undefined
    ? config.privacySignerClassHash
    : normalizeFelt(expectString(request.class_hash, "class_hash"));
  if (classHash !== config.privacySignerClassHash) {
    throw new Error("privacy proof signer class_hash is not allowlisted");
  }
  if (signerPublicKey === "0x0") {
    throw new Error("signer_public_key cannot be zero");
  }
  return {
    signer_public_key: signerPublicKey,
    salt,
    class_hash: classHash,
  };
}

export function validateRelayPrivacySignerRequest(
  value: unknown,
  config: Pick<PaymasterConfig, "allowedContracts">
): RelayPrivacySignerRequest {
  const request = expectRecord(value, "request") as Partial<RelayPrivacySignerRequest>;
  const accountAddress = normalizeFelt(expectString(request.account_address, "account_address"));
  const callsValue = request.calls;
  if (!Array.isArray(callsValue) || callsValue.length !== 1) {
    throw new Error("privacy signer relay requires exactly one call");
  }
  const calls = callsValue.map(validateCall);
  const call = calls[0];
  if (!call) {
    throw new Error("privacy signer relay requires exactly one call");
  }
  if (call.entrypoint !== "approve") {
    throw new Error("privacy signer relay only supports token approve");
  }
  if (call.calldata.length !== 3) {
    throw new Error("token approve calldata is invalid");
  }
  const spender = call.calldata[0];
  if (!spender) {
    throw new Error("token approve calldata is invalid");
  }
  if (!config.allowedContracts.has(call.contract_address)) {
    throw new Error("token approve contract is not allowlisted");
  }
  if (!config.allowedContracts.has(spender)) {
    throw new Error("token approve spender is not allowlisted");
  }
  return {
    account_address: accountAddress,
    calls,
    nonce: normalizeFelt(expectString(request.nonce, "nonce")),
    signature_r: normalizeFelt(expectString(request.signature_r, "signature_r")),
    signature_s: normalizeFelt(expectString(request.signature_s, "signature_s")),
  };
}

function validateDirectRelayedCall(
  call: StarknetCallPayload,
  hasProof: boolean,
  allowDirectWithdrawalRelays: boolean,
): void {
  if (call.entrypoint === "apply_actions" && hasProof) {
    return;
  }
  if (call.entrypoint === "withdraw_settlement_output_with_proof_facts" && hasProof) {
    if (!allowDirectWithdrawalRelays) {
      throw new Error("direct withdrawal relay sponsorship is disabled");
    }
    return;
  }
  if (call.entrypoint === "cancel_renewal_parent_marker") {
    assertRenewalCancelMarkerCalldata(call);
    return;
  }
  if (!isPausedWithdrawalEntrypoint(call.entrypoint)) {
    throw new Error("direct paymaster relay is only allowed for withdrawals");
  }
  if (!allowDirectWithdrawalRelays) {
    throw new Error("direct withdrawal relay sponsorship is disabled");
  }
}

function assertRenewalCancelMarkerCalldata(call: StarknetCallPayload): void {
  const calldata = call.calldata;
  if (calldata.length < 8) {
    throw new Error("renewal cancellation calldata is invalid");
  }

  const cancelMarker = feltToBigInt(calldata[0], "cancel marker");
  const cancelAuthority = feltToBigInt(calldata[1], "cancel authority");
  const sparseKeyLow = feltToBigInt(calldata[2], "renewal sparse key low");
  const sparseKeyHigh = feltToBigInt(calldata[3], "renewal sparse key high");
  if (cancelMarker === 0n) {
    throw new Error("renewal cancellation marker cannot be zero");
  }
  if (cancelAuthority === 0n) {
    throw new Error("renewal cancellation authority cannot be zero");
  }
  if (sparseKeyLow > U128_MAX || sparseKeyHigh > U128_MAX) {
    throw new Error("renewal cancellation sparse key is out of range");
  }

  const pathCount = Number(feltToBigInt(calldata[4], "renewal merkle path length"));
  if (!Number.isSafeInteger(pathCount) || pathCount < 0) {
    throw new Error("renewal cancellation merkle path length is invalid");
  }
  if (pathCount !== 0 && pathCount !== RENEWAL_SPARSE_TREE_DEPTH) {
    throw new Error("renewal cancellation merkle path length is invalid");
  }

  const directionsLenIndex = 5 + pathCount;
  if (directionsLenIndex >= calldata.length) {
    throw new Error("renewal cancellation calldata is invalid");
  }
  const directionsCount = Number(
    feltToBigInt(calldata[directionsLenIndex], "renewal merkle directions length")
  );
  if (directionsCount !== pathCount) {
    throw new Error("renewal cancellation merkle path and direction lengths differ");
  }

  const expectedLength = 4 + 1 + pathCount + 1 + directionsCount + 2;
  if (calldata.length !== expectedLength) {
    throw new Error("renewal cancellation calldata is invalid");
  }

  const directionsStart = directionsLenIndex + 1;
  for (let index = 0; index < directionsCount; index += 1) {
    const bit = feltToBigInt(calldata[directionsStart + index], "renewal merkle direction");
    if (bit !== 0n && bit !== 1n) {
      throw new Error("renewal cancellation merkle direction is invalid");
    }
  }

  const signatureR = feltToBigInt(calldata[calldata.length - 2], "renewal cancellation signature r");
  const signatureS = feltToBigInt(calldata[calldata.length - 1], "renewal cancellation signature s");
  if (signatureR === 0n || signatureS === 0n) {
    throw new Error("renewal cancellation signature cannot be zero");
  }
}

function isPausedWithdrawalEntrypoint(entrypoint: string): boolean {
  return (
    entrypoint === "withdraw_settlement_output_to_l2" ||
    entrypoint === "withdraw_to_l2"
  );
}

function validateCall(value: unknown): StarknetCallPayload {
  const call = expectRecord(value, "call") as Partial<StarknetCallPayload>;
  const contractAddress = normalizeFelt(
    expectString(call.contract_address, "call.contract_address")
  );
  const entrypoint = expectString(call.entrypoint, "call.entrypoint").trim();
  const calldata = expectStringArray(call.calldata, "call.calldata").map(normalizeFelt);

  if (!entrypoint) {
    throw new Error("call.entrypoint cannot be empty");
  }

  return {
    contract_address: contractAddress,
    entrypoint,
    calldata
  };
}

function assertOutsideCallMatchesPayload(
  call: StarknetCallPayload,
  outsideExecution: Record<string, unknown>
): void {
  const calls = outsideExecution.calls;
  if (!Array.isArray(calls) || calls.length !== 1) {
    throw new Error("outside execution must contain exactly one inner call");
  }

  const outsideCall = expectRecord(calls[0], "outsideExecution.calls[0]");
  const outsideTo = normalizeFelt(expectString(outsideCall.to, "outside call to"));
  const outsideSelector = normalizeFelt(expectString(outsideCall.selector, "outside call selector"));
  const expectedSelector = normalizeFelt(String(selector.getSelectorFromName(call.entrypoint)));
  const outsideCalldata = expectStringArray(outsideCall.calldata, "outside call calldata").map(
    normalizeFelt
  );

  if (outsideTo !== call.contract_address) {
    throw new Error("outside execution target does not match payload call");
  }
  if (outsideSelector !== expectedSelector) {
    throw new Error("outside execution selector does not match payload call");
  }
  if (!sameArray(outsideCalldata, call.calldata)) {
    throw new Error("outside execution calldata does not match payload call");
  }
}

function expectRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function expectString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return expectString(value, label);
}

function expectUnixSeconds(value: unknown, label: string): number {
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^[0-9]+$/.test(value)
        ? Number(value)
        : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative integer timestamp`);
  }
  return parsed;
}

function expectStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string")) {
    throw new Error(`${label} must be a non-empty string array`);
  }
  return value as string[];
}

function optionalStringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return expectStringArray(value, label);
}

function assertWithdrawalAmountBucket(
  call: StarknetCallPayload,
  withdrawalAmountBuckets: Set<string>
): void {
  if (withdrawalAmountBuckets.size === 0) {
    return;
  }
  const amount = withdrawalAmountForEntrypoint(call);
  if (amount === null) {
    return;
  }
  if (!withdrawalAmountBuckets.has(amount.toString())) {
    throw new Error("withdrawal amount is not in an allowed privacy bucket");
  }
}

function withdrawalAmountForEntrypoint(call: StarknetCallPayload): bigint | null {
  if (call.entrypoint === "withdraw_settlement_output_with_proof_facts") {
    const amount = call.calldata[7];
    return amount === undefined ? null : BigInt(amount);
  }
  if (call.entrypoint === "withdraw_settlement_output_to_l2") {
    const amount = call.calldata[3];
    return amount === undefined ? null : BigInt(amount);
  }
  if (call.entrypoint === "withdraw_verified_note") {
    const amount = call.calldata[1];
    return amount === undefined ? null : BigInt(amount);
  }
  return null;
}

function expectSignature(value: unknown, label: string): void {
  if (Array.isArray(value)) {
    expectStringArray(value, label);
    return;
  }

  if (value && typeof value === "object") {
    const signature = value as { r?: unknown; s?: unknown };
    normalizeFeltValue(signature.r, `${label}.r`);
    normalizeFeltValue(signature.s, `${label}.s`);
    return;
  }

  throw new Error(`${label} must be a non-empty string array or an object with r and s`);
}

function normalizeFeltValue(value: unknown, label: string): string {
  if (typeof value === "string") {
    return normalizeFelt(value);
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return normalizeFelt(String(value));
  }
  throw new Error(`${label} must be a felt string or non-negative integer`);
}

function feltToBigInt(value: string | undefined, label: string): bigint {
  if (value === undefined) {
    throw new Error(`${label} must be a felt value`);
  }
  try {
    return BigInt(value);
  } catch {
    throw new Error(`${label} must be a felt value`);
  }
}

function sameArray(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

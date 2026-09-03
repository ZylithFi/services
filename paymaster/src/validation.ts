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
const SUPPORTED_EXECUTE_OUTSIDE_ENTRYPOINTS = new Set([
  "apply_actions",
  "submit_settlement_with_proof_facts",
]);
const EXECUTE_OUTSIDE_REQUEST_KEYS = new Set([
  "chain_id",
  "signer_address",
  "paymaster_address",
  "call",
  "outside_transaction",
  "relay_nonce",
  "proof",
  "proof_facts",
]);
const ENSURE_PRIVACY_SIGNER_REQUEST_KEYS = new Set([
  "signer_public_key",
  "salt",
  "class_hash",
]);
const RELAY_PRIVACY_SIGNER_REQUEST_KEYS = new Set([
  "account_address",
  "calls",
  "nonce",
  "signature_r",
  "signature_s",
]);
const CALL_KEYS = new Set(["contract_address", "entrypoint", "calldata"]);
const OUTSIDE_TRANSACTION_KEYS = new Set([
  "outsideExecution",
  "signerAddress",
  "version",
  "signature",
]);
const OUTSIDE_EXECUTION_KEYS = new Set([
  "caller",
  "nonce",
  "execute_after",
  "execute_before",
  "calls",
]);
const OUTSIDE_CALL_KEYS = new Set(["to", "selector", "calldata"]);
const SIGNATURE_OBJECT_KEYS = new Set(["r", "s"]);

export function validateExecuteOutsideRequest(
  value: unknown,
  config: Pick<
    PaymasterConfig,
    | "accountAddress"
    | "allowedContracts"
    | "allowedEntrypoints"
    | "chainId"
    | "proofRequiredEntrypoints"
  >,
  nowUnixSeconds = Math.floor(Date.now() / 1000)
): ExecuteOutsideRequest {
  const request = expectRecord(value, "request") as Partial<ExecuteOutsideRequest>;
  assertAllowedKeys(request, EXECUTE_OUTSIDE_REQUEST_KEYS, "request");
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
  if (!SUPPORTED_EXECUTE_OUTSIDE_ENTRYPOINTS.has(call.entrypoint)) {
    throw new Error("call entrypoint is not supported by paymaster");
  }
  if (
    SUPPORTED_EXECUTE_OUTSIDE_ENTRYPOINTS.has(call.entrypoint) &&
    !config.proofRequiredEntrypoints.has(call.entrypoint)
  ) {
    throw new Error("supported paymaster entrypoint must be proof-required");
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
  const outsideTransaction = request.outside_transaction
    ? (expectRecord(request.outside_transaction, "outside_transaction") as unknown as ExecuteOutsideRequest["outside_transaction"])
    : undefined;

  if (outsideTransaction) {
    validateOutsideTransaction(outsideTransaction, signerAddress, config.accountAddress, call, nowUnixSeconds);
  } else {
    validateDirectRelayedCall(call, Boolean(proof && proofFacts && proofFacts.length > 0));
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
  assertAllowedKeys(
    outsideTransaction as unknown as Record<string, unknown>,
    OUTSIDE_TRANSACTION_KEYS,
    "outside_transaction"
  );
  assertAllowedKeys(
    outsideExecution,
    OUTSIDE_EXECUTION_KEYS,
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
  const request = expectRecord(value, "request") as Partial<EnsurePrivacySignerRequest>;
  assertAllowedKeys(request, ENSURE_PRIVACY_SIGNER_REQUEST_KEYS, "request");
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
  config: Pick<PaymasterConfig, "allowedContracts" | "approvalSpenders">
): RelayPrivacySignerRequest {
  const request = expectRecord(value, "request") as Partial<RelayPrivacySignerRequest>;
  assertAllowedKeys(request, RELAY_PRIVACY_SIGNER_REQUEST_KEYS, "request");
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
  if (!config.approvalSpenders.has(spender)) {
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
): void {
  if (call.entrypoint === "apply_actions" && hasProof) {
    return;
  }
  throw new Error("direct paymaster relay requires proof facts for supported direct calls");
}

function validateCall(value: unknown): StarknetCallPayload {
  const call = expectRecord(value, "call") as Partial<StarknetCallPayload>;
  assertAllowedKeys(call, CALL_KEYS, "call");
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
  assertAllowedKeys(outsideCall, OUTSIDE_CALL_KEYS, "outsideExecution.calls[0]");
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

function assertAllowedKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  label: string
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(`${label}.${key} is not supported`);
    }
  }
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


function expectSignature(value: unknown, label: string): void {
  if (Array.isArray(value)) {
    expectStringArray(value, label);
    return;
  }

  if (value && typeof value === "object") {
    const signature = value as Record<string, unknown> & { r?: unknown; s?: unknown };
    assertAllowedKeys(signature, SIGNATURE_OBJECT_KEYS, label);
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


function sameArray(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

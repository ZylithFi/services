import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash } from "node:crypto";

import { normalizeFelt } from "./config.js";
import type { ExecuteOutsideRequest, ExecuteOutsideResponse } from "./types.js";

export type SubmissionRecord = {
  key: string;
  signer_address: string;
  outside_nonce: string;
  transaction_hash: string;
  submitted_at_unix_ms: number;
};

export class SubmissionStore {
  private loaded = false;
  private readonly records = new Map<string, SubmissionRecord>();
  private readonly inFlight = new Map<string, Promise<ExecuteOutsideResponse>>();

  constructor(private readonly path: string | null) {}

  async runOnce(
    request: ExecuteOutsideRequest,
    submit: () => Promise<ExecuteOutsideResponse>
  ): Promise<ExecuteOutsideResponse> {
    await this.load();

    const key = submissionKey(request);
    const existing = this.records.get(key);
    if (existing) {
      return { transaction_hash: existing.transaction_hash };
    }

    const inFlight = this.inFlight.get(key);
    if (inFlight) {
      return inFlight;
    }

    const promise = this.submitAndRecord(key, request, submit);
    this.inFlight.set(key, promise);
    try {
      return await promise;
    } finally {
      this.inFlight.delete(key);
    }
  }

  async get(request: ExecuteOutsideRequest): Promise<SubmissionRecord | undefined> {
    await this.load();
    return this.records.get(submissionKey(request));
  }

  private async submitAndRecord(
    key: string,
    request: ExecuteOutsideRequest,
    submit: () => Promise<ExecuteOutsideResponse>
  ): Promise<ExecuteOutsideResponse> {
    const result = await submit();
    const record: SubmissionRecord = {
      key,
      signer_address: request.signer_address,
      outside_nonce: submissionNonce(request),
      transaction_hash: result.transaction_hash,
      submitted_at_unix_ms: Date.now()
    };
    this.records.set(key, record);
    await this.persistBestEffort();
    return result;
  }

  private async load(): Promise<void> {
    if (this.loaded) {
      return;
    }
    this.loaded = true;
    if (!this.path) {
      return;
    }

    let body: string;
    try {
      body = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return;
      }
      throw error;
    }

    const records = JSON.parse(body) as SubmissionRecord[];
    if (!Array.isArray(records)) {
      throw new Error("submission log must contain an array");
    }
    for (const record of records) {
      if (
        record &&
        typeof record.key === "string" &&
        typeof record.transaction_hash === "string"
      ) {
        this.records.set(record.key, record);
      }
    }
  }

  private async persistBestEffort(): Promise<void> {
    if (!this.path) {
      return;
    }

    try {
      await mkdir(dirname(this.path), { recursive: true });
      const tempPath = `${this.path}.tmp`;
      await writeFile(tempPath, `${JSON.stringify([...this.records.values()], null, 2)}\n`);
      await rename(tempPath, this.path);
    } catch (error) {
      console.error("failed to persist paymaster submission log", error);
    }
  }
}

export function submissionKey(request: ExecuteOutsideRequest): string {
  if (request.outside_transaction) {
    const signerAddress = normalizeFelt(request.signer_address);
    const nonce = submissionNonce(request);
    return `${signerAddress}:${nonce}`;
  }
  return submissionNonce(request);
}

function submissionNonce(request: ExecuteOutsideRequest): string {
  if (request.outside_transaction) {
    return normalizeFelt(String(request.outside_transaction.outsideExecution.nonce));
  }
  return `direct:${createHash("sha256")
    .update(JSON.stringify({
      chain_id: normalizeFelt(request.chain_id),
      paymaster_address: normalizeFelt(request.paymaster_address),
      call: request.call,
      proof: request.proof ?? null,
      proof_facts: request.proof_facts ?? null
    }))
    .digest("hex")}`;
}

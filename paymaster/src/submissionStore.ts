import { mkdir, open, readFile, rename, stat, unlink } from "node:fs/promises";
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

let tempFileCounter = 0;
const MAX_SUBMISSION_LOG_BYTES = 64 * 1024 * 1024;
const MAX_SUBMISSION_RECORDS = 100_000;
const SUBMISSION_RECORD_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
const SUBMISSION_PRUNE_INTERVAL_MS = 60_000;
const SUBMISSION_RECORD_KEYS = new Set([
  "key",
  "signer_address",
  "outside_nonce",
  "transaction_hash",
  "submitted_at_unix_ms"
]);

export class SubmissionStore {
  private loaded = false;
  private loadPromise: Promise<void> | null = null;
  private persistTail: Promise<void> = Promise.resolve();
  private readonly records = new Map<string, SubmissionRecord>();
  private readonly inFlight = new Map<string, Promise<ExecuteOutsideResponse>>();
  private lastPrunedAtUnixMs = 0;

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
    this.pruneRecords(record.submitted_at_unix_ms);
    await this.persistBestEffort();
    return result;
  }

  private async load(): Promise<void> {
    if (this.loaded) {
      return;
    }
    if (this.loadPromise) {
      return this.loadPromise;
    }
    this.loadPromise = this.loadFromDisk();
    try {
      await this.loadPromise;
      this.loaded = true;
    } finally {
      this.loadPromise = null;
    }
  }

  private async loadFromDisk(): Promise<void> {
    if (!this.path) {
      return;
    }

    let body: string;
    try {
      const metadata = await stat(this.path);
      if (metadata.size > MAX_SUBMISSION_LOG_BYTES) {
        throw new Error("submission log is too large");
      }
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
    const loadedRecords = new Map<string, SubmissionRecord>();
    for (const record of records) {
      validateSubmissionRecord(record);
      if (loadedRecords.has(record.key)) {
        throw new Error(`submission log contains duplicate key ${record.key}`);
      }
      loadedRecords.set(record.key, record);
    }
    this.records.clear();
    for (const [key, record] of loadedRecords) {
      this.records.set(key, record);
    }
    this.pruneRecords(Date.now(), true);
  }

  private async persistBestEffort(): Promise<void> {
    const run = this.persistTail
      .catch(() => undefined)
      .then(() => this.persistSnapshotBestEffort());
    this.persistTail = run;
    return run;
  }

  private async persistSnapshotBestEffort(): Promise<void> {
    if (!this.path) {
      return;
    }

    try {
      await mkdir(dirname(this.path), { recursive: true });
      const tempPath = `${this.path}.${process.pid}.${tempFileCounter++}.tmp`;
      const handle = await open(tempPath, "wx");
      try {
        await handle.writeFile(`${JSON.stringify([...this.records.values()], null, 2)}\n`);
        await handle.sync();
      } finally {
        await handle.close();
      }
      try {
        await rename(tempPath, this.path);
      } catch (error) {
        await unlink(tempPath).catch(() => undefined);
        throw error;
      }
      const directory = await open(dirname(this.path), "r");
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
    } catch (error) {
      console.error("failed to persist paymaster submission log", error);
    }
  }

  private pruneRecords(nowUnixMs: number, force = false): void {
    if (
      !force &&
      this.records.size <= MAX_SUBMISSION_RECORDS &&
      nowUnixMs - this.lastPrunedAtUnixMs < SUBMISSION_PRUNE_INTERVAL_MS
    ) {
      return;
    }
    const oldestAllowed = Math.max(0, nowUnixMs - SUBMISSION_RECORD_RETENTION_MS);
    for (const [key, record] of this.records) {
      if (record.submitted_at_unix_ms < oldestAllowed) {
        this.records.delete(key);
      }
    }
    if (this.records.size > MAX_SUBMISSION_RECORDS) {
      const oldest = [...this.records.values()]
        .sort((left, right) => left.submitted_at_unix_ms - right.submitted_at_unix_ms)
        .slice(0, this.records.size - MAX_SUBMISSION_RECORDS);
      for (const record of oldest) {
        this.records.delete(record.key);
      }
    }
    this.lastPrunedAtUnixMs = nowUnixMs;
  }
}

function validateSubmissionRecord(value: unknown): asserts value is SubmissionRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("submission log contains an invalid record");
  }
  for (const key of Object.keys(value)) {
    if (!SUBMISSION_RECORD_KEYS.has(key)) {
      throw new Error(`submission log record contains unsupported field ${key}`);
    }
  }
  const record = value as Partial<SubmissionRecord>;
  if (
    typeof record.key !== "string" ||
    !record.key ||
    typeof record.signer_address !== "string" ||
    typeof record.outside_nonce !== "string" ||
    typeof record.transaction_hash !== "string" ||
    !record.transaction_hash ||
    typeof record.submitted_at_unix_ms !== "number" ||
    !Number.isSafeInteger(record.submitted_at_unix_ms) ||
    record.submitted_at_unix_ms < 0
  ) {
    throw new Error("submission log contains an invalid record");
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

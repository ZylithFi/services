import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { mkdir, open, readFile, rename, stat, unlink } from "node:fs/promises";
import { dirname } from "node:path";

import type { PaymasterConfig } from "./config.js";
import type { SubmitterDeps } from "./starknetSubmitter.js";
import {
  relayPrivacyProofSignerCall,
  submitProofBearingOutsideExecution,
} from "./starknetSubmitter.js";
import { SubmissionStore } from "./submissionStore.js";
import {
  validateExecuteOutsideRequest,
  validateRelayPrivacySignerRequest
} from "./validation.js";

export type PaymasterServerDeps = SubmitterDeps & {
  submissionStore?: SubmissionStore;
};

const PAYMASTER_REQUEST_BODY_TIMEOUT_MS = 30_000;
const PAYMASTER_MAX_PENDING_SUBMISSIONS = 128;

export function createPaymasterServer(config: PaymasterConfig, deps: PaymasterServerDeps = {}) {
  const signerRateLimiter = new FixedWindowRateLimiter(config.signerLimitPerMinute);
  const clientRateLimiter = new FixedWindowRateLimiter(config.signerLimitPerMinute * 3);
  const submissionQueues = new SubmissionQueues(PAYMASTER_MAX_PENDING_SUBMISSIONS);
  const submissionStore = deps.submissionStore ?? new SubmissionStore(config.submissionLogPath);
  const signerRelayBudget = new SignerRelayBudget(
    config.signerRelayLimitPerDay,
    config.signerRelayLogPath
  );
  const sponsoredFeeBudget = new SponsoredFeeBudget(
    config.dailySponsoredFeeFri,
    config.sponsoredFeeLogPath,
    config.dailySponsoredFeePerPrincipalFri
  );
  const budgetedDeps = (principal: string) => ({
    ...deps,
    reserveSponsoredFee: async (maximumFeeFri: bigint) => {
      const upstreamRelease = await deps.reserveSponsoredFee?.(maximumFeeFri);
      try {
        const localRelease = await sponsoredFeeBudget.reserve(maximumFeeFri, principal);
        return async () => {
          await Promise.all([localRelease(), upstreamRelease?.()]);
        };
      } catch (error) {
        await upstreamRelease?.();
        throw error;
      }
    },
  });
  const metrics = new PaymasterMetrics();

  return createServer(async (request, response) => {
    try {
      if (!validateCors(request, response, config)) {
        return;
      }

      if (request.method === "OPTIONS") {
        sendJson(request, response, 204, {});
        return;
      }

      if (request.method === "GET" && request.url === "/health") {
        sendJson(request, response, 200, {
          status: "ok",
          registry_version: config.registryVersion,
          registry_hash: config.registryHash,
        });
        return;
      }

      if (request.method === "GET" && request.url === "/metrics") {
        requireMetricsAuth(request, config);
        sendText(request, response, 200, metrics.renderPrometheus());
        return;
      }

      if (request.method === "POST" && request.url === "/privacy-signer/relay") {
        const result = await measuredPaymasterRoute(metrics, "privacy_signer_relay", async () => {
          const validated = validateRelayPrivacySignerRequest(await readJsonBody(request, config), config);
          enforceRequestLimits(request, config, signerRateLimiter, clientRateLimiter, validated.account_address);
          return submissionQueues.enqueue(config.accountAddress, async () => {
            const release = await signerRelayBudget.reserve(relaySponsorshipKey(validated));
            try {
              return await relayPrivacyProofSignerCall(
                validated,
                config,
                budgetedDeps(validated.account_address),
              );
            } catch (error) {
              await release();
              throw error;
            }
          });
        });
        sendJson(request, response, 200, result);
        return;
      }

      if (request.method !== "POST" || request.url !== "/execute-outside") {
        sendJson(request, response, 404, { error: "not_found" });
        return;
      }

      const result = await measuredPaymasterRoute(metrics, "execute_outside", async () => {
        const validated = validateExecuteOutsideRequest(await readJsonBody(request, config), config);
        enforceRequestLimits(request, config, signerRateLimiter, clientRateLimiter, validated.signer_address);
        return submissionStore.runOnce(validated, () =>
          submissionQueues.enqueue(config.accountAddress, () =>
            submitProofBearingOutsideExecution(
              validated,
              config,
              budgetedDeps(validated.signer_address),
            )
          )
        );
      });
      sendJson(request, response, 200, result);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const status = statusForError(message);
      const safeMessage = safeLogErrorMessage(message);
      console.error(JSON.stringify({
        event: "paymaster_request_failed",
        method: request.method,
        url: request.url,
        status,
        error: safeMessage,
      }));
      sendJson(request, response, status, { error: safeMessage });
    }
  });
}

function safeLogErrorMessage(message: string): string {
  return message
    .replace(/"calldata"\s*:\s*\[[^\]]*\]/gi, '"calldata":[...]')
    .replace(/"signature"\s*:\s*\[[^\]]*\]/gi, '"signature":[...]')
    .replace(/"proof"\s*:\s*"[^"]*"/gi, '"proof":"<redacted>"')
    .replace(/"proof_facts"\s*:\s*\[[^\]]*\]/gi, '"proof_facts":[...]')
    .replace(/0x[0-9a-fA-F]{33,}/g, "<felt>")
    .replace(/\b[0-9]{32,}\b/g, "<number>")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 600);
}

function enforceRequestLimits(
  request: IncomingMessage,
  config: PaymasterConfig,
  signerRateLimiter: FixedWindowRateLimiter,
  clientRateLimiter: FixedWindowRateLimiter,
  signerAddress: string
): void {
  signerRateLimiter.check(`signer:${signerAddress}`);
  clientRateLimiter.check(`ip:${clientIp(request, config)}`);
}

async function measuredPaymasterRoute<T>(
  metrics: PaymasterMetrics,
  operation: string,
  run: () => Promise<T>
): Promise<T> {
  const startedAt = Date.now();
  try {
    const result = await run();
    metrics.record(operation, "success", Date.now() - startedAt);
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    metrics.record(operation, `http_${statusForError(message)}`, Date.now() - startedAt);
    throw error;
  }
}

function requireMetricsAuth(request: IncomingMessage, config: PaymasterConfig): void {
  if (!config.internalApiToken) {
    throw new Error("paymaster metrics token is not configured");
  }
  const expected = `Bearer ${config.internalApiToken}`;
  if (!constantTimeStringEqual(request.headers.authorization, expected)) {
    throw new Error("metrics authorization failed");
  }
}

function constantTimeStringEqual(actual: string | undefined, expected: string): boolean {
  if (typeof actual !== "string") return false;
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  const maxLength = Math.max(actualBytes.length, expectedBytes.length, 1);
  const paddedActual = Buffer.alloc(maxLength);
  const paddedExpected = Buffer.alloc(maxLength);
  actualBytes.copy(paddedActual);
  expectedBytes.copy(paddedExpected);
  return (
    timingSafeEqual(paddedActual, paddedExpected) &&
    actualBytes.length === expectedBytes.length
  );
}

function clientIp(request: IncomingMessage, config: PaymasterConfig): string {
  const socketIp = normalizeRemoteAddress(request.socket.remoteAddress ?? "unknown");
  if (config.trustProxyHeaders && isTrustedProxy(socketIp, config.trustedProxyCidrs)) {
    const forwarded = request.headers["x-forwarded-for"];
    if (forwarded !== undefined) {
      return forwardedClientIp(forwarded, config.trustedProxyCidrs) ?? socketIp;
    }
    const realIp = request.headers["x-real-ip"];
    const realClientIp = forwardedClientIp(realIp, config.trustedProxyCidrs);
    if (realClientIp) return realClientIp;
  }
  return socketIp;
}

function normalizeRemoteAddress(address: string): string {
  return address.startsWith("::ffff:") ? address.slice("::ffff:".length) : address;
}

function forwardedClientIp(
  value: string | string[] | undefined,
  trustedProxyCidrs: string[]
): string | null {
  const raw = Array.isArray(value) ? value[0] : value;
  const chain = (raw ?? "").split(",");
  for (let index = chain.length - 1; index >= 0; index -= 1) {
    const candidate = normalizeRemoteAddress(chain[index]?.trim() ?? "");
    if (!candidate || isIP(candidate) === 0) return null;
    if (!isTrustedProxy(candidate, trustedProxyCidrs)) return candidate;
  }
  return null;
}

function isTrustedProxy(peerIp: string, cidrs: string[]): boolean {
  return cidrs.some((cidr) => ipMatchesCidr(peerIp, cidr));
}

function ipMatchesCidr(peerIp: string, cidr: string): boolean {
  const normalizedCidr = normalizeRemoteAddress(cidr.trim());
  const [network, prefixText] = normalizedCidr.split("/");
  if (!network) return false;
  if (prefixText === undefined) {
    return normalizeRemoteAddress(network) === peerIp;
  }
  const peer = ipv4ToUint(peerIp);
  const base = ipv4ToUint(network);
  const prefix = Number(prefixText);
  if (peer === null || base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (peer & mask) === (base & mask);
}

function ipv4ToUint(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    result = ((result << 8) | octet) >>> 0;
  }
  return result;
}

async function readJsonBody(request: IncomingMessage, config: PaymasterConfig): Promise<unknown> {
  requireJsonContentType(request);
  return JSON.parse(
    await readBody(request, config.maxBodyBytes, PAYMASTER_REQUEST_BODY_TIMEOUT_MS)
  ) as unknown;
}

function requireJsonContentType(request: IncomingMessage): void {
  const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new Error("content-type must be application/json");
  }
}

function readBody(request: IncomingMessage, maxBytes: number, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    let settled = false;
    const timeout = setTimeout(() => {
      fail(new Error("request body timed out"));
    }, timeoutMs);

    const cleanup = () => {
      clearTimeout(timeout);
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onAborted);
    };
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      request.resume();
      reject(error);
    };
    const onData = (chunk: Buffer) => {
      size += chunk.byteLength;
      if (size > maxBytes) {
        fail(new Error("request body too large"));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks).toString("utf8"));
    };
    const onError = (error: Error) => fail(error);
    const onAborted = () => fail(new Error("request body was aborted"));

    request.on("data", onData);
    request.on("end", onEnd);
    request.on("error", onError);
    request.on("aborted", onAborted);
  });
}

function validateCors(
  request: IncomingMessage,
  response: ServerResponse,
  config: PaymasterConfig
): boolean {
  const origin = request.headers.origin;
  if (!origin) {
    return true;
  }

  if (!isOriginAllowed(config, origin)) {
    sendJson(request, response, 403, { error: "origin is not allowlisted" }, false);
    return false;
  }

  return true;
}

function isOriginAllowed(config: PaymasterConfig, origin: string): boolean {
  return config.allowedOrigins.has(origin);
}

function sendJson(
  request: IncomingMessage,
  response: ServerResponse,
  statusCode: number,
  body: unknown,
  includeCors = true
): void {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "cache-control": "no-store"
  };
  const origin = request.headers.origin;
  if (origin && includeCors) {
    headers["access-control-allow-origin"] = origin;
    headers.vary = "origin";
    headers["access-control-allow-methods"] = "POST, GET, OPTIONS";
    headers["access-control-allow-headers"] = "content-type";
  }

  response.writeHead(statusCode, {
    ...headers
  });
  response.end(JSON.stringify(body));
}

function sendText(
  request: IncomingMessage,
  response: ServerResponse,
  statusCode: number,
  body: string
): void {
  const headers: Record<string, string> = {
    "content-type": "text/plain; version=0.0.4",
    "cache-control": "no-store"
  };
  const origin = request.headers.origin;
  if (origin) {
    headers["access-control-allow-origin"] = origin;
    headers.vary = "origin";
    headers["access-control-allow-methods"] = "POST, GET, OPTIONS";
    headers["access-control-allow-headers"] = "content-type, authorization";
  }

  response.writeHead(statusCode, headers);
  response.end(body);
}

function statusForError(message: string): number {
  if (message.includes("request body too large")) {
    return 413;
  }
  if (message.includes("content-type must be application/json")) {
    return 415;
  }
  if (message.includes("request body timed out")) {
    return 408;
  }
  if (message.includes("submission queue is full")) {
    return 503;
  }
  if (
    message.includes("submission journal is unavailable") ||
    message.includes("submission outcome is pending reconciliation")
  ) {
    return 503;
  }
  if (
    message.includes("authorization failed") ||
    message.includes("authorization required")
  ) {
    return 401;
  }
  if (message.includes("metrics token is not configured")) {
    return 503;
  }
  if (
    message.includes("not allowlisted") ||
    message.includes("does not match") ||
    message.includes("outside execution caller")
  ) {
    return 403;
  }
  if (message.includes("rate limit")) {
    return 429;
  }
  if (message.includes("deployment budget exhausted")) {
    return 429;
  }
  if (message.includes("relay budget exhausted")) {
    return 429;
  }
  if (
    message.includes("sponsored fee limit exceeded")
    || message.includes("sponsored fee budget exhausted")
  ) {
    return 429;
  }
  if (message.includes("approval was already sponsored")) {
    return 409;
  }
  return 400;
}

const PAYMASTER_LATENCY_BUCKETS_MS = [
  10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000
];
const PAYMASTER_OPERATIONS = ["execute_outside", "privacy_signer_relay"];

class PaymasterMetrics {
  private readonly outcomes = new Map<string, number>();
  private readonly histograms = new Map<string, HistogramCounts>();

  record(operation: string, outcome: string, latencyMs: number): void {
    const key = `${operation}|${outcome}`;
    this.outcomes.set(key, (this.outcomes.get(key) ?? 0) + 1);
    let histogram = this.histograms.get(operation);
    if (!histogram) {
      histogram = new HistogramCounts(PAYMASTER_LATENCY_BUCKETS_MS);
      this.histograms.set(operation, histogram);
    }
    histogram.observe(Math.max(0, Math.trunc(latencyMs)));
  }

  renderPrometheus(): string {
    const lines: string[] = [
      "# HELP zylith_paymaster_requests_total Paymaster relay requests by operation and outcome.",
      "# TYPE zylith_paymaster_requests_total counter"
    ];
    for (const [key, count] of this.outcomes) {
      const [operation = "unknown", outcome = "unknown"] = key.split("|", 2);
      lines.push(
        `zylith_paymaster_requests_total{operation="${operation}",outcome="${outcome}"} ${count}`
      );
    }
    for (const operation of PAYMASTER_OPERATIONS) {
      if (![...this.outcomes.keys()].some((key) => key.startsWith(`${operation}|`))) {
        lines.push(
          `zylith_paymaster_requests_total{operation="${operation}",outcome="success"} 0`
        );
      }
    }
    for (const operation of PAYMASTER_OPERATIONS) {
      if (!this.histograms.has(operation)) {
        lines.push(
          ...new HistogramCounts(PAYMASTER_LATENCY_BUCKETS_MS).render(
            `zylith_paymaster_${operation}_latency_ms`
          )
        );
      }
    }
    for (const [operation, histogram] of this.histograms) {
      lines.push(...histogram.render(`zylith_paymaster_${operation}_latency_ms`));
    }
    return `${lines.join("\n")}\n`;
  }
}

class HistogramCounts {
  private readonly counts = new Map<number, number>();
  private overflow = 0;
  private count = 0;
  private sum = 0;

  constructor(private readonly buckets: number[]) {}

  observe(value: number): void {
    const bucket = this.buckets.find((candidate) => value <= candidate);
    if (bucket === undefined) {
      this.overflow += 1;
    } else {
      this.counts.set(bucket, (this.counts.get(bucket) ?? 0) + 1);
    }
    this.count += 1;
    this.sum += value;
  }

  render(metric: string): string[] {
    const lines = [`# HELP ${metric} Paymaster route latency.`, `# TYPE ${metric} histogram`];
    let cumulative = 0;
    for (const bucket of this.buckets) {
      cumulative += this.counts.get(bucket) ?? 0;
      lines.push(`${metric}_bucket{le="${bucket}"} ${cumulative}`);
    }
    cumulative += this.overflow;
    lines.push(`${metric}_bucket{le="+Inf"} ${cumulative}`);
    lines.push(`${metric}_count ${this.count}`);
    lines.push(`${metric}_sum ${this.sum}`);
    return lines;
  }
}

export class FixedWindowRateLimiter {
  private readonly buckets = new Map<string, { windowStartedAt: number; count: number }>();
  private lastSweepAt = 0;

  constructor(private readonly limitPerMinute: number) {}

  check(key: string, now = Date.now()): void {
    const windowMs = 60_000;
    if (now - this.lastSweepAt >= windowMs) {
      for (const [bucketKey, bucket] of this.buckets) {
        if (now - bucket.windowStartedAt >= windowMs * 2) {
          this.buckets.delete(bucketKey);
        }
      }
      this.lastSweepAt = now;
    }
    const existing = this.buckets.get(key);
    if (!existing || now - existing.windowStartedAt >= windowMs) {
      this.buckets.set(key, { windowStartedAt: now, count: 1 });
      return;
    }

    existing.count += 1;
    if (existing.count > this.limitPerMinute) {
      throw new Error("signer rate limit exceeded");
    }
  }

  get size(): number {
    return this.buckets.size;
  }
}

type SignerRelayBudgetRecord = {
  utc_day: string;
  reserved: number;
  sponsorships: string[];
};

export class SignerRelayBudget {
  private loaded = false;
  private record: SignerRelayBudgetRecord = {
    utc_day: utcDay(),
    reserved: 0,
    sponsorships: [],
  };
  private persistTail: Promise<void> = Promise.resolve();

  constructor(private readonly limitPerDay: number, private readonly path: string | null) {
    if (!Number.isSafeInteger(limitPerDay) || limitPerDay <= 0) {
      throw new Error("signer relay limit must be a positive integer");
    }
  }

  async reserve(key: string): Promise<() => Promise<void>> {
    await this.load();
    this.rotateIfNeeded();
    if (this.record.sponsorships.includes(key)) {
      throw new Error("privacy signer approval was already sponsored");
    }
    if (this.record.reserved >= this.limitPerDay) {
      throw new Error("privacy signer relay budget exhausted");
    }
    const reservationDay = this.record.utc_day;
    this.record.reserved += 1;
    this.record.sponsorships.push(key);
    await this.persist();
    let released = false;
    return async () => {
      if (released) return;
      released = true;
      this.record.sponsorships = this.record.sponsorships.filter(
        (sponsorship) => sponsorship !== key
      );
      this.rotateIfNeeded();
      if (this.record.utc_day === reservationDay) {
        this.record.reserved = Math.max(0, this.record.reserved - 1);
      }
      await this.persist();
    };
  }

  private async load(): Promise<void> {
    if (this.loaded) return;
    if (!this.path) {
      this.loaded = true;
      return;
    }
    let body: string;
    try {
      const metadata = await stat(this.path);
      if (metadata.size > 64 * 1024 * 1024) {
        throw new Error("signer relay budget file is too large");
      }
      body = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        this.loaded = true;
        return;
      }
      throw error;
    }
    if (body.trim()) {
      const parsed = JSON.parse(body) as Partial<SignerRelayBudgetRecord>;
      if (
        typeof parsed.utc_day !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(parsed.utc_day) ||
        !Number.isSafeInteger(parsed.reserved) ||
        (parsed.reserved ?? 0) < 0 ||
        !Array.isArray(parsed.sponsorships) ||
        parsed.sponsorships.some((key) => typeof key !== "string")
      ) {
        throw new Error("signer relay budget file is invalid");
      }
      this.record = {
        utc_day: parsed.utc_day,
        reserved: parsed.reserved as number,
        sponsorships: [...new Set(parsed.sponsorships)],
      };
      this.rotateIfNeeded();
    }
    this.loaded = true;
  }

  private rotateIfNeeded(): void {
    const today = utcDay();
    if (this.record.utc_day !== today) {
      this.record.utc_day = today;
      this.record.reserved = 0;
    }
  }

  private async persist(): Promise<void> {
    if (!this.path) return;
    const snapshot = JSON.stringify(this.record) + "\n";
    this.persistTail = this.persistTail.then(async () => {
      await mkdir(dirname(this.path!), { recursive: true });
      const tempPath = `${this.path}.${process.pid}.relay.tmp`;
      const handle = await open(tempPath, "w");
      try {
        await handle.writeFile(snapshot, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      try {
        await rename(tempPath, this.path!);
      } catch (error) {
        await unlink(tempPath).catch(() => undefined);
        throw error;
      }
    });
    return this.persistTail;
  }
}

type SponsoredFeeBudgetRecord = {
  utc_day: string;
  spent_fri: string;
  principals: Record<string, string>;
};

export class SponsoredFeeBudget {
  private loaded = false;
  private record: SponsoredFeeBudgetRecord = {
    utc_day: utcDay(),
    spent_fri: "0",
    principals: {},
  };
  private tail: Promise<void> = Promise.resolve();

  constructor(
    private readonly limitPerDay: bigint,
    private readonly path: string | null,
    private readonly limitPerPrincipalPerDay: bigint = limitPerDay,
  ) {
    if (limitPerDay <= 0n) throw new Error("daily sponsored fee limit must be positive");
    if (limitPerPrincipalPerDay <= 0n || limitPerPrincipalPerDay > limitPerDay) {
      throw new Error("per-principal sponsored fee limit is invalid");
    }
  }

  async reserve(maximumFeeFri: bigint, principal = "legacy"): Promise<() => Promise<void>> {
    if (maximumFeeFri <= 0n) return Promise.reject(new Error("sponsored fee must be positive"));
    if (!/^[a-zA-Z0-9:_-]{1,160}$/.test(principal)) {
      return Promise.reject(new Error("sponsored fee principal is invalid"));
    }
    let reservationDay = "";
    const operation = this.tail.then(async () => {
      await this.load();
      this.rotateIfNeeded();
      reservationDay = this.record.utc_day;
      const spent = BigInt(this.record.spent_fri);
      const principalSpent = BigInt(this.record.principals[principal] ?? "0");
      if (spent + maximumFeeFri > this.limitPerDay) {
        throw new Error("daily sponsored fee budget exhausted");
      }
      if (principalSpent + maximumFeeFri > this.limitPerPrincipalPerDay) {
        throw new Error("daily sponsored fee budget exhausted for principal");
      }
      this.record.spent_fri = String(spent + maximumFeeFri);
      this.record.principals[principal] = String(principalSpent + maximumFeeFri);
      await this.persist();
    });
    this.tail = operation.catch(() => undefined);
    await operation;
    let released = false;
    return async () => {
      if (released) return;
      released = true;
      const release = this.tail.then(async () => {
        await this.load();
        this.rotateIfNeeded();
        if (this.record.utc_day !== reservationDay) return;
        const spent = BigInt(this.record.spent_fri);
        if (spent < maximumFeeFri) {
          throw new Error("sponsored fee budget accounting underflow");
        }
        this.record.spent_fri = String(spent - maximumFeeFri);
        const principalSpent = BigInt(this.record.principals[principal] ?? "0");
        if (principalSpent < maximumFeeFri) {
          throw new Error("sponsored fee principal accounting underflow");
        }
        const remaining = principalSpent - maximumFeeFri;
        if (remaining === 0n) delete this.record.principals[principal];
        else this.record.principals[principal] = String(remaining);
        await this.persist();
      });
      this.tail = release.catch(() => undefined);
      await release;
    };
  }

  private async load(): Promise<void> {
    if (this.loaded) return;
    if (!this.path) {
      this.loaded = true;
      return;
    }
    let body: string;
    try {
      const metadata = await stat(this.path);
      if (metadata.size > 8_192) throw new Error("sponsored fee budget file is too large");
      body = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        this.loaded = true;
        return;
      }
      throw error;
    }
    if (body.trim()) {
      const parsed = JSON.parse(body) as Partial<SponsoredFeeBudgetRecord>;
      if (
        typeof parsed.utc_day !== "string"
        || !/^\d{4}-\d{2}-\d{2}$/.test(parsed.utc_day)
        || typeof parsed.spent_fri !== "string"
        || !/^\d+$/.test(parsed.spent_fri)
        || BigInt(parsed.spent_fri) > this.limitPerDay
        || !parsed.principals
        || typeof parsed.principals !== "object"
        || Array.isArray(parsed.principals)
        || Object.entries(parsed.principals).some(([principal, spent]) =>
          !/^[a-zA-Z0-9:_-]{1,160}$/.test(principal)
          || typeof spent !== "string"
          || !/^\d+$/.test(spent)
          || BigInt(spent) > this.limitPerPrincipalPerDay
        )
      ) {
        throw new Error("sponsored fee budget file is invalid");
      }
      this.record = {
        utc_day: parsed.utc_day,
        spent_fri: parsed.spent_fri,
        principals: parsed.principals,
      };
      this.rotateIfNeeded();
    }
    this.loaded = true;
  }

  private rotateIfNeeded(): void {
    const today = utcDay();
    if (this.record.utc_day !== today) {
      this.record = { utc_day: today, spent_fri: "0", principals: {} };
    }
  }

  private async persist(): Promise<void> {
    if (!this.path) return;
    await mkdir(dirname(this.path), { recursive: true });
    const tempPath = `${this.path}.${process.pid}.fee.tmp`;
    const handle = await open(tempPath, "w");
    try {
      await handle.writeFile(`${JSON.stringify(this.record)}\n`, "utf8");
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
  }
}

function relaySponsorshipKey(request: {
  account_address: string;
  calls: Array<{ contract_address: string; calldata: string[] }>;
}): string {
  const call = request.calls[0];
  if (!call) throw new Error("privacy signer relay requires exactly one call");
  return `${request.account_address}:${call.contract_address}:${call.calldata[0]}`;
}

function utcDay(now = new Date()): string {
  return now.toISOString().slice(0, 10);
}

export class SubmissionQueues {
  private readonly tails = new Map<string, Promise<unknown>>();
  private pendingCount = 0;

  constructor(private readonly maxPending = PAYMASTER_MAX_PENDING_SUBMISSIONS) {
    if (!Number.isSafeInteger(maxPending) || maxPending <= 0) {
      throw new Error("maxPending must be a positive integer");
    }
  }

  enqueue<T>(queueKey: string, task: () => Promise<T>): Promise<T> {
    if (this.pendingCount >= this.maxPending) {
      throw new Error("paymaster submission queue is full");
    }
    this.pendingCount += 1;
    const tail = this.tails.get(queueKey) ?? Promise.resolve();
    const run = tail
      .catch(() => undefined)
      .then(task)
      .finally(() => {
        this.pendingCount -= 1;
      });
    const queuedTail = run.then(
      () => undefined,
      () => undefined
    );
    this.tails.set(queueKey, queuedTail);
    void queuedTail.then(() => {
      if (this.tails.get(queueKey) === queuedTail) {
        this.tails.delete(queueKey);
      }
    });
    return run;
  }

  get size(): number {
    return this.tails.size;
  }

  get pending(): number {
    return this.pendingCount;
  }
}

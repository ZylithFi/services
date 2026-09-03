import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

import type { PaymasterConfig } from "./config.js";
import type { SubmitterDeps } from "./starknetSubmitter.js";
import {
  ensurePrivacyProofSignerContract,
  relayPrivacyProofSignerCall,
  submitProofBearingOutsideExecution
} from "./starknetSubmitter.js";
import { SubmissionStore } from "./submissionStore.js";
import {
  validateEnsurePrivacySignerRequest,
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
        sendJson(request, response, 200, { status: "ok" });
        return;
      }

      if (request.method === "GET" && request.url === "/metrics") {
        requireMetricsAuth(request, config);
        sendText(request, response, 200, metrics.renderPrometheus());
        return;
      }

      if (request.method === "POST" && request.url === "/privacy-signer/ensure") {
        const result = await measuredPaymasterRoute(metrics, "privacy_signer_ensure", async () => {
          requireJsonContentType(request);
          const rawBody = await readBody(
            request,
            config.maxBodyBytes,
            PAYMASTER_REQUEST_BODY_TIMEOUT_MS
          );
          const body = JSON.parse(rawBody) as unknown;
          const validated = validateEnsurePrivacySignerRequest(body, config);
          enforceRequestLimits(request, config, signerRateLimiter, clientRateLimiter, validated.signer_public_key);
          return submissionQueues.enqueue(config.accountAddress, () =>
            ensurePrivacyProofSignerContract(validated, config, deps)
          );
        });
        sendJson(request, response, 200, result);
        return;
      }

      if (request.method === "POST" && request.url === "/privacy-signer/relay") {
        const result = await measuredPaymasterRoute(metrics, "privacy_signer_relay", async () => {
          requireJsonContentType(request);
          const rawBody = await readBody(
            request,
            config.maxBodyBytes,
            PAYMASTER_REQUEST_BODY_TIMEOUT_MS
          );
          const body = JSON.parse(rawBody) as unknown;
          const validated = validateRelayPrivacySignerRequest(body, config);
          enforceRequestLimits(request, config, signerRateLimiter, clientRateLimiter, validated.account_address);
          return submissionQueues.enqueue(config.accountAddress, () =>
            relayPrivacyProofSignerCall(validated, config, deps)
          );
        });
        sendJson(request, response, 200, result);
        return;
      }

      if (request.method !== "POST" || request.url !== "/execute-outside") {
        sendJson(request, response, 404, { error: "not_found" });
        return;
      }

      const result = await measuredPaymasterRoute(metrics, "execute_outside", async () => {
        requireJsonContentType(request);
        const rawBody = await readBody(
          request,
          config.maxBodyBytes,
          PAYMASTER_REQUEST_BODY_TIMEOUT_MS
        );
        const body = JSON.parse(rawBody) as unknown;
        const validated = validateExecuteOutsideRequest(body, config);
        enforceRequestLimits(request, config, signerRateLimiter, clientRateLimiter, validated.signer_address);
        return submissionStore.runOnce(validated, () =>
          submissionQueues.enqueue(config.accountAddress, () =>
            submitProofBearingOutsideExecution(validated, config, deps)
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
    const forwardedIp = forwardedClientIp(forwarded);
    if (forwardedIp) return forwardedIp;
    const realIp = request.headers["x-real-ip"];
    const realClientIp = forwardedClientIp(realIp);
    if (realClientIp) return realClientIp;
  }
  return socketIp;
}

function normalizeRemoteAddress(address: string): string {
  return address.startsWith("::ffff:") ? address.slice("::ffff:".length) : address;
}

function forwardedClientIp(value: string | string[] | undefined): string | null {
  const raw = Array.isArray(value) ? value[0] : value;
  const candidate = normalizeRemoteAddress((raw ?? "").split(",")[0]?.trim() ?? "");
  return candidate && isIP(candidate) !== 0 ? candidate : null;
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
  if (message.includes("authorization failed")) {
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
  return 400;
}

const PAYMASTER_LATENCY_BUCKETS_MS = [
  10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000
];
const PAYMASTER_OPERATIONS = ["execute_outside", "privacy_signer_ensure", "privacy_signer_relay"];

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

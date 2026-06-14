import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";

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

export function createPaymasterServer(config: PaymasterConfig, deps: PaymasterServerDeps = {}) {
  const signerRateLimiter = new FixedWindowRateLimiter(config.signerLimitPerMinute);
  const clientRateLimiter = new FixedWindowRateLimiter(config.signerLimitPerMinute * 3);
  const submissionQueues = new SubmissionQueues();
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
          const rawBody = await readBody(request, config.maxBodyBytes);
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
          const rawBody = await readBody(request, config.maxBodyBytes);
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
        const rawBody = await readBody(request, config.maxBodyBytes);
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
      sendJson(request, response, status, { error: message });
    }
  });
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
  if (request.headers.authorization !== expected) {
    throw new Error("metrics authorization failed");
  }
}

function clientIp(request: IncomingMessage, config: PaymasterConfig): string {
  const socketIp = normalizeRemoteAddress(request.socket.remoteAddress ?? "unknown");
  if (config.trustProxyHeaders && isTrustedProxy(socketIp, config.trustedProxyCidrs)) {
    const forwarded = request.headers["x-forwarded-for"];
    if (typeof forwarded === "string" && forwarded.trim()) {
      return forwarded.split(",")[0]?.trim() || "unknown";
    }
    const realIp = request.headers["x-real-ip"];
    if (typeof realIp === "string" && realIp.trim()) {
      return realIp.trim();
    }
  }
  return socketIp;
}

function normalizeRemoteAddress(address: string): string {
  return address.startsWith("::ffff:") ? address.slice("::ffff:".length) : address;
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

function readBody(request: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];

    request.on("data", (chunk: Buffer) => {
      size += chunk.byteLength;
      if (size > maxBytes) {
        reject(new Error("request body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", reject);
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
  return config.allowedOrigins.has(origin) ||
    config.allowedOriginPatterns.some((pattern) => pattern.test(origin));
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

class FixedWindowRateLimiter {
  private readonly buckets = new Map<string, { windowStartedAt: number; count: number }>();

  constructor(private readonly limitPerMinute: number) {}

  check(key: string, now = Date.now()): void {
    const windowMs = 60_000;
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
}

class SubmissionQueues {
  private readonly tails = new Map<string, Promise<unknown>>();

  enqueue<T>(queueKey: string, task: () => Promise<T>): Promise<T> {
    const tail = this.tails.get(queueKey) ?? Promise.resolve();
    const run = tail.catch(() => undefined).then(task);
    this.tails.set(queueKey, run.then(
      () => undefined,
      () => undefined
    ));
    return run;
  }
}

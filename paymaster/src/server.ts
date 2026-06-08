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

      if (request.method === "POST" && request.url === "/privacy-signer/ensure") {
        const rawBody = await readBody(request, config.maxBodyBytes);
        const body = JSON.parse(rawBody) as unknown;
        const validated = validateEnsurePrivacySignerRequest(body, config);
        enforceRequestLimits(request, config, signerRateLimiter, clientRateLimiter, validated.signer_public_key);
        const result = await submissionQueues.enqueue(config.accountAddress, () =>
          ensurePrivacyProofSignerContract(validated, config, deps)
        );
        sendJson(request, response, 200, result);
        return;
      }

      if (request.method === "POST" && request.url === "/privacy-signer/relay") {
        const rawBody = await readBody(request, config.maxBodyBytes);
        const body = JSON.parse(rawBody) as unknown;
        const validated = validateRelayPrivacySignerRequest(body, config);
        enforceRequestLimits(request, config, signerRateLimiter, clientRateLimiter, validated.account_address);
        const result = await submissionQueues.enqueue(config.accountAddress, () =>
          relayPrivacyProofSignerCall(validated, config, deps)
        );
        sendJson(request, response, 200, result);
        return;
      }

      if (request.method !== "POST" || request.url !== "/execute-outside") {
        sendJson(request, response, 404, { error: "not_found" });
        return;
      }

      const rawBody = await readBody(request, config.maxBodyBytes);
      const body = JSON.parse(rawBody) as unknown;
      const validated = validateExecuteOutsideRequest(body, config);
      enforceRequestLimits(request, config, signerRateLimiter, clientRateLimiter, validated.signer_address);
      const result = await submissionStore.runOnce(validated, () =>
        submissionQueues.enqueue(config.accountAddress, () =>
          submitProofBearingOutsideExecution(validated, config, deps)
        )
      );
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

function statusForError(message: string): number {
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

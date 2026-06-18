#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const args = new Set(process.argv.slice(2));
const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sdkDist = resolve(rootDir, "sdk/dist/index.js");

main().catch((error) => {
  console.error(`managed maker daemon failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

async function main() {
  if (!existsSync(sdkDist)) {
    throw new Error("SDK build is missing; run `cd client && npm run build:sdk` before starting the daemon");
  }
  const sdkModule = await import(pathToFileURL(sdkDist).href);
  const config = await loadConfig();
  const runtime = await loadRuntime(config);
  const strategies = normalizeStrategies(requiredArray(config.strategies, "strategies"));
  const requireQuoteOnlyAuthorization = optionalBool(
    process.env.ZYLITH_MANAGED_MAKER_REQUIRE_QUOTE_ONLY_AUTHORIZATION ?? config.require_quote_only_authorization,
    config.read_only === true ? false : true,
  );
  validateQuoteOnlyRuntime({ runtime, strategies, requireQuoteOnlyAuthorization });
  const relay = config.relay_url
    ? new sdkModule.ZylithRelaySdk({ relayUrl: config.relay_url })
    : undefined;
  const makerSdk = new sdkModule.ZylithMakerSdk({ relay });
  const marketData = new sdkModule.MarketDataEngine({
    sources: buildMarketSources(config, sdkModule),
    fairPricePolicy: requiredObject(config.fair_price_policy, "fair_price_policy"),
  });
  const statePath = requiredString(process.env.ZYLITH_MANAGED_MAKER_STATE_PATH ?? config.state_path, "state_path");
  const events = createEventCounters();
  const runner = new sdkModule.ZylithManagedMakerRunner({
    sdk: makerSdk,
    runtime,
    marketData,
    strategies,
    currentBatch: currentBatchLoader(config),
    store: jsonStateStore(resolve(statePath)),
    intervalMs: optionalPositiveInt(process.env.ZYLITH_MANAGED_MAKER_INTERVAL_MS ?? config.interval_ms, 30_000),
    submissionSafetyBufferMs: optionalPositiveInt(
      process.env.ZYLITH_MANAGED_MAKER_SUBMISSION_SAFETY_BUFFER_MS ?? config.submission_safety_buffer_ms,
      15_000,
    ),
    requireQuoteOnlyAuthorization,
    onEvent: (event) => {
      events.record(event);
      if (process.env.ZYLITH_MANAGED_MAKER_LOG_EVENTS === "true") {
        console.log(JSON.stringify({ ts: Date.now(), event }));
      }
    },
  });

  if (args.has("--once")) {
    const result = await runner.runOnce();
    const output = {
      ok: result.failed.length === 0,
      result,
      telemetry: runner.telemetrySnapshot(),
      ops: await safeOpsSnapshot(runner),
    };
    console.log(JSON.stringify(output, null, 2));
    if (result.failed.length > 0) process.exit(2);
    process.exit(0);
    return;
  }

  const server = await startTelemetryServer({ runner, events });
  runner.start();

  const shutdown = async () => {
    runner.stop();
    await new Promise((resolveShutdown) => server.close(resolveShutdown));
    process.exit(0);
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

function normalizeStrategies(strategies) {
  return strategies.map((strategy, index) => {
    if (!strategy || typeof strategy !== "object" || Array.isArray(strategy)) {
      throw new Error(`strategies[${index}] must be an object`);
    }
    const normalized = { ...strategy };
    if (normalized.managedMakerAuthorization === undefined && normalized.managed_maker_authorization !== undefined) {
      normalized.managedMakerAuthorization = normalized.managed_maker_authorization;
    }
    return normalized;
  });
}

function validateQuoteOnlyRuntime({ runtime, strategies, requireQuoteOnlyAuthorization }) {
  if (!requireQuoteOnlyAuthorization) return;
  if (typeof runtime.submitDelegatedPrivateOrder !== "function") {
    throw new Error("production managed maker daemon requires runtime.submitDelegatedPrivateOrder()");
  }
  for (const strategy of strategies) {
    if (strategy.enabled === false) continue;
    if (!strategy.managedMakerAuthorization) {
      throw new Error(`strategy ${strategy.id ?? "<unnamed>"} requires managed_maker_authorization`);
    }
  }
}

async function loadConfig() {
  const configPath = process.env.ZYLITH_MANAGED_MAKER_CONFIG;
  if (!configPath) throw new Error("ZYLITH_MANAGED_MAKER_CONFIG is required");
  return JSON.parse(await readFile(resolve(configPath), "utf8"));
}

async function loadRuntime(config) {
  const modulePath = requiredString(
    process.env.ZYLITH_MANAGED_MAKER_RUNTIME_MODULE ?? config.runtime_module,
    "runtime_module",
  );
  const runtimeModule = await import(pathToFileURL(resolve(modulePath)).href);
  const factory =
    runtimeModule.createManagedMakerRuntime ??
    runtimeModule.createRuntime ??
    runtimeModule.default;
  if (typeof factory !== "function") {
    throw new Error("runtime module must export createManagedMakerRuntime, createRuntime, or default");
  }
  const runtime = await factory({ config, env: process.env });
  for (const method of ["getBalances", "getOrders"]) {
    if (typeof runtime?.[method] !== "function") throw new Error(`runtime is missing ${method}()`);
  }
  return runtime;
}

function buildMarketSources(config, sdkModule) {
  const sources = requiredArray(config.market_sources, "market_sources");
  return sources.map((source, index) => buildMarketSource(source, `market_sources[${index}]`, sdkModule));
}

function buildMarketSource(source, path, sdkModule) {
  const kind = requiredString(source.kind, `${path}.kind`);
  let built;
  if (kind === "fixed") {
    const prices = requiredObject(source.prices, `${path}.prices`);
    const observedAt = typeof source.observed_at_unix_ms === "number" ? source.observed_at_unix_ms : undefined;
    built = {
      id: requiredString(source.id, `${path}.id`),
      async observe(pair) {
        const price = Number(prices[pair]);
        if (!Number.isFinite(price) || price <= 0) return null;
        return { source: source.id, pair, price, observedAt: observedAt ?? Date.now() };
      },
    };
  } else if (kind === "http-json") {
    built = sdkModule.createHttpJsonPriceSource({
      id: requiredString(source.id, `${path}.id`),
      url: requiredString(source.url, `${path}.url`),
      pricePath: requiredString(source.price_path, `${path}.price_path`),
      observedAtPath: source.observed_at_path,
      pairPath: source.pair_path,
      headers: source.headers,
      priceScale: source.price_scale,
    });
  } else if (kind === "starknet-oracle") {
    built = sdkModule.createStarknetOraclePriceSource({
      id: requiredString(source.id, `${path}.id`),
      rpcUrl: requiredString(source.rpc_url, `${path}.rpc_url`),
      contractAddress: requiredString(source.contract_address, `${path}.contract_address`),
      entrypoint: requiredString(source.entrypoint, `${path}.entrypoint`),
      calldata: requiredArray(source.calldata, `${path}.calldata`),
      priceScale: source.price_scale === undefined ? undefined : Number(source.price_scale),
      decimalsIndex: source.decimals_index,
      timestampIndex: source.timestamp_index,
      sourceCountIndex: source.source_count_index,
      minSourceCount: source.min_source_count,
    });
  } else if (kind === "ratio") {
    built = sdkModule.createRatioPriceSource({
      id: requiredString(source.id, `${path}.id`),
      pair: requiredString(source.pair, `${path}.pair`),
      numerator: buildMarketSource(
        requiredObject(source.numerator, `${path}.numerator`),
        `${path}.numerator`,
        sdkModule,
      ),
      denominator: buildMarketSource(
        requiredObject(source.denominator, `${path}.denominator`),
        `${path}.denominator`,
        sdkModule,
      ),
    });
  } else {
    throw new Error(`unsupported market source kind ${kind}`);
  }
  if (source.pairs !== undefined) {
    built = sdkModule.createPairScopedPriceSource(
      built,
      requiredArray(source.pairs, `${path}.pairs`).map((pair) => requiredString(pair, `${path}.pairs[]`)),
    );
  }
  return built;
}

function currentBatchLoader(config) {
  const coordinatorUrl = stripTrailingSlash(requiredString(config.coordinator_url, "coordinator_url"));
  const template = typeof config.current_batch_path_template === "string"
    ? config.current_batch_path_template
    : "/api/pairs/{base}/{quote}/batches/current";
  return async (pair) => {
    const [base, quote] = pair.pair_id.split("/");
    if (!base || !quote) throw new Error(`invalid pair id ${pair.pair_id}`);
    const path = template
      .replaceAll("{base}", encodeURIComponent(base))
      .replaceAll("{quote}", encodeURIComponent(quote))
      .replaceAll("{pair}", encodeURIComponent(pair.pair_id));
    const signal = AbortSignal.timeout(optionalPositiveInt(config.current_batch_timeout_ms, 10_000));
    const response = await fetch(`${coordinatorUrl}${path}`, { headers: { accept: "application/json" }, signal });
    if (!response.ok) throw new Error(await responseError(response, "current batch request failed"));
    return response.json();
  };
}

function jsonStateStore(path) {
  return {
    async loadState() {
      if (!existsSync(path)) return null;
      return JSON.parse(await readFile(path, "utf8"));
    },
    async saveState(state) {
      await mkdir(dirname(path), { recursive: true });
      const tmp = `${path}.${process.pid}.tmp`;
      await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`);
      await rename(tmp, path);
    },
  };
}

async function startTelemetryServer({ runner, events }) {
  const host = process.env.ZYLITH_MANAGED_MAKER_METRICS_HOST ?? "127.0.0.1";
  const port = optionalPositiveInt(process.env.ZYLITH_MANAGED_MAKER_METRICS_PORT, 3510);
  const startedAt = Date.now();
  const server = createServer(async (request, response) => {
    if (request.url === "/health") {
      const state = runner.currentState();
      writeJson(response, {
        service: "zylith-managed-maker",
        status: "ok",
        started_at_unix_ms: startedAt,
        telemetry: runner.telemetrySnapshot(),
        submitted_epoch_count: Object.keys(state.submittedEpochs).length,
        retained_failure_count: state.failures.length,
        last_run_at_unix_ms: state.lastRunAt,
      });
      return;
    }
    if (request.url === "/metrics") {
      response.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
      response.end(renderMetrics({ runner, events, startedAt }));
      return;
    }
    response.writeHead(404, { "content-type": "text/plain" });
    response.end("not found\n");
  });
  await new Promise((resolveListen) => server.listen(port, host, resolveListen));
  const address = server.address();
  console.log(`managed maker daemon listening on ${host}:${typeof address === "object" && address ? address.port : port}`);
  return server;
}

function renderMetrics({ runner, events, startedAt }) {
  const telemetry = runner.telemetrySnapshot();
  const state = runner.currentState();
  const lines = [
    "# HELP zylith_managed_maker_up Managed maker daemon process health.",
    "# TYPE zylith_managed_maker_up gauge",
    "zylith_managed_maker_up 1",
    "# TYPE zylith_managed_maker_started_at_unix_ms gauge",
    `zylith_managed_maker_started_at_unix_ms ${startedAt}`,
    "# TYPE zylith_managed_maker_submitted_total counter",
    `zylith_managed_maker_submitted_total ${telemetry.submitted}`,
    "# TYPE zylith_managed_maker_skipped_total counter",
    `zylith_managed_maker_skipped_total ${telemetry.skipped}`,
    "# TYPE zylith_managed_maker_failed_total counter",
    `zylith_managed_maker_failed_total ${telemetry.failed}`,
    "# TYPE zylith_managed_maker_state_submitted_epochs gauge",
    `zylith_managed_maker_state_submitted_epochs ${Object.keys(state.submittedEpochs).length}`,
    "# TYPE zylith_managed_maker_state_retained_failures gauge",
    `zylith_managed_maker_state_retained_failures ${state.failures.length}`,
  ];
  if (state.lastRunAt) lines.push(`zylith_managed_maker_last_run_at_unix_ms ${state.lastRunAt}`);
  for (const entry of events.entries()) {
    lines.push(`zylith_managed_maker_events_total{type="${label(entry.type)}",strategy="${label(entry.strategyId)}",pair="${label(entry.pair)}"} ${entry.count}`);
  }
  return `${lines.join("\n")}\n`;
}

function createEventCounters() {
  const counts = new Map();
  return {
    record(event) {
      const key = `${event.type}\t${event.strategyId}\t${event.pair}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    },
    entries() {
      return [...counts.entries()].map(([key, count]) => {
        const [type, strategyId, pair] = key.split("\t");
        return { type, strategyId, pair, count };
      });
    },
  };
}

async function safeOpsSnapshot(runner) {
  try {
    return await runner.opsSnapshot();
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function requiredString(value, name) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required`);
  return value;
}

function requiredArray(value, name) {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  return value;
}

function requiredObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value;
}

function optionalPositiveInt(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`expected positive integer, got ${value}`);
  return parsed;
}

function optionalBool(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  throw new Error(`expected boolean, got ${value}`);
}

function writeJson(response, body) {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body)}\n`);
}

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

async function responseError(response, fallback) {
  const text = await response.text().catch(() => "");
  return text.trim() || `${fallback}: HTTP ${response.status}`;
}

function label(value) {
  return String(value ?? "").replaceAll("\\", "\\\\").replaceAll("\"", "\\\"");
}

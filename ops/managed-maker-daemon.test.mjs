import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const daemon = resolve("ops/managed-maker-daemon.mjs");

test("managed maker daemon runs one production cycle with persisted telemetry state", async () => {
  buildSdk();
  const fixture = await createFixture();
  const result = await spawnNode([daemon, "--once"], {
    env: { ...process.env, ...fixture.env },
  });
  await fixture.close();

  assert.equal(result.status, 0, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, true);
  assert.equal(output.result.submitted.length, 1);
  assert.equal(output.result.submitted[0].curveCount, 1);
  assert.equal(output.telemetry.submitted, 1);
});

test("managed maker daemon exposes health and prometheus telemetry", async () => {
  buildSdk();
  const fixture = await createFixture();
  const port = await freePort();
  const child = spawn(process.execPath, [daemon], {
    env: {
      ...process.env,
      ...fixture.env,
      ZYLITH_MANAGED_MAKER_METRICS_PORT: String(port),
      ZYLITH_MANAGED_MAKER_INTERVAL_MS: "1000",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    const health = await pollJson(`http://127.0.0.1:${port}/health`);
    assert.equal(health.service, "zylith-managed-maker");
    assert.equal(health.status, "ok");

    const metrics = await fetch(`http://127.0.0.1:${port}/metrics`).then((response) => response.text());
    assert.match(metrics, /zylith_managed_maker_up 1/);
    assert.match(metrics, /zylith_managed_maker_submitted_total/);
    assert.match(metrics, /zylith_managed_maker_state_submitted_epochs/);
  } finally {
    child.kill("SIGTERM");
    await new Promise((resolve) => child.once("exit", resolve));
    await fixture.close();
  }
});

test("managed maker daemon rejects production strategies without quote-only authorization", async () => {
  buildSdk();
  const fixture = await createFixture({ omitManagedAuthorization: true });
  const result = await spawnNode([daemon, "--once"], {
    env: { ...process.env, ...fixture.env },
  });
  await fixture.close();

  assert.equal(result.status, 1);
  assert.match(result.stderr, /requires managed_maker_authorization/);
});

function buildSdk() {
  const result = spawnSync("npm", ["run", "build:sdk"], {
    cwd: resolve("client"),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

function spawnNode(args, options) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, {
      ...options,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("exit", (status) => resolve({ status, stdout, stderr }));
  });
}

async function createFixture(options = {}) {
  const dir = mkdtempSync(join(tmpdir(), "zylith-maker-daemon-"));
  const coordinator = await createCoordinator();
  const runtimeModule = join(dir, "runtime.mjs");
  const configPath = join(dir, "config.json");
  const statePath = join(dir, "state.json");

  writeFileSync(runtimeModule, `
let submitted = 0;
export async function createManagedMakerRuntime() {
  return {
    getBalances() {
      return [
        { asset: "ETH", available: "5000000000000000000", locked: "0" },
        { asset: "USDC", available: "10000000000", locked: "0" }
      ];
    },
    getOrders() { return []; },
    getPrivateStrategies() { return []; },
    async submitDelegatedPrivateOrder(intent, authorization) {
      submitted += 1;
      return { order_id: "ord-" + submitted, strategy_id: "strategy-" + submitted, intent, authorization };
    }
  };
}
`);

  writeFileSync(configPath, JSON.stringify({
    coordinator_url: coordinator.url,
    runtime_module: runtimeModule,
    state_path: statePath,
    fair_price_policy: { maxStalenessMs: 60_000, maxDivergenceBps: 100, minSources: 1 },
    market_sources: [
      { id: "fixture", kind: "fixed", prices: { "ETH/USDC": 2500 } },
    ],
    strategies: [
      {
        id: "managed-eth-usdc",
        pair: {
          pair_id: "ETH/USDC",
          base_asset_id: "ETH",
          quote_asset_id: "USDC",
          min_order_amount: "0.001",
          enabled: true,
        },
        strategy: {
          pair: "ETH/USDC",
          side: "Ask",
          targetBaseRatio: 0.35,
          targetBaseRatioMin: 0.2,
          targetBaseRatioMax: 0.5,
          baseSpreadBps: 35,
          volatilityBps: 10,
          inventorySkewBps: 100,
          bandCount: 3,
          maxEpochBase: 0.1,
          minBandBase: 0.01,
          maxExposureBase: 0.2,
          relayMode: "SelfRelay",
          durationHours: 1,
        },
        risk: {
          minSpreadBps: 10,
          maxSpreadBps: 200,
          maxPriceDeviationBps: 300,
          maxEpochBase: 0.1,
          maxInventoryImbalanceBps: 4_000,
          allowBid: true,
          allowAsk: true,
        },
        ...(options.omitManagedAuthorization ? {} : { managed_maker_authorization: managedAuthorizationFixture() }),
      },
    ],
  }, null, 2));

  return {
    env: {
      ZYLITH_MANAGED_MAKER_CONFIG: configPath,
      ZYLITH_MANAGED_MAKER_RUNTIME_MODULE: runtimeModule,
      ZYLITH_MANAGED_MAKER_STATE_PATH: statePath,
    },
    close: coordinator.close,
  };
}

function managedAuthorizationFixture() {
  return {
    policy: {
      version: 1,
      delegate_public_key: "0x123",
      pair_id: "ETH/USDC",
      allow_buy: false,
      allow_sell: true,
      max_epoch_base: "100000000000000000",
      min_price: "2400000000",
      max_price: "2600000000",
      valid_from_epoch: "1",
      valid_until_epoch: "5",
      relay_mode: "SelfRelay",
      parent_order_commitment: "0x0",
      recipient_owner_public_key: "0xabc",
      recipient_spend_authority: "0xdef",
      recipient_withdraw_authority: "0x456",
      recipient_residual_withdraw_authority: "0x456",
      auditor_view_allowed: false,
      policy_nonce: "1",
    },
    owner_authorization: {
      signature_r: "0x1",
      signature_s: "0x2",
    },
  };
}

async function createCoordinator() {
  const server = createServer((request, response) => {
    if (request.url === "/api/pairs/ETH/USDC/batches/current") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        batch_id: "batch-eth-usdc-1",
        pair_id: "ETH/USDC",
        epoch_id: 1,
        close_time_unix_ms: Date.now() + 90_000,
        status: "Open",
        order_count_bucket: "0",
      }));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address();
  assert.equal(typeof address, "object");
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolveClose) => server.close(resolveClose)),
  };
}

async function pollJson(url) {
  const deadline = Date.now() + 5000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolvePoll) => setTimeout(resolvePoll, 100));
  }
  throw lastError ?? new Error(`timed out polling ${url}`);
}

async function freePort() {
  const server = createServer();
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address();
  assert.equal(typeof address, "object");
  const port = address.port;
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

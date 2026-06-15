#!/usr/bin/env node
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sdkDist = resolve(rootDir, "sdk/dist/index.js");
const epochs = positiveArg("--epochs", 2_880);

main().catch((error) => {
  console.error(`managed maker chaos test failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

async function main() {
  if (!existsSync(sdkDist)) {
    throw new Error("SDK build is missing; run `cd client && npm run build:sdk` before running chaos tests");
  }
  const {
    MarketDataEngine,
    ZylithMakerSdk,
    ZylithManagedMakerRunner,
  } = await import(pathToFileURL(sdkDist).href);

  const clock = { epoch: 1, now: 1_900_000_000_000 };
  const state = { submittedEpochs: {}, failures: [] };
  const submissions = new Map();
  const partialFailures = [];
  const events = [];
  const runtime = fakeRuntime({ clock, submissions });
  const makerSdk = new ZylithMakerSdk({ relay: fakeRelay({ clock, partialFailures }) });
  const marketData = new MarketDataEngine({
    sources: [
      priceSource("primary", clock, 1.0),
      priceSource("confirming", clock, 1.0008),
    ],
    fairPricePolicy: { maxStalenessMs: 120_000, maxDivergenceBps: 250, minSources: 2 },
    now: () => clock.now,
  });
  const runner = new ZylithManagedMakerRunner({
    sdk: makerSdk,
    runtime,
    marketData,
    strategies: strategies(clock),
    currentBatch: async (pair) => ({
      batch_id: `batch-${pair.pair_id.toLowerCase().replaceAll("/", "-")}-${clock.epoch}`,
      pair_id: pair.pair_id,
      epoch_id: clock.epoch,
      close_time_unix_ms: clock.now + 60_000,
      status: "Open",
      order_count_bucket: "0-4",
    }),
    store: {
      loadState: () => state,
      saveState: (next) => {
        state.submittedEpochs = { ...next.submittedEpochs };
        state.failures = [...next.failures];
        state.lastRunAt = next.lastRunAt;
      },
    },
    now: () => clock.now,
    submissionSafetyBufferMs: 15_000,
    onEvent: (event) => events.push({ ...event, epoch: clock.epoch }),
  });

  for (let epoch = 1; epoch <= epochs; epoch += 1) {
    clock.epoch = epoch;
    clock.now = 1_900_000_000_000 + epoch * 90_000;
    await runner.runOnce();
    await runner.runOnce();
    assertNoDuplicateSubmissions(state);
  }

  const telemetry = runner.telemetrySnapshot();
  const submittedEpochs = Object.values(state.submittedEpochs);
  const multiPairCoverage = new Set(submittedEpochs.map((entry) => entry.pair));
  assert(telemetry.submitted > 0, "expected successful submissions");
  assert(telemetry.skipped > 0, "expected stale/divergent/duplicate skips");
  assert(telemetry.failed > 0, "expected injected outage failures");
  assert(partialFailures.length > 0, "expected relay outage partial-exposure markers");
  assert(multiPairCoverage.has("ETH/USDC") && multiPairCoverage.has("STRK/ETH"), "expected multi-pair coverage");
  assert([...submissions.values()].some((entry) => entry.assetSet.has("ETH") && entry.assetSet.has("USDC")), "expected ETH/USDC asset coverage");
  assert([...submissions.values()].some((entry) => entry.assetSet.has("STRK") && entry.assetSet.has("ETH")), "expected STRK/ETH asset coverage");

  console.log(JSON.stringify({
    ok: true,
    epochs,
    simulated_days: Number(((epochs * 90_000) / 86_400_000).toFixed(2)),
    telemetry,
    submitted_epoch_count: submittedEpochs.length,
    partial_relay_outage_count: partialFailures.length,
    retained_failure_count: state.failures.length,
    event_count: events.length,
  }, null, 2));
}

function fakeRuntime({ clock, submissions }) {
  return {
    getBalances() {
      return [
        { asset: "ETH", available: "20000000000000000000", locked: "1000000000000000000" },
        { asset: "USDC", available: "300000000000", locked: "0" },
        { asset: "STRK", available: "8000000000000000000000", locked: "500000000000000000000" },
      ];
    },
    getOrders() {
      if (clock.epoch % 29 !== 0) return [];
      return [{
        ordRef: `pending-${clock.epoch}`,
        pair: "ETH/USDC",
        side: "Sell",
        amount: "0.08",
        limitPrice: "2600",
        status: "settling",
        epochId: clock.epoch,
      }];
    },
    getPrivateStrategies() {
      return [{
        id: "managed-eth-usdc",
        mode: "Managed",
        pair: "ETH/USDC",
        status: "active",
        submitted_children: [],
      }];
    },
    async submitPrivateOrder(intent) {
      if (clock.epoch % 97 === 0) throw new Error("injected wallet/prover outage before exposure");
      const key = `${intent.pairId}:${clock.epoch}:${intent.side}`;
      const current = submissions.get(key) ?? { count: 0, assetSet: assetsForPair(intent.pairId) };
      current.count += 1;
      submissions.set(key, current);
      const packageId = `pkg-${intent.pairId.replace("/", "-")}-${clock.epoch}-${intent.side}`;
      return {
        order_id: `order-${key}`,
        strategy_id: `strategy-${key}`,
        offline_package: intent.relayMode === "ZylithRelay"
          ? renewalPackage(packageId, intent.pairId, clock.epoch)
          : undefined,
      };
    },
    async markPrivateStrategyRelayRegistered() {},
  };
}

function fakeRelay({ clock, partialFailures }) {
  return {
    async registerPackage(renewalPackage) {
      if (clock.epoch % 131 === 0) {
        partialFailures.push({ epoch: clock.epoch, package_id: renewalPackage.package_id });
        throw new Error("injected relay outage after package creation");
      }
      return {
        package_id: renewalPackage.package_id,
        package_commitment: renewalPackage.package_commitment,
        pair: renewalPackage.pair,
        start_epoch: renewalPackage.start_epoch,
        end_epoch: renewalPackage.end_epoch,
        slot_count: renewalPackage.slot_count,
        relay_mode: renewalPackage.relay_mode,
        pending_slots: 1,
        submitted_slots: 0,
        failed_slots: 0,
        updated_at_unix_ms: Date.now(),
      };
    },
  };
}

function strategies(clock) {
  return [
    {
      id: "managed-eth-usdc",
      pair: pair("ETH/USDC", "ETH", "USDC"),
      strategy: strategy("ETH/USDC", "Both", "ZylithRelay", 0.3),
      risk: risk(),
      permission: permission("ETH/USDC", clock),
    },
    {
      id: "managed-strk-eth",
      pair: pair("STRK/ETH", "STRK", "ETH"),
      strategy: strategy("STRK/ETH", "Both", "SelfRelay", 0.5),
      risk: risk(),
      permission: permission("STRK/ETH", clock),
    },
  ];
}

function pair(pairId, base, quote) {
  return {
    pair_id: pairId,
    base_asset_id: base,
    quote_asset_id: quote,
    min_order_amount: "0.001",
    enabled: true,
  };
}

function strategy(pairId, side, relayMode, targetBaseRatio) {
  return {
    pair: pairId,
    side,
    targetBaseRatio,
    targetBaseRatioMin: Math.max(0.05, targetBaseRatio - 0.2),
    targetBaseRatioMax: Math.min(0.95, targetBaseRatio + 0.2),
    baseSpreadBps: 40,
    volatilityBps: 20,
    inventorySkewBps: 120,
    bandCount: 3,
    maxEpochBase: pairId === "STRK/ETH" ? 40 : 0.2,
    minBandBase: pairId === "STRK/ETH" ? 1 : 0.01,
    maxExposureBase: pairId === "STRK/ETH" ? 80 : 0.4,
    relayMode,
    durationHours: 1,
  };
}

function risk() {
  return {
    minSpreadBps: 15,
    maxSpreadBps: 300,
    maxPriceDeviationBps: 400,
    maxEpochBase: 100,
    maxInventoryImbalanceBps: 3_000,
    allowBid: true,
    allowAsk: true,
  };
}

function permission(pairId, clock) {
  return {
    pairs: [pairId],
    sides: ["Buy", "Sell"],
    maxEpochBase: pairId === "STRK/ETH" ? 80 : 0.4,
    maxPriceDeviationBps: 500,
    expiresAt: clock.now + 365 * 86_400_000,
    relayModes: ["SelfRelay", "ZylithRelay"],
  };
}

function priceSource(id, clock, multiplier) {
  return {
    id,
    async observe(pairId) {
      if (clock.epoch % 41 === 0 && id === "confirming") return null;
      const base = pairId === "ETH/USDC" ? 2500 : 0.00004;
      const jump = clock.epoch % 53 === 0 && id === "confirming" ? 1.08 : 1;
      return {
        source: id,
        pair: pairId,
        price: base * multiplier * jump * (1 + Math.sin(clock.epoch / 25) * 0.003),
        observedAt: clock.now - (clock.epoch % 67 === 0 && id === "primary" ? 180_000 : 1000),
      };
    },
  };
}

function renewalPackage(packageId, pairId, epoch) {
  return {
    version: 1,
    package_id: packageId,
    package_commitment: `commitment-${packageId}`,
    created_at_unix_ms: Date.now(),
    pair: pairId,
    start_epoch: epoch,
    end_epoch: epoch + 1,
    slot_count: 1,
    relay_mode: "ZylithRelay",
    parent_cancel_authority: "0xabc",
    parent_cancel_marker: "0xdef",
    relay_authorization: {
      signer_public_key: "0x1",
      signature_r: "0x2",
      signature_s: "0x3",
    },
    slots: [],
  };
}

function assertNoDuplicateSubmissions(state) {
  const seen = new Set();
  for (const submission of Object.values(state.submittedEpochs)) {
    const key = `${submission.strategyId}:${submission.batchId}`;
    assert(!seen.has(key), `duplicate submitted epoch ${key}`);
    seen.add(key);
  }
}

function assetsForPair(pairId) {
  const [base, quote] = pairId.split("/");
  return new Set([base, quote]);
}

function positiveArg(name, fallback) {
  const raw = process.argv.find((arg) => arg.startsWith(`${name}=`));
  if (!raw) return fallback;
  const value = Number(raw.slice(name.length + 1));
  if (!Number.isInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

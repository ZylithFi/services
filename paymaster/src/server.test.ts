import { AddressInfo } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import type { PaymasterConfig } from "./config.js";
import { createPaymasterServer } from "./server.js";
import type { StarknetRuntime } from "./starknetSubmitter.js";
import type { ExecuteOutsideRequest } from "./types.js";

const servers: ReturnType<typeof createPaymasterServer>[] = [];

afterEach(async () => {
  await Promise.all(
    servers.map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
        })
    )
  );
  servers.length = 0;
});

describe("paymaster server", () => {
  it("handles a validated execute-outside request", async () => {
    const server = createPaymasterServer(config(), {
      fetchImpl: fakeRpcFetch(),
      runtime: fakeRuntime()
    });
    servers.push(server);
    const url = await listen(server);

    const response = await fetch(`${url}/execute-outside`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example"
      },
      body: JSON.stringify(request)
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe("https://app.example");
    await expect(response.json()).resolves.toEqual({ transaction_hash: "0xtx" });
  });

  it("protects metrics and reports paymaster route outcomes", async () => {
    const server = createPaymasterServer(config(), {
      fetchImpl: fakeRpcFetch(),
      runtime: fakeRuntime()
    });
    servers.push(server);
    const url = await listen(server);

    const rejected = await fetch(`${url}/metrics`);
    expect(rejected.status).toBe(401);

    const success = await postRequest(url, request);
    expect(success.status).toBe(200);
    const badRequest = await fetch(`${url}/execute-outside`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example"
      },
      body: JSON.stringify({
        ...request,
        paymaster_address: "0xdead"
      })
    });
    expect(badRequest.status).toBe(403);

    const metrics = await fetch(`${url}/metrics`, {
      headers: { authorization: "Bearer test-paymaster-token" }
    });
    expect(metrics.status).toBe(200);
    const body = await metrics.text();
    expect(body).toContain(
      'zylith_paymaster_requests_total{operation="execute_outside",outcome="success"} 1'
    );
    expect(body).toContain(
      'zylith_paymaster_requests_total{operation="execute_outside",outcome="http_403"} 1'
    );
    expect(body).toContain("zylith_paymaster_execute_outside_latency_ms_count 2");
    expect(body).not.toContain("proof-bytes");
    expect(body).not.toContain("0x777");
  });

  it("rejects disallowed origins before paying for work", async () => {
    const server = createPaymasterServer(config());
    servers.push(server);
    const url = await listen(server);

    const response = await fetch(`${url}/execute-outside`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://evil.example"
      },
      body: JSON.stringify(request)
    });

    expect(response.status).toBe(403);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("allows configured wildcard preview origins", async () => {
    const server = createPaymasterServer(
      {
        ...config(),
        allowedOriginPatterns: [/^https:\/\/[a-z0-9-]+\.vercel\.app$/]
      },
      {
        fetchImpl: fakeRpcFetch(),
        runtime: fakeRuntime()
      }
    );
    servers.push(server);
    const url = await listen(server);

    const response = await fetch(`${url}/execute-outside`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://zylith-git-main-tanctl.vercel.app"
      },
      body: JSON.stringify(request)
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe(
      "https://zylith-git-main-tanctl.vercel.app"
    );
  });

  it("serializes submissions through the paymaster account", async () => {
    let active = 0;
    let maxActive = 0;
    const fetchImpl = fakeRpcFetch(async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise((resolve) => setTimeout(resolve, 20));
        active -= 1;
    });
    const server = createPaymasterServer(config(), {
      fetchImpl,
      runtime: fakeRuntime()
    });
    servers.push(server);
    const url = await listen(server);

    const [first, second] = await Promise.all([
      postRequest(url, request),
      postRequest(url, {
        ...request,
        outside_transaction: {
          ...request.outside_transaction,
          outsideExecution: {
            ...request.outside_transaction.outsideExecution,
            nonce: "0xa"
          }
        }
      })
    ]);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(maxActive).toBe(1);
  });

  it("does not resubmit duplicate signed outside-execution nonces", async () => {
    let submits = 0;
    const server = createPaymasterServer(config(), {
      fetchImpl: fakeRpcFetch(async () => {
        submits += 1;
      }),
      runtime: fakeRuntime()
    });
    servers.push(server);
    const url = await listen(server);

    const first = await postRequest(url, request);
    const second = await postRequest(url, request);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    await expect(second.json()).resolves.toEqual({ transaction_hash: "0xtx" });
    expect(submits).toBe(1);
  });

  it("ignores forwarded IP headers from untrusted direct clients", async () => {
    const server = createPaymasterServer(
      {
        ...config(),
        signerLimitPerMinute: 1,
        trustProxyHeaders: true,
        trustedProxyCidrs: ["10.0.0.0/8"]
      },
      {
        fetchImpl: fakeRpcFetch(),
        runtime: fakeRuntime()
      }
    );
    servers.push(server);
    const url = await listen(server);

    const responses: Response[] = [];
    for (let index = 0; index < 4; index += 1) {
      const signer = `0x${(0x770 + index).toString(16)}`;
      const body = {
        ...request,
        signer_address: signer,
        outside_transaction: {
          ...request.outside_transaction,
          signerAddress: signer,
          outsideExecution: {
            ...request.outside_transaction.outsideExecution,
            nonce: `0x${(0x90 + index).toString(16)}`
          }
        }
      };
      responses.push(
        await fetch(`${url}/execute-outside`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example",
            "x-forwarded-for": `203.0.113.${index + 1}`
          },
          body: JSON.stringify(body)
        })
      );
    }

    expect(responses.map((response) => response.status)).toEqual([200, 200, 200, 429]);
  });

  it("relays privacy signer approvals without process-local ensure state", async () => {
    const server = createPaymasterServer(config(), {
      fetchImpl: fakeRpcFetch(),
      runtime: fakeRuntime()
    });
    servers.push(server);
    const url = await listen(server);
    const relayBody = {
      account_address: "0x1234",
      calls: [{
        contract_address: "0x123",
        entrypoint: "approve",
        calldata: ["0x123", "0x1", "0x0"]
      }],
      nonce: "0x55",
      signature_r: "0xaa",
      signature_s: "0xbb"
    };

    const relayBeforeEnsure = await fetch(`${url}/privacy-signer/relay`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example"
      },
      body: JSON.stringify(relayBody)
    });
    expect(relayBeforeEnsure.status).toBe(200);
    await expect(relayBeforeEnsure.json()).resolves.toEqual({ transaction_hash: "0xtx" });

    const ensure = await fetch(`${url}/privacy-signer/ensure`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example"
      },
      body: JSON.stringify({
        signer_public_key: "0x777",
        salt: "0x88",
        class_hash: "0xabc"
      })
    });
    expect(ensure.status).toBe(200);
    await expect(ensure.json()).resolves.toMatchObject({
      contract_address: "0x1234"
    });

    const relayAfterEnsure = await fetch(`${url}/privacy-signer/relay`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example"
      },
      body: JSON.stringify(relayBody)
    });
    expect(relayAfterEnsure.status).toBe(200);
    await expect(relayAfterEnsure.json()).resolves.toEqual({ transaction_hash: "0xtx" });
  });
});

function config(): PaymasterConfig {
  return {
    rpcUrl: "https://rpc.example",
    chainId: "0x534e5f5345504f4c4941",
    accountAddress: "0xabc",
    privateKey: "0xkey",
    privacySignerClassHash: "0xabc",
    allowedContracts: new Set(["0x123"]),
    allowedEntrypoints: new Set(["apply_actions"]),
    proofRequiredEntrypoints: new Set(["apply_actions"]),
    withdrawalAmountBuckets: new Set(),
    allowDirectWithdrawalRelays: false,
    bindHost: "127.0.0.1",
    port: 0,
    maxBodyBytes: 1_000_000,
    allowedOrigins: new Set(["https://app.example"]),
    allowedOriginPatterns: [],
    signerLimitPerMinute: 20,
    trustProxyHeaders: false,
    trustedProxyCidrs: [],
    internalApiToken: "test-paymaster-token",
    submissionLogPath: null
  };
}

function fakeRpcFetch(onAddInvoke?: () => Promise<void> | void): typeof fetch {
  return async (_url, init) => {
    const body = JSON.parse(String(init?.body));
    if (body.method === "starknet_estimateFee") {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: [
            {
              resource_bounds: {
                l1_gas: { max_amount: "0x1", max_price_per_unit: "0x2" },
                l2_gas: { max_amount: "0x3", max_price_per_unit: "0x4" },
                l1_data_gas: { max_amount: "0x5", max_price_per_unit: "0x6" }
              }
            }
          ]
        }),
        { status: 200 }
      );
    }
    await onAddInvoke?.();
    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: { transaction_hash: "0xtx" }
      }),
      { status: 200 }
    );
  };
}

function listen(server: ReturnType<typeof createPaymasterServer>): Promise<string> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

function postRequest(url: string, body: ExecuteOutsideRequest): Promise<Response> {
  return fetch(`${url}/execute-outside`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://app.example"
    },
    body: JSON.stringify(body)
  });
}

const request: ExecuteOutsideRequest = {
  chain_id: "0x534e5f5345504f4c4941",
  signer_address: "0x777",
  paymaster_address: "0xabc",
  call: {
    contract_address: "0x123",
    entrypoint: "apply_actions",
    calldata: ["0x1"]
  },
  outside_transaction: {
    outsideExecution: {
      caller: "0xabc",
      nonce: "0x9",
      execute_after: String(Math.floor(Date.now() / 1000) - 60),
      execute_before: String(Math.floor(Date.now() / 1000) + 3600),
      calls: [
        {
          to: "0x123",
          selector: "0x246333a752c1ac637ff1591c5c885e27d56060d241a29aad8475072da0777db",
          calldata: ["0x1"]
        }
      ]
    },
    signerAddress: "0x777",
    version: "2",
    signature: ["0xa", "0xb"]
  },
  proof: "proof-bytes",
  proof_facts: ["0x1"]
};

function fakeRuntime(): StarknetRuntime {
  return {
    RpcProvider: class {
      constructor(_options: { nodeUrl: string }) {}

      async getClassHashAt() {
        return "0xabc";
      }
    },
    Account: class {
      constructor(_options: unknown) {}

      async getNonce() {
        return "0x7";
      }

      async getCairoVersion() {
        return "1";
      }

      async deploy() {
        return { transaction_hash: "0xdeploy", contract_address: "0x1234" };
      }

      async estimateInvokeFee() {
        return {
          resourceBounds: {
            l1_gas: { max_amount: 1n, max_price_per_unit: 2n },
            l2_gas: { max_amount: 3n, max_price_per_unit: 4n },
            l1_data_gas: { max_amount: 5n, max_price_per_unit: 6n }
          }
        };
      }

      async buildInvocation() {
        return {
          contractAddress: "0xabc",
          calldata: ["1"],
          signature: ["0xa", "0xb"],
          nonce: "0x7",
          resourceBounds: {
            l1_gas: { max_amount: 1n, max_price_per_unit: 2n },
            l2_gas: { max_amount: 3n, max_price_per_unit: 4n },
            l1_data_gas: { max_amount: 5n, max_price_per_unit: 6n }
          },
          tip: 0,
          paymasterData: [],
          accountDeploymentData: [],
          nonceDataAvailabilityMode: "L1",
          feeDataAvailabilityMode: "L1"
        };
      }
    },
    CallData: {
      toHex: (values: unknown[]) => values.map(String)
    },
    EDataAvailabilityMode: {
      L1: "L1"
    },
    ETransactionVersion3: {
      V3: "0x3"
    },
    outsideExecution: {
      buildExecuteFromOutsideCall: () => [
        {
          contractAddress: "0x777",
          entrypoint: "execute_from_outside_v2",
          calldata: ["0x1"]
        }
      ]
    },
    hash: {
      calculateContractAddressFromHash: () => "0x1234"
    }
  } as const satisfies StarknetRuntime;
}

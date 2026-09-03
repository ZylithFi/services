import { describe, expect, it, vi } from "vitest";

import type { StarknetRuntime } from "./starknetSubmitter.js";
import {
  ensurePrivacyProofSignerContract,
  relayPrivacyProofSignerCall,
  submitProofBearingOutsideExecution
} from "./starknetSubmitter.js";
import type {
  EnsurePrivacySignerRequest,
  ExecuteOutsideRequest,
  RelayPrivacySignerRequest
} from "./types.js";

describe("submitProofBearingOutsideExecution", () => {
  it("submits a proof-bearing invoke directly through JSON-RPC", async () => {
    const seen: { body?: unknown; estimateBody?: unknown } = {};
    const result = await submitProofBearingOutsideExecution(
      request,
      {
        rpcUrl: "https://rpc.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      {
        runtime: fakeRuntime,
        fetchImpl: async (_url, init) => {
          const body = JSON.parse(init?.body as string);
          if (body.method === "starknet_estimateFee") {
            seen.estimateBody = body;
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: [
                  {
                    l1_gas_consumed: "0x2",
                    l1_gas_price: "0x4",
                    l2_gas_consumed: "0x6",
                    l2_gas_price: "0x8",
                    l1_data_gas_consumed: "0xa",
                    l1_data_gas_price: "0xc"
                  }
                ]
              }),
              { status: 200 }
            );
          }
          seen.body = body;
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              result: { transaction_hash: "0xtx" }
            }),
            { status: 200 }
          );
        }
      }
    );

    const body = seen.body as {
      method: string;
      params: {
        invoke_transaction: {
          proof: string;
          proof_facts: string[];
          calldata: string[];
          signature: string[];
          resource_bounds: {
            l1_gas: { max_amount: string; max_price_per_unit: string };
            l2_gas: { max_amount: string; max_price_per_unit: string };
            l1_data_gas: { max_amount: string; max_price_per_unit: string };
          };
        };
      };
    };
    const estimateBody = seen.estimateBody as {
      method: string;
      params: {
        request: Array<{
          proof: string;
          proof_facts: string[];
        }>;
      };
    };
    expect(result.transaction_hash).toBe("0xtx");
    expect(estimateBody.method).toBe("starknet_estimateFee");
    expect(estimateBody.params.request[0].proof).toBe("proof-bytes");
    expect(estimateBody.params.request[0].proof_facts).toEqual(["0x1"]);
    expect(body.method).toBe("starknet_addInvokeTransaction");
    expect(body.params.invoke_transaction.proof).toBe("proof-bytes");
    expect(body.params.invoke_transaction.proof_facts).toEqual(["0x1"]);
    expect(body.params.invoke_transaction.signature).toEqual(["0xa", "0xb"]);
    expect(body.params.invoke_transaction.resource_bounds).toEqual({
      l1_gas: { max_amount: "0x3", max_price_per_unit: "0x6" },
      l2_gas: { max_amount: "0x9", max_price_per_unit: "0xc" },
      l1_data_gas: { max_amount: "0xf", max_price_per_unit: "0x12" }
    });
  });

  it("uses the configured RPC URL for every Starknet provider", async () => {
    const providerUrls: string[] = [];
    const runtime = {
      ...fakeRuntime,
      RpcProvider: class {
        constructor(options: { nodeUrl: string }) {
          providerUrls.push(options.nodeUrl);
        }

        async getClassHashAt(contractAddress: string) {
          if (contractAddress === "0x99") return "0xabc";
          return null;
        }
      }
    } satisfies StarknetRuntime;
    const fetchImpl: typeof fetch = async (_url, init) => {
      const body = JSON.parse(init?.body as string);
      if (body.method === "starknet_estimateFee") {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            result: [
              {
                l1_gas_consumed: "0x2",
                l1_gas_price: "0x4",
                l2_gas_consumed: "0x6",
                l2_gas_price: "0x8",
                l1_data_gas_consumed: "0xa",
                l1_data_gas_price: "0xc"
              }
            ]
          }),
          { status: 200 }
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: { transaction_hash: "0xtx" }
        }),
        { status: 200 }
      );
    };

    await ensurePrivacyProofSignerContract(
      ensureRequest,
      {
        rpcUrl: "https://rpc.configured.example",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      { runtime }
    );
    await relayPrivacyProofSignerCall(
      relayRequest,
      {
        rpcUrl: "https://rpc.configured.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey",
        privacySignerClassHash: "0xabc"
      },
      { runtime, fetchImpl }
    );
    await submitProofBearingOutsideExecution(
      request,
      {
        rpcUrl: "https://rpc.configured.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      { runtime, fetchImpl }
    );

    expect(providerUrls).not.toHaveLength(0);
    expect(providerUrls.every((url) => url === "https://rpc.configured.example")).toBe(true);
  });

  it("rejects relayed outside execution without proof fields", async () => {
    const { proof: _proof, proof_facts: _proofFacts, ...plainRequest } = request;
    await expect(
      submitProofBearingOutsideExecution(plainRequest, {
        rpcUrl: "https://rpc.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      })
    ).rejects.toThrow("proof and proof_facts are required for paymaster execution");
  });

  it("submits direct proof-bearing apply_actions calls without outside execution", async () => {
    const { outside_transaction: _outsideTransaction, ...directRequest } = {
      ...request,
      call: {
        contract_address: "0x123",
        entrypoint: "apply_actions",
        calldata: ["0x1", "0x2", "0x3"]
      },
      relay_nonce: "0x456"
    };
    const seen: { body?: unknown } = {};
    const runtime = {
      ...fakeRuntime,
      outsideExecution: {
        buildExecuteFromOutsideCall: () => {
          throw new Error("outside execution should not be used for direct proof relays");
        }
      }
    } satisfies StarknetRuntime;
    const result = await submitProofBearingOutsideExecution(
      directRequest,
      {
        rpcUrl: "https://rpc.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      {
        runtime,
        fetchImpl: async (_url, init) => {
          const body = JSON.parse(init?.body as string);
          if (body.method === "starknet_estimateFee") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: [
                  {
                    l1_gas_consumed: "0x2",
                    l1_gas_price: "0x4",
                    l2_gas_consumed: "0x6",
                    l2_gas_price: "0x8",
                    l1_data_gas_consumed: "0xa",
                    l1_data_gas_price: "0xc"
                  }
                ]
              }),
              { status: 200 }
            );
          }
          seen.body = body;
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              result: { transaction_hash: "0xdirect" }
            }),
            { status: 200 }
          );
        }
      }
    );

    expect(result.transaction_hash).toBe("0xdirect");
    expect((seen.body as { params: { invoke_transaction: { proof?: string } } }).params.invoke_transaction.proof).toBe("proof-bytes");
  });

  it("falls back to bounded resources when generic proof-bearing fee estimation fails", async () => {
    const methods: string[] = [];
    const seen: { body?: unknown } = {};
    const result = await submitProofBearingOutsideExecution(
      request,
      {
        rpcUrl: "https://rpc.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      {
        runtime: fakeRuntime,
        fetchImpl: async (_url, init) => {
          const body = JSON.parse(init?.body as string);
          methods.push(body.method);
          if (body.method === "starknet_estimateFee") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                error: {
                  code: 41,
                  message: "Transaction execution error"
                }
              }),
              { status: 200 }
            );
          }
          if (body.method === "starknet_getBlockWithTxHashes") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: {
                  l1_gas_price: { price_in_fri: "0x2" },
                  l2_gas_price: { price_in_fri: "0x3" },
                  l1_data_gas_price: { price_in_fri: "0x5" }
                }
              }),
              { status: 200 }
            );
          }
          seen.body = body;
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              result: { transaction_hash: "0xfallback" }
            }),
            { status: 200 }
          );
        }
      }
    );

    const body = seen.body as {
      params: {
        invoke_transaction: {
          resource_bounds: {
            l1_gas: { max_amount: string; max_price_per_unit: string };
            l2_gas: { max_amount: string; max_price_per_unit: string };
            l1_data_gas: { max_amount: string; max_price_per_unit: string };
          };
        };
      };
    };
    expect(result.transaction_hash).toBe("0xfallback");
    expect(methods).toEqual([
      "starknet_estimateFee",
      "starknet_getBlockWithTxHashes",
      "starknet_addInvokeTransaction"
    ]);
    expect(body.params.invoke_transaction.resource_bounds).toEqual({
      l1_gas: { max_amount: "0x0", max_price_per_unit: "0x4" },
      l2_gas: { max_amount: "0xaba9500", max_price_per_unit: "0x6" },
      l1_data_gas: { max_amount: "0x1f40", max_price_per_unit: "0xa" }
    });
  });

  it("falls back on structured allowance simulation errors only after live transfer preflight passes", async () => {
    const methods: string[] = [];
    let starknetCallCount = 0;
    const seen: { body?: unknown } = {};
    const requestWithTransfer = {
      ...request,
      outside_transaction: undefined,
      call: {
        contract_address: "0x123",
        entrypoint: "apply_actions",
        calldata: ["0x1", "0x2", "0x777", "0x456", "0x5"]
      }
    };

    const result = await submitProofBearingOutsideExecution(
      requestWithTransfer,
      {
        rpcUrl: "https://rpc.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      {
        runtime: fakeRuntime,
        fetchImpl: async (_url, init) => {
          const body = JSON.parse(init?.body as string);
          methods.push(body.method);
          if (body.method === "starknet_estimateFee") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                error: {
                  code: 41,
                  message: "Transaction execution error",
                  data: {
                    execution_error: "\"Insufficient ERC20 allowance\""
                  }
                }
              }),
              { status: 200 }
            );
          }
          if (body.method === "starknet_call") {
            starknetCallCount += 1;
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: starknetCallCount === 3 ? ["0x0"] : ["0x5", "0x0"]
              }),
              { status: 200 }
            );
          }
          if (body.method === "starknet_getBlockWithTxHashes") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: {
                  l1_gas_price: { price_in_fri: "0x2" },
                  l2_gas_price: { price_in_fri: "0x3" },
                  l1_data_gas_price: { price_in_fri: "0x5" }
                }
              }),
              { status: 200 }
            );
          }
          seen.body = body;
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              result: { transaction_hash: "0xpreflight-fallback" }
            }),
            { status: 200 }
          );
        }
      }
    );

    expect(result.transaction_hash).toBe("0xpreflight-fallback");
    expect(methods).toEqual([
      "starknet_estimateFee",
      "starknet_call",
      "starknet_call",
      "starknet_call",
      "starknet_getBlockWithTxHashes",
      "starknet_addInvokeTransaction"
    ]);
    expect(seen.body).toBeTruthy();
  });

  it("falls back on current privacy-pool server-action calldata with screening suffix after live transfer preflight passes", async () => {
    const methods: string[] = [];
    let starknetCallCount = 0;
    const seen: { body?: unknown } = {};
    const requestWithCurrentPoolActions = {
      ...request,
      outside_transaction: undefined,
      call: {
        contract_address: "0x123",
        entrypoint: "apply_actions",
        calldata: [
          "0x6",
          "0x2",
          "0x777",
          "0x456",
          "0x5",
          "0x7",
          "0xa1",
          "0xa2",
          "0xa3",
          "0x456",
          "0xabc1",
          "0x8",
          "0xabc1",
          "0x999",
          "0x9",
          "0xdead",
          "0xa",
          "0xbeef",
          "0x2",
          "0x1",
          "0x2",
          "0xb",
          "0xbeef",
          "0x0",
          "0x1"
        ]
      }
    };

    const result = await submitProofBearingOutsideExecution(
      requestWithCurrentPoolActions,
      {
        rpcUrl: "https://rpc.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      {
        runtime: fakeRuntime,
        fetchImpl: async (_url, init) => {
          const body = JSON.parse(init?.body as string);
          methods.push(body.method);
          if (body.method === "starknet_estimateFee") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                error: {
                  code: 41,
                  message: "Transaction execution error",
                  data: {
                    execution_error: "\"Insufficient ERC20 allowance\""
                  }
                }
              }),
              { status: 200 }
            );
          }
          if (body.method === "starknet_call") {
            starknetCallCount += 1;
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: starknetCallCount === 3 ? ["0x0"] : ["0x5", "0x0"]
              }),
              { status: 200 }
            );
          }
          if (body.method === "starknet_getBlockWithTxHashes") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: {
                  l1_gas_price: { price_in_fri: "0x2" },
                  l2_gas_price: { price_in_fri: "0x3" },
                  l1_data_gas_price: { price_in_fri: "0x5" }
                }
              }),
              { status: 200 }
            );
          }
          seen.body = body;
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              result: { transaction_hash: "0xcurrent-pool-fallback" }
            }),
            { status: 200 }
          );
        }
      }
    );

    expect(result.transaction_hash).toBe("0xcurrent-pool-fallback");
    expect(methods).toEqual([
      "starknet_estimateFee",
      "starknet_call",
      "starknet_call",
      "starknet_call",
      "starknet_getBlockWithTxHashes",
      "starknet_addInvokeTransaction"
    ]);
    expect(seen.body).toBeTruthy();
  });

  it("does not fallback when the paymaster lacks privacy-pool fee allowance", async () => {
    const methods: string[] = [];
    let starknetCallCount = 0;
    const requestWithTransfer = {
      ...request,
      outside_transaction: undefined,
      call: {
        contract_address: "0x123",
        entrypoint: "apply_actions",
        calldata: ["0x1", "0x2", "0x777", "0x456", "0x5"]
      }
    };

    await expect(
      submitProofBearingOutsideExecution(
        requestWithTransfer,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey"
        },
        {
          runtime: fakeRuntime,
          fetchImpl: async (_url, init) => {
            const body = JSON.parse(init?.body as string);
            methods.push(body.method);
            if (body.method === "starknet_estimateFee") {
              return new Response(
                JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  error: {
                    code: 41,
                    message: "Transaction execution error",
                    data: {
                      execution_error: "\"Insufficient ERC20 allowance\""
                    }
                  }
                }),
                { status: 200 }
              );
            }
            if (body.method === "starknet_call") {
              starknetCallCount += 1;
              const result =
                starknetCallCount === 3
                  ? ["0x5"]
                  : starknetCallCount === 5
                    ? ["0x0", "0x0"]
                    : ["0x5", "0x0"];
              return new Response(
                JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  result
                }),
                { status: 200 }
              );
            }
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: { transaction_hash: "0xunreachable" }
              }),
              { status: 200 }
            );
          }
        }
      )
    ).rejects.toThrow(
      "Starknet RPC rejected proof-bearing fee estimate: code=41 message=Transaction execution error data={\"execution_error\":\"\\\"Insufficient ERC20 allowance\\\"\"}"
    );
    expect(methods).toEqual([
      "starknet_estimateFee",
      "starknet_call",
      "starknet_call",
      "starknet_call",
      "starknet_call",
      "starknet_call"
    ]);
  });

  it("does not fallback on malformed structured transfer calldata", async () => {
    const methods: string[] = [];
    const malformedTransferRequest = {
      ...request,
      outside_transaction: undefined,
      call: {
        contract_address: "0x123",
        entrypoint: "apply_actions",
        calldata: ["0x1", "0x2", "0x777", "0x456", "0x5", "0xdead"]
      }
    };

    await expect(
      submitProofBearingOutsideExecution(
        malformedTransferRequest,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey"
        },
        {
          runtime: fakeRuntime,
          fetchImpl: async (_url, init) => {
            const body = JSON.parse(init?.body as string);
            methods.push(body.method);
            if (body.method === "starknet_estimateFee") {
              return new Response(
                JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  error: {
                    code: 41,
                    message: "Transaction execution error",
                    data: {
                      execution_error: "\"Insufficient ERC20 allowance\""
                    }
                  }
                }),
                { status: 200 }
              );
            }
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: { transaction_hash: "0xunreachable" }
              }),
              { status: 200 }
            );
          }
        }
      )
    ).rejects.toThrow(
      "Starknet RPC rejected proof-bearing fee estimate: code=41 message=Transaction execution error data={\"execution_error\":\"\\\"Insufficient ERC20 allowance\\\"\"}"
    );
    expect(methods).toEqual(["starknet_estimateFee"]);
  });

  it("does not relay proof-bearing calls when fee estimation includes structured revert data", async () => {
    const methods: string[] = [];
    const privateFelt =
      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    await expect(
      submitProofBearingOutsideExecution(
        request,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey"
        },
        {
          runtime: fakeRuntime,
          fetchImpl: async (_url, init) => {
            const body = JSON.parse(init?.body as string);
            methods.push(body.method);
            if (body.method === "starknet_estimateFee") {
              return new Response(
                JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  error: {
                    code: 41,
                    message: "Transaction execution error",
                    data: {
                      execution_error: "\"Insufficient ERC20 allowance\"",
                      calldata: privateFelt
                    }
                  }
                }),
                { status: 200 }
              );
            }
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: { transaction_hash: "0xunreachable" }
              }),
              { status: 200 }
            );
          }
        }
      )
    ).rejects.toThrow(
      "Starknet RPC rejected proof-bearing fee estimate: code=41 message=Transaction execution error data={\"execution_error\":\"\\\"Insufficient ERC20 allowance\\\"\",\"calldata\":\"<felt>\"}"
    );
    expect(methods).toEqual(["starknet_estimateFee"]);
  });

  it("aborts stalled Starknet RPC calls", async () => {
    vi.useFakeTimers();
    try {
      const attempt = submitProofBearingOutsideExecution(
        request,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey"
        },
        {
          runtime: fakeRuntime,
          fetchImpl: async (_url, init) =>
            new Promise<Response>((_resolve, reject) => {
              init?.signal?.addEventListener("abort", () => {
                reject(new DOMException("aborted", "AbortError"));
              });
            })
        }
      );

      const assertion = expect(attempt).rejects.toThrow("Starknet RPC request timed out");
      await vi.advanceTimersByTimeAsync(30_000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("aborts a Starknet RPC response body that never completes", async () => {
    vi.useFakeTimers();
    try {
      const attempt = submitProofBearingOutsideExecution(
        request,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey"
        },
        {
          runtime: fakeRuntime,
          fetchImpl: async () =>
            new Response(
              new ReadableStream({
                start(controller) {
                  controller.enqueue(new TextEncoder().encode('{"jsonrpc":"2.0"'));
                }
              }),
              { status: 200 }
            )
        }
      );

      const assertion = expect(attempt).rejects.toThrow("Starknet RPC request timed out");
      await vi.advanceTimersByTimeAsync(30_000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects oversized Starknet RPC response bodies", async () => {
    await expect(
      submitProofBearingOutsideExecution(
        request,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey"
        },
        {
          runtime: fakeRuntime,
          fetchImpl: async () =>
            new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                padding: "x".repeat(1_000_000)
              }),
              { status: 200 }
            )
        }
      )
    ).rejects.toThrow("Starknet RPC response body is too large");
  });

  it("rebuilds and retries when the paymaster account nonce is stale", async () => {
    let nonceIndex = 0;
    const addInvokeNonces: string[] = [];
    const runtime = {
      ...fakeRuntime,
      Account: class extends fakeRuntime.Account {
        async getNonce() {
          const nonce = nonceIndex === 0 ? "0x7" : "0x8";
          nonceIndex += 1;
          return nonce;
        }

        async buildInvocation(calls: unknown, details: { resourceBounds?: unknown; nonce?: string }) {
          const invocation = await super.buildInvocation(calls, details);
          return {
            ...invocation,
            nonce: details.nonce ?? invocation.nonce
          };
        }
      }
    } satisfies StarknetRuntime;
    let addInvokeAttempts = 0;
    const result = await submitProofBearingOutsideExecution(
      request,
      {
        rpcUrl: "https://rpc.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      {
        runtime,
        fetchImpl: async (_url, init) => {
          const body = JSON.parse(init?.body as string);
          if (body.method === "starknet_estimateFee") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: [
                  {
                    l1_gas_consumed: "0x2",
                    l1_gas_price: "0x4",
                    l2_gas_consumed: "0x6",
                    l2_gas_price: "0x8",
                    l1_data_gas_consumed: "0xa",
                    l1_data_gas_price: "0xc"
                  }
                ]
              }),
              { status: 200 }
            );
          }
          addInvokeAttempts += 1;
          addInvokeNonces.push(body.params.invoke_transaction.nonce);
          if (addInvokeAttempts === 1) {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                error: {
                  code: 52,
                  message: "Invalid transaction nonce",
                  data: "MempoolError(NonceTooOld { tx_nonce: Nonce(0x7), account_nonce: Nonce(0x8) })"
                }
              }),
              { status: 200 }
            );
          }
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              result: { transaction_hash: "0xretry" }
            }),
            { status: 200 }
          );
        }
      }
    );

    expect(result.transaction_hash).toBe("0xretry");
    expect(addInvokeNonces).toEqual(["0x7", "0x8"]);
  });

  it("redacts large RPC error fields before surfacing proof-bearing failures", async () => {
    const privateFelt =
      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const hugeNumber = "12345678901234567890123456789012345678901234567890";

    await expect(
      submitProofBearingOutsideExecution(
        request,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey"
        },
        {
          runtime: fakeRuntime,
          fetchImpl: async (_url, init) => {
            const body = JSON.parse(init?.body as string);
            if (body.method === "starknet_estimateFee") {
              return new Response(
                JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  error: {
                    code: 52,
                    message: "Transaction execution failed",
                    data: `calldata=${privateFelt} amount=${hugeNumber}`
                  }
                }),
                { status: 200 }
              );
            }
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: { transaction_hash: "0xunreachable" }
              }),
              { status: 200 }
            );
          }
        }
      )
    ).rejects.toThrow(
      "Starknet RPC rejected proof-bearing fee estimate: code=52 message=Transaction execution failed data=calldata=<felt> amount=<number>"
    );
  });

  it("does not echo malformed fee estimate resource payloads", async () => {
    const privateFelt =
      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    let thrown: unknown;
    try {
      await submitProofBearingOutsideExecution(
        request,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey"
        },
        {
          runtime: fakeRuntime,
          fetchImpl: async (_url, init) => {
            const body = JSON.parse(init?.body as string);
            if (body.method === "starknet_estimateFee") {
              return new Response(
                JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  result: [
                    {
                      resource_bounds: {
                        l1_gas: { max_amount: "0x1", max_price_per_unit: "0x1" },
                        debug_trace: privateFelt
                      }
                    }
                  ]
                }),
                { status: 200 }
              );
            }
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: { transaction_hash: "0xunreachable" }
              }),
              { status: 200 }
            );
          }
        }
      );
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(Error);
    const message = (thrown as Error).message;
    expect(message).toContain("failed to parse proof-bearing fee estimate resource bounds");
    expect(message).not.toContain(privateFelt);
  });

  it("retries embedded signer deployment when the paymaster nonce is already pending", async () => {
    const deployNonces: unknown[] = [];
    let deployAttempts = 0;
    let nonceIndex = 0;
    const runtime = {
      ...fakeRuntime,
      Account: class extends fakeRuntime.Account {
        async getNonce() {
          const nonce = nonceIndex === 0 ? "0x7" : "0x8";
          nonceIndex += 1;
          return nonce;
        }

        async deploy(_payload: unknown, details?: Record<string, unknown>) {
          deployAttempts += 1;
          deployNonces.push(details?.nonce);
          if (deployAttempts === 1) {
            throw new Error("MempoolError(DuplicateNonce { nonce: Nonce(0x7) })");
          }
          return { transaction_hash: "0xdeploy" };
        }
      }
    } satisfies StarknetRuntime;

    const result = await ensurePrivacyProofSignerContract(
      ensureRequest,
      {
        rpcUrl: "https://rpc.example",
        accountAddress: "0xabc",
        privateKey: "0xkey"
      },
      { runtime }
    );

    expect(result).toEqual({
      contract_address: "0x1234",
      deployed: true,
      transaction_hash: "0xdeploy"
    });
    expect(deployNonces).toEqual(["0x7", "0x8"]);
  });

  it("only relays privacy signer calls for the configured signer class hash", async () => {
    const seen: { body?: unknown } = {};
    const runtime = {
      ...fakeRuntime,
      RpcProvider: class {
        constructor(_options: { nodeUrl: string }) {}

        async getClassHashAt(contractAddress: string) {
          if (contractAddress === "0x99") {
            return "0xabc";
          }
          return null;
        }
      }
    } satisfies StarknetRuntime;

    const result = await relayPrivacyProofSignerCall(
      relayRequest,
      {
        rpcUrl: "https://rpc.example",
        chainId: "0x534e5f5345504f4c4941",
        accountAddress: "0xabc",
        privateKey: "0xkey",
        privacySignerClassHash: "0xabc"
      },
      {
        runtime,
        fetchImpl: async (_url, init) => {
          const body = JSON.parse(init?.body as string);
          if (body.method === "starknet_estimateFee") {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: [
                  {
                    l1_gas_consumed: "0x2",
                    l1_gas_price: "0x4",
                    l2_gas_consumed: "0x6",
                    l2_gas_price: "0x8",
                    l1_data_gas_consumed: "0xa",
                    l1_data_gas_price: "0xc"
                  }
                ]
              }),
              { status: 200 }
            );
          }
          seen.body = body;
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              result: { transaction_hash: "0xrelayed" }
            }),
            { status: 200 }
          );
        }
      }
    );

    expect(result.transaction_hash).toBe("0xrelayed");
    expect(
      (seen.body as { params: { invoke_transaction: { calldata: string[] } } }).params
        .invoke_transaction.calldata
    ).toEqual(["1", "2"]);
  });

  it("rejects privacy signer relay calls to non-signer contracts", async () => {
    await expect(
      relayPrivacyProofSignerCall(
        relayRequest,
        {
          rpcUrl: "https://rpc.example",
          chainId: "0x534e5f5345504f4c4941",
          accountAddress: "0xabc",
          privateKey: "0xkey",
          privacySignerClassHash: "0xabc"
        },
        { runtime: fakeRuntime }
      )
    ).rejects.toThrow("privacy proof signer account is not deployed");
  });
});

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
      execute_after: "1",
      execute_before: "2",
      calls: []
    },
    signerAddress: "0x777",
    version: "2",
    signature: ["0x1", "0x2"]
  },
  proof: "proof-bytes",
  proof_facts: ["0x1"]
};

const ensureRequest: EnsurePrivacySignerRequest = {
  signer_public_key: "0x111",
  salt: "0x222",
  class_hash: "0x333"
};

const relayRequest: RelayPrivacySignerRequest = {
  account_address: "0x99",
  calls: [
    {
      contract_address: "0x123",
      entrypoint: "approve",
      calldata: ["0x456", "0x1", "0x0"]
    }
  ],
  nonce: "0x1",
  signature_r: "0x2",
  signature_s: "0x3"
};

const fakeRuntime = {
  RpcProvider: class {
    constructor(_options: { nodeUrl: string }) {}

    async getClassHashAt() {
      return null;
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

    async buildInvocation(_calls: unknown, details: { resourceBounds?: unknown }) {
      return {
        contractAddress: "0xabc",
        calldata: ["1", "2"],
        signature: ["0xa", "0xb"],
        nonce: "0x7",
        resourceBounds: details.resourceBounds ?? {
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

    async deploy(_payload: unknown, _details?: Record<string, unknown>) {
      return { transaction_hash: "0xdeploy" };
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
  hash: {
    calculateContractAddressFromHash: () => "0x1234"
  },
  outsideExecution: {
    buildExecuteFromOutsideCall: () => [
      {
        contractAddress: "0x777",
        entrypoint: "execute_from_outside_v2",
        calldata: ["0x1"]
      }
    ]
  }
} satisfies StarknetRuntime;

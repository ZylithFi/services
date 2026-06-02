import { describe, expect, it } from "vitest";

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

  it("submits plain relayed outside execution without proof fields", async () => {
    const { proof: _proof, proof_facts: _proofFacts, ...plainRequest } = request;
    const seen: { body?: unknown; estimateBody?: unknown } = {};
    const result = await submitProofBearingOutsideExecution(
      plainRequest,
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
              result: { transaction_hash: "0xplain" }
            }),
            { status: 200 }
          );
        }
      }
    );

    const body = seen.body as {
      params: {
        invoke_transaction: {
          proof?: string;
          proof_facts?: string[];
        };
      };
    };
    const estimateBody = seen.estimateBody as {
      params: {
        request: Array<{
          proof?: string;
          proof_facts?: string[];
        }>;
      };
    };
    expect(result.transaction_hash).toBe("0xplain");
    expect(estimateBody.params.request[0].proof).toBeUndefined();
    expect(estimateBody.params.request[0].proof_facts).toBeUndefined();
    expect(body.params.invoke_transaction.proof).toBeUndefined();
    expect(body.params.invoke_transaction.proof_facts).toBeUndefined();
  });

  it("submits direct proof-bearing withdrawal calls without outside execution", async () => {
    const { outside_transaction: _outsideTransaction, ...directRequest } = {
      ...request,
      call: {
        contract_address: "0x123",
        entrypoint: "withdraw_settlement_output_with_proof_facts",
        calldata: ["0x1", "0x2", "0x3", "0x4", "0x5", "0x6", "0x7", "0x64"]
      },
      relay_nonce: "0x456"
    };
    const seen: { body?: unknown } = {};
    const runtime = {
      ...fakeRuntime,
      outsideExecution: {
        buildExecuteFromOutsideCall: () => {
          throw new Error("outside execution should not be used for direct withdrawals");
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

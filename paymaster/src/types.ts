import type { OutsideTransaction } from "starknet";

export type StarknetCallPayload = {
  contract_address: string;
  entrypoint: string;
  calldata: string[];
};

export type ExecuteOutsideRequest = {
  chain_id: string;
  signer_address: string;
  paymaster_address: string;
  call: StarknetCallPayload;
  authorization_call?: StarknetCallPayload;
  outside_transaction?: OutsideTransaction;
  relay_nonce?: string;
  proof?: string;
  proof_facts?: string[];
};

export type ExecuteOutsideResponse = {
  transaction_hash: string;
};

export type RpcSuccess = {
  jsonrpc: "2.0";
  id: number;
  result: {
    transaction_hash?: string;
  };
};

export type RpcFailure = {
  jsonrpc: "2.0";
  id: number;
  error: unknown;
};

export type RpcResponse = RpcSuccess | RpcFailure;

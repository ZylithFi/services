import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { SubmissionStore } from "./submissionStore.js";
import type { ExecuteOutsideRequest } from "./types.js";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs.length = 0;
});

describe("SubmissionStore", () => {
  it("returns the original transaction hash for duplicate outside nonces", async () => {
    const path = await tempPath();
    const store = new SubmissionStore(path);
    let submits = 0;

    const first = await store.runOnce(request, async () => {
      submits += 1;
      return { transaction_hash: "0xfirst" };
    });
    const second = await store.runOnce(request, async () => {
      submits += 1;
      return { transaction_hash: "0xsecond" };
    });

    expect(first.transaction_hash).toBe("0xfirst");
    expect(second.transaction_hash).toBe("0xfirst");
    expect(submits).toBe(1);
    await expect(readFile(path, "utf8")).resolves.toContain("0xfirst");
  });

  it("deduplicates concurrent duplicate submissions", async () => {
    const store = new SubmissionStore(null);
    let submits = 0;

    const [first, second] = await Promise.all([
      store.runOnce(request, async () => {
        submits += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return { transaction_hash: "0xfirst" };
      }),
      store.runOnce(request, async () => {
        submits += 1;
        return { transaction_hash: "0xsecond" };
      })
    ]);

    expect(first.transaction_hash).toBe("0xfirst");
    expect(second.transaction_hash).toBe("0xfirst");
    expect(submits).toBe(1);
  });

  it("loads prior submissions after restart", async () => {
    const path = await tempPath();
    await new SubmissionStore(path).runOnce(request, async () => ({
      transaction_hash: "0xfirst"
    }));

    const restarted = new SubmissionStore(path);
    const result = await restarted.runOnce(request, async () => ({
      transaction_hash: "0xsecond"
    }));

    expect(result.transaction_hash).toBe("0xfirst");
  });
});

async function tempPath(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "zylith-paymaster-"));
  tempDirs.push(dir);
  return join(dir, "submissions.json");
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
      execute_after: "1",
      execute_before: "2",
      calls: []
    },
    signerAddress: "0x777",
    version: "2",
    signature: ["0xa", "0xb"]
  },
  proof: "proof-bytes",
  proof_facts: ["0x1"]
};

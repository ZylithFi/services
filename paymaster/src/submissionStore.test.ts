import { mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
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

  it("waits for one shared initial load before accepting concurrent requests", async () => {
    const path = await tempPath();
    await new SubmissionStore(path).runOnce(request, async () => ({
      transaction_hash: "0xfirst"
    }));
    const restarted = new SubmissionStore(path);
    let submits = 0;

    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        restarted.runOnce(request, async () => {
          submits += 1;
          return { transaction_hash: "0xduplicate" };
        })
      )
    );

    expect(submits).toBe(0);
    expect(results.every((result) => result.transaction_hash === "0xfirst")).toBe(true);
  });

  it("can retry loading after a malformed log is repaired", async () => {
    const path = await tempPath();
    const store = new SubmissionStore(path);
    await writeFile(path, "{ invalid json");
    await expect(store.get(request)).rejects.toThrow();
    await writeFile(path, JSON.stringify([submissionRecord("0xfirst")]));

    const result = await store.runOnce(request, async () => ({
      transaction_hash: "0xduplicate"
    }));

    expect(result.transaction_hash).toBe("0xfirst");
  });

  it("rejects replay log records with unsupported fields", async () => {
    const path = await tempPath();
    await writeFile(path, JSON.stringify([{ ...submissionRecord("0xfirst"), unexpected_extra: true }]));

    await expect(new SubmissionStore(path).get(request)).rejects.toThrow(
      "unsupported field unexpected_extra"
    );
  });

  it("prunes expired replay records when loading after restart", async () => {
    const path = await tempPath();
    await writeFile(path, JSON.stringify([submissionRecord("0xexpired", 1)]));
    const store = new SubmissionStore(path);
    let submits = 0;

    const result = await store.runOnce(request, async () => {
      submits += 1;
      return { transaction_hash: "0xfresh" };
    });

    expect(submits).toBe(1);
    expect(result.transaction_hash).toBe("0xfresh");
  });

  it("rejects an oversized replay log before reading it into memory", async () => {
    const path = await tempPath();
    const handle = await open(path, "w");
    try {
      await handle.truncate(64 * 1024 * 1024 + 1);
    } finally {
      await handle.close();
    }

    await expect(new SubmissionStore(path).get(request)).rejects.toThrow(
      "submission log is too large"
    );
  });

  it("serializes concurrent snapshots so restart retains every submission", async () => {
    const path = await tempPath();
    const store = new SubmissionStore(path);
    const firstRequest = requestWithNonce("0xa");
    const secondRequest = requestWithNonce("0xb");
    await Promise.all([
      store.runOnce(firstRequest, async () => ({ transaction_hash: "0xfirst" })),
      store.runOnce(secondRequest, async () => ({ transaction_hash: "0xsecond" }))
    ]);

    const restarted = new SubmissionStore(path);
    let submits = 0;
    const [first, second] = await Promise.all([
      restarted.runOnce(firstRequest, async () => {
        submits += 1;
        return { transaction_hash: "0xduplicate-first" };
      }),
      restarted.runOnce(secondRequest, async () => {
        submits += 1;
        return { transaction_hash: "0xduplicate-second" };
      })
    ]);

    expect(submits).toBe(0);
    expect(first.transaction_hash).toBe("0xfirst");
    expect(second.transaction_hash).toBe("0xsecond");
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

function requestWithNonce(nonce: string): ExecuteOutsideRequest {
  return {
    ...request,
    outside_transaction: {
      ...request.outside_transaction!,
      outsideExecution: {
        ...request.outside_transaction!.outsideExecution,
        nonce
      }
    }
  };
}

function submissionRecord(transactionHash: string, submittedAtUnixMs = Date.now()) {
  return {
    key: "0x777:0x9",
    signer_address: "0x777",
    outside_nonce: "0x9",
    transaction_hash: transactionHash,
    submitted_at_unix_ms: submittedAtUnixMs
  };
}

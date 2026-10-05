import { describe, expect, it } from "vitest";

import { parsePrivacyPoolActions } from "./privacyPoolActions.js";

const normalize = (value: string) => `0x${BigInt(value).toString(16)}`;

describe("parsePrivacyPoolActions", () => {
  it("parses every pinned server-action ABI variant without layout drift", () => {
    const actions = parsePrivacyPoolActions(
      [
        "12",
        "0", "11", "2", "12", "13",
        "1", "14", "15", "16", "17",
        "2", "18", "19", "20",
        "3", "21", "22", "23",
        "4", "24", "25", "26", "27", "28",
        "5", "29", "30", "31", "32", "33", "34",
        "6", "35", "36", "37",
        "7", "38", "39", "40", "41", "42",
        "8", "43", "44",
        "9", "45",
        "10", "0x789", "2", "46", "47",
        "11", "0x999", "2", "48", "49",
      ],
      normalize,
    );

    expect(actions).not.toBeNull();
    expect(actions).toHaveLength(12);
    expect(actions?.map((action) => action.variant)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    expect(actions?.[4]).toEqual({ variant: 4 });
    expect(actions?.[7]).toEqual({
      variant: 7,
      token: "0x29",
      noteId: "0x2a",
    });
    expect(actions?.at(-2)).toEqual({
      variant: 10,
      target: "0x789",
      calldata: ["0x2e", "0x2f"],
    });
    expect(actions?.at(-1)).toEqual({
      variant: 11,
      target: "0x999",
      calldata: ["0x30", "0x31"],
    });
  });

  it("accepts only the pinned optional screening suffix shapes", () => {
    const invoke = ["1", "10", "0x789", "0"];

    expect(parsePrivacyPoolActions([...invoke, "1"], normalize)).not.toBeNull();
    expect(
      parsePrivacyPoolActions([...invoke, "0", "100", "101", "102"], normalize),
    ).not.toBeNull();
    expect(parsePrivacyPoolActions([...invoke, "0", "100"], normalize)).toBeNull();
    expect(parsePrivacyPoolActions([...invoke, "2"], normalize)).toBeNull();
  });

  it("rejects truncated, unknown, oversized, and trailing action data", () => {
    expect(parsePrivacyPoolActions(["1", "10", "0x789", "1"], normalize)).toBeNull();
    expect(parsePrivacyPoolActions(["1", "12"], normalize)).toBeNull();
    expect(parsePrivacyPoolActions(["257"], normalize)).toBeNull();
    expect(
      parsePrivacyPoolActions(["1", "10", "0x789", "0", "77", "78"], normalize),
    ).toBeNull();
  });
});

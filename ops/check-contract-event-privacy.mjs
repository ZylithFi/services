#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../contracts/src", import.meta.url).pathname;
const forbiddenPatterns = [
  { pattern: /#\s*\[\s*event\s*\]/i, reason: "Cairo #[event] declaration" },
  { pattern: /\benum\s+Event\b/, reason: "Cairo Event enum" },
  { pattern: /\bemit\s*\(/, reason: "contract event emission" },
];
const forbiddenFieldNames = [
  "witness",
  "preimage",
  "matched_orders",
  "consumed_inputs",
  "output_notes",
  "fee_rows",
  "fees",
  "private_report",
  "recovery_records",
];

const failures = [];

for (const file of cairoFiles(root)) {
  const text = readFileSync(file, "utf8");
  for (const { pattern, reason } of forbiddenPatterns) {
    if (pattern.test(text)) {
      failures.push(`${file}: contains ${reason}; add an explicit event privacy review before exposing contract events`);
    }
  }
  for (const field of forbiddenFieldNames) {
    const fieldPattern = new RegExp(`\\b${field}\\b`, "i");
    if (fieldPattern.test(text) && /#\s*\[\s*event\s*\]|\benum\s+Event\b|\bemit\s*\(/i.test(text)) {
      failures.push(`${file}: event surface mentions private field '${field}'`);
    }
  }
}

if (failures.length > 0) {
  console.error("contract event privacy check failed");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("contract event privacy check passed");

function* cairoFiles(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      yield* cairoFiles(path);
    } else if (path.endsWith(".cairo")) {
      yield path;
    }
  }
}

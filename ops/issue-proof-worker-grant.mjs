#!/usr/bin/env node
// issues one short-lived, one-time registration grant for an exactly pinned worker image.

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const queueUrl = required("ZYLITH_PROOF_QUEUE_URL").replace(/\/+$/, "");
const response = await fetch(`${queueUrl}/internal/proof-workers/grants`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-zylith-proof-control-token": required("ZYLITH_PROOF_QUEUE_CONTROL_TOKEN"),
  },
  body: JSON.stringify({
    worker_id: required("ZYLITH_PROOF_WORKER_ID"),
    capabilities: {
      prover_build_id: required("ZYLITH_PROVER_BUILD_ID"),
      proof_version: required("ZYLITH_PROOF_VERSION"),
      program_variant: "VIRTUAL_SNOS",
      virtual_program_hash: required("ZYLITH_VIRTUAL_PROGRAM_HASH"),
      starknet_os_output_version: "VIRTUAL_SNOS0",
      starknet_os_config_hash: required("ZYLITH_STARKNET_OS_CONFIG_HASH"),
    },
  }),
});

if (!response.ok) {
  throw new Error(`proof queue returned http ${response.status}`);
}
const grant = await response.json();
if (!/^[0-9a-f]{64}$/.test(grant.token) || !(grant.expires_at_unix_ms > Date.now())) {
  throw new Error("proof queue returned an invalid registration grant");
}
process.stdout.write(`${JSON.stringify(grant)}\n`);

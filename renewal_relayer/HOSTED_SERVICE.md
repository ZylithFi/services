# Hosted Renewal Operation Boundary

The open-source renewal relayer is the tool an account owner or operator can run
for exact-epoch child-intent submission. Zylith Relay is the hosted operation
around that tool.

## Public Relayer Repo Scope

The public relayer package should stay useful and complete for self-hosters:

- binary/service entrypoint;
- Dockerfile;
- systemd example;
- config example;
- health and readiness endpoints;
- Prometheus metrics endpoint;
- durable SQLite state;
- due-slot queue;
- exact-epoch submission;
- bounded retry logic;
- ordered coordinator/prover failover configuration;
- package refresh and deletion APIs;
- machine-readable ops alerts and optional alert webhooks;
- self-hosting documentation.

This is enough for a technical operator to run a renewal relay with their own
operations and liveness controls.

## Self Relay

Self Relay is for users or operators who want direct control over renewal
package submission and are comfortable operating infrastructure.

The operator owns:

- deployment and upgrades;
- persistent storage and backups;
- RPC/provider health;
- gas/paymaster configuration;
- monitoring and alerting;
- missed-slot response;
- package-expiry response;
- safe migrations and rollbacks;
- privacy timing parameter choices.

Self Relay should expose basic operational analytics: health, readiness, queue
depth, submitted children, failed submissions, missed epochs, retry counts,
package status, package results, local CSV export, logs, Prometheus metrics, and
machine-readable ops summaries/alerts.

Self Relay is deliberately valid. The product line is not "you must use
Zylith's relay." It is "you can operate this yourself, or Zylith can operate it
for you."

## Zylith Relay

Zylith Relay is hosted renewal-package operation.

The hosted service should include:

- multi-region relay runtime;
- RPC failover operation and transaction retry handling;
- queue and due-slot monitoring;
- missed-slot and failed-slot alerting;
- package-expiry alerts and renewal reminders;
- hosted gas/paymaster operations;
- hosted submission timing defaults and bounded smoothing where package policy allows it;
- encrypted immediate settlement reports;
- fill reports, epoch history, and CSV/API exports;
- missed opportunity and missed renewal reports;
- release management and incident response;
- support for debugging stuck packages or failed submissions.

## Metadata Boundary

Hosted relay operation necessarily sees operational metadata: package id,
accepted relay mode, pair, epoch schedule, due-slot timing, submission attempts,
retry outcomes, package expiry, and health metrics. It does not receive spend
keys, withdrawal keys, or authority to alter a signed child intent, but the
schedule/package metadata itself is sensitive.

The hosted service must mitigate that boundary with:

- package-scoped authorization and strict relay-mode enforcement;
- minimizing stored plaintext fields to what submission requires;
- explicit retention limits configured relative to package expiry;
- protected metrics and dashboards;
- rate limits and per-package access controls;
- URL allowlists and strict mode for outbound coordinator/prover calls;
- explicit disclosure in advanced renewal UI and docs.

## Internal Hosted-Service Surface

These pieces are not just the public binary hosted by Zylith. They are hosted
operations around the binary:

- multi-region orchestration;
- production dashboards;
- alert routing through hosted on-call/webhook infrastructure;
- incident runbooks;
- RPC provider routing;
- gas/paymaster funding operations;
- nonce and replacement-transaction handling;
- release automation;
- SLA/support process.

The repo gives operators the tool. The hosted service gives them the operation.

## Product Framing

Avoid describing Zylith Relay as a generic hosted relayer. The precise wording is:

```text
Zylith Relay is hosted renewal-package operation for persistent private intents.
```

The practical comparison:

```text
Self Relay:
full control, full operational burden.

Zylith Relay:
hosted renewals, monitoring, retries, gas ops, reporting, alerts,
hosted timing defaults, support, and operational accountability.
```

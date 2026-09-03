# Hosted Relay Product Boundary

The open-source renewal relayer is the tool a liquidity operator can run. Zylith
Relay is the hosted operation around that tool.

## Public Relayer Repo Scope

The public relayer package should stay useful and complete for self-hosters:

- binary/service entrypoint;
- Dockerfile;
- systemd example;
- config example;
- health and readiness endpoints;
- Prometheus metrics endpoint;
- durable SQLite state;
- basic due-slot queue;
- exact-epoch submission;
- bounded retry logic;
- ordered coordinator/prover failover configuration;
- package refresh and deletion APIs;
- machine-readable ops alerts and optional alert webhooks;
- self-hosting documentation.

This is enough for a technical liquidity operator to run a relay without paying Zylith a
hosted-relay fee.

## Self Relay

Self Relay is for liquidity operators who want 0bps hosted-relay fees and are comfortable
operating infrastructure.

The liquidity operator owns:

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
machine-readable ops summaries/alerts. It should not be positioned as the full
hosted performance or liquidity-intelligence product.

Self Relay is deliberately valid. The product line is not "you must use
Zylith's relay." It is "you can operate this yourself, or you can pay Zylith to
operate it well."

## Zylith Relay

Zylith Relay is hosted liquidity-position operations.

The paid service should include:

- multi-region relay runtime;
- RPC failover operation and transaction retry handling;
- queue and due-slot monitoring;
- missed-slot and failed-slot alerting;
- package-expiry alerts and renewal reminders;
- hosted gas/paymaster operations;
- hosted submission timing defaults and bounded smoothing where package policy allows it;
- encrypted immediate settlement reports;
- liquidity health dashboard;
- fill reports, epoch history, and CSV/API exports;
- call-auction-native liquidity TCA;
- curve performance and band-utilization analytics;
- missed opportunity and missed renewal reports;
- inventory exposure and relay-fee impact reports;
- release management and incident response;
- support for debugging stuck packages or failed submissions.

## Metadata Boundary

Hosted relay operation necessarily sees operational metadata: package id,
accepted relay mode, pair, epoch schedule, due-slot timing, submission attempts,
retry outcomes, package expiry, and health metrics. It does not receive LP
spend keys, withdrawal keys, or authority to alter a signed curve, but the
schedule/package metadata itself is sensitive.

The hosted service must mitigate that boundary with:

- package-scoped authorization and strict relay-mode enforcement;
- minimizing stored plaintext fields to what submission requires;
- explicit retention limits configured relative to package expiry;
- protected metrics and dashboards;
- rate limits and per-package access controls;
- URL allowlists and strict mode for outbound coordinator/prover calls;
- explicit disclosure in liquidity-facing UI and docs.

## Internal Hosted-Service Surface

These pieces are not just the public binary hosted by Zylith. They are hosted
operations around the binary:

- multi-region orchestration;
- production dashboards;
- alert routing through hosted on-call/webhook infrastructure;
- incident runbooks;
- hosted liquidity analytics UI;
- RPC provider routing;
- gas/paymaster funding operations;
- nonce and replacement-transaction handling;
- release automation;
- SLA/support process.

The repo gives liquidity operators the tool. The service gives them the operation.

## Pricing Rationale

The 1-2bps fee is not for source code. It is for operational reliability,
privacy-safe defaults, monitoring, reporting, gas ops, and support.

Self Relay remains available and economically valid:

```text
Self Relay:   0bps, full control, full operational burden.
Zylith Relay: 1-2bps, hosted renewals, monitoring, retries, gas ops,
              reporting, alerts, and hosted timing defaults.
```

This makes the fee optional instead of extractive. Sophisticated liquidity
operators can run their own relay. Operators who prefer not to operate
infrastructure can pay for the hosted service.

## Product Framing

Avoid describing Zylith Relay as a "hosted relayer." That sounds cloneable and
commodity.

Use:

```text
Zylith Relay is hosted liquidity-position operations.
```

The practical comparison:

```text
Self Relay:
0bps, full control, full operational burden.

Zylith Relay:
1-2bps, hosted renewals, monitoring, retries, gas ops, reporting, alerts,
hosted timing defaults, support, and operational accountability.
```

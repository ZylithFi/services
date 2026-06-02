# Managed Relay Product Boundary

The open-source renewal relayer is the tool a maker can run. Zylith Relay is the
managed operation around that tool.

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
- package refresh and deletion APIs;
- self-hosting documentation.

This is enough for a technical maker to operate a relay without paying Zylith a
managed-relay fee.

## Self Relay

Self relay is for makers who want 0bps managed-relay fees and are comfortable
operating infrastructure.

The maker owns:

- deployment and upgrades;
- persistent storage and backups;
- RPC/provider health;
- gas/paymaster configuration;
- monitoring and alerting;
- missed-slot response;
- package-expiry response;
- safe migrations and rollbacks;
- privacy timing parameter choices.

Self relay should expose basic operational analytics: health, readiness, queue
depth, submitted children, failed submissions, missed epochs, retry counts,
package status, package results, local CSV export, logs, and Prometheus metrics.
It should not be positioned as the full managed TCA or maker-intelligence
product.

Self relay is deliberately valid. The product line is not "you must use
Zylith's relay." It is "you can operate this yourself, or you can pay Zylith to
operate it well."

## Zylith Relay

Zylith Relay is managed maker liquidity operations.

The paid service should include:

- multi-region relay runtime;
- RPC failover and transaction retry handling;
- queue and due-slot monitoring;
- missed-slot and failed-slot alerting;
- package-expiry alerts and renewal reminders;
- managed gas/paymaster operations;
- privacy-safe timing defaults and submission smoothing;
- encrypted immediate settlement reports;
- maker health dashboard;
- fill reports, epoch history, and CSV/API exports;
- call-auction-native maker TCA;
- curve performance and band-utilization analytics;
- missed opportunity and missed renewal reports;
- inventory exposure and relay-fee impact reports;
- release management and incident response;
- support for debugging stuck packages or failed submissions.

## Internal Managed-Service Surface

These pieces are not just the public binary hosted by Zylith. They are managed
operations around the binary:

- multi-region orchestration;
- production dashboards;
- alert routing;
- incident runbooks;
- managed maker analytics UI;
- RPC provider routing;
- gas/paymaster funding operations;
- nonce and replacement-transaction handling;
- release automation;
- SLA/support process.

The repo gives makers the tool. The service gives them the operation.

## Pricing Rationale

The 1-2bps fee is not for source code. It is for operational reliability,
privacy-safe defaults, monitoring, reporting, gas ops, and support.

Self relay remains available and economically valid:

```text
Self relay:   0bps, full control, full operational burden.
Zylith relay: 1-2bps, managed renewals, monitoring, retries, gas ops,
              reporting, alerts, and privacy-safe timing defaults.
```

This makes the fee optional instead of extractive. Sophisticated makers can run
their own relay. Makers who prefer not to operate infrastructure can pay for the
managed service.

## Product Framing

Avoid describing Zylith Relay as a "hosted relayer." That sounds cloneable and
commodity.

Use:

```text
Zylith Relay is managed maker liquidity operations.
```

The practical comparison:

```text
Self Relay:
0bps, full control, full operational burden.

Zylith Relay:
1-2bps, managed renewals, monitoring, retries, gas ops, reporting, alerts,
privacy-safe timing defaults, support, and operational accountability.
```

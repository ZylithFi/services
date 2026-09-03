# Zylith Renewal Relayer

The renewal relayer submits pre-authorized liquidity-position child orders for exact
epochs. It does not receive spend keys, withdrawal keys, or the ability to change a
position's curve outside the package signed by the wallet.

There are two deployment modes:

| Mode | `ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE` | Relay fee | Operator |
| --- | --- | --- | --- |
| Self Relay | `SelfRelay` | 0bps | The liquidity operator |
| Zylith Relay | `ZylithRelay` | 1-2bps on matched liquidity volume | Zylith |

`relay_mode` is bound into the package/order commitment. A Self Relay should
only accept `SelfRelay` packages. The hosted Zylith Relay should only accept
`ZylithRelay` packages.

## Trust Model

The relayer can:

- submit an authorized child order for its exact epoch;
- observe the pair, epoch, submission outcome, and relay health metadata;
- observe package schedule metadata, package identifiers, due-slot timing, and
  retry/result metadata required to operate renewal submission;
- report child submission/fill status back to the wallet.

The relayer cannot:

- spend or withdraw liquidity funds;
- alter price bands, depth, side, or inventory caps;
- submit a slot for the wrong epoch;
- continue as a compliant relay once the accepted package's parent cancellation
  marker is recorded on-chain.

Missed epochs are not backfilled. If a Self Relay is down, liquidity for
those epochs is simply not submitted.

Hosted Zylith Relay is therefore a metadata trust boundary. It does not receive
spend or withdrawal keys, but it necessarily sees the operational schedule and
package metadata needed to submit authorized children. Production deployments
mitigate that boundary with registration-time package authorization, stripped
registration signatures at rest, package-scoped access tokens, bounded
retention, protected metrics, rate limits, strict URL allowlists, and explicit
disclosure in the liquidity UX.

## Quick Start

Build from the repository root:

```sh
cargo build --release -p zylith-renewal-relayer
```

Create a durable state directory and env file:

```sh
sudo mkdir -p /var/lib/zylith-renewal-relayer
sudo chown "$USER" /var/lib/zylith-renewal-relayer
cp renewal_relayer/examples/self-host.env.example .env.relayer
```

Edit `.env.relayer`, then run:

```sh
set -a
. ./.env.relayer
set +a
./target/release/zylith-renewal-relayer
```

Expose the service behind HTTPS. The wallet only accepts HTTPS endpoints except
for `localhost` development.

Docker build from the repository root:

```sh
docker build -f renewal_relayer/Dockerfile -t zylith-renewal-relayer:latest .
docker run --rm --env-file .env.relayer -p 3400:3400 \
  -v /var/lib/zylith-renewal-relayer:/var/lib/zylith-renewal-relayer \
  zylith-renewal-relayer:latest
```

Systemd deployment:

```sh
sudo useradd --system --home /var/lib/zylith-renewal-relayer --shell /usr/sbin/nologin zylith || true
sudo install -d -o zylith -g zylith /var/lib/zylith-renewal-relayer
sudo install -d /etc/zylith /opt/zylith/bin
sudo install -m 600 .env.relayer /etc/zylith/renewal-relayer.env
sudo install -m 755 ./target/release/zylith-renewal-relayer /opt/zylith/bin/
sudo install -m 644 renewal_relayer/examples/zylith-renewal-relayer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zylith-renewal-relayer
```

## Required Production Settings

For a self-hosted liquidity relay:

```sh
ZYLITH_RENEWAL_RELAY_STRICT=true
ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE=SelfRelay
ZYLITH_RENEWAL_RELAY_STORE_PATH=/var/lib/zylith-renewal-relayer/relay.sqlite
ZYLITH_RENEWAL_RELAY_COORDINATOR_URL=https://api.zylith.fi
ZYLITH_RENEWAL_RELAY_PROVER_URL=https://api.zylith.fi
ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN=...
ZYLITH_RENEWAL_RELAY_PROVER_CONTROL_TOKEN=...
ZYLITH_RENEWAL_RELAY_ALLOWED_ORIGINS=https://app.zylith.fi
```

Strict mode fails closed if the durable SQLite store, pinned coordinator/prover
URLs, internal tick token, prover proof-status token, or allowed origins are
missing. The prover proof-status token is used only to read exact
`reuse_state` for previously submitted reused-funding slots. Public proof-job
routes expose bucketed counts and always report `reuse_state=unknown`, so they
cannot be used to infer no-fill safely.
Self-hosted liquidity relays do not need Zylith's coordinator control token; they
submit children through the public coordinator order route after the official
private ingress returns an accepted coordinator submission.

`ZYLITH_RENEWAL_RELAY_COORDINATOR_CONTROL_TOKEN` is only for Zylith-operated or
otherwise authorized deployments that require internal coordinator access.
Package submission uses the public order route after private ingress acceptance.

## Configuration Reference

| Variable | Required in strict mode | Purpose |
| --- | --- | --- |
| `ZYLITH_RENEWAL_RELAY_STRICT` | recommended | Fails closed when production safety config is missing. |
| `ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE` | yes | Use `SelfRelay` for liquidity-operator relays and `ZylithRelay` for hosted service. |
| `ZYLITH_RENEWAL_RELAY_BIND_ADDR` | no | Listener address, usually private behind nginx/Caddy. |
| `ZYLITH_RENEWAL_RELAY_STORE_PATH` | yes | Durable `.sqlite` or `.db` state path. |
| `ZYLITH_RENEWAL_RELAY_COORDINATOR_URL` | yes | Pinned coordinator base URL. |
| `ZYLITH_RENEWAL_RELAY_PROVER_URL` | yes | Pinned private ingress/prover base URL. |
| `ZYLITH_RENEWAL_RELAY_COORDINATOR_URLS` | no | Comma-separated ordered coordinator failover URLs. Overrides the single coordinator URL when set. |
| `ZYLITH_RENEWAL_RELAY_PROVER_URLS` | no | Comma-separated ordered private-ingress/prover failover URLs. Overrides the single prover URL when set. |
| `ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN` | yes | Bearer token for internal tick trigger access. |
| `ZYLITH_RENEWAL_RELAY_PROVER_CONTROL_TOKEN` | yes | Bearer token for the prover proof-job status route used by reused-funding guards. |
| `ZYLITH_RENEWAL_RELAY_ALLOWED_ORIGINS` | yes | Comma-separated browser origins allowed to register packages. |
| `ZYLITH_RENEWAL_RELAY_MAX_PACKAGE_SLOTS` | no | Upper bound for accepted package size. Default supports about 20d at 20s epochs. |
| `ZYLITH_RENEWAL_RELAY_RETRY_BACKOFF_MS` | no | Failed-slot retry backoff. |
| `ZYLITH_RENEWAL_RELAY_MAX_ATTEMPTS` | no | Max failed submission attempts per slot. |
| `ZYLITH_RENEWAL_RELAY_RATE_LIMIT_PER_MINUTE` | no | Package API rate limit per caller. |
| `ZYLITH_RENEWAL_RELAY_PACKAGE_EXPIRY_WARNING_EPOCHS` | no | Epoch horizon for package-expiry warnings in ops summaries and metrics. |
| `ZYLITH_RENEWAL_RELAY_ALERT_WEBHOOK_URLS` | no | Comma-separated webhook URLs for active ops alerts. |
| `ZYLITH_RENEWAL_RELAY_ALERT_WEBHOOK_TOKEN` | no | Optional bearer token attached to alert webhook requests. |
| `ZYLITH_RENEWAL_RELAY_ALERT_REPEAT_MS` | no | Minimum repeat interval for the same alert key. Default: 15 minutes. |

## HTTP Surface

Liquidity package routes:

- `POST /packages`
- `GET /packages/{package_id}`
- `GET /packages/{package_id}/results`
- `GET /packages/{package_id}/results.csv`
- `DELETE /packages/{package_id}`

`POST /packages` accepts either the configured package bearer token or the
package's embedded registration signature. A successful registration returns a
package-scoped `access_token`; browser clients use that token through
`x-zylith-relay-package-access-token` for status, results, CSV export, and
delete. The relay strips the embedded `relay_authorization` before durable
storage and stores only a hash of the package access token. Operators can
alternatively use the configured package bearer token or internal relay token.

Operational routes:

- `GET /health`
- `GET /ready`
- `GET /metrics`
- `GET /ops/summary`
- `GET /ops/alerts`
- `POST /api/internal/relay/tick`

`/health` and `/ready` are intentionally minimal. `/api/internal/relay/tick`,
`/metrics`, `/ops/summary`, and `/ops/alerts` require
`ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN`.

## Metrics and Alerts

`GET /metrics` exposes Prometheus text metrics:

- `zylith_renewal_relay_packages`
- `zylith_renewal_relay_slots`
- `zylith_renewal_relay_submitted_slots`
- `zylith_renewal_relay_pending_slots`
- `zylith_renewal_relay_missed_slots`
- `zylith_renewal_relay_failed_slots`
- `zylith_renewal_relay_awaiting_wallet_refresh_slots`
- `zylith_renewal_relay_retryable_failed_slots`
- `zylith_renewal_relay_package_expiring_soon`
- `zylith_renewal_relay_warning_alerts`
- `zylith_renewal_relay_critical_alerts`

`GET /ops/summary` returns the same operational state as JSON: readiness,
configured relay mode, store kind, package count, slot counters, per-package
horizon, and active alerts. `GET /ops/alerts` returns just the active alert list.
These endpoints are intended for a liquidity operator's Prometheus exporter, cron checks,
webhook bridge, or local dashboard.

If `ZYLITH_RENEWAL_RELAY_ALERT_WEBHOOK_URLS` is configured, the relayer posts the
active ops-alert payload after worker or manual ticks. Delivery is de-duplicated
by severity, alert code, and package id for `ZYLITH_RENEWAL_RELAY_ALERT_REPEAT_MS`
so a persistent condition does not spam the destination every tick.

Minimum production alerts:

- `/ready` is not HTTP 200 for more than one minute.
- `zylith_renewal_relay_missed_slots` increases.
- `zylith_renewal_relay_failed_slots` increases repeatedly.
- Package expiry is less than the liquidity operator's renewal lead time.
- Disk free space for the SQLite volume is low.
- RPC/prover/coordinator request latency or error rate spikes.

`renewal_relayer/examples/prometheus-alerts.yml` contains a starter Prometheus
rule group for readiness, missed slots, failed slots, package expiry, and
critical/warning alert gauges.

The open-source relayer exposes raw operational counters. Zylith Relay turns the
same underlying events into hosted monitoring, alerting, liquidity reports,
support workflows, and privacy-safe operating defaults.

## Wallet Configuration

In the liquidity workspace:

1. Open `Advanced`.
2. Set `Renewal operator` to `Self-hosted relay`.
3. Enter your HTTPS relay endpoint.
4. Activate the curve.

The wallet creates a `SelfRelay` renewal package and submits it to your endpoint.
The package is signed by the parent cancel authority, so the relay can verify it
without a shared bearer token.

## Security Boundary

The Self Relay should be treated as an order-routing component, not a
wallet. It only receives exact-slot child submissions generated by the LP's
wallet. It should not hold spend keys, withdrawal keys, wallet signatures, or
seed material.

The package signature proves the LP authorized this exact relay package for
registration. It is not reused as a status/results/delete credential; those
operations require the package-scoped access token returned at registration or an
operator token. The `relay_mode` field prevents a self-relay package from being
accepted by the hosted Zylith Relay endpoint and prevents hosted-relay
packages from being accepted by a correctly configured self-host relay.

## Operations Checklist

- Run behind HTTPS with a real certificate.
- Restrict CORS to the Zylith app origin you use.
- Keep the SQLite store on persistent disk and back it up.
- Monitor `/ready`; it should return HTTP 200.
- Scrape `/metrics` for submitted, missed, and failed slots.
- Alert when missed or failed slots increase.
- Alert before package expiry.
- Keep RPC and coordinator URLs stable and monitored.
- Restart with systemd or another supervisor.
- Upgrade intentionally and keep the previous binary available for rollback.
- Keep the internal token outside shell history and repo files.
- Test package registration and `/ready` after every upgrade.

## Zylith Relay vs Self Relay

Self Relay gives 0bps hosted-relay fees and full control, but the liquidity
operator owns all operations: hosting, upgrades, queue monitoring,
gas/paymaster configuration, RPC failover configuration, retries,
package-expiry handling, migrations, and incident response.

Zylith Relay is hosted liquidity-position operations: multi-region runtime,
RPC failover operation, queue monitoring, missed-slot and package-expiry alerts,
retries, gas operations, encrypted reports, position dashboards, CSV/API
exports, support, release management, and hosted timing defaults.

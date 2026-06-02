# Zylith Renewal Relayer

The renewal relayer submits pre-authorized maker-curve child orders for exact epochs.
It does not receive spend keys, withdrawal keys, or the ability to change a maker's
curve outside the package signed by the wallet.

There are two deployment modes:

| Mode | `ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE` | Relay fee | Operator |
| --- | --- | --- | --- |
| Self relay | `SelfRelay` | 0bps | The maker |
| Zylith relay | `ZylithRelay` | 1-2bps on matched maker volume | Zylith |

`relay_mode` is bound into the package/order commitment. A self-hosted relay should
only accept `SelfRelay` packages. The managed Zylith relay should only accept
`ZylithRelay` packages.

## Trust Model

The relayer can:

- submit an authorized child order for its exact epoch;
- observe the pair, epoch, submission outcome, and relay health metadata;
- report child submission/fill status back to the wallet.

The relayer cannot:

- spend or withdraw maker funds;
- alter price bands, depth, side, or inventory caps;
- submit a slot for the wrong epoch;
- continue after the maker submits the parent cancellation marker on-chain.

Missed epochs are not backfilled. If a self-hosted relay is down, liquidity for
those epochs is simply not submitted.

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

For a self-hosted maker relay:

```sh
ZYLITH_RENEWAL_RELAY_STRICT=true
ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE=SelfRelay
ZYLITH_RENEWAL_RELAY_STORE_PATH=/var/lib/zylith-renewal-relayer/relay.sqlite
ZYLITH_RENEWAL_RELAY_COORDINATOR_URL=https://api.zylith.fi
ZYLITH_RENEWAL_RELAY_PROVER_URL=https://api.zylith.fi
ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN=...
ZYLITH_RENEWAL_RELAY_ALLOWED_ORIGINS=https://app.zylith.fi
```

Strict mode fails closed if the durable SQLite store, pinned coordinator/prover
URLs, internal tick token, or allowed origins are missing. Self-hosted maker
relays do not need Zylith's coordinator control token; they submit children
through the public coordinator order route after the official private ingress
returns an accepted coordinator submission.

`ZYLITH_RENEWAL_RELAY_COORDINATOR_CONTROL_TOKEN` is only for Zylith-operated or
otherwise authorized deployments that are allowed to submit through the managed
maker-order route.

## Configuration Reference

| Variable | Required in strict mode | Purpose |
| --- | --- | --- |
| `ZYLITH_RENEWAL_RELAY_STRICT` | recommended | Fails closed when production safety config is missing. |
| `ZYLITH_RENEWAL_RELAY_ACCEPT_RELAY_MODE` | yes | Use `SelfRelay` for maker-operated relays and `ZylithRelay` for managed service. |
| `ZYLITH_RENEWAL_RELAY_BIND_ADDR` | no | Listener address, usually private behind nginx/Caddy. |
| `ZYLITH_RENEWAL_RELAY_STORE_PATH` | yes | Durable `.sqlite` or `.db` state path. |
| `ZYLITH_RENEWAL_RELAY_COORDINATOR_URL` | yes | Pinned coordinator base URL. |
| `ZYLITH_RENEWAL_RELAY_PROVER_URL` | yes | Pinned private ingress/prover base URL. |
| `ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN` | yes | Bearer token for internal tick trigger access. |
| `ZYLITH_RENEWAL_RELAY_ALLOWED_ORIGINS` | yes | Comma-separated browser origins allowed to register packages. |
| `ZYLITH_RENEWAL_RELAY_MAX_PACKAGE_SLOTS` | no | Upper bound for accepted package size. Default supports 90d at 90s epochs. |
| `ZYLITH_RENEWAL_RELAY_RETRY_BACKOFF_MS` | no | Failed-slot retry backoff. |
| `ZYLITH_RENEWAL_RELAY_MAX_ATTEMPTS` | no | Max failed submission attempts per slot. |
| `ZYLITH_RENEWAL_RELAY_RATE_LIMIT_PER_MINUTE` | no | Package API rate limit per caller. |

## HTTP Surface

Public maker package routes:

- `POST /packages`
- `GET /packages/{package_id}`
- `GET /packages/{package_id}/results`
- `GET /packages/{package_id}/results.csv`
- `DELETE /packages/{package_id}`

Operational routes:

- `GET /health`
- `GET /ready`
- `GET /metrics`
- `POST /api/internal/relay/tick`

`/api/internal/relay/tick` requires `ZYLITH_RENEWAL_RELAY_INTERNAL_TOKEN` when
configured. Strict production mode requires this token.

## Metrics and Alerts

`GET /metrics` exposes Prometheus text metrics:

- `zylith_renewal_relay_packages`
- `zylith_renewal_relay_slots`
- `zylith_renewal_relay_submitted_slots`
- `zylith_renewal_relay_pending_slots`
- `zylith_renewal_relay_missed_slots`
- `zylith_renewal_relay_failed_slots`
- `zylith_renewal_relay_awaiting_wallet_refresh_slots`

Minimum production alerts:

- `/ready` is not HTTP 200 for more than one minute.
- `zylith_renewal_relay_missed_slots` increases.
- `zylith_renewal_relay_failed_slots` increases repeatedly.
- Package expiry is less than the maker's renewal lead time.
- Disk free space for the SQLite volume is low.
- RPC/prover/coordinator request latency or error rate spikes.

The open-source relayer exposes raw operational counters. Zylith Relay turns the
same underlying events into managed monitoring, alerting, maker-facing reports,
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

The self-hosted relay should be treated as an order-routing component, not a
wallet. It only receives exact-slot child submissions generated by the maker's
wallet. It should not hold spend keys, withdrawal keys, wallet passphrases, or
seed material.

The package signature proves the maker authorized this relay package. The
`relay_mode` field prevents a self-relay package from being accepted by the
managed Zylith Relay endpoint and prevents managed-relay packages from being
accepted by a correctly configured self-host relay.

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

Self relay gives 0bps managed-relay fees and full control, but the maker owns
all operations: hosting, upgrades, queue monitoring, gas/paymaster configuration,
RPC failover, retries, package-expiry handling, migrations, and incident
response.

Zylith Relay is managed maker liquidity operations: multi-region runtime, RPC
failover, queue monitoring, missed-slot and package-expiry alerts, retries, gas
operations, encrypted reports, maker dashboards, CSV exports, support, release
management, and privacy-safe timing defaults.

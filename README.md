# netwatch — find out *which layer* of your internet is breaking

A zero-dependency bash watchdog for diagnosing short, intermittent internet
outages — the kind that are over before you can open a terminal, where
"the internet is down" turns out to mean something much more specific.

netwatch probes every 5 seconds at multiple network layers **in parallel**.
When anything fails it opens an *incident*: it logs a pass/fail matrix every
cycle, captures a deep diagnostic snapshot in the background (curl timing
breakdowns, TLS handshake detail, routes, mtr), and when service recovers it
writes a markdown report with a **verdict** about which layer broke. It can
alert via desktop notification and/or push to your phone through a
self-hosted [ntfy](https://ntfy.sh) server — deliberately LAN-only, because
an internet-based alert about the internet being down never arrives.

## The probe layers

| Probe | What it tests | If only this fails... |
|---|---|---|
| `gw_ping` | ICMP to your router (auto-detected) | LAN/router problem |
| `wan_ping_cf`, `wan_ping_gg` | ICMP to 1.1.1.1 / 8.8.8.8 | WAN/ISP outage |
| `dns_system` | lookup via the system resolver (what apps use) | DNS broken |
| `dns_router`, `dns_public` | `dig` direct to router vs 1.1.1.1, cache-busted | isolates *which* resolver failed |
| `tcp_443` | raw TCP connect to 1.1.1.1:443 — no DNS, no TLS | TCP blocked (NAT/conntrack) |
| `https_google`, `https_cloudflare` | full HTTPS request | the "ping works but no websites" case |
| `https_aws` | HTTPS to s3.us-east-1 | provider-specific upstream issue |
| `https_ip` | HTTPS to a literal IP | separates DNS-dependent failures |
| `https_v6` | HTTPS over IPv6 (if you have a v6 route) | broken v6 stalls browsers while v4 tools look fine |

The *combination* is the diagnosis. Example: ICMP and DNS green while
`tcp_443` and `https_*` go red means your router's NAT table or your ISP is
eating TCP — a completely different conversation with support than "it's
down".

False-positive control: failed probes are re-confirmed once before an
incident opens (a single dropped ping is normal background noise), and
recovery requires 3 consecutive clean cycles.

## Install on a host (recommended)

Runs as a systemd **user** service — no root, works on immutable distros.
Needed: `bash`, `curl`, `ping`. Optional: `dig` (enables the per-resolver
DNS probes), `mtr` or `traceroute` (better snapshots), `notify-send`
(desktop popups). Everything is feature-detected; missing tools degrade
gracefully.

```bash
git clone <this-repo> && cd internet-diagnostic
./install.sh
```

Why host over container: the watchdog's value is seeing **exactly what your
apps see** — same network stack, same resolver config — and desktop
notifications need your session bus. Use the container only where that
trade-off makes sense (a headless box, a NAS).

## Install with Docker

```bash
docker compose up -d --build              # netwatch alone
docker compose --profile ntfy up -d       # + a LAN ntfy push server
```

Notes:

- **`network_mode: host` is required** (already set in the compose file). On
  a bridge network netwatch would probe Docker's NAT and report the Docker
  bridge as your "gateway" — the results would be meaningless.
- Desktop notifications don't work from a container; set
  `NETWATCH_NTFY_URL` instead (see Alerts below).
- Reports land in `./data/incidents/`.

## Usage

```bash
netwatch.sh              # run forever (what the service/container does)
netwatch.sh --once       # one probe cycle + full snapshot, printed to stdout
```

`--once` is the mid-outage panic button: instant layered status plus a deep
snapshot, exit code non-zero if anything is failing.

Host-install paths: log at `~/.local/share/netwatch/netwatch.log`, one
report per outage in `~/.local/share/netwatch/incidents/`, live view via
`journalctl --user -u netwatch -f`.

## Configuration (env vars)

| Variable | Default | Purpose |
|---|---|---|
| `NETWATCH_INTERVAL` | `5` | seconds between probe cycles |
| `NETWATCH_DIR` | `~/.local/share/netwatch` | data directory |
| `NETWATCH_NTFY_URL` | *(off)* | ntfy topic URL for push alerts, e.g. `http://<lan-ip>:8090/internet-alerts` |

## Alerts

- **Desktop**: automatic when `notify-send` exists — critical popup at
  incident open (with the failing probes), normal popup at recovery (with
  the verdict).
- **Phone**: run ntfy on your LAN (the compose `ntfy` profile does this),
  set `NETWATCH_NTFY_URL`, and subscribe in the ntfy Android app with the
  server set to your LAN address and **instant delivery** enabled — that
  makes the app hold a direct connection instead of relying on Google's
  internet-dependent push. iOS can't do instant delivery against
  self-hosted servers; expect delays there.

## Reading a report

Each incident report contains:

1. **Timeline** — one row per 5s cycle, `.`/`X` per probe, so you can watch
   the failure spread and recover.
2. **Verdict** — failure counts per probe and a plain-English diagnosis
   (LAN vs WAN vs DNS vs TCP/NAT vs TLS/MTU vs single-destination).
3. **Snapshot** — captured at incident start: interface/route/ARP state,
   ping statistics, curl timing splits (`dns=… connect=… tls=…`), verbose
   TLS handshake, and an mtr/traceroute path.

## Companion setup

netwatch pairs well with [Uptime Kuma](https://github.com/louislam/uptime-kuma)
mirroring the same layered targets (20s interval, 1 retry) for long-term
history and graphs: ping the gateway and 1.1.1.1, DNS via router and via
1.1.1.1, TCP to 1.1.1.1:443, HTTPS to `google.com/generate_204` and an
endpoint of a provider you care about. Wire its alerts to the same LAN ntfy
topic. During an outage the dashboard rows going red top-down mirror
netwatch's verdict, with graphs.

Caveat worth knowing: a suspend/resume or a deliberate router reboot looks
like an incident — check report timestamps against what you were doing.

## License

MIT

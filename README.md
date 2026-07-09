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

netwatch can only observe the WAN while it is running, so a host reboot or
power loss is a blind spot, not an internet outage. To keep that gap from
being misread, it refreshes a `last-alive` timestamp every cycle and writes a
`last-clean-shutdown` marker when it receives `SIGTERM`/`SIGINT` (a graceful
`systemctl stop`/reboot). On the next start it logs one of:

- `previous shutdown was CLEAN …` — graceful stop; host was simply off.
- `UNCLEAN restart …` — no marker, so power loss or crash; the gap's WAN
  status is unknown.

Either way it is explicitly **not** counted as a detected internet incident —
no report is opened for netwatch's own downtime.

## Configuration (env vars)

Machine-specific settings (your LAN ntfy URL, etc.) live in a gitignored
`.env`. Copy the template and edit it:

```sh
cp .env.example .env
```

docker-compose auto-loads `.env`; the desktop subscriber (`ntfy-toast.sh`)
sources a sibling `.env` if present. You can also set any of these directly in
the environment, which always overrides `.env`:

| Variable | Default | Purpose |
|---|---|---|
| `NETWATCH_INTERVAL` | `5` | seconds between probe cycles |
| `NETWATCH_DIR` | `~/.local/share/netwatch` | data directory |
| `NETWATCH_NTFY_URL` | *(off)* | ntfy topic URL for push alerts, e.g. `http://<lan-ip>:8090/internet-alerts` |
| `NETWATCH_DATA_DIR` | `./data` | (web dashboard) host path of the data dir to mount |
| `NETWATCH_WEB_PORT` | `8091` | (web dashboard) host port |
| `NETWATCH_WEB_IFACE` | *(placeholder)* | (web dashboard) LAN interface used in rendered fix commands |
| `NETWATCH_WEB_LAN_DNS` | *(placeholder)* | (web dashboard) LAN DNS servers used in rendered fix commands |

## Web dashboard

A small LAN-only dashboard (`web/`, stdlib Python, no dependencies) renders
the netwatch data dir read-only:

- **Live status banner** — green/red from the `last-alive` marker and any
  open incident, auto-refreshing every 5 s; a third state calls out when
  netwatch *itself* isn't running (internet state unknown ≠ outage).
- **Playbooks** — each incident's failing-probe set is matched against a
  knowledge base of known failure signatures (VPN DNS wipe, WAN outage,
  provider-only loss, conntrack, MTU, …) and the dashboard shows the
  diagnosis plus copy-pasteable fix commands *while the outage is
  happening*. Set `NETWATCH_WEB_IFACE`/`NETWATCH_WEB_LAN_DNS` in `.env` so
  the commands come out ready to paste.
- **Incident browser** — every report with verdict, timeline, and snapshot;
  incidents interrupted by a reboot are labeled as such.
- **Local playbook overlays** — the committed playbooks are deliberately
  generic. Drop TOML files in `playbooks.d/` (gitignored) to extend them
  with your environment's specifics — which VPN client eats your DNS, your
  ISP's known failure modes — or to add whole new playbooks with
  declarative probe-match rules. Overlay entries get a `local` badge and
  are re-read on change. Format: `playbooks.d/README.md`.

```sh
docker compose up -d --build web     # http://<lan-ip>:8091
```

Being LAN-hosted it stays reachable during an internet outage — same
reasoning as the LAN ntfy server.

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

## Desktop alerts on other PCs

The host running netwatch gets popups directly. To get the **same alerts on
other machines** on the home network — a Windows PC, a partner's laptop,
etc. — subscribe them to the LAN ntfy topic. Because ntfy is on your LAN,
these alerts are internet-independent, exactly like the phone push.

> **Why not just open the ntfy web app?** Its background push needs HTTPS
> (browser service workers won't run on a plain-HTTP LAN origin, and a
> `192.168.x.x` address doesn't get the `localhost` exception). A browser tab
> would only notify while it's open. The scripts in `subscribers/` instead
> stream the topic directly and fire **native OS toasts** in the background.
> One bonus of the streaming approach: a PC that was asleep during an outage
> still gets the alert on wake, recovered from the ntfy server's message cache.

All scripts take the server URL and topic via parameters/env; point them at
your ntfy server (default examples use `http://192.168.1.100:8090` /
`internet-alerts`).

### Windows — `subscribers/ntfy-toast.ps1` (PowerShell + BurntToast)

```powershell
Install-Module -Name BurntToast -Scope CurrentUser      # one-time
.\ntfy-toast.ps1 -Server http://192.168.1.100:8090 -Topic internet-alerts
```

Autostart at logon (runs hidden, survives reboots) — the script header has a
ready-to-paste `Register-ScheduledTask` snippet.

### Linux — `subscribers/ntfy-toast.sh` (notify-send)

```bash
mkdir -p ~/bin ~/.config/systemd/user
cp subscribers/ntfy-toast.sh ~/bin/
cp subscribers/ntfy-toast.service ~/.config/systemd/user/
# edit the Environment= lines in the unit to point at your server/topic
systemctl --user daemon-reload
systemctl --user enable --now ntfy-toast
```

### macOS — `subscribers/ntfy-toast.sh` (osascript)

The same script works on macOS (it auto-detects `osascript`; nothing extra to
install). Run it directly, or autostart with a launchd LaunchAgent at
`~/Library/LaunchAgents/com.netwatch.ntfy-toast.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.netwatch.ntfy-toast</string>
  <key>ProgramArguments</key>
  <array><string>/Users/you/bin/ntfy-toast.sh</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NTFY_SERVER</key><string>http://192.168.1.100:8090</string>
    <key>NTFY_TOPIC</key><string>internet-alerts</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
```

Then `launchctl load ~/Library/LaunchAgents/com.netwatch.ntfy-toast.plist`.

> Prefer an off-the-shelf app? The official `ntfy` CLI
> (`ntfy subscribe <url> <command>`) and the `ntfy-desktop` tray client both
> work against a self-hosted LAN server too — the scripts above just avoid any
> extra install and give native toasts out of the box.

## Reading a report

Each incident report contains:

1. **Timeline** — one row per 5s cycle, `.`/`X` per probe, so you can watch
   the failure spread and recover.
2. **Verdict** — failure counts per probe and a plain-English diagnosis
   (LAN vs WAN vs DNS vs TCP/NAT vs TLS/MTU vs single-destination). The DNS
   case is split further: if the system resolver fails while direct `dig`
   to *both* the router and 1.1.1.1 still answers, the verdict is **system
   resolver redirected** — your resolver path was hijacked (typically a VPN
   pushing all DNS to its own server) rather than the network or ISP breaking.
3. **Snapshot** — captured at incident start: interface/route/ARP state,
   ping statistics, curl timing splits (`dns=… connect=… tls=…`), verbose
   TLS handshake, an mtr/traceroute path, and VPN / DNS-redirect indicators
   (a tunnel address on `lo`, a `tun`/`wg` device, or a resolved `~.`
   catch-all routing domain).

## Companion setup

netwatch pairs well with [Uptime Kuma](https://github.com/louislam/uptime-kuma)
mirroring the same layered targets (20s interval, 1 retry) for long-term
history and graphs: ping the gateway and 1.1.1.1, DNS via router and via
1.1.1.1, TCP to 1.1.1.1:443, HTTPS to `google.com/generate_204` and an
endpoint of a provider you care about. Wire its alerts to the same LAN ntfy
topic. During an outage the dashboard rows going red top-down mirror
netwatch's verdict, with graphs.

> **Kuma 1.23.x + ntfy gotcha:** the ntfy provider builds a "view" action
> button from the monitor's URL field, which ping/DNS/port monitors don't
> have — the ntfy server rejects those alerts with HTTP 400 and they
> **silently never arrive** (Kuma's "Test" button works, because test sends
> skip the button). Workaround: set each non-HTTP monitor's URL field to
> any valid URL, e.g. its own dashboard link
> (`http://<kuma-host>/dashboard/<monitor-id>`). Don't trust the test
> button — verify by making a monitor genuinely fail once (point it at
> `192.0.2.1` briefly) and confirming the alert reaches your phone.

Caveat worth knowing: a suspend/resume or a deliberate router reboot looks
like an incident — check report timestamps against what you were doing.

## Prior art & how netwatch differs

The "is my internet down / log my ISP outages" space is well-trodden. netwatch
isn't trying to be another up/down logger or a metrics dashboard — its niche is
**cross-probe classification** (naming *which layer* broke) plus
**internet-independent alerting**. If that's not what you need, reach for a
mature tool instead:

- **Latency/loss graphing over time** → [SmokePing](https://github.com/oetiker/SmokePing)
- **Dashboards / full metrics stack** → [internet-monitoring](https://github.com/maxandersen/internet-monitoring) or [internet-pi](https://github.com/geerlingguy/internet-pi) (Prometheus + Grafana + blackbox-exporter)
- **Service/status-page uptime monitoring** → [Uptime Kuma](https://github.com/louislam/uptime-kuma), [Gatus](https://github.com/TwiN/gatus)
- **Plain ping logging for an ISP support case** → [pinguno](https://github.com/twome/pinguno)

The closest neighbors each capture *one* of netwatch's ideas but not the whole:
[WirePeep](https://github.com/menees/WirePeep) checks layered targets (gateway /
public DNS / modem) but is a Windows GUI that reports downtime windows, not
verdicts; [wanstatus](https://github.com/cjnaz/wanstatus) splits WAN from LAN but
alerts over (internet-dependent) email/SMS;
[gitbls/internet-monitor](https://github.com/gitbls/internet-monitor) ships as a
systemd service with action hooks but does no classification and no LAN-local
push.

What I haven't found packaged together elsewhere: the **DNS-hijack / VPN-resolver
redirection** and **Cloudflare-only (partial-anycast) routing** verdicts,
**LAN-hosted alerting by design** so notifications survive the outage they
report, and **self-downtime accounting** (liveness markers so time the host was
off is never logged as an internet outage) — all as a single ~500-line bash
script running as a systemd *user* service on an immutable distro.

## License

MIT

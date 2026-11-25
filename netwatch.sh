#!/usr/bin/env bash
#
# netwatch — layered internet-connectivity watchdog
#
# Probes the network every few seconds at several layers (gateway, WAN ICMP,
# DNS, raw TCP, HTTPS/TLS to multiple destinations). When any probe fails it
# opens an incident: logs a pass/fail matrix every cycle, captures a deep
# diagnostic snapshot, and on recovery writes a markdown report with a
# verdict about which layer broke.
#
# Usage:
#   netwatch.sh            run forever (intended for systemd)
#   netwatch.sh --once     single probe cycle + deep snapshot to stdout
#
# Config (env vars):
#   NETWATCH_DIR        data dir (default ~/.local/share/netwatch)
#   NETWATCH_INTERVAL   seconds between probe cycles (default 5)
#   NETWATCH_NTFY_URL   ntfy topic URL for push alerts, e.g.
#                       http://<lan-ip>:8090/internet-alerts (default: off).
#                       Point it at a LAN-hosted ntfy server — an internet
#                       service can't deliver alerts about the internet being
#                       down.
#   NETWATCH_SERVICE_PROBES
#                       optional third-party service probes, space/comma-
#                       separated name=url pairs (default: off), e.g.
#                         claude=statuspage:https://status.claude.com
#                       A "statuspage:" prefix queries the statuspage.io v2
#                       API and maps the provider's indicator: "none" = up,
#                       "minor"/"maintenance" = degraded, "major"/"critical"
#                       (or API unreachable) = down. An unresolved incident
#                       shows as degraded even when the indicator is "none".
#                       A "statuspage-major:" prefix reads the same API but
#                       ignores the routine noise of large providers
#                       (Cloudflare, Akamai sit at "minor" most days):
#                       "none"/"minor"/"maintenance" and open incidents = up,
#                       "major" = degraded, "critical" (or unreachable) = down.
#                       A "slackstatus:" prefix reads Slack's own status API
#                       (/api/v2.0.0/current): "ok" = up, an active incident
#                       or notice = degraded, an active outage (or API
#                       unreachable) = down.
#                       A plain http(s) url is a binary reachability check
#                       (up/down only): any HTTP status below 500 is up —
#                       redirects and 4xx prove the service answered — while
#                       5xx, timeouts and connect failures are down.
#                       Informational only: shown on the web dashboard, never
#                       opens incidents, never alerts — answers "is it me or
#                       them?" when a SaaS you rely on is having a bad day.

set -u

DATA_DIR="${NETWATCH_DIR:-$HOME/.local/share/netwatch}"
INTERVAL="${NETWATCH_INTERVAL:-5}"
RECOVERY_CYCLES=3      # consecutive clean cycles required to close an incident
PING_TIMEOUT=2
CURL_TIMEOUT=5

NTFY_URL="${NETWATCH_NTFY_URL:-}"

INCIDENT_DIR="$DATA_DIR/incidents"
LOG_FILE="$DATA_DIR/netwatch.log"

# Liveness markers. LAST_ALIVE_FILE is refreshed every probe cycle, so it
# bounds the moment netwatch stopped to within one INTERVAL. SHUTDOWN_MARKER is
# written only on a graceful stop (SIGTERM/SIGINT). On the next start the gap
# between them tells us whether the host was shut down cleanly or lost power /
# crashed — either way it's netwatch's own downtime, NOT an internet outage,
# because nothing was probing the WAN during the gap.
LAST_ALIVE_FILE="$DATA_DIR/last-alive"
SHUTDOWN_MARKER="$DATA_DIR/last-clean-shutdown"
STAMP_FMT='+%s %Y-%m-%dT%H:%M:%S%z'

have() { command -v "$1" >/dev/null 2>&1; }

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$LOG_FILE"; }

# Desktop popup — works from the systemd user service as long as the session
# bus socket exists at its default path. Silently unavailable in containers.
# notify-send blocks on a D-Bus round trip with no timeout of its own; if the
# notification daemon is wedged that stalls the probe loop, so bound it.
desktop_notify() {
    have notify-send || return 0
    DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus}" \
        timeout 5 notify-send --app-name=netwatch --urgency="$1" "$2" "$3" 2>/dev/null || true
}

ntfy_notify() {
    [[ -n $NTFY_URL ]] || return 0
    local prio=default
    [[ $1 == critical ]] && prio=high
    curl -s -o /dev/null --max-time 5 -H "Title: $2" -H "Priority: $prio" \
        -d "$3" "$NTFY_URL" || true
}

notify() { desktop_notify "$1" "$2" "$3"; ntfy_notify "$1" "$2" "$3"; }

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

GATEWAY=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
HAS_V6=0
[[ -n $(ip -6 route show default 2>/dev/null) ]] && HAS_V6=1
HAS_DIG=0
have dig && HAS_DIG=1

# Probe order matters only for display. Each probe_<name> function must exit
# 0 on success within its own timeout.
PROBES=(gw_ping wan_ping_cf wan_ping_gg dns_system tcp_443 https_google https_cloudflare https_aws https_ip)
[[ $HAS_DIG -eq 1 ]] && PROBES+=(dns_router dns_public)
[[ $HAS_V6 -eq 1 ]] && PROBES+=(https_v6)

# --- ICMP ---
probe_gw_ping()    { ping -n -c1 -W"$PING_TIMEOUT" "$GATEWAY"; }
probe_wan_ping_cf() { ping -n -c1 -W"$PING_TIMEOUT" 1.1.1.1; }
probe_wan_ping_gg() { ping -n -c1 -W"$PING_TIMEOUT" 8.8.8.8; }

# --- DNS ---
# dns_system goes through nsswitch/systemd-resolved — the same path apps use
# (may be answered from cache; that is also true for apps, so it's the right
# measurement). The dig probes use a random subdomain to defeat caching;
# NXDOMAIN still exits 0, so any answer at all counts as "resolver reachable".
probe_dns_system() { timeout 3 getent ahosts google.com; }
probe_dns_router() { dig +time=2 +tries=1 @"$GATEWAY" "r$RANDOM.netwatch-probe.example.com" >/dev/null; }
probe_dns_public() { dig +time=2 +tries=1 @1.1.1.1 "r$RANDOM.netwatch-probe.example.com" >/dev/null; }

# --- TCP / TLS / HTTP ---
# tcp_443 is a raw TCP connect with no DNS and no TLS — separates "TCP itself
# is blocked" from "TLS handshakes fail". https_ip does TLS to a literal IP,
# removing DNS from the equation entirely.
probe_tcp_443()        { timeout 3 bash -c '> /dev/tcp/1.1.1.1/443'; }
probe_https_google()    { curl -s -o /dev/null --max-time "$CURL_TIMEOUT" https://www.google.com/generate_204; }
probe_https_cloudflare() { curl -s -o /dev/null --max-time "$CURL_TIMEOUT" https://cp.cloudflare.com/; }
probe_https_aws()       { curl -s -o /dev/null --max-time "$CURL_TIMEOUT" https://s3.us-east-1.amazonaws.com/; }
probe_https_ip()        { curl -s -o /dev/null --max-time "$CURL_TIMEOUT" https://1.1.1.1/; }
probe_https_v6()        { curl -6 -s -o /dev/null --max-time "$CURL_TIMEOUT" https://www.google.com/generate_204; }

# ---------------------------------------------------------------------------
# Service probes — optional, user-defined, informational only
# ---------------------------------------------------------------------------
# Parsed from NETWATCH_SERVICE_PROBES (see header). Deliberately separate
# from PROBES: service results never touch CYCLE_FAILED, incidents, verdicts,
# or notifications — a SaaS outage is not an internet outage. Current state
# is published to $SERVICE_STATUS_FILE for the web dashboard, and probing is
# paced to roughly every 30s (statuspage APIs cache ~60s; probing a third
# party every 5s is rude and buys nothing).

SERVICE_STATUS_FILE="$DATA_DIR/service-status"
SERVICE_DOWN_CYCLES=2   # consecutive non-up service cycles before leaving "up"
SERVICE_EVERY=$(( (30 + INTERVAL - 1) / INTERVAL ))
(( SERVICE_EVERY < 1 )) && SERVICE_EVERY=1

SERVICE_NAMES=()
declare -A SERVICE_URL SERVICE_KIND SERVICE_STATE SERVICE_SINCE SERVICE_STREAK \
           SERVICE_CYCLE_RESULT
SERVICE_DUE=0
SERVICE_SUSPENDED=0

parse_service_probes() {
    local raw="${NETWATCH_SERVICE_PROBES:-}" pairs=() pair name url kind
    raw=${raw//,/ }
    # read -ra never glob-expands — URLs legitimately contain ? and *
    read -ra pairs <<< "$raw" || true
    for pair in "${pairs[@]}"; do
        [[ -z $pair ]] && continue
        name=${pair%%=*}      # split on the FIRST = only; query strings have =
        url=${pair#*=}
        if [[ $pair != *=* || ! $name =~ ^[A-Za-z0-9_-]+$ || -z $url ]]; then
            log "service probe skipped — malformed entry: $pair"
            continue
        fi
        kind=https
        case $url in
            statuspage-major:*) kind=statuspage-major; url=${url#statuspage-major:} ;;
            statuspage:*)       kind=statuspage;       url=${url#statuspage:} ;;
            slackstatus:*)      kind=slackstatus;      url=${url#slackstatus:} ;;
        esac
        if [[ $url != http://* && $url != https://* ]]; then
            log "service probe skipped — not an http(s) url: $pair"
            continue
        fi
        SERVICE_NAMES+=("$name")
        SERVICE_URL[$name]=${url%/}
        SERVICE_KIND[$name]=$kind
        SERVICE_STATE[$name]=up
        SERVICE_SINCE[$name]=$(date +%s)
        SERVICE_STREAK[$name]=0
    done
}
mkdir -p "$DATA_DIR"   # parse may log() before run_daemon's mkdir
parse_service_probes

# Prints the observed level on stdout: up | degraded | down.
probe_service() {
    local url=${SERVICE_URL[$1]} kind=${SERVICE_KIND[$1]} body ind code
    if [[ $kind == statuspage || $kind == statuspage-major ]]; then
        # summary.json, not status.json: it also lists unresolved incidents.
        # No jq in the minimal image — strip whitespace so one grep handles
        # compact and pretty-printed JSON.
        body=$(curl -s -L --max-redirs 3 --max-time "$CURL_TIMEOUT" "$url/api/v2/summary.json" \
            | tr -d '[:space:]')
        ind=$(grep -Eo '"indicator":"[a-z]+"' <<<"$body" | head -n1)
        ind=${ind%\"}; ind=${ind##*\"}
        if [[ $kind == statuspage-major ]]; then
            # Large providers always have some narrow product or regional
            # issue open, so "minor" and open incidents say nothing about
            # whether the internet at large is affected. Only the top two
            # indicator levels count.
            case $ind in
                none|minor|maintenance) echo up ;;
                major)                  echo degraded ;;
                *)                      echo down ;;   # critical, unreachable, unparseable
            esac
            return
        fi
        # Providers often drop the indicator to "none" while an incident is
        # still open (e.g. "monitoring"), so an open incident counts as at
        # least degraded.
        if [[ $ind == none && $body == *'"incidents":[{'* ]]; then
            ind=minor
        fi
        case $ind in
            none)              echo up ;;
            minor|maintenance) echo degraded ;;
            *)                 echo down ;;   # major/critical, unreachable, unparseable
        esac
    elif [[ $kind == slackstatus ]]; then
        # Slack runs its own status API, not statuspage.io. Top-level
        # "status" is "ok" with nothing open, or "active" with entries in
        # active_incidents, each typed "outage", "incident" or "notice".
        body=$(curl -s -L --max-redirs 3 --max-time "$CURL_TIMEOUT" "$url/api/v2.0.0/current" \
            | tr -d '[:space:]')
        if [[ $body == *'"status":"ok"'* && $body == *'"active_incidents":[]'* ]]; then
            echo up
        elif [[ $body == *'"active_incidents":['* && $body == *'"type":"outage"'* ]]; then
            echo down
        elif [[ $body == *'"active_incidents":[{'* ]]; then
            echo degraded
        else
            echo down   # unreachable or unparseable
        fi
    else
        # Plain reachability has no degraded signal to read — binary only.
        # Check the status code, not just curl's exit status: a SaaS outage
        # usually still answers, with a 5xx from its front door. 3xx/4xx
        # count as up — login pages redirect, and APIs 401/404 a bare GET.
        # 000 = no HTTP response at all (DNS, connect, TLS or timeout).
        code=$(curl -s -o /dev/null --max-time "$CURL_TIMEOUT" -w '%{http_code}' "$url")
        if [[ $code =~ ^[1-4][0-9][0-9]$ ]]; then
            echo up
        else
            echo down
        fi
    fi
}

service_update_states() {
    local s observed prev
    for s in "${SERVICE_NAMES[@]}"; do
        observed=${SERVICE_CYCLE_RESULT[$s]:-down}
        prev=${SERVICE_STATE[$s]}
        if [[ $observed == up ]]; then
            if [[ $prev != up ]]; then
                log "SERVICE UP — $s after ~$(( $(date +%s) - ${SERVICE_SINCE[$s]} ))s"
                SERVICE_SINCE[$s]=$(date +%s)
            fi
            SERVICE_STATE[$s]=up
            SERVICE_STREAK[$s]=0
        else
            # Debounce leaving "up"; once non-up, follow the observed level
            # directly (degraded<->down needs no second confirmation).
            SERVICE_STREAK[$s]=$(( ${SERVICE_STREAK[$s]} + 1 ))
            if [[ $prev != "$observed" ]] && (( ${SERVICE_STREAK[$s]} >= SERVICE_DOWN_CYCLES )); then
                SERVICE_STATE[$s]=$observed
                SERVICE_SINCE[$s]=$(date +%s)
                log "SERVICE ${observed^^} — $s (${SERVICE_KIND[$s]} ${SERVICE_URL[$s]}) — informational, not an internet incident"
            fi
        fi
    done
}

# Atomic publish for the dashboard (which reads the data dir from another
# container): temp file in the SAME directory so mv is a rename, not a copy.
# Header line = write time; then one line per service:
#   name state since_epoch kind url        (state: up|degraded|down|unknown)
write_service_status() {
    local tmp="$SERVICE_STATUS_FILE.tmp" s state
    {
        date "$STAMP_FMT"
        for s in "${SERVICE_NAMES[@]}"; do
            state=${SERVICE_STATE[$s]}
            (( SERVICE_SUSPENDED )) && state=unknown
            printf '%s %s %s %s %s\n' "$s" "$state" "${SERVICE_SINCE[$s]}" \
                "${SERVICE_KIND[$s]}" "${SERVICE_URL[$s]}"
        done
    } > "$tmp" 2>/dev/null || return 0
    mv -f "$tmp" "$SERVICE_STATUS_FILE" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Probe cycle — all probes in parallel; cycle time is bounded by the slowest
# timeout (~5s), not the sum.
# ---------------------------------------------------------------------------

CYCLE_FAILED=()

run_cycle() {
    local tmp p pids=()
    tmp=$(mktemp -d)
    for p in "${PROBES[@]}"; do
        ( "probe_$p" >/dev/null 2>&1 && : > "$tmp/$p.ok" ) &
        pids+=($!)
    done
    # Service probes join the same parallel batch on their due cycles but
    # collect into their own result set — never CYCLE_FAILED. The svc.
    # marker prefix avoids collisions with internet-probe names.
    if (( SERVICE_DUE )); then
        for p in "${SERVICE_NAMES[@]}"; do
            ( probe_service "$p" > "$tmp/svc.$p.result" 2>/dev/null ) &
            pids+=($!)
        done
    fi
    # wait on probe pids only — a bare `wait` would also block on the
    # background snapshot job and stall probing mid-incident
    wait "${pids[@]}"
    CYCLE_FAILED=()
    for p in "${PROBES[@]}"; do
        [[ -e "$tmp/$p.ok" ]] || CYCLE_FAILED+=("$p")
    done
    if (( SERVICE_DUE )); then
        local r
        for p in "${SERVICE_NAMES[@]}"; do
            r=$(cat "$tmp/svc.$p.result" 2>/dev/null)
            [[ $r == up || $r == degraded || $r == down ]] || r=down
            SERVICE_CYCLE_RESULT[$p]=$r
        done
    fi
    rm -rf "$tmp"
}

# A single dropped ICMP packet is normal internet noise — before opening an
# incident, re-run just the failed probes once and keep only repeat failures.
confirm_failures() {
    local still=() p
    sleep 1
    for p in "${CYCLE_FAILED[@]}"; do
        "probe_$p" >/dev/null 2>&1 || still+=("$p")
    done
    CYCLE_FAILED=()
    [[ ${#still[@]} -gt 0 ]] && CYCLE_FAILED=("${still[@]}")
}

# Probes that routinely miss a single cycle without anything actually being
# down, so a lone miss isn't worth an incident report and a phone alert:
#   dns_router — the router's DNS forwarder dropping one query is common,
#     self-healing noise, and rarely affects real browsing (the system resolver
#     often isn't the gateway).
#   https_aws  — s3.us-east-1 periodically answers fine but slowly, straddling
#     CURL_TIMEOUT. Observed 2026-08-03: a 2.3s DNS lookup in one sample and a
#     4.2s TLS handshake in another, while www.google.com stayed at 0.05s on the
#     same link in the same moment. That's latency at the destination, not loss.
#   wan_ping_cf, wan_ping_gg, dns_public — each sends exactly one packet, so
#     low upstream loss trips them on its own. Observed 2026-09-24: 5–12% loss
#     inside the ISP's transit opened ~30 one-cycle incidents in an evening
#     while every TCP/HTTPS probe stayed green. A real WAN drop fails several
#     probes at once, so it never looks like a lone miss.
# A genuine failure persists into the next cycle; a blip is gone by then.
DEBOUNCE_PROBES=(dns_router https_aws wan_ping_cf wan_ping_gg dns_public)

# True for a confirmed-failure cycle whose ONLY failing probe is debounceable.
single_flaky_probe() {
    [[ ${#CYCLE_FAILED[@]} -eq 1 ]] || return 1
    local p
    for p in "${DEBOUNCE_PROBES[@]}"; do
        [[ ${CYCLE_FAILED[0]} == "$p" ]] && return 0
    done
    return 1
}

cycle_matrix_line() {
    local p marks=""
    for p in "${PROBES[@]}"; do
        local mark="."
        local f
        for f in "${CYCLE_FAILED[@]:-}"; do [[ $f == "$p" ]] && mark="X"; done
        marks+="$mark"
    done
    printf '%s  %s  fail: %s' "$(date +%H:%M:%S)" "$marks" "${CYCLE_FAILED[*]:-none}"
}

# ---------------------------------------------------------------------------
# Deep snapshot — captured once per incident (and in --once mode)
# ---------------------------------------------------------------------------

section() {
    local title=$1; shift
    printf '\n--- %s ---\n$ %s\n' "$title" "$*"
    timeout 30 "$@" 2>&1
}

CURL_TIMING_FMT='dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s http=%{http_code}\n'

# Heuristics for "something is redirecting DNS / tunneling" — most often a VPN.
# Prints one indicator per line; no output means none detected. A VPN that
# pushes all DNS to its own server breaks the system resolver (getent, hostname
# HTTPS) while leaving direct `dig @server` queries — and the rest of the
# network — working, which is exactly the dns_system-fails/dig-probes-pass
# pattern the verdict keys on.
vpn_indicators() {
    # Userspace VPNs often park their tunnel address on lo rather than a tun dev
    ip -o addr show dev lo 2>/dev/null \
        | awk '$4 !~ /^127\./ && $4 !~ /^::1\// {print "non-loopback address on lo: " $4}'
    # Kernel tunnel interfaces
    ip -br link show 2>/dev/null \
        | awk '$1 ~ /^(tun|tap|wg|ppp|utun)[0-9]*/ {print "tunnel interface present: " $1}'
    # A resolved link advertising the catch-all (~.) routing domain captures ALL
    # name resolution for the host. resolvectl talks to systemd-resolved over
    # D-Bus and blocks indefinitely when resolved is wedged — which is exactly
    # the state a VPN teardown leaves it in, i.e. the incident this call is
    # meant to characterize — so bound it or it stalls the probe loop.
    have resolvectl && timeout 5 resolvectl domain 2>/dev/null \
        | awk '/~\./ {print "resolver catch-all routing domain: " $0}'
}

snapshot() {
    echo "### Deep snapshot at $(date -Is)"
    section "Interfaces"      ip -br addr
    section "Default routes"  ip route show default
    section "IPv6 routes"     ip -6 route show default
    section "Neighbors (ARP)" ip neigh
    have resolvectl && section "resolvectl status" resolvectl status
    printf '\n--- VPN / DNS-redirect indicators ---\n'
    vpn_indicators | grep . || echo "(none detected)"
    section "Ping gateway x5"  ping -n -c5 -i0.3 -W2 "$GATEWAY"
    section "Ping 1.1.1.1 x5"  ping -n -c5 -i0.3 -W2 1.1.1.1
    section "curl timing google.com (IPv4)" \
        curl -4 -sS -o /dev/null --max-time 10 -w "$CURL_TIMING_FMT" https://www.google.com/generate_204
    [[ $HAS_V6 -eq 1 ]] && section "curl timing google.com (IPv6)" \
        curl -6 -sS -o /dev/null --max-time 10 -w "$CURL_TIMING_FMT" https://www.google.com/generate_204
    section "curl timing s3.us-east-1" \
        curl -sS -o /dev/null --max-time 10 -w "$CURL_TIMING_FMT" https://s3.us-east-1.amazonaws.com/
    section "curl verbose google.com (TLS detail)" \
        curl -sv -o /dev/null --max-time 10 https://www.google.com/generate_204
    # Trace every destination family the probes cover, not just Cloudflare.
    # In a destination-specific incident the 1.1.1.1 trace is the one path
    # still working — tracing only it proves nothing. The traces to 8.8.8.8
    # and s3.us-east-1 are what pin the failure to an upstream hop.
    local tracer=() target
    if have mtr; then
        tracer=(mtr -rwbz -c3)
    elif have traceroute; then
        tracer=(traceroute -n -w2 -q1)
    elif have tracepath; then
        tracer=(tracepath -n)
    fi
    if [[ ${#tracer[@]} -gt 0 ]]; then
        # Run the traces concurrently: incident_close waits on the snapshot
        # before writing the report, and three serial traces (~25s, dominated
        # by unresponsive hops timing out) would stall the probe loop that
        # long after recovery. Output is buffered per target and emitted in a
        # fixed order so reports stay diffable.
        local td pids=(); td=$(mktemp -d)
        for target in 1.1.1.1 8.8.8.8 s3.us-east-1.amazonaws.com; do
            section "${tracer[0]} to $target" "${tracer[@]}" "$target" \
                > "$td/$target" 2>&1 &
            pids+=($!)
        done
        # Wait on these PIDs specifically, not a bare `wait`: --once calls
        # snapshot in the main shell, which may own other background jobs.
        wait "${pids[@]}"
        for target in 1.1.1.1 8.8.8.8 s3.us-east-1.amazonaws.com; do
            cat "$td/$target"
        done
        rm -rf "$td"
    fi
}

# ---------------------------------------------------------------------------
# Verdict — classify the incident from per-probe failure counts
# ---------------------------------------------------------------------------

declare -A FAIL_COUNT
INCIDENT_CYCLES=0

fc() { echo "${FAIL_COUNT[$1]:-0}"; }

verdict() {
    local total=$INCIDENT_CYCLES
    echo "Probe failure counts over $total incident cycle(s):"
    local p
    for p in "${PROBES[@]}"; do
        printf '  %-18s %s/%s\n' "$p" "$(fc "$p")" "$total"
    done
    echo

    local icmp_wan_ok=1 dns_ok=1
    [[ $(fc wan_ping_cf) -gt 0 && $(fc wan_ping_gg) -gt 0 ]] && icmp_wan_ok=0
    [[ $(fc dns_system) -gt 0 ]] && dns_ok=0

    if [[ $(fc gw_ping) -gt 0 ]]; then
        echo "VERDICT: LAN problem — the router itself ($GATEWAY) stopped answering."
        echo "Suspect: router reboot/crash, switch, cabling, or local interface."
    elif [[ $icmp_wan_ok -eq 0 ]]; then
        echo "VERDICT: WAN outage — gateway reachable but nothing past it."
        echo "Suspect: modem/ONT resync or ISP-side outage."
    elif [[ $dns_ok -eq 0 ]]; then
        if [[ $HAS_DIG -eq 1 && $(fc dns_router) -eq 0 && $(fc dns_public) -eq 0 ]]; then
            echo "VERDICT: system resolver redirected — resolution via the system"
            echo "resolver failed while direct DNS queries to BOTH the router and"
            echo "1.1.1.1 succeeded. The network, the ISP, and the DNS servers are"
            echo "fine; something redirected only this host's resolver path. Most"
            echo "often a VPN pushing all DNS to its own server (see the VPN / DNS-"
            echo "redirect indicators in the snapshot). The fix is VPN/resolver-side."
        elif [[ $HAS_DIG -eq 1 && $(fc dns_router) -gt 0 && $(fc dns_public) -eq 0 ]]; then
            echo "VERDICT: DNS failure — raw connectivity fine, name resolution broken."
            echo "Router's DNS forwarder failed while public DNS (1.1.1.1) worked —"
            echo "pointing your machine/DHCP at 1.1.1.1/8.8.8.8 directly would dodge this."
        else
            echo "VERDICT: DNS failure — raw connectivity fine, name resolution broken."
        fi
        if [[ -n $VPN_AT_OPEN ]]; then
            echo "VPN/redirect indicators captured at incident start:"
            printf '%s\n' "$VPN_AT_OPEN" | sed 's/^/  - /'
        fi
    elif [[ $(fc https_google) -gt 0 || $(fc https_cloudflare) -gt 0 || $(fc https_aws) -gt 0 ]]; then
        if [[ $(fc https_google) -eq 0 && $(fc https_cloudflare) -eq 0 && $(fc https_aws) -gt 0 ]]; then
            echo "VERDICT: destination-specific — only AWS us-east-1 failed; everything"
            echo "else was healthy. Not your network; upstream provider issue."
        elif [[ $(fc https_google) -eq 0 && $(fc https_aws) -eq 0 && $(fc https_cloudflare) -gt 0 ]]; then
            # Several probes (wan_ping_cf, tcp_443, https_ip, dns_public) all
            # target 1.1.1.1, so a Cloudflare-only reachability loss would
            # otherwise trip the tcp_443 "conntrack" branch below. Google AND
            # AWS staying up proves the rest of the internet — and your TCP
            # stack — were fine, so the only thing broken is the path to one
            # anycast provider.
            echo "VERDICT: single upstream unreachable — only Cloudflare/1.1.1.1 was"
            echo "affected (ping 1.1.1.1, raw TCP + TLS to 1.1.1.1, cp.cloudflare.com,"
            echo "and @1.1.1.1 DNS all failed) while Google, AWS, and 8.8.8.8 stayed up"
            echo "the whole time. The rest of the internet was fine: this is a routing/"
            echo "peering failure on the path to Cloudflare, upstream of you (see the"
            echo "mtr to 1.1.1.1 in the snapshot) — NOT your router or a TCP/conntrack"
            echo "problem. If 1.1.1.1 is your primary resolver, put a non-Cloudflare"
            echo "server first so a Cloudflare flap doesn't take your DNS with it."
        elif [[ $(fc https_cloudflare) -eq 0 && $(fc wan_ping_cf) -eq 0 \
                && $(fc tcp_443) -eq 0 && $(fc https_ip) -eq 0 \
                && $(fc dns_public) -eq 0 ]]; then
            # Mirror image of the Cloudflare-only branch above. Every probe
            # that stayed green targets 1.1.1.1; the ones that failed target
            # Google or AWS. A local fault (router, NAT, MTU, resolver) cannot
            # spare one destination and break another, so the fault is upstream.
            echo "VERDICT: destination-specific — the paths to Google and/or AWS"
            echo "failed while every Cloudflare-path probe (ping 1.1.1.1, raw TCP"
            echo "443, TLS to 1.1.1.1, cp.cloudflare.com, @1.1.1.1 DNS) stayed green"
            echo "throughout. Your LAN, router and ISP first hops were therefore"
            echo "fine — a local fault could not spare one destination and break"
            echo "another. This is a routing/peering failure upstream of you."
            echo "Compare the traces to 8.8.8.8 and s3.us-east-1 against the one to"
            echo "1.1.1.1 in the snapshot to see which hop the working and broken"
            echo "paths diverge at."
            if [[ $(fc wan_ping_gg) -gt 0 ]]; then
                echo "ICMP to 8.8.8.8 failed too, so this is packets not reaching the"
                echo "destination — not a TLS, MTU or middlebox problem."
            fi
        elif [[ $(fc tcp_443) -gt 0 ]]; then
            echo "VERDICT: TCP broken while ICMP and DNS worked — raw TCP connects to"
            echo "port 443 failed. This matches your earlier outage (ping + dig OK, no"
            echo "websites). Suspect: router NAT/conntrack table exhaustion or ISP"
            echo "dropping TCP. Check the router's connection-table stats / uptime."
        else
            echo "VERDICT: HTTPS failed on paths whose TCP was never independently"
            echo "tested — the raw TCP probe only connects to 1.1.1.1, so it passing"
            echo "does not prove TCP reached the destinations that broke. Read the"
            echo "connect= field in the curl timing sections: connect=0 means the TCP"
            echo "handshake itself never completed (routing/filtering upstream), while"
            echo "a non-zero connect= with an empty tls= means the TLS handshake"
            echo "stalled — MTU/fragmentation or an intercepting middlebox."
        fi
        if [[ $HAS_V6 -eq 1 && $(fc https_v6) -gt 0 && $(fc https_google) -eq 0 ]]; then
            echo "Note: only IPv6 HTTPS failed — browsers prefer IPv6, so a broken v6"
            echo "path stalls page loads while v4 tools look fine."
        fi
    else
        echo "VERDICT: transient blip — failures didn't persist or didn't fit a"
        echo "pattern. Check the timeline matrix above."
    fi
}

# ---------------------------------------------------------------------------
# Incident lifecycle
# ---------------------------------------------------------------------------

INCIDENT_FILE=""
INCIDENT_START=0
SNAP_PID=""
VPN_AT_OPEN=""

incident_open() {
    mkdir -p "$INCIDENT_DIR"
    INCIDENT_START=$(date +%s)
    INCIDENT_FILE="$INCIDENT_DIR/incident-$(date +%Y%m%d-%H%M%S).md"
    INCIDENT_CYCLES=0
    FAIL_COUNT=()
    # Captured now (foreground), while a VPN that triggered the incident is most
    # likely still attached — the daemon may restart/recover before close.
    VPN_AT_OPEN=$(vpn_indicators)
    log "INCIDENT OPENED — failing: ${CYCLE_FAILED[*]} — $INCIDENT_FILE"
    notify critical "Internet incident" "Failing: ${CYCLE_FAILED[*]}"
    {
        echo "# netwatch incident — $(date -Is)"
        echo
        echo "First failing probes: ${CYCLE_FAILED[*]}"
        echo
        echo "## Timeline"
        echo
        echo '```'
        echo "probes: ${PROBES[*]}"
        echo "(. = ok, X = fail)"
    } > "$INCIDENT_FILE"
    # Snapshot runs in the background so the probe cadence isn't interrupted;
    # merged into the report at close.
    ( snapshot > "$INCIDENT_FILE.snapshot" 2>&1 ) &
    SNAP_PID=$!
}

incident_record_cycle() {
    INCIDENT_CYCLES=$((INCIDENT_CYCLES + 1))
    local p
    for p in "${CYCLE_FAILED[@]:-}"; do
        [[ -n $p ]] && FAIL_COUNT[$p]=$(( ${FAIL_COUNT[$p]:-0} + 1 ))
    done
    cycle_matrix_line >> "$INCIDENT_FILE"
    echo >> "$INCIDENT_FILE"
}

incident_close() {
    local duration=$(( $(date +%s) - INCIDENT_START ))
    [[ -n $SNAP_PID ]] && wait "$SNAP_PID" 2>/dev/null
    {
        echo '```'
        echo
        echo "## Verdict"
        echo
        echo '```'
        verdict
        echo '```'
        echo
        echo "Duration: ~${duration}s (recovery confirmed after $RECOVERY_CYCLES clean cycles)"
        echo
        echo "## Snapshot (captured at incident start)"
        echo
        echo '```'
        cat "$INCIDENT_FILE.snapshot" 2>/dev/null
        echo '```'
    } >> "$INCIDENT_FILE"
    rm -f "$INCIDENT_FILE.snapshot"
    log "INCIDENT CLOSED — duration ~${duration}s — report: $INCIDENT_FILE"
    notify normal "Internet recovered after ~${duration}s" \
        "$(verdict | grep -m1 '^VERDICT:' || echo 'See report') — $INCIDENT_FILE"
    INCIDENT_FILE=""
}

# ---------------------------------------------------------------------------
# Liveness / clean-shutdown markers
# ---------------------------------------------------------------------------

# Refreshed every cycle: "netwatch was alive and probing as of this time".
touch_alive() { date "$STAMP_FMT" > "$LAST_ALIVE_FILE" 2>/dev/null || true; }

# SIGTERM is what systemd sends on `stop`/reboot/`shutdown`; SIGINT is Ctrl-C.
# Writing the marker here is what makes a graceful stop distinguishable from a
# power cut — on a real power loss this handler never gets to run.
mark_clean_shutdown() {
    date "$STAMP_FMT" > "$SHUTDOWN_MARKER" 2>/dev/null || true
    log "shutdown signal received — wrote clean-shutdown marker; exiting"
    exit 0
}

# Run once at startup: classify the just-ended downtime from the two markers
# plus the kernel boot time, and log a verdict. Always consumes (deletes) the
# shutdown marker so it can't be reused by a later unclean boot.
report_startup_gap() {
    local now alive_epoch alive_iso shut_epoch shut_iso gap
    now=$(date +%s)

    if [[ ! -r $LAST_ALIVE_FILE ]]; then
        log "no prior last-alive marker — first run or fresh data dir; nothing to classify"
        return
    fi
    read -r alive_epoch alive_iso < "$LAST_ALIVE_FILE"

    if [[ -r $SHUTDOWN_MARKER ]]; then
        read -r shut_epoch shut_iso < "$SHUTDOWN_MARKER"
        rm -f "$SHUTDOWN_MARKER"
        # Valid only if the graceful stop happened at/after the last probe cycle.
        if [[ -n ${shut_epoch:-} && ${shut_epoch} =~ ^[0-9]+$ && $shut_epoch -ge $alive_epoch ]]; then
            gap=$(( now - shut_epoch ))
            log "previous shutdown was CLEAN at $shut_iso — host powered off for ~${gap}s before this start; not an internet outage"
            return
        fi
    fi

    gap=$(( now - alive_epoch ))
    log "UNCLEAN restart — netwatch last alive $alive_iso with no valid clean-shutdown marker (power loss or crash). Internet status during this ~${gap}s gap is UNKNOWN — NOT a detected internet outage."
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

run_once() {
    echo "netwatch one-shot — gateway=$GATEWAY dig=$HAS_DIG ipv6=$HAS_V6"
    echo
    SERVICE_DUE=1
    run_cycle
    local p state f
    for p in "${PROBES[@]}"; do
        state="OK"
        for f in "${CYCLE_FAILED[@]:-}"; do [[ $f == "$p" ]] && state="FAIL"; done
        printf '  %-18s %s\n' "$p" "$state"
    done
    if (( ${#SERVICE_NAMES[@]} )); then
        echo
        echo "  service probes (informational — never affect incidents or exit code):"
        for p in "${SERVICE_NAMES[@]}"; do
            state=${SERVICE_CYCLE_RESULT[$p]:-down}
            printf '  %-18s %s  (%s %s)\n' "$p" "${state^^}" "${SERVICE_KIND[$p]}" "${SERVICE_URL[$p]}"
        done
    fi
    echo
    if [[ ${#CYCLE_FAILED[@]} -eq 0 ]]; then
        echo "All probes passed."
    else
        echo "FAILURES: ${CYCLE_FAILED[*]}"
    fi
    echo
    snapshot
    # exit code is internet-only by design — a down third-party service must
    # not make --once report your network as broken
    [[ ${#CYCLE_FAILED[@]} -eq 0 ]]
}

run_daemon() {
    mkdir -p "$DATA_DIR" "$INCIDENT_DIR"
    trap mark_clean_shutdown TERM INT
    # NOTE: services must NOT be appended to the "probes:" list below — the
    # web dashboard parses that suffix as the internet-probe set.
    log "netwatch started — gateway=$GATEWAY interval=${INTERVAL}s dig=$HAS_DIG ipv6=$HAS_V6 probes: ${PROBES[*]}"
    if (( ${#SERVICE_NAMES[@]} )); then
        log "service probes (informational, ~every $(( SERVICE_EVERY * INTERVAL ))s): ${SERVICE_NAMES[*]}"
    else
        # a file left by a previous config would render ghost chips forever
        rm -f "$SERVICE_STATUS_FILE"
    fi
    report_startup_gap
    local clean_streak=0 heartbeat=0 debounce_pending=0 cycle_i=0
    while true; do
        SERVICE_DUE=0
        (( ${#SERVICE_NAMES[@]} )) && (( cycle_i % SERVICE_EVERY == 0 )) && SERVICE_DUE=1
        cycle_i=$(( cycle_i + 1 ))
        run_cycle
        touch_alive
        # Service state updates run against the RAW cycle results, before
        # confirm_failures mutates CYCLE_FAILED. While any internet probe is
        # failing (or an incident is open) service results are meaningless —
        # everything fails when the WAN is down — so publish "unknown" and
        # freeze the service state machine instead of screaming SERVICE DOWN.
        if (( ${#SERVICE_NAMES[@]} )); then
            if [[ ${#CYCLE_FAILED[@]} -gt 0 || -n $INCIDENT_FILE ]]; then
                SERVICE_SUSPENDED=1
            else
                SERVICE_SUSPENDED=0
                (( SERVICE_DUE )) && service_update_states
            fi
            write_service_status
        fi
        if [[ -z $INCIDENT_FILE ]]; then
            [[ ${#CYCLE_FAILED[@]} -gt 0 ]] && confirm_failures
            if [[ ${#CYCLE_FAILED[@]} -gt 0 ]]; then
                # Debounce a lone miss on a known-flaky probe: require it to
                # fail two consecutive cycles before opening an incident. A
                # genuine outage persists; a one-off blip is gone next cycle.
                if single_flaky_probe && (( debounce_pending == 0 )); then
                    debounce_pending=1
                    log "${CYCLE_FAILED[0]} single miss — debouncing one cycle before opening"
                else
                    debounce_pending=0
                    incident_open
                    incident_record_cycle
                    clean_streak=0
                fi
            else
                debounce_pending=0
                heartbeat=$((heartbeat + 1))
                # one log line per ~hour so the journal shows it's alive
                if (( heartbeat * INTERVAL >= 3600 )); then
                    log "heartbeat — all ${#PROBES[@]} probes OK"
                    heartbeat=0
                fi
            fi
        else
            incident_record_cycle
            if [[ ${#CYCLE_FAILED[@]} -eq 0 ]]; then
                clean_streak=$((clean_streak + 1))
                if (( clean_streak >= RECOVERY_CYCLES )); then
                    incident_close
                    clean_streak=0
                fi
            else
                clean_streak=0
                log "incident ongoing — failing: ${CYCLE_FAILED[*]}"
            fi
        fi
        sleep "$INTERVAL"
    done
}

if [[ -z $GATEWAY ]]; then
    echo "netwatch: no default route found — is the network up?" >&2
    exit 1
fi

case "${1:-}" in
    --once) run_once ;;
    "")     run_daemon ;;
    *)      echo "usage: netwatch.sh [--once]" >&2; exit 2 ;;
esac

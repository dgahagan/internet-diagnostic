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

set -u

DATA_DIR="${NETWATCH_DIR:-$HOME/.local/share/netwatch}"
INTERVAL="${NETWATCH_INTERVAL:-5}"
RECOVERY_CYCLES=3      # consecutive clean cycles required to close an incident
PING_TIMEOUT=2
CURL_TIMEOUT=5

NTFY_URL="${NETWATCH_NTFY_URL:-}"

INCIDENT_DIR="$DATA_DIR/incidents"
LOG_FILE="$DATA_DIR/netwatch.log"

have() { command -v "$1" >/dev/null 2>&1; }

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$LOG_FILE"; }

# Desktop popup — works from the systemd user service as long as the session
# bus socket exists at its default path. Silently unavailable in containers.
desktop_notify() {
    have notify-send || return 0
    DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus}" \
        notify-send --app-name=netwatch --urgency="$1" "$2" "$3" 2>/dev/null || true
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
    # wait on probe pids only — a bare `wait` would also block on the
    # background snapshot job and stall probing mid-incident
    wait "${pids[@]}"
    CYCLE_FAILED=()
    for p in "${PROBES[@]}"; do
        [[ -e "$tmp/$p.ok" ]] || CYCLE_FAILED+=("$p")
    done
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

snapshot() {
    echo "### Deep snapshot at $(date -Is)"
    section "Interfaces"      ip -br addr
    section "Default routes"  ip route show default
    section "IPv6 routes"     ip -6 route show default
    section "Neighbors (ARP)" ip neigh
    have resolvectl && section "resolvectl status" resolvectl status
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
    if have mtr; then
        section "mtr to 1.1.1.1" mtr -rwbz -c3 1.1.1.1
    elif have traceroute; then
        section "traceroute to 1.1.1.1" traceroute -n -w2 -q1 1.1.1.1
    elif have tracepath; then
        section "tracepath to 1.1.1.1" tracepath -n 1.1.1.1
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
        echo "VERDICT: DNS failure — raw connectivity fine, name resolution broken."
        if [[ $HAS_DIG -eq 1 && $(fc dns_router) -gt 0 && $(fc dns_public) -eq 0 ]]; then
            echo "Router's DNS forwarder failed while public DNS (1.1.1.1) worked —"
            echo "pointing your machine/DHCP at 1.1.1.1/8.8.8.8 directly would dodge this."
        fi
    elif [[ $(fc https_google) -gt 0 || $(fc https_cloudflare) -gt 0 || $(fc https_aws) -gt 0 ]]; then
        if [[ $(fc https_google) -eq 0 && $(fc https_cloudflare) -eq 0 && $(fc https_aws) -gt 0 ]]; then
            echo "VERDICT: destination-specific — only AWS us-east-1 failed; everything"
            echo "else was healthy. Not your network; upstream provider issue."
        elif [[ $(fc tcp_443) -gt 0 ]]; then
            echo "VERDICT: TCP broken while ICMP and DNS worked — raw TCP connects to"
            echo "port 443 failed. This matches your earlier outage (ping + dig OK, no"
            echo "websites). Suspect: router NAT/conntrack table exhaustion or ISP"
            echo "dropping TCP. Check the router's connection-table stats / uptime."
        else
            echo "VERDICT: TLS/HTTP layer broken — TCP connects succeeded but HTTPS"
            echo "requests failed. Suspect: MTU/fragmentation (TLS handshakes use big"
            echo "packets, pings don't) or an intercepting middlebox. See the curl"
            echo "timing/verbose sections in the snapshot for where it stalled."
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

incident_open() {
    mkdir -p "$INCIDENT_DIR"
    INCIDENT_START=$(date +%s)
    INCIDENT_FILE="$INCIDENT_DIR/incident-$(date +%Y%m%d-%H%M%S).md"
    INCIDENT_CYCLES=0
    FAIL_COUNT=()
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
# Modes
# ---------------------------------------------------------------------------

run_once() {
    echo "netwatch one-shot — gateway=$GATEWAY dig=$HAS_DIG ipv6=$HAS_V6"
    echo
    run_cycle
    local p
    for p in "${PROBES[@]}"; do
        local state="OK" f
        for f in "${CYCLE_FAILED[@]:-}"; do [[ $f == "$p" ]] && state="FAIL"; done
        printf '  %-18s %s\n' "$p" "$state"
    done
    echo
    if [[ ${#CYCLE_FAILED[@]} -eq 0 ]]; then
        echo "All probes passed."
    else
        echo "FAILURES: ${CYCLE_FAILED[*]}"
    fi
    echo
    snapshot
    [[ ${#CYCLE_FAILED[@]} -eq 0 ]]
}

run_daemon() {
    mkdir -p "$DATA_DIR" "$INCIDENT_DIR"
    log "netwatch started — gateway=$GATEWAY interval=${INTERVAL}s dig=$HAS_DIG ipv6=$HAS_V6 probes: ${PROBES[*]}"
    local clean_streak=0 heartbeat=0
    while true; do
        run_cycle
        if [[ -z $INCIDENT_FILE ]]; then
            [[ ${#CYCLE_FAILED[@]} -gt 0 ]] && confirm_failures
            if [[ ${#CYCLE_FAILED[@]} -gt 0 ]]; then
                incident_open
                incident_record_cycle
                clean_streak=0
            else
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

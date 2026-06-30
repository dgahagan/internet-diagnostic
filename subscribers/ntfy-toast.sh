#!/usr/bin/env bash
#
# ntfy-toast — stream a LAN ntfy topic and pop native desktop notifications.
#
# A streaming subscriber for receiving netwatch/Uptime-Kuma outage alerts on
# any Linux or macOS desktop on the home network. It reads the topic's JSON
# stream directly (no browser, no ntfy CLI needed) and fires:
#   - notify-send  on Linux
#   - osascript    on macOS   (both are built in; nothing extra to install)
#
# Why a streaming subscriber and not the ntfy web app: background Web Push
# needs HTTPS, which a plain-HTTP LAN server can't provide — so a browser tab
# would only notify while it's open. This keeps working in the background.
#
# Usage:
#   ntfy-toast.sh                         # uses the env defaults below
#   NTFY_SERVER=http://192.168.1.100:8090 NTFY_TOPIC=internet-alerts ntfy-toast.sh
#
# Config: set NTFY_SERVER / NTFY_TOPIC in the environment, or in a `.env` file
# next to this script (copy .env.example). The environment wins over .env.
#
# Autostart (Linux): install as a systemd user service — see ntfy-toast.service.
# Autostart (macOS): use a launchd LaunchAgent — see the README.

set -u

# Load a sibling .env if present, as defaults — the environment (and systemd
# Environment= / inline VAR=... overrides) always wins over .env.
ENV_FILE="$(dirname "$0")/.env"
if [[ -f $ENV_FILE ]]; then
    while IFS='=' read -r key val; do
        [[ $key == \#* || -z $key ]] && continue
        [[ -z ${!key:-} ]] && export "$key=$val"
    done < "$ENV_FILE"
fi

SERVER="${NTFY_SERVER:-http://192.168.1.100:8090}"
TOPIC="${NTFY_TOPIC:-internet-alerts}"
SERVER="${SERVER%/}"

have() { command -v "$1" >/dev/null 2>&1; }

if have notify-send; then
    NOTIFIER=linux
elif have osascript; then
    NOTIFIER=macos
else
    echo "ntfy-toast: no notifier found (need notify-send on Linux or osascript on macOS)" >&2
    exit 1
fi

have curl    || { echo "ntfy-toast: curl is required" >&2; exit 1; }
have python3 || { echo "ntfy-toast: python3 is required (for JSON parsing)" >&2; exit 1; }

# Fire one native notification. Args: urgency(low|normal|critical) title body
notify() {
    local urgency=$1 title=$2 body=$3
    case "$NOTIFIER" in
        linux)
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus}" \
                notify-send --app-name=netwatch --urgency="$urgency" "$title" "$body" 2>/dev/null || true
            ;;
        macos)
            # osascript has no urgency; escape embedded backslashes/quotes
            local t=${title//\\/\\\\}; t=${t//\"/\\\"}
            local b=${body//\\/\\\\}; b=${b//\"/\\\"}
            osascript -e "display notification \"$b\" with title \"$t\"" 2>/dev/null || true
            ;;
    esac
}

echo "ntfy-toast: subscribing to $SERVER/$TOPIC (notifier: $NOTIFIER)" >&2

# Dedupe across reconnects: message ids we've already shown are appended here.
SEEN_FILE=$(mktemp)
trap 'rm -f "$SEEN_FILE"' EXIT

# First connect shows only messages from now on (no history replay). On every
# reconnect we advance this to the last seen message time, so anything
# published during the drop is recovered from the server's cache; dedupe by id
# prevents the boundary message from toasting twice.
SINCE=now

# Reconnect loop — a streaming HTTP connection drops periodically (keepalive
# timeouts, blips); that's expected, we just reconnect.
while true; do
    while IFS= read -r line; do
        if [[ $line == SINCE\ * ]]; then
            SINCE=${line#SINCE }
            continue
        fi
        IFS=$'\t' read -r urgency title body <<<"$line"
        [[ -z ${title:-} ]] && title="netwatch"
        notify "${urgency:-normal}" "$title" "${body:-}"
    done < <(
        curl -sN "$SERVER/$TOPIC/json?since=$SINCE" 2>/dev/null | \
        python3 -u -c '
import sys, json
seen_path = sys.argv[1]
try:
    seen = set(open(seen_path).read().split())
except FileNotFoundError:
    seen = set()
for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    try:
        m = json.loads(raw)
    except ValueError:
        continue
    t = m.get("time")
    if t:
        print("SINCE %d" % int(t)); sys.stdout.flush()
    if m.get("event") != "message":
        continue
    mid = m.get("id", "")
    if mid and mid in seen:
        continue
    if mid:
        seen.add(mid)
        with open(seen_path, "a") as f:
            f.write(mid + "\n")
    prio = m.get("priority") or 3
    urgency = "critical" if prio >= 4 else ("low" if prio <= 2 else "normal")
    title = (m.get("title") or "netwatch").replace("\t", " ").replace("\n", " ")
    body  = (m.get("message") or "").replace("\t", " ").replace("\n", " ")
    print("%s\t%s\t%s" % (urgency, title, body)); sys.stdout.flush()
' "$SEEN_FILE"
    )

    sleep 3
done

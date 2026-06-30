#!/usr/bin/env bash
#
# Host install: copies netwatch to ~/bin and enables it as a systemd user
# service. Entirely user-level — works on immutable distros (Silverblue,
# Bazzite, etc.) without touching the OS image.

set -euo pipefail

cd "$(dirname "$0")"

mkdir -p ~/bin ~/.config/systemd/user
install -m 755 netwatch.sh ~/bin/netwatch.sh
install -m 644 netwatch.service ~/.config/systemd/user/netwatch.service

systemctl --user daemon-reload
systemctl --user enable netwatch
# restart (not `enable --now`) so a re-install of an already-running daemon
# actually picks up the new netwatch.sh instead of leaving the old one running
systemctl --user restart netwatch
systemctl --user status netwatch --no-pager --lines=3 || true

cat <<'EOF'

netwatch installed and running.

  follow live:      journalctl --user -u netwatch -f
  manual check:     ~/bin/netwatch.sh --once
  incident reports: ~/.local/share/netwatch/incidents/

To enable phone push alerts, add your ntfy topic URL to the service:
  systemctl --user edit netwatch
    [Service]
    Environment=NETWATCH_NTFY_URL=http://<lan-ip>:8090/internet-alerts
  systemctl --user restart netwatch
EOF

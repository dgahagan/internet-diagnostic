# Desktop alerts on other PCs

The host running netwatch gets popups directly (via `notify-send`). To get
the **same alerts on other machines** on the home network — a Windows PC, a
partner's laptop — subscribe them to the LAN ntfy topic with the scripts in
this directory. Because ntfy is on your LAN, these alerts are
internet-independent, exactly like the phone push.

> **Why not just open the ntfy web app?** Its background push needs HTTPS
> (browser service workers won't run on a plain-HTTP LAN origin, and a
> `192.168.x.x` address doesn't get the `localhost` exception). A browser tab
> would only notify while it's open. The scripts here instead stream the
> topic directly and fire **native OS toasts** in the background.
> One bonus of the streaming approach: a PC that was asleep during an outage
> still gets the alert on wake, recovered from the ntfy server's message cache.

All scripts take the server URL and topic via parameters/env; point them at
your ntfy server (default examples use `http://192.168.1.100:8090` /
`internet-alerts`).

## Windows — `ntfy-toast.ps1` (PowerShell + BurntToast)

```powershell
Install-Module -Name BurntToast -Scope CurrentUser      # one-time
.\ntfy-toast.ps1 -Server http://192.168.1.100:8090 -Topic internet-alerts
```

Autostart at logon (runs hidden, survives reboots) — the script header has a
ready-to-paste `Register-ScheduledTask` snippet.

## Linux — `ntfy-toast.sh` (notify-send)

```bash
mkdir -p ~/bin ~/.config/systemd/user
cp ntfy-toast.sh ~/bin/
cp ntfy-toast.service ~/.config/systemd/user/
# edit the Environment= lines in the unit to point at your server/topic
systemctl --user daemon-reload
systemctl --user enable --now ntfy-toast
```

## macOS — `ntfy-toast.sh` (osascript)

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
> work against a self-hosted LAN server too — the scripts here just avoid any
> extra install and give native toasts out of the box.

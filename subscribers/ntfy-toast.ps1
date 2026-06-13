<#
.SYNOPSIS
    Stream a LAN ntfy topic and pop native Windows toast notifications.

.DESCRIPTION
    A streaming subscriber for receiving netwatch / Uptime-Kuma outage alerts
    on a Windows desktop on the home network. It reads the topic's JSON stream
    directly and raises native Windows toasts via the BurntToast module — no
    browser tab required.

    Why a streaming subscriber and not the ntfy web app: background Web Push
    needs HTTPS, which a plain-HTTP LAN server can't provide, so a browser tab
    would only notify while it is open. This keeps working in the background.

.PREREQUISITES
    Install BurntToast once (per user, no admin needed):
        Install-Module -Name BurntToast -Scope CurrentUser

.PARAMETER Server
    Base URL of the ntfy server, e.g. http://192.168.1.100:8090

.PARAMETER Topic
    Topic to subscribe to, e.g. internet-alerts

.EXAMPLE
    .\ntfy-toast.ps1 -Server http://192.168.1.100:8090 -Topic internet-alerts

.NOTES
    Autostart at logon (run hidden, survives reboots). Run once:

        $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\path\to\ntfy-toast.ps1" -Server http://192.168.1.100:8090 -Topic internet-alerts'
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName 'netwatch ntfy-toast' -Action $action -Trigger $trigger -Settings $set
#>

[CmdletBinding()]
param(
    [string]$Server = 'http://192.168.1.100:8090',
    [string]$Topic  = 'internet-alerts'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name BurntToast)) {
    Write-Error "BurntToast module not found. Install it with: Install-Module -Name BurntToast -Scope CurrentUser"
    exit 1
}
Import-Module BurntToast

$Server = $Server.TrimEnd('/')
$seen   = New-Object 'System.Collections.Generic.HashSet[string]'
# First connect shows only messages from now on (no history replay). On every
# reconnect we advance $since to the last seen message time so anything sent
# during the drop is recovered from the server cache; dedupe by id prevents
# the boundary message toasting twice.
$since  = 'now'

Write-Host "ntfy-toast: subscribing to $Server/$Topic"

while ($true) {
    try {
        $url    = "$Server/$Topic/json?since=$since"
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
        $stream = $client.GetStreamAsync($url).GetAwaiter().GetResult()
        $reader = New-Object System.IO.StreamReader($stream)

        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            try { $m = $line | ConvertFrom-Json } catch { continue }

            if ($m.time)  { $since = [int64]$m.time }
            if ($m.event -ne 'message') { continue }

            $id = [string]$m.id
            if ($id -and $seen.Contains($id)) { continue }
            if ($id) { [void]$seen.Add($id) }

            $title = if ($m.title) { [string]$m.title } else { 'netwatch' }
            $body  = if ($m.message) { [string]$m.message } else { '' }

            New-BurntToastNotification -Text $title, $body
        }
    }
    catch {
        # Connection dropped or server briefly unreachable — expected; reconnect.
        Write-Host "ntfy-toast: stream ended ($($_.Exception.Message)); reconnecting..."
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($client) { $client.Dispose() }
    }

    Start-Sleep -Seconds 3
}

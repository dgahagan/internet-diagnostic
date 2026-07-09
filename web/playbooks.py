"""Failure-signature playbooks for the netwatch dashboard.

Each playbook maps a probe-failure signature to a diagnosis and concrete
remediation steps. classify() takes the set of failing probe names (from a
live incident's last cycle, or a report's "First failing probes" line) and
returns the first matching playbook.

Machine-specific values (LAN interface name, LAN DNS servers) come from the
environment so this file stays generic — set NETWATCH_WEB_IFACE and
NETWATCH_WEB_LAN_DNS in .env.
"""

import os

IFACE = os.environ.get("NETWATCH_WEB_IFACE", "").strip() or "<lan-interface>"
LAN_DNS = os.environ.get("NETWATCH_WEB_LAN_DNS", "").strip() or "<lan-dns-servers>"

# Probes that all target Cloudflare/1.1.1.1 — used to spot a provider-only loss.
CF_SET = {"wan_ping_cf", "tcp_443", "https_ip", "https_cloudflare", "dns_public"}

PLAYBOOKS = [
    {
        "id": "lan_router",
        "title": "Router / LAN down",
        "severity": "local",
        "signature": "gw_ping failing — the router itself stopped answering.",
        "cause": "Router reboot or crash, switch or cabling fault, or this "
                 "host's own interface went down.",
        "just_me": "Everything on the LAN is affected — other devices on WiFi "
                   "will be down too (phone on mobile data still works).",
        "fixes": [
            {"desc": "Check the router's lights / power; power-cycle it if hung."},
            {"desc": "Check this host's link state:", "cmd": f"ip -br addr show {IFACE}"},
            {"desc": "If only this host lost link, bounce the connection:",
             "cmd": f"nmcli device reapply {IFACE}"},
        ],
    },
    {
        "id": "wan_outage",
        "title": "WAN outage (ISP-side)",
        "severity": "wait",
        "signature": "Gateway pings fine but BOTH WAN pings (1.1.1.1 and 8.8.8.8) "
                     "fail, along with everything upstream.",
        "cause": "Modem/ONT resync or an outage inside the ISP's network.",
        "just_me": "Whole household is down. Phone on mobile data works.",
        "fixes": [
            {"desc": "Nothing to fix locally — wait it out (past ones self-healed "
                     "in ~1–3 min)."},
            {"desc": "If it lasts, power-cycle the modem/ONT."},
            {"desc": "Keep the incident report (it captures an mtr mid-outage) "
                     "as evidence for your ISP."},
        ],
    },
    {
        "id": "aws_blip",
        "title": "AWS-only blip",
        "severity": "ignore",
        "signature": "Only https_aws (s3.us-east-1) failing; everything else green.",
        "cause": "Transient problem at AWS us-east-1 or on the path to it — "
                 "usually clears in well under a minute.",
        "just_me": "Not you, not your ISP. Only AWS-hosted things may hiccup.",
        "fixes": [
            {"desc": "Ignore. If it persists >5 min check status.aws.amazon.com "
                     "from your phone."},
        ],
    },
    {
        "id": "dns_router_blip",
        "title": "Router DNS forwarder blip",
        "severity": "ignore",
        "signature": "Only dns_router failing for a cycle or two.",
        "cause": "The router's DNS forwarder dropped a query — common, "
                 "self-healing noise. netwatch already debounces single misses.",
        "just_me": "Usually invisible in real browsing (the system resolver "
                   "isn't the gateway).",
        "fixes": [
            {"desc": "Ignore unless it persists across many cycles — then treat "
                     "as 'DNS via router broken' and check the router."},
        ],
    },
    {
        "id": "transient_blip",
        "title": "Transient single-probe blip",
        "severity": "ignore",
        "signature": "A single WAN ping (one of 1.1.1.1 / 8.8.8.8) failing "
                     "briefly, everything else green.",
        "cause": "A dropped packet or a momentary flap on one path — normal "
                 "internet noise.",
        "just_me": "Nobody notices these in practice.",
        "fixes": [
            {"desc": "Ignore unless it recurs in clusters — then look at the "
                     "incident timeline for a pattern."},
        ],
    },
    {
        "id": "vpn_dns_wipe",
        "title": "VPN DNS wipe (system resolver dead)",
        "severity": "local",
        "signature": "dns_system + hostname-HTTPS probes failing while dns_router, "
                     "dns_public, https_ip and all pings stay green.",
        "cause": "A VPN that pushes DNS into the system resolver disconnected "
                 "and its teardown removed the DNS configuration instead of "
                 "restoring the LAN's. Raw connectivity is fine; the host just "
                 "has nowhere to send name lookups.",
        "just_me": "Only this host. Phone and other devices are fine — the "
                   "internet is NOT down.",
        "fixes": [
            {"desc": "DO NOT reboot — restore DNS in one command by re-applying "
                     "the interface's DHCP config:",
             "cmd": f"nmcli device reapply {IFACE}"},
            {"desc": "Or set the LAN DNS servers back directly:",
             "cmd": f"sudo resolvectl dns {IFACE} {LAN_DNS}"},
            {"desc": "Verify resolution is back:",
             "cmd": "getent ahosts google.com && resolvectl status | head -20"},
            {"desc": "Then reconnect the VPN."},
        ],
    },
    {
        "id": "router_dns",
        "title": "DNS via router broken",
        "severity": "local",
        "signature": "dns_system and dns_router failing while dns_public "
                     "(@1.1.1.1) works.",
        "cause": "The router's DNS forwarder (or the LAN DNS server it points "
                 "at, e.g. a Pi-hole) is down; public DNS is reachable.",
        "just_me": "Everything on the LAN using the router/LAN resolver for DNS is "
                   "affected.",
        "fixes": [
            {"desc": "Point this host at public DNS temporarily:",
             "cmd": f"sudo resolvectl dns {IFACE} 1.1.1.1 8.8.8.8"},
            {"desc": "Check the LAN DNS service / router and restore it, "
                     "then revert:", "cmd": f"nmcli device reapply {IFACE}"},
        ],
    },
    {
        "id": "cloudflare_path",
        "title": "Cloudflare/1.1.1.1 unreachable (peering flap)",
        "severity": "wait",
        "signature": "Only the probes that target 1.1.1.1/Cloudflare fail "
                     "(wan_ping_cf, tcp_443, https_ip, https_cloudflare, "
                     "dns_public) while Google, AWS and 8.8.8.8 stay green.",
        "cause": "Routing/peering failure on the path to Cloudflare's anycast, "
                 "upstream of you. The rest of the internet is fine.",
        "just_me": "Anyone routed through the same upstream is affected; most "
                   "browsing works, Cloudflare-fronted sites may not.",
        "fixes": [
            {"desc": "Nothing to fix locally; it clears when the route heals."},
            {"desc": "If 1.1.1.1 is your primary resolver, put a non-Cloudflare "
                     "server first so a Cloudflare flap can't take DNS with it."},
        ],
    },
    {
        "id": "tcp_broken",
        "title": "TCP broken, ICMP/DNS fine",
        "severity": "local",
        "signature": "tcp_443 (raw TCP connect) failing while pings and DNS work.",
        "cause": "Router NAT/conntrack table exhaustion, or the ISP dropping "
                 "TCP.",
        "just_me": "Whole LAN affected for new connections; phone on mobile "
                   "data works.",
        "fixes": [
            {"desc": "Check the router's connection-table stats / uptime; "
                     "reboot the router if its conntrack table is full."},
            {"desc": "If it recurs with a clean router, it's ISP-side — keep "
                     "the reports as evidence."},
        ],
    },
    {
        "id": "tls_mtu",
        "title": "TLS/HTTP broken, TCP fine",
        "severity": "local",
        "signature": "HTTPS probes failing while raw TCP connects succeed.",
        "cause": "MTU/fragmentation trouble (TLS handshakes use big packets, "
                 "pings don't) or an intercepting middlebox.",
        "just_me": "Usually affects the whole LAN.",
        "fixes": [
            {"desc": "Check the curl timing/verbose sections in the snapshot "
                     "for where the handshake stalls."},
            {"desc": "Test a lower MTU:",
             "cmd": f"sudo ip link set {IFACE} mtu 1400  # revert with mtu 1500"},
        ],
    },
]

FALLBACK = {
    "id": "unknown",
    "title": "Unclassified signature",
    "severity": "info",
    "signature": "Doesn't match a known pattern.",
    "cause": "See the incident timeline and snapshot — and the verdict netwatch "
             "writes at close.",
    "just_me": "Check whether your phone (on WiFi, then on mobile data) can "
               "reach the internet to split LAN vs ISP.",
    "fixes": [
        {"desc": "Run a one-shot probe cycle with a deep snapshot:",
         "cmd": "~/bin/netwatch.sh --once"},
    ],
}


def classify(failing):
    """Return the playbook matching a set of failing probe names."""
    f = set(failing)
    if not f:
        return None
    if "gw_ping" in f:
        return _get("lan_router")
    if "wan_ping_cf" in f and "wan_ping_gg" in f:
        return _get("wan_outage")
    if f == {"https_aws"}:
        return _get("aws_blip")
    if f == {"dns_router"}:
        return _get("dns_router_blip")
    if f in ({"wan_ping_cf"}, {"wan_ping_gg"}):
        return _get("transient_blip")
    if "dns_system" in f and not f & {"dns_router", "dns_public", "https_ip",
                                      "wan_ping_cf", "wan_ping_gg", "tcp_443"}:
        return _get("vpn_dns_wipe")
    if "dns_system" in f and "dns_router" in f and "dns_public" not in f:
        return _get("router_dns")
    if len(f) >= 2 and f <= CF_SET:
        return _get("cloudflare_path")
    if "tcp_443" in f and "dns_system" not in f:
        return _get("tcp_broken")
    if f & {"https_google", "https_cloudflare", "https_aws", "https_ip"} \
            and "tcp_443" not in f:
        return _get("tls_mtu")
    return FALLBACK


def _get(pid):
    return next(p for p in PLAYBOOKS if p["id"] == pid)


# For closed incidents netwatch's verdict is computed over ALL incident cycles,
# so it beats classifying from the first-fail probe set (which can be a subset
# — e.g. a WAN outage whose first cycle only caught one WAN ping).
_VERDICT_MAP = [
    ("LAN problem", "lan_router"),
    ("WAN outage", "wan_outage"),
    ("system resolver redirected", "vpn_dns_wipe"),
    ("DNS failure", "router_dns"),
    ("destination-specific", "aws_blip"),
    ("single upstream unreachable", "cloudflare_path"),
    ("TCP broken", "tcp_broken"),
    ("TLS/HTTP layer broken", "tls_mtu"),
    ("transient blip", "transient_blip"),
]


def classify_verdict(verdict_text):
    """Map a report's VERDICT line to a playbook, or None."""
    for prefix, pid in _VERDICT_MAP:
        if verdict_text and verdict_text.startswith(prefix):
            return _get(pid)
    return None

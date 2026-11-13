"""Failure-signature playbooks for the netwatch dashboard.

Each playbook maps a probe-failure signature to a diagnosis and concrete
remediation steps. classify() takes the set of failing probe names (from a
live incident's last cycle, or a report's "First failing probes" line) and
returns the first matching playbook.

Two layers keep committed code generic while letting an instance carry its
own environment knowledge:

  * Machine values (LAN interface, LAN DNS) come from NETWATCH_WEB_IFACE /
    NETWATCH_WEB_LAN_DNS so rendered fix commands are paste-ready.
  * Local playbook overlays — TOML files in NETWATCH_PLAYBOOKS_DIR
    (gitignored `playbooks.d/`) — can extend a built-in playbook with
    instance-specific cause/fix detail, or add whole new playbooks with
    declarative match rules. See playbooks.d/README.md for the format.
    Files are re-read when they change; no restart needed.
"""

import copy
import os
import tomllib

IFACE = os.environ.get("NETWATCH_WEB_IFACE", "").strip() or "<lan-interface>"
LAN_DNS = os.environ.get("NETWATCH_WEB_LAN_DNS", "").strip() or "<lan-dns-servers>"
PLAYBOOKS_DIR = os.environ.get("NETWATCH_PLAYBOOKS_DIR", "/playbooks.d")

# Probes that all target Cloudflare/1.1.1.1 — used to spot a provider-only loss.
CF_SET = {"wan_ping_cf", "tcp_443", "https_ip", "https_cloudflare", "dns_public"}
# Probes that target Google or AWS — the complement used to spot the reverse
# case, where everything except Cloudflare goes unreachable.
UPSTREAM_SET = {"wan_ping_gg", "https_google", "https_aws", "https_v6"}

BASE_PLAYBOOKS = [
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
            {"desc": "Nothing to fix locally — short drops usually self-heal "
                     "in a few minutes."},
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
        "just_me": "Everything on the LAN using the router/LAN resolver for "
                   "DNS is affected.",
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
        "id": "upstream_path",
        "title": "Google/AWS unreachable (peering flap)",
        "severity": "wait",
        "signature": "Probes targeting Google and/or AWS fail (wan_ping_gg, "
                     "https_google, https_aws) while every Cloudflare-path "
                     "probe stays green.",
        "cause": "Routing/peering failure upstream of you on the paths to "
                 "Google/AWS. A local fault could not spare one destination "
                 "and break another, so your LAN, router and ISP first hops "
                 "are fine. The mirror image of the Cloudflare-path flap.",
        "just_me": "Anyone routed through the same upstream is affected; "
                   "Cloudflare-fronted sites keep working, which is what "
                   "makes it look like a partial outage.",
        "fixes": [
            {"desc": "Nothing to fix locally; it clears when the route heals."},
            {"desc": "Confirm where the paths diverge — compare the traces to "
                     "8.8.8.8 and s3.us-east-1 against the one to 1.1.1.1 in "
                     "the incident snapshot."},
            {"desc": "If it keeps recurring, this is worth an ISP ticket with "
                     "the incident reports attached — they show the ISP's own "
                     "hops clean and the failure past them."},
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
        "signature": "HTTPS probes failing while raw TCP to 1.1.1.1 succeeds.",
        "cause": "MTU/fragmentation trouble (TLS handshakes use big packets, "
                 "pings don't) or an intercepting middlebox. Confirm before "
                 "acting: tcp_443 only tests 1.1.1.1, so it passing does not "
                 "prove TCP reached the destinations that failed.",
        "just_me": "Usually affects the whole LAN.",
        "fixes": [
            {"desc": "Check connect= in the snapshot's curl timing sections "
                     "first: connect=0 means TCP never completed (a routing "
                     "problem, not MTU); a non-zero connect= with an empty "
                     "tls= is a genuine handshake stall."},
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


# ---------------------------------------------------------------------------
# Local overlays — TOML files in PLAYBOOKS_DIR, re-read whenever they change
# ---------------------------------------------------------------------------

_cache = {"stamp": None, "merged": None, "customs": None}


def _dir_stamp():
    try:
        return tuple(sorted(
            (e.name, e.stat().st_mtime) for e in os.scandir(PLAYBOOKS_DIR)
            if e.name.endswith(".toml") and e.is_file()))
    except OSError:
        return ()


def _load_overlays():
    """Parse overlay files -> (overrides-by-id, custom playbooks in file order).
    A bad file is skipped with a warning in the container log, never fatal."""
    overrides, customs = {}, []
    for name, _ in _dir_stamp():
        path = os.path.join(PLAYBOOKS_DIR, name)
        try:
            with open(path, "rb") as f:
                doc = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as e:
            print(f"playbooks.d: skipping {name}: {e}", flush=True)
            continue
        if "extends" in doc:
            overrides.setdefault(doc["extends"], []).append((name, doc))
        elif "id" in doc and "match" in doc:
            customs.append((name, doc))
        else:
            print(f"playbooks.d: skipping {name}: needs either 'extends' or "
                  f"'id' + '[match]'", flush=True)
    return overrides, customs


def _apply_override(pb, doc):
    for key in ("title", "severity", "signature", "cause", "just_me"):
        if key in doc:
            pb[key] = doc[key]
    if "extra_cause" in doc:
        pb["cause"] = pb["cause"].rstrip() + " " + doc["extra_cause"]
    if "fixes" in doc:
        pb["fixes"] = list(doc["fixes"])
    if "extra_fixes" in doc:
        pb["fixes"] = pb["fixes"] + list(doc["extra_fixes"])
    pb["local"] = True


def _custom_matches(match, f):
    """Declarative match rules for custom playbooks. At least one rule must be
    present; an empty [match] table would otherwise match every outage."""
    if not any(k in match for k in ("exact", "all_of", "any_of", "none_of")):
        return False
    if "exact" in match:
        return f == set(match["exact"])
    if not set(match.get("all_of", [])) <= f:
        return False
    if set(match.get("none_of", [])) & f:
        return False
    if "any_of" in match and not set(match["any_of"]) & f:
        return False
    return True


def _refresh():
    stamp = _dir_stamp()
    if stamp == _cache["stamp"]:
        return
    overrides, customs = _load_overlays()
    merged = {}
    for base in BASE_PLAYBOOKS + [FALLBACK]:
        pb = copy.deepcopy(base)
        for name, doc in overrides.get(pb["id"], []):
            _apply_override(pb, doc)
        merged[pb["id"]] = pb
    custom_pbs = []
    for name, doc in customs:
        if doc["id"] in merged:
            print(f"playbooks.d: skipping {name}: id {doc['id']!r} collides "
                  f"with a built-in — use 'extends' instead", flush=True)
            continue
        pb = {"id": doc["id"],
              "title": doc.get("title", doc["id"]),
              "severity": doc.get("severity", "info"),
              "signature": doc.get("signature", ""),
              "cause": doc.get("cause", ""),
              "just_me": doc.get("just_me", ""),
              "fixes": list(doc.get("fixes", [])),
              "match": doc["match"],
              "local": True}
        custom_pbs.append(pb)
        merged[pb["id"]] = pb
    _cache.update(stamp=stamp, merged=merged, customs=custom_pbs)


def _get(pid):
    _refresh()
    return _cache["merged"][pid]


def get_all():
    """Every playbook for the /playbooks page — customs first (they match
    first), then built-ins with any overrides applied, then the fallback."""
    _refresh()
    builtins = [_cache["merged"][p["id"]] for p in BASE_PLAYBOOKS]
    return _cache["customs"] + builtins + [_cache["merged"]["unknown"]]


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify(failing):
    """Return the playbook matching a set of failing probe names."""
    _refresh()
    f = set(failing)
    if not f:
        return None
    for pb in _cache["customs"]:
        if _custom_matches(pb["match"], f):
            return pb
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
    # Mirror of the CF_SET rule above: nothing on the Cloudflare path failed,
    # but Google/AWS-targeted probes did. Must precede the tls_mtu rule, which
    # would otherwise claim TCP was fine — tcp_443 only ever tests 1.1.1.1.
    if len(f) >= 2 and not f & CF_SET and f <= UPSTREAM_SET:
        return _get("upstream_path")
    if "tcp_443" in f and "dns_system" not in f:
        return _get("tcp_broken")
    if f & {"https_google", "https_cloudflare", "https_aws", "https_ip"} \
            and "tcp_443" not in f:
        return _get("tls_mtu")
    return _get("unknown")


def classify_verdict(verdict_text):
    """Map a report's VERDICT line to a playbook, or None."""
    if not verdict_text:
        return None
    _refresh()
    for pb in _cache["customs"]:
        prefix = pb["match"].get("verdict_prefix")
        if prefix and verdict_text.startswith(prefix):
            return pb
    for prefix, pid in _VERDICT_MAP:
        if verdict_text.startswith(prefix):
            return _get(pid)
    return None

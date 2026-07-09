"""Static documentation of netwatch's probes for the dashboard.

Mirrors the probe definitions in netwatch.sh — if a probe is added there,
add its card here. The dashboard shows which of these are actually active
on an instance by parsing the probe list from netwatch's startup log line
(dns_router/dns_public need dig; https_v6 needs an IPv6 default route).
"""

LAYERS = ["LAN", "WAN ICMP", "DNS", "TCP", "TLS/HTTP"]

PROBES = [
    {
        "id": "gw_ping",
        "layer": "LAN",
        "target": "your default gateway (router)",
        "check": "One ICMP ping, 2s timeout.",
        "why": "The first hop. If the router itself doesn't answer, nothing "
               "past it can work — the problem is inside your house, not the "
               "internet.",
        "fails": "Router reboot/crash, switch or cabling fault, or this "
                 "host's own interface.",
    },
    {
        "id": "wan_ping_cf",
        "layer": "WAN ICMP",
        "target": "1.1.1.1 (Cloudflare anycast)",
        "check": "One ICMP ping, 2s timeout.",
        "why": "Is the internet reachable at the raw IP level, beyond the "
               "router?",
        "fails": "Together with wan_ping_gg = WAN outage (modem/ONT/ISP). "
                 "Alone = a Cloudflare-path flap, not a real outage.",
    },
    {
        "id": "wan_ping_gg",
        "layer": "WAN ICMP",
        "target": "8.8.8.8 (Google anycast)",
        "check": "One ICMP ping, 2s timeout.",
        "why": "Second, independent provider — so a single provider's routing "
               "flap isn't mistaken for the whole WAN being down.",
        "fails": "Together with wan_ping_cf = WAN outage. Alone = a "
                 "Google-path flap.",
    },
    {
        "id": "dns_system",
        "layer": "DNS",
        "target": "google.com via the system resolver",
        "check": "getent ahosts — resolution through nsswitch/systemd-resolved, "
                 "the exact path real applications use (cache included, "
                 "because apps get the cache too).",
        "why": "Measures DNS the way your browser experiences it, not the way "
               "a debugging tool does.",
        "fails": "Apps can't resolve names. If dns_router and dns_public still "
                 "pass, only THIS host's resolver path is broken — the classic "
                 "VPN-ate-my-DNS symptom.",
    },
    {
        "id": "dns_router",
        "layer": "DNS",
        "target": "your gateway's DNS forwarder",
        "check": "dig @gateway for a random, uncacheable subdomain (NXDOMAIN "
                 "counts as answered — any reply means the resolver is up).",
        "why": "Separates 'the router's DNS died' from 'DNS in general died'.",
        "fails": "Router's forwarder (or the LAN DNS server behind it) is "
                 "down. A single-cycle miss is debounced as noise.",
        "requires": "dig installed (bind-tools/dnsutils)",
    },
    {
        "id": "dns_public",
        "layer": "DNS",
        "target": "1.1.1.1 as a DNS server",
        "check": "dig @1.1.1.1 for a random, uncacheable subdomain.",
        "why": "A resolver that needs nothing from your LAN — if this answers, "
               "DNS as a service is fine upstream.",
        "fails": "Public DNS unreachable — usually part of a bigger WAN or "
                 "Cloudflare-path failure rather than a DNS problem.",
        "requires": "dig installed (bind-tools/dnsutils)",
    },
    {
        "id": "tcp_443",
        "layer": "TCP",
        "target": "1.1.1.1 port 443",
        "check": "Raw TCP connect — no DNS lookup, no TLS handshake.",
        "why": "Separates 'TCP itself is broken' from 'TLS/HTTP is broken'. "
               "Pings can pass while every TCP connection dies (NAT/conntrack "
               "exhaustion — the failure mode that inspired this project).",
        "fails": "New TCP connections are being dropped: router connection "
                 "table full, or the ISP interfering with TCP.",
    },
    {
        "id": "https_google",
        "layer": "TLS/HTTP",
        "target": "https://www.google.com/generate_204",
        "check": "Full HTTPS request: DNS + TCP + TLS + HTTP, 5s budget.",
        "why": "The whole stack end-to-end — this is what 'the internet works' "
               "actually means to a user.",
        "fails": "Compare with the layers below it to see which ingredient "
                 "broke: DNS probes, tcp_443, or https_ip.",
    },
    {
        "id": "https_cloudflare",
        "layer": "TLS/HTTP",
        "target": "https://cp.cloudflare.com/",
        "check": "Full HTTPS request, 5s budget.",
        "why": "Second full-stack destination on separate infrastructure.",
        "fails": "With https_google also failing: stack-wide problem. Alone "
                 "(with the other 1.1.1.1 probes): Cloudflare-path flap.",
    },
    {
        "id": "https_aws",
        "layer": "TLS/HTTP",
        "target": "https://s3.us-east-1.amazonaws.com/",
        "check": "Full HTTPS request, 5s budget.",
        "why": "Third provider, third network — makes destination-specific "
               "blips (one cloud having a bad minute) identifiable as such.",
        "fails": "Alone: an AWS/us-east-1 blip, not your network.",
    },
    {
        "id": "https_ip",
        "layer": "TLS/HTTP",
        "target": "https://1.1.1.1/ (literal IP)",
        "check": "Full HTTPS request to an IP address — DNS removed from the "
                 "equation entirely.",
        "why": "If hostname HTTPS fails but this passes, the web is fine and "
               "DNS is your problem.",
        "fails": "TLS/HTTP genuinely broken (or the Cloudflare path is down — "
                 "check wan_ping_cf).",
    },
    {
        "id": "https_v6",
        "layer": "TLS/HTTP",
        "target": "https://www.google.com/generate_204 over IPv6",
        "check": "Full HTTPS request forced over IPv6.",
        "why": "Browsers prefer IPv6 when offered — a broken v6 path stalls "
               "page loads while every IPv4 tool looks healthy.",
        "fails": "IPv6-only breakage: pages hang in browsers, curl -4 works.",
        "requires": "an IPv6 default route",
    },
]


def by_id(pid):
    return next((p for p in PROBES if p["id"] == pid), None)

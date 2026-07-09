# Local playbook overlays

Drop `*.toml` files here to teach the web dashboard about **your**
environment — the VPN you run, your ISP's known failure modes, that one
flaky switch. Files in this directory are gitignored (except this README
and the `.sample`), so instance-specific detail never ends up in the repo.
The dashboard re-reads them when they change; no container restart needed.

Files load in name order — prefix with a number (`10-vpn.toml`) if order
matters. There are two kinds of file:

## 1. Extend a built-in playbook

Add local knowledge to one of the generic playbooks (see `/playbooks` in
the dashboard for their ids: `lan_router`, `wan_outage`, `vpn_dns_wipe`,
`router_dns`, `cloudflare_path`, `tcp_broken`, `tls_mtu`, `aws_blip`,
`dns_router_blip`, `transient_blip`, `unknown`):

```toml
extends = "vpn_dns_wipe"

# Appended to the generic cause text:
extra_cause = "On this machine the culprit is Acme Corp VPN — its client wipes resolv.conf on disconnect."

# Appended after the generic fix steps:
[[extra_fixes]]
desc = "Reconnect with a fresh login:"
cmd = "acme-vpn connect --reauth"
```

Fields `title`, `severity`, `signature`, `cause`, `just_me` **replace** the
built-in value when present; `extra_cause` appends text; `fixes` replaces
the whole step list while `extra_fixes` appends steps.

## 2. Add a whole new playbook

Give it a unique `id` and a `[match]` table of declarative rules against
the failing-probe set. Custom playbooks are checked **before** built-ins.

```toml
id = "smart_tv_storm"
title = "Smart-TV multicast storm"
severity = "local"
signature = "gw_ping flapping while WAN stays up."
cause = "The living-room TV floods the LAN with mDNS after a firmware update."
just_me = "Whole LAN gets laggy."

[match]
all_of = ["gw_ping"]          # every listed probe must be failing
none_of = ["wan_ping_cf"]     # none of these may be failing
# any_of = [...]              # at least one must be failing
# exact = [...]               # the failing set must be exactly this
# verdict_prefix = "LAN problem"   # also claim closed incidents whose
                                   # VERDICT line starts with this

[[fixes]]
desc = "Unplug the TV. Seriously."

[[fixes]]
desc = "Check mDNS packet rates:"
cmd = "sudo tcpdump -i <lan-interface> -c 50 port 5353"
```

Playbooks from this directory show a `local` badge in the dashboard.
A file that fails to parse is skipped with a warning in
`docker logs netwatch-web`.

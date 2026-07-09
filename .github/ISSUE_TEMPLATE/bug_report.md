---
name: Bug report
about: Something misbehaved, misdetected, or broke
labels: bug
---

**What happened?**

<!-- What did you see, and what did you expect instead? -->

**`netwatch.sh --once` output**

<!-- Paste the output (redact IPs you consider private). This shows the
probe matrix + snapshot and answers most environment questions at once. -->

```
paste here
```

**How is netwatch running?**

- [ ] host install (`install.sh` / systemd user service)
- [ ] docker compose
- [ ] just the web dashboard

**Environment**

- OS / distro:
- Anything unusual about the network? (VPN, PiHole/self-hosted DNS, CGNAT, IPv6-only, …):

**Relevant log lines / incident report**

<!-- Host install: ~/.local/share/netwatch/netwatch.log and incidents/;
compose: ./data/. -->

# Contributing to netwatch

Thanks for your interest! Bug reports, playbook signatures, and portability
fixes are all welcome.

## Design constraints (please keep these)

- **`netwatch.sh` is zero-dependency bash** — `bash`, `curl`, `ping` only;
  everything else (`dig`, `mtr`, `notify-send`, IPv6) must be feature-detected
  and degrade gracefully. No jq, no python in the probe path.
- **`web/` is stdlib Python** — no pip installs, so the image builds offline
  and the dashboard runs anywhere Python 3.11+ does.
- **Alerting must survive the outage it reports** — anything that alerts via
  an internet service defeats the point. LAN-hosted paths only.
- Service probes are informational by design: they must never open incidents,
  never alert, and never affect `--once`'s exit code.

## Developing

```bash
./netwatch.sh --once        # one probe cycle + snapshot, non-zero exit on failure
bash -n netwatch.sh         # syntax check
shellcheck -S warning netwatch.sh install.sh subscribers/ntfy-toast.sh
python3 -m py_compile web/*.py
```

To hack on the dashboard without a running netwatch, point it at a synthetic
data dir — see the `web-smoke` job in `.github/workflows/ci.yml` for a
copy-pasteable example, then:

```bash
NETWATCH_DIR=/path/to/fake-data python3 web/app.py   # http://localhost:8091
```

CI runs those same checks on every push/PR.

## Adding playbooks

Generic failure signatures (things true of *any* network) belong in
`web/playbooks.py`. Environment-specific knowledge (your VPN client, your
ISP's quirks) belongs in gitignored `playbooks.d/` TOML overlays — see
`playbooks.d/README.md`. If you've found a signature you think is general,
a PR against `web/playbooks.py` with the probe-set rationale is very welcome.

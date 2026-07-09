#!/usr/bin/env python3
"""netwatch-web — LAN dashboard for netwatch incident data.

Reads the netwatch data directory (read-only) and serves:
  /                live status banner + matched playbook + incident list
  /incident/<name> a single incident report, rendered
  /playbooks       the full signature -> remediation knowledge base
  /api/status      JSON for the auto-refreshing banner

Stdlib only — no dependencies to install, so the image builds offline.
"""

import html
import json
import os
import re
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import playbooks

DATA_DIR = os.environ.get("NETWATCH_DIR", "/data")
INCIDENT_DIR = os.path.join(DATA_DIR, "incidents")
LOG_FILE = os.path.join(DATA_DIR, "netwatch.log")
LAST_ALIVE = os.path.join(DATA_DIR, "last-alive")
INTERVAL = int(os.environ.get("NETWATCH_INTERVAL", "5") or 5)
# last-alive is touched every cycle; allow a few missed cycles before
# declaring netwatch itself down.
STALE_SECS = max(30, INTERVAL * 6)
PORT = int(os.environ.get("NETWATCH_WEB_PORT", "8091") or 8091)

INCIDENT_NAME_RE = re.compile(r"^incident-\d{8}-\d{6}\.md$")


# ---------------------------------------------------------------------------
# Data-dir parsing
# ---------------------------------------------------------------------------

def read_last_alive():
    try:
        with open(LAST_ALIVE) as f:
            epoch, iso = f.read().split(None, 1)
        return int(epoch), iso.strip()
    except (OSError, ValueError):
        return None, None


def log_tail(n=25):
    try:
        with open(LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 64 * 1024))
            lines = f.read().decode(errors="replace").splitlines()
        return lines[-n:]
    except OSError:
        return []


def parse_incident(path):
    """Cheap single-pass parse of one report file."""
    name = os.path.basename(path)
    info = {
        "name": name,
        "start_iso": None,
        "first_failing": [],
        "verdict": None,
        "duration": None,
        "last_fail_line": None,
        "mtime": 0,
    }
    try:
        info["mtime"] = os.path.getmtime(path)
        with open(path, errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("# netwatch incident — "):
                    info["start_iso"] = line.split("— ", 1)[1]
                elif line.startswith("First failing probes: "):
                    info["first_failing"] = line.split(": ", 1)[1].split()
                elif line.startswith("VERDICT:") and not info["verdict"]:
                    info["verdict"] = line[len("VERDICT:"):].strip()
                elif line.startswith("Duration: "):
                    info["duration"] = line.split(": ", 1)[1]
                elif "  fail: " in line:
                    info["last_fail_line"] = line
    except OSError:
        return None
    return info


def incident_state(info, netwatch_fresh):
    """closed | open | interrupted — a verdict means closed; without one the
    file is live only while netwatch is running and still appending."""
    if info["verdict"] or info["duration"]:
        return "closed"
    if netwatch_fresh and time.time() - info["mtime"] < STALE_SECS:
        return "open"
    return "interrupted"


def failing_from_line(line):
    if not line or "fail: " not in line:
        return []
    probes = line.split("fail: ", 1)[1].strip()
    return [] if probes == "none" else probes.split()


def list_incidents():
    try:
        names = [n for n in os.listdir(INCIDENT_DIR) if INCIDENT_NAME_RE.match(n)]
    except OSError:
        return []
    names.sort(reverse=True)
    out = []
    for n in names:
        info = parse_incident(os.path.join(INCIDENT_DIR, n))
        if info:
            out.append(info)
    return out


def get_status():
    now = time.time()
    epoch, iso = read_last_alive()
    fresh = epoch is not None and now - epoch < STALE_SECS
    incidents = list_incidents()

    status = {
        "state": "ok",
        "detail": "",
        "alive_iso": iso,
        "alive_age": None if epoch is None else int(now - epoch),
        "failing": [],
        "playbook": None,
        "incident": None,
        "checked_at": int(now),
    }

    if not fresh:
        status["state"] = "stale"
        if epoch is None:
            status["detail"] = "no last-alive marker found — is the data dir mounted?"
        else:
            status["detail"] = (f"netwatch hasn't probed in {int(now - epoch)}s "
                                f"(last alive {iso}). The watchdog itself is down "
                                "— internet state is unknown.")
        return status, incidents

    open_inc = next((i for i in incidents
                     if incident_state(i, fresh) == "open"), None)
    if open_inc:
        failing = failing_from_line(open_inc["last_fail_line"]) \
                  or open_inc["first_failing"]
        pb = playbooks.classify(failing)
        status.update({
            "state": "outage",
            "failing": failing,
            "playbook": pb["id"] if pb else None,
            "incident": open_inc["name"],
            "detail": f"incident open since {open_inc['start_iso']}",
        })
    return status, incidents


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

STYLE = """
:root { color-scheme: light dark; --ok:#1a7f37; --bad:#c93c37; --warn:#b58900;
        --muted:#777; --card:#8881; --border:#8884; }
body { font-family: system-ui, sans-serif; max-width: 60rem; margin: 0 auto;
       padding: 1rem; line-height: 1.45; }
a { color: inherit; }
nav { display:flex; gap:1rem; align-items:baseline; margin-bottom:1rem; }
nav h1 { font-size:1.2rem; margin:0; } nav a { color:var(--muted); }
.banner { border-radius:8px; padding:1rem 1.2rem; margin-bottom:1rem;
          border:1px solid var(--border); }
.banner.ok { border-left:6px solid var(--ok); }
.banner.outage { border-left:6px solid var(--bad); }
.banner.stale { border-left:6px solid var(--warn); }
.banner h2 { margin:0 0 .3rem; font-size:1.1rem; }
.banner .sub { color:var(--muted); font-size:.9rem; }
.probes { margin:.4rem 0 0; }
.probe { display:inline-block; padding:.1rem .5rem; border-radius:99px;
         background:var(--bad); color:#fff; font-size:.8rem; margin:.15rem; }
.card { background:var(--card); border:1px solid var(--border);
        border-radius:8px; padding:1rem 1.2rem; margin-bottom:1rem; }
.card h3 { margin-top:0; }
.sev { font-size:.75rem; padding:.1rem .5rem; border-radius:99px; color:#fff;
       vertical-align:middle; }
.sev.local{background:var(--bad);} .sev.wait{background:var(--warn);}
.sev.ignore{background:var(--ok);} .sev.info{background:var(--muted);}
table { border-collapse:collapse; width:100%; font-size:.9rem; }
th,td { text-align:left; padding:.35rem .6rem; border-bottom:1px solid var(--border); }
td.v { color:var(--muted); }
.st { font-size:.75rem; padding:.05rem .45rem; border-radius:99px; color:#fff; }
.st.closed{background:var(--muted);} .st.open{background:var(--bad);}
.st.interrupted{background:var(--warn);}
pre, code { background:var(--card); border-radius:6px; }
pre { padding:.7rem; overflow-x:auto; font-size:.8rem;
      border:1px solid var(--border); }
code { padding:.1rem .3rem; }
.fix { margin:.6rem 0; }
details summary { cursor:pointer; color:var(--muted); }
footer { color:var(--muted); font-size:.8rem; margin-top:2rem; }
"""

POLL_JS = """
async function poll() {
  try {
    const r = await fetch('/api/status'); const s = await r.json();
    if (s.state !== document.body.dataset.state) { location.reload(); return; }
    const el = document.getElementById('age');
    if (el && s.alive_age !== null) el.textContent = s.alive_age + 's ago';
  } catch (e) { /* server briefly unreachable; keep trying */ }
}
setInterval(poll, 5000);
"""


def page(title, body, state="ok"):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title><style>{STYLE}</style></head>
<body data-state="{state}">
<nav><h1>netwatch</h1><a href="/">status</a>
<a href="/playbooks">playbooks</a></nav>
{body}
<footer>netwatch-web — data dir mounted read-only; probes every {INTERVAL}s.
<script>{POLL_JS}</script></footer></body></html>"""


def esc(s):
    return html.escape(str(s or ""))


def render_playbook_card(pb, compact=False):
    fixes = ""
    for f in pb["fixes"]:
        fixes += f'<div class="fix">{esc(f["desc"])}'
        if f.get("cmd"):
            fixes += f'<pre>{esc(f["cmd"])}</pre>'
        fixes += "</div>"
    body = "" if compact else (
        f'<p><b>Signature:</b> {esc(pb["signature"])}</p>'
        f'<p><b>Cause:</b> {esc(pb["cause"])}</p>'
        f'<p><b>Who\'s affected:</b> {esc(pb["just_me"])}</p>')
    return (f'<div class="card" id="{pb["id"]}">'
            f'<h3>{esc(pb["title"])} '
            f'<span class="sev {pb["severity"]}">{pb["severity"]}</span></h3>'
            f'{body}<b>What to do:</b>{fixes}</div>')


def render_index():
    status, incidents = get_status()
    fresh = status["state"] != "stale"

    if status["state"] == "outage":
        chips = "".join(f'<span class="probe">{esc(p)}</span>'
                        for p in status["failing"])
        banner = (f'<div class="banner outage"><h2>OUTAGE — '
                  f'{esc(status["detail"])}</h2>'
                  f'<div class="probes">{chips}</div>'
                  f'<div class="sub">report: <a href="/incident/'
                  f'{esc(status["incident"])}">{esc(status["incident"])}</a>'
                  f' · last probe <span id="age">{status["alive_age"]}s ago'
                  f'</span></div></div>')
        pb = playbooks.classify(status["failing"]) or playbooks.FALLBACK
        banner += render_playbook_card(pb)
    elif status["state"] == "stale":
        banner = (f'<div class="banner stale"><h2>netwatch not reporting</h2>'
                  f'<div class="sub">{esc(status["detail"])}</div></div>')
    else:
        banner = (f'<div class="banner ok"><h2>All probes passing</h2>'
                  f'<div class="sub">last probe <span id="age">'
                  f'{status["alive_age"]}s ago</span> ({esc(status["alive_iso"])})'
                  f'</div></div>')

    rows = ""
    for i in incidents[:60]:
        st = incident_state(i, fresh)
        pb = playbooks.classify_verdict(i["verdict"]) \
            or playbooks.classify(i["first_failing"])
        verdict = i["verdict"] or ("in progress" if st == "open"
                                   else "no verdict (interrupted by shutdown/reboot)")
        pb_link = (f' · <a href="/playbooks#{pb["id"]}">{esc(pb["title"])}</a>'
                   if pb else "")
        rows += (f'<tr><td><a href="/incident/{esc(i["name"])}">'
                 f'{esc(i["start_iso"] or i["name"])}</a></td>'
                 f'<td><span class="st {st}">{st}</span></td>'
                 f'<td>{esc(" ".join(i["first_failing"]))}</td>'
                 f'<td class="v">{esc(verdict)}{pb_link}</td></tr>')
    table = (f'<h2>Incidents ({len(incidents)})</h2><table>'
             f'<tr><th>start</th><th></th><th>first failing</th>'
             f'<th>verdict / playbook</th></tr>{rows}</table>') if rows \
        else "<p>No incidents recorded.</p>"

    tail = "\n".join(log_tail())
    log_block = (f'<details><summary>netwatch.log tail</summary>'
                 f'<pre>{esc(tail)}</pre></details>')
    return page("netwatch status", banner + table + log_block, status["state"])


def render_incident(name):
    path = os.path.join(INCIDENT_DIR, name)
    try:
        with open(path, errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    # If the incident is still open the snapshot lives in a sibling file.
    snap = ""
    try:
        with open(path + ".snapshot", errors="replace") as f:
            snap = f.read()
    except OSError:
        pass

    info = parse_incident(path)
    pb = None
    if info:
        pb = playbooks.classify_verdict(info["verdict"]) \
            or playbooks.classify(info["first_failing"])
    pb_card = render_playbook_card(pb) if pb else ""

    # Minimal markdown rendering: the reports are headings + fenced blocks.
    out, in_pre = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            out.append("</pre>" if in_pre else "<pre>")
            in_pre = not in_pre
        elif in_pre:
            out.append(esc(line))
        elif line.startswith("## "):
            out.append(f"<h2>{esc(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h2>{esc(line[2:])}</h2>")
        elif line.strip():
            out.append(f"<p>{esc(line)}</p>")
    if in_pre:
        out.append("</pre>")
    if snap:
        out.append("<h2>Snapshot (incident still open)</h2>")
        out.append(f"<pre>{esc(snap)}</pre>")
    return page(name, pb_card + "\n".join(out))


def render_playbooks():
    cards = "".join(render_playbook_card(p) for p in playbooks.PLAYBOOKS)
    cards += render_playbook_card(playbooks.FALLBACK)
    intro = ("<p>Known failure signatures for this network, matched "
             "automatically against the failing-probe set of live and past "
             "incidents.</p>")
    return page("netwatch playbooks", intro + cards)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/status":
            status, _ = get_status()
            return self._send(200, json.dumps(status), "application/json")
        if path == "/":
            return self._send(200, render_index())
        if path == "/playbooks":
            return self._send(200, render_playbooks())
        if path.startswith("/incident/"):
            name = os.path.basename(path[len("/incident/"):])
            if INCIDENT_NAME_RE.match(name):
                body = render_incident(name)
                if body is not None:
                    return self._send(200, body)
        return self._send(404, page("not found", "<p>Not found.</p>"))

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # quiet access log
        pass


if __name__ == "__main__":
    print(f"netwatch-web serving on :{PORT} — data dir {DATA_DIR}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

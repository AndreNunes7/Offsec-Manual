# OffSec Manual — Pi Agent

Companion service for [OffSec Manual](../index.html). It runs on a Raspberry
Pi (or any machine with the tools installed) and exposes a small HTTP API
that the app's "Executar via Pi" buttons call to trigger real recon/vuln
scans and pull back structured results.

This is a **deliberate exception** to the main app's "no backend, single
file" rule — see the "Pi Agent" section of `../CLAUDE.md` for why. The two
stay decoupled: `index.html` keeps working standalone with zero setup; this
agent only matters if you want the "Executar via Pi" buttons to do anything.

## Requirements

- Python 3.7+ (stdlib only — no `pip install`, nothing to break on a headless Pi)
- Whichever scanning tools you want to use, installed and on `PATH`:
  [`nmap`](https://nmap.org/), [`subfinder`](https://github.com/projectdiscovery/subfinder),
  [`httpx`](https://github.com/projectdiscovery/httpx), [`nuclei`](https://github.com/projectdiscovery/nuclei),
  [`sqlmap`](https://github.com/sqlmapproject/sqlmap) (active SQL injection testing),
  [`dalfox`](https://github.com/hahwul/dalfox) (XSS scanning),
  and/or [`OblivionSec`](https://github.com/AndreNunes7/OblivionSec) (`pip install -e .`
  in its repo gives the `oblivion` command — five of its subcommands are wired in:
  `subdomains`, `passive`, `webrecon` (directory/file brute force), `webvuln`, `exposed`).
  `GET /api/v1/health` reports which of these are actually found on `PATH` —
  you don't need all of them to use the ones you have.
  `sqlmap` and `dalfox` run active injection attempts (not passive recon) — only point
  them at targets you're explicitly authorized to test, same as everything else here.
  `dalfox`'s JSON field names have shifted across releases; if a run finishes with no
  findings despite exit code 0, check `parse_dalfox_json()` in `parsers.py` against your
  installed version's actual output.
- [`ffuf`](https://github.com/ffuf/ffuf) needs wordlists in `pi-agent/wordlists/` — three
  files from [SecLists](https://github.com/danielmiessler/SecLists)'s `Discovery/Web-Content/`
  (`raft-medium-directories.txt`, `raft-small-directories.txt`, `common.txt`). No `sudo`
  needed — download them straight into the agent's own directory instead of the full
  SecLists repo or a system-wide `/usr/share/seclists/` install:
  ```bash
  cd pi-agent && mkdir -p wordlists
  base=https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content
  for f in raft-medium-directories raft-small-directories common; do
    curl -sSL -o wordlists/$f.txt $base/$f.txt
  done
  ```
  `tools.py`'s `FFUF_WORDLISTS` resolves these paths relative to the script directory, so
  this works regardless of where `pi-agent/` is checked out. Without them, `POST
  /api/v1/jobs` for ffuf returns a `400` naming the missing file instead of silently
  failing; `GET /api/v1/health`'s `wordlists` field also reports which of the three are
  actually present.
- [`wafw00f`](https://github.com/EnableSecurity/wafw00f) and [`arjun`](https://github.com/s0md3v/Arjun)
  install with plain `pip3 install --user wafw00f arjun` — no sudo, no system package.
  [`katana`](https://github.com/projectdiscovery/katana) is a Go binary, same install style
  as `subfinder`/`httpx`/`nuclei` (`go install github.com/projectdiscovery/katana/cmd/katana@latest`).

## Optional tools (testssl.sh, wpscan, nikto, osv-scanner)

Not installed by default and not covered above — `GET /api/v1/health`'s `tools` field
reports which of the full 20-tool set are actually on `PATH`, and the app's Pipeline tab
marks anything missing as "não instalado" and skips it in "Rodar tudo" instead of trying
and failing. Install whichever you want from their own projects
([testssl.sh](https://github.com/drwetter/testssl.sh),
[wpscan](https://github.com/wpscanteam/wpscan), [nikto](https://github.com/sullo/nikto),
[osv-scanner](https://github.com/google/osv-scanner)) and re-check `/api/v1/health`.

## Setup

```bash
cd pi-agent
cp config.example.json config.json
```

Edit `config.json`:
- **`token`** — replace `CHANGE_ME_INSECURE_DEFAULT` with a long random string
  (e.g. `python3 -c "import secrets;print(secrets.token_hex(32))"`). This is
  the only thing standing between anything on your network and the ability
  to run scans through this agent — do not skip it.
- **`bind`** — `127.0.0.1` by default (only reachable from the same machine —
  fine for testing the agent without a Pi, see below). To actually use it
  from the browser on another machine, set this to the Pi's LAN IP (e.g.
  `192.168.1.50`). **Never** set this to `0.0.0.0` and expose it to the
  internet — there is no rate limiting or IP allowlisting here beyond the
  bearer token, this is a LAN-only tool for your own authorized engagements.
- **`job_timeout_seconds`** — default `1800` (30 min). A running scan process
  is killed and the job marked `error` if it exceeds this.

Run it:

```bash
python3 agent.py
```

`config.json` is gitignored — your real token never gets committed.

### Running as a systemd service on the Pi (optional)

```ini
# /etc/systemd/system/offsec-pi-agent.service
[Unit]
Description=OffSec Manual Pi Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/pi/offsec-manual/pi-agent/agent.py
WorkingDirectory=/home/pi/offsec-manual/pi-agent
Restart=on-failure
User=pi

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now offsec-pi-agent
```

## Connecting from the app

In OffSec Manual, open the engagement modal → "Agente Pi" section, and set
the URL (e.g. `http://192.168.1.50:8787`) and the token from your
`config.json`. Then open **Automação (Agente Pi)** in the sidebar — all
scanning lives there now, grouped by PTES stage (Recon, Information
Gathering, Scanning, Vulnerability Analysis, Exploitation — each stage card
shows its PTES §-reference, and each tool in the legend carries its own
MITRE ATT&CK/CWE/OWASP tags), with a single "Rodar tudo via Pi" button that
runs every configured tool against the session's target in sequence and
drops the results into Achados as drafts. There is no separate confirmation
checkbox before that button — the server already requires `confirm: true`
on every job request regardless of what the UI sends (see Security notes
below), so the checkbox was pure click-friction with no actual gate behind
it, and was removed.

## Security notes

- **Every** endpoint requires `Authorization: Bearer <token>`, including
  `/health` — an unauthenticated health check would still leak which tools
  are installed.
- Target/parameter validation happens **again on the server**, even though
  the browser also validates — never trust the client. Targets must match a
  conservative hostname/IP/CIDR charset; tool parameters are restricted to a
  small fixed enum (e.g. nmap's scan profile, nuclei's severity list) —
  never a free-text flags string.
- Commands are run via `subprocess.Popen(argv, shell=False)` with an argv
  list built from the allowlist in `tools.py` — there is no shell to inject
  into even if validation somehow had a gap.
- No HTTPS is implemented here. If you need the LAN hop encrypted, put a
  reverse proxy (e.g. Caddy, nginx) in front of the agent — out of scope for
  this script.
- No accounts, no per-tool permissions, no request signing beyond the bearer
  token. This is intentionally minimal for a personal, single-user tool —
  not a multi-tenant product.

## Testing without a physical Raspberry Pi

Run the agent on your own dev machine and point the app at `localhost`:

```bash
python3 agent.py
```

Then in the app's "Agente Pi" settings, use `http://127.0.0.1:8787` and the
token from `config.json`. For a safe test target, use
[`scanme.nmap.org`](https://nmap.org/book/testing.html) — nmap's own
publicly, explicitly authorized scanning target — rather than scanning
anything you don't control. Verify:

- `GET /api/v1/health` reflects the tools you actually have installed locally.
- A full job lifecycle: `POST /api/v1/jobs` → poll `GET /api/v1/jobs/{id}` →
  `GET /api/v1/jobs/{id}/result` once `status` is `done`.
- A request with a missing/wrong token gets `401` on every route.
- A request with `confirm` missing or `false` gets rejected with `400`.

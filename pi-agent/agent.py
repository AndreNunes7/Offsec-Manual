#!/usr/bin/env python3
"""OffSec Manual — Pi Agent.

Minimal HTTP API (stdlib only, no pip install needed) that runs real recon/
vuln tools (nmap, subfinder, httpx, nuclei) on request from the OffSec Manual
browser app and hands back normalized, finding-shaped results.

LAN-only by design: every route requires a bearer token, there is no rate
limiting or IP allowlisting beyond that token, and it is not meant to be
exposed to the internet. See README.md before running this anywhere but a
trusted home/lab network.
"""
import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from jobs import JobManager  # noqa: E402
from tools import FFUF_WORDLISTS, TOOL_REGISTRY, validate_params, validate_session, validate_target  # noqa: E402

CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.json')
EXAMPLE_CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.example.json')

JOB_ROUTE_RE = re.compile(r'^/api/v1/jobs/([a-f0-9]{6,32})$')
JOB_RESULT_ROUTE_RE = re.compile(r'^/api/v1/jobs/([a-f0-9]{6,32})/result$')
JOB_RAW_ROUTE_RE = re.compile(r'^/api/v1/jobs/([a-f0-9]{6,32})/raw$')
JOB_CANCEL_ROUTE_RE = re.compile(r'^/api/v1/jobs/([a-f0-9]{6,32})/cancel$')


def load_config():
    path = CONFIG_PATH if os.path.isfile(CONFIG_PATH) else EXAMPLE_CONFIG_PATH
    if path == EXAMPLE_CONFIG_PATH:
        sys.stderr.write(
            'AVISO: config.json não encontrado — usando config.example.json (token padrão inseguro).\n'
            'Copie config.example.json para config.json e troque o token antes de usar isto de verdade.\n'
        )
    with open(path, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    cfg.setdefault('bind', '127.0.0.1')
    cfg.setdefault('port', 8787)
    cfg.setdefault('job_timeout_seconds', 1800)
    cfg.setdefault('retention_days', 7)
    cfg.setdefault('max_jobs', 200)
    # (v25) quantos scans rodam simultaneamente; o resto fica 'queued' até abrir slot.
    cfg.setdefault('max_concurrent_jobs', 2)
    jobs_dir = cfg.get('jobs_dir', 'jobs')
    if not os.path.isabs(jobs_dir):
        jobs_dir = os.path.join(SCRIPT_DIR, jobs_dir)
    cfg['jobs_dir'] = jobs_dir
    return cfg


CONFIG = load_config()
JOBS = JobManager(CONFIG['jobs_dir'], timeout_seconds=CONFIG['job_timeout_seconds'],
                  max_concurrent=CONFIG.get('max_concurrent_jobs', 2))


class Handler(BaseHTTPRequestHandler):
    server_version = 'OffSecPiAgent/1.0'

    # ---- helpers ----------------------------------------------------
    def _cors(self):
        # index.html opened via file:// (double-clicked, not served) sends either no
        # Origin header or the literal string "null" — echoing that back as
        # Access-Control-Allow-Origin is spec-ambiguous and some browsers refuse it,
        # which surfaces to the user as a bare "Failed to fetch" with no server-side
        # trace. Neither case carries credentials (no cookies, just a manually-attached
        # Bearer header), so falling back to a wildcard is safe here.
        origin = self.headers.get('Origin')
        if origin and origin != 'null':
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        else:
            self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        # Chrome's Private Network Access (v28): a page whose own address isn't already
        # "private" — which includes a file:// page, since file:// has no network address at
        # all — sends `Access-Control-Request-Private-Network: true` on the CORS preflight
        # before it'll let fetch() reach a LAN/private IP like this agent's. Without echoing
        # this back, the preflight itself succeeds but Chrome silently kills the real
        # request client-side — surfaces to the user as a bare "Failed to fetch" with
        # nothing in this server's access log, since the request never actually lands here.
        if self.headers.get('Access-Control-Request-Private-Network') == 'true':
            self.send_header('Access-Control-Allow-Private-Network', 'true')

    def _json(self, status, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(status)
        self._cors()
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return False
        token = auth[len('Bearer '):]
        return hmac.compare_digest(token, CONFIG['token'])

    # ---- routes -------------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if not self._authorized():
            return self._json(401, {'error': 'unauthorized'})
        path = urlparse(self.path).path

        if path == '/api/v1/health':
            tools = {name: shutil.which(spec['bin']) is not None for name, spec in TOOL_REGISTRY.items()}
            wordlists = {name: os.path.isfile(p) for name, p in FFUF_WORDLISTS.items()}
            return self._json(200, {'ok': True, 'tools': tools, 'wordlists': wordlists})

        if path == '/api/v1/jobs':
            return self._json(200, {'jobs': JOBS.list_jobs()})

        m = JOB_RESULT_ROUTE_RE.match(path)
        if m:
            meta = JOBS.get_status(m.group(1))
            if meta is None:
                return self._json(404, {'error': 'not found'})
            if meta['status'] != 'done':
                return self._json(409, {'error': 'job not done', 'status': meta['status']})
            return self._json(200, {'result': JOBS.get_result(m.group(1)) or [], 'warning': meta.get('warning')})

        m = JOB_RAW_ROUTE_RE.match(path)
        if m:
            raw = JOBS.get_raw(m.group(1))
            if raw is None:
                return self._json(404, {'error': 'not found'})
            self.send_response(200)
            self._cors()
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        m = JOB_ROUTE_RE.match(path)
        if m:
            meta = JOBS.get_status(m.group(1))
            if meta is None:
                return self._json(404, {'error': 'not found'})
            return self._json(200, meta)

        return self._json(404, {'error': 'not found'})

    def do_POST(self):
        if not self._authorized():
            return self._json(401, {'error': 'unauthorized'})
        path = urlparse(self.path).path
        # Cancelar um job em execução (v27) — o botão "Parar" do pipeline chama isto por job.
        m = JOB_CANCEL_ROUTE_RE.match(path)
        if m:
            ok = JOBS.cancel_job(m.group(1))
            return self._json(200 if ok else 404, {'ok': ok})
        if path != '/api/v1/jobs':
            return self._json(404, {'error': 'not found'})

        length = int(self.headers.get('Content-Length', 0) or 0)
        raw_body = self.rfile.read(length) if length else b'{}'
        try:
            body = json.loads(raw_body or b'{}')
        except ValueError:
            return self._json(400, {'error': 'invalid json'})
        if not isinstance(body, dict):
            return self._json(400, {'error': 'invalid json'})

        tool = body.get('tool')
        target = body.get('target', '')
        params = body.get('params') or {}
        session = body.get('session') or ''
        confirm = body.get('confirm')

        if confirm is not True:
            return self._json(400, {'error': 'confirm must be true'})
        if tool not in TOOL_REGISTRY:
            return self._json(400, {'error': 'unknown tool'})
        if not validate_target(target):
            return self._json(400, {'error': 'invalid target'})
        if not validate_params(tool, params):
            return self._json(400, {'error': 'invalid params'})
        if not validate_session(session):
            return self._json(400, {'error': 'invalid session header'})
        if shutil.which(TOOL_REGISTRY[tool]['bin']) is None:
            return self._json(400, {'error': 'tool not installed on agent: ' + tool})
        check_fn = TOOL_REGISTRY[tool].get('preflight_check')
        if check_fn:
            err = check_fn(params)
            if err:
                return self._json(400, {'error': err})

        try:
            job_id = JOBS.start_job(tool, target, params, session or None)
        except ValueError as exc:
            # Ex.: alvo que o nmap não consegue escanear (URL/path cru) — builder recusa na
            # hora com mensagem clara em vez de morrer a thread e deixar o cliente no escuro.
            return self._json(400, {'error': str(exc)})
        return self._json(201, {'jobId': job_id, 'status': 'queued'})

    def do_DELETE(self):
        if not self._authorized():
            return self._json(401, {'error': 'unauthorized'})
        m = JOB_ROUTE_RE.match(urlparse(self.path).path)
        if not m:
            return self._json(404, {'error': 'not found'})
        ok = JOBS.delete_job(m.group(1))
        return self._json(200 if ok else 404, {'ok': ok})

    def log_message(self, fmt, *args):
        sys.stderr.write('%s - %s\n' % (self.address_string(), fmt % args))


def _open_bound_socket(host, port):
    """Create a TCP socket bound to host:port.

    Raises OSError (errno 99 / EADDRNOTAVAIL) when the interface holding `host`
    is not up yet — the exact boot-time failure this module exists to survive.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    return sock


def _current_lan_ip():
    """Resolve this machine's current non-loopback IPv4, for the explicit fallback.

    Prefers `hostname -I`; falls back to `ip -o -4 addr show` (both stock on
    Raspberry Pi OS). Returns a concrete host — never 0.0.0.0 — because binding
    to 0.0.0.0 would expose the agent on every interface, which this LAN-only
    project must never do.
    """
    for cmd in (('hostname', '-I'), ('ip', '-o', '-4', 'addr', 'show')):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for word in re.findall(r'\d+\.\d+\.\d+\.\d+', out or ''):
            if not word.startswith('127.'):
                return word
    return None


def _bind_with_retry(bind_host, port, retry_interval=5.0, min_wait=120.0):
    """Return (bound_socket, actual_host), surviving slow interface bring-up at boot.

    At boot the address in CONFIG['bind'] (usually the wlan0 IP) may not exist
    yet — `_open_bound_socket` fails with EADDRNOTAVAIL (errno 99) and the whole
    agent used to die. This retries every `retry_interval` seconds for at least
    `min_wait` seconds so a slowly-coming-up interface is simply waited on. If
    the configured address never appears, it falls back to the machine's current
    LAN IP (`_current_lan_ip`) and binds that instead — still a concrete host,
    never 0.0.0.0 — logging the swap loudly so the config mismatch is visible.
    A fixed 5s cadence was chosen over exponential backoff because the interface
    either comes up or not; a constant interval keeps the boot wait bounded and
    the retry log readable.
    """
    start = time.monotonic()
    last_err = None
    while True:
        try:
            return _open_bound_socket(bind_host, port), bind_host
        except OSError as e:
            last_err = e
            elapsed = time.monotonic() - start
            sys.stderr.write(
                'bind %s:%s falhou (após %.0fs de espera): %s\n' % (bind_host, port, elapsed, e)
            )
            if elapsed >= min_wait:
                break
            time.sleep(retry_interval)
    fallback = _current_lan_ip()
    if fallback and fallback != bind_host:
        try:
            sock = _open_bound_socket(fallback, port)
            sys.stderr.write(
                'AVISO: IP configurado %s indisponível após %.0fs — bindando em %s '
                '(IP LAN atual). Corrija config.json se o IP do host mudou.\n'
                % (bind_host, min_wait, fallback)
            )
            return sock, fallback
        except OSError as e:
            last_err = e
    raise OSError('impossível bindar %s:%s: %s' % (bind_host, port, last_err))


def main():
    JOBS.cleanup(CONFIG.get('retention_days', 7), CONFIG.get('max_jobs', 200))
    sock, bound_host = _bind_with_retry(CONFIG['bind'], CONFIG['port'])
    # The retry loop above already bound the socket; construct the server without
    # binding again (bind_and_activate=False) and hand it the live socket, so the
    # bind happens exactly once and with the host we actually bound.
    server = ThreadingHTTPServer((bound_host, CONFIG['port']), Handler, bind_and_activate=False)
    server.socket.close()
    server.socket = sock
    server.server_address = (bound_host, CONFIG['port'])
    server.server_name = bound_host
    server.server_port = CONFIG['port']
    server.server_activate()
    print('OffSec Pi Agent ouvindo em http://%s:%s (jobs_dir=%s)' % (bound_host, CONFIG['port'], CONFIG['jobs_dir']))
    if bound_host not in ('127.0.0.1', 'localhost'):
        sys.stderr.write(
            'AVISO: bind fora de localhost — confirme que esta é uma LAN confiável.\n'
            'Este agente não tem rate limit nem allowlist de IP além do token.\n'
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()

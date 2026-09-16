"""Parsers that turn raw tool output into the normalized finding shape:
{ title, severity, affected, description, evidence, sourceTool, meta }
severity is always one of: info | baixo | medio | alto | critico

`meta` (added — see index.html's "Achados & Relatório"/Pi Agent notes in CLAUDE.md for the
full rationale) is an optional flat dict of tool-specific structured fields — port/service
for nmap, status code/title/tech for httpx, etc. It rides alongside the free-text `evidence`
string (still used for the Markdown report) so the browser can render a real table instead
of regex-guessing structure out of aggregated evidence text. Every parser below is free to
omit `meta` or leave it as {} — the frontend falls back to its text heuristic either way.
Values must be JSON-serializable (str/int/float/bool/None only)."""
import glob
import json
import os
import re
import xml.etree.ElementTree as ET

_TRUNCATE_MAX = 8000
_TRUNCATE_MARKER = '\n…[truncado]'


def _truncate(text, max_len=_TRUNCATE_MAX):
    """Corta um texto longo (evidência de scanner) num limite alto com marcador
    explícito, em vez de um slice silencioso que perde dado sem avisar. Aceita
    qualquer JSON-serializable; dicts/listas são achatados com json.dumps."""
    if not isinstance(text, str):
        text = json.dumps(text, ensure_ascii=False)
    if len(text) <= max_len:
        return text
    return text[:max_len - len(_TRUNCATE_MARKER)] + _TRUNCATE_MARKER


def _short(text, n=90):
    """Versão curta e legível de um texto pra cabeçalho (título) de achado — colapsa
    quebras/espaços, corta sem partir palavra e avisa com '…'. O corpo completo sempre vai
    pra evidência/meta; o título só precisa ser escaneável. Era isso que faltava no
    'Header de segurança: HTTPConnectionPool(...)' gigante que o usuário reclamou."""
    if not text:
        return ''
    text = re.sub(r'\s+', ' ', str(text)).strip()
    if len(text) <= n:
        return text
    cut = text[:n]
    last = cut.rfind(' ')
    if last > n * 0.5:
        cut = cut[:last]
    return cut.rstrip(',;:- ') + '…'


# Indicadores de falha de conexão/DNS que o oblivion passive despeja cru no campo `issue`.
# Quando o texto bate aqui, não é um header faltando: é o alvo fora do alcance — vira um
# achado `info` próprio ("Falha de conexão com o alvo") em vez de um falso "baixo" com o
# trace completo no título.
_CONN_ERROR_HINTS = (
    'não foi possível conectar', 'nao foi possivel conectar',
    'max retries exceeded', 'nameresolutionerror', 'failed to resolve',
    'failed to connect', 'connectionerror', 'connection refused',
    'connection timed out', 'timed out', 'timeout', 'unreachable',
    'host not found', 'dns', 'errno', 'name or service not known',
)


def _is_conn_error(text):
    t = (text or '').lower()
    return any(h in t for h in _CONN_ERROR_HINTS)


# Reedição ofensiva das mensagens DEFENSIVAS que o oblivion passive despeja em `issues`
# (origem: Oblivion/oblivion/recon/passive.py — SECURITY_HEADERS, ex. "Protege contra
# downgrade para HTTP (HSTS ausente)."). Esta é uma ferramenta ofensiva: o achado deve
# dizer o que o ATACANTE consegue fazer por causa da ausência do header, não que o
# defensor perdeu uma proteção. Cada entrada é (titulo_curto, detalhe): o TÍTULO fica
# enxuto na lista ("HSTS ausente") e o resto ("permite downgrade HTTPS→HTTP...") vai pro
# meta.attack/detail, que a UI mostra no detalhamento do achado — títulos gigantes eram
# exatamente o que o usuário reclamou. A chave é o token que o texto do issue contém;
# o texto original segue preservado em `evidence`/`meta.issue`.
_OFFENSIVE_HEADER_MAP = {
    'hsts': ('HSTS ausente', 'Permite downgrade HTTPS→HTTP e sequestro de sessão via sniffing'),
    'csp': ('CSP ausente', 'XSS/injeção de conteúdo sem bloqueio do navegador'),
    'x-frame-options': ('Clickjacking viável', 'Falta X-Frame-Options (UI redressing da vítima)'),
    'x-content-type-options': ('MIME sniffing viável', 'Falta X-Content-Type-Options (smuggle de script/upload)'),
    'referrer-policy': ('Vazamento de URLs via Referer', 'Falta Referrer-Policy (token/query vazam para terceiros)'),
    'permissions-policy': ('APIs sensíveis liberadas', 'Falta Permissions-Policy (camera/mic/location via embeds)'),
}


def _offensive_header_issue(issue):
    """Reescreve o texto defensivo do oblivion passive no ponto de vista do atacante.
    Devolve (titulo_curto, detalhe) quando o texto casa com um header conhecido (ou com o
    CORS permissivo); None quando não casa — aí o texto cru segue como antes."""
    t = (issue or '').lower()
    for token, (title, detail) in _OFFENSIVE_HEADER_MAP.items():
        if token in t:
            return title, detail
    if 'cors' in t and ('permissivo' in t or 'access-control-allow-origin' in t):
        return 'CORS permissivo', 'Qualquer origem pode ler a resposta (Access-Control-Allow-Origin: *)'
    return None


NUCLEI_SEVERITY_MAP = {
    'critical': 'critico',
    'high': 'alto',
    'medium': 'medio',
    'low': 'baixo',
    'info': 'info',
}

# oblivion webvuln já usa a mesma escala (critical/high/medium/low/info) do nuclei.
OBLIVION_SEVERITY_MAP = NUCLEI_SEVERITY_MAP


def parse_nmap_xml(path):
    results = []
    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError, OSError):
        return results
    root = tree.getroot()
    for host in root.findall('host'):
        addr_el = host.find('address')
        addr = addr_el.get('addr') if addr_el is not None else '?'
        ports_el = host.find('ports')
        if ports_el is None:
            continue
        for port in ports_el.findall('port'):
            state_el = port.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            portid = port.get('portid', '?')
            proto = port.get('protocol', 'tcp')
            service_el = port.find('service')
            svc_name = service_el.get('name', '') if service_el is not None else ''
            product = service_el.get('product', '') if service_el is not None else ''
            version = service_el.get('version', '') if service_el is not None else ''
            banner = ' '.join(p for p in (svc_name, product, version) if p)
            results.append({
                'title': 'Porta aberta %s/%s — %s' % (portid, proto, banner or svc_name or 'desconhecido'),
                'severity': 'info',
                'affected': '%s:%s' % (addr, portid),
                'description': 'nmap — detecção de serviço/versão.',
                'evidence': '%s/%s open %s' % (portid, proto, banner),
                'sourceTool': 'nmap',
                'meta': {'host': addr, 'port': portid, 'protocol': proto, 'service': svc_name, 'product': product, 'version': version},
            })
    return results


def parse_subfinder_jsonl(path):
    results = []
    try:
        f = open(path, 'r', encoding='utf-8', errors='ignore')
    except (FileNotFoundError, OSError):
        return results
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            host = None
            try:
                obj = json.loads(line)
                host = obj.get('host') or obj.get('input')
            except ValueError:
                host = line
            if not host:
                continue
            results.append({
                'title': 'Subdomínio descoberto: %s' % host,
                'severity': 'info',
                'affected': host,
                'description': 'Descoberto via subfinder.',
                'evidence': host,
                'sourceTool': 'subfinder',
                'meta': {'host': host},
            })
    return results


def parse_httpx_jsonl(path):
    results = []
    try:
        f = open(path, 'r', encoding='utf-8', errors='ignore')
    except (FileNotFoundError, OSError):
        return results
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            url = obj.get('url') or obj.get('input') or ''
            status = obj.get('status_code', obj.get('status-code', ''))
            title = obj.get('title', '')
            tech = ', '.join(obj.get('tech') or [])
            label = url
            if status:
                label += ' (%s%s)' % (status, ', ' + tech if tech else '')
            results.append({
                'title': 'Host ativo: %s' % (label or url),
                'severity': 'info',
                'affected': url,
                'description': 'Probe HTTP via httpx.' + (' Título: ' + title if title else ''),
                'evidence': _truncate(obj),
                'sourceTool': 'httpx',
                'meta': {
                    'statusCode': status, 'title': title, 'tech': tech,
                    'webServer': obj.get('webserver', ''),
                    'contentLength': obj.get('content_length', obj.get('content-length', '')),
                },
            })
    return results


def parse_nuclei_jsonl(path):
    results = []
    try:
        f = open(path, 'r', encoding='utf-8', errors='ignore')
    except (FileNotFoundError, OSError):
        return results
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            info = obj.get('info') or {}
            sev = NUCLEI_SEVERITY_MAP.get(str(info.get('severity', 'info')).lower(), 'info')
            evidence = obj.get('extracted-results') or obj.get('curl-command') or obj
            results.append({
                'title': info.get('name', obj.get('template-id', 'Achado nuclei')),
                'severity': sev,
                'affected': obj.get('matched-at') or obj.get('host') or '',
                'description': info.get('description', '') or ('Template: %s' % obj.get('template-id', '')),
                'evidence': _truncate(evidence),
                'sourceTool': 'nuclei',
                'meta': {
                    'templateId': obj.get('template-id', ''), 'matcherName': obj.get('matcher-name', ''),
                    'tags': ', '.join(info.get('tags') or []),
                },
            })
    return results


def _read_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, OSError, ValueError):
        return None


def parse_oblivion_subdomains(path):
    """`oblivion subdomains -d <domain> -o <path> --format json` -> JSON array of hostnames."""
    data = _read_json(path)
    results = []
    for host in (data or []):
        results.append({
            'title': 'Subdomínio descoberto: %s' % host,
            'severity': 'info',
            'affected': host,
            'description': 'oblivion subdomains — crt.sh, Wayback, OTX, HackerTarget, Anubis.',
            'evidence': host,
            'sourceTool': 'oblivion-subdomains',
            'meta': {'host': host},
        })
    return results


def parse_oblivion_passive(path):
    """`oblivion passive -u <url>` -> {subdomains: [...], security_headers: {...}, fingerprint: {...}}."""
    data = _read_json(path) or {}
    results = []
    for host in (data.get('subdomains') or []):
        results.append({
            'title': 'Subdomínio descoberto (passive): %s' % host,
            'severity': 'info',
            'affected': host,
            'description': 'oblivion passive — crt.sh.',
            'evidence': host,
            'sourceTool': 'oblivion-passive',
            'meta': {'host': host},
        })
    headers = data.get('security_headers') or {}
    for issue in (headers.get('issues') or []):
        if _is_conn_error(issue):
            results.append({
                'title': 'Falha de conexão com o alvo',
                'severity': 'info',
                'affected': headers.get('url', ''),
                'description': 'oblivion passive — não foi possível estabelecer conexão com o alvo para checar headers de segurança. O host pode estar fora do ar, sem resposta, ou o alvo informado está inválido.',
                'evidence': issue,
                'sourceTool': 'oblivion-passive',
                'meta': {'error': issue},
            })
            continue
        off = _offensive_header_issue(issue)
        if off:
            title, detail = off
            results.append({
                'title': title,
                'severity': 'baixo',
                'affected': headers.get('url', ''),
                'description': 'oblivion passive — header de segurança ausente no alvo: %s — %s. O texto original do scanner segue na evidência.' % (title, detail),
                'evidence': issue,
                'sourceTool': 'oblivion-passive',
                'meta': {'issue': issue, 'attack': '%s — %s' % (title, detail)},
            })
            continue
        results.append({
            'title': 'Header de segurança: %s' % _short(issue, 90),
            'severity': 'baixo',
            'affected': headers.get('url', ''),
            'description': 'oblivion passive — checagem de headers de segurança.',
            'evidence': issue,
            'sourceTool': 'oblivion-passive',
            'meta': {'issue': issue},
        })
    fp = data.get('fingerprint') or {}
    if fp.get('guesses') or fp.get('server') or fp.get('powered_by') or fp.get('generator'):
        parts = []
        if fp.get('server'):
            parts.append('Server: %s' % fp['server'])
        if fp.get('powered_by'):
            parts.append('X-Powered-By: %s' % fp['powered_by'])
        if fp.get('generator'):
            parts.append('Generator: %s' % fp['generator'])
        if fp.get('guesses'):
            parts.append('Tecnologias: %s' % ', '.join(fp['guesses']))
        results.append({
            'title': 'Fingerprint de tecnologia',
            'severity': 'info',
            'affected': fp.get('url', ''),
            'description': 'oblivion passive — fingerprint.',
            'evidence': '; '.join(parts),
            'sourceTool': 'oblivion-passive',
            'meta': {'server': fp.get('server', ''), 'poweredBy': fp.get('powered_by', ''), 'tech': ', '.join(fp.get('guesses') or [])},
        })
    return results


def parse_oblivion_webrecon(path):
    """`oblivion webrecon -u <url>` (brute force de diretórios/arquivos) -> JSON array de hits."""
    data = _read_json(path)
    results = []
    for hit in (data or []):
        results.append({
            'title': '%s encontrado: %s' % (hit.get('type', 'Caminho'), hit.get('url', '')),
            'severity': 'info',
            'affected': hit.get('url', ''),
            'description': 'oblivion webrecon — brute force de diretórios/arquivos.',
            'evidence': 'status=%s size=%s' % (hit.get('status'), hit.get('size')),
            'sourceTool': 'oblivion-webrecon',
            'meta': {'statusCode': hit.get('status'), 'size': hit.get('size'), 'type': hit.get('type', '')},
        })
    return results


def parse_oblivion_webvuln(path):
    """`oblivion webvuln -u <url>` -> {url, findings: [{check, severity, detail}]}."""
    data = _read_json(path) or {}
    url = data.get('url', '')
    results = []
    for finding in (data.get('findings') or []):
        sev = OBLIVION_SEVERITY_MAP.get(str(finding.get('severity', 'info')).lower(), 'info')
        results.append({
            'title': 'Web vuln (%s)' % finding.get('check', '?'),
            'severity': sev,
            'affected': url,
            'description': 'oblivion webvuln — checagem: %s.' % finding.get('check', ''),
            'evidence': finding.get('detail', ''),
            'sourceTool': 'oblivion-webvuln',
            'meta': {'check': finding.get('check', '')},
        })
    return results


def parse_oblivion_exposed(path):
    """`oblivion exposed -u <url>` -> JSON array de {url, status, evidence}."""
    data = _read_json(path)
    results = []
    for hit in (data or []):
        results.append({
            'title': 'Arquivo sensível exposto: %s' % hit.get('url', ''),
            'severity': 'alto',
            'affected': hit.get('url', ''),
            'description': 'oblivion exposed — caminho sensível conhecido acessível.',
            'evidence': hit.get('evidence') or ('status=%s' % hit.get('status')),
            'sourceTool': 'oblivion-exposed',
            'meta': {'statusCode': hit.get('status')},
        })
    return results


_SQLMAP_PARAM_RE = re.compile(r'^Parameter:\s*(.+)$', re.MULTILINE)
_SQLMAP_TYPE_RE = re.compile(r'^\s*Type:\s*(.+)$', re.MULTILINE)
_SQLMAP_TITLE_RE = re.compile(r'^\s*Title:\s*(.+)$', re.MULTILINE)
_SQLMAP_PAYLOAD_RE = re.compile(r'^\s*Payload:\s*(.+)$', re.MULTILINE)
# `--dbs` (v26 `enumerate` param) prints "available databases [N]:" followed by one
# "[*] <name>" line per database, outside the '---'-delimited injection blocks above.
_SQLMAP_DBS_RE = re.compile(r'available databases \[\d+\]:\n((?:\[\*\]\s*.+\n?)+)')


def parse_sqlmap_log(path):
    """sqlmap --output-dir=<job_dir> -> <job_dir>/<host>/log, texto com blocos
    delimitados por linhas '---' e um 'Parameter: <nome> (<método>)' por parâmetro
    injetável encontrado. path aqui é o raw_path (arquivo que sqlmap nunca escreve — ver
    comentário em build_sqlmap_argv) então usamos seu diretório pra achar o log de verdade."""
    job_dir = os.path.dirname(path)
    results = []
    for log_path in glob.glob(os.path.join(job_dir, '*', 'log')):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except OSError:
            continue
        blocks = re.split(r'\n-{3,}\n', text)
        for block in blocks:
            m = _SQLMAP_PARAM_RE.search(block)
            if not m:
                continue
            param = m.group(1).strip()
            types = _SQLMAP_TYPE_RE.findall(block)
            titles = _SQLMAP_TITLE_RE.findall(block)
            payloads = _SQLMAP_PAYLOAD_RE.findall(block)
            results.append({
                'title': 'SQL Injection — %s' % (titles[0].strip() if titles else param),
                'severity': 'critico',
                'affected': param,
                'description': 'sqlmap — %s' % (types[0].strip() if types else 'parâmetro injetável'),
                'evidence': _truncate(payloads[0].strip() if payloads else block.strip()),
                'sourceTool': 'sqlmap',
                'meta': {
                    'parameter': param, 'type': types[0].strip() if types else '',
                    'payload': payloads[0].strip() if payloads else '',
                },
            })
        dbs_match = _SQLMAP_DBS_RE.search(text)
        if dbs_match:
            db_names = [ln.split(']', 1)[1].strip() for ln in dbs_match.group(1).splitlines() if ln.strip()]
            if db_names:
                results.append({
                    'title': '%d banco(s) de dados enumerado(s)' % len(db_names),
                    'severity': 'info',
                    'affected': ', '.join(db_names),
                    'description': 'sqlmap --dbs — enumeração de bancos de dados via a injeção já confirmada.',
                    'evidence': '\n'.join(db_names),
                    'sourceTool': 'sqlmap',
                    'meta': {'databases': ', '.join(db_names), 'count': len(db_names)},
                })
    return results


# dalfox's exact JSON field names have shifted across releases; this reads the common
# ones defensively (dict.get with fallbacks) rather than assuming one fixed schema —
# verify against your installed `dalfox version` if a run's findings look empty
# despite exit code 0, and adjust the .get() keys below to match.
DALFOX_SEVERITY_MAP = {
    'high': 'alto',
    'medium': 'medio',
    'low': 'baixo',
    'info': 'info',
}


def parse_dalfox_json(path):
    """`dalfox url <target> --format json -o <path>` -> JSON array of finding objects."""
    data = _read_json(path)
    results = []
    for hit in (data or []):
        if not isinstance(hit, dict):
            continue
        param = hit.get('param', '')
        payload = hit.get('payload') or hit.get('evidence', '')
        url = hit.get('data') or hit.get('url', '')
        if not (param or payload or url):
            # dalfox v2 writes a bare `[{}]` when it finds nothing on the target —
            # an empty hit isn't a finding, it's dalfox's "no results" sentinel.
            continue
        sev = DALFOX_SEVERITY_MAP.get(str(hit.get('severity', 'medium')).lower(), 'medio')
        results.append({
            'title': 'XSS (%s)%s' % (hit.get('type', 'dalfox'), (' — param ' + param) if param else ''),
            'severity': sev,
            'affected': url,
            'description': 'dalfox — %s' % (hit.get('message_str') or hit.get('inject_type') or 'varredura de XSS'),
            'evidence': _truncate(payload),
            'sourceTool': 'dalfox',
            'meta': {'param': param, 'type': hit.get('type', ''), 'payload': payload},
        })
    return results


# ---- testssl.sh / wpscan / gitleaks (v24) ---------------------------------------------
# Três ferramentas de alto valor pro pipeline: avaliação TLS (testssl.sh), WordPress
# (wpscan) e segredos em repositório exposto (gitleaks). Todas escrevem arquivo
# determinístico (--json-pretty/--output/--report-path), então seguem o mesmo contrato de
# output dos outros tools — sem glob/timestamp-guessing.

TESTSSL_SEVERITY_MAP = {
    'CRITICAL': 'critico',
    'HIGH': 'alto',
    'MEDIUM': 'medio',
    'LOW': 'baixo',
}


def parse_testssl_json(path):
    """`testssl.sh --json-pretty <file> <host>` -> JSON array de checagens TLS. Cada objeto
    tem id/severity/finding/ip/port/cve/cwe. Severidade "OK" é o resultado normal de uma
    checagem que passou — não é achado, então é filtrada aqui (mesmo raciocínio do nuclei
    com info: checagem saudável não entra como finding)."""
    data = _read_json(path)
    results = []
    for f in (data or []):
        if not isinstance(f, dict):
            continue
        sev_raw = str(f.get('severity') or 'INFO').upper()
        if sev_raw in ('OK', 'NONE'):
            continue
        sev = TESTSSL_SEVERITY_MAP.get(sev_raw, 'info')
        name = f.get('finding') or f.get('id') or 'Checagem TLS'
        title = ('%s — %s' % (f['id'], name)) if f.get('id') else name
        host = f.get('ip') or ''
        port = f.get('port') or ''
        affected = ('%s:%s' % (host, port)) if host else (('porta %s' % port) if port else '')
        cve = f.get('cve') or ''
        evidence = str(f.get('finding') or '')
        if cve:
            evidence += ('\nCVE: %s' % cve)
        results.append({
            'title': title,
            'severity': sev,
            'affected': affected,
            'description': 'testssl.sh — checagem TLS.',
            'evidence': _truncate(evidence),
            'sourceTool': 'testssl',
            'meta': {'id': f.get('id', ''), 'cve': cve, 'severity': sev_raw},
        })
    return results


def _wpscan_vulns_to_results(vulns, context, results):
    for v in (vulns or []):
        if not isinstance(v, dict):
            continue
        title = v.get('title') or v.get('id') or 'Vulnerabilidade WordPress'
        cvss = v.get('cvss') or {}
        score = None
        try:
            score = float(cvss.get('score'))
        except (TypeError, ValueError):
            score = None
        if score is None:
            sev = 'medio'  # sem CVSS, wpscan não garante mais que isso
        elif score >= 9.0:
            sev = 'critico'
        elif score >= 7.0:
            sev = 'alto'
        elif score >= 4.0:
            sev = 'medio'
        else:
            sev = 'baixo'
        refs = v.get('references') or {}
        cves = refs.get('cve') or []
        results.append({
            'title': title,
            'severity': sev,
            'affected': context,
            'description': 'wpscan — %s' % (v.get('id') or 'vulnerabilidade WordPress'),
            'evidence': _truncate(v.get('references') or v),
            'sourceTool': 'wpscan',
            'meta': {'id': v.get('id', ''), 'cve': ', '.join(cves), 'score': (score if score is not None else '')},
        })


def parse_wpscan_json(path):
    """`wpscan --url <url> --format json --output <file>` -> JSON com version.vulnerabilities,
    plugins.<slug>.vulnerabilities e main_theme.vulnerabilities. Sem token da wpvulndb o
    wpscan ainda enumera versões/plugins; a lista de CVEs fica limitada — achados de plugin
    costumam sumir, então um "0 achados" não significa WordPress limpo."""
    data = _read_json(path)
    results = []
    if not isinstance(data, dict):
        return results
    url = data.get('site_url') or data.get('url') or ''
    version = data.get('version')
    if isinstance(version, dict):
        _wpscan_vulns_to_results(version.get('vulnerabilities'), url, results)
    for slug, plugin in (data.get('plugins') or {}).items():
        if isinstance(plugin, dict):
            _wpscan_vulns_to_results(plugin.get('vulnerabilities'), url, results)
    theme = data.get('main_theme')
    if isinstance(theme, dict):
        _wpscan_vulns_to_results(theme.get('vulnerabilities'), url, results)
    return results


def parse_gitleaks_json(path):
    """`gitleaks detect --source <repo> --report-format json --report-path <file>` -> JSON
    array de secrets encontrados. O gitleaks sai com exit code 1 quando acha leaks — o
    jobs.py não liga para o exit code (parse roda de qualquer jeito), então isso não vira
    erro de job."""
    data = _read_json(path)
    results = []
    for hit in (data or []):
        if not isinstance(hit, dict):
            continue
        rule = hit.get('RuleID') or hit.get('rule_id') or 'segredo'
        file_ = hit.get('File') or hit.get('file') or ''
        desc = hit.get('Description') or ''
        results.append({
            'title': 'Segredo exposto: %s (%s)' % (rule, file_ or '?'),
            'severity': 'alto',
            'affected': file_,
            'description': 'gitleaks — %s' % (desc or rule),
            'evidence': _truncate(hit),
            'sourceTool': 'gitleaks',
            'meta': {'rule': rule, 'file': file_, 'commit': hit.get('Commit') or hit.get('commit') or ''},
        })
    return results


# ---- ffuf / nikto / osv-scanner (v25) ---------------------------------------------------
# Fase Exploitation no pipeline? Não — estes três fecham Scanning (ffuf/nikto) e
# Vulnerability Analysis (osv-scanner). ffuf e osv-scanner entram com a mesma mecânica de
# pre_build (git clone) do gitleaks quando o alvo é um repo; nikto escreve JSON
# determinístico. ffuf é o único que precisa do placeholder FUZZ na URL alvo — o builder
# anexa /FUZZ quando o usuário esquece.

def parse_ffuf_json(path):
    """`ffuf -u <alvo>/FUZZ -w <wordlist> -o <file> -of json` -> JSON dict com 'results':
    [{url, status, length, words, lines, redirectlocation, input:{FUZZ}}]. Cada hit vira um
    achado info (recon, não julgamento de vulnerabilidade) — o browser agrega numa finding
    única com tabela de itens (mesmo contrato do oblivion-webrecon)."""
    data = _read_json(path)
    results = []
    if not isinstance(data, dict):
        return results
    for hit in (data.get('results') or []):
        if not isinstance(hit, dict):
            continue
        url = hit.get('url') or ''
        results.append({
            'title': 'Caminho encontrado (ffuf): %s' % url,
            'severity': 'info',
            'affected': url,
            'description': 'ffuf — brute force de diretórios/arquivos.',
            'evidence': 'status=%s size=%s' % (hit.get('status'), hit.get('length')),
            'sourceTool': 'ffuf',
            'meta': {
                'statusCode': hit.get('status'), 'size': hit.get('length'),
                'url': url, 'redirect': hit.get('redirectlocation') or '',
            },
        })
    return results


def parse_nikto_xml(path):
    """`nikto -h <alvo> -Format xml -output <file>` -> XML `<niktoscan><scandetails ...>
    <item id osvdbid method><description/><uri/><namelink/></item>...`. Usamos XML (não o
    JSON, que a versão do apt (2.1.5) nem suporta, nem o CSV, cujo writer da 2.1.5 injeta
    lixo `SCALAR(0x..)`/`HASH(0x..)` no meio dos campos). O nikto não classifica severidade
    por achado (a triagem é do pentester), então o default é 'baixo' — nunca inventa um
    'critico' sem julgamento humano. Cada <item> vira um achado individual (não-agregado)."""
    results = []
    try:
        tree = ET.parse(path)
    except (FileNotFoundError, OSError, ET.ParseError):
        return results
    root = tree.getroot()
    details = root.find('.//scandetails')
    host = ''
    port = ''
    if details is not None:
        host = details.get('targethostname') or details.get('targetip') or ''
        port = details.get('targetport') or ''
    affected = host + ((':' + str(port)) if port else '')
    for item in root.iter('item'):
        desc_el = item.find('description')
        uri_el = item.find('uri')
        msg = (desc_el.text or '').strip() if desc_el is not None else ''
        uri = (uri_el.text or '').strip() if uri_el is not None else ''
        if not msg:
            continue
        osvdb = item.get('osvdbid') or ''
        method = item.get('method') or ''
        evidence = msg + (('\nURI: %s' % uri) if uri else '')
        results.append({
            'title': (msg[:160] + '…') if len(msg) > 160 else msg,
            'severity': 'baixo',
            'affected': (affected + uri) if uri else affected,
            'description': 'nikto — checagem de servidor web.',
            'evidence': _truncate(evidence),
            'sourceTool': 'nikto',
            'meta': {'method': method, 'uri': uri, 'osvdb': osvdb if osvdb not in ('', '0') else ''},
        })
    return results


def _cvss_score_to_severity(score):
    """Mesma régua de severidade do wpscan: >=9 crítico, >=7 alto, >=4 médio, senão baixo.
    Extraída pra ficar única — osv-scanner usa a mesma. Sem score utilizável -> medio."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return 'medio'
    if score >= 9.0:
        return 'critico'
    if score >= 7.0:
        return 'alto'
    if score >= 4.0:
        return 'medio'
    return 'baixo'


def parse_osv_scanner_json(path):
    """`osv-scanner --format json --output <file> <repo_dir>` -> JSON dict com 'results':
    [{package:{name,version,ecosystem}, vulnerabilities:[{id, aliases, summary, severity}]}].
    O alvo é um repo git (mesmo pre_build clone do gitleaks). Cada CVE vira achado
    individual com severity mapeada do CVSS."""
    data = _read_json(path)
    results = []
    if not isinstance(data, dict):
        return results
    for entry in (data.get('results') or []):
        if not isinstance(entry, dict):
            continue
        pkg = entry.get('package') or {}
        pkg_name = pkg.get('name') or ''
        ecosystem = pkg.get('ecosystem') or ''
        version = pkg.get('version') or ''
        affected = '%s (%s %s)' % (pkg_name, ecosystem, version) if pkg_name else (entry.get('source') or '')
        for v in (entry.get('vulnerabilities') or []):
            if not isinstance(v, dict):
                continue
            score = ''
            sev = 'medio'
            for s in (v.get('severity') or []):
                if isinstance(s, dict) and s.get('score') is not None:
                    score = s.get('score')
                    sev = _cvss_score_to_severity(score)
                    break
            aliases = v.get('aliases') or []
            summary = v.get('summary') or v.get('details') or ''
            vuln_id = v.get('id') or (aliases[0] if aliases else 'Vulnerabilidade OSV')
            title = ('%s (%s)' % (vuln_id, pkg_name)) if pkg_name else vuln_id
            results.append({
                'title': title,
                'severity': sev,
                'affected': affected,
                'description': 'osv-scanner — %s' % (summary[:200] if summary else 'dependência vulnerável'),
                'evidence': _truncate(summary or v),
                'sourceTool': 'osv-scanner',
                'meta': {
                    'vulnId': v.get('id', ''), 'aliases': ', '.join(aliases),
                    'package': pkg_name, 'version': version, 'ecosystem': ecosystem,
                    'score': str(score),
                },
            })
    return results


# ---- wafw00f / arjun / katana (v26) -----------------------------------------------------
# Três ferramentas novas de scanning: wafw00f identifica se há um WAF na frente do alvo
# (informa quão agressivo vale a pena ser com sqlmap/dalfox), arjun descobre parâmetros GET
# escondidos (alimenta o que sqlmap/dalfox têm pra testar), katana é um crawler de verdade
# (segue links/JS, não só adivinha caminhos como ffuf/oblivion-webrecon) — as três rodam
# `pip install --user` / binário Go já presente no agente, sem sudo.

def parse_wafw00f_json(path):
    """`wafw00f -a -o <path>.json <alvo>` -> JSON array: [{detected, firewall, manufacturer,
    trigger_url, url}]. Sinal 'info' — saber que há (ou não) um WAF orienta a triagem
    (sqlmap/dalfox mais conservadores contra um alvo com WAF confirmado), não é em si uma
    vulnerabilidade."""
    data = _read_json(path)
    results = []
    for hit in (data or []):
        if not isinstance(hit, dict):
            continue
        detected = bool(hit.get('detected'))
        firewall = hit.get('firewall') or 'Nenhum'
        url = hit.get('url') or ''
        title = ('WAF detectado: %s' % firewall) if detected else 'Nenhum WAF detectado'
        results.append({
            'title': title,
            'severity': 'info',
            'affected': url,
            'description': 'wafw00f — fingerprint de Web Application Firewall.',
            'evidence': 'firewall=%s manufacturer=%s trigger_url=%s' % (
                firewall, hit.get('manufacturer') or '', hit.get('trigger_url') or ''),
            'sourceTool': 'wafw00f',
            'meta': {
                'detected': detected, 'firewall': firewall,
                'manufacturer': hit.get('manufacturer') or '',
            },
        })
    return results


def parse_arjun_json(path):
    """`arjun -u <alvo> -w <wordlist> -oJ <path>` -> JSON dict `{url: [param, param, ...]}`.
    v2.2.7 só grava o arquivo quando encontra pelo menos um parâmetro — _read_json retornando
    None (arquivo ausente) já significa 'nada encontrado', tratado como lista vazia."""
    data = _read_json(path)
    results = []
    if not isinstance(data, dict):
        return results
    for url, params in data.items():
        if not isinstance(params, list) or not params:
            continue
        param_list = [str(p) for p in params]
        results.append({
            'title': '%d parâmetro(s) oculto(s) encontrado(s) em %s' % (len(param_list), url),
            'severity': 'info',
            'affected': url,
            'description': 'arjun — descoberta de parâmetros HTTP ocultos (não testados na URL padrão).',
            'evidence': ', '.join(param_list),
            'sourceTool': 'arjun',
            'meta': {'url': url, 'params': ', '.join(param_list), 'count': len(param_list)},
        })
    return results


def parse_gau_json(path):
    """`gau <domain> --json --o <path>` -> um objeto JSON por linha: {"url": "..."}. URLs
    históricas de arquivos públicos (Wayback, CommonCrawl, OTX, URLScan). Cada URL vira um
    achado 'info' (recon passivo); o browser agrega numa finding única (mesmo contrato de
    katana/ffuf). Alvos que são IP interno não têm pegada em arquivos públicos — retorno
    vazio nesse caso é esperado, não é erro."""
    results = []
    try:
        f = open(path, 'r', encoding='utf-8', errors='ignore')
    except (FileNotFoundError, OSError):
        return results
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                url = json.loads(line).get('url')
            except ValueError:
                url = line if line.startswith('http') else None
            if not url:
                continue
            results.append({
                'title': 'URL histórica (gau): %s' % url,
                'severity': 'info',
                'affected': url,
                'description': 'gau — URL de arquivos públicos (Wayback/CommonCrawl/OTX/URLScan).',
                'evidence': url,
                'sourceTool': 'gau',
                'meta': {'url': url},
            })
    return results


def parse_waybackurls_txt(path):
    """`waybackurls` (alvo via stdin) -> uma URL por linha em texto puro no stdout, que o
    runner (output_stdout) grava direto em <path>. Mesma ideia do gau, provedores um pouco
    diferentes (Wayback + CommonCrawl + VirusTotal)."""
    results = []
    seen = set()
    try:
        f = open(path, 'r', encoding='utf-8', errors='ignore')
    except (FileNotFoundError, OSError):
        return results
    with f:
        for line in f:
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            results.append({
                'title': 'URL histórica (waybackurls): %s' % url,
                'severity': 'info',
                'affected': url,
                'description': 'waybackurls — URL de arquivos públicos (Wayback/CommonCrawl/VirusTotal).',
                'evidence': url,
                'sourceTool': 'waybackurls',
                'meta': {'url': url},
            })
    return results


def parse_katana_jsonl(path):
    """`katana -u <alvo> -jsonl -omit-raw -omit-body -o <path>` -> um objeto JSON por linha:
    {request:{endpoint,method,tag,attribute,source}, response:{status_code,headers,
    content_length}}. Cada endpoint rastreado (via crawling real de links/JS, não brute
    force de wordlist) vira um achado 'info' — o browser agrega numa finding única (mesmo
    contrato de ffuf/oblivion-webrecon)."""
    results = []
    try:
        f = open(path, 'r', encoding='utf-8', errors='ignore')
    except (FileNotFoundError, OSError):
        return results
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            req = obj.get('request') or {}
            resp = obj.get('response') or {}
            endpoint = req.get('endpoint') or ''
            if not endpoint:
                continue
            status = resp.get('status_code')
            headers = resp.get('headers') or {}
            results.append({
                'title': 'Endpoint rastreado (katana): %s' % endpoint,
                'severity': 'info',
                'affected': endpoint,
                'description': 'katana — crawling de links/formulários/JS.',
                'evidence': 'method=%s status=%s content-type=%s' % (
                    req.get('method') or 'GET', status, headers.get('Content-Type') or ''),
                'sourceTool': 'katana',
                'meta': {
                    'method': req.get('method') or 'GET', 'statusCode': status,
                    'contentType': headers.get('Content-Type') or '',
                    'contentLength': resp.get('content_length'),
                    'source': req.get('source') or '',
                },
            })
    return results

"""Tool registry: allowlist-based argv builders (never string concatenation —
subprocess is always called with shell=False) plus server-side target/param
validation. This is the single place that decides what a client can ask the
agent to run.
"""
import os
import re

from parsers import (
    parse_arjun_json,
    parse_dalfox_json,
    parse_ffuf_json,
    parse_gau_json,
    parse_gitleaks_json,
    parse_httpx_jsonl,
    parse_katana_jsonl,
    parse_waybackurls_txt,
    parse_nikto_xml,
    parse_nmap_xml,
    parse_nuclei_jsonl,
    parse_oblivion_exposed,
    parse_oblivion_passive,
    parse_oblivion_subdomains,
    parse_oblivion_webrecon,
    parse_oblivion_webvuln,
    parse_osv_scanner_json,
    parse_sqlmap_log,
    parse_subfinder_jsonl,
    parse_testssl_json,
    parse_wafw00f_json,
    parse_wpscan_json,
)

# hostname / IPv4 / IPv4 CIDR / IPv6 charset only — no shell metacharacters.
TARGET_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9\.\-:_/]{0,252}$')

# Sessão autenticada (v24): um único header "Nome: valor" (Cookie/Authorization/...) que o
# cliente manda por job e o agente injeta nos argv de ferramentas HTTP. Nunca aceita
# CR/LF, então não há como escapar pra uma linha injetada; o valor é um único elemento de
# argv (shell=False), então nem mesmo isso seria executável — é defesa em profundidade.
SESSION_RE = re.compile(r'^[A-Za-z0-9!#$%&\'*+\-.^_`|~]+\s*:\s*[^\r\n]{0,512}$')


def validate_target(target):
    if not isinstance(target, str) or not target:
        return False
    return bool(TARGET_RE.match(target))


def validate_session(session):
    if not session:
        return True
    if not isinstance(session, str) or len(session) > 512:
        return False
    if '\r' in session or '\n' in session:
        return False
    return bool(SESSION_RE.match(session))


def _normalize_host_target(target):
    """Extrai (host, porta) de um alvo pra ferramentas host-only (nmap/testssl): tira
    scheme e path de uma URL (`http://192.168.0.19:8080/turismo/` -> ('192.168.0.19','8080'))
    e separa `host:porta`/IPv6 `[::1]:8080`. Devolve (None, None) quando não der pra extrair
    nada usável. É o curinga do bug real: o frontend mandava `http://...:8080/path/` cru, o
    nmap morria com "Unable to split netmask ... No targets were specified" e o job virava
    um "done" fantasma com 0 hosts."""
    t = str(target or '').strip()
    if not t:
        return None, None
    m = re.match(r'^[a-z][a-z0-9+.\-]*://', t, re.I)
    if m:
        t = t[m.end():]
    t = t.split('/')[0]
    if not t:
        return None, None
    port = ''
    if t.startswith('['):
        if ']' in t:
            host, _, rest = t.partition(']')
            host += ']'
            if rest.startswith(':'):
                port = rest[1:]
        else:
            host = t
    else:
        host, _, port = t.partition(':')
    host = host.strip()
    port = port.strip()
    if not host:
        return None, None
    return host, port


NMAP_PROFILES = {
    'discovery': ['-sn'],
    'top-ports': ['-sV', '--top-ports', '100'],
    'full': ['-sV', '-p-'],
    'udp-top': ['-sU', '--top-ports', '50'],
}

NUCLEI_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}
DEFAULT_NUCLEI_SEVERITY = 'medium,high,critical'


def _nuclei_severity_tokens(severity):
    tokens = [s.strip() for s in (severity or '').split(',') if s.strip()]
    if not tokens or any(t not in NUCLEI_SEVERITIES for t in tokens):
        return None
    return tokens


def build_nmap_argv(target, params, raw_path, session=None):
    host, url_port = _normalize_host_target(target)
    if not host:
        raise ValueError('alvo inválido para nmap: %r — use host/IP sem scheme/path' % (target,))
    # Porta explícita vence (decisão do usuário): se o alvo tinha :8080 ou o cliente mandou
    # params.port, nmap mira só naquela porta com -sV — mais relevante que o perfil.
    port = (str(params.get('port') or '')).strip() or url_port
    profile = params.get('profile', 'top-ports')
    flags = NMAP_PROFILES.get(profile, NMAP_PROFILES['top-ports'])
    argv = ['nmap', '-Pn']
    if port:
        argv += ['-sV', '-p', port]
    else:
        argv += flags
    argv += ['-oX', raw_path, host]
    return argv


def build_subfinder_argv(target, params, raw_path, session=None):
    return ['subfinder', '-d', target, '-silent', '-oJ', '-o', raw_path]


def build_httpx_argv(target, params, raw_path, session=None):
    argv = ['httpx', '-u', target, '-title', '-tech-detect', '-status-code', '-json', '-o', raw_path]
    if session:
        argv += ['-H', session]
    return argv


def build_nuclei_argv(target, params, raw_path, session=None):
    tokens = _nuclei_severity_tokens(params.get('severity', DEFAULT_NUCLEI_SEVERITY)) or ['medium', 'high', 'critical']
    argv = ['nuclei', '-u', target, '-severity', ','.join(tokens), '-jsonl', '-o', raw_path]
    if session:
        argv += ['-H', session]
    return argv


# OblivionSec (github.com/AndreNunes7/OblivionSec) — companion CLI, `pip install -e .`
# on the agent machine gives the `oblivion` command used below. All five subcommands
# share the same `-o <path> --format json -q` convention (see per_target()/_save() in
# oblivion/cli.py): -o with an explicit path writes deterministic JSON there, -q keeps
# status noise on stderr only. None of these take extra params (paramKey stays None).
def build_oblivion_subdomains_argv(target, params, raw_path, session=None):
    return ['oblivion', 'subdomains', '-d', target, '-o', raw_path, '--format', 'json', '-q']


def build_oblivion_passive_argv(target, params, raw_path, session=None):
    return ['oblivion', 'passive', '-u', target, '-o', raw_path, '--format', 'json', '-q']


def build_oblivion_webrecon_argv(target, params, raw_path, session=None):
    return ['oblivion', 'webrecon', '-u', target, '-o', raw_path, '--format', 'json', '-q']


def build_oblivion_webvuln_argv(target, params, raw_path, session=None):
    return ['oblivion', 'webvuln', '-u', target, '-o', raw_path, '--format', 'json', '-q']


def build_oblivion_exposed_argv(target, params, raw_path, session=None):
    return ['oblivion', 'exposed', '-u', target, '-o', raw_path, '--format', 'json', '-q']


# sqlmap/dalfox — fase Exploitation (PTES §5): tentativa ativa de injeção, não apenas
# varredura passiva. Perfis conservadores por padrão (ver SQLMAP_PROFILES).
# v26: cada nível de level/risk ganhou uma variante `-dbs` que soma `--dbs` — sqlmap só
# tenta listar bancos DEPOIS de já ter confirmado a injeção (fluxo normal dele), então não
# aumenta o risco além do que o level/risk escolhido já permite; só faz sqlmap perguntar
# "quais bancos essa injeção já confirmada consegue ler". Mantido como variante do mesmo
# paramKey 'profile' (não um segundo param) porque o picker do pipeline só suporta um
# dropdown por ferramenta — ver AGENT_TOOL_DEFS em index.html.
SQLMAP_PROFILES = {
    'safe': ['--level=1', '--risk=1'],
    'level2': ['--level=2', '--risk=1'],
    'aggressive': ['--level=3', '--risk=2'],
    'safe-dbs': ['--level=1', '--risk=1'],
    'level2-dbs': ['--level=2', '--risk=1'],
    'aggressive-dbs': ['--level=3', '--risk=2'],
}
SQLMAP_ENUM_PROFILES = {'safe-dbs', 'level2-dbs', 'aggressive-dbs'}


def build_sqlmap_argv(target, params, raw_path, session=None):
    """sqlmap não escreve um único arquivo de resultado determinístico (ao contrário de
    todo outro tool aqui) — ele grava um `log` de texto dentro de --output-dir/<host>/.
    Por isso apontamos --output-dir para o próprio job_dir (dirname de raw_path, já único
    por job) em vez de tentar forçar raw_path como arquivo; parse_sqlmap_log() faz glob
    nesse diretório. Efeito colateral aceito: GET /jobs/{id}/raw não encontra `raw.*` e
    responde 404 pra este tool — só o /result (já parseado) funciona, o que é o que a UI
    usa mesmo. Perfis `*-dbs` (v26) somam `--dbs`; parse_sqlmap_log() lê o "available
    databases [N]:" resultante como um achado 'info' extra."""
    profile = params.get('profile', 'safe')
    flags = SQLMAP_PROFILES.get(profile, SQLMAP_PROFILES['safe'])
    output_dir = os.path.dirname(raw_path)
    argv = ['sqlmap', '-u', target, '--batch', '--forms', '--crawl=1'] + flags + ['--output-dir', output_dir]
    if profile in SQLMAP_ENUM_PROFILES:
        argv.append('--dbs')
    if session:
        argv += ['--headers', session]
    return argv


DALFOX_DEEP_LABEL = 'deep'


def build_dalfox_argv(target, params, raw_path, session=None):
    """`deep=deep` (v26, novo paramKey — dalfox não tinha nenhum antes) soma
    `--deep-domxss`: mais payloads de DOM XSS testados, mais lento. Sem risco adicional
    (mesma categoria de teste, só mais cobertura)."""
    argv = ['dalfox', 'url', target, '--format', 'json', '-o', raw_path, '--silence']
    if params.get('deep') == DALFOX_DEEP_LABEL:
        argv.append('--deep-domxss')
    if session:
        argv += ['-H', session]
    return argv


# ---- testssl.sh / wpscan / gitleaks (v24) ---------------------------------------------
# Três ferramentas de alto valor, todas com arquivo de saída determinístico:
# testssl.sh --json-pretty <file>; wpscan --format json --output <file>;
# gitleaks detect --report-path <file>. Só gitleaks foge do padrão "1 Popen só": ele
# precisa de um repo clonado, então a entrada leva um pre_build (git clone --depth 1
# num subdir do job) que o jobs.py executa ANTES do argv principal — mesmo mecanismo de
# timeout/kill, shell=False em ambos.
def build_testssl_argv(target, params, raw_path, session=None):
    host, url_port = _normalize_host_target(target)
    if not host:
        raise ValueError('alvo inválido para testssl: %r — use host/IP sem scheme/path' % (target,))
    port = (str(params.get('port') or '')).strip() or url_port
    return ['testssl.sh', '--quiet', '--json-pretty', raw_path,
            (host + ':' + port) if port else host]


def build_wpscan_argv(target, params, raw_path, session=None):
    return ['wpscan', '--url', target, '--format', 'json', '--output', raw_path,
            '--random-user-agent', '--no-banner', '--disable-tls-checks']


def _gitleaks_repo_dir(raw_path):
    return os.path.join(os.path.dirname(raw_path), 'repo')


def build_gitleaks_clone_argv(target, params, raw_path):
    return ['git', 'clone', '--depth', '1', '--quiet', target, _gitleaks_repo_dir(raw_path)]


def build_gitleaks_argv(target, params, raw_path, session=None):
    return ['gitleaks', 'detect', '--source', _gitleaks_repo_dir(raw_path),
            '--report-format', 'json', '--report-path', raw_path, '--no-banner', '--redact']


# ---- ffuf / nikto / osv-scanner (v25) ---------------------------------------------------
# ffuf: brute force de diretórios com wordlist de um enum fixo — nunca caminho livre do
# cliente. O alvo precisa do placeholder FUZZ; se o usuário esqueceu, anexamos /FUZZ.
# Wordlists vivem em pi-agent/wordlists/ (v26) — não em /usr/share/seclists/, que exige
# root pra instalar (apt install seclists) e nem sempre está presente. Baixadas direto do
# SecLists (raw.githubusercontent.com) pra dentro do próprio diretório do agente, sem sudo:
#   mkdir -p wordlists && for f in raft-medium-directories raft-small-directories common; do
#     curl -sSL -o wordlists/$f.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/$f.txt
#   done
_WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wordlists')
FFUF_WORDLISTS = {
    'raft-medium': os.path.join(_WORDLISTS_DIR, 'raft-medium-directories.txt'),
    'raft-small': os.path.join(_WORDLISTS_DIR, 'raft-small-directories.txt'),
    'common': os.path.join(_WORDLISTS_DIR, 'common.txt'),
}
DEFAULT_FFUF_WORDLIST = 'raft-medium'


def ffuf_preflight(params):
    """Checado pelo agent.py ANTES de spawnar o job — sem isso, ffuf falha com um
    `stat ... no such file or directory` enterrado no stderr.log, e como jobs.py não
    olha o exit code do passo principal, o job aparecia como 'done' com 0 achados,
    indistinguível de um alvo limpo. Retorna a mensagem de erro (str) ou None se ok."""
    wordlist = params.get('wordlist', DEFAULT_FFUF_WORDLIST)
    path = FFUF_WORDLISTS.get(wordlist, FFUF_WORDLISTS[DEFAULT_FFUF_WORDLIST])
    if not os.path.isfile(path):
        return 'wordlist não encontrada no agente: %s — instale o SecLists (ver pi-agent/README.md)' % path
    return None


def build_ffuf_argv(target, params, raw_path, session=None):
    wordlist = params.get('wordlist', DEFAULT_FFUF_WORDLIST)
    wl_path = FFUF_WORDLISTS.get(wordlist, FFUF_WORDLISTS[DEFAULT_FFUF_WORDLIST])
    fuzz_target = target if 'FUZZ' in target else target.rstrip('/') + '/FUZZ'
    argv = ['ffuf', '-u', fuzz_target, '-w', wl_path, '-o', raw_path, '-of', 'json', '-s']
    if session:
        argv += ['-H', session]
    return argv


def build_nikto_argv(target, params, raw_path, session=None):
    # -Format xml (a 2.1.5 do apt não tem json e o CSV vem corrompido — ver parse_nikto_xml).
    # -Tuning 123bde limita aos grupos de alto sinal (arquivos interessantes, misconfig,
    # info disclosure, injeção, XSS) — um nikto sem tuning roda 6000+ checagens e trava o
    # pipeline por 15-30 min; o job_timeout ainda é o teto de segurança.
    return ['nikto', '-h', target, '-Format', 'xml', '-output', raw_path,
            '-nointeractive', '-Tuning', '123bde']


def _osv_repo_dir(raw_path):
    return os.path.join(os.path.dirname(raw_path), 'repo')


def build_osv_clone_argv(target, params, raw_path):
    return ['git', 'clone', '--depth', '1', '--quiet', target, _osv_repo_dir(raw_path)]


def build_osv_scanner_argv(target, params, raw_path, session=None):
    return ['osv-scanner', '--format', 'json', '--output', raw_path, _osv_repo_dir(raw_path)]


# ---- wafw00f / arjun / katana (v26) -----------------------------------------------------
# Três ferramentas de scanning novas, instaladas sem sudo (pip --user / binário Go já
# presente): wafw00f identifica WAF na frente do alvo (orienta o quão conservador ser com
# sqlmap/dalfox), arjun descobre parâmetros GET ocultos, katana é um crawler de verdade
# (segue links/formulários/JS — acha URLs parametrizadas que um brute-force de wordlist
# como ffuf/oblivion-webrecon nunca adivinharia).
def build_wafw00f_argv(target, params, raw_path, session=None):
    return ['wafw00f', '-a', '-o', raw_path, target]


def build_arjun_argv(target, params, raw_path, session=None):
    argv = ['arjun', '-u', target, '-oJ', raw_path, '-T', '10']
    if session:
        argv += ['--headers', session]
    return argv


KATANA_DEPTHS = {'shallow': '1', 'normal': '2', 'deep': '3'}
DEFAULT_KATANA_DEPTH = 'normal'


def build_katana_argv(target, params, raw_path, session=None):
    depth = KATANA_DEPTHS.get(params.get('depth', DEFAULT_KATANA_DEPTH), KATANA_DEPTHS[DEFAULT_KATANA_DEPTH])
    argv = ['katana', '-u', target, '-jsonl', '-silent', '-d', depth, '-timeout', '10',
            '-omit-raw', '-omit-body', '-o', raw_path]
    if session:
        argv += ['-H', session]
    return argv


# gau / waybackurls (v27) — information gathering passivo: descobrem URLs históricas de
# arquivos públicos. Ambos são orientados a DOMÍNIO (não URL) — o frontend resolve o alvo
# pro host base antes de mandar (ver agentToolTarget/agentHostFromTarget em index.html).
# gau aceita o domínio como argumento posicional e escreve JSONL no --o. waybackurls só lê
# o domínio do stdin e escreve URLs no stdout — daí os flags stdin_target/output_stdout no
# TOOL_REGISTRY, tratados pelo runner (jobs.py).
def build_gau_argv(target, params, raw_path, session=None):
    return ['gau', target, '--json', '--o', raw_path, '--threads', '5', '--timeout', '20',
            '--providers', 'wayback,commoncrawl,otx']


def build_waybackurls_argv(target, params, raw_path, session=None):
    return ['waybackurls', '-no-subs']


TOOL_REGISTRY = {
    'nmap': {
        'bin': 'nmap', 'raw_ext': 'xml',
        'build_argv': build_nmap_argv, 'parse': parse_nmap_xml,
        'params_allowed': {'profile', 'port'},
    },
    'subfinder': {
        'bin': 'subfinder', 'raw_ext': 'jsonl',
        'build_argv': build_subfinder_argv, 'parse': parse_subfinder_jsonl,
        'params_allowed': set(),
    },
    'httpx': {
        'bin': 'httpx', 'raw_ext': 'jsonl',
        'build_argv': build_httpx_argv, 'parse': parse_httpx_jsonl,
        'params_allowed': set(),
    },
    'nuclei': {
        'bin': 'nuclei', 'raw_ext': 'jsonl',
        'build_argv': build_nuclei_argv, 'parse': parse_nuclei_jsonl,
        'params_allowed': {'severity'},
    },
    'osv-scanner': {
        'bin': 'osv-scanner', 'raw_ext': 'json',
        'build_argv': build_osv_scanner_argv, 'pre_build': build_osv_clone_argv,
        'parse': parse_osv_scanner_json,
        'params_allowed': set(),
        # exit 1 = vulnerabilities found (expected outcome, not a failure).
        'ok_exit_codes': {1},
    },
    'oblivion-subdomains': {
        'bin': 'oblivion', 'raw_ext': 'json',
        'build_argv': build_oblivion_subdomains_argv, 'parse': parse_oblivion_subdomains,
        'params_allowed': set(),
    },
    'oblivion-passive': {
        'bin': 'oblivion', 'raw_ext': 'json',
        'build_argv': build_oblivion_passive_argv, 'parse': parse_oblivion_passive,
        'params_allowed': set(),
    },
    'oblivion-webrecon': {
        'bin': 'oblivion', 'raw_ext': 'json',
        'build_argv': build_oblivion_webrecon_argv, 'parse': parse_oblivion_webrecon,
        'params_allowed': set(),
    },
    'oblivion-webvuln': {
        'bin': 'oblivion', 'raw_ext': 'json',
        'build_argv': build_oblivion_webvuln_argv, 'parse': parse_oblivion_webvuln,
        'params_allowed': set(),
    },
    'oblivion-exposed': {
        'bin': 'oblivion', 'raw_ext': 'json',
        'build_argv': build_oblivion_exposed_argv, 'parse': parse_oblivion_exposed,
        'params_allowed': set(),
    },
    'sqlmap': {
        'bin': 'sqlmap', 'raw_ext': 'log',
        'build_argv': build_sqlmap_argv, 'parse': parse_sqlmap_log,
        'params_allowed': {'profile'},
    },
    'dalfox': {
        'bin': 'dalfox', 'raw_ext': 'json',
        'build_argv': build_dalfox_argv, 'parse': parse_dalfox_json,
        'params_allowed': {'deep'},
    },
    'testssl': {
        'bin': 'testssl.sh', 'raw_ext': 'json',
        'build_argv': build_testssl_argv, 'parse': parse_testssl_json,
        'params_allowed': {'port'},
    },
    'ffuf': {
        'bin': 'ffuf', 'raw_ext': 'json',
        'build_argv': build_ffuf_argv, 'parse': parse_ffuf_json,
        'params_allowed': {'wordlist'},
        'preflight_check': ffuf_preflight,
    },
    'nikto': {
        'bin': 'nikto', 'raw_ext': 'xml',
        'build_argv': build_nikto_argv, 'parse': parse_nikto_xml,
        'params_allowed': set(),
    },
    'wpscan': {
        'bin': 'wpscan', 'raw_ext': 'json',
        'build_argv': build_wpscan_argv, 'parse': parse_wpscan_json,
        'params_allowed': set(),
    },
    'gitleaks': {
        'bin': 'gitleaks', 'raw_ext': 'json',
        'build_argv': build_gitleaks_argv, 'pre_build': build_gitleaks_clone_argv,
        'parse': parse_gitleaks_json,
        'params_allowed': set(),
        # exit 1 = leaks found (expected outcome, not a failure).
        'ok_exit_codes': {1},
    },
    'wafw00f': {
        'bin': 'wafw00f', 'raw_ext': 'json',
        'build_argv': build_wafw00f_argv, 'parse': parse_wafw00f_json,
        'params_allowed': set(),
    },
    'arjun': {
        'bin': 'arjun', 'raw_ext': 'json',
        'build_argv': build_arjun_argv, 'parse': parse_arjun_json,
        'params_allowed': set(),
    },
    'katana': {
        'bin': 'katana', 'raw_ext': 'jsonl',
        'build_argv': build_katana_argv, 'parse': parse_katana_jsonl,
        'params_allowed': {'depth'},
    },
    'gau': {
        'bin': 'gau', 'raw_ext': 'jsonl',
        'build_argv': build_gau_argv, 'parse': parse_gau_json,
        'params_allowed': set(),
    },
    'waybackurls': {
        'bin': 'waybackurls', 'raw_ext': 'txt',
        'build_argv': build_waybackurls_argv, 'parse': parse_waybackurls_txt,
        'params_allowed': set(),
        'stdin_target': True, 'output_stdout': True,
    },
}


def validate_params(tool, params):
    spec = TOOL_REGISTRY.get(tool)
    if spec is None or not isinstance(params, dict):
        return False
    allowed = spec['params_allowed']
    if any(k not in allowed for k in params):
        return False
    if tool == 'nmap' and params.get('profile', 'top-ports') not in NMAP_PROFILES:
        return False
    if tool == 'nuclei' and _nuclei_severity_tokens(params.get('severity', DEFAULT_NUCLEI_SEVERITY)) is None:
        return False
    if tool == 'sqlmap' and params.get('profile', 'safe') not in SQLMAP_PROFILES:
        return False
    if tool == 'dalfox' and params.get('deep', 'normal') not in ('normal', 'deep'):
        return False
    if tool == 'ffuf' and params.get('wordlist', DEFAULT_FFUF_WORDLIST) not in FFUF_WORDLISTS:
        return False
    if tool == 'katana' and params.get('depth', DEFAULT_KATANA_DEPTH) not in KATANA_DEPTHS:
        return False
    return True

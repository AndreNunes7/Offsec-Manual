"""Job lifecycle: start a scan as a background subprocess, track status in a
per-job meta.json file, parse the raw tool output into the normalized shape
once the process exits. All state lives on disk under jobs_dir — the browser
only ever sees a summary via the HTTP API, never these files directly.
"""
import glob
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

from tools import TOOL_REGISTRY


def _atomic_write_json(path, obj):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def _stderr_tail(stderr_path, max_chars=2000):
    try:
        with open(stderr_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError:
        return ''
    return text[-max_chars:]


# Piadas à parte: um scan "done" com 0 resultados é indistinguível de um alvo limpo — e foi
# exatamente assim que o nmap passou batido com URL no alvo ("No targets were specified / 0
# hosts scanned", exit 0). Só salvamos aviso quando o stderr tem cara de problema real;
# stderr de banner (subfinder/httpx em execução limpa) não dispara pra não encher de ruído.
_STDERR_SUSPECT = (
    'error', 'failed', 'no targets', '0 hosts scanned', '0 hosts up', 'unable to',
    'invalid', 'permission denied', 'denied', 'cannot', "can't", 'exception', 'warn',
    'refused', 'timeout', 'timed out', 'could not', 'not found', 'no such',
)


def _stderr_suspicious(text):
    t = (text or '').lower()
    return any(h in t for h in _STDERR_SUSPECT)


def _kill_tree(proc):
    """Mata o processo e toda a árvore. start_new_session=True no Popen dá ao scan um
    process group próprio no POSIX, então o killpg derruba também filhos que a ferramenta
    tenha spawnado (sqlmap/nuclei fazem isso) — sem isso, o timeout matava só o processo
    direto e deixava órfãos rodando. Windows não tem setsid/killpg: cai no proc.kill()."""
    try:
        if os.name == 'posix':
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


class JobManager:
    def __init__(self, jobs_dir, timeout_seconds=1800, max_concurrent=2):
        self.jobs_dir = jobs_dir
        self.timeout_seconds = timeout_seconds
        # (v25) MAX_CONCURRENT_JOBS: um semáforo limita quantos subprocessos de scan rodam
        # ao mesmo tempo. Jobs além do limite ficam com status 'queued' no disco (o browser
        # já mostra "na fila") e são retomados quando um slot libera. Antes disso, "Rodar
        # tudo" com 17 ferramentas spawnava tudo em paralelo e saturava a Pi.
        self._sem = threading.Semaphore(max_concurrent)
        # (v27) Cancelamento: guarda o Popen do passo em execução por job_id pra que
        # cancel_job() consiga matar a árvore de processos sob demanda (o botão "Parar" da
        # UI). _cancelled marca jobs que foram cancelados pra que o worker não tente parsear
        # a saída parcial e não sobrescreva o status 'cancelado' com 'done'. Lock protege os
        # dois entre a thread do worker e a thread do request HTTP que chama cancel.
        self._running = {}
        self._cancelled = set()
        self._proc_lock = threading.Lock()
        os.makedirs(self.jobs_dir, exist_ok=True)

    def start_job(self, tool, target, params, session=None):
        spec = TOOL_REGISTRY[tool]
        job_id = uuid.uuid4().hex[:12]
        job_dir = os.path.join(self.jobs_dir, job_id)
        os.makedirs(job_dir, exist_ok=True)
        raw_path = os.path.join(job_dir, 'raw.' + spec['raw_ext'])
        argv = spec['build_argv'](target, params, raw_path, session)
        pre_argv = spec['pre_build'](target, params, raw_path) if 'pre_build' in spec else []
        meta = {
            'id': job_id, 'tool': tool, 'target': target, 'params': params,
            'cmdline': shlex.join(pre_argv + argv),  # rastreabilidade (WS-E) — argv real do job
            'session': bool(session),  # só o flag — o valor do header nunca é gravado em disco
            'status': 'queued', 'createdAt': int(time.time() * 1000),
            'startedAt': None, 'finishedAt': None, 'exitCode': None, 'error': None,
            'warning': None,
        }
        self._save_meta(job_dir, meta)
        t = threading.Thread(target=self._run, args=(job_id, job_dir, pre_argv, argv, spec, raw_path, target), daemon=True)
        t.start()
        return job_id

    def cancel_job(self, job_id):
        """Cancela um job: marca como cancelado e mata a árvore do processo em execução (se
        houver). Retorna True se o job existe (mesmo que já tenha terminado — o marcador
        impede que uma corrida termine o parse depois). Chamado pela rota POST .../cancel."""
        job_dir = os.path.join(self.jobs_dir, job_id)
        if not os.path.isdir(job_dir):
            return False
        with self._proc_lock:
            self._cancelled.add(job_id)
            proc = self._running.get(job_id)
        if proc is not None:
            _kill_tree(proc)
        else:
            # Job ainda 'queued' (preso no semáforo) ou já terminou — grava o status
            # cancelado direto pra que a UI reflita, já que não há processo pra matar.
            try:
                meta = self._load_meta(job_dir)
                if meta.get('status') in ('queued', 'running'):
                    meta['status'] = 'error'
                    meta['error'] = 'cancelado pelo usuário'
                    meta['finishedAt'] = int(time.time() * 1000)
                    self._save_meta(job_dir, meta)
            except (OSError, ValueError):
                pass
        return True

    def _save_meta(self, job_dir, meta):
        _atomic_write_json(os.path.join(job_dir, 'meta.json'), meta)

    def _load_meta(self, job_dir):
        with open(os.path.join(job_dir, 'meta.json'), 'r', encoding='utf-8') as f:
            return json.load(f)

    def _run(self, job_id, job_dir, pre_argv, argv, spec, raw_path, target):
        """Adquire um slot do semáforo (v25) antes de tocar no job — jobs parados no limite
        de concorrência continuam 'queued'. O finally garante release em qualquer saída
        (timeout, binário ausente, parse error), senão um slot vazaria e o pipeline pararia.
        Também limpa o registro de processo/cancelamento do job (v27)."""
        # Se o job já foi cancelado enquanto esperava no semáforo, nem começa.
        with self._proc_lock:
            if job_id in self._cancelled:
                self._mark_cancelled(job_dir)
                return
        self._sem.acquire()
        try:
            self._run_worker(job_id, job_dir, pre_argv, argv, spec, raw_path, target)
        finally:
            self._sem.release()
            with self._proc_lock:
                self._running.pop(job_id, None)
                self._cancelled.discard(job_id)

    def _mark_cancelled(self, job_dir):
        try:
            meta = self._load_meta(job_dir)
        except (OSError, ValueError):
            return
        meta['status'] = 'error'
        meta['error'] = 'cancelado pelo usuário'
        meta['finishedAt'] = int(time.time() * 1000)
        self._save_meta(job_dir, meta)

    def _run_worker(self, job_id, job_dir, pre_argv, argv, spec, raw_path, target):
        meta = self._load_meta(job_dir)
        meta['status'] = 'running'
        meta['startedAt'] = int(time.time() * 1000)
        self._save_meta(job_dir, meta)

        # (v27) Ferramentas sem flag de output próprio (waybackurls) escrevem o resultado no
        # stdout — nesse caso o stdout do processo VIRA o raw_path que o parser lê, em vez do
        # stdout.log. E `stdin_target` alimenta o alvo no stdin do processo (waybackurls só
        # aceita domínio por stdin, não por argv).
        stdout_target = raw_path if spec.get('output_stdout') else os.path.join(job_dir, 'stdout.log')
        stderr_path = os.path.join(job_dir, 'stderr.log')
        stdin_bytes = (target + '\n').encode('utf-8') if spec.get('stdin_target') else None
        try:
            with open(stdout_target, 'wb') as out, open(stderr_path, 'wb') as err:
                popen_kwargs = dict(stdout=out, stderr=err, shell=False)
                if stdin_bytes is not None:
                    popen_kwargs['stdin'] = subprocess.PIPE
                if os.name == 'posix':
                    popen_kwargs['start_new_session'] = True
                exit_code = 0
                steps = ([pre_argv] if pre_argv else []) + [argv]
                for step_argv in steps:
                    proc = subprocess.Popen(step_argv, **popen_kwargs)
                    with self._proc_lock:
                        # Cancelado entre o acquire e o Popen: mata na hora e sai.
                        already = job_id in self._cancelled
                        self._running[job_id] = proc
                    if already:
                        _kill_tree(proc)
                        proc.wait()
                        self._mark_cancelled(job_dir)
                        return
                    if stdin_bytes is not None and step_argv is argv:
                        try:
                            proc.stdin.write(stdin_bytes)
                            proc.stdin.close()
                        except (BrokenPipeError, OSError):
                            pass
                    try:
                        exit_code = proc.wait(timeout=self.timeout_seconds)
                    except subprocess.TimeoutExpired:
                        _kill_tree(proc)
                        proc.wait()
                        meta['status'] = 'error'
                        meta['error'] = 'timeout after %ds' % self.timeout_seconds
                        meta['finishedAt'] = int(time.time() * 1000)
                        self._save_meta(job_dir, meta)
                        return
                    with self._proc_lock:
                        cancelled = job_id in self._cancelled
                    if cancelled:
                        # Morto por cancel_job() no meio do wait — não parseia saída parcial.
                        self._mark_cancelled(job_dir)
                        return
                    if step_argv is not argv and exit_code != 0:
                        # passo prévio (ex.: git clone do gitleaks) falhou — não faz sentido
                        # rodar o passo principal sobre um repo que não existe.
                        meta['status'] = 'error'
                        meta['error'] = 'passo prévio falhou (exit %d)' % exit_code
                        meta['finishedAt'] = int(time.time() * 1000)
                        self._save_meta(job_dir, meta)
                        return
            meta['exitCode'] = exit_code
            # A ferramenta principal pode sair com código != 0 sem que o job tenha
            # "falhado" de fato — gitleaks/osv-scanner usam exit 1 pra dizer "achei
            # algo" (ok_exit_codes cobre isso). Pra todo o resto, um exit inesperado
            # não vira status='error' (o resultado parseado pode estar vazio mas
            # válido), mas fica registrado como aviso não-fatal com o fim do stderr,
            # em vez de silenciosamente virar "done" sem nenhum sinal de que algo
            # deu errado (foi assim que o ffuf com wordlist ausente passou batido).
            ok_codes = spec.get('ok_exit_codes', set())
            if exit_code != 0 and exit_code not in ok_codes:
                meta['warning'] = 'ferramenta encerrou com código de saída %d — fim do stderr: %s' % (
                    exit_code, _stderr_tail(stderr_path))
        except FileNotFoundError:
            meta['status'] = 'error'
            meta['error'] = 'binário da ferramenta não encontrado no agente'
            meta['finishedAt'] = int(time.time() * 1000)
            self._save_meta(job_dir, meta)
            return
        except OSError as e:
            meta['status'] = 'error'
            meta['error'] = str(e)
            meta['finishedAt'] = int(time.time() * 1000)
            self._save_meta(job_dir, meta)
            return

        with self._proc_lock:
            cancelled = job_id in self._cancelled
        if cancelled:
            self._mark_cancelled(job_dir)
            return
        try:
            result = spec['parse'](raw_path)
            _atomic_write_json(os.path.join(job_dir, 'result.json'), result)
            meta['status'] = 'done'
        except Exception as e:  # parser bugs must not crash the job thread
            meta['status'] = 'error'
            meta['error'] = 'parse error: %s' % e
        # (WS-B) vazio NÃO é silêncio: parse ok mas 0 resultados + stderr suspeito -> aviso no
        # meta.json (o front mostra chip/toast). Ex.: nmap com alvo URL -> "0 hosts scanned".
        stderr_tail = _stderr_tail(stderr_path, 400)
        if meta.get('status') == 'done' and not result and meta.get('warning') is None and _stderr_suspicious(stderr_tail):
            meta['warning'] = 'scan retornou 0 resultados — fim do stderr: %s' % stderr_tail
        meta['finishedAt'] = int(time.time() * 1000)
        self._save_meta(job_dir, meta)

    def get_status(self, job_id):
        job_dir = os.path.join(self.jobs_dir, job_id)
        if not os.path.isdir(job_dir):
            return None
        return self._load_meta(job_dir)

    def get_result(self, job_id):
        path = os.path.join(self.jobs_dir, job_id, 'result.json')
        if not os.path.isfile(path):
            return None
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def get_raw(self, job_id):
        matches = glob.glob(os.path.join(self.jobs_dir, job_id, 'raw.*'))
        if not matches:
            return None
        with open(matches[0], 'rb') as f:
            return f.read()

    def list_jobs(self, limit=50):
        try:
            job_ids = sorted(os.listdir(self.jobs_dir), reverse=True)
        except FileNotFoundError:
            return []
        out = []
        for jid in job_ids[:limit]:
            meta = self.get_status(jid)
            if meta:
                out.append(meta)
        return out

    def delete_job(self, job_id):
        job_dir = os.path.join(self.jobs_dir, job_id)
        if os.path.isdir(job_dir):
            shutil.rmtree(job_dir)
            return True
        return False

    def _load_created(self, job_dir):
        """createdAt (ms epoch) do job, ou 0 se o meta.json estiver ilegível/ausente."""
        try:
            with open(os.path.join(job_dir, 'meta.json'), 'r', encoding='utf-8') as f:
                return json.load(f).get('createdAt') or 0
        except (OSError, ValueError):
            return 0

    def cleanup(self, retention_days=7, max_jobs=200):
        """Retenção em disco: apaga job dirs mais antigos que retention_days e, se ainda
        restarem mais que max_jobs, remove os mais antigos até o limite. Chamado uma vez no
        startup do agente (ver agent.main) — o jobs_dir cresce a cada scan, e sem isso o
        disco da Pi enche sem aviso. Não toca jobs em execução (eles também têm createdAt
        recente e nunca são os mais antigos)."""
        cutoff = (time.time() - retention_days * 86400) * 1000
        jobs = []
        try:
            names = os.listdir(self.jobs_dir)
        except FileNotFoundError:
            return
        for name in names:
            job_dir = os.path.join(self.jobs_dir, name)
            if not os.path.isdir(job_dir):
                continue
            jobs.append((self._load_created(job_dir), job_dir))
        jobs.sort(key=lambda x: x[0], reverse=True)  # mais recentes primeiro
        removed = 0
        kept = []
        for created, job_dir in jobs:
            if created < cutoff:
                shutil.rmtree(job_dir, ignore_errors=True)
                removed += 1
            else:
                kept.append(job_dir)
        for job_dir in kept[max_jobs:]:
            shutil.rmtree(job_dir, ignore_errors=True)
            removed += 1
        if removed:
            sys.stderr.write('[cleanup] %d job(s) antigo(s) removido(s) de %s\n' % (removed, self.jobs_dir))

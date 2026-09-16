#!/usr/bin/env python3
"""Testes dos parsers do Pi Agent (stdlib only, sem dependência).

Rode de dentro de pi-agent/:

    python test_parsers.py

Cobre os 11 parsers do TOOL_REGISTRY com fixtures sintéticas em arquivos
temporários. Valida o contrato do "Normalized result shape" (ver CLAUDE.md,
seção Pi Agent): todo resultado tem title/severity/affected/description/
evidence/sourceTool, severity está na escala do app, e meta é um dict
JSON-serializable.
"""
import json
import os
import tempfile
import unittest

import parsers

VALID_SEVERITIES = {'info', 'baixo', 'medio', 'alto', 'critico'}
REQUIRED_KEYS = {'title', 'severity', 'affected', 'description', 'evidence', 'sourceTool'}


def write_tmp(content, suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)
    return path


def assert_result_shape(testcase, results, source_tool):
    testcase.assertIsInstance(results, list)
    for r in results:
        testcase.assertIsInstance(r, dict)
        testcase.assertTrue(REQUIRED_KEYS.issubset(set(r)), 'faltam chaves: %s' % (REQUIRED_KEYS - set(r)))
        testcase.assertIn(r['severity'], VALID_SEVERITIES, 'severity fora da escala: %r' % r['severity'])
        testcase.assertIsInstance(r['evidence'], str)
        testcase.assertEqual(r['sourceTool'], source_tool)
        testcase.assertIsInstance(r['title'], str)
        meta = r.get('meta', {})
        testcase.assertIsInstance(meta, dict)
        json.dumps(meta)  # falha se algo não for serializável


class TestNmapXML(unittest.TestCase):
    def test_open_ports_only(self):
        xml = ('<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>'
               '<ports>'
               '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0p1"/></port>'
               '<port protocol="tcp" portid="23"><state state="closed"/></port>'
               '</ports></host></nmaprun>')
        path = write_tmp(xml, '.xml')
        try:
            results = parsers.parse_nmap_xml(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['affected'], '10.0.0.5:22')
        self.assertEqual(r['meta']['port'], '22')
        self.assertEqual(r['meta']['service'], 'ssh')
        assert_result_shape(self, results, 'nmap')

    def test_empty_or_missing(self):
        self.assertEqual(parsers.parse_nmap_xml('/nao/existe.xml'), [])
        path = write_tmp('<nmaprun/>', '.xml')
        try:
            self.assertEqual(parsers.parse_nmap_xml(path), [])
        finally:
            os.unlink(path)


class TestSubfinderJSONL(unittest.TestCase):
    def test_lines(self):
        path = write_tmp('{"host":"api.exemplo.com"}\n{"host":"dev.exemplo.com"}\n', '.jsonl')
        try:
            results = parsers.parse_subfinder_jsonl(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['meta']['host'], 'api.exemplo.com')
        assert_result_shape(self, results, 'subfinder')

    def test_bad_line_falls_back_to_text(self):
        path = write_tmp('sub.exemplo.com\n', '.jsonl')
        try:
            results = parsers.parse_subfinder_jsonl(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['affected'], 'sub.exemplo.com')


class TestHttpxJSONL(unittest.TestCase):
    def test_full_line(self):
        path = write_tmp(json.dumps({
            'url': 'http://x.exemplo.com', 'status_code': 200, 'title': 'Início',
            'tech': ['nginx', 'react'], 'webserver': 'nginx', 'content_length': 1234,
        }) + '\n', '.jsonl')
        try:
            results = parsers.parse_httpx_jsonl(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['meta']['statusCode'], 200)
        self.assertEqual(r['meta']['title'], 'Início')
        self.assertEqual(r['meta']['webServer'], 'nginx')
        assert_result_shape(self, results, 'httpx')


class TestNucleiJSONL(unittest.TestCase):
    def test_severity_mapping(self):
        path = write_tmp(json.dumps({
            'template-id': 'cve-2026-0001', 'matched-at': 'http://x/admin',
            'info': {'name': 'Reflected XSS', 'severity': 'high', 'description': 'desc', 'tags': ['xss', 'cve']},
            'extracted-results': ['<script>alert(1)</script>'],
        }) + '\n', '.jsonl')
        try:
            results = parsers.parse_nuclei_jsonl(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['severity'], 'alto')
        self.assertEqual(r['meta']['templateId'], 'cve-2026-0001')
        self.assertIn('xss', r['meta']['tags'])
        assert_result_shape(self, results, 'nuclei')


class TestOblivionSubdomains(unittest.TestCase):
    def test_array_of_hosts(self):
        path = write_tmp(json.dumps(['a.exemplo.com', 'b.exemplo.com']), '.json')
        try:
            results = parsers.parse_oblivion_subdomains(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)
        assert_result_shape(self, results, 'oblivion-subdomains')


class TestOblivionPassive(unittest.TestCase):
    def test_sections(self):
        data = {
            'subdomains': ['s.exemplo.com'],
            'security_headers': {'url': 'http://x.exemplo.com', 'issues': ['missing CSP header']},
            'fingerprint': {'url': 'http://x.exemplo.com', 'server': 'nginx', 'guesses': ['React']},
        }
        path = write_tmp(json.dumps(data), '.json')
        try:
            results = parsers.parse_oblivion_passive(path)
        finally:
            os.unlink(path)
        # 1 subdomain (info) + 1 header issue (baixo) + 1 fingerprint (info)
        self.assertEqual(len(results), 3)
        sevs = {r['severity'] for r in results}
        self.assertEqual(sevs, {'info', 'baixo'})
        assert_result_shape(self, results, 'oblivion-passive')

    def test_connection_error_becomes_info_finding(self):
        # O erro de conexão cru que o oblivion passive despeja em `issues` não é um header
        # faltando: vira um achado `info` próprio com o trace completo na evidência/meta, e
        # título curto — não um falso "baixo" com HTTPConnectionPool(...) inteiro no título.
        data = {
            'security_headers': {
                'url': 'http://http:',
                'issues': ["Não foi possível conectar: HTTPConnectionPool(host='http', port=80): "
                           'Max retries exceeded with url: / (Caused by NameResolutionError('
                           "\"HTTPConnection(host='http', port=80): Failed to resolve 'http' "
                           "([Errno -2] Name or service not known)\"))"],
            },
        }
        path = write_tmp(json.dumps(data), '.json')
        try:
            results = parsers.parse_oblivion_passive(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['severity'], 'info')
        self.assertEqual(r['title'], 'Falha de conexão com o alvo')
        self.assertIn('Max retries', r['evidence'])
        self.assertEqual(r['meta'].get('error'), r['evidence'])
        self.assertNotIn('HTTPConnectionPool', r['title'])
        assert_result_shape(self, results, 'oblivion-passive')

    def test_header_issue_offensive_phrasing(self):
        # A mensagem defensiva do oblivion passive ("Protege contra downgrade para HTTP
        # (HSTS ausente).") vira achado ofensivo: TÍTULO curto ("HSTS ausente") na lista e o
        # detalhe do ataque completo no meta.attack — que a UI mostra no detalhamento.
        # O original segue na evidência/meta.issue.
        data = {
            'security_headers': {
                'url': 'http://x.exemplo.com',
                'issues': ['Protege contra downgrade para HTTP (HSTS ausente).'],
            },
        }
        path = write_tmp(json.dumps(data), '.json')
        try:
            results = parsers.parse_oblivion_passive(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['severity'], 'baixo')
        self.assertEqual(r['title'], 'HSTS ausente')
        self.assertNotIn('downgrade', r['title'])
        self.assertNotIn('Protege contra', r['title'])
        self.assertIn('downgrade HTTPS', r['meta']['attack'])
        self.assertEqual(r['meta']['attack'], 'HSTS ausente — Permite downgrade HTTPS→HTTP e sequestro de sessão via sniffing')
        self.assertIn('HSTS ausente', r['evidence'])
        assert_result_shape(self, results, 'oblivion-passive')

    def test_cors_permissive_offensive(self):
        data = {
            'security_headers': {
                'url': 'http://x.exemplo.com',
                'issues': ['CORS permissivo: Access-Control-Allow-Origin: * (qualquer origem pode ler a resposta).'],
            },
        }
        path = write_tmp(json.dumps(data), '.json')
        try:
            results = parsers.parse_oblivion_passive(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['title'], 'CORS permissivo')
        self.assertIn('pode ler a resposta', r['meta']['attack'])
        self.assertEqual(r['meta']['attack'], 'CORS permissivo — Qualquer origem pode ler a resposta (Access-Control-Allow-Origin: *)')
        assert_result_shape(self, results, 'oblivion-passive')


class TestOblivionWebrecon(unittest.TestCase):
    def test_hits(self):
        path = write_tmp(json.dumps([
            {'url': 'http://x/admin', 'status': 200, 'size': 1024, 'type': 'directory'},
            {'url': 'http://x/backup.zip', 'status': 200, 'size': 999999, 'type': 'file'},
        ]), '.json')
        try:
            results = parsers.parse_oblivion_webrecon(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['meta']['statusCode'], 200)
        assert_result_shape(self, results, 'oblivion-webrecon')


class TestOblivionWebvuln(unittest.TestCase):
    def test_findings(self):
        path = write_tmp(json.dumps({
            'url': 'http://x.exemplo.com',
            'findings': [{'check': 'CORS', 'severity': 'high', 'detail': 'origin refletido no ACAO'}],
        }), '.json')
        try:
            results = parsers.parse_oblivion_webvuln(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['severity'], 'alto')
        assert_result_shape(self, results, 'oblivion-webvuln')


class TestOblivionExposed(unittest.TestCase):
    def test_hits(self):
        path = write_tmp(json.dumps([
            {'url': 'http://x/.git/config', 'status': 200, 'evidence': 'credential helper'},
        ]), '.json')
        try:
            results = parsers.parse_oblivion_exposed(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['severity'], 'alto')
        assert_result_shape(self, results, 'oblivion-exposed')


class TestSQLMapLog(unittest.TestCase):
    SQLMAP_LOG = (
        'sqlmap identified the following injection point(s) with a total of 63 HTTP(s) requests:\n'
        '---\n'
        'Parameter: id (GET)\n'
        '    Type: boolean-based blind\n'
        '    Title: AND boolean-based blind\n'
        '    Payload: id=1 AND 1=1\n'
        '---\n'
    )

    def test_blocks(self):
        # sqlmap escreve <job_dir>/<host>/log — simulamos a árvore.
        with tempfile.TemporaryDirectory() as job_dir:
            host_dir = os.path.join(job_dir, '192.168.1.1')
            os.makedirs(host_dir)
            with open(os.path.join(host_dir, 'log'), 'w', encoding='utf-8') as f:
                f.write(self.SQLMAP_LOG)
            results = parsers.parse_sqlmap_log(os.path.join(job_dir, 'raw.log'))
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['severity'], 'critico')
        self.assertEqual(r['meta']['parameter'], 'id (GET)')
        self.assertEqual(r['meta']['type'], 'boolean-based blind')
        self.assertIn('AND 1=1', r['meta']['payload'])
        assert_result_shape(self, results, 'sqlmap')

    def test_dbs_enumeration_adds_extra_finding(self):
        # `enumerate=dbs` soma `--dbs` ao argv; sqlmap imprime esse bloco fora dos '---'.
        log = self.SQLMAP_LOG + (
            '[INFO] fetching database names\n'
            'available databases [2]:\n'
            '[*] information_schema\n'
            '[*] mrturismo\n'
        )
        with tempfile.TemporaryDirectory() as job_dir:
            host_dir = os.path.join(job_dir, '192.168.1.1')
            os.makedirs(host_dir)
            with open(os.path.join(host_dir, 'log'), 'w', encoding='utf-8') as f:
                f.write(log)
            results = parsers.parse_sqlmap_log(os.path.join(job_dir, 'raw.log'))
        self.assertEqual(len(results), 2)
        dbs_finding = results[1]
        self.assertEqual(dbs_finding['severity'], 'info')
        self.assertIn('information_schema', dbs_finding['evidence'])
        self.assertIn('mrturismo', dbs_finding['evidence'])
        self.assertEqual(dbs_finding['meta']['count'], 2)
        assert_result_shape(self, results, 'sqlmap')


class TestDalfoxJSON(unittest.TestCase):
    def test_fields(self):
        path = write_tmp(json.dumps([
            {'param': 'q', 'payload': '<script>alert(1)</script>', 'severity': 'high',
             'type': 'reflected', 'message_str': 'XSS refletido', 'data': 'http://x/?q=1'},
        ]), '.json')
        try:
            results = parsers.parse_dalfox_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['severity'], 'alto')
        self.assertEqual(r['meta']['param'], 'q')
        self.assertIn('script', r['evidence'])
        assert_result_shape(self, results, 'dalfox')

    def test_empty_object_returns_no_results(self):
        # dalfox v2 writes a bare `[{}]` when it finds nothing on the target.
        path = write_tmp(json.dumps([{}]), '.json')
        try:
            results = parsers.parse_dalfox_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(results, [])


class TestTruncate(unittest.TestCase):
    def test_short_passthrough(self):
        self.assertEqual(parsers._truncate('abc'), 'abc')

    def test_long_gets_marker(self):
        out = parsers._truncate('x' * 9000)
        self.assertTrue(out.endswith('…[truncado]'))
        self.assertLessEqual(len(out), 8000)

    def test_non_string_serialized(self):
        out = parsers._truncate({'a': 'b'})
        self.assertEqual(out, '{"a": "b"}')


class TestMissingFiles(unittest.TestCase):
    def test_all_parsers_handle_missing(self):
        for name in ('parse_nmap_xml', 'parse_subfinder_jsonl', 'parse_httpx_jsonl',
                     'parse_nuclei_jsonl', 'parse_oblivion_subdomains', 'parse_oblivion_passive',
                     'parse_oblivion_webrecon', 'parse_oblivion_webvuln', 'parse_oblivion_exposed',
                     'parse_sqlmap_log', 'parse_dalfox_json',
                     'parse_testssl_json', 'parse_wpscan_json', 'parse_gitleaks_json',
                     'parse_ffuf_json', 'parse_nikto_xml', 'parse_osv_scanner_json',
                     'parse_gau_json', 'parse_waybackurls_txt', 'parse_katana_jsonl',
                     'parse_wafw00f_json', 'parse_arjun_json'):
            fn = getattr(parsers, name)
            try:
                out = fn('/nao/existe/arquivo')
            except Exception as e:  # pragma: no cover
                self.fail('%s quebrou com arquivo ausente: %r' % (name, e))
            self.assertIsInstance(out, list)
            self.assertEqual(out, [], '%s deveria retornar []' % name)


class TestTestssl(unittest.TestCase):
    def test_findings_only_ok_filtered(self):
        data = json.dumps([
            {'id': 'SSLv2', 'severity': 'HIGH', 'finding': 'SSLv2 offered', 'ip': '10.0.0.5', 'port': 443, 'cve': 'CVE-2015-3197'},
            {'id': 'cipherlist_3DES', 'severity': 'MEDIUM', 'finding': '3DES ciphers offered', 'ip': '10.0.0.5', 'port': 443},
            {'id': 'heartbleed', 'severity': 'CRITICAL', 'finding': 'Heartbleed', 'ip': '10.0.0.5', 'port': 443, 'cve': 'CVE-2014-0160'},
            {'id': 'TLS1_2', 'severity': 'OK', 'finding': 'TLS1.2 offered'},
        ])
        path = write_tmp(data, '.json')
        try:
            results = parsers.parse_testssl_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]['severity'], 'alto')
        self.assertEqual(results[1]['severity'], 'medio')
        self.assertEqual(results[2]['severity'], 'critico')
        self.assertEqual(results[2]['affected'], '10.0.0.5:443')
        self.assertIn('CVE-2014-0160', results[2]['evidence'])
        assert_result_shape(self, results, 'testssl')


class TestWpscan(unittest.TestCase):
    def test_version_plugins_theme(self):
        data = json.dumps({
            'site_url': 'https://wp.example',
            'version': {'number': '5.8', 'vulnerabilities': [
                {'id': '12345', 'title': 'XSS no upload', 'cvss': {'score': 9.5}, 'references': {'cve': ['CVE-2021-0001']}},
            ]},
            'plugins': {
                'contact-form-7': {'version': '5.4', 'vulnerabilities': [
                    {'id': '54321', 'title': 'SQLi no form', 'cvss': {'score': 7.2}},
                ]},
            },
            'main_theme': {'version': '1.0', 'vulnerabilities': [
                {'id': '11111', 'title': 'XSS no tema', 'cvss': {'score': 5.0}},
            ]},
        })
        path = write_tmp(data, '.json')
        try:
            results = parsers.parse_wpscan_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]['severity'], 'critico')
        self.assertEqual(results[1]['severity'], 'alto')
        self.assertEqual(results[2]['severity'], 'medio')
        self.assertEqual(results[0]['affected'], 'https://wp.example')
        self.assertIn('CVE-2021-0001', results[0]['meta']['cve'])
        assert_result_shape(self, results, 'wpscan')

    def test_no_vulns(self):
        path = write_tmp(json.dumps({'site_url': 'https://wp.example'}), '.json')
        try:
            self.assertEqual(parsers.parse_wpscan_json(path), [])
        finally:
            os.unlink(path)


class TestGitleaks(unittest.TestCase):
    def test_leaks(self):
        data = json.dumps([
            {'RuleID': 'aws-access-token', 'Description': 'AWS Access Token',
             'File': 'deploy/env.sh', 'Commit': 'a1b2c3', 'Secret': 'AKIA...'},
            {'RuleID': 'generic-api-key', 'Description': 'Generic API Key',
             'File': 'src/config.php', 'Commit': 'd4e5f6', 'Secret': 'sk-xxx'},
        ])
        path = write_tmp(data, '.json')
        try:
            results = parsers.parse_gitleaks_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['severity'], 'alto')
        self.assertEqual(results[0]['affected'], 'deploy/env.sh')
        self.assertIn('aws-access-token', results[0]['title'])
        assert_result_shape(self, results, 'gitleaks')


class TestFfuf(unittest.TestCase):
    def test_results(self):
        data = json.dumps({'results': [
            {'url': 'http://x/admin', 'status': 200, 'length': 1024, 'redirectlocation': ''},
            {'url': 'http://x/backup.zip', 'status': 403, 'length': 21, 'redirectlocation': ''},
        ]})
        path = write_tmp(data, '.json')
        try:
            results = parsers.parse_ffuf_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)
        r = results[0]
        self.assertEqual(r['severity'], 'info')
        self.assertEqual(r['meta']['statusCode'], 200)
        self.assertEqual(r['meta']['size'], 1024)
        self.assertEqual(r['affected'], 'http://x/admin')
        assert_result_shape(self, results, 'ffuf')

    def test_non_dict_ignored(self):
        path = write_tmp(json.dumps({'results': ['nope', 42]}), '.json')
        try:
            self.assertEqual(parsers.parse_ffuf_json(path), [])
        finally:
            os.unlink(path)


class TestNikto(unittest.TestCase):
    NIKTO_XML = (
        '<?xml version="1.0" ?>\n<niktoscan version="2.1.5">\n'
        '<scandetails targetip="10.0.0.9" targethostname="10.0.0.9" targetport="80">\n'
        '<item id="999954" osvdbid="0" method="GET">'
        '<description><![CDATA[Server leaks inode numbers via ETag header]]></description>'
        '<uri><![CDATA[/index.html]]></uri></item>\n'
        '<item id="12345" osvdbid="3092" method="GET">'
        '<description><![CDATA[X-XSS-Protection header not defined]]></description>'
        '<uri><![CDATA[/]]></uri></item>\n'
        '<item id="0" osvdbid="0" method="GET"><description><![CDATA[]]></description><uri/></item>\n'
        '</scandetails>\n</niktoscan>\n'
    )

    def test_items_default_low(self):
        path = write_tmp(self.NIKTO_XML, '.xml')
        try:
            results = parsers.parse_nikto_xml(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)  # item de descrição vazia é ignorado
        self.assertEqual(results[0]['severity'], 'baixo')
        self.assertEqual(results[0]['affected'], '10.0.0.9:80/index.html')
        self.assertEqual(results[1]['meta']['osvdb'], '3092')
        assert_result_shape(self, results, 'nikto')

    def test_missing_file_returns_no_results(self):
        self.assertEqual(parsers.parse_nikto_xml('/nonexistent/nikto.xml'), [])


class TestOsvScanner(unittest.TestCase):
    def test_cvss_mapping_and_packages(self):
        data = json.dumps({'results': [
            {'package': {'name': 'lodash', 'version': '4.17.15', 'ecosystem': 'npm'},
             'vulnerabilities': [
                 {'id': 'GHSA-xxxx-xxxx-xxxx', 'aliases': ['CVE-2021-23337'],
                  'summary': 'Command Injection', 'severity': [{'type': 'CVSS_V3', 'score': 8.7}]},
                 {'id': 'GHSA-yyyy', 'aliases': [], 'summary': 'ReDoS',
                  'severity': [{'type': 'CVSS_V3', 'score': 5.3}]},
             ]},
        ]})
        path = write_tmp(data, '.json')
        try:
            results = parsers.parse_osv_scanner_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['severity'], 'alto')
        self.assertEqual(results[1]['severity'], 'medio')
        self.assertEqual(results[0]['meta']['package'], 'lodash')
        self.assertEqual(results[0]['meta']['aliases'], 'CVE-2021-23337')
        self.assertEqual(results[0]['affected'], 'lodash (npm 4.17.15)')
        assert_result_shape(self, results, 'osv-scanner')


class TestWafw00f(unittest.TestCase):
    def test_detected(self):
        data = json.dumps([{
            'detected': True, 'firewall': 'Cloudflare', 'manufacturer': 'Cloudflare Inc.',
            'trigger_url': None, 'url': 'http://x/',
        }])
        path = write_tmp(data, '.json')
        try:
            results = parsers.parse_wafw00f_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['severity'], 'info')
        self.assertIn('Cloudflare', r['title'])
        self.assertTrue(r['meta']['detected'])
        assert_result_shape(self, results, 'wafw00f')

    def test_not_detected(self):
        data = json.dumps([{'detected': False, 'firewall': 'None', 'manufacturer': 'None',
                             'trigger_url': None, 'url': 'http://x/'}])
        path = write_tmp(data, '.json')
        try:
            results = parsers.parse_wafw00f_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]['meta']['detected'])
        self.assertIn('Nenhum', results[0]['title'])


class TestArjun(unittest.TestCase):
    def test_params_found(self):
        data = json.dumps({'http://x/search.php': ['q', 'page']})
        path = write_tmp(data, '.json')
        try:
            results = parsers.parse_arjun_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r['severity'], 'info')
        self.assertEqual(r['meta']['count'], 2)
        self.assertIn('q', r['meta']['params'])
        assert_result_shape(self, results, 'arjun')

    def test_missing_file_returns_no_results(self):
        # arjun só grava o arquivo quando encontra algo — sem ele, sem achado.
        self.assertEqual(parsers.parse_arjun_json('/nonexistent/path.json'), [])


class TestKatana(unittest.TestCase):
    def test_lines(self):
        lines = [
            json.dumps({'request': {'endpoint': 'http://x/a', 'method': 'GET'},
                        'response': {'status_code': 200, 'headers': {'Content-Type': 'text/html'}, 'content_length': 100}}),
            json.dumps({'request': {'endpoint': 'http://x/pages.php?page=b64', 'method': 'GET', 'source': 'http://x/a'},
                        'response': {'status_code': 200, 'headers': {}, 'content_length': 50}}),
        ]
        path = write_tmp('\n'.join(lines), '.jsonl')
        try:
            results = parsers.parse_katana_jsonl(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)
        assert_result_shape(self, results, 'katana')
        self.assertEqual(results[1]['meta']['statusCode'], 200)

    def test_missing_file_returns_no_results(self):
        self.assertEqual(parsers.parse_katana_jsonl('/nonexistent/path.jsonl'), [])


class TestGau(unittest.TestCase):
    def test_jsonl_urls(self):
        lines = '\n'.join([json.dumps({'url': 'http://x/a.js'}), json.dumps({'url': 'http://x/b.php'})])
        path = write_tmp(lines, '.jsonl')
        try:
            results = parsers.parse_gau_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['severity'], 'info')
        self.assertEqual(results[0]['meta']['url'], 'http://x/a.js')
        assert_result_shape(self, results, 'gau')

    def test_missing_file_returns_no_results(self):
        self.assertEqual(parsers.parse_gau_json('/nonexistent/g.jsonl'), [])


class TestWaybackurls(unittest.TestCase):
    def test_dedupes_urls(self):
        path = write_tmp('http://x/a\nhttp://x/b\nhttp://x/a\n', '.txt')
        try:
            results = parsers.parse_waybackurls_txt(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(results), 2)  # duplicata removida
        assert_result_shape(self, results, 'waybackurls')

    def test_missing_file_returns_no_results(self):
        self.assertEqual(parsers.parse_waybackurls_txt('/nonexistent/w.txt'), [])


class TestToolsRegistry(unittest.TestCase):
    """Contrato do TOOL_REGISTRY (v25): toda tool tem bin/build_argv/parse e params
    limitados; builders novos seguem o padrão; validate_params rejeita params fora do
    enum. Sem isso, o frontend pode mandar um job que quebra no meio do pipeline."""

    def test_all_registered_tools_well_formed(self):
        import tools
        self.assertEqual(len(tools.TOOL_REGISTRY), 22)
        for name, spec in tools.TOOL_REGISTRY.items():
            self.assertIn('bin', spec)
            self.assertIn('build_argv', spec)
            self.assertIn('parse', spec)
            self.assertIn('raw_ext', spec)
            self.assertTrue(callable(spec['build_argv']))
            self.assertTrue(callable(spec['parse']))
            self.assertIsInstance(spec['params_allowed'], set)
            # parser do registry bate com o sourceTool esperado
            results = spec['parse']('/nao/existe')
            self.assertEqual(results, [])
            self.assertTrue(tools.validate_params(name, {}), 'params vazios devem valer pra %s' % name)
            # build_argv TEM que aceitar a assinatura de 4 args que jobs.start_job usa
            # (target, params, raw_path, session) — um builder de 3 args quebra a thread do
            # agente em runtime (foi o bug que fazia o oblivion-passive/nmap/subfinder
            # sumirem do pipeline). pre_build, quando existe, é chamado com 3 args.
            argv = spec['build_argv']('exemplo.com', {}, '/tmp/raw.x', 'Cookie: a=b')
            self.assertIsInstance(argv, list)
            self.assertTrue(all(isinstance(a, str) for a in argv), 'argv de %s deve ser lista de str' % name)
            if 'pre_build' in spec:
                pre = spec['pre_build']('exemplo.com', {}, '/tmp/raw.x')
                self.assertIsInstance(pre, list)

    def test_validate_params_rejects_unknown_and_bad_enum(self):
        import tools
        self.assertFalse(tools.validate_params('nmap', {'exec': 'rm -rf /'}))
        self.assertFalse(tools.validate_params('ffuf', {'wordlist': '../etc/passwd'}))
        self.assertTrue(tools.validate_params('ffuf', {'wordlist': 'raft-medium'}))

    def test_ffuf_builder_appends_fuzz_and_validates_target(self):
        import tools
        raw = os.path.join('jobs', 'abc', 'raw.json')
        argv = tools.build_ffuf_argv('http://x.exemplo.com', {}, raw)
        self.assertEqual(argv[1], '-u')
        self.assertEqual(argv[2], 'http://x.exemplo.com/FUZZ')
        self.assertTrue(tools.validate_target('http://x.exemplo.com'))
        self.assertTrue(tools.validate_target('https://github.com/org/repo.git'))
        self.assertFalse(tools.validate_target('x; rm -rf /'))

    def test_osv_clone_and_scan_share_repo_dir(self):
        import tools
        raw = os.path.join('jobs', 'abc', 'raw.json')
        clone = tools.build_osv_clone_argv('https://github.com/org/repo.git', {}, raw)
        scan = tools.build_osv_scanner_argv('https://github.com/org/repo.git', {}, raw)
        self.assertEqual(clone[0], 'git')
        self.assertEqual(scan[0], 'osv-scanner')
        self.assertIn('--format', scan)
        self.assertIn('--output', scan)

    def test_nmap_builder_normalizes_url_target(self):
        import tools
        raw = '/tmp/raw.xml'
        # O bug real (v32): o alvo URL cru chegava no argv (`nmap ... http://x:8080/path/`) e o
        # nmap morria em "Unable to split netmask ... No targets were specified", virando um
        # "done" fantasma com 0 achados. Agora o builder normaliza host + porta explícita.
        argv = tools.build_nmap_argv('http://192.168.0.19:8080/turismo/', {}, raw)
        self.assertEqual(argv[-1], '192.168.0.19')
        self.assertIn('-p', argv)
        self.assertIn('8080', argv)
        self.assertNotIn('--top-ports', argv)
        # sem porta na URL -> perfil escolhido
        argv2 = tools.build_nmap_argv('http://x.exemplo.com', {}, raw)
        self.assertEqual(argv2[-1], 'x.exemplo.com')
        self.assertIn('--top-ports', argv2)
        # params.port vence e -sV mira na porta
        argv3 = tools.build_nmap_argv('x.exemplo.com', {'profile': 'full', 'port': '8443'}, raw)
        self.assertEqual(argv3[-1], 'x.exemplo.com')
        self.assertIn('-p', argv3)
        self.assertIn('8443', argv3)
        self.assertNotIn('-p-', argv3)
        # host:porta sem scheme também separa
        argv4 = tools.build_nmap_argv('192.168.0.5:22', {}, raw)
        self.assertEqual(argv4[-1], '192.168.0.5')
        self.assertIn('22', argv4)
        # alvo inválido -> erro claro (o agent.py vira 400), nunca job fantasma
        with self.assertRaises(ValueError):
            tools.build_nmap_argv('http://', {}, raw)
        with self.assertRaises(ValueError):
            tools.build_nmap_argv('', {}, raw)

    def test_nmap_testssl_params_allow_port(self):
        import tools
        self.assertTrue(tools.validate_params('nmap', {'profile': 'top-ports', 'port': '8080'}))
        self.assertTrue(tools.validate_params('nmap', {'port': '443'}))
        self.assertTrue(tools.validate_params('testssl', {'port': '443'}))
        self.assertFalse(tools.validate_params('nmap', {'exec': 'rm -rf /'}))

    def test_host_normalization_helper(self):
        import tools
        self.assertEqual(tools._normalize_host_target('http://192.168.0.19:8080/turismo/'), ('192.168.0.19', '8080'))
        self.assertEqual(tools._normalize_host_target('x.exemplo.com'), ('x.exemplo.com', ''))
        self.assertEqual(tools._normalize_host_target('192.168.0.5:22'), ('192.168.0.5', '22'))
        self.assertEqual(tools._normalize_host_target('[::1]:8443'), ('[::1]', '8443'))
        self.assertEqual(tools._normalize_host_target(''), (None, None))
        self.assertEqual(tools._normalize_host_target('http://'), (None, None))

    def test_testssl_builder_normalizes(self):
        import tools
        raw = '/tmp/raw.json'
        argv = tools.build_testssl_argv('https://x.exemplo.com:443/login', {}, raw)
        self.assertEqual(argv[-1], 'x.exemplo.com:443')
        argv2 = tools.build_testssl_argv('x.exemplo.com', {'port': '8443'}, raw)
        self.assertEqual(argv2[-1], 'x.exemplo.com:8443')
        with self.assertRaises(ValueError):
            tools.build_testssl_argv('https://', {}, raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)

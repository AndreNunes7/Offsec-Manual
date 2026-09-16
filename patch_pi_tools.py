import re
with open('/home/andre/tools/pi-agent/tools.py', 'r') as f:
    content = f.read()

helper = '''\n# Normaliza target para ferramentas que esperam apenas host:porta (ex: oblivion*).\n# Remove esquema (http://, https://) e caminho, mantem host:porta.\ndef _normalize_host_target(target):\n    if not target:\n        return ""\n    t = target.strip()\n    if t.startswith("http://"):\n        t = t[7:]\n    elif t.startswith("https://"):\n        t = t[8:]\n    for sep in ["/", "?", "#"]:\n        if sep in t:\n            t = t.split(sep)[0]\n    return t\n'''

pattern = r'(def validate_session\(session\):.*?return bool\(SESSION_RE.match\(session\)\))'
match = re.search(pattern, content, re.DOTALL)
if match:
    insert_pos = match.end()
    content = content[:insert_pos] + '\n\n' + helper + content[insert_pos:]
    with open('/home/andre/tools/pi-agent/tools.py', 'w') as f:
        f.write(content)
    print('Helper added')
else:
    print('Pattern not found')
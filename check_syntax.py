import ast
with open('/home/andre/tools/pi-agent/agent.py', 'r') as f:
    content = f.read()
try:
    ast.parse(content)
    print("Syntax OK")
except SyntaxError as e:
    print(f"Syntax Error at line {e.lineno}: {e.msg}")
    lines = content.split('\n')
    for i in range(max(0, e.lineno-3), min(len(lines), e.lineno+3)):
        print(f"{i+1:4}: {lines[i]}")
---
mode: subagent
description: |-
  Este projeto tem frontend e backend em máquinas diferentes.

  ## Frontend (local, Windows)
  - Caminho: D:/desenvolvimento/offsec-manual
  - Edite esses arquivos diretamente no sistema de arquivos local.

  ## Backend (remoto, Raspberry Pi)
  - Host: andre@192.168.0.19
  - Caminho remoto: /home/andre/pi-agent/ 
  - Para editar arquivos remotos, use comandos ssh, por exemplo:
    ssh pi@192.168.x.x "cat > /home/pi/pi-agent/modules/x.py" <<'EOF'
    ...conteúdo...
    EOF
  - Para rodar/testar o backend remotamente:
    ssh pi@192.168.x.x "cd pi-agent && python3 agent.py"
  - Nunca peça senha ao usuário — a autenticação já é por chave SSH.
---


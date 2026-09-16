#!/bin/sh
export PATH="$HOME/tools/go/bin:$HOME/tools:$HOME/tools/Oblivion:$HOME/tools/Oblivion/env/bin:$HOME/.local/bin:$HOME/tools/go/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
cd "$HOME/tools/pi-agent"
exec python3 -u agent.py
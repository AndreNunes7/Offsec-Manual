#!/bin/bash
pkill -9 -f agent.py
sleep 2
cd /home/andre/tools/pi-agent
nohup bash -c 'while true; do python3 -u agent.py; sleep 5; done' > agent.log 2>&1 &
sleep 5
curl -s -H 'Authorization: Bearer 2093aa42cdc6823c3c56a2e4a98e8877ff561d3b206824a7675671f4effd434b' http://192.168.0.14:8787/api/v1/health | python3 -m json.tool
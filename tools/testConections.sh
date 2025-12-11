#!/bin/bash
#sed -i 's/\r$//' tools/testConections.sh && chmod +x tools/testConections.sh

PROXY_USER="admin"
PROXY_PASS="0000"
PROXY_HOST="127.0.0.1"
PROXY_PORT="1080"

for i in {1..500}; do
    curl -x "socks5h://$PROXY_USER:$PROXY_PASS@$PROXY_HOST:$PROXY_PORT" \
         http://www.google.com:81 \
         --max-time 5 \
         > /dev/null 2>&1 &
done

wait

echo "Stress test finished: 500 connections launched via SOCKS5 (admin/0000)."
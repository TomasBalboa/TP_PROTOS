#!/bin/bash

SERVER="${SERVER:-127.0.0.1}"
SOCKS5_PORT="${SOCKS5_PORT:-1080}"
MGMT_PORT="${MGMT_PORT:-9090}"
CONNECTIONS="${1:-1018}"
DURATION="${2:-30}"
PIDS=()

count_active() {
    local n=0
    for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null && ((n++)); done
    echo $n
}

cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
}

trap 'echo ""; cleanup; exit 130' INT TERM

command -v nc &>/dev/null || { echo "ERROR: netcat no instalado"; exit 1; }

echo "Stress Test: $CONNECTIONS conexiones, ${DURATION}s"
echo "Servidor: $SERVER:$SOCKS5_PORT"

nc -z -w 2 "$SERVER" "$SOCKS5_PORT" 2>/dev/null || { echo "ERROR: Servidor no responde"; exit 1; }

echo ""
echo "Métricas iniciales:"
echo -ne '\x01\x05admin\x040000\x01\x03\x00' | nc -w 2 "$SERVER" "$MGMT_PORT" 2>/dev/null | tail -n +3

echo ""
echo "Abriendo $CONNECTIONS conexiones..."
for i in $(seq 1 $CONNECTIONS); do
    (sleep $((DURATION + 5)) | nc "$SERVER" "$SOCKS5_PORT") &>/dev/null &
    PIDS+=($!)
    sleep 0.005
    [ $((i % (CONNECTIONS / 10))) -eq 0 ] && echo -ne "  $((i * 100 / CONNECTIONS))%\r"
done
echo "  100%"

echo ""
echo "Monitoreando ${DURATION}s..."
sleep 2
SUCCESS=$(count_active)
FAIL=$((CONNECTIONS - SUCCESS))
echo "  Exitosas: $SUCCESS/$CONNECTIONS"

for t in $(seq 5 5 $DURATION); do
    sleep 5
    echo -ne "  [${t}s] Activas: $(count_active)  \r"
done
echo ""

echo -n "Cerrando... "
cleanup
echo "OK"

echo ""
echo "Métricas finales:"
echo -ne '\x01\x05admin\x040000\x01\x03\x00' | nc -w 2 "$SERVER" "$MGMT_PORT" 2>/dev/null | tail -n +3

echo ""
echo "=== RESUMEN ==="
echo "Solicitadas: $CONNECTIONS | Exitosas: $SUCCESS | Fallidas: $FAIL"
[ $FAIL -eq 0 ] && echo "RESULTADO: ÉXITO (100%)" && exit 0
[ $SUCCESS -gt $((CONNECTIONS / 2)) ] && echo "RESULTADO: PARCIAL" && exit 1
echo "RESULTADO: FALLO" && exit 2

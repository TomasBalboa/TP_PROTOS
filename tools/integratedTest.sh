#!/bin/bash
#IGUAL QUE TODOS LOS SH, los modificos para que ande en bash:
sed -i 's/\r$//' tools/integratedTest.sh && chmod +x tools/integratedTest.sh
# ================= CONFIG =================

CONNECTIONS=3000           # Total de conexiones a lanzar
CONCURRENCY=300           # Número de conexiones concurrentes máximas
SERVER="127.0.0.1"        # Dirección del proxy
PORT="1080"               # Puerto del proxy SOCKS5 (sin auth)

URLS=(
  "https://example.org"
  "https://www.google.com"
  "https://www.cloudflare.com"
  "https://www.gnu.org"
  "https://www.wikipedia.org"
  "https://www.kernel.org"
  "https://www.mozilla.org"
  "https://www.github.com"
  "https://nbg1-speed.hetzner.com/100MB.bin"
  "https://www.stackoverflow.com"
)

URLS_JOINED=$(IFS='|'; echo "${URLS[*]}")

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="stress_results_${TIMESTAMP}.log"
SUMMARYFILE="stress_summary_${TIMESTAMP}.txt"

echo "== SOCKSv5 integrated stress test =="
echo "Proxy: $SERVER:$PORT (no auth)"
echo "Total connections: $CONNECTIONS"
echo "Concurrency: $CONCURRENCY"
echo "Endpoints: ${#URLS[@]}"
echo "Log file: $LOGFILE"
echo ""

echo "[check] Probing proxy with a simple request..."
if ! curl -x "socks5h://$SERVER:$PORT" --connect-timeout 3 --max-time 5 -s -o /dev/null "https://www.google.com"; then
    echo "[check] ERROR: proxy socks5h://$SERVER:$PORT no respondió correctamente."
    echo "Abortando test. Verificá que el servidor esté levantado y escuchando."
    exit 1
fi
echo "[check] OK: el proxy responde. Iniciando stress test..."
echo ""

> "$LOGFILE"

echo "[run] Lanzando conexiones..."
seq 1 "$CONNECTIONS" | xargs -n1 -P"$CONCURRENCY" -I{} bash -c '
  ID="$1"

  IFS="|" read -r -a URL_ARRAY <<< "'"$URLS_JOINED"'"
  IDX=$(( (ID - 1) % ${#URL_ARRAY[@]} ))
  URL="${URL_ARRAY[$IDX]}"

  START_S=$(date +%s)

  RESULT=$(curl -x "socks5h://'"$SERVER"':'"$PORT"'" \
      --connect-timeout 5 --max-time 15 \
      -w "%{http_code}" -o /dev/null -s "$URL" 2>&1)

  END_S=$(date +%s)
  ELAPSED=$(( (END_S - START_S) * 1000 ))

  echo "[$ID] URL: $URL | Code: $RESULT | Time_ms: ${ELAPSED}" >> "'"$LOGFILE"'"
' _ {}

echo ""
echo "Stress test completado. Los resultados detallados se encuentran en $LOGFILE"
echo ""

echo "== HTTP code summary =="
grep -o "Code: [0-9]*" "$LOGFILE" | sort | uniq -c

echo ""
echo "== Average response time =="
awk '{split($0,a,"Time_ms: "); if (a[2]!="") {sum+=a[2]; count++}} END {if (count>0) printf("Promedio: %.2f ms (%d muestras)\n", sum/count, count); else print "No se midió tiempo"}' "$LOGFILE"

# Guardar un pequeño resumen en archivo aparte
{
    echo "Proxy: $SERVER:$PORT (no auth)"
    echo "Total connections: $CONNECTIONS"
    echo "Concurrency: $CONCURRENCY"
    echo "Endpoints: ${#URLS[@]}"
    echo ""
    echo "HTTP code counts:"
    grep -o "Code: [0-9]*" "$LOGFILE" | sort | uniq -c
    echo ""
    echo "Average response time (ms):"
    awk '{split($0,a,"Time_ms: "); if (a[2]!="") {sum+=a[2]; count++}} END {if (count>0) printf("%.2f (n=%d)\n", sum/count, count); else print "N/A"}' "$LOGFILE"
} > "$SUMMARYFILE"

echo ""
echo "Resumen guardado en $SUMMARYFILE"
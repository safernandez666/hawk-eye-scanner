#!/bin/bash
# Reset Poirot DSPM: limpia alertas SQLite, casos TheHive y archivos temporales
# Cada paso es independiente: si uno falla, los demás se ejecutan igual
# Uso: ./reset.sh

# Cargar variables de .env si existe (solo THEHIVE_*)
if [ -f .env ]; then
    eval "$(grep "^THEHIVE_" .env | sed 's/^/export /')"
fi

DB_PATH="${ALERTS_DB_PATH:-hawk-scanner/data/alerts.db}"
THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
# Si la URL contiene 'thehive:' (hostname interno de Docker), cambiar a localhost
if echo "$THEHIVE_URL" | grep -q 'thehive:'; then
    THEHIVE_URL="http://localhost:9000"
fi
THEHIVE_API_KEY="${THEHIVE_API_KEY:-}"
THEHIVE_USER="${THEHIVE_USER:-}"
THEHIVE_PASSWORD="${THEHIVE_PASSWORD:-}"

# Use temp directory for cookies (cleanup on exit)
COOKIE_JAR=$(mktemp /tmp/thehive_reset.XXXXXX.cookies)
trap 'rm -f "$COOKIE_JAR" 2>/dev/null || true' EXIT

# Si no hay credenciales en env, intentar leerlas de connection.yml
if command -v python3 &>/dev/null; then
    if [ -z "$THEHIVE_API_KEY" ]; then
        THEHIVE_API_KEY=$(python3 -c "
import yaml
try:
    with open('hawk-scanner/connection.yml') as f:
        c = yaml.safe_load(f)
    print(c.get('notify',{}).get('channels',{}).get('thehive',{}).get('api_key',''))
except: pass
" 2>/dev/null)
    fi
    if [ -z "$THEHIVE_USER" ]; then
        THEHIVE_USER=$(python3 -c "
import yaml
try:
    with open('hawk-scanner/connection.yml') as f:
        c = yaml.safe_load(f)
    print(c.get('notify',{}).get('channels',{}).get('thehive',{}).get('user',''))
except: pass
" 2>/dev/null)
    fi
    if [ -z "$THEHIVE_PASSWORD" ]; then
        THEHIVE_PASSWORD=$(python3 -c "
import yaml
try:
    with open('hawk-scanner/connection.yml') as f:
        c = yaml.safe_load(f)
    print(c.get('notify',{}).get('channels',{}).get('thehive',{}).get('password',''))
except: pass
" 2>/dev/null)
    fi
fi

ALERT_COUNT=0
SCAN_COUNT=0
CASE_COUNT=0
CASES_DELETED=0

echo ""
echo "========================================="
echo "  Poirot DSPM - Reset Completo"
echo "========================================="
echo ""

# 1. Limpiar base de datos SQLite
echo "[1/3] Limpiando base de datos de alertas..."
if [ -f "$DB_PATH" ]; then
    ALERT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0")
    echo "  Alertas encontradas: $ALERT_COUNT"
    sqlite3 "$DB_PATH" "DELETE FROM alerts;" 2>/dev/null || true
    sqlite3 "$DB_PATH" "DELETE FROM sqlite_sequence WHERE name='alerts';" 2>/dev/null || true
    # También limpiar case_status si existe
    sqlite3 "$DB_PATH" "DELETE FROM case_status;" 2>/dev/null || true
    sqlite3 "$DB_PATH" "DELETE FROM sqlite_sequence WHERE name='case_status';" 2>/dev/null || true
    # Limpiar historial de scans
    SCAN_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM scan_history;" 2>/dev/null || echo "0")
    sqlite3 "$DB_PATH" "DELETE FROM scan_history;" 2>/dev/null || true
    sqlite3 "$DB_PATH" "DELETE FROM sqlite_sequence WHERE name='scan_history';" 2>/dev/null || true
    echo "  ✅ Base de datos limpiada (alertas: $ALERT_COUNT, scans: $SCAN_COUNT, case_status)"
else
    echo "  ⚠️  No se encontró: $DB_PATH"
fi

echo ""

# 2. Eliminar casos en TheHive
echo "[2/3] Limpiando casos en TheHive..."

AUTH_METHOD=""

# Intentar login con usuario/password primero (más confiable)
if [ -n "$THEHIVE_USER" ] && [ -n "$THEHIVE_PASSWORD" ]; then
    rm -f "$COOKIE_JAR"
    LOGIN_RES=$(curl -s -c "$COOKIE_JAR" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"$THEHIVE_USER\",\"password\":\"$THEHIVE_PASSWORD\"}" \
        "$THEHIVE_URL/api/v1/login" 2>/dev/null)
    if echo "$LOGIN_RES" | grep -q '"_id"'; then
        echo "  Conectado a TheHive como $THEHIVE_USER"
        AUTH_METHOD="cookie"
    fi
fi

# Si falló el login, intentar con API key
if [ -z "$AUTH_METHOD" ] && [ -n "$THEHIVE_API_KEY" ]; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $THEHIVE_API_KEY" \
        "$THEHIVE_URL/api/v1/status" 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "  Conectado a TheHive con API key"
        AUTH_METHOD="apikey"
    else
        echo "  ⚠️  TheHive no disponible (HTTP $HTTP_CODE) - se omite"
    fi
fi

if [ -z "$AUTH_METHOD" ]; then
    echo "  ⚠️  No hay credenciales configuradas - se omite"
fi

if [ -n "$AUTH_METHOD" ]; then
    # Listar todos los casos según método de auth
    if [ "$AUTH_METHOD" = "cookie" ]; then
        CASES_JSON=$(curl -s -b "$COOKIE_JAR" \
            -H "Content-Type: application/json" \
            -d '{"query":[{"_name":"listCase"}]}' \
            "$THEHIVE_URL/api/v1/query" 2>/dev/null)
    else
        CASES_JSON=$(curl -s \
            -H "Authorization: Bearer $THEHIVE_API_KEY" \
            -H "Content-Type: application/json" \
            -d '{"query":[{"_name":"listCase"}]}' \
            "$THEHIVE_URL/api/v1/query" 2>/dev/null)
    fi
    
    export CASES_JSON

    # Extraer IDs usando Python
    CASE_IDS=$(python3 -c "
import sys, json, os
try:
    cases = json.loads(os.environ.get('CASES_JSON', '[]'))
    if isinstance(cases, list):
        for c in cases:
            if isinstance(c, dict) and '_id' in c:
                print(c['_id'])
except Exception as e:
    sys.stderr.write(f'Error: {e}\\n')
" 2>/dev/null)

    # Contar casos (líneas no vacías)
    CASE_COUNT=0
    if [ -n "$CASE_IDS" ]; then
        CASE_COUNT=$(printf '%s\n' "$CASE_IDS" | grep -v '^$' | wc -l | tr -d '[:space:]')
    fi
    
    echo "  Casos encontrados: $CASE_COUNT"
    
    if [ "$CASE_COUNT" -gt 0 ]; then
        while IFS= read -r CASE_ID; do
            [ -z "$CASE_ID" ] && continue
            if [ "$AUTH_METHOD" = "cookie" ]; then
                DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
                    -X DELETE -b "$COOKIE_JAR" \
                    "$THEHIVE_URL/api/v1/case/$CASE_ID?force=true" 2>/dev/null)
            else
                DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
                    -X DELETE \
                    -H "Authorization: Bearer $THEHIVE_API_KEY" \
                    "$THEHIVE_URL/api/v1/case/$CASE_ID?force=true" 2>/dev/null)
            fi
            if [ "$DEL_CODE" = "200" ] || [ "$DEL_CODE" = "204" ]; then
                CASES_DELETED=$((CASES_DELETED + 1))
            fi
        done <<< "$CASE_IDS"
        echo "  ✅ $CASES_DELETED/$CASE_COUNT casos eliminados"
    else
        echo "  ℹ️  No hay casos para eliminar"
    fi
fi

echo ""

# 3. Limpiar archivos JSON temporales
echo "[3/3] Limpiando archivos temporales..."
if docker ps 2>/dev/null | grep -q hawk-scanner; then
    docker exec hawk-scanner sh -c "rm -f /app/alerts/*.json 2>/dev/null || true" 2>/dev/null || true
    echo "  ✅ Archivos temporales eliminados"
else
    echo "  ℹ️  Contenedor hawk-scanner no activo (opcional)"
fi

echo ""
echo "========================================="
echo "  ✅ Reset completado"
echo "========================================="
echo ""
echo "Resumen:"
echo "  - Alertas DB eliminadas: $ALERT_COUNT"
echo "  - Scans historial eliminados: $SCAN_COUNT"
echo "  - Casos TheHive eliminados: $CASES_DELETED"
echo "  - Tabla case_status: limpiada"
echo "  - Archivos temporales: limpiados"
echo ""

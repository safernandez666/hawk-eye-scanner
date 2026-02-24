#!/bin/bash
# Reset Poirot DSPM: limpia alertas SQLite, casos TheHive y archivos temporales
# Cada paso es independiente: si uno falla, los demás se ejecutan igual
# Uso: ./reset.sh

DB_PATH="${ALERTS_DB_PATH:-hawk-scanner/data/alerts.db}"
THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
THEHIVE_API_KEY="${THEHIVE_API_KEY:-}"

# Si no hay API key en env, intentar leerla de connection.yml
if [ -z "$THEHIVE_API_KEY" ] && command -v python3 &>/dev/null; then
    THEHIVE_API_KEY=$(python3 -c "
import yaml
try:
    with open('hawk-scanner/connection.yml') as f:
        c = yaml.safe_load(f)
    print(c.get('notify',{}).get('channels',{}).get('thehive',{}).get('api_key',''))
except: pass
" 2>/dev/null)
fi

ALERT_COUNT=0
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
    echo "  ✅ Base de datos limpiada"
else
    echo "  ⚠️  No se encontró: $DB_PATH"
fi

echo ""

# 2. Eliminar casos en TheHive
echo "[2/3] Limpiando casos en TheHive..."
if [ -n "$THEHIVE_API_KEY" ]; then
    # Verificar conectividad
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $THEHIVE_API_KEY" \
        "$THEHIVE_URL/api/v1/status" 2>/dev/null)

    if [ "$HTTP_CODE" = "200" ]; then
        echo "  Conectado a TheHive ($THEHIVE_URL)"

        # Listar todos los casos
        CASES_JSON=$(curl -s \
            -H "Authorization: Bearer $THEHIVE_API_KEY" \
            -H "Content-Type: application/json" \
            -d '{"query":[{"_name":"listCase"}]}' \
            "$THEHIVE_URL/api/v1/query" 2>/dev/null)
        
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
                DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
                    -X DELETE \
                    -H "Authorization: Bearer $THEHIVE_API_KEY" \
                    "$THEHIVE_URL/api/v1/case/$CASE_ID?force=true" 2>/dev/null)
                if [ "$DEL_CODE" = "200" ] || [ "$DEL_CODE" = "204" ]; then
                    CASES_DELETED=$((CASES_DELETED + 1))
                fi
            done <<< "$CASE_IDS"
            echo "  ✅ $CASES_DELETED/$CASE_COUNT casos eliminados"
        else
            echo "  ℹ️  No hay casos para eliminar"
        fi
    else
        echo "  ⚠️  TheHive no disponible (HTTP $HTTP_CODE) - se omite"
    fi
else
    echo "  ⚠️  No hay API key configurada - se omite"
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
echo "  - Casos TheHive eliminados: $CASES_DELETED"
echo "  - Archivos temporales: limpiados"
echo ""

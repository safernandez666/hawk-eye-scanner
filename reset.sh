#!/bin/bash
# Reset Poirot DSPM: elimina todos los casos de TheHive y limpia la DB
# Uso: ./reset.sh

THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
THEHIVE_API_KEY="${THEHIVE_API_KEY:-FEdjJZ0rxWGZoXsIPOAdVmuOivmgo3h9}"
DB_PATH="${ALERTS_DB_PATH:-hawk-scanner/data/alerts.db}"
COUNT=0
ALERT_COUNT=0
DELETED=0

echo "========================================="
echo "  Poirot DSPM - Reset Completo"
echo "========================================="
echo ""
echo "TheHive URL: $THEHIVE_URL"
echo ""

# 1. Verificar conexión
echo "[0/3] Verificando conexión con TheHive..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${THEHIVE_URL}/api/v1/status" \
    -H "Authorization: Bearer ${THEHIVE_API_KEY}" 2>/dev/null || echo "000")

if [ "$STATUS" != "200" ]; then
    echo "  ❌ No se pudo conectar a TheHive (HTTP $STATUS)"
    echo ""
    echo "  Verificando si TheHive está corriendo..."
    docker ps | grep thehive || echo "  El contenedor 'thehive' no está corriendo"
    exit 1
fi
echo "  ✅ Conectado a TheHive"
echo ""

# 2. Obtener y eliminar casos
echo "[1/3] Buscando casos en TheHive..."

# Guardar respuesta en archivo temporal para evitar problemas de bash con JSON grande
TMPFILE=$(mktemp)
curl -s -X POST "${THEHIVE_URL}/api/v1/query" \
    -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"query":[{"_name":"listCase"}]}' \
    -o "$TMPFILE" 2>/dev/null

# Contar y extraer IDs con Python (one-liner, sin problemas de quoting)
COUNT=$(python3 -c 'import sys,json;d=json.load(open(sys.argv[1]));print(len(d) if isinstance(d,list) else 0)' "$TMPFILE" 2>/dev/null || echo "0")

echo "  Encontrados: $COUNT casos"

if [ "$COUNT" -gt 0 ]; then
    echo ""
    echo "  Eliminando casos..."

    # Extraer IDs con Python y eliminar uno por uno
    python3 -c 'import sys,json;d=json.load(open(sys.argv[1]));[print(c["_id"]) for c in d if "_id" in c]' "$TMPFILE" 2>/dev/null | \
    while read -r CASE_ID; do
        if [ -n "$CASE_ID" ]; then
            HTTP_CODE=$(curl -s -X DELETE "${THEHIVE_URL}/api/v1/case/${CASE_ID}?force=true" \
                -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
                -w "%{http_code}" -o /dev/null 2>/dev/null)

            if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
                echo "    ✅ Eliminado: $CASE_ID"
            elif [ "$HTTP_CODE" = "404" ]; then
                echo "    ⚠️  No encontrado: $CASE_ID"
            else
                echo "    ❌ Error $HTTP_CODE: $CASE_ID"
            fi
        fi
    done

    echo ""

    # Verificar que se eliminaron
    echo "  Verificando eliminación..."
    REMAINING=$(curl -s -X POST "${THEHIVE_URL}/api/v1/query" \
        -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"query":[{"_name":"listCase"}]}' 2>/dev/null | \
        python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d) if isinstance(d,list) else "?")' 2>/dev/null || echo "?")
    echo "  Casos restantes: $REMAINING"
else
    echo "  ℹ️  No hay casos para eliminar"
fi

rm -f "$TMPFILE"

echo ""

# 3. Limpiar base de datos SQLite
echo "[2/3] Limpiando base de datos de alertas..."
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

# 4. Limpiar archivos JSON temporales
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
echo "  - Casos TheHive eliminados: $COUNT"
echo "  - Alertas DB eliminadas: $ALERT_COUNT"
echo ""

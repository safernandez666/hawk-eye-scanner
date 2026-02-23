#!/bin/bash
# Reset Poirot DSPM: limpia la base de datos SQLite y archivos temporales
# NOTA: Los casos de TheHive NO se eliminan
# Uso: ./reset.sh

DB_PATH="${ALERTS_DB_PATH:-hawk-scanner/data/alerts.db}"
ALERT_COUNT=0

echo "========================================="
echo "  Poirot DSPM - Reset (Sin TheHive)"
echo "========================================="
echo ""
echo "⚠️  Los casos en TheHive se mantienen intactos"
echo ""

# 1. Limpiar base de datos SQLite
echo "[1/2] Limpiando base de datos de alertas..."
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

# 2. Limpiar archivos JSON temporales
echo "[2/2] Limpiando archivos temporales..."
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
echo "  - Casos TheHive: preservados (no modificados)"
echo ""
echo "El próximo scan creará nuevas alertas en la DB"
echo "y casos nuevos en TheHive (si hay hallazgos críticos)"
echo ""

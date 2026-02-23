#!/bin/bash

# Script para iniciar el stack de desarrollo completo
# Backend Flask en :5001 + Dashboard Next.js en :3000

set -e

echo "🚀 Iniciando Hawk-Eye DSPM Development Stack..."

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Función para limpiar procesos al salir
cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Deteniendo servicios...${NC}"
    if [ -n "$FLASK_PID" ]; then
        kill $FLASK_PID 2>/dev/null || true
    fi
    if [ -n "$NEXT_PID" ]; then
        kill $NEXT_PID 2>/dev/null || true
    fi
    echo -e "${GREEN}✅ Servicios detenidos${NC}"
    exit 0
}

# Capturar señales de salida
trap cleanup SIGINT SIGTERM EXIT

# Matar procesos previos si existen
echo -e "${YELLOW}Limpiando procesos previos...${NC}"
pkill -f "dev.py" 2>/dev/null || true
sleep 2

# Verificar que el puerto 5001 esté libre
if lsof -Pi :5001 -sTCP:LISTEN >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️ Puerto 5001 ocupado. Liberando...${NC}"
    lsof -ti :5001 | xargs kill -9 2>/dev/null || true
    sleep 2
fi

# Verificar que el puerto 3000 esté libre
if lsof -Pi :3000 -sTCP:LISTEN >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️ Puerto 3000 ocupado. Liberando...${NC}"
    lsof -ti :3000 | xargs kill -9 2>/dev/null || true
    sleep 2
fi

# Iniciar backend Flask
echo -e "${BLUE}🔌 Iniciando Backend Flask en :5001...${NC}"
cd /Users/santiago/Documents/dsmp
python3 dashboard/dev.py > /tmp/flask.log 2>&1 &
FLASK_PID=$!

# Esperar a que Flask esté listo
echo "⏳ Esperando que Flask esté listo..."
for i in {1..30}; do
    if curl -s http://localhost:5001/api/health >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Backend Flask listo${NC}"
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ Timeout esperando Flask${NC}"
        echo "Logs de Flask:"
        tail -20 /tmp/flask.log
        exit 1
    fi
done

# Iniciar frontend Next.js
echo -e "${BLUE}🎨 Iniciando Dashboard Next.js en :3000...${NC}"
cd /Users/santiago/Documents/dsmp/dashboard/frontend-next
npm run dev > /tmp/next.log 2>&1 &
NEXT_PID=$!

# Esperar a que Next.js esté listo
echo "⏳ Esperando que Next.js esté listo..."
for i in {1..60}; do
    if curl -s http://localhost:3000 >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Dashboard Next.js listo${NC}"
        break
    fi
    sleep 1
    if [ $i -eq 60 ]; then
        echo -e "${RED}❌ Timeout esperando Next.js${NC}"
        echo "Logs de Next.js:"
        tail -20 /tmp/next.log
        exit 1
    fi
done

echo ""
echo -e "${GREEN}=================================${NC}"
echo -e "${GREEN}🎉 Stack de desarrollo listo!${NC}"
echo -e "${GREEN}=================================${NC}"
echo ""
echo -e "📊 Dashboard:  ${BLUE}http://localhost:3000${NC}"
echo -e "🔌 API Flask:  ${BLUE}http://localhost:5001${NC}"
echo ""
echo -e "Logs Flask:  tail -f /tmp/flask.log"
echo -e "Logs Next.js: tail -f /tmp/next.log"
echo ""
echo -e "${YELLOW}Presiona Ctrl+C para detener todo${NC}"
echo ""

# Mantener el script corriendo y mostrar logs
wait

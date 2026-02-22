#!/bin/sh

# Iniciar la API en background
cd /app
python api.py &
API_PID=$!

# Iniciar nginx en foreground
nginx -g 'daemon off;' &
NGINX_PID=$!

# Función para manejar señales de terminación
cleanup() {
    echo "Shutting down..."
    kill $API_PID 2>/dev/null
    kill $NGINX_PID 2>/dev/null
    exit 0
}

trap cleanup SIGTERM SIGINT

# Esperar a que cualquiera de los procesos termine
wait $API_PID
wait $NGINX_PID

#!/usr/bin/env python3
"""
Servidor de desarrollo local para el Dashboard Poirot DSPM.
Sirve el frontend estático + API Flask en un solo proceso.
Conecta a los servicios Docker (MySQL, S3, TheHive) via localhost.

Uso:
    python dashboard/dev.py

Requiere:
    pip install flask flask-cors pyyaml requests
"""

import os
import sys

# Paths locales (relativo al root del proyecto)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault('ALERTS_DB_PATH', os.path.join(PROJECT_ROOT, 'hawk-scanner', 'data', 'alerts.db'))
os.environ.setdefault('FINGERPRINT_PATH', os.path.join(PROJECT_ROOT, 'hawk-scanner', 'fingerprint.yml'))
os.environ.setdefault('CONNECTION_PATH', os.path.join(PROJECT_ROOT, 'hawk-scanner', 'connection.yml'))
os.environ.setdefault('THEHIVE_URL', 'http://localhost:9000')
os.environ.setdefault('THEHIVE_API_KEY', 'cyj8nR1aydTRN3ONoeJhIjRbYI9YYLix')

# Agregar el directorio api/ al path para importar api.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api'))

from api import app

# Servir frontend estático desde Flask
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), 'frontend')


@app.route('/')
def serve_index():
    return app.send_static_file('index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return app.send_static_file(filename)


app.static_folder = FRONTEND_DIR
app.static_url_path = ''

if __name__ == '__main__':
    print(f"\n  Poirot DSPM - Desarrollo Local")
    print(f"  ================================")
    print(f"  Frontend: {FRONTEND_DIR}")
    print(f"  DB:       {os.environ['ALERTS_DB_PATH']}")
    print(f"  TheHive:  {os.environ['THEHIVE_URL']}")
    print(f"  ================================")
    port = int(os.environ.get('PORT', 5001))
    print(f"  Abrir: http://localhost:{port}\n")
    app.run(host='0.0.0.0', port=port, debug=True)

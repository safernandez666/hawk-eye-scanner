#!/usr/bin/env python3
"""
Servidor de desarrollo - Solo API Flask (puerto 5001)
El frontend Next.js se sirve via 'npm run dev' (puerto 3000)

Uso:
    Terminal 1: python dashboard/dev.py
    Terminal 2: cd dashboard/frontend-next && npm run dev

    Abrir: http://localhost:3000

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    print(f"\n  Poirot DSPM - API Development Server")
    print(f"  =====================================")
    print(f"  API:      http://localhost:{port}/api")
    print(f"  DB:       {os.environ['ALERTS_DB_PATH']}")
    print(f"  TheHive:  {os.environ['THEHIVE_URL']}")
    print(f"  =====================================")
    print(f"  Para el frontend Next.js:")
    print(f"    cd dashboard/frontend-next && npm run dev")
    print(f"  Abrir: http://localhost:3000\n")
    app.run(host='0.0.0.0', port=port, debug=True)

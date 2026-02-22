#!/usr/bin/env python3
"""
API REST para el Dashboard DSPM
Expone datos de la base de SQLite de hawk-scanner
"""

import sqlite3
import io
import csv
import json
import socket
import subprocess
import yaml
import requests
from datetime import datetime
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# Path a la base de datos de hawk-scanner
DB_PATH = os.environ.get('ALERTS_DB_PATH', '/app/data/alerts.db')

# Paths a archivos de configuración
FINGERPRINT_PATH = os.environ.get('FINGERPRINT_PATH', '/app/config/fingerprint.yml')
CONNECTION_PATH = os.environ.get('CONNECTION_PATH', '/app/config/connection.yml')

# TheHive config
THEHIVE_URL = os.environ.get('THEHIVE_URL', 'http://thehive:9000')
THEHIVE_API_KEY = os.environ.get('THEHIVE_API_KEY', '')

# Mapa de severidad por patrón (replica severity_classifier.py)
SEVERITY_MAP = {
    "Credit Card - Visa": "CRITICAL",
    "Credit Card - Mastercard": "CRITICAL",
    "Credit Card - American Express": "CRITICAL",
    "Credit Card - Discover": "CRITICAL",
    "AWS Secret Key": "CRITICAL",
    "Private Key": "CRITICAL",
    "Social Security Number (SSN)": "HIGH",
    "AWS Access Key": "HIGH",
    "Generic Password": "HIGH",
    "API Key": "HIGH",
    "JWT Token": "HIGH",
    "URL with Credentials": "HIGH",
    "Email Address": "MEDIUM",
    "Phone Number - US": "MEDIUM",
    "Phone Number - International": "MEDIUM",
    "IP Address - Private": "MEDIUM",
    "IBAN": "MEDIUM",
    "Bitcoin Address": "LOW",
}


def get_db_connection():
    """Obtiene conexión a la base de datos"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint de health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'db_available': os.path.exists(DB_PATH)
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Obtiene estadísticas generales del dashboard"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total de alertas
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]
        
        # Por severidad
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM alerts 
            WHERE status IN ('NEW', 'REOPENED', 'SENT')
            GROUP BY severity
        ''')
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Por estado
        cursor.execute('''
            SELECT status, COUNT(*) as count 
            FROM alerts 
            GROUP BY status
        ''')
        by_status = {row['status']: row['count'] for row in cursor.fetchall()}
        
        # Críticas pendientes
        cursor.execute('''
            SELECT COUNT(*) FROM alerts
            WHERE severity IN ('CRITICAL', 'HIGH')
            AND status IN ('NEW', 'REOPENED', 'SENT')
            AND (thehive_status IS NULL OR thehive_status IN ('New', 'InProgress'))
        ''')
        critical_pending = cursor.fetchone()[0]
        
        # Por fuente de datos
        cursor.execute('''
            SELECT data_source, COUNT(*) as count 
            FROM alerts 
            GROUP BY data_source
        ''')
        by_source = {row['data_source']: row['count'] for row in cursor.fetchall()}
        
        # Re-aperturas
        cursor.execute('''
            SELECT COUNT(*), SUM(reopen_count) FROM alerts WHERE reopen_count > 0
        ''')
        reopen_data = cursor.fetchone()
        
        # Casos en TheHive
        cursor.execute('''
            SELECT thehive_status, COUNT(*) as count 
            FROM alerts 
            WHERE thehive_case_id IS NOT NULL
            GROUP BY thehive_status
        ''')
        thehive_stats = {row['thehive_status'] or 'Unknown': row['count'] for row in cursor.fetchall()}
        
        conn.close()
        
        return jsonify({
            'total_alerts': total,
            'by_severity': by_severity,
            'by_status': by_status,
            'by_source': by_source,
            'critical_pending': critical_pending,
            'reopened_alerts': reopen_data[0] or 0,
            'total_reopens': reopen_data[1] or 0,
            'thehive_stats': thehive_stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Obtiene lista de alertas con filtros opcionales"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Parámetros de query
        severity = request.args.get('severity')
        status = request.args.get('status')
        data_source = request.args.get('source')
        limit = request.args.get('limit', 100, type=int)
        
        # Construir query dinámicamente
        where_clauses = []
        params = []
        
        if severity:
            where_clauses.append('severity = ?')
            params.append(severity)
        if status:
            where_clauses.append('status = ?')
            params.append(status)
        if data_source:
            where_clauses.append('data_source = ?')
            params.append(data_source)
        
        query = 'SELECT * FROM alerts'
        if where_clauses:
            query += ' WHERE ' + ' AND '.join(where_clauses)
        query += ' ORDER BY first_seen DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        alerts = []
        for row in rows:
            alert = {
                'id': row['id'],
                'alert_hash': row['alert_hash'],
                'pattern_name': row['pattern_name'],
                'data_source': row['data_source'],
                'location': row['location'],
                'severity': row['severity'],
                'status': row['status'],
                'first_seen': row['first_seen'],
                'last_seen': row['last_seen'],
                'count': row['count'],
                'thehive_case_id': row['thehive_case_id'],
                'thehive_status': row['thehive_status'],
                'reopen_count': row['reopen_count'],
                'notes': row['notes']
            }
            alerts.append(alert)
        
        conn.close()
        
        return jsonify({
            'alerts': alerts,
            'count': len(alerts),
            'filters': {
                'severity': severity,
                'status': status,
                'source': data_source
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_hash>', methods=['GET'])
def get_alert_detail(alert_hash):
    """Obtiene detalle de una alerta específica"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM alerts WHERE alert_hash = ?', (alert_hash,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'Alert not found'}), 404
        
        alert = {
            'id': row['id'],
            'alert_hash': row['alert_hash'],
            'pattern_name': row['pattern_name'],
            'data_source': row['data_source'],
            'location': row['location'],
            'severity': row['severity'],
            'status': row['status'],
            'first_seen': row['first_seen'],
            'last_seen': row['last_seen'],
            'count': row['count'],
            'thehive_case_id': row['thehive_case_id'],
            'thehive_status': row['thehive_status'],
            'reopen_count': row['reopen_count'],
            'notes': row['notes']
        }
        
        conn.close()
        
        return jsonify(alert)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/patterns', methods=['GET'])
def get_patterns_summary():
    """Obtiene resumen de patrones detectados"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                pattern_name,
                severity,
                COUNT(*) as count,
                SUM(CASE WHEN status = 'NEW' THEN 1 ELSE 0 END) as new_count
            FROM alerts
            GROUP BY pattern_name, severity
            ORDER BY count DESC
        ''')
        
        patterns = []
        for row in cursor.fetchall():
            patterns.append({
                'pattern_name': row['pattern_name'],
                'severity': row['severity'],
                'total_count': row['count'],
                'new_count': row['new_count']
            })
        
        conn.close()
        
        return jsonify({
            'patterns': patterns,
            'total_patterns': len(patterns)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    """Obtiene timeline de detecciones por día"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        days = request.args.get('days', 30, type=int)
        
        cursor.execute('''
            SELECT 
                date(first_seen) as date,
                severity,
                COUNT(*) as count
            FROM alerts
            WHERE first_seen >= date('now', ?)
            GROUP BY date(first_seen), severity
            ORDER BY date
        ''', (f'-{days} days',))
        
        timeline = {}
        for row in cursor.fetchall():
            date = row['date']
            if date not in timeline:
                timeline[date] = {}
            timeline[date][row['severity']] = row['count']
        
        conn.close()
        
        return jsonify({
            'timeline': timeline,
            'days': days
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# CONFIG ENDPOINTS (patterns & sources)
# ==========================================

def read_yaml(path):
    """Lee un archivo YAML y retorna su contenido"""
    with open(path, 'r') as f:
        return yaml.safe_load(f) or {}


def write_yaml(path, data):
    """Escribe datos a un archivo YAML"""
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


@app.route('/api/config/patterns', methods=['GET'])
def get_config_patterns():
    """Lista patrones configurados en fingerprint.yml"""
    try:
        patterns = read_yaml(FINGERPRINT_PATH)
        result = []
        for name, regex in patterns.items():
            result.append({
                'name': name,
                'regex': regex,
                'severity': SEVERITY_MAP.get(name, 'MEDIUM')
            })
        return jsonify({'patterns': result, 'total': len(result)})
    except FileNotFoundError:
        return jsonify({'patterns': [], 'total': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/patterns', methods=['POST'])
def add_config_pattern():
    """Agrega un patrón a fingerprint.yml"""
    try:
        data = request.get_json()
        name = (data.get('name') or '').strip()
        regex = (data.get('regex') or '').strip()

        if not name or not regex:
            return jsonify({'error': 'name y regex son requeridos'}), 400

        patterns = read_yaml(FINGERPRINT_PATH)
        if name in patterns:
            return jsonify({'error': f'El patrón "{name}" ya existe'}), 409

        patterns[name] = regex
        write_yaml(FINGERPRINT_PATH, patterns)
        return jsonify({'message': f'Patrón "{name}" agregado', 'severity': SEVERITY_MAP.get(name, 'MEDIUM')}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/patterns/<name>', methods=['PUT'])
def edit_config_pattern(name):
    """Edita la regex de un patrón en fingerprint.yml"""
    try:
        data = request.get_json()
        regex = (data.get('regex') or '').strip()
        if not regex:
            return jsonify({'error': 'regex es requerido'}), 400

        patterns = read_yaml(FINGERPRINT_PATH)
        if name not in patterns:
            return jsonify({'error': f'Patrón "{name}" no encontrado'}), 404

        patterns[name] = regex
        write_yaml(FINGERPRINT_PATH, patterns)
        return jsonify({'message': f'Patrón "{name}" actualizado'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/patterns/<name>', methods=['DELETE'])
def delete_config_pattern(name):
    """Elimina un patrón de fingerprint.yml"""
    try:
        patterns = read_yaml(FINGERPRINT_PATH)
        if name not in patterns:
            return jsonify({'error': f'Patrón "{name}" no encontrado'}), 404

        del patterns[name]
        write_yaml(FINGERPRINT_PATH, patterns)
        return jsonify({'message': f'Patrón "{name}" eliminado'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/sources', methods=['GET'])
def get_config_sources():
    """Lista fuentes configuradas en connection.yml"""
    try:
        config = read_yaml(CONNECTION_PATH)
        sources_config = config.get('sources', {})
        result = []
        for source_type, instances in sources_config.items():
            if not isinstance(instances, dict):
                continue
            for instance_name, instance_config in instances.items():
                result.append({
                    'type': source_type,
                    'name': instance_name,
                    'config': instance_config
                })
        return jsonify({'sources': result, 'total': len(result)})
    except FileNotFoundError:
        return jsonify({'sources': [], 'total': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/sources', methods=['POST'])
def add_config_source():
    """Agrega una fuente a connection.yml"""
    try:
        data = request.get_json()
        source_type = (data.get('type') or '').strip()
        name = (data.get('name') or '').strip()
        source_config = data.get('config', {})

        if not source_type or not name:
            return jsonify({'error': 'type y name son requeridos'}), 400

        # Validar campos requeridos según tipo
        required = {
            'mysql': ['host', 'port', 'user', 'password', 'database'],
            's3': ['access_key', 'secret_key', 'bucket_name', 'endpoint_url'],
        }
        if source_type in required:
            missing = [f for f in required[source_type] if not source_config.get(f)]
            if missing:
                return jsonify({'error': f'Campos requeridos faltantes: {", ".join(missing)}'}), 400

        config = read_yaml(CONNECTION_PATH)
        if 'sources' not in config:
            config['sources'] = {}
        if source_type not in config['sources']:
            config['sources'][source_type] = {}
        if name in config['sources'][source_type]:
            return jsonify({'error': f'La fuente "{source_type}/{name}" ya existe'}), 409

        config['sources'][source_type][name] = source_config
        write_yaml(CONNECTION_PATH, config)
        return jsonify({'message': f'Fuente "{source_type}/{name}" agregada'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/sources/<source_type>/<name>', methods=['DELETE'])
def delete_config_source(source_type, name):
    """Elimina una fuente de connection.yml"""
    try:
        config = read_yaml(CONNECTION_PATH)
        sources = config.get('sources', {})

        if source_type not in sources or name not in sources.get(source_type, {}):
            return jsonify({'error': f'Fuente "{source_type}/{name}" no encontrada'}), 404

        del sources[source_type][name]
        if not sources[source_type]:
            del sources[source_type]
        write_yaml(CONNECTION_PATH, config)
        return jsonify({'message': f'Fuente "{source_type}/{name}" eliminada'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# THEHIVE PROXY ENDPOINTS
# ==========================================

def thehive_headers():
    return {'Authorization': f'Bearer {THEHIVE_API_KEY}', 'Content-Type': 'application/json'}


@app.route('/api/thehive/status', methods=['GET'])
def thehive_status():
    """Verifica conectividad con TheHive"""
    try:
        r = requests.get(f'{THEHIVE_URL}/api/v1/status', headers=thehive_headers(), timeout=5)
        return jsonify({'status': 'connected', 'code': r.status_code})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/thehive/cases', methods=['GET'])
def thehive_cases():
    """Lista casos de TheHive"""
    try:
        payload = {"query": [{"_name": "listCase"}]}
        r = requests.post(f'{THEHIVE_URL}/api/v1/query', headers=thehive_headers(), json=payload, timeout=10)
        if r.status_code != 200:
            return jsonify({'error': f'TheHive responded {r.status_code}', 'detail': r.text}), 502
        return jsonify({'cases': r.json()})
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/api/thehive/cases/<case_id>', methods=['GET'])
def thehive_case_detail(case_id):
    """Detalle de un caso de TheHive"""
    try:
        r = requests.get(f'{THEHIVE_URL}/api/v1/case/{case_id}', headers=thehive_headers(), timeout=10)
        if r.status_code != 200:
            return jsonify({'error': f'TheHive responded {r.status_code}'}), 502
        return jsonify(r.json())
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/api/thehive/sync', methods=['POST'])
def thehive_sync():
    """Envia alertas CRITICAL/HIGH sin caso a TheHive y actualiza la DB"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT alert_hash, pattern_name, data_source, location, severity
            FROM alerts
            WHERE severity IN ('CRITICAL', 'HIGH')
            AND (thehive_case_id IS NULL OR thehive_case_id = '')
        ''')
        pending = cursor.fetchall()

        if not pending:
            conn.close()
            return jsonify({'message': 'No hay alertas pendientes de enviar', 'created': 0})

        headers = thehive_headers()
        created = 0
        errors = 0

        for row in pending:
            alert_hash = row['alert_hash']
            title = f"[{row['data_source'].upper()}] {row['pattern_name']}"
            description = (
                f"# Hallazgo de Datos Sensibles\n\n"
                f"**Detectado por:** Hawk-Eye Scanner\n"
                f"**Hash:** `{alert_hash}`\n\n"
                f"## Detalles\n\n"
                f"- **Patron:** {row['pattern_name']}\n"
                f"- **Severidad:** {row['severity']}\n"
                f"- **Fuente:** {row['data_source']}\n"
                f"- **Ubicacion:** {row['location']}\n"
            )

            severity_val = 3 if row['severity'] == 'CRITICAL' else 2
            case_data = {
                'title': title,
                'description': description,
                'severity': severity_val,
                'tlp': 2,
                'pap': 2,
                'tags': [row['data_source'], row['severity'].lower(), 'hawk-scanner', 'poirot-sync'],
                'flag': row['severity'] == 'CRITICAL'
            }

            try:
                r = requests.post(
                    f'{THEHIVE_URL}/api/v1/case',
                    headers=headers, json=case_data, timeout=10
                )
                if r.status_code in [200, 201]:
                    case_id = r.json().get('_id', '')
                    cursor.execute(
                        'UPDATE alerts SET thehive_case_id = ?, thehive_status = ? WHERE alert_hash = ?',
                        (case_id, 'New', alert_hash)
                    )
                    created += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

        conn.commit()
        conn.close()

        return jsonify({
            'message': f'{created} casos creados en TheHive',
            'created': created,
            'errors': errors
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# SCANNER TRIGGER ENDPOINTS
# ==========================================

@app.route('/api/scanner/run', methods=['POST'])
def scanner_run():
    """Ejecuta el scanner manualmente via docker exec"""
    try:
        result = subprocess.run(
            ['docker', 'exec', 'hawk-scanner', 'python3', '/app/run_hawk_scanner.py'],
            capture_output=True, text=True, timeout=300
        )
        return jsonify({
            'status': 'completed' if result.returncode == 0 else 'error',
            'returncode': result.returncode,
            'stdout': result.stdout[-2000:] if result.stdout else '',
            'stderr': result.stderr[-2000:] if result.stderr else ''
        })
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'timeout', 'message': 'El escaneo excedio el tiempo limite (5min)'}), 504
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/scanner/status', methods=['GET'])
def scanner_status():
    """Verifica si el scanner container esta corriendo"""
    try:
        result = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Running}}', 'hawk-scanner'],
            capture_output=True, text=True, timeout=10
        )
        running = result.stdout.strip() == 'true'
        return jsonify({'running': running})
    except Exception as e:
        return jsonify({'running': False, 'error': str(e)})


# ==========================================
# ALERTS EXPORT ENDPOINTS
# ==========================================

@app.route('/api/alerts/export', methods=['GET'])
def export_alerts():
    """Exporta alertas en CSV o JSON"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Mismos filtros que /api/alerts
        severity = request.args.get('severity')
        status = request.args.get('status')
        data_source = request.args.get('source')

        where_clauses = []
        params = []
        if severity:
            where_clauses.append('severity = ?')
            params.append(severity)
        if status:
            where_clauses.append('status = ?')
            params.append(status)
        if data_source:
            where_clauses.append('data_source = ?')
            params.append(data_source)

        query = 'SELECT * FROM alerts'
        if where_clauses:
            query += ' WHERE ' + ' AND '.join(where_clauses)
        query += ' ORDER BY first_seen DESC'

        cursor.execute(query, params)
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        alerts = [dict(zip(columns, row)) for row in rows]
        conn.close()

        fmt = request.args.get('format', 'csv')

        if fmt == 'json':
            return Response(
                json.dumps(alerts, indent=2, default=str),
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=alerts.json'}
            )

        # CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        writer.writerows(alerts)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=alerts.csv'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# SOURCES HEALTH CHECK
# ==========================================

def resolve_host(host):
    """Intenta resolver hostname; si falla (Docker hostname fuera de Docker), usa localhost"""
    try:
        socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return host
    except socket.gaierror:
        return 'localhost'


def resolve_endpoint(url):
    """Reemplaza hostname no resolvible en una URL con localhost"""
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(url)
    resolved = resolve_host(parsed.hostname)
    if resolved != parsed.hostname:
        netloc = f'{resolved}:{parsed.port}' if parsed.port else resolved
        return urlunparse(parsed._replace(netloc=netloc))
    return url


@app.route('/api/config/sources/health', methods=['GET'])
def sources_health():
    """Verifica conectividad de cada fuente configurada"""
    try:
        config = read_yaml(CONNECTION_PATH)
        sources_config = config.get('sources', {})
        results = []

        for source_type, instances in sources_config.items():
            if not isinstance(instances, dict):
                continue
            for name, cfg in instances.items():
                entry = {'type': source_type, 'name': name, 'status': 'error', 'message': ''}
                try:
                    if source_type == 'mysql':
                        host = resolve_host(cfg.get('host', 'localhost'))
                        port = int(cfg.get('port', 3306))
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(3)
                        s.connect((host, port))
                        s.close()
                        entry['status'] = 'connected'
                        entry['message'] = f'{host}:{port} accesible'
                    elif source_type == 's3':
                        endpoint = cfg.get('endpoint_url', '')
                        if endpoint:
                            endpoint = resolve_endpoint(endpoint)
                            r = requests.get(endpoint, timeout=3)
                            entry['status'] = 'connected'
                            entry['message'] = f'Endpoint responde ({r.status_code})'
                        else:
                            entry['message'] = 'No endpoint_url configurado'
                    else:
                        entry['message'] = 'Tipo no soportado para health check'
                except Exception as e:
                    entry['message'] = str(e)
                results.append(entry)

        return jsonify({'sources': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Crear directorio de datos si no existe
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    # Iniciar con gunicorn en producción, flask dev en desarrollo
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    if debug_mode:
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        # Gunicorn se encargará en producción
        app.run(host='0.0.0.0', port=5000, debug=False)

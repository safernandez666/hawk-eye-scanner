#!/usr/bin/env python3
"""
API REST para el Dashboard DSPM
Expone datos de la base de SQLite de hawk-scanner
"""

import sqlite3
import io
import csv
import json
import shutil
import socket
import subprocess
import threading
import yaml
import requests
from datetime import datetime
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
import os

app = Flask(__name__)
CORS(app)

scheduler = BackgroundScheduler()
scheduler.start()

# Path a la base de datos de hawk-scanner
DB_PATH = os.environ.get('ALERTS_DB_PATH', '/app/data/alerts.db')

# Paths a archivos de configuración
FINGERPRINT_PATH = os.environ.get('FINGERPRINT_PATH', '/app/config/fingerprint.yml')
CONNECTION_PATH = os.environ.get('CONNECTION_PATH', '/app/config/connection.yml')

# TheHive config
_THEHIVE_ENABLED_ENV = os.environ.get('THEHIVE_ENABLED', '').lower()


def _is_thehive_enabled():
    """Verifica si TheHive esta habilitado: connection.yml tiene prioridad sobre env var"""
    try:
        config = read_yaml(CONNECTION_PATH)
        channel_enabled = config.get('notify', {}).get('channels', {}).get('thehive', {}).get('enabled')
        # Si está definido en connection.yml, usar ese valor
        if channel_enabled is not None:
            return bool(channel_enabled)
    except Exception:
        pass
    
    # Fallback a env var si no está definido en connection.yml
    if _THEHIVE_ENABLED_ENV == 'true':
        return True
    if _THEHIVE_ENABLED_ENV == 'false':
        return False
    
    return False


def _get_thehive_config():
    """Lee URL y API key de TheHive: primero env vars, luego connection.yml"""
    url = os.environ.get('THEHIVE_URL', '')
    api_key = os.environ.get('THEHIVE_API_KEY', '')
    if not url or not api_key:
        try:
            config = read_yaml(CONNECTION_PATH)
            thehive_cfg = config.get('notify', {}).get('channels', {}).get('thehive', {})
            if not url:
                url = thehive_cfg.get('url', 'http://thehive:9000')
            if not api_key:
                api_key = thehive_cfg.get('api_key', '')
        except Exception:
            pass
    if not url:
        url = 'http://thehive:9000'
    return url, api_key

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
        
        # Calcular Data Risk Score
        risk_score = (
            by_severity.get('CRITICAL', 0) * 10 +
            by_severity.get('HIGH', 0) * 5 +
            by_severity.get('MEDIUM', 0) * 2 +
            by_severity.get('LOW', 0) * 1
        )
        
        # Calcular Remediation Rate (cerrados / total)
        closed_count = by_status.get('CLOSED', 0)
        remediation_rate = (closed_count / total * 100) if total > 0 else 0
        
        # Calcular MTTR (tiempo promedio de resolución)
        cursor.execute('''
            SELECT AVG(
                CASE 
                    WHEN first_seen != last_seen 
                    THEN (julianday(last_seen) - julianday(first_seen)) * 24 * 60
                    ELSE NULL 
                END
            ) as avg_resolution_minutes
            FROM alerts 
            WHERE status = 'CLOSED'
        ''')
        mttr_result = cursor.fetchone()
        mttr_hours = (mttr_result[0] or 0) / 60 if mttr_result[0] else 0
        
        # Top patterns (tipos de datos sensibles) - TODOS los patrones
        cursor.execute('''
            SELECT pattern_name, COUNT(*) as count 
            FROM alerts 
            GROUP BY pattern_name 
            ORDER BY count DESC 
        ''')
        top_patterns = [{'name': row['pattern_name'], 'count': row['count']} for row in cursor.fetchall()]
        
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
            'risk_score': risk_score,
            'remediation_rate': round(remediation_rate, 1),
            'mttr_hours': round(mttr_hours, 1),
            'top_patterns': top_patterns,
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
        latest = request.args.get('latest', 'false').lower() == 'true'
        
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
        # Si latest=true, ordenar por last_seen para ver alertas del último scan
        order_by = 'last_seen DESC' if latest else 'first_seen DESC'
        query += f' ORDER BY {order_by} LIMIT ?'
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
                'source': data_source,
                'latest': latest
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
        for name, config in patterns.items():
            # Soportar formato nuevo (dict) y viejo (string)
            if isinstance(config, dict):
                result.append({
                    'name': name,
                    'regex': config.get('regex', ''),
                    'category': config.get('category', 'OTHER'),
                    'severity': config.get('severity', 'MEDIUM')
                })
            else:
                # Formato viejo (solo regex como string)
                result.append({
                    'name': name,
                    'regex': config,
                    'category': 'OTHER',
                    'severity': SEVERITY_MAP.get(name, 'MEDIUM')
                })
        return jsonify({'patterns': result, 'total': len(result)})
    except FileNotFoundError:
        return jsonify({'patterns': [], 'total': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Categorías válidas
VALID_CATEGORIES = ['PCI', 'CREDENTIALS', 'PII', 'INFRA', 'CRYPTO', 'OTHER']

@app.route('/api/config/patterns', methods=['POST'])
def add_config_pattern():
    """Agrega un patrón a fingerprint.yml"""
    try:
        data = request.get_json()
        name = (data.get('name') or '').strip()
        regex = (data.get('regex') or '').strip()
        severity = (data.get('severity') or 'MEDIUM').strip()
        category = (data.get('category') or 'OTHER').strip()

        if not name or not regex:
            return jsonify({'error': 'name y regex son requeridos'}), 400

        # Validar severidad
        if severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity = 'MEDIUM'
        
        # Validar categoría
        if category not in VALID_CATEGORIES:
            category = 'OTHER'

        patterns = read_yaml(FINGERPRINT_PATH)
        if name in patterns:
            return jsonify({'error': f'El patrón "{name}" ya existe'}), 409

        # Guardar en formato nuevo (dict con regex, category, severity)
        patterns[name] = {
            'regex': regex,
            'category': category,
            'severity': severity
        }
        write_yaml(FINGERPRINT_PATH, patterns)
        
        return jsonify({
            'message': f'Patrón "{name}" agregado', 
            'severity': severity,
            'category': category
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/patterns/<name>', methods=['PUT'])
def edit_config_pattern(name):
    """Edita la regex, categoría y severidad de un patrón en fingerprint.yml"""
    try:
        data = request.get_json()
        regex = (data.get('regex') or '').strip()
        severity = (data.get('severity') or '').strip()
        category = (data.get('category') or '').strip()
        
        if not regex:
            return jsonify({'error': 'regex es requerido'}), 400

        patterns = read_yaml(FINGERPRINT_PATH)
        if name not in patterns:
            return jsonify({'error': f'Patrón "{name}" no encontrado'}), 404

        # Obtener configuración actual
        current = patterns[name]
        if isinstance(current, dict):
            current_severity = current.get('severity', 'MEDIUM')
            current_category = current.get('category', 'OTHER')
        else:
            current_severity = SEVERITY_MAP.get(name, 'MEDIUM')
            current_category = 'OTHER'

        # Validar y actualizar
        final_severity = severity if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else current_severity
        final_category = category if category in VALID_CATEGORIES else current_category

        # Guardar en formato nuevo
        patterns[name] = {
            'regex': regex,
            'category': final_category,
            'severity': final_severity
        }
        write_yaml(FINGERPRINT_PATH, patterns)
        
        return jsonify({
            'message': f'Patrón "{name}" actualizado',
            'severity': final_severity,
            'category': final_category
        })
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
            'gdrive': ['credentials_file'],
            'onedrive': ['client_id', 'client_secret', 'tenant_id', 'refresh_token'],
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
# FEATURE FLAGS
# ==========================================

@app.route('/api/config/features', methods=['GET'])
def get_features():
    """Retorna feature flags para el frontend"""
    return jsonify({'thehive_enabled': _is_thehive_enabled()})


# ==========================================
# THEHIVE PROXY ENDPOINTS
# ==========================================

def thehive_headers():
    _, api_key = _get_thehive_config()
    return {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}


@app.route('/api/thehive/status', methods=['GET'])
def thehive_status():
    """Verifica conectividad con TheHive"""
    if not _is_thehive_enabled():
        return jsonify({'status': 'disabled'})
    
    url, api_key = _get_thehive_config()
    
    # Validar que la API key esté configurada
    if not api_key or api_key.strip() == '' or api_key == 'YOUR_THEHIVE_API_KEY':
        return jsonify({'status': 'missing_credentials', 'message': 'API key no configurada'})
    
    try:
        r = requests.get(f'{url}/api/v1/status', headers=thehive_headers(), timeout=5)
        if r.status_code == 200:
            return jsonify({'status': 'connected', 'code': r.status_code})
        elif r.status_code == 401:
            return jsonify({'status': 'unauthorized', 'message': 'API key invalida'})
        else:
            return jsonify({'status': 'error', 'code': r.status_code, 'message': 'Error de conexion'})
    except requests.exceptions.ConnectionError:
        return jsonify({'status': 'unreachable', 'message': 'No se puede conectar a TheHive'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/thehive/cases', methods=['GET'])
def thehive_cases():
    """Lista casos de TheHive"""
    if not _is_thehive_enabled():
        return jsonify({'cases': []})
    try:
        url, _ = _get_thehive_config()
        payload = {"query": [{"_name": "listCase"}]}
        r = requests.post(f'{url}/api/v1/query', headers=thehive_headers(), json=payload, timeout=10)
        if r.status_code != 200:
            return jsonify({'error': f'TheHive responded {r.status_code}', 'detail': r.text}), 502
        return jsonify({'cases': r.json()})
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/api/thehive/cases/<case_id>', methods=['GET'])
def thehive_case_detail(case_id):
    """Detalle de un caso de TheHive"""
    if not _is_thehive_enabled():
        return jsonify({'error': 'TheHive is disabled'}), 404
    try:
        url, _ = _get_thehive_config()
        r = requests.get(f'{url}/api/v1/case/{case_id}', headers=thehive_headers(), timeout=10)
        if r.status_code != 200:
            return jsonify({'error': f'TheHive responded {r.status_code}'}), 502
        return jsonify(r.json())
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/api/thehive/sync', methods=['POST'])
def thehive_sync():
    """Envia todas las alertas sin caso a TheHive y actualiza la DB"""
    if not _is_thehive_enabled():
        return jsonify({'created': 0, 'message': 'TheHive disabled'})
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT alert_hash, pattern_name, data_source, location, severity
            FROM alerts
            WHERE (thehive_case_id IS NULL OR thehive_case_id = '')
        ''')
        pending = cursor.fetchall()

        if not pending:
            conn.close()
            return jsonify({'message': 'No hay alertas pendientes de enviar', 'created': 0})

        url, _ = _get_thehive_config()
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
                    f'{url}/api/v1/case',
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

# Estado global del scan (en memoria, un solo scan a la vez)
_scan_state = {
    'running': False,
    'started_at': None,
    'result': None,   # {status, returncode, stdout, stderr, message}
    'logs': [],        # líneas de log en tiempo real
}
_scan_lock = threading.Lock()


def _run_scan_background(docker_path, sources=None):
    """Ejecuta el scan en background y actualiza _scan_state"""
    global _scan_state
    try:
        cmd = [docker_path, 'exec', 'hawk-scanner', 'python3', '-u', '/app/run_hawk_scanner.py']
        if sources:
            cmd.extend(['--sources', ','.join(sources)])
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        # Leer línea por línea para logs en tiempo real
        for line in process.stdout:
            stripped = line.rstrip('\n')
            if stripped:
                with _scan_lock:
                    _scan_state['logs'].append(stripped)

        process.wait(timeout=300)

        with _scan_lock:
            _scan_state['running'] = False
            _scan_state['result'] = {
                'status': 'completed' if process.returncode == 0 else 'error',
                'returncode': process.returncode,
            }
    except subprocess.TimeoutExpired:
        process.kill()
        with _scan_lock:
            _scan_state['running'] = False
            _scan_state['result'] = {'status': 'timeout', 'message': 'Excedio el tiempo limite (5min)'}
    except Exception as e:
        with _scan_lock:
            _scan_state['running'] = False
            _scan_state['result'] = {'status': 'error', 'message': str(e)}


def _scheduled_scan():
    """Triggered by APScheduler - runs scan if not already running."""
    global _scan_state
    with _scan_lock:
        if _scan_state['running']:
            print("[scheduler] Scan already running, skipping")
            return
    docker_path = shutil.which('docker')
    if not docker_path:
        print("[scheduler] Docker not found")
        return
    
    # Leer fuentes configuradas del scheduler
    sources = None
    try:
        config = read_yaml(CONNECTION_PATH)
        sched = config.get('scheduler', {})
        sources = sched.get('sources', [])
        if not sources:
            sources = None  # Escanea todas si no hay fuentes configuradas
    except Exception:
        sources = None
    
    with _scan_lock:
        _scan_state['running'] = True
        _scan_state['started_at'] = datetime.now().isoformat()
        _scan_state['result'] = None
        _scan_state['logs'] = []
    thread = threading.Thread(target=_run_scan_background, args=(docker_path, sources), daemon=True)
    thread.start()
    source_msg = f"fuentes: {sources}" if sources else "todas las fuentes"
    print(f"[scheduler] Scan triggered at {datetime.now().isoformat()} ({source_msg})")


def _init_scheduler():
    """Read scheduler config from connection.yml and set up APScheduler job."""
    try:
        config = read_yaml(CONNECTION_PATH)
    except Exception:
        return
    sched_cfg = config.get('scheduler', {})
    if sched_cfg.get('enabled') and sched_cfg.get('interval_hours'):
        hours = sched_cfg['interval_hours']
        scheduler.add_job(_scheduled_scan, 'interval', hours=hours, id='scan_job', replace_existing=True)
        print(f"[scheduler] Scan scheduled every {hours}h")


@app.route('/api/scanner/run', methods=['POST'])
def scanner_run():
    """Inicia el scanner en background y retorna inmediatamente"""
    global _scan_state

    with _scan_lock:
        if _scan_state['running']:
            return jsonify({'status': 'already_running', 'message': 'Ya hay un escaneo en curso'}), 409

    docker_path = shutil.which('docker')  # shutil imported at top
    if not docker_path:
        return jsonify({
            'status': 'error',
            'message': 'Docker no encontrado en el PATH.'
        }), 500

    # Leer fuentes seleccionadas del body
    data = request.get_json() or {}
    sources = data.get('sources')  # Lista de fuentes, ej: ['mysql', 's3']

    with _scan_lock:
        _scan_state['running'] = True
        _scan_state['started_at'] = datetime.now().isoformat()
        _scan_state['result'] = None
        _scan_state['logs'] = []

    thread = threading.Thread(target=_run_scan_background, args=(docker_path, sources), daemon=True)
    thread.start()

    source_msg = f" ({', '.join(sources)})" if sources else ""
    return jsonify({'status': 'started', 'message': f'Escaneo iniciado{source_msg}'})


@app.route('/api/scanner/status', methods=['GET'])
def scanner_status():
    """Retorna estado del scan: running, logs nuevos, resultado"""
    # Parámetro para paginación de logs (el frontend pide desde línea N)
    since = request.args.get('since', 0, type=int)

    with _scan_lock:
        new_logs = _scan_state['logs'][since:]
        return jsonify({
            'running': _scan_state['running'],
            'started_at': _scan_state['started_at'],
            'result': _scan_state['result'],
            'logs': new_logs,
            'total_logs': len(_scan_state['logs']),
        })


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
                        bucket = cfg.get('bucket_name', '')
                        if endpoint and bucket:
                            endpoint = resolve_endpoint(endpoint)
                            # Check bucket specifically, not just endpoint
                            bucket_url = f"{endpoint.rstrip('/')}/{bucket}"
                            r = requests.get(bucket_url, timeout=3)
                            if r.status_code == 200:
                                entry['status'] = 'connected'
                                entry['message'] = f'Bucket "{bucket}" accesible'
                            elif r.status_code == 404:
                                entry['status'] = 'error'
                                entry['message'] = f'Bucket "{bucket}" no existe'
                            else:
                                entry['status'] = 'connected'
                                entry['message'] = f'Bucket responde ({r.status_code})'
                        elif not endpoint:
                            entry['message'] = 'No endpoint_url configurado'
                        else:
                            entry['message'] = 'No bucket_name configurado'
                    elif source_type in ('gdrive', 'onedrive'):
                        entry['status'] = 'configured'
                        entry['message'] = 'Configurado (verificacion requiere autenticacion)'
                    else:
                        entry['message'] = 'Tipo no soportado para health check'
                except Exception as e:
                    entry['message'] = str(e)
                results.append(entry)

        return jsonify({'sources': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# NOTIFICATION CONFIG ENDPOINTS
# ==========================================

@app.route('/api/config/notifications', methods=['GET'])
def get_notifications_config():
    """Lista canales de notificacion configurados en connection.yml"""
    try:
        config = read_yaml(CONNECTION_PATH)
        channels = config.get('notify', {}).get('channels', {})
        return jsonify({'channels': channels})
    except FileNotFoundError:
        return jsonify({'channels': {}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/notifications/<channel>', methods=['PUT'])
def update_notification_channel(channel):
    """Actualiza la configuracion de un canal de notificacion"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Body JSON requerido'}), 400

        valid_channels = ['thehive', 'smtp', 'slack', 'teams', 'webhook']
        if channel not in valid_channels:
            return jsonify({'error': f'Canal invalido. Validos: {valid_channels}'}), 400

        config = read_yaml(CONNECTION_PATH)
        if 'notify' not in config:
            config['notify'] = {}
        if 'channels' not in config['notify']:
            config['notify']['channels'] = {}

        config['notify']['channels'][channel] = data
        write_yaml(CONNECTION_PATH, config)
        return jsonify({'message': f'Canal "{channel}" actualizado'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/notifications/<channel>/test', methods=['POST'])
def test_notification_channel(channel):
    """Envia una notificacion de prueba por el canal indicado (async para SMTP+Ollama)"""
    try:
        valid_channels = ['thehive', 'smtp', 'slack', 'teams', 'webhook']
        if channel not in valid_channels:
            return jsonify({'error': f'Canal invalido. Validos: {valid_channels}'}), 400

        # Leer config actual o usar body del request
        data = request.get_json()
        if data:
            channel_config = data
        else:
            config = read_yaml(CONNECTION_PATH)
            channel_config = config.get('notify', {}).get('channels', {}).get(channel, {})

        if not channel_config:
            return jsonify({'error': f'Canal "{channel}" no configurado'}), 404

        from notification_manager import NotificationManager
        nm = NotificationManager(config_path=None)

        # Run in background thread so the UI doesn't block
        def _send():
            try:
                result = nm.send_test(channel, channel_config)
                print(f"[test-notification] {channel}: {result.get('status')}")
            except Exception as e:
                print(f"[test-notification] {channel}: error - {e}")

        thread = threading.Thread(target=_send, daemon=True)
        thread.start()
        return jsonify({'status': 'sent', 'message': 'Enviando en background...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# OLLAMA CONFIG ENDPOINTS
# ==========================================

@app.route('/api/ollama/models', methods=['POST'])
def get_ollama_models():
    """Fetch available models from an Ollama server."""
    try:
        data = request.get_json() or {}
        url = data.get('url', 'http://host.docker.internal:11434')
        resp = requests.get(f"{url}/api/tags", timeout=10)
        resp.raise_for_status()
        models = resp.json().get('models', [])
        return jsonify({'models': [m['name'] for m in models]})
    except Exception as e:
        return jsonify({'error': str(e), 'models': []}), 502


@app.route('/api/config/ollama', methods=['GET'])
def get_ollama_config():
    """Read Ollama config from connection.yml"""
    try:
        config = read_yaml(CONNECTION_PATH)
        ollama = config.get('notify', {}).get('ollama', {})
        return jsonify(ollama)
    except FileNotFoundError:
        return jsonify({})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/ollama', methods=['PUT'])
def update_ollama_config():
    """Update Ollama config in connection.yml"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Body JSON requerido'}), 400

        config = read_yaml(CONNECTION_PATH)
        if 'notify' not in config:
            config['notify'] = {}
        config['notify']['ollama'] = data
        write_yaml(CONNECTION_PATH, config)
        return jsonify({'message': 'Ollama config updated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# SCHEDULER JOBS ENDPOINTS (Multi-job support)
# ==========================================

import uuid

def _run_scheduled_scan_with_sources(sources=None):
    """Wrapper para ejecutar scan con fuentes específicas"""
    docker_path = shutil.which('docker')
    if not docker_path:
        print("[scheduler] Docker not found")
        return
    with _scan_lock:
        _scan_state['running'] = True
        _scan_state['started_at'] = datetime.now().isoformat()
        _scan_state['result'] = None
        _scan_state['logs'] = []
    thread = threading.Thread(target=_run_scan_background, args=(docker_path, sources), daemon=True)
    thread.start()
    source_msg = f"fuentes: {sources}" if sources else "todas las fuentes"
    print(f"[scheduler] Scan triggered ({source_msg})")


@app.route('/api/scheduler/jobs', methods=['GET'])
def get_scheduler_jobs():
    """Get all scheduled jobs"""
    try:
        config = read_yaml(CONNECTION_PATH)
        jobs = config.get('scheduler_jobs', [])
        
        # Enrich with next run time from APScheduler
        enriched_jobs = []
        for job in jobs:
            job_id = job.get('id')
            sched_job = scheduler.get_job(job_id)
            enriched_job = job.copy()
            if sched_job and sched_job.next_run_time:
                enriched_job['next_run'] = sched_job.next_run_time.isoformat()
            else:
                enriched_job['next_run'] = None
            enriched_jobs.append(enriched_job)
        
        return jsonify({'jobs': enriched_jobs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scheduler/jobs', methods=['POST'])
def create_scheduler_job():
    """Create a new scheduled job"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Body JSON requerido'}), 400

        job_id = f"job_{uuid.uuid4().hex[:8]}"
        name = data.get('name', 'Tarea programada')
        schedule_type = data.get('schedule_type', 'interval')
        sources = data.get('sources', [])

        job_config = {
            'id': job_id,
            'name': name,
            'schedule_type': schedule_type,
            'sources': sources,
            'enabled': True,
        }

        # Configure APScheduler job
        if schedule_type == 'cron':
            cron_expression = data.get('cron_expression', '0 9 * * 1')
            parts = cron_expression.split()
            if len(parts) != 5:
                return jsonify({'error': 'Formato cron invalido. Usa: min hora dia mes dia_semana'}), 400
            
            job_config['cron_expression'] = cron_expression
            scheduler.add_job(
                _run_scheduled_scan_with_sources, 'cron',
                minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4],
                id=job_id, replace_existing=True, args=[sources]
            )
        else:
            interval_hours = data.get('interval_hours', 24)
            try:
                interval_hours = float(interval_hours)
                if interval_hours < 0.5:
                    interval_hours = 0.5
            except (TypeError, ValueError):
                interval_hours = 24
            
            job_config['interval_hours'] = interval_hours
            scheduler.add_job(
                _run_scheduled_scan_with_sources, 'interval',
                hours=interval_hours, id=job_id, replace_existing=True, args=[sources]
            )

        # Save to config
        config = read_yaml(CONNECTION_PATH)
        if 'scheduler_jobs' not in config:
            config['scheduler_jobs'] = []
        config['scheduler_jobs'].append(job_config)
        write_yaml(CONNECTION_PATH, config)

        return jsonify({'message': 'Tarea creada', 'job': job_config})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scheduler/jobs/<job_id>', methods=['DELETE'])
def delete_scheduler_job(job_id):
    """Delete a specific scheduled job"""
    try:
        # Remove from APScheduler
        try:
            scheduler.remove_job(job_id)
        except Exception:
            pass
        
        # Remove from config
        config = read_yaml(CONNECTION_PATH)
        if 'scheduler_jobs' in config:
            config['scheduler_jobs'] = [j for j in config['scheduler_jobs'] if j.get('id') != job_id]
            write_yaml(CONNECTION_PATH, config)
        
        return jsonify({'message': 'Tarea eliminada'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scheduler/jobs/<job_id>', methods=['PUT'])
def update_scheduler_job(job_id):
    """Update a scheduled job"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Body JSON requerido'}), 400

        config = read_yaml(CONNECTION_PATH)
        jobs = config.get('scheduler_jobs', [])
        job = next((j for j in jobs if j.get('id') == job_id), None)
        
        if not job:
            return jsonify({'error': 'Tarea no encontrada'}), 404

        # Update fields
        if 'name' in data:
            job['name'] = data['name']
        if 'enabled' in data:
            job['enabled'] = data['enabled']

        write_yaml(CONNECTION_PATH, config)
        return jsonify({'message': 'Tarea actualizada', 'job': job})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate-regex', methods=['POST'])
def validate_regex():
    """Valida una expresión regular contra texto de prueba"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Body JSON requerido'}), 400
        
        regex = data.get('regex', '').strip()
        test_text = data.get('test_text', '')
        
        if not regex:
            return jsonify({'error': 'Regex es requerido'}), 400
        
        import re
        
        # Intentar compilar la regex
        try:
            pattern = re.compile(regex)
        except re.error as e:
            return jsonify({
                'valid': False,
                'error': f'Regex inválida: {str(e)}',
                'matches': []
            })
        
        # Buscar matches
        matches = []
        for match in pattern.finditer(test_text):
            matches.append({
                'start': match.start(),
                'end': match.end(),
                'value': match.group(),
                'groups': match.groups()
            })
        
        return jsonify({
            'valid': True,
            'matches': matches,
            'match_count': len(matches)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Initialize scheduler from config on app startup
_init_scheduler()


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

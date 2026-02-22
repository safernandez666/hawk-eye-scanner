#!/usr/bin/env python3
"""
API REST para el Dashboard DSPM
Expone datos de la base de SQLite de hawk-scanner
"""

import sqlite3
import json
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# Path a la base de datos de hawk-scanner
DB_PATH = os.environ.get('ALERTS_DB_PATH', '/app/data/alerts.db')


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

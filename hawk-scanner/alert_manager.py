#!/usr/bin/env python3
"""Sistema de tracking y deduplicación de alertas"""

import sqlite3
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional

class AlertManager:
    def __init__(self, db_path='/app/data/alerts.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Inicializa la base de datos SQLite con schema completo"""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_hash TEXT UNIQUE NOT NULL,
                    pattern_name TEXT NOT NULL,
                    data_source TEXT NOT NULL,
                    location TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT DEFAULT 'NEW',
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    count INTEGER DEFAULT 1,
                    notes TEXT,
                    thehive_case_id TEXT,
                    thehive_status TEXT,
                    reopen_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Índices para búsquedas rápidas
            c.execute('CREATE INDEX IF NOT EXISTS idx_alert_hash ON alerts(alert_hash)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_status ON alerts(status)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_thehive_case ON alerts(thehive_case_id)')

            conn.commit()

        print(f"✅ Base de datos inicializada: {self.db_path}")

    def _generate_hash(self, finding: Dict) -> str:
        """Genera un hash único para el hallazgo"""
        key_parts = [
            finding.get('data_source', ''),
            finding.get('pattern_name', ''),
            finding.get('database', '') + finding.get('table', '') + finding.get('column', ''),
            finding.get('bucket', '') + finding.get('file_path', '')
        ]

        key_string = '|'.join(str(p) for p in key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    def process_finding(self, finding: Dict) -> Dict:
        """Procesa un hallazgo: lo registra o actualiza si ya existe"""
        alert_hash = self._generate_hash(finding)

        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()

            # Verificar si ya existe
            c.execute('''
                SELECT id, count, thehive_status, reopen_count
                FROM alerts
                WHERE alert_hash = ?
            ''', (alert_hash,))
            existing = c.fetchone()

            if existing:
                alert_id, current_count, thehive_status, reopen_count = existing

                # 🔥 NUEVA LÓGICA: Si fue resuelto y aparece de nuevo → RE-ABRIR
                resolved_states = ['TruePositive', 'Resolved', 'Closed']

                if thehive_status in resolved_states:
                    # Ya fue resuelto pero vuelve a aparecer → RE-OCURRENCIA
                    print(f"   🔄 Re-ocurrencia detectada: {finding.get('pattern_name')}")

                    c.execute('''
                        UPDATE alerts
                        SET count = count + 1,
                            last_seen = CURRENT_TIMESTAMP,
                            status = 'REOPENED',
                            thehive_status = NULL,
                            thehive_case_id = NULL,
                            reopen_count = reopen_count + 1
                        WHERE alert_hash = ?
                    ''', (alert_hash,))
                    conn.commit()

                    return {
                        'is_new': True,  # ✅ Tratar como NUEVO para crear caso
                        'is_reopen': True,
                        'alert_hash': alert_hash,
                        'count': current_count + 1,
                        'reopen_count': reopen_count + 1,
                        'finding': finding
                    }
                else:
                    # Ya existe y sigue pendiente → Incrementar contador
                    c.execute('''
                        UPDATE alerts
                        SET count = count + 1,
                            last_seen = CURRENT_TIMESTAMP
                        WHERE alert_hash = ?
                    ''', (alert_hash,))
                    conn.commit()

                    return {
                        'is_new': False,
                        'is_reopen': False,
                        'alert_hash': alert_hash,
                        'count': current_count + 1,
                        'finding': finding
                    }
            else:
                # Nuevo: insertar
                location = self._get_location(finding)

                c.execute('''
                    INSERT INTO alerts
                    (alert_hash, pattern_name, data_source, location, severity, status)
                    VALUES (?, ?, ?, ?, ?, 'NEW')
                ''', (
                    alert_hash,
                    finding.get('pattern_name', 'Unknown'),
                    finding.get('data_source', 'unknown'),
                    location,
                    finding.get('severity', 'LOW')
                ))
                conn.commit()

                return {
                    'is_new': True,
                    'is_reopen': False,
                    'alert_hash': alert_hash,
                    'count': 1,
                    'finding': finding
                }

    def _get_location(self, finding: Dict) -> str:
        """Extrae la ubicación del hallazgo"""
        if finding.get('data_source') == 'mysql':
            return f"{finding.get('database')}.{finding.get('table')}.{finding.get('column')}"
        elif finding.get('data_source') == 's3':
            return f"{finding.get('bucket')}/{finding.get('file_path')}"
        return 'unknown'

    def update_thehive_case(self, alert_hash: str, case_id: str, status: str = 'New'):
        """Actualiza el caso de TheHive asociado a una alerta"""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE alerts
                SET thehive_case_id = ?,
                    thehive_status = ?,
                    status = 'SENT',
                    last_seen = CURRENT_TIMESTAMP
                WHERE alert_hash = ?
            ''', (case_id, status, alert_hash))
            conn.commit()

    def get_critical_with_cases(self):
        """Obtiene alertas críticas con sus case IDs de TheHive"""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                SELECT
                    alert_hash,
                    pattern_name,
                    severity,
                    thehive_case_id,
                    thehive_status,
                    location
                FROM alerts
                WHERE severity IN ('CRITICAL', 'HIGH')
                AND status IN ('NEW', 'SENT', 'REOPENED')
                ORDER BY first_seen DESC
            ''')
            return c.fetchall()

    def get_stats(self):
        """Obtiene estadísticas de alertas"""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()

            # Total de alertas
            c.execute('SELECT COUNT(*) FROM alerts')
            total = c.fetchone()[0]

            # Por severidad (solo activas)
            c.execute('''
                SELECT severity, COUNT(*)
                FROM alerts
                WHERE status IN ('NEW', 'REOPENED', 'SENT')
                GROUP BY severity
            ''')
            by_severity = dict(c.fetchall())

            # Críticas pendientes (no resueltas en TheHive)
            c.execute('''
                SELECT COUNT(*)
                FROM alerts
                WHERE severity IN ('CRITICAL', 'HIGH')
                AND status IN ('NEW', 'REOPENED', 'SENT')
                AND (thehive_status IS NULL
                     OR thehive_status IN ('New', 'InProgress'))
            ''')
            critical_pending = c.fetchone()[0]

            # Casos en TheHive por estado
            c.execute('''
                SELECT thehive_status, COUNT(*)
                FROM alerts
                WHERE thehive_case_id IS NOT NULL
                GROUP BY thehive_status
            ''')
            thehive_stats = dict(c.fetchall())

            # Re-aperturas
            c.execute('''
                SELECT COUNT(*), SUM(reopen_count)
                FROM alerts
                WHERE status = 'REOPENED'
            ''')
            reopen_data = c.fetchone()
            reopened_alerts = reopen_data[0] if reopen_data else 0
            total_reopens = reopen_data[1] if reopen_data and reopen_data[1] else 0

            return {
                'total': total,
                'by_severity': by_severity,
                'critical_pending': critical_pending,
                'thehive_stats': thehive_stats,
                'reopened_alerts': reopened_alerts,
                'total_reopens': total_reopens
            }

    def mark_as_false_positive(self, alert_hash: str, notes: str = ''):
        """Marca una alerta como falso positivo"""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE alerts
                SET status = 'FALSE_POSITIVE',
                    notes = ?
                WHERE alert_hash = ?
            ''', (notes, alert_hash))
            conn.commit()

    def mark_as_acknowledged(self, alert_hash: str, notes: str = ''):
        """Marca una alerta como reconocida"""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE alerts
                SET status = 'ACKNOWLEDGED',
                    notes = ?
                WHERE alert_hash = ?
            ''', (notes, alert_hash))
            conn.commit()

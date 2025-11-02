#!/usr/bin/env python3
"""Alert Manager - Sistema de tracking con SQLite"""

import hashlib
import sqlite3
from datetime import datetime
from typing import List, Dict

class AlertManager:
    def __init__(self, db_path="data/alerts.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Crea la base de datos si no existe"""
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_hash TEXT UNIQUE NOT NULL,
                pattern_name TEXT,
                data_source TEXT,
                location TEXT,
                severity TEXT,
                status TEXT DEFAULT 'NEW',
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                count INTEGER DEFAULT 1,
                notes TEXT
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_hash ON alerts(alert_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON alerts(status)')
        
        conn.commit()
        conn.close()
        print(f"✅ Base de datos inicializada: {self.db_path}")
    
    def generate_hash(self, finding: Dict) -> str:
        """Genera hash único del hallazgo"""
        key_fields = [
            finding.get('data_source', ''),
            finding.get('pattern_name', ''),
            finding.get('database', '') + finding.get('table', '') + finding.get('column', ''),
            finding.get('bucket', '') + finding.get('file_path', ''),
        ]
        key_string = '|'.join(key_fields)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]
    
    def get_location(self, finding: Dict) -> str:
        """Extrae ubicación legible"""
        if finding.get('data_source') == 'mysql':
            return f"{finding.get('database')}.{finding.get('table')}.{finding.get('column')}"
        elif finding.get('data_source') == 's3':
            return f"s3://{finding.get('bucket')}/{finding.get('file_path')}"
        return "unknown"
    
    def process_finding(self, finding: Dict) -> Dict:
        """Procesa un hallazgo y lo guarda o actualiza"""
        alert_hash = self.generate_hash(finding)
        location = self.get_location(finding)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # ¿Ya existe?
        cursor.execute('SELECT id, status, count FROM alerts WHERE alert_hash = ?', (alert_hash,))
        existing = cursor.fetchone()
        
        now = datetime.now()
        
        if existing:
            # Actualizar
            alert_id, status, count = existing
            cursor.execute('''
                UPDATE alerts 
                SET last_seen = ?, count = count + 1
                WHERE alert_hash = ?
            ''', (now, alert_hash))
            is_new = False
        else:
            # Crear nuevo
            cursor.execute('''
                INSERT INTO alerts (
                    alert_hash, pattern_name, data_source, location,
                    severity, status, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_hash,
                finding.get('pattern_name'),
                finding.get('data_source'),
                location,
                finding.get('severity'),
                'NEW',
                now,
                now
            ))
            alert_id = cursor.lastrowid
            is_new = True
            status = 'NEW'
        
        conn.commit()
        conn.close()
        
        return {
            'alert_id': alert_id,
            'alert_hash': alert_hash,
            'is_new': is_new,
            'status': status,
            'finding': finding
        }
    
    def get_stats(self) -> Dict:
        """Estadísticas de alertas"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT status, COUNT(*) FROM alerts GROUP BY status')
        by_status = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE status = "NEW" AND severity = "CRITICAL"')
        critical_pending = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'by_status': by_status,
            'critical_pending': critical_pending
        }

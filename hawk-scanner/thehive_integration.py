#!/usr/bin/env python3
"""Integración con TheHive para auto-creación de casos"""

import requests
import json
from datetime import datetime
from typing import Dict, List

class TheHiveIntegration:
    def __init__(self, url="http://thehive:9000", api_key=None):
        self.url = url.rstrip('/')
        self.api_key = api_key or "J6ZvFWfmvrIfcyaCUgYlgHo7vg9mIOE+"  # ← CAMBIAR ESTO
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
    
    def create_case(self, finding: Dict, alert_hash: str) -> str:
        """Crea un caso en TheHive desde un hallazgo"""
        
        # Mapear severidad a TLP
        severity_map = {
            'CRITICAL': {'severity': 3, 'tlp': 3, 'pap': 3},  # RED
            'HIGH': {'severity': 3, 'tlp': 2, 'pap': 2},      # AMBER
            'MEDIUM': {'severity': 2, 'tlp': 1, 'pap': 1},    # GREEN
            'LOW': {'severity': 1, 'tlp': 0, 'pap': 0}        # WHITE
        }
        
        severity_info = severity_map.get(finding.get('severity', 'LOW'), severity_map['LOW'])
        
        # Construir título
        title = f"[{finding['data_source'].upper()}] {finding['pattern_name']}"
        
        # Construir descripción
        description = self._build_description(finding)
        
        # Tags
        tags = [
            finding['data_source'],
            finding['pattern_name'].replace(' ', '-').lower(),
            finding.get('severity', 'unknown'),
            'hawk-scanner',
            'automated'
        ]
        
        # Payload del caso
        case_data = {
            'title': title,
            'description': description,
            'severity': severity_info['severity'],
            'tlp': severity_info['tlp'],
            'pap': severity_info['pap'],
            'tags': tags,
            'flag': finding.get('severity') == 'CRITICAL',  # Flag si es crítico
        }
        
        try:
            response = requests.post(
                f'{self.url}/api/v1/case',
                headers=self.headers,
                json=case_data,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                case = response.json()
                case_id = case.get('_id')
                
                # Agregar observables
                self._add_observables(case_id, finding)
                
                print(f"   ✅ Caso creado en TheHive: {case_id}")
                return case_id
            else:
                print(f"   ❌ Error creando caso: {response.status_code}")
                print(f"      {response.text}")
                return None
                
        except Exception as e:
            print(f"   ❌ Excepción al crear caso: {e}")
            return None
    
    def _build_description(self, finding: Dict) -> str:
        """Construye descripción detallada del caso"""
        desc = f"# Hallazgo de Datos Sensibles\n\n"
        desc += f"**Detectado por:** Hawk-Eye Scanner\n"
        desc += f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        desc += f"## Detalles del Hallazgo\n\n"
        desc += f"- **Patrón:** {finding['pattern_name']}\n"
        desc += f"- **Severidad:** {finding.get('severity', 'Unknown')}\n"
        desc += f"- **Fuente:** {finding['data_source']}\n\n"
        
        if finding['data_source'] == 'mysql':
            desc += f"### Base de Datos MySQL\n\n"
            desc += f"- **Base de datos:** {finding.get('database')}\n"
            desc += f"- **Tabla:** {finding.get('table')}\n"
            desc += f"- **Columna:** {finding.get('column')}\n\n"
        elif finding['data_source'] == 's3':
            desc += f"### Amazon S3\n\n"
            desc += f"- **Bucket:** {finding.get('bucket')}\n"
            desc += f"- **Archivo:** {finding.get('file_path')}\n\n"
        
        matches = finding.get('matches', [])
        if matches:
            desc += f"## Matches Detectados ({len(matches)})\n\n"
            desc += "```\n"
            for match in matches[:10]:  # Primeros 10
                desc += f"{match}\n"
            if len(matches) > 10:
                desc += f"... y {len(matches) - 10} más\n"
            desc += "```\n\n"
        
        desc += f"## Acciones Recomendadas\n\n"
        
        if finding.get('severity') == 'CRITICAL':
            desc += "⚠️ **ACCIÓN INMEDIATA REQUERIDA**\n\n"
            desc += "1. Aislar los datos afectados\n"
            desc += "2. Notificar al equipo de seguridad\n"
            desc += "3. Revisar logs de acceso\n"
            desc += "4. Implementar controles de acceso\n"
        else:
            desc += "1. Revisar el hallazgo\n"
            desc += "2. Validar si es un falso positivo\n"
            desc += "3. Aplicar remediación si corresponde\n"
        
        return desc
    
    def _add_observables(self, case_id: str, finding: Dict):
        """Agrega observables (IOCs) al caso"""
        observables = []
        
        # Agregar matches como observables
        matches = finding.get('matches', [])
        pattern_name = finding['pattern_name']
        
        for match in matches[:5]:  # Primeros 5
            observable_type = self._get_observable_type(pattern_name)
            
            observables.append({
                'dataType': observable_type,
                'data': match,
                'tlp': 2,
                'ioc': True,
                'tags': [pattern_name.lower().replace(' ', '-')],
                'message': f'Detectado por Hawk-Scanner en {finding["data_source"]}'
            })
        
        # Enviar observables
        for obs in observables:
            try:
                response = requests.post(
                    f'{self.url}/api/v1/case/{case_id}/observable',
                    headers=self.headers,
                    json=obs,
                    timeout=10
                )
                if response.status_code not in [200, 201]:
                    print(f"   ⚠️  Error agregando observable: {response.status_code}")
            except Exception as e:
                print(f"   ⚠️  Error agregando observable: {e}")
    
    def _get_observable_type(self, pattern_name: str) -> str:
        """Mapea tipo de patrón a tipo de observable en TheHive"""
        mapping = {
            'Credit Card': 'other',
            'SSN': 'other',
            'Email': 'mail',
            'Phone': 'other',
            'AWS': 'other',
            'IP Address': 'ip',
            'URL': 'url',
            'Bitcoin': 'other'
        }
        
        for key, value in mapping.items():
            if key in pattern_name:
                return value
        
        return 'other'
    
    def test_connection(self) -> bool:
        """Prueba la conexión con TheHive"""
        try:
            response = requests.get(
                f'{self.url}/api/v1/status',
                headers=self.headers,
                timeout=5
            )
            return response.status_code == 200
        except:
            return False

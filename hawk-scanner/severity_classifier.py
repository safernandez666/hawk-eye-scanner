#!/usr/bin/env python3
"""
Clasificador de severidad basado en fingerprint.yml
Lee la severidad definida por el usuario en la configuración de patrones
"""

import yaml
import os

# Caché del fingerprint
_fingerprint_severity_map = None

def _load_severity_map():
    """Carga el mapa de severidad desde fingerprint.yml"""
    global _fingerprint_severity_map
    
    if _fingerprint_severity_map is not None:
        return _fingerprint_severity_map
    
    _fingerprint_severity_map = {}
    fingerprint_path = os.environ.get('FINGERPRINT_PATH', '/app/fingerprint.yml')
    
    try:
        with open(fingerprint_path, 'r') as f:
            data = yaml.safe_load(f)
        
        for name, config in data.items():
            if name is None:
                continue
            if isinstance(config, dict) and 'severity' in config:
                _fingerprint_severity_map[name] = config['severity']
    except Exception:
        pass
    
    return _fingerprint_severity_map

def get_severity(pattern_name):
    """
    Retorna la severidad del patrón según fingerprint.yml
    
    Args:
        pattern_name (str): Nombre del patrón detectado
        
    Returns:
        str: Nivel de severidad (CRITICAL, HIGH, MEDIUM, LOW)
    """
    severity_map = _load_severity_map()
    return severity_map.get(pattern_name, 'MEDIUM')

def reclassify_findings(findings):
    """
    Reclasifica la severidad de todos los hallazgos según fingerprint.yml
    
    Args:
        findings (list): Lista de hallazgos a reclasificar
        
    Returns:
        list: Hallazgos con severidad corregida
    """
    for finding in findings:
        pattern = finding.get('pattern_name', '')
        # Guardar severidad original por si se necesita
        finding['severity_original'] = finding.get('severity')
        # Aplicar nueva severidad basada en fingerprint.yml
        finding['severity'] = get_severity(pattern)
    
    return findings

def get_severity_stats(findings):
    """
    Obtiene estadísticas de severidad
    
    Args:
        findings (list): Lista de hallazgos
        
    Returns:
        dict: Conteo por severidad
    """
    from collections import Counter
    return dict(Counter([f.get('severity', 'UNKNOWN') for f in findings]))

def get_critical_findings(findings):
    """
    Filtra solo hallazgos críticos
    
    Args:
        findings (list): Lista de hallazgos
        
    Returns:
        list: Solo hallazgos CRITICAL
    """
    return [f for f in findings if f.get('severity') == 'CRITICAL']

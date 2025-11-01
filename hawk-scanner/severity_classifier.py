#!/usr/bin/env python3
"""
Clasificador de severidad inteligente para Hawk-Eye Scanner
Reclasifica hallazgos basándose en el TIPO de dato, no en la cantidad
"""

# Mapa de severidad por tipo de patrón
SEVERITY_MAP = {
    # CRITICAL - Datos que permiten fraude inmediato o acceso total
    "CRITICAL": [
        "Credit Card - Visa",
        "Credit Card - Mastercard", 
        "Credit Card - American Express",
        "Credit Card - Discover",
        "AWS Secret Key",
        "Private Key",
        "Private Key - RSA",
        "Private Key - DSA",
        "Private Key - EC",
        "Private Key - OPENSSH",
        "Private Key - PGP",
    ],
    
    # HIGH - PII sensible o credenciales de acceso
    "HIGH": [
        "Social Security Number (SSN)",
        "AWS Access Key",
        "Generic Password",
        "API Key",
        "JWT Token",
        "URL with Credentials",
        "GitHub Token",
        "Slack Token",
        "Google API Key",
        "Stripe API Key",
    ],
    
    # MEDIUM - Información que facilita ataques o phishing
    "MEDIUM": [
        "Email Address",
        "Phone Number - US",
        "Phone Number - International",
        "IP Address - Private",
        "IBAN",
    ],
    
    # LOW - Información menos sensible
    "LOW": [
        "Bitcoin Address",
        "Ethereum Address",
    ]
}

def get_severity(pattern_name):
    """
    Retorna la severidad correcta basada en el tipo de patrón
    
    Args:
        pattern_name (str): Nombre del patrón detectado
        
    Returns:
        str: Nivel de severidad (CRITICAL, HIGH, MEDIUM, LOW)
    """
    for severity, patterns in SEVERITY_MAP.items():
        if pattern_name in patterns:
            return severity
    return "MEDIUM"  # Default si no está clasificado

def reclassify_findings(findings):
    """
    Reclasifica la severidad de todos los hallazgos
    
    Args:
        findings (list): Lista de hallazgos a reclasificar
        
    Returns:
        list: Hallazgos con severidad corregida
    """
    for finding in findings:
        pattern = finding.get('pattern_name', '')
        # Guardar severidad original por si se necesita
        finding['severity_original'] = finding.get('severity')
        # Aplicar nueva severidad basada en tipo
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
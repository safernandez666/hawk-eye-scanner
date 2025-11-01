#!/usr/bin/env python3
import subprocess
import json
import os
import sys
from datetime import datetime
from collections import Counter
from severity_classifier import reclassify_findings, get_critical_findings

# Directorios
ALERTS_DIR = "/app/alerts"
RESULTS_DIR = "/app/alerts"

# Crear directorio si no existe
os.makedirs(ALERTS_DIR, exist_ok=True)

# Timestamp para los archivos
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

def run_scan(source_type, output_file):
    """Ejecuta un escaneo y guarda resultados"""
    print(f"🔍 Escaneando {source_type}...")
    cmd = [
        "hawk_scanner",
        source_type,
        "--connection", "connection.yml",
        "--fingerprint", "fingerprint.yml",
        "--json", output_file
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {source_type} completado: {output_file}")
            return True
        else:
            print(f"❌ Error en {source_type}:")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ Excepción en {source_type}: {e}")
        return False

def consolidate_results(mysql_file, s3_file, output_file):
    """Consolida los resultados en un solo archivo"""
    all_results = []
    
    # Cargar MySQL
    if os.path.exists(mysql_file):
        with open(mysql_file, 'r') as f:
            mysql_data = json.load(f)
            # Manejar estructura de diccionario
            if isinstance(mysql_data, dict):
                for key, findings in mysql_data.items():
                    if isinstance(findings, list):
                        all_results.extend(findings)
            elif isinstance(mysql_data, list):
                all_results.extend(mysql_data)
    
    # Cargar S3
    if os.path.exists(s3_file):
        with open(s3_file, 'r') as f:
            s3_data = json.load(f)
            # Manejar estructura de diccionario
            if isinstance(s3_data, dict):
                for key, findings in s3_data.items():
                    if isinstance(findings, list):
                        all_results.extend(findings)
            elif isinstance(s3_data, list):
                all_results.extend(s3_data)
    
    # ✅ RECLASIFICAR SEVERIDAD BASADA EN TIPO DE DATO
    all_results = reclassify_findings(all_results)
    
    # Guardar consolidado
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"📊 Resultados consolidados: {len(all_results)} hallazgos")
    return all_results

def display_findings(results):
    """Muestra los hallazgos en consola de forma legible"""
    if not results:
        print("\n✅ No se detectaron hallazgos de seguridad")
        return
    
    print(f"\n{'='*70}")
    print(f"🔍 HALLAZGOS DETECTADOS")
    print(f"{'='*70}")
    
    # Agrupar por severidad
    by_severity = {}
    for r in results:
        severity = r.get('severity', 'Unknown')
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(r)
    
    # Orden de severidad (nuevo orden con CRITICAL)
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'Unknown']
    severity_icons = {
        'CRITICAL': '🔴',
        'HIGH': '🟠', 
        'MEDIUM': '🟡',
        'LOW': '🟢',
        'Unknown': '⚪'
    }
    
    for severity in severity_order:
        if severity not in by_severity:
            continue
        
        findings = by_severity[severity]
        icon = severity_icons.get(severity, '⚪')
        
        print(f"\n{icon} {severity} - {len(findings)} hallazgos")
        print("-" * 70)
        
        # Mostrar todos los CRITICAL, máximo 5 del resto
        max_display = len(findings) if severity == 'CRITICAL' else min(5, len(findings))
        
        for i, finding in enumerate(findings[:max_display], 1):
            print(f"\n  [{i}] {finding.get('pattern_name', 'Unknown Pattern')}")
            print(f"      Fuente: {finding.get('data_source', 'unknown')}")
            
            # Información específica según la fuente
            if finding.get('data_source') == 'mysql':
                print(f"      Base de datos: {finding.get('database', 'N/A')}")
                print(f"      Tabla: {finding.get('table', 'N/A')}")
                print(f"      Columna: {finding.get('column', 'N/A')}")
            elif finding.get('data_source') == 's3':
                print(f"      Bucket: {finding.get('bucket', 'N/A')}")
                print(f"      Archivo: {finding.get('file_path', 'N/A')}")
            
            # Mostrar matches (limitado)
            matches = finding.get('matches', [])
            if matches:
                match_preview = matches[:3]
                print(f"      Matches: {', '.join(match_preview)}")
                if len(matches) > 3:
                    print(f"      ... y {len(matches) - 3} más")
        
        if len(findings) > max_display:
            print(f"\n  ... y {len(findings) - max_display} hallazgos más de severidad {severity}")

def generate_summary(results, output_file):
    """Genera un resumen consolidado de todos los hallazgos"""
    valid_results = [r for r in results if isinstance(r, dict) and 'pattern_name' in r]
    
    summary = {
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(valid_results),
        "by_severity": dict(Counter([r.get('severity', 'unknown') for r in valid_results])),
        "by_pattern": dict(Counter([r.get('pattern_name', 'unknown') for r in valid_results])),
        "by_source": dict(Counter([r.get('data_source', 'unknown') for r in valid_results])),
        "findings": valid_results
    }
    
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"\n{'='*70}")
    print(f"📈 RESUMEN ESTADÍSTICO")
    print(f"{'='*70}")
    print(f"   📊 Total de hallazgos: {summary['total_findings']}")
    
    print(f"\n   🚨 Por severidad:")
    # Orden específico para mostrar
    severity_display_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    for severity in severity_display_order:
        count = summary['by_severity'].get(severity, 0)
        if count > 0:
            print(f"      {severity}: {count}")
    
    print(f"\n   📁 Por fuente:")
    for source, count in summary['by_source'].items():
        print(f"      {source}: {count}")
    
    print(f"\n   🔍 Top 5 patrones más detectados:")
    top_patterns = sorted(summary['by_pattern'].items(), 
                         key=lambda x: x[1], reverse=True)[:5]
    for pattern, count in top_patterns:
        print(f"      {pattern}: {count}")
    
    # ⚠️ ALERTAS CRÍTICAS
    critical = get_critical_findings(valid_results)
    if critical:
        print(f"\n   ⚠️  ATENCIÓN: {len(critical)} hallazgos CRÍTICOS detectados")
        print(f"      Requieren acción inmediata")
    
    return summary

if __name__ == "__main__":
    print("=" * 70)
    print("🦅 HAWK-EYE SCANNER - Automated Security Scan")
    print("=" * 70)
    
    # Archivos de salida
    mysql_output = f"{RESULTS_DIR}/mysql_{timestamp}.json"
    s3_output = f"{RESULTS_DIR}/s3_{timestamp}.json"
    consolidated_output = f"{RESULTS_DIR}/consolidated_{timestamp}.json"
    summary_output = f"{RESULTS_DIR}/summary_{timestamp}.json"
    latest_output = f"{RESULTS_DIR}/latest.json"
    
    # Ejecutar escaneos
    mysql_success = run_scan("mysql", mysql_output)
    s3_success = run_scan("s3", s3_output)
    
    if mysql_success or s3_success:
        # Consolidar resultados
        results = consolidate_results(mysql_output, s3_output, consolidated_output)
        
        # Mostrar hallazgos en consola
        display_findings(results)
        
        # Generar resumen
        generate_summary(results, summary_output)
        
        # Copiar como "latest" para fácil acceso
        with open(latest_output, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"✅ Escaneo completado exitosamente")
        print(f"📁 Resultados guardados en: {ALERTS_DIR}/")
        print(f"{'='*70}\n")
    else:
        print("\n❌ Escaneo falló")
        exit(1)
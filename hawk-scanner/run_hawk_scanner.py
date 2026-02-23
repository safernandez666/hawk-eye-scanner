#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import json
import os
import sys
import yaml
import re as regex_module
from datetime import datetime
from collections import Counter
from severity_classifier import reclassify_findings, get_critical_findings
from alert_manager import AlertManager
from notification_manager import NotificationManager

ALERTS_DIR = "/app/alerts"
RESULTS_DIR = "/app/alerts"

os.makedirs(ALERTS_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

def prepare_fingerprint_for_scanner(input_file="fingerprint.yml", output_file="/tmp/fingerprint_compat.yml"):
    """Convierte el fingerprint con metadata a formato compatible con hawk_scanner"""
    with open(input_file, 'r') as f:
        data = yaml.safe_load(f)

    compatible_patterns = {}
    for name, config in data.items():
        if isinstance(config, dict) and 'regex' in config:
            compatible_patterns[name] = config['regex']
        elif isinstance(config, str):
            compatible_patterns[name] = config

    with open(output_file, 'w') as f:
        yaml.dump(compatible_patterns, f, default_flow_style=False, allow_unicode=True)

    return output_file


def prepare_connection_for_scanner(input_file="connection.yml", output_file="/tmp/connection_compat.yml"):
    """Extrae solo las fuentes de connection.yml en formato compatible con hawk_scanner"""
    with open(input_file, 'r') as f:
        data = yaml.safe_load(f)

    # hawk_scanner espera un dict con key 'sources' que contiene mysql:, s3:, etc.
    sources = data.get('sources', {})
    if not sources:
        # Si no hay key 'sources', asumir que ya esta en formato plano
        sources = {k: v for k, v in data.items() if k not in ('notify',)}

    # Guardar con wrapper 'sources' como espera hawk_scanner
    output_data = {'sources': sources}
    
    with open(output_file, 'w') as f:
        yaml.dump(output_data, f, default_flow_style=False, allow_unicode=True)

    return output_file


def run_scan(source_type, output_file):
    print(f"🔍 Escaneando {source_type}...")

    # Preparar archivos compatibles con hawk_scanner
    compat_fingerprint = prepare_fingerprint_for_scanner()
    compat_connection = prepare_connection_for_scanner()

    cmd = [
        "hawk_scanner",
        source_type,
        "--connection", compat_connection,
        "--fingerprint", compat_fingerprint,
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
    all_results = []

    if os.path.exists(mysql_file):
        with open(mysql_file, 'r') as f:
            mysql_data = json.load(f)
            if isinstance(mysql_data, dict):
                for key, findings in mysql_data.items():
                    if isinstance(findings, list):
                        all_results.extend(findings)
            elif isinstance(mysql_data, list):
                all_results.extend(mysql_data)

    if os.path.exists(s3_file):
        with open(s3_file, 'r') as f:
            s3_data = json.load(f)
            if isinstance(s3_data, dict):
                for key, findings in s3_data.items():
                    if isinstance(findings, list):
                        all_results.extend(findings)
            elif isinstance(s3_data, list):
                all_results.extend(s3_data)

    all_results = reclassify_findings(all_results)

    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)

    print(f"📊 Resultados consolidados: {len(all_results)} hallazgos")
    return all_results

def display_findings(results):
    """Muestra hallazgos detectados"""
    if not results:
        print("\n✅ No se detectaron hallazgos de seguridad")
        return

    print(f"\n{'='*70}")
    print(f"🔍 HALLAZGOS DETECTADOS")
    print(f"{'='*70}")

    by_severity = {}
    for r in results:
        severity = r.get('severity', 'Unknown')
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(r)

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

        max_display = len(findings) if severity == 'CRITICAL' else min(5, len(findings))

        for i, finding in enumerate(findings[:max_display], 1):
            print(f"\n  [{i}] {finding.get('pattern_name', 'Unknown Pattern')}")
            print(f"      Fuente: {finding.get('data_source', 'unknown')}")

            if finding.get('data_source') == 'mysql':
                print(f"      Base de datos: {finding.get('database', 'N/A')}")
                print(f"      Tabla: {finding.get('table', 'N/A')}")
                print(f"      Columna: {finding.get('column', 'N/A')}")
            elif finding.get('data_source') == 's3':
                print(f"      Bucket: {finding.get('bucket', 'N/A')}")
                print(f"      Archivo: {finding.get('file_path', 'N/A')}")

            matches = finding.get('matches', [])
            if matches:
                match_preview = matches[:3]
                print(f"      Matches: {', '.join(match_preview)}")
                if len(matches) > 3:
                    print(f"      ... y {len(matches) - 3} más")

        if len(findings) > max_display:
            print(f"\n  ... y {len(findings) - max_display} hallazgos más de severidad {severity}")

def generate_final_summary(results, output_file, tracking_stats, cases_created, thehive_available):
    """Genera resumen final consolidado con TODA la información"""
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
    print(f"📈 RESUMEN FINAL CONSOLIDADO")
    print(f"{'='*70}")
    
    # 1. HALLAZGOS DETECTADOS
    print(f"\n📊 Hallazgos Detectados:")
    print(f"   • Total: {summary['total_findings']}")

    print(f"\n   🚨 Por severidad:")
    severity_display_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    for severity in severity_display_order:
        count = summary['by_severity'].get(severity, 0)
        if count > 0:
            print(f"      {severity}: {count}")

    print(f"\n   📁 Por fuente:")
    for source, count in summary['by_source'].items():
        print(f"      {source}: {count}")

    print(f"\n   🔍 Top 5 patrones:")
    top_patterns = sorted(summary['by_pattern'].items(),
                         key=lambda x: x[1], reverse=True)[:5]
    for pattern, count in top_patterns:
        print(f"      {pattern}: {count}")

    # 2. TRACKING
    print(f"\n📋 Sistema de Tracking:")
    critical_count = tracking_stats.get('by_severity', {}).get('CRITICAL', 0)
    high_count = tracking_stats.get('by_severity', {}).get('HIGH', 0)
    print(f"   • Total críticos/high: {critical_count + high_count}")
    print(f"   • Pendientes de revisar: {tracking_stats['critical_pending']}")
    
    if tracking_stats.get('reopened_alerts', 0) > 0:
        print(f"\n   🔄 Re-aperturas detectadas:")
        print(f"      • Casos re-abiertos: {tracking_stats['reopened_alerts']}")
        print(f"      • Total re-ocurrencias: {tracking_stats.get('total_reopens', 0)}")

    # 3. THEHIVE
    if thehive_available:
        print(f"\n🎯 Integración con TheHive:")
        if cases_created > 0:
            print(f"   • Casos nuevos creados: {cases_created}")
        
        if tracking_stats.get('thehive_stats'):
            print(f"\n   📊 Estado de casos:")
            thehive_stats = tracking_stats['thehive_stats']
            for status, count in thehive_stats.items():
                if status:
                    print(f"      • {status}: {count}")
        
        print(f"\n   🌐 Dashboard: http://localhost:9000")
    else:
        print(f"\n⚠️  TheHive: No disponible")

    # 4. ALERTAS CRÍTICAS
    critical = get_critical_findings(valid_results)
    if critical:
        print(f"\n⚠️  ATENCIÓN: {len(critical)} hallazgos CRÍTICOS requieren acción inmediata")

    return summary

if __name__ == "__main__":
    print("=" * 70)
    print("🦅 HAWK-EYE SCANNER - Automated Security Scan")
    print("=" * 70)

    mysql_output = f"{RESULTS_DIR}/mysql_{timestamp}.json"
    s3_output = f"{RESULTS_DIR}/s3_{timestamp}.json"
    consolidated_output = f"{RESULTS_DIR}/consolidated_{timestamp}.json"
    summary_output = f"{RESULTS_DIR}/summary_{timestamp}.json"
    latest_output = f"{RESULTS_DIR}/latest.json"

    # 1. ESCANEO
    mysql_success = run_scan("mysql", mysql_output)
    s3_success = run_scan("s3", s3_output)

    if mysql_success or s3_success:
        results = consolidate_results(mysql_output, s3_output, consolidated_output)

        # 2. TRACKING (AGRUPADO POR HASH)
        print(f"\n{'='*70}")
        print("🔄 Procesando con sistema de tracking...")
        print(f"{'='*70}")

        alert_mgr = AlertManager()

        # AGRUPAR FINDINGS POR HASH PRIMERO
        findings_by_hash = {}
        for finding in results:
            alert_hash = alert_mgr._generate_hash(finding)
            if alert_hash not in findings_by_hash:
                findings_by_hash[alert_hash] = []
            findings_by_hash[alert_hash].append(finding)

        # PROCESAR UN SOLO FINDING POR UBICACIÓN
        new_alerts = []
        duplicate_count = 0
        reopen_count = 0

        for alert_hash, findings_group in findings_by_hash.items():
            # Tomar el primer finding del grupo (representativo de la ubicación)
            representative_finding = findings_group[0]
            
            # Consolidar todos los matches del grupo
            all_matches = []
            for f in findings_group:
                all_matches.extend(f.get('matches', []))
            representative_finding['matches'] = all_matches
            
            processed = alert_mgr.process_finding(representative_finding)
            if processed['is_new']:
                new_alerts.append(processed)
                if processed.get('is_reopen'):
                    reopen_count += 1
            else:
                duplicate_count += 1

        print(f"\n📊 Resultados del tracking:")
        print(f"   • Total de hallazgos: {len(results)}")
        print(f"   • Ubicaciones únicas: {len(findings_by_hash)}")
        print(f"   • Alertas NUEVAS: {len(new_alerts)}")
        if reopen_count > 0:
            print(f"   • Re-aperturas: {reopen_count} 🔄")
        print(f"   • Ya vistos: {duplicate_count}")

        stats = alert_mgr.get_stats()
        if stats['critical_pending'] > 0:
            print(f"\n   ⚠️  {stats['critical_pending']} alertas CRÍTICAS pendientes")

        # 3. MOSTRAR HALLAZGOS
        display_findings(results)

        # Preparar datos para notificaciones y resumen
        valid_results = [r for r in results if isinstance(r, dict) and 'pattern_name' in r]
        summary_data = {
            "scan_date": datetime.now().isoformat(),
            "total_findings": len(valid_results),
            "by_severity": dict(Counter([r.get('severity', 'unknown') for r in valid_results])),
            "by_pattern": dict(Counter([r.get('pattern_name', 'unknown') for r in valid_results])),
            "by_source": dict(Counter([r.get('data_source', 'unknown') for r in valid_results])),
        }

        # 4. NOTIFICACIONES (incluye TheHive si esta habilitado)
        print(f"\n{'='*70}")
        print("📨 Enviando notificaciones...")
        print(f"{'='*70}")
        notifier = NotificationManager()
        notif_results = notifier.send_all(summary_data, stats, new_alerts, alert_mgr=alert_mgr)
        if notif_results:
            for ch, res in notif_results.items():
                ch_status = res.get('status', 'unknown')
                print(f"   • {ch}: {ch_status}")
        else:
            print("   No hay canales habilitados")

        # Refrescar stats despues de notificaciones (TheHive puede haber actualizado casos)
        stats = alert_mgr.get_stats()

        # Derivar info de TheHive para el resumen
        thehive_result = notif_results.get('thehive', {})
        thehive_available = thehive_result.get('status') == 'sent'
        cases_created = thehive_result.get('cases_created', 0)

        # 5. RESUMEN FINAL
        summary = generate_final_summary(results, summary_output, stats, cases_created, thehive_available)

        with open(latest_output, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n{'='*70}")
        print(f"✅ Escaneo completado exitosamente")
        print(f"📁 Resultados guardados en: {ALERTS_DIR}/")
        print(f"{'='*70}\n")
    else:
        print("\n❌ Escaneo falló")
        exit(1)
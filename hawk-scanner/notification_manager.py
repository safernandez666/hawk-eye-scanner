#!/usr/bin/env python3
"""
Notification Manager - Envia notificaciones por SMTP, Slack, Teams, Webhook y TheHive
tras cada scan de hawk-scanner.
"""

import json
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.request import Request, urlopen
from urllib.error import URLError

import requests
import yaml

CONFIG_PATH = os.environ.get('CONNECTION_PATH', 'connection.yml')


class NotificationManager:
    def __init__(self, config_path=None):
        self.channels = {}
        self.ollama_config = {}
        path = config_path or CONFIG_PATH
        try:
            with open(path, 'r') as f:
                config = yaml.safe_load(f) or {}
            notify_config = config.get('notify', {})
            self.channels = notify_config.get('channels', {})
            self.ollama_config = notify_config.get('ollama', {})
        except Exception as e:
            print(f"[notifications] No se pudo leer config: {e}")

    def send_all(self, summary, stats, new_alerts, alert_mgr=None):
        """Envia notificaciones por todos los canales habilitados."""
        results = {}
        if not self.channels:
            print("[notifications] No hay canales configurados")
            return results

        text = self._build_text(summary, stats, new_alerts)

        for name, cfg in self.channels.items():
            if not cfg.get('enabled'):
                continue
            severity_filter = cfg.get('severity_filter', [])
            if severity_filter and not self._has_matching_severity(summary, severity_filter):
                results[name] = {'status': 'skipped', 'reason': 'no matching severity'}
                continue
            try:
                if name == 'thehive':
                    # TheHive siempre se ejecuta (hace sync de casos existentes)
                    cases_created = self._send_thehive(cfg, new_alerts, alert_mgr)
                    results[name] = {'status': 'sent', 'cases_created': cases_created}
                    print(f"[notifications] thehive: {cases_created} casos creados")
                    continue
                # Para el resto de canales, solo notificar si hay alertas nuevas
                if not new_alerts:
                    results[name] = {'status': 'skipped', 'reason': 'no new alerts'}
                    continue
                if name == 'smtp':
                    self._send_smtp(cfg, text, summary)
                elif name == 'slack':
                    self._send_slack(cfg, text, summary)
                elif name == 'teams':
                    self._send_teams(cfg, text, summary)
                elif name == 'webhook':
                    self._send_webhook(cfg, summary, stats, new_alerts)
                results[name] = {'status': 'sent'}
                print(f"[notifications] {name}: enviado OK")
            except Exception as e:
                results[name] = {'status': 'error', 'error': str(e)}
                print(f"[notifications] {name}: error - {e}")
        return results

    def send_test(self, channel_name, channel_config):
        """Envia una notificacion de prueba con datos fake."""
        fake_summary = {
            'total_findings': 10,
            'by_severity': {'CRITICAL': 2, 'HIGH': 3, 'MEDIUM': 4, 'LOW': 1},
            'by_pattern': {'Private Key': 5, 'SSN': 3, 'Email Address': 2},
        }
        fake_stats = {
            'critical_pending': 2,
            'reopened_alerts': 1,
            'total_reopens': 1,
            'by_severity': {'CRITICAL': 2, 'HIGH': 3},
        }
        fake_alerts = [
            {'finding': {'pattern_name': 'Private Key', 'severity': 'CRITICAL'}, 'is_new': True},
            {'finding': {'pattern_name': 'SSN', 'severity': 'HIGH'}, 'is_new': True},
        ]
        text = self._build_text(fake_summary, fake_stats, fake_alerts)
        text = "[TEST] " + text

        try:
            if channel_name == 'smtp':
                self._send_smtp(channel_config, text, fake_summary)
            elif channel_name == 'slack':
                self._send_slack(channel_config, text, fake_summary)
            elif channel_name == 'teams':
                self._send_teams(channel_config, text, fake_summary)
            elif channel_name == 'webhook':
                self._send_webhook(channel_config, fake_summary, fake_stats, fake_alerts)
            elif channel_name == 'thehive':
                from thehive_integration import TheHiveIntegration
                url = channel_config.get('url', 'http://thehive:9000')
                api_key = channel_config.get('api_key', '')
                thehive = TheHiveIntegration(url=url, api_key=api_key)
                if not thehive.test_connection():
                    raise ConnectionError(f'No se pudo conectar a TheHive en {url}')
            return {'status': 'sent'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    # ---- Internal methods ----

    def _has_matching_severity(self, summary, severity_filter):
        by_sev = summary.get('by_severity', {})
        for sev in severity_filter:
            if by_sev.get(sev, 0) > 0:
                return True
        return False

    def _build_text(self, summary, stats, new_alerts):
        by_sev = summary.get('by_severity', {})
        sev_parts = []
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = by_sev.get(s, 0)
            if count > 0:
                sev_parts.append(f"{count} {s}")

        new_count = len(new_alerts) if new_alerts else 0
        reopened = stats.get('reopened_alerts', 0)
        critical_pending = stats.get('critical_pending', 0)

        top_patterns = sorted(
            summary.get('by_pattern', {}).items(),
            key=lambda x: x[1], reverse=True
        )[:5]

        lines = [
            "Poirot DSPM - Scan Report",
            "=" * 40,
            "  " + " | ".join(sev_parts) if sev_parts else "  No findings",
        ]

        detail_parts = []
        if new_count > 0:
            detail_parts.append(f"{new_count} new alerts")
        if reopened > 0:
            detail_parts.append(f"{reopened} reopened")
        if detail_parts:
            lines.append("  " + " | ".join(detail_parts))

        if critical_pending > 0:
            lines.append(f"  {critical_pending} critical pending")

        if top_patterns:
            lines.append("")
            lines.append("Top findings:")
            for pattern, count in top_patterns:
                lines.append(f"  - {pattern}: {count} detections")

        return "\n".join(lines)

    def _send_smtp(self, cfg, text, summary=None):
        msg = MIMEMultipart('alternative')
        msg['From'] = cfg.get('from_address', '')
        msg['To'] = cfg.get('to_addresses', '')
        msg['Subject'] = 'Poirot DSPM - Scan Report'

        # Always attach plain text as fallback
        msg.attach(MIMEText(text, 'plain'))

        # If Ollama enabled, generate and attach HTML
        if self.ollama_config.get('enabled') and summary:
            try:
                html = self._generate_html_with_ollama(text, summary)
                msg.attach(MIMEText(html, 'html'))
            except Exception as e:
                print(f"[ollama] HTML generation failed, using plain text: {e}")

        host = cfg.get('host', 'localhost')
        port = int(cfg.get('port', 587))
        use_tls = cfg.get('use_tls', True)

        server = smtplib.SMTP(host, port, timeout=10)
        if use_tls:
            server.starttls()
        username = cfg.get('username', '')
        password = cfg.get('password', '')
        if username and password:
            server.login(username, password)
        to_list = [a.strip() for a in msg['To'].split(',') if a.strip()]
        server.sendmail(msg['From'], to_list, msg.as_string())
        server.quit()

    def _generate_html_with_ollama(self, plain_text, summary):
        """Build HTML email with deterministic template + Ollama-generated analysis."""
        from datetime import datetime

        by_sev = summary.get('by_severity', {})
        by_src = summary.get('by_source', {})
        by_pat = summary.get('by_pattern', {})
        total = summary.get('total_findings', 0)
        top_patterns = sorted(by_pat.items(), key=lambda x: x[1], reverse=True)[:7]
        fecha = datetime.now().strftime('%d/%m/%Y %H:%M')

        print(f"[ollama] Summary data: total={total}, by_sev={by_sev}, by_src={by_src}, by_pat={by_pat}")

        # --- Ask Ollama ONLY for the analysis paragraph ---
        analysis = self._get_ollama_analysis(summary)

        # --- Build severity cards ---
        sev_colors = {
            'CRITICAL': ('#dc2626', '#fef2f2', '#991b1b'),
            'HIGH': ('#ea580c', '#fff7ed', '#9a3412'),
            'MEDIUM': ('#ca8a04', '#fefce8', '#854d0e'),
            'LOW': ('#16a34a', '#f0fdf4', '#166534'),
        }
        severity_cards = ''
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = by_sev.get(sev, 0)
            border, bg, text_color = sev_colors[sev]
            severity_cards += (
                f'<div style="flex:1;min-width:100px;background:{bg};border:1px solid {border};'
                f'border-radius:8px;padding:16px;text-align:center;">'
                f'<div style="font-size:28px;font-weight:700;color:{border};">{count}</div>'
                f'<div style="font-size:12px;color:{text_color};margin-top:4px;font-weight:600;">{sev}</div>'
                f'</div>'
            )

        # --- Build patterns table ---
        pattern_rows = ''
        for i, (pat, count) in enumerate(top_patterns):
            bg = '#f9fafb' if i % 2 == 0 else '#ffffff'
            pattern_rows += (
                f'<tr style="background:{bg};">'
                f'<td style="padding:10px 12px;font-size:14px;color:#1f2937;">{pat}</td>'
                f'<td style="padding:10px 12px;font-size:14px;color:#1f2937;text-align:right;font-weight:600;">{count}</td>'
                f'</tr>'
            )

        # --- Build sources table ---
        src_labels = {
            'mysql': ('MySQL', '&#128450;'),
            's3': ('Amazon S3', '&#9729;'),
            'gdrive': ('Google Drive', '&#128193;'),
            'onedrive': ('OneDrive', '&#128193;'),
        }
        source_rows = ''
        for i, (src, count) in enumerate(by_src.items()):
            label, icon = src_labels.get(src, (src, '&#128196;'))
            bg = '#f9fafb' if i % 2 == 0 else '#ffffff'
            source_rows += (
                f'<tr style="background:{bg};">'
                f'<td style="padding:10px 12px;font-size:14px;color:#1f2937;">{icon} {label}</td>'
                f'<td style="padding:10px 12px;font-size:14px;color:#1f2937;text-align:right;font-weight:600;">{count}</td>'
                f'</tr>'
            )

        html = f'''<div style="background:#f5f7fa;padding:40px 20px;font-family:system-ui,-apple-system,sans-serif;">
  <div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;box-shadow:0 4px 6px rgba(0,0,0,0.1);overflow:hidden;">
    <div style="background:linear-gradient(135deg,#1e3a8a 0%,#3b82f6 100%);padding:30px;text-align:center;color:white;">
      <h1 style="margin:0;font-size:24px;font-weight:700;">Poirot DSPM</h1>
      <p style="margin:8px 0 0 0;opacity:0.9;font-size:14px;">Reporte de Seguridad &mdash; {fecha}</p>
    </div>
    <div style="padding:24px 30px;background:#f8fafc;border-bottom:1px solid #e5e7eb;">
      <h2 style="margin:0 0 16px 0;font-size:18px;color:#1f2937;">Resumen &mdash; {total} hallazgos</h2>
      <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
        {severity_cards}
      </div>
    </div>
    <div style="padding:24px 30px;border-bottom:1px solid #e5e7eb;">
      <h3 style="margin:0 0 12px 0;font-size:16px;color:#1f2937;">Top Patrones Detectados</h3>
      <table style="width:100%;border-collapse:collapse;">
        <tr style="border-bottom:2px solid #e5e7eb;">
          <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;text-transform:uppercase;">Patron</th>
          <th style="padding:8px 12px;text-align:right;font-size:12px;color:#6b7280;text-transform:uppercase;">Cantidad</th>
        </tr>
        {pattern_rows}
      </table>
    </div>
    <div style="padding:24px 30px;border-bottom:1px solid #e5e7eb;">
      <h3 style="margin:0 0 12px 0;font-size:16px;color:#1f2937;">Fuentes Escaneadas</h3>
      <table style="width:100%;border-collapse:collapse;">
        <tr style="border-bottom:2px solid #e5e7eb;">
          <th style="padding:8px 12px;text-align:left;font-size:12px;color:#6b7280;text-transform:uppercase;">Fuente</th>
          <th style="padding:8px 12px;text-align:right;font-size:12px;color:#6b7280;text-transform:uppercase;">Hallazgos</th>
        </tr>
        {source_rows}
      </table>
    </div>
    <div style="padding:24px 30px;">
      <div style="background:#eff6ff;border-left:4px solid #3b82f6;padding:20px;border-radius:0 8px 8px 0;">
        <h4 style="margin:0 0 10px 0;color:#1e40af;font-size:14px;">Analisis y Recomendaciones</h4>
        <p style="margin:0;color:#1f2937;font-size:14px;line-height:1.6;">{analysis}</p>
      </div>
    </div>
    <div style="padding:20px;text-align:center;border-top:1px solid #e5e7eb;background:#f9fafb;">
      <p style="margin:0;color:#9ca3af;font-size:12px;">Generado por Poirot DSPM</p>
    </div>
  </div>
</div>'''
        return html

    def _get_ollama_analysis(self, summary):
        """Ask Ollama to generate only the analysis paragraph."""
        ollama_cfg = self.ollama_config
        url = ollama_cfg.get('url', 'http://host.docker.internal:11434')
        model = ollama_cfg.get('model', 'llama3.2')

        by_sev = summary.get('by_severity', {})
        by_src = summary.get('by_source', {})
        by_pat = summary.get('by_pattern', {})
        top_patterns = sorted(by_pat.items(), key=lambda x: x[1], reverse=True)[:7]

        src_labels = {'mysql': 'base de datos MySQL', 's3': 'bucket S3',
                      'gdrive': 'Google Drive', 'onedrive': 'OneDrive'}
        source_lines = [f"- {src_labels.get(s, s)}: {c} hallazgos" for s, c in by_src.items()]
        pattern_lines = [f"- {p}: {c} detecciones" for p, c in top_patterns]

        prompt = f"""Sos un analista de ciberseguridad. Escribi un parrafo de analisis (4-5 oraciones) en espanol sobre este escaneo de datos sensibles.

DATOS:
Total: {summary.get('total_findings', 0)} hallazgos
Severidad: CRITICAL={by_sev.get('CRITICAL', 0)}, HIGH={by_sev.get('HIGH', 0)}, MEDIUM={by_sev.get('MEDIUM', 0)}, LOW={by_sev.get('LOW', 0)}

Fuentes escaneadas:
{chr(10).join(source_lines)}

Patrones detectados:
{chr(10).join(pattern_lines)}

INSTRUCCIONES:
1. Menciona CADA fuente por nombre (ej: "En la base de datos MySQL se detectaron...", "En el bucket S3 se encontraron...")
2. Destaca los patrones mas criticos y su riesgo real (ej: claves privadas expuestas permiten acceso no autorizado)
3. Da 2-3 recomendaciones concretas y accionables
4. Escribe SOLO el parrafo, sin titulos, sin HTML, sin markdown, sin bullet points. Texto plano corrido."""

        resp = requests.post(
            f"{url}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            },
            timeout=120,
        )
        resp.raise_for_status()
        analysis = resp.json()["message"]["content"].strip()

        # Clean up: remove "Nota:" disclaimers the model sometimes appends
        import re
        for marker in ['Nota:', 'Note:', 'Disclaimer:', 'NOTA:']:
            idx = analysis.find(marker)
            if idx > 0:
                analysis = analysis[:idx].strip()

        # Remove any HTML tags the model might inject
        analysis = re.sub(r'<[^>]+>', '', analysis)
        print(f"[ollama] Analysis generated ({len(analysis)} chars)")
        return analysis

    def _send_slack(self, cfg, text, summary):
        by_sev = summary.get('by_severity', {})
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Poirot DSPM - Scan Report"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CRITICAL:* {by_sev.get('CRITICAL', 0)}"},
                    {"type": "mrkdwn", "text": f"*HIGH:* {by_sev.get('HIGH', 0)}"},
                    {"type": "mrkdwn", "text": f"*MEDIUM:* {by_sev.get('MEDIUM', 0)}"},
                    {"type": "mrkdwn", "text": f"*LOW:* {by_sev.get('LOW', 0)}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"```{text}```"}
            }
        ]
        payload = json.dumps({"blocks": blocks}).encode('utf-8')
        req = Request(cfg['webhook_url'], data=payload, headers={'Content-Type': 'application/json'})
        urlopen(req, timeout=10)

    def _send_teams(self, cfg, text, summary):
        by_sev = summary.get('by_severity', {})
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "d63939" if by_sev.get('CRITICAL', 0) > 0 else "f76707",
            "summary": "Poirot DSPM - Scan Report",
            "sections": [{
                "activityTitle": "Poirot DSPM - Scan Report",
                "facts": [
                    {"name": "CRITICAL", "value": str(by_sev.get('CRITICAL', 0))},
                    {"name": "HIGH", "value": str(by_sev.get('HIGH', 0))},
                    {"name": "MEDIUM", "value": str(by_sev.get('MEDIUM', 0))},
                    {"name": "LOW", "value": str(by_sev.get('LOW', 0))},
                    {"name": "Total", "value": str(summary.get('total_findings', 0))},
                ],
                "text": text
            }]
        }
        payload = json.dumps(card).encode('utf-8')
        req = Request(cfg['webhook_url'], data=payload, headers={'Content-Type': 'application/json'})
        urlopen(req, timeout=10)

    def _send_webhook(self, cfg, summary, stats, new_alerts):
        payload_data = {
            'source': 'poirot-dspm',
            'event': 'scan_complete',
            'summary': summary,
            'stats': stats,
            'new_alerts_count': len(new_alerts) if new_alerts else 0,
        }
        url = cfg.get('url', '')
        method = cfg.get('method', 'POST').upper()
        headers = cfg.get('headers', {'Content-Type': 'application/json'})

        payload = json.dumps(payload_data, default=str).encode('utf-8')
        req = Request(url, data=payload, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        urlopen(req, timeout=10)

    def _send_thehive(self, cfg, new_alerts, alert_mgr):
        """Crea casos en TheHive para cada alerta nueva usando TheHiveIntegration."""
        from thehive_integration import TheHiveIntegration

        url = cfg.get('url', 'http://thehive:9000')
        api_key = cfg.get('api_key', '')
        create_cases = cfg.get('create_cases', True)
        severity_filter = cfg.get('severity_filter', [])

        thehive = TheHiveIntegration(url=url, api_key=api_key)

        print("[thehive] Conectando con TheHive...")
        if not thehive.test_connection():
            raise ConnectionError(f'No se pudo conectar a TheHive en {url}')

        # Sincronizar estados de casos existentes
        if alert_mgr:
            print("[thehive] Sincronizando estados de casos...")
            synced = thehive.sync_cases_status(alert_mgr)
            print(f"[notifications] thehive: sync - open={synced.get('open', 0)}, resolved={synced.get('resolved', 0)}")

        if not create_cases:
            print("[notifications] thehive: create_cases=false, solo sync")
            return 0

        if not new_alerts:
            return 0

        # Filtrar alertas que aplican por severidad
        eligible = [a for a in new_alerts
                    if not severity_filter or a['finding'].get('severity') in severity_filter]

        total = len(eligible)
        if total == 0:
            print("[thehive] No se crearon casos nuevos")
            return 0

        print(f"[thehive] Creando {total} casos en TheHive...")

        cases_created = 0
        for i, alert in enumerate(eligible, 1):
            finding = alert['finding']
            is_reopen = alert.get('is_reopen', False)
            alert_hash = alert['alert_hash']

            case_id = thehive.create_case(finding, alert_hash, is_reopen)
            if case_id and alert_mgr:
                alert_mgr.update_thehive_case(alert_hash, case_id, 'New')
                cases_created += 1
            print(f"[thehive] Caso {i}/{total}")

        return cases_created

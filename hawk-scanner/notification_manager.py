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

import yaml

CONFIG_PATH = os.environ.get('CONNECTION_PATH', 'connection.yml')


class NotificationManager:
    def __init__(self, config_path=None):
        self.channels = {}
        path = config_path or CONFIG_PATH
        try:
            with open(path, 'r') as f:
                config = yaml.safe_load(f) or {}
            self.channels = config.get('notify', {}).get('channels', {})
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
                    cases_created = self._send_thehive(cfg, new_alerts, alert_mgr)
                    results[name] = {'status': 'sent', 'cases_created': cases_created}
                    print(f"[notifications] thehive: {cases_created} casos creados")
                    continue
                elif name == 'smtp':
                    self._send_smtp(cfg, text)
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
                self._send_smtp(channel_config, text)
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

    def _send_smtp(self, cfg, text):
        msg = MIMEMultipart()
        msg['From'] = cfg.get('from_address', '')
        msg['To'] = cfg.get('to_addresses', '')
        msg['Subject'] = 'Poirot DSPM - Scan Report'
        msg.attach(MIMEText(text, 'plain'))

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

        if not thehive.test_connection():
            raise ConnectionError(f'No se pudo conectar a TheHive en {url}')

        # Sincronizar estados de casos existentes
        if alert_mgr:
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

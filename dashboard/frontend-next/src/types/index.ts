export interface Alert {
  id: number;
  alert_hash: string;
  pattern_name: string;
  data_source: string;
  location: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'NEW' | 'SENT' | 'ACKNOWLEDGED' | 'FALSE_POSITIVE' | 'REOPENED' | 'CLOSED';
  first_seen: string;
  last_seen: string;
  count: number;
  thehive_case_id?: string;
  thehive_status?: string;
  reopen_count: number;
  notes?: string;
}

export interface Stats {
  total_alerts: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_source: Record<string, number>;
  critical_pending: number;
  reopened_alerts: number;
  total_reopens: number;
  thehive_stats: Record<string, number>;
  timestamp: string;
}

export interface Pattern {
  pattern_name: string;
  severity: string;
  total_count: number;
  new_count: number;
}

export interface PatternConfig {
  name: string;
  regex: string;
  severity: string;
}

export interface Source {
  type: string;
  name: string;
  config: Record<string, unknown>;
  status?: string;
  message?: string;
}

export interface TimelineEntry {
  date: string;
  CRITICAL?: number;
  HIGH?: number;
  MEDIUM?: number;
  LOW?: number;
}

export interface TheHiveCase {
  _id: string;
  title: string;
  description?: string;
  severity: number;
  status: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ScannerStatus {
  running: boolean;
  error?: string;
}

export interface NotificationChannel {
  enabled: boolean;
  severity_filter: string[];
  // TheHive
  url?: string;
  api_key?: string;
  create_cases?: boolean;
  // SMTP
  host?: string;
  port?: number;
  use_tls?: boolean;
  username?: string;
  password?: string;
  from_address?: string;
  to_addresses?: string;
  // Slack / Teams
  webhook_url?: string;
  // Webhook
  method?: string;
  headers?: Record<string, string>;
}

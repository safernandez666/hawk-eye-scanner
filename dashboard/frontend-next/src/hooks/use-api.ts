"use client";

import { useState, useEffect, useCallback } from "react";
import type { Alert, Stats, Pattern, Source, TimelineEntry, TheHiveCase, ScannerStatus, NotificationChannel, OllamaConfig, SchedulerConfig } from "@/types";

const API_BASE = "/api";

async function fetcher<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}

// Generic hook for data fetching
export function useApi<T>(url: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    if (!url) return;
    setLoading(true);
    setError(null);
    try {
      const result = await fetcher<T>(url);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [url]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch: fetchData };
}

// Feature flags
export function useFeatures() {
  return useApi<{ thehive_enabled: boolean }>(`${API_BASE}/config/features`);
}

// Specific hooks
export function useStats() {
  return useApi<Stats>(`${API_BASE}/stats`);
}

export function useAlerts(severity?: string, status?: string, source?: string, latest?: boolean) {
  const params = new URLSearchParams();
  if (severity) params.append("severity", severity);
  if (status) params.append("status", status);
  if (source) params.append("source", source);
  if (latest) params.append("latest", "true");
  const query = params.toString() ? `?${params.toString()}` : "";
  return useApi<{ alerts: Alert[]; count: number }>(`${API_BASE}/alerts${query}`);
}

export function usePatterns() {
  return useApi<{ patterns: Pattern[]; total_patterns: number }>(`${API_BASE}/patterns`);
}

export function useTimeline(days = 30) {
  return useApi<{ timeline: Record<string, TimelineEntry>; days: number }>(
    `${API_BASE}/timeline?days=${days}`
  );
}

export function useSources() {
  return useApi<{ sources: Source[]; total: number }>(`${API_BASE}/config/sources`);
}

export function useSourcesHealth() {
  return useApi<{ sources: Source[] }>(`${API_BASE}/config/sources/health`);
}

export function useTheHiveCases(enabled: boolean = true) {
  return useApi<{ cases: TheHiveCase[] }>(enabled ? `${API_BASE}/thehive/cases` : null);
}

export function useTheHiveStatus(enabled: boolean = true) {
  return useApi<{ status: string; code?: number; message?: string }>(enabled ? `${API_BASE}/thehive/status` : null);
}

export function useScannerStatus() {
  return useApi<ScannerStatus>(`${API_BASE}/scanner/status`);
}

// Mutations
export async function runScanner() {
  return fetcher<{ 
    status: "completed" | "error" | "timeout"; 
    returncode?: number;
    stdout?: string;
    stderr?: string;
    message?: string;
  }>(`${API_BASE}/scanner/run`, {
    method: "POST",
  });
}

export async function syncTheHive() {
  return fetcher<{ message: string; created: number }>(`${API_BASE}/thehive/sync`, {
    method: "POST",
  });
}

// Notifications
export function useNotifications() {
  return useApi<{ channels: Record<string, NotificationChannel> }>(`${API_BASE}/config/notifications`);
}

export async function updateNotificationChannel(channel: string, config: NotificationChannel) {
  return fetcher<{ message: string }>(`${API_BASE}/config/notifications/${channel}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
}

export async function testNotificationChannel(channel: string, config: NotificationChannel) {
  return fetcher<{ status: string; error?: string }>(`${API_BASE}/config/notifications/${channel}/test`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
}

// Ollama
export function useOllamaConfig() {
  return useApi<OllamaConfig>(`${API_BASE}/config/ollama`);
}

export async function updateOllamaConfig(config: OllamaConfig) {
  return fetcher<{ message: string }>(`${API_BASE}/config/ollama`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
}

export async function fetchOllamaModels(url: string) {
  return fetcher<{ models: string[] }>(`${API_BASE}/ollama/models`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
}

// Scheduler
export function useSchedulerConfig() {
  return useApi<SchedulerConfig>(`${API_BASE}/config/scheduler`);
}

export async function updateSchedulerConfig(config: { enabled: boolean; interval_hours: number }) {
  return fetcher<{ message: string }>(`${API_BASE}/config/scheduler`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
}

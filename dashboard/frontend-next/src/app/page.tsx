"use client";

import { useState } from "react";
import { StatsCard } from "@/components/stats-card";
import { SeverityBadge, StatusBadge } from "@/components/severity-badge";
import { useStats, useAlerts } from "@/hooks/use-api";
import { Skeleton } from "@/components/ui/skeleton";
import { ScannerButton } from "@/components/scanner-button";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertTriangle,
  ShieldAlert,
  Database,
  RefreshCw,
  CheckCircle,
  Download,
  FileSpreadsheet,
  FileText,
  File,
} from "lucide-react";
import { SeverityDonutChart } from "@/components/severity-donut-chart";
import { TimelineChart } from "@/components/timeline-chart";
import { SourcesBarChart } from "@/components/sources-bar-chart";
import { toast } from "sonner";

const COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
};

export default function DashboardPage() {
  const { data: stats, loading: statsLoading, refetch: refetchStats } = useStats();
  const { data: alertsData, loading: alertsLoading, refetch: refetchAlerts } = useAlerts(undefined, undefined, undefined, true);
  
  // Filtros
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const severityData = stats
    ? Object.entries(stats.by_severity).map(([name, value]) => ({
        name,
        value,
        color: COLORS[name as keyof typeof COLORS] || "#8884d8",
      }))
    : [];

  const sourceData = stats
    ? Object.entries(stats.by_source).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  // Filtrar alertas
  const filteredAlerts = alertsData?.alerts.filter((alert) => {
    if (severityFilter !== "ALL" && alert.severity !== severityFilter) return false;
    if (statusFilter !== "ALL" && alert.status !== statusFilter) return false;
    return true;
  }) || [];

  // Exportar datos
  const exportData = (format: 'csv' | 'json') => {
    if (!filteredAlerts.length) {
      toast.error("No hay alertas para exportar");
      return;
    }
    
    const params = new URLSearchParams();
    if (severityFilter !== "ALL") params.append("severity", severityFilter);
    if (statusFilter !== "ALL") params.append("status", statusFilter);
    params.append("format", format);
    
    window.open(`/api/alerts/export?${params.toString()}`, '_blank');
    toast.success(`Exportando ${format.toUpperCase()}...`);
  };

  return (
    <div className="space-y-6">
      {/* Actions Bar */}
      <div className="flex items-center justify-end">
        <ScannerButton onScanComplete={() => {
          refetchStats();
          refetchAlerts();
        }} />
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statsLoading ? (
          <>
            <Skeleton className="h-32" />
            <Skeleton className="h-32" />
            <Skeleton className="h-32" />
            <Skeleton className="h-32" />
          </>
        ) : (
          <>
            <StatsCard
              title="Total Alertas"
              value={stats?.total_alerts || 0}
              description="Hallazgos acumulados"
              icon={AlertTriangle}
              color="blue"
            />
            <StatsCard
              title="Críticas Pendientes"
              value={stats?.critical_pending || 0}
              description="Requieren atención inmediata"
              icon={ShieldAlert}
              color="red"
            />
            <StatsCard
              title="Fuentes Monitoreadas"
              value={Object.keys(stats?.by_source || {}).length}
              description="Bases de datos y buckets"
              icon={Database}
              color="purple"
            />
            <StatsCard
              title="Re-aperturas"
              value={stats?.total_reopens || 0}
              description="Alertas re-abiertas"
              icon={RefreshCw}
              color="orange"
            />
          </>
        )}
      </div>

      {/* Charts Row: Donut más grande */}
      <div className="grid gap-4 lg:grid-cols-4 items-stretch">
        {/* Timeline - 1 columna */}
        <div className="lg:col-span-1 h-full">
          <TimelineChart />
        </div>
        
        {/* Severity Donut - 2 columnas (más ancho) */}
        <div className="lg:col-span-2 h-full">
          <SeverityDonutChart
            data={severityData}
            total={stats?.total_alerts || 0}
            loading={statsLoading}
          />
        </div>
        
        {/* Sources Bar - 1 columna */}
        <div className="lg:col-span-1 h-full">
          <SourcesBarChart data={sourceData} loading={statsLoading} />
        </div>
      </div>

      {/* Recent Alerts con filtros y exportación */}
      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <CardTitle>Alertas Recientes</CardTitle>
              <CardDescription>
                Hallazgos del último escaneo
              </CardDescription>
            </div>
            
            {/* Filtros y Exportación */}
            <div className="flex flex-wrap items-center gap-2">
              {/* Filtro Severidad */}
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[130px]">
                  <SelectValue placeholder="Severidad" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">Todas</SelectItem>
                  <SelectItem value="CRITICAL">Critical</SelectItem>
                  <SelectItem value="HIGH">High</SelectItem>
                  <SelectItem value="MEDIUM">Medium</SelectItem>
                  <SelectItem value="LOW">Low</SelectItem>
                </SelectContent>
              </Select>

              {/* Filtro Estado */}
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[130px]">
                  <SelectValue placeholder="Estado" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">Todos</SelectItem>
                  <SelectItem value="NEW">Nuevo</SelectItem>
                  <SelectItem value="SENT">Enviado</SelectItem>
                  <SelectItem value="ACKNOWLEDGED">Ack</SelectItem>
                  <SelectItem value="CLOSED">Cerrado</SelectItem>
                </SelectContent>
              </Select>

              {/* Exportar CSV */}
              <Button 
                variant="outline" 
                size="icon"
                onClick={() => exportData('csv')}
                title="Exportar CSV"
              >
                <FileSpreadsheet className="h-4 w-4" />
              </Button>

              {/* Exportar JSON */}
              <Button 
                variant="outline" 
                size="icon"
                onClick={() => exportData('json')}
                title="Exportar JSON"
              >
                <FileText className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {alertsLoading ? (
            <Skeleton className="h-48" />
          ) : filteredAlerts.length > 0 ? (
            <>
              <div className="mb-2 text-sm text-muted-foreground">
                Mostrando {filteredAlerts.length} alertas
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Patrón</TableHead>
                    <TableHead>Fuente</TableHead>
                    <TableHead>Ubicación</TableHead>
                    <TableHead>Severidad</TableHead>
                    <TableHead>Estado</TableHead>
                    <TableHead>Fecha</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAlerts.slice(0, 10).map((alert) => (
                    <TableRow key={alert.alert_hash}>
                      <TableCell className="font-medium">
                        {alert.pattern_name}
                      </TableCell>
                      <TableCell>{alert.data_source}</TableCell>
                      <TableCell className="max-w-[200px] truncate">
                        {alert.location}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={alert.severity} />
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={alert.status} />
                      </TableCell>
                      <TableCell>
                        {new Date(alert.first_seen).toLocaleDateString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </>
          ) : (
            <div className="flex h-32 items-center justify-center text-muted-foreground">
              <CheckCircle className="mr-2 h-5 w-5" />
              No hay alertas con los filtros seleccionados
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

"use client";

import { useState, useEffect } from "react";
import { useTheHiveCases, useTheHiveStatus, useFeatures, useNotifications } from "@/hooks/use-api";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
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
import { Briefcase, CheckCircle, XCircle, RefreshCw, Filter, Database, Cloud, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { syncTheHive } from "@/hooks/use-api";

const SEVERITY_LABELS: Record<number, string> = {
  1: "LOW",
  2: "MEDIUM",
  3: "HIGH",
  4: "CRITICAL",
};

// Extraer fuente y nombre limpio del título "[MYSQL] Credit Card - Visa"
function parseTitle(title: string): { source: string; name: string } {
  const match = title.match(/^\[([^\]]+)\]\s*(.+)$/);
  if (match) {
    return { source: match[1], name: match[2] };
  }
  return { source: "", name: title };
}

function formatDate(ts: number | string | undefined): string {
  if (!ts) return "N/A";
  // TheHive puede enviar timestamps en milisegundos o ISO strings
  const date = typeof ts === "string" ? new Date(ts) : new Date(ts);
  return date.toLocaleDateString("es-ES", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
}

const SEVERITY_FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const STATUS_FILTERS = ["ALL", "Open", "InProgress", "Resolved", "Closed"];

export default function CasesPage() {
  const { data: features, loading: featuresLoading, refetch: refetchFeatures } = useFeatures();
  const { data: notificationsData, loading: notificationsLoading, refetch: refetchNotifications } = useNotifications();
  
  // Verificar si The Hive está habilitado en notificaciones
  const thehiveChannel = notificationsData?.channels?.thehive;
  const isTheHiveEnabled = thehiveChannel?.enabled ?? false;
  
  // Solo llamar a los hooks de TheHive si está habilitado a nivel sistema y notificaciones
  const shouldFetchTheHive = !!features?.thehive_enabled && isTheHiveEnabled;
  const { data: casesData, loading: casesLoading, refetch } = useTheHiveCases(shouldFetchTheHive);
  const { data: statusData, loading: statusLoading } = useTheHiveStatus(shouldFetchTheHive);
  
  const [syncing, setSyncing] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  
  // Polling: verificar periódicamente si TheHive se habilitó desde otra pestaña/settings
  useEffect(() => {
    // Solo hacer polling cuando TheHive está deshabilitado para detectar cuando se habilite
    if (!shouldFetchTheHive) {
      const interval = setInterval(() => {
        refetchFeatures();
        refetchNotifications();
      }, 3000); // Cada 3 segundos
      return () => clearInterval(interval);
    }
  }, [shouldFetchTheHive, refetchFeatures, refetchNotifications]);

  // Nivel sistema: TheHive no está configurado
  if (!featuresLoading && !features?.thehive_enabled) {
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Briefcase className="h-12 w-12 text-muted-foreground mb-4" />
            <CardTitle className="mb-2">TheHive no configurado</CardTitle>
            <CardDescription className="text-center max-w-md mb-4">
              Configure la conexion con TheHive para gestionar casos de seguridad.
            </CardDescription>
            <Button variant="outline" onClick={() => window.location.href = '/settings'}>
              Configurar conexion
            </Button>
            <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" />
              Verificando estado...
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }
  
  // Nivel notificaciones: TheHive está deshabilitado en configuración
  if (!featuresLoading && !notificationsLoading && features?.thehive_enabled && !isTheHiveEnabled) {
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Briefcase className="h-12 w-12 text-muted-foreground mb-4" />
            <CardTitle className="mb-2">TheHive deshabilitado</CardTitle>
            <CardDescription className="text-center max-w-md mb-4">
              La integracion con TheHive esta deshabilitada en la configuracion de notificaciones.
              Los casos no se sincronizaran hasta que lo habilites.
            </CardDescription>
            <div className="flex items-center gap-4">
              <Button variant="outline" onClick={() => window.location.href = '/settings'}>
                Ir a Configuracion
              </Button>
            </div>
            <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" />
              Verificando estado...
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const handleSync = async () => {
    setSyncing(true);
    try {
      const result = await syncTheHive();
      toast.success(result.message);
      refetch();
    } catch (error) {
      toast.error("Error al sincronizar con TheHive");
    } finally {
      setSyncing(false);
    }
  };

  // Filtrar casos
  const filteredCases = casesData?.cases?.filter((caseItem) => {
    const matchSeverity = severityFilter === "ALL" || SEVERITY_LABELS[caseItem.severity] === severityFilter;
    const matchStatus = statusFilter === "ALL" || caseItem.status === statusFilter;
    return matchSeverity && matchStatus;
  }) || [];

  const isConnected = statusData?.status === "connected";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button onClick={handleSync} disabled={syncing || !isConnected}>
          <RefreshCw className={`mr-2 h-4 w-4 ${syncing ? "animate-spin" : ""}`} />
          Sincronizar Alertas
        </Button>
      </div>

      {/* Connection Status */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Estado de The Hive:</span>
              {statusLoading ? (
                <Skeleton className="h-5 w-24" />
              ) : isConnected ? (
                <Badge
                  variant="outline"
                  className="text-green-600 border-green-600"
                >
                  <CheckCircle className="mr-1 h-3 w-3" />
                  Conectado
                </Badge>
              ) : (
                <Badge variant="outline" className="text-red-600 border-red-600">
                  <XCircle className="mr-1 h-3 w-3" />
                  Desconectado
                </Badge>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Filters */}
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Filtrar por:</span>
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Severidad" />
              </SelectTrigger>
              <SelectContent>
                {SEVERITY_FILTERS.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s === "ALL" ? "Todas las severidades" : s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Estado" />
              </SelectTrigger>
              <SelectContent>
                {STATUS_FILTERS.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s === "ALL" ? "Todos los estados" : s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <span className="text-sm text-muted-foreground ml-auto">
              Mostrando {filteredCases.length} de {casesData?.cases?.length || 0} casos
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Cases Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Briefcase className="h-5 w-5" />
            <CardTitle>Casos en TheHive</CardTitle>
          </div>
          <CardDescription>
            {casesData?.cases?.length || 0} casos totales
          </CardDescription>
        </CardHeader>
        <CardContent>
          {casesLoading ? (
            <Skeleton className="h-64" />
          ) : filteredCases.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Fuente</TableHead>
                  <TableHead>Hallazgo</TableHead>
                  <TableHead>Severidad</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead>Creado</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredCases.map((caseItem) => {
                  const { source, name } = parseTitle(caseItem.title);
                  return (
                    <TableRow key={caseItem._id}>
                      <TableCell>
                        <Badge variant="outline" className="gap-1 font-mono text-xs">
                          {source.toUpperCase().includes("S3") ? (
                            <Cloud className="h-3 w-3" />
                          ) : (
                            <Database className="h-3 w-3" />
                          )}
                          {source.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-medium max-w-[300px] truncate" title={caseItem.title}>
                        {name}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            caseItem.severity === 4
                              ? "critical"
                              : caseItem.severity === 3
                              ? "high"
                              : caseItem.severity === 2
                              ? "medium"
                              : "low"
                          }
                        >
                          {SEVERITY_LABELS[caseItem.severity] || "UNKNOWN"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {caseItem.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">
                        {formatDate(caseItem.createdAt)}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <div className="flex h-32 items-center justify-center text-muted-foreground">
              No hay casos que coincidan con los filtros
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

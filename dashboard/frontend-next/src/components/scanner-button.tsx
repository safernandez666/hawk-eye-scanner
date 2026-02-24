"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import {
  Play,
  Loader2,
  CheckCircle,
  XCircle,
  RefreshCw,
  Database,
  Cloud,
} from "lucide-react";
import { toast } from "sonner";
import { useSources } from "@/hooks/use-api";

interface ScannerStatus {
  running: boolean;
  started_at: string | null;
  result: {
    status: "completed" | "error" | "timeout";
    returncode?: number;
    message?: string;
  } | null;
  logs: string[];
  total_logs: number;
}

interface ScannerButtonProps {
  onScanComplete?: () => void;
}

// Extrae el paso actual de los logs de forma limpia
function getCurrentStep(logs: string[]): string {
  if (logs.length === 0) return "Iniciando escaneo...";

  // Buscar el último log significativo (de atrás hacia adelante)
  for (let i = logs.length - 1; i >= 0; i--) {
    const line = logs[i].trim();
    if (!line) continue;

    // Skip líneas decorativas, separadores y warnings internos
    if (line.startsWith("=") || line.startsWith("---")) continue;
    if (line.includes("Error agregando observable")) continue;

    // Progreso de creación de casos en TheHive: "[thehive] Caso 3/5"
    const caseProgress = line.match(/\[thehive\] Caso (\d+)\/(\d+)/);
    if (caseProgress) {
      return `Creando casos en TheHive... ${caseProgress[1]}/${caseProgress[2]}`;
    }

    // Fases de TheHive
    if (line.includes("[thehive] Conectando")) return "Conectando con TheHive...";
    if (line.includes("[thehive] Sincronizando")) return "Sincronizando estados en TheHive...";
    if (line.includes("[thehive] Creando")) return "Creando casos en TheHive...";

    // Mapeo de patrones a mensajes limpios
    if (line.includes("Escaneando") && (line.includes("mysql") || line.includes("s3") || line.includes("🔍"))) {
      return "Escaneando fuentes de datos...";
    }
    if (line.includes("completado") && !line.includes("Escaneo completado")) return "Analizando resultados...";
    if (line.includes("Resultados consolidados")) return "Analizando hallazgos...";
    if (line.includes("Procesando con sistema")) return "Procesando hallazgos...";
    if (line.includes("Base de datos inicializada")) return "Guardando resultados...";
    if (line.includes("Sincronizando estados")) return "Sincronizando con TheHive...";
    if (line.includes("Enviando notificaciones")) return "Enviando notificaciones...";
    if (line.includes("Escaneo completado")) return "Finalizando...";
  }

  return "Procesando...";
}

export function ScannerButton({ onScanComplete }: ScannerButtonProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<ScannerStatus["result"]>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const logOffset = useRef(0);
  
  // Source selection state
  const { data: sourcesData } = useSources();
  const [showSourceSelection, setShowSourceSelection] = useState(false);
  const [selectedSources, setSelectedSources] = useState<string[]>([]);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const pollStatus = useCallback(async () => {
    try {
      const res = await fetch(`/api/scanner/status?since=${logOffset.current}`);
      const data: ScannerStatus = await res.json();

      if (data.logs.length > 0) {
        setLogs((prev) => [...prev, ...data.logs]);
        logOffset.current = data.total_logs;
      }

      if (data.running) {
        setProgress((p) => Math.min(p + 3, 90));
      }

      if (!data.running && data.result) {
        if (pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
        setIsScanning(false);
        setProgress(100);
        setResult(data.result);

        if (data.result.status === "completed" && data.result.returncode === 0) {
          toast.success("Escaneo completado");
          onScanComplete?.();
        } else if (data.result.status === "timeout") {
          toast.warning("Timeout");
        } else {
          toast.error("Error en el escaneo");
        }
      }
    } catch {
      // Network error — keep polling
    }
  }, [onScanComplete]);

  const handleStartScan = () => {
    // Show source selection dialog first
    if (sourcesData?.sources && sourcesData.sources.length > 0) {
      // Guardar los TIPOS de fuentes (mysql, s3), no los nombres
      setSelectedSources(sourcesData.sources.map((s: {type: string}) => s.type));
      setShowSourceSelection(true);
    } else {
      // No sources configured, start scan directly
      handleScan([]);
    }
  };

  const handleScan = async (sources: string[]) => {
    setShowSourceSelection(false);
    setIsOpen(true);
    setIsScanning(true);
    setProgress(5);
    setResult(null);
    setLogs([]);
    logOffset.current = 0;

    try {
      const res = await fetch("/api/scanner/run", { 
        method: "POST",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sources: sources.length > 0 ? sources : undefined })
      });
      const data = await res.json();

      if (data.status === "error") {
        setIsScanning(false);
        setResult({ status: "error", message: data.message });
        return;
      }

      setProgress(10);
      pollRef.current = setInterval(pollStatus, 1500);
    } catch (error) {
      setIsScanning(false);
      setProgress(100);
      const errorMsg = error instanceof Error ? error.message : "Error de conexión";
      setResult({ status: "error", message: errorMsg });
      toast.error("Error de comunicación");
    }
  };

  const handleClose = () => {
    if (!isScanning) {
      setIsOpen(false);
      if (isSuccess) {
        window.location.reload();
      }
    }
  };

  const isSuccess = result?.status === "completed" && result.returncode === 0;
  const isTimeout = result?.status === "timeout";
  const isError = result && !isSuccess && !isTimeout;
  
  const currentStep = getCurrentStep(logs);

  return (
    <>
      <Button
        onClick={handleStartScan}
        disabled={isScanning}
        className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
      >
        {isScanning ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Escaneando...
          </>
        ) : (
          <>
            <Play className="mr-2 h-4 w-4" />
            Escanear Ahora
          </>
        )}
      </Button>

      {/* Source Selection Dialog */}
      <Dialog open={showSourceSelection} onOpenChange={setShowSourceSelection}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader>
            <DialogTitle>Seleccionar Fuentes</DialogTitle>
            <DialogDescription>
              Elige qué fuentes de datos quieres escanear
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-3 py-4">
            {sourcesData?.sources?.map((source: {name: string, type: string}) => (
              <div key={source.name} className="flex items-center space-x-3">
                <Checkbox 
                  id={`source-${source.type}`}
                  checked={selectedSources.includes(source.type)}
                  onCheckedChange={(checked) => {
                    if (checked) {
                      setSelectedSources([...selectedSources, source.type]);
                    } else {
                      setSelectedSources(selectedSources.filter(s => s !== source.type));
                    }
                  }}
                />
                <Label htmlFor={`source-${source.type}`} className="flex items-center gap-2 cursor-pointer">
                  {source.type === 's3' ? <Cloud className="h-4 w-4" /> : <Database className="h-4 w-4" />}
                  {source.name}
                  <span className="text-xs text-muted-foreground">({source.type})</span>
                </Label>
              </div>
            ))}
          </div>
          
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setShowSourceSelection(false)}>
              Cancelar
            </Button>
            <Button 
              onClick={() => handleScan(selectedSources)}
              disabled={selectedSources.length === 0}
            >
              <Play className="mr-2 h-4 w-4" />
              Escanear {selectedSources.length > 0 && `(${selectedSources.length})`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Scan Progress Dialog */}
      <Dialog open={isOpen} onOpenChange={handleClose}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader className="text-center pb-0">
            <div className="flex justify-center mb-3">
              {isScanning ? (
                <div className="relative">
                  <div className="absolute inset-0 animate-ping rounded-full bg-blue-400 opacity-20" />
                  <Loader2 className="h-12 w-12 animate-spin text-blue-600" />
                </div>
              ) : isSuccess ? (
                <CheckCircle className="h-12 w-12 text-green-600" />
              ) : isTimeout ? (
                <CheckCircle className="h-12 w-12 text-yellow-500" />
              ) : isError ? (
                <XCircle className="h-12 w-12 text-red-600" />
              ) : null}
            </div>
            <DialogTitle>
              {isScanning
                ? "Escaneando..."
                : isSuccess
                ? "Escaneo completado"
                : isTimeout
                ? "Tiempo excedido"
                : isError
                ? "Error en el escaneo"
                : "Preparando..."}
            </DialogTitle>
            <DialogDescription>
              {isScanning
                ? currentStep
                : isSuccess
                ? "Los resultados están disponibles"
                : isError
                ? result?.message || "Error de comunicación"
                : ""}
            </DialogDescription>
          </DialogHeader>

          {isScanning && (
            <div className="pt-2">
              <Progress value={progress} className="h-2" />
            </div>
          )}

          <DialogFooter className="gap-2 pt-2">
            {!isScanning && result && (
              <>
                <Button variant="outline" onClick={() => window.location.reload()} className="gap-2">
                  <RefreshCw className="h-4 w-4" />
                  Refrescar Datos
                </Button>
                <Button onClick={() => setIsOpen(false)}>
                  Cerrar
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

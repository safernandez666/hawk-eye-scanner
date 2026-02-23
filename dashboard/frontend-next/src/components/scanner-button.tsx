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
import { Progress } from "@/components/ui/progress";
import {
  Play,
  Loader2,
  CheckCircle,
  XCircle,
  RefreshCw,
} from "lucide-react";
import { toast } from "sonner";

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
    
    // Skip líneas decorativas y separadores
    if (line.startsWith("=") || line.startsWith("🦅") || line.startsWith("📈") || line.startsWith("📋")) continue;
    if (line.startsWith("---")) continue;
    
    // Mapeo de patrones a mensajes limpios
    if (line.includes("🔍 Escaneando")) return "Escaneando fuentes de datos...";
    if (line.includes("completado") && line.includes("✅")) return "Analizando resultados...";
    if (line.includes("Procesando con sistema")) return "Procesando hallazgos...";
    if (line.includes("Base de datos inicializada")) return "Guardando resultados...";
    if (line.includes("Sincronizando estados")) return "Sincronizando con TheHive...";
    if (line.includes("Enviando alertas")) return "Enviando notificaciones...";
    if (line.includes("Escaneo completado")) return "Finalizando...";
    if (line.includes("Resultados consolidados")) return "Analizando hallazgos...";
    
    // Capturar líneas con emojis de progreso
    const emojiMatch = line.match(/^[🔍✅❌📊🔄📋⏳⚠️🔄🔴🟠🟡🟢]+\s*(.+)/);
    if (emojiMatch) {
      const clean = emojiMatch[1].trim();
      if (clean.length > 3 && clean.length < 60 && !clean.startsWith("-")) {
        return clean;
      }
    }
    
    // Si la línea tiene contenido útil (no es solo decoración)
    if (line.length > 5 && line.length < 60 && 
        !line.startsWith("[") && 
        !line.match(/^(INFO|DEBUG|ERROR|WARN)/i) &&
        !line.includes("Traceback") &&
        !line.includes("File \"/")) {
      return line;
    }
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

  const handleScan = async () => {
    setIsOpen(true);
    setIsScanning(true);
    setProgress(5);
    setResult(null);
    setLogs([]);
    logOffset.current = 0;

    try {
      const res = await fetch("/api/scanner/run", { method: "POST" });
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
        onClick={handleScan}
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

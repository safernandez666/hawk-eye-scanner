"use client";

import { useState } from "react";
import { useSources, useSourcesHealth } from "@/hooks/use-api";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Database, CheckCircle, XCircle, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

interface Source {
  type: string;
  name: string;
  config: Record<string, unknown>;
  status?: string;
  message?: string;
}

const SOURCE_TYPES = [
  { value: "mysql", label: "MySQL", fields: [
    { name: "host", label: "Host", type: "text", placeholder: "localhost" },
    { name: "port", label: "Puerto", type: "number", placeholder: "3306" },
    { name: "database", label: "Base de Datos", type: "text", placeholder: "mydb" },
    { name: "user", label: "Usuario", type: "text", placeholder: "root" },
    { name: "password", label: "Contraseña", type: "password", placeholder: "********" },
    { name: "limit_start", label: "Límite Inicio", type: "number", placeholder: "0" },
    { name: "limit_end", label: "Límite Fin", type: "number", placeholder: "10000" },
  ]},
  { value: "s3", label: "Amazon S3", fields: [
    { name: "access_key", label: "Access Key", type: "text", placeholder: "AKIA..." },
    { name: "secret_key", label: "Secret Key", type: "password", placeholder: "********" },
    { name: "bucket_name", label: "Nombre del Bucket", type: "text", placeholder: "my-bucket" },
    { name: "endpoint_url", label: "Endpoint URL", type: "text", placeholder: "https://s3.amazonaws.com" },
  ]},
];

export default function SourcesPage() {
  const { data: sourcesData, loading: sourcesLoading, refetch } = useSources();
  const { data: healthData, loading: healthLoading } = useSourcesHealth();

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [selectedSource, setSelectedSource] = useState<Source | null>(null);
  
  // Form state
  const [sourceType, setSourceType] = useState("mysql");
  const [sourceName, setSourceName] = useState("");
  const [formConfig, setFormConfig] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Combine sources with health status
  const sourcesWithHealth = sourcesData?.sources.map((source) => {
    const health = healthData?.sources.find(
      (h) => h.type === source.type && h.name === source.name
    );
    return { ...source, ...health };
  });

  const resetForm = () => {
    setSourceType("mysql");
    setSourceName("");
    setFormConfig({});
    setSelectedSource(null);
  };

  const handleAdd = async () => {
    if (!sourceName.trim()) {
      toast.error("El nombre de la fuente es requerido");
      return;
    }

    // Validar campos requeridos
    const currentType = SOURCE_TYPES.find(t => t.value === sourceType);
    const requiredFields = currentType?.fields.filter(f => f.type !== "number") || [];
    for (const field of requiredFields) {
      if (!formConfig[field.name]) {
        toast.error(`El campo "${field.label}" es requerido`);
        return;
      }
    }
    
    setIsSubmitting(true);
    try {
      // Convertir números
      const config = { ...formConfig };
      if (sourceType === "mysql") {
        config.port = formConfig.port || "3306";
        config.limit_start = formConfig.limit_start || "0";
        config.limit_end = formConfig.limit_end || "10000";
      }

      const res = await fetch("/api/config/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: sourceType,
          name: sourceName,
          config,
        }),
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Error al agregar fuente");
      }
      
      toast.success("Fuente agregada exitosamente");
      setIsAddOpen(false);
      resetForm();
      refetch();
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!selectedSource) return;
    
    setIsSubmitting(true);
    try {
      const res = await fetch(
        `/api/config/sources/${selectedSource.type}/${selectedSource.name}`,
        { method: "DELETE" }
      );
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Error al eliminar fuente");
      }
      
      toast.success("Fuente eliminada exitosamente");
      setIsDeleteOpen(false);
      resetForm();
      refetch();
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const openDelete = (source: Source) => {
    setSelectedSource(source);
    setIsDeleteOpen(true);
  };

  const updateFormConfig = (field: string, value: string) => {
    setFormConfig(prev => ({ ...prev, [field]: value }));
  };

  const currentType = SOURCE_TYPES.find(t => t.value === sourceType);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Button onClick={() => { resetForm(); setIsAddOpen(true); }}>
          <Plus className="mr-2 h-4 w-4" />
          Nueva Fuente
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            <CardTitle>Fuentes Configuradas</CardTitle>
          </div>
          <CardDescription>
            {sourcesLoading ? "Cargando..." : `${sourcesData?.total || 0} fuentes monitoreadas`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {sourcesLoading || healthLoading ? (
            <Skeleton className="h-64" />
          ) : sourcesWithHealth && sourcesWithHealth.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tipo</TableHead>
                  <TableHead>Nombre</TableHead>
                  <TableHead>Host/Endpoint</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead className="text-right">Acciones</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sourcesWithHealth.map((source) => (
                  <TableRow key={`${source.type}-${source.name}`}>
                    <TableCell className="font-medium uppercase">
                      {source.type}
                    </TableCell>
                    <TableCell>{source.name}</TableCell>
                    <TableCell>
                      {(source.config.host as string) ||
                        (source.config.endpoint_url as string) ||
                        "N/A"}
                    </TableCell>
                    <TableCell>
                      {source.status === "connected" ? (
                        <Badge
                          variant="outline"
                          className="text-green-600 border-green-600"
                        >
                          <CheckCircle className="mr-1 h-3 w-3" />
                          Conectado
                        </Badge>
                      ) : (
                        <Badge
                          variant="outline"
                          className="text-red-600 border-red-600"
                        >
                          <XCircle className="mr-1 h-3 w-3" />
                          Error
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-red-600 hover:text-red-700"
                        onClick={() => openDelete(source)}
                        title="Eliminar"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex h-32 items-center justify-center text-muted-foreground">
              No hay fuentes configuradas
            </div>
          )}
        </CardContent>
      </Card>

      {/* Dialog: Agregar Fuente */}
      <Dialog open={isAddOpen} onOpenChange={setIsAddOpen}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Agregar Nueva Fuente</DialogTitle>
            <DialogDescription>
              Configura una nueva fuente de datos en connection.yml
            </DialogDescription>
          </DialogHeader>
          
          <Tabs value={sourceType} onValueChange={setSourceType} className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="mysql">MySQL</TabsTrigger>
              <TabsTrigger value="s3">Amazon S3</TabsTrigger>
            </TabsList>
            
            {SOURCE_TYPES.map((type) => (
              <TabsContent key={type.value} value={type.value} className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="source-name">Nombre de la Fuente</Label>
                  <Input
                    id="source-name"
                    placeholder={`Ej: ${type.value}_production`}
                    value={sourceName}
                    onChange={(e) => setSourceName(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Identificador único para esta fuente
                  </p>
                </div>
                
                {type.fields.map((field) => (
                  <div key={field.name} className="space-y-2">
                    <Label htmlFor={field.name}>{field.label}</Label>
                    <Input
                      id={field.name}
                      type={field.type}
                      placeholder={field.placeholder}
                      value={formConfig[field.name] || ""}
                      onChange={(e) => updateFormConfig(field.name, e.target.value)}
                    />
                  </div>
                ))}
              </TabsContent>
            ))}
          </Tabs>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsAddOpen(false)}>
              Cancelar
            </Button>
            <Button onClick={handleAdd} disabled={isSubmitting}>
              {isSubmitting ? "Agregando..." : "Agregar Fuente"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Dialog: Eliminar Fuente */}
      <Dialog open={isDeleteOpen} onOpenChange={setIsDeleteOpen}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader>
            <DialogTitle>Eliminar Fuente</DialogTitle>
            <DialogDescription>
              ¿Estás seguro de que deseas eliminar la fuente &quot;{selectedSource?.name}&quot; ({selectedSource?.type})?
              Esta acción no se puede deshacer.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDeleteOpen(false)}>
              Cancelar
            </Button>
            <Button variant="destructive" onClick={handleDelete} disabled={isSubmitting}>
              {isSubmitting ? "Eliminando..." : "Eliminar"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

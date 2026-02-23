"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { SeverityBadge } from "@/components/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
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
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Fingerprint, AlertCircle, Plus, Pencil, Trash2, Eye, Play, CheckCircle, XCircle, CreditCard, Key, User, Contact, Bitcoin } from "lucide-react";
import { toast } from "sonner";

interface PatternConfig {
  name: string;
  regex: string;
  category: string;
  severity: string;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const CATEGORIES = ["PCI", "CREDENTIALS", "PII", "INFRA", "CRYPTO", "OTHER"] as const;

// Mapa de categorías para mostrar
const CATEGORY_LABELS: Record<string, { label: string; icon: React.ElementType }> = {
  PCI: { label: "Tarjetas (PCI)", icon: CreditCard },
  CREDENTIALS: { label: "Credenciales", icon: Key },
  PII: { label: "PII / Acceso", icon: User },
  INFRA: { label: "Contacto / Infra", icon: Contact },
  CRYPTO: { label: "Crypto", icon: Bitcoin },
  OTHER: { label: "Otros", icon: Fingerprint }
};

// Función para obtener la categoría de un patrón
function getPatternCategory(categoryKey: string): { key: string; label: string; icon: React.ElementType } {
  const cat = CATEGORY_LABELS[categoryKey] || CATEGORY_LABELS['OTHER'];
  return { key: categoryKey, label: cat.label, icon: cat.icon };
}

export default function PatternsPage() {
  const { data, loading, error, refetch } = useApi<{ patterns: PatternConfig[]; total: number }>("/api/config/patterns");
  
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [isViewOpen, setIsViewOpen] = useState(false);
  const [isTestOpen, setIsTestOpen] = useState(false);
  const [selectedPattern, setSelectedPattern] = useState<PatternConfig | null>(null);
  
  // Form state
  const [formName, setFormName] = useState("");
  const [formRegex, setFormRegex] = useState("");
  const [formSeverity, setFormSeverity] = useState("MEDIUM");
  const [formCategory, setFormCategory] = useState("OTHER");
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  // Regex tester state
  const [testText, setTestText] = useState("");
  const [testResults, setTestResults] = useState<{valid: boolean; matches: any[]; match_count: number; error?: string} | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  const resetForm = () => {
    setFormName("");
    setFormRegex("");
    setFormSeverity("MEDIUM");
    setFormCategory("OTHER");
    setSelectedPattern(null);
  };

  // Regex validation state for add form
  const [addFormValidation, setAddFormValidation] = useState<{valid: boolean; error?: string} | null>(null);
  const [isValidatingAdd, setIsValidatingAdd] = useState(false);

  const validateAddRegex = async () => {
    if (!formRegex.trim()) return;
    
    setIsValidatingAdd(true);
    try {
      const res = await fetch("/api/validate-regex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ regex: formRegex, test_text: "test" })
      });
      const result = await res.json();
      setAddFormValidation(result.valid ? { valid: true } : { valid: false, error: result.error });
    } catch (error: any) {
      setAddFormValidation({ valid: false, error: "Error al validar" });
    } finally {
      setIsValidatingAdd(false);
    }
  };

  const handleAdd = async () => {
    if (!formName.trim() || !formRegex.trim()) {
      toast.error("Nombre y regex son requeridos");
      return;
    }
    
    setIsSubmitting(true);
    try {
      const res = await fetch("/api/config/patterns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          name: formName, 
          regex: formRegex, 
          severity: formSeverity,
          category: formCategory 
        }),
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Error al agregar patrón");
      }
      
      toast.success("Patrón agregado exitosamente");
      setIsAddOpen(false);
      resetForm();
      setAddFormValidation(null);
      refetch();
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEdit = async () => {
    if (!selectedPattern || !formRegex.trim()) {
      toast.error("Regex es requerido");
      return;
    }
    
    setIsSubmitting(true);
    try {
      const res = await fetch(`/api/config/patterns/${encodeURIComponent(selectedPattern.name)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          regex: formRegex,
          severity: formSeverity,
          category: formCategory
        }),
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Error al editar patrón");
      }
      
      toast.success("Patrón actualizado exitosamente");
      setIsEditOpen(false);
      resetForm();
      refetch();
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!selectedPattern) return;
    
    setIsSubmitting(true);
    try {
      const res = await fetch(`/api/config/patterns/${encodeURIComponent(selectedPattern.name)}`, {
        method: "DELETE",
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Error al eliminar patrón");
      }
      
      toast.success("Patrón eliminado exitosamente");
      setIsDeleteOpen(false);
      resetForm();
      refetch();
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const openEdit = (pattern: PatternConfig) => {
    setSelectedPattern(pattern);
    setFormName(pattern.name);
    setFormRegex(pattern.regex);
    setFormSeverity(pattern.severity);
    setFormCategory(pattern.category || "OTHER");
    setIsEditOpen(true);
  };

  const openDelete = (pattern: PatternConfig) => {
    setSelectedPattern(pattern);
    setIsDeleteOpen(true);
  };

  const openView = (pattern: PatternConfig) => {
    setSelectedPattern(pattern);
    setIsViewOpen(true);
  };

  const openTest = (pattern: PatternConfig) => {
    setSelectedPattern(pattern);
    setTestText("");
    setTestResults(null);
    setIsTestOpen(true);
  };

  const testRegex = async () => {
    if (!selectedPattern) return;
    
    setIsTesting(true);
    try {
      const res = await fetch("/api/validate-regex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          regex: selectedPattern.regex,
          test_text: testText
        })
      });
      
      const result = await res.json();
      setTestResults(result);
    } catch (error: any) {
      toast.error("Error al validar regex: " + error.message);
    } finally {
      setIsTesting(false);
    }
  };

  // Truncar regex para mostrar en tabla
  const truncateRegex = (regex: string, maxLength: number = 40) => {
    if (regex.length <= maxLength) return regex;
    return regex.substring(0, maxLength) + "...";
  };

  // Agrupar patrones por categoría
  const getPatternsByCategory = () => {
    if (!data?.patterns) return {};
    
    const grouped: Record<string, PatternConfig[]> = {};
    
    // Inicializar categorías
    for (const cat of CATEGORIES) {
      grouped[cat] = [];
    }
    
    // Agregar patrones a sus categorías
    for (const pattern of data.patterns) {
      const categoryKey = pattern.category || "OTHER";
      if (!grouped[categoryKey]) grouped[categoryKey] = [];
      grouped[categoryKey].push(pattern);
    }
    
    return grouped;
  };

  const patternsByCategory = getPatternsByCategory();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Button onClick={() => { resetForm(); setIsAddOpen(true); }}>
          <Plus className="mr-2 h-4 w-4" />
          Nuevo Patrón
        </Button>
      </div>

      {loading ? (
        <Skeleton className="h-96" />
      ) : error ? (
        <div className="flex h-32 flex-col items-center justify-center gap-2 text-muted-foreground">
          <AlertCircle className="h-8 w-8 text-red-500" />
          <p>Error al cargar patrones: {error}</p>
        </div>
      ) : data?.patterns && data.patterns.length > 0 ? (
        <div className="space-y-6">
          {CATEGORIES.map((key) => {
            const patterns = patternsByCategory[key] || [];
            if (patterns.length === 0) return null;
            
            const category = CATEGORY_LABELS[key];
            const CategoryIcon = category.icon;
            
            return (
              <Card key={key}>
                <CardHeader className="pb-3">
                  <div className="flex items-center gap-2">
                    <CategoryIcon className="h-5 w-5 text-primary" />
                    <CardTitle className="text-lg">{category.label}</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Nombre del Patrón</TableHead>
                        <TableHead>Severidad</TableHead>
                        <TableHead className="max-w-md">Regex</TableHead>
                        <TableHead className="text-right">Acciones</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {patterns.map((pattern) => (
                        <TableRow key={pattern.name}>
                          <TableCell className="font-medium">
                            {pattern.name}
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={pattern.severity as any} />
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                        <code className="text-xs bg-muted px-2 py-1 rounded font-mono max-w-[200px] truncate">
                          {truncateRegex(pattern.regex)}
                        </code>
                        <Button 
                          variant="ghost" 
                          size="icon" 
                          className="h-6 w-6"
                          onClick={() => openView(pattern)}
                          title="Ver regex completo"
                        >
                          <Eye className="h-3 w-3" />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon" 
                          className="h-6 w-6 text-green-600"
                          onClick={() => openTest(pattern)}
                          title="Probar regex"
                        >
                          <Play className="h-3 w-3" />
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button 
                          variant="ghost" 
                          size="icon" 
                          onClick={() => openEdit(pattern)}
                          title="Editar"
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon" 
                          className="text-red-600 hover:text-red-700"
                          onClick={() => openDelete(pattern)}
                          title="Eliminar"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
                  </Table>
                </CardContent>
              </Card>
            );
          })}
          
          {/* Patrones sin categoría */}
          {patternsByCategory["OTHER"] && patternsByCategory["OTHER"].length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5 text-primary" />
                  <CardTitle className="text-lg">Otros</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Nombre del Patrón</TableHead>
                      <TableHead>Severidad</TableHead>
                      <TableHead className="max-w-md">Regex</TableHead>
                      <TableHead className="text-right">Acciones</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {patternsByCategory["OTHER"].map((pattern) => (
                      <TableRow key={pattern.name}>
                        <TableCell className="font-medium">
                          {pattern.name}
                        </TableCell>
                        <TableCell>
                          <SeverityBadge severity={pattern.severity as any} />
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <code className="text-xs bg-muted px-2 py-1 rounded font-mono max-w-[200px] truncate">
                              {truncateRegex(pattern.regex)}
                            </code>
                            <Button 
                              variant="ghost" 
                              size="icon" 
                              className="h-6 w-6"
                              onClick={() => openView(pattern)}
                              title="Ver regex completo"
                            >
                              <Eye className="h-3 w-3" />
                            </Button>
                            <Button 
                              variant="ghost" 
                              size="icon" 
                              className="h-6 w-6 text-green-600"
                              onClick={() => openTest(pattern)}
                              title="Probar regex"
                            >
                              <Play className="h-3 w-3" />
                            </Button>
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            <Button 
                              variant="ghost" 
                              size="icon" 
                              onClick={() => openEdit(pattern)}
                              title="Editar"
                            >
                              <Pencil className="h-4 w-4" />
                            </Button>
                            <Button 
                              variant="ghost" 
                              size="icon" 
                              className="text-red-600 hover:text-red-700"
                              onClick={() => openDelete(pattern)}
                              title="Eliminar"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </div>
      ) : (
        <Card>
          <CardContent className="flex h-32 items-center justify-center text-muted-foreground">
            No hay patrones configurados en fingerprint.yml
          </CardContent>
        </Card>
      )}

      {/* Dialog: Agregar Patrón */}
      <Dialog open={isAddOpen} onOpenChange={setIsAddOpen}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Agregar Nuevo Patrón</DialogTitle>
            <DialogDescription>
              Crea un nuevo patrón de detección en fingerprint.yml
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Nombre del Patrón</Label>
              <Input
                id="name"
                placeholder="Ej: DNI Argentina"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="regex">Expresión Regular (Regex)</Label>
              <Textarea
                id="regex"
                placeholder="Ej: \\b\\d{2}\\.\\d{3}\\.\\d{3}\\b"
                value={formRegex}
                onChange={(e) => setFormRegex(e.target.value)}
                rows={3}
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground">
                Usa sintaxis de Python regex. Las barras invertidas deben escaparse (\\d, \\w, etc.)
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="category">Categoría</Label>
              <Select value={formCategory} onValueChange={setFormCategory}>
                <SelectTrigger>
                  <SelectValue placeholder="Selecciona categoría" />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c}>{CATEGORY_LABELS[c].label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                La categoría determina cómo se clasifica el patrón
              </p>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="severity">Severidad</Label>
              <Select value={formSeverity} onValueChange={setFormSeverity}>
                <SelectTrigger>
                  <SelectValue placeholder="Selecciona severidad" />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                La severidad determina si se crea caso en The Hive (CRITICAL/HIGH)
              </p>
            </div>
            
            {/* Regex Validator */}
            <div className="space-y-2 pt-2 border-t">
              <div className="flex items-center justify-between">
                <Label>Validar Regex</Label>
                <Button 
                  type="button" 
                  variant="outline" 
                  size="sm" 
                  onClick={validateAddRegex}
                  disabled={isValidatingAdd || !formRegex}
                >
                  {isValidatingAdd ? "Validando..." : "Probar Regex"}
                </Button>
              </div>
              {addFormValidation && (
                <div className={`p-2 rounded text-sm ${addFormValidation.valid ? 'bg-green-50 text-green-700 border border-green-200' : 'bg-red-50 text-red-700 border border-red-200'}`}>
                  {addFormValidation.valid ? (
                    <span className="flex items-center gap-1"><CheckCircle className="h-4 w-4" /> Regex válida</span>
                  ) : (
                    <span className="flex items-center gap-1"><XCircle className="h-4 w-4" /> {addFormValidation.error}</span>
                  )}
                </div>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsAddOpen(false)}>
              Cancelar
            </Button>
            <Button onClick={handleAdd} disabled={isSubmitting}>
              {isSubmitting ? "Agregando..." : "Agregar Patrón"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Dialog: Editar Patrón */}
      <Dialog open={isEditOpen} onOpenChange={setIsEditOpen}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Editar Patrón</DialogTitle>
            <DialogDescription>
              Modifica la expresión regular de &quot;{selectedPattern?.name}&quot;
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Nombre (solo lectura)</Label>
              <Input value={selectedPattern?.name || ""} disabled />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-regex">Expresión Regular (Regex)</Label>
              <Textarea
                id="edit-regex"
                value={formRegex}
                onChange={(e) => setFormRegex(e.target.value)}
                rows={5}
                className="font-mono text-sm"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-category">Categoría</Label>
              <Select value={formCategory} onValueChange={setFormCategory}>
                <SelectTrigger>
                  <SelectValue placeholder="Selecciona categoría" />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c}>{CATEGORY_LABELS[c].label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="edit-severity">Severidad</Label>
              <Select value={formSeverity} onValueChange={setFormSeverity}>
                <SelectTrigger>
                  <SelectValue placeholder="Selecciona severidad" />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsEditOpen(false)}>
              Cancelar
            </Button>
            <Button onClick={handleEdit} disabled={isSubmitting}>
              {isSubmitting ? "Guardando..." : "Guardar Cambios"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Dialog: Ver Regex Completo */}
      <Dialog open={isViewOpen} onOpenChange={setIsViewOpen}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>Ver Patrón Completo</DialogTitle>
            <DialogDescription>
              {selectedPattern?.name}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div>
              <Label className="text-xs text-muted-foreground uppercase">Nombre</Label>
              <p className="font-medium">{selectedPattern?.name}</p>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground uppercase">Severidad</Label>
              <div className="mt-1">
                <SeverityBadge severity={selectedPattern?.severity as any} />
              </div>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground uppercase">Expresión Regular</Label>
              <div className="mt-1 p-3 bg-muted rounded-md">
                <code className="font-mono text-sm break-all whitespace-pre-wrap">
                  {selectedPattern?.regex}
                </code>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => setIsViewOpen(false)}>Cerrar</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Dialog: Probar Regex */}
      <Dialog open={isTestOpen} onOpenChange={setIsTestOpen}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>Validador de Regex</DialogTitle>
            <DialogDescription>
              Prueba el patrón &quot;{selectedPattern?.name}&quot; contra texto de ejemplo
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div>
              <Label className="text-xs text-muted-foreground uppercase">Regex</Label>
              <div className="mt-1 p-2 bg-muted rounded-md">
                <code className="font-mono text-sm break-all">
                  {selectedPattern?.regex}
                </code>
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="test-text">Texto de prueba</Label>
              <Textarea
                id="test-text"
                placeholder="Ingresa texto para probar el patrón..."
                value={testText}
                onChange={(e) => setTestText(e.target.value)}
                rows={4}
              />
            </div>

            <Button 
              onClick={testRegex} 
              disabled={isTesting || !testText}
              className="w-full"
            >
              {isTesting ? (
                "Probando..."
              ) : (
                <>
                  <Play className="mr-2 h-4 w-4" />
                  Probar Regex
                </>
              )}
            </Button>

            {testResults && (
              <div className={`p-4 rounded-md ${testResults.valid ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}`}>
                <div className="flex items-center gap-2 mb-2">
                  {testResults.valid ? (
                    <>
                      <CheckCircle className="h-5 w-5 text-green-600" />
                      <span className="font-medium text-green-800">Regex válida</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="h-5 w-5 text-red-600" />
                      <span className="font-medium text-red-800">Regex inválida</span>
                    </>
                  )}
                </div>
                
                {testResults.valid && (
                  <div className="space-y-2">
                    <p className="text-sm text-green-700">
                      {testResults.match_count === 0 
                        ? "No se encontraron coincidencias" 
                        : `Se encontraron ${testResults.match_count} coincidencia(s):`}
                    </p>
                    {testResults.matches && testResults.matches.length > 0 && (
                      <div className="space-y-1">
                        {testResults.matches.map((match, idx) => (
                          <div key={idx} className="p-2 bg-white rounded border border-green-200">
                            <code className="font-mono text-sm text-green-900">{match.value}</code>
                            <span className="text-xs text-green-600 ml-2">
                              (pos: {match.start}-{match.end})
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
                
                {!testResults.valid && testResults.error && (
                  <p className="text-sm text-red-700">{testResults.error}</p>
                )}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsTestOpen(false)}>
              Cerrar
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Dialog: Eliminar Patrón */}
      <Dialog open={isDeleteOpen} onOpenChange={setIsDeleteOpen}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader>
            <DialogTitle>Eliminar Patrón</DialogTitle>
            <DialogDescription>
              ¿Estás seguro de que deseas eliminar el patrón &quot;{selectedPattern?.name}&quot;?
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

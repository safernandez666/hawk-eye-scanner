"use client";

import { useState, useEffect } from "react";
import { useNotifications, updateNotificationChannel, testNotificationChannel, useOllamaConfig, updateOllamaConfig, fetchOllamaModels, useSchedulerJobs, createSchedulerJob, deleteSchedulerJob } from "@/hooks/use-api";
import type { SchedulerJob } from "@/types";
import type { NotificationChannel, OllamaConfig } from "@/types";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Mail, MessageSquare, Globe, Send, Save, Loader2, Plug, Bot, Clock, Bell, Cpu, Trash2, X } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";

// Icono personalizado de abeja para TheHive
const BeeIcon = ({ className }: { className?: string }) => (
  <svg 
    className={className} 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2" 
    strokeLinecap="round" 
    strokeLinejoin="round"
  >
    <path d="M12 2a4 4 0 0 0-4 4c0 2.5 2 4 4 5 2-1 4-2.5 4-5a4 4 0 0 0-4-4z" />
    <path d="M8 10c-2 0-4 2-4 4s2 4 4 4" />
    <path d="M16 10c2 0 4 2 4 4s-2 4-4 4" />
    <path d="M8 14h8" />
    <path d="M8 17h8" />
    <path d="M6 8l-2 3" />
    <path d="M18 8l2 3" />
  </svg>
);
import { toast } from "sonner";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const CHANNEL_META: Record<string, { label: string; icon: React.ElementType; description: string }> = {
  thehive: { label: "The Hive", icon: BeeIcon, description: "Integracion SOAR - creacion automatica de casos" },
  smtp: { label: "SMTP (Email)", icon: Mail, description: "Enviar reportes por correo electronico" },
  slack: { label: "Slack", icon: MessageSquare, description: "Notificaciones via Slack webhook" },
  teams: { label: "Teams", icon: MessageSquare, description: "Notificaciones via Microsoft Teams webhook" },
  webhook: { label: "Webhook", icon: Globe, description: "POST/PUT generico a cualquier URL" },
};

const SMTP_FIELDS = [
  { name: "host", label: "Host SMTP", type: "text", placeholder: "smtp.gmail.com" },
  { name: "port", label: "Puerto", type: "number", placeholder: "587" },
  { name: "username", label: "Usuario", type: "text", placeholder: "user@example.com" },
  { name: "password", label: "Password", type: "password", placeholder: "********" },
  { name: "from_address", label: "Remitente (email)", type: "text", placeholder: "alerts@example.com" },
  { name: "from_name", label: "Alias del remitente", type: "text", placeholder: "Poirot Security" },
  { name: "to_addresses", label: "Destinatarios (separados por coma)", type: "text", placeholder: "admin@example.com, security@example.com" },
];

const SLACK_FIELDS = [
  { name: "webhook_url", label: "Webhook URL", type: "text", placeholder: "https://hooks.slack.com/services/..." },
];

const TEAMS_FIELDS = [
  { name: "webhook_url", label: "Webhook URL", type: "text", placeholder: "https://outlook.office.com/webhook/..." },
];

const WEBHOOK_FIELDS = [
  { name: "url", label: "URL", type: "text", placeholder: "https://api.example.com/alerts" },
  { name: "method", label: "Metodo HTTP", type: "text", placeholder: "POST" },
];

const THEHIVE_FIELDS = [
  { name: "url", label: "TheHive URL", type: "text", placeholder: "http://thehive:9000" },
  { name: "api_key", label: "API Key", type: "password", placeholder: "Tu API key de TheHive" },
];

const CHANNEL_FIELDS: Record<string, typeof SMTP_FIELDS> = {
  thehive: THEHIVE_FIELDS,
  smtp: SMTP_FIELDS,
  slack: SLACK_FIELDS,
  teams: TEAMS_FIELDS,
  webhook: WEBHOOK_FIELDS,
};

function getDefaultChannel(name: string): NotificationChannel {
  const base: NotificationChannel = { enabled: false, severity_filter: ["CRITICAL", "HIGH", "MEDIUM"] };
  if (name === "thehive") {
    return { ...base, url: "http://thehive:9000", api_key: "", create_cases: true, severity_filter: ["CRITICAL", "HIGH"] };
  }
  if (name === "smtp") {
    return { ...base, host: "", port: 587, use_tls: true, username: "", password: "", from_address: "", from_name: "", to_addresses: "", severity_filter: ["CRITICAL", "HIGH"] };
  }
  if (name === "slack" || name === "teams") {
    return { ...base, webhook_url: "" };
  }
  return { ...base, url: "", method: "POST", headers: { "Content-Type": "application/json" }, severity_filter: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] };
}

const INTERVAL_OPTIONS = [
  { value: "1", label: "Cada 1 hora" },
  { value: "6", label: "Cada 6 horas" },
  { value: "12", label: "Cada 12 horas" },
  { value: "24", label: "Cada 24 horas (diario)" },
  { value: "168", label: "Cada 168 horas (semanal)" },
];

export default function SettingsPage() {
  const { data, loading, refetch } = useNotifications();
  const { data: ollamaData, loading: ollamaLoading, refetch: refetchOllama } = useOllamaConfig();
  
  const [localChannels, setLocalChannels] = useState<Record<string, NotificationChannel>>({});
  const [saving, setSaving] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("integrations");

  // Ollama state
  const [ollamaConfig, setOllamaConfig] = useState<OllamaConfig>({ enabled: false, url: "http://ollama:11434", model: "llama3.2:3b" });
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [savingOllama, setSavingOllama] = useState(false);

  // Scheduler state (multi-job)
  const { data: jobsData, loading: jobsLoading, refetch: refetchJobs } = useSchedulerJobs();
  const [showNewJobForm, setShowNewJobForm] = useState(false);
  const [newJobName, setNewJobName] = useState("");
  const [newJobType, setNewJobType] = useState<'interval' | 'cron'>('interval');
  const [newJobInterval, setNewJobInterval] = useState("24");
  const [newJobCronDay, setNewJobCronDay] = useState("1");
  const [newJobCronHour, setNewJobCronHour] = useState("9");
  const [newJobSources, setNewJobSources] = useState<string[]>([]);
  const [savingJob, setSavingJob] = useState(false);
  const [deletingJobId, setDeletingJobId] = useState<string | null>(null);
  const [jobToDelete, setJobToDelete] = useState<SchedulerJob | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  useEffect(() => {
    if (data?.channels) {
      const merged: Record<string, NotificationChannel> = {};
      for (const name of ["thehive", "smtp", "slack", "teams", "webhook"]) {
        merged[name] = { ...getDefaultChannel(name), ...data.channels[name] };
      }
      setLocalChannels(merged);
    }
  }, [data]);

  useEffect(() => {
    if (ollamaData) {
      setOllamaConfig({
        enabled: ollamaData.enabled ?? false,
        url: ollamaData.url || "http://ollama:11434",
        model: ollamaData.model || "llama3.2:3b",
      });
    }
  }, [ollamaData]);



  const updateField = (channel: string, field: string, value: unknown) => {
    setLocalChannels((prev) => ({
      ...prev,
      [channel]: { ...prev[channel], [field]: value },
    }));
  };

  const toggleSeverity = (channel: string, severity: string) => {
    setLocalChannels((prev) => {
      const current = prev[channel]?.severity_filter || [];
      const next = current.includes(severity)
        ? current.filter((s) => s !== severity)
        : [...current, severity];
      return { ...prev, [channel]: { ...prev[channel], severity_filter: next } };
    });
  };

  const handleSave = async (channel: string) => {
    setSaving(channel);
    try {
      const result = await updateNotificationChannel(channel, localChannels[channel]);
      toast.success(`Canal "${CHANNEL_META[channel].label}" guardado`);
      if (result?.restart_required) {
        toast.message("Reinicio requerido", {
          description: "Reinicia los contenedores para aplicar los cambios (dashboard y hawk-scanner).",
        });
      }
      refetch();
    } catch (err: any) {
      toast.error(err.message || "Error al guardar");
    } finally {
      setSaving(null);
    }
  };

  const handleTest = async (channel: string) => {
    setTesting(channel);
    try {
      const result = await testNotificationChannel(channel, localChannels[channel]);
      if (result.status === "sent") {
        if (channel === "thehive") {
          toast.success(`Conexión exitosa con "${CHANNEL_META[channel].label}"`);
        } else {
          toast.success(`Prueba enviandose por "${CHANNEL_META[channel].label}" (puede demorar unos segundos)`);
        }
      } else {
        toast.error(`Error: ${result.error || "Fallo al conectar"}`);
      }
    } catch (err: any) {
      toast.error(err.message || "Error al conectar");
    } finally {
      setTesting(null);
    }
  };

  const handleLoadModels = async () => {
    setLoadingModels(true);
    try {
      const result = await fetchOllamaModels(ollamaConfig.url);
      setOllamaModels(result.models || []);
      if (result.models?.length > 0) {
        toast.success(`${result.models.length} modelos encontrados`);
      } else {
        toast.warning("No se encontraron modelos en el servidor");
      }
    } catch {
      toast.error("No se pudo conectar con Ollama");
      setOllamaModels([]);
    } finally {
      setLoadingModels(false);
    }
  };

  const handleSaveOllama = async () => {
    setSavingOllama(true);
    try {
      const result = await updateOllamaConfig(ollamaConfig);
      toast.success("Configuracion de Ollama guardada");
      if (result?.restart_required) {
        toast.message("Reinicio requerido", {
          description: "Reinicia los contenedores para aplicar los cambios (dashboard y hawk-scanner).",
        });
      }
      refetchOllama();
    } catch (err: any) {
      toast.error(err.message || "Error al guardar");
    } finally {
      setSavingOllama(false);
    }
  };

  const handleCreateJob = async () => {
    if (!newJobName.trim()) {
      toast.error("El nombre es obligatorio");
      return;
    }
    
    setSavingJob(true);
    try {
      const job: any = {
        name: newJobName,
        schedule_type: newJobType,
        sources: newJobSources,
        enabled: true,
      };
      
      if (newJobType === 'interval') {
        job.interval_hours = Number(newJobInterval);
      } else {
        job.cron_expression = `0 ${newJobCronHour} * * ${newJobCronDay}`;
      }
      
      await createSchedulerJob(job);
      toast.success("Tarea creada");
      setShowNewJobForm(false);
      setNewJobName("");
      setNewJobSources([]);
      refetchJobs();
    } catch (err: any) {
      toast.error(err.message || "Error al crear tarea");
    } finally {
      setSavingJob(false);
    }
  };

  const openDeleteModal = (job: SchedulerJob) => {
    setJobToDelete(job);
    setShowDeleteModal(true);
  };

  const handleDeleteJob = async () => {
    if (!jobToDelete) return;
    
    setDeletingJobId(jobToDelete.id);
    try {
      await deleteSchedulerJob(jobToDelete.id);
      toast.success("Tarea eliminada");
      setShowDeleteModal(false);
      setJobToDelete(null);
      refetchJobs();
    } catch (err: any) {
      toast.error(err.message || "Error al eliminar");
    } finally {
      setDeletingJobId(null);
    }
  };

  if (loading || ollamaLoading || jobsLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="flex flex-wrap gap-1 h-auto w-full">
          <TabsTrigger value="integrations" className="flex items-center gap-2">
            <Plug className="h-4 w-4" />
            Integraciones
          </TabsTrigger>
          <TabsTrigger value="notifications" className="flex items-center gap-2">
            <Bell className="h-4 w-4" />
            Notificaciones
          </TabsTrigger>
          <TabsTrigger value="automations" className="flex items-center gap-2">
            <Cpu className="h-4 w-4" />
            Automatizaciones
          </TabsTrigger>
        </TabsList>

        {/* INTEGRACIONES TAB */}
        <TabsContent value="integrations" className="space-y-6">
          <div className="grid gap-6">
            {/* TheHive Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <BeeIcon className="h-5 w-5" />
                    <CardTitle>The Hive</CardTitle>
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="thehive-enabled" className="text-sm">
                      {localChannels.thehive?.enabled ? "Habilitado" : "Deshabilitado"}
                    </Label>
                    <Switch
                      id="thehive-enabled"
                      checked={localChannels.thehive?.enabled ?? false}
                      onCheckedChange={(v) => updateField("thehive", "enabled", v)}
                    />
                  </div>
                </div>
                <CardDescription>Integracion SOAR - creacion automatica de casos</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4 sm:grid-cols-2">
                  {THEHIVE_FIELDS.map((field) => (
                    <div key={field.name} className="space-y-2">
                      <Label htmlFor={`thehive-${field.name}`}>{field.label}</Label>
                      <Input
                        id={`thehive-${field.name}`}
                        type={field.type}
                        placeholder={field.placeholder}
                        value={(localChannels.thehive as any)?.[field.name] ?? ""}
                        onChange={(e) =>
                          updateField("thehive", field.name, field.type === "number" ? Number(e.target.value) : e.target.value)
                        }
                      />
                    </div>
                  ))}
                </div>
                <div className="space-y-3">
                  <Label>Filtro de severidad</Label>
                  <div className="flex flex-wrap gap-3">
                    {SEVERITIES.map((sev) => {
                      const checked = localChannels.thehive?.severity_filter?.includes(sev) ?? false;
                      return (
                        <div key={sev} className="flex items-center gap-2">
                          <Checkbox
                            id={`thehive-sev-${sev}`}
                            checked={checked}
                            onCheckedChange={() => toggleSeverity("thehive", sev)}
                          />
                          <Label htmlFor={`thehive-sev-${sev}`}>
                            <Badge variant="outline" className={sev === "CRITICAL" ? "border-red-600 text-red-600" : sev === "HIGH" ? "border-orange-500 text-orange-500" : sev === "MEDIUM" ? "border-yellow-500 text-yellow-500" : "border-green-500 text-green-500"}>
                              {sev}
                            </Badge>
                          </Label>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="flex gap-3">
                  <Button onClick={() => handleSave("thehive")} disabled={saving === "thehive"}>
                    {saving === "thehive" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                    Guardar
                  </Button>
                  <Button variant="outline" onClick={() => handleTest("thehive")} disabled={testing === "thehive" || !localChannels.thehive?.enabled}>
                    {testing === "thehive" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plug className="mr-2 h-4 w-4" />}
                    Conectar
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Ollama Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Bot className="h-5 w-5" />
                    <CardTitle>AI (Ollama)</CardTitle>
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="ollama-enabled" className="text-sm">{ollamaConfig.enabled ? "Habilitado" : "Deshabilitado"}</Label>
                    <Switch id="ollama-enabled" checked={ollamaConfig.enabled} onCheckedChange={(v) => setOllamaConfig((prev) => ({ ...prev, enabled: v }))} />
                  </div>
                </div>
                <CardDescription>Genera emails HTML profesionales con analisis contextual usando IA</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2 sm:col-span-2">
                    <Label htmlFor="ollama-url">URL del servidor Ollama</Label>
                    <div className="flex gap-2">
                      <Input id="ollama-url" type="text" placeholder="http://ollama:11434" value={ollamaConfig.url} onChange={(e) => setOllamaConfig((prev) => ({ ...prev, url: e.target.value }))} className="flex-1" />
                      <Button variant="outline" onClick={handleLoadModels} disabled={loadingModels}>
                        {loadingModels ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Globe className="mr-2 h-4 w-4" />}
                        Cargar Modelos
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-2 sm:col-span-2">
                    <Label htmlFor="ollama-model">Modelo</Label>
                    {ollamaModels.length > 0 ? (
                      <Select value={ollamaConfig.model} onValueChange={(v) => setOllamaConfig((prev) => ({ ...prev, model: v }))}>
                        <SelectTrigger id="ollama-model"><SelectValue placeholder="Seleccionar modelo" /></SelectTrigger>
                        <SelectContent>{ollamaModels.map((m) => (<SelectItem key={m} value={m}>{m}</SelectItem>))}</SelectContent>
                      </Select>
                    ) : (
                      <Input id="ollama-model" type="text" placeholder="llama3.2:3b" value={ollamaConfig.model} onChange={(e) => setOllamaConfig((prev) => ({ ...prev, model: e.target.value }))} />
                    )}
                  </div>
                </div>
                <div className="flex gap-3">
                  <Button onClick={handleSaveOllama} disabled={savingOllama}>
                    {savingOllama ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                    Guardar
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* NOTIFICACIONES TAB */}
        <TabsContent value="notifications" className="space-y-6">
          <div className="grid gap-6">
            {/* SMTP Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Mail className="h-5 w-5" />
                    <CardTitle>SMTP (Email)</CardTitle>
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="smtp-enabled" className="text-sm">{localChannels.smtp?.enabled ? "Habilitado" : "Deshabilitado"}</Label>
                    <Switch id="smtp-enabled" checked={localChannels.smtp?.enabled ?? false} onCheckedChange={(v) => updateField("smtp", "enabled", v)} />
                  </div>
                </div>
                <CardDescription>Enviar reportes por correo electronico</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4 sm:grid-cols-2">
                  {SMTP_FIELDS.map((field) => (
                    <div key={field.name} className="space-y-2">
                      <Label htmlFor={`smtp-${field.name}`}>{field.label}</Label>
                      <Input id={`smtp-${field.name}`} type={field.type} placeholder={field.placeholder} value={(localChannels.smtp as any)?.[field.name] ?? ""} onChange={(e) => updateField("smtp", field.name, field.type === "number" ? Number(e.target.value) : e.target.value)} />
                    </div>
                  ))}
                  <div className="flex items-center gap-2 sm:col-span-2">
                    <Checkbox id="smtp-tls" checked={localChannels.smtp?.use_tls ?? true} onCheckedChange={(v) => updateField("smtp", "use_tls", !!v)} />
                    <Label htmlFor="smtp-tls">Usar TLS</Label>
                  </div>
                </div>
                <div className="space-y-3">
                  <Label>Filtro de severidad</Label>
                  <div className="flex flex-wrap gap-3">
                    {SEVERITIES.map((sev) => {
                      const checked = localChannels.smtp?.severity_filter?.includes(sev) ?? false;
                      return (
                        <div key={sev} className="flex items-center gap-2">
                          <Checkbox id={`smtp-sev-${sev}`} checked={checked} onCheckedChange={() => toggleSeverity("smtp", sev)} />
                          <Label htmlFor={`smtp-sev-${sev}`}>
                            <Badge variant="outline" className={sev === "CRITICAL" ? "border-red-600 text-red-600" : sev === "HIGH" ? "border-orange-500 text-orange-500" : sev === "MEDIUM" ? "border-yellow-500 text-yellow-500" : "border-green-500 text-green-500"}>{sev}</Badge>
                          </Label>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="flex gap-3">
                  <Button onClick={() => handleSave("smtp")} disabled={saving === "smtp"}>
                    {saving === "smtp" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                    Guardar
                  </Button>
                  <Button variant="outline" onClick={() => handleTest("smtp")} disabled={testing === "smtp" || !localChannels.smtp?.enabled}>
                    {testing === "smtp" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
                    Enviar Prueba
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Slack Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <MessageSquare className="h-5 w-5" />
                    <CardTitle>Slack</CardTitle>
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="slack-enabled" className="text-sm">{localChannels.slack?.enabled ? "Habilitado" : "Deshabilitado"}</Label>
                    <Switch id="slack-enabled" checked={localChannels.slack?.enabled ?? false} onCheckedChange={(v) => updateField("slack", "enabled", v)} />
                  </div>
                </div>
                <CardDescription>Notificaciones via Slack webhook</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="slack-webhook_url">Webhook URL</Label>
                  <Input id="slack-webhook_url" type="text" placeholder="https://hooks.slack.com/services/..." value={(localChannels.slack as any)?.webhook_url ?? ""} onChange={(e) => updateField("slack", "webhook_url", e.target.value)} />
                </div>
                <div className="space-y-3">
                  <Label>Filtro de severidad</Label>
                  <div className="flex flex-wrap gap-3">
                    {SEVERITIES.map((sev) => {
                      const checked = localChannels.slack?.severity_filter?.includes(sev) ?? false;
                      return (
                        <div key={sev} className="flex items-center gap-2">
                          <Checkbox id={`slack-sev-${sev}`} checked={checked} onCheckedChange={() => toggleSeverity("slack", sev)} />
                          <Label htmlFor={`slack-sev-${sev}`}>
                            <Badge variant="outline" className={sev === "CRITICAL" ? "border-red-600 text-red-600" : sev === "HIGH" ? "border-orange-500 text-orange-500" : sev === "MEDIUM" ? "border-yellow-500 text-yellow-500" : "border-green-500 text-green-500"}>{sev}</Badge>
                          </Label>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="flex gap-3">
                  <Button onClick={() => handleSave("slack")} disabled={saving === "slack"}>
                    {saving === "slack" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                    Guardar
                  </Button>
                  <Button variant="outline" onClick={() => handleTest("slack")} disabled={testing === "slack" || !localChannels.slack?.enabled}>
                    {testing === "slack" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
                    Enviar Prueba
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Teams Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <MessageSquare className="h-5 w-5" />
                    <CardTitle>Microsoft Teams</CardTitle>
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="teams-enabled" className="text-sm">{localChannels.teams?.enabled ? "Habilitado" : "Deshabilitado"}</Label>
                    <Switch id="teams-enabled" checked={localChannels.teams?.enabled ?? false} onCheckedChange={(v) => updateField("teams", "enabled", v)} />
                  </div>
                </div>
                <CardDescription>Notificaciones via Microsoft Teams webhook</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="teams-webhook_url">Webhook URL</Label>
                  <Input id="teams-webhook_url" type="text" placeholder="https://outlook.office.com/webhook/..." value={(localChannels.teams as any)?.webhook_url ?? ""} onChange={(e) => updateField("teams", "webhook_url", e.target.value)} />
                </div>
                <div className="space-y-3">
                  <Label>Filtro de severidad</Label>
                  <div className="flex flex-wrap gap-3">
                    {SEVERITIES.map((sev) => {
                      const checked = localChannels.teams?.severity_filter?.includes(sev) ?? false;
                      return (
                        <div key={sev} className="flex items-center gap-2">
                          <Checkbox id={`teams-sev-${sev}`} checked={checked} onCheckedChange={() => toggleSeverity("teams", sev)} />
                          <Label htmlFor={`teams-sev-${sev}`}>
                            <Badge variant="outline" className={sev === "CRITICAL" ? "border-red-600 text-red-600" : sev === "HIGH" ? "border-orange-500 text-orange-500" : sev === "MEDIUM" ? "border-yellow-500 text-yellow-500" : "border-green-500 text-green-500"}>{sev}</Badge>
                          </Label>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="flex gap-3">
                  <Button onClick={() => handleSave("teams")} disabled={saving === "teams"}>
                    {saving === "teams" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                    Guardar
                  </Button>
                  <Button variant="outline" onClick={() => handleTest("teams")} disabled={testing === "teams" || !localChannels.teams?.enabled}>
                    {testing === "teams" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
                    Enviar Prueba
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Webhook Card */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Globe className="h-5 w-5" />
                    <CardTitle>Webhook</CardTitle>
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="webhook-enabled" className="text-sm">{localChannels.webhook?.enabled ? "Habilitado" : "Deshabilitado"}</Label>
                    <Switch id="webhook-enabled" checked={localChannels.webhook?.enabled ?? false} onCheckedChange={(v) => updateField("webhook", "enabled", v)} />
                  </div>
                </div>
                <CardDescription>POST/PUT generico a cualquier URL</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4 sm:grid-cols-2">
                  {WEBHOOK_FIELDS.map((field) => (
                    <div key={field.name} className="space-y-2">
                      <Label htmlFor={`webhook-${field.name}`}>{field.label}</Label>
                      <Input id={`webhook-${field.name}`} type={field.type} placeholder={field.placeholder} value={(localChannels.webhook as any)?.[field.name] ?? ""} onChange={(e) => updateField("webhook", field.name, field.type === "number" ? Number(e.target.value) : e.target.value)} />
                    </div>
                  ))}
                </div>
                <div className="space-y-3">
                  <Label>Filtro de severidad</Label>
                  <div className="flex flex-wrap gap-3">
                    {SEVERITIES.map((sev) => {
                      const checked = localChannels.webhook?.severity_filter?.includes(sev) ?? false;
                      return (
                        <div key={sev} className="flex items-center gap-2">
                          <Checkbox id={`webhook-sev-${sev}`} checked={checked} onCheckedChange={() => toggleSeverity("webhook", sev)} />
                          <Label htmlFor={`webhook-sev-${sev}`}>
                            <Badge variant="outline" className={sev === "CRITICAL" ? "border-red-600 text-red-600" : sev === "HIGH" ? "border-orange-500 text-orange-500" : sev === "MEDIUM" ? "border-yellow-500 text-yellow-500" : "border-green-500 text-green-500"}>{sev}</Badge>
                          </Label>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="flex gap-3">
                  <Button onClick={() => handleSave("webhook")} disabled={saving === "webhook"}>
                    {saving === "webhook" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                    Guardar
                  </Button>
                  <Button variant="outline" onClick={() => handleTest("webhook")} disabled={testing === "webhook" || !localChannels.webhook?.enabled}>
                    {testing === "webhook" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
                    Enviar Prueba
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* AUTOMATIZACIONES TAB - Multi-Job Scheduler */}
        <TabsContent value="automations" className="space-y-6">
          {/* Lista de tareas existentes */}
          {jobsData?.jobs && jobsData.jobs.length > 0 && (
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Tareas Programadas</h3>
              {jobsData.jobs.map((job) => (
                <Card key={job.id}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4 text-muted-foreground" />
                          <span className="font-medium">{job.name}</span>
                          {job.schedule_type === 'interval' ? (
                            <Badge variant="outline">⏱️ Cada {job.interval_hours}h</Badge>
                          ) : (
                            <Badge variant="outline">📅 {job.cron_expression}</Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <span>Fuentes: {job.sources.length > 0 ? job.sources.join(', ') : 'Todas'}</span>
                          {job.next_run && (
                            <>
                              <span>•</span>
                              <span>Proximo: {new Date(job.next_run).toLocaleString()}</span>
                            </>
                          )}
                        </div>
                      </div>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => openDeleteModal(job)}
                        disabled={deletingJobId === job.id}
                      >
                        {deletingJobId === job.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* Formulario para nueva tarea */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  <CardTitle>Nueva Tarea Programada</CardTitle>
                </div>
                <Button variant="outline" onClick={() => setShowNewJobForm(!showNewJobForm)}>
                  {showNewJobForm ? 'Cancelar' : 'Agregar Tarea'}
                </Button>
              </div>
              <CardDescription>
                Programa escaneos automaticos para ejecutarse periodicamente
              </CardDescription>
            </CardHeader>
            {showNewJobForm && (
              <CardContent className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="job-name">Nombre de la tarea</Label>
                  <Input
                    id="job-name"
                    placeholder="Ej: Escaneo MySQL diario"
                    value={newJobName}
                    onChange={(e) => setNewJobName(e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Tipo de programacion</Label>
                  <Select value={newJobType} onValueChange={(v) => setNewJobType(v as 'interval' | 'cron')}>
                    <SelectTrigger>
                      <SelectValue placeholder="Seleccionar tipo" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="interval">⏱️ Intervalo regular</SelectItem>
                      <SelectItem value="cron">📅 Horario especifico</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Seleccion de fuentes */}
                <div className="space-y-3">
                  <Label>Fuentes a escanear</Label>
                  <div className="flex flex-wrap gap-4">
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="newjob-mysql"
                        checked={newJobSources.includes('mysql')}
                        onCheckedChange={(checked) => {
                          if (checked) {
                            setNewJobSources([...newJobSources, 'mysql']);
                          } else {
                            setNewJobSources(newJobSources.filter(s => s !== 'mysql'));
                          }
                        }}
                      />
                      <Label htmlFor="newjob-mysql" className="cursor-pointer">🗄️ MySQL</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="newjob-s3"
                        checked={newJobSources.includes('s3')}
                        onCheckedChange={(checked) => {
                          if (checked) {
                            setNewJobSources([...newJobSources, 's3']);
                          } else {
                            setNewJobSources(newJobSources.filter(s => s !== 's3'));
                          }
                        }}
                      />
                      <Label htmlFor="newjob-s3" className="cursor-pointer">☁️ Amazon S3</Label>
                    </div>
                  </div>
                  {newJobSources.length === 0 && (
                    <p className="text-xs text-muted-foreground">
                      Si no seleccionas ninguna fuente, se escanearan todas.
                    </p>
                  )}
                </div>

                {newJobType === 'interval' ? (
                  <div className="space-y-2">
                    <Label htmlFor="newjob-interval">Frecuencia de escaneo</Label>
                    <Select value={newJobInterval} onValueChange={setNewJobInterval}>
                      <SelectTrigger id="newjob-interval">
                        <SelectValue placeholder="Seleccionar intervalo" />
                      </SelectTrigger>
                      <SelectContent>
                        {INTERVAL_OPTIONS.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                ) : (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Dia de la semana</Label>
                      <Select value={newJobCronDay} onValueChange={setNewJobCronDay}>
                        <SelectTrigger>
                          <SelectValue placeholder="Seleccionar dia" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="0">Domingo</SelectItem>
                          <SelectItem value="1">Lunes</SelectItem>
                          <SelectItem value="2">Martes</SelectItem>
                          <SelectItem value="3">Miercoles</SelectItem>
                          <SelectItem value="4">Jueves</SelectItem>
                          <SelectItem value="5">Viernes</SelectItem>
                          <SelectItem value="6">Sabado</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Hora (24h)</Label>
                      <Select value={newJobCronHour} onValueChange={setNewJobCronHour}>
                        <SelectTrigger>
                          <SelectValue placeholder="Seleccionar hora" />
                        </SelectTrigger>
                        <SelectContent>
                          {Array.from({length: 24}, (_, i) => (
                            <SelectItem key={i} value={String(i)}>{String(i).padStart(2, '0')}:00</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                )}

                <div className="flex gap-3 pt-2">
                  <Button onClick={handleCreateJob} disabled={savingJob}>
                    {savingJob ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Save className="mr-2 h-4 w-4" />
                    )}
                    Crear Tarea
                  </Button>
                </div>
              </CardContent>
            )}
          </Card>

          {!jobsData?.jobs?.length && !showNewJobForm && (
            <div className="text-center py-8 text-muted-foreground">
              <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No hay tareas programadas</p>
              <p className="text-sm">Haz clic en &quot;Agregar Tarea&quot; para crear una</p>
            </div>
          )}

          {/* Modal de confirmacion para eliminar */}
          <Dialog open={showDeleteModal} onOpenChange={setShowDeleteModal}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Confirmar eliminacion</DialogTitle>
                <DialogDescription>
                  ¿Estas seguro de que deseas eliminar la tarea &quot;{jobToDelete?.name}&quot;?
                  <br /><br />
                  Esta accion no se puede deshacer.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter className="flex gap-3">
                <Button variant="outline" onClick={() => setShowDeleteModal(false)}>
                  Cancelar
                </Button>
                <Button variant="destructive" onClick={handleDeleteJob} disabled={deletingJobId !== null}>
                  {deletingJobId ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="mr-2 h-4 w-4" />
                  )}
                  Eliminar
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </TabsContent>
      </Tabs>
    </div>
  );
}

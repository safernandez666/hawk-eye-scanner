"use client";

import { useState, useEffect } from "react";
import { useNotifications, updateNotificationChannel, testNotificationChannel, useOllamaConfig, updateOllamaConfig, fetchOllamaModels, useSchedulerConfig, updateSchedulerConfig } from "@/hooks/use-api";
import type { NotificationChannel, OllamaConfig, SchedulerConfig } from "@/types";
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
import { Mail, MessageSquare, Globe, Send, Save, Loader2, Plug, Bot, Clock } from "lucide-react";

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
  const { data: schedulerData, loading: schedulerLoading, refetch: refetchScheduler } = useSchedulerConfig();
  const [localChannels, setLocalChannels] = useState<Record<string, NotificationChannel>>({});
  const [saving, setSaving] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("thehive");

  // Ollama state
  const [ollamaConfig, setOllamaConfig] = useState<OllamaConfig>({ enabled: false, url: "http://ollama:11434", model: "llama3.2:3b" });
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [savingOllama, setSavingOllama] = useState(false);

  // Scheduler state
  const [schedulerEnabled, setSchedulerEnabled] = useState(false);
  const [schedulerInterval, setSchedulerInterval] = useState("24");
  const [savingScheduler, setSavingScheduler] = useState(false);

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

  useEffect(() => {
    if (schedulerData) {
      setSchedulerEnabled(schedulerData.enabled ?? false);
      setSchedulerInterval(String(schedulerData.interval_hours ?? 24));
    }
  }, [schedulerData]);

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
      await updateNotificationChannel(channel, localChannels[channel]);
      toast.success(`Canal "${CHANNEL_META[channel].label}" guardado`);
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
      await updateOllamaConfig(ollamaConfig);
      toast.success("Configuracion de Ollama guardada");
      refetchOllama();
    } catch (err: any) {
      toast.error(err.message || "Error al guardar");
    } finally {
      setSavingOllama(false);
    }
  };

  const handleSaveScheduler = async () => {
    setSavingScheduler(true);
    try {
      await updateSchedulerConfig({
        enabled: schedulerEnabled,
        interval_hours: Number(schedulerInterval),
      });
      toast.success("Scheduler actualizado");
      refetchScheduler();
    } catch (err: any) {
      toast.error(err.message || "Error al guardar");
    } finally {
      setSavingScheduler(false);
    }
  };

  if (loading || ollamaLoading || schedulerLoading) {
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
          {Object.entries(CHANNEL_META).map(([key, meta]) => (
            <TabsTrigger key={key} value={key} className="flex items-center gap-2">
              <meta.icon className="h-4 w-4" />
              {meta.label}
            </TabsTrigger>
          ))}
          <TabsTrigger value="ollama" className="flex items-center gap-2">
            <Bot className="h-4 w-4" />
            AI (Ollama)
          </TabsTrigger>
          <TabsTrigger value="scheduler" className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Scheduler
          </TabsTrigger>
        </TabsList>

        {Object.entries(CHANNEL_META).map(([channelName, meta]) => {
          const ch = localChannels[channelName] || getDefaultChannel(channelName);
          const fields = CHANNEL_FIELDS[channelName] || [];

          return (
            <TabsContent key={channelName} value={channelName}>
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <meta.icon className="h-5 w-5" />
                      <CardTitle>{meta.label}</CardTitle>
                    </div>
                    <div className="flex items-center gap-2">
                      <Label htmlFor={`${channelName}-enabled`} className="text-sm">
                        {ch.enabled ? "Habilitado" : "Deshabilitado"}
                      </Label>
                      <Switch
                        id={`${channelName}-enabled`}
                        checked={ch.enabled}
                        onCheckedChange={(v) => updateField(channelName, "enabled", v)}
                      />
                    </div>
                  </div>
                  <CardDescription>{meta.description}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Fields */}
                  <div className="grid gap-4 sm:grid-cols-2">
                    {fields.map((field) => (
                      <div key={field.name} className="space-y-2">
                        <Label htmlFor={`${channelName}-${field.name}`}>{field.label}</Label>
                        <Input
                          id={`${channelName}-${field.name}`}
                          type={field.type}
                          placeholder={field.placeholder}
                          value={(ch as any)[field.name] ?? ""}
                          onChange={(e) =>
                            updateField(
                              channelName,
                              field.name,
                              field.type === "number" ? Number(e.target.value) : e.target.value
                            )
                          }
                        />
                      </div>
                    ))}
                    {channelName === "smtp" && (
                      <div className="flex items-center gap-2 sm:col-span-2">
                        <Checkbox
                          id={`${channelName}-tls`}
                          checked={ch.use_tls ?? true}
                          onCheckedChange={(v) => updateField(channelName, "use_tls", !!v)}
                        />
                        <Label htmlFor={`${channelName}-tls`}>Usar TLS</Label>
                      </div>
                    )}
                  </div>

                  {/* Severity filter */}
                  <div className="space-y-3">
                    <Label>Filtro de severidad</Label>
                    <p className="text-sm text-muted-foreground">
                      Solo se enviaran notificaciones para las severidades seleccionadas
                    </p>
                    <div className="flex flex-wrap gap-3">
                      {SEVERITIES.map((sev) => {
                        const checked = ch.severity_filter?.includes(sev) ?? false;
                        return (
                          <div key={sev} className="flex items-center gap-2">
                            <Checkbox
                              id={`${channelName}-sev-${sev}`}
                              checked={checked}
                              onCheckedChange={() => toggleSeverity(channelName, sev)}
                            />
                            <Label htmlFor={`${channelName}-sev-${sev}`}>
                              <Badge
                                variant="outline"
                                className={
                                  sev === "CRITICAL"
                                    ? "border-red-600 text-red-600"
                                    : sev === "HIGH"
                                      ? "border-orange-500 text-orange-500"
                                      : sev === "MEDIUM"
                                        ? "border-yellow-500 text-yellow-500"
                                        : "border-green-500 text-green-500"
                                }
                              >
                                {sev}
                              </Badge>
                            </Label>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-3 pt-2">
                    <Button onClick={() => handleSave(channelName)} disabled={saving === channelName}>
                      {saving === channelName ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Save className="mr-2 h-4 w-4" />
                      )}
                      Guardar
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => handleTest(channelName)}
                      disabled={testing === channelName || ch.enabled !== true}
                    >
                      {testing === channelName ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : channelName === "thehive" ? (
                        <Plug className="mr-2 h-4 w-4" />
                      ) : (
                        <Send className="mr-2 h-4 w-4" />
                      )}
                      {channelName === "thehive" ? "Conectar" : "Enviar Prueba"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          );
        })}

        {/* Ollama Tab */}
        <TabsContent value="ollama">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Bot className="h-5 w-5" />
                  <CardTitle>AI (Ollama)</CardTitle>
                </div>
                <div className="flex items-center gap-2">
                  <Label htmlFor="ollama-enabled" className="text-sm">
                    {ollamaConfig.enabled ? "Habilitado" : "Deshabilitado"}
                  </Label>
                  <Switch
                    id="ollama-enabled"
                    checked={ollamaConfig.enabled}
                    onCheckedChange={(v) => setOllamaConfig((prev) => ({ ...prev, enabled: v }))}
                  />
                </div>
              </div>
              <CardDescription>
                Genera emails HTML profesionales con analisis contextual usando Ollama (mejora las notificaciones SMTP)
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor="ollama-url">URL del servidor Ollama</Label>
                  <div className="flex gap-2">
                    <Input
                      id="ollama-url"
                      type="text"
                      placeholder="http://ollama:11434"
                      value={ollamaConfig.url}
                      onChange={(e) => setOllamaConfig((prev) => ({ ...prev, url: e.target.value }))}
                      className="flex-1"
                    />
                    <Button variant="outline" onClick={handleLoadModels} disabled={loadingModels}>
                      {loadingModels ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Globe className="mr-2 h-4 w-4" />
                      )}
                      Cargar Modelos
                    </Button>
                  </div>
                </div>
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor="ollama-model">Modelo</Label>
                  {ollamaModels.length > 0 ? (
                    <Select
                      value={ollamaConfig.model}
                      onValueChange={(v) => setOllamaConfig((prev) => ({ ...prev, model: v }))}
                    >
                      <SelectTrigger id="ollama-model">
                        <SelectValue placeholder="Seleccionar modelo" />
                      </SelectTrigger>
                      <SelectContent>
                        {ollamaModels.map((m) => (
                          <SelectItem key={m} value={m}>{m}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <Input
                      id="ollama-model"
                      type="text"
                      placeholder="llama3.2:3b"
                      value={ollamaConfig.model}
                      onChange={(e) => setOllamaConfig((prev) => ({ ...prev, model: e.target.value }))}
                    />
                  )}
                  <p className="text-sm text-muted-foreground">
                    Haz clic en &quot;Cargar Modelos&quot; para listar los modelos disponibles en el servidor
                  </p>
                </div>
              </div>
              <div className="flex gap-3 pt-2">
                <Button onClick={handleSaveOllama} disabled={savingOllama}>
                  {savingOllama ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="mr-2 h-4 w-4" />
                  )}
                  Guardar
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Scheduler Tab */}
        <TabsContent value="scheduler">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  <CardTitle>Scheduler</CardTitle>
                </div>
                <div className="flex items-center gap-2">
                  <Label htmlFor="scheduler-enabled" className="text-sm">
                    {schedulerEnabled ? "Habilitado" : "Deshabilitado"}
                  </Label>
                  <Switch
                    id="scheduler-enabled"
                    checked={schedulerEnabled}
                    onCheckedChange={setSchedulerEnabled}
                  />
                </div>
              </div>
              <CardDescription>
                Configura escaneos automaticos a intervalos regulares
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="scheduler-interval">Frecuencia de escaneo</Label>
                <Select value={schedulerInterval} onValueChange={setSchedulerInterval}>
                  <SelectTrigger id="scheduler-interval">
                    <SelectValue placeholder="Seleccionar intervalo" />
                  </SelectTrigger>
                  <SelectContent>
                    {INTERVAL_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {schedulerData?.next_run && schedulerEnabled && (
                <div className="rounded-md border p-3 text-sm">
                  <span className="text-muted-foreground">Proximo escaneo: </span>
                  <span className="font-medium">{new Date(schedulerData.next_run).toLocaleString()}</span>
                </div>
              )}

              {!schedulerEnabled && (
                <p className="text-sm text-muted-foreground">
                  Habilita el scheduler para ejecutar escaneos automaticamente
                </p>
              )}

              <div className="flex gap-3 pt-2">
                <Button onClick={handleSaveScheduler} disabled={savingScheduler}>
                  {savingScheduler ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="mr-2 h-4 w-4" />
                  )}
                  Guardar
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

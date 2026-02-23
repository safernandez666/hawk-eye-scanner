"use client";

import { useState, useEffect } from "react";
import { useNotifications, updateNotificationChannel, testNotificationChannel } from "@/hooks/use-api";
import type { NotificationChannel } from "@/types";
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
import { Mail, MessageSquare, Globe, Send, Save, Loader2, Plug } from "lucide-react";

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
  { name: "from_address", label: "Remitente", type: "text", placeholder: "alerts@example.com" },
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
    return { ...base, host: "", port: 587, use_tls: true, username: "", password: "", from_address: "", to_addresses: "", severity_filter: ["CRITICAL", "HIGH"] };
  }
  if (name === "slack" || name === "teams") {
    return { ...base, webhook_url: "" };
  }
  return { ...base, url: "", method: "POST", headers: { "Content-Type": "application/json" }, severity_filter: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] };
}

export default function SettingsPage() {
  const { data, loading, refetch } = useNotifications();
  const [localChannels, setLocalChannels] = useState<Record<string, NotificationChannel>>({});
  const [saving, setSaving] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  useEffect(() => {
    if (data?.channels) {
      const merged: Record<string, NotificationChannel> = {};
      for (const name of ["thehive", "smtp", "slack", "teams", "webhook"]) {
        merged[name] = { ...getDefaultChannel(name), ...data.channels[name] };
      }
      setLocalChannels(merged);
    }
  }, [data]);

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
          toast.success(`Prueba enviada por "${CHANNEL_META[channel].label}"`);
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

  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Tabs defaultValue="thehive" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          {Object.entries(CHANNEL_META).map(([key, meta]) => (
            <TabsTrigger key={key} value={key} className="flex items-center gap-2">
              <meta.icon className="h-4 w-4" />
              {meta.label}
            </TabsTrigger>
          ))}
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
                      disabled={testing === channelName}
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
      </Tabs>
    </div>
  );
}

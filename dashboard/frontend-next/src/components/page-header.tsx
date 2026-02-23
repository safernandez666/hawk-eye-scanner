"use client";

import { usePathname } from "next/navigation";
import { ModeToggle } from "@/components/mode-toggle";
import { Separator } from "@/components/ui/separator";

const pageTitles: Record<string, { title: string; subtitle: string }> = {
  "/": {
    title: "Dashboard",
    subtitle: "Resumen de datos sensibles detectados en tu infraestructura",
  },
  "/alerts": {
    title: "Alertas",
    subtitle: "Gestiona los hallazgos de datos sensibles detectados",
  },
  "/patterns": {
    title: "Patrones",
    subtitle: "Tipos de datos sensibles detectados en tu infraestructura",
  },

  "/sources": {
    title: "Fuentes",
    subtitle: "Fuentes de datos configuradas para escaneo",
  },
  "/cases": {
    title: "Casos",
    subtitle: "Casos en TheHive creados desde el scanner",
  },
  "/settings": {
    title: "Configuracion",
    subtitle: "Canales de notificacion para alertas de escaneo",
  },
};

export function PageHeader() {
  const pathname = usePathname();
  const pageInfo = pageTitles[pathname] || { title: "Dashboard", subtitle: "" };

  return (
    <>
      <header className="flex h-16 shrink-0 items-center justify-between border-b px-6">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{pageInfo.title}</h1>
          <p className="text-sm text-muted-foreground hidden sm:block">{pageInfo.subtitle}</p>
        </div>
        <ModeToggle />
      </header>
      <Separator />
    </>
  );
}

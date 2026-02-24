"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect } from "react";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  AlertTriangle,
  Fingerprint,
  Database,
  Briefcase,
  Settings,
} from "lucide-react";
import { MoustacheIcon } from "./icons";
import { useFeatures, useNotifications } from "@/hooks/use-api";

const navItems = [
  {
    title: "Dashboard",
    href: "/",
    icon: LayoutDashboard,
  },
  {
    title: "Alertas",
    href: "/alerts",
    icon: AlertTriangle,
  },
  {
    title: "Patrones",
    href: "/patterns",
    icon: Fingerprint,
  },
  {
    title: "Fuentes",
    href: "/sources",
    icon: Database,
  },
  {
    title: "Casos",
    href: "/cases",
    icon: Briefcase,
    requiresTheHive: true,
  },
  {
    title: "Configuracion",
    href: "/settings",
    icon: Settings,
  },
];

interface SidebarProps {
  className?: string;
}

export function Sidebar({ className }: SidebarProps) {
  const pathname = usePathname();
  const { data: features, refetch: refetchFeatures } = useFeatures();
  const { refetch: refetchNotifications } = useNotifications();
  
  // Polling para detectar cambios en estado de TheHive
  useEffect(() => {
    const interval = setInterval(() => {
      refetchFeatures();
      refetchNotifications();
    }, 3000); // Cada 3 segundos
    return () => clearInterval(interval);
  }, [refetchFeatures, refetchNotifications]);
  
  const thehiveEnabled = features?.thehive_enabled ?? false;

  const visibleItems = navItems.filter(
    (item) => !item.requiresTheHive || thehiveEnabled
  );

  return (
    <aside className={cn("flex h-[calc(100vh-2rem)] w-64 flex-col border-r bg-background", className)}>
      <div className="flex h-full flex-col">
        {/* Logo */}
        <div className="flex h-20 items-center border-b px-6">
          <Link href="/" className="flex items-center gap-3">
            <MoustacheIcon className="h-7 w-7 text-primary mt-4" />
            <div className="flex flex-col">
              <span className="text-xl font-bold">Poirot</span>
              <span className="text-[10px] text-muted-foreground tracking-wide">Data Security Posture Management</span>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 p-4">
          {visibleItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                )}
              >
                <item.icon className="h-4 w-4" />
                {item.title}
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="border-t p-4">
          <div className="text-xs text-muted-foreground">
            <p className="font-medium">Poirot</p>
            <p>by Santiago Fernandez</p>
          </div>
        </div>
      </div>
    </aside>
  );
}

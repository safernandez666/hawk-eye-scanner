"use client";

import { useTimeline } from "@/hooks/use-api";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
};

export function TimelineChart() {
  const { data, loading } = useTimeline(30);

  // Transform data for recharts
  const chartData = data?.timeline
    ? Object.entries(data.timeline)
        .sort(([a], [b]) => new Date(a).getTime() - new Date(b).getTime())
        .map(([date, values]) => ({
          date: new Date(date).toLocaleDateString("es-ES", {
            day: "2-digit",
            month: "short",
          }),
          CRITICAL: values.CRITICAL || 0,
          HIGH: values.HIGH || 0,
          MEDIUM: values.MEDIUM || 0,
          LOW: values.LOW || 0,
        }))
    : [];

  if (loading) {
    return (
      <Card className="h-full">
        <CardHeader>
          <CardTitle>Timeline de Detecciones</CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[300px]" />
        </CardContent>
      </Card>
    );
  }

  if (chartData.length === 0) {
    return (
      <Card className="h-full">
        <CardHeader>
          <CardTitle>Timeline de Detecciones</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex h-[300px] items-center justify-center text-muted-foreground">
            No hay datos disponibles para el período seleccionado
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Timeline de Detecciones (30 días)</CardTitle>
      </CardHeader>
      <CardContent className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.CRITICAL} stopOpacity={0.3}/>
                <stop offset="95%" stopColor={COLORS.CRITICAL} stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.HIGH} stopOpacity={0.3}/>
                <stop offset="95%" stopColor={COLORS.HIGH} stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.MEDIUM} stopOpacity={0.3}/>
                <stop offset="95%" stopColor={COLORS.MEDIUM} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5e7eb" />
            <XAxis 
              dataKey="date" 
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#6b7280', fontSize: 12 }}
            />
            <YAxis 
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#6b7280', fontSize: 12 }}
            />
            <Tooltip 
              contentStyle={{ 
                borderRadius: '8px', 
                border: 'none', 
                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)' 
              }}
            />
            <Area
              type="monotone"
              dataKey="CRITICAL"
              stackId="1"
              stroke={COLORS.CRITICAL}
              fill="url(#colorCritical)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="HIGH"
              stackId="1"
              stroke={COLORS.HIGH}
              fill="url(#colorHigh)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="MEDIUM"
              stackId="1"
              stroke={COLORS.MEDIUM}
              fill="url(#colorMedium)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="LOW"
              stackId="1"
              stroke={COLORS.LOW}
              fillOpacity={0}
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

"use client";

import { useTimeline } from "@/hooks/use-api";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { LineChart as LineChartIcon } from "lucide-react";

const COLORS = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#16a34a",
};

export default function TimelinePage() {
  const { data, loading } = useTimeline(30);

  // Transform data for recharts
  const chartData = data?.timeline
    ? Object.entries(data.timeline)
        .sort(([a], [b]) => new Date(a).getTime() - new Date(b).getTime())
        .map(([date, values]) => ({
          date: new Date(date).toLocaleDateString("es-ES", {
            day: "2-digit",
            month: "2-digit",
          }),
          CRITICAL: values.CRITICAL || 0,
          HIGH: values.HIGH || 0,
          MEDIUM: values.MEDIUM || 0,
          LOW: values.LOW || 0,
        }))
    : [];

  return (
    <div className="space-y-6">


      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <LineChartIcon className="h-5 w-5" />
            <CardTitle>Evolución de Detecciones</CardTitle>
          </div>
          <CardDescription>
            Alertas por día y severidad
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <Skeleton className="h-[400px]" />
          ) : chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={400}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="CRITICAL"
                  stroke={COLORS.CRITICAL}
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="HIGH"
                  stroke={COLORS.HIGH}
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="MEDIUM"
                  stroke={COLORS.MEDIUM}
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="LOW"
                  stroke={COLORS.LOW}
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[400px] items-center justify-center text-muted-foreground">
              No hay datos disponibles para el período seleccionado
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

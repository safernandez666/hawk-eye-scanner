"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface Pattern {
  name: string;
  count: number;
}

interface TopPatternsChartProps {
  data: Pattern[];
  loading?: boolean;
}

const COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6"];

export function TopPatternsChart({ data, loading }: TopPatternsChartProps) {
  if (loading) {
    return (
      <Card className="h-full">
        <CardHeader className="pb-0">
          <Skeleton className="h-5 w-40" />
        </CardHeader>
        <CardContent className="pt-6">
          <Skeleton className="h-[220px]" />
        </CardContent>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card className="h-full">
        <CardHeader className="pb-0">
          <CardTitle className="text-sm font-medium">
            Top Tipos de Datos
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-6">
          <div className="h-[220px] flex items-center justify-center text-muted-foreground text-sm">
            No hay datos disponibles
          </div>
        </CardContent>
      </Card>
    );
  }

  // Encontrar el valor máximo para calcular el dominio
  const maxCount = Math.max(...data.map(d => d.count));

  return (
    <Card className="h-full">
      <CardHeader className="pb-0">
        <CardTitle className="text-sm font-medium">
          Top Tipos de Datos Sensibles
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-6">
        <div className="h-[220px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              layout="vertical"
              margin={{ top: 5, right: 50, left: 5, bottom: 5 }}
            >
              <XAxis 
                type="number" 
                domain={[0, maxCount * 1.2]}
                tick={{ fontSize: 10 }}
                allowDecimals={false}
              />
              <YAxis
                type="category"
                dataKey="name"
                width={140}
                tick={{ fontSize: 11 }}
                interval={0}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: "rgba(0,0,0,0.05)" }}
                contentStyle={{
                  backgroundColor: "hsl(var(--background))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "6px",
                  fontSize: "12px",
                }}
                formatter={(value: number) => [`${value} hallazgos`, "Cantidad"]}
              />
              <Bar 
                dataKey="count" 
                radius={[0, 4, 4, 0]} 
                barSize={28}
                label={{ 
                  position: 'right', 
                  fill: '#666', 
                  fontSize: 11,
                  formatter: (value: number) => value > 0 ? value : ''
                }}
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

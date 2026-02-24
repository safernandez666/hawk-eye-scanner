"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";

interface Pattern {
  name: string;
  count: number;
}

interface DataTypesPipelineProps {
  data: Pattern[];
  loading?: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  "Private Key": "bg-red-500",
  "AWS Access Key": "bg-orange-500",
  "JWT Token": "bg-orange-500",
  "Social Security Number (SSN)": "bg-orange-500",
  "Email Address": "bg-yellow-500",
  "Phone Number - US": "bg-yellow-500",
  "IBAN": "bg-yellow-500",
  "IP Address - Private": "bg-yellow-500",
  "Bitcoin Address": "bg-green-500",
};

const getBarColor = (name: string) => {
  return SEVERITY_COLORS[name] || "bg-blue-500";
};

export function DataTypesPipeline({ data, loading }: DataTypesPipelineProps) {
  if (loading) {
    return (
      <Card className="h-full">
        <CardHeader className="pb-3">
          <Skeleton className="h-5 w-48" />
        <Skeleton className="h-4 w-32 mt-1" />
        </CardHeader>
        <CardContent className="space-y-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card className="h-full">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">
            Tipos de Datos Encontrados
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[200px] flex items-center justify-center text-muted-foreground text-sm">
            No hay datos disponibles
          </div>
        </CardContent>
      </Card>
    );
  }

  // Calcular el TOTAL de todos los casos
  const total = data.reduce((sum, d) => sum + d.count, 0);
  
  // Ordenar por cantidad (mayor a menor)
  const sortedData = [...data].sort((a, b) => b.count - a.count);

  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium">
            Tipos de Datos Encontrados
          </CardTitle>
          <Badge variant="outline" className="text-xs font-bold">
            Total: {total}
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground">
          {data.length} categorías • Distribución por tipo de dato
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {sortedData.map((item) => {
          // Porcentaje del TOTAL (no del máximo)
          const percentageOfTotal = total > 0 ? (item.count / total) * 100 : 0;
          
          return (
            <div key={item.name} className="space-y-1.5">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium truncate max-w-[180px]" title={item.name}>
                  {item.name}
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">
                    {percentageOfTotal.toFixed(1)}%
                  </span>
                  <Badge variant="secondary" className="text-xs min-w-[40px] text-center">
                    {item.count}
                  </Badge>
                </div>
              </div>
              <div className="h-3 w-full bg-gray-100 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${getBarColor(item.name)}`}
                  style={{ width: `${percentageOfTotal}%` }}
                />
              </div>
            </div>
          );
        })}
        
        {/* Barra de referencia del total */}
        <div className="pt-3 border-t mt-4">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>0</span>
            <span>Distribución del total de hallazgos</span>
            <span>{total}</span>
          </div>
          <div className="h-1.5 w-full bg-gray-200 rounded-full mt-1">
            <div className="h-full w-full bg-gradient-to-r from-gray-300 via-gray-400 to-gray-500 rounded-full opacity-30" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

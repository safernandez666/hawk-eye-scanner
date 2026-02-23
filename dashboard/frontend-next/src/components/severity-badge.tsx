import { Badge } from "@/components/ui/badge";
import type { Alert } from "@/types";

interface SeverityBadgeProps {
  severity: Alert["severity"];
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const variantMap: Record<string, "default" | "destructive" | "outline" | "secondary"> = {
    CRITICAL: "destructive",
    HIGH: "default",
    MEDIUM: "secondary",
    LOW: "outline",
  };
  
  const colorClass = {
    CRITICAL: "bg-red-100 text-red-700 hover:bg-red-100 border-red-200",
    HIGH: "bg-orange-100 text-orange-700 hover:bg-orange-100 border-orange-200",
    MEDIUM: "bg-yellow-100 text-yellow-700 hover:bg-yellow-100 border-yellow-200",
    LOW: "bg-green-100 text-green-700 hover:bg-green-100 border-green-200",
  };
  
  return (
    <Badge 
      variant="outline" 
      className={colorClass[severity] || ""}
    >
      {severity}
    </Badge>
  );
}

interface StatusBadgeProps {
  status: Alert["status"];
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const colorClass: Record<string, string> = {
    NEW: "bg-blue-100 text-blue-700 border-blue-200",
    SENT: "bg-blue-100 text-blue-700 border-blue-200",
    ACKNOWLEDGED: "bg-purple-100 text-purple-700 border-purple-200",
    FALSE_POSITIVE: "bg-gray-100 text-gray-700 border-gray-200",
    REOPENED: "bg-amber-100 text-amber-700 border-amber-200",
    CLOSED: "bg-gray-100 text-gray-700 border-gray-200",
  };
  
  return (
    <Badge variant="outline" className={colorClass[status] || ""}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

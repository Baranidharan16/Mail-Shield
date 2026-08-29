import { AlertTriangle, Info, AlertCircle, ShieldAlert, Shield, Activity, FileKey, Brain, Box } from "lucide-react";

export type Level = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;

interface SeverityStyle {
  bg: string;
  text: string;
  dot: string;
  border: string;
  label: string;
}

const LEVEL_STYLES: Record<string, SeverityStyle> = {
  INFO:     { bg: "bg-sev-info",     text: "text-sev-info",     dot: "bg-lab-400",       border: "border-lab-600/40",    label: "Info" },
  LOW:      { bg: "bg-sev-low",      text: "text-sev-low",      dot: "bg-blue-signal",   border: "border-blue-signal/40",  label: "Low" },
  MEDIUM:   { bg: "bg-sev-medium",   text: "text-sev-medium",   dot: "bg-amber-signal",  border: "border-amber-signal/40", label: "Medium" },
  HIGH:     { bg: "bg-sev-high",     text: "text-sev-high",     dot: "bg-orange-signal", border: "border-orange-signal/40",label: "High" },
  CRITICAL: { bg: "bg-sev-critical", text: "text-sev-critical", dot: "bg-crimson-signal",border: "border-sev-critical",    label: "Critical" },
};

export function SeverityBadge({ level }: { level: Level }) {
  const normalized = (level || "INFO").toUpperCase();
  const style = LEVEL_STYLES[normalized] ?? LEVEL_STYLES.INFO;
  const Icon = normalized === "CRITICAL" ? ShieldAlert : normalized === "HIGH" || normalized === "MEDIUM" ? AlertTriangle : Info;

  return (
    <span className={`status-pill border ${style.bg} ${style.border} ${style.text} shadow-sm backdrop-blur-md inline-flex items-center gap-1.5`}>
      <Icon className="h-3 w-3 shrink-0" strokeWidth={2.5} />
      {normalized}
    </span>
  );
}

export function ClassificationBadge({ level, size = "md" }: { level: Level; size?: "sm" | "md" | "lg" }) {
  const isSm = size === "sm";
  const isLg = size === "lg";
  const normalized = (level || "INFO").toUpperCase();
  const base = "status-pill border bg-white/[0.04] backdrop-blur-md shadow-sm inline-flex items-center gap-1.5";
  let color = "text-lab-400 border-white/10";
  let icon = <Info className={isSm ? "h-3 w-3" : isLg ? "h-4 w-4" : "h-3.5 w-3.5"} />;

  switch (normalized) {
    case "CRITICAL":
    case "MALWARE":
      color = "text-crimson-glow border-crimson-signal/35 glow-red bg-crimson-signal/10";
      icon = <AlertCircle className={isSm ? "h-3 w-3" : isLg ? "h-4 w-4" : "h-3.5 w-3.5"} />;
      break;
    case "HIGH":
    case "PHISHING":
      color = "text-orange-signal border-orange-signal/30 bg-orange-signal/10";
      icon = <FileKey className={isSm ? "h-3 w-3" : isLg ? "h-4 w-4" : "h-3.5 w-3.5"} />;
      break;
    case "MEDIUM":
    case "SOCIAL_ENGINEERING":
      color = "text-amber-signal border-amber-signal/30 glow-amber bg-amber-signal/10";
      icon = <Activity className={isSm ? "h-3 w-3" : isLg ? "h-4 w-4" : "h-3.5 w-3.5"} />;
      break;
    case "LOW":
    case "SPAM":
      color = "text-blue-signal border-blue-signal/30 bg-blue-signal/10";
      icon = <Box className={isSm ? "h-3 w-3" : isLg ? "h-4 w-4" : "h-3.5 w-3.5"} />;
      break;
    case "BEC":
      color = "text-purple-signal border-purple-signal/30 bg-purple-signal/10";
      icon = <Brain className={isSm ? "h-3 w-3" : isLg ? "h-4 w-4" : "h-3.5 w-3.5"} />;
      break;
    case "CLEAN":
      color = "text-phosphor-400 border-phosphor-500/30 glow-green bg-phosphor-500/10";
      icon = <Shield className={isSm ? "h-3 w-3" : isLg ? "h-4 w-4" : "h-3.5 w-3.5"} />;
      break;
    default:
      color = "text-lab-300 border-white/10";
      break;
  }

  const sizeCls = isLg ? "px-3.5 py-1.5 text-sm" : isSm ? "text-[9px] px-2 py-0.5" : "text-xs px-2.5 py-1";

  return (
    <span className={`${base} ${color} ${sizeCls}`}>
      {icon} {normalized.replace(/_/g, " ")}
    </span>
  );
}

export function AlertStatusBadge({ status }: { status: string }) {
  const normalized = (status || "DETECTED").toUpperCase();
  const styles: Record<string, string> = {
    DETECTED:     "bg-sev-critical/20 text-crimson-glow border border-sev-critical",
    TRIAGED:      "bg-sev-high/20 text-orange-signal border border-sev-high",
    INVESTIGATING:"bg-sev-medium/20 text-amber-signal border border-sev-medium",
    CONTAINED:    "bg-sev-low/20 text-blue-signal border border-sev-low",
    RESOLVED:     "bg-phosphor-500/10 text-phosphor-400 border border-phosphor-500/30",
  };
  const cls = styles[normalized] ?? styles.DETECTED;
  return (
    <span className={`status-pill ${cls} backdrop-blur-md`}>
      {normalized}
    </span>
  );
}

export function levelColor(level: Level): string {
  const map: Record<string, string> = {
    CRITICAL: "text-crimson-glow",
    HIGH: "text-orange-signal",
    MEDIUM: "text-amber-signal",
    LOW: "text-blue-signal",
    INFO: "text-lab-400",
  };
  return map[(level || "INFO").toUpperCase()] ?? "text-lab-400";
}

export function scoreToClassification(score: number): Level {
  if (score >= 81) return "CRITICAL";
  if (score >= 61) return "HIGH";
  if (score >= 31) return "MEDIUM";
  return "LOW";
}

export function sevColor(sev: string): string {
  const map: Record<string, string> = {
    CRITICAL: "#ff6b5e",
    HIGH: "#f97316",
    MEDIUM: "#e8a23d",
    LOW: "#3b82f6",
    INFO: "#7c8fa0",
  };
  return map[(sev || "INFO").toUpperCase()] ?? "#7c8fa0";
}

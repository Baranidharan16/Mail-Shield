import {
  Upload, Network, ShieldAlert, Link2, Globe2, AlertTriangle,
  CheckCircle2, FileText, Lock, Activity, Clock, Cpu, Bot, Share2,
} from "lucide-react";
import type { TimelineEvent } from "../types/investigation";


const ICON_MAP: Record<string, any> = {
  upload: Upload,
  network: Network,
  shield: ShieldAlert,
  link: Link2,
  globe: Globe2,
  "alert-triangle": AlertTriangle,
  "check-circle": CheckCircle2,
  "file-text": FileText,
  lock: Lock,
  activity: Activity,
  clock: Clock,
  cpu: Cpu,
  bot: Bot,
  share2: Share2,
  mail: FileText,
};

const TYPE_COLORS: Record<string, string> = {
  INGESTION: "#3ddc97",
  EMAIL_DATE: "#6ee8b1",
  RELAY_HOP: "#3b82f6",
  SYSTEM: "#7c8fa0",
  ANALYSIS_COMPLETE: "#3ddc97",
  REPORT: "#a9bac8",
  BLOCKCHAIN: "#8b5cf6",
};

function formatTs(ts: string | null) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("en-IN", {
      month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

interface Props {
  events: TimelineEvent[];
}

export default function InvestigationTimeline({ events }: Props) {
  if (events.length === 0) {
    return (
      <div className="p-6 text-center text-lab-500 text-sm">
        No timeline events available yet. Analysis must complete first.
      </div>
    );
  }

  return (
    <div className="relative">
      {events.map((ev, i) => {
        const Icon = ICON_MAP[ev.icon] ?? Activity;
        const color = TYPE_COLORS[ev.type] ?? "#7c8fa0";
        const isLast = i === events.length - 1;

        return (
          <div key={i} className="flex gap-4 relative">
            {/* Connector line */}
            {!isLast && (
              <div
                className="absolute left-5 top-10 bottom-0 w-px"
                style={{ background: `linear-gradient(to bottom, ${color}44, transparent)` }}
              />
            )}

            {/* Icon */}
            <div
              className="shrink-0 h-10 w-10 rounded-full flex items-center justify-center ring-4 ring-lab-900 z-10"
              style={{ backgroundColor: `${color}22`, border: `1.5px solid ${color}66` }}
            >
              <Icon className="h-4 w-4" style={{ color }} strokeWidth={1.75} />
            </div>

            {/* Content */}
            <div className={`flex-1 pb-6 ${isLast ? "" : ""}`}>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-sm font-medium text-lab-200">{ev.label}</div>
                  {ev.detail && (
                    <div className="text-xs text-lab-400 mt-0.5 font-data break-all">{ev.detail}</div>
                  )}
                  {ev.actor && ev.actor !== "system" && (
                    <div className="text-[10px] text-lab-500 mt-1">Actor: {ev.actor}</div>
                  )}
                </div>
                <div className="text-[11px] text-lab-500 evidence-tag shrink-0 text-right">
                  <div>{formatTs(ev.timestamp)}</div>
                  <div
                    className="text-[9px] mt-0.5 uppercase tracking-widest"
                    style={{ color }}
                  >
                    {ev.type.replace(/_/g, " ")}
                  </div>
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

import { Lock, Upload, Eye, FileOutput, CheckCircle2, Hash } from "lucide-react";
import type { ChainOfCustodyResponse } from "../types/investigation";

function formatTs(ts: string | null | undefined) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("en-IN", {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

const ACTION_ICONS: Record<string, any> = {
  EVIDENCE_UPLOAD: Upload,
  EVIDENCE_ANCHORED: Lock,
  FORENSIC_ANALYSIS_COMPLETE: CheckCircle2,
  NOTE_ADDED: FileOutput,
  CASE_STATUS_UPDATE: CheckCircle2,
  ANALYST_ASSIGNED: Eye,
  EVIDENCE_HASH_COMPUTED: Hash,
};

const ACTION_COLORS: Record<string, string> = {
  EVIDENCE_UPLOAD: "#3ddc97",
  EVIDENCE_ANCHORED: "#8b5cf6",
  FORENSIC_ANALYSIS_COMPLETE: "#3ddc97",
  THREAT_INTELLIGENCE: "#e8a23d",
  CORRELATION: "#3b82f6",
};

interface Props {
  data: ChainOfCustodyResponse;
}

export default function ChainOfCustody({ data }: Props) {
  const entries = [
    // Synthetic initial upload event
    {
      timestamp: data.created_at,
      actor: data.created_by,
      action: "EVIDENCE_UPLOAD",
      detail: `SHA-256: ${data.evidence_hash?.slice(0, 16)}…`,
    },
    ...data.audit_trail,
    // Blockchain anchor if present
    ...(data.blockchain_anchor.block_hash
      ? [{
          timestamp: data.blockchain_anchor.anchored_at ?? null,
          actor: "system",
          action: "EVIDENCE_ANCHORED",
          detail: `Block #${data.blockchain_anchor.block_index} · ${data.blockchain_anchor.block_hash?.slice(0, 16)}…`,
        }]
      : []),
  ];

  return (
    <div className="space-y-0">
      {entries.map((entry, i) => {
        const Icon = ACTION_ICONS[entry.action] ?? Lock;
        const color = ACTION_COLORS[entry.action] ?? "#7c8fa0";
        const isLast = i === entries.length - 1;

        return (
          <div key={i} className="flex gap-3 relative">
            {!isLast && (
              <div className="absolute left-4 top-9 bottom-0 w-px bg-lab-700" />
            )}
            <div
              className="shrink-0 h-8 w-8 rounded-full flex items-center justify-center z-10"
              style={{ backgroundColor: `${color}20`, border: `1px solid ${color}44` }}
            >
              <Icon className="h-3.5 w-3.5" style={{ color }} strokeWidth={1.75} />
            </div>
            <div className="flex-1 pb-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-xs font-semibold text-lab-200 evidence-tag">
                    {entry.action.replace(/_/g, " ")}
                  </div>
                  {entry.detail && (
                    <div className="text-[11px] text-lab-400 font-data mt-0.5 break-all">{entry.detail}</div>
                  )}
                  <div className="text-[10px] text-lab-500 mt-0.5">
                    Actor: <span className="text-lab-400">{entry.actor ?? "system"}</span>
                  </div>
                </div>
                <div className="text-[10px] font-data text-lab-500 shrink-0 text-right">
                  {formatTs(entry.timestamp)}
                </div>
              </div>
            </div>
          </div>
        );
      })}

      {/* Evidence hash footer */}
      <div className="mt-2 p-3 rounded-md bg-lab-800/60 border border-lab-700">
        <div className="text-[10px] text-lab-500 evidence-tag mb-1">ORIGINAL EVIDENCE SHA-256</div>
        <div className="font-data text-xs text-phosphor-400 break-all">{data.evidence_hash}</div>
        <div className="text-[10px] text-lab-600 mt-1">Submitted by: {data.created_by}</div>
      </div>
    </div>
  );
}

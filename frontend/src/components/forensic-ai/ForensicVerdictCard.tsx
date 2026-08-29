/**
 * ForensicVerdictCard — Hero verdict display showing classification, risk score,
 * AI confidence, evidence strength, IOCs, and forensic conclusion.
 */
import { Shield, Target, Zap, Database, AlertCircle } from "lucide-react";
import type { ForensicAIResult } from "../../types/investigation";

interface Props {
  data: ForensicAIResult;
}

const SEV_COLORS: Record<string, { text: string; bg: string; border: string; glow: string }> = {
  CRITICAL: { text: "#ff6b5e", bg: "rgba(226,72,61,0.12)", border: "rgba(226,72,61,0.4)", glow: "0 0 24px rgba(226,72,61,0.3)" },
  HIGH: { text: "#f97316", bg: "rgba(249,115,22,0.12)", border: "rgba(249,115,22,0.4)", glow: "0 0 24px rgba(249,115,22,0.2)" },
  MEDIUM: { text: "#e8a23d", bg: "rgba(232,162,61,0.12)", border: "rgba(232,162,61,0.35)", glow: "0 0 24px rgba(232,162,61,0.2)" },
  LOW: { text: "#3ddc97", bg: "rgba(61,220,151,0.10)", border: "rgba(61,220,151,0.3)", glow: "0 0 16px rgba(61,220,151,0.15)" },
};

const STRENGTH_COLOR: Record<string, string> = {
  "VERY HIGH": "#ff6b5e",
  HIGH: "#f97316",
  MEDIUM: "#e8a23d",
  LOW: "#3b82f6",
  INSUFFICIENT: "#7c8fa0",
};

export default function ForensicVerdictCard({ data }: Props) {
  const sev = SEV_COLORS[data.threat_severity] ?? SEV_COLORS.LOW;
  const score = data.risk_score;

  return (
    <div className="space-y-4">
      {/* Top row: score + classification + metadata */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Risk score dial */}
        <div
          className="rounded-xl p-5 flex flex-col items-center justify-center"
          style={{ background: sev.bg, border: `1px solid ${sev.border}`, boxShadow: sev.glow }}
        >
          <div
            className="text-5xl font-bold font-mono mb-1 tabular-nums"
            style={{ color: sev.text }}
          >
            {score.toFixed(0)}
          </div>
          <div className="text-xs font-mono" style={{ color: sev.text, opacity: 0.7 }}>
            / 100 RISK SCORE
          </div>
          <div
            className="mt-3 px-4 py-1 rounded-full text-xs font-mono font-bold tracking-widest"
            style={{ background: sev.bg, color: sev.text, border: `1px solid ${sev.border}` }}
          >
            {data.threat_severity}
          </div>
        </div>

        {/* Classification */}
        <div
          className="rounded-xl p-5 flex flex-col justify-between"
          style={{ background: "#19212a", border: "1px solid #232d38" }}
        >
          <div className="flex items-center gap-2 mb-3">
            <Target size={14} style={{ color: "#a78bfa" }} />
            <span className="text-xs font-mono tracking-wider" style={{ color: "#7c8fa0" }}>
              PRIMARY CLASSIFICATION
            </span>
          </div>
          <div className="text-xl font-bold mb-2" style={{ color: "#cfdbe4" }}>
            {data.classification.primary}
          </div>
          {data.classification.secondary.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {data.classification.secondary.map((s) => (
                <span
                  key={s}
                  className="text-[11px] px-2 py-0.5 rounded font-mono"
                  style={{ background: "rgba(139,92,246,0.12)", color: "#c4b5fd", border: "1px solid rgba(139,92,246,0.2)" }}
                >
                  {s}
                </span>
              ))}
            </div>
          )}
          <div className="mt-3 flex items-center gap-2">
            <div
              className="flex-1 h-1.5 rounded-full overflow-hidden"
              style={{ background: "#232d38" }}
            >
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${data.classification.confidence * 100}%`,
                  background: "linear-gradient(90deg, #8b5cf6, #a78bfa)",
                }}
              />
            </div>
            <span className="text-xs font-mono" style={{ color: "#7c8fa0" }}>
              {(data.classification.confidence * 100).toFixed(0)}% conf
            </span>
          </div>
        </div>

        {/* Metrics */}
        <div
          className="rounded-xl p-5 flex flex-col gap-3"
          style={{ background: "#19212a", border: "1px solid #232d38" }}
        >
          <MetricRow
            label="AI CONFIDENCE"
            value={`${(data.ai_confidence * 100).toFixed(0)}%`}
            color="#3ddc97"
            icon={<Zap size={12} />}
          />
          <MetricRow
            label="EVIDENCE STRENGTH"
            value={data.evidence_strength}
            color={STRENGTH_COLOR[data.evidence_strength] ?? "#7c8fa0"}
            icon={<Shield size={12} />}
          />
          <MetricRow
            label="ARTIFACTS ANALYZED"
            value={String(data.artifacts_analyzed)}
            color="#3b82f6"
            icon={<Database size={12} />}
          />
          <MetricRow
            label="IOCs EXTRACTED"
            value={String(data.iocs.length)}
            color="#e8a23d"
            icon={<AlertCircle size={12} />}
          />
        </div>
      </div>

      {/* Forensic conclusion */}
      <div
        className="rounded-xl p-4"
        style={{ background: "rgba(139,92,246,0.06)", border: "1px solid rgba(139,92,246,0.18)" }}
      >
        <div className="flex items-center gap-2 mb-2">
          <span className="text-xs font-mono font-bold tracking-widest" style={{ color: "#a78bfa" }}>
            FORENSIC CONCLUSION
          </span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ background: "rgba(139,92,246,0.15)", color: "#c4b5fd" }}>
            [AI INFERENCE + LOCAL HEURISTIC]
          </span>
        </div>
        <p className="text-sm leading-relaxed" style={{ color: "#a9bac8" }}>
          {data.forensic_conclusion}
        </p>
      </div>

      {/* IOC pills */}
      {data.iocs.length > 0 && (
        <div>
          <p className="text-[11px] font-mono mb-2" style={{ color: "#4a5a6b" }}>
            INDICATORS OF COMPROMISE ({data.iocs.length})
          </p>
          <div className="flex flex-wrap gap-1.5">
            {data.iocs.map((ioc, i) => (
              <span
                key={i}
                className="text-[11px] font-mono px-2 py-1 rounded flex items-center gap-1"
                style={{
                  background: ioc.type === "EMAIL" ? "rgba(59,130,246,0.1)" : ioc.type === "URL" ? "rgba(249,115,22,0.1)" : ioc.type === "IP" ? "rgba(232,162,61,0.1)" : "rgba(61,220,151,0.08)",
                  color: ioc.type === "EMAIL" ? "#60a5fa" : ioc.type === "URL" ? "#fb923c" : ioc.type === "IP" ? "#e8a23d" : "#3ddc97",
                  border: "1px solid rgba(255,255,255,0.06)",
                }}
              >
                <span className="opacity-60">[{ioc.type}]</span>
                <span className="truncate max-w-[180px]">{ioc.value}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function MetricRow({
  label,
  value,
  color,
  icon,
}: {
  label: string;
  value: string;
  color: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-1.5">
        <span style={{ color }}>{icon}</span>
        <span className="text-[11px] font-mono" style={{ color: "#4a5a6b" }}>
          {label}
        </span>
      </div>
      <span className="text-sm font-mono font-bold" style={{ color }}>
        {value}
      </span>
    </div>
  );
}

/**
 * EvidenceReasoningPanel — Shows evidence cards (with source labeling,
 * impact rating, severity) and the ordered reasoning chain.
 */
import { useState } from "react";
import { Shield, FileText, Globe, Brain, ChevronRight, Info } from "lucide-react";
import type { ForensicAIResult, EvidenceCard } from "../../types/investigation";

interface Props {
  data: ForensicAIResult;
}

const SEV_STYLE: Record<string, { text: string; bg: string; border: string }> = {
  CRITICAL: { text: "#ff6b5e", bg: "rgba(226,72,61,0.10)", border: "rgba(226,72,61,0.35)" },
  HIGH: { text: "#f97316", bg: "rgba(249,115,22,0.10)", border: "rgba(249,115,22,0.3)" },
  MEDIUM: { text: "#e8a23d", bg: "rgba(232,162,61,0.10)", border: "rgba(232,162,61,0.3)" },
  LOW: { text: "#3b82f6", bg: "rgba(59,130,246,0.10)", border: "rgba(59,130,246,0.28)" },
  SAFE: { text: "#3ddc97", bg: "rgba(61,220,151,0.08)", border: "rgba(61,220,151,0.25)" },
};

const SOURCE_ICON: Record<string, React.ReactNode> = {
  "[EMAIL HEADER]": <Shield size={11} />,
  "[EMAIL CONTENT]": <FileText size={11} />,
  "[LOCAL HEURISTIC]": <Globe size={11} />,
  "[AI INFERENCE]": <Brain size={11} />,
};

const SOURCE_COLOR: Record<string, string> = {
  "[EMAIL HEADER]": "#60a5fa",
  "[EMAIL CONTENT]": "#f97316",
  "[LOCAL HEURISTIC]": "#3ddc97",
  "[AI INFERENCE]": "#a78bfa",
  "[HISTORICAL CASE]": "#e8a23d",
};

function EvidenceCardItem({ card }: { card: EvidenceCard }) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEV_STYLE[card.severity] ?? SEV_STYLE.LOW;
  const srcColor = SOURCE_COLOR[card.source] ?? "#7c8fa0";
  const srcIcon = SOURCE_ICON[card.source];

  return (
    <div
      className="rounded-lg overflow-hidden cursor-pointer transition-all hover:brightness-110"
      style={{ background: sev.bg, border: `1px solid ${sev.border}` }}
      onClick={() => setExpanded((e) => !e)}
    >
      <div className="flex items-start gap-3 p-3.5">
        {/* Left: severity bar */}
        <div
          className="w-1 rounded-full self-stretch shrink-0"
          style={{ background: sev.text, minHeight: "40px" }}
        />
        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2 mb-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold" style={{ color: sev.text }}>
                {card.name}
              </span>
              <span
                className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                style={{ background: sev.bg, color: sev.text, border: `1px solid ${sev.border}` }}
              >
                {card.severity}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span
                className="flex items-center gap-1 text-[10px] font-mono"
                style={{ color: srcColor }}
              >
                {srcIcon}
                {card.source}
              </span>
              <span
                className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                style={{
                  color: card.impact === "HIGH" ? "#f97316" : card.impact === "MEDIUM" ? "#e8a23d" : "#7c8fa0",
                  background: "rgba(0,0,0,0.2)",
                }}
              >
                {card.impact} impact
              </span>
            </div>
          </div>

          <p className="text-xs font-mono truncate" style={{ color: "#cfdbe4" }}>
            {card.finding}
          </p>

          {expanded && (
            <div className="mt-2.5 pt-2.5" style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}>
              <p className="text-xs leading-relaxed mb-2" style={{ color: "#a9bac8" }}>
                {card.explanation}
              </p>
              {card.evidence_refs.filter((r) => r).length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {card.evidence_refs.filter((r) => r).slice(0, 3).map((ref, i) => (
                    <span
                      key={i}
                      className="text-[10px] font-mono px-2 py-0.5 rounded"
                      style={{ background: "rgba(255,255,255,0.05)", color: "#7c8fa0" }}
                    >
                      {ref.length > 60 ? ref.substring(0, 57) + "…" : ref}
                    </span>
                  ))}
                </div>
              )}
              {card.risk_contribution > 0 && (
                <p className="text-[10px] mt-1.5 font-mono" style={{ color: "#4a5a6b" }}>
                  Risk contribution: +{card.risk_contribution} pts
                </p>
              )}
            </div>
          )}
        </div>

        {/* Expand icon */}
        <ChevronRight
          size={14}
          style={{ color: "#4a5a6b", transform: expanded ? "rotate(90deg)" : "none", transition: "transform 0.2s" }}
        />
      </div>
    </div>
  );
}

export default function EvidenceReasoningPanel({ data }: Props) {
  const [tab, setTab] = useState<"cards" | "chain">("cards");

  const groupedBySource = {
    "[EMAIL HEADER]": data.evidence_cards.filter((c) => c.source === "[EMAIL HEADER]"),
    "[EMAIL CONTENT]": data.evidence_cards.filter((c) => c.source === "[EMAIL CONTENT]"),
    "[LOCAL HEURISTIC]": data.evidence_cards.filter((c) => c.source === "[LOCAL HEURISTIC]"),
    "[AI INFERENCE]": data.evidence_cards.filter((c) => c.source === "[AI INFERENCE]"),
  };

  return (
    <div>
      {/* Tab bar */}
      <div className="flex gap-1 mb-4 p-1 rounded-lg" style={{ background: "#10151a" }}>
        {(["cards", "chain"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="flex-1 py-2 rounded-md text-xs font-mono font-bold tracking-wider transition-all"
            style={{
              background: tab === t ? "#19212a" : "transparent",
              color: tab === t ? "#cfdbe4" : "#4a5a6b",
              border: tab === t ? "1px solid #232d38" : "1px solid transparent",
            }}
          >
            {t === "cards" ? `EVIDENCE CARDS (${data.evidence_cards.length})` : `REASONING CHAIN (${data.reasoning_chain.length})`}
          </button>
        ))}
      </div>

      {tab === "cards" && (
        <div className="space-y-4">
          {Object.entries(groupedBySource).map(([source, cards]) => {
            if (cards.length === 0) return null;
            const srcColor = SOURCE_COLOR[source] ?? "#7c8fa0";
            return (
              <div key={source}>
                <div className="flex items-center gap-2 mb-2">
                  <span style={{ color: srcColor }} className="flex items-center gap-1">
                    {SOURCE_ICON[source]}
                  </span>
                  <span className="text-[11px] font-mono font-bold tracking-widest" style={{ color: srcColor }}>
                    {source}
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ background: "rgba(255,255,255,0.04)", color: "#4a5a6b" }}>
                    {cards.length}
                  </span>
                </div>
                <div className="space-y-2">
                  {cards.map((card) => (
                    <EvidenceCardItem key={card.id} card={card} />
                  ))}
                </div>
              </div>
            );
          })}
          {data.evidence_cards.length === 0 && (
            <div className="text-center py-8 text-sm" style={{ color: "#4a5a6b" }}>
              No evidence cards generated — investigation may be incomplete.
            </div>
          )}
        </div>
      )}

      {tab === "chain" && (
        <div className="space-y-2">
          {data.reasoning_chain.map((step, i) => (
            <div key={step.step} className="flex gap-3">
              {/* Step connector */}
              <div className="flex flex-col items-center">
                <div
                  className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-mono font-bold shrink-0"
                  style={{ background: "rgba(139,92,246,0.2)", border: "1px solid rgba(139,92,246,0.4)", color: "#a78bfa" }}
                >
                  {step.step}
                </div>
                {i < data.reasoning_chain.length - 1 && (
                  <div className="w-px flex-1 mt-1" style={{ background: "linear-gradient(to bottom, rgba(139,92,246,0.3), transparent)" }} />
                )}
              </div>

              {/* Step content */}
              <div className="flex-1 pb-4">
                <div
                  className="rounded-lg p-3"
                  style={{ background: "#19212a", border: "1px solid #232d38" }}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-sm font-semibold" style={{ color: "#cfdbe4" }}>
                      {step.label}
                    </span>
                    {step.evidence_ids.length > 0 && (
                      <span className="text-[10px] font-mono" style={{ color: "#4a5a6b" }}>
                        {step.evidence_ids.length} evidence item{step.evidence_ids.length !== 1 ? "s" : ""}
                      </span>
                    )}
                  </div>
                  <p className="text-xs leading-relaxed" style={{ color: "#7c8fa0" }}>
                    {step.detail}
                  </p>
                  {step.leads_to && (
                    <div className="flex items-center gap-1 mt-2">
                      <span className="text-[10px] font-mono" style={{ color: "#4a5a6b" }}>→ leads to:</span>
                      <span className="text-[10px] font-mono" style={{ color: "#a78bfa" }}>{step.leads_to}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}

          {data.reasoning_chain.length === 0 && (
            <div className="flex items-center gap-2 text-sm py-6" style={{ color: "#4a5a6b" }}>
              <Info size={14} />
              No reasoning chain available for this investigation.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

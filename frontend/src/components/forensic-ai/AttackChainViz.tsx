/**
 * AttackChainViz — Visual attack chain from Attacker → Steps → Outcome.
 * Built from evidence, not invented.
 */
import { ArrowRight, ShieldX, ShieldCheck } from "lucide-react";
import type { ForensicAIResult } from "../../types/investigation";

interface Props {
  data: ForensicAIResult;
}

const THREAT_COLORS = {
  node: { bg: "rgba(226,72,61,0.10)", border: "rgba(226,72,61,0.35)", text: "#ff6b5e", dot: "#e2483d" },
  safe: { bg: "rgba(61,220,151,0.08)", border: "rgba(61,220,151,0.3)", text: "#3ddc97", dot: "#3ddc97" },
};

export default function AttackChainViz({ data }: Props) {
  const chain = data.attack_chain;
  if (!chain.length) {
    return (
      <div className="text-sm text-center py-6" style={{ color: "#4a5a6b" }}>
        No attack chain data available for this investigation.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2 mb-1">
        <ShieldX size={14} style={{ color: "#e2483d" }} />
        <span className="text-xs font-mono font-bold tracking-widest" style={{ color: "#7c8fa0" }}>
          ATTACK CHAIN — {data.classification.primary.toUpperCase()}
        </span>
      </div>

      {/* Chain nodes — horizontal scroll on narrow screens, vertical on mobile */}
      <div className="overflow-x-auto pb-2">
        <div className="flex items-start gap-0 min-w-max">
          {chain.map((node, i) => {
            const colors = node.threat ? THREAT_COLORS.node : THREAT_COLORS.safe;
            const isLast = i === chain.length - 1;
            return (
              <div key={node.position} className="flex items-center gap-0">
                {/* Node card */}
                <div
                  className="rounded-xl p-3.5 flex flex-col items-center text-center relative"
                  style={{
                    width: "140px",
                    background: colors.bg,
                    border: `1px solid ${colors.border}`,
                  }}
                >
                  {/* Position bubble */}
                  <div
                    className="absolute -top-3 left-1/2 -translate-x-1/2 w-6 h-6 rounded-full flex items-center justify-center text-xs font-mono font-bold"
                    style={{ background: colors.dot, color: "#fff", boxShadow: `0 0 8px ${colors.dot}66` }}
                  >
                    {node.position}
                  </div>

                  <div className="mt-3 mb-1">
                    {node.threat ? (
                      <ShieldX size={16} style={{ color: colors.text }} />
                    ) : (
                      <ShieldCheck size={16} style={{ color: colors.text }} />
                    )}
                  </div>

                  <div className="text-xs font-bold mb-1.5" style={{ color: colors.text }}>
                    {node.label}
                  </div>

                  <div className="text-[10px] leading-tight" style={{ color: "#7c8fa0" }}>
                    {node.detail.length > 60 ? node.detail.substring(0, 57) + "…" : node.detail}
                  </div>
                </div>

                {/* Arrow connector */}
                {!isLast && (
                  <div className="flex items-center px-1" style={{ color: "#4a5a6b" }}>
                    <ArrowRight size={18} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Chain detail legend */}
      <div className="space-y-2 mt-2">
        {chain.map((node) => (
          <div
            key={node.position}
            className="flex gap-2.5 p-2.5 rounded-lg"
            style={{
              background: node.threat ? "rgba(226,72,61,0.05)" : "rgba(61,220,151,0.04)",
              border: `1px solid ${node.threat ? "rgba(226,72,61,0.15)" : "rgba(61,220,151,0.12)"}`,
            }}
          >
            <div
              className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-mono font-bold shrink-0 mt-0.5"
              style={{ background: node.threat ? "#e2483d" : "#3ddc97", color: "#fff" }}
            >
              {node.position}
            </div>
            <div>
              <div className="text-xs font-bold mb-0.5" style={{ color: node.threat ? "#ff6b5e" : "#3ddc97" }}>
                {node.label}
              </div>
              <div className="text-xs" style={{ color: "#7c8fa0" }}>
                {node.detail}
              </div>
            </div>
          </div>
        ))}
      </div>

      <p className="text-[11px]" style={{ color: "#4a5a6b" }}>
        ⚠️ Attack chain constructed from forensic evidence. Nodes labeled [AI INFERENCE] where no direct evidence confirmed the step.
      </p>
    </div>
  );
}

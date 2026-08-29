import { CheckCircle2, ShieldAlert, Sparkles, Scale } from "lucide-react";
import type { RiskScoreOut } from "../types/investigation";

interface Props {
  rsb: RiskScoreOut;
}

export default function ForensicEvidenceBreakdown({ rsb }: Props) {
  const explanation = rsb.explanation as any;
  const evidenceItems = explanation?.evidence_items || [];
  const combinationBonuses = explanation?.combination_bonuses || [];
  const score = rsb.overall_score;
  const classification = rsb.classification;

  return (
    <div className="card-lab p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-lab-700">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-phosphor-500/10 border border-phosphor-500/30 flex items-center justify-center">
            <Scale className="h-5 w-5 text-phosphor-400" />
          </div>
          <div>
            <h3 className="font-bold text-base text-lab-100">Forensic Evidence & Scoring Proof</h3>
            <p className="text-xs text-lab-400">
              Deterministic point-by-point calculation explaining the exact classification.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="font-data text-2xl font-bold text-phosphor-400">
              {score.toFixed(0)} <span className="text-xs text-lab-500 font-normal">/ 100</span>
            </div>
            <div className="text-[10px] text-lab-500 evidence-tag">AGGREGATED SCORE</div>
          </div>
          <span
            className={`status-pill px-3 py-1 text-xs ${
              classification === "CRITICAL"
                ? "bg-sev-critical text-crimson-glow border border-sev-critical"
                : classification === "HIGH"
                ? "bg-sev-high text-orange-signal border border-sev-high"
                : classification === "MEDIUM"
                ? "bg-sev-medium text-amber-signal border border-sev-medium"
                : "bg-sev-low text-phosphor-400 border border-sev-low"
            }`}
          >
            {classification} SEVERITY
          </span>
        </div>
      </div>

      {/* Primary Evidence Items */}
      <div>
        <div className="text-xs font-semibold text-lab-400 evidence-tag mb-3 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-orange-signal" />
          CORROBORATED FORENSIC EVIDENCE
        </div>

        {evidenceItems.length === 0 ? (
          <div className="text-xs text-lab-500 italic p-3 rounded bg-lab-850">
            No severe threat signals detected. Baseline score remains LOW.
          </div>
        ) : (
          <div className="space-y-2">
            {evidenceItems.map((item: any, idx: number) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 rounded-md bg-lab-850/80 border border-lab-700/70 hover:border-lab-600 transition-colors"
              >
                <div className="flex items-start gap-2.5">
                  <CheckCircle2 className="h-4 w-4 text-phosphor-500 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-lab-200">{item.name}</div>
                    <div className="text-[11px] text-lab-500 mt-0.5">{item.detail}</div>
                  </div>
                </div>
                <div className="font-data font-bold text-sm text-phosphor-400 shrink-0 ml-4">
                  +{item.points} <span className="text-[10px] text-lab-500 font-normal">pts</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Combination Bonuses */}
      {combinationBonuses.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-purple-signal evidence-tag mb-3 flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-purple-signal" />
            COMPOUND THREAT COMBINATION BONUSES
          </div>
          <div className="space-y-2">
            {combinationBonuses.map((bonus: any, idx: number) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 rounded-md bg-purple-signal/5 border border-purple-signal/30"
              >
                <div className="flex items-start gap-2.5">
                  <Sparkles className="h-4 w-4 text-purple-signal shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-purple-300">{bonus.name}</div>
                    <div className="text-[11px] text-lab-400 mt-0.5">{bonus.detail}</div>
                  </div>
                </div>
                <div className="font-data font-bold text-sm text-purple-400 shrink-0 ml-4">
                  +{bonus.points} <span className="text-[10px] text-lab-500 font-normal">pts</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Math Footer */}
      <div className="pt-3 border-t border-lab-700/70 flex flex-wrap items-center justify-between gap-2 text-xs text-lab-400">
        <div className="font-data text-[11px]">
          Score Formula: <span className="text-lab-300">min(100, evidence_points + combination_bonuses)</span>
        </div>
        <div className="font-data text-xs text-phosphor-400 font-bold">
          Total Calculated: {score.toFixed(1)} / 100
        </div>
      </div>
    </div>
  );
}

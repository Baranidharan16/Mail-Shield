import { useState } from "react";
import { CheckCircle2, AlertTriangle, ExternalLink, Info } from "lucide-react";
import type { Recommendation } from "../types/investigation";
import { SeverityBadge } from "./Badges";

const DEMO_ACTIONS = new Set([
  "QUARANTINE_EMAIL",
  "BLOCK_DOMAIN",
  "BLOCK_URL",
  "BLOCK_SENDER",
  "SEARCH_SIMILAR",
]);

interface Props {
  recommendations: Recommendation[];
}

export default function RecommendedResponsePanel({ recommendations }: Props) {
  const [approved, setApproved] = useState<Set<string>>(new Set());

  if (recommendations.length === 0) {
    return (
      <div className="p-6 text-center text-lab-500 text-sm">
        <Info className="h-6 w-6 mx-auto mb-2 opacity-40" />
        No recommended actions generated yet.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {recommendations.map((rec) => {
        const isDemo = DEMO_ACTIONS.has(rec.action?.toUpperCase?.());
        const isApproved = approved.has(rec.id) || rec.approval_status === "APPROVED";

        return (
          <div
            key={rec.id}
            className={`border rounded-md p-4 transition-all ${
              isApproved
                ? "border-phosphor-500/30 bg-phosphor-500/5"
                : "border-lab-700 bg-lab-900/40 hover:border-lab-600"
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  {isApproved ? (
                    <CheckCircle2 className="h-4 w-4 text-phosphor-500 shrink-0" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-amber-signal shrink-0" />
                  )}
                  <span className="text-sm font-semibold text-lab-200">
                    {rec.action.replace(/_/g, " ")}
                  </span>
                  {isDemo && (
                    <span className="text-[10px] evidence-tag text-lab-500 border border-lab-600 rounded px-1.5 py-0.5">DEMO ACTION</span>
                  )}
                </div>
                <p className="text-xs text-lab-400">{rec.reason}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <SeverityBadge level={rec.severity} />
                {rec.requires_human_approval && !isApproved && (
                  <button
                    onClick={() => setApproved((s) => new Set([...s, rec.id]))}
                    className="text-[11px] text-phosphor-400 border border-phosphor-500/30 rounded px-2.5 py-1 hover:bg-phosphor-500/10 transition-colors evidence-tag"
                  >
                    Approve
                  </button>
                )}
                {isApproved && (
                  <span className="text-[11px] text-phosphor-400 evidence-tag">APPROVED</span>
                )}
              </div>
            </div>

            {rec.requires_human_approval && !isApproved && (
              <div className="mt-2 text-[10px] text-lab-500 flex items-center gap-1">
                <ExternalLink className="h-3 w-3" />
                Requires analyst approval — no external system action taken automatically.
              </div>
            )}
          </div>
        );
      })}

      <p className="text-[11px] text-lab-600 italic mt-2">
        Actions marked DEMO ACTION do not connect to a real email gateway, firewall, or blocking system in this prototype environment.
        Human approval is required before any real-world action.
      </p>
    </div>
  );
}

import { useState } from "react";
import { ChevronDown, ChevronRight, Shield, Link2, Globe2, Server, MessageSquareWarning } from "lucide-react";
import type { RiskScoreOut } from "../types/investigation";
import type { AuthenticationResultOut } from "../types/investigation";

interface Props {
  rsb: RiskScoreOut;
  auth?: AuthenticationResultOut | null;
}

const DIMENSION_META: Record<string, { icon: any; label: string; color: string }> = {
  authentication:    { icon: Shield,               label: "Authentication Analysis",   color: "#e2483d" },
  header:            { icon: Server,               label: "Header Anomalies",           color: "#f97316" },
  sender_identity:   { icon: Globe2,               label: "Sender Identity",            color: "#e8a23d" },
  domain:            { icon: Globe2,               label: "Domain Reputation",          color: "#e8a23d" },
  url:               { icon: Link2,                label: "URL Analysis",               color: "#f97316" },
  social_engineering:{ icon: MessageSquareWarning, label: "Social Engineering",         color: "#e2483d" },
  infrastructure:    { icon: Server,               label: "Infrastructure",             color: "#7c8fa0" },
};

function FactorRow({
  name,
  dim,
  auth,
}: {
  name: string;
  dim: { score: number; weight: number; weighted_contribution: number; signals: string[] };
  auth?: AuthenticationResultOut | null;
}) {
  const [open, setOpen] = useState(false);
  const meta = DIMENSION_META[name] ?? { icon: Shield, label: name.replace(/_/g, " "), color: "#7c8fa0" };
  const Icon = meta.icon;
  const pct = Math.min(100, dim.score);
  const contribution = dim.weighted_contribution.toFixed(1);

  return (
    <div className="border border-lab-700 rounded-md overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-lab-800/60 transition-colors text-left"
      >
        <Icon className="h-4 w-4 shrink-0" style={{ color: meta.color }} strokeWidth={1.75} />
        <span className="flex-1 text-sm font-medium text-lab-200 capitalize">{meta.label}</span>
        <div className="flex items-center gap-3">
          {/* Mini bar */}
          <div className="w-24 h-1.5 bg-lab-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full"
              style={{ width: `${pct}%`, backgroundColor: meta.color, boxShadow: `0 0 6px ${meta.color}55` }}
            />
          </div>
          <span className="font-data text-xs text-lab-300 w-10 text-right">+{contribution}</span>
          {open ? <ChevronDown className="h-3.5 w-3.5 text-lab-500" /> : <ChevronRight className="h-3.5 w-3.5 text-lab-500" />}
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-0 bg-lab-900/40 border-t border-lab-700/60 space-y-3">
          {/* Score details */}
          <div className="grid grid-cols-3 gap-3 mt-3">
            <div className="text-center">
              <div className="font-data text-xl font-bold" style={{ color: meta.color }}>{dim.score.toFixed(0)}</div>
              <div className="text-[10px] text-lab-500 evidence-tag">RAW SCORE</div>
            </div>
            <div className="text-center">
              <div className="font-data text-xl font-bold text-lab-300">×{dim.weight.toFixed(2)}</div>
              <div className="text-[10px] text-lab-500 evidence-tag">WEIGHT</div>
            </div>
            <div className="text-center">
              <div className="font-data text-xl font-bold text-phosphor-400">+{contribution}</div>
              <div className="text-[10px] text-lab-500 evidence-tag">CONTRIBUTION</div>
            </div>
          </div>

          {/* Auth details for authentication row */}
          {name === "authentication" && auth && (
            <div className="space-y-1.5">
              {[
                { label: "SPF", value: auth.spf_result },
                { label: "DKIM", value: auth.dkim_result },
                { label: "DMARC", value: auth.dmarc_result },
                { label: "From ↔ Reply-To", value: auth.from_reply_to_aligned === null ? "unknown" : auth.from_reply_to_aligned ? "aligned" : "misaligned" },
              ].map(({ label, value }) => (
                <div key={label} className="flex justify-between text-xs">
                  <span className="text-lab-500">{label}</span>
                  <span className={`font-data ${
                    value === "PASS" || value === "aligned" ? "text-phosphor-400" :
                    value === "FAIL" || value === "misaligned" ? "text-crimson-glow" :
                    "text-amber-signal"
                  }`}>
                    {value ?? "—"}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Signals */}
          {dim.signals.length > 0 && (
            <div className="space-y-1">
              <div className="text-[10px] text-lab-500 evidence-tag">DETECTED SIGNALS</div>
              {dim.signals.map((s, i) => (
                <div key={i} className="flex gap-2 text-xs text-lab-300">
                  <span className="text-crimson-signal shrink-0">›</span>
                  {s}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function RiskBreakdownPanel({ rsb, auth }: Props) {
  const breakdown = rsb.explanation?.dimension_breakdown ?? {};

  return (
    <div className="space-y-2">
      {Object.entries(breakdown).map(([name, dim]) => (
        <FactorRow key={name} name={name} dim={dim} auth={auth} />
      ))}
      {/* Total */}
      <div className="flex justify-between items-center px-4 py-3 rounded-md bg-lab-800/60 border border-lab-600 mt-2">
        <span className="text-sm font-semibold text-lab-200">Total Risk Score</span>
        <span className="font-data font-bold text-xl text-phosphor-400">{rsb.overall_score.toFixed(1)} / 100</span>
      </div>
    </div>
  );
}

import { useState } from "react";
import { AlertOctagon, ShieldAlert, CheckCircle2, Lock, ArrowDownRight, ExternalLink } from "lucide-react";
import { ClassificationBadge } from "./Badges";

interface Props {
  caseId: string;
  riskScore: number;
  riskLevel: string;
  threatType?: string;
  detectedAt?: string;
  keyIndicators: string[];
  onScrollToSection?: (sectionId: string) => void;
}

export default function SOCAlertPanel({
  caseId,
  riskScore,
  riskLevel,
  threatType = "Phishing / Social Engineering",
  detectedAt,
  keyIndicators,
  onScrollToSection,
}: Props) {
  const [quarantined, setQuarantined] = useState(false);

  const isCritical = riskLevel === "CRITICAL";
  const borderColor = isCritical ? "border-crimson-signal/60" : "border-orange-signal/60";
  const glow = isCritical ? "glow-red shadow-red-950/40" : "glow-amber shadow-amber-950/40";

  return (
    <div className={`glass-card border-2 ${borderColor} ${glow} p-6 mb-6 shadow-2xl relative overflow-hidden`}>
      {/* Top Banner Tag */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-white/10 mb-5 relative z-10">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg flex items-center justify-center bg-crimson-signal/20 border border-crimson-signal/40 backdrop-blur-md">
            <AlertOctagon className="h-6 w-6 text-crimson-glow animate-pulse" strokeWidth={2} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-base tracking-wide text-crimson-glow evidence-tag">
                🚨 SOC SECURITY ALERT
              </span>
              <span className="live-dot" />
            </div>
            <div className="text-xs text-lab-400 font-data mt-0.5">
              INCIDENT ID: <span className="text-lab-200 font-bold">{caseId}</span>
              {detectedAt && (
                <span className="ml-2 text-lab-500">
                  · DETECTED: {new Date(detectedAt).toLocaleString()}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <ClassificationBadge level={riskLevel} size="lg" />
          <div className="text-right">
            <div className="font-data text-2xl font-bold text-crimson-glow leading-none">
              {riskScore.toFixed(0)}<span className="text-xs text-lab-500 font-normal">/100</span>
            </div>
            <div className="text-[10px] text-lab-500 evidence-tag">RISK SCORE</div>
          </div>
        </div>
      </div>

      {/* Threat Summary & Key Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 relative z-10">
        <div>
          <div className="text-[10px] text-lab-500 evidence-tag mb-1">CLASSIFIED THREAT TYPE</div>
          <div className="font-bold text-base text-lab-100 mb-3 flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-orange-signal" />
            {threatType}
          </div>

          <div className="text-[10px] text-lab-500 evidence-tag mb-2">KEY DETECTED INDICATORS</div>
          <div className="space-y-1.5">
            {keyIndicators.slice(0, 5).map((indicator, idx) => (
              <div key={idx} className="flex items-start gap-2 text-xs text-lab-300">
                <span className="text-crimson-glow font-bold mt-0.5">•</span>
                <span className="leading-relaxed">{indicator}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recommended Actions & Buttons */}
        <div className="space-y-4 md:border-l md:border-white/10 md:pl-6">
          <div>
            <div className="text-[10px] text-lab-500 evidence-tag mb-1">RECOMMENDED IMMEDIATE ACTIONS</div>
            <div className="text-xs text-lab-300 space-y-1">
              <div className="flex items-center gap-2 text-phosphor-400 font-semibold">
                <CheckCircle2 className="h-3.5 w-3.5" /> 1. Quarantine email from inbox
              </div>
              <div className="flex items-center gap-2 text-lab-400">
                <span className="text-lab-500 font-data">›</span> 2. Block sender domain & source IP relay
              </div>
              <div className="flex items-center gap-2 text-lab-400">
                <span className="text-lab-500 font-data">›</span> 3. Preserve SHA-256 evidence chain of custody
              </div>
            </div>
          </div>

          <div className="flex flex-wrap gap-2.5 pt-2">
            <button
              onClick={() => setQuarantined(!quarantined)}
              className={`px-4 py-2 rounded-md font-bold text-xs evidence-tag transition-all flex items-center gap-2 ${
                quarantined
                  ? "bg-phosphor-500/20 text-phosphor-400 border border-phosphor-500/50"
                  : "bg-crimson-signal text-lab-950 hover:bg-crimson-glow shadow-lg"
              }`}
            >
              <Lock className="h-3.5 w-3.5" />
              {quarantined ? "✓ EMAIL QUARANTINED" : "QUARANTINE EMAIL"}
            </button>

            {onScrollToSection && (
              <>
                <button
                  onClick={() => onScrollToSection("attack-graph-section")}
                  className="px-3.5 py-2 rounded-md text-xs font-semibold text-lab-300 border border-white/10 hover:bg-white/10 hover:text-white transition-colors flex items-center gap-1.5 backdrop-blur-md"
                >
                  <ArrowDownRight className="h-3.5 w-3.5 text-phosphor-500" />
                  View Attack Graph
                </button>
                <button
                  onClick={() => onScrollToSection("evidence-breakdown-section")}
                  className="px-3.5 py-2 rounded-md text-xs font-semibold text-lab-300 border border-white/10 hover:bg-white/10 hover:text-white transition-colors flex items-center gap-1.5 backdrop-blur-md"
                >
                  <ExternalLink className="h-3.5 w-3.5 text-blue-signal" />
                  Forensic Evidence
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

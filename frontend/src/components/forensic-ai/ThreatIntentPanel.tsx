/**
 * ThreatIntentPanel — Displays primary/secondary classification, threat intent,
 * IOCs, and related cases.
 */
import { Target, Crosshair, Link2, Users } from "lucide-react";
import type { ForensicAIResult } from "../../types/investigation";

interface Props {
  data: ForensicAIResult;
}

const INTENT_COLORS: Record<string, string> = {
  "Credential Theft": "#e2483d",
  "Financial Theft": "#f97316",
  "Malware Delivery": "#ff6b5e",
  "Identity Impersonation": "#a78bfa",
  "Account Takeover": "#e2483d",
  "Data Collection": "#e8a23d",
  "Payment Redirection": "#f97316",
  "Extortion": "#ff6b5e",
  "Threat / Intimidation": "#e2483d",
  "Social Engineering": "#e8a23d",
  "Spam Advertising": "#3b82f6",
  "Unknown": "#7c8fa0",
};

export default function ThreatIntentPanel({ data }: Props) {
  const intentColor = INTENT_COLORS[data.threat_intent.intent] ?? "#7c8fa0";
  const conf = data.threat_intent.confidence;
  const cls = data.classification;

  return (
    <div className="space-y-4">
      {/* Intent card */}
      <div
        className="rounded-xl p-4"
        style={{
          background: `rgba(${hexToRgb(intentColor)}, 0.07)`,
          border: `1px solid rgba(${hexToRgb(intentColor)}, 0.3)`,
        }}
      >
        <div className="flex items-center gap-2 mb-3">
          <Crosshair size={14} style={{ color: intentColor }} />
          <span className="text-xs font-mono font-bold tracking-wider" style={{ color: intentColor }}>
            THREAT INTENT
          </span>
        </div>

        <div className="flex items-center justify-between mb-2">
          <span className="text-xl font-bold" style={{ color: "#cfdbe4" }}>
            {data.threat_intent.intent}
          </span>
          <span className="text-sm font-mono font-bold" style={{ color: intentColor }}>
            {(conf * 100).toFixed(0)}%
          </span>
        </div>

        {/* Confidence bar */}
        <div className="mb-3 h-1.5 rounded-full" style={{ background: "#232d38" }}>
          <div
            className="h-full rounded-full transition-all"
            style={{ width: `${conf * 100}%`, background: `linear-gradient(90deg, ${intentColor}, ${intentColor}cc)` }}
          />
        </div>

        <p className="text-sm leading-relaxed" style={{ color: "#a9bac8" }}>
          {data.threat_intent.reason}
        </p>
      </div>

      {/* Classification breakdown */}
      <div
        className="rounded-xl p-4"
        style={{ background: "#19212a", border: "1px solid #232d38" }}
      >
        <div className="flex items-center gap-2 mb-3">
          <Target size={14} style={{ color: "#a78bfa" }} />
          <span className="text-xs font-mono font-bold tracking-wider" style={{ color: "#7c8fa0" }}>
            ATTACK CLASSIFICATION
          </span>
        </div>

        <div className="flex items-center gap-2 mb-3">
          <div
            className="px-3 py-1.5 rounded-lg text-sm font-bold"
            style={{ background: "rgba(139,92,246,0.15)", color: "#c4b5fd", border: "1px solid rgba(139,92,246,0.3)" }}
          >
            {cls.primary}
          </div>
          <span className="text-xs font-mono" style={{ color: "#4a5a6b" }}>
            {(cls.confidence * 100).toFixed(0)}% confidence
          </span>
        </div>

        {cls.secondary.length > 0 && (
          <div>
            <p className="text-[11px] font-mono mb-2" style={{ color: "#4a5a6b" }}>SECONDARY CLASSIFICATIONS:</p>
            <div className="flex flex-wrap gap-2">
              {cls.secondary.map((s) => (
                <span
                  key={s}
                  className="text-xs px-2 py-1 rounded font-mono"
                  style={{ background: "rgba(139,92,246,0.08)", color: "#c4b5fd", border: "1px solid rgba(139,92,246,0.18)" }}
                >
                  {s}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Related cases */}
      {data.related_cases.length > 0 && (
        <div
          className="rounded-xl p-4"
          style={{ background: "#19212a", border: "1px solid #232d38" }}
        >
          <div className="flex items-center gap-2 mb-3">
            <Users size={14} style={{ color: "#e8a23d" }} />
            <span className="text-xs font-mono font-bold tracking-wider" style={{ color: "#7c8fa0" }}>
              RELATED CASES — CAMPAIGN CORRELATION
            </span>
          </div>
          <div className="space-y-2">
            {data.related_cases.map((rc) => (
              <div
                key={rc.investigation_id}
                className="flex items-center justify-between p-3 rounded-lg"
                style={{ background: "rgba(232,162,61,0.06)", border: "1px solid rgba(232,162,61,0.2)" }}
              >
                <div>
                  <div className="text-sm font-mono font-bold" style={{ color: "#e8a23d" }}>
                    {rc.case_id}
                  </div>
                  <div className="text-xs mt-0.5" style={{ color: "#4a5a6b" }}>
                    {rc.relationship} — {(rc.similarity_score * 100).toFixed(0)}% similarity
                  </div>
                  {rc.reasons.length > 0 && (
                    <div className="text-xs mt-1" style={{ color: "#7c8fa0" }}>
                      {rc.reasons.slice(0, 2).join(", ")}
                    </div>
                  )}
                </div>
                <Link2 size={14} style={{ color: "#e8a23d", opacity: 0.6 }} />
              </div>
            ))}
          </div>
          <p className="text-xs mt-3" style={{ color: "#4a5a6b" }}>
            ⚠️ Shared infrastructure suggests a coordinated attack campaign.
          </p>
        </div>
      )}

      {/* Recommended response */}
      <div
        className="rounded-xl p-4"
        style={{ background: "rgba(61,220,151,0.04)", border: "1px solid rgba(61,220,151,0.15)" }}
      >
        <p className="text-xs font-mono font-bold mb-2 tracking-wider" style={{ color: "#3ddc97" }}>
          RECOMMENDED RESPONSE
        </p>
        <p className="text-sm leading-relaxed" style={{ color: "#a9bac8" }}>
          {data.recommended_response}
        </p>
      </div>
    </div>
  );
}

// Tiny utility: hex to rgb string
function hexToRgb(hex: string): string {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  if (!result) return "139,92,246";
  return `${parseInt(result[1], 16)},${parseInt(result[2], 16)},${parseInt(result[3], 16)}`;
}

/**
 * SocialEngineeringPanel — Displays 23 social engineering signal scores
 * with bar chart visualization, sorted by score.
 * Clearly labeled as "detected linguistic signals" — NOT psychological certainty.
 */
import { useState } from "react";
import { AlertTriangle, Eye, EyeOff } from "lucide-react";
import type { ForensicAIResult, SocialEngineeringSignal } from "../../types/investigation";

interface Props {
  data: ForensicAIResult;
}

function ScoreBar({ score }: { score: number }) {
  const color =
    score >= 70 ? "#e2483d" : score >= 50 ? "#f97316" : score >= 30 ? "#e8a23d" : "#3b82f6";
  return (
    <div
      className="flex-1 h-2 rounded-full overflow-hidden"
      style={{ background: "#232d38" }}
    >
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${score}%`, background: `linear-gradient(90deg, ${color}aa, ${color})` }}
      />
    </div>
  );
}

function SignalRow({ signal, highlighted }: { signal: SocialEngineeringSignal; highlighted: boolean }) {
  const [showEvidence, setShowEvidence] = useState(false);
  const scoreColor =
    signal.score >= 70 ? "#e2483d" : signal.score >= 50 ? "#f97316" : signal.score >= 30 ? "#e8a23d" : "#7c8fa0";

  if (!signal.detected) return null;

  return (
    <div
      className="rounded-lg p-3 transition-all"
      style={{
        background: highlighted ? "rgba(226,72,61,0.07)" : "rgba(255,255,255,0.02)",
        border: highlighted ? "1px solid rgba(226,72,61,0.2)" : "1px solid transparent",
      }}
    >
      <div className="flex items-center gap-3">
        <div
          className="w-2 h-2 rounded-full shrink-0"
          style={{ background: scoreColor, boxShadow: signal.score >= 60 ? `0 0 6px ${scoreColor}` : "none" }}
        />
        <span className="text-xs font-medium flex-1" style={{ color: "#cfdbe4" }}>
          {signal.signal}
        </span>
        <ScoreBar score={signal.score} />
        <span className="text-xs font-mono font-bold w-10 text-right" style={{ color: scoreColor }}>
          {signal.score}
        </span>
        <button
          className="ml-1 transition-opacity hover:opacity-80"
          onClick={() => setShowEvidence((v) => !v)}
        >
          {showEvidence ? (
            <EyeOff size={12} style={{ color: "#4a5a6b" }} />
          ) : (
            <Eye size={12} style={{ color: "#4a5a6b" }} />
          )}
        </button>
      </div>
      {showEvidence && signal.evidence !== "Not detected" && (
        <div
          className="mt-2 ml-5 text-[11px] font-mono px-2 py-1.5 rounded"
          style={{ background: "rgba(0,0,0,0.3)", color: "#7c8fa0" }}
        >
          {signal.evidence}
        </div>
      )}
    </div>
  );
}

export default function SocialEngineeringPanel({ data }: Props) {
  const [showAll, setShowAll] = useState(false);

  const detected = data.social_engineering_signals
    .filter((s) => s.detected)
    .sort((a, b) => b.score - a.score);

  const notDetected = data.social_engineering_signals.filter((s) => !s.detected);
  const visibleDetected = showAll ? detected : detected.slice(0, 8);

  const manipRisk = data.overall_manipulation_risk;
  const manipColor =
    manipRisk >= 70 ? "#e2483d" : manipRisk >= 45 ? "#f97316" : manipRisk >= 25 ? "#e8a23d" : "#3ddc97";

  const criticalSignals = detected.filter((s) => s.score >= 70);
  const highSignals = detected.filter((s) => s.score >= 50 && s.score < 70);

  return (
    <div className="space-y-4">
      {/* Overall manipulation risk gauge */}
      <div
        className="rounded-xl p-4 flex items-center gap-5"
        style={{ background: "#19212a", border: "1px solid #232d38" }}
      >
        {/* Circular indicator */}
        <div className="relative flex items-center justify-center shrink-0">
          <svg width="72" height="72">
            <circle cx="36" cy="36" r="28" fill="none" stroke="#232d38" strokeWidth="6" />
            <circle
              cx="36" cy="36" r="28"
              fill="none"
              stroke={manipColor}
              strokeWidth="6"
              strokeDasharray={`${175.93 * manipRisk / 100} 175.93`}
              strokeLinecap="round"
              transform="rotate(-90 36 36)"
              style={{ filter: `drop-shadow(0 0 4px ${manipColor}66)` }}
            />
          </svg>
          <span
            className="absolute text-lg font-bold font-mono"
            style={{ color: manipColor }}
          >
            {manipRisk}
          </span>
        </div>

        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-bold" style={{ color: "#cfdbe4" }}>
              Overall Manipulation Risk
            </span>
          </div>
          <p className="text-xs" style={{ color: "#7c8fa0" }}>
            {detected.length} of {data.social_engineering_signals.length} signal types detected ·{" "}
            {criticalSignals.length} critical · {highSignals.length} high
          </p>
          <div className="flex flex-wrap gap-1 mt-2">
            {criticalSignals.slice(0, 3).map((s) => (
              <span
                key={s.signal}
                className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                style={{ background: "rgba(226,72,61,0.12)", color: "#ff6b5e", border: "1px solid rgba(226,72,61,0.3)" }}
              >
                {s.signal}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Disclaimer */}
      <div
        className="flex items-start gap-2 px-3 py-2.5 rounded-lg text-xs"
        style={{ background: "rgba(232,162,61,0.06)", border: "1px solid rgba(232,162,61,0.18)" }}
      >
        <AlertTriangle size={12} style={{ color: "#e8a23d", marginTop: "1px", flexShrink: 0 }} />
        <span style={{ color: "#7c8fa0" }}>
          These are <strong style={{ color: "#e8a23d" }}>detected linguistic signals</strong> in the email content — content patterns that indicate manipulation
          intent, not psychological certainties. Analyst judgment required.
        </span>
      </div>

      {/* Signal list */}
      {detected.length === 0 ? (
        <div className="text-center py-8 text-sm" style={{ color: "#4a5a6b" }}>
          No social engineering signals detected in this investigation.
        </div>
      ) : (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between mb-2">
            <p className="text-[11px] font-mono tracking-wider" style={{ color: "#4a5a6b" }}>
              DETECTED SIGNALS — SORTED BY SCORE
            </p>
            <p className="text-[11px] font-mono" style={{ color: "#4a5a6b" }}>
              SIGNAL / 100
            </p>
          </div>
          {visibleDetected.map((s) => (
            <SignalRow key={s.signal} signal={s} highlighted={s.score >= 70} />
          ))}

          {detected.length > 8 && (
            <button
              className="w-full text-xs py-2 rounded-lg font-mono transition-colors hover:brightness-110"
              style={{ background: "rgba(255,255,255,0.04)", color: "#7c8fa0", border: "1px solid #232d38" }}
              onClick={() => setShowAll((v) => !v)}
            >
              {showAll ? `Show Less` : `Show All ${detected.length} Detected Signals`}
            </button>
          )}

          {/* Not detected */}
          {notDetected.length > 0 && (
            <details className="mt-3">
              <summary className="text-[11px] font-mono cursor-pointer" style={{ color: "#4a5a6b" }}>
                {notDetected.length} signal types not detected ▸
              </summary>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {notDetected.map((s) => (
                  <span
                    key={s.signal}
                    className="text-[10px] font-mono px-2 py-0.5 rounded"
                    style={{ background: "rgba(255,255,255,0.03)", color: "#4a5a6b", border: "1px solid rgba(255,255,255,0.05)" }}
                  >
                    {s.signal}
                  </span>
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

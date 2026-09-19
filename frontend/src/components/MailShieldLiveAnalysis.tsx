import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Sparkles,
  ArrowRight,
  RefreshCw,
  Cpu,
  Brain,
  Search,
  Lock,
} from "lucide-react";
import type { MailShieldAnalysisResponse } from "../types/investigation";
import ThreatGauge from "./ThreatGauge";
import type { Level } from "./Badges";
import { quarantineInvestigation } from "../api/client";
import { QuarantineConfirmModal } from "./QuarantineConfirmModal";
import { useState } from "react";

interface Props {
  data: MailShieldAnalysisResponse;
  onReset: () => void;
  onViewDetails?: () => void;
  investigationId?: string;
}

export default function MailShieldLiveAnalysis({ data, onReset, onViewDetails, investigationId }: Props) {
  const isPhishing = data.ml.prediction.toLowerCase() === "phishing";
  const riskLevel = data.risk.level as Level;

  const [isQuarantineModalOpen, setIsQuarantineModalOpen] = useState(false);
  const [quarantineState, setQuarantineState] = useState<"idle" | "loading" | "success" | "failed">("idle");
  const [quarantineFeedback, setQuarantineFeedback] = useState<{ type: "success" | "error"; text: string } | null>(null);

  async function handleConfirmQuarantine() {
    const targetId = investigationId || data.analysis_id;
    if (!targetId) return;
    setQuarantineState("loading");
    setQuarantineFeedback(null);
    try {
      const res = await quarantineInvestigation(targetId);
      setQuarantineState("success");
      setQuarantineFeedback({
        type: "success",
        text: `Email successfully isolated under ${res.label_name || "Quarantine"} in Gmail and removed from INBOX.`,
      });
      setIsQuarantineModalOpen(false);
    } catch (err: any) {
      setQuarantineState("failed");
      const detail = err?.response?.data?.detail || "Quarantine action failed via Gmail API.";
      setQuarantineFeedback({
        type: "error",
        text: `QUARANTINE FAILED: ${detail}`,
      });
      setIsQuarantineModalOpen(false);
    }
  }

  // Format NLP threat patterns for display
  const threatPatterns = [
    { label: "Urgency Coercion", value: data.nlp.urgency, key: "urgency" },
    { label: "Credential Request", value: data.nlp.credential_request, key: "credential_request" },
    { label: "Financial Manipulation", value: data.nlp.financial_manipulation, key: "financial_manipulation" },
    { label: "Entity Impersonation", value: data.nlp.impersonation, key: "impersonation" },
    { label: "Threat Language", value: data.nlp.threat_language, key: "threat_language" },
    { label: "Suspicious Call-to-Action", value: data.nlp.suspicious_action, key: "suspicious_action" },
  ];

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl mx-auto">
      {/* Top Banner: Email Metadata */}
      <div className="glass-section p-5 md:p-6 rounded-2xl border-white/10 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-phosphor-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/5 pb-4 mb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="status-pill text-[10px] font-mono border bg-white/5 text-lab-300 border-white/10">
                ANALYSIS ID: {data.analysis_id.slice(0, 8)}
              </span>
              {data.forensics.reply_to_mismatch && (
                <span className="status-pill text-[10px] font-mono border bg-crimson-signal/15 text-crimson-glow border-crimson-signal/30 flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" /> DOMAIN MISMATCH
                </span>
              )}
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight break-words">
              {data.email.subject || "No Subject"}
            </h2>
          </div>

          <div className="flex items-center gap-2 self-start md:self-auto flex-wrap">
            {(investigationId || data.analysis_id) && (
              quarantineState === "success" ? (
                <span className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-xs font-bold font-mono tracking-wider">
                  <Lock className="h-3.5 w-3.5 text-emerald-400" /> QUARANTINED
                </span>
              ) : (
                <button
                  onClick={() => setIsQuarantineModalOpen(true)}
                  disabled={quarantineState === "loading"}
                  className="btn-glass text-xs py-2 px-3 flex items-center gap-1.5 border-red-500/40 bg-red-600/20 hover:bg-red-600/30 text-red-300 cursor-pointer disabled:opacity-60 font-semibold"
                >
                  {quarantineState === "loading" ? (
                    <>
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" /> Quarantining...
                    </>
                  ) : quarantineState === "failed" ? (
                    <>
                      <AlertTriangle className="h-3.5 w-3.5 text-red-400" /> QUARANTINE FAILED (RETRY)
                    </>
                  ) : (
                    <>
                      <Lock className="h-3.5 w-3.5 text-red-400" /> QUARANTINE
                    </>
                  )}
                </button>
              )
            )}
            <button
              onClick={onReset}
              className="btn-glass text-xs py-2 px-3 flex items-center gap-1.5 text-lab-300 hover:text-white"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Analyze Another
            </button>
            {onViewDetails && (
              <button
                onClick={onViewDetails}
                className="btn-glass-primary text-xs py-2 px-3 flex items-center gap-1.5"
              >
                Full Dossier <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {quarantineFeedback && (
          <div
            className={`mb-4 p-3 rounded-xl border flex items-center justify-between text-xs font-mono animate-fade-in ${
              quarantineFeedback.type === "success"
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                : "bg-red-500/10 border-red-500/30 text-red-300"
            }`}
          >
            <div className="flex items-center gap-2">
              {quarantineFeedback.type === "success" ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
              )}
              <span>{quarantineFeedback.text}</span>
            </div>
            <button
              onClick={() => setQuarantineFeedback(null)}
              className="text-slate-400 hover:text-white p-1 cursor-pointer"
            >
              ×
            </button>
          </div>
        )}

        {/* Sender / Routing Details */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
          <div className="bg-black/20 p-2.5 rounded-xl border border-white/5">
            <div className="text-lab-500 text-[11px] mb-0.5">Sender (From)</div>
            <div className="font-mono text-lab-100 truncate" title={data.email.sender}>
              {data.email.sender || "Unknown"}
            </div>
            <div className="text-[10px] text-lab-400 mt-1">Domain: {data.email.sender_domain || "—"}</div>
          </div>

          <div className="bg-black/20 p-2.5 rounded-xl border border-white/5">
            <div className="text-lab-500 text-[11px] mb-0.5">Reply-To Address</div>
            <div className="font-mono text-lab-100 truncate" title={data.email.reply_to}>
              {data.email.reply_to || data.email.sender || "—"}
            </div>
            <div className="text-[10px] text-lab-400 mt-1">
              Destination Domain: {data.email.reply_to_domain || "—"}
            </div>
          </div>

          <div className="bg-black/20 p-2.5 rounded-xl border border-white/5">
            <div className="text-lab-500 text-[11px] mb-0.5">Forensic Artifacts</div>
            <div className="text-lab-200">
              {data.forensics.urls?.length ?? 0} URLs detected · {data.forensics.attachment_count ?? 0} Attachments
            </div>
            <div className="text-[10px] text-phosphor-400 mt-1 font-mono">
              Hops: {data.forensics.received_hop_count} MTA nodes
            </div>
          </div>
        </div>
      </div>

      {/* Primary Verdicts Grid (Risk Score + ML Classification + Forensics) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Card 1: Deterministic Risk Engine */}
        <div className="glass-section p-6 rounded-2xl flex flex-col items-center justify-between text-center relative border-white/10">
          <div className="w-full flex items-center justify-between text-xs text-lab-400 border-b border-white/5 pb-2.5 mb-3">
            <span className="font-mono tracking-wider text-[11px] uppercase flex items-center gap-1.5">
              <Cpu className="h-3.5 w-3.5 text-phosphor-400" /> RISK ENGINE
            </span>
            <span className="text-[10px] text-lab-500">Deterministic</span>
          </div>

          <ThreatGauge
            score={data.risk.score}
            classification={riskLevel}
            confidence={data.ml.confidence}
            size={160}
          />

          <div className="w-full mt-4 pt-3 border-t border-white/5 text-left text-xs space-y-1.5 max-h-32 overflow-y-auto custom-scrollbar">
            <div className="text-[10px] uppercase font-mono text-lab-400">Scoring Evidence Factors:</div>
            {data.risk.contributing_factors.map((f, i) => (
              <div key={i} className="text-[11px] text-lab-300 flex items-start gap-1.5">
                <span className="text-phosphor-500 mt-0.5">•</span>
                <span>{f}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Card 2: ML Phishing Model */}
        <div className="glass-section p-6 rounded-2xl flex flex-col justify-between border-white/10">
          <div>
            <div className="flex items-center justify-between text-xs text-lab-400 border-b border-white/5 pb-2.5 mb-4">
              <span className="font-mono tracking-wider text-[11px] uppercase flex items-center gap-1.5">
                <Brain className="h-3.5 w-3.5 text-blue-400" /> ML PHISHING MODEL
              </span>
              <span className="text-[10px] text-lab-500 font-mono">ML threat model v2 (calibrated probability)</span>
            </div>

            <div className="text-center py-3">
              <div
                className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider mb-3 ${
                  isPhishing
                    ? "bg-crimson-signal/15 text-crimson-glow border border-crimson-signal/40"
                    : "bg-phosphor-500/15 text-phosphor-300 border border-phosphor-500/40"
                }`}
              >
                {isPhishing ? (
                  <>
                    <ShieldAlert className="h-4 w-4" /> PHISHING DETECTED
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-4 w-4" /> LEGITIMATE EMAIL
                  </>
                )}
              </div>

              <div className="text-3xl font-bold font-data text-white mb-1">
                {(data.ml.phishing_probability * 100).toFixed(1)}%
              </div>
              <div className="text-xs text-lab-400">Phishing Probability</div>
            </div>

            <div className="space-y-2 mt-4 text-xs">
              <div className="flex justify-between text-lab-300 text-[11px]">
                <span>Inference Confidence:</span>
                <span className="font-mono text-white">{(data.ml.confidence * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full bg-lab-800 rounded-full h-2 overflow-hidden">
                <div
                  className={`h-full transition-all duration-700 ${
                    isPhishing ? "bg-crimson-signal" : "bg-phosphor-500"
                  }`}
                  style={{ width: `${Math.max(5, data.ml.phishing_probability * 100)}%` }}
                />
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-white/5 text-[11px] text-lab-500">
            Bidirectional deep learning feature representation analyzing email linguistic syntax and behavioral lures.
          </div>
        </div>

        {/* Card 3: Forensic & Authentication Signals */}
        <div className="glass-section p-6 rounded-2xl flex flex-col justify-between border-white/10">
          <div>
            <div className="flex items-center justify-between text-xs text-lab-400 border-b border-white/5 pb-2.5 mb-4">
              <span className="font-mono tracking-wider text-[11px] uppercase flex items-center gap-1.5">
                <Search className="h-3.5 w-3.5 text-amber-400" /> FORENSIC SIGNALS
              </span>
              <span className="text-[10px] text-lab-500">RFC Standards</span>
            </div>

            <div className="space-y-3">
              {/* SPF */}
              <div className="flex items-center justify-between p-2 rounded-xl bg-black/20 border border-white/5 text-xs">
                <span className="text-lab-300 font-mono">SPF Status:</span>
                <span
                  className={`font-bold font-mono px-2 py-0.5 rounded text-[11px] ${
                    data.forensics.spf === "PASS"
                      ? "text-phosphor-400 bg-phosphor-500/10 border border-phosphor-500/20"
                      : data.forensics.spf in ["FAIL", "PERMERROR"]
                      ? "text-crimson-glow bg-crimson-signal/15 border border-crimson-signal/30"
                      : "text-amber-signal bg-amber-signal/15 border border-amber-signal/30"
                  }`}
                >
                  {data.forensics.spf}
                </span>
              </div>

              {/* DKIM */}
              <div className="flex items-center justify-between p-2 rounded-xl bg-black/20 border border-white/5 text-xs">
                <span className="text-lab-300 font-mono">DKIM Signature:</span>
                <span
                  className={`font-bold font-mono px-2 py-0.5 rounded text-[11px] ${
                    data.forensics.dkim === "PASS"
                      ? "text-phosphor-400 bg-phosphor-500/10 border border-phosphor-500/20"
                      : data.forensics.dkim in ["FAIL", "PERMERROR"]
                      ? "text-crimson-glow bg-crimson-signal/15 border border-crimson-signal/30"
                      : "text-lab-400 bg-lab-800/40"
                  }`}
                >
                  {data.forensics.dkim}
                </span>
              </div>

              {/* DMARC */}
              <div className="flex items-center justify-between p-2 rounded-xl bg-black/20 border border-white/5 text-xs">
                <span className="text-lab-300 font-mono">DMARC Policy:</span>
                <span
                  className={`font-bold font-mono px-2 py-0.5 rounded text-[11px] ${
                    data.forensics.dmarc === "PASS"
                      ? "text-phosphor-400 bg-phosphor-500/10 border border-phosphor-500/20"
                      : data.forensics.dmarc in ["FAIL", "REJECT", "QUARANTINE"]
                      ? "text-crimson-glow bg-crimson-signal/15 border border-crimson-signal/30"
                      : "text-lab-400 bg-lab-800/40"
                  }`}
                >
                  {data.forensics.dmarc}
                </span>
              </div>

              {/* URL Suspicion Count */}
              <div className="flex items-center justify-between p-2 rounded-xl bg-black/20 border border-white/5 text-xs">
                <span className="text-lab-300">Suspicious URLs:</span>
                <span
                  className={`font-bold font-mono px-2 py-0.5 rounded text-[11px] ${
                    data.forensics.suspicious_url_count > 0
                      ? "text-crimson-glow bg-crimson-signal/15"
                      : "text-phosphor-400 bg-phosphor-500/10"
                  }`}
                >
                  {data.forensics.suspicious_url_count} flagged
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-white/5 text-[11px] text-lab-500 truncate">
            Domains: {data.forensics.domains.join(", ") || "None"}
          </div>
        </div>
      </div>

      {/* NLP Threat-Pattern Classifier Breakdown (All 6 Patterns) */}
      <div className="glass-section p-6 rounded-2xl border-white/10">
        <div className="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-phosphor-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              MailShield NLP Threat-Pattern Classifier
            </h3>
          </div>
          <span className="text-xs text-lab-500 font-mono">Rule-matched social-engineering patterns · 6 dimensions</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {threatPatterns.map((pat) => {
            const pct = Math.round(pat.value * 100);
            const isHigh = pct >= 65;
            const isMed = pct >= 35 && pct < 65;
            const barColor = isHigh
              ? "bg-crimson-signal"
              : isMed
              ? "bg-amber-signal"
              : "bg-phosphor-500";

            return (
              <div
                key={pat.key}
                className="bg-black/25 p-3.5 rounded-xl border border-white/5 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-medium text-lab-200">{pat.label}</span>
                  <span
                    className={`font-mono text-xs font-bold ${
                      isHigh ? "text-crimson-glow" : isMed ? "text-amber-signal" : "text-phosphor-400"
                    }`}
                  >
                    {pct}%
                  </span>
                </div>

                <div className="w-full bg-lab-800/60 rounded-full h-1.5 overflow-hidden mb-2">
                  <div
                    className={`h-full transition-all duration-500 ${barColor}`}
                    style={{ width: `${Math.max(4, pct)}%` }}
                  />
                </div>

                <div className="text-[10px] text-lab-500 font-mono">
                  {isHigh ? "Critical Threat Signal" : isMed ? "Moderate Signal" : "Baseline / Safe"}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* AI Reasoning & Explanation Layer */}
      <div className="glass-section p-6 rounded-2xl border-white/10 space-y-4">
        <div className="flex items-center justify-between border-b border-white/5 pb-3">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-phosphor-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              AI Forensic Reasoning & SOC Guidance
            </h3>
          </div>
          <span className="text-[11px] text-phosphor-400/80 bg-phosphor-500/10 px-2 py-0.5 rounded border border-phosphor-500/20 font-mono">
            Correlated Evidence
          </span>
        </div>

        {/* Summary Box */}
        <div className="p-4 rounded-xl bg-phosphor-500/5 border border-phosphor-500/15 text-sm text-lab-200 leading-relaxed">
          {data.ai_reasoning.summary}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* Why Detected */}
          <div className="bg-black/20 p-4 rounded-xl border border-white/5 space-y-2">
            <div className="font-semibold text-white uppercase tracking-wider text-[11px] font-mono flex items-center gap-1.5">
              <Search className="h-3.5 w-3.5 text-blue-400" /> Detection Rationale
            </div>
            <ul className="space-y-1.5">
              {data.ai_reasoning.why_detected.map((item, idx) => (
                <li key={idx} className="text-lab-300 flex items-start gap-2">
                  <span className="text-blue-400 mt-0.5">›</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Key Indicators */}
          <div className="bg-black/20 p-4 rounded-xl border border-white/5 space-y-2">
            <div className="font-semibold text-white uppercase tracking-wider text-[11px] font-mono flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-400" /> Observable Threat Indicators
            </div>
            <ul className="space-y-1.5">
              {data.ai_reasoning.key_indicators.map((item, idx) => (
                <li key={idx} className="text-lab-300 flex items-start gap-2">
                  <span className="text-amber-400 mt-0.5">›</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Recommended Incident Response Actions */}
        {data.ai_reasoning.recommended_actions.length > 0 && (
          <div className="bg-black/25 p-4 rounded-xl border border-white/5 space-y-2.5">
            <div className="font-semibold text-white uppercase tracking-wider text-[11px] font-mono flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-phosphor-400" /> Recommended Containment Actions
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {data.ai_reasoning.recommended_actions.map((act, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5 flex items-start gap-2 text-xs text-lab-200"
                >
                  <span className="h-4 w-4 rounded-full bg-phosphor-500/20 text-phosphor-400 text-[10px] font-mono flex items-center justify-center shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <span>{act}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Confidence Note */}
        <div className="text-[11px] text-lab-500 flex items-center gap-1.5 border-t border-white/5 pt-3">
          <Clock className="h-3 w-3 text-lab-600" />
          <span>{data.ai_reasoning.confidence_note}</span>
        </div>
      </div>

      {/* Quarantine Confirmation Modal */}
      <QuarantineConfirmModal
        isOpen={isQuarantineModalOpen}
        onClose={() => setIsQuarantineModalOpen(false)}
        onConfirm={handleConfirmQuarantine}
        loading={quarantineState === "loading"}
        subject={data.email.subject || "No Subject"}
        sender={data.email.sender || undefined}
      />
    </div>
  );
}

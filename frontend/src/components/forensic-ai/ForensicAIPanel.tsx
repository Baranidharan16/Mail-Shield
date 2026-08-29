/**
 * ForensicAIPanel — Main orchestrator for the Forensic AI Intelligence Layer.
 * Renders all AI sub-panels: Verdict, Evidence, Social Engineering, Timeline,
 * Attack Chain, AI Chat, and Agentic Response.
 *
 * Inserted ABOVE existing sections in InvestigationDetailPage.tsx.
 * Existing components are NOT changed.
 */
import { useEffect, useState } from "react";
import {
  Brain,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Cpu,
  Download,
  Loader2,
} from "lucide-react";
import type { ForensicAIResult } from "../../types/investigation";
import { getForensicAI, getForensicAIReport } from "../../api/client";

import ForensicVerdictCard from "./ForensicVerdictCard";
import EvidenceReasoningPanel from "./EvidenceReasoningPanel";
import ThreatIntentPanel from "./ThreatIntentPanel";
import SocialEngineeringPanel from "./SocialEngineeringPanel";
import AttackChainViz from "./AttackChainViz";
import ForensicAIChat from "./ForensicAIChat";
import AgenticResponsePanel from "./AgenticResponsePanel";

interface Props {
  investigationId: string;
  caseId: string;
}

type Section =
  | "verdict"
  | "evidence"
  | "intent"
  | "social"
  | "chain"
  | "chat"
  | "response";

export default function ForensicAIPanel({ investigationId, caseId }: Props) {
  const [aiData, setAiData] = useState<ForensicAIResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [openSections, setOpenSections] = useState<Set<Section>>(
    new Set(["verdict", "evidence", "intent"])
  );

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    getForensicAI(investigationId)
      .then((data) => {
        if (active) {
          setAiData(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (active) {
          setError(err?.response?.data?.detail || err.message || "AI analysis failed");
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [investigationId]);

  function toggleSection(section: Section) {
    setOpenSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  }

  async function handleDownloadReport() {
    setDownloading(true);
    try {
      const report = await getForensicAIReport(investigationId);
      const blob = new Blob([JSON.stringify(report, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `forensic-ai-report-${caseId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setDownloading(false);
    }
  }

  const severityGlow: Record<string, string> = {
    CRITICAL: "0 0 32px rgba(226, 72, 61, 0.25)",
    HIGH: "0 0 32px rgba(249, 115, 22, 0.20)",
    MEDIUM: "0 0 32px rgba(232, 162, 61, 0.15)",
    LOW: "0 0 20px rgba(61, 220, 151, 0.10)",
  };

  const borderColor: Record<string, string> = {
    CRITICAL: "rgba(226, 72, 61, 0.45)",
    HIGH: "rgba(249, 115, 22, 0.35)",
    MEDIUM: "rgba(232, 162, 61, 0.30)",
    LOW: "rgba(61, 220, 151, 0.25)",
  };

  const severity = aiData?.threat_severity ?? "LOW";

  return (
    <div
      className="mb-8 rounded-2xl overflow-hidden glass-panel border transition-all duration-500 relative"
      style={{
        borderColor: borderColor[severity] ?? borderColor.LOW,
        boxShadow: severityGlow[severity] ?? "none",
      }}
    >
      {/* Dynamic ambient morphing SVG glow behind header */}
      <div className="absolute top-0 right-0 w-96 h-32 pointer-events-none opacity-20 overflow-hidden">
        <svg viewBox="0 0 400 150" className="w-full h-full">
          <path
            d="M 0,0 Q 150,120 300,40 T 400,100 L 400,0 Z"
            fill="url(#cyberMeshGrad1)"
            className="transition-all duration-600 ease-in-out"
          />
        </svg>
      </div>

      {/* Panel header */}
      <div
        className="flex items-center justify-between px-6 py-4.5 cursor-pointer select-none border-b border-white/10 relative z-1"
        style={{
          background: "linear-gradient(90deg, rgba(61,220,151,0.08) 0%, rgba(139,92,246,0.06) 100%)",
        }}
        onClick={() => setCollapsed((c) => !c)}
      >
        <div className="flex items-center gap-3.5">
          <div
            className="flex items-center justify-center w-10 h-10 rounded-xl bg-purple-500/15 border border-purple-500/35 glow-green"
          >
            <Brain size={20} className="text-purple-300 svg-glow" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-sm tracking-widest text-purple-300">
                FORENSIC AI INTELLIGENCE LAYER
              </span>
              <span
                className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-200 border border-purple-500/40"
              >
                EVIDENCE-GROUNDED
              </span>
            </div>
            <p className="text-xs mt-0.5 text-lab-300">
              AI reasoning · 23 Linguistic signals · Attack chain · Evidence-grounded chat · Agentic SOC response
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {aiData && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleDownloadReport();
              }}
              disabled={downloading}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-mono font-bold transition-all hover:scale-105 active:scale-95 bg-phosphor-500/15 text-phosphor-300 border border-phosphor-500/35 hover:bg-phosphor-500/25 cursor-pointer"
            >
              {downloading ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
              AI Report
            </button>
          )}
          <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-lab-400 hover:text-white transition-colors">
            {collapsed ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </div>
        </div>
      </div>

      {!collapsed && (
        <div className="p-6 space-y-5">
          {/* Loading state */}
          {loading && (
            <div className="flex flex-col items-center justify-center py-16 gap-4">
              <div className="relative">
                <div
                  className="w-14 h-14 rounded-full flex items-center justify-center"
                  style={{ background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.3)" }}
                >
                  <Cpu size={24} style={{ color: "#a78bfa" }} className="animate-pulse" />
                </div>
                <div
                  className="absolute inset-0 rounded-full animate-ping"
                  style={{ background: "rgba(139,92,246,0.1)" }}
                />
              </div>
              <div className="text-center">
                <p className="font-mono text-sm" style={{ color: "#a78bfa" }}>
                  Running forensic AI analysis…
                </p>
                <p className="text-xs mt-1" style={{ color: "#4a5a6b" }}>
                  Grounding conclusions in evidence
                </p>
              </div>
            </div>
          )}

          {/* Error state */}
          {error && !loading && (
            <div
              className="flex items-center gap-3 px-4 py-3 rounded-lg"
              style={{ background: "rgba(226,72,61,0.08)", border: "1px solid rgba(226,72,61,0.25)" }}
            >
              <AlertTriangle size={16} style={{ color: "#e2483d" }} />
              <span className="text-sm" style={{ color: "#e2483d" }}>
                AI analysis unavailable: {error}
              </span>
            </div>
          )}

          {/* Data loaded */}
          {aiData && !loading && (
            <>
              {/* Verdict — always visible */}
              <ForensicVerdictCard data={aiData} />

              {/* Evidence Reasoning */}
              <SectionWrapper
                title="Evidence Reasoning"
                subtitle={`${aiData.evidence_cards.length} evidence items · ${aiData.reasoning_chain.length} reasoning steps`}
                sectionId="evidence"
                open={openSections.has("evidence")}
                onToggle={() => toggleSection("evidence")}
                accent="#3b82f6"
              >
                <EvidenceReasoningPanel data={aiData} />
              </SectionWrapper>

              {/* Threat Intent */}
              <SectionWrapper
                title="Threat Intent & Classification"
                subtitle={`${aiData.classification.primary} · ${(aiData.classification.confidence * 100).toFixed(0)}% confidence`}
                sectionId="intent"
                open={openSections.has("intent")}
                onToggle={() => toggleSection("intent")}
                accent="#f97316"
              >
                <ThreatIntentPanel data={aiData} />
              </SectionWrapper>

              {/* Social Engineering */}
              <SectionWrapper
                title="Social Engineering Analysis"
                subtitle={`Manipulation Risk: ${aiData.overall_manipulation_risk}/100 · ${aiData.social_engineering_signals.filter((s) => s.detected).length} signals detected`}
                sectionId="social"
                open={openSections.has("social")}
                onToggle={() => toggleSection("social")}
                accent="#e8a23d"
              >
                <SocialEngineeringPanel data={aiData} />
              </SectionWrapper>

              {/* Attack Chain */}
              <SectionWrapper
                title="Attack Chain Visualization"
                subtitle={`${aiData.attack_chain.length} chain nodes · ${aiData.classification.primary}`}
                sectionId="chain"
                open={openSections.has("chain")}
                onToggle={() => toggleSection("chain")}
                accent="#8b5cf6"
              >
                <AttackChainViz data={aiData} />
              </SectionWrapper>

              {/* Forensic AI Chat */}
              <SectionWrapper
                title="Forensic AI Chat"
                subtitle="Evidence-grounded Q&A · Prompt-injection protected"
                sectionId="chat"
                open={openSections.has("chat")}
                onToggle={() => toggleSection("chat")}
                accent="#3ddc97"
              >
                <ForensicAIChat investigationId={investigationId} aiData={aiData} />
              </SectionWrapper>

              {/* Agentic Response */}
              <SectionWrapper
                title="Agentic Response System"
                subtitle="All destructive actions require human approval"
                sectionId="response"
                open={openSections.has("response")}
                onToggle={() => toggleSection("response")}
                accent="#e2483d"
              >
                <AgenticResponsePanel data={aiData} investigationId={investigationId} />
              </SectionWrapper>

              {/* Disclaimer */}
              <p className="text-xs text-center pt-2" style={{ color: "#4a5a6b" }}>
                {aiData.disclaimer}
              </p>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Collapsible Section Wrapper ─────────────────────────────────────────────

interface SectionWrapperProps {
  title: string;
  subtitle: string;
  sectionId: Section;
  open: boolean;
  onToggle: () => void;
  accent: string;
  children: React.ReactNode;
}

function SectionWrapper({ title, subtitle, open, onToggle, accent, children }: SectionWrapperProps) {
  return (
    <div
      className="rounded-xl overflow-hidden glass-card transition-all duration-400"
    >
      <button
        className="w-full flex items-center justify-between px-5 py-3.5 transition-colors hover:bg-white/5 cursor-pointer"
        onClick={onToggle}
      >
        <div className="flex items-center gap-3">
          <div
            className="w-1.5 h-6 rounded-full transition-all duration-500"
            style={{ background: accent, boxShadow: `0 0 10px ${accent}60` }}
          />
          <div className="text-left">
            <div className="text-sm font-semibold text-white">
              {title}
            </div>
            <div className="text-[11px] mt-0.5 text-lab-400 font-mono">
              {subtitle}
            </div>
          </div>
        </div>
        <div className="w-6 h-6 rounded-lg bg-white/5 flex items-center justify-center text-lab-400">
          {open ? (
            <ChevronUp size={14} />
          ) : (
            <ChevronDown size={14} />
          )}
        </div>
      </button>
      {open && (
        <div
          className="px-5 pb-5 pt-3 border-t border-white/10"
        >
          {children}
        </div>
      )}
    </div>
  );
}

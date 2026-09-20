import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  UploadCloud,
  FileText,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Shield,
  Zap,
  Lock,
  Brain,
  Sparkles,
} from "lucide-react";
import {
  uploadEmail,
  analyzeEmailDirect,
  analyzeRawTextDirect,
  getModelStatus,
} from "../api/client";
import type {
  InvestigationStatus,
  MailShieldAnalysisResponse,
  ModelStatusResponse,
} from "../types/investigation";
import MailShieldLiveAnalysis from "../components/MailShieldLiveAnalysis";
import GmailInboxPanel from "../components/GmailInboxPanel";
import { Mail } from "lucide-react";

const STAGES: { status: InvestigationStatus; label: string; desc: string }[] = [
  { status: "QUEUED", label: "Evidence Received & Parsed", desc: "Headers, bodies, and URLs extracted" },
  { status: "PROCESSING", label: "Dual Model & Forensic Inference", desc: "Running ML + NLP models, rule engine and header forensics" },
  { status: "COMPLETED", label: "Analysis Complete", desc: "Risk score and AI reasoning generated" },
];

export default function UploadPage() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<"file" | "raw" | "gmail">("file");
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [rawText, setRawText] = useState("");
  const [rawSubject, setRawSubject] = useState("");
  const [status, setStatus] = useState<InvestigationStatus | "IDLE">("IDLE");
  const [error, setError] = useState<string | null>(null);
  const [modelStatus, setModelStatus] = useState<ModelStatusResponse | null>(null);
  const [mailshieldAnalysis, setMailshieldAnalysis] = useState<MailShieldAnalysisResponse | null>(null);
  const [investigationId, setInvestigationId] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    getModelStatus().then(setModelStatus).catch(() => {});
  }, []);

  const handleFile = useCallback((f: File | null) => {
    setError(null);
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".eml") && !f.name.toLowerCase().endsWith(".txt")) {
      setError("Please select a .eml email file.");
      return;
    }
    setFile(f);
  }, []);

  async function startAnalysis() {
    if (activeTab === "file" && !file) return;
    if (activeTab === "raw" && !rawText.trim()) return;

    setStatus("PROCESSING");
    setError(null);

    try {
      let res: MailShieldAnalysisResponse;
      if (activeTab === "file" && file) {
        // Concurrently run direct MailShield pipeline
        res = await analyzeEmailDirect(file);
        // Also register in SQLite backend asynchronously for historical dossiers
        uploadEmail(file)
          .then((created) => setInvestigationId(created.id))
          .catch(() => {});
      } else {
        res = await analyzeRawTextDirect(rawText, rawSubject || "Manual Text Analysis");
      }

      setMailshieldAnalysis(res);
      setStatus("COMPLETED");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Analysis failed. Confirm the MailShield backend is running.");
      setStatus("IDLE");
    }
  }

  const isBusy = status === "QUEUED" || status === "PROCESSING";
  const currentStageIndex = STAGES.findIndex((s) => s.status === status);

  // If live analysis completed, display the full MailShieldLiveAnalysis card
  if (mailshieldAnalysis) {
    return (
      <div className="p-6 md:p-8 max-w-4xl mx-auto">
        <MailShieldLiveAnalysis
          data={mailshieldAnalysis}
          investigationId={investigationId || undefined}
          onReset={() => {
            setMailshieldAnalysis(null);
            setFile(null);
            setRawText("");
            setStatus("IDLE");
            setInvestigationId(null);
          }}
          onViewDetails={investigationId ? () => navigate(`/investigations/${investigationId}`) : undefined}
        />
      </div>
    );
  }

  return (
    <div className="p-6 md:p-8 max-w-3xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="page-header-glass mb-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2">
          <div className="flex items-center gap-2.5">
            <Shield className="h-5 w-5 text-phosphor-500" strokeWidth={2} />
            <h1 className="text-xl font-bold tracking-tight text-white">MailShield Threat Analysis Console</h1>
          </div>

          {/* Model Status Pill */}
          {modelStatus && (
            <div className="flex items-center gap-2 text-[11px] font-mono self-start sm:self-auto">
              <span className="flex items-center gap-1 text-phosphor-400 bg-phosphor-500/10 px-2 py-0.5 rounded border border-phosphor-500/25">
                <Brain className="h-3 w-3" /> ML + NLP Ready
              </span>
              <span className="flex items-center gap-1 text-lab-300 bg-white/5 px-2 py-0.5 rounded border border-white/10">
                <Sparkles className="h-3 w-3 text-amber-400" />{" "}
                {modelStatus.gemini_configured ? "Gemini Online" : "AI Heuristics"}
              </span>
            </div>
          )}
        </div>

        <p className="text-sm text-lab-400">
          Upload an <span className="font-mono text-lab-300">.eml</span> email file or paste email content to execute real-time ML phishing classification, NLP threat pattern extraction, and deterministic risk scoring.
        </p>
      </div>

      {/* Feature Badges */}
      <div className="flex flex-wrap gap-2 mb-6">
        {[
          "ML + NLP Phishing Classifiers",
          "6-Pattern NLP Threat Model",
          "RFC Header Forensics",
          "Deterministic Risk Engine",
          "AI Incident Response Guidance",
        ].map((f) => (
          <span key={f} className="filter-chip text-[11px]">
            <Zap className="h-2.5 w-2.5 text-phosphor-400" /> {f}
          </span>
        ))}
      </div>

      {/* Input Mode Selector */}
      {!isBusy && (
        <div className="flex gap-2 p-1 bg-black/20 rounded-xl border border-white/5 mb-4 max-w-md">
          <button
            onClick={() => { setActiveTab("file"); setError(null); }}
            className={`flex-1 text-xs py-1.5 px-3 rounded-lg font-medium transition-all ${
              activeTab === "file" ? "bg-white/10 text-white shadow-sm" : "text-lab-400 hover:text-lab-200"
            }`}
          >
            Upload .eml
          </button>
          <button
            onClick={() => { setActiveTab("raw"); setError(null); }}
            className={`flex-1 text-xs py-1.5 px-3 rounded-lg font-medium transition-all ${
              activeTab === "raw" ? "bg-white/10 text-white shadow-sm" : "text-lab-400 hover:text-lab-200"
            }`}
          >
            Raw Email Text
          </button>
          <button
            onClick={() => { setActiveTab("gmail"); setError(null); }}
            className={`flex-1 text-xs py-1.5 px-3 rounded-lg font-medium transition-all flex items-center justify-center gap-1.5 ${
              activeTab === "gmail" ? "bg-white/10 text-white shadow-sm" : "text-lab-400 hover:text-lab-200"
            }`}
          >
            <Mail className="h-3.5 w-3.5 text-red-400" />
            Gmail Acquisition
          </button>
        </div>
      )}

      {/* Upload Box (File Mode) */}
      {!isBusy && activeTab === "file" && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files?.[0] ?? null); }}
          onClick={() => inputRef.current?.click()}
          className={`glass-section rounded-2xl p-10 md:p-12 text-center cursor-pointer transition-all duration-300 ${
            dragOver
              ? "border-phosphor-500/50 bg-phosphor-500/8 shadow-[0_0_30px_rgba(37,34,30,0.05)]"
              : file
              ? "border-phosphor-500/30 bg-phosphor-500/5"
              : "hover:border-white/15 hover:bg-white/[0.02]"
          }`}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".eml,.txt"
            className="hidden"
            onChange={(e) => handleFile(e.target.files?.[0] ?? null)}
          />
          {file ? (
            <>
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-phosphor-500/15 border border-phosphor-500/35 flex items-center justify-center">
                <FileText className="h-8 w-8 text-phosphor-400" strokeWidth={1.5} />
              </div>
              <div className="font-mono text-lab-100 font-medium text-sm">{file.name}</div>
              <div className="text-xs text-lab-500 mt-1.5">{(file.size / 1024).toFixed(1)} KB · click to change</div>
            </>
          ) : (
            <>
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
                <UploadCloud className="h-8 w-8 text-lab-500" strokeWidth={1.5} />
              </div>
              <div className="text-lab-200 font-medium text-sm">Drop a .eml email file here, or click to browse</div>
              <div className="text-xs text-lab-500 mt-1.5">Max 20 MB · .eml format</div>
            </>
          )}
        </div>
      )}

      {/* Raw Text Box (Raw Mode) */}
      {!isBusy && activeTab === "raw" && (
        <div className="glass-section p-5 rounded-2xl border-white/10 space-y-3">
          <input
            type="text"
            placeholder="Subject Line (optional)"
            value={rawSubject}
            onChange={(e) => setRawSubject(e.target.value)}
            className="w-full px-3.5 py-2 rounded-xl bg-black/30 border border-white/10 text-white text-xs font-mono focus:outline-none focus:border-phosphor-500/50"
          />
          <textarea
            rows={7}
            placeholder="Paste raw email body, headers, or suspicious text message here..."
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            className="w-full p-3.5 rounded-xl bg-black/30 border border-white/10 text-white text-xs font-mono focus:outline-none focus:border-phosphor-500/50 resize-y"
          />
        </div>
      )}

      {/* Gmail Inbox Tab */}
      {!isBusy && activeTab === "gmail" && (
        <GmailInboxPanel
          onAnalysisStart={() => {
            setStatus("PROCESSING");
            setError(null);
          }}
          onAnalyzeSuccess={(res, invId) => {
            setMailshieldAnalysis(res);
            setInvestigationId(invId);
            setStatus("COMPLETED");
          }}
          onError={(err) => {
            setError(err);
            setStatus("IDLE");
          }}
        />
      )}

      {/* Error Message */}
      {error && (
        <div className="glass-section border-crimson-signal/35 bg-crimson-signal/5 p-4 mt-4 text-sm text-crimson-glow flex items-start gap-2.5 rounded-xl">
          <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
          {error}
        </div>
      )}

      {/* Start Button */}
      {!isBusy && (file || (activeTab === "raw" && rawText.trim())) && !error && (
        <button
          onClick={startAnalysis}
          className="btn-glass-primary mt-5 w-full justify-center py-3 text-sm flex items-center gap-2"
        >
          <Shield className="h-4 w-4" strokeWidth={2.2} />
          Execute MailShield Analysis
        </button>
      )}

      {/* In-Flight Pipeline Live Status */}
      {isBusy && (
        <div className="glass-section p-6 mt-6 animate-fade-in border-white/10">
          <div className="flex items-center gap-2 mb-5">
            <Loader2 className="h-4 w-4 text-phosphor-400 animate-spin" />
            <div className="text-xs font-mono uppercase tracking-wider text-lab-400">
              MAILSHIELD PIPELINE — IN-FLIGHT INFERENCE
            </div>
          </div>

          <div className="space-y-4">
            {STAGES.map((stage, idx) => {
              const done = currentStageIndex > idx;
              const active = currentStageIndex === idx;
              return (
                <div
                  key={stage.status}
                  className={`flex items-start gap-3 transition-opacity ${
                    !done && !active ? "opacity-40" : ""
                  }`}
                >
                  <div className="shrink-0 mt-0.5">
                    {done ? (
                      <CheckCircle2 className="h-5 w-5 text-phosphor-500" />
                    ) : active ? (
                      <Loader2 className="h-5 w-5 text-phosphor-400 animate-spin" />
                    ) : (
                      <div className="h-5 w-5 rounded-full border-2 border-lab-700" />
                    )}
                  </div>
                  <div>
                    <div
                      className={`text-sm font-medium ${
                        done ? "text-lab-100" : active ? "text-phosphor-400 font-semibold" : "text-lab-500"
                      }`}
                    >
                      {stage.label}
                    </div>
                    <div className="text-[11px] text-lab-500 mt-0.5">{stage.desc}</div>
                  </div>
                </div>
              );
            })}
          </div>

          <p className="text-[11px] text-lab-600 mt-5 border-t border-white/5 pt-4">
            Running the trained ML/NLP models and deterministic forensic analyzers.
          </p>
        </div>
      )}

      {/* Security Note */}
      {!isBusy && !file && (
        <div className="flex items-start gap-2.5 mt-6 text-[11px] text-lab-600">
          <Lock className="h-3.5 w-3.5 shrink-0 mt-0.5 text-lab-700" />
          <span>
            Evidence files are handled with strict chain-of-custody preservation. No attachments are executed and no URLs are followed.
          </span>
        </div>
      )}
    </div>
  );
}

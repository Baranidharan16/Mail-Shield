import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { UploadCloud, FileText, Loader2, AlertCircle, CheckCircle2, Shield, Zap, Lock } from "lucide-react";
import { uploadEmail, getInvestigation } from "../api/client";
import type { InvestigationStatus } from "../types/investigation";

const STAGES: { status: InvestigationStatus; label: string; desc: string }[] = [
  { status: "QUEUED", label: "Evidence Received & Hashed", desc: "SHA-256 fingerprint computed and stored" },
  { status: "PROCESSING", label: "Forensic Analysis Engine Running", desc: "Header analysis, authentication, AI scoring" },
  { status: "COMPLETED", label: "Investigation Complete", desc: "Full report and SOC alert generated" },
];

export default function UploadPage() {
  const navigate = useNavigate();
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<InvestigationStatus | "IDLE">("IDLE");
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback((f: File | null) => {
    setError(null);
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".eml")) {
      setError("Only .eml email files are accepted.");
      return;
    }
    setFile(f);
  }, []);

  async function startAnalysis() {
    if (!file) return;
    setStatus("QUEUED");
    setError(null);
    try {
      const created = await uploadEmail(file);
      pollUntilDone(created.id);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Upload failed. Confirm the backend is reachable.");
      setStatus("IDLE");
    }
  }

  async function pollUntilDone(id: string) {
    const start = Date.now();
    const poll = async (): Promise<void> => {
      const detail = await getInvestigation(id);
      setStatus(detail.status);
      if (detail.status === "COMPLETED" || detail.status === "FAILED") {
        if (detail.status === "COMPLETED") { navigate(`/investigations/${id}`); }
        else { setError(detail.error_message || "Analysis failed."); }
        return;
      }
      if (Date.now() - start > 30000) { setError("Analysis is taking longer than expected. Check case history shortly."); return; }
      setTimeout(poll, 500);
    };
    poll();
  }

  const isBusy = status !== "IDLE";
  const currentStageIndex = STAGES.findIndex((s) => s.status === status);

  return (
    <div className="p-6 md:p-8 max-w-2xl animate-fade-in">

      {/* Header */}
      <div className="page-header-glass mb-6">
        <div className="flex items-center gap-2.5 mb-1">
          <Shield className="h-5 w-5 text-phosphor-500" strokeWidth={1.75} />
          <h1 className="text-xl font-bold tracking-tight text-white">Email Analysis Console</h1>
        </div>
        <p className="text-sm text-lab-400">
          Upload a <span className="font-data text-lab-300">.eml</span> email file to begin forensic investigation.
          The file will be parsed, hashed, and processed through the full analysis pipeline.
        </p>
      </div>

      {/* Feature Pills */}
      <div className="flex flex-wrap gap-2 mb-6">
        {["SHA-256 Integrity Hashing", "AI Threat Scoring", "Header Authentication", "Geolocation Intelligence", "Attack Graph Analysis"].map((f) => (
          <span key={f} className="filter-chip text-[11px]">
            <Zap className="h-2.5 w-2.5" /> {f}
          </span>
        ))}
      </div>

      {/* Drop Zone */}
      {!isBusy && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files?.[0] ?? null); }}
          onClick={() => inputRef.current?.click()}
          className={`glass-section rounded-2xl p-10 md:p-14 text-center cursor-pointer transition-all duration-300 ${
            dragOver
              ? "border-phosphor-500/50 bg-phosphor-500/8 shadow-[0_0_30px_rgba(61,220,151,0.12)]"
              : file
              ? "border-phosphor-500/30 bg-phosphor-500/5"
              : "hover:border-white/15 hover:bg-white/[0.02]"
          }`}
        >
          <input ref={inputRef} type="file" accept=".eml" className="hidden" onChange={(e) => handleFile(e.target.files?.[0] ?? null)} />
          {file ? (
            <>
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-phosphor-500/15 border border-phosphor-500/35 flex items-center justify-center">
                <FileText className="h-8 w-8 text-phosphor-400" strokeWidth={1.5} />
              </div>
              <div className="font-data text-lab-100 font-medium text-sm">{file.name}</div>
              <div className="text-xs text-lab-500 mt-1.5">{(file.size / 1024).toFixed(1)} KB · click to change</div>
            </>
          ) : (
            <>
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
                <UploadCloud className="h-8 w-8 text-lab-500" strokeWidth={1.5} />
              </div>
              <div className="text-lab-200 font-medium text-sm">Drop a .eml file here, or click to browse</div>
              <div className="text-xs text-lab-500 mt-1.5">Max 10 MB · .eml only</div>
            </>
          )}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="glass-section border-crimson-signal/35 bg-crimson-signal/5 p-4 mt-4 text-sm text-crimson-glow flex items-start gap-2.5 rounded-xl">
          <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
          {error}
        </div>
      )}

      {/* Start Button */}
      {!isBusy && file && !error && (
        <button onClick={startAnalysis} className="btn-glass-primary mt-5 w-full justify-center py-3 text-sm">
          <Shield className="h-4 w-4" strokeWidth={2.2} />
          Begin Forensic Analysis
        </button>
      )}

      {/* Pipeline Status */}
      {isBusy && (
        <div className="glass-section p-6 mt-6 animate-fade-in">
          <div className="flex items-center gap-2 mb-5">
            <Loader2 className="h-4 w-4 text-amber-signal animate-spin" />
            <div className="text-xs evidence-tag text-lab-400">FORENSIC ANALYSIS PIPELINE — LIVE STATUS</div>
          </div>
          <div className="space-y-4">
            {STAGES.map((stage, idx) => {
              const done = currentStageIndex > idx || status === "COMPLETED";
              const active = currentStageIndex === idx && status !== "COMPLETED";
              return (
                <div key={stage.status} className={`flex items-start gap-3 transition-opacity ${!done && !active ? "opacity-40" : ""}`}>
                  <div className="shrink-0 mt-0.5">
                    {done ? (
                      <CheckCircle2 className="h-5 w-5 text-phosphor-500" />
                    ) : active ? (
                      <Loader2 className="h-5 w-5 text-amber-signal animate-spin" />
                    ) : (
                      <div className="h-5 w-5 rounded-full border-2 border-lab-700" />
                    )}
                  </div>
                  <div>
                    <div className={`text-sm font-medium ${done ? "text-lab-100" : active ? "text-amber-signal" : "text-lab-500"}`}>
                      {stage.label}
                    </div>
                    <div className="text-[11px] text-lab-600 mt-0.5">{stage.desc}</div>
                  </div>
                </div>
              );
            })}
          </div>
          <p className="text-[11px] text-lab-600 mt-5 border-t border-white/5 pt-4">
            Reflects the investigation's real-time status field in the forensic database — not a simulated progress bar.
          </p>
        </div>
      )}

      {/* Security note */}
      {!isBusy && !file && (
        <div className="flex items-start gap-2.5 mt-6 text-[11px] text-lab-600">
          <Lock className="h-3.5 w-3.5 shrink-0 mt-0.5 text-lab-700" />
          <span>Files are processed locally. Evidence hash is recorded in the integrity ledger for chain-of-custody compliance.</span>
        </div>
      )}
    </div>
  );
}

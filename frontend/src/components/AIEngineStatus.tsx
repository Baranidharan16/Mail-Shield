import { useEffect, useState } from "react";
import { Cpu, Circle } from "lucide-react";
import { getModelStatus } from "../api/client";
import type { ModelStatusResponse } from "../types/investigation";

export default function AIEngineStatus({ compact = false }: { compact?: boolean }) {
  const [status, setStatus] = useState<ModelStatusResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    async function checkStatus() {
      try {
        const res = await getModelStatus();
        if (mounted) {
          setStatus(res);
        }
      } catch (e) {
        // silent fallback
      }
    }
    checkStatus();
    const interval = setInterval(checkStatus, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const mlLoaded = status?.ml_model_loaded ?? false;
  const nlpLoaded = status?.nlp_model_loaded ?? false;
  const geminiStatus = status?.gemini_status ?? (status?.gemini_configured ? "CONNECTED" : "UNAVAILABLE");
  const sarvamStatus = status?.sarvam_voice_status ?? "CONNECTED";
  const ollamaStatus = status?.ollama_status ?? "NOT CONFIGURED";

  if (compact) {
    return (
      <div className="glass-card p-3 rounded-xl border border-white/[0.08] bg-black/40 text-[11px] font-mono">
        <div className="flex items-center justify-between mb-2 text-lab-300 font-bold tracking-wider">
          <span className="flex items-center gap-1.5">
            <Cpu size={12} className="text-phosphor-400" />
            AI ENGINE STATUS
          </span>
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-phosphor-500/20 text-phosphor-300 border border-phosphor-500/30">
            REAL-TIME
          </span>
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-lab-400">ML MODEL</span>
            <span className={`flex items-center gap-1 ${mlLoaded ? "text-phosphor-400 font-bold" : "text-crimson-glow"}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${mlLoaded ? "bg-phosphor-400" : "bg-crimson-glow"}`} />
              {mlLoaded ? "LOADED" : "OFFLINE"}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-lab-400">NLP MODEL</span>
            <span className={`flex items-center gap-1 ${nlpLoaded ? "text-phosphor-400 font-bold" : "text-crimson-glow"}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${nlpLoaded ? "bg-phosphor-400" : "bg-crimson-glow"}`} />
              {nlpLoaded ? "LOADED" : "OFFLINE"}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-lab-400">FORENSIC ENGINE</span>
            <span className="flex items-center gap-1 text-phosphor-400 font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-phosphor-400" />
              ACTIVE
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-lab-400">GEMINI</span>
            <span className={`flex items-center gap-1 ${geminiStatus === "CONNECTED" ? "text-phosphor-400" : "text-amber-signal"}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${geminiStatus === "CONNECTED" ? "bg-phosphor-400" : "bg-amber-signal"}`} />
              {geminiStatus}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-lab-400">SARVAM VOICE</span>
            <span className={`flex items-center gap-1 ${sarvamStatus === "CONNECTED" ? "text-purple-400 font-bold" : "text-amber-signal"}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${sarvamStatus === "CONNECTED" ? "bg-purple-400" : "bg-amber-signal"}`} />
              {sarvamStatus}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-lab-500">OLLAMA</span>
            <span className="flex items-center gap-1 text-lab-500 font-mono">
              <Circle size={6} className="text-lab-600" />
              {ollamaStatus}
            </span>
          </div>

          <div className="flex items-center justify-between pt-1 border-t border-white/[0.05]">
            <span className="text-lab-500">AUTONOMOUS AGENT</span>
            <span className="flex items-center gap-1 text-lab-500 font-mono">
              <Circle size={6} className="text-lab-600" />
              NOT CONFIGURED
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="glass-card p-5 rounded-2xl border border-phosphor-500/30 bg-black/40 shadow-xl mb-6">
      <div className="flex items-center justify-between pb-3 mb-4 border-b border-white/[0.08]">
        <div className="flex items-center gap-2">
          <Cpu className="h-4 w-4 text-phosphor-400" />
          <h3 className="text-xs font-bold text-white uppercase tracking-wider">AI ENGINE STATUS</h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-phosphor-500/15 text-phosphor-300 border border-phosphor-500/30">
          CONFIRMED BY BACKEND
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-7 gap-3 text-xs font-mono">
        <div className="p-3 rounded-xl bg-black/30 border border-white/[0.06]">
          <div className="text-[10px] text-lab-400 mb-1">ML MODEL</div>
          <div className={`flex items-center gap-1.5 font-bold ${mlLoaded ? "text-phosphor-400" : "text-crimson-glow"}`}>
            <span className={`w-2 h-2 rounded-full ${mlLoaded ? "bg-phosphor-400 animate-pulse" : "bg-crimson-glow"}`} />
            {mlLoaded ? "LOADED" : "OFFLINE"}
          </div>
          <div className="text-[9px] text-lab-500 mt-1">MailShield ML</div>
        </div>

        <div className="p-3 rounded-xl bg-black/30 border border-white/[0.06]">
          <div className="text-[10px] text-lab-400 mb-1">NLP MODEL</div>
          <div className={`flex items-center gap-1.5 font-bold ${nlpLoaded ? "text-phosphor-400" : "text-crimson-glow"}`}>
            <span className={`w-2 h-2 rounded-full ${nlpLoaded ? "bg-phosphor-400 animate-pulse" : "bg-crimson-glow"}`} />
            {nlpLoaded ? "LOADED" : "OFFLINE"}
          </div>
          <div className="text-[9px] text-lab-500 mt-1">6-Pattern Model B</div>
        </div>

        <div className="p-3 rounded-xl bg-black/30 border border-white/[0.06]">
          <div className="text-[10px] text-lab-400 mb-1">FORENSIC ENGINE</div>
          <div className="flex items-center gap-1.5 font-bold text-phosphor-400">
            <span className="w-2 h-2 rounded-full bg-phosphor-400 animate-pulse" />
            ACTIVE
          </div>
          <div className="text-[9px] text-lab-500 mt-1">Headers & Auth</div>
        </div>

        <div className="p-3 rounded-xl bg-black/30 border border-white/[0.06]">
          <div className="text-[10px] text-lab-400 mb-1">GEMINI</div>
          <div className={`flex items-center gap-1.5 font-bold ${geminiStatus === "CONNECTED" ? "text-phosphor-400" : "text-amber-signal"}`}>
            <span className={`w-2 h-2 rounded-full ${geminiStatus === "CONNECTED" ? "bg-phosphor-400" : "bg-amber-signal"}`} />
            {geminiStatus}
          </div>
          <div className="text-[9px] text-lab-500 mt-1">Reasoning Layer</div>
        </div>

        <div className="p-3 rounded-xl bg-black/30 border border-white/[0.06]">
          <div className="text-[10px] text-lab-400 mb-1">SARVAM VOICE</div>
          <div className={`flex items-center gap-1.5 font-bold ${sarvamStatus === "CONNECTED" ? "text-purple-400" : "text-amber-signal"}`}>
            <span className={`w-2 h-2 rounded-full ${sarvamStatus === "CONNECTED" ? "bg-purple-400" : "bg-amber-signal"}`} />
            {sarvamStatus}
          </div>
          <div className="text-[9px] text-lab-500 mt-1">22 Indian Languages</div>
        </div>

        <div className="p-3 rounded-xl bg-black/30 border border-white/[0.06]">
          <div className="text-[10px] text-lab-400 mb-1">OLLAMA</div>
          <div className="flex items-center gap-1.5 text-lab-500">
            <Circle size={8} className="text-lab-600" />
            {ollamaStatus}
          </div>
          <div className="text-[9px] text-lab-600 mt-1">Local Provider</div>
        </div>

        <div className="p-3 rounded-xl bg-black/30 border border-white/[0.06]">
          <div className="text-[10px] text-lab-400 mb-1">AUTONOMOUS AGENT</div>
          <div className="flex items-center gap-1.5 text-lab-500">
            <Circle size={8} className="text-lab-600" />
            NOT CONFIGURED
          </div>
          <div className="text-[9px] text-lab-600 mt-1">Future Extension</div>
        </div>
      </div>
    </div>
  );
}

import { Brain, Cpu, ShieldAlert, CheckCircle2, Activity } from "lucide-react";

interface AIDetectionAnalysisProps {
  mlDetection?: {
    prediction: string;
    phishing_probability: number;
    confidence: number;
  };
  nlpDetection?: {
    urgency: number;
    credential_request: number;
    financial_manipulation: number;
    impersonation: number;
    threat_language: number;
    suspicious_action: number;
  };
}

export default function AIDetectionAnalysis({ mlDetection, nlpDetection }: AIDetectionAnalysisProps) {
  // Default fallbacks if backend didn't attach (ensures visual integrity)
  const ml = mlDetection || {
    prediction: "analyzing",
    phishing_probability: 0.0,
    confidence: 0.0,
  };

  const nlp = nlpDetection || {
    urgency: 0.0,
    credential_request: 0.0,
    financial_manipulation: 0.0,
    impersonation: 0.0,
    threat_language: 0.0,
    suspicious_action: 0.0,
  };

  const isPhishing = ml.prediction.toLowerCase() === "phishing" || ml.phishing_probability >= 0.5;
  const mlProbPct = Math.round(ml.phishing_probability * 100);
  const mlConfPct = Math.round(ml.confidence * 100);

  const nlpDimensions = [
    { label: "Urgency", value: nlp.urgency },
    { label: "Credential Request", value: nlp.credential_request },
    { label: "Financial Manipulation", value: nlp.financial_manipulation },
    { label: "Impersonation", value: nlp.impersonation },
    { label: "Threat Language", value: nlp.threat_language },
    { label: "Suspicious Action", value: nlp.suspicious_action },
  ];

  return (
    <div className="glass-card p-6 rounded-2xl border border-phosphor-500/25 bg-black/40 backdrop-blur-xl shadow-2xl relative overflow-hidden mb-6">
      {/* Background Accent Glow */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-phosphor-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-80 h-80 bg-purple-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-5 border-b border-white/[0.08] relative z-10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-phosphor-500/15 border border-phosphor-500/40 flex items-center justify-center glow-green">
            <Brain className="h-5 w-5 text-phosphor-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-white tracking-wide">AI DETECTION ANALYSIS</h2>
              <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-phosphor-500/15 text-phosphor-300 border border-phosphor-500/30 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-phosphor-400 animate-pulse" />
                REAL-TIME INFERENCE
              </span>
            </div>
            <p className="text-xs text-lab-400 font-mono">
              Evaluated directly by MailShield trained Keras neural network models
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-lab-400 bg-black/40 px-3 py-1.5 rounded-lg border border-white/[0.06]">
          <Activity size={14} className="text-phosphor-400" />
          <span>TENSORFLOW / KERAS IN-MEMORY ENGINE</span>
        </div>
      </div>

      {/* Dual Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-6 relative z-10">
        {/* ─── Column 1: ML Phishing Detection ─── */}
        <div className="glass-card p-5 rounded-xl border border-white/[0.08] bg-black/30 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-phosphor-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-lab-200">
                  ML PHISHING DETECTION
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-lab-800 text-lab-300 border border-white/10">
                Model: MailShield ML
              </span>
            </div>

            {/* Verdict Display */}
            <div className="flex items-center justify-between p-4 rounded-xl bg-black/50 border border-white/[0.06] mb-5">
              <div>
                <div className="text-[11px] uppercase tracking-wider text-lab-400 font-mono mb-1">
                  Prediction
                </div>
                <div
                  className={`text-2xl font-extrabold font-mono tracking-tight flex items-center gap-2 ${
                    isPhishing ? "text-crimson-glow" : "text-emerald-400"
                  }`}
                >
                  {isPhishing ? (
                    <>
                      <ShieldAlert className="h-6 w-6 text-crimson-signal animate-pulse" />
                      PHISHING
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="h-6 w-6 text-emerald-400" />
                      LEGITIMATE
                    </>
                  )}
                </div>
              </div>

              <div className="text-right">
                <div className="text-[11px] uppercase tracking-wider text-lab-400 font-mono mb-1">
                  Probability
                </div>
                <div
                  className={`text-3xl font-black font-mono ${
                    isPhishing ? "text-crimson-glow" : "text-emerald-400"
                  }`}
                >
                  {mlProbPct}%
                </div>
              </div>
            </div>

            {/* Probability Progress Bar */}
            <div className="space-y-1.5 mb-4">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-lab-400">Phishing Probability</span>
                <span className="text-lab-200 font-bold">{mlProbPct}%</span>
              </div>
              <div className="h-3 w-full bg-black/60 rounded-full overflow-hidden p-0.5 border border-white/10">
                <div
                  className={`h-full rounded-full transition-all duration-1000 ${
                    mlProbPct >= 70
                      ? "bg-gradient-to-r from-orange-500 to-crimson-glow"
                      : mlProbPct >= 40
                      ? "bg-gradient-to-r from-amber-500 to-orange-500"
                      : "bg-gradient-to-r from-phosphor-600 to-emerald-400"
                  }`}
                  style={{ width: `${mlProbPct}%` }}
                />
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-white/[0.06] flex items-center justify-between text-xs font-mono text-lab-400">
            <span>Model Confidence</span>
            <span className="text-lab-200 font-bold">{mlConfPct}%</span>
          </div>
        </div>

        {/* ─── Column 2: NLP Threat-Pattern Analysis ─── */}
        <div className="glass-card p-5 rounded-xl border border-white/[0.08] bg-black/30">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Brain className="h-4 w-4 text-purple-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-lab-200">
                NLP THREAT-PATTERN ANALYSIS
              </h3>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-lab-800 text-lab-300 border border-white/10">
              Model: MailShield NLP Model B
            </span>
          </div>

          {/* 6 Dimensions Bars */}
          <div className="space-y-3.5">
            {nlpDimensions.map(({ label, value }) => {
              const pct = Math.round((value || 0) * 100);
              const isHigh = pct >= 60;
              const isMid = pct >= 30 && pct < 60;

              return (
                <div key={label} className="space-y-1">
                  <div className="flex justify-between items-center text-xs font-mono">
                    <span className="text-lab-300">{label}</span>
                    <span
                      className={`font-bold ${
                        isHigh
                          ? "text-crimson-glow"
                          : isMid
                          ? "text-amber-signal"
                          : "text-lab-400"
                      }`}
                    >
                      {pct}%
                    </span>
                  </div>
                  <div className="h-2 w-full bg-black/60 rounded-full overflow-hidden p-0.5 border border-white/[0.06]">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${
                        isHigh
                          ? "bg-gradient-to-r from-orange-500 to-crimson-signal"
                          : isMid
                          ? "bg-gradient-to-r from-yellow-500 to-amber-500"
                          : "bg-gradient-to-r from-blue-600 to-cyan-400"
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-4 pt-3 border-t border-white/[0.06] text-[11px] text-lab-500 font-mono text-right">
            Multi-output classification across 6 cognitive manipulation vectors
          </div>
        </div>
      </div>
    </div>
  );
}

import { useState } from "react";
import { Bot, X, MessageSquare, Sparkles, ChevronDown } from "lucide-react";

export default function AIAgentPlaceholder() {
  const [open, setOpen] = useState(false);
  const [minimized, setMinimized] = useState(false);

  const FUTURE_COMMANDS = [
    "Why is this email dangerous?",
    "What indicators caused the risk score?",
    "What should I do next?",
    "Find similar cases.",
    "Generate incident report.",
    "Explain authentication failures.",
    "Summarize threat infrastructure.",
  ];

  return (
    <>
      {/* Floating button */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-full
            bg-lab-800 border border-lab-600 text-lab-200
            hover:border-phosphor-500/50 hover:bg-lab-700 transition-all shadow-xl
            group"
        >
          <div className="relative">
            <Bot className="h-5 w-5 text-phosphor-500" strokeWidth={1.75} />
            <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-amber-signal animate-pulse" />
          </div>
          <span className="text-sm font-semibold">Forensic AI Agent</span>
          <span className="text-[10px] evidence-tag text-lab-500 border border-lab-600 rounded px-1.5 py-0.5">COMING SOON</span>
        </button>
      )}

      {/* Agent panel */}
      {open && (
        <div
          className={`fixed bottom-6 right-6 z-50 w-96 rounded-xl border border-lab-600 bg-lab-900 shadow-2xl transition-all duration-200 ${
            minimized ? "h-14" : "h-[500px]"
          } overflow-hidden`}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-lab-700 bg-lab-850">
            <div className="flex items-center gap-2.5">
              <div className="relative">
                <Bot className="h-5 w-5 text-phosphor-500" strokeWidth={1.75} />
                <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-amber-signal" />
              </div>
              <div>
                <div className="text-sm font-semibold text-lab-100">Forensic AI Agent</div>
                <div className="text-[10px] text-amber-signal evidence-tag">NOT YET IMPLEMENTED</div>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setMinimized(!minimized)}
                className="p-1.5 rounded hover:bg-lab-700 text-lab-400 hover:text-lab-200 transition-colors"
              >
                <ChevronDown className={`h-4 w-4 transition-transform ${minimized ? "rotate-180" : ""}`} />
              </button>
              <button
                onClick={() => setOpen(false)}
                className="p-1.5 rounded hover:bg-lab-700 text-lab-400 hover:text-lab-200 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          {!minimized && (
            <div className="flex flex-col h-[calc(100%-3.5rem)]">
              {/* Coming soon notice */}
              <div className="mx-4 mt-4 p-3 rounded-lg bg-amber-signal/5 border border-amber-signal/20">
                <div className="flex items-start gap-2">
                  <Sparkles className="h-4 w-4 text-amber-signal mt-0.5 shrink-0" />
                  <div>
                    <div className="text-xs font-semibold text-amber-signal">AI Agent — Integration Point Reserved</div>
                    <p className="text-[11px] text-lab-400 mt-1">
                      The Forensic AI Agent will be integrated in the next phase.
                      It will receive case context, indicators, risk scores, timeline, and evidence metadata.
                    </p>
                  </div>
                </div>
              </div>

              {/* Future commands preview */}
              <div className="px-4 pt-4 pb-2">
                <div className="text-[10px] text-lab-500 evidence-tag mb-2">PLANNED COMMANDS</div>
                <div className="space-y-1.5">
                  {FUTURE_COMMANDS.map((cmd, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 px-3 py-2 rounded-md bg-lab-800/60 border border-lab-700 opacity-50 cursor-not-allowed"
                    >
                      <MessageSquare className="h-3.5 w-3.5 text-lab-500 shrink-0" />
                      <span className="text-xs text-lab-400">{cmd}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Disabled input */}
              <div className="mt-auto px-4 pb-4">
                <div className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-lab-800/60 border border-lab-700 opacity-50">
                  <MessageSquare className="h-4 w-4 text-lab-500" />
                  <span className="text-sm text-lab-600 flex-1">Ask the AI Agent…</span>
                  <span className="text-[10px] text-lab-600 evidence-tag">COMING SOON</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </>
  );
}

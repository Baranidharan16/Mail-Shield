import { useState, useRef, useEffect, useCallback } from "react";
import {
  Shield, X, Send, Sparkles, ChevronDown, ChevronUp,
  Bot, Loader2, RotateCcw, Activity,
  Copy, Check, Radio, Terminal
} from "lucide-react";

import {
  postMailShieldChat,
  getDashboardStats,
  getRecentAlerts,
  type MailShieldEmailContext,
  type ChatHistoryEntry,
} from "../api/client";
import { useChat } from "../context/ChatContext";

// ─── Types ───────────────────────────────────────────────────────────────────

interface Message {
  id: string;
  role: "assistant" | "user";
  text: string;
  engine?: string;
  error?: boolean;
  timestamp?: string;
}

interface Props {
  emailContext?: MailShieldEmailContext;
}

// ─── Quick action sets ────────────────────────────────────────────────────────

const CASE_ACTIONS = [
  { label: "Explain This Email", prompt: "Can you explain what is happening with this email and why it might be dangerous?" },
  { label: "Why Is It Dangerous?", prompt: "Why is this email considered dangerous? What are the key risk factors?" },
  { label: "Analyze SPF/DKIM/DMARC", prompt: "Can you explain the SPF, DKIM, and DMARC results in simple language?" },
  { label: "Analyze URLs & Links", prompt: "What can you tell me about the URLs found in this email and why they are risky?" },
  { label: "Inspect Attachments", prompt: "Are the attachments in this email dangerous? What should I watch out for?" },
  { label: "Defensive Steps", prompt: "What defensive containment steps should I take regarding this email threat?" },
];

const GLOBAL_ACTIONS = [
  { label: "📊 Live Forensic Stats", prompt: "What are the current overall platform forensic statistics and threat metrics?" },
  { label: "🚨 Show Critical Alerts", prompt: "Summarize the recent critical alerts and urgent security warnings." },
  { label: "🛡️ Explain SPF/DKIM/DMARC", prompt: "Explain how SPF, DKIM, and DMARC protect email security and why failures occur." },
  { label: "🔬 Detect Domain Spoofing", prompt: "How does MailShield detect domain lookalikes and spoofing attacks?" },
  { label: "💡 SOC Forensic Guide", prompt: "What are the best forensic procedures when analyzing a suspicious spear-phishing email?" },
];

// ─── Markdown Formatter ───────────────────────────────────────────────────────

function renderMarkdown(text: string) {
  const lines = text.split("\n");
  return lines.map((line, i) => {
    // Bullet lines
    const isBullet = line.trim().startsWith("- ") || line.trim().startsWith("• ");
    const cleanLine = isBullet ? line.trim().replace(/^[-•]\s*/, "") : line;

    const parts = cleanLine.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);

    const formatted = parts.map((part, j) => {
      if (part.startsWith("**") && part.endsWith("**")) {
        return (
          <strong key={j} className="text-phosphor-300 font-semibold">
            {part.slice(2, -2)}
          </strong>
        );
      }
      if (part.startsWith("`") && part.endsWith("`")) {
        return (
          <code
            key={j}
            className="px-1.5 py-0.5 mx-0.5 rounded bg-lab-900 border border-lab-700 font-mono text-[11px] text-phosphor-400"
          >
            {part.slice(1, -1)}
          </code>
        );
      }
      return <span key={j}>{part}</span>;
    });

    if (isBullet) {
      return (
        <div key={i} className="flex items-start gap-2 my-1 pl-1">
          <span className="text-phosphor-400 text-xs mt-0.5">•</span>
          <span className="flex-1">{formatted}</span>
        </div>
      );
    }

    return (
      <div key={i} className={line.trim() === "" ? "h-2" : "my-0.5"}>
        {formatted}
      </div>
    );
  });
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function MailShieldChatbot({ emailContext: propContext }: Props) {
  const {
    isOpen,
    setIsOpen,
    activeContext: contextFromState,
    queuedPrompt,
    clearQueuedPrompt,
  } = useChat();

  // Prefer context from props if supplied, otherwise context from global state
  const effectiveContext = propContext ?? contextFromState;

  const [minimized, setMinimized] = useState(false);
  const [input, setInput] = useState("");
  const [systemStats, setSystemStats] = useState<Record<string, any> | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      text: "👋 Welcome to **MailShield AI** — your real-time Forensic Intelligence Sentinel powered by **Google Gemini**.\n\nI continuously monitor email forensic telemetry, authentication health (SPF, DKIM, DMARC), risk scores, and platform alerts. Ask me anything or select a quick action below.",
      engine: "gemini",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);

  const [history, setHistory] = useState<ChatHistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Load telemetry stats on mount for global forensic awareness
  useEffect(() => {
    let mounted = true;
    getDashboardStats()
      .then((stats) => {
        if (mounted) setSystemStats(stats);
      })
      .catch(() => {});

    getRecentAlerts(5)
      .then((alerts) => {
        if (mounted) setRecentAlerts(alerts);
      })
      .catch(() => {});

    return () => {
      mounted = false;
    };
  }, []);

  // Update welcome message dynamically when context switches
  useEffect(() => {
    if (effectiveContext?.case_id) {
      setMessages((prev) => {
        const hasCaseWelcome = prev.some((m) => m.id === `case-welcome-${effectiveContext.case_id}`);
        if (!hasCaseWelcome) {
          return [
            ...prev,
            {
              id: `case-welcome-${effectiveContext.case_id}`,
              role: "assistant",
              text: `🔍 **Forensic Investigation Loaded: Case ${effectiveContext.case_id}**\n\n- **Threat Level**: \`${effectiveContext.threat_level ?? "N/A"}\`\n- **Threat Score**: \`${effectiveContext.threat_score?.toFixed(0) ?? "?"}/100\`\n- **Authentication**: SPF=\`${effectiveContext.spf ?? "N/A"}\`, DKIM=\`${effectiveContext.dkim ?? "N/A"}\`, DMARC=\`${effectiveContext.dmarc ?? "N/A"}\`\n\nI am analyzing this specific email threat. Ask me to explain headers, URLs, attachments, or recommended mitigations.`,
              engine: "gemini",
              timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
            },
          ];
        }
        return prev;
      });
    }
  }, [effectiveContext]);

  // Handle auto-scroll
  useEffect(() => {
    if (isOpen && !minimized) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isOpen, minimized]);

  // Auto-focus input when opened
  useEffect(() => {
    if (isOpen && !minimized) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen, minimized]);

  // Handle queued prompt from other components
  useEffect(() => {
    if (queuedPrompt && isOpen) {
      sendMessage(queuedPrompt);
      clearQueuedPrompt();
    }
  }, [queuedPrompt, isOpen]);

  const sendMessage = useCallback(
    async (text: string) => {
      if (!text.trim() || loading) return;

      const userMsg: Message = {
        id: `u-${Date.now()}`,
        role: "user",
        text: text.trim(),
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };

      setMessages((prev) => [...prev, userMsg]);
      setInput("");
      setLoading(true);

      // Build composite context with telemetry
      const compositeContext: MailShieldEmailContext = {
        ...(effectiveContext || {}),
        system_stats: systemStats ?? undefined,
        recent_alerts: recentAlerts.length > 0 ? recentAlerts : undefined,
      };

      try {
        const res = await postMailShieldChat(text.trim(), compositeContext, history);
        const aiMsg: Message = {
          id: `a-${Date.now()}`,
          role: "assistant",
          text: res.reply,
          engine: res.engine || "gemini",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        };

        setMessages((prev) => [...prev, aiMsg]);
        setHistory((prev) => [
          ...prev,
          { role: "user", text: text.trim() },
          { role: "model", text: res.reply },
        ]);
      } catch (err: any) {
        setMessages((prev) => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            role: "assistant",
            text: "⚠️ **Forensic Sentinel Offline**: Unable to connect to backend AI services. Please verify backend server status.",
            error: true,
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          },
        ]);
      } finally {
        setLoading(false);
      }
    },
    [loading, effectiveContext, systemStats, recentAlerts, history]
  );

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  }

  function resetChat() {
    setMessages([
      {
        id: "welcome-reset",
        role: "assistant",
        text: effectiveContext?.case_id
          ? `🔄 **Chat reset.** Forensic context for **Case ${effectiveContext.case_id}** is active. Ask me anything about this investigation.`
          : "🔄 **Chat reset.** Ready to assist with email forensics and live threat monitoring.",
        engine: "gemini",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      },
    ]);
    setHistory([]);
  }

  function copyText(id: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  const actionsToDisplay = effectiveContext?.case_id ? CASE_ACTIONS : GLOBAL_ACTIONS;

  return (
    <>
      {/* ── Floating Launcher Trigger ─────────────────────────────────────── */}
      {!isOpen && (
        <button
          id="mailshield-ai-open-btn"
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-full
            bg-gradient-to-r from-lab-900 via-lab-850 to-lab-900 border border-phosphor-500/50
            text-lab-100 hover:border-phosphor-400 hover:scale-[1.02] active:scale-[0.98]
            transition-all duration-300 shadow-2xl shadow-black/70 backdrop-blur-xl group"
          aria-label="Open MailShield AI Chatbot"
        >
          <div className="relative flex items-center justify-center w-8 h-8 rounded-full bg-phosphor-500/15 border border-phosphor-500/40 glow-green">
            <Shield className="h-4 w-4 text-phosphor-400" strokeWidth={2} />
            <span className="absolute -top-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-phosphor-500 animate-ping opacity-75" />
            <span className="absolute -top-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-phosphor-500" />
          </div>

          <div className="text-left">
            <div className="text-xs font-bold tracking-tight text-lab-100 flex items-center gap-1.5">
              MailSheild AI
              <Sparkles size={11} className="text-phosphor-400 animate-pulse" />
            </div>
            <div className="text-[10px] text-phosphor-400 font-mono flex items-center gap-1">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-phosphor-500" />
              FORENSIC SENTINEL
            </div>
          </div>

          {effectiveContext?.case_id && (
            <span className="ml-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40">
              CASE ACTIVE
            </span>
          )}
        </button>
      )}

      {/* ── Main Chatbot Window ────────────────────────────────────────────── */}
      {isOpen && (
        <div
          id="mailshield-ai-panel"
          className={`fixed bottom-6 right-6 z-50 w-[420px] max-w-[calc(100vw-2rem)] rounded-2xl overflow-hidden
            shadow-2xl shadow-black/80 border border-phosphor-500/30 bg-lab-950/95 backdrop-blur-xl
            transition-all duration-300 ease-in-out flex flex-col
            ${minimized ? "h-14" : "h-[630px] max-h-[calc(100vh-5rem)]"}`}
        >
          {/* ── Window Header ────────────────────────────────────────────── */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 bg-gradient-to-r from-lab-900 via-lab-850 to-lab-900 shrink-0 select-none">
            <div className="flex items-center gap-2.5">
              <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-phosphor-500/15 border border-phosphor-500/40 glow-green">
                <Shield className="h-4 w-4 text-phosphor-400" strokeWidth={2} />
                <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-phosphor-500" />
              </div>

              <div>
                <div className="text-sm font-bold text-lab-100 leading-none flex items-center gap-1.5">
                  MailShield AI
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-mono">
                    GEMINI 2.0
                  </span>
                </div>
                <div className="text-[10px] text-phosphor-400 font-mono mt-0.5 flex items-center gap-1">
                  <Activity size={10} className="text-phosphor-400 animate-pulse" />
                  {effectiveContext?.case_id
                    ? `MONITORING · CASE ${effectiveContext.case_id}`
                    : "FORENSIC SENTINEL · LIVE"}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                id="mailshield-reset-btn"
                onClick={resetChat}
                title="Reset conversation"
                className="p-1.5 rounded-lg hover:bg-white/5 text-lab-400 hover:text-lab-200 transition-colors"
              >
                <RotateCcw className="h-3.5 w-3.5" />
              </button>
              <button
                id="mailshield-minimize-btn"
                onClick={() => setMinimized(!minimized)}
                title={minimized ? "Expand" : "Minimize"}
                className="p-1.5 rounded-lg hover:bg-white/5 text-lab-400 hover:text-lab-200 transition-colors"
              >
                {minimized ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
              <button
                id="mailshield-close-btn"
                onClick={() => setIsOpen(false)}
                title="Close"
                className="p-1.5 rounded-lg hover:bg-white/5 text-lab-400 hover:text-crimson-signal transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* ── Collapsible Content ───────────────────────────────────────── */}
          {!minimized && (
            <>
              {/* ── Live Forensic Telemetry HUD Strip ───────────────────────── */}
              <div className="px-3.5 py-2 bg-lab-900/90 border-b border-white/5 flex items-center justify-between text-[11px] font-mono shrink-0">
                {effectiveContext?.case_id ? (
                  <div className="flex items-center gap-3 w-full justify-between">
                    <div className="flex items-center gap-1.5">
                      <span className="text-lab-400">Score:</span>
                      <span
                        className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${
                          (effectiveContext.threat_score ?? 0) >= 70
                            ? "bg-crimson-signal/20 text-crimson-signal border border-crimson-signal/30"
                            : (effectiveContext.threat_score ?? 0) >= 40
                            ? "bg-amber-signal/20 text-amber-signal border border-amber-signal/30"
                            : "bg-phosphor-500/20 text-phosphor-400 border border-phosphor-500/30"
                        }`}
                      >
                        {effectiveContext.threat_score?.toFixed(0) ?? "?"}/100
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-lab-500">SPF:</span>
                      <span className={effectiveContext.spf === "PASS" ? "text-phosphor-400" : "text-amber-signal"}>
                        {effectiveContext.spf ?? "—"}
                      </span>
                      <span className="text-lab-500">DKIM:</span>
                      <span className={effectiveContext.dkim === "PASS" ? "text-phosphor-400" : "text-amber-signal"}>
                        {effectiveContext.dkim ?? "—"}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-3 w-full justify-between">
                    <div className="flex items-center gap-1.5">
                      <Radio size={12} className="text-phosphor-400 animate-pulse" />
                      <span className="text-lab-300">Live SOC Telemetry</span>
                    </div>
                    {systemStats && (
                      <div className="flex items-center gap-2 text-[10px]">
                        <span className="text-crimson-signal font-semibold">
                          CRIT: {systemStats.critical ?? 0}
                        </span>
                        <span className="text-amber-signal font-semibold">
                          HIGH: {systemStats.high ?? 0}
                        </span>
                        <span className="text-lab-400">
                          ALERTS: {systemStats.active_alerts ?? 0}
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* ── Messages Stream ───────────────────────────────────────── */}
              <div className="flex-1 overflow-y-auto px-4 py-3.5 space-y-3.5 scrollbar-thin scrollbar-thumb-lab-700 text-xs">
                {messages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex gap-2.5 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                  >
                    {msg.role === "assistant" && (
                      <div className="shrink-0 w-7 h-7 rounded-lg bg-phosphor-500/10 border border-phosphor-500/30 flex items-center justify-center mt-0.5">
                        <Shield className="h-3.5 w-3.5 text-phosphor-400" />
                      </div>
                    )}

                    <div
                      className={`max-w-[85%] rounded-xl px-3.5 py-2.5 relative group leading-relaxed ${
                        msg.role === "user"
                          ? "bg-phosphor-500/15 border border-phosphor-500/30 text-lab-100 rounded-tr-xs"
                          : msg.error
                          ? "bg-crimson-signal/15 border border-crimson-signal/30 text-crimson-signal rounded-tl-xs"
                          : "bg-lab-900/85 border border-lab-700/80 text-lab-200 rounded-tl-xs shadow-lg shadow-black/20"
                      }`}
                    >
                      {msg.role === "assistant" && (
                        <div className="flex items-center justify-between gap-2 mb-1.5 pb-1 border-b border-white/5 text-[10px] font-mono text-lab-500">
                          <span className="flex items-center gap-1 text-phosphor-400">
                            <Sparkles size={9} />
                            {msg.engine === "gemini" ? "Google Gemini AI" : "Forensic Reasoning Engine"}
                          </span>

                          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button
                              onClick={() => copyText(msg.id, msg.text)}
                              title="Copy response"
                              className="p-1 rounded hover:bg-white/5 text-lab-400 hover:text-lab-200"
                            >
                              {copiedId === msg.id ? (
                                <Check size={10} className="text-phosphor-400" />
                              ) : (
                                <Copy size={10} />
                              )}
                            </button>
                            <span>{msg.timestamp}</span>
                          </div>
                        </div>
                      )}

                      {msg.role === "assistant" ? (
                        <div className="space-y-1">{renderMarkdown(msg.text)}</div>
                      ) : (
                        <span>{msg.text}</span>
                      )}
                    </div>

                    {msg.role === "user" && (
                      <div className="shrink-0 w-7 h-7 rounded-lg bg-lab-800 border border-lab-700 flex items-center justify-center mt-0.5">
                        <Bot className="h-3.5 w-3.5 text-lab-400" />
                      </div>
                    )}
                  </div>
                ))}

                {/* Loading indicator */}
                {loading && (
                  <div className="flex gap-2.5 justify-start">
                    <div className="shrink-0 w-7 h-7 rounded-lg bg-phosphor-500/10 border border-phosphor-500/30 flex items-center justify-center mt-0.5">
                      <Shield className="h-3.5 w-3.5 text-phosphor-400" />
                    </div>
                    <div className="px-3.5 py-2.5 rounded-xl rounded-tl-xs bg-lab-900/85 border border-lab-700/80 flex items-center gap-2 text-xs text-lab-400">
                      <Loader2 className="h-3.5 w-3.5 animate-spin text-phosphor-400" />
                      <span className="font-mono text-[11px]">Gemini analyzing forensic telemetry…</span>
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>

              {/* ── Quick Forensic Action Chips ───────────────────────────── */}
              <div className="px-3 py-2 bg-lab-900/50 border-t border-white/5 shrink-0">
                <div className="text-[9px] font-mono text-lab-500 uppercase tracking-wider mb-1.5 px-0.5 flex items-center justify-between">
                  <span>Forensic Prompts</span>
                  <span className="text-phosphor-500/80">{effectiveContext?.case_id ? "Active Case" : "SOC Overview"}</span>
                </div>
                <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto scrollbar-none">
                  {actionsToDisplay.map((action) => (
                    <button
                      key={action.label}
                      onClick={() => sendMessage(action.prompt)}
                      disabled={loading}
                      className="text-[10px] px-2 py-1 rounded bg-lab-850 hover:bg-phosphor-500/10
                        border border-lab-700/80 hover:border-phosphor-500/40 text-lab-300 hover:text-phosphor-300
                        transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* ── Input Bar ─────────────────────────────────────────────── */}
              <div className="p-3 bg-lab-950 border-t border-white/10 shrink-0">
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-lab-900/90 border border-lab-700/80 focus-within:border-phosphor-500/50 focus-within:ring-1 focus-within:ring-phosphor-500/20 transition-all">
                  <Terminal size={14} className="text-lab-500 shrink-0" />
                  <input
                    id="mailshield-chat-input"
                    ref={inputRef}
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask Gemini about forensic threats, headers, SPF/DKIM…"
                    disabled={loading}
                    className="flex-1 bg-transparent text-xs text-lab-100 placeholder-lab-500 outline-none disabled:opacity-50"
                    maxLength={500}
                  />
                  <button
                    id="mailshield-send-btn"
                    onClick={() => sendMessage(input)}
                    disabled={!input.trim() || loading}
                    className="shrink-0 w-7 h-7 rounded-lg bg-phosphor-500/20 hover:bg-phosphor-500/30
                      border border-phosphor-500/40 text-phosphor-400 hover:text-phosphor-300
                      flex items-center justify-center transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                    aria-label="Send query"
                  >
                    {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                  </button>
                </div>

                <div className="flex items-center justify-between mt-2 px-1 text-[9px] font-mono text-lab-500">
                  <span className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-phosphor-400" />
                    API Key: Configured (Gemini)
                  </span>
                  <span>Press Enter ↵</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
}

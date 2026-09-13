import { useState, useRef, useEffect, useCallback } from "react";
import {
  Shield, X, Send, Sparkles, ChevronDown, ChevronUp,
  Loader2, RotateCcw,
  Copy, Check, Radio, Mic, Volume2, VolumeX, Globe
} from "lucide-react";

import {
  postAssistantChat,
  postAssistantTranscribe,
  postAssistantSpeak,
  getDashboardStats,
  getRecentAlerts,
  type MailShieldEmailContext,
} from "../api/client";
import { useChat } from "../context/ChatContext";

// ── Supported 22 Indian Languages + English (Sarvam AI) ────────────────────────
export const INDIAN_LANGUAGES = [
  { code: "en-IN", name: "English (India)", native: "English" },
  { code: "ta-IN", name: "Tamil", native: "தமிழ்" },
  { code: "hi-IN", name: "Hindi", native: "हिन्दी" },
  { code: "te-IN", name: "Telugu", native: "తెలుగు" },
  { code: "kn-IN", name: "Kannada", native: "ಕನ್ನಡ" },
  { code: "ml-IN", name: "Malayalam", native: "മലയാളം" },
  { code: "mr-IN", name: "Marathi", native: "मराठी" },
  { code: "bn-IN", name: "Bengali", native: "বাংলা" },
  { code: "gu-IN", name: "Gujarati", native: "ગુજરાતી" },
  { code: "pa-IN", name: "Punjabi", native: "ਪੰਜਾਬੀ" },
  { code: "or-IN", name: "Odia", native: "ଓଡ଼ିଆ" },
  { code: "as-IN", name: "Assamese", native: "অসমীয়া" },
  { code: "ur-IN", name: "Urdu", native: "اردو" },
  { code: "sa-IN", name: "Sanskrit", native: "संस्कृतम्" },
  { code: "mai-IN", name: "Maithili", native: "मैथिली" },
  { code: "ne-IN", name: "Nepali", native: "नेपाली" },
  { code: "kok-IN", name: "Konkani", native: "कोंकणी" },
  { code: "ks-IN", name: "Kashmiri", native: "کٲشُر" },
  { code: "sd-IN", name: "Sindhi", native: "سنڌي" },
  { code: "sat-IN", name: "Santali", native: "ᱥᱟᱱᱛᱟᱲᱤ" },
  { code: "brx-IN", name: "Bodo", native: "बड़ो" },
  { code: "doi-IN", name: "Dogri", native: "डोगरी" },
];

// ─── Types ───────────────────────────────────────────────────────────────────

interface Message {
  id: string;
  role: "assistant" | "user";
  text: string;
  engine?: string;
  error?: boolean;
  timestamp?: string;
  audioBase64?: string;
}

interface Props {
  emailContext?: MailShieldEmailContext;
}

// ─── Quick action prompts ────────────────────────────────────────────────────

const INVESTIGATION_ACTIONS = [
  { label: "What is the risk?", prompt: "What is the risk score and risk level evaluated for this email?" },
  { label: "Why is this phishing?", prompt: "Why was this email classified as phishing? Explain the specific evidence." },
  { label: "What did NLP detect?", prompt: "What did the MailShield NLP threat-pattern model detect across the 6 dimensions?" },
  { label: "Explain SPF failure", prompt: "Explain the SPF, DKIM, and DMARC authentication findings in detail." },
  { label: "Explain in Tamil", prompt: "Explain this email threat and analysis findings in Tamil (தமிழ்)." },
  { label: "What should I do?", prompt: "What defensive SOC containment actions should I take immediately?" },
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
    activeContext: globalContext,
  } = useChat();

  const [isMinimized, setIsMinimized] = useState(false);

  const effectiveContext = propContext || globalContext;

  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      text: "👋 **MailShield AI Forensic Sentinel is online.**\n\nI am grounded in live telemetry from your trained Keras ML phishing detector, NLP threat-pattern classifier, and forensic header inspection.\n\nAsk me about threat vectors, authentication failures, or speak in any of **22 Indian languages** with the microphone below.",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);

  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [systemStats, setSystemStats] = useState<any>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Sarvam Multilingual Voice States
  const [selectedLang, setSelectedLang] = useState<string>("en-IN");
  const [isRecording, setIsRecording] = useState(false);
  const [transcribing, setTranscribing] = useState(false);
  const [speakingId, setSpeakingId] = useState<string | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const currentAudioRef = useRef<HTMLAudioElement | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    if (isOpen && !isMinimized) {
      scrollToBottom();
    }
  }, [messages, isOpen, isMinimized, scrollToBottom]);

  // Load contextual dashboard stats
  useEffect(() => {
    let unmounted = false;
    async function loadStats() {
      try {
        const [stats, alerts] = await Promise.all([
          getDashboardStats().catch(() => null),
          getRecentAlerts(5).catch(() => []),
        ]);
        if (!unmounted) {
          if (stats) setSystemStats(stats);
          if (alerts) setRecentAlerts(alerts);
        }
      } catch {
        // graceful
      }
    }
    loadStats();
    return () => {
      unmounted = true;
    };
  }, []);

  // Stop any playing audio on unmount or reset
  useEffect(() => {
    return () => {
      if (currentAudioRef.current) {
        currentAudioRef.current.pause();
        currentAudioRef.current = null;
      }
    };
  }, []);

  // ── Send Message ─────────────────────────────────────────────────────────────
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

      const compositeContext: any = {
        ...(effectiveContext || {}),
        system_stats: systemStats ?? undefined,
        recent_alerts: recentAlerts.length > 0 ? recentAlerts : undefined,
      };

      try {
        const res = await postAssistantChat(
          text.trim(),
          compositeContext,
          messages.slice(-4).map((m) => ({ role: m.role === "user" ? "user" : "model", content: m.text })),
          selectedLang
        );

        const aiMsg: Message = {
          id: `a-${Date.now()}`,
          role: "assistant",
          text: res.answer,
          engine: res.engine || "gemini",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        };

        setMessages((prev) => [...prev, aiMsg]);
      } catch (err: any) {
        setMessages((prev) => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            role: "assistant",
            text: "⚠️ **Forensic Sentinel Offline**: Unable to connect to backend AI reasoning. Grounded local models remain active.",
            error: true,
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          },
        ]);
      } finally {
        setLoading(false);
      }
    },
    [loading, effectiveContext, systemStats, recentAlerts, messages, selectedLang]
  );

  // ── Voice Recording (Sarvam STT) ─────────────────────────────────────────────
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mediaRecorder = new MediaRecorder(stream);
      mediaRecorderRef.current = mediaRecorder;
      audioChunksRef.current = [];

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunksRef.current.push(event.data);
        }
      };

      mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: "audio/wav" });
        stream.getTracks().forEach((track) => track.stop());

        if (audioBlob.size > 0) {
          setTranscribing(true);
          try {
            const res = await postAssistantTranscribe(audioBlob, selectedLang);
            if (res.transcript && res.transcript.trim()) {
              sendMessage(res.transcript);
            }
          } catch (err) {
            console.error("Sarvam transcription error:", err);
          } finally {
            setTranscribing(false);
          }
        }
      };

      mediaRecorder.start();
      setIsRecording(true);
    } catch (err) {
      console.error("Microphone access denied:", err);
      alert("Microphone access is required for Sarvam AI voice queries.");
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
    }
  };

  // ── Voice Playback (Sarvam TTS) ──────────────────────────────────────────────
  const playAudioResponse = async (msg: Message) => {
    if (speakingId === msg.id) {
      if (currentAudioRef.current) {
        currentAudioRef.current.pause();
        currentAudioRef.current = null;
      }
      setSpeakingId(null);
      return;
    }

    try {
      setSpeakingId(msg.id);

      let b64 = msg.audioBase64;
      if (!b64) {
        const res = await postAssistantSpeak(msg.text, selectedLang);
        b64 = res.audio_base64;
        if (b64) {
          msg.audioBase64 = b64;
        }
      }

      if (b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const blob = new Blob([bytes], { type: "audio/wav" });
        const url = URL.createObjectURL(blob);
        const audio = new Audio(url);
        currentAudioRef.current = audio;

        audio.play();
        audio.onended = () => {
          setSpeakingId(null);
          URL.revokeObjectURL(url);
        };
        audio.onerror = () => {
          setSpeakingId(null);
          URL.revokeObjectURL(url);
        };
      } else {
        setSpeakingId(null);
      }
    } catch (err) {
      console.error("Sarvam TTS playback error:", err);
      setSpeakingId(null);
    }
  };

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  }

  function resetChat() {
    if (currentAudioRef.current) {
      currentAudioRef.current.pause();
      currentAudioRef.current = null;
    }
    setSpeakingId(null);
    setMessages([
      {
        id: "welcome-reset",
        role: "assistant",
        text: effectiveContext?.case_id
          ? `🔄 **Chat reset.** Forensic telemetry for **Case ${effectiveContext.case_id}** is active. Ask me anything about this investigation.`
          : "🔄 **Chat reset.** Ready to assist with email forensics and live threat telemetry.",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      },
    ]);
  }

  function copyText(id: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  const actionsToDisplay = effectiveContext?.case_id ? INVESTIGATION_ACTIONS : GLOBAL_ACTIONS;

  return (
    <>
      {/* ── Floating Launcher Trigger (Bottom-Right) ───────────────────────── */}
      {!isOpen && (
        <button
          id="mailshield-ai-open-btn"
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-full
            bg-gradient-to-r from-lab-900 via-lab-850 to-lab-900 border border-phosphor-500/50
            text-lab-100 hover:border-phosphor-400 hover:scale-[1.02] active:scale-[0.98]
            transition-all duration-300 shadow-2xl shadow-black/70 backdrop-blur-xl group"
          aria-label="Open MailShield AI Assistant"
        >
          <div className="relative flex items-center justify-center w-8 h-8 rounded-full bg-phosphor-500/15 border border-phosphor-500/40 glow-green">
            <Shield className="h-4 w-4 text-phosphor-400" strokeWidth={2} />
            <span className="absolute -top-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-phosphor-500 animate-ping opacity-75" />
            <span className="absolute -top-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-phosphor-500" />
          </div>

          <div className="text-left">
            <div className="text-xs font-bold tracking-tight text-lab-100 flex items-center gap-1.5">
              MailShield AI
              <Sparkles size={11} className="text-phosphor-400 animate-pulse" />
            </div>
            <div className="text-[10px] text-phosphor-400 font-mono flex items-center gap-1">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-phosphor-500" />
              FORENSIC SENTINEL • LIVE
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
          id="mailshield-chatbot-window"
          className={`fixed bottom-6 right-6 z-50 flex flex-col rounded-2xl
            bg-lab-950/95 border border-phosphor-500/40 backdrop-blur-2xl
            shadow-2xl shadow-black/90 transition-all duration-300 overflow-hidden
            ${isMinimized ? "w-80 h-14" : "w-[440px] max-w-[calc(100vw-2rem)] h-[650px] max-h-[calc(100vh-5rem)]"}`}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 bg-lab-900/90 border-b border-white/[0.08] select-none">
            <div className="flex items-center gap-2.5">
              <div className="relative flex items-center justify-center w-7 h-7 rounded-full bg-phosphor-500/15 border border-phosphor-500/40">
                <Shield className="h-3.5 w-3.5 text-phosphor-400" />
                <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-phosphor-500 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-bold text-white tracking-tight">MailShield AI</span>
                  <span className="text-[9px] px-1.5 py-0.2 rounded font-mono bg-phosphor-500/20 text-phosphor-300 border border-phosphor-500/30">
                    GEMINI + SARVAM
                  </span>
                </div>
                <div className="text-[9.5px] text-phosphor-400 font-mono tracking-wider flex items-center gap-1">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-phosphor-500" />
                  FORENSIC SENTINEL • LIVE
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1">
              {/* Reset Chat */}
              <button
                onClick={resetChat}
                title="Clear conversation"
                className="p-1.5 rounded-lg text-lab-400 hover:text-lab-200 hover:bg-white/5 transition-colors"
              >
                <RotateCcw size={13} />
              </button>

              {/* Minimize/Maximize */}
              <button
                onClick={() => setIsMinimized(!isMinimized)}
                className="p-1.5 rounded-lg text-lab-400 hover:text-lab-200 hover:bg-white/5 transition-colors"
                title={isMinimized ? "Expand" : "Minimize"}
              >
                {isMinimized ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </button>

              {/* Close */}
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-lab-400 hover:text-lab-200 hover:bg-white/5 transition-colors"
                title="Close"
              >
                <X size={14} />
              </button>
            </div>
          </div>

          {!isMinimized && (
            <>
              {/* Context Bar */}
              <div className="px-3.5 py-1.5 bg-black/40 border-b border-white/[0.04] flex items-center justify-between text-[10px] font-mono text-lab-400">
                <div className="flex items-center gap-1.5 truncate">
                  <Radio size={10} className="text-phosphor-400 animate-pulse shrink-0" />
                  <span className="truncate">
                    {effectiveContext?.case_id
                      ? `Active Investigation: Case ${effectiveContext.case_id}`
                      : "Global SOC Forensic Telemetry Active"}
                  </span>
                </div>

                {/* Indian Language Selector */}
                <div className="flex items-center gap-1 shrink-0 ml-2">
                  <Globe size={11} className="text-purple-400" />
                  <select
                    value={selectedLang}
                    onChange={(e) => setSelectedLang(e.target.value)}
                    className="bg-lab-900 border border-white/10 rounded px-1.5 py-0.5 text-[10px] text-lab-200 focus:outline-none focus:border-phosphor-500 font-mono"
                    title="Select Sarvam Indian Language"
                  >
                    {INDIAN_LANGUAGES.map((lang) => (
                      <option key={lang.code} value={lang.code}>
                        {lang.native} ({lang.name.split(" ")[0]})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Message List */}
              <div className="flex-1 overflow-y-auto p-4 space-y-3.5 text-xs scanline">
                {messages.map((m) => (
                  <div
                    key={m.id}
                    className={`flex flex-col ${m.role === "user" ? "items-end" : "items-start"}`}
                  >
                    <div
                      className={`max-w-[85%] rounded-2xl px-3.5 py-2.5 relative group shadow-sm ${
                        m.role === "user"
                          ? "bg-gradient-to-br from-phosphor-700/80 to-phosphor-900/90 text-white border border-phosphor-500/30 rounded-br-sm"
                          : m.error
                          ? "bg-crimson-glow/10 border border-crimson-glow/30 text-crimson-glow rounded-bl-sm"
                          : "bg-lab-900/80 border border-white/[0.08] text-lab-200 rounded-bl-sm"
                      }`}
                    >
                      <div className="leading-relaxed">{renderMarkdown(m.text)}</div>

                      {/* Message Footer Controls */}
                      <div className="flex items-center justify-between mt-2 pt-1 border-t border-white/[0.05] text-[9.5px] font-mono text-lab-400 gap-3">
                        <span>{m.timestamp}</span>

                        <div className="flex items-center gap-1">
                          {/* Sarvam Audio Playback for Assistant */}
                          {m.role === "assistant" && !m.error && (
                            <button
                              onClick={() => playAudioResponse(m)}
                              className={`p-1 rounded hover:bg-white/10 transition-colors flex items-center gap-1 ${
                                speakingId === m.id ? "text-phosphor-300 font-bold" : "text-lab-400"
                              }`}
                              title={speakingId === m.id ? "Stop voice" : "Read aloud with Sarvam Voice"}
                            >
                              {speakingId === m.id ? (
                                <>
                                  <VolumeX size={11} className="text-crimson-glow" />
                                  <span>Stop</span>
                                </>
                              ) : (
                                <>
                                  <Volume2 size={11} />
                                  <span>Voice</span>
                                </>
                              )}
                            </button>
                          )}

                          {/* Copy Button */}
                          <button
                            onClick={() => copyText(m.id, m.text)}
                            className="p-1 rounded hover:bg-white/10 text-lab-400 hover:text-white transition-colors"
                            title="Copy text"
                          >
                            {copiedId === m.id ? <Check size={11} className="text-phosphor-400" /> : <Copy size={11} />}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}

                {/* Loading / Transcribing Indicator */}
                {(loading || transcribing) && (
                  <div className="flex items-center gap-2 text-lab-400 text-xs font-mono pl-2">
                    <Loader2 size={14} className="animate-spin text-phosphor-400" />
                    <span>
                      {transcribing
                        ? "Sarvam AI transcribing speech across 22 Indian languages…"
                        : "MailShield AI evaluating forensic telemetry…"}
                    </span>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>

              {/* Quick Actions Chips */}
              <div className="px-3 py-2 bg-black/40 border-t border-white/[0.06] overflow-x-auto whitespace-nowrap flex gap-1.5 scrollbar-thin">
                {actionsToDisplay.map((act, i) => (
                  <button
                    key={i}
                    onClick={() => sendMessage(act.prompt)}
                    disabled={loading}
                    className="text-[10px] px-2.5 py-1 rounded-full bg-lab-900/80 border border-white/10
                      text-lab-300 hover:text-phosphor-300 hover:border-phosphor-500/40
                      transition-colors shrink-0 disabled:opacity-50"
                  >
                    {act.label}
                  </button>
                ))}
              </div>

              {/* Input & Microphone Bar */}
              <div className="p-3 bg-lab-900 border-t border-white/[0.08]">
                <div className="flex items-center gap-2">
                  {/* Microphone Button (Sarvam STT) */}
                  <button
                    onClick={isRecording ? stopRecording : startRecording}
                    disabled={loading || transcribing}
                    className={`p-2 rounded-xl border transition-all flex items-center justify-center shrink-0 ${
                      isRecording
                        ? "bg-crimson-signal text-white border-crimson-glow animate-pulse shadow-lg shadow-crimson-signal/50"
                        : "bg-lab-800 border-white/10 text-lab-300 hover:text-phosphor-300 hover:border-phosphor-500/40"
                    }`}
                    title={isRecording ? "Stop Recording" : "Speak in any of 22 Indian languages (Sarvam STT)"}
                  >
                    <Mic size={16} />
                  </button>

                  {/* Text Input */}
                  <input
                    id="mailshield-chat-input"
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    disabled={loading || isRecording}
                    placeholder={
                      isRecording
                        ? "Listening... (Speak now)"
                        : "Ask a question about this email or SOC telemetry…"
                    }
                    className="flex-1 bg-lab-950 border border-white/10 rounded-xl px-3.5 py-2 text-xs
                      text-white placeholder-lab-500 focus:outline-none focus:border-phosphor-500/60
                      focus:ring-1 focus:ring-phosphor-500/40 transition-all font-mono"
                  />

                  {/* Send Button */}
                  <button
                    onClick={() => sendMessage(input)}
                    disabled={!input.trim() || loading || isRecording}
                    className="p-2 rounded-xl bg-phosphor-600 hover:bg-phosphor-500 disabled:opacity-40
                      text-black transition-colors shrink-0 flex items-center justify-center font-bold"
                    title="Send message"
                  >
                    <Send size={15} />
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
}

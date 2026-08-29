/**
 * ForensicAIChat — Real evidence-grounded AI chat panel.
 * Replaces the placeholder with a functional chat system.
 *
 * Features:
 * - Suggested question chips
 * - Free-form question input
 * - Prompt injection protection (handled server-side)
 * - Markdown-formatted answers
 * - Evidence reference display
 * - Follow-up suggestion chips
 */
import { useState, useRef, useEffect } from "react";
import { Send, Bot, User, Shield, Loader2, RotateCcw } from "lucide-react";
import type { ForensicAIResult, ForensicAIChatResponse } from "../../types/investigation";
import { postForensicAIChat } from "../../api/client";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  evidenceRefs?: string[];
  followups?: string[];
  timestamp: Date;
}

interface Props {
  investigationId: string;
  aiData: ForensicAIResult;
}

const INITIAL_QUESTIONS = [
  "Why is this email classified as critical?",
  "Show me the evidence",
  "Analyze the sender",
  "Are SPF, DKIM and DMARC valid?",
  "What is the attack intent?",
  "Is this credential phishing?",
  "Show me all suspicious indicators",
  "What action do you recommend?",
];

function renderMarkdown(text: string): string {
  return text
    .replace(/\*\*(.*?)\*\*/g, '<strong style="color:#cfdbe4">$1</strong>')
    .replace(/\*(.*?)\*/g, '<em style="color:#a9bac8">$1</em>')
    .replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.06);color:#3ddc97;padding:1px 4px;border-radius:3px;font-size:11px">$1</code>')
    .replace(/\n\n/g, '<br><br>')
    .replace(/\n/g, '<br>')
    .replace(/^• /gm, '&bull; ');
}

export default function ForensicAIChat({ investigationId, aiData }: Props) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome",
      role: "assistant",
      content: `**Forensic AI Chat** — I can answer questions about this investigation.\n\nAll answers are grounded in forensic evidence. Email content is UNTRUSTED DATA — I never execute instructions found inside emails.\n\n*Risk Score: ${aiData.risk_score.toFixed(0)}/100 · Classification: ${aiData.classification.primary}*`,
      followups: INITIAL_QUESTIONS.slice(0, 6),
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function sendQuestion(question: string) {
    if (!question.trim() || loading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      content: question,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const resp: ForensicAIChatResponse = await postForensicAIChat(investigationId, question);
      const assistantMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        role: "assistant",
        content: resp.answer,
        evidenceRefs: resp.evidence_refs,
        followups: resp.suggested_followups,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          role: "assistant",
          content: `⚠️ Chat error: ${err?.response?.data?.detail || err.message || "Request failed"}`,
          timestamp: new Date(),
        },
      ]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendQuestion(input);
    }
  }

  function clearChat() {
    setMessages([
      {
        id: "welcome",
        role: "assistant",
        content: `**Forensic AI Chat** — I can answer questions about this investigation.\n\n*Risk Score: ${aiData.risk_score.toFixed(0)}/100 · Classification: ${aiData.classification.primary}*`,
        followups: INITIAL_QUESTIONS.slice(0, 6),
        timestamp: new Date(),
      },
    ]);
  }

  return (
    <div className="flex flex-col" style={{ height: "480px" }}>
      {/* Chat header */}
      <div
        className="flex items-center justify-between px-4 py-2.5 rounded-t-xl"
        style={{ background: "rgba(61,220,151,0.06)", borderBottom: "1px solid rgba(61,220,151,0.15)" }}
      >
        <div className="flex items-center gap-2">
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center"
            style={{ background: "rgba(61,220,151,0.15)", border: "1px solid rgba(61,220,151,0.3)" }}
          >
            <Bot size={14} style={{ color: "#3ddc97" }} />
          </div>
          <div>
            <div className="text-xs font-mono font-bold" style={{ color: "#3ddc97" }}>
              Forensic AI · Evidence-Grounded
            </div>
            <div className="text-[10px]" style={{ color: "#4a5a6b" }}>
              All answers cite investigation data · Prompt injection blocked
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 text-[10px] font-mono" style={{ color: "#4a5a6b" }}>
            <Shield size={10} style={{ color: "#3ddc97" }} />
            SAFE MODE
          </div>
          <button
            onClick={clearChat}
            className="flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded transition-opacity hover:opacity-80"
            style={{ color: "#4a5a6b", border: "1px solid #232d38", background: "#19212a" }}
          >
            <RotateCcw size={10} /> Clear
          </button>
        </div>
      </div>

      {/* Messages */}
      <div
        className="flex-1 overflow-y-auto px-4 py-3 space-y-3"
        style={{ background: "#10151a" }}
      >
        {messages.map((msg) => (
          <div key={msg.id} className={`flex gap-2.5 ${msg.role === "user" ? "flex-row-reverse" : ""}`}>
            {/* Avatar */}
            <div
              className="w-7 h-7 rounded-full flex items-center justify-center shrink-0 mt-1"
              style={{
                background: msg.role === "assistant" ? "rgba(61,220,151,0.15)" : "rgba(139,92,246,0.15)",
                border: `1px solid ${msg.role === "assistant" ? "rgba(61,220,151,0.3)" : "rgba(139,92,246,0.3)"}`,
              }}
            >
              {msg.role === "assistant" ? (
                <Bot size={12} style={{ color: "#3ddc97" }} />
              ) : (
                <User size={12} style={{ color: "#a78bfa" }} />
              )}
            </div>

            {/* Bubble */}
            <div className={`max-w-[80%] ${msg.role === "user" ? "items-end" : "items-start"} flex flex-col`}>
              <div
                className="rounded-xl px-4 py-2.5 text-sm"
                style={{
                  background: msg.role === "assistant" ? "#19212a" : "rgba(139,92,246,0.15)",
                  border: `1px solid ${msg.role === "assistant" ? "#232d38" : "rgba(139,92,246,0.3)"}`,
                  color: "#a9bac8",
                  lineHeight: "1.6",
                }}
                dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }}
              />

              {/* Evidence refs */}
              {msg.evidenceRefs && msg.evidenceRefs.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {msg.evidenceRefs.slice(0, 4).map((ref, i) => (
                    <span
                      key={i}
                      className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                      style={{ background: "rgba(61,220,151,0.08)", color: "#3ddc97", border: "1px solid rgba(61,220,151,0.18)" }}
                    >
                      📎 {ref.length > 40 ? ref.substring(0, 37) + "…" : ref}
                    </span>
                  ))}
                </div>
              )}

              {/* Follow-up chips */}
              {msg.followups && msg.followups.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {msg.followups.slice(0, 4).map((q) => (
                    <button
                      key={q}
                      onClick={() => sendQuestion(q)}
                      disabled={loading}
                      className="text-[11px] font-mono px-2 py-1 rounded-full transition-all hover:brightness-110 disabled:opacity-40"
                      style={{
                        background: "rgba(61,220,151,0.08)",
                        color: "#3ddc97",
                        border: "1px solid rgba(61,220,151,0.2)",
                      }}
                    >
                      {q}
                    </button>
                  ))}
                </div>
              )}

              <span className="text-[10px] mt-1 opacity-40" style={{ color: "#7c8fa0" }}>
                {msg.timestamp.toLocaleTimeString()}
              </span>
            </div>
          </div>
        ))}

        {/* Loading indicator */}
        {loading && (
          <div className="flex gap-2.5">
            <div
              className="w-7 h-7 rounded-full flex items-center justify-center"
              style={{ background: "rgba(61,220,151,0.15)", border: "1px solid rgba(61,220,151,0.3)" }}
            >
              <Bot size={12} style={{ color: "#3ddc97" }} />
            </div>
            <div
              className="rounded-xl px-4 py-3 flex items-center gap-2"
              style={{ background: "#19212a", border: "1px solid #232d38" }}
            >
              <Loader2 size={13} style={{ color: "#3ddc97" }} className="animate-spin" />
              <span className="text-xs" style={{ color: "#4a5a6b" }}>Analyzing evidence…</span>
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Quick question chips */}
      <div
        className="px-3 py-2 overflow-x-auto flex gap-1.5 flex-nowrap"
        style={{ background: "#10151a", borderTop: "1px solid #232d38" }}
      >
        {INITIAL_QUESTIONS.map((q) => (
          <button
            key={q}
            onClick={() => sendQuestion(q)}
            disabled={loading}
            className="text-[10px] font-mono px-2.5 py-1.5 rounded-full whitespace-nowrap transition-all hover:brightness-110 disabled:opacity-40 shrink-0"
            style={{
              background: "rgba(139,92,246,0.08)",
              color: "#c4b5fd",
              border: "1px solid rgba(139,92,246,0.2)",
            }}
          >
            {q}
          </button>
        ))}
      </div>

      {/* Input bar */}
      <div
        className="flex items-center gap-2 px-3 py-2.5 rounded-b-xl"
        style={{ background: "#19212a", borderTop: "1px solid #232d38" }}
      >
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask about this investigation… (e.g. 'Why is this critical?')"
          disabled={loading}
          className="flex-1 bg-transparent text-sm outline-none placeholder:text-[#4a5a6b] disabled:opacity-50"
          style={{ color: "#cfdbe4" }}
        />
        <button
          onClick={() => sendQuestion(input)}
          disabled={!input.trim() || loading}
          className="w-8 h-8 rounded-lg flex items-center justify-center transition-all hover:brightness-125 disabled:opacity-30"
          style={{ background: "rgba(61,220,151,0.18)", border: "1px solid rgba(61,220,151,0.3)" }}
        >
          <Send size={13} style={{ color: "#3ddc97" }} />
        </button>
      </div>
    </div>
  );
}

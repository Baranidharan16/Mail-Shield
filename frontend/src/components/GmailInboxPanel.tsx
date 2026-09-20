import React, { useState, useEffect } from "react";
import {
  Mail,
  ShieldCheck,
  Search,
  RefreshCw,
  Lock,
  Zap,
  LogOut,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import {
  getGmailStatus,
  getGmailAuthUrl,
  getGmailMessages,
  analyzeGmailMessage,
  quarantineGmailMessage,
  releaseGmailMessage,
  disconnectGmail,
  type GmailMessageItem,
  type GmailStatusResponse,
} from "../api/client";
import type { MailShieldAnalysisResponse } from "../types/investigation";

import { QuarantineConfirmModal } from "./QuarantineConfirmModal";

interface GmailInboxPanelProps {
  onAnalyzeSuccess: (res: MailShieldAnalysisResponse, investigationId: string) => void;
  onAnalysisStart: () => void;
  onError: (err: string) => void;
}

export const GmailInboxPanel: React.FC<GmailInboxPanelProps> = ({
  onAnalyzeSuccess,
  onAnalysisStart,
  onError,
}) => {
  const [status, setStatus] = useState<GmailStatusResponse | null>(null);
  const [messages, setMessages] = useState<GmailMessageItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [quarantiningId, setQuarantiningId] = useState<string | null>(null);
  const [confirmMsg, setConfirmMsg] = useState<GmailMessageItem | null>(null);
  const [actionFeedback, setActionFeedback] = useState<{ id: string; type: "success" | "error"; message: string } | null>(null);

  const fetchStatusAndMessages = async () => {
    setLoading(true);
    try {
      const st = await getGmailStatus();
      setStatus(st);
      if (st.connected) {
        const msgs = await getGmailMessages();
        setMessages(msgs);
      }
    } catch (err: any) {
      console.warn("Gmail status lookup note:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatusAndMessages();
  }, []);

  const handleConnectOAuth = async () => {
    try {
      const { authorization_url } = await getGmailAuthUrl();
      if (authorization_url) {
        window.location.href = authorization_url;
      }
    } catch (err: any) {
      onError("Could not start Google sign-in. Please try again (if Google shows 'access blocked', ask the admin to add your Gmail as a test user).");
    }
  };


  const handleDisconnect = async () => {
    setLoading(true);
    try {
      await disconnectGmail();
      setStatus(null);
      setMessages([]);
    } catch (err: any) {
      onError("Failed to disconnect Gmail.");
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const msgs = await getGmailMessages(searchQuery);
      setMessages(msgs);
    } catch (err: any) {
      onError("Failed to search Gmail messages.");
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyze = async (msg: GmailMessageItem) => {
    setAnalyzingId(msg.id);
    onAnalysisStart();
    try {
      const res = await analyzeGmailMessage(msg.id);
      onAnalyzeSuccess(res.analysis, res.investigation_id);
    } catch (err: any) {
      onError(err?.response?.data?.detail || "Failed to analyze raw email from Gmail.");
    } finally {
      setAnalyzingId(null);
    }
  };

  const handleToggleQuarantine = async (msg: GmailMessageItem) => {
    if (msg.is_quarantined) {
      setQuarantiningId(msg.id);
      try {
        await releaseGmailMessage(msg.id);
        setMessages((prev) =>
          prev.map((m) => (m.id === msg.id ? { ...m, is_quarantined: false } : m))
        );
        setActionFeedback({
          id: msg.id,
          type: "success",
          message: "Email released back to INBOX.",
        });
        const st = await getGmailStatus();
        setStatus(st);
      } catch (err: any) {
        onError(err?.response?.data?.detail || "Failed to release email to INBOX.");
      } finally {
        setQuarantiningId(null);
      }
    } else {
      // Trigger confirmation modal asking for permission (Keep vs Move)
      setConfirmMsg(msg);
    }
  };

  const handleConfirmQuarantine = async () => {
    if (!confirmMsg) return;
    const targetMsg = confirmMsg;
    setQuarantiningId(targetMsg.id);
    setActionFeedback(null);
    try {
      const res = await quarantineGmailMessage(targetMsg.id);
      setMessages((prev) =>
        prev.map((m) => (m.id === targetMsg.id ? { ...m, is_quarantined: true } : m))
      );
      setActionFeedback({
        id: targetMsg.id,
        type: "success",
        message: res.action || "QUARANTINED",
      });
      const st = await getGmailStatus();
      setStatus(st);
      setConfirmMsg(null);
    } catch (err: any) {
      const detail = err?.response?.data?.detail || "Gmail API quarantine failed.";
      setActionFeedback({
        id: targetMsg.id,
        type: "error",
        message: `QUARANTINE FAILED: ${detail}`,
      });
      onError(`Quarantine failed: ${detail}`);
      setConfirmMsg(null);
    } finally {
      setQuarantiningId(null);
    }
  };

  if (!status?.connected) {
    return (
      <div className="glass-section rounded-2xl p-8 text-center border-white/10 space-y-6">
        <div className="w-16 h-16 mx-auto rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center">
          <Mail className="h-8 w-8 text-red-400" strokeWidth={1.5} />
        </div>

        <div className="max-w-md mx-auto">
          <h3 className="text-base font-bold text-white mb-2">Connect Gmail for Live Forensics</h3>
          <p className="text-xs text-lab-400 leading-relaxed">
            Sign in with Google to let MailShield read your inbox. New mail is analysed automatically
            (ML + NLP + header forensics) and every result is hash-anchored for integrity. Your mailbox is
            only changed if you click Quarantine.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 max-w-sm mx-auto">
          <button
            onClick={handleConnectOAuth}
            className="w-full sm:w-auto btn-glass-primary flex items-center justify-center gap-2 py-2.5 px-4 text-xs font-semibold"
          >
            <Mail className="h-4 w-4" />
            Connect Google OAuth
          </button>
        </div>

        <div className="p-3 bg-black/30 rounded-xl border border-white/5 max-w-md mx-auto text-left text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-1.5 text-slate-300 font-semibold mb-1">
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
            MailShield Zero-Password OAuth Protocol
          </div>
          <div>• Scopes: read messages (analysis); modify labels only when you quarantine</div>
          <div>• Password never stored or requested</div>
          <div>• Direct RFC822 byte acquisition for SHA-256 hashing</div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Connected Account Header */}
      <div className="glass-section p-4 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-white/10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <Mail className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-white">{status.email}</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                LIVE GMAIL CONNECTED
              </span>
            </div>
            <div className="text-[11px] text-lab-400 font-mono mt-0.5">
              {messages.length} messages loaded · {status.quarantined_count} quarantined
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            onClick={fetchStatusAndMessages}
            disabled={loading}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs flex items-center gap-1.5 transition-all"
            title="Refresh Inbox"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={handleDisconnect}
            className="p-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-300 text-xs flex items-center gap-1.5 border border-red-500/20 transition-all"
          >
            <LogOut className="h-3.5 w-3.5" />
            Disconnect
          </button>
        </div>
      </div>

      {/* Inbox Search Form */}
      <form onSubmit={handleSearch} className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search Gmail messages (e.g. from:ceo, subject:invoice)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-black/30 border border-white/10 text-white text-xs font-mono focus:outline-none focus:border-phosphor-500/50"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="btn-glass-primary px-4 text-xs font-semibold flex items-center gap-1.5"
        >
          {loading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : "Search"}
        </button>
      </form>

      {actionFeedback && (
        <div
          className={`p-3 rounded-xl border flex items-center justify-between text-xs font-mono animate-fade-in ${
            actionFeedback.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
              : "bg-red-500/10 border-red-500/30 text-red-300"
          }`}
        >
          <div className="flex items-center gap-2">
            {actionFeedback.type === "success" ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
            )}
            <span>{actionFeedback.message}</span>
          </div>
          <button
            onClick={() => setActionFeedback(null)}
            className="text-slate-400 hover:text-white p-1 cursor-pointer"
          >
            ×
          </button>
        </div>
      )}

      {/* Messages List */}
      <div className="glass-section rounded-2xl border-white/10 overflow-hidden divide-y divide-white/5">
        {messages.length === 0 ? (
          <div className="p-8 text-center text-xs text-lab-400">
            No messages found matching search criteria.
          </div>
        ) : (
          messages.map((msg) => {
            const isAnalyzing = analyzingId === msg.id;
            const isQuarantining = quarantiningId === msg.id;

            return (
              <div
                key={msg.id}
                className={`p-4 hover:bg-white/[0.02] transition-colors flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                  msg.is_quarantined ? "bg-red-500/5 border-l-2 border-red-500" : ""
                }`}
              >
                {/* Email Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-xs font-semibold text-white truncate max-w-sm">
                      {msg.sender}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">
                      {msg.date}
                    </span>
                    {msg.threat_preview && (
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold uppercase tracking-wider ${
                          msg.threat_preview === "CRITICAL"
                            ? "bg-red-500/20 text-red-400 border border-red-500/40"
                            : msg.threat_preview === "HIGH"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                            : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                        }`}
                      >
                        {msg.threat_preview}
                      </span>
                    )}
                    {msg.is_quarantined && (
                      <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/40 font-bold flex items-center gap-1">
                        <Lock className="h-2.5 w-2.5" /> QUARANTINED BY MAILSHIELD
                      </span>
                    )}
                  </div>

                  <div className="text-xs text-slate-200 font-medium truncate mb-1">
                    {msg.subject}
                  </div>
                  <div className="text-[11px] text-slate-400 line-clamp-1">
                    {msg.snippet}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0 pt-2 md:pt-0">
                  <button
                    onClick={() => handleAnalyze(msg)}
                    disabled={isAnalyzing}
                    className="btn-glass-secondary py-1.5 px-3 text-xs flex items-center gap-1.5 disabled:opacity-50"
                  >
                    {isAnalyzing ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Zap className="h-3.5 w-3.5 text-phosphor-400" />
                    )}
                    {isAnalyzing ? "Acquiring..." : "Analyze with MailShield"}
                  </button>

                  <button
                    onClick={() => handleToggleQuarantine(msg)}
                    disabled={isQuarantining}
                    className={`py-1.5 px-2.5 rounded-lg text-xs font-mono flex items-center gap-1 border transition-all cursor-pointer ${
                      msg.is_quarantined
                        ? "bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border-emerald-500/30 font-semibold"
                        : "bg-red-500/10 hover:bg-red-500/20 text-red-300 border-red-500/30 font-semibold"
                    }`}
                  >
                    {isQuarantining ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" /> Quarantining...
                      </>
                    ) : msg.is_quarantined ? (
                      <>
                        <Lock className="h-3.5 w-3.5 text-emerald-400" /> QUARANTINED
                      </>
                    ) : (
                      <>
                        <Lock className="h-3.5 w-3.5" /> Quarantine
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Confirmation Modal for Permission to Keep or Move */}
      <QuarantineConfirmModal
        isOpen={!!confirmMsg}
        onClose={() => setConfirmMsg(null)}
        onConfirm={handleConfirmQuarantine}
        loading={quarantiningId === confirmMsg?.id}
        subject={confirmMsg?.subject}
        sender={confirmMsg?.sender}
        accountEmail={status?.email}
      />
    </div>
  );
};
export default GmailInboxPanel;

import React from "react";
import { ShieldAlert, Lock, X, RefreshCw, CheckCircle2, ArrowRight } from "lucide-react";

interface QuarantineConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  loading?: boolean;
  subject?: string;
  sender?: string;
  accountEmail?: string;
  destination?: "quarantine" | "spam";
}

export const QuarantineConfirmModal: React.FC<QuarantineConfirmModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  loading = false,
  subject,
  sender,
  accountEmail,
  destination,
}) => {
  if (!isOpen) return null;

  const isBoopathy =
    (accountEmail && accountEmail.toLowerCase().includes("baranidharanboopathy66")) ||
    destination === "quarantine";

  const targetLabelName = isBoopathy ? "Quarantine" : "Spam";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div
        className="relative w-full max-w-md rounded-2xl border border-red-500/30 bg-[#fefdfc]/95 p-6 shadow-2xl shadow-red-950/40 text-left"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          disabled={loading}
          className="absolute top-4 right-4 p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-50"
          title="Close"
        >
          <X className="h-4 w-4" />
        </button>

        {/* Header Icon + Title */}
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/40 flex items-center justify-center text-red-400 shrink-0">
            <Lock className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-tight">
              Confirm Email Isolation
            </h3>
            <div className="text-[11px] font-mono text-red-400/90 flex items-center gap-1 mt-0.5">
              <ShieldAlert className="h-3 w-3" />
              Gmail API Quarantine Action
            </div>
          </div>
        </div>

        {/* Email Context Summary */}
        {(subject || sender) && (
          <div className="mb-4 p-3 rounded-xl bg-black/40 border border-white/5 space-y-1 text-xs font-mono">
            {sender && (
              <div className="truncate text-slate-300">
                <span className="text-slate-500">From: </span>
                {sender}
              </div>
            )}
            {subject && (
              <div className="truncate text-slate-200 font-medium">
                <span className="text-slate-500">Subject: </span>
                {subject}
              </div>
            )}
          </div>
        )}

        {/* Body Explanation */}
        <div className="space-y-2.5 text-xs text-slate-300 leading-relaxed mb-6">
          <p>
            Do you want to isolate this email from your Gmail account?
          </p>

          <div className="p-3 rounded-xl bg-red-500/5 border border-red-500/20 text-[11px] text-slate-300 space-y-1.5">
            <div className="flex items-start gap-2">
              <ArrowRight className="h-3.5 w-3.5 text-red-400 shrink-0 mt-0.5" />
              <span>
                <strong>Remove from INBOX:</strong> The email will no longer appear in your primary Gmail inbox.
              </span>
            </div>
            <div className="flex items-start gap-2">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
              <span>
                <strong>Move to {targetLabelName}:</strong> The email will be tagged with the user label{" "}
                <span className="font-mono text-white font-semibold">"{targetLabelName}"</span> in Gmail.
              </span>
            </div>
            <div className="flex items-start gap-2">
              <Lock className="h-3.5 w-3.5 text-phosphor-400 shrink-0 mt-0.5" />
              <span>
                <strong>Evidence Preserved:</strong> The email is <em>never permanently deleted</em>, and the forensic dossier remains stored in MailShield.
              </span>
            </div>
          </div>
        </div>

        {/* Choice Prompt: KEEP vs MOVE */}
        <div className="flex items-center justify-end gap-3 pt-3 border-t border-white/10">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="px-4 py-2 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-slate-200 text-xs font-semibold transition-all disabled:opacity-50 cursor-pointer"
          >
            Keep in Inbox
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={loading}
            className="px-4 py-2 rounded-xl border border-red-500/40 bg-red-600/80 hover:bg-red-600 text-snow text-xs font-semibold flex items-center gap-1.5 shadow-lg shadow-red-950/50 transition-all disabled:opacity-60 cursor-pointer"
          >
            {loading ? (
              <>
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                Quarantining...
              </>
            ) : (
              <>
                <Lock className="h-3.5 w-3.5" />
                Move to {targetLabelName}
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default QuarantineConfirmModal;

import React, { useState } from "react";
import {
  ShieldAlert,
  KeyRound,
  DownloadCloud,
  CreditCard,
  CheckSquare,
  Square,
  AlertOctagon,
  Lock,
  Radio,
  CheckCircle2,
} from "lucide-react";
import { postThreatAction } from "../api/client";

interface SecurityDecisionTreeProps {
  investigationId: string;
  caseId?: string;
  threatClass?: string;
  className?: string;
}

export const SecurityDecisionTree: React.FC<SecurityDecisionTreeProps> = ({
  investigationId,
  caseId,
  threatClass = "THREAT",
  className = "",
}) => {
  const [clickedLink, setClickedLink] = useState(false);
  const [enteredCreds, setEnteredCreds] = useState(false);
  const [openedAttachment, setOpenedAttachment] = useState(false);
  const [authorizedPayment, setAuthorizedPayment] = useState(false);

  const [executingAction, setExecutingAction] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const handleAction = async (actionType: "QUARANTINE_MESSAGE" | "REVOKE_TOKEN" | "ISOLATE_MAILBOX" | "PUSH_FIREWALL_BLOCK") => {
    try {
      setExecutingAction(actionType);
      const res = await postThreatAction(investigationId, actionType);
      setActionSuccess(`Action ${res.action} successfully registered in SOC Audit Log (${res.action_id}).`);
      setTimeout(() => setActionSuccess(null), 5000);
    } catch (err: any) {
      alert("Failed to execute containment action: " + (err?.response?.data?.detail || err.message));
    } finally {
      setExecutingAction(null);
    }
  };

  const getUrgencyLevel = () => {
    if (authorizedPayment || enteredCreds) return { label: "CRITICAL SEVERITY INCIDENT", color: "text-red-400", bg: "bg-red-500/10 border-red-500/30" };
    if (openedAttachment || clickedLink) return { label: "HIGH SUSPICION EVENT", color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/30" };
    return { label: "SUSPECTED PHISHING PRE-CLICK", color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/30" };
  };

  const urgency = getUrgencyLevel();

  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/80 p-5 backdrop-blur-md shadow-xl ${className}`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              Security Incident Response Decision Tree
              <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 font-mono">
                SOC Playbook
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Interactive victim exposure triage & containment for {caseId || "investigation"} ({threatClass})
            </p>
          </div>
        </div>

        <div className={`px-3 py-1 rounded-md text-xs font-mono font-semibold border ${urgency.bg} ${urgency.color}`}>
          {urgency.label}
        </div>
      </div>

      {actionSuccess && (
        <div className="my-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          {actionSuccess}
        </div>
      )}

      {/* Interactive Questionnaire */}
      <div className="my-4">
        <span className="text-xs font-semibold text-slate-300 block mb-2 font-mono uppercase tracking-wider">
          Step 1: Check all victim exposure vectors that occurred:
        </span>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          <div
            onClick={() => setClickedLink(!clickedLink)}
            className={`p-3 rounded-lg border text-xs cursor-pointer flex items-center gap-3 transition-colors ${
              clickedLink ? "bg-amber-500/10 border-amber-500/40 text-white" : "bg-slate-950/50 border-slate-800 text-slate-400 hover:bg-slate-800/40"
            }`}
          >
            {clickedLink ? <CheckSquare className="h-4 w-4 text-amber-400 shrink-0" /> : <Square className="h-4 w-4 shrink-0" />}
            <div>
              <div className="font-medium text-slate-200">1. Clicked link in message</div>
              <div className="text-[11px] text-slate-500">Browser opened the destination URL</div>
            </div>
          </div>

          <div
            onClick={() => setEnteredCreds(!enteredCreds)}
            className={`p-3 rounded-lg border text-xs cursor-pointer flex items-center gap-3 transition-colors ${
              enteredCreds ? "bg-red-500/10 border-red-500/40 text-white" : "bg-slate-950/50 border-slate-800 text-slate-400 hover:bg-slate-800/40"
            }`}
          >
            {enteredCreds ? <CheckSquare className="h-4 w-4 text-red-400 shrink-0" /> : <Square className="h-4 w-4 shrink-0" />}
            <div>
              <div className="font-medium text-slate-200">2. Entered password, OTP, or PIN</div>
              <div className="text-[11px] text-slate-500">Credentials submitted to the phishing page</div>
            </div>
          </div>

          <div
            onClick={() => setOpenedAttachment(!openedAttachment)}
            className={`p-3 rounded-lg border text-xs cursor-pointer flex items-center gap-3 transition-colors ${
              openedAttachment ? "bg-amber-500/10 border-amber-500/40 text-white" : "bg-slate-950/50 border-slate-800 text-slate-400 hover:bg-slate-800/40"
            }`}
          >
            {openedAttachment ? <CheckSquare className="h-4 w-4 text-amber-400 shrink-0" /> : <Square className="h-4 w-4 shrink-0" />}
            <div>
              <div className="font-medium text-slate-200">3. Downloaded/Opened attachment</div>
              <div className="text-[11px] text-slate-500">File executed or macros enabled</div>
            </div>
          </div>

          <div
            onClick={() => setAuthorizedPayment(!authorizedPayment)}
            className={`p-3 rounded-lg border text-xs cursor-pointer flex items-center gap-3 transition-colors ${
              authorizedPayment ? "bg-red-500/10 border-red-500/40 text-white" : "bg-slate-950/50 border-slate-800 text-slate-400 hover:bg-slate-800/40"
            }`}
          >
            {authorizedPayment ? <CheckSquare className="h-4 w-4 text-red-400 shrink-0" /> : <Square className="h-4 w-4 shrink-0" />}
            <div>
              <div className="font-medium text-slate-200">4. Updated bank account / sent money</div>
              <div className="text-[11px] text-slate-500">Wire transfer or payroll diversion</div>
            </div>
          </div>
        </div>
      </div>

      {/* Dynamic Prioritized Action Plan */}
      <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 my-4">
        <span className="text-xs font-semibold text-slate-300 block mb-2 font-mono uppercase tracking-wider">
          Step 2: Prioritized Containment Playbook
        </span>

        <ul className="space-y-2 text-xs">
          {enteredCreds && (
            <li className="p-2 rounded bg-red-500/10 border border-red-500/20 text-red-300 flex items-start gap-2">
              <KeyRound className="h-4 w-4 shrink-0 mt-0.5 text-red-400" />
              <div>
                <strong>Immediate Credential Revocation:</strong> Invalidate all active OAuth / SSO tokens for this user account. Force enterprise password reset across Active Directory / IdP.
              </div>
            </li>
          )}

          {authorizedPayment && (
            <li className="p-2 rounded bg-red-500/10 border border-red-500/20 text-red-300 flex items-start gap-2">
              <CreditCard className="h-4 w-4 shrink-0 mt-0.5 text-red-400" />
              <div>
                <strong>Emergency Financial Freeze:</strong> Notify finance department and beneficiary bank immediately. Request wire recall under SWIFT MT192 / RBI cyber fraud protocol.
              </div>
            </li>
          )}

          {openedAttachment && (
            <li className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300 flex items-start gap-2">
              <DownloadCloud className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
              <div>
                <strong>Endpoint Isolation:</strong> Isolate user machine from corporate LAN. Run deep EDR forensic memory dump and rootkit detection for scheduled task persistence.
              </div>
            </li>
          )}

          {clickedLink && !enteredCreds && (
            <li className="p-2 rounded bg-blue-500/10 border border-blue-500/20 text-blue-300 flex items-start gap-2">
              <Lock className="h-4 w-4 shrink-0 mt-0.5 text-blue-400" />
              <div>
                <strong>Web Gateway Telemetry:</strong> Check proxy/DNS logs for outgoing HTTP POST traffic to determine if any payload or cookie session tokens were exfiltrated.
              </div>
            </li>
          )}

          <li className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-300 flex items-start gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5 text-emerald-400" />
            <div>
              <strong>Tenant-Wide Message Purge:</strong> Search mailboxes across the organization for identical Subject / Sender / IOC patterns and quash unread copies.
            </div>
          </li>
        </ul>
      </div>

      {/* Step 3: SOC Containment One-Click Buttons */}
      <div className="pt-3 border-t border-slate-800/80">
        <span className="text-xs font-semibold text-slate-300 block mb-2 font-mono uppercase tracking-wider">
          Step 3: Execute Direct Containment Actions:
        </span>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => handleAction("QUARANTINE_MESSAGE")}
            disabled={!!executingAction}
            className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-snow text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <AlertOctagon className="h-3.5 w-3.5" />
            {executingAction === "QUARANTINE_MESSAGE" ? "Quarantining..." : "Quarantine Message"}
          </button>

          <button
            onClick={() => handleAction("REVOKE_TOKEN")}
            disabled={!!executingAction}
            className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-snow text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <KeyRound className="h-3.5 w-3.5" />
            {executingAction === "REVOKE_TOKEN" ? "Revoking..." : "Revoke User Session"}
          </button>

          <button
            onClick={() => handleAction("PUSH_FIREWALL_BLOCK")}
            disabled={!!executingAction}
            className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-snow text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Lock className="h-3.5 w-3.5" />
            {executingAction === "PUSH_FIREWALL_BLOCK" ? "Pushing..." : "Block Relay IP at Firewall"}
          </button>

          <button
            onClick={() => handleAction("ISOLATE_MAILBOX")}
            disabled={!!executingAction}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Radio className="h-3.5 w-3.5" />
            {executingAction === "ISOLATE_MAILBOX" ? "Isolating..." : "Isolate Mailbox"}
          </button>
        </div>
      </div>
    </div>
  );
};

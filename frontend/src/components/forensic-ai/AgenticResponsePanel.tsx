/**
 * AgenticResponsePanel — Displays recommended response actions with
 * human-approval workflow (APPROVE / REJECT buttons).
 * NO destructive action executes without explicit approval.
 */
import { useState } from "react";
import {
  ShieldAlert,
  CheckCircle,
  XCircle,
  Clock,
  Lock,
  Info,
  Zap,
  Mail,
  Ban,
  Search,
  Bell,
} from "lucide-react";
import type { ForensicAIResult } from "../../types/investigation";

interface Props {
  data: ForensicAIResult;
  investigationId: string;
}

interface AgentAction {
  id: string;
  action: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  requiresApproval: boolean;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXECUTED";
  destructive: boolean;
  icon: React.ReactNode;
}

const SEV_COLORS: Record<string, { text: string; bg: string; border: string }> = {
  CRITICAL: { text: "#ff6b5e", bg: "rgba(226,72,61,0.10)", border: "rgba(226,72,61,0.3)" },
  HIGH: { text: "#f97316", bg: "rgba(249,115,22,0.10)", border: "rgba(249,115,22,0.3)" },
  MEDIUM: { text: "#e8a23d", bg: "rgba(232,162,61,0.10)", border: "rgba(232,162,61,0.3)" },
  LOW: { text: "#3ddc97", bg: "rgba(61,220,151,0.08)", border: "rgba(61,220,151,0.25)" },
};

function buildActions(data: ForensicAIResult): AgentAction[] {
  const score = data.risk_score;
  const cls = data.classification.primary;
  const actions: AgentAction[] = [];

  if (score >= 50) {
    actions.push({
      id: "quarantine",
      action: "Quarantine Email",
      severity: score >= 75 ? "CRITICAL" : "HIGH",
      reason: `Risk score ${score.toFixed(0)}/100 — email meets quarantine threshold.`,
      requiresApproval: true,
      status: "PENDING",
      destructive: false,
      icon: <Mail size={14} />,
    });
  }

  if (data.iocs.some((i) => i.type === "URL" || i.type === "DOMAIN")) {
    actions.push({
      id: "block-urls",
      action: "Block Malicious URLs & Domains",
      severity: score >= 75 ? "HIGH" : "MEDIUM",
      reason: `${data.iocs.filter((i) => i.type === "URL" || i.type === "DOMAIN").length} suspicious URL(s)/domain(s) identified.`,
      requiresApproval: true,
      status: "PENDING",
      destructive: false,
      icon: <Ban size={14} />,
    });
  }

  if (score >= 60) {
    actions.push({
      id: "block-sender",
      action: "Block Sender Domain",
      severity: "HIGH",
      reason: `Authentication failures + ${cls} classification justify sender domain block.`,
      requiresApproval: true,
      status: "PENDING",
      destructive: false,
      icon: <Ban size={14} />,
    });
  }

  actions.push({
    id: "search-similar",
    action: "Search for Similar Emails",
    severity: "MEDIUM",
    reason: "Scan mailboxes for emails from same sender or with matching URLs/domains.",
    requiresApproval: false,
    status: "PENDING",
    destructive: false,
    icon: <Search size={14} />,
  });

  if (score >= 75) {
    actions.push({
      id: "escalate",
      action: "Escalate to SOC Tier 2",
      severity: "HIGH",
      reason: "Critical threat score requires senior analyst review.",
      requiresApproval: false,
      status: "PENDING",
      destructive: false,
      icon: <Bell size={14} />,
    });
  }

  if (
    cls === "Credential Phishing" ||
    cls === "Account Takeover" ||
    data.threat_intent.intent === "Credential Theft"
  ) {
    actions.push({
      id: "credential-reset",
      action: "Initiate Credential Reset for Affected User",
      severity: "HIGH",
      reason: "Credential phishing detected — force password reset to prevent account compromise.",
      requiresApproval: true,
      status: "PENDING",
      destructive: false,
      icon: <Lock size={14} />,
    });
  }

  actions.push({
    id: "preserve-evidence",
    action: "Preserve Forensic Evidence",
    severity: "MEDIUM",
    reason: "Lock case evidence for chain-of-custody compliance. Non-destructive.",
    requiresApproval: false,
    status: "PENDING",
    destructive: false,
    icon: <ShieldAlert size={14} />,
  });

  return actions;
}

export default function AgenticResponsePanel({ data }: Props) {
  const [actions, setActions] = useState<AgentAction[]>(() => buildActions(data));
  const [log, setLog] = useState<{ timestamp: string; action: string; result: string }[]>([]);

  function approve(id: string) {
    setActions((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: "APPROVED" } : a))
    );
    const action = actions.find((a) => a.id === id);
    if (action) {
      setLog((prev) => [
        ...prev,
        {
          timestamp: new Date().toLocaleTimeString(),
          action: action.action,
          result: "APPROVED — queued for execution",
        },
      ]);
    }
  }

  function reject(id: string) {
    setActions((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: "REJECTED" } : a))
    );
    const action = actions.find((a) => a.id === id);
    if (action) {
      setLog((prev) => [
        ...prev,
        {
          timestamp: new Date().toLocaleTimeString(),
          action: action.action,
          result: "REJECTED by analyst",
        },
      ]);
    }
  }

  const pending = actions.filter((a) => a.status === "PENDING" && a.requiresApproval);
  const auto = actions.filter((a) => !a.requiresApproval);
  const decided = actions.filter((a) => a.status !== "PENDING" && a.requiresApproval);

  return (
    <div className="space-y-4">
      {/* Safety notice */}
      <div
        className="flex items-start gap-2 px-3 py-2.5 rounded-lg text-xs"
        style={{ background: "rgba(232,162,61,0.06)", border: "1px solid rgba(232,162,61,0.18)" }}
      >
        <Info size={12} style={{ color: "#e8a23d", marginTop: "1px", flexShrink: 0 }} />
        <span style={{ color: "#7c8fa0" }}>
          <strong style={{ color: "#e8a23d" }}>Human-in-the-loop required.</strong> All destructive or
          significant actions require explicit analyst approval. No action executes automatically.
        </span>
      </div>

      {/* Pending approval */}
      {pending.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Clock size={12} style={{ color: "#e8a23d" }} />
            <span className="text-xs font-mono font-bold tracking-wider" style={{ color: "#e8a23d" }}>
              PENDING APPROVAL ({pending.length})
            </span>
          </div>
          <div className="space-y-2">
            {pending.map((action) => {
              const sev = SEV_COLORS[action.severity];
              return (
                <div
                  key={action.id}
                  className="rounded-xl p-4"
                  style={{ background: sev.bg, border: `1px solid ${sev.border}` }}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2.5">
                      <span style={{ color: sev.text, marginTop: "2px" }}>{action.icon}</span>
                      <div>
                        <div className="text-sm font-bold mb-1" style={{ color: sev.text }}>
                          {action.action}
                        </div>
                        <div className="text-xs mb-2" style={{ color: "#7c8fa0" }}>
                          {action.reason}
                        </div>
                        <div className="flex items-center gap-1.5 text-[10px] font-mono" style={{ color: "#4a5a6b" }}>
                          <Lock size={9} />
                          Requires human approval
                          <span
                            className="px-1.5 py-0.5 rounded"
                            style={{ background: sev.bg, color: sev.text, border: `1px solid ${sev.border}` }}
                          >
                            {action.severity}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex gap-2 shrink-0">
                      <button
                        onClick={() => approve(action.id)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all hover:brightness-110"
                        style={{ background: "rgba(61,220,151,0.15)", color: "#3ddc97", border: "1px solid rgba(61,220,151,0.3)" }}
                      >
                        <CheckCircle size={12} /> APPROVE
                      </button>
                      <button
                        onClick={() => reject(action.id)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all hover:brightness-110"
                        style={{ background: "rgba(226,72,61,0.12)", color: "#e2483d", border: "1px solid rgba(226,72,61,0.25)" }}
                      >
                        <XCircle size={12} /> REJECT
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Auto-executable actions */}
      {auto.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Zap size={12} style={{ color: "#3ddc97" }} />
            <span className="text-xs font-mono font-bold tracking-wider" style={{ color: "#4a5a6b" }}>
              AUTO-APPROVABLE ACTIONS ({auto.length})
            </span>
          </div>
          <div className="space-y-1.5">
            {auto.map((action) => {
              const sev = SEV_COLORS[action.severity];
              return (
                <div
                  key={action.id}
                  className="rounded-lg p-3 flex items-center gap-3"
                  style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #232d38" }}
                >
                  <span style={{ color: sev.text }}>{action.icon}</span>
                  <div className="flex-1">
                    <div className="text-xs font-semibold" style={{ color: "#cfdbe4" }}>
                      {action.action}
                    </div>
                    <div className="text-[11px]" style={{ color: "#4a5a6b" }}>
                      {action.reason}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded" style={{ background: "rgba(61,220,151,0.1)", color: "#3ddc97" }}>
                    NO APPROVAL NEEDED
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Decided actions */}
      {decided.length > 0 && (
        <div>
          <p className="text-[11px] font-mono tracking-wider mb-2" style={{ color: "#4a5a6b" }}>
            DECIDED ACTIONS
          </p>
          <div className="space-y-1.5">
            {decided.map((action) => (
              <div
                key={action.id}
                className="flex items-center gap-3 p-3 rounded-lg"
                style={{
                  background: action.status === "APPROVED" ? "rgba(61,220,151,0.06)" : "rgba(226,72,61,0.06)",
                  border: `1px solid ${action.status === "APPROVED" ? "rgba(61,220,151,0.2)" : "rgba(226,72,61,0.2)"}`,
                }}
              >
                {action.status === "APPROVED" ? (
                  <CheckCircle size={14} style={{ color: "#3ddc97" }} />
                ) : (
                  <XCircle size={14} style={{ color: "#e2483d" }} />
                )}
                <div className="flex-1">
                  <div className="text-xs font-semibold" style={{ color: "#cfdbe4" }}>
                    {action.action}
                  </div>
                </div>
                <span
                  className="text-[10px] font-mono font-bold px-2 py-0.5 rounded"
                  style={{ color: action.status === "APPROVED" ? "#3ddc97" : "#e2483d" }}
                >
                  {action.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Action log */}
      {log.length > 0 && (
        <div
          className="rounded-xl p-4"
          style={{ background: "#10151a", border: "1px solid #232d38" }}
        >
          <p className="text-[11px] font-mono tracking-wider mb-2" style={{ color: "#4a5a6b" }}>
            ACTION LOG
          </p>
          <div className="space-y-1.5">
            {log.map((entry, i) => (
              <div key={i} className="flex gap-3 text-xs">
                <span className="font-mono shrink-0" style={{ color: "#4a5a6b" }}>
                  {entry.timestamp}
                </span>
                <span style={{ color: "#7c8fa0" }}>{entry.action}</span>
                <span
                  className="font-mono ml-auto shrink-0"
                  style={{ color: entry.result.includes("APPROVED") ? "#3ddc97" : "#e2483d" }}
                >
                  {entry.result}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

import { useState } from "react";
import { PhoneCall, ShieldAlert, Lock, FileSearch, Share2, AlertCircle, CheckCircle2 } from "lucide-react";

interface Props {
  caseId: string;
  riskLevel: string;
  onScrollToSection?: (sectionId: string) => void;
}

export default function SOCHelpline({ caseId, riskLevel, onScrollToSection }: Props) {
  const [quarantined, setQuarantined] = useState(false);
  const [incidentCreated, setIncidentCreated] = useState(false);

  if (riskLevel !== "HIGH" && riskLevel !== "CRITICAL") {
    return null;
  }

  return (
    <div className="card-lab p-6 border-l-4 border-l-crimson-signal bg-lab-900 shadow-xl mb-6">
      <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-lab-700">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-full flex items-center justify-center bg-crimson-signal/20 border border-crimson-signal/40">
            <PhoneCall className="h-5 w-5 text-crimson-glow" strokeWidth={2} />
          </div>
          <div>
            <div className="font-bold text-base text-lab-100 flex items-center gap-2">
              🚨 SOC HELPLINE & INCIDENT ESCALATION
            </div>
            <div className="text-xs text-crimson-glow font-medium mt-0.5">
              Security incident detected for case <span className="font-data font-bold">{caseId}</span>.
            </div>
          </div>
        </div>

        <div className="px-3 py-1.5 rounded bg-lab-800 border border-lab-700 text-xs text-lab-300 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-orange-signal" />
          <span>SOC escalation required — Contact your organization's security team.</span>
        </div>
      </div>

      {/* Recommended immediate actions list */}
      <div className="my-5">
        <div className="text-xs font-semibold text-lab-200 evidence-tag mb-3">
          RECOMMENDED IMMEDIATE PROTOCOL:
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          {[
            { num: "1", title: "Quarantine the email", desc: "Isolate from the mail server to prevent recipient interaction." },
            { num: "2", title: "Do not click links or attachments", desc: "Payloads may deploy ransomware or credential harvesters." },
            { num: "3", title: "Preserve the original .eml", desc: "Ensure SHA-256 hash integrity for forensic admissibility." },
            { num: "4", title: "Investigate sender and source IP", desc: "Check relay hops and verify WHOIS/ASN infrastructure." },
            { num: "5", title: "Review related messages", desc: "Search across inboxes for identical campaign IOCs." },
            { num: "6", title: "Escalate to the security team", desc: "File incident report for tier-2 SOC containment." },
          ].map((item) => (
            <div key={item.num} className="flex items-start gap-2.5 p-2.5 rounded bg-lab-850 border border-lab-700/60">
              <span className="h-5 w-5 rounded-full bg-lab-700 flex items-center justify-center font-data font-bold text-phosphor-400 text-[11px] shrink-0">
                {item.num}
              </span>
              <div>
                <div className="font-semibold text-lab-200">{item.title}</div>
                <div className="text-lab-500 text-[11px] mt-0.5">{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Buttons */}
      <div className="flex flex-wrap items-center gap-3 pt-3 border-t border-lab-700/70">
        <button
          onClick={() => setQuarantined(!quarantined)}
          className={`px-4 py-2 rounded font-bold text-xs evidence-tag transition-all flex items-center gap-2 ${
            quarantined
              ? "bg-phosphor-500/20 text-phosphor-400 border border-phosphor-500/40"
              : "bg-crimson-signal text-lab-950 hover:bg-crimson-glow shadow-md"
          }`}
        >
          <Lock className="h-3.5 w-3.5" />
          {quarantined ? "✓ EMAIL QUARANTINED" : "QUARANTINE EMAIL"}
        </button>

        <button
          onClick={() => onScrollToSection && onScrollToSection("forensics-section")}
          className="px-4 py-2 rounded text-xs font-semibold text-lab-200 bg-lab-800 hover:bg-lab-700 border border-lab-600 transition-colors flex items-center gap-2"
        >
          <FileSearch className="h-3.5 w-3.5 text-phosphor-500" />
          VIEW FORENSICS
        </button>

        <button
          onClick={() => onScrollToSection && onScrollToSection("attack-graph-section")}
          className="px-4 py-2 rounded text-xs font-semibold text-lab-200 bg-lab-800 hover:bg-lab-700 border border-lab-600 transition-colors flex items-center gap-2"
        >
          <Share2 className="h-3.5 w-3.5 text-blue-signal" />
          VIEW ATTACK GRAPH
        </button>

        <button
          onClick={() => setIncidentCreated(true)}
          className={`px-4 py-2 rounded text-xs font-semibold border transition-colors flex items-center gap-2 ${
            incidentCreated
              ? "bg-purple-signal/20 text-purple-signal border-purple-signal/40"
              : "text-lab-300 border-lab-600 hover:bg-lab-800"
          }`}
        >
          {incidentCreated ? <CheckCircle2 className="h-3.5 w-3.5" /> : <AlertCircle className="h-3.5 w-3.5" />}
          {incidentCreated ? `INCIDENT #${caseId.replace("CASE-", "INC-")} CREATED` : "CREATE INCIDENT"}
        </button>
      </div>

      <div className="mt-3 text-[11px] text-lab-500 italic">
        Prototype environment notice: Emergency actions take effect within the MailShield local vault. Escalation notifies registered SOC tier-1 analysts.
      </div>
    </div>
  );
}

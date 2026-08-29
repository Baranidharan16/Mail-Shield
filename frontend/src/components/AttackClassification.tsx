import { Tag, TrendingUp, Cpu, ShieldAlert } from "lucide-react";
import type { FindingOut, RiskScoreOut } from "../types/investigation";

const ATTACK_TYPE_MAP: Record<string, { label: string; description: string; color: string }> = {
  PHISHING: {
    label: "Phishing Attack",
    description: "Fraudulent email designed to steal credentials or sensitive information by impersonating a trusted entity.",
    color: "#e2483d",
  },
  BUSINESS_EMAIL_COMPROMISE: {
    label: "Business Email Compromise (BEC)",
    description: "Targeted attack spoofing a CEO, vendor, or partner to manipulate an employee into fraud.",
    color: "#f97316",
  },
  MALWARE_DELIVERY: {
    label: "Malware Delivery",
    description: "Email carries or links to a payload designed to install malicious software on the recipient system.",
    color: "#8b5cf6",
  },
  SPEAR_PHISHING: {
    label: "Spear Phishing",
    description: "Targeted phishing campaign using personalized information to increase credibility and deception.",
    color: "#e2483d",
  },
  ADVANCE_FEE_FRAUD: {
    label: "Advance Fee Fraud / 419 Scam",
    description: "Fraudulent offer promising large rewards in exchange for upfront fees or personal information.",
    color: "#e8a23d",
  },
  SPAM: {
    label: "Unsolicited Bulk Email / Spam",
    description: "Mass-distributed email without targeted deception intent, often commercial or promotional.",
    color: "#3b82f6",
  },
  LOOKALIKE_DOMAIN: {
    label: "Lookalike Domain Attack",
    description: "Uses a domain visually similar to a legitimate brand to deceive recipients into trusting the sender.",
    color: "#f97316",
  },
  BENIGN: {
    label: "No Threat Detected",
    description: "Email analysis did not identify malicious indicators consistent with a threat classification.",
    color: "#3ddc97",
  },
};



function inferAttackType(findings: FindingOut[], rsb: RiskScoreOut | null): string {
  if (!findings.length) return "BENIGN";

  const cats = findings.map((f) => f.category.toUpperCase());
  const sevMap = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

  // Sort by severity
  const sorted = [...findings].sort(
    (a, b) => (sevMap[b.severity.toUpperCase() as keyof typeof sevMap] ?? 0) - (sevMap[a.severity.toUpperCase() as keyof typeof sevMap] ?? 0)
  );

  // Check for attachment findings → malware
  if (sorted.some((f) => f.category.toUpperCase() === "ATTACHMENT")) return "MALWARE_DELIVERY";
  // Domain lookalike?
  if (sorted.some((f) => f.category.toUpperCase() === "DOMAIN" && f.explanation.toLowerCase().includes("lookalike"))) return "LOOKALIKE_DOMAIN";
  // High score + social engineering → BEC
  if (rsb && rsb.overall_score > 75 && sorted.some((f) => f.category.toUpperCase() === "SOCIAL_ENGINEERING")) return "BUSINESS_EMAIL_COMPROMISE";
  // Authentication failure + high score → spear phishing
  if (rsb && rsb.overall_score > 65 && cats.includes("AUTHENTICATION")) return "SPEAR_PHISHING";
  // URL phishing
  if (cats.includes("URL")) return "PHISHING";
  // Default to phishing for high risk
  if (rsb && rsb.overall_score > 40) return "PHISHING";
  return "SPAM";
}

interface Props {
  findings: FindingOut[];
  rsb: RiskScoreOut | null;
  classification: string | null;
}

export default function AttackClassification({ findings, rsb, classification }: Props) {
  const attackType = inferAttackType(findings, rsb);
  const info = ATTACK_TYPE_MAP[attackType] ?? ATTACK_TYPE_MAP.SPAM;

  // Top findings for evidence
  const topFindings = [...findings]
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 4);

  // Confidence from risk score
  const confidence = rsb?.confidence ?? 0.5;
  const confidencePct = (confidence * 100).toFixed(0);

  return (
    <div className="space-y-4">
      {/* Primary classification */}
      <div
        className="p-4 rounded-md border"
        style={{ backgroundColor: `${info.color}10`, borderColor: `${info.color}30` }}
      >
        <div className="flex items-start gap-3">
          <div
            className="h-10 w-10 rounded-full flex items-center justify-center shrink-0"
            style={{ backgroundColor: `${info.color}20`, border: `1.5px solid ${info.color}40` }}
          >
            <ShieldAlert className="h-5 w-5" style={{ color: info.color }} strokeWidth={1.75} />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <span className="font-bold text-base" style={{ color: info.color }}>{info.label}</span>
              <span
                className="text-[10px] evidence-tag px-2 py-0.5 rounded"
                style={{ backgroundColor: `${info.color}20`, color: info.color }}
              >
                {attackType}
              </span>
            </div>
            <p className="text-xs text-lab-400 leading-relaxed">{info.description}</p>
          </div>
        </div>
      </div>

      {/* Confidence & Risk level */}
      <div className="grid grid-cols-2 gap-3">
        <div className="p-3 rounded-md bg-lab-800/50 border border-lab-700 text-center">
          <div className="flex items-center justify-center gap-1 mb-1">
            <Cpu className="h-3.5 w-3.5 text-phosphor-500" />
            <span className="text-[10px] text-lab-500 evidence-tag">ML CONFIDENCE</span>
          </div>
          <div className="font-data text-xl font-bold text-phosphor-400">{confidencePct}%</div>
        </div>
        <div className="p-3 rounded-md bg-lab-800/50 border border-lab-700 text-center">
          <div className="flex items-center justify-center gap-1 mb-1">
            <TrendingUp className="h-3.5 w-3.5 text-amber-signal" />
            <span className="text-[10px] text-lab-500 evidence-tag">RISK LEVEL</span>
          </div>
          <div
            className="font-data text-xl font-bold evidence-tag"
            style={{
              color:
                classification === "CRITICAL" ? "#ff6b5e" :
                classification === "HIGH" ? "#f97316" :
                classification === "MEDIUM" ? "#e8a23d" :
                "#3ddc97",
            }}
          >
            {classification ?? "—"}
          </div>
        </div>
      </div>

      {/* Supporting evidence */}
      {topFindings.length > 0 && (
        <div>
          <div className="text-[10px] text-lab-500 evidence-tag mb-2">CLASSIFICATION EVIDENCE</div>
          <div className="space-y-2">
            {topFindings.map((f, i) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <Tag className="h-3.5 w-3.5 text-lab-500 mt-0.5 shrink-0" />
                <div>
                  <span className="font-semibold text-lab-200">{f.title}</span>
                  <span className="text-lab-500 ml-2 font-data">({(f.confidence * 100).toFixed(0)}%)</span>
                  <div className="text-lab-500 text-[11px] mt-0.5">{f.explanation}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

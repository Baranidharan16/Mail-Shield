import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft, Mail, Link2, Globe2, Network, FileWarning, MessageSquareWarning,
  Download, ShieldAlert, Fingerprint, Clock, GitBranch,
  Lock, Layers, AlertTriangle, Shield, ListChecks, Users, MapPin,
  ChevronDown, ChevronRight, CheckCircle2, RefreshCw,
} from "lucide-react";
import {
  getInvestigation, getReport, getAttackGraph, getRecommendations,
  getChainOfCustody, getTimeline, getGeoIntelligence, getCampaign,
  getOriginTrace, quarantineInvestigation, type OriginTraceResult,
} from "../api/client";
import { QuarantineConfirmModal } from "../components/QuarantineConfirmModal";
import type {
  InvestigationDetail, AttackGraphData, Recommendation,
  ChainOfCustodyResponse, TimelineResponse, GeoResponse, CampaignResponse,
} from "../types/investigation";
import ThreatGauge from "../components/ThreatGauge";
import { ClassificationBadge } from "../components/Badges";
import RiskBreakdownPanel from "../components/RiskBreakdownPanel";
import AttackGraphPanel from "../components/AttackGraphPanel";
import InvestigationTimeline from "../components/InvestigationTimeline";
import ChainOfCustody from "../components/ChainOfCustody";
import BlockchainIntegrityPanel from "../components/BlockchainIntegrityPanel";
import RecommendedResponsePanel from "../components/RecommendedResponsePanel";
import SimilarCasesPanel from "../components/SimilarCasesPanel";
import ThreatIntelPanel from "../components/ThreatIntelPanel";
import AttackClassification from "../components/AttackClassification";
import AIDetectionAnalysis from "../components/AIDetectionAnalysis";
import SOCAlertPanel from "../components/SOCAlertPanel";
import SOCHelpline from "../components/SOCHelpline";
import ForensicEvidenceBreakdown from "../components/ForensicEvidenceBreakdown";
import { InteractiveGeoMap } from "../components/InteractiveGeoMap";
import { EarliestObservableNodePanel } from "../components/EarliestObservableNodePanel";
import { SecurityDecisionTree } from "../components/SecurityDecisionTree";


function Section({
  id, title, icon: Icon, children, badge, defaultOpen = true,
}: {
  id?: string; title: string; icon: any; children: React.ReactNode; badge?: React.ReactNode; defaultOpen?: boolean;
}) {
  const [collapsed, setCollapsed] = useState(!defaultOpen);
  return (
    <div id={id} className="glass-section scroll-mt-6">
      <button
        className="glass-section-header w-full flex items-center gap-2.5 text-left"
        onClick={() => setCollapsed(!collapsed)}
      >
        <Icon className="h-4 w-4 text-phosphor-500 shrink-0" strokeWidth={1.75} />
        <h2 className="font-semibold text-sm text-white flex-1">{title}</h2>
        {badge}
        {collapsed ? <ChevronRight className="h-4 w-4 text-lab-500" /> : <ChevronDown className="h-4 w-4 text-lab-500" />}
      </button>
      {!collapsed && <div className="p-5">{children}</div>}
    </div>
  );
}

function KV({ label, value, mono = true }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4 py-1.5 text-sm border-b border-lab-800 last:border-0">
      <span className="text-lab-500 shrink-0">{label}</span>
      <span className={`text-right text-lab-200 break-all ${mono ? "font-data" : ""}`}>{value ?? "—"}</span>
    </div>
  );
}

function AlignBadge({ aligned }: { aligned: boolean | null }) {
  if (aligned === null) return <span className="text-lab-600 text-xs font-data">unknown</span>;
  return aligned ? (
    <span className="text-phosphor-400 text-xs font-data font-semibold">ALIGNED</span>
  ) : (
    <span className="text-crimson-glow text-xs font-data font-semibold">MISALIGNED</span>
  );
}

function AuthBadge({ result }: { result: string | null }) {
  if (!result) return <span className="text-lab-600 text-xs font-data">—</span>;
  const upper = result.toUpperCase();
  const color = upper === "PASS" ? "text-phosphor-400" : upper === "FAIL" || upper === "SOFTFAIL" || upper === "PERMERROR" ? "text-crimson-glow" : "text-amber-signal";
  return <span className={`text-xs font-data font-bold ${color}`}>{upper}</span>;
}

export default function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState(true);

  // Lazy-loaded supplemental data
  const [graph, setGraph] = useState<AttackGraphData | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [custody, setCustody] = useState<ChainOfCustodyResponse | null>(null);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [geo, setGeo] = useState<GeoResponse | null>(null);
  const [campaign, setCampaign] = useState<CampaignResponse | null>(null);
  const [originTrace, setOriginTrace] = useState<OriginTraceResult | null>(null);

  // Quarantine action state
  const [isQuarantineModalOpen, setIsQuarantineModalOpen] = useState(false);
  const [quarantineState, setQuarantineState] = useState<"idle" | "loading" | "success" | "failed">("idle");
  const [quarantineFeedback, setQuarantineFeedback] = useState<{ type: "success" | "error"; text: string } | null>(null);

  async function handleConfirmQuarantine() {
    if (!id) return;
    setQuarantineState("loading");
    setQuarantineFeedback(null);
    try {
      const res = await quarantineInvestigation(id);
      setQuarantineState("success");
      setData((prev) => (prev ? { ...prev, case_status: "CONTAINED" } : null));
      setQuarantineFeedback({
        type: "success",
        text: `Email successfully quarantined to ${res.label_name || "Quarantine"} and removed from INBOX.`,
      });
      setIsQuarantineModalOpen(false);
    } catch (err: any) {
      setQuarantineState("failed");
      const detail = err?.response?.data?.detail || "Quarantine operation failed via Gmail API.";
      setQuarantineFeedback({
        type: "error",
        text: `QUARANTINE FAILED: ${detail}`,
      });
      setIsQuarantineModalOpen(false);
    }
  }

  function scrollToSection(sectionId: string) {
    const el = document.getElementById(sectionId);
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  }

  useEffect(() => {
    if (!id) return;
    getInvestigation(id).then(setData).finally(() => setLoading(false));
  }, [id]);

  // Load supplemental data once main data is ready
  useEffect(() => {
    if (!id || !data || data.status !== "COMPLETED") return;
    setGraphLoading(true);
    Promise.allSettled([
      getAttackGraph(id).then(setGraph),
      getRecommendations(id).then(setRecommendations),
      getChainOfCustody(id).then(setCustody),
      getTimeline(id).then(setTimeline),
      getGeoIntelligence(id).then(setGeo),
      getCampaign(id).then(setCampaign),
      getOriginTrace(id).then(setOriginTrace),
    ]).finally(() => setGraphLoading(false));
  }, [id, data?.status]);


  async function downloadReport() {
    if (!id) return;
    const report = await getReport(id);
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${data?.case_id ?? "report"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading) return <div className="p-8 text-lab-400 text-sm">Loading investigation…</div>;
  if (!data) return <div className="p-8 text-crimson-glow text-sm">Investigation not found.</div>;

  const rsb = data.risk_score_breakdown;
  const meta = data.email_metadata;
  const auth = data.authentication_result;

  const isHighOrCritical = data.classification === "HIGH" || data.classification === "CRITICAL";

  // Build list of key indicators for the SOC Alert Banner
  const keyIndicators: string[] = [];
  if (auth) {
    if (auth.spf_result && auth.spf_result !== "PASS") keyIndicators.push(`SPF authentication failed (${auth.spf_result})`);
    if (auth.dkim_result && auth.dkim_result !== "PASS") keyIndicators.push(`DKIM signature failed / unaligned (${auth.dkim_result})`);
    if (auth.dmarc_result && auth.dmarc_result !== "PASS") keyIndicators.push(`DMARC policy validation failed (${auth.dmarc_result})`);
    if (auth.from_reply_to_aligned === false) keyIndicators.push("Sender From and Reply-To domain mismatch (spoofing indicator)");
  }
  if (data.urls && data.urls.some((u) => u.risk_score && u.risk_score > 30)) {
    keyIndicators.push("Suspicious / deceptive URL link detected in message body");
  }
  if (data.domains && data.domains.some((d) => d.lookalike_of)) {
    keyIndicators.push("Lookalike domain impersonation identified");
  }
  data.indicators.forEach((ind) => {
    keyIndicators.push(`${ind.indicator_type.replace(/_/g, " ").toUpperCase()}: ${ind.explanation}`);
  });
  if (keyIndicators.length === 0) {
    keyIndicators.push("Elevated risk indicators observed across email headers and content.");
  }

  return (
    <div className="p-8 max-w-6xl">
      <Link to="/history" className="inline-flex items-center gap-1.5 text-xs text-lab-400 hover:text-lab-200 mb-4">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to case history
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl font-bold tracking-tight font-data">{data.case_id}</h1>
            {data.classification && (
              <ClassificationBadge level={data.classification} size="lg" />
            )}
          </div>
          <div className="text-lab-400 text-sm mt-2 font-data break-all">{data.original_filename}</div>
          <div className="flex gap-3 flex-wrap mt-2 text-xs text-lab-500">
            <span>{new Date(data.created_at).toLocaleString()}</span>
            {data.analyzed_at && (
              <>
                <span>·</span>
                <span>Analyzed: {new Date(data.analyzed_at).toLocaleString()}</span>
              </>
            )}
            <span>·</span>
            <span className={`font-semibold evidence-tag ${
              data.status === "COMPLETED" ? "text-phosphor-400" :
              data.status === "FAILED" ? "text-crimson-glow" :
              "text-amber-signal"
            }`}>{data.status}</span>
          </div>
        </div>
        <div className="flex items-center gap-2 mt-1 shrink-0">
          {(data.original_filename?.startsWith("gmail_") || (data.notes && data.notes.some((n: any) => n?.gmail_message_id))) && (
            (data.case_status === "CONTAINED" || quarantineState === "success") ? (
              <span className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-xs font-bold font-mono tracking-wider">
                <Lock className="h-3.5 w-3.5 text-emerald-400" /> QUARANTINED
              </span>
            ) : (
              <button
                onClick={() => setIsQuarantineModalOpen(true)}
                disabled={quarantineState === "loading"}
                className={`inline-flex items-center gap-2 text-xs font-mono font-bold px-3 py-2 rounded-md transition-all cursor-pointer ${
                  quarantineState === "failed"
                    ? "border border-red-500 bg-red-500/20 text-red-300 hover:bg-red-500/30"
                    : "border border-red-500/40 bg-red-600/20 hover:bg-red-600/30 text-red-300 shadow-sm shadow-red-950/40"
                }`}
              >
                {quarantineState === "loading" ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" /> QUARANTINING...
                  </>
                ) : quarantineState === "failed" ? (
                  <>
                    <AlertTriangle className="h-3.5 w-3.5" /> QUARANTINE FAILED (RETRY)
                  </>
                ) : (
                  <>
                    <Lock className="h-3.5 w-3.5 text-red-400" /> QUARANTINE
                  </>
                )}
              </button>
            )
          )}
          <button
            onClick={downloadReport}
            className="inline-flex items-center gap-2 border border-lab-700 text-lab-300 text-sm px-4 py-2 rounded-md hover:border-lab-500 hover:text-lab-100 transition-colors"
          >
            <Download className="h-4 w-4" strokeWidth={1.75} />
            Report JSON
          </button>
        </div>
      </div>

      {quarantineFeedback && (
        <div
          className={`mb-6 p-4 rounded-xl border flex items-center justify-between text-xs font-mono animate-fade-in ${
            quarantineFeedback.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
              : "bg-red-500/10 border-red-500/30 text-red-300"
          }`}
        >
          <div className="flex items-center gap-2">
            {quarantineFeedback.type === "success" ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
            )}
            <span>{quarantineFeedback.text}</span>
          </div>
          <button
            onClick={() => setQuarantineFeedback(null)}
            className="text-slate-400 hover:text-white p-1 cursor-pointer"
          >
            ×
          </button>
        </div>
      )}

      {/* 🚨 SOC SECURITY ALERT BANNER (Automatic for HIGH & CRITICAL) */}
      {isHighOrCritical && (
        <SOCAlertPanel
          caseId={data.case_id}
          riskScore={data.risk_score ?? rsb?.overall_score ?? 80}
          riskLevel={data.classification ?? "HIGH"}
          threatType={graph?.threat_category || "Phishing / Social Engineering"}
          detectedAt={data.analyzed_at || data.created_at}
          keyIndicators={keyIndicators}
          onScrollToSection={scrollToSection}
        />
      )}

      {/* 🚨 SOC HELPLINE & ESCALATION PROTOCOL (Automatic for HIGH & CRITICAL) */}
      {isHighOrCritical && (
        <SOCHelpline
          caseId={data.case_id}
          riskLevel={data.classification ?? "HIGH"}
          onScrollToSection={scrollToSection}
        />
      )}

      {/* Risk gauge + quick facts */}
      {rsb && (
        <div className="glass-section p-6 mb-6">
          <div className="flex flex-col md:flex-row items-center gap-8">
            <ThreatGauge
              score={data.risk_score ?? rsb.overall_score}
              classification={data.classification ?? rsb.classification}
              confidence={data.confidence ?? rsb.confidence}
              size={180}
            />
            <div className="flex-1 space-y-3">
              <div className="text-[10px] text-lab-500 evidence-tag mb-2">FORENSIC RISK DIMENSIONS</div>
              {[
                { label: "Authentication", score: rsb.authentication_score },
                { label: "Header Anomalies", score: rsb.header_score },
                { label: "Sender Identity", score: rsb.sender_identity_score },
                { label: "Domain", score: rsb.domain_score },
                { label: "URL Risk", score: rsb.url_score },
                { label: "Social Engineering", score: rsb.social_engineering_score },
                { label: "Infrastructure", score: rsb.infrastructure_score },
              ].map(({ label, score }) => {
                const color = score >= 70 ? "#e2483d" : score >= 40 ? "#e8a23d" : "#3ddc97";
                return (
                  <div key={label} className="flex items-center gap-3">
                    <span className="text-xs text-lab-500 w-36 shrink-0">{label}</span>
                    <div className="flex-1 h-1.5 bg-lab-800 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
                    </div>
                    <span className="font-data text-xs w-8 text-right" style={{ color }}>{score.toFixed(0)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {data.status !== "COMPLETED" && (
        <div className="glass-section p-4 mb-6 text-sm text-amber-signal flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          Investigation status: {data.status}. Full analysis panels will appear once the investigation completes.
          {data.error_message && <span className="ml-2 text-crimson-glow">Error: {data.error_message}</span>}
        </div>
      )}

      {/* ── AI DETECTION ANALYSIS (Real Keras ML + NLP Models) ─────────────── */}
      <AIDetectionAnalysis
        mlDetection={data.ml_detection}
        nlpDetection={data.nlp_detection}
      />

      <div className="space-y-4">
        {/* 1. Attack Relationship Graph */}
        <div id="attack-graph-section" className="scroll-mt-6">
          <AttackGraphPanel data={graph} loading={graphLoading} />
        </div>

        {/* 2. Forensic Evidence & Scoring Proof */}
        {rsb && (
          <div id="evidence-breakdown-section" className="scroll-mt-6">
            <ForensicEvidenceBreakdown rsb={rsb} />
          </div>
        )}

        {/* 3. Attack Classification */}
        <Section id="forensics-section" title="Attack Classification & Taxonomy" icon={ShieldAlert}>
          <AttackClassification
            findings={data.findings}
            rsb={rsb}
            classification={data.classification}
          />
        </Section>

        {/* 4. Risk Score Breakdown */}
        {rsb && (
          <Section title="Explainable Risk Score Breakdown" icon={Layers}>
            <RiskBreakdownPanel rsb={rsb} auth={auth} />
          </Section>
        )}

        {/* 5. Email Metadata */}
        {meta && (
          <Section title="Email Metadata & Headers" icon={Mail}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-0">
                <KV label="From" value={meta.from_address} />
                <KV label="Display Name" value={meta.from_display_name} mono={false} />
                <KV label="Subject" value={meta.subject} mono={false} />
                <KV label="Date" value={meta.date_parsed ?? meta.date_raw} />
                <KV label="Message-ID" value={meta.message_id} />
                <KV label="Reply-To" value={meta.reply_to} />
                <KV label="Return-Path" value={meta.return_path} />
                <KV label="X-Mailer / UA" value={meta.x_mailer ?? meta.user_agent} />
              </div>
              <div className="space-y-0">
                <KV label="To" value={meta.to_addresses?.join(", ")} mono={false} />
                <KV label="MIME Version" value={meta.mime_version} />
                <KV label="Content-Type" value={meta.content_type} />
                <KV label="Sender Domain" value={meta.sender_domain} />
                <KV label="Reply-To Domain" value={meta.reply_to_domain} />
                <KV label="Return-Path Domain" value={meta.return_path_domain} />
                <KV label="File Size" value={`${(data.file_size_bytes / 1024).toFixed(1)} KB`} />
                <KV label="MIME Type" value={data.mime_type} />
              </div>
            </div>
            {meta.attachments && meta.attachments.length > 0 && (
              <div className="mt-5">
                <div className="text-[10px] text-lab-500 evidence-tag mb-2">ATTACHMENTS</div>
                <div className="space-y-2">
                  {meta.attachments.map((att, i) => (
                    <div key={i} className="flex items-center gap-3 px-3 py-2 rounded-md bg-lab-800/50 border border-lab-700 text-xs">
                      <FileWarning className="h-4 w-4 text-amber-signal shrink-0" />
                      <span className="flex-1 font-data">{att.filename ?? "unnamed"}</span>
                      <span className="text-lab-500">{att.content_type}</span>
                      <span className="text-lab-500">{(att.size_bytes / 1024).toFixed(1)} KB</span>
                      <span className="text-lab-600 break-all max-w-[200px] truncate">SHA256: {att.sha256.slice(0, 16)}…</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Section>
        )}

        {/* 6. Authentication Analysis */}
        {auth && (
          <Section title="Email Authentication Analysis (SPF / DKIM / DMARC)" icon={Shield}>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              {[
                { label: "SPF", result: auth.spf_result, domain: auth.spf_domain },
                { label: "DKIM", result: auth.dkim_result, domain: auth.dkim_domain },
                { label: "DMARC", result: auth.dmarc_result, policy: auth.dmarc_policy },
              ].map(({ label, result, domain, policy }) => (
                <div key={label} className="p-4 rounded-md bg-lab-800/50 border border-lab-700 text-center">
                  <div className="text-[10px] text-lab-500 evidence-tag mb-1">{label}</div>
                  <AuthBadge result={result} />
                  {(domain || policy) && (
                    <div className="text-[10px] text-lab-500 mt-1 font-data">{domain ?? policy}</div>
                  )}
                </div>
              ))}
            </div>
            <div className="space-y-0">
              <KV label="From ↔ Return-Path" value={<AlignBadge aligned={auth.from_return_path_aligned} />} />
              <KV label="From ↔ Reply-To" value={<AlignBadge aligned={auth.from_reply_to_aligned} />} />
              <KV label="DKIM Domain Aligned" value={<AlignBadge aligned={auth.dkim_domain_aligned} />} />
              <KV label="DMARC Alignment Pass" value={<AlignBadge aligned={auth.dmarc_alignment_pass} />} />
              <KV label="Source" value={auth.source} />
            </div>
          </Section>
        )}

        {/* 7. Routing Analysis */}
        {data.received_hops.length > 0 && (
          <Section
            title="Email Routing & Relay Hops"
            icon={Network}
            badge={<span className="text-[10px] evidence-tag text-lab-500 bg-lab-800 border border-lab-700 rounded px-2 py-0.5">{data.received_hops.length} hops</span>}
          >
            <div className="space-y-3">
              {data.received_hops.map((hop) => (
                <div key={hop.hop_index} className="border border-lab-700 rounded-md p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-data text-xs text-phosphor-500 w-6">#{hop.hop_index}</span>
                    {hop.ip_address && (
                      <span className="font-data text-sm text-blue-signal">{hop.ip_address}</span>
                    )}
                    {hop.timestamp_parsed && (
                      <span className="ml-auto font-data text-xs text-lab-500">
                        {new Date(hop.timestamp_parsed).toLocaleString()}
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 text-xs">
                    <KV label="From" value={hop.from_host} />
                    <KV label="By" value={hop.by_host} />
                    <KV label="Protocol" value={hop.with_protocol} />
                  </div>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* SIH Layer 3: Earliest Reliable Observable Sending Node */}
        {originTrace && (
          <div id="origin-node-section" className="scroll-mt-6">
            <EarliestObservableNodePanel traceResult={originTrace} />
          </div>
        )}

        {/* Interactive Geolocation & Relay Path */}
        {originTrace && (
          <div id="geomap-section" className="scroll-mt-6">
            <InteractiveGeoMap traceResult={originTrace} />
          </div>
        )}

        {/* 8. Threat Intel */}

        <Section title="Threat Intelligence & IOCs" icon={MapPin}>
          <ThreatIntelPanel geo={geo} inv={data} />
        </Section>

        {/* 9. URL Analysis */}
        {data.urls.length > 0 && (
          <Section
            title="URL Analysis"
            icon={Link2}
            badge={<span className="text-[10px] evidence-tag text-lab-500 bg-lab-800 border border-lab-700 rounded px-2 py-0.5">{data.urls.length} URLs</span>}
          >
            <div className="space-y-3">
              {data.urls.map((url, i) => (
                <div key={i} className="border border-lab-700 rounded-md p-4">
                  <div className="flex items-start gap-2 mb-2">
                    <Link2 className="h-4 w-4 text-lab-500 mt-0.5 shrink-0" />
                    <div className="font-data text-xs text-lab-200 break-all flex-1">{url.url}</div>
                    {url.risk_score != null && (
                      <span
                        className={`font-data text-xs font-bold shrink-0 ${
                          url.risk_score >= 70 ? "text-crimson-glow" : url.risk_score >= 40 ? "text-amber-signal" : "text-phosphor-400"
                        }`}
                      >
                        {url.risk_score.toFixed(0)}
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {[
                      url.is_ip_based && "IP-based",
                      url.is_shortened && "Shortened",
                      url.is_punycode && "Punycode/IDN",
                      url.has_suspicious_tld && "Suspicious TLD",
                      url.anchor_text_mismatch && "Anchor mismatch",
                      url.has_encoded_chars && "Encoded chars",
                      url.suspicious_query_params && "Suspicious params",
                    ]
                      .filter(Boolean)
                      .map((flag) => (
                        <span key={String(flag)} className="text-[10px] evidence-tag bg-crimson-signal/10 text-crimson-glow border border-crimson-signal/20 rounded px-1.5 py-0.5">
                          {String(flag)}
                        </span>
                      ))}
                    {!url.is_https && (
                      <span className="text-[10px] evidence-tag bg-amber-signal/10 text-amber-signal border border-amber-signal/20 rounded px-1.5 py-0.5">
                        No HTTPS
                      </span>
                    )}
                  </div>
                  {url.risk_reasons && url.risk_reasons.length > 0 && (
                    <div className="mt-2 space-y-0.5">
                      {url.risk_reasons.map((r, ri) => (
                        <div key={ri} className="text-[11px] text-lab-400 flex gap-1.5">
                          <span className="text-crimson-signal">›</span>{r}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* 10. Domain Analysis */}
        {data.domains.length > 0 && (
          <Section
            title="Domain Analysis"
            icon={Globe2}
            badge={<span className="text-[10px] evidence-tag text-lab-500 bg-lab-800 border border-lab-700 rounded px-2 py-0.5">{data.domains.length} domains</span>}
          >
            <div className="space-y-2">
              {data.domains.map((d, i) => (
                <div key={i} className="border border-lab-700 rounded-md p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-data text-sm text-lab-200">{d.domain}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] evidence-tag text-lab-500">{d.role?.toUpperCase()}</span>
                      {d.risk_score != null && (
                        <span className={`font-data text-sm font-bold ${d.risk_score >= 70 ? "text-crimson-glow" : d.risk_score >= 40 ? "text-amber-signal" : "text-phosphor-400"}`}>
                          {d.risk_score.toFixed(0)}
                        </span>
                      )}
                    </div>
                  </div>
                  {d.lookalike_of && (
                    <div className="text-xs text-crimson-glow mt-1">
                      ⚠ Lookalike of <span className="font-data">{d.lookalike_of}</span>
                      {d.similarity_score != null && ` (${(d.similarity_score * 100).toFixed(0)}% similarity)`}
                    </div>
                  )}
                  <div className="flex flex-wrap gap-1.5 mt-1.5">
                    {d.is_punycode && <span className="text-[10px] evidence-tag bg-amber-signal/10 text-amber-signal border border-amber-signal/20 rounded px-1.5 py-0.5">Punycode</span>}
                    {d.suspicious_tld && <span className="text-[10px] evidence-tag bg-amber-signal/10 text-amber-signal border border-amber-signal/20 rounded px-1.5 py-0.5">Suspicious TLD</span>}
                    {d.excessive_hyphenation && <span className="text-[10px] evidence-tag bg-amber-signal/10 text-amber-signal border border-amber-signal/20 rounded px-1.5 py-0.5">Excessive hyphens</span>}
                  </div>
                  {d.evidence && d.evidence.length > 0 && (
                    <div className="mt-1.5 space-y-0.5">
                      {d.evidence.map((e, ei) => (
                        <div key={ei} className="text-[11px] text-lab-400 flex gap-1.5">
                          <span className="text-amber-signal">›</span>{e}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* 11. Forensic Findings */}
        {data.findings.length > 0 && (
          <Section
            title="Forensic Findings"
            icon={Fingerprint}
            badge={<span className="text-[10px] evidence-tag text-lab-500 bg-lab-800 border border-lab-700 rounded px-2 py-0.5">{data.findings.length} rules fired</span>}
          >
            <div className="space-y-2">
              {data.findings.map((f, i) => (
                <div key={i} className="border border-lab-700 rounded-md p-4">
                  <div className="flex items-start gap-3">
                    <ClassificationBadge level={f.severity} size="sm" />
                    <div className="flex-1">
                      <div className="text-sm font-semibold text-lab-200">{f.title}</div>
                      <div className="text-[10px] text-lab-500 evidence-tag mb-1">{f.rule_id} · {f.category}</div>
                      <p className="text-xs text-lab-400">{f.explanation}</p>
                      {f.evidence && f.evidence.length > 0 && (
                        <div className="mt-2 space-y-0.5">
                          {f.evidence.map((e, ei) => (
                            <div key={ei} className="text-[11px] text-lab-500 flex gap-1.5">
                              <span className="text-phosphor-500">›</span>{e}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="text-right shrink-0">
                      <div className="font-data text-xs text-lab-400">{(f.confidence * 100).toFixed(0)}%</div>
                      <div className="text-[10px] text-lab-500">confidence</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* 12. Threat Indicators */}
        {data.indicators.length > 0 && (
          <Section
            title="Threat Indicators"
            icon={MessageSquareWarning}
            badge={<span className="text-[10px] evidence-tag text-lab-500 bg-lab-800 border border-lab-700 rounded px-2 py-0.5">{data.indicators.length} indicators</span>}
          >
            <div className="space-y-2">
              {data.indicators.map((ind, i) => (
                <div key={i} className="flex items-start gap-3 border border-lab-700 rounded-md p-3">
                  <ClassificationBadge level={ind.severity} size="sm" />
                  <div className="flex-1">
                    <div className="text-xs font-semibold text-lab-200 evidence-tag">{ind.indicator_type}</div>
                    <p className="text-xs text-lab-400 mt-0.5">{ind.explanation}</p>
                    {ind.matched_evidence && (
                      <div className="text-[11px] font-data text-phosphor-400 mt-1 break-all">{ind.matched_evidence}</div>
                    )}
                  </div>
                  <span className="font-data text-xs text-lab-400 shrink-0">{(ind.confidence * 100).toFixed(0)}%</span>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* Interactive Incident Response Decision Tree */}
        <div id="decision-tree-section" className="scroll-mt-6">
          <SecurityDecisionTree
            investigationId={id ?? ""}
            caseId={data.case_id}
            threatClass={data.classification ?? "THREAT"}
          />
        </div>

        {/* 13. Recommended Response */}
        <Section title="Recommended Response Actions" icon={ListChecks}>
          <RecommendedResponsePanel recommendations={recommendations} />
        </Section>

        {/* 14. Investigation Timeline */}
        <Section title="Forensic Investigation Timeline" icon={Clock}>
          {timeline ? (
            <InvestigationTimeline events={timeline.events} />
          ) : (
            <div className="text-xs text-lab-500 italic">
              {data.status !== "COMPLETED" ? "Timeline available after analysis completes." : "Loading timeline…"}
            </div>
          )}
        </Section>

        {/* 15. Similar Cases */}
        <Section title="Similar Cases / Campaign Correlation" icon={Users}>
          <SimilarCasesPanel data={campaign} currentId={id ?? ""} />
        </Section>

        {/* 16. Evidence Integrity */}
        <Section title="Evidence Integrity & Blockchain Anchor" icon={Lock}>
          <BlockchainIntegrityPanel
            investigationId={id ?? ""}
            evidenceHash={data.evidence_hash_sha256}
            blockInfo={custody?.blockchain_anchor ?? null}
          />
        </Section>

        {/* 17. Chain of Custody */}
        {custody && (
          <Section title="Chain of Custody" icon={GitBranch}>
            <ChainOfCustody data={custody} />
          </Section>
        )}

        {/* 18. Evidence Evidence Record */}
        <Section title="Evidence Record" icon={Fingerprint}>
          <div className="space-y-0">
            <KV label="SHA-256" value={data.evidence_hash_sha256} />
            <KV label="File Size" value={`${(data.file_size_bytes / 1024).toFixed(2)} KB`} />
            <KV label="Original Filename" value={data.original_filename} />
            <KV label="MIME Type" value={data.mime_type} />
            <KV label="Case ID" value={data.case_id} />
            <KV label="Investigation ID" value={data.id} />
            <KV label="Created" value={new Date(data.created_at).toISOString()} />
            <KV label="Updated" value={new Date(data.updated_at).toISOString()} />
            {data.analyzed_at && <KV label="Analyzed" value={new Date(data.analyzed_at).toISOString()} />}
          </div>
        </Section>
      </div>

      {/* Quarantine Confirmation Modal */}
      <QuarantineConfirmModal
        isOpen={isQuarantineModalOpen}
        onClose={() => setIsQuarantineModalOpen(false)}
        onConfirm={handleConfirmQuarantine}
        loading={quarantineState === "loading"}
        subject={data.email_metadata?.subject || data.original_filename}
        sender={data.email_metadata?.from_address || undefined}
      />
    </div>
  );
}

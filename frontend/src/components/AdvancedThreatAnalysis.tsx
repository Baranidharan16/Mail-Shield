import { useEffect, useRef, useState } from "react";
import {
  Mail, Brain, AlertTriangle, Lock, Box, FileText, Link2, CheckCircle2, XCircle, MinusCircle, Loader2,
  ChevronDown, ChevronRight, ShieldAlert, ShieldCheck, ShieldQuestion, Download, RefreshCw, Scale, Crosshair,
  Bot, FileWarning, Globe2, Activity, Target, Wrench,
} from "lucide-react";
import { getApiErrorMessage } from "../api/client";
import {
  getAdvancedAnalysis, runSandbox, downloadThreatReport,
  type AdvancedAnalysis, type SandboxFile, type Checkpoint,
} from "../api/advanced";

const VERDICT: Record<string, { text: string; ring: string; bg: string; Icon: typeof ShieldAlert }> = {
  MALICIOUS: { text: "text-crimson-glow", ring: "border-crimson-signal/50", bg: "bg-crimson-signal/10", Icon: ShieldAlert },
  SUSPICIOUS: { text: "text-amber-300", ring: "border-amber-500/40", bg: "bg-amber-500/10", Icon: ShieldQuestion },
  SAFE: { text: "text-phosphor-300", ring: "border-phosphor-500/40", bg: "bg-phosphor-500/10", Icon: ShieldCheck },
};
const SEV_CLS: Record<string, string> = {
  CRITICAL: "text-crimson-glow border-crimson-signal/40 bg-crimson-signal/10",
  HIGH: "text-orange-400 border-orange-500/40 bg-orange-500/10",
  MEDIUM: "text-amber-300 border-amber-500/40 bg-amber-500/10",
  LOW: "text-sky-300 border-sky-400/30 bg-sky-400/10",
  INFO: "text-lab-500 border-white/10",
};
const STEP_ICONS = [Mail, Brain, AlertTriangle, Lock, Box, FileText, Link2];

function Chip({ label, cls }: { label: string; cls?: string }) {
  return <span className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded border whitespace-nowrap ${cls ?? SEV_CLS[label] ?? "text-lab-400 border-white/10"}`}>{label}</span>;
}

function VerdictChip({ v }: { v?: string | null }) {
  if (!v) return <Chip label="—" />;
  const s = VERDICT[v];
  return <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${s ? `${s.text} ${s.ring} ${s.bg}` : "text-lab-400 border-white/10"}`}>{v}</span>;
}

function Panel({ id, title, icon: Icon, badge, children, defaultOpen = true }: {
  id?: string; title: string; icon: typeof Box; badge?: React.ReactNode; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div id={id} className="glass-section scroll-mt-6">
      <button className="glass-section-header w-full flex items-center gap-2.5 text-left" onClick={() => setOpen(!open)}>
        <Icon className="h-4 w-4 text-phosphor-500 shrink-0" strokeWidth={1.75} />
        <h2 className="font-semibold text-sm text-white flex-1">{title}</h2>
        {badge}
        {open ? <ChevronDown className="h-4 w-4 text-lab-500" /> : <ChevronRight className="h-4 w-4 text-lab-500" />}
      </button>
      {open && <div className="p-5">{children}</div>}
    </div>
  );
}

function stepStyle(status: string) {
  const s = status.toUpperCase();
  if (["DONE", "COMPLETED", "ANCHORED", "QUARANTINED", "YES"].includes(s)) return "border-phosphor-500/50 bg-phosphor-500/10 text-phosphor-300";
  if (["RUNNING", "QUEUED", "PENDING"].includes(s)) return "border-sky-400/40 bg-sky-400/10 text-sky-300";
  if (["UNAVAILABLE", "FAILED"].includes(s)) return "border-crimson-signal/40 bg-crimson-signal/10 text-crimson-glow";
  return "border-white/10 bg-white/[0.03] text-lab-500";
}

function CheckIcon({ s }: { s: string }) {
  if (s === "FAIL") return <XCircle className="h-4 w-4 text-crimson-glow shrink-0" />;
  if (s === "WARN") return <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />;
  if (s === "PASS") return <CheckCircle2 className="h-4 w-4 text-phosphor-400 shrink-0" />;
  return <MinusCircle className="h-4 w-4 text-lab-500 shrink-0" />;
}

function Bar({ value, color }: { value: number; color: string }) {
  return (
    <div className="flex-1 h-1.5 bg-lab-800 rounded-full overflow-hidden">
      <div className="h-full rounded-full" style={{ width: `${Math.max(2, Math.min(100, value))}%`, backgroundColor: color }} />
    </div>
  );
}

function FileCard({ f, depth = 0 }: { f: SandboxFile; depth?: number }) {
  const [open, setOpen] = useState(f.verdict !== "SAFE" && depth === 0);
  const findings = f.findings.filter((x) => x.severity !== "INFO");
  return (
    <div className={`rounded-lg border border-lab-700 bg-lab-800/40 ${depth ? "ml-5 mt-2" : ""}`}>
      <button onClick={() => setOpen(!open)} className="w-full flex flex-wrap items-center gap-3 px-3 py-2.5 text-left text-xs">
        <FileWarning className={`h-4 w-4 shrink-0 ${VERDICT[f.verdict]?.text ?? ""}`} />
        <span className="font-data font-semibold text-lab-100 break-all flex-1 min-w-[160px]">{f.filename}</span>
        <span className="text-lab-500">{f.detected_type}</span>
        <span className="text-lab-500 font-data">{(f.size_bytes / 1024).toFixed(1)} KB</span>
        <VerdictChip v={f.verdict} />
        <span className="font-data text-lab-400 w-10 text-right">{Math.round(f.score)}</span>
        {open ? <ChevronDown className="h-3.5 w-3.5 text-lab-500" /> : <ChevronRight className="h-3.5 w-3.5 text-lab-500" />}
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-3 text-xs">
          <div className="grid md:grid-cols-2 gap-x-6 gap-y-1 font-data text-[11px]">
            <div className="break-all"><span className="text-lab-500">SHA-256 </span>{f.sha256}</div>
            <div className="break-all"><span className="text-lab-500">MD5 </span>{f.md5}</div>
            <div><span className="text-lab-500">Declared </span>{f.declared_content_type || "—"} <span className="text-lab-500 ml-2">Ext </span>{f.extension || "—"}</div>
            <div><span className="text-lab-500">Entropy </span>{f.entropy} <span className="text-lab-600">(≥7.2 ≈ packed/encrypted)</span></div>
          </div>
          {findings.length > 0 ? (
            <div className="space-y-1.5">
              {findings.map((x, i) => (
                <div key={i} className="flex items-start gap-2 p-2 rounded-md bg-lab-900/40 border border-white/[0.05]">
                  <Chip label={x.severity} />
                  <div className="flex-1 min-w-0">
                    <div className="text-lab-100 font-semibold">{x.title} <span className="text-lab-600 font-data font-normal">[{x.rule_id}{x.mitre ? ` · ${x.mitre}` : ""}]</span></div>
                    <div className="text-lab-400 leading-relaxed">{x.explanation}</div>
                    {x.evidence && <div className="text-lab-500 font-data break-all mt-0.5">evidence: {x.evidence}</div>}
                  </div>
                </div>
              ))}
            </div>
          ) : <div className="text-phosphor-300">No malicious or suspicious static indicators.</div>}
          {(f.iocs.urls.length > 0 || f.iocs.ips.length > 0) && (
            <div>
              <div className="text-[10px] text-lab-500 evidence-tag mb-1">EMBEDDED IOCs</div>
              <div className="font-data text-[11px] text-lab-300 break-all space-y-0.5">
                {[...f.iocs.urls.slice(0, 8), ...f.iocs.ips.slice(0, 5)].map((u) => <div key={u}>{u}</div>)}
              </div>
            </div>
          )}
          {f.children?.map((c) => <FileCard key={c.sha256 + c.filename} f={c} depth={depth + 1} />)}
        </div>
      )}
    </div>
  );
}

export default function AdvancedThreatAnalysis({ investigationId, caseId, status }: { investigationId: string; caseId: string; status: string }) {
  const [a, setA] = useState<AdvancedAnalysis | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const polls = useRef(0);

  useEffect(() => {
    if (status !== "COMPLETED") return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    polls.current = 0;
    const load = async () => {
      try {
        const d = await getAdvancedAnalysis(investigationId);
        if (!alive) return;
        setA(d);
        setErr(null);
        const pending = !d.exists || d.pipeline_status === "RUNNING" || d.pipeline_status === "PENDING"
          || ["RUNNING", "QUEUED"].includes(d.sandbox?.status ?? "");
        if (pending && polls.current++ < 60) timer = setTimeout(load, 4000);
      } catch (e) {
        if (alive) setErr(getApiErrorMessage(e, "Could not load sandbox / threat-report data."));
      }
    };
    load();
    return () => { alive = false; clearTimeout(timer); };
  }, [investigationId, status, busy]);

  async function rerun() {
    setBusy(true);
    try {
      await runSandbox(investigationId);
      setA((p) => (p ? { ...p, pipeline_status: "RUNNING", sandbox: p.sandbox ? { ...p.sandbox, status: "RUNNING" } : p.sandbox } : p));
    } catch (e) {
      setErr(getApiErrorMessage(e, "Could not submit to the sandbox."));
    } finally {
      setTimeout(() => setBusy(false), 500);
    }
  }

  if (status !== "COMPLETED") return null;
  if (err && !a) return <div className="glass-section p-4 mb-6 text-xs text-crimson-glow">{err}</div>;
  if (!a || !a.exists || !a.threat_report) {
    return (
      <div className="glass-section p-5 mb-6 flex items-center gap-2 text-xs text-lab-400">
        <Loader2 className="w-4 h-4 animate-spin" />
        {a?.pipeline_status === "FAILED" ? `Threat-report pipeline failed: ${a.error}` :
          "Quarantine → isolated sandbox → AI-security / GRC / VAPT analysis in progress (the sandbox may take up to a minute to wake up)…"}
      </div>
    );
  }

  const tr = a.threat_report;
  const vs = VERDICT[tr.final_verdict] ?? VERDICT.SUSPICIOUS;
  const sb = a.sandbox!;
  const res = sb.result;
  const ai = a.ai_security!;
  const grc = a.grc!;
  const vapt = a.vapt!;
  const running = a.pipeline_status === "RUNNING" || ["RUNNING", "QUEUED"].includes(sb.status);
  const fails = tr.where_it_went_wrong.filter((c: Checkpoint) => c.status === "FAIL").length;

  return (
    <div id="threat-report-section" className="space-y-4 mb-6 scroll-mt-6">
      {/* ── pipeline + consolidated verdict ───────────────────────────────── */}
      <div className={`rounded-2xl border ${vs.ring} ${vs.bg} p-6`}>
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <vs.Icon className={`w-8 h-8 ${vs.text}`} />
          <div>
            <div className={`text-xl font-bold tracking-tight ${vs.text}`}>Consolidated threat verdict: {tr.final_verdict}</div>
            <div className="text-[11px] text-lab-400 font-mono">AI detection + isolated sandbox + AI security + GRC · {fails} checkpoint(s) failed</div>
          </div>
          <div className="ml-auto flex items-center gap-4">
            <div className="text-right">
              <div className={`text-3xl font-bold font-data ${vs.text}`}>{Math.round(tr.final_score)}</div>
              <div className="text-[10px] text-lab-500 font-mono">COMBINED / 100</div>
            </div>
          </div>
        </div>

        {/* pipeline stepper */}
        <div className="flex flex-wrap items-stretch gap-1.5 mb-4">
          {tr.pipeline.map((s, i) => {
            const Icon = STEP_ICONS[i] ?? Box;
            const live = running && (s.step.startsWith("Isolated") || s.step.startsWith("Threat") || s.step.startsWith("Blockchain"));
            return (
              <div key={s.step} className="flex items-center gap-1.5">
                <div className={`rounded-lg border px-2.5 py-2 min-w-[118px] ${stepStyle(live ? "RUNNING" : s.status)}`} title={s.detail ?? ""}>
                  <div className="flex items-center gap-1.5 text-[11px] font-semibold">
                    {live ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Icon className="h-3.5 w-3.5" />} {s.step}
                  </div>
                  <div className="text-[10px] font-mono mt-0.5 opacity-90">{live ? "RUNNING" : s.status.replace(/_/g, " ")}</div>
                </div>
                {i < tr.pipeline.length - 1 && <ChevronRight className="h-3.5 w-3.5 text-lab-500 shrink-0" />}
              </div>
            );
          })}
        </div>

        <div className="space-y-1 text-xs text-lab-300 mb-4">
          {tr.verdict_reasons.slice(0, 6).map((r, i) => <div key={i} className="flex gap-2"><span className={vs.text}>•</span><span>{r}</span></div>)}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button onClick={() => downloadThreatReport(investigationId, caseId, "pdf")}
            className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-md border border-lab-700 text-lab-200 hover:border-lab-500 cursor-pointer">
            <Download className="h-3.5 w-3.5" /> Threat report (PDF)
          </button>
          <button onClick={() => downloadThreatReport(investigationId, caseId, "json")}
            className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-md border border-lab-700 text-lab-200 hover:border-lab-500 cursor-pointer">
            <Download className="h-3.5 w-3.5" /> JSON
          </button>
          <button onClick={rerun} disabled={running || busy}
            className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-md border border-lab-700 text-lab-200 hover:border-lab-500 disabled:opacity-50 cursor-pointer">
            <RefreshCw className={`h-3.5 w-3.5 ${running ? "animate-spin" : ""}`} /> {running ? "Sandbox running…" : "Re-run sandbox"}
          </button>
          {a.ledger?.block_index != null && (
            <span className="text-[11px] font-mono text-lab-400 ml-auto break-all">
              Ledger block #{a.ledger.block_index} · {a.ledger.case_ref} · report SHA-256 {a.ledger.report_hash?.slice(0, 16)}…
            </span>
          )}
        </div>
      </div>

      {/* ── where it went wrong ───────────────────────────────────────────── */}
      <Panel title="Where the e-mail went wrong — checkpoint analysis" icon={Target}
        badge={<Chip label={`${fails} FAIL`} cls={fails ? SEV_CLS.CRITICAL : SEV_CLS.INFO} />}>
        <div className="space-y-2">
          {tr.where_it_went_wrong.map((c) => (
            <div key={c.checkpoint} className="flex items-start gap-3 p-2.5 rounded-md bg-lab-800/40 border border-lab-700">
              <CheckIcon s={c.status} />
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-lab-100">{c.checkpoint}</span>
                  <Chip label={c.status.replace("_", " ")} cls={c.status === "FAIL" ? SEV_CLS.CRITICAL : c.status === "WARN" ? SEV_CLS.MEDIUM : c.status === "PASS" ? "text-phosphor-300 border-phosphor-500/40" : SEV_CLS.INFO} />
                </div>
                <div className="text-xs text-lab-400 mt-0.5">{c.summary}</div>
                {c.evidence.length > 0 && (
                  <div className="mt-1 space-y-0.5">
                    {c.evidence.slice(0, 4).map((e, i) => <div key={i} className="text-[11px] font-data text-lab-500 break-all">› {e}</div>)}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </Panel>

      {/* ── sandbox ───────────────────────────────────────────────────────── */}
      <Panel id="sandbox-section" title="Isolated sandbox analysis — attachments, URLs & behaviour" icon={Box}
        badge={<span className="flex items-center gap-1.5"><Chip label={sb.status.replace(/_/g, " ")} cls={SEV_CLS.INFO} />{sb.verdict && <VerdictChip v={sb.verdict} />}</span>}>
        <div className="grid md:grid-cols-4 gap-3 mb-4 text-xs">
          <div className="p-3 rounded-md bg-lab-800/50 border border-lab-700"><div className="text-[10px] text-lab-500 evidence-tag">QUARANTINE</div><div className="font-semibold text-lab-100 mt-1">{a.quarantine?.status.replace(/_/g, " ")}</div><div className="text-lab-500 mt-0.5">{a.quarantine?.reason}</div></div>
          <div className="p-3 rounded-md bg-lab-800/50 border border-lab-700"><div className="text-[10px] text-lab-500 evidence-tag">SANDBOX VERDICT</div><div className="mt-1"><VerdictChip v={sb.verdict} /></div><div className="text-lab-500 mt-1 font-data">score {sb.score != null ? Math.round(sb.score) : "—"} / 100</div></div>
          <div className="p-3 rounded-md bg-lab-800/50 border border-lab-700"><div className="text-[10px] text-lab-500 evidence-tag">ISOLATION</div><div className="text-lab-200 mt-1">Separate container · no secrets · static only</div><div className="text-lab-500 mt-0.5 font-data">{res?.isolation ? `${res.isolation.mode}, net ${String(res.isolation.limits.network)}` : "HMAC-signed job"}</div></div>
          <div className="p-3 rounded-md bg-lab-800/50 border border-lab-700"><div className="text-[10px] text-lab-500 evidence-tag">SUBMITTED</div><div className="text-lab-200 mt-1">{sb.submission ? `${sb.submission.files.length} file(s) · ${sb.submission.url_count} URL(s)` : "—"}</div><div className="text-lab-500 mt-0.5 font-data">{res?.engine_version ?? ""}{res?.duration_ms != null ? ` · ${res.duration_ms} ms` : ""}</div></div>
        </div>
        {sb.error && <div className="mb-3 p-2.5 rounded-md border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300">{sb.error}</div>}
        {sb.status === "NOT_REQUIRED" && <div className="text-xs text-lab-400">Not sandboxed: the e-mail was not classified suspicious (change the sandbox scope in SOC configuration, or run it manually).</div>}
        {sb.status === "NO_ARTIFACTS" && <div className="text-xs text-lab-400">Quarantined, but the e-mail carried no attachments, links or HTML to detonate.</div>}
        {res && (
          <div className="space-y-4">
            {res.reasons.length > 0 && (
              <div className="space-y-1 text-xs">
                {res.reasons.slice(0, 5).map((r, i) => <div key={i} className="text-lab-300">› {r}</div>)}
              </div>
            )}
            {res.files.length > 0 && (
              <div>
                <div className="text-[10px] text-lab-500 evidence-tag mb-2">ATTACHMENTS ({res.files.length})</div>
                <div className="space-y-2">{res.files.map((f) => <FileCard key={f.sha256 + f.filename} f={f} />)}</div>
              </div>
            )}
            {res.urls.length > 0 && (
              <div>
                <div className="text-[10px] text-lab-500 evidence-tag mb-2">URLS ({res.urls.length}) — analysed statically, never fetched</div>
                <div className="space-y-1.5">
                  {res.urls.map((u) => (
                    <div key={u.url} className="flex flex-wrap items-center gap-2 px-3 py-2 rounded-md bg-lab-800/40 border border-lab-700 text-xs">
                      <Globe2 className="h-3.5 w-3.5 text-lab-500 shrink-0" />
                      <span className="font-data text-lab-200 break-all flex-1 min-w-[200px]">{u.url}</span>
                      <VerdictChip v={u.verdict} />
                      {u.verdict !== "SAFE" && <div className="basis-full text-lab-500 pl-5">{u.findings.filter((x) => x.severity !== "LOW").map((x) => x.title).join(" · ") || u.findings.map((x) => x.title).join(" · ")}</div>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {res.html_body.findings.length > 0 && (
              <div>
                <div className="text-[10px] text-lab-500 evidence-tag mb-2">HTML BODY BEHAVIOUR</div>
                {res.html_body.findings.map((x, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs mb-1"><Chip label={x.severity} /><span className="text-lab-200">{x.title} — <span className="text-lab-400">{x.explanation}</span></span></div>
                ))}
              </div>
            )}
            {res.predicted_behavior.length > 0 && (
              <div>
                <div className="text-[10px] text-lab-500 evidence-tag mb-2 flex items-center gap-1.5"><Activity className="h-3 w-3" /> PREDICTED BEHAVIOUR (static inference — nothing was executed)</div>
                <div className="space-y-1">{res.predicted_behavior.map((b) => <div key={b} className="text-xs text-lab-300">› {b}</div>)}</div>
              </div>
            )}
            {res.mitre_techniques.length > 0 && (
              <div className="flex flex-wrap gap-1.5">{res.mitre_techniques.map((t) => <Chip key={t} label={t} cls="text-sky-300 border-sky-400/30" />)}</div>
            )}
          </div>
        )}
      </Panel>

      {/* ── AI security ───────────────────────────────────────────────────── */}
      <Panel title="AI security — attacks on AI & how MailShield's AI is protected" icon={Bot}
        badge={<Chip label={ai.verdict.replace(/_/g, " ")} cls={ai.verdict === "MANIPULATION_DETECTED" ? SEV_CLS.CRITICAL : ai.verdict === "SUSPICIOUS" ? SEV_CLS.MEDIUM : "text-phosphor-300 border-phosphor-500/40"} />}>
        <div className="grid md:grid-cols-2 gap-6">
          <div>
            <div className="text-[10px] text-lab-500 evidence-tag mb-2">ADVERSARIAL-AI SIGNALS IN THIS E-MAIL</div>
            <div className="flex items-center gap-3 mb-3 text-xs">
              <span className="text-lab-500 w-40 shrink-0">AI-written lure likelihood</span>
              <Bar value={ai.ai_generated_likelihood * 100} color={ai.ai_generated_likelihood >= 0.7 ? "#cf3520" : ai.ai_generated_likelihood >= 0.45 ? "#d99a2b" : "#5f8f55"} />
              <span className="font-data w-10 text-right">{Math.round(ai.ai_generated_likelihood * 100)}%</span>
            </div>
            <div className="text-[10px] text-lab-600 mb-3">{ai.ai_generated_note}</div>
            {ai.findings.length === 0 ? <div className="text-xs text-phosphor-300">{ai.summary}</div> : (
              <div className="space-y-2">
                {ai.findings.map((f, i) => (
                  <div key={i} className="p-2 rounded-md bg-lab-800/40 border border-lab-700 text-xs">
                    <div className="flex items-center gap-2"><Chip label={f.severity} /><span className="font-semibold text-lab-100">{f.title}</span></div>
                    <div className="text-lab-400 mt-1">{f.explanation}</div>
                    {f.evidence && <div className="font-data text-lab-500 mt-0.5 break-all">evidence: {f.evidence}</div>}
                    <div className="text-[10px] text-lab-600 mt-0.5">{f.mitre_atlas_or_attack} · targets {f.targets}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div>
            <div className="text-[10px] text-lab-500 evidence-tag mb-2">GUARDRAILS PROTECTING OUR OWN AI</div>
            <div className="space-y-1.5">
              {ai.guardrails.map((g) => (
                <div key={g.control} className="flex items-start gap-2 text-xs">
                  {g.status === "ACTIVE" ? <CheckCircle2 className="h-3.5 w-3.5 text-phosphor-400 shrink-0 mt-0.5" /> : <MinusCircle className="h-3.5 w-3.5 text-lab-500 shrink-0 mt-0.5" />}
                  <div><span className="text-lab-100 font-semibold">{g.control}</span> <span className="text-[10px] font-mono text-lab-500">{g.status}</span><div className="text-lab-500">{g.detail}</div></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Panel>

      {/* ── GRC ───────────────────────────────────────────────────────────── */}
      <Panel title="GRC — Indian law & regulatory compliance mapping" icon={Scale}
        badge={<Chip label={grc.status.replace(/_/g, " ")} cls={grc.violations ? SEV_CLS.CRITICAL : grc.obligations ? SEV_CLS.MEDIUM : "text-phosphor-300 border-phosphor-500/40"} />}>
        <div className="flex flex-wrap gap-3 mb-4 text-xs">
          <span className="px-2.5 py-1 rounded-md border border-crimson-signal/30 text-crimson-glow">{grc.violations} potential violation(s)</span>
          <span className="px-2.5 py-1 rounded-md border border-amber-500/30 text-amber-300">{grc.obligations} reporting obligation(s)</span>
          <span className="px-2.5 py-1 rounded-md border border-sky-400/30 text-sky-300">{grc.control_gaps} control gap(s)</span>
        </div>
        {grc.items.length === 0 ? <div className="text-xs text-phosphor-300">No rule violations indicated by the evidence.</div> : (
          <div className="space-y-2.5">
            {grc.items.map((it) => (
              <div key={it.rule_id} className="p-3 rounded-md bg-lab-800/40 border border-lab-700 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip label={it.type.replace("_", " ")} cls={it.type === "VIOLATION" ? SEV_CLS.CRITICAL : it.type === "OBLIGATION" ? SEV_CLS.MEDIUM : SEV_CLS.LOW} />
                  <Chip label={it.severity} />
                  <span className="font-semibold text-lab-100">{it.title}</span>
                </div>
                <div className="text-lab-300 mt-1"><span className="font-semibold">{it.framework}</span> — {it.provision}</div>
                <div className="text-lab-400 mt-1">{it.description}</div>
                {it.evidence.length > 0 && <div className="mt-1 space-y-0.5">{it.evidence.map((e, i) => <div key={i} className="font-data text-[11px] text-lab-500 break-all">evidence › {e}</div>)}</div>}
                {it.actions.length > 0 && <div className="mt-1 space-y-0.5">{it.actions.map((x, i) => <div key={i} className="text-[11px] text-phosphor-300">action › {x}</div>)}</div>}
              </div>
            ))}
          </div>
        )}
        {grc.reporting_channels.length > 0 && (
          <div className="mt-4 grid md:grid-cols-3 gap-2 text-xs">
            {grc.reporting_channels.map((c) => (
              <div key={c.name} className="p-2.5 rounded-md border border-lab-700"><div className="font-semibold text-lab-100">{c.name}</div><div className="font-data text-lab-300">{c.contact}</div><div className="text-lab-500">{c.when}</div></div>
            ))}
          </div>
        )}
        <div className="text-[10px] text-lab-600 mt-3">{grc.disclaimer}</div>
      </Panel>

      {/* ── VAPT ──────────────────────────────────────────────────────────── */}
      <Panel title="VAPT — attacker intention, attack path & exploited weaknesses" icon={Crosshair}
        badge={<Chip label={`EXPLOITABILITY ${Math.round(vapt.exploitability_score)}`} cls={vapt.exploitability_score >= 70 ? SEV_CLS.CRITICAL : vapt.exploitability_score >= 40 ? SEV_CLS.MEDIUM : SEV_CLS.INFO} />}>
        <div className="grid md:grid-cols-2 gap-6 mb-5">
          <div>
            <div className="text-[10px] text-lab-500 evidence-tag mb-2">HACKER'S INTENTION</div>
            <div className="p-3 rounded-md border border-crimson-signal/30 bg-crimson-signal/5 mb-3">
              <div className="text-sm font-bold text-lab-100">{vapt.primary_intent.label}</div>
              <div className="text-xs text-lab-400 mt-0.5">{vapt.primary_intent.attacker_objective}</div>
            </div>
            <div className="space-y-2">
              {vapt.intents.map((i) => (
                <div key={i.intent} className="text-xs">
                  <div className="flex items-center gap-3">
                    <span className="text-lab-300 w-60 shrink-0 truncate" title={i.label}>{i.label}</span>
                    <Bar value={i.confidence * 100} color={i.confidence >= 0.8 ? "#cf3520" : i.confidence >= 0.6 ? "#d99a2b" : "#5f8f55"} />
                    <span className="font-data w-10 text-right">{Math.round(i.confidence * 100)}%</span>
                  </div>
                  {i.evidence.length > 0 && <div className="text-[10px] text-lab-500 font-data ml-1 mt-0.5 break-all">{i.evidence.slice(0, 3).join(" · ")}</div>}
                </div>
              ))}
            </div>
          </div>
          <div>
            <div className="text-[10px] text-lab-500 evidence-tag mb-2">KILL CHAIN</div>
            <div className="space-y-1">
              {vapt.kill_chain.map((k) => (
                <div key={k.stage} className="flex items-start gap-2 text-xs">
                  {k.observed ? <XCircle className="h-3.5 w-3.5 text-crimson-glow shrink-0 mt-0.5" /> : <MinusCircle className="h-3.5 w-3.5 text-lab-600 shrink-0 mt-0.5" />}
                  <div className="min-w-0"><span className={k.observed ? "text-lab-100 font-semibold" : "text-lab-500"}>{k.stage}</span>
                    {k.observed && <span className="text-lab-400"> — {k.evidence}</span>}
                    {k.mitre && k.observed && <span className="text-[10px] font-mono text-sky-300 ml-1">{k.mitre}</span>}</div>
                </div>
              ))}
            </div>
            {vapt.mitre_attack.length > 0 && <div className="flex flex-wrap gap-1.5 mt-3">{vapt.mitre_attack.map((t) => <Chip key={t} label={t} cls="text-sky-300 border-sky-400/30" />)}</div>}
          </div>
        </div>
        <div className="text-[10px] text-lab-500 evidence-tag mb-2 flex items-center gap-1.5"><Wrench className="h-3 w-3" /> WHERE THE WEAKNESS IS — AND HOW TO FIX IT</div>
        {vapt.weaknesses.length === 0 ? <div className="text-xs text-phosphor-300">No exploited weakness identified.</div> : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-[10px] text-lab-500 evidence-tag border-b border-lab-700">
                <th className="py-2 pr-3">RISK</th><th className="py-2 pr-3">WEAKNESS</th><th className="py-2 pr-3">LOCATION</th><th className="py-2 pr-3">REMEDIATION</th><th className="py-2">OWNER</th></tr></thead>
              <tbody>
                {vapt.weaknesses.map((w) => (
                  <tr key={w.id} className="border-b border-lab-800 align-top">
                    <td className="py-2 pr-3"><Chip label={w.rating} /><div className="text-[10px] text-lab-600 font-data mt-0.5">{w.score}/16</div></td>
                    <td className="py-2 pr-3"><div className="font-semibold text-lab-100">{w.title}</div><div className="text-lab-500">{w.description}</div>
                      {w.evidence.length > 0 && <div className="font-data text-[10px] text-lab-600 break-all mt-0.5">{w.evidence.join(" · ")}</div>}</td>
                    <td className="py-2 pr-3 text-lab-300">{w.location}</td>
                    <td className="py-2 pr-3 text-lab-300">{w.remediation}</td>
                    <td className="py-2 text-lab-400">{w.owner}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="mt-3 text-xs"><span className="text-lab-500">Attack path: </span><span className="text-lab-200">{vapt.attack_path}</span></div>
        <div className="text-[10px] text-lab-600 mt-2">{vapt.scope_note}</div>
      </Panel>
    </div>
  );
}

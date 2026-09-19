import { useEffect, useState } from "react";
import {
  ShieldAlert, ShieldCheck, ShieldQuestion, Route, Globe2, Fingerprint, KeyRound, Brain,
  Crosshair, Link2, Lock, RefreshCw, ChevronRight, Info, Loader2, Server,
} from "lucide-react";
import { getForensicVerdict, verifyEvidence, getApiErrorMessage } from "../api/client";
import type { ForensicVerdict, VerdictField } from "../types/investigation";

const STATUS_STYLE: Record<string, { ring: string; text: string; bg: string; Icon: typeof ShieldAlert }> = {
  THREAT: { ring: "border-crimson-signal/50", text: "text-crimson-glow", bg: "bg-crimson-signal/10", Icon: ShieldAlert },
  SUSPICIOUS: { ring: "border-amber-500/40", text: "text-amber-300", bg: "bg-amber-500/10", Icon: ShieldQuestion },
  SAFE: { ring: "border-phosphor-500/40", text: "text-phosphor-300", bg: "bg-phosphor-500/10", Icon: ShieldCheck },
};

const INFRA_STYLE: Record<string, string> = {
  KNOWN_INFRASTRUCTURE: "text-phosphor-300 border-phosphor-500/30 bg-phosphor-500/10",
  SUSPICIOUS_INFRASTRUCTURE: "text-crimson-glow border-crimson-signal/40 bg-crimson-signal/10",
  UNKNOWN_INFRASTRUCTURE: "text-amber-300 border-amber-500/30 bg-amber-500/10",
  INTERNAL_OR_PRIVATE: "text-lab-300 border-white/10 bg-white/5",
};

function pct(v: number | null | undefined) {
  return v === null || v === undefined ? "n/a" : `${Math.round(v)}%`;
}

function Tag({ status }: { status: string }) {
  const cls =
    status === "OBSERVED" ? "text-phosphor-300 border-phosphor-500/40"
      : status === "INFERRED" ? "text-sky-300 border-sky-400/40"
        : "text-lab-500 border-white/10";
  return <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${cls}`}>{status}</span>;
}

function Card({ title, icon: Icon, children }: { title: string; icon: typeof Route; children: React.ReactNode }) {
  return (
    <div className="glass-section p-5">
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-4 h-4 text-phosphor-400" />
        <h3 className="text-sm font-bold text-white tracking-tight">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function FieldRow({ label, f }: { label: string; f?: VerdictField | null }) {
  if (!f) return null;
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 border-b border-white/[0.05] text-xs">
      <span className="text-lab-500 shrink-0">{label}</span>
      <span className="flex items-center gap-2 text-right">
        <span className={f.value ? "text-lab-100 font-data break-all" : "text-lab-600 italic"}>{f.value ?? "Unknown"}</span>
        <Tag status={f.status} />
      </span>
    </div>
  );
}

export default function ForensicVerdictPanel({ investigationId, status }: { investigationId: string; status: string }) {
  const [v, setV] = useState<ForensicVerdict | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    if (status !== "COMPLETED") return;
    let alive = true;
    getForensicVerdict(investigationId)
      .then((d) => alive && setV(d))
      .catch((e) => alive && setError(getApiErrorMessage(e, "Could not load the forensic verdict.")));
    return () => { alive = false; };
  }, [investigationId, status]);

  async function recheck() {
    if (!v) return;
    setChecking(true);
    try {
      const integrity = await verifyEvidence(investigationId);
      setV({ ...v, integrity: integrity as unknown as ForensicVerdict["integrity"] });
    } finally {
      setChecking(false);
    }
  }

  if (status !== "COMPLETED") return null;
  if (error) return <div className="glass-section p-4 mb-6 text-xs text-crimson-glow">{error}</div>;
  if (!v) {
    return (
      <div className="glass-section p-6 mb-6 flex items-center gap-2 text-xs text-lab-400">
        <Loader2 className="w-4 h-4 animate-spin" /> Building forensic verdict (header route, GeoIP, domain intelligence)…
      </div>
    );
  }

  const c = v.conclusion;
  const st = STATUS_STYLE[c.status] ?? STATUS_STYLE.SUSPICIOUS;
  const o = v.origin;

  return (
    <div id="forensic-verdict-section" className="space-y-4 mb-6 scroll-mt-6">
      {/* ── ONE CLEAR FORENSIC RESULT ─────────────────────────────────── */}
      <div className={`rounded-2xl border ${st.ring} ${st.bg} p-6`}>
        <div className="flex items-center gap-3 mb-4">
          <st.Icon className={`w-8 h-8 ${st.text}`} />
          <div>
            <div className={`text-xl font-bold tracking-tight ${st.text}`}>{c.headline}</div>
            <div className="text-[11px] text-lab-400 font-mono">Generated from this email's own evidence · case {v.case_id}</div>
          </div>
          <div className="ml-auto text-right">
            <div className={`text-3xl font-bold font-data ${st.text}`}>{Math.round(c.risk_score)}</div>
            <div className="text-[10px] text-lab-500 font-mono">RISK / 100</div>
          </div>
        </div>
        <div className="grid md:grid-cols-2 gap-x-8 gap-y-2 text-sm">
          <div><span className="text-lab-500">Threat type: </span><span className="text-white font-semibold">{c.threat_type}</span></div>
          <div><span className="text-lab-500">Confidence: </span><span className="text-white">{c.confidence} ({Math.round(c.confidence_value * 100)}%)</span></div>
          <div><span className="text-lab-500">ML risk: </span><span className="text-white font-data">{pct(c.ml_risk)}</span></div>
          <div><span className="text-lab-500">NLP risk: </span><span className="text-white font-data">{pct(c.nlp_risk)}</span></div>
          <div className="md:col-span-2"><span className="text-lab-500">Observed origin: </span><span className="text-lab-100 font-data break-all">{c.observed_origin}</span></div>
          <div className="md:col-span-2"><span className="text-lab-500">Threat path: </span><span className="text-lab-100 font-data break-all">{c.threat_path}</span></div>
          {c.likely_attack_vectors.length > 0 && (
            <div className="md:col-span-2"><span className="text-lab-500">Likely attack vector: </span><span className="text-white">{c.likely_attack_vectors.join(", ")}</span></div>
          )}
        </div>
        {c.primary_evidence.length > 0 && (
          <ul className="mt-4 space-y-1 text-xs text-lab-200">
            {c.primary_evidence.map((e, i) => (
              <li key={i} className="flex gap-2"><ChevronRight className="w-3 h-3 mt-0.5 shrink-0 text-lab-500" />{e}</li>
            ))}
          </ul>
        )}
        <div className="mt-4 p-3 rounded-xl bg-black/20 border border-white/10 text-xs text-lab-100">
          <span className="font-bold text-white">Recommended action: </span>{c.recommended_action}
        </div>
      </div>

      {/* ── agent + models ─────────────────────────────────────────────── */}
      <div className="grid lg:grid-cols-2 gap-4">
        <Card title="Forensic Agent & Detection Layers" icon={Brain}>
          <div className="text-xs mb-3">
            <span className={v.forensic_agent.triggered ? "text-crimson-glow font-semibold" : "text-lab-400"}>
              {v.forensic_agent.triggered ? "Deep forensic agent TRIGGERED" : "Deep forensic agent not required"}
            </span>
            <div className="text-[10px] text-lab-500 mt-1">{v.forensic_agent.rule}</div>
            {v.forensic_agent.triggers.map((t, i) => <div key={i} className="text-lab-200 mt-1">• {t}</div>)}
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-white/5">
              <div className="text-lab-500 text-[10px] font-mono">ML · FORENSIC FEATURES</div>
              <div className="text-white text-lg font-data">{v.models.ml.threat_probability != null ? `${Math.round(v.models.ml.threat_probability * 100)}%` : "n/a"}</div>
              <div className="text-lab-400">{v.models.ml.label ?? "unavailable"} · v{v.models.ml.model_version ?? "?"}</div>
              {v.models.ml.top_features.slice(0, 4).map((f, i) => (
                <div key={i} className="text-[10px] text-lab-400 mt-1" title={f.meaning}>{f.feature}</div>
              ))}
            </div>
            <div className="p-3 rounded-lg bg-white/5">
              <div className="text-lab-500 text-[10px] font-mono">NLP · LANGUAGE MODEL</div>
              <div className="text-white text-lg font-data">{v.models.nlp.threat_probability != null ? `${Math.round(v.models.nlp.threat_probability * 100)}%` : "n/a"}</div>
              <div className="text-lab-400">{v.models.nlp.label ?? "unavailable"} · v{v.models.nlp.model_version ?? "?"}</div>
              {v.models.nlp.top_terms.slice(0, 5).map((t, i) => (
                <span key={i} className="inline-block text-[10px] text-lab-300 bg-white/5 rounded px-1 mr-1 mt-1">{t.term}</span>
              ))}
            </div>
          </div>
          {v.models.nlp.suspicious_sentences.length > 0 && (
            <div className="mt-3 space-y-1">
              <div className="text-[10px] text-lab-500 font-mono">MOST SUSPICIOUS SENTENCES</div>
              {v.models.nlp.suspicious_sentences.map((s, i) => (
                <div key={i} className="text-[11px] text-lab-200 border-l-2 border-crimson-signal/50 pl-2">
                  “{s.sentence}” <span className="text-lab-500 font-data">({Math.round(s.phishing_probability * 100)}%)</span>
                </div>
              ))}
            </div>
          )}
          {v.models.nlp.pattern_indicators.length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] text-lab-500 font-mono mb-1">RULE-MATCHED PHRASES</div>
              {v.models.nlp.pattern_indicators.slice(0, 5).map((p, i) => (
                <div key={i} className="text-[11px] text-lab-300">• <b>{p.type.replace(/_/g, " ")}</b>: “{p.evidence}”</div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Authentication (SPF · DKIM · DMARC · ARC)" icon={KeyRound}>
          {(["spf", "dkim", "dmarc"] as const).map((k) => {
            const a = v.authentication[k];
            const good = a.result === "PASS";
            const bad = ["FAIL", "SOFTFAIL", "PERMERROR"].includes(a.result);
            return (
              <div key={k} className="py-2 border-b border-white/[0.05]">
                <div className="flex items-center justify-between text-xs">
                  <span className="uppercase font-mono text-lab-300">{k}</span>
                  <span className={`font-data font-bold ${good ? "text-phosphor-300" : bad ? "text-crimson-glow" : "text-lab-400"}`}>{a.result}</span>
                </div>
                <div className="text-[11px] text-lab-400 mt-0.5">{a.meaning}</div>
              </div>
            );
          })}
          <div className="py-2 text-[11px] text-lab-400">
            <span className="uppercase font-mono text-lab-300 text-xs">ARC </span>{v.authentication.arc.meaning}
          </div>
        </Card>
      </div>

      {/* ── identity ───────────────────────────────────────────────────── */}
      <Card title="Sender Identity" icon={Fingerprint}>
        <div className="grid md:grid-cols-2 gap-x-8 text-xs">
          {[
            ["From", v.identity.from], ["Display name", v.identity.display_name], ["Reply-To", v.identity.reply_to],
            ["Return-Path", v.identity.return_path], ["Sender domain", v.identity.sender_domain],
          ].map(([k, val]) => (
            <div key={k as string} className="flex justify-between py-1.5 border-b border-white/[0.05]">
              <span className="text-lab-500">{k}</span><span className="text-lab-100 font-data break-all text-right">{val || "—"}</span>
            </div>
          ))}
        </div>
        <div className="mt-3 space-y-1 text-[11px]">
          {v.identity.reply_to_mismatch && <div className="text-amber-300">• Reply-To domain differs from the From domain — replies go somewhere else.</div>}
          {v.identity.return_path_mismatch && <div className="text-amber-300">• Return-Path (bounce) domain differs from the From domain.</div>}
          {v.identity.display_name_impersonation.map((d, i) => <div key={i} className="text-crimson-glow">• {d}</div>)}
          {v.identity.lookalike_domains.map((l, i) => (
            <div key={i} className="text-crimson-glow">• {l.domain} ({l.role}) resembles <b>{l.resembles}</b></div>
          ))}
        </div>
      </Card>

      {/* ── threat path ────────────────────────────────────────────────── */}
      <Card title="Threat Path / Attack Hops" icon={Route}>
        <div className="flex flex-wrap items-center gap-2 mb-4">
          {v.threat_path.map((p, i) => (
            <div key={i} className="flex items-center gap-2">
              <div className={`px-2.5 py-1.5 rounded-lg border text-[11px] ${INFRA_STYLE[p.infrastructure] ?? "text-lab-200 border-white/10 bg-white/5"}`}>
                <div className="text-[9px] opacity-70 font-mono">{p.stage}</div>
                <div className="font-data break-all">{p.node}</div>
              </div>
              {i < v.threat_path.length - 1 && <ChevronRight className="w-4 h-4 text-lab-500" />}
            </div>
          ))}
        </div>
        {v.route.length === 0 ? (
          <div className="text-xs text-lab-500">No Received headers were present, so no relay path can be reconstructed.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead className="text-lab-500 font-mono text-[10px]">
                <tr className="text-left"><th className="py-1 pr-3">HOP</th><th className="pr-3">FROM → BY</th><th className="pr-3">IP / rDNS</th><th className="pr-3">NETWORK</th><th className="pr-3">COUNTRY</th><th className="pr-3">TIME</th><th>ROLE / INDICATORS</th></tr>
              </thead>
              <tbody>
                {v.route.map((h) => (
                  <tr key={h.hop} className="border-t border-white/[0.05] align-top">
                    <td className="py-1.5 pr-3 font-data">{h.hop}<div className="text-[9px] text-lab-500">hdr #{h.received_header_number}</div></td>
                    <td className="pr-3 break-all text-lab-200">{h.from_host || "?"} → {h.by_host || "?"}</td>
                    <td className="pr-3 font-data break-all">{h.ip || "—"}{h.reverse_dns && <div className="text-lab-500">{h.reverse_dns}</div>}</td>
                    <td className="pr-3 text-lab-300">{h.network || "—"}{h.asn && <div className="text-lab-500">{h.asn}</div>}</td>
                    <td className="pr-3 text-lab-300">{h.country || "—"}</td>
                    <td className="pr-3 text-lab-400 font-data">{h.timestamp ? h.timestamp.replace("T", " ").slice(0, 19) : "—"}</td>
                    <td>
                      <span className={`inline-block px-1.5 py-0.5 rounded border text-[9px] ${INFRA_STYLE[h.infrastructure]}`}>{h.infrastructure.replace(/_/g, " ")}</span>
                      <div className="text-lab-400">{h.role}</div>
                      {h.suspicious_indicators.map((s, i) => <div key={i} className="text-crimson-glow">• {s}</div>)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="text-[10px] text-lab-500 mt-2">Hop 1 is the earliest observed hop. Hops are not assumed malicious; each is classified as known, suspicious or unknown infrastructure from network ownership.</div>
      </Card>

      {/* ── threat origin ──────────────────────────────────────────────── */}
      {o && (
        <Card title="Threat Origin (observed infrastructure)" icon={Globe2}>
          {!o.determined ? (
            <div className="text-sm text-amber-300">{o.message}<div className="text-xs text-lab-400 mt-1">{o.reason}</div></div>
          ) : (
            <div className="grid md:grid-cols-2 gap-x-8">
              <div>
                <FieldRow label="Observed IP" f={o.observed_ip} />
                <div className="text-[10px] text-lab-500 -mt-1 mb-1">Evidence: {o.observed_ip?.evidence}</div>
                <FieldRow label="Timestamp" f={o.timestamp} />
                <FieldRow label="Claimed hostname (HELO)" f={o.claimed_hostname} />
                <FieldRow label="Reverse DNS" f={o.reverse_dns} />
                <FieldRow label="ASN" f={o.asn} />
                <FieldRow label="Network / ISP" f={o.network} />
                <FieldRow label="Provider" f={o.mail_provider} />
              </div>
              <div>
                <FieldRow label="Country" f={o.country} />
                <FieldRow label="Region" f={o.region} />
                <FieldRow label="City" f={o.city} />
                <FieldRow label="Approx. coordinates" f={o.coordinates} />
                <FieldRow label="Timezone" f={o.timezone} />
                <FieldRow label="Infrastructure type" f={o.infrastructure_type} />
                <FieldRow label="Sender domain" f={o.sender_domain} />
                <div className="flex justify-between py-1.5 text-xs"><span className="text-lab-500">Confidence</span><span className="text-white">{o.confidence}</span></div>
              </div>
            </div>
          )}
          <div className="mt-3 space-y-1 text-[11px]">
            {o.location_caveat && <div className="text-amber-300 flex gap-1.5"><Info className="w-3 h-3 mt-0.5 shrink-0" />{o.location_caveat}</div>}
            {o.confidence_reason && <div className="text-lab-400">{o.confidence_reason}</div>}
            {o.geo_lookup_note && <div className="text-lab-500">GeoIP: {o.geo_lookup_note}</div>}
            {o.accuracy_note && <div className="text-lab-500">{o.accuracy_note}</div>}
            <div className="text-lab-300 font-semibold">{o.disclaimer}</div>
          </div>
        </Card>
      )}

      {/* ── attack vectors ─────────────────────────────────────────────── */}
      <Card title="How This Threat Reaches You (evidence-backed vectors)" icon={Crosshair}>
        {v.attack_vectors.length === 0 ? (
          <div className="text-xs text-lab-400">No attack vector is supported by the evidence in this email.</div>
        ) : (
          <div className="grid md:grid-cols-2 gap-3">
            {v.attack_vectors.map((a) => (
              <div key={a.key} className="p-3 rounded-lg bg-white/5 border border-white/10">
                <div className="text-xs font-semibold text-white">{a.vector}</div>
                {a.evidence.map((e, i) => <div key={i} className="text-[11px] text-lab-300 mt-1 break-all">• {e}</div>)}
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* ── domain intel ───────────────────────────────────────────────── */}
      {v.domain_intelligence.length > 0 && (
        <Card title="Domain Intelligence (RDAP / DNS, live)" icon={Server}>
          <div className="overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead className="text-lab-500 font-mono text-[10px]"><tr className="text-left"><th className="py-1 pr-3">DOMAIN</th><th className="pr-3">AGE</th><th className="pr-3">REGISTRAR</th><th className="pr-3">MX</th><th>DMARC</th></tr></thead>
              <tbody>
                {v.domain_intelligence.map((d) => (
                  <tr key={d.domain} className="border-t border-white/[0.05]">
                    <td className="py-1.5 pr-3 font-data">{d.domain}</td>
                    <td className={`pr-3 ${d.newly_registered ? "text-crimson-glow font-semibold" : "text-lab-300"}`}>{d.domain_age_days != null ? `${d.domain_age_days} days` : (d.rdap_reason ? "unavailable" : "—")}</td>
                    <td className="pr-3 text-lab-300">{d.registrar || "—"}</td>
                    <td className="pr-3 text-lab-300 break-all">{d.mx.length ? d.mx.join(", ") : "none"}</td>
                    <td className="text-lab-300">{d.dmarc_policy ? `p=${d.dmarc_policy}` : "no record"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* ── integrity ──────────────────────────────────────────────────── */}
      {v.integrity && (
        <Card title="Forensic Integrity (hash-chain ledger)" icon={Lock}>
          <div className="flex items-center gap-3 mb-2">
            <span className={`text-sm font-bold ${v.integrity.status === "VALID" ? "text-phosphor-300" : v.integrity.status === "MODIFIED" ? "text-crimson-glow" : "text-amber-300"}`}>
              Integrity: {v.integrity.status}
            </span>
            <button onClick={recheck} disabled={checking} className="ml-auto text-[11px] flex items-center gap-1 px-2 py-1 rounded border border-white/10 text-lab-300 hover:text-white">
              <RefreshCw className={`w-3 h-3 ${checking ? "animate-spin" : ""}`} /> Re-verify now
            </button>
          </div>
          {v.integrity.forensic_report && (
            <div className="text-[11px] text-lab-400 space-y-1 font-data break-all">
              <div>Report: {v.integrity.forensic_report.status} · anchored {v.integrity.forensic_report.anchored_hash?.slice(0, 24)}… · now {v.integrity.forensic_report.current_hash?.slice(0, 24)}…</div>
              <div>Evidence file: {v.integrity.evidence_file?.status}{v.integrity.evidence_file?.note ? ` — ${v.integrity.evidence_file.note}` : ""}</div>
              <div>Block #{v.integrity.ledger?.block_index} · chain {v.integrity.ledger?.chain_intact ? "intact" : "BROKEN"}</div>
            </div>
          )}
          <div className="text-[10px] text-lab-500 mt-2 flex gap-1.5"><Link2 className="w-3 h-3 shrink-0" />{v.integrity.what_is_on_the_ledger} {v.integrity.scope_note}</div>
        </Card>
      )}
    </div>
  );
}

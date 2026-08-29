import { Globe2, Wifi, Copy, CheckCircle2 } from "lucide-react";
import { useState } from "react";
import type { GeoResponse, InvestigationDetail } from "../types/investigation";

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }
  return (
    <button onClick={copy} className="p-1 rounded hover:bg-lab-700 text-lab-500 hover:text-lab-200 transition-colors">
      {copied ? <CheckCircle2 className="h-3.5 w-3.5 text-phosphor-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

function KV({ label, value, copyable = false }: { label: string; value?: string | null; copyable?: boolean }) {
  if (!value) return null;
  return (
    <div className="flex justify-between items-center gap-4 py-1.5 text-xs border-b border-lab-800 last:border-0">
      <span className="text-lab-500 shrink-0">{label}</span>
      <div className="flex items-center gap-1.5 text-right">
        <span className="font-data text-lab-300 break-all">{value}</span>
        {copyable && <CopyButton value={value} />}
      </div>
    </div>
  );
}

interface Props {
  geo: GeoResponse | null;
  inv: InvestigationDetail;
}

export default function ThreatIntelPanel({ geo, inv }: Props) {
  const publicIPs = (geo?.results ?? []).filter((r) => !r.is_private);
  const allIPs = inv.ip_addresses ?? [];

  // Collect all IOCs
  const iocIPs = allIPs.map((ip) => ({ type: "IP", value: ip.ip_address, source: ip.source ?? "header" }));
  const iocDomains = inv.domains.map((d) => ({ type: "DOMAIN", value: d.domain, source: d.role ?? "unknown" }));
  const iocURLs = inv.urls.map((u) => ({ type: "URL", value: u.url, source: u.source_location ?? "body" }));
  const iocEmails = [
    inv.email_metadata?.from_address && { type: "EMAIL", value: inv.email_metadata.from_address, source: "from" },
    inv.email_metadata?.reply_to && { type: "EMAIL", value: inv.email_metadata.reply_to, source: "reply-to" },
    inv.email_metadata?.return_path && { type: "EMAIL", value: inv.email_metadata.return_path, source: "return-path" },
  ].filter(Boolean) as { type: string; value: string; source: string }[];
  const attachHashes = (inv.email_metadata?.attachments ?? []).map((a) => ({
    type: "HASH", value: a.sha256, source: `attachment: ${a.filename ?? "unknown"}`,
  }));
  const allIOCs = [...iocIPs, ...iocDomains, ...iocURLs, ...iocEmails, ...attachHashes];

  function exportIOCs() {
    const lines = allIOCs.map((ioc) => `${ioc.type}\t${ioc.value}\t${ioc.source}`);
    const blob = new Blob([`TYPE\tVALUE\tSOURCE\n${lines.join("\n")}`], { type: "text/tab-separated-values" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${inv.case_id}_iocs.tsv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-5">
      {/* Threat Infrastructure Attribution */}
      <div>
        <div className="text-[10px] text-lab-500 evidence-tag mb-3">THREAT INFRASTRUCTURE ATTRIBUTION</div>
        <div className="text-[10px] text-amber-signal bg-amber-signal/5 border border-amber-signal/20 rounded p-2 mb-3">
          Infrastructure correlation only. IP geolocation reflects observed relay infrastructure — NOT a confirmed attacker physical location.
        </div>

        {/* IP Intelligence */}
        {publicIPs.length > 0 ? (
          <div className="space-y-3">
            {publicIPs.map((r, i) => (
              <div key={i} className="border border-lab-700 rounded-md p-3">
                <div className="flex items-center gap-2 mb-2">
                  <Wifi className="h-4 w-4 text-blue-signal" strokeWidth={1.75} />
                  <span className="font-data text-sm text-lab-200">{r.ip_address}</span>
                  <span className="text-[10px] text-lab-500 evidence-tag">{r.source ?? "received"}</span>
                </div>
                {r.geo ? (
                  <div className="space-y-0">
                    <KV label="Country" value={r.geo.country} />
                    <KV label="Region" value={r.geo.region} />
                    <KV label="City" value={r.geo.city} />
                    <KV label="ASN" value={r.geo.asn} />
                    <KV label="ISP / Org" value={r.geo.org} />
                    {r.geo.error && <div className="text-[11px] text-lab-500 italic">{r.geo.error}</div>}
                  </div>
                ) : (
                  <div className="text-xs text-lab-500 italic">Geo lookup not available.</div>
                )}
              </div>
            ))}
          </div>
        ) : allIPs.length > 0 ? (
          <div className="space-y-2">
            {allIPs.map((ip, i) => (
              <div key={i} className="flex items-center justify-between px-3 py-2 border border-lab-700 rounded-md text-xs">
                <span className="font-data text-lab-300">{ip.ip_address}</span>
                <div className="flex gap-2">
                  <span className="text-lab-500">{ip.is_private ? "private" : "public"}</span>
                  <span className="text-lab-600">{ip.source}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-xs text-lab-500 italic">No IP addresses extracted from this email.</div>
        )}
      </div>

      {/* Domain Intelligence */}
      {inv.domains.length > 0 && (
        <div>
          <div className="text-[10px] text-lab-500 evidence-tag mb-2">DOMAIN INTELLIGENCE</div>
          <div className="space-y-2">
            {inv.domains.map((d, i) => (
              <div key={i} className="border border-lab-700 rounded-md p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Globe2 className="h-4 w-4 text-amber-signal" strokeWidth={1.75} />
                  <span className="font-data text-sm text-lab-200">{d.domain}</span>
                  <span className="text-[10px] text-lab-500 evidence-tag ml-auto">{d.role?.toUpperCase()}</span>
                </div>
                {d.lookalike_of && (
                  <div className="text-xs text-crimson-glow">
                    ⚠ Possible lookalike of: <span className="font-data">{d.lookalike_of}</span>
                    {d.similarity_score && ` (${(d.similarity_score * 100).toFixed(0)}% similarity)`}
                  </div>
                )}
                {d.suspicious_tld && <div className="text-xs text-amber-signal">· Suspicious TLD</div>}
                {d.is_punycode && <div className="text-xs text-amber-signal">· Punycode / IDN encoding</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IOC Section */}
      {allIOCs.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <div className="text-[10px] text-lab-500 evidence-tag">INDICATORS OF COMPROMISE</div>
            <button
              onClick={exportIOCs}
              className="text-[10px] text-phosphor-400 hover:text-phosphor-300 border border-phosphor-500/30 rounded px-2 py-1 transition-colors evidence-tag"
            >
              Export IOCs
            </button>
          </div>
          <div className="space-y-1.5 max-h-64 overflow-y-auto">
            {allIOCs.map((ioc, i) => (
              <div key={i} className="flex items-center gap-2 px-3 py-2 bg-lab-800/40 rounded border border-lab-700/60 text-xs">
                <span className="font-data text-[10px] text-lab-500 w-14 shrink-0">{ioc.type}</span>
                <span className="font-data text-lab-200 flex-1 break-all">{ioc.value}</span>
                <span className="text-lab-600 text-[10px] shrink-0">{ioc.source}</span>
                <CopyButton value={ioc.value} />
              </div>
            ))}
          </div>
        </div>
      )}

      {allIOCs.length === 0 && (
        <div className="text-xs text-lab-500 italic text-center py-4">
          No indicators of compromise extracted. Analysis must complete first.
        </div>
      )}
    </div>
  );
}

/**
 * GeoOriginIntelPanel - Email Origin Geolocation Intelligence
 * DISCLAIMER: Shows observed mail relay infrastructure ONLY.
 * Does NOT establish physical attacker location.
 */
import { useState } from "react";
import {
  Globe2, Wifi, AlertTriangle, Copy, CheckCircle2,
  RefreshCw, Info, ChevronDown, ChevronRight, Shield,
} from "lucide-react";
import type { GeoResponse, GeoResult, InvestigationDetail } from "../types/investigation";

function CopyBtn({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1400); }); }}
      className="p-1 rounded hover:bg-lab-700 text-lab-500 hover:text-phosphor-400 transition-colors" title="Copy">
      {copied ? <CheckCircle2 className="h-3 w-3 text-phosphor-400" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

type ConfLevel = "HIGH" | "MEDIUM" | "LOW" | "NONE";
function ConfidencePill({ level }: { level: ConfLevel }) {
  const cfg: Record<ConfLevel, { label: string; bg: string; color: string; border: string }> = {
    HIGH:   { label: "HIGH CONFIDENCE",   bg: "rgba(61,220,151,0.12)",  color: "#3ddc97", border: "rgba(61,220,151,0.3)"  },
    MEDIUM: { label: "MEDIUM CONFIDENCE", bg: "rgba(232,162,61,0.12)",  color: "#e8a23d", border: "rgba(232,162,61,0.3)"  },
    LOW:    { label: "LOW CONFIDENCE",    bg: "rgba(249,115,22,0.12)",  color: "#f97316", border: "rgba(249,115,22,0.3)"  },
    NONE:   { label: "UNAVAILABLE",       bg: "rgba(74,90,107,0.2)",   color: "#4a5a6b", border: "rgba(74,90,107,0.3)"   },
  };
  const c = cfg[level];
  return <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border" style={{ background: c.bg, color: c.color, borderColor: c.border }}>{c.label}</span>;
}

function deriveConfidence(r: GeoResult): ConfLevel {
  if (!r.geo || r.geo.error) return "NONE";
  if (r.is_private) return "NONE";
  const g = r.geo as Record<string, unknown>;
  if (g["is_synthetic_demo_data"]) return "MEDIUM";
  if (g["country"] && g["city"] && g["asn"]) return "HIGH";
  if (g["country"] && g["asn"]) return "MEDIUM";
  if (g["country"]) return "LOW";
  return "NONE";
}

function IPOriginCard({ result, index }: { result: GeoResult; index: number }) {
  const [open, setOpen] = useState(index === 0);
  const geo = result.geo as Record<string, unknown> | null;
  const confidence = deriveConfidence(result);
  const borderColor = result.is_private ? "rgba(74,90,107,0.4)"
    : confidence === "HIGH" ? "rgba(226,72,61,0.4)"
    : confidence === "MEDIUM" ? "rgba(232,162,61,0.3)" : "rgba(74,90,107,0.3)";

  return (
    <div className="rounded-xl overflow-hidden" style={{ border: `1px solid ${borderColor}`, background: "rgba(16,21,26,0.7)" }}>
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors">
        <div className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0"
          style={{ background: result.is_private ? "rgba(74,90,107,0.2)" : "rgba(226,72,61,0.15)", border: `1px solid ${borderColor}` }}>
          {result.is_private ? <Shield className="h-4 w-4" style={{ color: "#4a5a6b" }} /> : <Wifi className="h-4 w-4" style={{ color: "#e2483d" }} />}
        </div>
        <div className="flex-1 text-left">
          <div className="flex items-center gap-2">
            <span className="font-mono font-bold text-sm" style={{ color: "#cfdbe4" }}>{result.ip_address}</span>
            <CopyBtn value={result.ip_address} />
          </div>
          <div className="text-[10px] font-mono" style={{ color: "#4a5a6b" }}>
            {result.source ?? "received-header"}{result.hop_index != null ? ` · HOP #${result.hop_index}` : ""}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {result.is_private
            ? <span className="text-[10px] font-mono px-2 py-0.5 rounded" style={{ background: "rgba(74,90,107,0.15)", color: "#4a5a6b", border: "1px solid rgba(74,90,107,0.3)" }}>PRIVATE</span>
            : <ConfidencePill level={confidence} />}
          {open ? <ChevronDown className="h-3.5 w-3.5" style={{ color: "#4a5a6b" }} /> : <ChevronRight className="h-3.5 w-3.5" style={{ color: "#4a5a6b" }} />}
        </div>
      </button>
      {open && (
        <div className="px-4 pb-4 pt-1 border-t" style={{ borderColor: "rgba(255,255,255,0.05)" }}>
          {result.is_private ? (
            <div className="text-xs py-2" style={{ color: "#7c8fa0" }}>Private/reserved address. No geolocation applicable - internal relay node.</div>
          ) : !geo ? (
            <div className="text-xs py-2 italic" style={{ color: "#4a5a6b" }}>Geolocation data unavailable.</div>
          ) : geo["error"] ? (
            <div className="text-xs py-2" style={{ color: "#e8a23d" }}>{String(geo["error"])}</div>
          ) : (
            <div className="mt-2 space-y-1">
              {Boolean(geo["is_synthetic_demo_data"]) && (
                <div className="mb-2 text-[10px] font-mono px-2.5 py-1.5 rounded-lg" style={{ background: "rgba(232,162,61,0.08)", color: "#e8a23d", border: "1px solid rgba(232,162,61,0.2)" }}>
                  SYNTHETIC DEMO DATA — RFC 5737 documentation range. Not a real IP.
                </div>
              )}
              {[
                { label: "Probable Country", value: geo["country"] as string },
                { label: "Region",           value: geo["region"] as string },
                { label: "City",             value: geo["city"] as string },
                { label: "ASN",              value: geo["asn"] as string },
                { label: "ISP / Org",        value: (geo["isp"] ?? geo["org"]) as string },
                { label: "Datacenter",       value: geo["hosting"] === true ? "YES - cloud/datacenter" : geo["hosting"] === false ? "No" : undefined },
              ].map(({ label, value }) => value ? (
                <div key={label} className="flex items-center justify-between py-1.5 border-b text-xs" style={{ borderColor: "rgba(255,255,255,0.04)" }}>
                  <span className="font-mono" style={{ color: "#4a5a6b" }}>{label}</span>
                  <span className="font-mono font-semibold" style={{ color: "#cfdbe4" }}>{value}</span>
                </div>
              ) : null)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface Props { geo: GeoResponse | null; inv: InvestigationDetail; loading?: boolean; }

export default function GeoOriginIntelPanel({ geo, inv, loading }: Props) {
  const results = geo?.results ?? [];
  const allIPs = inv.ip_addresses ?? [];
  const publicResults = results.filter(r => !r.is_private);
  if (loading) return (
    <div className="flex items-center gap-2 py-6 justify-center text-xs" style={{ color: "#4a5a6b" }}>
      <RefreshCw className="h-4 w-4 animate-spin" /> Loading origin intelligence...
    </div>
  );
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 px-4 py-3 rounded-xl text-xs" style={{ background: "rgba(232,162,61,0.07)", border: "1px solid rgba(232,162,61,0.22)" }}>
        <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" style={{ color: "#e8a23d" }} />
        <div>
          <span className="font-bold font-mono" style={{ color: "#e8a23d" }}>PROBABLE ORIGIN — INFRASTRUCTURE ONLY: </span>
          <span style={{ color: "#7c8fa0" }}>{geo?.disclaimer ?? "IP geolocation reflects observed mail relay infrastructure, NOT the physical location of the sender or attacker. Results are probabilistic estimates only."}</span>
        </div>
      </div>
      {allIPs.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Total IPs Observed",    value: allIPs.length,                              color: "#cfdbe4" },
            { label: "Public Infrastructure", value: allIPs.filter(ip => !ip.is_private).length, color: "#e2483d" },
            { label: "Geo-Located Nodes",     value: publicResults.filter(r => r.geo && !(r.geo as Record<string,unknown>)["error"]).length, color: "#3ddc97" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-xl px-4 py-3 text-center" style={{ background: "rgba(16,21,26,0.8)", border: "1px solid rgba(255,255,255,0.07)" }}>
              <div className="font-mono font-bold text-2xl" style={{ color }}>{value}</div>
              <div className="text-[10px] font-mono mt-0.5" style={{ color: "#4a5a6b" }}>{label.toUpperCase()}</div>
            </div>
          ))}
        </div>
      )}
      {results.length > 0 ? (
        <div className="space-y-2">
          <div className="text-[10px] font-mono font-bold tracking-wider" style={{ color: "#4a5a6b" }}>SOURCE INFRASTRUCTURE NODES ({results.length})</div>
          {results.map((r, i) => <IPOriginCard key={i} result={r} index={i} />)}
        </div>
      ) : allIPs.length > 0 ? (
        <div className="space-y-2">
          <div className="text-[10px] font-mono font-bold tracking-wider" style={{ color: "#4a5a6b" }}>DETECTED IP ADDRESSES ({allIPs.length})</div>
          {allIPs.map((ip, i) => (
            <div key={i} className="flex items-center justify-between px-4 py-3 rounded-xl text-xs" style={{ background: "rgba(16,21,26,0.7)", border: "1px solid rgba(74,90,107,0.3)" }}>
              <div className="flex items-center gap-2">
                <Wifi className="h-3.5 w-3.5" style={{ color: ip.is_private ? "#4a5a6b" : "#3b82f6" }} />
                <span className="font-mono font-semibold" style={{ color: "#cfdbe4" }}>{ip.ip_address}</span>
                <CopyBtn value={ip.ip_address} />
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded" style={{ background: ip.is_private ? "rgba(74,90,107,0.15)" : "rgba(59,130,246,0.12)", color: ip.is_private ? "#4a5a6b" : "#3b82f6", border: `1px solid ${ip.is_private ? "rgba(74,90,107,0.3)" : "rgba(59,130,246,0.3)"}` }}>{ip.is_private ? "PRIVATE" : "PUBLIC"}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8 text-xs" style={{ color: "#4a5a6b" }}>
          <Globe2 className="h-8 w-8 mx-auto mb-2 opacity-40" />
          No IP addresses extracted from Received headers.
        </div>
      )}
      {publicResults.length > 0 && (
        <div className="rounded-xl px-4 py-3 flex items-start gap-3" style={{ background: "rgba(16,21,26,0.6)", border: "1px solid rgba(255,255,255,0.06)" }}>
          <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color: "#4a5a6b" }} />
          <div className="text-[11px]" style={{ color: "#7c8fa0" }}>
            <span className="font-mono font-bold" style={{ color: "#a9bac8" }}>ORIGIN CONFIDENCE: </span>
            IP geolocation is typically 95-99% accurate at country level, 55-80% at city level.
            VPNs, proxies, Tor exit nodes and cloud infrastructure may obscure the true origin.
            This panel establishes <span className="font-bold" style={{ color: "#e8a23d" }}>probable source infrastructure</span>, not a confirmed attacker location.
          </div>
        </div>
      )}
    </div>
  );
}

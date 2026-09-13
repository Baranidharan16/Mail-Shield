import React from "react";
import { Server, AlertTriangle, Cpu, CheckCircle2 } from "lucide-react";
import type { OriginTraceResult } from "../api/client";


interface EarliestObservableNodePanelProps {
  traceResult: OriginTraceResult | null;
  className?: string;
}

export const EarliestObservableNodePanel: React.FC<EarliestObservableNodePanelProps> = ({
  traceResult,
  className = "",
}) => {
  if (!traceResult) return null;

  const earliest = traceResult.earliest_node;
  const anomalies = traceResult.anomalies || [];

  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/80 p-5 backdrop-blur-md shadow-xl ${className}`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
            <Server className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              Earliest Reliable Observable Sending Node
              <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/30 font-mono">
                SIH Layer 3
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              The first non-forged, verifiable public mail relay node identified in the transmission path
            </p>
          </div>
        </div>

        {/* Verdict Badge */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-3 py-1 rounded-md bg-slate-800 text-slate-200 border border-slate-700">
            Type: <strong className="text-emerald-400">{traceResult.infrastructure_type}</strong>
          </span>
          <span className="text-xs font-mono px-3 py-1 rounded-md bg-slate-800 text-slate-200 border border-slate-700">
            Conf: <strong className="text-emerald-400">{Math.round(traceResult.confidence_score <= 1 ? traceResult.confidence_score * 100 : traceResult.confidence_score)}%</strong>
          </span>

        </div>
      </div>

      {/* Primary Details Grid */}
      {earliest ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-4">
          <div className="bg-slate-950/70 p-3.5 rounded-lg border border-slate-800/80">
            <span className="text-[11px] text-slate-500 uppercase tracking-wider block font-mono">Observed IP Address</span>
            <span className="text-base font-bold text-white font-mono mt-0.5 block">{earliest.ip_address}</span>
            <span className="text-xs text-slate-400 mt-1 block">
              Hop #{earliest.hop_index} • {earliest.protocol}
            </span>
          </div>

          <div className="bg-slate-950/70 p-3.5 rounded-lg border border-slate-800/80">
            <span className="text-[11px] text-slate-500 uppercase tracking-wider block font-mono">From / By Identifiers</span>
            <span className="text-xs font-medium text-slate-200 mt-0.5 block truncate" title={earliest.from_host || "N/A"}>
              From: {earliest.from_host || "N/A"}
            </span>
            <span className="text-xs text-slate-400 mt-0.5 block truncate" title={earliest.by_host || "N/A"}>
              By: {earliest.by_host || "N/A"}
            </span>
          </div>

          <div className="bg-slate-950/70 p-3.5 rounded-lg border border-slate-800/80">
            <span className="text-[11px] text-slate-500 uppercase tracking-wider block font-mono">Probable ISP & Hosting</span>
            <span className="text-xs font-medium text-slate-200 mt-0.5 block truncate">
              {earliest.geo_data?.isp || earliest.geo_data?.org || "Commercial Hosting Provider"}
            </span>
            <span className="text-xs text-slate-400 mt-0.5 block">
              {earliest.geo_data?.city ? `${earliest.geo_data.city}, ` : ""}{earliest.geo_data?.country || "International"}
            </span>
          </div>
        </div>
      ) : (
        <div className="my-4 p-4 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          No external public hops observed. The message originated entirely within an internal/private network.
        </div>
      )}

      {/* Summary Narrative */}
      <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/60 text-xs text-slate-300 leading-relaxed font-sans">
        <strong className="text-white">Forensic Attribution Verdict: </strong>
        {traceResult.summary_verdict}
      </div>

      {/* Header Relay Anomalies Checklist */}
      <div className="mt-4 pt-3 border-t border-slate-800/80">
        <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
          <Cpu className="h-3.5 w-3.5 text-slate-400" />
          Transmission Path Anomaly Detection
        </div>

        {anomalies.length > 0 ? (
          <div className="space-y-2">
            {anomalies.map((a, i) => (
              <div
                key={i}
                className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs flex items-start gap-2.5"
              >
                <AlertTriangle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
                <div>
                  <span className="font-semibold text-red-300">{a.type}</span>
                  <span className="text-slate-400 ml-2 text-[11px] font-mono">Severity: {a.severity}</span>
                  <p className="text-slate-300 text-[11px] mt-0.5">{a.description}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs flex items-center gap-2 text-emerald-300">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <span>Relay sequence verified: strict chronological order preserved, no forged or inverted timestamps detected.</span>
          </div>
        )}
      </div>
    </div>
  );
};

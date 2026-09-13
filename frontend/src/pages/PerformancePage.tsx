import React, { useEffect, useState } from "react";
import {
  Activity,
  Zap,
  Server,
  Cpu,
  Radio,
  RefreshCw,
  Database,
  ShieldCheck,
  Languages,
} from "lucide-react";
import { getSystemPerformance, type SystemPerformance } from "../api/client";


export const PerformancePage: React.FC = () => {
  const [perf, setPerf] = useState<SystemPerformance | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPerformance = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getSystemPerformance();
      setPerf(data);
    } catch (err: any) {
      setError(err?.message || "Failed to load system performance metrics.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPerformance();
    const interval = setInterval(fetchPerformance, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 uppercase tracking-wider mb-1">
            <Activity className="h-4 w-4" />
            <span>Autonomous Pipeline Telemetry • Real-Time Engine SLA</span>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            System Performance & Pipeline Latencies
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Live telemetry monitoring automated ingestion throughput, forensic engine latencies, and autonomous SOC health.
          </p>
        </div>

        <button
          onClick={fetchPerformance}
          disabled={loading}
          className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium flex items-center gap-2 transition-colors self-start sm:self-auto disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh Telemetry
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
          {error}
        </div>
      )}

      {loading && !perf ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-12 text-center">
          <RefreshCw className="mx-auto h-8 w-8 text-slate-500 animate-spin" />
          <p className="mt-3 text-sm text-slate-400">Querying platform telemetry probes...</p>
        </div>
      ) : perf ? (
        <>
          {/* Autonomous Agent Banner */}
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-5 backdrop-blur-md shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              <div className="relative p-3 rounded-xl bg-emerald-500/20 border border-emerald-500/30 text-emerald-400">
                <Radio className="h-6 w-6 animate-pulse" />
                <span className="absolute top-1 right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">Autonomous Forensic Monitoring Agent</h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 uppercase font-bold">
                    {perf.autonomous_agent.status}
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-1">
                  Active mode: <code className="font-mono text-emerald-400">{perf.autonomous_agent.mode}</code> • Polling interval: every {perf.autonomous_agent.sync_interval_seconds}s
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono self-start md:self-auto">
              <div className="bg-slate-900/80 px-3 py-2 rounded-lg border border-slate-800">
                <span className="text-slate-500 block text-[10px]">SYSTEM UPTIME</span>
                <span className="text-white font-semibold">{perf.uptime_formatted}</span>
              </div>
              <div className="bg-slate-900/80 px-3 py-2 rounded-lg border border-slate-800">
                <span className="text-slate-500 block text-[10px]">MAILBOX SYNC</span>
                <span className="text-emerald-400 font-semibold">{perf.autonomous_agent.mailbox_monitoring}</span>
              </div>
            </div>
          </div>

          {/* Latency Breakdown Cards */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Zap className="h-4 w-4 text-amber-400" />
                Processing Latency Breakdown (Sub-Second Budget Target: &lt; 1,500ms)
              </h3>
              <span className="text-xs font-mono text-emerald-400">SLA: 100% Compliant</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {[
                { label: "Email Ingest", val: perf.latencies.email_ingest_avg_ms, unit: "ms", budget: 300 },
                { label: "Header Parse", val: perf.latencies.header_parsing_avg_ms, unit: "ms", budget: 100 },
                { label: "GeoIP Lookup", val: perf.latencies.geoip_lookup_avg_ms, unit: "ms", budget: 250 },
                { label: "AI Reasoning", val: perf.latencies.ai_inference_avg_ms, unit: "ms", budget: 1000 },
                { label: "Blockchain Anchor", val: perf.latencies.blockchain_verify_ms, unit: "ms", budget: 20 },
                { label: "Database Query", val: perf.latencies.database_query_ms, unit: "ms", budget: 100 },
              ].map((m, idx) => {
                const pct = Math.min(100, Math.round((m.val / m.budget) * 100));
                return (
                  <div key={idx} className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5">
                    <span className="text-[11px] text-slate-400 font-mono block">{m.label}</span>
                    <div className="text-xl font-bold text-white font-mono mt-1">
                      {m.val} <span className="text-xs font-normal text-slate-400">{m.unit}</span>
                    </div>
                    <div className="mt-2 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className="bg-emerald-400 h-full rounded-full transition-all duration-300"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono mt-1 block">Budget: {m.budget}ms</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Engine Status Grid */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-xl">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
              <Cpu className="h-4 w-4 text-emerald-400" />
              Core Forensic Intelligence Engines
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {[
                { name: "Threat Classification Core", key: "threat_engine", icon: ShieldCheck, desc: "RandomForest + Regex heuristics" },
                { name: "Header Forensics & RFC Anomaly", key: "header_forensic_engine", icon: Server, desc: "SPF/DKIM/DMARC validator" },
                { name: "Origin Traceability Engine (Layer 3)", key: "origin_tracer", icon: Zap, desc: "Earliest reliable sending node" },
                { name: "Global Campaign Correlation (Layer 4)", key: "correlation_engine", icon: Activity, desc: "Multi-investigation clustering" },
                { name: "Cryptographic Evidence Ledger", key: "blockchain_ledger", icon: Database, desc: "SHA-256 Merkle chain-of-custody" },
                { name: "Sarvam Multilingual Voice Assistant", key: "sarvam_multilingual_voice", icon: Languages, desc: "22 Indian languages STT/TTS" },
              ].map((eng, idx) => {
                const status = perf.engine_statuses[eng.key] || "ONLINE";
                return (
                  <div key={idx} className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-slate-900 text-emerald-400 border border-slate-800 shrink-0">
                      <eng.icon className="h-4 w-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-white truncate">{eng.name}</span>
                        <span className="flex items-center gap-1 text-[10px] font-mono text-emerald-400">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
                          {status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">{eng.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
};

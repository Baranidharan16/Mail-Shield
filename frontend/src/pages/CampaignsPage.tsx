import React, { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import {
  Network,
  ShieldAlert,
  Layers,
  Server,
  Globe,
  RefreshCw,
  Radio,
  Share2,
  CheckCircle2,
  Search,
  Eye,
} from "lucide-react";

import {
  getCampaigns,
  getGlobalGraph,
  type CampaignItem,
  type GlobalGraphData,
  type CampaignCase,
  type CampaignAttribution,
} from "../api/client";

export const CampaignsPage: React.FC = () => {
  const [campaigns, setCampaigns] = useState<CampaignItem[]>([]);
  const [graphData, setGraphData] = useState<GlobalGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Real-time polling state
  const [liveSync, setLiveSync] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<string>(new Date().toLocaleTimeString());
  const [viewMode, setViewMode] = useState<"CLUSTERS" | "GRAPH">("CLUSTERS");
  const [searchQuery, setSearchQuery] = useState("");
  const pollTimerRef = useRef<any>(null);

  const fetchCampaignsAndGraph = async (isBackground = false) => {
    try {
      if (!isBackground) setLoading(true);
      else setRefreshing(true);
      setError(null);

      const [cData, gData] = await Promise.all([
        getCampaigns(),
        getGlobalGraph().catch(() => null),
      ]);

      setCampaigns(cData);
      if (gData) setGraphData(gData);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err: any) {
      setError(err?.message || "Failed to load real-time campaign correlations.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchCampaignsAndGraph(false);
  }, []);

  // Real-time automatic polling every 5 seconds when liveSync is enabled
  useEffect(() => {
    if (!liveSync) {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      return;
    }

    pollTimerRef.current = setInterval(() => {
      fetchCampaignsAndGraph(true);
    }, 5000);

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [liveSync]);

  // Aggregate high-level statistics
  const totalCases = campaigns.reduce((acc, c) => acc + c.case_count, 0);
  const totalDomains = new Set(campaigns.flatMap((c) => c.domains)).size;
  const totalIps = new Set(campaigns.flatMap((c) => c.ips)).size;

  // Filtered campaigns
  const filteredCampaigns = campaigns.filter((c) => {
    const q = searchQuery.toLowerCase();
    return (
      c.name.toLowerCase().includes(q) ||
      c.campaign_code.toLowerCase().includes(q) ||
      c.threat_class.toLowerCase().includes(q) ||
      c.domains.some((d) => d.toLowerCase().includes(q)) ||
      c.ips.some((ip) => ip.includes(q)) ||
      c.cases.some((cs) => cs.subject?.toLowerCase().includes(q) || cs.case_id?.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      {/* Top Header & Live Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 uppercase tracking-wider mb-1">
            <Network className="h-4 w-4" />
            <span>Cross-Investigation Correlation Engine • SIH 26106 Layer 4</span>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
            Threat Campaigns & Attack Clusters
            {liveSync && (
              <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono font-medium">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                LIVE SYNC
              </span>
            )}
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time multi-case attribution correlating shared domains, bulletproof infrastructure IPs, and threat kit indicators.
          </p>
        </div>

        {/* Action controls */}
        <div className="flex flex-wrap items-center gap-2.5 self-start md:self-auto">
          {/* Live Sync Toggle */}
          <button
            onClick={() => setLiveSync(!liveSync)}
            className={`px-3 py-2 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-colors ${
              liveSync
                ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300"
                : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
            }`}
          >
            <Radio className={`h-3.5 w-3.5 ${liveSync ? "animate-pulse text-emerald-400" : ""}`} />
            {liveSync ? "Live Polling (5s)" : "Polling Paused"}
          </button>

          {/* Manual Refresh */}
          <button
            onClick={() => fetchCampaignsAndGraph(false)}
            disabled={refreshing || loading}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing || loading ? "animate-spin text-emerald-400" : ""}`} />
            {refreshing ? "Correlating..." : "Scan Now"}
          </button>

          <span className="text-[11px] text-slate-500 font-mono hidden sm:inline-block">
            Updated: {lastUpdated}
          </span>
        </div>
      </div>

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] text-slate-400 uppercase font-mono block">Campaign Clusters</span>
          <div className="text-2xl font-bold text-white font-mono mt-1">{campaigns.length}</div>
          <span className="text-[10px] text-emerald-400 font-mono">Active Clusters</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] text-slate-400 uppercase font-mono block">Correlated Cases</span>
          <div className="text-2xl font-bold text-white font-mono mt-1">{totalCases}</div>
          <span className="text-[10px] text-slate-400 font-mono">Under Investigation</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] text-slate-400 uppercase font-mono block">Shared Domains</span>
          <div className="text-2xl font-bold text-blue-400 font-mono mt-1">{totalDomains}</div>
          <span className="text-[10px] text-slate-400 font-mono">Impersonation / Spoofed</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] text-slate-400 uppercase font-mono block">Threat Relay IPs</span>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-1">{totalIps}</div>
          <span className="text-[10px] text-slate-400 font-mono">Public Upstream Nodes</span>
        </div>
      </div>

      {/* Toolbar: Search + View Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-900/80 border border-slate-800 rounded-xl backdrop-blur-md">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search campaigns by code, domain, IP, threat class, or subject..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-1.5 self-end sm:self-auto bg-slate-950 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setViewMode("CLUSTERS")}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              viewMode === "CLUSTERS"
                ? "bg-slate-800 text-white shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            Campaign Cards ({filteredCampaigns.length})
          </button>
          <button
            onClick={() => setViewMode("GRAPH")}
            className={`px-3 py-1 rounded text-xs font-medium flex items-center gap-1.5 transition-colors ${
              viewMode === "GRAPH"
                ? "bg-slate-800 text-white shadow-sm"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Share2 className="h-3.5 w-3.5 text-emerald-400" />
            Global Attack Graph
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Loading state */}
      {loading ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-12 text-center">
          <RefreshCw className="mx-auto h-8 w-8 text-slate-500 animate-spin" />
          <p className="mt-3 text-sm text-slate-400">Scanning forensic cases for common threat infrastructure...</p>
        </div>
      ) : viewMode === "GRAPH" && graphData ? (
        /* Global Attack Graph View */
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-xl">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <div className="flex items-center gap-2">
              <Share2 className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">Unified Cross-Case Threat Correlation Graph</h3>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
              <span>{graphData.total_nodes} Entities</span>
              <span>•</span>
              <span>{graphData.total_links} Relationships</span>
            </div>
          </div>

          <div className="relative w-full h-96 bg-slate-950 rounded-lg border border-slate-800/80 p-4 overflow-hidden flex flex-col justify-between">
            {/* SVG Visual graph diagram */}
            <svg className="w-full h-full" viewBox="0 0 800 350">
              <defs>
                <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#10b981" stopOpacity="0.6" />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity="0.6" />
                </linearGradient>
              </defs>

              {/* Render dynamic links */}
              {graphData.links.slice(0, 40).map((_link, idx) => {
                const x1 = 120 + ((idx * 83) % 550);
                const y1 = 60 + ((idx * 67) % 220);
                const x2 = 180 + (((idx + 3) * 79) % 550);
                const y2 = 80 + (((idx + 5) * 71) % 220);
                return (
                  <line
                    key={idx}
                    x1={x1}
                    y1={y1}
                    x2={x2}
                    y2={y2}
                    stroke="url(#edgeGrad)"
                    strokeWidth="1.5"
                    strokeDasharray="4,3"
                    className="opacity-40"
                  />
                );
              })}

              {/* Render Nodes */}
              {graphData.nodes.slice(0, 30).map((node, idx) => {
                const x = 120 + ((idx * 83) % 550);
                const y = 60 + ((idx * 67) % 220);
                const isCase = node.type === "CASE";
                const isDom = node.type === "DOMAIN";


                return (
                  <g key={node.id} className="cursor-pointer group">
                    <circle
                      cx={x}
                      cy={y}
                      r={isCase ? 16 : 11}
                      fill={isCase ? "#ef4444" : isDom ? "#3b82f6" : "#f59e0b"}
                      fillOpacity={0.8}
                      stroke="#ffffff"
                      strokeWidth={1.5}
                      className="transition-transform group-hover:scale-125"
                    />
                    <text
                      x={x}
                      y={y + 24}
                      fill="#94a3b8"
                      fontSize="10"
                      textAnchor="middle"
                      className="font-mono select-none"
                    >
                      {node.label.length > 18 ? node.label.slice(0, 16) + "…" : node.label}
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* Graph Legend */}
            <div className="flex flex-wrap items-center gap-4 text-xs font-mono bg-slate-900/90 border border-slate-800 p-2.5 rounded-lg self-start">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
                <span className="text-slate-300">Forensic Cases</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
                <span className="text-slate-300">Impersonated Domains</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
                <span className="text-slate-300">Relay Infrastructure IPs</span>
              </div>
            </div>
          </div>
        </div>
      ) : filteredCampaigns.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-12 text-center">
          <Layers className="mx-auto h-8 w-8 text-slate-500" />
          <p className="mt-3 text-sm text-slate-300 font-medium">No Matching Threat Campaigns</p>
          <p className="text-xs text-slate-500 mt-1">
            Try adjusting your search criteria or load threat scenarios from the Email Analysis console.
          </p>
        </div>
      ) : (
        /* Campaign Cards List */
        <div className="grid grid-cols-1 gap-4">
          {filteredCampaigns.map((camp) => {
            const attr = typeof camp.attribution_support === "object" && camp.attribution_support !== null
              ? (camp.attribution_support as CampaignAttribution)
              : null;

            const isHighOrCrit = camp.threat_class === "CRITICAL" || camp.threat_class === "HIGH" || camp.average_risk_score >= 70;

            return (
              <div
                key={camp.campaign_code}
                className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-lg hover:border-slate-700 transition-colors"
              >
                {/* Campaign Header */}
                <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-slate-800/80 gap-3">
                  <div className="flex items-center gap-3">
                    <div className={`p-2.5 rounded-lg border ${
                      isHighOrCrit
                        ? "bg-red-500/10 border-red-500/20 text-red-400"
                        : "bg-indigo-500/10 border-indigo-500/20 text-indigo-400"
                    }`}>
                      <ShieldAlert className="h-5 w-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/30 font-bold">
                          {camp.campaign_code}
                        </span>
                        <h2 className="text-base font-semibold text-white">{camp.name}</h2>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Threat Class: <strong className="text-slate-200">{camp.threat_class}</strong>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 self-start md:self-auto">
                    <div className="text-right">
                      <div className="text-[10px] text-slate-400 uppercase font-mono">Linked Cases</div>
                      <div className="text-sm font-bold text-white font-mono">{camp.case_count} Cases</div>
                    </div>
                    <div className="text-right">
                      <div className="text-[10px] text-slate-400 uppercase font-mono">Avg Risk Score</div>
                      <div className={`text-sm font-bold font-mono ${
                        camp.average_risk_score >= 70 ? "text-red-400" : camp.average_risk_score >= 40 ? "text-amber-400" : "text-emerald-400"
                      }`}>
                        {camp.average_risk_score} / 100
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-[10px] text-slate-400 uppercase font-mono">Attribution Conf</div>
                      <div className="text-sm font-bold text-emerald-400 font-mono">{camp.confidence_percent}%</div>
                    </div>
                  </div>
                </div>

                {/* Attribution Support Evidence */}
                <div className="my-3 text-xs bg-slate-950/60 p-3 rounded-lg border border-slate-800/70">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-semibold text-slate-200 uppercase font-mono tracking-wide text-[11px]">
                      Attribution Analysis & Infrastructure Rationale:
                    </span>
                    {attr && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {attr.type}
                      </span>
                    )}
                  </div>
                  {attr && attr.reasons ? (
                    <ul className="space-y-1 text-slate-400 text-[11px]">
                      {attr.reasons.map((r, i) => (
                        <li key={i} className="flex items-center gap-1.5">
                          <CheckCircle2 className="h-3 w-3 text-emerald-400 shrink-0" />
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-slate-300 text-[11px]">{String(camp.attribution_support)}</p>
                  )}
                </div>

                {/* Infrastructure Indicators (Domains & IPs) */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 my-3">
                  <div className="bg-slate-950/40 p-3 rounded-lg border border-slate-800/60">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 mb-1.5 font-mono">
                      <Globe className="h-3.5 w-3.5 text-blue-400" />
                      Associated Domains ({camp.domains.length})
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {camp.domains.length > 0 ? (
                        camp.domains.map((dom, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded text-[11px] font-mono bg-blue-500/10 text-blue-300 border border-blue-500/20"
                          >
                            {dom}
                          </span>
                        ))
                      ) : (
                        <span className="text-[11px] text-slate-500 italic">No public domain extracted</span>
                      )}
                    </div>
                  </div>

                  <div className="bg-slate-950/40 p-3 rounded-lg border border-slate-800/60">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 mb-1.5 font-mono">
                      <Server className="h-3.5 w-3.5 text-amber-400" />
                      Observed Relay IPs ({camp.ips.length})
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {camp.ips.length > 0 ? (
                        camp.ips.map((ip, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/20"
                          >
                            {ip}
                          </span>
                        ))
                      ) : (
                        <span className="text-[11px] text-slate-500 italic">No external IPs observed</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Linked Cases List */}
                <div className="mt-3 pt-3 border-t border-slate-800/80">
                  <span className="text-[11px] text-slate-400 font-mono uppercase block mb-2 font-semibold">
                    Correlated Cases in this Campaign ({camp.cases.length}):
                  </span>
                  <div className="space-y-2">
                    {camp.cases.map((cs: CampaignCase, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-slate-950/50 border border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="font-mono text-emerald-400 font-medium shrink-0">
                            {cs.case_id}
                          </span>
                          <span className="text-slate-200 truncate font-medium" title={cs.subject}>
                            {cs.subject || "(No Subject)"}
                          </span>
                          <span className="text-slate-500 text-[11px] truncate hidden md:inline" title={cs.sender}>
                            from {cs.sender}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                            cs.classification === "CRITICAL"
                              ? "bg-red-500/20 text-red-300"
                              : cs.classification === "HIGH"
                              ? "bg-amber-500/20 text-amber-300"
                              : "bg-emerald-500/20 text-emerald-300"
                          }`}>
                            {cs.classification}
                          </span>
                          <span className="font-mono font-bold text-white text-[11px]">
                            {cs.risk_score}
                          </span>
                          <Link
                            to={`/investigations/${cs.investigation_id}`}
                            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors flex items-center gap-1"
                            title="Open Investigation"
                          >
                            <Eye className="h-3 w-3" />
                            <span className="text-[10px]">Open</span>
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

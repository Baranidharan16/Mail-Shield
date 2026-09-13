import React, { useState } from "react";
import { Globe, MapPin, AlertTriangle, Server, Navigation } from "lucide-react";
import type { OriginTraceResult, ObservableNode } from "../api/client";

interface InteractiveGeoMapProps {
  traceResult: OriginTraceResult | null;
  className?: string;
}

export const InteractiveGeoMap: React.FC<InteractiveGeoMapProps> = ({ traceResult, className = "" }) => {
  const [selectedNode, setSelectedNode] = useState<ObservableNode | null>(
    traceResult?.earliest_node || null
  );

  if (!traceResult) {
    return (
      <div className={`rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center ${className}`}>
        <Globe className="mx-auto h-8 w-8 text-slate-500 animate-spin" />
        <p className="mt-2 text-sm text-slate-400">Loading infrastructure relay topology...</p>
      </div>
    );
  }

  const nodes = traceResult.relay_path || [];

  // Convert real lat/lon to percentage coordinates on equirectangular SVG map
  // lat: 90 (top) to -90 (bottom) -> y% = ((90 - lat) / 180) * 100
  // lon: -180 (left) to 180 (right) -> x% = ((lon + 180) / 360) * 100
  // STRICT RULE: No fake or fabricated coordinates.
  const getCoords = (node: ObservableNode) => {
    const lat = node.geo_data?.lat;
    const lon = node.geo_data?.lon;

    if (typeof lat === "number" && typeof lon === "number" && !isNaN(lat) && !isNaN(lon)) {
      const x = Math.max(5, Math.min(95, ((lon + 180) / 360) * 100));
      const y = Math.max(10, Math.min(90, ((90 - lat) / 180) * 100));
      return { x, y, lat, lon, hasValidCoords: true };
    }
    return { x: 0, y: 0, lat: null, lon: null, hasValidCoords: false };
  };

  const geolocatedNodes = nodes.filter((n) => getCoords(n).hasValidCoords);
  const unlocatedCount = nodes.length - geolocatedNodes.length;

  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-xl ${className}`}>
      {/* Header with Title and Evidentiary Disclaimer */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Globe className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              Infrastructure Geolocation & Relay Path
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Layer 3 Traceability
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Visualizing observable mail relay hops and earliest upstream infrastructure
            </p>
          </div>
        </div>

        {/* Confidence Indicator */}
        <div className="flex items-center gap-3 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 self-start sm:self-auto">
          <div className="text-right">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Location Confidence</div>
            <div className="text-sm font-bold text-emerald-400 font-mono">
              {Math.round(traceResult.confidence_score <= 1 ? traceResult.confidence_score * 100 : traceResult.confidence_score)}%
            </div>
          </div>
          <div className="w-12 bg-slate-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-gradient-to-r from-amber-500 to-emerald-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.round(traceResult.confidence_score <= 1 ? traceResult.confidence_score * 100 : traceResult.confidence_score)}%` }}
            />
          </div>
        </div>
      </div>

      {/* Forensic Evidentiary Integrity Notice */}
      <div className="my-3 flex items-start gap-2.5 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs leading-relaxed">
        <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
        <div>
          <span className="font-semibold uppercase tracking-wide">Evidentiary Standard: </span>
          {traceResult.disclaimer || "Physical location cannot be determined with absolute certainty from public routing telemetry. Identifies probable infrastructure hosting location."}
        </div>
      </div>

      {/* Interactive Map Visualizer */}
      <div className="relative w-full h-72 sm:h-84 bg-slate-950 rounded-lg border border-slate-800/80 overflow-hidden my-4 flex items-center justify-center">
        {/* World Map SVG Canvas */}
        <svg
          viewBox="0 0 1000 500"
          className="w-full h-full opacity-60 pointer-events-none select-none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Grid pattern */}
          <defs>
            <pattern id="grid" width="50" height="50" patternUnits="userSpaceOnUse">
              <path d="M 50 0 L 0 0 0 50" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
            </pattern>
            <linearGradient id="relayGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" />
              <stop offset="50%" stopColor="#f59e0b" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.9" />
            </linearGradient>
          </defs>
          <rect width="1000" height="500" fill="url(#grid)" />

          {/* Equator & Meridians */}
          <line x1="0" y1="250" x2="1000" y2="250" stroke="rgba(255,255,255,0.05)" strokeDasharray="3,3" />
          <line x1="500" y1="0" x2="500" y2="500" stroke="rgba(255,255,255,0.05)" strokeDasharray="3,3" />

          {/* World Continents Stylized Silhouette */}
          <path
            d="M150 140 Q 220 120 280 150 T 260 260 T 170 240 Z M 270 300 Q 320 340 310 440 T 260 400 Z M 480 120 Q 560 100 620 150 T 540 240 Z M 490 260 Q 560 280 540 400 T 470 340 Z M 680 140 Q 860 120 880 260 T 700 300 Z M 760 350 Q 850 360 840 440 T 750 420 Z"
            fill="rgba(51, 65, 85, 0.35)"
          />

          {/* Connection Arc between real geolocated hops */}
          {geolocatedNodes.length > 1 && (
            <polyline
              points={geolocatedNodes
                .map((n) => {
                  const c = getCoords(n);
                  return `${c.x * 10},${c.y * 5}`;
                })
                .join(" ")}
              fill="none"
              stroke="url(#relayGradient)"
              strokeWidth="2.5"
              strokeDasharray="6,4"
              className="animate-pulse"
            />
          )}
        </svg>

        {/* Render Node Pins on Top */}
        <div className="absolute inset-0 pointer-events-auto">
          {nodes.map((node, idx) => {
            const coords = getCoords(node);
            if (!coords.hasValidCoords) return null;

            const isEarliest = node.is_earliest_reliable;
            const isSelected = selectedNode?.ip_address === node.ip_address;

            return (
              <div
                key={idx}
                style={{ left: `${coords.x}%`, top: `${coords.y}%` }}
                className="absolute -translate-x-1/2 -translate-y-1/2 cursor-pointer group z-10"
                onClick={() => setSelectedNode(node)}
              >
                {/* Radar pulse for earliest node */}
                {isEarliest && (
                  <span className="absolute -inset-2 rounded-full bg-red-500/30 animate-ping" />
                )}

                <div
                  className={`relative flex items-center justify-center w-7 h-7 rounded-full border shadow-lg transition-transform duration-200 group-hover:scale-125 ${
                    isEarliest
                      ? "bg-red-500/20 border-red-500 text-red-400"
                      : node.is_private
                      ? "bg-slate-800 border-slate-600 text-slate-400"
                      : "bg-emerald-500/20 border-emerald-500 text-emerald-400"
                  } ${isSelected ? "ring-2 ring-white scale-110" : ""}`}
                >
                  <MapPin className="h-3.5 w-3.5" />
                </div>

                {/* Tooltip on hover */}
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block bg-slate-900 text-[11px] text-white px-2 py-1 rounded shadow-md whitespace-nowrap border border-slate-700 pointer-events-none z-20">
                  <div className="font-bold">{isEarliest ? "Origin Candidate" : `Hop #${node.hop_index}`}</div>
                  <div>{node.ip_address}</div>
                  <div className="text-slate-400">{node.geo_data?.city ? `${node.geo_data.city}, ${node.geo_data.country}` : "Location available"}</div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Map Legend & Unresolved node status */}
        <div className="absolute bottom-2 left-2 flex flex-wrap items-center gap-3 bg-slate-950/90 px-3 py-1.5 rounded border border-slate-800 text-[11px] backdrop-blur-sm">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block animate-pulse"></span>
            <span className="text-slate-300">Probable Origin Candidate</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block"></span>
            <span className="text-slate-300">Public Mail Relay Node</span>
          </div>
          {unlocatedCount > 0 && (
            <div className="flex items-center gap-1 text-amber-400 text-[10px] border-l border-slate-800 pl-2">
              <AlertTriangle className="h-3 w-3" />
              <span>{unlocatedCount} hop(s) private/unresolved (location unavailable)</span>
            </div>
          )}
        </div>
      </div>

      {/* Selected Node Inspector Details */}
      {selectedNode && (
        <div className="bg-slate-950/80 rounded-lg p-4 border border-slate-800/90">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800/60">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-emerald-400" />
              <span className="text-xs uppercase tracking-wider text-slate-300 font-mono font-bold">
                {selectedNode.is_earliest_reliable ? "Origin Candidate Infrastructure" : `Relay Hop #${selectedNode.hop_index} Analysis`}
              </span>
            </div>
            <div className="flex items-center gap-2">
              {selectedNode.is_earliest_reliable ? (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                  EARLIEST OBSERVABLE
                </span>
              ) : null}
              <span
                className={`text-xs px-2 py-0.5 rounded font-mono ${
                  selectedNode.infrastructure_type === "CLOUD_VPS"
                    ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                    : selectedNode.infrastructure_type === "VPN_PROXY"
                    ? "bg-red-500/20 text-red-300 border border-red-500/30"
                    : "bg-slate-800 text-slate-300"
                }`}
              >
                {selectedNode.infrastructure_type || "ROUTING_RELAY"}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <div className="text-slate-500">IP Address</div>
              <div className="text-white font-mono font-medium">{selectedNode.ip_address || "Private RFC1918"}</div>
            </div>
            <div>
              <div className="text-slate-500">From Host / RDNS</div>
              <div className="text-slate-200 truncate" title={selectedNode.from_host || "N/A"}>
                {selectedNode.from_host || "N/A"}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Infrastructure Location</div>
              <div className="text-slate-200">
                {selectedNode.geo_data?.city || selectedNode.geo_data?.country ? (
                  `${selectedNode.geo_data?.city || "Unknown City"}, ${selectedNode.geo_data?.country || "Unknown Country"}`
                ) : (
                  <span className="text-slate-400 italic">Location unavailable</span>
                )}
              </div>
            </div>
            <div>
              <div className="text-slate-500">ISP / ASN</div>
              <div className="text-slate-200 truncate" title={selectedNode.geo_data?.isp || "N/A"}>
                {selectedNode.geo_data?.isp || selectedNode.geo_data?.asn || "N/A"}
              </div>
            </div>
          </div>

          {/* Network Classification Details */}
          <div className="mt-3 pt-2 border-t border-slate-900 grid grid-cols-3 gap-2 text-[11px] font-mono">
            <div className="flex items-center gap-1.5 text-slate-400">
              <span>VPN:</span>
              <span className="text-white">{selectedNode.infrastructure_type === "VPN_PROXY" ? "Possible" : "Not detected"}</span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-400">
              <span>Proxy:</span>
              <span className="text-white">Not detected</span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-400">
              <span>Tor Exit:</span>
              <span className="text-white">Not detected</span>
            </div>
          </div>
        </div>
      )}

      {/* Relay Path Timeline List */}
      <div className="mt-4 pt-3 border-t border-slate-800/80">
        <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Navigation className="h-3.5 w-3.5 text-emerald-400" />
            Chronological Transmission Sequence ({nodes.length} Hops Analyzed)
          </div>
          <span className="text-[10px] text-slate-400 font-mono">Earliest Sender $\to$ Destination</span>
        </div>
        <div className="space-y-2">
          {nodes.map((n, i) => (
            <div
              key={i}
              onClick={() => setSelectedNode(n)}
              className={`p-2.5 rounded-lg border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2 cursor-pointer transition-colors ${
                selectedNode?.ip_address === n.ip_address
                  ? "bg-slate-800/80 border-slate-600"
                  : "bg-slate-950/40 border-slate-800/60 hover:bg-slate-800/40"
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-slate-500">#{n.hop_index}</span>
                <span className="font-mono text-white font-medium">{n.ip_address || "Private IP"}</span>
                {n.is_earliest_reliable && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400 border border-red-500/30">
                    Origin Candidate
                  </span>
                )}
                <span className="text-slate-400 text-[11px] truncate max-w-xs">
                  {n.from_host ? `from ${n.from_host}` : ""}
                </span>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
                <span>{n.geo_data?.country || (n.is_private ? "Private RFC1918" : "Location unavailable")}</span>
                <span className="text-slate-600">•</span>
                <span>{n.protocol}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

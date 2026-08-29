import { useState, useRef } from "react";
import { Share2, ZoomIn, ZoomOut, RotateCcw, AlertTriangle, ShieldCheck, ShieldAlert, Key, Globe2, Link2, Server, User } from "lucide-react";
import type { AttackGraphData, GraphNode } from "../types/investigation";

import type { GeoResponse } from "../types/investigation";

interface Props {
  data: AttackGraphData | null;
  loading?: boolean;
  geo?: GeoResponse | null;
  onSelectOrigin?: () => void;
}

const TYPE_CONFIG: Record<string, { label: string; color: string; icon: any }> = {
  EMAIL:          { label: "EMAIL",          color: "#3ddc97", icon: ShieldAlert },
  IDENTITY:       { label: "IDENTITY",       color: "#6ee8b1", icon: User },
  SENDER:         { label: "SENDER",         color: "#6ee8b1", icon: User },
  REPLY_TO:       { label: "REPLY-TO",       color: "#f97316", icon: User },
  IP:             { label: "IP ADDRESS",     color: "#3b82f6", icon: Server },
  DOMAIN:         { label: "DOMAIN",         color: "#e8a23d", icon: Globe2 },
  URL:            { label: "URL",            color: "#f97316", icon: Link2 },
  AUTHENTICATION: { label: "AUTHENTICATION", color: "#8b5cf6", icon: Key },
  AUTH:           { label: "AUTHENTICATION", color: "#8b5cf6", icon: Key },
  THREAT:         { label: "THREAT",         color: "#e2483d", icon: AlertTriangle },
  RISK:           { label: "RISK LEVEL",     color: "#ff6b5e", icon: ShieldCheck },
};

function normType(t: string | undefined): string {
  if (!t) return "OTHER";
  const up = t.toUpperCase();
  if (up === "SENDER" || up === "REPLY_TO" || up === "IDENTITY") return "IDENTITY";
  if (up.startsWith("AUTH")) return "AUTHENTICATION";
  if (up === "THREAT" || up === "THREAT_CAT" || up === "INDICATOR") return "THREAT";
  if (up === "RISK") return "RISK";
  if (up === "IP") return "IP";
  if (up === "DOMAIN") return "DOMAIN";
  if (up === "URL") return "URL";
  if (up === "EMAIL") return "EMAIL";
  return up;
}

function getNodeColor(node: GraphNode): string {
  const ntype = normType(node.type);
  if (node.status === "PASS") return "#3ddc97";
  if (node.status === "FAIL" || node.status === "SOFTFAIL" || node.status === "PERMERROR") return "#e2483d";
  if (node.risk_score !== undefined && node.risk_score >= 70) return "#e2483d";
  if (node.risk_score !== undefined && node.risk_score >= 40) return "#f97316";
  return TYPE_CONFIG[ntype]?.color ?? "#7c8fa0";
}

function truncate(s: string, n = 22) {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

export default function AttackGraphPanel({ data, loading, geo, onSelectOrigin }: Props) {
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const containerRef = useRef<HTMLDivElement>(null);

  if (loading) {
    return (
      <div className="card-lab p-8 text-center text-lab-400 text-sm">
        <div className="h-6 w-6 border-2 border-phosphor-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
        Generating Attack Relationship Graph from analyzed email…
      </div>
    );
  }

  if (!data || !data.nodes || data.nodes.length === 0) {
    return (
      <div className="card-lab p-8 text-center text-lab-500 text-sm">
        <Share2 className="h-8 w-8 mx-auto mb-3 opacity-30 text-phosphor-500" />
        <div className="text-lab-300 font-medium">Attack Relationship Graph Not Yet Available</div>
        <div className="text-xs mt-1 text-lab-500">Graph generates automatically once an email is uploaded and analyzed.</div>
      </div>
    );
  }

  // Structured multi-layer layout:
  // Layer 0: Root Email (Center or Column 0)
  // Layer 1: Identity & Authentication
  // Layer 2: Infrastructure & URLs
  // Layer 3: Threat Indicators, Category & Final Risk
  const layers: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [] };

  data.nodes.forEach((n) => {
    const ntype = normType(n.type);
    if (ntype === "EMAIL") {
      layers[0].push(n);
    } else if (ntype === "IDENTITY" || ntype === "AUTHENTICATION") {
      layers[1].push(n);
    } else if (ntype === "IP" || ntype === "DOMAIN" || ntype === "URL") {
      layers[2].push(n);
    } else {
      layers[3].push(n);
    }
  });

  const W = 880;
  const H = 460;
  const colCount = 4;
  const colWidth = W / (colCount + 0.5);

  const nodePositions: Record<string, { x: number; y: number }> = {};

  [0, 1, 2, 3].forEach((colIdx) => {
    const colNodes = layers[colIdx];
    const x = colWidth * (colIdx + 0.7);
    const count = colNodes.length;
    colNodes.forEach((n, idx) => {
      const y = (H / (count + 1)) * (idx + 1);
      nodePositions[n.id] = { x, y };
    });
  });

  return (
    <div className="card-lab overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3.5 border-b border-lab-700 flex flex-wrap items-center justify-between gap-3 bg-lab-900/90">
        <div className="flex items-center gap-2.5">
          <Share2 className="h-4 w-4 text-phosphor-500" strokeWidth={1.75} />
          <div>
            <h2 className="font-semibold text-sm text-lab-200">Attack Relationship Graph</h2>
            <div className="text-[10px] text-lab-500 font-data">
              {data.nodes.length} entities · {data.edges.length} relationships
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setZoom((z) => Math.max(0.6, z - 0.1))}
            className="p-1.5 rounded text-lab-400 hover:text-lab-200 hover:bg-lab-800 transition-colors"
            title="Zoom out"
          >
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <span className="font-data text-xs text-lab-400 w-12 text-center">{Math.round(zoom * 100)}%</span>
          <button
            onClick={() => setZoom((z) => Math.min(1.8, z + 0.1))}
            className="p-1.5 rounded text-lab-400 hover:text-lab-200 hover:bg-lab-800 transition-colors"
            title="Zoom in"
          >
            <ZoomIn className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={() => setZoom(1)}
            className="p-1.5 rounded text-lab-400 hover:text-lab-200 hover:bg-lab-800 transition-colors"
            title="Reset view"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      <div ref={containerRef} className="relative overflow-auto bg-lab-950/70" style={{ height: 460 }}>
        <svg
          width={W * zoom}
          height={H * zoom}
          viewBox={`0 0 ${W} ${H}`}
          style={{ minWidth: "100%", display: "block" }}
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <marker id="arrow-green" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="#3ddc97" />
            </marker>
            <marker id="arrow-red" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="#e2483d" />
            </marker>
            <marker id="arrow-neutral" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="#4a5a6b" />
            </marker>

            {/* Glowing filter */}
            <filter id="glow-node" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Layer Background Guides */}
          {[
            { label: "TARGET EMAIL", x: colWidth * 0.7 },
            { label: "IDENTITY / AUTH", x: colWidth * 1.7 },
            { label: "INFRASTRUCTURE / URLS", x: colWidth * 2.7 },
            { label: "THREATS & RISK", x: colWidth * 3.7 },
          ].map((guide, idx) => (
            <g key={idx}>
              <line
                x1={guide.x}
                y1={20}
                x2={guide.x}
                y2={H - 20}
                stroke="#19212a"
                strokeWidth={1}
                strokeDasharray="4 4"
              />
              <text
                x={guide.x}
                y={18}
                textAnchor="middle"
                fontSize="9"
                fill="#2f3c4a"
                fontFamily="IBM Plex Mono"
                fontWeight="700"
                letterSpacing="0.08em"
              >
                {guide.label}
              </text>
            </g>
          ))}

          {/* Edges */}
          {data.edges.map((e, i) => {
            const src = nodePositions[e.source];
            const tgt = nodePositions[e.target];
            if (!src || !tgt) return null;

            const rel = e.relation || e.label || "";
            const isHighRiskEdge = rel.includes("MISMATCH") || rel.includes("THREAT") || rel.includes("CRITICAL") || rel.includes("FAIL");
            const strokeColor = isHighRiskEdge ? "#e2483d" : "#2f3c4a";
            const markerId = isHighRiskEdge ? "url(#arrow-red)" : "url(#arrow-neutral)";

            // Calculate bezier curve control points for smooth routing
            const dx = tgt.x - src.x;
            const cx1 = src.x + dx * 0.4;
            const cy1 = src.y;
            const cx2 = src.x + dx * 0.6;
            const cy2 = tgt.y;

            return (
              <g key={i}>
                <path
                  d={`M ${src.x} ${src.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${tgt.x} ${tgt.y}`}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={isHighRiskEdge ? 2 : 1.2}
                  markerEnd={markerId}
                  opacity={isHighRiskEdge ? 0.9 : 0.6}
                />
                {e.label && (
                  <text
                    x={(src.x + tgt.x) / 2}
                    y={(src.y + tgt.y) / 2 - 3}
                    textAnchor="middle"
                    fontSize="8.5"
                    fill={isHighRiskEdge ? "#ff6b5e" : "#4a5a6b"}
                    fontFamily="IBM Plex Mono"
                    fontWeight="600"
                  >
                    {e.label}
                  </text>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {data.nodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;

            const color = getNodeColor(node);
            const isSelected = selected?.id === node.id;
            const ntype = normType(node.type);
            const isRoot = ntype === "EMAIL";
            const r = isRoot ? 26 : isSelected ? 24 : 18;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                className="graph-node cursor-pointer"
                onClick={() => setSelected(isSelected ? null : node)}
              >
                {/* Outer halo */}
                <circle
                  r={r + 4}
                  fill="transparent"
                  stroke={color}
                  strokeWidth={isSelected ? 2 : 1}
                  strokeDasharray={isSelected ? "3 3" : "none"}
                  opacity={isSelected ? 0.8 : 0.25}
                />
                {/* Core node */}
                <circle
                  r={r}
                  fill="#10151a"
                  stroke={color}
                  strokeWidth={isRoot || isSelected ? 2.5 : 1.75}
                  filter="url(#glow-node)"
                />
                {/* Inner color dot */}
                <circle
                  r={isRoot ? 8 : 5}
                  fill={color}
                  opacity={0.85}
                />
                {/* Category tag */}
                <text
                  y={-(r + 6)}
                  textAnchor="middle"
                  fontSize="8"
                  fill={color}
                  fontFamily="IBM Plex Mono"
                  fontWeight="700"
                  letterSpacing="0.05em"
                >
                  {TYPE_CONFIG[ntype]?.label ?? ntype}
                </text>
                {/* Label text */}
                <text
                  y={r + 14}
                  textAnchor="middle"
                  fontSize="9"
                  fill={isSelected ? "#e8eef2" : "#a9bac8"}
                  fontFamily="IBM Plex Mono"
                  fontWeight={isSelected || isRoot ? "700" : "500"}
                >
                  {truncate(node.label || node.value || node.id, 24)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Selected Node Details Drawer */}
      {selected && (
        <div className="border-t border-lab-700 px-5 py-4 bg-lab-900/90 flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1 max-w-xl">
            <div className="flex items-center gap-2">
              <span
                className="status-pill text-[10px]"
                style={{
                  backgroundColor: `${getNodeColor(selected)}22`,
                  color: getNodeColor(selected),
                  borderColor: `${getNodeColor(selected)}44`,
                }}
              >
                {normType(selected.type)}
              </span>
              <span className="font-data font-bold text-sm text-lab-100">{selected.label}</span>
            </div>
            {selected.value && (
              <div className="font-data text-xs text-lab-400 break-all">{selected.value}</div>
            )}
            {selected.risk_score !== undefined && (
              <div className="text-xs text-lab-500">
                Entity Risk Contribution:{" "}
                <span className="font-data font-bold" style={{ color: getNodeColor(selected) }}>
                  {selected.risk_score.toFixed(0)}/100
                </span>
              </div>
            )}
            {normType(selected.type) === "IP" && (
              <div className="pt-2 border-t border-lab-800 mt-2">
                {(() => {
                  const ipResult = geo?.results?.find(r => r.ip_address === selected.label || r.ip_address === selected.value);
                  const g = ipResult?.geo as any;
                  return (
                    <div className="flex flex-wrap items-center gap-3 text-xs">
                      <span className="text-[10px] evidence-tag text-amber-signal bg-amber-signal/10 border border-amber-signal/30 px-2 py-0.5 rounded">
                        PROBABLE ORIGIN (RELAY)
                      </span>
                      {g && !g.error ? (
                        <span className="text-lab-300 font-data">
                          {[g.city, g.region, g.country].filter(Boolean).join(", ")} {g.asn ? `(${g.asn})` : ""}
                        </span>
                      ) : (
                        <span className="text-lab-500 italic">Network relay infrastructure node</span>
                      )}
                      {onSelectOrigin && (
                        <button
                          onClick={onSelectOrigin}
                          className="text-[11px] text-phosphor-400 hover:text-phosphor-300 font-mono underline ml-auto"
                        >
                          View Geolocation Intelligence Card ↓
                        </button>
                      )}
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
          <button
            onClick={() => setSelected(null)}
            className="text-xs text-lab-500 hover:text-lab-200 border border-lab-700 rounded px-2.5 py-1"
          >
            Close Details ✕
          </button>
        </div>
      )}

      {/* Interactive Legend */}
      <div className="border-t border-lab-700 px-5 py-2.5 flex flex-wrap items-center gap-4 bg-lab-850">
        <span className="text-[10px] text-lab-500 evidence-tag">ENTITY TYPES:</span>
        {Object.entries(TYPE_CONFIG).slice(0, 7).map(([key, cfg]) => (
          <div key={key} className="flex items-center gap-1.5 text-[10px] text-lab-400 font-data">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: cfg.color }} />
            {cfg.label}
          </div>
        ))}
      </div>
    </div>
  );
}

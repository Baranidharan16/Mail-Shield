/**
 * MailShield — Real Interactive Geolocation Map
 *
 * Leaflet with real map tiles (no API key): Street (OpenStreetMap),
 * Satellite (Esri World Imagery), Dark (CARTO) and Terrain (OpenTopoMap).
 * Renders the actual relay hops, the sender's client IP (when a submission
 * server stamped it) and the claimed sender domain's A/MX infrastructure,
 * all returned by the backend origin-trace endpoint.
 *
 * DATA INTEGRITY RULES:
 *  - Only renders real lat/lon from the API response; never fabricates coordinates.
 *  - Labels the origin candidate as "Probable Origin IP", never "Hacker Location".
 *  - "Location unavailable" is shown when geo data is missing.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import {
  Globe, MapPin, AlertTriangle, Server, Navigation, Maximize2, Minimize2, Crosshair, ShieldAlert,
} from "lucide-react";
import type { OriginTraceResult, ObservableNode, SenderInfraItem } from "../api/client";

interface InteractiveGeoMapProps {
  traceResult: OriginTraceResult | null;
  loading?: boolean;
  className?: string;
}

type BaseLayerKey = "street" | "satellite" | "dark" | "terrain";

const BASE_LAYERS: Record<BaseLayerKey, { label: string; url: string; attribution: string; maxZoom: number; subdomains?: string }> = {
  street: {
    label: "Street",
    url: "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    maxZoom: 19,
    subdomains: "abc",
  },
  satellite: {
    label: "Satellite",
    url: "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
    attribution: "Tiles &copy; Esri &mdash; Esri, Maxar, Earthstar Geographics, GIS User Community",
    maxZoom: 19,
  },
  dark: {
    label: "Dark",
    url: "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
    maxZoom: 20,
    subdomains: "abcd",
  },
  terrain: {
    label: "Terrain",
    url: "https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png",
    attribution: 'Map data &copy; OpenStreetMap contributors, SRTM | Style &copy; <a href="https://opentopomap.org">OpenTopoMap</a>',
    maxZoom: 17,
    subdomains: "abc",
  },
};
const FALLBACK_ORDER: BaseLayerKey[] = ["dark", "street", "satellite", "terrain"];

const hasCoords = (g?: { lat?: number | null; lon?: number | null } | null) =>
  !!g && typeof g.lat === "number" && typeof g.lon === "number" && !isNaN(g.lat) && !isNaN(g.lon);

const markerColor = (node: ObservableNode) => {
  if (node.is_earliest_reliable) return "#ef4444"; // red — origin candidate
  if (node.source === "client_ip_header") return "#f97316"; // orange — client IP
  if (node.is_private) return "#64748b"; // grey — private/RFC1918
  return "#10b981"; // green — relay hop
};

const esc = (v: unknown) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

function pulseIcon(color: string, size: number, pulse: boolean) {
  return L.divIcon({
    className: "",
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
    popupAnchor: [0, -size / 2],
    html: `<span class="ms-marker${pulse ? " ms-marker-pulse" : ""}" style="--c:${color};width:${size}px;height:${size}px"></span>`,
  });
}

function infraIcon() {
  return L.divIcon({
    className: "",
    iconSize: [16, 16],
    iconAnchor: [8, 8],
    popupAnchor: [0, -8],
    html: `<span class="ms-marker-infra"></span>`,
  });
}

export const InteractiveGeoMap: React.FC<InteractiveGeoMapProps> = ({ traceResult, loading, className = "" }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<L.Map | null>(null);
  const tileRef = useRef<L.TileLayer | null>(null);
  const boundsRef = useRef<L.LatLngBounds | null>(null);
  const failedLayers = useRef<Set<BaseLayerKey>>(new Set());
  const [selectedNode, setSelectedNode] = useState<ObservableNode | null>(traceResult?.earliest_node || null);
  const [baseLayer, setBaseLayer] = useState<BaseLayerKey>("dark");
  const [expanded, setExpanded] = useState(false);
  const [tileWarning, setTileWarning] = useState<string | null>(null);
  const [mapError, setMapError] = useState<string | null>(null);

  useEffect(() => {
    setSelectedNode(traceResult?.earliest_node || null);
  }, [traceResult]);

  const nodes = useMemo(() => traceResult?.relay_path || [], [traceResult]);
  const geoNodes = useMemo(() => nodes.filter((n) => hasCoords(n.geo_data)), [nodes]);
  const infra = useMemo(
    () => (traceResult?.sender_infrastructure || []).filter((i) => hasCoords(i.geo)),
    [traceResult],
  );
  const unlocatedCount = nodes.length - geoNodes.length;
  const hasAnything = geoNodes.length > 0 || infra.length > 0;

  // ---- Create the map ONCE per trace (synchronous; no async race) ----------
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !hasAnything) return;

    // A previous (StrictMode / fast refresh) instance may still own the node.
    if (mapRef.current) {
      mapRef.current.remove();
      mapRef.current = null;
    }
    delete (el as unknown as { _leaflet_id?: number })._leaflet_id;

    let map: L.Map;
    try {
      map = L.map(el, { scrollWheelZoom: false, zoomControl: true, attributionControl: true, worldCopyJump: true });
    } catch (err) {
      console.error("Leaflet map error:", err);
      setMapError("Interactive map could not be initialised in this browser.");
      return;
    }
    setMapError(null);
    mapRef.current = map;
    map.on("focus", () => map.scrollWheelZoom.enable());
    map.on("blur", () => map.scrollWheelZoom.disable());

    const latLngs: L.LatLngTuple[] = [];

    geoNodes.forEach((node) => {
      const lat = node.geo_data!.lat!;
      const lon = node.geo_data!.lon!;
      latLngs.push([lat, lon]);
      const color = markerColor(node);
      const g = node.geo_data!;
      const role = node.is_earliest_reliable
        ? "Probable Origin IP Candidate"
        : node.source === "client_ip_header"
        ? "Sender Client IP"
        : `Relay Hop #${node.hop_index}`;
      const rep = node.reputation;
      const repLine = rep?.checked
        ? rep.listed_on && rep.listed_on.length
          ? `<div style="color:#dc2626"><b>DNSBL:</b> listed on ${esc(rep.listed_on.join(", "))}</div>`
          : `<div><b>DNSBL:</b> not listed</div>`
        : "";
      const marker = L.marker([lat, lon], {
        icon: pulseIcon(color, node.is_earliest_reliable ? 20 : 14, !!node.is_earliest_reliable),
        zIndexOffset: node.is_earliest_reliable ? 1000 : 0,
        keyboard: true,
        title: `${role} ${node.ip_address || ""}`,
      }).addTo(map);
      marker.bindPopup(`
        <div style="font-size:12px;min-width:220px;line-height:1.6">
          <div style="font-weight:700;margin-bottom:4px;color:${color}">${esc(role)}</div>
          <div><b>IP:</b> ${esc(node.ip_address || "Private")}</div>
          <div><b>Location:</b> ${esc(g.city || "Unknown city")}, ${esc(g.region ? g.region + ", " : "")}${esc(g.country || "Unknown country")}</div>
          <div><b>ISP / Org:</b> ${esc(g.isp || g.org || g.asn || "Unknown")}</div>
          ${g.asn ? `<div><b>ASN:</b> ${esc(g.asn)}</div>` : ""}
          ${node.from_host ? `<div><b>Host:</b> ${esc(node.from_host)}</div>` : ""}
          ${node.infrastructure_type ? `<div><b>Infra:</b> ${esc(node.infrastructure_type)}</div>` : ""}
          ${g.proxy ? `<div style="color:#dc2626"><b>Proxy / VPN / Tor flag</b></div>` : ""}
          ${repLine}
          <div style="color:#94a3b8;font-size:10px;margin-top:6px">Lat ${lat.toFixed(3)} / Lon ${lon.toFixed(3)} · ${esc(g.source || "GeoIP")}</div>
          ${node.is_earliest_reliable ? `<div style="background:#fef3c7;color:#92400e;padding:3px 6px;border-radius:4px;font-size:10px;margin-top:6px">Physical location cannot be determined with certainty. This is the earliest observable IP in the path.</div>` : ""}
        </div>`);
      marker.on("click", () => setSelectedNode(node));
    });

    // Chronological relay path, animated
    if (latLngs.length > 1) {
      L.polyline(latLngs, { color: "#f59e0b", weight: 3, opacity: 0.9, dashArray: "10 8", className: "ms-relay-path" }).addTo(map);
    }

    // Claimed-sender domain infrastructure (DNS A / MX)
    infra.forEach((it: SenderInfraItem) => {
      const g = it.geo!;
      const ll: L.LatLngTuple = [g.lat!, g.lon!];
      latLngs.push(ll);
      L.marker(ll, { icon: infraIcon(), title: `${it.record} ${it.host}` })
        .addTo(map)
        .bindPopup(`
          <div style="font-size:12px;min-width:220px;line-height:1.6">
            <div style="font-weight:700;margin-bottom:4px;color:#a855f7">Sender domain infrastructure (${esc(it.record)})</div>
            <div><b>Domain:</b> ${esc(it.domain)} <span style="color:#94a3b8">(${esc(String(it.role).replace(/_/g, " ").toLowerCase())})</span></div>
            <div><b>Host:</b> ${esc(it.host)}</div>
            <div><b>IP:</b> ${esc(it.ip)}</div>
            <div><b>Location:</b> ${esc(g.city || "Unknown city")}, ${esc(g.country || "Unknown country")}</div>
            <div><b>Hosting:</b> ${esc(g.isp || g.org || "Unknown")}</div>
          </div>`);
    });

    if (latLngs.length === 1) {
      map.setView(latLngs[0], 5);
      boundsRef.current = L.latLngBounds(latLngs);
    } else {
      const b = L.latLngBounds(latLngs);
      boundsRef.current = b;
      map.fitBounds(b, { padding: [40, 40], maxZoom: 7 });
    }

    // Keep tiles correct when the card is resized / revealed after layout.
    const ro = new ResizeObserver(() => map.invalidateSize());
    ro.observe(el);
    const t = window.setTimeout(() => map.invalidateSize(), 250);

    return () => {
      window.clearTimeout(t);
      ro.disconnect();
      map.remove();
      if (mapRef.current === map) mapRef.current = null;
      tileRef.current = null;
    };
  }, [geoNodes, infra, hasAnything]);

  // ---- Base layer (swap without rebuilding markers) + automatic fallback ----
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;
    const cfg = BASE_LAYERS[baseLayer];
    if (tileRef.current) map.removeLayer(tileRef.current);
    let errors = 0;
    const layer = L.tileLayer(cfg.url, {
      attribution: cfg.attribution,
      maxZoom: cfg.maxZoom,
      subdomains: cfg.subdomains || "abc",
    });
    let loaded = 0;
    layer.on("tileload", () => { loaded += 1; });
    layer.on("tileerror", () => {
      errors += 1;
      if (errors === 6 && loaded === 0) {
        failedLayers.current.add(baseLayer);
        const next = FALLBACK_ORDER.find((k) => !failedLayers.current.has(k));
        if (next) {
          setTileWarning(`${cfg.label} tiles are not loading on this network — switched to ${BASE_LAYERS[next].label}.`);
          setBaseLayer(next);
        } else {
          setTileWarning("Map tiles are blocked on this network — markers and relay path are still shown.");
        }
      }
    });
    layer.on("load", () => { if (loaded > 0) setTileWarning(null); });
    layer.addTo(map);
    tileRef.current = layer;
  }, [baseLayer, geoNodes, infra]);

  useEffect(() => {
    const id = window.setTimeout(() => mapRef.current?.invalidateSize(), 220);
    return () => window.clearTimeout(id);
  }, [expanded]);

  const flyTo = (n: ObservableNode) => {
    setSelectedNode(n);
    if (mapRef.current && hasCoords(n.geo_data)) {
      mapRef.current.flyTo([n.geo_data!.lat!, n.geo_data!.lon!], 8, { duration: 1.2 });
    }
  };

  if (loading || (!traceResult && loading !== false)) {
    return (
      <div className={`rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center ${className}`}>
        <Globe className="mx-auto h-8 w-8 text-slate-500 animate-spin" />
        <p className="mt-2 text-sm text-slate-400">Loading infrastructure relay topology...</p>
      </div>
    );
  }

  if (!traceResult) {
    return (
      <div className={`rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center ${className}`}>
        <MapPin className="mx-auto h-8 w-8 text-slate-600" />
        <p className="mt-2 text-sm text-slate-300 font-medium">Relay Infrastructure Trace Unavailable</p>
        <p className="mt-1 text-xs text-slate-500">No external routing hops or observable public origin could be retrieved for this email.</p>
      </div>
    );
  }

  const confidence = traceResult.confidence_score <= 1 ? traceResult.confidence_score * 100 : traceResult.confidence_score;
  const sel = selectedNode;
  const selRep = sel?.reputation;

  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-xl ${className}`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Globe className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white flex items-center gap-2 flex-wrap">
              Infrastructure Geolocation &amp; Sender Trace
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Live map
              </span>
              {traceResult.client_origin_detected && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-orange-500/10 text-orange-300 border border-orange-500/30">
                  Sender client IP found
                </span>
              )}
            </h3>
            <p className="text-xs text-slate-400">
              Real IP geolocation of relay hops, sender client IP and sender-domain DNS infrastructure
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 self-start sm:self-auto">
          <div className="text-right">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Location Confidence</div>
            <div className="text-sm font-bold text-emerald-400 font-mono">{Math.round(confidence)}%</div>
          </div>
          <div className="w-12 bg-slate-800 rounded-full h-2 overflow-hidden">
            <div className="bg-gradient-to-r from-amber-500 to-emerald-400 h-full rounded-full transition-all duration-500" style={{ width: `${Math.round(confidence)}%` }} />
          </div>
        </div>
      </div>

      {/* Evidentiary Disclaimer */}
      <div className="my-3 flex items-start gap-2.5 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs leading-relaxed">
        <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
        <div>
          <span className="font-semibold uppercase tracking-wide">Evidentiary Standard: </span>
          {traceResult.disclaimer ||
            "Physical location cannot be determined with absolute certainty from public routing telemetry. Identifies probable infrastructure hosting location only. Do not use as sole evidence."}
        </div>
      </div>

      {/* Hop Summary Stats */}
      <div className="flex flex-wrap gap-2 mb-3 text-xs">
        <div className="flex items-center gap-1.5 bg-slate-900/50 rounded px-2 py-1 border border-slate-800">
          <span className="w-2 h-2 rounded-full bg-slate-500 inline-block" />
          <span className="text-slate-400">Total Hops:</span>
          <span className="text-white font-mono font-medium">{nodes.length}</span>
        </div>
        <div className="flex items-center gap-1.5 bg-slate-900/50 rounded px-2 py-1 border border-slate-800">
          <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
          <span className="text-slate-400">Geolocated:</span>
          <span className="text-white font-mono font-medium">{geoNodes.length}</span>
        </div>
        {infra.length > 0 && (
          <div className="flex items-center gap-1.5 bg-slate-900/50 rounded px-2 py-1 border border-purple-800/40">
            <span className="w-2 h-2 rounded-sm bg-purple-500 inline-block" />
            <span className="text-slate-400">Sender-domain servers:</span>
            <span className="text-white font-mono font-medium">{infra.length}</span>
          </div>
        )}
        {unlocatedCount > 0 && (
          <div className="flex items-center gap-1.5 bg-slate-900/50 rounded px-2 py-1 border border-amber-800/40">
            <AlertTriangle className="h-3 w-3 text-amber-400" />
            <span className="text-amber-400">{unlocatedCount} private/unresolved</span>
          </div>
        )}
      </div>

      {/* Map */}
      <div className="relative w-full rounded-lg overflow-hidden border border-slate-700/60 my-2">
        {!hasAnything ? (
          <div className="h-64 flex flex-col items-center justify-center bg-slate-900/80 text-slate-400 text-sm gap-2 px-6 text-center">
            <MapPin className="h-8 w-8 text-slate-600" />
            <p>No geolocatable hops — all IPs are private/RFC1918 or the GeoIP service was unreachable.</p>
          </div>
        ) : (
          <>
            <div
              ref={containerRef}
              style={{ height: expanded ? "620px" : "380px", width: "100%", zIndex: 0, transition: "height .2s ease" }}
              id="mailshield-relay-map"
              className="ms-map bg-slate-950"
            />
            {mapError && (
              <div className="absolute inset-0 flex items-center justify-center bg-slate-900/90 text-red-400 text-sm">{mapError}</div>
            )}
            {/* Map toolbar */}
            <div className="absolute top-2 right-2 z-[500] flex flex-col items-end gap-1.5">
              <div className="flex rounded-md overflow-hidden border border-slate-700 bg-slate-950/85 backdrop-blur text-[11px] font-mono">
                {(Object.keys(BASE_LAYERS) as BaseLayerKey[]).map((k) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setBaseLayer(k)}
                    className={`px-2 py-1 transition-colors ${baseLayer === k ? "bg-emerald-500/25 text-emerald-300" : "text-slate-300 hover:bg-slate-800"}`}
                  >
                    {BASE_LAYERS[k].label}
                  </button>
                ))}
              </div>
              <div className="flex gap-1.5">
                <button
                  type="button"
                  title="Fit all points"
                  onClick={() => boundsRef.current && mapRef.current?.fitBounds(boundsRef.current, { padding: [40, 40], maxZoom: 7 })}
                  className="p-1.5 rounded-md border border-slate-700 bg-slate-950/85 text-slate-300 hover:text-white"
                >
                  <Crosshair className="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  title={expanded ? "Collapse map" : "Expand map"}
                  onClick={() => setExpanded((v) => !v)}
                  className="p-1.5 rounded-md border border-slate-700 bg-slate-950/85 text-slate-300 hover:text-white"
                >
                  {expanded ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>
            {tileWarning && (
              <div className="absolute bottom-2 left-2 z-[500] text-[11px] px-2 py-1 rounded bg-slate-950/90 text-amber-300 border border-amber-500/40">
                {tileWarning}
              </div>
            )}
          </>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3 text-[11px] mt-2 mb-4">
        <div className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-red-500 inline-block" /><span className="text-slate-300">Probable Origin Candidate</span></div>
        <div className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-orange-500 inline-block" /><span className="text-slate-300">Sender Client IP</span></div>
        <div className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-emerald-400 inline-block" /><span className="text-slate-300">Public Mail Relay</span></div>
        <div className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-purple-500 inline-block" /><span className="text-slate-300">Sender Domain A/MX</span></div>
        <div className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-slate-500 inline-block" /><span className="text-slate-300">Private RFC1918</span></div>
        <div className="flex items-center gap-1.5"><span className="w-6 border-t-2 border-dashed border-amber-400 inline-block" /><span className="text-slate-300">Relay Path</span></div>
      </div>

      {/* Selected Node Inspector */}
      {sel && (
        <div className="bg-slate-950/80 rounded-lg p-4 border border-slate-800/90">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800/60 gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-emerald-400" />
              <span className="text-xs uppercase tracking-wider text-slate-300 font-mono font-bold">
                {sel.is_earliest_reliable
                  ? "Origin Candidate Infrastructure"
                  : sel.source === "client_ip_header"
                  ? "Sender Client IP"
                  : `Relay Hop #${sel.hop_index} Analysis`}
              </span>
            </div>
            <div className="flex items-center gap-2">
              {sel.is_earliest_reliable && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">EARLIEST OBSERVABLE</span>
              )}
              {sel.infrastructure_type && (
                <span
                  className={`text-xs px-2 py-0.5 rounded font-mono ${
                    sel.infrastructure_type === "CLOUD_VPS"
                      ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                      : sel.infrastructure_type === "VPN_PROXY"
                      ? "bg-red-500/20 text-red-300 border border-red-500/30"
                      : sel.infrastructure_type === "MAIL_PROVIDER"
                      ? "bg-sky-500/15 text-sky-300 border border-sky-500/30"
                      : "bg-slate-800 text-slate-300"
                  }`}
                >
                  {sel.infrastructure_type}
                </span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <div className="text-slate-500">IP Address</div>
              <div className="text-white font-mono font-medium">{sel.ip_address || "Private RFC1918"}</div>
            </div>
            <div>
              <div className="text-slate-500">{sel.source === "client_ip_header" ? "Evidence Header" : "From Host / RDNS"}</div>
              <div className="text-slate-200 truncate" title={sel.from_host || "N/A"}>{sel.from_host || "N/A"}</div>
            </div>
            <div>
              <div className="text-slate-500">Infrastructure Location</div>
              <div className="text-slate-200">
                {sel.geo_data?.city || sel.geo_data?.country ? (
                  `${sel.geo_data?.city || "Unknown City"}, ${sel.geo_data?.country || "Unknown Country"}`
                ) : (
                  <span className="text-slate-400 italic">Location unavailable</span>
                )}
              </div>
            </div>
            <div>
              <div className="text-slate-500">ISP / ASN</div>
              <div className="text-slate-200 truncate" title={sel.geo_data?.isp || "N/A"}>
                {sel.geo_data?.isp || sel.geo_data?.asn || "N/A"}
              </div>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-xs">
            <div className="flex items-center gap-1.5 text-slate-400">
              <span>Proxy / VPN / Tor:</span>
              <span className={sel.geo_data?.proxy ? "text-red-400 font-semibold" : "text-white"}>
                {sel.geo_data ? (sel.geo_data.proxy ? "Flagged" : "Not flagged") : "Unknown"}
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-400">
              <span>Hosting / Data-centre:</span>
              <span className="text-white">{sel.geo_data ? (sel.geo_data.hosting ? "Yes" : "No") : "Unknown"}</span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-400">
              <ShieldAlert className="h-3.5 w-3.5" />
              <span>DNS blocklists:</span>
              <span className={selRep?.listed_on?.length ? "text-red-400 font-semibold" : "text-white"}>
                {!selRep?.checked
                  ? "Not checked"
                  : selRep.listed_on && selRep.listed_on.length
                  ? `Listed (${selRep.listed_on.join(", ")})`
                  : "Clean"}
              </span>
            </div>
            {sel.geo_data?.source && (
              <div className="flex items-center gap-1.5 text-slate-500">
                <span>GeoIP source:</span>
                <span className="text-slate-300">{sel.geo_data.source}</span>
              </div>
            )}
          </div>
          {sel.flags && sel.flags.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {sel.flags.map((f, i) => (
                <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">{f}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Relay Path Timeline */}
      <div className="mt-4 pt-3 border-t border-slate-800/80">
        <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Navigation className="h-3.5 w-3.5 text-emerald-400" />
            Chronological Transmission Sequence ({nodes.length} Hops Analyzed)
          </div>
          <span className="text-[10px] text-slate-400 font-mono">Earliest Sender → Destination</span>
        </div>
        <div className="space-y-2">
          {nodes.map((n, i) => (
            <div
              key={i}
              onClick={() => flyTo(n)}
              className={`p-2.5 rounded-lg border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2 cursor-pointer transition-colors ${
                sel?.ip_address === n.ip_address && sel?.hop_index === n.hop_index
                  ? "bg-slate-800/80 border-slate-600"
                  : "bg-slate-950/40 border-slate-800/60 hover:bg-slate-800/40"
              }`}
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className="font-mono text-slate-500">{n.source === "client_ip_header" ? "CLIENT" : `#${n.hop_index}`}</span>
                <span className="font-mono text-white font-medium">{n.ip_address || "Private IP"}</span>
                {n.is_earliest_reliable && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400 border border-red-500/30">Origin Candidate</span>
                )}
                {n.reputation?.listed_on && n.reputation.listed_on.length > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-300 border border-red-500/30">Blocklisted</span>
                )}
                <span className="text-slate-400 text-[11px] truncate max-w-xs">{n.from_host ? `from ${n.from_host}` : ""}</span>
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

      {/* Sender domain infrastructure table */}
      {(traceResult.sender_infrastructure || []).length > 0 && (
        <div className="mt-4 pt-3 border-t border-slate-800/80">
          <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
            <Server className="h-3.5 w-3.5 text-purple-400" />
            Claimed Sender Domain Infrastructure (live DNS A / MX)
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {(traceResult.sender_infrastructure || []).map((it, i) => (
              <div key={i} className="p-2.5 rounded-lg border border-slate-800/60 bg-slate-950/40 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-white truncate">{it.host}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">{it.record}</span>
                </div>
                <div className="text-slate-400 font-mono mt-0.5">{it.ip}</div>
                <div className="text-slate-400 mt-0.5">
                  {it.geo ? `${it.geo.city || "Unknown city"}, ${it.geo.country || "Unknown country"} · ${it.geo.isp || it.geo.org || ""}` : "Location unavailable"}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">{it.domain} · {String(it.role).replace(/_/g, " ").toLowerCase()}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

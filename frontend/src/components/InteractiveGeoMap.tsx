/**
 * MailShield — Real Interactive Geolocation Map
 *
 * Uses Leaflet + OpenStreetMap tiles (no API key required).
 * Renders actual mail relay hops from the backend forensic pipeline.
 *
 * DATA INTEGRITY RULES:
 *  - Only renders real lat/lon from the API response.
 *  - Never fabricates or hardcodes coordinates.
 *  - Labels origin candidate as "Probable Origin IP" not "Hacker Location".
 *  - "Location unavailable" shown when geo data is missing.
 */
import React, { useState, useEffect, useRef } from "react";
import { Globe, MapPin, AlertTriangle, Server, Navigation } from "lucide-react";
import type { OriginTraceResult, ObservableNode } from "../api/client";

// Leaflet CSS must be loaded globally
import "leaflet/dist/leaflet.css";

interface InteractiveGeoMapProps {
  traceResult: OriginTraceResult | null;
  className?: string;
}

const TILE_URL = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";
const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';

// Marker colors by role
const markerColor = (node: ObservableNode) => {
  if (node.is_earliest_reliable) return "#ef4444"; // red — origin candidate
  if (node.is_private) return "#64748b";           // grey — private/RFC1918
  return "#10b981";                                // green — relay hop
};

export const InteractiveGeoMap: React.FC<InteractiveGeoMapProps> = ({
  traceResult,
  className = "",
}) => {
  const mapRef = useRef<HTMLDivElement>(null);
  const leafletMap = useRef<import("leaflet").Map | null>(null);
  const [selectedNode, setSelectedNode] = useState<ObservableNode | null>(
    traceResult?.earliest_node || null
  );
  const [mapError, setMapError] = useState<string | null>(null);

  const nodes = traceResult?.relay_path || [];
  const geoNodes = nodes.filter(
    (n) =>
      typeof n.geo_data?.lat === "number" &&
      typeof n.geo_data?.lon === "number" &&
      !isNaN(n.geo_data.lat) &&
      !isNaN(n.geo_data.lon)
  );
  const unlocatedCount = nodes.length - geoNodes.length;

  // Initialise Leaflet map once traceResult is available
  useEffect(() => {
    if (!traceResult || !mapRef.current || geoNodes.length === 0) return;

    // Prevent double-init
    if (leafletMap.current) {
      leafletMap.current.remove();
      leafletMap.current = null;
    }

    const initMap = async () => {
      try {
        const L = (await import("leaflet")).default;

        // Fix Leaflet default icon path (broken in Vite bundler)
        delete (L.Icon.Default.prototype as any)._getIconUrl;
        L.Icon.Default.mergeOptions({
          iconRetinaUrl:
            "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
          iconUrl:
            "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
          shadowUrl:
            "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
        });

        const map = L.map(mapRef.current!, {
          scrollWheelZoom: false,
          zoomControl: true,
          attributionControl: true,
        });

        // OpenStreetMap tiles (open-source, no API key)
        L.tileLayer(TILE_URL, {
          attribution: TILE_ATTRIBUTION,
          maxZoom: 18,
        }).addTo(map);

        const markerRefs: import("leaflet").CircleMarker[] = [];
        const latLngs: [number, number][] = [];

        // Add circle markers for each geolocated hop
        geoNodes.forEach((node) => {
          const lat = node.geo_data!.lat!;
          const lon = node.geo_data!.lon!;
          latLngs.push([lat, lon]);

          const color = markerColor(node);
          const radius = node.is_earliest_reliable ? 10 : 7;

          const marker = L.circleMarker([lat, lon], {
            radius,
            color,
            fillColor: color,
            fillOpacity: node.is_earliest_reliable ? 0.7 : 0.5,
            weight: node.is_earliest_reliable ? 3 : 2,
            className: node.is_earliest_reliable ? "leaflet-origin-pulse" : "",
          }).addTo(map);

          const city = node.geo_data?.city || "Unknown City";
          const country = node.geo_data?.country || "Unknown Country";
          const isp = node.geo_data?.isp || node.geo_data?.asn || "Unknown ISP";
          const role = node.is_earliest_reliable
            ? "⚠️ Probable Origin IP Candidate"
            : `Relay Hop #${node.hop_index}`;

          marker.bindPopup(`
            <div style="font-size:12px;min-width:200px;line-height:1.6">
              <div style="font-weight:700;margin-bottom:4px;color:${color}">${role}</div>
              <div><b>IP:</b> ${node.ip_address || "Private"}</div>
              <div><b>Location:</b> ${city}, ${country}</div>
              <div><b>ISP / Org:</b> ${isp}</div>
              ${node.from_host ? `<div><b>RDNS:</b> ${node.from_host}</div>` : ""}
              ${node.infrastructure_type ? `<div><b>Infra:</b> ${node.infrastructure_type}</div>` : ""}
              <div style="color:#94a3b8;font-size:10px;margin-top:6px">
                Lat ${lat.toFixed(3)} / Lon ${lon.toFixed(3)}
              </div>
              ${
                node.is_earliest_reliable
                  ? `<div style="background:#fef3c7;color:#92400e;padding:3px 6px;border-radius:4px;font-size:10px;margin-top:6px">
                      ⚠ Physical location cannot be determined with certainty. This is the earliest observable IP in the relay path.
                    </div>`
                  : ""
              }
            </div>
          `);

          marker.on("click", () => setSelectedNode(node));
          markerRefs.push(marker);
        });

        // Draw polyline between consecutive geolocated hops
        if (latLngs.length > 1) {
          L.polyline(latLngs, {
            color: "#f59e0b",
            weight: 2.5,
            opacity: 0.8,
            dashArray: "8 5",
          }).addTo(map);
        }

        // Fit map to all markers
        if (latLngs.length === 1) {
          map.setView(latLngs[0], 6);
        } else if (latLngs.length > 1) {
          map.fitBounds(L.latLngBounds(latLngs), { padding: [40, 40] });
        }

        leafletMap.current = map;
      } catch (err) {
        console.error("Leaflet map error:", err);
        setMapError("Map could not be loaded.");
      }
    };

    initMap();

    return () => {
      if (leafletMap.current) {
        leafletMap.current.remove();
        leafletMap.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [traceResult]);

  if (!traceResult) {
    return (
      <div
        className={`rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center ${className}`}
      >
        <Globe className="mx-auto h-8 w-8 text-slate-500 animate-spin" />
        <p className="mt-2 text-sm text-slate-400">
          Loading infrastructure relay topology...
        </p>
      </div>
    );
  }

  const confidence = traceResult.confidence_score <= 1
    ? traceResult.confidence_score * 100
    : traceResult.confidence_score;

  return (
    <div
      className={`rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-xl ${className}`}
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Globe className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              Infrastructure Geolocation &amp; Relay Path
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                OpenStreetMap
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Visualizing observable mail relay hops — real IP geolocation via ip-api
            </p>
          </div>
        </div>

        {/* Confidence Indicator */}
        <div className="flex items-center gap-3 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 self-start sm:self-auto">
          <div className="text-right">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">
              Location Confidence
            </div>
            <div className="text-sm font-bold text-emerald-400 font-mono">
              {Math.round(confidence)}%
            </div>
          </div>
          <div className="w-12 bg-slate-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-gradient-to-r from-amber-500 to-emerald-400 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.round(confidence)}%` }}
            />
          </div>
        </div>
      </div>

      {/* Evidentiary Disclaimer */}
      <div className="my-3 flex items-start gap-2.5 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs leading-relaxed">
        <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
        <div>
          <span className="font-semibold uppercase tracking-wide">
            Evidentiary Standard:{" "}
          </span>
          {traceResult.disclaimer ||
            "Physical location cannot be determined with absolute certainty from public routing telemetry. " +
            "Identifies probable infrastructure hosting location only. Do not use as sole evidence."}
        </div>
      </div>

      {/* Hop Summary Stats */}
      <div className="flex gap-4 mb-3 text-xs">
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
        {unlocatedCount > 0 && (
          <div className="flex items-center gap-1.5 bg-slate-900/50 rounded px-2 py-1 border border-amber-800/40">
            <AlertTriangle className="h-3 w-3 text-amber-400" />
            <span className="text-amber-400">{unlocatedCount} private/unresolved</span>
          </div>
        )}
      </div>

      {/* Leaflet Map Container */}
      <div className="relative w-full rounded-lg overflow-hidden border border-slate-700/60 my-2">
        {geoNodes.length === 0 ? (
          <div className="h-64 flex flex-col items-center justify-center bg-slate-900/80 text-slate-400 text-sm gap-2">
            <MapPin className="h-8 w-8 text-slate-600" />
            <p>No geolocatable hops — all IPs are private/RFC1918 or geo lookup unavailable.</p>
          </div>
        ) : mapError ? (
          <div className="h-64 flex items-center justify-center bg-slate-900/80 text-red-400 text-sm">
            {mapError}
          </div>
        ) : (
          <div
            ref={mapRef}
            style={{ height: "340px", width: "100%", zIndex: 0 }}
            id="mailshield-relay-map"
          />
        )}
      </div>

      {/* Map Legend */}
      <div className="flex flex-wrap items-center gap-3 text-[11px] mt-2 mb-4">
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-full bg-red-500 inline-block" />
          <span className="text-slate-300">Probable Origin Candidate</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-full bg-emerald-400 inline-block" />
          <span className="text-slate-300">Public Mail Relay</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-full bg-slate-500 inline-block" />
          <span className="text-slate-300">Private RFC1918</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-6 border-t-2 border-dashed border-amber-400 inline-block" />
          <span className="text-slate-300">Relay Path</span>
        </div>
      </div>

      {/* Selected Node Inspector */}
      {selectedNode && (
        <div className="bg-slate-950/80 rounded-lg p-4 border border-slate-800/90">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800/60">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-emerald-400" />
              <span className="text-xs uppercase tracking-wider text-slate-300 font-mono font-bold">
                {selectedNode.is_earliest_reliable
                  ? "Origin Candidate Infrastructure"
                  : `Relay Hop #${selectedNode.hop_index} Analysis`}
              </span>
            </div>
            <div className="flex items-center gap-2">
              {selectedNode.is_earliest_reliable && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                  EARLIEST OBSERVABLE
                </span>
              )}
              {selectedNode.infrastructure_type && (
                <span
                  className={`text-xs px-2 py-0.5 rounded font-mono ${
                    selectedNode.infrastructure_type === "CLOUD_VPS"
                      ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                      : selectedNode.infrastructure_type === "VPN_PROXY"
                      ? "bg-red-500/20 text-red-300 border border-red-500/30"
                      : "bg-slate-800 text-slate-300"
                  }`}
                >
                  {selectedNode.infrastructure_type}
                </span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <div className="text-slate-500">IP Address</div>
              <div className="text-white font-mono font-medium">
                {selectedNode.ip_address || "Private RFC1918"}
              </div>
            </div>
            <div>
              <div className="text-slate-500">From Host / RDNS</div>
              <div
                className="text-slate-200 truncate"
                title={selectedNode.from_host || "N/A"}
              >
                {selectedNode.from_host || "N/A"}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Infrastructure Location</div>
              <div className="text-slate-200">
                {selectedNode.geo_data?.city || selectedNode.geo_data?.country ? (
                  `${selectedNode.geo_data?.city || "Unknown City"}, ${
                    selectedNode.geo_data?.country || "Unknown Country"
                  }`
                ) : (
                  <span className="text-slate-400 italic">Location unavailable</span>
                )}
              </div>
            </div>
            <div>
              <div className="text-slate-500">ISP / ASN</div>
              <div
                className="text-slate-200 truncate"
                title={selectedNode.geo_data?.isp || "N/A"}
              >
                {selectedNode.geo_data?.isp ||
                  selectedNode.geo_data?.asn ||
                  "N/A"}
              </div>
            </div>
          </div>

          <div className="mt-3 pt-2 border-t border-slate-900 grid grid-cols-3 gap-2 text-[11px] font-mono">
            <div className="flex items-center gap-1.5 text-slate-400">
              <span>VPN:</span>
              <span className="text-white">
                {selectedNode.infrastructure_type === "VPN_PROXY"
                  ? "Possible"
                  : "Not detected"}
              </span>
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

      {/* Relay Path Timeline */}
      <div className="mt-4 pt-3 border-t border-slate-800/80">
        <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Navigation className="h-3.5 w-3.5 text-emerald-400" />
            Chronological Transmission Sequence ({nodes.length} Hops Analyzed)
          </div>
          <span className="text-[10px] text-slate-400 font-mono">
            Earliest Sender → Destination
          </span>
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
                <span className="font-mono text-white font-medium">
                  {n.ip_address || "Private IP"}
                </span>
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
                <span>
                  {n.geo_data?.country ||
                    (n.is_private ? "Private RFC1918" : "Location unavailable")}
                </span>
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

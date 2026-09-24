import { useEffect, useState, useRef } from "react";
import { Radio, AlertTriangle, ShieldCheck, Info, Activity } from "lucide-react";
import { getRecentAlerts } from "../api/client";
import type { AlertOut } from "../types/investigation";
import { sevColor } from "./Badges";

function formatTime(iso: string) {
  try {
    return new Date(iso).toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  } catch {
    return iso;
  }
}

function FeedIcon({ sev }: { sev: string }) {
  const color = sevColor(sev);
  if (sev === "CRITICAL" || sev === "HIGH") return <AlertTriangle style={{ color }} className="h-3.5 w-3.5 shrink-0" />;
  if (sev === "MEDIUM") return <Activity style={{ color }} className="h-3.5 w-3.5 shrink-0" />;
  if (sev === "LOW") return <ShieldCheck style={{ color }} className="h-3.5 w-3.5 shrink-0" />;
  return <Info className="h-3.5 w-3.5 shrink-0 text-lab-400" />;
}

interface FeedEntry {
  time: string;
  severity: string;
  label: string;
  id: string;
}

export default function LiveThreatFeed() {
  const [entries, setEntries] = useState<FeedEntry[]>([]);
  const [connected, setConnected] = useState(false);
  // isFetching guards against concurrent requests when poll fires while previous is still in-flight
  const isFetching = useRef(false);

  async function fetchAndMerge() {
    if (isFetching.current) return; // prevent race conditions from overlapping poll calls
    isFetching.current = true;
    try {
      const alerts = await getRecentAlerts(30);
      const mapped: FeedEntry[] = alerts.map((a: AlertOut) => ({
        id: a.id,
        time: a.created_at ? formatTime(a.created_at) : "—",
        severity: a.severity,
        label: `${a.classification} — ${a.key_reason.slice(0, 80)}`,
      }));
      setEntries(mapped);
      setConnected(true);
    } catch {
      setConnected(false);
    } finally {
      isFetching.current = false;
    }
  }

  useEffect(() => {
    fetchAndMerge();
    const interval = setInterval(fetchAndMerge, 10000);
    return () => clearInterval(interval);
  }, []);

  // AUTO-SCROLL ROOT CAUSE FIX:
  // The removed effect called bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  // on every `entries` state update. Since entries changed every 10 seconds via polling,
  // this caused the entire page to jump automatically — regardless of where the user was.
  // Fix: removed the effect entirely. The feed uses a self-contained overflow-y-auto
  // scroll container; its scroll position is independent of the outer page scroll.

  return (
    <div className="card-lab flex flex-col h-80">
      {/* Header */}
      <div className="px-4 py-3 border-b border-lab-700 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4 text-phosphor-500 animate-pulse" strokeWidth={1.75} />
          <span className="text-sm font-semibold text-lab-200">Live Threat Feed</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`h-2 w-2 rounded-full ${connected ? "bg-phosphor-500" : "bg-crimson-signal"} animate-pulse`} />
          <span className="text-[10px] evidence-tag text-lab-400">{connected ? "LIVE" : "OFFLINE"}</span>
        </div>
      </div>

      {/* Feed entries — self-contained scroll; never touches outer page scroll position */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-2 font-data text-xs">
        {entries.length === 0 ? (
          <div className="text-lab-500 text-center mt-6 text-sm">No alert events yet. Upload a .eml file to generate alerts.</div>
        ) : (
          entries.map((e) => (
            <div key={e.id} className="flex items-start gap-2.5 py-1 border-b border-lab-800 last:border-0">
              <span className="text-lab-500 shrink-0 w-20">{e.time}</span>
              <FeedIcon sev={e.severity} />
              <span style={{ color: sevColor(e.severity) }} className="font-semibold shrink-0 w-20">
                {e.severity}
              </span>
              <span className="text-lab-300 break-all leading-relaxed">{e.label}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

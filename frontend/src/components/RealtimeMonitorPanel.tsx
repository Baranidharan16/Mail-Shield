import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Radar, RefreshCw, Play, Pause, AlertTriangle, ShieldCheck, ShieldAlert, ShieldQuestion, Loader2 } from "lucide-react";
import { getMonitorStatus, getMonitoredEmails, runMonitorNow, setMonitorEnabled, getApiErrorMessage } from "../api/client";
import type { MonitorStatus, MonitoredEmail } from "../types/investigation";

const V: Record<string, { cls: string; Icon: typeof ShieldAlert }> = {
  THREAT: { cls: "text-crimson-glow", Icon: ShieldAlert },
  SUSPICIOUS: { cls: "text-amber-300", Icon: ShieldQuestion },
  SAFE: { cls: "text-phosphor-300", Icon: ShieldCheck },
};

function ago(iso: string | null) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

/** Real-time Gmail threat monitor: new inbox mail is analysed automatically by the backend. */
export default function RealtimeMonitorPanel() {
  const [status, setStatus] = useState<MonitorStatus | null>(null);
  const [rows, setRows] = useState<MonitoredEmail[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, r] = await Promise.all([getMonitorStatus(), getMonitoredEmails(15)]);
      setStatus(s);
      setRows(r);
      setErr(null);
    } catch (e) {
      setErr(getApiErrorMessage(e, "Monitor status unavailable."));
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 20000); // UI refresh; analysis itself runs server-side
    return () => clearInterval(t);
  }, [load]);

  async function toggle() {
    if (!status) return;
    setBusy(true);
    try { await setMonitorEnabled(!status.enabled_for_you); await load(); } finally { setBusy(false); }
  }
  async function runNow() {
    setBusy(true);
    try { await runMonitorNow(); await load(); } catch (e) { setErr(getApiErrorMessage(e)); } finally { setBusy(false); }
  }

  return (
    <div className="glass-section p-5">
      <div className="flex items-center gap-2 mb-3">
        <Radar className={`w-4 h-4 ${status?.enabled_for_you ? "text-phosphor-400 animate-pulse" : "text-lab-500"}`} />
        <h3 className="text-sm font-bold text-white">Real-time Email Threat Monitor</h3>
        <div className="ml-auto flex gap-2">
          {status?.gmail_connected && (
            <>
              <button onClick={runNow} disabled={busy} className="text-[11px] flex items-center gap-1 px-2 py-1 rounded border border-white/10 text-lab-300 hover:text-white">
                {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />} Check now
              </button>
              <button onClick={toggle} disabled={busy} className="text-[11px] flex items-center gap-1 px-2 py-1 rounded border border-white/10 text-lab-300 hover:text-white">
                {status.enabled_for_you ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                {status.enabled_for_you ? "Pause" : "Resume"}
              </button>
            </>
          )}
        </div>
      </div>

      {err && <div className="text-xs text-crimson-glow mb-2">{err}</div>}
      {status && !status.gmail_connected && (
        <div className="text-xs text-lab-400">
          Connect your Gmail (Upload page → Gmail) to enable automatic, near-real-time analysis of new inbox mail.
          Only read access is used for analysis; your mailbox is never modified unless you choose to quarantine.
        </div>
      )}
      {status?.gmail_connected && (
        <div className="text-[11px] text-lab-400 mb-3 flex flex-wrap gap-x-4">
          <span>Status: <b className={status.enabled_for_you ? "text-phosphor-300" : "text-amber-300"}>{status.enabled_for_you ? "ACTIVE" : "PAUSED"}</b></span>
          <span>Checks every {status.poll_interval_seconds}s</span>
          <span>Last check: {ago(status.last_success_at)}</span>
          <span>Analysed: {status.messages_processed}</span>
        </div>
      )}
      {status?.last_error && (
        <div className="text-[11px] text-amber-300 mb-2 flex gap-1"><AlertTriangle className="w-3 h-3 mt-0.5" />{status.last_error}</div>
      )}

      {rows.length > 0 && (
        <div className="divide-y divide-white/[0.05]">
          {rows.map((r) => {
            const v = r.verdict ? V[r.verdict] : null;
            const body = (
              <div className="flex items-center gap-3 py-2 text-xs">
                {v ? <v.Icon className={`w-4 h-4 shrink-0 ${v.cls}`} /> : <span className="w-4 h-4 shrink-0 text-lab-600">·</span>}
                <div className="min-w-0 flex-1">
                  <div className="text-lab-100 truncate">{r.subject || (r.status === "SKIPPED" ? "(skipped)" : "(no subject)")}</div>
                  <div className="text-lab-500 truncate text-[10px]">{r.sender || r.detail || r.status}</div>
                </div>
                {r.risk_score != null && <span className={`font-data ${v?.cls ?? "text-lab-400"}`}>{Math.round(r.risk_score)}</span>}
                <span className="text-[10px] text-lab-500 w-16 text-right">{ago(r.processed_at)}</span>
              </div>
            );
            return r.investigation_id
              ? <Link key={r.message_id} to={`/investigations/${r.investigation_id}`} className="block hover:bg-white/[0.03]">{body}</Link>
              : <div key={r.message_id}>{body}</div>;
          })}
        </div>
      )}
    </div>
  );
}

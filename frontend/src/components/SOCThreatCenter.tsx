import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getRecentAlerts, acknowledgeAlert } from "../api/client";
import type { AlertOut } from "../types/investigation";
import { ShieldAlert, AlertTriangle, CheckCircle2, ShieldCheck, Activity, ArrowRight, RefreshCw } from "lucide-react";
import { SeverityBadge, ClassificationBadge } from "./Badges";
import SOCHelpline from "./SOCHelpline";

function IncidentCard({ alert, onSelect, selected }: { alert: AlertOut, onSelect: () => void, selected: boolean }) {
  const isCrit = alert.severity === "CRITICAL";
  return (
    <div
      onClick={onSelect}
      className={`soc-incident-card ${alert.severity.toLowerCase()} ${selected ? "ring-2 ring-phosphor-500/50 bg-white/5" : ""} ${alert.acknowledged ? "opacity-60" : ""}`}
    >
      <div className="flex justify-between items-start mb-3">
        <SeverityBadge level={alert.severity} />
        {!alert.acknowledged && isCrit && <span className="live-dot" />}
      </div>
      <div className="font-semibold text-sm text-lab-100 mb-2 leading-tight line-clamp-2">{alert.key_reason}</div>
      <div className="flex items-center gap-2 text-[10px] text-lab-500 font-data">
        <span>{new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
        <span>•</span>
        <span className="truncate max-w-[100px]">{alert.classification}</span>
      </div>
    </div>
  );
}

export default function SOCThreatCenter() {
  const [alerts, setAlerts] = useState<AlertOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<AlertOut | null>(null);
  const navigate = useNavigate();

  const load = () => { setLoading(true); getRecentAlerts(50).then(setAlerts).finally(() => setLoading(false)); };
  useEffect(() => { load(); }, []);

  const handleAck = async (id: string) => {
    try {
      await acknowledgeAlert(id);
      setAlerts(alerts.map(a => a.id === id ? { ...a, acknowledged: true } : a));
      if (selectedAlert?.id === id) setSelectedAlert({ ...selectedAlert, acknowledged: true });
    } catch (e) { console.error(e); }
  };

  const unackCount = alerts.filter(a => !a.acknowledged).length;
  const critCount = alerts.filter(a => a.severity === "CRITICAL" && !a.acknowledged).length;

  return (
    <div className="p-6 md:p-8 max-w-[1600px] mx-auto h-[calc(100vh-56px)] flex flex-col animate-fade-in">

      <div className="page-header-glass flex items-center justify-between shrink-0 mb-6 !p-4 !rounded-xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-crimson-signal/15 border border-crimson-signal/30 flex items-center justify-center glow-red">
            <ShieldAlert className="h-5 w-5 text-crimson-glow" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">SOC Threat Center</h1>
            <div className="text-[11px] text-lab-400 font-data mt-0.5">ACTIVE INCIDENT TRIAGE & THREAT RESPONSE</div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex gap-4 px-4 py-2 bg-black/40 rounded-lg border border-white/5">
            <div className="text-center">
              <div className="text-[10px] text-lab-500 font-data">UNACKNOWLEDGED</div>
              <div className="text-lg font-bold text-amber-signal leading-none">{unackCount}</div>
            </div>
            <div className="text-center">
              <div className="text-[10px] text-lab-500 font-data">CRITICAL</div>
              <div className="text-lg font-bold text-crimson-glow leading-none flex items-center justify-center gap-1">
                {critCount > 0 && <span className="live-dot" />} {critCount}
              </div>
            </div>
          </div>
          <button onClick={load} className="btn-glass-secondary p-2"><RefreshCw className="h-4 w-4" /></button>
        </div>
      </div>

      <div className="flex-1 flex gap-6 min-h-0">

        <div className="w-[320px] shrink-0 flex flex-col bg-black/20 rounded-xl border border-white/5 overflow-hidden">
          <div className="p-3 border-b border-white/5 bg-black/40 flex justify-between items-center text-xs font-semibold text-lab-300">
            <span>Incident Queue</span>
            <span className="bg-white/10 px-2 py-0.5 rounded-full">{alerts.length}</span>
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-3 custom-scrollbar">
            {loading ? (
               <div className="text-center p-4 text-lab-500"><RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2" /></div>
            ) : alerts.length === 0 ? (
               <div className="text-center p-4 text-lab-500">No recent alerts.</div>
            ) : (
               alerts.map(a => <IncidentCard key={a.id} alert={a} onSelect={() => setSelectedAlert(a)} selected={selectedAlert?.id === a.id} />)
            )}
          </div>
        </div>

        <div className="flex-1 glass-section flex flex-col overflow-hidden relative">
          {selectedAlert ? (
            <div className="flex-1 overflow-y-auto p-6 md:p-8">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <SeverityBadge level={selectedAlert.severity} />
                    <ClassificationBadge level={selectedAlert.classification} />
                    {selectedAlert.acknowledged ? (
                      <span className="status-pill bg-phosphor-500/10 border-phosphor-500/30 text-phosphor-400 text-[10px]"><ShieldCheck className="h-3 w-3" /> ACKNOWLEDGED</span>
                    ) : (
                      <span className="status-pill bg-amber-signal/10 border-amber-signal/30 text-amber-signal text-[10px] animate-pulse"><Activity className="h-3 w-3" /> ACTION REQUIRED</span>
                    )}
                  </div>
                  <h2 className="text-2xl font-bold text-white mb-2">{selectedAlert.case_id || selectedAlert.classification}</h2>
                  <div className="font-data text-xs text-lab-400">{new Date(selectedAlert.created_at).toLocaleString()}</div>
                </div>
                {!selectedAlert.acknowledged && (
                  <button onClick={() => handleAck(selectedAlert.id)} className="btn-glass-primary">
                    <CheckCircle2 className="h-4 w-4" /> Acknowledge Alert
                  </button>
                )}
              </div>

              <div className="glass-card p-5 bg-crimson-signal/5 border-crimson-signal/20 mb-6">
                <h3 className="text-[11px] evidence-tag font-bold text-crimson-glow mb-2 flex items-center gap-2"><AlertTriangle className="h-4 w-4" /> PRIMARY THREAT REASON</h3>
                <p className="text-lab-100 font-medium leading-relaxed">{selectedAlert.key_reason}</p>
              </div>

              <div className="glass-card p-5 mb-6">
                <h3 className="text-[11px] evidence-tag font-bold text-phosphor-400 mb-2">RECOMMENDED SOC PROTOCOL</h3>
                <p className="text-lab-300 leading-relaxed whitespace-pre-wrap">
                  1. Quarantine malicious email artifacts from mail gateway.{"\n"}
                  2. Block sender domain and source IP relay hops.{"\n"}
                  3. Verify SHA-256 cryptographic chain of custody before forensic archival.
                </p>
              </div>

              <div className="flex gap-4 border-t border-white/10 pt-6 mt-auto">
                <button
                  onClick={() => selectedAlert.investigation_id && navigate(`/investigations/${selectedAlert.investigation_id}`)}
                  className="btn-glass-secondary flex-1 justify-center"
                >
                  View Full Forensic Report <ArrowRight className="h-4 w-4 ml-2" />
                </button>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-lab-500 p-10">
              <ShieldAlert className="h-16 w-16 mb-4 opacity-20" strokeWidth={1} />
              <p className="text-lg font-medium text-lab-400">Select an incident from the queue to triage.</p>
              <p className="text-sm mt-2">The SOC Threat Center allows analysts to review, acknowledge, and action AI-generated security alerts.</p>
            </div>
          )}
        </div>

        <div className="w-[340px] shrink-0 hidden xl:block">
          <SOCHelpline caseId={selectedAlert?.case_id || "SOC-ACTIVE"} riskLevel={selectedAlert?.severity || "HIGH"} />
        </div>
      </div>
    </div>
  );
}

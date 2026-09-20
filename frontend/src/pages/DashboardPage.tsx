import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  getDashboardStats,
  getRecentAlerts,
  getGmailStatus,
  getGmailAuthUrl,
  getGmailMessages,
  analyzeGmailMessage,
  disconnectGmail,
  type GmailMessageItem,
  type GmailStatusResponse,
} from "../api/client";
import type { DashboardStats, AlertOut, MailShieldAnalysisResponse } from "../types/investigation";
import { ClassificationBadge, SeverityBadge } from "../components/Badges";
import LiveThreatFeed from "../components/LiveThreatFeed";
import RealtimeMonitorPanel from "../components/RealtimeMonitorPanel";
import MailShieldLiveAnalysis from "../components/MailShieldLiveAnalysis";
import {
  ShieldAlert, ShieldCheck, Activity, Database, AlertTriangle,
  Cpu, RefreshCw, UploadCloud, Link2, ArrowUpRight, Shield,
  TrendingUp, Archive, Mail, ChevronDown, ChevronUp,
  Search, Zap, LogOut,
} from "lucide-react";

function formatTs(iso: string) {
  try { return new Date(iso).toLocaleString("en-IN", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }); }
  catch { return iso; }
}

interface StatCardProps {
  label: string; value: string | number; sub?: string;
  color?: string; icon: any; glow?: string; trend?: string;
}

function StatCard({ label, value, sub, color = "text-lab-200", icon: Icon, glow, trend }: StatCardProps) {
  return (
    <div className={`glass-stat-card px-5 py-4 flex items-center gap-4 cursor-default ${glow ?? ""}`}>
      <div className={`h-12 w-12 rounded-xl flex items-center justify-center border shrink-0 ${
        color === "text-crimson-glow" ? "bg-crimson-signal/10 border-crimson-signal/25" :
        color === "text-phosphor-400" ? "bg-phosphor-500/10 border-phosphor-500/25" :
        color === "text-amber-signal" ? "bg-amber-signal/10 border-amber-signal/25" :
        "bg-white/5 border-white/10"
      }`}>
        <Icon className={`h-5 w-5 ${color}`} strokeWidth={1.75} />
      </div>
      <div className="flex-1 min-w-0">
        <div className={`text-2xl font-bold font-data leading-none ${color}`}>{value}</div>
        <div className="text-xs text-lab-400 font-medium mt-1">{label}</div>
        {sub && <div className="text-[10px] text-lab-500 font-data mt-0.5">{sub}</div>}
      </div>
      {trend && (
        <div className="text-[10px] text-phosphor-400 evidence-tag flex items-center gap-0.5">
          <TrendingUp className="h-3 w-3" />{trend}
        </div>
      )}
    </div>
  );
}

function MiniBar({ label, count, total, color }: { label: string; count: number; total: number; color: string }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div className="flex items-center gap-3">
      <div className="w-20 text-right text-[11px] evidence-tag text-lab-400 font-semibold">{label}</div>
      <div className="flex-1 h-1.5 bg-black/40 rounded-full overflow-hidden border border-white/5">
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{ width: `${pct}%`, backgroundColor: color, boxShadow: `0 0 6px ${color}70` }}
        />
      </div>
      <div className="font-data text-sm font-bold w-8 text-right" style={{ color }}>{count}</div>
    </div>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<AlertOut[]>([]);
  const [loading, setLoading] = useState(true);

  // Gmail OAuth Integration State
  const [gmailStatus, setGmailStatus] = useState<GmailStatusResponse | null>(null);
  const [gmailMessages, setGmailMessages] = useState<GmailMessageItem[]>([]);
  const [gmailLoading, setGmailLoading] = useState(false);
  const [showGmailDrawer, setShowGmailDrawer] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [analyzingMessageId, setAnalyzingMessageId] = useState<string | null>(null);
  const [gmailAnalysis, setGmailAnalysis] = useState<MailShieldAnalysisResponse | null>(null);
  const [gmailInvestigationId, setGmailInvestigationId] = useState<string | null>(null);
  const [gmailError, setGmailError] = useState<string | null>(null);

  async function loadGmail() {
    setGmailLoading(true);
    setGmailError(null);
    try {
      const st = await getGmailStatus();
      setGmailStatus(st);
      if (st.connected) {
        if (st.gmail_error) {
          setGmailError(st.gmail_error);
          setGmailMessages([]);
        } else {
          try {
            const msgs = await getGmailMessages();
            setGmailMessages(msgs);
          } catch (err: any) {
            setGmailError(err?.response?.data?.detail || "Failed to load Gmail messages.");
          }
        }
      }
    } catch {
      setGmailStatus(null);
    } finally {
      setGmailLoading(false);
    }
  }

  async function load() {
    setLoading(true);
    try {
      const [s, a] = await Promise.all([getDashboardStats(), getRecentAlerts(6)]);
      setStats(s); setRecentAlerts(a);
    } catch {
      setStats({ total_investigations: 0, critical: 0, high: 0, medium: 0, low: 0, processing: 0, completed: 0, failed: 0, campaigns: 0, active_alerts: 0 });
    } finally { setLoading(false); }
    loadGmail();
  }

  useEffect(() => { load(); }, []);

  const handleConnectGmail = async () => {
    setGmailLoading(true);
    setGmailError(null);
    try {
      const { authorization_url } = await getGmailAuthUrl();
      if (authorization_url) {
        window.location.href = authorization_url;
      }
    } catch (err: any) {
      setGmailError(err?.response?.data?.detail || "Failed to initiate Google OAuth.");
      setGmailLoading(false);
    }
  };

  const handleDisconnectGmail = async () => {
    setGmailLoading(true);
    try {
      await disconnectGmail();
      setGmailStatus({ connected: false, email: "", messages_total: 0, quarantined_count: 0 });
      setGmailMessages([]);
      setShowGmailDrawer(false);
    } catch (err: any) {
      setGmailError("Failed to disconnect Gmail.");
    } finally {
      setGmailLoading(false);
    }
  };

  const handleSearchGmail = async (e: React.FormEvent) => {
    e.preventDefault();
    setGmailLoading(true);
    try {
      const msgs = await getGmailMessages(searchQuery);
      setGmailMessages(msgs);
    } catch (err: any) {
      setGmailError(err?.response?.data?.detail || "Failed to search Gmail messages.");
    } finally {
      setGmailLoading(false);
    }
  };

  const handleAnalyzeEmail = async (msg: GmailMessageItem) => {
    setAnalyzingMessageId(msg.id);
    setGmailError(null);
    try {
      const res = await analyzeGmailMessage(msg.id);
      setGmailAnalysis(res.analysis);
      setGmailInvestigationId(res.investigation_id);
      load(); // refresh dashboard stats
    } catch (err: any) {
      setGmailError(err?.response?.data?.detail || "Failed to analyze raw email from Gmail.");
    } finally {
      setAnalyzingMessageId(null);
    }
  };

  const totalThreats = (stats?.critical ?? 0) + (stats?.high ?? 0) + (stats?.medium ?? 0) + (stats?.low ?? 0);
  const detectionRate = stats?.total_investigations ? ((totalThreats / stats.total_investigations) * 100).toFixed(0) : "—";

  // If viewing an analysis result from Gmail
  if (gmailAnalysis) {
    return (
      <div className="p-6 md:p-8 max-w-4xl mx-auto">
        <MailShieldLiveAnalysis
          data={gmailAnalysis}
          investigationId={gmailInvestigationId || undefined}
          onReset={() => {
            setGmailAnalysis(null);
            setGmailInvestigationId(null);
          }}
          onViewDetails={gmailInvestigationId ? () => navigate(`/investigations/${gmailInvestigationId}`) : undefined}
        />
      </div>
    );
  }

  return (
    <div className="p-6 md:p-8 max-w-7xl space-y-6 animate-fade-in">

      {/* Page Header */}
      <div className="page-header-glass flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <Shield className="h-5 w-5 text-phosphor-500" strokeWidth={1.75} />
            <h1 className="text-xl font-bold tracking-tight text-white">Security Overview</h1>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-phosphor-500/15 text-phosphor-400 border border-phosphor-500/28 tracking-widest">
              REAL-TIME
            </span>
          </div>
          <p className="text-sm text-lab-400">Real-time email threat monitoring and forensic intelligence</p>
        </div>
        <div className="flex items-center gap-2.5 flex-shrink-0">
          {(loading || gmailLoading) && <RefreshCw className="h-4 w-4 text-phosphor-400 animate-spin" />}
          <button onClick={load} className="btn-glass-secondary text-sm px-3 py-2 gap-1.5 cursor-pointer">
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
          <button onClick={() => navigate("/upload")} className="btn-glass-primary text-sm cursor-pointer">
            <UploadCloud className="h-4 w-4" strokeWidth={2.2} /> Analyze Email
          </button>
        </div>
      </div>

      {/* ── GMAIL INTEGRATION SECTION ────────────────────────────────────────── */}
      <div className="glass-section rounded-2xl p-5 border-white/10 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border ${
              gmailStatus?.connected
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                : "bg-red-500/10 border-red-500/30 text-red-400"
            }`}>
              <Mail className="h-5 w-5" strokeWidth={1.75} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-white">
                  {gmailStatus?.connected ? "GMAIL CONNECTED ✓" : "CONNECT GMAIL"}
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                  gmailStatus?.connected
                    ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                    : "bg-white/5 text-lab-400 border-white/10"
                }`}>
                  {gmailStatus?.connected ? "OAUTH ACTIVE" : "DISCONNECTED"}
                </span>
              </div>
              <div className="text-xs text-lab-400 mt-0.5">
                {gmailStatus?.connected ? (
                  <span>Google account: <strong className="text-white font-mono">{gmailStatus.email}</strong></span>
                ) : (
                  "Connect your Gmail mailbox to acquire raw RFC822 messages and run forensic threat analysis."
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 self-end sm:self-auto">
            {gmailStatus?.connected ? (
              <>
                <button
                  onClick={() => setShowGmailDrawer(!showGmailDrawer)}
                  className="btn-glass-secondary text-xs px-3.5 py-2 flex items-center gap-1.5 cursor-pointer"
                >
                  <Mail className="h-3.5 w-3.5" />
                  VIEW EMAILS
                  {showGmailDrawer ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                </button>
                <button
                  onClick={handleDisconnectGmail}
                  disabled={gmailLoading}
                  className="p-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-300 text-xs flex items-center gap-1.5 border border-red-500/20 transition-all cursor-pointer"
                  title="Disconnect Gmail"
                >
                  <LogOut className="h-3.5 w-3.5" />
                  Disconnect
                </button>
              </>
            ) : (
              <button
                onClick={handleConnectGmail}
                disabled={gmailLoading}
                className="btn-glass-secondary text-xs px-4 py-2.5 flex items-center gap-2 cursor-pointer"
              >
                <Mail className="h-4 w-4" />
                CONNECT GMAIL
              </button>
            )}
          </div>
        </div>

        {/* Gmail Error Notice */}
        {gmailError && (
          <div className="text-xs font-mono text-crimson-glow bg-crimson-signal/10 border border-crimson-signal/25 rounded-xl p-3">
            {gmailError}
          </div>
        )}

        {/* Recent Emails Drawer */}
        {gmailStatus?.connected && showGmailDrawer && (
          <div className="border-t border-white/10 pt-4 space-y-3 animate-fade-in">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5">
              <div className="text-xs font-semibold text-lab-200">
                Recent Emails ({gmailMessages.length})
              </div>
              <form onSubmit={handleSearchGmail} className="flex gap-2 w-full sm:w-auto">
                <div className="relative flex-1 sm:w-64">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search recent emails..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-black/30 border border-white/10 text-white text-xs font-mono focus:outline-none focus:border-phosphor-500/50"
                  />
                </div>
                <button
                  type="submit"
                  disabled={gmailLoading}
                  className="btn-glass-secondary text-xs px-3 py-1.5 flex items-center gap-1"
                >
                  Search
                </button>
                <button
                  type="button"
                  onClick={loadGmail}
                  disabled={gmailLoading}
                  className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs"
                  title="Refresh Gmail"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${gmailLoading ? "animate-spin" : ""}`} />
                </button>
              </form>
            </div>

            {/* Email List Table */}
            <div className="overflow-x-auto rounded-xl border border-white/5 bg-black/20">
              {gmailMessages.length === 0 ? (
                <div className="p-6 text-center text-xs text-lab-400">
                  {gmailLoading ? "Loading Gmail messages..." : "No recent emails found."}
                </div>
              ) : (
                <table className="glass-table w-full text-left text-xs">
                  <thead>
                    <tr>
                      <th className="py-2.5 px-3">SENDER</th>
                      <th className="py-2.5 px-3">SUBJECT</th>
                      <th className="py-2.5 px-3">DATE</th>
                      <th className="py-2.5 px-3">MESSAGE ID</th>
                      <th className="py-2.5 px-3 text-right">ACTION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {gmailMessages.map((m) => {
                      const isAnalyzing = analyzingMessageId === m.id;
                      return (
                        <tr key={m.id} className="hover:bg-white/[0.02] transition-colors">
                          <td className="py-2.5 px-3 max-w-[180px] truncate text-white font-medium">
                            {m.sender}
                          </td>
                          <td className="py-2.5 px-3 max-w-[240px] truncate text-slate-300" title={m.subject}>
                            {m.subject || "(No Subject)"}
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap text-lab-500 font-mono text-[11px]">
                            {m.date}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[10px] text-lab-500 truncate max-w-[120px]" title={m.id}>
                            {m.id}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              onClick={() => handleAnalyzeEmail(m)}
                              disabled={isAnalyzing}
                              className="btn-glass-secondary py-1 px-2.5 text-[11px] font-semibold inline-flex items-center gap-1 cursor-pointer disabled:opacity-50"
                            >
                              {isAnalyzing ? (
                                <RefreshCw className="h-3 w-3 animate-spin" />
                              ) : (
                                <Zap className="h-3 w-3 text-phosphor-400" />
                              )}
                              {isAnalyzing ? "Analyzing..." : "ANALYZE"}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Stat Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Emails Analyzed" value={loading ? "…" : (stats?.total_investigations ?? 0)} icon={Database} color="text-lab-200" />
        <StatCard label="Active Alerts" value={loading ? "…" : (stats?.active_alerts ?? 0)} icon={AlertTriangle} color="text-crimson-glow"
          glow={stats?.active_alerts ? "glow-red" : ""} />
        <StatCard label="Processing" value={loading ? "…" : (stats?.processing ?? 0)} icon={Cpu} color="text-amber-signal" />
        <StatCard label="Completed" value={loading ? "…" : (stats?.completed ?? 0)} icon={ShieldCheck} color="text-phosphor-400" glow="glow-green" />
      </div>

      {/* Threat Distribution + Live Feed */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

        {/* Threat Breakdown */}
        <div className="glass-section">
          <div className="glass-section-header">
            <ShieldAlert className="h-4 w-4 text-crimson-glow" strokeWidth={1.75} />
            <h2 className="text-sm font-semibold text-lab-100 flex-1">Threat Overview</h2>
            <span className="font-data text-xs px-2.5 py-0.5 rounded-full bg-white/5 border border-white/8 text-lab-300">
              {totalThreats} classified
            </span>
          </div>
          <div className="p-5 space-y-3.5">
            <MiniBar label="CRITICAL" count={stats?.critical ?? 0} total={totalThreats} color="#b9301f" />
            <MiniBar label="HIGH" count={stats?.high ?? 0} total={totalThreats} color="#e0712a" />
            <MiniBar label="MEDIUM" count={stats?.medium ?? 0} total={totalThreats} color="#d99a2b" />
            <MiniBar label="LOW" count={stats?.low ?? 0} total={totalThreats} color="#0f66ae" />
          </div>
          <div className="px-5 pb-4 grid grid-cols-3 gap-3 border-t border-white/[0.05] pt-4">
            {[
              { label: "DETECTION RATE", value: detectionRate + "%", color: "text-phosphor-400" },
              { label: "CAMPAIGNS", value: stats?.campaigns ?? 0, color: "text-purple-signal" },
              { label: "FAILED", value: stats?.failed ?? 0, color: "text-crimson-glow" },
            ].map(({ label, value, color }) => (
              <div key={label} className="glass-card p-3 text-center !rounded-xl">
                <div className={`font-data text-xl font-bold ${color}`}>{value}</div>
                <div className="text-[9.5px] text-lab-500 evidence-tag mt-0.5">{label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Live Feed */}
        <div className="glass-section overflow-hidden">
          <LiveThreatFeed />
        </div>
      </div>

      {/* Real-time Gmail monitor (server-side, automatic) */}
      <RealtimeMonitorPanel />

      {/* Recent Alerts Table */}
      {recentAlerts.length > 0 && (
        <div className="glass-section overflow-hidden">
          <div className="glass-section-header">
            <Activity className="h-4 w-4 text-amber-signal" strokeWidth={1.75} />
            <h2 className="text-sm font-semibold text-lab-100 flex-1">Recent Threat Events</h2>
            <button
              onClick={() => navigate("/alerts")}
              className="text-xs font-semibold text-phosphor-400 hover:text-phosphor-300 transition-colors flex items-center gap-1 cursor-pointer"
            >
              View SOC Center <ArrowUpRight size={12} />
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="glass-table">
              <thead>
                <tr>
                  <th>SEVERITY</th>
                  <th>CLASSIFICATION</th>
                  <th>KEY REASON</th>
                  <th>THREAT SCORE</th>
                  <th>TIME</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => a.investigation_id && navigate(`/investigations/${a.investigation_id}`)}
                    className="cursor-pointer"
                  >
                    <td><SeverityBadge level={a.severity} /></td>
                    <td><ClassificationBadge level={a.classification} size="sm" /></td>
                    <td className="text-lab-300 max-w-xs truncate" title={a.key_reason ?? ""}>{a.key_reason ?? "—"}</td>
                    <td>
                      <span className={`font-data font-bold ${
                        a.threat_score >= 80 ? "text-crimson-glow" : a.threat_score >= 60 ? "text-orange-signal" : "text-amber-signal"
                      }`}>{a.threat_score.toFixed(0)}</span>
                    </td>
                    <td className="text-lab-500 text-[11px] font-data whitespace-nowrap">{formatTs(a.created_at)}</td>
                    <td>
                      <span className={`text-[10px] evidence-tag font-semibold ${a.acknowledged ? "text-lab-500" : "text-crimson-glow flex items-center gap-1.5"}`}>
                        {!a.acknowledged && <span className="live-dot" />}
                        {a.acknowledged ? "ACKNOWLEDGED" : "UNACKNOWLEDGED"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Quick Action Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[
          { label: "SOC Threat Center", sub: "Triage and manage active security incidents", to: "/alerts", icon: AlertTriangle, color: "text-crimson-glow", accent: "crimson" },
          { label: "Evidence Vault", sub: "Preserved artifacts and forensic metadata", to: "/evidence-vault", icon: Archive, color: "text-purple-signal", accent: "purple" },
          { label: "Integrity Ledger", sub: "Immutable SHA-256 chain-of-custody records", to: "/ledger", icon: Link2, color: "text-phosphor-400", accent: "green" },
        ].map(({ label, sub, to, icon: Icon, color }) => (
          <button
            key={to}
            onClick={() => navigate(to)}
            className="glass-card p-5 text-left group cursor-pointer"
          >
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/8 flex items-center justify-center group-hover:border-phosphor-500/30 transition-colors">
                <Icon className={`h-5 w-5 ${color}`} strokeWidth={1.75} />
              </div>
              <ArrowUpRight size={15} className="text-lab-600 group-hover:text-phosphor-400 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-all" />
            </div>
            <div className="text-sm font-semibold text-lab-100 group-hover:text-phosphor-300 transition-colors">{label}</div>
            <div className="text-xs text-lab-500 mt-1">{sub}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

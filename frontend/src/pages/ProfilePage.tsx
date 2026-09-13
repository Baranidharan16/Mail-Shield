import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  User,
  Mail,
  Calendar,
  ShieldCheck,
  AlertTriangle,
  LogOut,
  Shield,
  CheckCircle2,
  Lock,
} from "lucide-react";

export default function ProfilePage() {
  const { user, logout, refreshUser } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    refreshUser();
  }, []);

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  const creationDate = user?.created_at
    ? new Date(user.created_at).toLocaleDateString("en-IN", {
        year: "numeric",
        month: "long",
        day: "numeric",
      })
    : "Active Analyst";

  const lastLogin = user?.last_login
    ? new Date(user.last_login).toLocaleString("en-IN", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      })
    : "Just now";

  return (
    <div className="p-6 md:p-8 max-w-4xl mx-auto space-y-6 animate-fade-in">
      {/* Header Banner */}
      <div className="page-header-glass flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <User className="h-5 w-5 text-phosphor-500" strokeWidth={1.75} />
            <h1 className="text-xl font-bold tracking-tight text-white">Security Analyst Profile</h1>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-phosphor-500/15 text-phosphor-400 border border-phosphor-500/28 tracking-widest">
              AUTHENTICATED
            </span>
          </div>
          <p className="text-sm text-lab-400">
            Account identity, investigation access scopes, and security settings
          </p>
        </div>

        <button
          onClick={handleLogout}
          className="btn-glass-secondary text-xs px-3.5 py-2 text-crimson-glow border-crimson-signal/30 hover:bg-crimson-signal/10 transition-colors flex items-center gap-2 cursor-pointer"
        >
          <LogOut size={14} />
          <span>Sign Out</span>
        </button>
      </div>

      {/* Main Profile Card */}
      <div className="glass-panel-heavy p-6 md:p-8 rounded-2xl border border-white/10 space-y-6">
        {/* User Identity Header */}
        <div className="flex items-center gap-4 pb-6 border-b border-white/[0.08]">
          <div className="relative flex items-center justify-center w-16 h-16 rounded-2xl bg-phosphor-500/15 border border-phosphor-500/35 glow-green shrink-0">
            <Shield className="w-8 h-8 text-phosphor-400" />
            <span className="absolute -top-0.5 -right-0.5 h-3 w-3 rounded-full bg-phosphor-500 ring-4 ring-lab-950" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              {user?.name || "Security Analyst"}
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 font-normal">
                <CheckCircle2 size={10} /> Active
              </span>
            </h2>
            <p className="text-sm text-lab-400 font-mono mt-0.5 flex items-center gap-1.5">
              <Mail size={13} className="text-lab-500" />
              {user?.email || "analyst@mailshield.ai"}
            </p>
          </div>
        </div>

        {/* Account Details Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="glass-card p-4 rounded-xl border border-white/[0.08] space-y-1">
            <div className="flex items-center gap-2 text-xs text-lab-400 font-mono">
              <Calendar size={13} className="text-phosphor-400" />
              <span>ACCOUNT CREATED</span>
            </div>
            <div className="text-sm font-semibold text-white">{creationDate}</div>
          </div>

          <div className="glass-card p-4 rounded-xl border border-white/[0.08] space-y-1">
            <div className="flex items-center gap-2 text-xs text-lab-400 font-mono">
              <Lock size={13} className="text-phosphor-400" />
              <span>LAST LOGIN SESSION</span>
            </div>
            <div className="text-sm font-semibold text-white">{lastLogin}</div>
          </div>
        </div>

        {/* Investigation & Threat Metrics */}
        <div className="space-y-3 pt-2">
          <h3 className="text-xs font-mono uppercase tracking-wider text-lab-400 font-semibold">
            Personal Investigation Portfolio
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="glass-stat-card p-5 rounded-xl border border-white/10 flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/25 flex items-center justify-center shrink-0">
                <ShieldCheck className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <div className="text-2xl font-bold font-data text-white">
                  {user?.total_investigations ?? 0}
                </div>
                <div className="text-xs text-lab-400 mt-0.5">Total Investigations Recorded</div>
              </div>
            </div>

            <div className="glass-stat-card p-5 rounded-xl border border-white/10 flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-crimson-signal/10 border border-crimson-signal/25 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-6 h-6 text-crimson-glow" />
              </div>
              <div>
                <div className="text-2xl font-bold font-data text-crimson-glow">
                  {user?.threats_detected ?? 0}
                </div>
                <div className="text-xs text-lab-400 mt-0.5">Threats / Phishing Incidents Detected</div>
              </div>
            </div>
          </div>
        </div>

        {/* Security & Cryptography Guarantee */}
        <div className="p-4 rounded-xl bg-black/40 border border-white/[0.06] text-xs text-lab-400 space-y-1.5 font-mono">
          <div className="text-phosphor-400 font-bold flex items-center gap-1.5">
            <Lock size={13} />
            <span>CRYPTOGRAPHIC SECURITY ATTESTATION</span>
          </div>
          <p className="text-[11px] leading-relaxed">
            Passwords are computationally hashed using Argon2 with a 64 MB memory cost.
            Plaintext passwords are never stored in memory or disk. All case dossiers, forensic artifacts,
            and threat metrics are strictly quarantined to your personal user account.
          </p>
        </div>
      </div>
    </div>
  );
}

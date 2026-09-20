import React, { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Shield, Mail, Lock, AlertCircle, CheckCircle2, Loader2, Eye, EyeOff } from "lucide-react";
import MorphingSvgBackground from "../components/MorphingSvgBackground";
import { getApiErrorMessage, requestPasswordReset, resetPassword } from "../api/client";

function Shell({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col justify-center items-center bg-lab-950 text-lab-100 relative overflow-hidden px-4 py-12">
      <MorphingSvgBackground />
      <div className="w-full max-w-md z-10 animate-fade-in">
        <div className="flex flex-col items-center text-center mb-8">
          <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-phosphor-500/15 border border-phosphor-500/40 glow-green mb-4">
            <Shield className="w-9 h-9 text-phosphor-400" strokeWidth={1.75} />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">MAILSHIELD</h1>
        </div>
        <div className="glass-panel-heavy p-8 rounded-2xl border border-white/10 shadow-2xl">
          <h2 className="text-lg font-bold text-white tracking-tight">{title}</h2>
          <p className="text-xs text-lab-400 mt-0.5 mb-6">{subtitle}</p>
          {children}
          <div className="mt-6 pt-5 border-t border-white/[0.08] text-center text-xs">
            <Link to="/login" className="text-phosphor-400 hover:text-phosphor-300 font-semibold">
              Back to sign in
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

function Banner({ kind, text }: { kind: "error" | "ok"; text: string }) {
  const cls =
    kind === "error"
      ? "bg-crimson-signal/15 border-crimson-signal/40 text-crimson-glow"
      : "bg-phosphor-500/10 border-phosphor-500/30 text-phosphor-300";
  const Icon = kind === "error" ? AlertCircle : CheckCircle2;
  return (
    <div className={`mb-5 p-3.5 rounded-xl border text-xs flex items-start gap-2.5 ${cls}`}>
      <Icon className="w-4 h-4 shrink-0 mt-0.5" />
      <div className="leading-relaxed">{text}</div>
    </div>
  );
}

const inputCls = "input-glass pl-10 pr-4 text-sm h-11 w-full text-lab-100 rounded-xl focus:border-phosphor-500/50";
const buttonCls =
  "w-full mt-2 h-11 rounded-xl bg-ember hover:bg-ember-deep text-snow font-bold text-sm flex items-center justify-center gap-2 disabled:opacity-60";

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return setError("Please enter a valid email address.");
    setBusy(true);
    try {
      setDone((await requestPasswordReset(email.trim())).message);
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell title="Reset your password" subtitle="We'll send a reset link if an account exists for this email.">
      {error && <Banner kind="error" text={error} />}
      {done ? (
        <Banner kind="ok" text={done} />
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <div className="relative">
            <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-lab-500" />
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="analyst@mailshield.ai" autoComplete="email" className={inputCls} />
          </div>
          <button type="submit" disabled={busy} className={buttonCls}>
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : null} SEND RESET LINK
          </button>
        </form>
      )}
    </Shell>
  );
}

export function ResetPasswordPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get("token") || "";
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(token ? null : "This reset link is invalid or incomplete.");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw))
      return setError("Password must have at least 8 characters, a letter and a number.");
    if (pw !== confirm) return setError("Passwords do not match.");
    setBusy(true);
    try {
      const res = await resetPassword({ token, new_password: pw, confirm_password: confirm });
      navigate("/login", { replace: true, state: { notice: res.message } });
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell title="Choose a new password" subtitle="All other devices will be signed out.">
      {error && <Banner kind="error" text={error} />}
      <form onSubmit={submit} className="space-y-4">
        <div className="relative">
          <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-lab-500" />
          <input type={show ? "text" : "password"} value={pw} onChange={(e) => setPw(e.target.value)} placeholder="New password" autoComplete="new-password" className={inputCls} />
          <button type="button" aria-label={show ? "Hide password" : "Show password"} onClick={() => setShow(!show)} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-lab-500">
            {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        <div className="relative">
          <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-lab-500" />
          <input type={show ? "text" : "password"} value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Confirm new password" autoComplete="new-password" className={inputCls} />
        </div>
        <button type="submit" disabled={busy || !token} className={buttonCls}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : null} UPDATE PASSWORD
        </button>
      </form>
    </Shell>
  );
}

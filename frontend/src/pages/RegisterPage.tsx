import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getApiErrorMessage } from "../api/client";

/** Mirrors the backend policy in services/auth_service.py::password_problems */
function passwordChecks(pw: string) {
  return [
    { ok: pw.length >= 8, label: "8+ characters" },
    { ok: /[A-Za-z]/.test(pw), label: "a letter" },
    { ok: /\d/.test(pw), label: "a number" },
  ];
}
import { Shield, Lock, Mail, User, Eye, EyeOff, ArrowRight, AlertCircle, CheckCircle2, Loader2 } from "lucide-react";
import MorphingSvgBackground from "../components/MorphingSvgBackground";

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (name.trim().length < 2) {
      setError("Please enter your full name (at least 2 characters).");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError("Please enter a valid email address.");
      return;
    }
    const failed = passwordChecks(password).filter((c) => !c.ok);
    if (failed.length) {
      setError("Password must contain " + failed.map((c) => c.label).join(", ") + ".");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match. Please re-enter.");
      return;
    }

    setSubmitting(true);
    try {
      await register(name.trim(), email.trim(), password, confirmPassword);
      navigate("/", { replace: true });
    } catch (err) {
      setError(getApiErrorMessage(err, "Registration failed. Please check your information."));
    } finally {
      setSubmitting(false);
    }
  }

  const passwordsMatch = password && confirmPassword && password === confirmPassword;

  return (
    <div className="min-h-screen flex flex-col justify-center items-center bg-lab-950 text-lab-100 relative overflow-hidden px-4 py-12">
      <MorphingSvgBackground />

      <div className="w-full max-w-md z-10 animate-fade-in">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="relative flex items-center justify-center w-16 h-16 rounded-2xl bg-phosphor-500/15 border border-phosphor-500/40 glow-green mb-4">
            <Shield className="w-9 h-9 text-phosphor-400" strokeWidth={1.75} />
            <span className="absolute -top-1 -right-1 h-3 w-3 rounded-full bg-phosphor-500 ring-4 ring-lab-950" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            MAILSHIELD
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-phosphor-500/20 text-phosphor-300 border border-phosphor-500/30">
              SIGN UP
            </span>
          </h1>
          <p className="text-xs text-lab-400 mt-1 font-mono tracking-wider">
            CREATE AN ANALYST PROFILE
          </p>
        </div>

        {/* Glassmorphic Register Card */}
        <div className="glass-panel-heavy p-8 rounded-2xl border border-white/10 shadow-2xl relative">
          <div className="mb-6">
            <h2 className="text-lg font-bold text-white tracking-tight">Create Your Account</h2>
            <p className="text-xs text-lab-400 mt-0.5">
              Securely store and isolate your email threat investigations
            </p>
          </div>

          {error && (
            <div className="mb-5 p-3.5 rounded-xl bg-crimson-signal/15 border border-crimson-signal/40 text-crimson-glow text-xs flex items-start gap-2.5 animate-shake">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="leading-relaxed">{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[11px] font-mono text-lab-300 uppercase tracking-wider mb-1.5 font-semibold">
                Full Name
              </label>
              <div className="relative">
                <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-lab-500" />
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Barani Dharan"
                  required
                  autoComplete="name"
                  className="input-glass pl-10 pr-4 text-sm h-11 w-full text-lab-100 rounded-xl focus:border-phosphor-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-mono text-lab-300 uppercase tracking-wider mb-1.5 font-semibold">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-lab-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@mailshield.ai"
                  required
                  autoComplete="email"
                  className="input-glass pl-10 pr-4 text-sm h-11 w-full text-lab-100 rounded-xl focus:border-phosphor-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-mono text-lab-300 uppercase tracking-wider mb-1.5 font-semibold">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-lab-500" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  autoComplete="new-password"
                  className="input-glass pl-10 pr-11 text-sm h-11 w-full text-lab-100 rounded-xl focus:border-phosphor-500/50"
                />
                <button
                  type="button"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-lab-500 hover:text-lab-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {password && (
                <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[10px] font-mono">
                  {passwordChecks(password).map((c) => (
                    <span key={c.label} className={c.ok ? "text-phosphor-400" : "text-lab-500"}>
                      {c.ok ? "✓" : "○"} {c.label}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-[11px] font-mono text-lab-300 uppercase tracking-wider font-semibold">
                  Confirm Password
                </label>
                {passwordsMatch && (
                  <span className="text-[10px] text-phosphor-400 flex items-center gap-1 font-mono">
                    <CheckCircle2 size={11} /> MATCH
                  </span>
                )}
              </div>
              <div className="relative">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-lab-500" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  autoComplete="new-password"
                  className={`input-glass pl-10 pr-4 text-sm h-11 w-full text-lab-100 rounded-xl ${
                    confirmPassword && !passwordsMatch ? "border-crimson-signal/50" : "focus:border-phosphor-500/50"
                  }`}
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full mt-2 h-11 rounded-xl bg-gradient-to-r from-phosphor-500 to-emerald-400
                text-lab-950 font-bold text-sm tracking-wide flex items-center justify-center gap-2
                shadow-lg shadow-phosphor-500/20 hover:brightness-110 active:scale-[0.99]
                transition-all duration-200 cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>CREATING ACCOUNT...</span>
                </>
              ) : (
                <>
                  <span>REGISTER FOR MAILSHIELD</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Switch to Login */}
          <div className="mt-6 pt-5 border-t border-white/[0.08] text-center">
            <p className="text-xs text-lab-400">
              Already registered with MailShield?{" "}
              <Link
                to="/login"
                className="text-phosphor-400 hover:text-phosphor-300 font-semibold underline underline-offset-2 transition-colors ml-1"
              >
                Sign in
              </Link>
            </p>
          </div>
        </div>

        {/* Security badge footer */}
        <div className="mt-6 text-center text-[10px] font-mono text-lab-600 flex items-center justify-center gap-2">
          <span>ARGON2 SECURED</span>
          <span>•</span>
          <span>ZERO PLAINTEXT PASSWORDS</span>
          <span>•</span>
          <span>ENTERPRISE FORENSICS</span>
        </div>
      </div>
    </div>
  );
}

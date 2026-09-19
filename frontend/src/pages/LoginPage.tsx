import React, { useState } from "react";
import { Link, Navigate, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getApiErrorMessage } from "../api/client";
import { Shield, Lock, Mail, Eye, EyeOff, ArrowRight, AlertCircle, Loader2 } from "lucide-react";
import MorphingSvgBackground from "../components/MorphingSvgBackground";

export default function LoginPage() {
  const { login, isAuthenticated, isLoading, sessionExpired } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);

  const from = (location.state as any)?.from?.pathname || "/";
  const notice: string | null =
    (location.state as any)?.notice || (sessionExpired ? "Your session has expired. Please sign in again." : null);

  if (!isLoading && isAuthenticated) {
    return <Navigate to={from} replace />;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!email.trim()) {
      setError("Please enter your email address.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError("Please enter a valid email address.");
      return;
    }
    if (!password) {
      setError("Please enter your password.");
      return;
    }

    setSubmitting(true);
    try {
      await login(email.trim(), password, rememberMe);
      navigate(from, { replace: true });
    } catch (err) {
      setError(getApiErrorMessage(err, "Sign-in failed. Please try again."));
    } finally {
      setSubmitting(false);
    }
  }

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
              PORTAL
            </span>
          </h1>
          <p className="text-xs text-lab-400 mt-1 font-mono tracking-wider">
            AI-POWERED EMAIL FORENSIC INTELLIGENCE
          </p>
        </div>

        {/* Glassmorphic Login Card */}
        <div className="glass-panel-heavy p-8 rounded-2xl border border-white/10 shadow-2xl relative">
          <div className="mb-6">
            <h2 className="text-lg font-bold text-white tracking-tight">Security Access Sign In</h2>
            <p className="text-xs text-lab-400 mt-0.5">
              Enter your authorized credentials to access your investigations
            </p>
          </div>

          {notice && !error && (
            <div className="mb-5 p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="leading-relaxed">{notice}</div>
            </div>
          )}

          {error && (
            <div className="mb-5 p-3.5 rounded-xl bg-crimson-signal/15 border border-crimson-signal/40 text-crimson-glow text-xs flex items-start gap-2.5 animate-shake">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="leading-relaxed">{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
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
                  autoComplete="current-password"
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
            </div>

            <div className="flex items-center justify-between text-xs">
              <label className="flex items-center gap-2 text-lab-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="accent-emerald-500 w-3.5 h-3.5"
                />
                Keep me signed in
              </label>
              <Link to="/forgot-password" className="text-phosphor-400 hover:text-phosphor-300">
                Forgot password?
              </Link>
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
                  <span>AUTHENTICATING...</span>
                </>
              ) : (
                <>
                  <span>SIGN IN TO MAILSHIELD</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Switch to Register */}
          <div className="mt-6 pt-5 border-t border-white/[0.08] text-center">
            <p className="text-xs text-lab-400">
              Don't have an analyst account?{" "}
              <Link
                to="/register"
                className="text-phosphor-400 hover:text-phosphor-300 font-semibold underline underline-offset-2 transition-colors ml-1"
              >
                Register here
              </Link>
            </p>
          </div>
        </div>

        {/* Security badge footer */}
        <div className="mt-6 text-center text-[10px] font-mono text-lab-600 flex items-center justify-center gap-2">
          <Link to="/privacy-policy" className="hover:text-lab-400">PRIVACY</Link>
          <span>•</span>
          <Link to="/terms" className="hover:text-lab-400">TERMS</Link>
          <span>•</span>
          <span>ARGON2 HASHED</span>
          <span>•</span>
          <span>JWT BEARER PROTECTED</span>
          <span>•</span>
          <span>USER DATA ISOLATED</span>
        </div>
      </div>
    </div>
  );
}

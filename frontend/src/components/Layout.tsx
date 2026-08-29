import { useState, useEffect } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  LayoutGrid, UploadCloud, History, Archive, Link2, FileText,
  Settings, ChevronRight, Sparkles, Radio, Shield, AlertTriangle,
  Brain, Search, Bell, Menu, X,
} from "lucide-react";
import MorphingSvgBackground from "./MorphingSvgBackground";
import MailShieldChatbot from "./MailShieldChatbot";
import { useChat } from "../context/ChatContext";

const NAV_ITEMS = [
  {
    group: "COMMAND CENTER",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutGrid, end: true },
      { to: "/alerts", label: "SOC Threat Center", icon: AlertTriangle },
    ],
  },
  {
    group: "INVESTIGATION",
    items: [
      { to: "/upload", label: "Email Analysis", icon: UploadCloud },
      { to: "/history", label: "Case History", icon: History },
    ],
  },
  {
    group: "FORENSICS",
    items: [
      { to: "/evidence-vault", label: "Evidence Vault", icon: Archive },
      { to: "/ledger", label: "Integrity Ledger", icon: Link2 },
    ],
  },
  {
    group: "SYSTEM",
    items: [
      { to: "/history", label: "Reports", icon: FileText },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

const morphShieldPaths = [
  "M 12 2 Q 18 1 20 5 Q 22 1 28 2 Q 29 14 20 26 Q 11 14 12 2 Z",
  "M 12 3 Q 17 2 20 4 Q 23 2 28 3 Q 30 15 20 27 Q 10 15 12 3 Z",
  "M 11 2 Q 18 1 20 5 Q 22 1 29 2 Q 29 13 20 25 Q 11 13 11 2 Z",
];

export default function Layout() {
  const { setIsOpen } = useChat();
  const navigate = useNavigate();
  const [shieldState, setShieldState] = useState(0);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [backendAlive, setBackendAlive] = useState(true);

  useEffect(() => {
    const timer = setInterval(() => setShieldState((s) => (s + 1) % 3), 2800);
    return () => clearInterval(timer);
  }, []);

  // Periodically ping backend health
  useEffect(() => {
    const check = () =>
      fetch("http://localhost:8000/api/v1/dashboard/stats", { signal: AbortSignal.timeout(3000) })
        .then(() => setBackendAlive(true))
        .catch(() => setBackendAlive(false));
    check();
    const t = setInterval(check, 30000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-lab-950 text-lab-100 relative overflow-hidden">
      <MorphingSvgBackground />

      {/* ─── TOP NAVIGATION BAR ───────────────────────────────────────── */}
      <header className="topbar-glass sticky top-0 z-50 flex-shrink-0">
        <div className="flex items-center h-14 px-4 gap-3">

          {/* Mobile hamburger */}
          <button
            className="lg:hidden p-2 rounded-lg text-lab-400 hover:text-lab-100 hover:bg-white/5 transition-colors"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>

          {/* Brand mark (top bar, desktop hidden — sidebar has full brand) */}
          <div className="flex items-center gap-2 lg:hidden">
            <div className="relative flex items-center justify-center w-7 h-7 rounded-md bg-phosphor-500/15 border border-phosphor-500/35">
              <svg viewBox="0 0 40 30" className="w-4 h-4 svg-glow">
                <path
                  d={morphShieldPaths[shieldState]}
                  fill="none" stroke="#3ddc97" strokeWidth="2.5"
                  strokeLinecap="round" strokeLinejoin="round"
                  className="transition-all duration-500 ease-in-out"
                />
              </svg>
            </div>
            <span className="font-bold text-lab-100 text-sm tracking-tight">MailShield</span>
          </div>

          {/* Search bar */}
          <div className="flex-1 max-w-md mx-4 hidden sm:flex">
            <div className="relative w-full">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-lab-500" />
              <input
                type="text"
                placeholder="Search investigations, cases, alerts…"
                className="input-glass pl-9 text-sm h-9 text-lab-300"
                onFocus={() => navigate("/history")}
                readOnly
              />
            </div>
          </div>

          <div className="flex items-center gap-2 ml-auto">
            {/* Protection status badge */}
            <div className={
              "hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold evidence-tag " +
              (backendAlive
                ? "bg-phosphor-500/10 border border-phosphor-500/25 text-phosphor-400"
                : "bg-crimson-signal/10 border border-crimson-signal/30 text-crimson-glow")
            }>
              <span className={backendAlive ? "live-dot" : "h-1.5 w-1.5 rounded-full bg-crimson-signal shrink-0"} />
              {backendAlive ? "● PROTECTED" : "● OFFLINE"}
            </div>

            {/* AI Chat button */}
            <button
              onClick={() => setIsOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold
                bg-gradient-to-r from-purple-500/15 via-phosphor-500/10 to-purple-500/15
                border border-phosphor-500/25 text-lab-200 hover:text-phosphor-300
                hover:border-phosphor-500/45 transition-all duration-200"
            >
              <Brain className="h-3.5 w-3.5 text-phosphor-400" />
              <span className="hidden md:inline">AI Assistant</span>
            </button>

            {/* Alerts bell */}
            <button
              onClick={() => navigate("/alerts")}
              className="relative p-2 rounded-lg text-lab-400 hover:text-lab-100 hover:bg-white/5 transition-colors"
            >
              <Bell className="h-4 w-4" />
              <span className="absolute top-1 right-1 h-2 w-2 rounded-full bg-crimson-signal animate-critical" />
            </button>
          </div>
        </div>
      </header>

      {/* ─── BODY (sidebar + main) ────────────────────────────────────── */}
      <div className="flex flex-1 min-h-0">

        {/* Mobile overlay */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* ─── GLASSMORPHIC SIDEBAR ──────────────────────────────────── */}
        <aside className={
          "w-64 shrink-0 border-r border-white/[0.06] glass-panel-heavy z-40 flex flex-col " +
          "fixed lg:relative inset-y-0 left-0 transition-transform duration-300 ease-in-out " +
          (sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0")
        }>

          {/* Brand */}
          <div className="px-5 py-5 border-b border-white/[0.06] flex items-center gap-3 flex-shrink-0">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-phosphor-500/12 border border-phosphor-500/30 glow-green">
              <svg viewBox="0 0 40 30" className="w-6 h-6 svg-glow">
                <path
                  d={morphShieldPaths[shieldState]}
                  fill="none" stroke="#3ddc97" strokeWidth="2"
                  strokeLinecap="round" strokeLinejoin="round"
                  className="transition-all duration-500 ease-in-out"
                />
                <circle cx="20" cy="14" r="2" fill="#3ddc97" className="animate-pulse" />
              </svg>
              <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-phosphor-500 ring-2 ring-lab-950" />
            </div>
            <div>
              <div className="font-bold tracking-tight text-lab-100 leading-none text-[15px] flex items-center gap-1.5">
                MailShield
                <Sparkles size={11} className="text-phosphor-400 opacity-75" />
              </div>
              <div className="text-[9.5px] text-lab-500 evidence-tag mt-0.5 leading-none">
                AI-POWERED EMAIL FORENSICS
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-2.5 py-4 space-y-4 overflow-y-auto">
            {NAV_ITEMS.map((group) => (
              <div key={group.group}>
                <div className="px-2.5 mb-1.5 text-[9px] text-lab-600 evidence-tag font-bold tracking-widest">
                  {group.group}
                </div>
                <div className="space-y-0.5">
                  {group.items.map(({ to, label, icon: Icon, end }) => (
                    <NavLink
                      key={label}
                      to={to}
                      end={end}
                      onClick={() => setSidebarOpen(false)}
                      className={({ isActive }) =>
                        "flex items-center justify-between gap-2.5 rounded-lg px-3 py-2.5 text-[13px] font-medium transition-all duration-200 " +
                        (isActive
                          ? "bg-phosphor-500/12 text-phosphor-400 border border-phosphor-500/35 glow-green"
                          : "text-lab-400 hover:bg-white/[0.04] hover:text-lab-200 border border-transparent")
                      }
                    >
                      <span className="flex items-center gap-2.5">
                        <Icon className="h-[15px] w-[15px] shrink-0" strokeWidth={1.75} />
                        {label}
                      </span>
                      <ChevronRight className="h-3 w-3 opacity-25 shrink-0" />
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </nav>

          {/* AI Forensic Chatbot launcher */}
          <div className="px-2.5 pb-2">
            <button
              onClick={() => { setIsOpen(true); setSidebarOpen(false); }}
              className="w-full flex items-center justify-between gap-2 rounded-xl px-3 py-2.5 text-xs font-semibold
                bg-gradient-to-r from-purple-500/12 via-phosphor-500/8 to-purple-500/12
                border border-phosphor-500/25 hover:border-phosphor-400/50
                text-lab-200 hover:text-phosphor-300 transition-all duration-250 group"
            >
              <span className="flex items-center gap-2">
                <Brain className="h-4 w-4 text-phosphor-400 group-hover:text-phosphor-300 transition-colors" />
                <span>Forensic AI Chat</span>
              </span>
              <span className="text-[8px] px-1.5 py-0.5 rounded bg-phosphor-500/20 text-phosphor-300 border border-phosphor-500/35 font-mono tracking-widest">
                GEMINI
              </span>
            </button>
          </div>

          {/* System Status footer */}
          <div className="px-3 pb-4 pt-2 border-t border-white/[0.06] mt-1">
            <div className="glass-card px-3.5 py-3 rounded-xl !bg-black/25">
              <div className="flex items-center gap-2 mb-1.5">
                <Radio className="h-3 w-3 text-phosphor-500 animate-pulse shrink-0" />
                <span className="text-[10px] text-lab-300 evidence-tag font-semibold tracking-wider">SYSTEM STATUS</span>
              </div>
              <div className="flex items-center gap-1.5 mb-1">
                <span className={backendAlive ? "live-dot" : "h-1.5 w-1.5 rounded-full bg-crimson-signal shrink-0"} />
                <span className={
                  "text-[10px] evidence-tag font-bold " +
                  (backendAlive ? "text-phosphor-400" : "text-crimson-glow")
                }>
                  {backendAlive ? "ANALYSIS ENGINE ONLINE" : "BACKEND OFFLINE"}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <Shield className="h-2.5 w-2.5 text-phosphor-500 shrink-0" />
                <span className="text-[9.5px] text-lab-500 evidence-tag">Protection Active</span>
              </div>
              <div className="text-[9px] text-lab-600 mt-1.5 font-mono">SIH 2026 · PS 26106 · AICTE CSC</div>
            </div>
          </div>
        </aside>

        {/* ─── MAIN CONTENT ─────────────────────────────────────────── */}
        <main className="flex-1 min-w-0 scanline overflow-y-auto relative">
          <div className="min-h-full">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Global AI Chatbot */}
      <MailShieldChatbot />
    </div>
  );
}

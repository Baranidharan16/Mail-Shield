import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Siren, VolumeX, Volume2, Check, CheckCheck, ExternalLink } from "lucide-react";
import {
  getSocAlarms, getSocConfig, ackSocAlarm, ackAllSocAlarms, SOC_CONFIG_EVENT,
  type SocAlarm, type SocConfig,
} from "../api/advanced";

/** Two-tone siren generated with WebAudio (no audio files to ship). */
function playSiren(ctx: AudioContext, seconds = 2.4) {
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = "sawtooth";
  const t0 = ctx.currentTime;
  for (let i = 0; i < seconds / 0.4; i++) {
    osc.frequency.setValueAtTime(i % 2 ? 660 : 880, t0 + i * 0.4);
  }
  gain.gain.setValueAtTime(0.0001, t0);
  gain.gain.exponentialRampToValueAtTime(0.12, t0 + 0.05);
  gain.gain.setValueAtTime(0.12, t0 + seconds - 0.1);
  gain.gain.exponentialRampToValueAtTime(0.0001, t0 + seconds);
  osc.connect(gain).connect(ctx.destination);
  osc.start(t0);
  osc.stop(t0 + seconds);
}

const POLL_MS = 15000;

export default function SOCAlarmCenter() {
  const navigate = useNavigate();
  const [alarms, setAlarms] = useState<SocAlarm[]>([]);
  const [cfg, setCfg] = useState<SocConfig | null>(null);
  const [muted, setMuted] = useState(false);
  const seen = useRef<Set<string>>(new Set());
  const first = useRef(true);
  const audio = useRef<AudioContext | null>(null);
  const lastSound = useRef(0);

  // Browsers only allow audio after a user gesture — unlock on first click/key.
  useEffect(() => {
    const unlock = () => {
      try {
        if (!audio.current) audio.current = new (window.AudioContext || (window as any).webkitAudioContext)();
        audio.current.resume();
      } catch { /* audio unsupported */ }
    };
    window.addEventListener("pointerdown", unlock, { once: true });
    window.addEventListener("keydown", unlock, { once: true });
    return () => { window.removeEventListener("pointerdown", unlock); window.removeEventListener("keydown", unlock); };
  }, []);

  useEffect(() => {
    getSocConfig().then(setCfg).catch(() => {});
    const onCfg = (e: Event) => setCfg((e as CustomEvent<SocConfig>).detail);
    window.addEventListener(SOC_CONFIG_EVENT, onCfg);
    return () => window.removeEventListener(SOC_CONFIG_EVENT, onCfg);
  }, []);

  const sound = useCallback(() => {
    if (muted || !cfg?.sound_enabled || !audio.current || audio.current.state !== "running") return;
    lastSound.current = Date.now();
    playSiren(audio.current);
  }, [muted, cfg?.sound_enabled]);

  const poll = useCallback(async () => {
    try {
      const d = await getSocAlarms("ACTIVE", 20);
      setAlarms(d.alarms);
      const fresh = d.alarms.filter((a) => !seen.current.has(a.id));
      d.alarms.forEach((a) => seen.current.add(a.id));
      if (fresh.length && !first.current && cfg?.alarm_enabled !== false) {
        sound();
        if (cfg?.browser_notifications && "Notification" in window && Notification.permission === "granted") {
          const a = fresh[0];
          const n = new Notification(`MailShield SOC alarm — ${a.severity}`, { body: a.title, tag: a.id, requireInteraction: a.severity === "CRITICAL" });
          n.onclick = () => { window.focus(); if (a.investigation_id) navigate(`/investigations/${a.investigation_id}`); };
        }
      } else if (d.alarms.length && cfg?.repeat_until_ack && Date.now() - lastSound.current > (cfg.repeat_interval_seconds || 30) * 1000) {
        sound();
      }
      first.current = false;
    } catch { /* not signed in / offline */ }
  }, [cfg, sound, navigate]);

  useEffect(() => {
    poll();
    const t = setInterval(poll, POLL_MS);
    return () => clearInterval(t);
  }, [poll]);

  if (!alarms.length || cfg?.alarm_enabled === false) return null;
  const top = alarms[0];
  const crit = alarms.some((a) => a.severity === "CRITICAL");

  async function ack(id: string) {
    await ackSocAlarm(id).catch(() => {});
    setAlarms((p) => p.filter((a) => a.id !== id));
  }
  async function ackAll() {
    await ackAllSocAlarms().catch(() => {});
    setAlarms([]);
  }

  return (
    <div role="alert" className={`relative z-40 flex flex-wrap items-center gap-3 px-4 py-2 text-xs border-b ${crit
      ? "bg-crimson-signal text-white border-crimson-glow animate-pulse"
      : "bg-orange-500 text-white border-orange-600"}`}>
      <Siren className="h-4 w-4 shrink-0" />
      <span className="font-bold tracking-wide font-mono">SOC ALARM · {alarms.length} ACTIVE</span>
      <span className="font-mono px-1.5 py-0.5 rounded bg-black/20">{top.severity}</span>
      <span className="font-mono px-1.5 py-0.5 rounded bg-black/20">{top.source}</span>
      {top.escalated && <span className="font-mono px-1.5 py-0.5 rounded bg-black/30">ESCALATED</span>}
      <span className="font-semibold truncate max-w-[40ch]" title={top.message ?? ""}>{top.title}</span>
      <div className="ml-auto flex items-center gap-1.5">
        {top.investigation_id && (
          <button onClick={() => navigate(`/investigations/${top.investigation_id}`)}
            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-white/15 hover:bg-white/25 cursor-pointer"><ExternalLink className="h-3.5 w-3.5" /> View case</button>
        )}
        <button onClick={() => ack(top.id)} className="inline-flex items-center gap-1 px-2 py-1 rounded bg-white/15 hover:bg-white/25 cursor-pointer"><Check className="h-3.5 w-3.5" /> Acknowledge</button>
        {alarms.length > 1 && (
          <button onClick={ackAll} className="inline-flex items-center gap-1 px-2 py-1 rounded bg-white/15 hover:bg-white/25 cursor-pointer"><CheckCheck className="h-3.5 w-3.5" /> Ack all</button>
        )}
        <button onClick={() => setMuted(!muted)} title={muted ? "Unmute siren" : "Mute siren for this session"}
          className="p-1 rounded bg-white/15 hover:bg-white/25 cursor-pointer">{muted ? <VolumeX className="h-3.5 w-3.5" /> : <Volume2 className="h-3.5 w-3.5" />}</button>
        <button onClick={() => navigate("/soc/config")} className="px-2 py-1 rounded bg-white/15 hover:bg-white/25 cursor-pointer">Configure</button>
      </div>
    </div>
  );
}

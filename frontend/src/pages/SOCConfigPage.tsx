import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Siren, Save, BellRing, Box, CheckCircle2, XCircle, Loader2, Webhook, History } from "lucide-react";
import { getApiErrorMessage } from "../api/client";
import {
  getSocConfig, updateSocConfig, getSocAlarms, ackSocAlarm, testSocAlarm, getSandboxHealth,
  type SocConfig, type SocAlarm,
} from "../api/advanced";

function Toggle({ label, hint, value, onChange }: { label: string; hint?: string; value: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-start justify-between gap-4 py-2.5 border-b border-lab-800 cursor-pointer">
      <span><span className="text-sm text-lab-100 font-medium">{label}</span>{hint && <span className="block text-xs text-lab-500">{hint}</span>}</span>
      <button type="button" onClick={() => onChange(!value)} aria-pressed={value}
        className={`relative w-10 h-5 rounded-full transition-colors shrink-0 mt-0.5 cursor-pointer ${value ? "bg-phosphor-500" : "bg-lab-700"}`}>
        <span style={{ backgroundColor: "#ffffff" }} className={`absolute top-0.5 h-4 w-4 rounded-full shadow transition-all ${value ? "left-5" : "left-0.5"}`} />
      </button>
    </label>
  );
}

function Select<T extends string>({ label, hint, value, options, onChange }: { label: string; hint?: string; value: T; options: { v: T; l: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5 border-b border-lab-800">
      <span><span className="text-sm text-lab-100 font-medium">{label}</span>{hint && <span className="block text-xs text-lab-500">{hint}</span>}</span>
      <select value={value} onChange={(e) => onChange(e.target.value as T)}
        className="text-sm bg-lab-900 border border-lab-700 rounded-md px-2 py-1 text-lab-100">
        {options.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}
      </select>
    </div>
  );
}

export default function SOCConfigPage() {
  const [cfg, setCfg] = useState<SocConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [alarms, setAlarms] = useState<SocAlarm[]>([]);
  const [health, setHealth] = useState<Awaited<ReturnType<typeof getSandboxHealth>> | null>(null);
  const [perm, setPerm] = useState<string>("Notification" in window ? Notification.permission : "unsupported");

  const loadAlarms = () => getSocAlarms(undefined, 30).then((d) => setAlarms(d.alarms)).catch(() => {});
  useEffect(() => {
    getSocConfig().then(setCfg).catch((e) => setMsg({ ok: false, text: getApiErrorMessage(e) }));
    loadAlarms();
    getSandboxHealth().then(setHealth).catch(() => setHealth({ reachable: false, configured: false }));
  }, []);

  const set = <K extends keyof SocConfig>(k: K, v: SocConfig[K]) => setCfg((c) => (c ? { ...c, [k]: v } : c));

  async function save() {
    if (!cfg) return;
    setSaving(true);
    setMsg(null);
    try {
      const { updated_at: _u, ...body } = cfg;
      void _u;
      setCfg(await updateSocConfig({ ...body, webhook_url: body.webhook_url || null, escalation_contact: body.escalation_contact || null }));
      setMsg({ ok: true, text: "SOC configuration saved." });
    } catch (e) {
      setMsg({ ok: false, text: getApiErrorMessage(e, "Could not save configuration.") });
    } finally {
      setSaving(false);
    }
  }

  async function askPermission() {
    if (!("Notification" in window)) return;
    setPerm(await Notification.requestPermission());
  }

  if (!cfg) return <div className="p-8 text-sm text-lab-400">{msg?.text ?? "Loading SOC configuration…"}</div>;

  return (
    <div className="p-8 max-w-5xl">
      <div className="flex items-center gap-3 mb-6">
        <Siren className="h-6 w-6 text-crimson-glow" />
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SOC Alarm Configuration</h1>
          <p className="text-sm text-lab-400">How the SOC is alerted when a threat e-mail, a malicious sandbox result or a regulatory violation is detected.</p>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <div className="glass-section p-5">
          <div className="flex items-center gap-2 mb-2"><BellRing className="h-4 w-4 text-phosphor-500" /><h2 className="font-semibold text-sm">Alarm rules</h2></div>
          <Toggle label="Alarms enabled" hint="Show the red alarm bar across every page" value={cfg.alarm_enabled} onChange={(v) => set("alarm_enabled", v)} />
          <Select label="Minimum severity" hint="Detections at or above this level raise an alarm" value={cfg.min_severity}
            options={[{ v: "MEDIUM", l: "MEDIUM and above" }, { v: "HIGH", l: "HIGH and above" }, { v: "CRITICAL", l: "CRITICAL only" }]}
            onChange={(v) => set("min_severity", v)} />
          <Toggle label="Siren sound" hint="Two-tone siren in the browser" value={cfg.sound_enabled} onChange={(v) => set("sound_enabled", v)} />
          <Toggle label="Repeat until acknowledged" value={cfg.repeat_until_ack} onChange={(v) => set("repeat_until_ack", v)} />
          <div className="flex items-center justify-between gap-4 py-2.5 border-b border-lab-800">
            <span className="text-sm text-lab-100 font-medium">Repeat interval (seconds)</span>
            <input type="number" min={10} max={600} value={cfg.repeat_interval_seconds}
              onChange={(e) => set("repeat_interval_seconds", Number(e.target.value))}
              className="w-24 text-sm bg-lab-900 border border-lab-700 rounded-md px-2 py-1 text-lab-100" />
          </div>
          <Toggle label="Browser / desktop notifications" hint={`Permission: ${perm}`} value={cfg.browser_notifications}
            onChange={(v) => { set("browser_notifications", v); if (v && perm === "default") askPermission(); }} />
          {cfg.browser_notifications && perm !== "granted" && perm !== "unsupported" && (
            <button onClick={askPermission} className="mt-2 text-xs underline text-lab-300 cursor-pointer">Allow notifications in this browser</button>
          )}
          <Toggle label="Alarm when sandbox confirms MALICIOUS" value={cfg.alarm_on_sandbox_malicious} onChange={(v) => set("alarm_on_sandbox_malicious", v)} />
          <Toggle label="Alarm on GRC (legal) violations" value={cfg.alarm_on_grc_violation} onChange={(v) => set("alarm_on_grc_violation", v)} />
          <Toggle label="Auto-escalate CRITICAL alarms" hint="Marks the alarm ESCALATED and notifies the escalation contact / webhook" value={cfg.auto_escalate_critical} onChange={(v) => set("auto_escalate_critical", v)} />
        </div>

        <div className="space-y-6">
          <div className="glass-section p-5">
            <div className="flex items-center gap-2 mb-2"><Box className="h-4 w-4 text-phosphor-500" /><h2 className="font-semibold text-sm">Isolated sandbox</h2></div>
            <Select label="Send to sandbox" hint="Which e-mails are quarantined and detonated automatically" value={cfg.sandbox_scope}
              options={[{ v: "SUSPICIOUS", l: "Suspicious e-mails (≥ MEDIUM)" }, { v: "ALL", l: "All e-mails" }, { v: "OFF", l: "Off (manual only)" }]}
              onChange={(v) => set("sandbox_scope", v)} />
            <div className="flex items-center gap-2 pt-3 text-sm">
              {health === null ? <Loader2 className="h-4 w-4 animate-spin text-lab-500" /> : health.reachable
                ? <CheckCircle2 className="h-4 w-4 text-phosphor-400" /> : <XCircle className="h-4 w-4 text-crimson-glow" />}
              <span className="text-lab-200">{health === null ? "Checking sandbox…" : health.reachable ? `Sandbox online · ${health.engine ?? ""}` :
                health.configured ? `Sandbox unreachable (${health.detail ?? "asleep?"}) — it wakes on the next submission` : "Sandbox not configured (SANDBOX_URL)"}</span>
            </div>
            <div className="text-xs text-lab-500 mt-1">Separate container · HMAC-signed requests · receives only attachment bytes, URLs and HTML — never credentials, database or host files.</div>
          </div>

          <div className="glass-section p-5">
            <div className="flex items-center gap-2 mb-2"><Webhook className="h-4 w-4 text-phosphor-500" /><h2 className="font-semibold text-sm">Escalation & integrations</h2></div>
            <label className="block py-2">
              <span className="text-sm text-lab-100 font-medium">Escalation contact</span>
              <input value={cfg.escalation_contact ?? ""} onChange={(e) => set("escalation_contact", e.target.value)} placeholder="soc-lead@org.in / +91-…"
                className="mt-1 w-full text-sm bg-lab-900 border border-lab-700 rounded-md px-2 py-1.5 text-lab-100" />
            </label>
            <label className="block py-2">
              <span className="text-sm text-lab-100 font-medium">Webhook (Slack / Teams / SIEM)</span>
              <input value={cfg.webhook_url ?? ""} onChange={(e) => set("webhook_url", e.target.value)} placeholder="https://hooks.slack.com/services/…"
                className="mt-1 w-full text-sm bg-lab-900 border border-lab-700 rounded-md px-2 py-1.5 text-lab-100 font-data" />
              <span className="text-xs text-lab-500">HTTPS only; internal/private addresses are refused. Payload carries no e-mail content.</span>
            </label>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 mt-6">
        <button onClick={save} disabled={saving}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-ember text-white text-sm font-semibold disabled:opacity-60 cursor-pointer">
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save configuration
        </button>
        <button onClick={async () => { await testSocAlarm().catch(() => {}); loadAlarms(); setMsg({ ok: true, text: "Test alarm raised — the alarm bar appears within 15 seconds." }); }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-lab-700 text-sm text-lab-200 hover:border-lab-500 cursor-pointer">
          <Siren className="h-4 w-4" /> Trigger test alarm
        </button>
        {msg && <span className={`text-sm ${msg.ok ? "text-phosphor-300" : "text-crimson-glow"}`}>{msg.text}</span>}
      </div>

      <div className="glass-section p-5 mt-8">
        <div className="flex items-center gap-2 mb-3"><History className="h-4 w-4 text-phosphor-500" /><h2 className="font-semibold text-sm">Alarm history</h2></div>
        {alarms.length === 0 ? <div className="text-sm text-lab-500">No alarms yet.</div> : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-[10px] text-lab-500 evidence-tag border-b border-lab-700">
                <th className="py-2 pr-3">TIME</th><th className="py-2 pr-3">SEVERITY</th><th className="py-2 pr-3">SOURCE</th><th className="py-2 pr-3">ALARM</th><th className="py-2 pr-3">STATUS</th><th className="py-2"></th></tr></thead>
              <tbody>
                {alarms.map((a) => (
                  <tr key={a.id} className="border-b border-lab-800 align-top">
                    <td className="py-2 pr-3 font-data text-lab-400 whitespace-nowrap">{a.created_at ? new Date(a.created_at).toLocaleString() : "—"}</td>
                    <td className="py-2 pr-3 font-mono font-semibold">{a.severity}{a.escalated ? " ↑" : ""}</td>
                    <td className="py-2 pr-3 font-mono text-lab-400">{a.source}</td>
                    <td className="py-2 pr-3"><div className="text-lab-100">{a.title}</div>{a.message && <div className="text-lab-500">{a.message}</div>}
                      {a.webhook_status && <div className="text-[10px] text-lab-600 font-mono">webhook: {a.webhook_status}</div>}</td>
                    <td className="py-2 pr-3 font-mono">{a.status}{a.acknowledged_by ? <div className="text-[10px] text-lab-600">{a.acknowledged_by}</div> : null}</td>
                    <td className="py-2 whitespace-nowrap">
                      {a.investigation_id && <Link to={`/investigations/${a.investigation_id}`} className="underline text-lab-300 mr-2">case</Link>}
                      {a.status === "ACTIVE" && <button onClick={async () => { await ackSocAlarm(a.id); loadAlarms(); }} className="underline text-lab-300 cursor-pointer">ack</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

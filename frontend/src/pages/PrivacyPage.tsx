import React, { useEffect, useState } from "react";
import { Shield, Trash2, Loader2, Database, Mail, Globe2, Link2, Scale, Clock } from "lucide-react";
import { deleteMyData, getMyDataSummary, getApiErrorMessage } from "../api/client";

function Block({ icon: Icon, title, children }: { icon: typeof Shield; title: string; children: React.ReactNode }) {
  return (
    <div className="glass-section p-5">
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4 text-phosphor-400" />
        <h2 className="text-sm font-bold text-white">{title}</h2>
      </div>
      <div className="text-xs text-lab-300 leading-relaxed space-y-2">{children}</div>
    </div>
  );
}

export const PrivacyPage: React.FC = () => {
  const [summary, setSummary] = useState<Record<string, any> | null>(null);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => getMyDataSummary().then(setSummary).catch(() => setSummary(null));
  useEffect(() => { load(); }, []);

  async function erase() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await deleteMyData();
      setMsg(`${r.message} (${r.deleted_investigations} investigations removed)`);
      setConfirm("");
      load();
    } catch (e) {
      setMsg(getApiErrorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const retention = summary?.retention_days;

  return (
    <div className="space-y-4 max-w-4xl">
      <div>
        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 uppercase tracking-wider mb-1">
          <Shield className="h-4 w-4" /> Privacy, data handling & ethical limits
        </div>
        <h1 className="text-2xl font-bold text-white tracking-tight">How MailShield handles your data</h1>
        <p className="text-xs text-lab-400 mt-1">This describes what the running system actually does (not a template).</p>
      </div>

      {summary && (
        <div className="glass-section p-4 grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
          <div><div className="text-xl font-data text-white">{String(summary.investigations)}</div><div className="text-[10px] text-lab-500">YOUR INVESTIGATIONS</div></div>
          <div><div className="text-xl font-data text-white">{String(summary.processed_emails)}</div><div className="text-[10px] text-lab-500">MONITORED EMAILS</div></div>
          <div><div className="text-xl font-data text-white">{summary.gmail_connected ? "Yes" : "No"}</div><div className="text-[10px] text-lab-500">GMAIL CONNECTED</div></div>
          <div><div className="text-xl font-data text-white">{retention ? `${retention} days` : "Kept"}</div><div className="text-[10px] text-lab-500">RETENTION</div></div>
        </div>
      )}

      <Block icon={Database} title="What is collected, why, and where it is stored">
        <p><b>Account:</b> name, e-mail, Argon2id password hash (never the password), login sessions (refresh tokens stored only as SHA-256 hashes).</p>
        <p><b>Emails you submit or that the monitor ingests:</b> the raw message file (evidence), parsed headers, sender/recipient addresses, subject, URLs, domains, relay IPs, attachment names + SHA-256 hashes (attachments are never opened or executed), and the forensic results (scores, findings, report).</p>
        <p><b>Why:</b> only to detect threats and to produce a verifiable forensic record for you. No data is used for advertising or model training without your explicit action.</p>
        <p><b>Where:</b> the platform's PostgreSQL database and the server's evidence storage. Every record carries your user id and the backend only ever returns records whose owner equals the signed-in user (enforced server-side on every route).</p>
      </Block>

      <Block icon={Clock} title="Retention & deletion">
        <p>Investigations older than <b>{retention ? `${retention} days` : "the configured retention period"}</b> are purged automatically (evidence file, parsed data, report). You can delete a single investigation or everything below at any time.</p>
        <p>Ledger blocks are kept after deletion because they contain only hashes and a case id — no e-mail content or personal data — and removing them would break the tamper-evident chain.</p>
      </Block>

      <Block icon={Mail} title="Gmail permissions">
        <p>Gmail is connected with Google OAuth 2.0 — MailShield never sees or stores your Google password. Scopes requested: your e-mail/profile (to show which account is linked), <code>gmail.readonly</code> (read messages for analysis) and <code>gmail.modify</code> (only used if you click Quarantine/Release, or if an administrator enables automatic quarantine).</p>
        <p>OAuth access and refresh tokens are encrypted at rest (Fernet/AES) and decrypted only in memory for an API call. They are never sent to the browser. Disconnecting Gmail or deleting your data removes them.</p>
        <p>Your own messages (sent from your address) are skipped by the monitor and your address is never treated as an attacker.</p>
      </Block>

      <Block icon={Globe2} title="Third-party services that receive data">
        <p><b>ip-api.com</b> — public relay IP addresses from headers (for approximate geolocation / network owner). <b>rdap.org / public DNS</b> — sender and link domains (registration age, MX, SPF, DMARC). <b>Google Gemini</b> (only if configured) — a summary of the detection results (subject, sender, scores, indicators) to write the plain-language explanation. <b>Sarvam AI</b> (only for voice features) — the text/audio you send to the assistant. No other third party receives e-mail data.</p>
        <p><b>Geolocation limits:</b> an IP location is the approximate location of network infrastructure (mail provider, cloud, VPN or ISP), accurate to country level at best and often wrong at city level. It is never the physical location or identity of the sender, and the platform never uses browser GPS or tracks people.</p>
      </Block>

      <Block icon={Link2} title="Blockchain-style integrity ledger">
        <p>When an analysis completes, the SHA-256 of the evidence file and of the forensic report are written to a hash-chained ledger (each block includes the previous block's hash). Verification recalculates both hashes from the current data and reports VALID or MODIFIED.</p>
        <p>The ledger stores only: case id, evidence hash, report hash, timestamp, previous hash, block hash. It proves integrity; it does not encrypt or hide the e-mail data, and it is not a public blockchain.</p>
      </Block>

      <Block icon={Scale} title="Ethical & legal limits">
        <p>MailShield is a defensive tool for analysing e-mails you are authorised to access. It does not access accounts without OAuth consent, deploy malware, probe or attack third-party systems, or claim to identify a person from an IP address. "Origin tracing" means describing infrastructure observed in the e-mail's own headers, always labelled OBSERVED / INFERRED / UNKNOWN.</p>
      </Block>

      <div className="glass-section p-5 border border-crimson-signal/30">
        <div className="flex items-center gap-2 mb-2"><Trash2 className="w-4 h-4 text-crimson-glow" /><h2 className="text-sm font-bold text-white">Delete all my forensic data</h2></div>
        <p className="text-xs text-lab-400 mb-3">Removes all your investigations, evidence files, monitor records and stored Gmail tokens. Your login account remains. This cannot be undone. Type <b>DELETE</b> to confirm.</p>
        <div className="flex gap-2">
          <input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="DELETE" className="input-glass h-9 px-3 text-sm rounded-lg w-40" />
          <button onClick={erase} disabled={confirm !== "DELETE" || busy}
            className="h-9 px-4 rounded-lg bg-crimson-signal/80 text-white text-xs font-bold disabled:opacity-40 flex items-center gap-2">
            {busy && <Loader2 className="w-3 h-3 animate-spin" />} Delete my data
          </button>
        </div>
        {msg && <div className="text-xs text-lab-200 mt-2">{msg}</div>}
      </div>
    </div>
  );
};

export default PrivacyPage;

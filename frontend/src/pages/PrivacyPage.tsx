import React, { useState } from "react";
import {
  Shield,
  Lock,
  EyeOff,
  CheckCircle2,
  Clock,
} from "lucide-react";


export const PrivacyPage: React.FC = () => {
  const [retentionDays, setRetentionDays] = useState("90");
  const [savedNotice, setSavedNotice] = useState(false);

  const sampleRawText = `Dear Employee,
Your account john.doe@victim-bank.com has been flagged for immediate suspension.
Please contact support manager Robert Smith at +91 98765 43210 or reset your credentials at:
http://login.victim-bank.com.sec-verify.xyz/login?user=john.doe@victim-bank.com
Temporary Password: Password#2026!`;

  const sampleMaskedText = `Dear Employee,
Your account [EMAIL_REDACTED_#1] has been flagged for immediate suspension.
Please contact support manager [NAME_REDACTED] at [PHONE_REDACTED] or reset your credentials at:
http://login.victim-bank.com.sec-verify.xyz/login?user=[EMAIL_REDACTED_#1]
Temporary Password: [CREDENTIAL_SECRET_REDACTED]`;

  const handleSaveRetention = () => {
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 4000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 uppercase tracking-wider mb-1">
          <Shield className="h-4 w-4" />
          <span>Forensic Privacy & Compliance Framework • DPDP Act 2023 / GDPR</span>
        </div>
        <h1 className="text-2xl font-bold text-white tracking-tight">
          Privacy, Data Protection & Evidence Handling
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Cryptographic chain-of-custody protocols, PII masking standards, and automated data retention policies.
        </p>
      </div>

      {/* Compliance Standard Badges */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <CheckCircle2 className="h-5 w-5" />
          </div>
          <div>
            <span className="text-xs font-bold text-white font-mono block">DPDP ACT 2023</span>
            <span className="text-[11px] text-slate-400">India Data Protection Compliant</span>
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <CheckCircle2 className="h-5 w-5" />
          </div>
          <div>
            <span className="text-xs font-bold text-white font-mono block">ISO / IEC 27037</span>
            <span className="text-[11px] text-slate-400">Digital Evidence Preservation</span>
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <CheckCircle2 className="h-5 w-5" />
          </div>
          <div>
            <span className="text-xs font-bold text-white font-mono block">GDPR ART. 32</span>
            <span className="text-[11px] text-slate-400">Security of Personal Data</span>
          </div>
        </div>
      </div>

      {/* Data Classification Matrix */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-xl">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
          <Lock className="h-4 w-4 text-emerald-400" />
          Forensic Data Classification & Handling Rules
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono">
                <th className="py-2.5 px-3">Data Tier</th>
                <th className="py-2.5 px-3">Description & Examples</th>
                <th className="py-2.5 px-3">Masking / Protection Rule</th>
                <th className="py-2.5 px-3">Retention</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-2.5 px-3 font-semibold text-red-400 font-mono">Tier 1: Credentials</td>
                <td className="py-2.5 px-3">Passwords, MFA tokens, session cookies in URLs or body</td>
                <td className="py-2.5 px-3 text-slate-300">
                  <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/20 font-mono">
                    Zero Persistence: Redacted Pre-Index
                  </span>
                </td>
                <td className="py-2.5 px-3 text-slate-400 font-mono">0 Days (Never Stored)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 font-semibold text-amber-400 font-mono">Tier 2: PII</td>
                <td className="py-2.5 px-3">Individual recipient names, phone numbers, personal email IDs</td>
                <td className="py-2.5 px-3 text-slate-300">
                  <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 font-mono">
                    Anonymized & Hashed with Salt
                  </span>
                </td>
                <td className="py-2.5 px-3 text-slate-400 font-mono">Active Investigation Only</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 font-semibold text-blue-400 font-mono">Tier 3: Network Telemetry</td>
                <td className="py-2.5 px-3">Received headers, public IPs, DNS resolution, ASNs</td>
                <td className="py-2.5 px-3 text-slate-300">
                  <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 font-mono">
                    Structured Forensic Extraction
                  </span>
                </td>
                <td className="py-2.5 px-3 text-slate-400 font-mono">{retentionDays} Days</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 font-semibold text-emerald-400 font-mono">Tier 4: Evidence Hash</td>
                <td className="py-2.5 px-3">SHA-256 raw email digest, Merkle root block</td>
                <td className="py-2.5 px-3 text-slate-300">
                  <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                    Immutable Append-Only Ledger
                  </span>
                </td>
                <td className="py-2.5 px-3 text-slate-400 font-mono">Permanent (Chain of Custody)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Live Masking Preview Comparison */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-xl">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
          <EyeOff className="h-4 w-4 text-emerald-400" />
          Automated Ingestion PII Redaction Engine (Demonstration)
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <span className="text-xs font-semibold text-slate-400 font-mono block mb-1.5">
              1. Raw Unsanitized Ingestion Payload (Memory Buffer)
            </span>
            <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed overflow-x-auto">
              {sampleRawText}
            </pre>
          </div>

          <div>
            <span className="text-xs font-semibold text-emerald-400 font-mono block mb-1.5">
              2. Sanitized Forensic Ledger Output (Stored & Analyzed by AI)
            </span>
            <pre className="p-3 rounded-lg bg-slate-950 border border-emerald-500/30 text-xs text-emerald-300 font-mono whitespace-pre-wrap leading-relaxed overflow-x-auto">
              {sampleMaskedText}
            </pre>
          </div>
        </div>
      </div>

      {/* Automated Retention Policy Settings */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-md shadow-xl">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-2">
          <Clock className="h-4 w-4 text-emerald-400" />
          SOC Data Retention & Quarantine Lifecyle
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Configure how long uncompressed evidence files are retained before automatic deletion. Cryptographic hashes and audit chains remain permanently archived.
        </p>

        {savedNotice && (
          <div className="mb-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            Retention policy updated: Artifacts older than {retentionDays} days will be safely purged nightly.
          </div>
        )}

        <div className="flex flex-col sm:flex-row sm:items-center gap-3">
          <select
            value={retentionDays}
            onChange={(e) => setRetentionDays(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-white rounded-lg px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500"
          >
            <option value="30">30 Days (Strict Data Minimization)</option>
            <option value="60">60 Days (Standard Corporate Policy)</option>
            <option value="90">90 Days (CERT-In Mandated Retention - Recommended)</option>
            <option value="180">180 Days (Extended Regulatory Audit)</option>
          </select>

          <button
            onClick={handleSaveRetention}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors self-start sm:self-auto"
          >
            Update Retention Policy
          </button>
        </div>
      </div>
    </div>
  );
};

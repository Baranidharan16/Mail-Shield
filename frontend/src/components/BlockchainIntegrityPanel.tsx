import { useState } from "react";
import { Link2, CheckCircle2, XCircle, Loader2, ShieldCheck, AlertTriangle } from "lucide-react";
import type { EvidenceVerifyResult } from "../types/investigation";
import { verifyEvidence } from "../api/client";

interface Props {
  investigationId: string;
  evidenceHash: string;
  blockInfo?: {
    block_index?: number | null;
    block_hash?: string | null;
    anchored_at?: string | null;
  } | null;
}

export default function BlockchainIntegrityPanel({ investigationId, evidenceHash, blockInfo }: Props) {
  const [result, setResult] = useState<EvidenceVerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleVerify() {
    setVerifying(true);
    setError(null);
    setResult(null);
    try {
      const r = await verifyEvidence(investigationId);
      setResult(r);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? "Verification failed — backend unreachable.");
    } finally {
      setVerifying(false);
    }
  }

  return (
    <div className="space-y-4">
      {/* Evidence hash */}
      <div className="p-4 rounded-md bg-lab-800/50 border border-lab-700">
        <div className="flex items-center gap-2 mb-3">
          <Link2 className="h-4 w-4 text-phosphor-500" strokeWidth={1.75} />
          <span className="text-xs font-semibold text-lab-200 evidence-tag">EVIDENCE SHA-256</span>
          <span className="text-[10px] text-purple-signal evidence-tag ml-auto">DEMO BLOCKCHAIN LEDGER</span>
        </div>
        <div className="font-data text-xs text-phosphor-400 break-all bg-lab-950/50 p-2 rounded border border-lab-700">
          {evidenceHash}
        </div>
      </div>

      {/* Ledger info */}
      {blockInfo?.block_index != null && (
        <div className="grid grid-cols-3 gap-3">
          <div className="p-3 rounded-md bg-lab-800/40 border border-lab-700 text-center">
            <div className="font-data text-lg font-bold text-purple-signal">#{blockInfo.block_index}</div>
            <div className="text-[10px] text-lab-500 evidence-tag">LEDGER BLOCK</div>
          </div>
          <div className="p-3 rounded-md bg-lab-800/40 border border-lab-700 text-center col-span-2">
            <div className="font-data text-xs text-lab-300 break-all">{blockInfo.block_hash?.slice(0, 32)}…</div>
            <div className="text-[10px] text-lab-500 evidence-tag mt-1">BLOCK HASH</div>
          </div>
        </div>
      )}

      {!blockInfo?.block_index && (
        <div className="p-3 rounded-md bg-amber-signal/5 border border-amber-signal/20 text-xs text-amber-signal">
          No blockchain anchor found yet. Analysis must complete successfully to anchor evidence.
        </div>
      )}

      {/* Verify button */}
      <button
        onClick={handleVerify}
        disabled={verifying}
        className="w-full flex items-center justify-center gap-2.5 py-3 rounded-md font-semibold text-sm transition-all
          bg-phosphor-500/10 text-phosphor-400 border border-phosphor-500/30
          hover:bg-phosphor-500/20 hover:border-phosphor-500/50
          disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {verifying ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <ShieldCheck className="h-4 w-4" strokeWidth={1.75} />
        )}
        {verifying ? "Verifying Evidence Integrity…" : "Verify Evidence Integrity"}
      </button>

      {/* Result */}
      {result && (
        <div className={`p-4 rounded-md border ${
          result.verified
            ? "bg-phosphor-500/5 border-phosphor-500/30"
            : "bg-crimson-signal/5 border-crimson-signal/30"
        }`}>
          <div className="flex items-center gap-2 mb-3">
            {result.verified ? (
              <CheckCircle2 className="h-5 w-5 text-phosphor-500" strokeWidth={1.75} />
            ) : (
              <XCircle className="h-5 w-5 text-crimson-glow" strokeWidth={1.75} />
            )}
            <span className={`font-bold text-sm evidence-tag ${result.verified ? "text-phosphor-400" : "text-crimson-glow"}`}>
              {result.verified ? "✓ EVIDENCE INTEGRITY VERIFIED" : "⚠ INTEGRITY VERIFICATION FAILED"}
            </span>
          </div>

          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between">
              <span className="text-lab-500">Evidence Hash Match</span>
              <span className={result.evidence_hash_match ? "text-phosphor-400 font-data" : "text-crimson-glow font-data"}>
                {result.evidence_hash_match ? "MATCH" : "MISMATCH"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-lab-500">Chain Integrity</span>
              <span className={result.chain_intact ? "text-phosphor-400 font-data" : "text-crimson-glow font-data"}>
                {result.chain_intact ? "INTACT" : "BROKEN"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-lab-500">Anchored</span>
              <span className={result.anchored ? "text-phosphor-400 font-data" : "text-amber-signal font-data"}>
                {result.anchored ? "YES" : "NOT ANCHORED"}
              </span>
            </div>
            {result.anchored_at && (
              <div className="flex justify-between">
                <span className="text-lab-500">Anchored At</span>
                <span className="font-data text-lab-300">
                  {new Date(result.anchored_at).toLocaleString()}
                </span>
              </div>
            )}
          </div>

          {result.message && (
            <div className="mt-3 text-[11px] text-lab-400 italic">{result.message}</div>
          )}
        </div>
      )}

      {error && (
        <div className="p-3 rounded-md bg-crimson-signal/5 border border-crimson-signal/30 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-crimson-glow shrink-0 mt-0.5" />
          <span className="text-xs text-crimson-glow">{error}</span>
        </div>
      )}

      <p className="text-[10px] text-lab-600 italic">
        DEMO BLOCKCHAIN LEDGER — This is a local tamper-evident hash chain. Hash linkage is cryptographically verified. Not connected to a public blockchain in this environment.
      </p>
    </div>
  );
}

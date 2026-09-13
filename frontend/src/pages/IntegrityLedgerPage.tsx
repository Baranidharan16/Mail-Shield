import { useEffect, useState } from "react";
import { Link2, ShieldCheck, Hash, Loader2, CheckCircle2, XCircle, RefreshCw, DatabaseZap } from "lucide-react";
import { listBlockchainBlocks, verifyBlockchain } from "../api/client";
import type { BlockchainBlock, BlockchainVerifyResult } from "../types/investigation";
import BlockchainBlockChainVisualizer from "../components/BlockchainBlockChainVisualizer";

function formatTs(iso: string) {
  try {
    return new Date(iso).toLocaleString("en-IN", {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit", hour12: false,
    });
  } catch { return iso; }
}

export default function IntegrityLedgerPage() {
  const [blocks, setBlocks] = useState<BlockchainBlock[]>([]);
  const [loading, setLoading] = useState(true);
  const [verifyResult, setVerifyResult] = useState<BlockchainVerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  const loadBlocks = () => {
    setLoading(true);
    listBlockchainBlocks(200).then(setBlocks).finally(() => setLoading(false));
  };

  useEffect(() => {
    loadBlocks();
  }, []);

  async function runVerify() {
    setVerifying(true);
    try {
      const r = await verifyBlockchain();
      setVerifyResult(r);
    } finally {
      setVerifying(false);
    }
  }

  return (
    <div className="p-6 md:p-8 max-w-6xl animate-fade-in">
      {/* Header */}
      <div className="page-header-glass flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <Link2 className="h-5 w-5 text-purple-signal" strokeWidth={1.75} />
            <h1 className="text-xl font-bold tracking-tight text-white">Integrity Ledger</h1>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-purple-signal/15 text-purple-400 border border-purple-signal/30 tracking-widest">
              HYPERLEDGER FABRIC & SHA-256 LEDGER
            </span>
          </div>
          <p className="text-sm text-lab-400">
            Immutable, tamper-evident SHA-256 cryptographic chain for all MailShield forensic evidence.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={runVerify}
            disabled={verifying}
            className="btn-glass-primary flex items-center gap-2 disabled:opacity-50"
          >
            {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" strokeWidth={1.75} />}
            {verifying ? "Verifying…" : "Verify Full Chain"}
          </button>
        </div>
      </div>

      {/* Verification result */}
      {verifyResult && (
        <div
          className={`mb-5 p-4 rounded-xl border flex items-start gap-3 glass-card ${
            verifyResult.verified
              ? "bg-phosphor-500/10 border-phosphor-500/40 glow-green"
              : "bg-crimson-signal/10 border-crimson-signal/40 glow-red"
          }`}
        >
          {verifyResult.verified ? (
            <CheckCircle2 className="h-5 w-5 text-phosphor-400 mt-0.5 shrink-0" strokeWidth={1.75} />
          ) : (
            <XCircle className="h-5 w-5 text-crimson-glow mt-0.5 shrink-0" strokeWidth={1.75} />
          )}
          <div>
            <div className={`font-bold evidence-tag text-sm ${verifyResult.verified ? "text-phosphor-400" : "text-crimson-glow"}`}>
              {verifyResult.verified ? "✓ CHAIN INTEGRITY VERIFIED" : "⚠ CHAIN INTEGRITY COMPROMISED"}
            </div>
            <div className="text-xs text-lab-300 mt-1">
              {verifyResult.message} · {verifyResult.block_count} blocks verified.
            </div>
          </div>
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <div className="glass-card px-5 py-4 text-center">
          <div className="font-data text-3xl font-bold text-purple-signal">{blocks.length}</div>
          <div className="text-[10px] text-lab-500 evidence-tag mt-1">LEDGER BLOCKS</div>
        </div>
        <div className="glass-card px-5 py-4 text-center">
          <div className="flex items-center justify-center gap-2 mb-1">
            <Hash className="h-4 w-4 text-lab-400" />
          </div>
          <div className="font-data text-sm text-lab-200">SHA-256</div>
          <div className="text-[10px] text-lab-500 evidence-tag mt-1">HASH ALGORITHM</div>
        </div>
        <div className="glass-card px-5 py-4 text-center">
          <div className="flex items-center justify-center gap-1.5 mb-1">
            <DatabaseZap className="h-4 w-4 text-phosphor-400" />
          </div>
          <div className="font-data text-sm text-phosphor-400">HYPERLEDGER FABRIC + DB</div>
          <div className="text-[10px] text-lab-500 evidence-tag mt-1">LEDGER BACKEND</div>
        </div>
      </div>

      {/* Interactive Tamper-Evident Proof Visualizer */}
      <BlockchainBlockChainVisualizer className="mb-6" />

      {/* Block chain visualization */}
      <div className="mb-4 text-xs text-lab-500 flex items-center gap-2">
        <div className="h-px flex-1 bg-white/10" />
        LIVE IMMUTABLE LEDGER CHAIN — {blocks.length} registered blocks
        <div className="h-px flex-1 bg-white/10" />
      </div>

      {loading ? (
        <div className="glass-section p-10 text-center text-lab-400 flex items-center justify-center gap-2">
          <RefreshCw className="h-4 w-4 animate-spin" /> Loading ledger…
        </div>
      ) : blocks.length === 0 ? (
        <div className="glass-section p-10 text-center text-lab-500">
          No blocks in the ledger yet. Upload a .eml file to anchor evidence.
        </div>
      ) : (
        <div className="space-y-3">
          {[...blocks].reverse().map((block, i) => (
            <div
              key={block.block_index}
              className="glass-card p-4 hover:border-white/20 transition-colors relative overflow-hidden"
            >
              {/* Block index accent */}
              <div
                className="absolute left-0 top-0 bottom-0 w-1 rounded-l-md"
                style={{ background: i === 0 ? "linear-gradient(to bottom, #3ddc97, #6ee8b1)" : "linear-gradient(to bottom, #8b5cf6, #6d28d9)" }}
              />

              <div className="pl-2 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span
                      className="font-data font-bold text-sm"
                      style={{ color: i === 0 ? "#3ddc97" : "#8b5cf6" }}
                    >
                      Block #{block.block_index}
                    </span>
                    {block.case_id && (
                      <span className="text-[10px] text-lab-300 font-data evidence-tag border border-white/10 bg-white/5 rounded px-1.5 py-0.5">
                        {block.case_id}
                      </span>
                    )}
                    {i === 0 && (
                      <span className="text-[10px] text-phosphor-400 evidence-tag bg-phosphor-500/10 border border-phosphor-500/20 px-1.5 py-0.5 rounded">LATEST</span>
                    )}
                  </div>
                  <div>
                    <div className="text-[10px] text-lab-500 evidence-tag mb-0.5">TIMESTAMP</div>
                    <div className="font-data text-xs text-lab-300">{formatTs(block.timestamp)}</div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div>
                    <div className="text-[10px] text-lab-500 evidence-tag mb-0.5">EVIDENCE HASH</div>
                    <div className="font-data text-[11px] text-lab-300 break-all bg-black/40 px-2.5 py-1.5 rounded border border-white/5">
                      {block.evidence_hash}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-lab-500 evidence-tag mb-0.5">BLOCK HASH</div>
                    <div className="font-data text-[11px] text-purple-400 break-all bg-black/40 px-2.5 py-1.5 rounded border border-purple-500/20">
                      {block.block_hash}
                    </div>
                  </div>
                  {block.block_index > 0 && (
                    <div>
                      <div className="text-[10px] text-lab-500 evidence-tag mb-0.5">PREVIOUS HASH</div>
                      <div className="font-data text-[11px] text-lab-500 break-all bg-black/30 px-2.5 py-1.5 rounded border border-white/5">
                        {block.previous_hash}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="mt-6 p-4 rounded-xl glass-card text-[11px] text-lab-400 italic">
        <strong className="text-lab-200">DEMO LOCAL LEDGER</strong> — This is a tamper-evident hash chain implemented locally using SHA-256 cryptographic hashing. Each block contains the evidence hash and previous block hash to detect any tampering. Hash linkage verification is cryptographically authentic.
      </div>
    </div>
  );
}

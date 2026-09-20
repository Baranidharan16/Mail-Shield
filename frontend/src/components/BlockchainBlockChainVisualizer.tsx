import React, { useState } from "react";
import { CheckCircle2, AlertTriangle, ShieldCheck, Edit3, ArrowRight } from "lucide-react";

interface BlockData {
  title: string;
  record: string;
  initialRecord: string;
  tamperedRecord: string;
  originalPrevHash: string;
  originalBlockHash: string;
  tamperedBlockHash: string;
}

export const BlockchainBlockChainVisualizer: React.FC<{ className?: string }> = ({ className = "" }) => {
  const [tamperedBlock, setTamperedBlock] = useState<number | null>(null); // null means no tamper, 1, 2, 3
  const [mode, setMode] = useState<"forensic" | "crypto">("forensic");

  // Base data for demonstration
  const forensicBlocks: BlockData[] = [
    {
      title: "Genesis",
      record: "MailShield Root Genesis",
      initialRecord: "MailShield Root Genesis",
      tamperedRecord: "MailShield Root Genesis",
      originalPrevHash: "000000000000",
      originalBlockHash: "7e0021c9a1b8",
      tamperedBlockHash: "7e0021c9a1b8",
    },
    {
      title: "Block 1",
      record: "EV-000101: Raw RFC822 EML SHA-256 Registered",
      initialRecord: "EV-000101: Raw RFC822 EML SHA-256 Registered",
      tamperedRecord: "EV-000101: Altered Header (Attacker spoofed)",
      originalPrevHash: "7e0021c9a1b8",
      originalBlockHash: "6b70c53f81e2",
      tamperedBlockHash: "1b69a473d09a",
    },
    {
      title: "Block 2",
      record: "EV-000102: Forensic Hop & IP Intel Hash Anchor",
      initialRecord: "EV-000102: Forensic Hop & IP Intel Hash Anchor",
      tamperedRecord: "EV-000102: Modified Origin IP 185.220.101.45",
      originalPrevHash: "6b70c53f81e2",
      originalBlockHash: "4cfc4571e09c",
      tamperedBlockHash: "9ec243e67b14",
    },
    {
      title: "Block 3",
      record: "EV-000103: Case Dossier & Authority PDF Signed",
      initialRecord: "EV-000103: Case Dossier & Authority PDF Signed",
      tamperedRecord: "EV-000103: Forged Authority Signature",
      originalPrevHash: "4cfc4571e09c",
      originalBlockHash: "ec81b92044aa",
      tamperedBlockHash: "8e317eb108ca",
    },
  ];

  const cryptoBlocks: BlockData[] = [
    {
      title: "Genesis",
      record: "Initial record",
      initialRecord: "Initial record",
      tamperedRecord: "Initial record",
      originalPrevHash: "000000",
      originalBlockHash: "7e0021",
      tamperedBlockHash: "7e0021",
    },
    {
      title: "Block 1",
      record: "Alice pays Bob 4 coins",
      initialRecord: "Alice pays Bob 4 coins",
      tamperedRecord: "Alice pays Bob 8 coins",
      originalPrevHash: "7e0021",
      originalBlockHash: "6b70c5",
      tamperedBlockHash: "1b69a4",
    },
    {
      title: "Block 2",
      record: "Bob pays Chen 2 coins",
      initialRecord: "Bob pays Chen 2 coins",
      tamperedRecord: "Bob pays Chen 9 coins",
      originalPrevHash: "6b70c5",
      originalBlockHash: "4cfc45",
      tamperedBlockHash: "9ec243",
    },
    {
      title: "Block 3",
      record: "Chen pays Dana 1 coins",
      initialRecord: "Chen pays Dana 1 coins",
      tamperedRecord: "Chen pays Dana 5 coins",
      originalPrevHash: "4cfc45",
      originalBlockHash: "ec81b9",
      tamperedBlockHash: "8e317e",
    },
  ];

  const blocks = mode === "forensic" ? forensicBlocks : cryptoBlocks;

  // Determine state of each block (0: Genesis, 1: Block 1, 2: Block 2, 3: Block 3)
  const getBlockStatus = (index: number) => {
    if (tamperedBlock === null) {
      return { status: "valid", color: "green" };
    }
    if (index < tamperedBlock) {
      return { status: "valid", color: "green" };
    }
    if (index === tamperedBlock) {
      return { status: "tampered", color: "orange" };
    }
    return { status: "broken", color: "red" };
  };

  return (
    <div className={`rounded-2xl border border-slate-800 bg-[#fefdfc] p-6 text-white shadow-2xl ${className}`}>
      {/* Top Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-700/60 mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
              Tamper-Evident SHA-256 Blockchain Proof
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Interactive Proof
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Demonstrates why modifying stored forensic evidence invalidates cryptographic hashes downstream.
            </p>
          </div>
        </div>

        {/* Mode Toggle */}
        <div className="flex items-center bg-slate-900 rounded-lg p-1 border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setMode("forensic")}
            className={`px-3 py-1 rounded transition-all ${
              mode === "forensic" ? "bg-purple-600 text-snow font-semibold" : "text-slate-400 hover:text-white"
            }`}
          >
            Forensic Evidence
          </button>
          <button
            onClick={() => setMode("crypto")}
            className={`px-3 py-1 rounded transition-all ${
              mode === "crypto" ? "bg-purple-600 text-snow font-semibold" : "text-slate-400 hover:text-white"
            }`}
          >
            Classic Ledger
          </button>
        </div>
      </div>

      {/* Visual Blockchain Columns */}
      <div className="overflow-x-auto pb-4">
        <div className="flex items-center justify-center min-w-[720px] gap-2 md:gap-3 py-4">
          {blocks.map((b, idx) => {
            const { status, color } = getBlockStatus(idx);
            const isTamperedThis = tamperedBlock === idx;
            const isBroken = status === "broken";

            // Compute displayed block hash
            const currentHash =
              isTamperedThis
                ? b.tamperedBlockHash
                : isBroken
                ? idx === 2 && tamperedBlock === 1
                  ? "9382d7"
                  : idx === 3 && tamperedBlock === 1
                  ? "395f02"
                  : b.tamperedBlockHash
                : b.originalBlockHash;

            // Compute displayed previous hash
            const prevHash =
              idx === 0
                ? b.originalPrevHash
                : isBroken
                ? b.originalPrevHash // stays as old pointer, causing mismatch with new block hash!
                : isTamperedThis
                ? b.originalPrevHash
                : b.originalPrevHash;

            const prevHashFailed = isBroken || (idx === tamperedBlock && idx > 0);

            return (
              <React.Fragment key={idx}>
                {/* Connector Arrow */}
                {idx > 0 && (
                  <div className="flex flex-col items-center justify-center px-1">
                    {prevHashFailed ? (
                      <div className="flex flex-col items-center">
                        <span className="text-red-500 font-bold text-xs">✕</span>
                        <div className="w-6 h-[2px] bg-red-500/80 my-0.5" />
                        <span className="text-[9px] text-red-400 font-mono">broken</span>
                      </div>
                    ) : (
                      <div className="flex items-center text-emerald-500">
                        <div className="w-6 h-[2px] bg-emerald-500" />
                        <ArrowRight className="h-3.5 w-3.5 -ml-1" />
                      </div>
                    )}
                  </div>
                )}

                {/* Individual Block */}
                <div
                  className={`w-44 sm:w-48 rounded-2xl border-2 p-3.5 flex flex-col justify-between transition-all duration-300 ${
                    color === "green"
                      ? "border-emerald-500/80 bg-slate-900/90 shadow-[0_0_15px_rgba(37,34,30,0.06)]"
                      : color === "orange"
                      ? "border-amber-500/90 bg-slate-900/90 shadow-[0_0_15px_rgba(37,34,30,0.06)]"
                      : "border-red-500/80 bg-slate-900/90 shadow-[0_0_15px_rgba(37,34,30,0.06)]"
                  }`}
                >
                  {/* Block Header */}
                  <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
                    <span className="font-bold text-sm text-white font-mono">{b.title}</span>
                    <span
                      className={`w-2.5 h-2.5 rounded-full inline-block ${
                        color === "green" ? "bg-emerald-400" : color === "orange" ? "bg-amber-400" : "bg-red-500 animate-pulse"
                      }`}
                    />
                  </div>

                  {/* Record Data */}
                  <div className="py-2">
                    <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Record</div>
                    <div className="flex items-start justify-between gap-1 mt-0.5 min-h-[42px]">
                      <span className={`text-xs font-medium leading-tight ${isTamperedThis ? "text-amber-300 font-semibold" : "text-slate-200"}`}>
                        {isTamperedThis ? b.tamperedRecord : b.initialRecord}
                      </span>
                      {idx > 0 && <Edit3 className="h-3 w-3 text-slate-500 shrink-0 mt-0.5" />}
                    </div>
                  </div>

                  {/* Previous Hash */}
                  <div className="pt-2 border-t border-slate-800/80">
                    <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Previous hash</div>
                    <div
                      className={`text-xs font-mono font-bold truncate mt-0.5 ${
                        prevHashFailed && idx >= (tamperedBlock ?? 99)
                          ? "text-red-400 bg-red-950/40 px-1 rounded border border-red-800/50"
                          : "text-white"
                      }`}
                    >
                      {prevHash}
                    </div>
                  </div>

                  {/* Block Hash */}
                  <div className="pt-2 mt-1">
                    <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Block hash</div>
                    <div
                      className={`text-xs font-mono font-bold truncate mt-0.5 ${
                        color === "orange"
                          ? "text-amber-400"
                          : color === "red"
                          ? "text-red-400"
                          : "text-white"
                      }`}
                    >
                      {currentHash}
                    </div>
                  </div>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Footer Status Message & Tamper Selector Slider */}
      <div className="mt-4 pt-4 border-t border-slate-800 flex flex-col items-center justify-center">
        <p className="text-sm font-serif italic text-slate-300 mb-4 text-center">
          {tamperedBlock === null ? (
            <span className="text-emerald-400 font-sans font-medium flex items-center gap-1.5">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 inline" />
              Every stored hash matches: the chain is valid.
            </span>
          ) : (
            <span className="text-amber-300 font-sans font-medium flex items-center gap-1.5">
              <AlertTriangle className="h-4 w-4 text-amber-400 inline" />
              Block {tamperedBlock} changed: its hash and every later link are invalid.
            </span>
          )}
        </p>

        {/* Interactive Selector Pill */}
        <div className="flex items-center gap-3 bg-slate-900/90 px-4 py-2 rounded-full border border-slate-700/80 shadow-inner">
          <span className="text-xs font-mono text-slate-400 font-semibold tracking-wide">Tampered block</span>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setTamperedBlock(null)}
              className={`w-9 h-7 rounded-full text-xs font-bold transition-all ${
                tamperedBlock === null
                  ? "bg-white text-slate-900 shadow-md scale-105"
                  : "bg-slate-800 text-slate-400 hover:text-white"
              }`}
            >
              —
            </button>
            <button
              onClick={() => setTamperedBlock(1)}
              className={`w-9 h-7 rounded-full text-xs font-bold transition-all ${
                tamperedBlock === 1
                  ? "bg-white text-slate-900 shadow-md scale-105"
                  : "bg-slate-800 text-slate-400 hover:text-white"
              }`}
            >
              1
            </button>
            <button
              onClick={() => setTamperedBlock(2)}
              className={`w-9 h-7 rounded-full text-xs font-bold transition-all ${
                tamperedBlock === 2
                  ? "bg-white text-slate-900 shadow-md scale-105"
                  : "bg-slate-800 text-slate-400 hover:text-white"
              }`}
            >
              2
            </button>
            <button
              onClick={() => setTamperedBlock(3)}
              className={`w-9 h-7 rounded-full text-xs font-bold transition-all ${
                tamperedBlock === 3
                  ? "bg-white text-slate-900 shadow-md scale-105"
                  : "bg-slate-800 text-slate-400 hover:text-white"
              }`}
            >
              3
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
export default BlockchainBlockChainVisualizer;

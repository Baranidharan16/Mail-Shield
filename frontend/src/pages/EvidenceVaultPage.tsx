import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Archive, Search, ShieldCheck, Hash, RefreshCw } from "lucide-react";
import { listInvestigations } from "../api/client";
import type { InvestigationSummary } from "../types/investigation";
import { ClassificationBadge } from "../components/Badges";

function formatTs(iso: string) {
  try {
    return new Date(iso).toLocaleString("en-IN", {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit", hour12: false,
    });
  } catch { return iso; }
}

export default function EvidenceVaultPage() {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  const loadData = () => {
    setLoading(true);
    listInvestigations(500).then(setInvestigations).finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const completed = investigations.filter((i) => i.status === "COMPLETED");
  const filtered = completed.filter(
    (i) =>
      !search ||
      i.case_id.toLowerCase().includes(search.toLowerCase()) ||
      i.filename.toLowerCase().includes(search.toLowerCase())
  );

  const totalCompleted = completed.length;
  const critical = completed.filter((i) => i.classification === "CRITICAL").length;
  const high = completed.filter((i) => i.classification === "HIGH").length;

  return (
    <div className="p-6 md:p-8 max-w-7xl animate-fade-in">
      <div className="page-header-glass flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <Archive className="h-5 w-5 text-purple-signal" strokeWidth={1.75} />
            <h1 className="text-xl font-bold tracking-tight text-white">Evidence Vault</h1>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-purple-signal/15 text-purple-400 border border-purple-signal/30 tracking-widest">
              SECURE
            </span>
          </div>
          <p className="text-sm text-lab-400">
            Immutable SHA-256 hashed evidence records for all completed investigations.
          </p>
        </div>
        <button onClick={loadData} className="btn-glass-secondary text-sm cursor-pointer">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {[
          { label: "Total Evidence Items", value: totalCompleted, color: "text-lab-200" },
          { label: "Critical Threats", value: critical, color: "text-crimson-glow" },
          { label: "High Threats", value: high, color: "text-orange-signal" },
          {
            label: "Integrity Status",
            value: "SHA-256",
            color: "text-phosphor-400",
          },
        ].map(({ label, value, color }) => (
          <div key={label} className="glass-card px-4 py-3 text-center">
            <div className={`text-2xl font-bold font-data ${color}`}>{value}</div>
            <div className="text-[10px] text-lab-500 evidence-tag mt-0.5">{label}</div>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="relative mb-5 max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-lab-500" />
        <input
          type="text"
          placeholder="Search case ID or filename…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-glass pl-9 pr-4 py-2 text-sm w-full"
        />
      </div>

      {/* Evidence table */}
      <div className="glass-section overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-lab-400 flex items-center justify-center gap-2">
            <RefreshCw className="h-4 w-4 animate-spin" /> Loading evidence…
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center text-lab-400 text-sm">
            {completed.length === 0
              ? "No completed investigations found. Upload a .eml file to create evidence records."
              : "No records match the search."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="glass-table">
              <thead>
                <tr>
                  <th>CASE ID</th>
                  <th>ORIGINAL FILE</th>
                  <th>CLASSIFICATION</th>
                  <th>RISK SCORE</th>
                  <th>HASH (SHA-256)</th>
                  <th>INTEGRITY</th>
                  <th>CREATED</th>
                  <th>ANALYZED</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((inv) => (
                  <tr
                    key={inv.id}
                    onClick={() => navigate(`/investigations/${inv.id}`)}
                    className="cursor-pointer group"
                  >
                    <td className="font-data text-phosphor-400 text-xs font-semibold">{inv.case_id}</td>
                    <td className="text-lab-300 text-xs truncate max-w-[180px]">
                      {inv.original_filename ?? inv.filename}
                    </td>
                    <td>
                      {inv.classification ? (
                        <ClassificationBadge level={inv.classification} size="sm" />
                      ) : (
                        <span className="text-lab-600">—</span>
                      )}
                    </td>
                    <td className="font-data text-sm font-bold text-amber-signal">
                      {inv.risk_score != null ? inv.risk_score.toFixed(1) : "—"}
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <Hash className="h-3.5 w-3.5 text-purple-signal shrink-0" />
                        <span className="font-data text-[11px] text-lab-400">
                          <span className="italic text-lab-500">see detail →</span>
                        </span>
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-1 text-phosphor-400 text-xs">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        <span className="evidence-tag text-[10px]">ANCHORED</span>
                      </div>
                    </td>
                    <td className="font-data text-[11px] text-lab-500">{formatTs(inv.created_at)}</td>
                    <td className="font-data text-[11px] text-lab-400">
                      {inv.analyzed_at ? formatTs(inv.analyzed_at) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className="mt-3 text-[11px] text-lab-600 font-data">
        {filtered.length} evidence records · Click any row to open the full investigation with evidence verification
      </p>
    </div>
  );
}

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listInvestigations } from "../api/client";
import type { InvestigationSummary } from "../types/investigation";
import { ClassificationBadge } from "../components/Badges";
import { Search, RefreshCw, ArrowUpRight, FileSearch, SortAsc } from "lucide-react";

function formatTs(iso: string) {
  try { return new Date(iso).toLocaleString("en-IN", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }); }
  catch { return iso; }
}

const STATUS_COLORS: Record<string, string> = {
  COMPLETED: "text-phosphor-400 bg-phosphor-500/10 border-phosphor-500/25",
  PROCESSING: "text-amber-signal bg-amber-signal/10 border-amber-signal/25",
  QUEUED: "text-blue-signal bg-blue-signal/10 border-blue-signal/25",
  FAILED: "text-crimson-glow bg-crimson-signal/10 border-crimson-signal/25",
};

export default function HistoryPage() {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [classFilter, setClassFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState<"created" | "score">("created");
  const navigate = useNavigate();

  useEffect(() => {
    listInvestigations(500).then(setInvestigations).finally(() => setLoading(false));
  }, []);

  const filtered = investigations
    .filter((i) => {
      const matchSearch = !search ||
        i.case_id.toLowerCase().includes(search.toLowerCase()) ||
        i.filename.toLowerCase().includes(search.toLowerCase()) ||
        (i as any).original_filename?.toLowerCase().includes(search.toLowerCase());
      const matchClass = classFilter === "ALL" || i.classification === classFilter;
      const matchStatus = statusFilter === "ALL" || i.status === statusFilter;
      return matchSearch && matchClass && matchStatus;
    })
    .sort((a, b) => sortBy === "score" ? (b.risk_score ?? 0) - (a.risk_score ?? 0) : new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  return (
    <div className="p-6 md:p-8 max-w-7xl animate-fade-in">

      {/* Header */}
      <div className="page-header-glass flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <FileSearch className="h-5 w-5 text-phosphor-500" strokeWidth={1.75} />
            <h1 className="text-xl font-bold tracking-tight text-white">Case History</h1>
          </div>
          <p className="text-sm text-lab-400">All forensic investigations stored in the database · {investigations.length} total</p>
        </div>
        <button
          onClick={() => listInvestigations(500).then(setInvestigations)}
          className="btn-glass-secondary text-sm cursor-pointer"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <div className="glass-section p-4 mb-5 rounded-xl">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[220px] flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-lab-500" />
            <input
              type="text"
              placeholder="Search cases, filenames…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input-glass pl-9 text-sm h-9"
            />
          </div>

          <div className="flex items-center gap-1.5 flex-wrap">
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((c) => (
              <button key={c} onClick={() => setClassFilter(c)}
                className={`filter-chip text-[11px] ${classFilter === c ? "active" : ""}`}>
                {c}
              </button>
            ))}
          </div>

          <div className="h-4 border-r border-white/10 hidden sm:block" />

          <div className="flex items-center gap-1.5">
            {["ALL", "COMPLETED", "PROCESSING", "FAILED"].map((s) => (
              <button key={s} onClick={() => setStatusFilter(s)}
                className={`filter-chip text-[11px] ${statusFilter === s ? "active" : ""}`}>
                {s}
              </button>
            ))}
          </div>

          <button onClick={() => setSortBy(sortBy === "created" ? "score" : "created")}
            className="filter-chip text-[11px] ml-auto">
            <SortAsc className="h-3 w-3" />
            {sortBy === "created" ? "Newest First" : "Highest Score"}
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="glass-section overflow-hidden">
        {loading ? (
          <div className="p-10 text-center">
            <RefreshCw className="h-6 w-6 text-phosphor-400 animate-spin mx-auto mb-3" />
            <div className="text-sm text-lab-500">Loading case history…</div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-14 text-center">
            <FileSearch className="h-10 w-10 text-lab-700 mx-auto mb-3" strokeWidth={1.25} />
            <div className="text-sm font-medium text-lab-400">No cases found</div>
            <div className="text-xs text-lab-600 mt-1">
              {search || classFilter !== "ALL" || statusFilter !== "ALL" ? "Try adjusting filters." : "Upload an email to start the first investigation."}
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="glass-table">
              <thead>
                <tr>
                  <th>CASE ID</th>
                  <th>FILENAME</th>
                  <th>CLASSIFICATION</th>
                  <th>RISK SCORE</th>
                  <th>STATUS</th>
                  <th>DATE</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((inv) => (
                  <tr
                    key={inv.id}
                    onClick={() => navigate(`/investigations/${inv.id}`)}
                    className="cursor-pointer"
                  >
                    <td className="font-data text-phosphor-400 font-bold text-[11px]">{inv.case_id}</td>
                    <td className="max-w-[180px] truncate text-lab-300 text-[12px]"
                      title={(inv as any).original_filename || inv.filename}>
                      {(inv as any).original_filename || inv.filename}
                    </td>
                    <td><ClassificationBadge level={inv.classification ?? "INFO"} size="sm" /></td>
                    <td>
                      {inv.risk_score !== null && inv.risk_score !== undefined ? (
                        <span className={`font-data font-bold ${
                          inv.risk_score >= 80 ? "text-crimson-glow" :
                          inv.risk_score >= 60 ? "text-orange-signal" :
                          inv.risk_score >= 30 ? "text-amber-signal" : "text-blue-signal"
                        }`}>{inv.risk_score.toFixed(0)}</span>
                      ) : <span className="text-lab-600">—</span>}
                    </td>
                    <td>
                      <span className={`text-[10px] evidence-tag px-2 py-0.5 rounded-full border font-semibold ${STATUS_COLORS[inv.status] ?? "text-lab-500"}`}>
                        {inv.status}
                      </span>
                    </td>
                    <td className="text-lab-500 text-[11px] font-data whitespace-nowrap">{formatTs(inv.created_at)}</td>
                    <td>
                      <ArrowUpRight className="h-3.5 w-3.5 text-lab-600 group-hover:text-phosphor-400" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!loading && filtered.length > 0 && (
          <div className="px-5 py-3 border-t border-white/[0.05] text-[11px] text-lab-600 flex items-center justify-between">
            <span>{filtered.length} of {investigations.length} cases</span>
            <span className="font-data">Click any row to open investigation</span>
          </div>
        )}
      </div>
    </div>
  );
}

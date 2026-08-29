import { Link } from "react-router-dom";
import { Users, ArrowUpRight } from "lucide-react";
import type { CampaignResponse } from "../types/investigation";

interface Props {
  data: CampaignResponse | null;
  currentId: string;
}

export default function SimilarCasesPanel({ data, currentId }: Props) {
  if (!data || data.campaign === null) {
    return (
      <div className="p-6 text-center text-lab-500 text-sm">
        <Users className="h-6 w-6 mx-auto mb-2 opacity-30" />
        <div>No related cases found.</div>
        <div className="text-xs mt-1 text-lab-600">
          Campaign correlation requires multiple investigations with shared indicators.
        </div>
      </div>
    );
  }

  const others = (data.members ?? []).filter((m) => m.investigation_id !== currentId);

  if (others.length === 0) {
    return (
      <div className="p-6 text-center text-lab-500 text-sm">
        No other cases linked to campaign <span className="font-data text-lab-300">{data.campaign_code}</span>.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {data.campaign_code && (
        <div className="px-3 py-2 rounded-md bg-lab-800/50 border border-lab-700 flex items-center justify-between text-xs">
          <span className="text-lab-500">Campaign</span>
          <span className="font-data text-purple-signal">{data.campaign_code}</span>
        </div>
      )}

      {others.map((m) => (
        <Link
          key={m.investigation_id}
          to={`/investigations/${m.investigation_id}`}
          className="flex items-center justify-between p-3 rounded-md border border-lab-700 hover:border-lab-500 hover:bg-lab-800/50 transition-all group"
        >
          <div>
            <div className="font-data text-sm text-phosphor-400 group-hover:text-phosphor-300">
              {m.case_id}
            </div>
            <div className="text-xs text-lab-500 mt-0.5">{m.relationship_label}</div>
            {m.reasons && m.reasons.length > 0 && (
              <div className="text-[10px] text-lab-600 mt-0.5 italic">
                {m.reasons.slice(0, 2).join(" · ")}
              </div>
            )}
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="font-data text-sm font-bold text-phosphor-400">
                {Math.round(m.similarity_score * 100)}%
              </div>
              <div className="text-[10px] text-lab-500">similarity</div>
            </div>
            <ArrowUpRight className="h-4 w-4 text-lab-500 group-hover:text-lab-200 transition-colors" />
          </div>
        </Link>
      ))}

      <p className="text-[10px] text-lab-600 italic">
        Similarity scores are computed from shared infrastructure, sender, URL, and indicator patterns. They indicate forensic correlation, not confirmed attacker attribution.
      </p>
    </div>
  );
}

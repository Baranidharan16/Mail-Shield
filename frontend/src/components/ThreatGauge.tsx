import { levelColor, type Level } from "./Badges";

interface Props {
  score: number;
  classification: Level;
  confidence: number;
  size?: number;
}

const COLOR_MAP: Record<string, string> = {
  LOW: "#3ddc97",
  MEDIUM: "#e8a23d",
  HIGH: "#e2483d",
  CRITICAL: "#ff6b5e",
};

export default function ThreatGauge({ score, classification, confidence, size = 176 }: Props) {
  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const dash = circumference * pct;
  const color = COLOR_MAP[classification] ?? "#7c8fa0";

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--color-lab-700)"
            strokeWidth={10}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={10}
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference}`}
            style={{ transition: "stroke-dasharray 0.6s ease-out", filter: `drop-shadow(0 0 6px ${color}55)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-4xl font-bold font-data" style={{ color }}>
            {score.toFixed(0)}
          </div>
          <div className="text-[11px] text-lab-400 evidence-tag">/ 100</div>
        </div>
      </div>
      <div className={`mt-3 font-bold evidence-tag text-lg ${levelColor(classification)}`}>{classification}</div>
      <div className="text-xs text-lab-400 mt-1 font-data">confidence {(confidence * 100).toFixed(0)}%</div>
    </div>
  );
}

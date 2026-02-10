"use client";

import { getScoreColor, getScoreLabel } from "@/lib/utils";

interface Props {
  score: number;
  size?: number;
}

export default function TrustScoreGauge({ score, size = 160 }: Props) {
  const color = getScoreColor(score);
  const label = getScoreLabel(score);
  const r = 45;
  const circumference = 2 * Math.PI * r;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-2">
      <svg
        width={size}
        height={size}
        viewBox="0 0 100 100"
        className="-rotate-90"
      >
        {/* Background ring */}
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke="#1e293b"
          strokeWidth="8"
        />
        {/* Score ring */}
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="score-ring"
          style={{ filter: `drop-shadow(0 0 6px ${color}50)` }}
        />
      </svg>
      {/* Center text (positioned over svg) */}
      <div
        className="flex flex-col items-center -mt-[calc(100%_-_0.5rem)]"
        style={{ marginTop: -(size * 0.65) }}
      >
        <span className="text-3xl font-bold" style={{ color }}>
          {score}
        </span>
        <span className="text-xs text-muted">/100</span>
      </div>
      <span
        className="mt-1 rounded-full px-3 py-0.5 text-xs font-semibold"
        style={{ backgroundColor: `${color}20`, color }}
      >
        {label}
      </span>
    </div>
  );
}

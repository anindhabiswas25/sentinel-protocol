import { BarChart3, ShieldCheck, ShieldAlert, TrendingUp } from "lucide-react";
import type { StatsResponse } from "@/lib/types";

const STAT_CARDS = (s: StatsResponse) => [
  {
    label: "Total Analyses",
    value: s.total_analyses,
    icon: <BarChart3 className="h-5 w-5" />,
    color: "text-accent",
    bg: "bg-accent/15",
  },
  {
    label: "Verified Contracts",
    value: s.verified_contracts,
    icon: <ShieldCheck className="h-5 w-5" />,
    color: "text-success",
    bg: "bg-success/15",
  },
  {
    label: "Unverified",
    value: s.unverified_contracts,
    icon: <ShieldAlert className="h-5 w-5" />,
    color: "text-danger",
    bg: "bg-danger/15",
  },
  {
    label: "Avg Trust Score",
    value: Math.round(s.average_trust_score),
    icon: <TrendingUp className="h-5 w-5" />,
    color: "text-warning",
    bg: "bg-warning/15",
  },
];

export default function StatsCards({ stats }: { stats: StatsResponse }) {
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {STAT_CARDS(stats).map((c) => (
        <div
          key={c.label}
          className="rounded-xl border border-card-border bg-card p-5 flex items-center gap-4"
        >
          <div className={`rounded-lg p-2.5 ${c.bg} ${c.color}`}>
            {c.icon}
          </div>
          <div>
            <p className="text-2xl font-bold">{c.value}</p>
            <p className="text-xs text-muted">{c.label}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

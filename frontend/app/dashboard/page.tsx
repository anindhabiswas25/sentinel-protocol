"use client";

import { useEffect, useState } from "react";
import StatsCards from "@/components/StatsCards";
import HistoryTable from "@/components/HistoryTable";
import LoadingSpinner from "@/components/LoadingSpinner";
import { getStats, getHistory, getHealth } from "@/lib/api";
import type { StatsResponse, AnalysisHistoryItem, HealthResponse } from "@/lib/types";
import { LayoutDashboard, Activity } from "lucide-react";

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [history, setHistory] = useState<AnalysisHistoryItem[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [s, h, hp] = await Promise.all([
          getStats(),
          getHistory(20),
          getHealth(),
        ]);
        setStats(s);
        setHistory(h);
        setHealth(hp);
      } catch {
        // silently fail — UI shows empty state
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8 space-y-10">
      {/* Title */}
      <div>
        <h1 className="flex items-center gap-2 text-3xl font-bold">
          <LayoutDashboard className="h-7 w-7 text-accent" />
          Dashboard
        </h1>
        <p className="mt-1 text-muted">
          Overview of all contract analyses performed
        </p>
      </div>

      {/* Backend status */}
      {health && (
        <div className="flex flex-wrap gap-3">
          {(
            [
              ["API", health.status],
              ["Database", health.database],
              ["Vector DB", health.vector_db],
              ["Blockchain", health.blockchain],
            ] as const
          ).map(([label, status]) => (
            <span
              key={label}
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${
                status === "connected" || status === "healthy"
                  ? "bg-success/15 text-success"
                  : "bg-danger/15 text-danger"
              }`}
            >
              <Activity className="h-3 w-3" />
              {label}: {status}
            </span>
          ))}
        </div>
      )}

      {/* Stats */}
      {stats && <StatsCards stats={stats} />}

      {/* History */}
      <div>
        <h2 className="mb-4 text-lg font-semibold">Recent Analyses</h2>
        <HistoryTable items={history} />
      </div>
    </div>
  );
}

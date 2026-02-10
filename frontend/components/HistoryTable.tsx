"use client";

import { formatAddress, formatDate, getScoreColor } from "@/lib/utils";
import type { AnalysisHistoryItem } from "@/lib/types";
import { ShieldCheck, ShieldAlert } from "lucide-react";
import Link from "next/link";

export default function HistoryTable({
  items,
}: {
  items: AnalysisHistoryItem[];
}) {
  if (items.length === 0) {
    return (
      <div className="rounded-xl border border-card-border bg-card p-10 text-center text-muted">
        No analyses yet. Start your first audit!
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-card-border bg-card">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-card-border text-left text-xs text-muted uppercase tracking-wider">
            <th className="px-4 py-3">Contract</th>
            <th className="px-4 py-3">Network</th>
            <th className="px-4 py-3">Verified</th>
            <th className="px-4 py-3">Trust Score</th>
            <th className="px-4 py-3">Date</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-card-border">
          {items.map((item) => {
            const color = getScoreColor(item.trust_score);
            return (
              <tr
                key={item.id}
                className="hover:bg-white/[0.02] transition-colors"
              >
                <td className="px-4 py-3">
                  <div>
                    <p className="font-medium">
                      {item.contract_name ?? "Unknown"}
                    </p>
                    <p className="font-mono text-xs text-muted">
                      {formatAddress(item.contract_address)}
                    </p>
                  </div>
                </td>
                <td className="px-4 py-3 capitalize">{item.network}</td>
                <td className="px-4 py-3">
                  {item.is_verified ? (
                    <ShieldCheck className="h-4 w-4 text-success" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 text-danger" />
                  )}
                </td>
                <td className="px-4 py-3">
                  <span
                    className="font-bold"
                    style={{ color }}
                  >
                    {item.trust_score}
                  </span>
                </td>
                <td className="px-4 py-3 text-muted text-xs">
                  {item.created_at ? formatDate(item.created_at) : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

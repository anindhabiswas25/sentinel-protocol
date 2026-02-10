"use client";

import TrustScoreGauge from "./TrustScoreGauge";
import VulnerabilityCard from "./VulnerabilityCard";
import {
  ShieldCheck,
  ShieldAlert,
  FileCode,
  Clock,
  ExternalLink,
  Copy,
  CheckCircle,
} from "lucide-react";
import { formatAddress, formatDate } from "@/lib/utils";
import { SEVERITY_CONFIG } from "@/lib/constants";
import type { ContractAnalysisResponse } from "@/lib/types";
import { useState } from "react";

export default function ResultsPanel({
  data,
}: {
  data: ContractAnalysisResponse;
}) {
  const { metadata, trust_score, summary, vulnerabilities, recommendations } =
    data;
  const [copied, setCopied] = useState(false);

  const copyAddress = async () => {
    await navigator.clipboard.writeText(metadata.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-6">
      {/* ── Contract Info Bar ──────────────────────── */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-card-border bg-card px-5 py-4">
        <div className="flex items-center gap-2">
          <FileCode className="h-5 w-5 text-accent" />
          <span className="font-semibold">
            {metadata.name ?? "Unknown Contract"}
          </span>
        </div>

        <button
          onClick={copyAddress}
          className="flex items-center gap-1 rounded-md bg-white/5 px-2 py-1 font-mono text-xs text-muted hover:text-foreground transition-colors"
        >
          {formatAddress(metadata.address)}
          {copied ? (
            <CheckCircle className="h-3 w-3 text-success" />
          ) : (
            <Copy className="h-3 w-3" />
          )}
        </button>

        <span className="rounded-full bg-accent/15 px-2.5 py-0.5 text-xs font-medium text-accent capitalize">
          {metadata.network}
        </span>

        {metadata.is_verified ? (
          <span className="flex items-center gap-1 rounded-full bg-success/15 px-2.5 py-0.5 text-xs font-medium text-success">
            <ShieldCheck className="h-3 w-3" /> Verified
          </span>
        ) : (
          <span className="flex items-center gap-1 rounded-full bg-danger/15 px-2.5 py-0.5 text-xs font-medium text-danger">
            <ShieldAlert className="h-3 w-3" /> Unverified
          </span>
        )}

        {metadata.is_proxy && (
          <span className="rounded-full bg-warning/15 px-2.5 py-0.5 text-xs font-medium text-warning">
            Proxy
          </span>
        )}

        <span className="ml-auto flex items-center gap-1 text-xs text-muted">
          <Clock className="h-3 w-3" />
          {formatDate(data.analysis_timestamp)}
        </span>
      </div>

      {/* ── Score + Severity Breakdown ─────────────── */}
      <div className="grid gap-6 md:grid-cols-3">
        {/* Gauge */}
        <div className="flex items-center justify-center rounded-xl border border-card-border bg-card p-6 glow-blue">
          <TrustScoreGauge score={trust_score.overall_score} />
        </div>

        {/* Sub-scores */}
        <div className="rounded-xl border border-card-border bg-card p-6 space-y-4">
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider">
            Score Breakdown
          </h3>
          {[
            { label: "Security", value: trust_score.security_score },
            { label: "Code Quality", value: trust_score.code_quality_score },
            { label: "Verification", value: trust_score.verification_score },
          ].map((s) => (
            <div key={s.label}>
              <div className="flex justify-between text-sm mb-1">
                <span>{s.label}</span>
                <span className="font-mono">{s.value}</span>
              </div>
              <div className="h-2 rounded-full bg-white/5 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${s.value}%`,
                    background: `linear-gradient(90deg, #3b82f6, ${
                      s.value >= 70 ? "#22c55e" : s.value >= 40 ? "#eab308" : "#ef4444"
                    })`,
                  }}
                />
              </div>
            </div>
          ))}
        </div>

        {/* Severity summary */}
        <div className="rounded-xl border border-card-border bg-card p-6 space-y-3">
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider">
            Findings ({summary.total_vulnerabilities})
          </h3>
          {(
            [
              ["critical", summary.critical_count],
              ["high", summary.high_count],
              ["medium", summary.medium_count],
              ["low", summary.low_count],
              ["informational", summary.informational_count],
            ] as const
          ).map(([sev, count]) => {
            const cfg =
              SEVERITY_CONFIG[sev as keyof typeof SEVERITY_CONFIG];
            return (
              <div
                key={sev}
                className="flex items-center justify-between text-sm"
              >
                <span className={cfg.text}>{cfg.label}</span>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-bold ${cfg.bg} ${cfg.text}`}
                >
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── LLM Insights ───────────────────────────── */}
      {summary.llm_insights && (
        <div className="rounded-xl border border-card-border bg-card p-6">
          <h3 className="mb-3 text-sm font-semibold text-muted uppercase tracking-wider">
            AI Analysis Insights
          </h3>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground/80">
            {summary.llm_insights}
          </p>
        </div>
      )}

      {/* ── Vulnerabilities List ───────────────────── */}
      {vulnerabilities.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider">
            Vulnerabilities
          </h3>
          {vulnerabilities.map((v) => (
            <VulnerabilityCard key={v.id} vuln={v} />
          ))}
        </div>
      )}

      {/* ── Recommendations ────────────────────────── */}
      {recommendations.length > 0 && (
        <div className="rounded-xl border border-card-border bg-card p-6">
          <h3 className="mb-3 text-sm font-semibold text-muted uppercase tracking-wider">
            Recommendations
          </h3>
          <ul className="space-y-2">
            {recommendations.map((rec, i) => (
              <li key={i} className="flex gap-2 text-sm">
                <span className="mt-0.5 text-accent">•</span>
                <span className="text-foreground/80">{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

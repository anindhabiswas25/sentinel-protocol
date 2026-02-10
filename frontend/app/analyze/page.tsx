"use client";

import { useState } from "react";
import ContractInput from "@/components/ContractInput";
import ResultsPanel from "@/components/ResultsPanel";
import LoadingSpinner from "@/components/LoadingSpinner";
import { analyzeContract, analyzeSourceCode, detectNetwork } from "@/lib/api";
import type { ContractAnalysisResponse } from "@/lib/types";
import { Shield, AlertTriangle, Globe } from "lucide-react";
import { capitalize } from "@/lib/utils";

export default function AnalyzePage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ContractAnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [detectedNetworks, setDetectedNetworks] = useState<string[]>([]);

  const handleAddress = async (address: string) => {
    setLoading(true);
    setError("");
    setResult(null);
    setDetectedNetworks([]);

    try {
      // Step 1 — Auto-detect network
      setStatus("Detecting network…");
      const detection = await detectNetwork(address);

      if (!detection.found || detection.networks.length === 0) {
        setError(
          "No contract found at this address on any supported network (Ethereum, Polygon, Arbitrum, Base)."
        );
        setLoading(false);
        setStatus("");
        return;
      }

      const network = detection.primary ?? detection.networks[0];
      setDetectedNetworks(detection.networks);
      setStatus(
        `Contract found on ${capitalize(network)}${detection.networks.length > 1 ? ` (+${detection.networks.length - 1} more)` : ""} — running AI analysis…`
      );

      // Step 2 — Analyze
      const data = await analyzeContract(address, network);
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
      setStatus("");
    }
  };

  const handleSource = async (code: string) => {
    setLoading(true);
    setError("");
    setResult(null);
    setDetectedNetworks([]);
    setStatus("Running AI analysis on source code…");
    try {
      const data = await analyzeSourceCode(code);
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
      setStatus("");
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 lg:px-8">
      <div className="mb-8 text-center">
        <h1 className="flex items-center justify-center gap-2 text-3xl font-bold">
          <Shield className="h-7 w-7 text-accent" />
          Analyze Contract
        </h1>
        <p className="mt-2 text-muted">
          Enter a contract address — the network is detected automatically
        </p>
      </div>

      <ContractInput
        onSubmitAddress={handleAddress}
        onSubmitSource={handleSource}
        loading={loading}
        statusMessage={status}
      />

      {/* Detected networks badge */}
      {detectedNetworks.length > 0 && !loading && (
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Globe className="h-4 w-4 text-accent" />
          <span className="text-xs text-muted">Detected on:</span>
          {detectedNetworks.map((n) => (
            <span
              key={n}
              className="rounded-full bg-accent/15 px-2.5 py-0.5 text-xs font-medium text-accent capitalize"
            >
              {n}
            </span>
          ))}
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="mt-12 flex flex-col items-center gap-4">
          <LoadingSpinner />
          <p className="text-sm text-muted animate-pulse">
            {status || "Running AI analysis — this may take 15-30 seconds…"}
          </p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="mt-8 flex items-center gap-3 rounded-xl border border-danger/40 bg-danger/10 px-5 py-4 text-sm text-danger">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="mt-10">
          <ResultsPanel data={result} />
        </div>
      )}
    </div>
  );
}

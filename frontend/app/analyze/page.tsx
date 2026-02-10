"use client";

import { useState } from "react";
import ContractInput from "@/components/ContractInput";
import ResultsPanel from "@/components/ResultsPanel";
import LoadingSpinner from "@/components/LoadingSpinner";
import { analyzeContract, analyzeSourceCode } from "@/lib/api";
import type { ContractAnalysisResponse } from "@/lib/types";
import type { ChainId } from "@/lib/constants";
import { Shield, AlertTriangle } from "lucide-react";

export default function AnalyzePage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ContractAnalysisResponse | null>(null);
  const [error, setError] = useState("");

  const handleAddress = async (address: string, chain: ChainId) => {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await analyzeContract(address, chain);
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  const handleSource = async (code: string) => {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await analyzeSourceCode(code);
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
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
          Enter a contract address or paste Solidity source code
        </p>
      </div>

      <ContractInput
        onSubmitAddress={handleAddress}
        onSubmitSource={handleSource}
        loading={loading}
      />

      {/* Loading state */}
      {loading && (
        <div className="mt-12 flex flex-col items-center gap-4">
          <LoadingSpinner />
          <p className="text-sm text-muted animate-pulse">
            Running AI analysis — this may take 15-30 seconds…
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

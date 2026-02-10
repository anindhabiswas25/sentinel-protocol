"use client";

import { useState } from "react";
import { Search, Code2 } from "lucide-react";
import { isValidAddress } from "@/lib/utils";

type Mode = "address" | "source";

interface Props {
  onSubmitAddress: (address: string) => void;
  onSubmitSource: (code: string) => void;
  loading: boolean;
  statusMessage?: string;
}

export default function ContractInput({
  onSubmitAddress,
  onSubmitSource,
  loading,
  statusMessage,
}: Props) {
  const [mode, setMode] = useState<Mode>("address");
  const [address, setAddress] = useState("");
  const [source, setSource] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (mode === "address") {
      if (!isValidAddress(address)) {
        setError("Enter a valid Ethereum address (0x…40 hex chars)");
        return;
      }
      onSubmitAddress(address);
    } else {
      if (source.trim().length < 20) {
        setError("Paste at least a minimal Solidity contract");
        return;
      }
      onSubmitSource(source);
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-2xl border border-card-border bg-card p-6 space-y-5"
    >
      {/* Mode toggle */}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => setMode("address")}
          className={`flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
            mode === "address"
              ? "bg-accent/15 text-accent"
              : "text-muted hover:text-foreground"
          }`}
        >
          <Search className="h-4 w-4" /> By Address
        </button>
        <button
          type="button"
          onClick={() => setMode("source")}
          className={`flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
            mode === "source"
              ? "bg-accent/15 text-accent"
              : "text-muted hover:text-foreground"
          }`}
        >
          <Code2 className="h-4 w-4" /> Paste Source
        </button>
      </div>

      {mode === "address" ? (
        <>
          <input
            type="text"
            placeholder="0x contract address — network is detected automatically"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            className="w-full rounded-lg border border-card-border bg-background px-4 py-3 font-mono text-sm placeholder:text-muted/50 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
          />
          {statusMessage && (
            <p className="text-sm text-accent animate-pulse">{statusMessage}</p>
          )}
        </>
      ) : (
        <textarea
          rows={8}
          placeholder="// Paste Solidity source code here…"
          value={source}
          onChange={(e) => setSource(e.target.value)}
          className="w-full rounded-lg border border-card-border bg-background px-4 py-3 font-mono text-sm placeholder:text-muted/50 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent resize-y"
        />
      )}

      {error && <p className="text-sm text-danger">{error}</p>}

      <button
        type="submit"
        disabled={loading}
        className="w-full rounded-lg bg-accent px-4 py-3 text-sm font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? "Analyzing…" : "Analyze Contract"}
      </button>
    </form>
  );
}

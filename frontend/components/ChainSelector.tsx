"use client";

import { SUPPORTED_CHAINS } from "@/lib/constants";
import type { ChainId } from "@/lib/constants";

interface Props {
  value: ChainId;
  onChange: (chain: ChainId) => void;
}

export default function ChainSelector({ value, onChange }: Props) {
  return (
    <div className="flex flex-wrap gap-2">
      {SUPPORTED_CHAINS.map((chain) => {
        const active = value === chain.id;
        return (
          <button
            key={chain.id}
            type="button"
            onClick={() => onChange(chain.id)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition-all ${
              active
                ? "border-accent bg-accent/15 text-accent"
                : "border-card-border bg-card text-muted hover:text-foreground hover:border-white/20"
            }`}
          >
            <span>{chain.icon}</span>
            <span>{chain.name}</span>
          </button>
        );
      })}
    </div>
  );
}

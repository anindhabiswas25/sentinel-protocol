/* ===== Sentinel Protocol – Constants ===== */

export const SUPPORTED_CHAINS = [
  { id: "ethereum", name: "Ethereum", icon: "⟠", color: "#627EEA" },
  { id: "polygon", name: "Polygon", icon: "⬡", color: "#8247E5" },
  { id: "arbitrum", name: "Arbitrum", icon: "🔵", color: "#28A0F0" },
  { id: "base", name: "Base", icon: "🔵", color: "#0052FF" },
] as const;

export type ChainId = (typeof SUPPORTED_CHAINS)[number]["id"];

export const SEVERITY_CONFIG = {
  critical: { label: "Critical", color: "#EF4444", bg: "bg-red-500/20", text: "text-red-400", border: "border-red-500/40" },
  high:     { label: "High",     color: "#F97316", bg: "bg-orange-500/20", text: "text-orange-400", border: "border-orange-500/40" },
  medium:   { label: "Medium",   color: "#EAB308", bg: "bg-yellow-500/20", text: "text-yellow-400", border: "border-yellow-500/40" },
  low:      { label: "Low",      color: "#22C55E", bg: "bg-green-500/20", text: "text-green-400", border: "border-green-500/40" },
  informational: { label: "Info", color: "#3B82F6", bg: "bg-blue-500/20", text: "text-blue-400", border: "border-blue-500/40" },
} as const;

export const RISK_COLORS: Record<string, string> = {
  Safe: "#22C55E",
  Low: "#22C55E",
  Medium: "#EAB308",
  High: "#F97316",
  Critical: "#EF4444",
  Unknown: "#6B7280",
};

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
